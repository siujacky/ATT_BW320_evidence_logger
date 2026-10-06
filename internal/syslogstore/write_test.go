package syslogstore

import (
	"bytes"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"attmonitor/internal/model"
)

func TestAppendWritesExactLines(t *testing.T) {
	s, _ := testStore(t, Options{})
	ms := msgs(t0, 3, "m")
	// Text that json.Marshal escapes, and a control character.
	ms[1].Raw, ms[1].Msg = "<b>a & b</b>\x01", "<b>a & b</b>\x01"
	sealed, err := s.Append(ms, 0, 0, t0)
	if err != nil || sealed != nil {
		t.Fatalf("Append: %v %v", sealed, err)
	}
	opens := openFiles(t, s.dir)
	if !slices.Equal(opens, []string{"open-20261005T221500.123456789Z.jsonl"}) {
		t.Fatalf("open files %v", opens)
	}
	got := readFile(t, filepath.Join(s.dir, opens[0]))
	if want := linesOf(t, ms); !bytes.Equal(got, want) {
		t.Fatalf("open chunk holds\n%s\nwant\n%s", got, want)
	}
	backslash := string(rune(92))
	if bytes.Contains(got, []byte("<b>")) || !bytes.Contains(got, []byte(backslash+"u003cb"+backslash+"u003ea "+backslash+"u0026 b")) ||
		!bytes.Contains(got, []byte(backslash+"u0001")) {
		t.Fatalf("not json.Marshal's escaping: %s", got)
	}
	// More messages go to the same chunk, after the first ones.
	more := msgs(t0.Add(time.Minute), 2, "n")
	if _, err := s.Append(more, 0, 0, t0.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if got, want := readFile(t, filepath.Join(s.dir, opens[0])), linesOf(t, append(ms, more...)); !bytes.Equal(got, want) {
		t.Fatalf("open chunk holds\n%s\nwant\n%s", got, want)
	}
	u := s.Usage()
	if u.OpenMessages != 5 || u.Messages != 5 || u.Chunks != 0 || u.Bytes != int64(len(linesOf(t, append(ms, more...)))) ||
		u.Oldest != ms[0].RX || u.Newest != more[1].RX || u.KeepMB != DefaultKeepMB || u.KeepDays != 0 {
		t.Fatalf("Usage: %+v", u)
	}
}

func TestAppendNothing(t *testing.T) {
	s, _ := testStore(t, Options{})
	if sealed, err := s.Append(nil, 0, 0, t0); err != nil || sealed != nil {
		t.Fatalf("Append: %v %v", sealed, err)
	}
	if n := names(t, s.dir); len(n) != 0 {
		t.Fatalf("files %v", n)
	}
	if c, err := s.Seal(t0.Add(time.Hour), "stop", true); err != nil || c != nil {
		t.Fatalf("Seal of nothing: %v %v", c, err)
	}
}

func TestCountsOnlyChunk(t *testing.T) {
	s, _ := testStore(t, Options{})
	if _, err := s.Append(nil, 2, 3, t0); err != nil {
		t.Fatal(err)
	}
	// Opened at now, empty, with its counts in the state file.
	open := filepath.Join(s.dir, "open-20261005T221500.123456789Z.jsonl")
	if b := readFile(t, open); len(b) != 0 {
		t.Fatalf("open chunk holds %q", b)
	}
	st, err := readState(filepath.Join(s.dir, "open-20261005T221500.123456789Z.state.json"))
	if err != nil || st != (openState{Dropped: 2, Rejected: 3}) {
		t.Fatalf("state %+v %v", st, err)
	}
	if _, err := s.Append(nil, 1, 0, t0.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	c, err := s.Seal(t0.Add(2*time.Second), "", true)
	if err != nil || c == nil {
		t.Fatalf("Seal: %v %v", c, err)
	}
	want := model.SyslogChunk{
		Name: "syslog-20261005T221500.123456789Z_20261005T221500.123456789Z.jsonl.gz",
		From: "2026-10-05T22:15:00.123456789Z", To: "2026-10-05T22:15:00.123456789Z",
		Messages: 0, Dropped: 3, Rejected: 3, Bytes: 0, SHA256: sha(nil), GzBytes: c.GzBytes, Reason: "stop",
	}
	if *c != want {
		t.Fatalf("sealed\n%+v\nwant\n%+v", *c, want)
	}
	checkChunk(t, s.dir, *c, nil)
	if n := names(t, s.dir); !slices.Equal(n, []string{want.Name, want.Name + ".json"}) {
		t.Fatalf("files %v", n)
	}
	// Another one at the same instant (a clock that stands still) gets a name of its own.
	if _, err := s.Append(nil, 1, 0, t0); err != nil {
		t.Fatal(err)
	}
	c2, err := s.Seal(t0, "", true)
	if err != nil || c2 == nil || c2.Name != "syslog-20261005T221500.123456789Z_20261005T221500.123456789Z-2.jsonl.gz" {
		t.Fatalf("second Seal: %+v %v", c2, err)
	}
	if u := s.Usage(); u.Chunks != 2 || u.Messages != 0 || u.Oldest != "" {
		t.Fatalf("Usage: %+v", u)
	}
}

func TestSealBySizeSplitsBatch(t *testing.T) {
	ms := msgs(t0, 10, "m")
	lineLen := int64(len(lineOf(t, ms[0])))
	for _, m := range ms {
		if int64(len(lineOf(t, m))) != lineLen {
			t.Fatal("lines differ in length")
		}
	}
	// A chunk reaches the limit with its third line.
	s, _ := testStore(t, Options{ChunkBytes: 2*lineLen + 1})
	sealed, err := s.Append(ms[:7], 0, 0, t0)
	if err != nil {
		t.Fatal(err)
	}
	if len(sealed) != 2 {
		t.Fatalf("sealed %d chunks, want 2: %+v", len(sealed), sealed)
	}
	for i, c := range sealed {
		part := ms[3*i : 3*i+3]
		if c.Reason != "size" || c.Messages != 3 || c.From != part[0].RX || c.To != part[2].RX {
			t.Fatalf("chunk %d: %+v", i, c)
		}
		if c.Name != sealedName(t0.Add(time.Duration(3*i)*time.Second), t0.Add(time.Duration(3*i+2)*time.Second), 1) {
			t.Fatalf("chunk %d named %s", i, c.Name)
		}
		checkChunk(t, s.dir, c, linesOf(t, part))
	}
	// The seventh message is in the open chunk, named after it; the next batch fills it.
	if opens := openFiles(t, s.dir); !slices.Equal(opens, []string{openName(t0.Add(6*time.Second), 1)}) {
		t.Fatalf("open files %v", opens)
	}
	sealed, err = s.Append(ms[7:], 0, 0, t0)
	if err != nil || len(sealed) != 1 || sealed[0].Messages != 3 || sealed[0].From != ms[6].RX {
		t.Fatalf("second batch sealed %+v, %v", sealed, err)
	}
	checkChunk(t, s.dir, sealed[0], linesOf(t, ms[6:9]))
	if u := s.Usage(); u.OpenMessages != 1 || u.Messages != 10 || u.Chunks != 3 {
		t.Fatalf("Usage: %+v", u)
	}
	// Nothing is lost or repeated.
	if got := entryTexts(queryAll(t, s)); !slices.Equal(got, reversed(ms)) {
		t.Fatalf("stored %v", got)
	}
}

func TestSealBySizeOneLargeLine(t *testing.T) {
	s, _ := testStore(t, Options{ChunkBytes: 10})
	m := msg(t0, strings.Repeat("x", 100))
	sealed, err := s.Append([]model.SyslogMessage{m}, 0, 0, t0)
	if err != nil || len(sealed) != 1 || sealed[0].Messages != 1 {
		t.Fatalf("sealed %+v, %v", sealed, err)
	}
	checkChunk(t, s.dir, sealed[0], lineOf(t, m))
	if len(openFiles(t, s.dir)) != 0 {
		t.Fatal("an open chunk remains")
	}
}

func TestSealByAge(t *testing.T) {
	s, _ := testStore(t, Options{ChunkAge: 5 * time.Minute})
	// Opened by its first Append; ChunkAge counts from then, not from the messages' times.
	opened := t0.Add(time.Hour)
	if _, err := s.Append(msgs(t0, 2, "m"), 0, 0, opened); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Append(msgs(t0.Add(time.Minute), 1, "n"), 0, 0, opened.Add(4*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if c, err := s.Seal(opened.Add(5*time.Minute-time.Nanosecond), "age", false); err != nil || c != nil {
		t.Fatalf("Seal before ChunkAge: %v %v", c, err)
	}
	c, err := s.Seal(opened.Add(5*time.Minute), "age", false)
	if err != nil || c == nil || c.Reason != "age" || c.Messages != 3 {
		t.Fatalf("Seal at ChunkAge: %+v %v", c, err)
	}
	if c, err := s.Seal(opened.Add(time.Hour), "age", false); err != nil || c != nil {
		t.Fatalf("Seal without an open chunk: %v %v", c, err)
	}
}

func TestSealForce(t *testing.T) {
	s, _ := testStore(t, Options{})
	ms := msgs(t0, 2, "m")
	if _, err := s.Append(ms, 4, 1, t0); err != nil {
		t.Fatal(err)
	}
	c, err := s.Seal(t0, "stop", true)
	if err != nil || c == nil {
		t.Fatalf("Seal: %v %v", c, err)
	}
	want := model.SyslogChunk{Name: sealedName(t0, t0.Add(time.Second), 1), From: ms[0].RX, To: ms[1].RX,
		Messages: 2, Dropped: 4, Rejected: 1, Bytes: int64(len(linesOf(t, ms))), SHA256: sha(linesOf(t, ms)),
		GzBytes: c.GzBytes, Reason: "stop"}
	if *c != want {
		t.Fatalf("sealed\n%+v\nwant\n%+v", *c, want)
	}
	checkChunk(t, s.dir, *c, linesOf(t, ms))
	sc := readSidecarFile(t, s.dir, c.Name)
	if sc.RXMin != ms[0].RX || sc.RXMax != ms[1].RX {
		t.Fatalf("sidecar range %s - %s", sc.RXMin, sc.RXMax)
	}
	// The open chunk's files are gone; the next message opens a new chunk.
	if n := names(t, s.dir); !slices.Equal(n, []string{c.Name, c.Name + ".json"}) {
		t.Fatalf("files %v", n)
	}
	if _, err := s.Append(msgs(t0.Add(time.Hour), 1, "n"), 0, 0, t0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if opens := openFiles(t, s.dir); len(opens) != 1 {
		t.Fatalf("open files %v", opens)
	}
}

func TestAppendCounts(t *testing.T) {
	s, _ := testStore(t, Options{})
	if _, err := s.Append(msgs(t0, 1, "a"), 1, 2, t0); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Append(nil, 3, 0, t0.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	// Negative counts are a caller's mistake: they count as 0.
	if _, err := s.Append(msgs(t0.Add(2*time.Second), 1, "b"), -5, 4, t0.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	st, err := readState(filepath.Join(s.dir, stateName(openName(t0, 1))))
	if err != nil || st != (openState{Dropped: 4, Rejected: 6}) {
		t.Fatalf("state %+v %v", st, err)
	}
	c, err := s.Seal(t0, "stop", true)
	if err != nil || c.Dropped != 4 || c.Rejected != 6 || c.Messages != 2 {
		t.Fatalf("Seal: %+v %v", c, err)
	}
}

func TestAppendInvalidReceiveTime(t *testing.T) {
	s, h := testStore(t, Options{})
	ms := msgs(t0, 3, "m")
	ms[1].RX = "yesterday"
	if _, err := s.Append(ms, 0, 0, t0); err != nil {
		t.Fatal(err)
	}
	if h.count("without a valid receive time") != 1 {
		t.Fatalf("not logged:\n%s", h.all())
	}
	c, err := s.Seal(t0, "stop", true)
	if err != nil || c.Messages != 2 || c.Dropped != 1 {
		t.Fatalf("Seal: %+v %v", c, err)
	}
	checkChunk(t, s.dir, *c, linesOf(t, []model.SyslogMessage{ms[0], ms[2]}))

	// A batch of only such messages still records them as dropped.
	bad := msg(t0, "x")
	bad.RX = ""
	if _, err := s.Append([]model.SyslogMessage{bad}, 0, 0, t0.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if c, err := s.Seal(t0.Add(time.Minute), "stop", true); err != nil || c.Messages != 0 || c.Dropped != 1 {
		t.Fatalf("Seal: %+v %v", c, err)
	}
}

func TestAppendWriteFailureCountsDropped(t *testing.T) {
	s, _ := testStore(t, Options{})
	if _, err := s.Append(msgs(t0, 2, "m"), 0, 0, t0); err != nil {
		t.Fatal(err)
	}
	// The handle fails from now on (as a failing disk would).
	s.open.f.Close()
	_, err := s.Append(msgs(t0.Add(time.Minute), 3, "n"), 1, 0, t0)
	if err == nil {
		t.Fatal("Append on a failing file succeeded")
	}
	s.mu.Lock()
	dropped, messages := s.open.dropped, s.open.messages
	s.mu.Unlock()
	if dropped != 4 || messages != 2 {
		t.Fatalf("after a failed write: dropped %d messages %d, want 4 and 2", dropped, messages)
	}
	// The state file has the counts, so a crash now keeps them.
	if st, err := readState(filepath.Join(s.dir, stateName(openName(t0, 1)))); err != nil || st.Dropped != 4 {
		t.Fatalf("state %+v %v", st, err)
	}
	if _, err := s.Seal(t0, "stop", true); err == nil {
		t.Fatal("Seal on a failing file succeeded")
	}
}

func TestSealFailureKeepsChunkOpen(t *testing.T) {
	s, _ := testStore(t, Options{ChunkBytes: 1})
	// The temporary file cannot be created: a directory has its name.
	if err := mkdir(filepath.Join(s.dir, sealTmp)); err != nil {
		t.Fatal(err)
	}
	ms := msgs(t0, 3, "m")
	sealed, err := s.Append(ms[:2], 0, 0, t0)
	if err == nil || len(sealed) != 0 {
		t.Fatalf("Append: %v %v", sealed, err)
	}
	// Both messages stay in the open chunk (larger than ChunkBytes), none is lost.
	if got := readFile(t, filepath.Join(s.dir, openName(t0, 1))); !bytes.Equal(got, linesOf(t, ms[:2])) {
		t.Fatalf("open chunk holds %s", got)
	}
	if err := removeDir(filepath.Join(s.dir, sealTmp)); err != nil {
		t.Fatal(err)
	}
	// The next Append seals the full chunk first.
	sealed, err = s.Append(ms[2:], 0, 0, t0)
	if err != nil || len(sealed) != 2 || sealed[0].Messages != 2 || sealed[1].Messages != 1 {
		t.Fatalf("Append: %+v %v", sealed, err)
	}
}

func TestClosedStore(t *testing.T) {
	s, _ := testStore(t, Options{})
	ms := msgs(t0, 2, "m")
	if _, err := s.Append(ms, 0, 0, t0); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if _, err := s.Append(ms, 0, 0, t0); !errors.Is(err, ErrClosed) {
		t.Fatalf("Append after Close: %v", err)
	}
	if _, err := s.Seal(t0, "stop", true); !errors.Is(err, ErrClosed) {
		t.Fatalf("Seal after Close: %v", err)
	}
	if _, err := s.Prune(t0); !errors.Is(err, ErrClosed) {
		t.Fatalf("Prune after Close: %v", err)
	}
	if _, err := s.Recover(t0); !errors.Is(err, ErrClosed) {
		t.Fatalf("Recover after Close: %v", err)
	}
	// Reading still works: the open chunk is read from its file.
	if got := entryTexts(queryAll(t, s)); !slices.Equal(got, reversed(ms)) {
		t.Fatalf("Query after Close: %v", got)
	}
}

func TestZeroTimeUsesNow(t *testing.T) {
	now := t0.Add(time.Hour)
	s, _ := testStore(t, Options{Now: func() time.Time { return now }})
	if _, err := s.Append(nil, 1, 0, time.Time{}); err != nil {
		t.Fatal(err)
	}
	if opens := openFiles(t, s.dir); !slices.Equal(opens, []string{openName(now, 1)}) {
		t.Fatalf("open files %v", opens)
	}
	now = now.Add(DefaultChunkAge)
	if c, err := s.Seal(time.Time{}, "", false); err != nil || c == nil || c.Reason != "age" {
		t.Fatalf("Seal: %+v %v", c, err)
	}
}

func TestOpenChunkNameTaken(t *testing.T) {
	// A file of an earlier chunk opened at the same time is still there (it could not be
	// deleted, or Recover has not run yet): the new chunk gets a name of its own.
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, openName(t0, 1)), nil)
	s, _ := testStore(t, Options{Dir: dir})
	ms := msgs(t0, 2, "m")
	if _, err := s.Append(ms, 0, 0, t0); err != nil {
		t.Fatal(err)
	}
	if opens := openFiles(t, dir); !slices.Equal(opens, []string{openName(t0, 2), openName(t0, 1)}) {
		t.Fatalf("open files %v", opens)
	}
	if got := readFile(t, filepath.Join(dir, openName(t0, 2))); !bytes.Equal(got, linesOf(t, ms)) {
		t.Fatalf("open chunk holds %s", got)
	}
	c, err := s.Seal(t0, "stop", true)
	if err != nil || c == nil || c.Messages != 2 {
		t.Fatalf("Seal: %+v %v", c, err)
	}
	if opens := openFiles(t, dir); !slices.Equal(opens, []string{openName(t0, 1)}) {
		t.Fatalf("open files %v", opens)
	}
}
