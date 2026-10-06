package syslogstore

import (
	"bytes"
	"path/filepath"
	"slices"
	"strconv"
	"testing"
	"time"

	"attmonitor/internal/model"
)

// leaveOpen writes the files of a chunk that a previous run left open: its content and, unless
// st is nil, its state file.
func leaveOpen(t *testing.T, dir string, opened time.Time, content []byte, st *openState) string {
	t.Helper()
	name := openName(opened, 1)
	writeFile(t, filepath.Join(dir, name), content)
	if st != nil {
		if err := writeState(filepath.Join(dir, stateName(name)), *st); err != nil {
			t.Fatal(err)
		}
	}
	return name
}

func TestRecoverSealsChunkLeftOpen(t *testing.T) {
	s, _ := testStore(t, Options{})
	ms := msgs(t0, 3, "m")
	if _, err := s.Append(ms, 1, 2, t0); err != nil {
		t.Fatal(err)
	}
	s, h := reopen(t, s, Options{}) // the service stopped without sealing (a crash)
	if u := s.Usage(); u.Messages != 0 {
		t.Fatalf("Usage before Recover: %+v", u)
	}
	got, err := s.Recover(t0.Add(time.Hour))
	if err != nil || len(got) != 1 {
		t.Fatalf("Recover: %+v %v", got, err)
	}
	c := got[0]
	want := model.SyslogChunk{Name: sealedName(t0, t0.Add(2*time.Second), 1), From: ms[0].RX, To: ms[2].RX,
		Messages: 3, Dropped: 1, Rejected: 2, Bytes: int64(len(linesOf(t, ms))), SHA256: sha(linesOf(t, ms)),
		GzBytes: c.GzBytes, Reason: "recovered"}
	if c != want {
		t.Fatalf("recovered\n%+v\nwant\n%+v", c, want)
	}
	checkChunk(t, s.dir, c, linesOf(t, ms))
	if n := names(t, s.dir); !slices.Equal(n, []string{c.Name, c.Name + ".json"}) {
		t.Fatalf("files %v", n)
	}
	if h.count("sealed a chunk left open") != 1 {
		t.Fatalf("not logged:\n%s", h.all())
	}
	if got, err := s.Recover(t0); err != nil || len(got) != 0 {
		t.Fatalf("second Recover: %+v %v", got, err)
	}
	if got := entryTexts(queryAll(t, s)); !slices.Equal(got, reversed(ms)) {
		t.Fatalf("stored %v", got)
	}
}

func TestRecoverCutsIncompleteLine(t *testing.T) {
	dir := t.TempDir()
	ms := msgs(t0, 2, "m")
	partial := []byte(`{"rx":"2026-10-05T22:15:02.1234`)
	name := leaveOpen(t, dir, t0, append(linesOf(t, ms), partial...), nil)
	s, h := testStore(t, Options{Dir: dir})
	got, err := s.Recover(t0)
	if err != nil || len(got) != 1 || got[0].Messages != 2 {
		t.Fatalf("Recover: %+v %v", got, err)
	}
	checkChunk(t, dir, got[0], linesOf(t, ms))
	if h.count("cut off the incomplete last line") != 1 || h.attr("cut off", "bytes") != strconv.Itoa(len(partial)) ||
		h.attr("cut off", "file") != name {
		t.Fatalf("cut not logged with its size:\n%s", h.all())
	}
}

func TestRecoverOnlyIncompleteLine(t *testing.T) {
	dir := t.TempDir()
	leaveOpen(t, dir, t0, []byte(`{"rx":"2026-10-05T22`), nil)
	s, h := testStore(t, Options{Dir: dir})
	got, err := s.Recover(t0)
	if err != nil || len(got) != 0 {
		t.Fatalf("Recover: %+v %v", got, err)
	}
	if n := names(t, dir); len(n) != 0 {
		t.Fatalf("files %v", n)
	}
	if h.attr("cut off", "bytes") != "20" || h.count("deleted an empty chunk left open") != 1 {
		t.Fatalf("log:\n%s", h.all())
	}
}

// sealKeepingOpenFiles seals a chunk of ms (counts 2 and 1) normally and then puts its open
// chunk's files back, as they were when a crash interrupted the sealing before it deleted them.
func sealKeepingOpenFiles(t *testing.T, dir string, ms []model.SyslogMessage) (model.SyslogChunk, string) {
	t.Helper()
	s, _ := testStore(t, Options{Dir: dir})
	if _, err := s.Append(ms, 2, 1, t0); err != nil {
		t.Fatal(err)
	}
	open := openFiles(t, dir)[0]
	openBytes := readFile(t, filepath.Join(dir, open))
	stateBytes := readFile(t, filepath.Join(dir, stateName(open)))
	c, err := s.Seal(t0, "stop", true)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, open), openBytes)
	writeFile(t, filepath.Join(dir, stateName(open)), stateBytes)
	return *c, open
}

func TestRecoverInterruptedBeforeDeletingOpenFile(t *testing.T) {
	dir := t.TempDir()
	ms := msgs(t0, 3, "m")
	sealed, _ := sealKeepingOpenFiles(t, dir, ms)
	s, h := testStore(t, Options{Dir: dir})
	got, err := s.Recover(t0)
	// Sealing never returned the chunk: Recover returns it, as sealed, and does not seal again.
	if err != nil || len(got) != 1 || got[0] != sealed {
		t.Fatalf("Recover: %+v %v, want %+v", got, err, sealed)
	}
	if n := names(t, dir); !slices.Equal(n, []string{sealed.Name, sealed.Name + ".json"}) {
		t.Fatalf("files %v", n)
	}
	checkChunk(t, dir, sealed, linesOf(t, ms))
	if h.count("completed the sealing") != 1 {
		t.Fatalf("not logged:\n%s", h.all())
	}
}

func TestRecoverInterruptedBeforeSidecar(t *testing.T) {
	dir := t.TempDir()
	ms := msgs(t0, 3, "m")
	sealed, _ := sealKeepingOpenFiles(t, dir, ms)
	if err := removeFile(filepath.Join(dir, sealed.Name+sidecarExt)); err != nil {
		t.Fatal(err)
	}
	s, h := testStore(t, Options{Dir: dir})
	if h.count("sidecar file was missing; rebuilt") != 1 {
		t.Fatalf("rebuild not logged:\n%s", h.all())
	}
	got, err := s.Recover(t0)
	// The rebuilt sidecar knew neither the counts nor the reason: the state file has the counts.
	want := sealed
	want.Reason = "recovered"
	if err != nil || len(got) != 1 || got[0] != want {
		t.Fatalf("Recover: %+v %v, want %+v", got, err, want)
	}
	checkChunk(t, dir, want, linesOf(t, ms))
	if n := names(t, dir); !slices.Equal(n, []string{sealed.Name, sealed.Name + ".json"}) {
		t.Fatalf("files %v", n)
	}
}

func TestRecoverInterruptedWhileCompressing(t *testing.T) {
	dir := t.TempDir()
	ms := msgs(t0, 2, "m")
	leaveOpen(t, dir, t0, linesOf(t, ms), &openState{Rejected: 5})
	writeFile(t, filepath.Join(dir, sealTmp), []byte("half a gzip file"))
	s, h := testStore(t, Options{Dir: dir})
	got, err := s.Recover(t0)
	if err != nil || len(got) != 1 || got[0].Messages != 2 || got[0].Rejected != 5 || got[0].Reason != "recovered" {
		t.Fatalf("Recover: %+v %v", got, err)
	}
	checkChunk(t, dir, got[0], linesOf(t, ms))
	if n := names(t, dir); !slices.Equal(n, []string{got[0].Name, got[0].Name + ".json"}) {
		t.Fatalf("files %v", n)
	}
	if h.count("deleted a temporary file") != 1 {
		t.Fatalf("not logged:\n%s", h.all())
	}
}

func TestRecoverChunkSealedAlready(t *testing.T) {
	dir := t.TempDir()
	ms := msgs(t0, 3, "m")
	sealed, open := sealKeepingOpenFiles(t, dir, ms)
	// The previous run sealed and returned the chunk but could not delete the open file.
	if err := writeState(filepath.Join(dir, stateName(open)), openState{Sealed: sealed.Name}); err != nil {
		t.Fatal(err)
	}
	s, h := testStore(t, Options{Dir: dir})
	got, err := s.Recover(t0)
	if err != nil || len(got) != 0 {
		t.Fatalf("Recover: %+v %v", got, err)
	}
	if n := names(t, dir); !slices.Equal(n, []string{sealed.Name, sealed.Name + ".json"}) {
		t.Fatalf("files %v", n)
	}
	if h.count("sealed already") != 1 {
		t.Fatalf("not logged:\n%s", h.all())
	}
}

func TestRecoverChunkSealedAlreadyAndPruned(t *testing.T) {
	dir := t.TempDir()
	leaveOpen(t, dir, t0, linesOf(t, msgs(t0, 2, "m")), &openState{Sealed: sealedName(t0, t0.Add(time.Second), 1)})
	s, _ := testStore(t, Options{Dir: dir})
	got, err := s.Recover(t0)
	if err != nil || len(got) != 0 {
		t.Fatalf("Recover: %+v %v", got, err)
	}
	if n := names(t, dir); len(n) != 0 {
		t.Fatalf("files %v", n)
	}
}

func TestRecoverChunkSealedAlreadyButChanged(t *testing.T) {
	dir := t.TempDir()
	ms := msgs(t0, 3, "m")
	sealed, open := sealKeepingOpenFiles(t, dir, ms)
	if err := writeState(filepath.Join(dir, stateName(open)), openState{Sealed: sealed.Name}); err != nil {
		t.Fatal(err)
	}
	// Someone added a line to the file after it was sealed: it is kept, not deleted.
	extra := lineOf(t, msg(t0.Add(time.Minute), "added"))
	writeFile(t, filepath.Join(dir, open), append(linesOf(t, ms), extra...))
	s, h := testStore(t, Options{Dir: dir})
	got, err := s.Recover(t0)
	if err != nil || len(got) != 1 || got[0].Messages != 4 || got[0].Reason != "recovered" {
		t.Fatalf("Recover: %+v %v", got, err)
	}
	if h.count("differs from the chunk it was sealed into") != 1 {
		t.Fatalf("not logged:\n%s", h.all())
	}
	if len(sealedFiles(t, dir)) != 2 || len(openFiles(t, dir)) != 0 {
		t.Fatalf("files %v", names(t, dir))
	}
}

func TestRecoverCountsOnlyChunk(t *testing.T) {
	dir := t.TempDir()
	leaveOpen(t, dir, t0, nil, &openState{Dropped: 4})
	s, _ := testStore(t, Options{Dir: dir})
	got, err := s.Recover(t0.Add(time.Hour))
	if err != nil || len(got) != 1 {
		t.Fatalf("Recover: %+v %v", got, err)
	}
	c := got[0]
	if c.Messages != 0 || c.Dropped != 4 || c.From != formatRX(t0) || c.To != formatRX(t0) ||
		c.Name != sealedName(t0, t0, 1) || c.SHA256 != sha(nil) {
		t.Fatalf("recovered %+v", c)
	}
}

func TestRecoverEmptyChunk(t *testing.T) {
	dir := t.TempDir()
	leaveOpen(t, dir, t0, nil, nil)
	s, _ := testStore(t, Options{Dir: dir})
	if got, err := s.Recover(t0); err != nil || len(got) != 0 {
		t.Fatalf("Recover: %+v %v", got, err)
	}
	if n := names(t, dir); len(n) != 0 {
		t.Fatalf("files %v", n)
	}
}

func TestRecoverDamagedStateFile(t *testing.T) {
	dir := t.TempDir()
	ms := msgs(t0, 1, "m")
	name := leaveOpen(t, dir, t0, linesOf(t, ms), nil)
	writeFile(t, filepath.Join(dir, stateName(name)), []byte("{not json"))
	s, h := testStore(t, Options{Dir: dir})
	got, err := s.Recover(t0)
	if err != nil || len(got) != 1 || got[0].Messages != 1 || got[0].Dropped != 0 {
		t.Fatalf("Recover: %+v %v", got, err)
	}
	if h.count("its counts are lost") != 1 {
		t.Fatalf("not logged:\n%s", h.all())
	}
	if n := names(t, dir); len(n) != 2 {
		t.Fatalf("files %v", n)
	}
}

func TestRecoverLeftovers(t *testing.T) {
	dir := t.TempDir()
	// A state file whose chunk was deleted, a sidecar whose chunk was deleted, temporary files,
	// and a file the store does not know.
	gone := sealedName(t0, t0, 1)
	writeFile(t, filepath.Join(dir, stateName(openName(t0, 1))), []byte(`{"dropped":1}`))
	writeFile(t, filepath.Join(dir, gone+sidecarExt), []byte(`{}`))
	writeFile(t, filepath.Join(dir, gone+sidecarExt+tmpExt), []byte(`{`))
	writeFile(t, filepath.Join(dir, sealTmp), []byte(`x`))
	writeFile(t, filepath.Join(dir, "notes.txt"), []byte(`mine`))
	s, _ := testStore(t, Options{Dir: dir})
	if got, err := s.Recover(t0); err != nil || len(got) != 0 {
		t.Fatalf("Recover: %+v %v", got, err)
	}
	if n := names(t, dir); !slices.Equal(n, []string{"notes.txt"}) {
		t.Fatalf("files %v", n)
	}
}

func TestRecoverOldestFirstAndKeepsCurrentChunk(t *testing.T) {
	dir := t.TempDir()
	a, b := msgs(t0, 2, "a"), msgs(t0.Add(time.Hour), 2, "b")
	leaveOpen(t, dir, t0.Add(time.Hour), linesOf(t, b), nil)
	leaveOpen(t, dir, t0, linesOf(t, a), nil)
	s, _ := testStore(t, Options{Dir: dir})
	// A chunk opened by this run (Append before Recover) is not touched.
	cur := msgs(t0.Add(2*time.Hour), 1, "c")
	if _, err := s.Append(cur, 0, 0, t0.Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	got, err := s.Recover(t0)
	if err != nil || len(got) != 2 || got[0].From != a[0].RX || got[1].From != b[0].RX {
		t.Fatalf("Recover: %+v %v", got, err)
	}
	if opens := openFiles(t, dir); !slices.Equal(opens, []string{openName(t0.Add(2*time.Hour), 1)}) {
		t.Fatalf("open files %v", opens)
	}
	if got := entryTexts(queryAll(t, s)); !slices.Equal(got, append(append(reversed(cur), reversed(b)...), reversed(a)...)) {
		t.Fatalf("stored %v", got)
	}
}

func TestRecoverDamagedLine(t *testing.T) {
	// A complete line that is not a message (damage, or an edit) is kept as it is: the chunk
	// holds exactly what the file held.
	dir := t.TempDir()
	ms := msgs(t0, 2, "m")
	content := append(append(lineOf(t, ms[0]), "garbage\n"...), lineOf(t, ms[1])...)
	leaveOpen(t, dir, t0, content, nil)
	s, h := testStore(t, Options{Dir: dir})
	got, err := s.Recover(t0)
	if err != nil || len(got) != 1 || got[0].Messages != 3 {
		t.Fatalf("Recover: %+v %v", got, err)
	}
	checkChunk(t, dir, got[0], content)
	// Query skips the line and says so once.
	for range 2 {
		if es := queryAll(t, s); !slices.Equal(entryTexts(es), reversed(ms)) {
			t.Fatalf("Query: %v", entryTexts(es))
		}
	}
	if h.count("lines of a chunk that cannot be read were skipped") != 1 || h.attr("were skipped", "lines") != "1" {
		t.Fatalf("log:\n%s", h.all())
	}
	if !bytes.Equal(content, gunzip(t, readFile(t, filepath.Join(dir, got[0].Name)))) {
		t.Fatal("content changed")
	}
}
