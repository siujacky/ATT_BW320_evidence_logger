package syslogstore

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"attmonitor/internal/config"
	"attmonitor/internal/contracts"
	"attmonitor/internal/model"
)

// fill appends ms to s in batches of per messages, sealing after each batch, and returns the
// sealed chunks.
func fill(t *testing.T, s *Store, ms []model.SyslogMessage, per int) []model.SyslogChunk {
	t.Helper()
	var out []model.SyslogChunk
	for i := 0; i < len(ms); i += per {
		batch := ms[i:min(i+per, len(ms))]
		sealed, err := s.Append(batch, 0, 0, t0)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, sealed...)
		c, err := s.Seal(t0, "stop", true)
		if err != nil {
			t.Fatal(err)
		}
		if c != nil {
			out = append(out, *c)
		}
	}
	return out
}

func TestNewOptions(t *testing.T) {
	if _, err := New(Options{}); err == nil {
		t.Fatal("New without Dir succeeded")
	}
	dir := filepath.Join(t.TempDir(), "data", "syslog")
	s, _ := testStore(t, Options{Dir: dir})
	if st, err := os.Stat(dir); err != nil || !st.IsDir() {
		t.Fatalf("Dir not created: %v", err)
	}
	if s.o.ChunkBytes != DefaultChunkBytes || s.o.ChunkAge != DefaultChunkAge {
		t.Fatalf("defaults: %d %v", s.o.ChunkBytes, s.o.ChunkAge)
	}
	if u := s.Usage(); u.KeepMB != DefaultKeepMB || u.KeepDays != 0 || u.Bytes != 0 || u.Chunks != 0 {
		t.Fatalf("Usage: %+v", u)
	}
	s2, _ := testStore(t, Options{KeepMB: -5, KeepDays: -1})
	if u := s2.Usage(); u.KeepMB != config.MinSyslogKeepMB || u.KeepDays != 0 {
		t.Fatalf("clamped: %+v", u)
	}
}

func TestSetRetention(t *testing.T) {
	s, _ := testStore(t, Options{KeepMB: 50, KeepDays: 7})
	if u := s.Usage(); u.KeepMB != 50 || u.KeepDays != 7 {
		t.Fatalf("Usage: %+v", u)
	}
	for _, c := range []struct{ mb, days, wantMB, wantDays int }{
		{200, 30, 200, 30},
		{0, 0, config.MinSyslogKeepMB, 0},
		{-1, -1, config.MinSyslogKeepMB, 0},
		{config.MaxSyslogKeepMB + 1, config.MaxSyslogKeepDays + 1, config.MaxSyslogKeepMB, config.MaxSyslogKeepDays},
	} {
		s.SetRetention(c.mb, c.days)
		if u := s.Usage(); u.KeepMB != c.wantMB || u.KeepDays != c.wantDays {
			t.Fatalf("SetRetention(%d, %d): %+v", c.mb, c.days, u)
		}
	}
}

func TestReopenIndexesSealedChunks(t *testing.T) {
	s, _ := testStore(t, Options{})
	ms := msgs(t0, 9, "m")
	chunks := fill(t, s, ms, 3)
	if len(chunks) != 3 {
		t.Fatalf("sealed %d chunks", len(chunks))
	}
	more := msgs(t0.Add(time.Hour), 2, "n")
	if _, err := s.Append(more, 0, 0, t0); err != nil {
		t.Fatal(err)
	}
	before := s.Usage()
	sidecars := map[string][]byte{}
	for _, c := range chunks {
		sidecars[c.Name] = readFile(t, filepath.Join(s.dir, c.Name+sidecarExt))
	}
	s, h := reopen(t, s, Options{})
	// Before Recover, the chunk left open is not counted; Recover seals it.
	u := s.Usage()
	if u.Chunks != 3 || u.Messages != 9 || u.Bytes != before.Bytes-int64(len(linesOf(t, more))) ||
		u.Oldest != ms[0].RX || u.Newest != ms[8].RX {
		t.Fatalf("Usage after reopening: %+v (before %+v)", u, before)
	}
	for _, c := range chunks {
		if !bytes.Equal(readFile(t, filepath.Join(s.dir, c.Name+sidecarExt)), sidecars[c.Name]) {
			t.Fatalf("sidecar of %s rewritten", c.Name)
		}
		checkChunk(t, s.dir, c, content(t, s.dir, c.Name))
	}
	if h.count("sidecar") != 0 {
		t.Fatalf("log:\n%s", h.all())
	}
	if got := s.Chunks(); !slices.Equal(got, refsOf(chunks)) {
		t.Fatalf("Chunks\n%+v\nwant\n%+v", got, chunks)
	}
	recovered, err := s.Recover(t0)
	if err != nil || len(recovered) != 1 {
		t.Fatalf("Recover: %+v %v", recovered, err)
	}
	if got := s.Chunks(); !slices.Equal(got, refsOf(append(chunks, recovered[0]))) {
		t.Fatalf("Chunks after Recover: %+v", got)
	}
	if got := entryTexts(queryAll(t, s)); !slices.Equal(got, append(reversed(more), reversed(ms)...)) {
		t.Fatalf("stored %v", got)
	}
}

func TestSidecarRebuilt(t *testing.T) {
	for _, damage := range []struct {
		name string
		do   func(path string, sc []byte) []byte // returns the new content (nil: delete)
		log  string
	}{
		{"missing", func(string, []byte) []byte { return nil }, "missing"},
		{"not json", func(string, []byte) []byte { return []byte("{") }, "damaged"},
		{"another chunk", func(_ string, sc []byte) []byte {
			return bytes.Replace(sc, []byte(`"name":"syslog-`), []byte(`"name":"syslog-x`), 1)
		}, "about another chunk"},
		{"other size", func(_ string, sc []byte) []byte {
			return bytes.Replace(sc, []byte(`"gz_bytes":`), []byte(`"gz_bytes":1`), 1)
		}, "not about the chunk file as it is"},
		{"bad sha", func(_ string, sc []byte) []byte {
			return bytes.Replace(sc, []byte(`"sha256":"`), []byte(`"sha256":"X`), 1)
		}, "damaged"},
	} {
		t.Run(damage.name, func(t *testing.T) {
			s, _ := testStore(t, Options{})
			ms := msgs(t0, 3, "m")
			if _, err := s.Append(ms, 2, 1, t0); err != nil {
				t.Fatal(err)
			}
			c, err := s.Seal(t0, "stop", true)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(s.dir, c.Name+sidecarExt)
			if b := damage.do(path, readFile(t, path)); b == nil {
				os.Remove(path)
			} else {
				writeFile(t, path, b)
			}
			s, h := reopen(t, s, Options{})
			if h.count("sidecar file was "+damage.log) != 1 {
				t.Fatalf("not logged:\n%s", h.all())
			}
			// Described from the file: the counts and the reason are the record's to tell.
			want := *c
			want.Dropped, want.Rejected, want.Reason = 0, 0, "recovered"
			checkChunk(t, s.dir, want, linesOf(t, ms))
			if u := s.Usage(); u.Chunks != 1 || u.Messages != 3 || u.Bytes != c.GzBytes {
				t.Fatalf("Usage: %+v", u)
			}
			if got := entryTexts(queryAll(t, s)); !slices.Equal(got, reversed(ms)) {
				t.Fatalf("stored %v", got)
			}
			// Rebuilt once: the next start finds it in order.
			_, h = reopen(t, s, Options{})
			if h.count("sidecar") != 0 {
				t.Fatalf("log:\n%s", h.all())
			}
		})
	}
}

func TestSidecarRebuiltKeepsReceiveRange(t *testing.T) {
	// The clock was set back while the chunk was open: its first message is not its earliest.
	s, _ := testStore(t, Options{})
	ms := []model.SyslogMessage{msg(t0, "a"), msg(t0.Add(-time.Hour), "b"), msg(t0.Add(time.Minute), "c")}
	if _, err := s.Append(ms, 0, 0, t0); err != nil {
		t.Fatal(err)
	}
	c, err := s.Seal(t0, "stop", true)
	if err != nil {
		t.Fatal(err)
	}
	if c.From != ms[0].RX || c.To != ms[2].RX {
		t.Fatalf("From/To %s %s", c.From, c.To)
	}
	sc := readSidecarFile(t, s.dir, c.Name)
	if sc.RXMin != ms[1].RX || sc.RXMax != ms[2].RX {
		t.Fatalf("sidecar range %s - %s", sc.RXMin, sc.RXMax)
	}
	os.Remove(filepath.Join(s.dir, c.Name+sidecarExt))
	s, _ = reopen(t, s, Options{})
	if sc := readSidecarFile(t, s.dir, c.Name); sc.RXMin != ms[1].RX || sc.RXMax != ms[2].RX {
		t.Fatalf("rebuilt range %s - %s", sc.RXMin, sc.RXMax)
	}
	if u := s.Usage(); u.Oldest != ms[1].RX || u.Newest != ms[2].RX {
		t.Fatalf("Usage: %+v", u)
	}
}

func TestUnreadableChunkLeftAlone(t *testing.T) {
	s, _ := testStore(t, Options{KeepMB: 1})
	ms := msgs(t0, 2, "m")
	if _, err := s.Append(ms, 0, 0, t0); err != nil {
		t.Fatal(err)
	}
	good, err := s.Seal(t0, "stop", true)
	if err != nil {
		t.Fatal(err)
	}
	// Two chunk files without sidecars that cannot be read: not gzip, and gzip cut short.
	bad1 := sealedName(t0.Add(-2*time.Hour), t0.Add(-2*time.Hour), 1)
	bad2 := sealedName(t0.Add(-time.Hour), t0.Add(-time.Hour), 1)
	writeFile(t, filepath.Join(s.dir, bad1), bytes.Repeat([]byte("garbage "), 100))
	gz := gzipBytes(t, bytes.Repeat(linesOf(t, ms), 50))
	writeFile(t, filepath.Join(s.dir, bad2), gz[:len(gz)/2])
	s, h := reopen(t, s, Options{KeepMB: 1})
	if h.count("cannot be read; it is left as it is and not counted as kept") != 2 {
		t.Fatalf("not logged:\n%s", h.all())
	}
	if u := s.Usage(); u.Chunks != 1 || u.Bytes != good.GzBytes || u.Messages != 2 {
		t.Fatalf("Usage: %+v", u)
	}
	for _, name := range []string{bad1, bad2} {
		if _, err := s.OpenChunk(name); !errors.Is(err, contracts.ErrNotFound) {
			t.Fatalf("OpenChunk(%s): %v", name, err)
		}
	}
	// Neither Recover nor Prune touches them; no sidecar is written for them.
	if _, err := s.Recover(t0); err != nil {
		t.Fatal(err)
	}
	if refs, err := s.Prune(t0.Add(1000 * 24 * time.Hour)); err != nil || len(refs) != 0 {
		// KeepDays is 0: only the size limit applies, and it is not reached.
		t.Fatalf("Prune: %+v %v", refs, err)
	}
	s.SetRetention(1, 1)
	refs, err := s.Prune(t0.Add(1000 * 24 * time.Hour))
	if err != nil || len(refs) != 1 || refs[0].Name != good.Name {
		t.Fatalf("Prune by age: %+v %v", refs, err)
	}
	if n := names(t, s.dir); !slices.Equal(n, []string{bad1, bad2}) {
		t.Fatalf("files %v", n)
	}
	if b := readFile(t, filepath.Join(s.dir, bad2)); !bytes.Equal(b, gz[:len(gz)/2]) {
		t.Fatal("an unreadable chunk was changed")
	}
}

// dirState is every file of a directory with its size, time and content.
func dirState(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		info, err := e.Info()
		if err != nil {
			t.Fatal(err)
		}
		out[e.Name()] = info.ModTime().String() + " " + sha(readFile(t, filepath.Join(dir, e.Name())))
	}
	return out
}

func TestReadOnly(t *testing.T) {
	w, _ := testStore(t, Options{})
	ms := msgs(t0, 6, "m")
	chunks := fill(t, w, ms[:4], 2)
	// One sidecar is missing, a temporary file is left over, and a chunk is open (the writer
	// keeps running).
	os.Remove(filepath.Join(w.dir, chunks[0].Name+sidecarExt))
	writeFile(t, filepath.Join(w.dir, sealTmp), []byte("x"))
	if _, err := w.Append(ms[4:], 0, 0, t0); err != nil {
		t.Fatal(err)
	}
	before := dirState(t, w.dir)

	h := &captureHandler{}
	ro, err := New(Options{Dir: w.dir, ReadOnly: true, Logger: slogFor(h)})
	if err != nil {
		t.Fatal(err)
	}
	if h.count("read-only: not written") != 1 {
		t.Fatalf("log:\n%s", h.all())
	}
	if u := ro.Usage(); u.Chunks != 2 || u.Messages != 6 || u.OpenMessages != 2 || u.Oldest != ms[0].RX || u.Newest != ms[5].RX {
		t.Fatalf("Usage: %+v", u)
	}
	es := queryAll(t, ro)
	if got := entryTexts(es); !slices.Equal(got, reversed(ms)) {
		t.Fatalf("Query: %v", got)
	}
	if es[0].Chunk != "" || es[2].Chunk != chunks[1].Name || es[5].Chunk != chunks[0].Name {
		t.Fatalf("chunks named %q %q %q", es[0].Chunk, es[2].Chunk, es[5].Chunk)
	}
	r, err := ro.OpenChunk(chunks[0].Name)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(r)
	r.Close()
	if !bytes.Equal(b, readFile(t, filepath.Join(w.dir, chunks[0].Name))) {
		t.Fatal("OpenChunk returned other bytes")
	}
	for name, err := range map[string]error{
		"Recover": func() error { _, err := ro.Recover(t0); return err }(),
		"Append":  func() error { _, err := ro.Append(ms, 1, 1, t0); return err }(),
		"Seal":    func() error { _, err := ro.Seal(t0, "stop", true); return err }(),
		"Prune":   func() error { _, err := ro.Prune(t0.Add(1000 * time.Hour)); return err }(),
	} {
		if !errors.Is(err, ErrReadOnly) {
			t.Errorf("%s on a read-only store: %v", name, err)
		}
	}
	ro.SetRetention(1, 1) // in memory only
	if u := ro.Usage(); u.KeepMB != 1 || u.KeepDays != 1 {
		t.Fatalf("Usage: %+v", u)
	}
	if err := ro.Close(); err != nil {
		t.Fatal(err)
	}
	if after := dirState(t, w.dir); !mapsEqual(before, after) {
		t.Fatalf("the read-only store changed the directory:\nbefore %v\nafter  %v", before, after)
	}

	// The writer's open chunk is read as it grows.
	more := msgs(t0.Add(time.Minute), 1, "n")
	if _, err := w.Append(more, 0, 0, t0); err != nil {
		t.Fatal(err)
	}
	if got := entryTexts(queryAll(t, ro)); !slices.Equal(got, append(reversed(more), reversed(ms)...)) {
		t.Fatalf("Query: %v", got)
	}
	// Once the writer seals it, its messages are in a chunk the read-only store does not know.
	if _, err := w.Seal(t0, "stop", true); err != nil {
		t.Fatal(err)
	}
	if got := entryTexts(queryAll(t, ro)); !slices.Equal(got, reversed(ms[:4])) {
		t.Fatalf("Query after the writer sealed: %v", got)
	}

	// A read-only store needs its directory and creates nothing.
	missing := filepath.Join(t.TempDir(), "none")
	if _, err := New(Options{Dir: missing, ReadOnly: true}); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("New on a missing directory: %v", err)
	}
	if _, err := os.Stat(missing); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the directory was created")
	}
}

func mapsEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

func TestUsageCountsOpenAndSealed(t *testing.T) {
	s, _ := testStore(t, Options{KeepMB: 7, KeepDays: 3})
	ms := msgs(t0, 5, "m")
	chunks := fill(t, s, ms[:3], 3)
	if _, err := s.Append(ms[3:], 0, 0, t0); err != nil {
		t.Fatal(err)
	}
	want := model.SyslogUsage{Bytes: chunks[0].GzBytes + int64(len(linesOf(t, ms[3:]))), Chunks: 1, Messages: 5,
		OpenMessages: 2, Oldest: ms[0].RX, Newest: ms[4].RX, KeepMB: 7, KeepDays: 3}
	if u := s.Usage(); u != want {
		t.Fatalf("Usage\n%+v\nwant\n%+v", u, want)
	}
}

func TestUsageDoesNotWaitForReaders(t *testing.T) {
	// Usage takes no lock held across file I/O: it answers while a reader holds the open chunk.
	s, _ := testStore(t, Options{})
	if _, err := s.Append(msgs(t0, 3, "m"), 0, 0, t0); err != nil {
		t.Fatal(err)
	}
	s.wmu.RLock()
	done := make(chan model.SyslogUsage)
	go func() { done <- s.Usage() }()
	select {
	case u := <-done:
		if u.OpenMessages != 3 {
			t.Errorf("Usage: %+v", u)
		}
	case <-time.After(5 * time.Second):
		t.Error("Usage waited for the open chunk's lock")
	}
	s.wmu.RUnlock()
}
