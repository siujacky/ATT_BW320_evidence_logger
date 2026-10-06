//go:build windows

package syslogstore

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func TestOpenChunkFileProtected(t *testing.T) {
	s, _ := testStore(t, Options{})
	ms := msgs(t0, 2, "m")
	if _, err := s.Append(ms, 0, 0, t0); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(s.dir, openFiles(t, s.dir)[0])
	// Others may read the open chunk, but not change, rename or delete it.
	if b, err := os.ReadFile(path); err != nil || !bytes.Equal(b, linesOf(t, ms)) {
		t.Fatalf("read: %v", err)
	}
	if f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0); err == nil {
		f.Close()
		t.Fatal("opened for writing")
	}
	if err := os.Remove(path); err == nil {
		t.Fatal("deleted")
	}
	if err := os.Rename(path, path+".x"); err == nil {
		t.Fatal("renamed")
	}
}

func TestPruneRetriesChunkHeldByAnotherProgram(t *testing.T) {
	s, h := testStore(t, Options{KeepDays: 1})
	chunks := fill(t, s, msgs(t0, 6, "m"), 2)
	// Another program reads the oldest chunk without letting it be deleted.
	f, err := os.Open(filepath.Join(s.dir, chunks[0].Name))
	if err != nil {
		t.Fatal(err)
	}
	later := t0.Add(48 * time.Hour)
	refs, err := s.Prune(later)
	if err != nil || !slices.Equal(refs, refsOf(chunks[1:])) {
		f.Close()
		t.Fatalf("Prune: %+v %v", refs, err)
	}
	if h.count("is in use; it is deleted later") != 1 {
		t.Fatalf("not logged:\n%s", h.all())
	}
	// It is kept as it was, and still counts.
	if u := s.Usage(); u.Chunks != 1 || u.Bytes != chunks[0].GzBytes {
		t.Fatalf("Usage: %+v", u)
	}
	checkChunk(t, s.dir, chunks[0], linesOf(t, msgs(t0, 2, "m")))
	f.Close()
	refs, err = s.Prune(later)
	if err != nil || !slices.Equal(refs, refsOf(chunks[:1])) {
		t.Fatalf("Prune after release: %+v %v", refs, err)
	}
	if n := names(t, s.dir); len(n) != 0 {
		t.Fatalf("files %v", n)
	}
}

func TestPruneRetriesSidecarHeldByAnotherProgram(t *testing.T) {
	s, h := testStore(t, Options{KeepDays: 1})
	chunks := fill(t, s, msgs(t0, 2, "m"), 2)
	f, err := os.Open(filepath.Join(s.dir, chunks[0].Name+sidecarExt))
	if err != nil {
		t.Fatal(err)
	}
	refs, err := s.Prune(t0.Add(48 * time.Hour))
	f.Close()
	// The chunk is gone: it is reported; its sidecar goes with the next writing call.
	if err != nil || !slices.Equal(refs, refsOf(chunks)) {
		t.Fatalf("Prune: %+v %v", refs, err)
	}
	if h.count("sidecar file is in use") != 1 {
		t.Fatalf("not logged:\n%s", h.all())
	}
	if n := names(t, s.dir); !slices.Equal(n, []string{chunks[0].Name + sidecarExt}) {
		t.Fatalf("files %v", n)
	}
	if _, err := s.Seal(t0, "stop", true); err != nil {
		t.Fatal(err)
	}
	if n := names(t, s.dir); len(n) != 0 {
		t.Fatalf("files %v", n)
	}
}

// A chunk whose deletion is on record (CommitPrune) leaves the store although another program
// holds its file; the file, and then its sidecar, are deleted once it lets go.
func TestCommitPruneWithAChunkHeldByAnotherProgram(t *testing.T) {
	s, h := testStore(t, Options{KeepDays: 1})
	chunks := fill(t, s, msgs(t0, 4, "m"), 2)
	held := filepath.Join(s.dir, chunks[0].Name)
	f, err := os.Open(held)
	if err != nil {
		t.Fatal(err)
	}
	later := t0.Add(48 * time.Hour)
	if plan, err := s.PlanPrune(later); err != nil || !slices.Equal(plan, refsOf(chunks)) {
		f.Close()
		t.Fatalf("PlanPrune: %+v %v", plan, err)
	}
	deleted, err := s.CommitPrune()
	if err == nil || !slices.Equal(deleted, refsOf(chunks)) {
		f.Close()
		t.Fatalf("CommitPrune: %+v %v", deleted, err)
	}
	if h.count("a deleted chunk's file is in use") != 1 {
		t.Fatalf("not logged:\n%s", h.all())
	}
	if u := s.Usage(); u.Chunks != 0 || u.Bytes != 0 {
		t.Fatalf("Usage: %+v", u)
	}
	if _, err := s.OpenChunk(chunks[0].Name); err == nil {
		t.Fatal("the deleted chunk can still be opened")
	}
	// Still held: the file and its sidecar stay, also through a retry.
	if _, err := s.Seal(later, "", false); err != nil {
		t.Fatal(err)
	}
	if n := names(t, s.dir); !slices.Equal(n, []string{chunks[0].Name, chunks[0].Name + sidecarExt}) {
		f.Close()
		t.Fatalf("files while held: %v", n)
	}
	f.Close()
	if _, err := s.Seal(later, "", false); err != nil {
		t.Fatal(err)
	}
	if n := names(t, s.dir); len(n) != 0 {
		t.Fatalf("files after release: %v", n)
	}
}

func TestSealOpenFileHeldByAnotherProgram(t *testing.T) {
	s, h := testStore(t, Options{})
	ms := msgs(t0, 3, "m")
	if _, err := s.Append(ms, 1, 0, t0); err != nil {
		t.Fatal(err)
	}
	open := openFiles(t, s.dir)[0]
	f, err := os.Open(filepath.Join(s.dir, open))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	c, err := s.Seal(t0, "stop", true)
	if err != nil || c == nil || c.Messages != 3 {
		t.Fatalf("Seal: %+v %v", c, err)
	}
	if h.count("open file is in use and is deleted later") != 1 {
		t.Fatalf("not logged:\n%s", h.all())
	}
	// The file stays; its state file says what it was sealed into.
	st, err := readState(filepath.Join(s.dir, stateName(open)))
	if err != nil || st.Sealed != c.Name {
		t.Fatalf("state %+v %v", st, err)
	}
	// The program still holds it: the next call cannot delete it either.
	more := msgs(t0.Add(time.Minute), 1, "n")
	if _, err := s.Append(more, 0, 0, t0); err != nil {
		t.Fatal(err)
	}
	if len(openFiles(t, s.dir)) != 2 {
		t.Fatalf("files %v", names(t, s.dir))
	}
	// Its messages are not shown twice.
	if got := entryTexts(queryAll(t, s)); !slices.Equal(got, append(reversed(more), reversed(ms)...)) {
		t.Fatalf("Query: %v", got)
	}

	// The service stops (a crash) before it could delete the file; at the next start, the
	// chunk is not sealed or returned again.
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	f.Close()
	s2, h2 := testStore(t, Options{Dir: s.dir})
	got, err := s2.Recover(t0)
	if err != nil || len(got) != 1 || got[0].From != more[0].RX {
		t.Fatalf("Recover: %+v %v", got, err)
	}
	if h2.count("sealed already") != 1 {
		t.Fatalf("not logged:\n%s", h2.all())
	}
	if sealed := sealedFiles(t, s.dir); len(sealed) != 2 || len(openFiles(t, s.dir)) != 0 {
		t.Fatalf("files %v", names(t, s.dir))
	}
}

func TestSealDeletesHeldOpenFileLater(t *testing.T) {
	s, h := testStore(t, Options{})
	if _, err := s.Append(msgs(t0, 2, "m"), 0, 0, t0); err != nil {
		t.Fatal(err)
	}
	open := openFiles(t, s.dir)[0]
	f, err := os.Open(filepath.Join(s.dir, open))
	if err != nil {
		t.Fatal(err)
	}
	c, err := s.Seal(t0, "stop", true)
	f.Close()
	if err != nil || c == nil {
		t.Fatalf("Seal: %v %v", c, err)
	}
	// The next writing call deletes the file and then its state file.
	if _, err := s.Prune(t0); err != nil {
		t.Fatal(err)
	}
	if n := names(t, s.dir); !slices.Equal(n, []string{c.Name, c.Name + sidecarExt}) {
		t.Fatalf("files %v", n)
	}
	if h.count("deleted a file that was in use before") != 2 {
		t.Fatalf("log:\n%s", h.all())
	}
}

func TestReaderInAnotherProcessDoesNotBlockPrune(t *testing.T) {
	w, _ := testStore(t, Options{KeepDays: 1})
	chunks := fill(t, w, msgs(t0, 2, "m"), 2)
	ro, err := New(Options{Dir: w.dir, ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	r, err := ro.OpenChunk(chunks[0].Name)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	// The writer deletes the chunk while the reader has it open; the reader still gets it all.
	refs, err := w.Prune(t0.Add(48 * time.Hour))
	if err != nil || len(refs) != 1 {
		t.Fatalf("Prune: %+v %v", refs, err)
	}
	b, err := io.ReadAll(r)
	if err != nil || int64(len(b)) != chunks[0].GzBytes || sha(gunzip(t, b)) != chunks[0].SHA256 {
		t.Fatalf("read after the deletion: %d bytes, %v", len(b), err)
	}
}

func TestRecoverRetriesLeftoverHeldByAnotherProgram(t *testing.T) {
	dir := t.TempDir()
	orphan := sealedName(t0, t0, 1) + sidecarExt // the sidecar of a deleted chunk
	writeFile(t, filepath.Join(dir, orphan), []byte(`{}`))
	f, err := os.Open(filepath.Join(dir, orphan))
	if err != nil {
		t.Fatal(err)
	}
	s, h := testStore(t, Options{Dir: dir})
	got, err := s.Recover(t0)
	f.Close()
	if err != nil || len(got) != 0 {
		t.Fatalf("Recover: %+v %v", got, err)
	}
	if h.count("could not delete the sidecar of a deleted chunk; trying again later") != 1 {
		t.Fatalf("not logged:\n%s", h.all())
	}
	if _, err := s.Prune(t0); err != nil {
		t.Fatal(err)
	}
	if n := names(t, dir); len(n) != 0 {
		t.Fatalf("files %v", n)
	}
}

// A chunk left open that another program holds cannot be recovered at the start; Recover, called
// again (the monitor does at every flush), seals it once it is free, and leaves alone the chunk
// this run opened meanwhile.
func TestRecoverAgainAfterALeftoverWasHeld(t *testing.T) {
	dir := t.TempDir()
	left := msgs(t0, 2, "left")
	name := leaveOpen(t, dir, t0, linesOf(t, left), nil)
	p, err := windows.UTF16PtrFromString(filepath.Join(dir, name))
	if err != nil {
		t.Fatal(err)
	}
	// Another program reads it without letting anyone write it.
	held, err := windows.CreateFile(p, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatal(err)
	}
	s, _ := testStore(t, Options{Dir: dir})
	if got, err := s.Recover(t0); err == nil || len(got) != 0 {
		windows.CloseHandle(held)
		t.Fatalf("Recover while the leftover is held: %+v %v", got, err)
	}
	now := msgs(t0.Add(time.Hour), 1, "now")
	if _, err := s.Append(now, 0, 0, t0.Add(time.Hour)); err != nil {
		windows.CloseHandle(held)
		t.Fatal(err)
	}
	windows.CloseHandle(held)
	got, err := s.Recover(t0.Add(time.Hour))
	if err != nil || len(got) != 1 || got[0].Messages != 2 || got[0].Reason != "recovered" {
		t.Fatalf("Recover once free: %+v %v", got, err)
	}
	checkChunk(t, dir, got[0], linesOf(t, left))
	if u := s.Usage(); u.OpenMessages != 1 || u.Chunks != 1 {
		t.Fatalf("Usage: %+v", u)
	}
	if es := queryAll(t, s); !slices.Equal(entryTexts(es), []string{"now-0", "left-1", "left-0"}) {
		t.Fatalf("messages %v", entryTexts(es))
	}
}
