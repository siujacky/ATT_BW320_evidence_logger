package ledger

// Integration round: Record(seq) used to re-read its segment from the start on every call. It now
// uses a bounded per-segment line-offset index. Correctness comes first: whatever the index says
// is re-checked against the bytes read, and any doubt falls back to the scan.

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"math/rand/v2"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"attmonitor/internal/contracts"
	"attmonitor/internal/model"
)

// scanEnvs returns every record (envelope and body) via Scan(0).
func scanEnvs(t *testing.T, r contracts.LedgerReader) ([]model.Envelope, []model.Body) {
	t.Helper()
	var envs []model.Envelope
	var bodies []model.Body
	if err := r.Scan(0, func(env model.Envelope, b model.Body) error {
		envs = append(envs, env)
		bodies = append(bodies, b)
		return nil
	}); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	return envs, bodies
}

// requireRecordsMatchScan checks Record(seq) against Scan for every record (newest first, so
// that several segments compete for the cache) and that seq head+1 is absent.
func requireRecordsMatchScan(t *testing.T, s *Store) {
	t.Helper()
	envs, bodies := scanEnvs(t, s)
	for i := len(bodies) - 1; i >= 0; i-- {
		env, body, err := s.Record(bodies[i].Seq)
		if err != nil || env != envs[i] || body.Seq != bodies[i].Seq || body.TS != bodies[i].TS ||
			body.Type != bodies[i].Type || !bytes.Equal(body.Data, bodies[i].Data) {
			t.Fatalf("Record(%d) = %+v, %v; Scan has %+v", bodies[i].Seq, body, err, bodies[i])
		}
	}
	if _, _, err := s.Record(bodies[len(bodies)-1].Seq + 1); !errors.Is(err, contracts.ErrNotFound) {
		t.Fatalf("Record beyond the head: %v", err)
	}
}

func indexStats(s *Store) (builds, extends, stale int64) {
	return s.idx.builds.Load(), s.idx.extends.Load(), s.idx.stale.Load()
}

func TestRecordIndexMatchesScan(t *testing.T) {
	s, dir, clk, _ := fiveDayLedger(t)
	if n, err := s.CompressSealed(48 * time.Hour); err != nil || n != 2 {
		t.Fatalf("CompressSealed = %d, %v", n, err)
	}
	opts := testOptions(dir, clk)
	opts.ReadOnly = true
	ro := openStore(t, opts)
	for name, st := range map[string]*Store{"writer": s, "read-only": ro} {
		t.Run(name, func(t *testing.T) {
			for round := 0; round < 2; round++ {
				requireRecordsMatchScan(t, st)
			}
			st.idx.mu.Lock()
			n := len(st.idx.entries)
			st.idx.mu.Unlock()
			if n > maxIndexedSegments {
				t.Fatalf("%d segment indexes cached, the bound is %d", n, maxIndexedSegments)
			}
		})
	}
}

// Repeated lookups are served from the index; the writer's active segment is extended, not
// rebuilt, as records are appended; a sealed segment's index survives the rotation.
func TestRecordIndexBuildsOnceAndExtendsIncrementally(t *testing.T) {
	s, _, clk := newLedger(t)
	refs := appendSamples(t, s, clk, 40, time.Second)
	for _, r := range refs {
		if _, b, err := s.Record(r.Seq); err != nil || b.Seq != r.Seq {
			t.Fatalf("Record(%d): %v", r.Seq, err)
		}
	}
	if b, e, _ := indexStats(s); b != 1 || e != 0 {
		t.Fatalf("builds %d, extends %d after lookups without appends", b, e)
	}
	more := appendSamples(t, s, clk, 10, time.Second)
	for _, r := range append(more, refs...) {
		if _, b, err := s.Record(r.Seq); err != nil || b.Seq != r.Seq {
			t.Fatalf("Record(%d): %v", r.Seq, err)
		}
	}
	if b, e, _ := indexStats(s); b != 1 || e != 1 {
		t.Fatalf("builds %d, extends %d after appending", b, e)
	}
	if _, _, err := s.Record(s.Head().Seq + 1); !errors.Is(err, contracts.ErrNotFound) {
		t.Fatalf("absent seq: %v", err)
	}
	clk.Advance(24 * time.Hour)
	next := appendSamples(t, s, clk, 3, time.Second) // rotates
	for _, r := range append(next, refs[0], more[9]) {
		if _, b, err := s.Record(r.Seq); err != nil || b.Seq != r.Seq {
			t.Fatalf("Record(%d) after rotation: %v", r.Seq, err)
		}
	}
	if b, e, st := indexStats(s); b != 2 || e != 1 || st != 0 {
		t.Fatalf("builds %d, extends %d, stale %d after rotation", b, e, st)
	}
}

// A read-only store follows the writer of another process: the index is extended as the file
// grows, and a line still being written is never returned.
func TestRecordIndexReadOnlyFollowsWriter(t *testing.T) {
	w, dir, clk := newLedger(t)
	refs := appendSamples(t, w, clk, 20, time.Second)
	opts := testOptions(dir, clk)
	opts.ReadOnly = true
	ro := openStore(t, opts)
	if _, b, err := ro.Record(refs[5].Seq); err != nil || b.Seq != refs[5].Seq {
		t.Fatalf("Record: %v", err)
	}
	more := appendSamples(t, w, clk, 10, time.Second)
	for _, r := range more {
		if _, b, err := ro.Record(r.Seq); err != nil || b.Seq != r.Seq {
			t.Fatalf("Record(%d) after the writer appended: %v", r.Seq, err)
		}
	}
	if b, e, _ := indexStats(ro); b != 1 || e != 1 {
		t.Fatalf("builds %d, extends %d", b, e)
	}
	w.Close()
	f, err := os.OpenFile(segPath(dir, segName(t0)), os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	line, _, err := encodeRecord(make(ed25519.PrivateKey, ed25519.PrivateKeySize), &model.Body{V: 1, Seq: more[9].Seq + 1,
		Prev: model.ZeroHash, TS: t0.Format(time.RFC3339Nano), Type: model.TypeSample, Data: []byte("{}")})
	if err != nil {
		t.Fatal(err)
	}
	f.Write(line[:len(line)-1]) // everything but the newline
	f.Close()
	if _, _, err := ro.Record(more[9].Seq + 1); !errors.Is(err, contracts.ErrNotFound) {
		t.Fatalf("a line without its newline was returned: %v", err)
	}
	requireRecordsMatchScan(t, ro)
}

// The writer's crash recovery in another process truncates a damaged tail that a read-only
// reader had already indexed and writes a recovery record at the same offset. The reader must
// notice and rebuild, whether the file then ends up shorter or longer.
func TestRecordIndexSurvivesRecoveryByAnotherWriter(t *testing.T) {
	for _, garbageLen := range []int{40, 8000} {
		t.Run(fmt.Sprint(garbageLen), func(t *testing.T) {
			dir := t.TempDir()
			clk := newClock(t0)
			w := openStore(t, testOptions(dir, clk))
			refs := appendSamples(t, w, clk, 10, time.Second)
			w.Close()
			path := segPath(dir, segName(t0))
			b, _ := os.ReadFile(path)
			garbage := []byte(`{"h":"` + strings.Repeat("0", garbageLen-9) + `"}` + "\n")
			os.WriteFile(path, append(b, garbage...), 0o644)

			opts := testOptions(dir, clk)
			opts.ReadOnly = true
			ro := openStore(t, opts)
			if _, b, err := ro.Record(refs[3].Seq); err != nil || b.Seq != refs[3].Seq {
				t.Fatalf("Record: %v", err)
			}
			clk.Advance(time.Minute)
			w2 := openStore(t, testOptions(dir, clk)) // quarantines the garbage, appends a recovery record
			head := w2.Head()
			_, body, err := ro.Record(head.Seq)
			if err != nil || body.Type != model.TypeRecovery || body.Seq != head.Seq {
				t.Fatalf("Record(%d) after recovery = %+v, %v", head.Seq, body, err)
			}
			if b, _, _ := indexStats(ro); b != 2 {
				t.Fatalf("builds %d: the stale index was not rebuilt", b)
			}
			requireRecordsMatchScan(t, ro)
		})
	}
}

// sealedDay builds a ledger whose first segment (n samples) is sealed, closes it and returns
// its directory, clock, signing key and the sealed segment's path.
func sealedDay(t *testing.T, n int) (string, *fakeClock, ed25519.PrivateKey, string) {
	t.Helper()
	dir := t.TempDir()
	clk := newClock(t0)
	s := openStore(t, testOptions(dir, clk))
	appendSamples(t, s, clk, n, time.Second)
	clk.Advance(24 * time.Hour)
	appendSamples(t, s, clk, 2, time.Second)
	priv := append(ed25519.PrivateKey(nil), s.priv...)
	s.Close()
	return dir, clk, priv, segPath(dir, segName(t0))
}

func readOnly(t *testing.T, dir string, clk *fakeClock) *Store {
	t.Helper()
	opts := testOptions(dir, clk)
	opts.ReadOnly = true
	return openStore(t, opts)
}

// A sealed segment rewritten in place with the same size and modification time looks unchanged
// to the index. The line read at an indexed offset no longer carries the expected seq: Record must
// fall back to the scan, return the record where it now lies, and drop the stale index.
func TestRecordIndexStaleOffsetsFallBackToScan(t *testing.T) {
	dir, clk, _, path := sealedDay(t, 30)
	lines := readLines(t, path)
	k := 1
	for k < len(lines)-1 && len(lines[k]) == len(lines[k+1]) {
		k++
	}
	if k >= len(lines)-1 {
		t.Fatal("no two adjacent lines of different length")
	}
	_, bk := parseLine(t, lines[k])
	envK, _ := parseLine(t, lines[k])
	ro := readOnly(t, dir, clk)
	if _, b, err := ro.Record(bk.Seq); err != nil || b.Seq != bk.Seq {
		t.Fatalf("Record: %v", err)
	}
	st, _ := os.Stat(path)
	lines[k], lines[k+1] = lines[k+1], lines[k]
	writeLines(t, path, lines)
	if err := os.Chtimes(path, st.ModTime(), st.ModTime()); err != nil {
		t.Fatal(err)
	}
	if st2, _ := os.Stat(path); st2.Size() != st.Size() || !st2.ModTime().Equal(st.ModTime()) {
		t.Skip("cannot make the rewritten file look unchanged on this file system")
	}
	env, b, err := ro.Record(bk.Seq)
	if err != nil || b.Seq != bk.Seq || env != envK {
		t.Fatalf("Record(%d) on stale offsets = %+v, %v", bk.Seq, b, err)
	}
	if b, _, st := indexStats(ro); b != 1 || st != 1 {
		t.Fatalf("builds %d, stale %d", b, st)
	}
	// The stale index was dropped: the next lookup rebuilds it from the file as it is now and
	// is answered by it.
	if env, b, err = ro.Record(bk.Seq); err != nil || b.Seq != bk.Seq || env != envK {
		t.Fatalf("Record(%d) after the rebuild = %+v, %v", bk.Seq, b, err)
	}
	if b, _, st := indexStats(ro); b != 2 || st != 1 {
		t.Fatalf("builds %d, stale %d: the stale index was not rebuilt", b, st)
	}
	requireRecordsMatchScan(t, ro)
	if _, _, st := indexStats(ro); st != 1 {
		t.Fatalf("stale %d after the rebuild", st)
	}
}

// A segment file replaced by another file (renamed over it) is indexed again even when size and
// modification time match: the index never describes a file other than the one it was built on.
func TestRecordIndexReplacedFileIsReindexed(t *testing.T) {
	dir, clk, _, path := sealedDay(t, 30)
	lines := readLines(t, path)
	k := 1
	for k < len(lines)-1 && len(lines[k]) == len(lines[k+1]) {
		k++
	}
	if k >= len(lines)-1 {
		t.Fatal("no two adjacent lines of different length")
	}
	envK, bk := parseLine(t, lines[k])
	ro := readOnly(t, dir, clk)
	if _, b, err := ro.Record(bk.Seq); err != nil || b.Seq != bk.Seq {
		t.Fatalf("Record: %v", err)
	}
	// Identify the original file by handle: a path-based Stat would look the identity up only
	// when compared, i.e. on the replacement.
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	st, err := f.Stat()
	f.Close()
	if err != nil {
		t.Fatal(err)
	}
	lines[k], lines[k+1] = lines[k+1], lines[k]
	tmp := path + ".replacement"
	writeLines(t, tmp, lines)
	if err := os.Chtimes(tmp, st.ModTime(), st.ModTime()); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
	if st2, _ := os.Stat(path); st2.Size() != st.Size() || !st2.ModTime().Equal(st.ModTime()) || os.SameFile(st, st2) {
		t.Skip("cannot replace the file with one of the same size and time on this file system")
	}
	env, b, err := ro.Record(bk.Seq)
	if err != nil || b.Seq != bk.Seq || env != envK {
		t.Fatalf("Record(%d) after the file was replaced = %+v, %v", bk.Seq, b, err)
	}
	if b, _, st := indexStats(ro); b != 2 || st != 0 {
		t.Fatalf("builds %d, stale %d: the replaced file must be re-indexed up front", b, st)
	}
}

// In a tampered segment that holds a seq twice, Record returns the first line in file order (as
// the scan does), and the unsorted index still answers every other seq.
func TestRecordIndexDuplicateSeqReturnsFirstInFileOrder(t *testing.T) {
	dir, clk, priv, path := sealedDay(t, 20)
	lines := readLines(t, path)
	envK, bk := parseLine(t, lines[5])
	forged := bk
	forged.Data = []byte(`{"forged":true}`)
	dup := reencode(t, priv, forged)
	lines = append(lines[:9], append([][]byte{dup}, lines[9:]...)...)
	writeLines(t, path, lines)
	ro := readOnly(t, dir, clk)
	env, b, err := ro.Record(bk.Seq)
	if err != nil || env != envK || !bytes.Equal(b.Data, bk.Data) {
		t.Fatalf("Record(%d) = %s, %v; want the first line in file order", bk.Seq, b.Data, err)
	}
	_, bodies := scanEnvs(t, ro)
	for _, want := range bodies {
		if _, got, err := ro.Record(want.Seq); err != nil || got.Seq != want.Seq {
			t.Fatalf("Record(%d): %v", want.Seq, err)
		}
	}
}

// A line whose quick seq prefix and parsed body disagree (or that does not parse) is not a
// record for that seq: the index must not change what Record answers, and must not be
// discarded as stale because of it.
func TestRecordIndexUnusableLineIsNotStale(t *testing.T) {
	dir, clk, _, path := sealedDay(t, 10)
	lines := readLines(t, path)
	_, b4 := parseLine(t, lines[4])
	// Drop the body's closing brace: the envelope and the quick seq prefix stay intact, the body
	// no longer parses.
	broken := bytes.Replace(lines[4], []byte("}\"}\n"), []byte("\"}\n"), 1)
	if bytes.Equal(broken, lines[4]) {
		t.Fatal("line layout changed")
	}
	if q, _, ok := quickSeqTS(broken); !ok || q != b4.Seq {
		t.Fatal("the quick seq prefix must survive")
	}
	if _, _, err := parseRecordLenient(broken); err == nil {
		t.Fatal("the body must not parse")
	}
	lines[4] = broken
	writeLines(t, path, lines)
	ro := readOnly(t, dir, clk)
	for round := 0; round < 2; round++ {
		if _, _, err := ro.Record(b4.Seq); !errors.Is(err, contracts.ErrNotFound) {
			t.Fatalf("Record of an unparsable line: %v", err)
		}
	}
	if b, _, st := indexStats(ro); b != 1 || st != 0 {
		t.Fatalf("builds %d, stale %d", b, st)
	}
}

// Compressed segments: the uncompressed bytes are kept within a budget; beyond it the record is
// read by streaming decompression. Both give the scan's answer.
func TestRecordIndexCompressedSegments(t *testing.T) {
	s, dir, clk, _ := fiveDayLedger(t)
	if n, err := s.CompressSealed(0); err != nil || n != 4 {
		t.Fatalf("CompressSealed = %d, %v", n, err)
	}
	requireRecordsMatchScan(t, s)
	if n := s.idx.dataBytes.Load(); n <= 0 || n > maxIndexDataBytes {
		t.Fatalf("cached uncompressed bytes %d", n)
	}

	old := maxIndexDataBytes
	maxIndexDataBytes = 64
	t.Cleanup(func() { maxIndexDataBytes = old })
	ro := readOnly(t, dir, clk)
	requireRecordsMatchScan(t, ro)
	requireRecordsMatchScan(t, ro)
	if n := ro.idx.dataBytes.Load(); n != 0 {
		t.Fatalf("%d uncompressed bytes cached beyond the budget", n)
	}
}

// Compression replaces a segment's file: Record keeps working, and the index of the removed
// uncompressed file is dropped.
func TestRecordIndexAcrossCompression(t *testing.T) {
	s, _, _, _ := fiveDayLedger(t)
	segs, _ := s.Segments()
	seq := segs[1].FirstSeq + 1
	if _, b, err := s.Record(seq); err != nil || b.Seq != seq {
		t.Fatalf("Record: %v", err)
	}
	if _, err := s.CompressSealed(0); err != nil {
		t.Fatal(err)
	}
	if _, b, err := s.Record(seq); err != nil || b.Seq != seq {
		t.Fatalf("Record after compression: %v", err)
	}
	s.idx.mu.Lock()
	defer s.idx.mu.Unlock()
	for _, e := range s.idx.entries {
		if strings.HasSuffix(e.path, segs[1].Name+".jsonl") {
			t.Fatalf("index of the removed file %s is still cached", e.path)
		}
	}
}

// Record runs concurrently with appends and rotations (run with -race).
func TestRecordIndexConcurrentWithAppends(t *testing.T) {
	s, _, clk := newLedger(t)
	appendSamples(t, s, clk, 20, time.Millisecond)
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			rng := rand.New(rand.NewPCG(uint64(g), 1))
			for {
				select {
				case <-stop:
					return
				default:
				}
				head := s.Head()
				seq := rng.Uint64N(head.Seq + 1)
				if _, b, err := s.Record(seq); err != nil || b.Seq != seq {
					t.Errorf("Record(%d) with head %d: %v", seq, head.Seq, err)
					return
				}
			}
		}(g)
	}
	for i := 0; i < 120; i++ {
		if i == 60 {
			clk.Advance(24 * time.Hour)
		}
		clk.Advance(time.Millisecond)
		if _, err := s.Append(model.TypeSample, samplePayload(uint64(i))); err != nil {
			t.Error(err)
			break
		}
	}
	close(stop)
	wg.Wait()
	requireRecordsMatchScan(t, s)
}
