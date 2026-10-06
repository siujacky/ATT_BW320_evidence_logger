package syslogstore

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"attmonitor/internal/contracts"
	"attmonitor/internal/model"
)

// chunkNames returns the names of cs.
func chunkNames(cs []model.SyslogChunk) []string {
	out := make([]string, len(cs))
	for i, c := range cs {
		out[i] = c.Name
	}
	return out
}

// Sealed chunks are unrecorded until MarkRecorded notes their syslog_chunk record. The sidecar
// keeps the note across a restart; a chunk whose sidecar had to be rebuilt is unrecorded again
// (its record may exist: the writer looks it up before recording one).
func TestMarkRecorded(t *testing.T) {
	s, _ := testStore(t, Options{})
	chunks := fill(t, s, msgs(t0, 6, "m"), 2)
	if len(chunks) != 3 {
		t.Fatalf("test setup: %d chunks", len(chunks))
	}
	if got := s.Unrecorded(); !slices.Equal(got, chunks) {
		t.Fatalf("Unrecorded after sealing: %v", chunkNames(got))
	}
	for range 2 { // noting it again changes nothing
		if err := s.MarkRecorded(chunks[1].Name, 42); err != nil {
			t.Fatal(err)
		}
	}
	want := []model.SyslogChunk{chunks[0], chunks[2]}
	if got := s.Unrecorded(); !slices.Equal(got, want) {
		t.Fatalf("Unrecorded: %v, want %v", chunkNames(got), chunkNames(want))
	}
	if sc := readSidecarFile(t, s.dir, chunks[1].Name); sc.Recorded != 42 || sc.SyslogChunk != chunks[1] {
		t.Fatalf("sidecar %+v", sc)
	}
	checkChunk(t, s.dir, chunks[1], linesOf(t, msgs(t0, 6, "m")[2:4]))
	if err := s.MarkRecorded("syslog-20261005T221500Z_20261005T221500Z.jsonl.gz", 7); !errors.Is(err, contracts.ErrNotFound) {
		t.Fatalf("an unknown chunk: %v", err)
	}
	if err := s.MarkRecorded(chunks[0].Name, 0); err == nil {
		t.Fatal("seq 0 accepted")
	}

	s2, _ := reopen(t, s, Options{})
	if got := s2.Unrecorded(); !slices.Equal(got, want) {
		t.Fatalf("after a restart: %v", chunkNames(got))
	}
	if err := os.Remove(filepath.Join(s2.dir, chunks[1].Name+sidecarExt)); err != nil {
		t.Fatal(err)
	}
	s3, _ := reopen(t, s2, Options{})
	if got := chunkNames(s3.Unrecorded()); !slices.Equal(got, chunkNames(chunks)) {
		t.Fatalf("after its sidecar was rebuilt: %v", got)
	}
	ro, err := New(Options{Dir: s3.dir, ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := ro.MarkRecorded(chunks[0].Name, 5); !errors.Is(err, ErrReadOnly) {
		t.Fatalf("a read-only store: %v", err)
	}
}

// PlanPrune deletes nothing: the chosen chunks no longer count and get no new readers until
// CommitPrune deletes them, or CancelPrune gives them back.
func TestPlanPrune(t *testing.T) {
	s, _ := testStore(t, Options{KeepMB: 1})
	chunks := bigChunks(t, s, t0, 3*mib/2, 20)
	want := wantPruned(chunks, 0, mib)
	if len(want) == 0 || len(want) == len(chunks) {
		t.Fatalf("test setup: %d of %d chunks to prune", len(want), len(chunks))
	}
	before := s.Usage()
	plan, err := s.PlanPrune(t0)
	if err != nil || !slices.Equal(plan, refsOf(want)) {
		t.Fatalf("PlanPrune: %+v %v\nwant %+v", plan, err, refsOf(want))
	}
	exists := func(name string) bool {
		_, err := os.Stat(filepath.Join(s.dir, name))
		return err == nil
	}
	for _, c := range want {
		if !exists(c.Name) || !exists(c.Name+sidecarExt) {
			t.Fatalf("PlanPrune deleted %s", c.Name)
		}
	}
	planned := s.Usage()
	if planned.Chunks != before.Chunks-len(want) || planned.Bytes > mib {
		t.Fatalf("Usage with a plan: %+v (before %+v)", planned, before)
	}
	if _, err := s.OpenChunk(want[0].Name); !errors.Is(err, contracts.ErrNotFound) {
		t.Fatalf("a chosen chunk was opened: %v", err)
	}
	if got := chunkNames(s.Unrecorded()); slices.Contains(got, want[0].Name) {
		t.Fatalf("a chosen chunk is listed as unrecorded: %v", got)
	}

	s.CancelPrune()
	if u := s.Usage(); u != before {
		t.Fatalf("Usage after CancelPrune: %+v, want %+v", u, before)
	}
	r, err := s.OpenChunk(want[0].Name)
	if err != nil {
		t.Fatalf("OpenChunk after CancelPrune: %v", err)
	}
	r.Close()

	if plan, err := s.PlanPrune(t0); err != nil || !slices.Equal(plan, refsOf(want)) {
		t.Fatalf("PlanPrune again: %+v %v", plan, err)
	}
	deleted, err := s.CommitPrune()
	if err != nil || !slices.Equal(deleted, refsOf(want)) {
		t.Fatalf("CommitPrune: %+v %v", deleted, err)
	}
	for _, c := range want {
		if exists(c.Name) || exists(c.Name+sidecarExt) {
			t.Fatalf("%s was not deleted", c.Name)
		}
	}
	if u := s.Usage(); u != planned {
		t.Fatalf("Usage after CommitPrune: %+v, want %+v", u, planned)
	}
	if refs, err := s.CommitPrune(); err != nil || len(refs) != 0 {
		t.Fatalf("CommitPrune without a plan: %+v %v", refs, err)
	}
	if plan, err := s.PlanPrune(t0); err != nil || len(plan) != 0 {
		t.Fatalf("PlanPrune within the limits: %+v %v", plan, err)
	}
}

// Prune gives back the chunks of a plan that was neither committed nor cancelled before it
// chooses: they are deleted (and returned) like any other.
func TestPruneEndsAnOpenPlan(t *testing.T) {
	s, _ := testStore(t, Options{KeepMB: 1})
	chunks := bigChunks(t, s, t0, 3*mib/2, 20)
	want := wantPruned(chunks, 0, mib)
	if _, err := s.PlanPrune(t0); err != nil {
		t.Fatal(err)
	}
	refs, err := s.Prune(t0)
	if err != nil || !slices.Equal(refs, refsOf(want)) {
		t.Fatalf("Prune: %+v %v\nwant %+v", refs, err, refsOf(want))
	}
	if refs, err := s.CommitPrune(); err != nil || len(refs) != 0 {
		t.Fatalf("CommitPrune after Prune: %+v %v", refs, err)
	}
}

// A chunk left open whose sealed twin is noted as recorded - its sealing returned and was
// recorded, only deleting the open file failed, and so did noting that - is only deleted: it
// is not returned again, which would record it twice.
func TestRecoverTwinRecordedAlready(t *testing.T) {
	dir := t.TempDir()
	ms := msgs(t0, 3, "m")
	sealed, _ := sealKeepingOpenFiles(t, dir, ms)
	s, h := testStore(t, Options{Dir: dir})
	if err := s.MarkRecorded(sealed.Name, 9); err != nil {
		t.Fatal(err)
	}
	got, err := s.Recover(t0)
	if err != nil || len(got) != 0 {
		t.Fatalf("Recover: %+v %v", got, err)
	}
	if n := names(t, dir); !slices.Equal(n, []string{sealed.Name, sealed.Name + sidecarExt}) {
		t.Fatalf("files %v", n)
	}
	if h.count("sealed and recorded already") != 1 {
		t.Fatalf("not logged:\n%s", h.all())
	}
	if len(s.Unrecorded()) != 0 {
		t.Fatalf("unrecorded: %v", chunkNames(s.Unrecorded()))
	}
}
