package syslogstore

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"attmonitor/internal/contracts"
	"attmonitor/internal/model"
)

// Chunks lists chunks whose messages were received in order as refsOf (prune_test.go) does.
func TestChunksListsTheSealedChunks(t *testing.T) {
	s, _, _, chunks := layout(t)
	if got := s.Chunks(); !slices.Equal(got, refsOf(chunks)) {
		t.Fatalf("Chunks\n%+v\nwant\n%+v", got, refsOf(chunks))
	}
	// The chunks a prune chose are no longer kept; cancelling the plan keeps them again.
	plan, err := s.PlanPrune(t0.Add(1000 * time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	s.SetRetention(1, 1)
	if plan, err = s.PlanPrune(t0.Add(1000 * time.Hour)); err != nil || len(plan) != 3 {
		t.Fatalf("PlanPrune: %v %v", plan, err)
	}
	if got := s.Chunks(); len(got) != 0 {
		t.Fatalf("Chunks during a planned prune: %+v", got)
	}
	s.CancelPrune()
	if got := s.Chunks(); !slices.Equal(got, refsOf(chunks)) {
		t.Fatalf("Chunks after CancelPrune: %+v", got)
	}
	// An empty store lists none (not nil, so it encodes as []).
	empty, _ := testStore(t, Options{})
	if got := empty.Chunks(); got == nil || len(got) != 0 {
		t.Fatalf("Chunks of an empty store: %#v", got)
	}
}

func TestChunksStateTheReceiveRangeWhenTheClockWasSetBack(t *testing.T) {
	s, _ := testStore(t, Options{})
	at := func(sec int) time.Time { return t0.Add(time.Duration(sec) * time.Second) }
	ms := []model.SyslogMessage{msg(at(10), "a"), msg(at(20), "b"), msg(at(5), "set back")}
	chunks := fill(t, s, ms, 3)
	if len(chunks) != 1 || chunks[0].From != ms[0].RX || chunks[0].To != ms[2].RX {
		t.Fatalf("sealed %+v", chunks)
	}
	want := refsOf(chunks)
	want[0].From, want[0].To = ms[2].RX, ms[1].RX // the earliest and the latest
	if got := s.Chunks(); !slices.Equal(got, want) {
		t.Fatalf("Chunks\n%+v\nwant\n%+v", got, want)
	}
	// The sidecar (and so the record) keeps the first and the last message's receive times.
	if sc := readSidecarFile(t, s.dir, chunks[0].Name); sc.From != ms[0].RX || sc.To != ms[2].RX {
		t.Fatalf("sidecar %+v", sc)
	}
	// Also after a restart (the range comes from the sidecar's rx_min and rx_max).
	s, _ = reopen(t, s, Options{})
	if got := s.Chunks(); !slices.Equal(got, want) {
		t.Fatalf("Chunks after reopening\n%+v\nwant\n%+v", got, want)
	}
}

func TestChunksOfAChunkWithoutMessages(t *testing.T) {
	s, _ := testStore(t, Options{})
	if _, err := s.Append(nil, 3, 1, t0); err != nil {
		t.Fatal(err)
	}
	c, err := s.Seal(t0, "stop", true)
	if err != nil || c == nil || c.Messages != 0 {
		t.Fatalf("Seal: %+v %v", c, err)
	}
	got := s.Chunks()
	if len(got) != 1 || got[0].From != formatRX(t0) || got[0].To != formatRX(t0) || got[0].Messages != 0 {
		t.Fatalf("Chunks: %+v", got)
	}
}

// eachOpen collects the texts EachOpen passes for [from, to).
func eachOpen(t *testing.T, s *Store, from, to time.Time) []string {
	t.Helper()
	var got []string
	err := s.EachOpen(context.Background(), from, to, func(m *model.SyslogMessage) error {
		got = append(got, m.Msg)
		return nil
	})
	if err != nil {
		t.Fatalf("EachOpen [%v, %v): %v", from, to, err)
	}
	return got
}

func TestEachOpenRange(t *testing.T) {
	s, _, ms, _ := layout(t) // m-9 and m-10 are in the open chunk
	at := func(i int) time.Time { return t0.Add(time.Duration(i) * time.Second) }
	for _, c := range []struct {
		from, to time.Time
		want     []string
	}{
		{time.Time{}, time.Time{}, []string{"m-9", "m-10"}}, // oldest first; a zero to has no end
		{at(9), at(10), []string{"m-9"}},                    // from included, to excluded
		{at(10), at(11), []string{"m-10"}},
		{at(0), at(9), nil}, // the sealed chunks are not read
		{at(11), at(20), nil},
		{at(10), at(10), nil}, // an empty period
		{at(10), at(9), nil},
	} {
		if got := eachOpen(t, s, c.from, c.to); !slices.Equal(got, c.want) {
			t.Errorf("EachOpen [%v, %v): %v, want %v", c.from, c.to, got, c.want)
		}
	}
	// Each call gets a message of its own, as stored.
	var kept []*model.SyslogMessage
	if err := s.EachOpen(context.Background(), time.Time{}, time.Time{}, func(m *model.SyslogMessage) error {
		kept = append(kept, m)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(kept) != 2 || kept[0] == kept[1] || kept[0].Raw != ms[9].Raw || kept[1].RX != ms[10].RX || *kept[0].Severity != 6 {
		t.Fatalf("messages %+v", kept)
	}
}

func TestEachOpenWithoutAnOpenChunk(t *testing.T) {
	s, _ := testStore(t, Options{})
	calls := 0
	fn := func(*model.SyslogMessage) error { calls++; return nil }
	if err := s.EachOpen(context.Background(), time.Time{}, time.Time{}, fn); err != nil || calls != 0 {
		t.Fatalf("EachOpen of an empty store: %v (%d calls)", err, calls)
	}
	fill(t, s, msgs(t0, 3, "m"), 3) // every message sealed
	if err := s.EachOpen(context.Background(), time.Time{}, time.Time{}, fn); err != nil || calls != 0 {
		t.Fatalf("EachOpen without an open chunk: %v (%d calls)", err, calls)
	}
}

func TestEachOpenStopsEarly(t *testing.T) {
	s, _ := testStore(t, Options{})
	if _, err := s.Append(msgs(t0, 5, "m"), 0, 0, t0); err != nil {
		t.Fatal(err)
	}
	var got []string
	err := s.EachOpen(context.Background(), time.Time{}, time.Time{}, func(m *model.SyslogMessage) error {
		got = append(got, m.Msg)
		if len(got) == 2 {
			return fmt.Errorf("enough: %w", contracts.ErrStop)
		}
		return nil
	})
	if err != nil || !slices.Equal(got, []string{"m-0", "m-1"}) {
		t.Fatalf("EachOpen with ErrStop: %v %v", got, err)
	}
	boom := errors.New("boom")
	calls := 0
	err = s.EachOpen(context.Background(), time.Time{}, time.Time{}, func(*model.SyslogMessage) error {
		calls++
		return boom
	})
	if !errors.Is(err, boom) || calls != 1 {
		t.Fatalf("EachOpen with an error: %v (%d calls)", err, calls)
	}
}

func TestEachOpenHonoursTheContext(t *testing.T) {
	s, _ := testStore(t, Options{ChunkBytes: 64 << 20}) // every message stays in the open chunk
	if _, err := s.Append(msgs(t0, 2*ctxEvery, "m"), 0, 0, t0); err != nil {
		t.Fatal(err)
	}
	if u := s.Usage(); u.OpenMessages != 2*ctxEvery {
		t.Fatalf("Usage %+v", u)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	calls := 0
	fn := func(*model.SyslogMessage) error { calls++; return nil }
	if err := s.EachOpen(ctx, time.Time{}, time.Time{}, fn); !errors.Is(err, context.Canceled) || calls != 0 {
		t.Fatalf("EachOpen with an ended context: %v (%d calls)", err, calls)
	}
	// Ended while reading: it stops within a few thousand lines.
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	err := s.EachOpen(ctx, time.Time{}, time.Time{}, func(*model.SyslogMessage) error {
		calls++
		if calls == 10 {
			cancel()
		}
		return nil
	})
	if !errors.Is(err, context.Canceled) || calls >= 2*ctxEvery {
		t.Fatalf("EachOpen with a context ended while reading: %v (%d calls)", err, calls)
	}
}

func TestEachOpenKeepsTheChunkFromBeingSealed(t *testing.T) {
	s, _ := testStore(t, Options{})
	if _, err := s.Append(msgs(t0, 3, "m"), 0, 0, t0); err != nil {
		t.Fatal(err)
	}
	sealed := make(chan *model.SyslogChunk, 1)
	var got []string
	err := s.EachOpen(context.Background(), time.Time{}, time.Time{}, func(m *model.SyslogMessage) error {
		got = append(got, m.Msg)
		if len(got) == 1 {
			go func() {
				c, err := s.Seal(t0, "stop", true)
				if err != nil {
					t.Error(err)
				}
				sealed <- c
			}()
			select {
			case <-sealed:
				t.Error("the open chunk was sealed while EachOpen read it")
			case <-time.After(50 * time.Millisecond):
			}
		}
		return nil
	})
	if err != nil || !slices.Equal(got, []string{"m-0", "m-1", "m-2"}) {
		t.Fatalf("EachOpen: %v %v", got, err)
	}
	if c := <-sealed; c == nil || c.Messages != 3 {
		t.Fatalf("sealed afterwards: %+v", c)
	}
	if got := eachOpen(t, s, time.Time{}, time.Time{}); got != nil {
		t.Fatalf("EachOpen after the seal: %v", got)
	}
}

// TestChunksListAChunkSealedAfterTheyWereListed: Chunks and EachOpen are separate snapshots - the
// messages of a chunk sealed between them are in neither - and listing the chunks again shows
// the chunk sealed meanwhile, with its messages (what the firewall view relies on to build again).
func TestChunksListAChunkSealedAfterTheyWereListed(t *testing.T) {
	s, _ := testStore(t, Options{})
	fill(t, s, msgs(t0, 2, "sealed"), 2)
	if _, err := s.Append(msgs(t0.Add(time.Minute), 3, "open"), 0, 0, t0); err != nil {
		t.Fatal(err)
	}
	before := s.Chunks()
	c, err := s.Seal(t0, "age", true)
	if err != nil || c == nil {
		t.Fatalf("Seal: %v %v", c, err)
	}
	if got := eachOpen(t, s, time.Time{}, time.Time{}); got != nil {
		t.Fatalf("EachOpen after the seal: %v", got)
	}
	after := s.Chunks()
	if len(before) != 1 || len(after) != 2 || after[0] != before[0] || after[1].Name != c.Name || after[1].Messages != 3 {
		t.Fatalf("Chunks before %+v, after %+v", before, after)
	}
}

func TestEachOpenOfAReadOnlyStore(t *testing.T) {
	w, _ := testStore(t, Options{})
	ms := msgs(t0, 4, "m")
	if _, err := w.Append(ms[:2], 0, 0, t0); err != nil {
		t.Fatal(err)
	}
	ro, err := New(Options{Dir: w.dir, ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	defer ro.Close()
	if got := eachOpen(t, ro, time.Time{}, time.Time{}); !slices.Equal(got, []string{"m-0", "m-1"}) {
		t.Fatalf("EachOpen: %v", got)
	}
	// The writer's open chunk is read as it grows.
	if _, err := w.Append(ms[2:], 0, 0, t0); err != nil {
		t.Fatal(err)
	}
	if got := eachOpen(t, ro, t0.Add(time.Second), time.Time{}); !slices.Equal(got, []string{"m-1", "m-2", "m-3"}) {
		t.Fatalf("EachOpen after more were written: %v", got)
	}
	// Once the writer seals it, there is nothing left to read.
	if _, err := w.Seal(t0, "stop", true); err != nil {
		t.Fatal(err)
	}
	if got := eachOpen(t, ro, time.Time{}, time.Time{}); got != nil {
		t.Fatalf("EachOpen after the writer sealed: %v", got)
	}
}

func TestEachOpenSkipsLinesThatDoNotParse(t *testing.T) {
	// A writer (another process) left an open chunk with damaged lines and a line being written.
	dir := t.TempDir()
	ms := msgs(t0, 3, "m")
	var b []byte
	b = append(b, lineOf(t, ms[0])...)
	b = append(b, "not json\n"...)
	b = append(b, `{"rx":"yesterday","msg":"bad time"}`+"\n"...)
	b = append(b, lineOf(t, ms[1])...)
	b = append(b, lineOf(t, ms[2])[:20]...) // no line feed yet
	writeFile(t, filepath.Join(dir, openName(t0, 1)), b)
	h := &captureHandler{}
	ro, err := New(Options{Dir: dir, ReadOnly: true, Logger: slogFor(h)})
	if err != nil {
		t.Fatal(err)
	}
	defer ro.Close()
	for range 2 {
		if got := eachOpen(t, ro, time.Time{}, time.Time{}); !slices.Equal(got, []string{"m-0", "m-1"}) {
			t.Fatalf("EachOpen: %v", got)
		}
	}
	if n := h.count("lines of a chunk that cannot be read were skipped"); n != 1 {
		t.Fatalf("logged %d times:\n%s", n, h.all())
	}
	if v := h.attr("cannot be read were skipped", "lines"); v != "2" {
		t.Fatalf("lines %q", v)
	}
	// A file that disappeared (sealed by the writer meanwhile) is not an error.
	if err := os.Remove(filepath.Join(dir, openName(t0, 1))); err != nil {
		t.Fatal(err)
	}
	if got := eachOpen(t, ro, time.Time{}, time.Time{}); got != nil {
		t.Fatalf("EachOpen of a deleted file: %v", got)
	}
}
