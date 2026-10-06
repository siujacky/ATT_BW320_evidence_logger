package connstore

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"attmonitor/internal/contracts"
)

// TestReadersNeverCountAMergedDayTwice merges late reads into a compressed day over and over
// while readers count the day's reads: a reader that read the new compressed file (which holds
// the plain file's reads) together with the plain file would count more reads than were ever
// stored.
func TestReadersNeverCountAMergedDayTwice(t *testing.T) {
	h := newHarness(t, at(1, 0, 10), Options{})
	const base = 20
	for i := range base {
		h.nat(at(0, 1, i), tcp(10, i, "203.0.113.5", 443))
	}
	h.nat(at(1, 0, 10), tcp(10, 1, "203.0.113.5", 443)) // compresses day 0
	var stored atomic.Int64                             // reads of day 0 stored, or being stored
	stored.Store(base)
	done := make(chan struct{})
	var wg sync.WaitGroup
	var mu sync.Mutex
	var problems []string
	for range 3 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			seen := 0
			for {
				select {
				case <-done:
					return
				default:
				}
				a, err := h.s.Aggregate(context.Background(), contracts.ConnQuery{From: at(0, 0, 0), To: at(1, 0, 0)})
				limit := int(stored.Load())
				mu.Lock()
				switch {
				case err != nil:
					problems = append(problems, err.Error())
				case a.Samples > limit:
					problems = append(problems, fmt.Sprintf("counted %d reads of day 0, at most %d were stored", a.Samples, limit))
				case a.Samples < seen:
					problems = append(problems, fmt.Sprintf("counted %d reads of day 0 after %d", a.Samples, seen))
				}
				mu.Unlock()
				seen = max(seen, a.Samples)
			}
		}()
	}
	const merges = 60
	for i := range merges {
		late := at(0, 23, 0).Add(time.Duration(i) * time.Second)
		h.clk.Set(late)
		stored.Add(1)
		h.nat(late, tcp(10, 1000+i, "198.51.100.7", 443)) // next to the compressed day
		now := at(1, 1, 0).Add(time.Duration(i) * time.Second)
		h.clk.Set(now)
		h.nat(now, tcp(10, 1, "203.0.113.5", 443)) // merges it
	}
	close(done)
	wg.Wait()
	for i, p := range problems {
		if i == 10 {
			break
		}
		t.Error(p)
	}
	if a := h.agg(at(0, 0, 0), at(1, 0, 0)); a.Samples != base+merges {
		t.Errorf("day 0 holds %d reads, want %d", a.Samples, base+merges)
	}
	if h.exists("nat-2026-10-05.jsonl") {
		t.Errorf("the last late read was not merged:\n%s", h.log.all())
	}
}

func TestReadersWaitWhileTheWriterChangesADay(t *testing.T) {
	h := newHarness(t, at(1, 12, 0), Options{})
	h.nat(at(0, 10, 0), tcp(10, 1, "203.0.113.5", 443))
	h.nat(at(1, 10, 0), tcp(10, 1, "203.0.113.5", 443))
	d := dayOf(at(0, 0, 0))
	mark := func() {
		h.s.mu.Lock()
		h.s.files[kindNAT][d].gen++
		h.s.mu.Unlock()
	}
	// Marked for longer than a reader waits: the day cannot be read now.
	mark()
	if _, err := h.s.openDay(kindNAT, d); !errors.Is(err, errChanged) {
		t.Errorf("openDay of a day being changed: %v", err)
	}
	// Marked for a moment: the reader waits for it.
	go func() {
		time.Sleep(5 * time.Millisecond)
		mark()
	}()
	r, err := h.s.openDay(kindNAT, d)
	if err != nil || r == nil {
		t.Fatalf("openDay after the change: %v", err)
	}
	r.close()
	if a := h.agg(at(0, 0, 0), at(1, 0, 0)); a.Samples != 1 {
		t.Errorf("day 0 = %d reads", a.Samples)
	}
}

func TestAFileAnotherProgramCutIsReadAsItIs(t *testing.T) {
	h := newHarness(t, at(1, 0, 30), Options{})
	h.nat(at(0, 10, 0), tcp(10, 1, "203.0.113.5", 443))
	h.nat(at(1, 0, 20), tcp(10, 1, "203.0.113.5", 443)) // compresses day 0
	// Late reads of day 0 (made before midnight, stored after it) in a plain file, closed after
	// each write.
	h.nat(at(0, 23, 50), tcp(10, 2, "203.0.113.5", 443))
	h.nat(at(0, 23, 51), tcp(10, 3, "203.0.113.5", 443))
	plain := h.file("nat-2026-10-05.jsonl")
	lines := h.lines("nat-2026-10-05.jsonl")
	// Another program cuts the file in the middle of its second line.
	if err := os.Truncate(plain, int64(len(lines[0])+1+len(lines[1])/2)); err != nil {
		t.Fatal(err)
	}
	if a := h.agg(at(0, 0, 0), at(1, 0, 0)); a.Samples != 2 {
		t.Errorf("readers: %d reads, want 2 (the compressed one and the complete line)", a.Samples)
	}
	// The next late read goes after the complete line: nothing is written beyond the file's end.
	h.nat(at(0, 23, 52), tcp(10, 4, "203.0.113.5", 443))
	got := h.lines("nat-2026-10-05.jsonl")
	if len(got) != 2 || got[0] != lines[0] || !strings.Contains(got[1], "23:52:00Z") {
		t.Errorf("the plain file after the next write = %q", got)
	}
	if h.log.count("shorter than the store wrote it") != 1 {
		t.Errorf("not logged:\n%s", h.log.all())
	}
	if a := h.agg(at(0, 0, 0), at(1, 0, 0)); a.Samples != 3 {
		t.Errorf("%d reads, want 3", a.Samples)
	}
	// Deleted by another program: the next late read starts the file again.
	if err := os.Remove(plain); err != nil {
		t.Fatal(err)
	}
	h.nat(at(0, 23, 53), tcp(10, 5, "203.0.113.5", 443))
	if got := h.lines("nat-2026-10-05.jsonl"); len(got) != 1 {
		t.Errorf("the plain file after it was deleted = %q", got)
	}
}
