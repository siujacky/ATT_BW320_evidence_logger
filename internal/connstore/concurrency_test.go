package connstore

import (
	"context"
	"fmt"
	"reflect"
	"sync"
	"testing"
	"time"

	"attmonitor/internal/contracts"
	"attmonitor/internal/model"
)

// TestConcurrentWriterAndReaders runs the monitor's writes - days rolling over every few
// appends (so days are compressed under the readers), the retention deleting the oldest,
// devices changing addresses - while readers query all the time. Run with -race. No reader may
// fail, see a half-written or damaged line, or a result that breaks the invariants; and at the
// end the results equal those of a store opened anew on the same files.
func TestConcurrentWriterAndReaders(t *testing.T) {
	h := newHarness(t, at(0, 0, 0), Options{KeepDays: 3})
	const appends = 160 // every 3 hours: 20 days, 20 rollovers and compressions, 17 days pruned
	var (
		mu       sync.Mutex
		problems []string
		queries  int
	)
	problem := func(format string, args ...any) {
		mu.Lock()
		problems = append(problems, fmt.Sprintf(format, args...))
		mu.Unlock()
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := range appends {
			tm := at(0, 0, 0).Add(time.Duration(i) * 3 * time.Hour)
			h.clk.Set(tm)
			if i%2 == 0 {
				// The laptop moves between two addresses.
				if err := h.s.AppendDevices(tm, []model.LANDevice{
					device(10+i%4, 1, "test-laptop", "Wi-Fi"), device(20, 2, "test-phone", "Wi-Fi"),
				}); err != nil {
					problem("AppendDevices: %v", err)
				}
			}
			var sessions []model.NATSession
			for j := range 60 {
				sessions = append(sessions, tcp(10+(i+j)%4, 40000+j, remoteOf(i+j), 443), udp(20, 50000+j, remoteOf(j), 53))
			}
			if err := h.s.AppendNAT(tm, model.NATTable{Sessions: sessions, InUse: len(sessions), Available: 9000}); err != nil {
				problem("AppendNAT: %v", err)
			}
			if i%10 == 9 {
				if err := h.s.Prune(time.Time{}); err != nil {
					problem("Prune: %v", err)
				}
			}
		}
	}()
	var wg sync.WaitGroup
	for r := range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for n := 0; ; n++ {
				select {
				case <-done:
					return
				default:
				}
				now := h.clk.Now()
				var q contracts.ConnQuery
				switch (n + r) % 4 {
				case 0:
					q = contracts.ConnQuery{From: now.Add(-24 * time.Hour), To: now.Add(time.Hour)}
				case 1:
					q = contracts.ConnQuery{} // everything
				case 2:
					q = contracts.ConnQuery{From: dayOf(now).start().AddDate(0, 0, -2), To: dayOf(now).start()} // whole past days
				case 3:
					q = contracts.ConnQuery{Device: macKey(1)}
				}
				a, err := h.s.Aggregate(context.Background(), q)
				if err != nil {
					problem("Aggregate: %v", err)
					continue
				}
				for _, p := range consistent(a) {
					problem("query %+v: %s", q, p)
				}
				if a.Samples > 0 && a.Open != 120 {
					problem("the newest read lists %d sessions, want 120", a.Open)
				}
				if u := h.s.Usage(); u.Files < 0 || u.Bytes < 0 {
					problem("Usage = %+v", u)
				}
				if devs, _ := h.s.Devices(); devs != nil && len(devs) != 2 {
					problem("Devices = %+v", devs)
				}
				mu.Lock()
				queries++
				mu.Unlock()
			}
		}()
	}
	<-done
	wg.Wait()
	for i, p := range problems {
		if i == 20 {
			t.Errorf("... %d more", len(problems)-20)
			break
		}
		t.Error(p)
	}
	if queries < 20 {
		t.Errorf("only %d queries ran while the writer did", queries)
	}
	for _, msg := range []string{"cannot be read", "could not", "failed"} {
		if n := h.log.count(msg); n > 0 {
			t.Errorf("%d log records %q:\n%s", n, msg, h.log.all())
		}
	}
	if u := h.s.Usage(); u.Error != "" {
		t.Errorf("Usage().Error = %q", u.Error)
	}

	// What the readers' cache holds is what the files hold.
	queries2 := []contracts.ConnQuery{{}, {Device: macKey(1)}, {From: at(17, 0, 0), To: at(19, 0, 0)}, {From: at(18, 5, 0), To: at(19, 7, 0)}}
	var cached []model.ConnAggregate
	for _, q := range queries2 {
		a, err := h.s.Aggregate(context.Background(), q)
		if err != nil {
			t.Fatal(err)
		}
		cached = append(cached, a)
	}
	h.reopen()
	for i, q := range queries2 {
		a, err := h.s.Aggregate(context.Background(), q)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(a, cached[i]) {
			t.Errorf("query %+v differs after reopening:\n%+v\nwant\n%+v", q, a, cached[i])
		}
	}
	// The last append was at day 19, 21:00: with 3 days kept, days 16 to 19 are left, 8 reads each.
	if a := cached[0]; a.Samples != 32 || a.First != rfc(at(16, 0, 0)) || a.Last != rfc(at(19, 21, 0)) {
		t.Errorf("kept: %d reads from %s to %s, want 32 from day 16 to day 19 21:00", a.Samples, a.First, a.Last)
	}
}
