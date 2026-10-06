package connstore

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"attmonitor/internal/model"
)

// eachDevices returns the reads EachDevices passes on for [from, to), each as its time and the name
// of its first device.
func eachDevices(t *testing.T, s *Store, from, to time.Time) []string {
	t.Helper()
	var got []string
	err := s.EachDevices(context.Background(), from, to, func(at time.Time, devices []model.LANDevice) error {
		name := ""
		if len(devices) > 0 {
			name = devices[0].Name
		}
		got = append(got, rfc(at)+" "+name)
		return nil
	})
	if err != nil {
		t.Fatalf("EachDevices(%s, %s): %v", rfc(from), rfc(to), err)
	}
	return got
}

// TestEachDevices: the Device List read in effect at from - the newest at or before it, else the
// first after it, even one after to - then every later read before to (no end for a zero to),
// oldest first, across days and compressed days. Of reads made at the same time, the one stored
// last is in effect. fn's error and ctx's end it.
func TestEachDevices(t *testing.T) {
	h := newHarness(t, at(3, 12, 0), Options{})
	if got := eachDevices(t, h.s, at(0, 0, 0), at(9, 0, 0)); len(got) != 0 {
		t.Fatalf("an empty store passed on %q", got)
	}
	type read struct {
		at   time.Time
		name string
	}
	reads := []read{
		{at(0, 10, 0), "r0"}, {at(0, 22, 0), "r1"},
		{at(1, 6, 0), "r2"}, {at(1, 6, 0), "r3"}, // the same time: r3 is stored last
		{at(2, 0, 0), "r4"}, {at(3, 9, 0), "r5"},
	}
	for _, r := range reads {
		h.devices(r.at, device(10, 1, r.name, "Ethernet"))
	}
	if !h.exists("devices-2026-10-05.jsonl.gz") || !h.exists("devices-2026-10-08.jsonl") {
		t.Fatal("the past days are not compressed, or today is not plain: the test reads both kinds of file")
	}
	want := func(names ...string) []string {
		var out []string
		for _, n := range names {
			i := slices.IndexFunc(reads, func(r read) bool { return r.name == n })
			out = append(out, rfc(reads[i].at)+" "+n)
		}
		return out
	}
	for _, c := range []struct {
		name     string
		from, to time.Time
		want     []string
	}{
		{"across days", at(1, 0, 0), at(2, 12, 0), want("r1", "r2", "r3", "r4")},
		{"before the first read", at(0, 0, 0), at(0, 23, 0), want("r0", "r1")},
		{"from at a read", at(0, 10, 0), at(0, 12, 0), want("r0")},
		{"to at a read", at(0, 9, 0), at(0, 22, 0), want("r0")},
		{"wholly before the first read", at(-2, 0, 0), at(-1, 0, 0), want("r0")},
		{"after the last read", at(4, 0, 0), at(5, 0, 0), want("r5")},
		{"between reads of the same time", at(1, 12, 0), time.Time{}, want("r3", "r4", "r5")},
		{"from the zero time", time.Time{}, at(0, 12, 0), want("r0")},
	} {
		if got := eachDevices(t, h.s, c.from, c.to); !slices.Equal(got, c.want) {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}

	// The devices passed on are fn's own.
	err := h.s.EachDevices(context.Background(), at(0, 0, 0), at(1, 0, 0), func(_ time.Time, devices []model.LANDevice) error {
		devices[0].Name = "changed"
		return nil
	})
	if got := eachDevices(t, h.s, at(0, 0, 0), at(1, 0, 0)); err != nil || !slices.Equal(got, want("r0", "r1")) {
		t.Errorf("after fn changed its devices: %q (%v)", got, err)
	}

	stop := errors.New("stop")
	n := 0
	err = h.s.EachDevices(context.Background(), at(0, 0, 0), time.Time{}, func(time.Time, []model.LANDevice) error {
		if n++; n == 2 {
			return stop
		}
		return nil
	})
	if !errors.Is(err, stop) || n != 2 {
		t.Errorf("fn's error: %v after %d reads, want it after 2", err, n)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := h.s.EachDevices(ctx, at(0, 0, 0), time.Time{}, func(time.Time, []model.LANDevice) error {
		t.Error("fn called after ctx ended")
		return nil
	}); !errors.Is(err, context.Canceled) {
		t.Errorf("ended ctx: %v", err)
	}

	// After a restart, and after the oldest days were pruned, the reads kept are passed on.
	h.reopen()
	if got := eachDevices(t, h.s, at(1, 0, 0), at(2, 12, 0)); !slices.Equal(got, want("r1", "r2", "r3", "r4")) {
		t.Errorf("after a restart: %q", got)
	}
	h.s.SetRetention(1, DefaultKeepMB)
	h.clk.Set(at(3, 12, 0).Add(2 * time.Hour)) // the age limit applies once the store has been open an hour
	if err := h.s.Prune(time.Time{}); err != nil {
		t.Fatal(err)
	}
	if got := eachDevices(t, h.s, at(0, 0, 0), at(9, 0, 0)); !slices.Equal(got, want("r4", "r5")) {
		t.Errorf("after the days older than a day were pruned: %q", got)
	}
}

// TestEachDevicesDamage: a line that cannot be decoded is skipped, logged once per file, and the
// reads around it are passed on.
func TestEachDevicesDamage(t *testing.T) {
	h := newHarness(t, at(0, 23, 0), Options{})
	h.devices(at(0, 10, 0), device(10, 1, "r0", "Ethernet"))
	if err := h.s.Close(); err != nil {
		t.Fatal(err)
	}
	appendFile(t, h.file("devices-2026-10-05.jsonl"), []byte("{not json\n"))
	h.open()
	h.devices(at(0, 12, 0), device(10, 1, "r2", "Ethernet"))
	for range 2 {
		if got := eachDevices(t, h.s, at(0, 10, 30), at(1, 0, 0)); len(got) != 2 || got[0] != rfc(at(0, 10, 0))+" r0" || got[1] != rfc(at(0, 12, 0))+" r2" {
			t.Fatalf("around a damaged line: %q", got)
		}
	}
	if n := h.log.count("lines that cannot be read were skipped"); n != 1 {
		t.Errorf("the damaged line was logged %d times, want once:\n%s", n, h.log.all())
	}
}
