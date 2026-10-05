package mongostore

import (
	"testing"
	"time"
)

func TestBackoffDelay(t *testing.T) {
	cases := []struct {
		base time.Duration
		n    int
		want time.Duration
	}{
		{5 * time.Second, 1, 5 * time.Second},
		{5 * time.Second, 2, 10 * time.Second},
		{5 * time.Second, 3, 20 * time.Second},
		{5 * time.Second, 4, 40 * time.Second},
		{5 * time.Second, 5, time.Minute},
		{5 * time.Second, 1000, time.Minute},
		{time.Millisecond, 1 << 30, time.Minute}, // no overflow
		{10 * time.Minute, 1, 10 * time.Minute},  // an Interval above the cap is used as is
		{10 * time.Minute, 50, 10 * time.Minute},
		{0, 1, defaultInterval},
	}
	for _, c := range cases {
		if got := backoffDelay(c.base, c.n); got != c.want {
			t.Errorf("backoffDelay(%v, %d) = %v, want %v", c.base, c.n, got, c.want)
		}
	}
	prev := time.Duration(0)
	for n := 1; n < 100; n++ {
		d := backoffDelay(time.Second, n)
		if d < prev || d > time.Minute {
			t.Fatalf("backoffDelay(1s, %d) = %v after %v", n, d, prev)
		}
		prev = d
	}
}

func TestLogGate(t *testing.T) {
	var g logGate
	t0 := time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC)
	step := func(state string, at time.Duration, repeat, want bool, wantSuppressed int) {
		t.Helper()
		ok, n := g.allow(state, t0.Add(at), repeat)
		if ok != want || (ok && n != wantSuppressed) {
			t.Fatalf("allow(%q, +%v) = %v, %d; want %v, %d", state, at, ok, n, want, wantSuppressed)
		}
	}
	step("down", 0, true, true, 0)                       // first entry
	step("down", time.Minute, true, false, 0)            // same state: suppressed
	step("down", 59*time.Minute, true, false, 0)         // still within the hour
	step("down", 61*time.Minute, true, true, 2)          // hourly reminder, two suppressed
	step("ok", 62*time.Minute, false, true, 0)           // state change
	step("ok", 5*time.Hour, false, false, 0)             // no reminders for a good state
	step("down", 5*time.Hour+time.Second, true, true, 0) // change again
	step("down", 4*time.Hour, true, true, 0)             // clock set back: not muted
	step("down", 4*time.Hour+time.Second, true, false, 0)
}
