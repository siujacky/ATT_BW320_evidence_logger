package probe

import (
	"math"
	"testing"
	"time"
)

func TestTicksToDuration(t *testing.T) {
	tests := []struct {
		ticks, freq int64
		want        time.Duration
	}{
		{0, 10_000_000, 0},
		{1, 10_000_000, 100 * time.Nanosecond},
		{10_000_000, 10_000_000, time.Second},
		{15_000_000, 10_000_000, 1500 * time.Millisecond},
		{3, 3_000_000_000, time.Nanosecond}, // TSC-like frequency: 1 ns per 3 ticks
		{-10_000_000, 10_000_000, -time.Second},
		{5, 0, 0},  // unusable frequency
		{5, -1, 0}, // unusable frequency
		// One year of uptime at 10 MHz: ticks*1e9 would overflow int64.
		{365 * 24 * 3600 * 10_000_000, 10_000_000, 365 * 24 * time.Hour},
		// A frequency above 9.2 GHz with a remainder close to it: rem*1e9 overflows int64,
		// so only a 128-bit intermediate gives the exact 999999999 ns.
		{2*9_999_999_967 - 1, 9_999_999_967, time.Second + 999_999_999},
	}
	for _, tt := range tests {
		if got := ticksToDuration(tt.ticks, tt.freq); got != tt.want {
			t.Errorf("ticksToDuration(%d, %d) = %v, want %v", tt.ticks, tt.freq, got, tt.want)
		}
	}
}

// TestHRClockResolution guards the evidence-critical property that RTTs are measured with
// sub-millisecond resolution. Go's own monotonic clock on Windows only advances at the
// system timer tick (0.5–15.6 ms), so a 2 ms gateway RTT measured with time.Since is
// recorded as 0 µs or as a whole tick.
func TestHRClockResolution(t *testing.T) {
	var minStep time.Duration = math.MaxInt64
	prev := hrNow()
	steps := 0
	for deadline := time.Now().Add(2 * time.Second); steps < 1000 && time.Now().Before(deadline); {
		now := hrNow()
		if now < prev {
			t.Fatalf("hrNow went backwards: %v -> %v", prev, now)
		}
		if d := now - prev; d > 0 {
			minStep = min(minStep, d)
			steps++
		}
		prev = now
	}
	if steps == 0 {
		t.Fatal("hrNow never advanced")
	}
	if minStep > 50*time.Microsecond {
		t.Fatalf("hrNow resolution is %v; RTTs need sub-millisecond resolution", minStep)
	}
}

func TestHRClockTracksRealTime(t *testing.T) {
	sw := startStopwatch()
	start := time.Now()
	time.Sleep(60 * time.Millisecond)
	got, ref := sw.elapsed(), time.Since(start)
	// The reference itself may be off by one coarse tick (≤ 15.6 ms) on Windows.
	if d := got - ref; d < -20*time.Millisecond || d > 20*time.Millisecond {
		t.Fatalf("stopwatch %v vs time.Since %v", got, ref)
	}
	if got < 50*time.Millisecond {
		t.Fatalf("stopwatch measured %v for a 60 ms sleep", got)
	}
	if sinceHR(hrNow()+time.Hour) != 0 {
		t.Fatal("sinceHR must clamp a start in the future to 0")
	}
}

func TestPreciseWallNow(t *testing.T) {
	a := preciseWallNow()
	b := time.Now()
	if a.Location() != time.UTC {
		t.Errorf("location %v, want UTC", a.Location())
	}
	if a != a.Round(0) {
		t.Error("preciseWallNow must not carry a monotonic reading")
	}
	if d := b.Sub(a); d < -20*time.Millisecond || d > 20*time.Millisecond {
		t.Fatalf("preciseWallNow %v differs from time.Now %v by %v", a, b, d)
	}
}

func TestMicros(t *testing.T) {
	for d, want := range map[time.Duration]int64{0: 1, time.Nanosecond: 1, 999: 1, time.Microsecond: 1,
		1500 * time.Microsecond: 1500, 2 * time.Second: 2_000_000, -time.Second: 1} {
		if got := micros(d); got != want {
			t.Errorf("micros(%v) = %d, want %d", d, got, want)
		}
	}
}
