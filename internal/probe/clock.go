package probe

import (
	"math/bits"
	"time"
)

// Interval measurements (RTTs, durations) use hrNow rather than time.Now/time.Since.
//
// On Windows, Go's monotonic clock reads the kernel's interrupt time, which advances only at
// the system timer tick: 15.625 ms unless some process has raised the timer resolution, and
// Go itself does not. Measured with time.Since, a 2 ms round trip to the gateway would be
// recorded as 0 (then 1 µs) or as one whole tick, which would make the RTT evidence wrong.
// hrNow uses QueryPerformanceCounter there (sub-microsecond resolution). Elsewhere it is
// Go's monotonic clock, which already has nanosecond resolution.

// hrEpoch anchors the fallback clock (time.Since(hrEpoch) is monotonic).
var hrEpoch = time.Now()

// stopwatch measures one interval on the high-resolution monotonic clock.
type stopwatch struct{ start time.Duration }

func startStopwatch() stopwatch { return stopwatch{start: hrNow()} }

// elapsed returns the time since the stopwatch started; never negative.
func (s stopwatch) elapsed() time.Duration { return sinceHR(s.start) }

// sinceHR returns hrNow()-start, clamped at zero.
func sinceHR(start time.Duration) time.Duration {
	if d := hrNow() - start; d > 0 {
		return d
	}
	return 0
}

// ticksToDuration converts a performance-counter reading to a Duration without overflowing
// (ticks*1e9 overflows int64 after about 15 minutes of uptime at 10 MHz).
func ticksToDuration(ticks, freq int64) time.Duration {
	if freq <= 0 {
		return 0
	}
	if ticks < 0 {
		return -ticksToDuration(-ticks, freq)
	}
	sec, rem := ticks/freq, ticks%freq
	// rem < freq, so rem*1e9/freq < 1e9 and the 128-bit division cannot overflow.
	hi, lo := bits.Mul64(uint64(rem), uint64(time.Second))
	ns, _ := bits.Div64(hi, lo, uint64(freq))
	return time.Duration(sec)*time.Second + time.Duration(ns)
}

// micros converts a measured duration to whole microseconds, at least 1 so that a
// measured answer is never mistaken for "no RTT" (the JSON field is omitempty).
func micros(d time.Duration) int64 {
	if us := d.Microseconds(); us > 0 {
		return us
	}
	return 1
}
