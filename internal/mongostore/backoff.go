package mongostore

import "time"

// maxBackoff caps the pause between attempts while synchronization fails (an Interval longer than
// this is used as is).
const maxBackoff = time.Minute

// remindEvery is the minimum time between two log entries for the same failure state.
const remindEvery = time.Hour

// backoffDelay returns the pause after the n-th consecutive failed attempt (n >= 1): base, doubled
// for every further failure, capped at max(base, maxBackoff).
func backoffDelay(base time.Duration, n int) time.Duration {
	if base <= 0 {
		base = defaultInterval
	}
	limit := max(base, maxBackoff)
	d := base
	for i := 1; i < n && d < limit; i++ {
		d *= 2
	}
	return min(d, limit)
}

// logGate limits log entries to one per state change, plus (when repeat is set) a reminder at
// most once per remindEvery while the state persists.
type logGate struct {
	state      string
	at         time.Time
	suppressed int
}

// allow reports whether an entry for state may be logged now, and how many entries for the
// state were suppressed since the last one.
func (g *logGate) allow(state string, now time.Time, repeat bool) (bool, int) {
	switch {
	case state != g.state || g.at.IsZero():
	case repeat && (now.Sub(g.at) >= remindEvery || now.Before(g.at)): // a clock set back must not mute the log
	default:
		g.suppressed++
		return false, 0
	}
	n := g.suppressed
	if state != g.state {
		n = 0
	}
	g.state, g.at, g.suppressed = state, now, 0
	return true, n
}
