package connstore

import (
	"cmp"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"
)

// opPrune names the retention in Usage().Error.
const opPrune = "prune"

// Prune applies the retention limits at now (the zero time: the current time). It deletes whole
// days, oldest first, with every file of the day of both kinds: each day that ended KeepDays
// days or more before now (all its reads are older than that), then, while the files kept take
// more than KeepMB MiB (compressed days at their stored size), the oldest days left. The day of
// now and later days are never deleted. A file that another program holds is deleted later; its
// day leaves the store at once (the error names it until it is deleted). The monitor calls it
// every hour, whether or not it appends (connections.enabled off); the appends call it at most
// once an hour.
//
// The age limit trusts the clock no further than the monotonic clock (see ageTime): it is not
// applied in the first hour after Open, and while the store's clock is more than an hour ahead of
// the time the monotonic clock has measured since the two last agreed - a step forward - it is
// applied as of that time instead of now, for a day at most.
func (s *Store) Prune(now time.Time) error {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	if s.closed {
		return ErrClosed
	}
	err := s.prune(s.when(now))
	s.noteResult(opPrune, err)
	return err
}

// ageDue applies the retention limits once the age limit applies: the timer Open sets runs it
// ageDelay after Open, so that the age limit is applied even when nothing appends or prunes
// (connections.enabled off).
func (s *Store) ageDue() {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	if s.closed {
		return
	}
	s.ageReady = true
	s.noteResult(opPrune, s.prune(s.now()))
}

// clockReading is a reading of the store's clock (its wall time only) and of the monotonic clock,
// taken together.
type clockReading struct {
	wall time.Time
	mono time.Duration
}

// ageTime returns the time as of which a prune at now applies the age limit, and false when it
// applies none (s.wmu held). What the age limit deletes is gone for good, and a clock that is
// wrong makes days look old: Windows' Secure Time Seeding has set clocks months ahead, and a
// single prune would then delete every day kept. So the age limit trusts the store's clock no
// further than the monotonic clock, which nothing sets:
//
//   - It does not apply before the store has been open for ageDelay (Open applies only the size
//     limit): a clock that was wrong when the service started and is corrected meanwhile deletes
//     nothing.
//   - It is applied as of now while the store's clock agrees with the time the monotonic clock
//     has measured since the two last agreed (within aheadTolerance), or is behind it (a step
//     back only deletes less, and is followed at once). When the clock is further ahead (a step
//     forward), the age limit is applied as of the monotonic clock's time instead - the days
//     that are old by it are still deleted - until the clock agrees again (it was set back) or
//     it has stayed ahead for aheadTrust (the step is taken as the correction of a clock that was
//     behind).
//
// A clock that is already wrong when the service starts, and stays wrong for more than ageDelay,
// is not caught: nothing in the store can tell it from a long stop.
func (s *Store) ageTime(now time.Time) (time.Time, bool) {
	m := s.mono()
	wall := s.now().Round(0)
	steady := s.ref.wall.Add(m - s.ref.mono)
	switch ahead := wall.Sub(steady); {
	case ahead <= aheadTolerance:
		if s.ahead {
			s.ahead = false
			s.log.Info("connection store: the clock agrees with the monotonic clock again; the age limit (keep_days) follows it again",
				"time", formatTime(wall))
		}
		s.ref = clockReading{wall: wall, mono: m}
	case !s.ahead:
		s.ahead, s.aheadSince = true, m
		s.log.Warn("connection store: the clock is ahead of the time the monotonic clock has measured (it was set forward); until they agree again, for a day at most, the age limit (keep_days) is applied as of the monotonic clock's time, so that no day is deleted for the step",
			"ahead", ahead.Round(time.Second).String(), "time", formatTime(wall), "applied_as_of", formatTime(steady))
	case m-s.aheadSince >= aheadTrust:
		s.ahead = false
		s.ref = clockReading{wall: wall, mono: m}
		s.log.Warn("connection store: the clock has stayed ahead of the monotonic clock for a day; the age limit (keep_days) follows it again",
			"ahead", ahead.Round(time.Second).String(), "time", formatTime(wall))
	}
	if !s.ageReady {
		if m-s.opened < s.ageDelay {
			return time.Time{}, false
		}
		s.ageReady = true
	}
	if s.ahead {
		return earlier(now, steady), true
	}
	return now, true
}

// prune is Prune (s.wmu held).
func (s *Store) prune(now time.Time) error {
	s.retryPending()
	ageNow, byAge := s.ageTime(now)
	s.mu.Lock()
	s.lastPrune = now
	keepDays, keepMB := s.keepDays, s.keepMB
	limit := int64(keepMB) * s.mib
	bytes := map[day]int64{}
	var total int64
	for k := range numKinds {
		for d, f := range s.files[k] {
			n := max(f.gz, 0) + max(f.plain, 0)
			bytes[d] += n
			total += n
		}
	}
	s.mu.Unlock()
	days := make([]day, 0, len(bytes))
	for d := range bytes {
		days = append(days, d)
	}
	slices.SortFunc(days, func(a, b day) int { return cmp.Compare(a, b) })
	today := dayOf(now)
	var cutoff time.Time
	if byAge {
		cutoff = ageNow.Add(-time.Duration(keepDays) * 24 * time.Hour)
	}
	deleted := false
	for _, d := range days {
		if d >= today {
			break
		}
		old := byAge && !d.end().After(cutoff)
		if !old && total <= limit {
			break
		}
		why := "keep_mb " + strconv.Itoa(keepMB)
		if old {
			why = "keep_days " + strconv.Itoa(keepDays)
		}
		s.deleteDay(d, bytes[d], why)
		total -= bytes[d]
		deleted = true
	}
	if deleted {
		s.refreshOldest()
	}
	if len(s.pending) > 0 {
		return fmt.Errorf("connstore: %d deleted file(s) are in use and are deleted later: %s", len(s.pending), strings.Join(s.pending, ", "))
	}
	return nil
}

// deleteDay deletes the files of both kinds of day d (bytes of them, beyond the limit why). Its
// files leave the index at once; one that another program holds is deleted later (s.wmu held).
func (s *Store) deleteDay(d day, bytes int64, why string) {
	for k := range numKinds {
		f, ok := s.entry(k, d)
		if !ok {
			continue
		}
		if w := s.w[k]; w != nil && w.day == d {
			if err := w.close(); err != nil {
				s.log.Warn("connection store: closing a day's file failed", "file", w.name, "err", err)
			}
			s.w[k] = nil
		}
		for _, gz := range [...]bool{true, false} {
			if gz && f.gz < 0 || !gz && f.plain < 0 {
				continue
			}
			s.deleteLater(s.path(k, d, gz))
		}
		s.mu.Lock()
		delete(s.files[k], d)
		delete(s.retryAt, fileKey{kind: k, day: d})
		delete(s.failures, opCompress(k, d))
		s.forgetWarnings(k, d)
		s.mu.Unlock()
		s.dropCached(k, d)
	}
	s.log.Info("connection store: deleted a day beyond the retention limits", "day", d.String(), "bytes", bytes, "limit", why)
}

// refreshOldest finds the time of the oldest read kept again, after days were deleted (s.wmu
// held).
func (s *Store) refreshOldest() {
	oldest := s.edgeTime(true)
	s.mu.Lock()
	s.oldest = oldest
	if oldest.IsZero() {
		s.newest = time.Time{}
	}
	s.mu.Unlock()
}
