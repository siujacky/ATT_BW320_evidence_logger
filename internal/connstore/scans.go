package connstore

import (
	"cmp"
	"context"
	"errors"
	"slices"
	"time"

	"attmonitor/internal/contracts"
	"attmonitor/internal/model"
)

// The LAN scans (docs/dhcp-table.md §6, contracts.ScanStore): the monitor's sweeps of the home
// network by ARP, one line each in scan-YYYY-MM-DD.jsonl - written, compressed, repaired and
// deleted with the other kinds' files, by the same rules and the same retention limits. A day holds
// a few dozen lines of a few KiB: they are read as they are, without a cache.

// timedScan is one LAN scan as EachScan passes it on.
type timedScan struct {
	t    time.Time
	scan model.LANScan
}

// EachScan calls fn, oldest first, with each LAN scan kept that began in [from, to) - a zero to:
// every later one - as it was appended (its At is when it began). Scans of the same time come in
// the order they were stored. Returning contracts.ErrStop from fn ends it with a nil error; any
// other error of fn ends it with that error, and so does ctx's (checked between days and every few
// lines).
//
// It is a reader like EachDevices: it works from a snapshot of the index and never waits for the
// writer, and holds one day's scans at a time. Lines that cannot be decoded are skipped, and so is
// a day that cannot be read (logged once per file). The scans passed to fn are fn's own.
func (s *Store) EachScan(ctx context.Context, from, to time.Time, fn func(scan model.LANScan) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	for _, e := range s.snapshot().days[kindScan] { // oldest first
		if !to.IsZero() && !e.day.start().Before(to) {
			return nil
		}
		if !e.day.end().After(from) {
			continue // every scan of the day began before from
		}
		scans, err := s.readScanDay(ctx, e.day, from, to)
		if err != nil {
			return err
		}
		for _, sc := range scans {
			if err := fn(sc.scan); err != nil {
				if errors.Is(err, contracts.ErrStop) {
					return nil
				}
				return err
			}
		}
	}
	return nil
}

// readScanDay returns the LAN scans of day d that began in [from, to) (a zero to: no end) for
// EachScan (scansOfDay): a day that cannot be read is logged once and has none; only ctx's error is
// returned.
func (s *Store) readScanDay(ctx context.Context, d day, from, to time.Time) ([]timedScan, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	scans, err := s.scansOfDay(ctx, d, from, to)
	if err != nil {
		if cerr := ctx.Err(); cerr != nil {
			return nil, cerr
		}
		s.warnOnce(fileName(kindScan, d, false), "connection store: a day of LAN scans cannot be read; its scans are left out", "err", err)
		return nil, nil
	}
	return scans, nil
}

// scansOfDay reads the LAN scans of day d that began in [from, to) (a zero to: no end), oldest
// first (scans of the same time in the order of the files); the lines outside the period are
// skipped without being decoded. Lines that cannot be decoded, and scans of another day, are
// skipped and logged once per file; nil when the store no longer has the day. ctx is checked every
// few lines.
func (s *Store) scansOfDay(ctx context.Context, d day, from, to time.Time) ([]timedScan, error) {
	r, err := s.openDay(kindScan, d)
	if err != nil || r == nil {
		return nil, err
	}
	defer r.close()
	in := func(t time.Time) bool { return !t.Before(from) && (to.IsZero() || t.Before(to)) }
	var scans []timedScan
	n, bad, foreign := 0, 0, 0
	damage, stop := r.each(func(line []byte) error {
		if n++; n%ctxEvery == 0 {
			if err := ctx.Err(); err != nil {
				return err
			}
		}
		if t, ok := peekTime(line); ok && dayOf(t) == d && !in(t) {
			return nil
		}
		t, scan, err := decodeScan(line)
		switch {
		case line == nil || err != nil:
			bad++
		case dayOf(t) != d:
			foreign++
		case in(t):
			scans = append(scans, timedScan{t: t, scan: scan})
		}
		return nil
	})
	if stop != nil {
		return nil, stop
	}
	s.noteReadProblems(kindScan, d, damage, bad, 0, foreign)
	slices.SortStableFunc(scans, func(a, b timedScan) int { return a.t.Compare(b.t) })
	return scans, nil
}

// loadLastScan loads the newest LAN scan (LastScan): the scan with the newest time of the newest
// day up to today that has a scan that can be decoded - of a later day only when no day up to
// today has one (the clock is behind now), as loadDevices chooses the Device List read. Open calls
// it holding s.wmu, and so does a prune that deleted the day of the newest scan.
func (s *Store) loadLastScan(today day) {
	s.mu.Lock()
	days := make([]day, 0, len(s.files[kindScan]))
	for d := range s.files[kindScan] {
		days = append(days, d)
	}
	s.mu.Unlock()
	// Today and the days before it, the newest first; then the later days, the newest first.
	slices.SortFunc(days, func(a, b day) int {
		if (a > today) != (b > today) {
			if a > today {
				return 1
			}
			return -1
		}
		return cmp.Compare(b, a)
	})
	for _, d := range days {
		r, err := s.openDay(kindScan, d)
		if err != nil || r == nil {
			if err != nil {
				s.log.Warn("connection store: a day of LAN scans cannot be read", "file", fileName(kindScan, d, false), "err", err)
			}
			continue
		}
		var best model.LANScan
		var bestT time.Time
		found, bad := false, 0
		damage, _ := r.each(func(line []byte) error {
			t, scan, err := decodeScan(line)
			switch {
			case line == nil || err != nil:
				bad++
			case dayOf(t) == d && (!found || !t.Before(bestT)):
				best, bestT, found = scan, t, true
			}
			return nil
		})
		r.close()
		s.noteReadProblems(kindScan, d, damage, bad, 0, 0)
		if found {
			s.mu.Lock()
			s.lastScan, s.lastScanAt, s.hasScan = best, bestT, true
			s.mu.Unlock()
			return
		}
	}
}
