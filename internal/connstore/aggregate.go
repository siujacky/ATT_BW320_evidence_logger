package connstore

import (
	"context"
	"time"

	"attmonitor/internal/contracts"
	"attmonitor/internal/model"
)

// ctxEvery is how many lines a scan reads between two checks of its context (a NAT line of a
// few hundred sessions takes about a tenth of a millisecond).
const ctxEvery = 16

// sumKey is the cache key of a day's summary: the stamps of the day's NAT files.
type sumKey struct {
	day       day
	gz, plain fileStamp
}

func (k sumKey) keyDay() day { return k.day }

// sumEntry is a cached summary of a whole day, with the fingerprint of the Device List reads
// that named its addresses.
type sumEntry struct {
	fp  uint64
	sum *summary
}

// Aggregate summarizes the NAT reads made in [q.From, q.To) (a zero From: from the oldest kept;
// a zero To: to the newest) by device and by flow - (device, remote address, port, protocol,
// direction). Each LAN address of a NAT read is named after the Device List read in effect: the
// newest at or before it, else the first after it - or, when that read does not list the address,
// the next read within devNextWithin (a device that has just joined). With q.Device, Devices and
// Flows hold that device only; Samples, First, Last and the newest read's totals stay those of
// every read. At most maxFlows flows are counted one by one, the heaviest: should the period hold
// more, the lightest are left out (FlowsLeftOut; their sessions count in their device's weight
// and LeftOut).
//
// Its work is bounded: a whole past UTC day inside the period comes from a cache of day
// summaries (keyed by the day's file names, sizes and modification times, and the Device List
// reads that named it), so only the days the period covers partly, and today, are read line by
// line - the lines outside the period are skipped without being decoded. When the period has
// more whole days than the cache holds, the cache keeps the newest (dayCache) and the others are
// read again. ctx is checked between days, every ctxEvery lines and every mergeEvery flows merged
// or written out. A day that cannot be read is logged and left out; damaged lines and sessions
// are skipped (logged once per file).
func (s *Store) Aggregate(ctx context.Context, q contracts.ConnQuery) (model.ConnAggregate, error) {
	if err := ctx.Err(); err != nil {
		return model.ConnAggregate{}, err
	}
	out := model.ConnAggregate{InUse: -1, Available: -1, Devices: []model.ConnDevice{}, Flows: []model.ConnFlow{}}
	from, to := q.From, q.To
	if !from.IsZero() {
		out.From = formatTime(from)
	}
	if !to.IsZero() {
		out.To = formatTime(to)
	}
	if from.Before(minTime) {
		from = minTime
	}
	if to.IsZero() || to.After(maxTime) {
		to = maxTime
	}
	if !from.Before(to) {
		return out, nil
	}
	sn := s.snapshot()
	v := newDevView(s, sn)
	m := newMerger(q.Device, s.maxFlows)
	for _, e := range sn.days[kindNAT] {
		d := e.day
		if !d.end().After(from) || !d.start().Before(to) {
			continue
		}
		if err := ctx.Err(); err != nil {
			return model.ConnAggregate{}, err
		}
		var sum *summary
		var err error
		if !d.start().Before(from) && !d.end().After(to) && d < sn.today {
			sum, err = s.daySummary(ctx, v, d)
		} else {
			s.stats.rawDays.Add(1)
			sum, _, err = s.scanDay(ctx, d, v.segment(d), later(from, d.start()), earlier(to, d.end()))
		}
		if err != nil {
			if cerr := ctx.Err(); cerr != nil {
				return model.ConnAggregate{}, cerr
			}
			s.warnOnce(fileName(kindNAT, d, e.gz >= 0), "connection store: a day of NAT table reads cannot be read; it is left out", "err", err)
			continue
		}
		if err := m.add(ctx, sum); err != nil {
			return model.ConnAggregate{}, err
		}
	}
	return m.result(ctx, out)
}

// daySummary returns the summary of the whole past day d: from the cache when the day's files
// and the Device List reads that name its addresses are the ones it was computed from, else
// computed (and cached, unless the cache is full of later days: see dayCache).
func (s *Store) daySummary(ctx context.Context, v *devView, d day) (*summary, error) {
	sg := v.segment(d)
	if gz, plain, ok := s.dayStamps(kindNAT, d); ok {
		if e, hit := s.sums.get(sumKey{day: d, gz: gz, plain: plain}); hit && e.fp == sg.fp {
			s.stats.sumHits.Add(1)
			return e.sum, nil
		}
	}
	s.stats.sumMisses.Add(1)
	sum, key, err := s.scanDay(ctx, d, sg, d.start(), d.end())
	if err != nil || sum == nil {
		return sum, err
	}
	s.sums.removeIf(func(k sumKey) bool { return k.day == d }) // an older version of the day
	s.sums.put(key, &sumEntry{fp: sg.fp, sum: sum}, sum.weight())
	return sum, nil
}

// scanDay reads the NAT reads of day d made in [lo, hi), naming their LAN addresses after the
// Device List reads of sg, and returns their summary (nil when the store no longer has the day)
// and the key of the files it read.
func (s *Store) scanDay(ctx context.Context, d day, sg *segment, lo, hi time.Time) (*summary, sumKey, error) {
	r, err := s.openDay(kindNAT, d)
	if err != nil || r == nil {
		return nil, sumKey{}, err
	}
	defer r.close()
	key := sumKey{day: d, gz: r.gzStamp, plain: r.plainStamp}
	sc := newScanner(s.maxFlows)
	sc.gateway = s.gateway
	n, badLines, badSessions, foreign := 0, 0, 0, 0
	damage, stop := r.each(func(line []byte) error {
		if n++; n%ctxEvery == 0 {
			if err := ctx.Err(); err != nil {
				return err
			}
		}
		if t, ok := peekTime(line); ok && (t.Before(lo) || !t.Before(hi)) {
			if dayOf(t) != d {
				foreign++
			}
			return nil
		}
		if line == nil {
			badLines++
			return nil
		}
		t, err := decodeNAT(line, &sc.line)
		switch {
		case err != nil:
			badLines++
			return nil
		case dayOf(t) != d:
			foreign++
			return nil
		case t.Before(lo) || !t.Before(hi):
			return nil
		}
		ns := t.UnixNano()
		badSessions += sc.add(ns, sg.at(ns), sg.after(ns))
		return nil
	})
	if stop != nil {
		return nil, key, stop
	}
	s.stats.lines.Add(int64(sc.read))
	s.noteReadProblems(kindNAT, d, damage, badLines, badSessions, foreign)
	return sc.finish(), key, nil
}

// noteReadProblems logs, once per file, what a reader of the day d of kind k could not read:
// a damaged file (the lines before the damage were read), lines that do not decode, sessions
// that do not (an index outside the line's string table, an address that does not parse), and
// reads of another day (a file edited by hand: every read the store writes goes to its own
// day's file).
func (s *Store) noteReadProblems(k kind, d day, damage error, badLines, badSessions, foreign int) {
	name := fileName(k, d, false)
	if damage != nil {
		s.warnOnce(name, "connection store: a file cannot be read to its end; the reads before the damage were used", "err", damage)
	}
	if badLines > 0 {
		s.warnOnce(name, "connection store: lines that cannot be read were skipped", "lines", badLines)
	}
	if badSessions > 0 {
		s.warnOnce(name, "connection store: NAT sessions that cannot be read were skipped", "sessions", badSessions)
	}
	if foreign > 0 {
		s.warnOnce(name, "connection store: reads of another day were skipped", "lines", foreign)
	}
}

// later returns the later of two times; earlier the earlier.
func later(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

func earlier(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
