package connstore

import (
	"cmp"
	"context"
	"slices"
	"time"

	"attmonitor/internal/model"
)

// timedDevices is one Device List read as EachDevices passes it on.
type timedDevices struct {
	t       time.Time
	devices []model.LANDevice
}

// EachDevices calls fn, oldest first, with the Device List read in effect at from - the newest
// made at or before it, else the first made after it - and then with every later read made
// before to (a zero to: every later read), each with the time it was made. The firewall view of
// the Network page (internal/netmap) names the LAN address of each packet the gateway's firewall
// dropped after the read in effect when the packet was received, as Aggregate names the LAN
// addresses of each NAT read: a device whose address DHCP gave to another one is not blamed for
// the other's packets.
//
// It is a reader: it works from a snapshot of the index and never waits for the writer, and it
// holds one day's reads at a time. Lines that cannot be decoded are skipped, and so is a day that
// cannot be read (logged once per file). It returns fn's error, which ends it, or ctx's, checked
// between days and every few lines. The devices passed to fn are fn's own.
func (s *Store) EachDevices(ctx context.Context, from, to time.Time, fn func(at time.Time, devices []model.LANDevice) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	days := s.snapshot().days[kindDevices] // oldest first
	fd := dayOf(from)
	// first is the first day on or after from's day; onFD says whether it is from's day, whose
	// reads both passes below need (read once: fdReads).
	first, onFD := slices.BinarySearchFunc(days, fd, func(e dayEntry, d day) int { return cmp.Compare(e.day, d) })
	var fdReads []timedDevices

	// The read in effect at from: the newest at or before it, on from's day or an earlier one.
	var effect *timedDevices
	last := first - 1
	if onFD {
		last = first
	}
	for i := last; i >= 0 && effect == nil; i-- {
		rs, err := s.readDevicesDay(ctx, days[i].day)
		if err != nil {
			return err
		}
		if onFD && i == first {
			fdReads = rs
		}
		for j := len(rs) - 1; j >= 0; j-- {
			if !rs[j].t.After(from) {
				effect = &rs[j]
				break
			}
		}
	}
	if effect != nil {
		if err := fn(effect.t, effect.devices); err != nil {
			return err
		}
	}

	// The reads after from: the first of them is the one in effect at from when none was made at
	// or before it (whenever it was made); the others count up to to.
	for i := first; i < len(days); i++ {
		d := days[i].day
		if effect != nil && !to.IsZero() && !d.start().Before(to) {
			return nil
		}
		rs := fdReads
		if !onFD || i != first {
			var err error
			if rs, err = s.readDevicesDay(ctx, d); err != nil {
				return err
			}
		}
		for j := range rs {
			r := &rs[j]
			switch {
			case !r.t.After(from):
				continue
			case effect == nil:
				effect = r
			case !to.IsZero() && !r.t.Before(to):
				return nil
			}
			if err := fn(r.t, r.devices); err != nil {
				return err
			}
		}
	}
	return nil
}

// readDevicesDay returns the Device List reads of day d for EachDevices (devicesOfDay): a day
// that cannot be read is logged once and has none; only ctx's error is returned.
func (s *Store) readDevicesDay(ctx context.Context, d day) ([]timedDevices, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	rs, err := s.devicesOfDay(ctx, d)
	if err != nil {
		if cerr := ctx.Err(); cerr != nil {
			return nil, cerr
		}
		s.warnOnce(fileName(kindDevices, d, false), "connection store: a day of Device List reads cannot be read; its devices are not named", "err", err)
		return nil, nil
	}
	return rs, nil
}

// devicesOfDay reads the Device List reads of day d, oldest first (reads of the same time in the
// order of the files). Lines that cannot be decoded, and reads of another day, are skipped and
// logged once per file; nil when the store no longer has the day. ctx is checked every few lines.
func (s *Store) devicesOfDay(ctx context.Context, d day) ([]timedDevices, error) {
	r, err := s.openDay(kindDevices, d)
	if err != nil || r == nil {
		return nil, err
	}
	defer r.close()
	var reads []timedDevices
	n, bad, foreign := 0, 0, 0
	damage, stop := r.each(func(line []byte) error {
		if n++; n%ctxEvery == 0 {
			if err := ctx.Err(); err != nil {
				return err
			}
		}
		t, devices, err := decodeDevices(line)
		switch {
		case line == nil || err != nil:
			bad++
		case dayOf(t) != d:
			foreign++
		default:
			reads = append(reads, timedDevices{t: t, devices: devices})
		}
		return nil
	})
	if stop != nil {
		return nil, stop
	}
	s.noteReadProblems(kindDevices, d, damage, bad, 0, foreign)
	slices.SortStableFunc(reads, func(a, b timedDevices) int { return a.t.Compare(b.t) })
	return reads, nil
}
