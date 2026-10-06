package connstore

import (
	"cmp"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"slices"
	"time"

	"attmonitor/internal/model"
)

// Open opens the store in dir (config.Paths.Connections), creating the directory when it does
// not exist. Only one Store may write a directory at a time: the monitor's (its ledger lock
// keeps a second one away). Open completes what a previous run left undone:
//
//   - a compressed copy whose writing was interrupted (<name>.jsonl.gz.tmp) is deleted: the
//     plain file it was being made from is still there;
//   - the incomplete last line of a plain file - a write a crash cut short - is cut off (logged
//     with its size);
//   - a plain file whose lines the day's compressed file ends with already (a crash between the
//     compressed file's rename and the plain file's deletion) is deleted; one with reads the
//     compressed file lacks (stored after the day was compressed, the clock having been set
//     back) is kept, and both are read until the next compression merges them.
//
// It then loads the newest Device List read (Devices) and finds the oldest and the newest read
// kept (Usage), and returns. The rest goes on in the background (settle), so that the service's
// start - and with it the evidence collection - never waits for it: the plain files of the days
// before today are compressed (seconds for a busy day: read, gzip, checked, fsynced) and the size
// limit (keep_mb) is applied; the writing methods wait for it, the readers read the files as the
// index lists them meanwhile (a plain day is read like a compressed one), and Close waits for it.
// The age limit (keep_days) waits until the store has been open for an hour (see Prune): Open sets
// a timer that applies it then, unless an append or Prune does first. Reads of a day after today
// (the clock was ahead when they were stored, or is behind now) are logged; they are kept. A
// damaged line is never fatal: it is skipped, and logged, when it is read. Files whose names are
// not the store's own are never touched.
func Open(dir string, opts Options) (*Store, error) {
	if dir == "" {
		return nil, errors.New("connstore: a directory is required")
	}
	if opts.KeepDays == 0 {
		opts.KeepDays = DefaultKeepDays
	}
	if opts.KeepMB == 0 {
		opts.KeepMB = DefaultKeepMB
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.DiscardHandler)
	}
	if opts.mono == nil {
		start := time.Now()
		opts.mono = func() time.Duration { return time.Since(start) }
	}
	if opts.ageDelay <= 0 {
		opts.ageDelay = ageDelay
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("connstore: %w", err)
	}
	s := &Store{
		dir:      dir,
		log:      opts.Logger,
		now:      opts.Now,
		retryAt:  map[fileKey]time.Time{},
		mib:      1 << 20,
		failures: map[string]failure{},
		warned:   map[string]bool{},
		sums:     newDayCache[sumKey, *sumEntry](summaryDays, summaryWeight),
		devs:     newDayCache[devKey, []*devRead](deviceDays, deviceDays),
		mono:     opts.mono,
		ageDelay: opts.ageDelay,
		maxFlows: maxFlows,
	}
	s.keepDays, s.keepMB = clampRetention(opts.KeepDays, opts.KeepMB)
	for k := range numKinds {
		s.files[k] = map[day]*dayFiles{}
	}
	s.opened = s.mono()
	s.ref = clockReading{wall: s.now().Round(0), mono: s.opened}
	s.wmu.Lock()
	defer s.wmu.Unlock()
	if err := s.load(); err != nil {
		return nil, err
	}
	s.settled = make(chan struct{})
	go s.settle(opts.settleStart)
	s.ageTimer = time.AfterFunc(s.ageDelay, s.ageDue)
	return s, nil
}

// settle does in the background what Open leaves (see Open): it compresses the plain files of the
// days before today and applies the size limit, holding wmu - the appends, Prune and Close wait for
// it - unless the store was closed first. start, when not nil, is called first, holding wmu (tests).
func (s *Store) settle(start func()) {
	defer close(s.settled)
	s.wmu.Lock()
	defer s.wmu.Unlock()
	if start != nil {
		start()
	}
	if s.closed {
		return
	}
	s.compressBefore(dayOf(s.now()), true)
	s.noteResult(opPrune, s.prune(s.now())) // the size limit only: see ageTime
}

// load indexes the directory and completes what a previous run left undone (see Open; s.wmu
// held).
func (s *Store) load() error {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return fmt.Errorf("connstore: %w", err)
	}
	type forms struct{ gz, plain bool }
	found := map[fileKey]*forms{}
	for _, e := range entries {
		if !e.Type().IsRegular() {
			continue
		}
		p, ok := parseFileName(e.Name())
		if !ok {
			continue
		}
		if p.tmp {
			if err := removeFile(s.path(p.kind, p.day, true) + tmpExt); err != nil {
				s.log.Warn("connection store: could not delete a compressed copy whose writing was interrupted", "file", e.Name(), "err", err)
			} else {
				s.log.Info("connection store: deleted a compressed copy whose writing was interrupted", "file", e.Name())
			}
			continue
		}
		key := fileKey{kind: p.kind, day: p.day}
		f := found[key]
		if f == nil {
			f = &forms{}
			found[key] = f
		}
		if p.gz {
			f.gz = true
		} else {
			f.plain = true
		}
	}
	keys := make([]fileKey, 0, len(found))
	for k := range found {
		keys = append(keys, k)
	}
	slices.SortFunc(keys, func(a, b fileKey) int {
		if c := cmp.Compare(a.kind, b.kind); c != 0 {
			return c
		}
		return cmp.Compare(a.day, b.day)
	})
	for _, key := range keys {
		f := found[key]
		e := &dayFiles{gz: -1, plain: -1}
		if f.gz {
			st, err := os.Stat(s.path(key.kind, key.day, true))
			if err != nil {
				s.log.Warn("connection store: a compressed day cannot be read; it is left out", "file", fileName(key.kind, key.day, true), "err", err)
			} else {
				e.gz = st.Size()
			}
		}
		if f.plain {
			if size, err := s.repairPlain(key.kind, key.day); err != nil {
				s.log.Warn("connection store: a day's file cannot be read; it is left out", "file", fileName(key.kind, key.day, false), "err", err)
			} else {
				e.plain = size
			}
		}
		if e.gz < 0 && e.plain < 0 {
			continue
		}
		s.files[key.kind][key.day] = e
		if e.gz >= 0 && e.plain >= 0 {
			s.settleBoth(key.kind, key.day, e)
		}
	}
	today := dayOf(s.now())
	s.warnLaterDays(today)
	s.loadDevices(today)
	oldest, newest := s.edgeTime(true), s.edgeTime(false)
	s.mu.Lock()
	s.oldest, s.newest = oldest, newest
	s.mu.Unlock()
	return nil
}

// warnLaterDays logs the latest day after today that has reads, if any: the clock was ahead when
// they were stored (or is behind now). They are kept, and are the newest reads until that day
// comes; the retention limits never delete today or a later day (s.wmu held).
func (s *Store) warnLaterDays(today day) {
	latest := today
	for k := range numKinds {
		for d := range s.files[k] {
			latest = max(latest, d)
		}
	}
	if latest > today {
		s.log.Warn("connection store: there are reads of a day after today (the clock was ahead when they were stored, or is behind now); they are kept, and are the newest until that day comes",
			"day", latest.String(), "today", today.String())
	}
}

// repairPlain cuts off the incomplete last line of the plain file of kind k and day d, if it
// has one, and returns the size of its complete lines. When another program holds the file, the
// line stays (the writer cuts it off before it appends) and is not read (s.wmu held).
func (s *Store) repairPlain(k kind, d day) (int64, error) {
	name := fileName(k, d, false)
	path := s.path(k, d, false)
	f, err := openWriter(path)
	if err != nil {
		r, rerr := openShared(path)
		if rerr != nil {
			return 0, err
		}
		defer r.Close()
		size, cut, cerr := completeLines(r)
		if cerr != nil {
			return 0, cerr
		}
		if cut > 0 {
			s.log.Warn("connection store: a day's file ends with an incomplete line (a write a crash cut short); it is in use and the line is left out",
				"file", name, "bytes", cut, "err", err)
		}
		return size, nil
	}
	defer f.Close()
	size, cut, err := completeLines(f)
	if err != nil {
		return 0, err
	}
	if cut > 0 {
		err := f.Truncate(size)
		if err == nil {
			err = f.Sync()
		}
		if err != nil {
			s.log.Warn("connection store: could not cut off the incomplete last line of a day's file; it is left out",
				"file", name, "bytes", cut, "err", err)
		} else {
			s.log.Warn("connection store: cut off the incomplete last line of a day's file (a write a crash interrupted)",
				"file", name, "bytes", cut)
		}
	}
	return size, nil
}

// settleBoth handles a day of kind k that has both a compressed and a plain file (e, its index
// entry): see Open (s.wmu held).
func (s *Store) settleBoth(k kind, d day, e *dayFiles) {
	plainPath := s.path(k, d, false)
	done, err := gzipEndsWith(s.path(k, d, true), plainPath, e.plain)
	switch {
	case err != nil:
		s.log.Warn("connection store: a day has a compressed and a plain file that cannot be compared; both are read",
			"file", fileName(k, d, false), "err", err)
	case done:
		s.deleteLater(plainPath)
		e.plain = -1
		s.log.Info("connection store: deleted a day's plain file that had been compressed already (an interrupted compression)",
			"file", fileName(k, d, false))
	default:
		s.log.Info("connection store: a compressed day has later reads in a plain file; they are merged when the day is compressed again",
			"file", fileName(k, d, false))
	}
}

// loadDevices loads the newest Device List read: the read with the newest time of the newest
// day up to today that has a read that can be decoded - of a later day only when no day up to
// today has one (the clock is behind now): a read dated after today was made while the clock was
// ahead, and the list it gives is older than the reads made since the clock was corrected
// (s.wmu held).
func (s *Store) loadDevices(today day) {
	s.mu.Lock()
	days := make([]day, 0, len(s.files[kindDevices]))
	for d := range s.files[kindDevices] {
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
		r, err := s.openDay(kindDevices, d)
		if err != nil || r == nil {
			if err != nil {
				s.log.Warn("connection store: a day of Device List reads cannot be read", "file", fileName(kindDevices, d, false), "err", err)
			}
			continue
		}
		var best []model.LANDevice
		var bestT time.Time
		bad := 0
		damage, _ := r.each(func(line []byte) error {
			t, devices, err := decodeDevices(line)
			switch {
			case line == nil || err != nil:
				bad++
			case dayOf(t) == d && (best == nil || !t.Before(bestT)):
				best, bestT = devices, t
			}
			return nil
		})
		r.close()
		s.noteReadProblems(kindDevices, d, damage, bad, 0, 0)
		if best != nil {
			s.mu.Lock()
			s.devices, s.devicesAt = best, bestT
			s.mu.Unlock()
			return
		}
	}
}

// edgeTime returns the time of the oldest read kept (oldest) or of the newest one, of either
// kind; zero when there is none. It reads the oldest (newest) day of each kind that has a read
// whose time can be told (s.wmu held).
func (s *Store) edgeTime(oldest bool) time.Time {
	var edge time.Time
	for k := range numKinds {
		s.mu.Lock()
		days := make([]day, 0, len(s.files[k]))
		for d := range s.files[k] {
			days = append(days, d)
		}
		s.mu.Unlock()
		slices.SortFunc(days, func(a, b day) int {
			if oldest {
				return cmp.Compare(a, b)
			}
			return cmp.Compare(b, a)
		})
		for _, d := range days {
			lo, hi, ok := s.dayTimes(k, d)
			if !ok {
				continue
			}
			switch {
			case edge.IsZero():
				edge = hi
				if oldest {
					edge = lo
				}
			case oldest && lo.Before(edge):
				edge = lo
			case !oldest && hi.After(edge):
				edge = hi
			}
			break
		}
	}
	return edge
}

// dayTimes returns the times of the oldest and the newest read of the day d of kind k; ok is
// false when it has none whose time can be told.
func (s *Store) dayTimes(k kind, d day) (lo, hi time.Time, ok bool) {
	r, err := s.openDay(k, d)
	if err != nil || r == nil {
		return lo, hi, false
	}
	defer r.close()
	var scratch natLine
	r.each(func(line []byte) error {
		t, tok := peekTime(line)
		if !tok && line != nil {
			var err error
			if k == kindNAT {
				t, err = decodeNAT(line, &scratch)
			} else {
				t, _, err = decodeDevices(line)
			}
			tok = err == nil
		}
		if !tok || dayOf(t) != d {
			return nil
		}
		if !ok || t.Before(lo) {
			lo = t
		}
		if !ok || t.After(hi) {
			hi = t
		}
		ok = true
		return nil
	})
	return lo, hi, ok
}
