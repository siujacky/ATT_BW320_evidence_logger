package connstore

import (
	"cmp"
	"errors"
	"log/slog"
	"net/netip"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"attmonitor/internal/config"
	"attmonitor/internal/contracts"
	"attmonitor/internal/model"
)

// Defaults of the retention limits (config.ConnectionsConfig).
const (
	DefaultKeepDays = 30
	DefaultKeepMB   = 200
)

const (
	// pruneEvery is how often the appends apply the retention limits.
	pruneEvery = time.Hour
	// ageDelay is how long the age limit (keep_days) waits after Open, which applies only the
	// size limit: a clock that is wrong when the service starts - Windows' Secure Time Seeding has
	// set clocks months ahead at boot - and is corrected within that time deletes nothing. Open
	// sets a timer to apply it then, should no append or Prune do it first.
	ageDelay = time.Hour
	// aheadTolerance is how far the store's clock may run ahead of the time the monotonic clock
	// has measured since the two last agreed before the age limit stops following it (ageTime).
	aheadTolerance = time.Hour
	// aheadTrust is how long the store's clock may stay that far ahead before the age limit
	// follows it again: a step that lasts that long is taken as the correction of a clock that
	// was behind, so that the age limit cannot stay held back until the next restart.
	aheadTrust = 24 * time.Hour
	// compressRetry is how long the appends wait before they try again to compress a day whose
	// compression failed (Open always tries).
	compressRetry = time.Hour
	// summaryDays bounds the number of days in the cache of day summaries: the 29 whole past days
	// of the longest view (30 days), with room to spare.
	summaryDays = 40
	// summaryWeight bounds the cache's total size, in devices and flows (a flow takes about 100
	// bytes, so about 100 MiB at most): a household's day has a few thousand flows (30 days of
	// BenchmarkAggregate30dWarm take 143,000), but unusual days - file sharing, a port scan
	// through the NAT - may have far more. The cache then holds the newest days that fit
	// (dayCache): the shorter views still come from it whole, and the longest reads its older
	// days again at each query.
	summaryWeight = 1 << 20
	// deviceDays bounds the cache of the Device List reads of a day (a few KiB each).
	deviceDays = 64
	// maxFlows bounds the distinct flows that a day's summary, and an aggregate, count one by one:
	// a month of a busy household holds about 150,000, but a device that opens connections to ever
	// new addresses - file sharing, a scan of the Internet, the gateway's 8,000 sessions to random
	// hosts - could make one query hold millions, GiB of memory inside the evidence logger. Beyond
	// the bound the lightest flows are left out (pruneFlows): their sessions still count in their
	// device's weight (ConnDevice.LeftOut says how many) and the aggregate says how many flows were
	// left out (ConnAggregate.FlowsLeftOut).
	maxFlows = 200_000
)

// ErrClosed is returned by the writing methods after Close.
var ErrClosed = errors.New("connstore: the store is closed")

var _ contracts.ConnStore = (*Store)(nil)

// Options configures Open. Zero values select the defaults.
type Options struct {
	// KeepDays and KeepMB are the retention limits (see SetRetention); 0 selects
	// DefaultKeepDays and DefaultKeepMB.
	KeepDays, KeepMB int
	Logger           *slog.Logger
	// Now is the clock (default time.Now): it tells which day is today (never pruned, and read
	// raw by Aggregate) and stands in for the zero time given to a method.
	Now func() time.Time
	// Gateway is the gateway's own address on the home network (gateway.host; the zero Addr when
	// unknown). Its sessions - the gateway sending its syslog to this computer, answering a
	// device's DNS query - belong to the gateway's key "gateway", like the sessions it opens from
	// its public address, not to a device of their own named after the address.
	Gateway netip.Addr

	// mono replaces the monotonic clock in tests: it returns the time elapsed since an arbitrary
	// origin. ageDelay replaces ageDelay in tests. settleStart, when set, is called as the
	// background work Open starts begins (settle; the tests hold it).
	mono        func() time.Duration
	ageDelay    time.Duration
	settleStart func()
}

// Store is the connection store (contracts.ConnStore): the NAT table and Device List reads in
// daily files. It is safe for one writer (the monitor, which calls AppendNAT, AppendDevices and
// Prune) and any number of concurrent readers (Aggregate, Devices, EachDevices, Usage).
type Store struct {
	dir string
	log *slog.Logger
	now func() time.Time

	// wmu serializes the writing methods: the appends, Prune, Close, Open's repairs and the age
	// limit's timer (ageDue). The readers never take it: they read the files a snapshot of the
	// index lists, up to the sizes it states.
	wmu    sync.Mutex
	closed bool
	// w is the file each kind is appended to: the plain file of the newest day appended to (nil
	// before the first append, after Close, and once that day was compressed).
	w [numKinds]*writer
	// pending are files that could not be deleted when they should have been (another program
	// held them); the writing methods try again.
	pending []string
	// retryAt: a day whose compression failed is not tried again by the appends before then.
	retryAt map[fileKey]time.Time

	// The clocks the age limit trusts (ageTime; s.wmu held). mono is the monotonic clock, which
	// nothing sets: the time elapsed since an arbitrary origin. opened is its reading at Open;
	// ageReady is set once the age limit applies, ageDelay after Open (the constant; the tests
	// shorten it); ref holds readings of the store's clock (its wall time only) and of mono taken
	// when the two last agreed; ahead is set while the store's clock runs ahead of ref's
	// account, since the mono reading aheadSince.
	mono       func() time.Duration
	ageDelay   time.Duration
	opened     time.Duration
	ageReady   bool
	ref        clockReading
	ahead      bool
	aheadSince time.Duration
	// ageTimer applies the age limit ageDelay after Open (ageDue).
	ageTimer *time.Timer
	// settled is closed once the background work Open starts (settle) has ended.
	settled chan struct{}

	// mu guards the fields below. It is never held during file I/O.
	mu sync.Mutex
	// files indexes the files of each kind by day.
	files            [numKinds]map[day]*dayFiles
	keepDays, keepMB int
	// mib is the size of a MiB of KeepMB (1 MiB; the tests make it smaller).
	mib int64
	// lastPrune is when the retention limits were last applied (zero: due at the next append).
	lastPrune time.Time
	// oldest and newest are the times of the oldest and the newest read kept (either kind).
	oldest, newest time.Time
	// devices is the newest Device List read (by its time; one dated after the clock gives way to
	// the next read stored: see AppendDevices) and devicesAt that time.
	devices   []model.LANDevice
	devicesAt time.Time
	// failures are the operations whose newest attempt failed (Usage().Error), by operation.
	failures map[string]failure
	// warned lists the problems logged already, by file and problem, so that a damaged file
	// read by every query is logged once.
	warned map[string]bool

	// maxFlows is the constant maxFlows (the tests lower it).
	maxFlows int
	// gateway is Options.Gateway (unmapped, without zone).
	gateway netip.Addr

	// sums caches the summaries of whole past days, devs the Device List reads of a day.
	sums *dayCache[sumKey, *sumEntry]
	devs *dayCache[devKey, []*devRead]
	// stats counts what the readers did, for the tests and the benchmarks.
	stats readStats
}

// readStats counts the readers' work.
type readStats struct {
	sumHits, sumMisses atomic.Int64 // whole past days found in the cache, and computed
	rawDays            atomic.Int64 // days read raw (partially covered, today)
	lines              atomic.Int64 // NAT lines decoded
}

// dayFiles are the files of one kind and day, as the index knows them.
type dayFiles struct {
	gz    int64 // size of the compressed file; -1 when there is none
	plain int64 // committed size of the plain file (its complete, synced lines); -1 when none
	// gen is odd while the writer replaces or deletes the day's files (a compression), and
	// changes with each such change: a reader whose day changed generation while it opened the
	// files opens them again (openDay).
	gen uint32
}

// fileKey names the files of one kind and day.
type fileKey struct {
	kind kind
	day  day
}

// failure is the newest failed attempt of an operation.
type failure struct {
	at  time.Time
	msg string
}

// clampRetention brings retention limits into the range the configuration allows: at least 1
// day and 1 MiB.
func clampRetention(keepDays, keepMB int) (int, int) {
	return min(max(keepDays, 1), config.MaxConnKeepDays), min(max(keepMB, 1), config.MaxConnKeepMB)
}

// Usage reports the files kept (compressed days at their stored size, plain files at their
// complete lines), the oldest and newest read kept, the retention limits and the newest failure
// of an operation whose last attempt failed. It never waits for file I/O.
func (s *Store) Usage() model.ConnStoreUsage {
	s.mu.Lock()
	defer s.mu.Unlock()
	u := model.ConnStoreUsage{KeepDays: s.keepDays, KeepMB: s.keepMB}
	for k := range numKinds {
		for _, f := range s.files[k] {
			for _, n := range [...]int64{f.gz, f.plain} {
				if n >= 0 {
					u.Bytes += n
					u.Files++
				}
			}
		}
	}
	if !s.oldest.IsZero() {
		u.Oldest, u.Newest = formatTime(s.oldest), formatTime(s.newest)
	}
	var newest failure
	for _, f := range s.failures {
		if newest.msg == "" || f.at.After(newest.at) {
			newest = f
		}
	}
	u.Error = newest.msg
	return u
}

// Devices returns the newest Device List read (by its time; nil before the first) and its time.
// A read dated after the clock - made while it was ahead - gives way to the next read stored
// (AppendDevices), and is passed over by Open while a day up to today has one. The slice is the
// caller's own.
func (s *Store) Devices() ([]model.LANDevice, time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.devices == nil {
		return nil, time.Time{}
	}
	return cloneDevices(s.devices), s.devicesAt
}

// cloneDevices returns a copy of devices that shares nothing with it.
func cloneDevices(devices []model.LANDevice) []model.LANDevice {
	out := slices.Clone(devices)
	for i := range out {
		out[i].IPv6 = slices.Clone(out[i].IPv6)
	}
	return out
}

// SetRetention changes the retention limits: no day whose reads are all more than keepDays days
// old, and at most keepMB MiB of files (values below 1 count as 1; values beyond the
// configuration's limits are brought within them). The next append applies them; Prune applies
// them at once.
func (s *Store) SetRetention(keepDays, keepMB int) {
	keepDays, keepMB = clampRetention(keepDays, keepMB)
	s.mu.Lock()
	s.keepDays, s.keepMB = keepDays, keepMB
	s.lastPrune = time.Time{}
	s.mu.Unlock()
}

// Close closes the files being appended to, stops the age limit's timer and waits for the
// background work Open started (see Open), which ends at once if it has not begun. Afterwards the
// writing methods fail with ErrClosed; reading keeps working.
func (s *Store) Close() error {
	err := s.closeFiles()
	if s.settled != nil {
		<-s.settled
	}
	return err
}

// closeFiles is Close but for the wait for the background work.
func (s *Store) closeFiles() error {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	if s.ageTimer != nil {
		s.ageTimer.Stop()
	}
	var errs []error
	for k, w := range s.w {
		if w != nil {
			errs = append(errs, w.close())
			s.w[k] = nil
		}
	}
	return errors.Join(errs...)
}

// when returns t, or the current time when t is the zero time.
func (s *Store) when(t time.Time) time.Time {
	if t.IsZero() {
		return s.now()
	}
	return t
}

// noteResult records the outcome of an operation's attempt for Usage().Error: a failure, or,
// with a nil err, that the operation works again.
func (s *Store) noteResult(op string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err == nil {
		delete(s.failures, op)
		return
	}
	s.failures[op] = failure{at: s.now(), msg: err.Error()}
}

// warnOnce logs a problem with a file the first time it is found.
func (s *Store) warnOnce(file, msg string, args ...any) {
	key := file + "\x00" + msg
	s.mu.Lock()
	seen := s.warned[key]
	s.warned[key] = true
	s.mu.Unlock()
	if !seen {
		s.log.Warn(msg, append([]any{"file", file}, args...)...)
	}
}

// forgetWarnings drops the warnings noted about the files of a day that is gone, so that a file
// of the same name, written later, is warned about again (s.mu held).
func (s *Store) forgetWarnings(k kind, d day) {
	for _, gz := range [...]bool{false, true} {
		name := fileName(k, d, gz)
		for key := range s.warned {
			if len(key) > len(name) && key[:len(name)] == name && key[len(name)] == 0 {
				delete(s.warned, key)
			}
		}
	}
}

// snapshot is what a reader works from: the files of each kind by day, as the index listed them
// at one point in time, and which day was today.
type snapshot struct {
	today day
	days  [numKinds][]dayEntry // oldest first
}

// dayEntry is the files of one day in a snapshot.
type dayEntry struct {
	day day
	dayFiles
}

// snapshot copies the index.
func (s *Store) snapshot() *snapshot {
	sn := &snapshot{today: dayOf(s.now())}
	s.mu.Lock()
	for k := range numKinds {
		sn.days[k] = make([]dayEntry, 0, len(s.files[k]))
		for d, f := range s.files[k] {
			sn.days[k] = append(sn.days[k], dayEntry{day: d, dayFiles: *f})
		}
	}
	s.mu.Unlock()
	for k := range numKinds {
		slices.SortFunc(sn.days[k], func(a, b dayEntry) int { return cmp.Compare(a.day, b.day) })
	}
	return sn
}

// entry returns the files of kind k and day d as the index lists them now.
func (s *Store) entry(k kind, d day) (dayFiles, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, ok := s.files[k][d]
	if !ok {
		return dayFiles{}, false
	}
	return *f, true
}

// indexed returns the index entry of kind k and day d, adding an empty one when there is none
// (s.mu held).
func (s *Store) indexed(k kind, d day) *dayFiles {
	f := s.files[k][d]
	if f == nil {
		f = &dayFiles{gz: -1, plain: -1}
		s.files[k][d] = f
	}
	return f
}

// path returns the path of a file of the store.
func (s *Store) path(k kind, d day, gz bool) string {
	return filepath.Join(s.dir, fileName(k, d, gz))
}
