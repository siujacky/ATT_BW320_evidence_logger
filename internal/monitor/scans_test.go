package monitor

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"attmonitor/internal/config"
	"attmonitor/internal/contracts"
	"attmonitor/internal/model"
)

// The LAN scan (scans.go, docs/dhcp-table.md §6): a sweep of the home network by ARP every
// connections.scan_interval, into the scan store - never into the evidence ledger - and never while
// the gateway is needed for evidence.

// ---------------------------------------------------------------------------- fakes

// fakeScanner is a contracts.LANScanner: each Scan is recorded and answered by scan (testScan when
// nil).
type fakeScanner struct {
	mu    sync.Mutex
	calls []time.Time
	scan  func(ctx context.Context) (model.LANScan, error)
}

func (f *fakeScanner) Scan(ctx context.Context) (model.LANScan, error) {
	f.mu.Lock()
	f.calls = append(f.calls, time.Now())
	scan := f.scan
	f.mu.Unlock()
	if scan == nil {
		return testScan(), nil
	}
	return scan(ctx)
}

// answer makes the scanner answer with scan.
func (f *fakeScanner) answer(scan func(ctx context.Context) (model.LANScan, error)) {
	f.mu.Lock()
	f.scan = scan
	f.mu.Unlock()
}

// sweeps returns when Scan was called.
func (f *fakeScanner) sweeps() []time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.calls)
}

var _ contracts.LANScanner = (*fakeScanner)(nil)

// testScan is a sweep of 192.168.1.0/24 (documentation MAC addresses) in which a laptop, this PC and
// the gateway answered; its At is the scanner's own clock, which the monitor replaces with its own.
func testScan() model.LANScan {
	return model.LANScan{At: "2026-01-01T00:00:00Z", TookMs: 8200, Subnet: "192.168.1.0/24", Self: "192.168.1.71", Asked: 254,
		Hosts: []model.LANHost{
			{IP: "192.168.1.64", MAC: "00:00:5e:00:53:01"},
			{IP: "192.168.1.71", MAC: "00:00:5e:00:53:71"},
			{IP: "192.168.1.254", MAC: "00:00:5e:00:53:fe"},
		}}
}

// fakeScanStore is an in-memory contracts.ScanStore: it keeps every scan appended (refusing them
// with err while it is set).
type fakeScanStore struct {
	mu    sync.Mutex
	scans []scanAppend
	err   error
}

// scanAppend is a scan appended to the fake scan store, with its time.
type scanAppend struct {
	t    time.Time
	scan model.LANScan
}

func (s *fakeScanStore) AppendScan(t time.Time, scan model.LANScan) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return s.err
	}
	scan.Hosts = slices.Clone(scan.Hosts)
	s.scans = append(s.scans, scanAppend{t: t, scan: scan})
	return nil
}

func (s *fakeScanStore) EachScan(context.Context, time.Time, time.Time, func(model.LANScan) error) error {
	return errors.New("fake scan store: EachScan is not part of these tests")
}

func (s *fakeScanStore) LastScan() (model.LANScan, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if n := len(s.scans); n > 0 {
		return s.scans[n-1].scan, true
	}
	return model.LANScan{}, false
}

// kept returns the scans appended.
func (s *fakeScanStore) kept() []scanAppend {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.scans)
}

// setErr makes the appends fail with err (nil: succeed again).
func (s *fakeScanStore) setErr(err error) {
	s.mu.Lock()
	s.err = err
	s.mu.Unlock()
}

var _ contracts.ScanStore = (*fakeScanStore)(nil)

// scanRig is a rig with a connection store, a scanner and a scan store whose LAN scan sampler sweeps
// every 80 ms, the first time 30 ms after the start (and after the Device List's first round, 10 ms
// after it); cfg, when given, may change the configuration first. The NAT table and the Device List
// are read once an hour (no access code is stored: the NAT reads do not happen). Its pauses are
// short.
func scanRig(t *testing.T, cfg func(*config.Config)) (*rig, *fakeScanner, *fakeScanStore) {
	t.Helper()
	c := testConfig()
	c.Connections.Interval = config.D(time.Hour)
	c.Connections.DevicesInterval = config.D(time.Hour)
	c.Connections.ScanInterval = config.D(80 * time.Millisecond)
	if cfg != nil {
		cfg(c)
	}
	store := &fakeConnStore{usage: model.ConnStoreUsage{Bytes: 4096, Files: 1, KeepDays: 30, KeepMB: 200}}
	sc, scans := &fakeScanner{}, &fakeScanStore{}
	r := newRigWith(t, c, nil, func(o *Options) { o.Conns, o.Scanner, o.Scans = store, sc, scans })
	if s := r.m.conns; s != nil {
		s.devFirst, s.scanFirst, s.busyRetry, s.holdPoll = 10*time.Millisecond, 30*time.Millisecond, 20*time.Millisecond, 2*time.Millisecond
	}
	answerDevices(r.gw, testDevices(), testDevicesPage, nil)
	return r, sc, scans
}

// scanProblem is the sampler's problem as Status.Connections shows it.
func scanProblem(r *rig) string {
	var p string
	r.m.conns.locked(func() { p = r.m.conns.scan.problem })
	return p
}

// ---------------------------------------------------------------------------- configuration

// No sweeps without a scanner, without a store for the scans, with connections.scan_interval 0 or
// with connections.enabled off: no worker, no Scan call, and the status says nothing of a scan.
func TestScanSamplerNeedsItsParts(t *testing.T) {
	for _, tc := range []struct {
		name string
		opt  func(o *Options)
		cfg  func(c *config.Config)
	}{
		{"no scanner", func(o *Options) { o.Scanner = nil }, nil},
		{"no scan store", func(o *Options) { o.Scans = nil }, nil},
		{"scan_interval 0", nil, func(c *config.Config) { c.Connections.ScanInterval = config.D(0) }},
		{"connections.enabled off", nil, func(c *config.Config) { c.Connections.Enabled = false }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := testConfig()
			c.Connections.DevicesInterval = config.D(time.Hour)
			c.Connections.ScanInterval = config.D(20 * time.Millisecond)
			if tc.cfg != nil {
				tc.cfg(c)
			}
			sc, scans := &fakeScanner{}, &fakeScanStore{}
			r := newRigWith(t, c, nil, func(o *Options) {
				o.Conns, o.Scanner, o.Scans = &fakeConnStore{}, sc, scans
				if tc.opt != nil {
					tc.opt(o)
				}
			})
			r.m.conns.devFirst, r.m.conns.scanFirst = time.Millisecond, time.Millisecond
			answerDevices(r.gw, testDevices(), testDevicesPage, nil)
			if r.m.scansOn() {
				t.Fatal("the scan sampler is on")
			}
			stop := r.start(t)
			time.Sleep(300 * time.Millisecond)
			if err := stop(); err != nil {
				t.Fatal(err)
			}
			if n := len(sc.sweeps()); n != 0 {
				t.Fatalf("%d sweeps", n)
			}
			if st := connStatus(t, r); st.ScanInterval != "" || st.ScanAt != "" || st.ScanNext != "" || st.ScanProblem != "" || st.ScanHosts != 0 {
				t.Fatalf("status %+v", st)
			}
		})
	}
}

// The sampler's tunables, and connections.scan_interval as configured: 0 is no sweeps, also in a
// hand-built configuration, where the other intervals take their defaults.
func TestScanSamplerDefaults(t *testing.T) {
	r := newRigWith(t, nil, nil, func(o *Options) { o.Conns, o.Scanner, o.Scans = &fakeConnStore{}, &fakeScanner{}, &fakeScanStore{} })
	if c := r.m.conns; c.scanInterval != time.Hour || c.scanFirst != 3*time.Minute || c.scanTimeout != 2*time.Minute+30*time.Second || !r.m.scansOn() {
		t.Fatalf("samplers %+v", c)
	}
	if st := connStatus(t, r); st.ScanInterval != "1h0m0s" || st.ScanNext != "" {
		t.Fatalf("status %+v", st)
	}
	cfg := testConfig()
	cfg.Connections = config.ConnectionsConfig{Enabled: true}
	r = newRigWith(t, cfg, nil, func(o *Options) { o.Conns, o.Scanner, o.Scans = &fakeConnStore{}, &fakeScanner{}, &fakeScanStore{} })
	if r.m.conns.scanInterval != 0 || r.m.scansOn() || r.m.conns.devInterval != 15*time.Minute {
		t.Fatalf("a hand-built configuration without scan_interval: %+v", r.m.conns)
	}
}

// ---------------------------------------------------------------------------- sweeps and status

// Run sweeps scanFirst after the start - and not before the Device List sampler's first round - then
// every connections.scan_interval, and appends every sweep to the scan store, dated by the monitor's
// clock; Status.Connections follows the newest sweep. The evidence ledger gets nothing of it.
func TestScanSamplerSweepsAtItsInterval(t *testing.T) {
	for _, tc := range []struct {
		name                string
		scanFirst, devFirst time.Duration
	}{
		{"after scanFirst", 150 * time.Millisecond, 10 * time.Millisecond},
		{"after the Device List's first round", 10 * time.Millisecond, 150 * time.Millisecond},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const interval = 80 * time.Millisecond
			r, sc, scans := scanRig(t, nil)
			r.m.conns.scanFirst, r.m.conns.devFirst = tc.scanFirst, tc.devFirst
			var fromScan []string
			var fromMu sync.Mutex
			byScan := func(what string) {
				buf := make([]byte, 64<<10)
				if strings.Contains(string(buf[:runtime.Stack(buf, false)]), ").scanLoop(") {
					fromMu.Lock()
					fromScan = append(fromScan, what)
					fromMu.Unlock()
				}
			}
			r.led.onAppend = func(b model.Body) { byScan("a " + b.Type + " record") }
			r.led.setOnPut(func([]byte) { byScan("a blob") })
			started := time.Now()
			stop := r.start(t)
			waitFor(t, "three sweeps kept", 20*time.Second, func() bool { return len(scans.kept()) >= 3 })
			if err := stop(); err != nil {
				t.Fatal(err)
			}
			calls := sc.sweeps()
			_, devTimes := r.gw.networkReads()
			if len(devTimes) == 0 || calls[0].Before(devTimes[0]) || calls[0].Sub(started) < 150*time.Millisecond {
				t.Fatalf("the first sweep %v after the start, the first Device List read %v", calls[0].Sub(started), devTimes)
			}
			for i := 1; i < len(calls); i++ {
				if gap := calls[i].Sub(calls[i-1]); gap < interval*3/4 {
					t.Fatalf("sweeps %v apart, the interval is %v", gap, interval)
				}
			}
			kept := scans.kept()
			if n := len(calls) - len(kept); n < 0 || n > 1 {
				t.Fatalf("%d of %d sweeps kept", len(kept), len(calls))
			}
			for i, k := range kept {
				want := testScan()
				want.At = fmtTS(k.t)
				if !reflect.DeepEqual(k.scan, want) || (i > 0 && !k.t.After(kept[i-1].t)) {
					t.Fatalf("sweep %d kept at %v: %+v", i, k.t, k.scan)
				}
			}
			st := connStatus(t, r)
			last := kept[len(kept)-1]
			next, ok := parseTS(st.ScanNext)
			if st.ScanInterval != "80ms" || st.ScanAt != fmtTS(last.t) || st.ScanHosts != 3 || st.ScanProblem != "" || !ok || !next.After(last.t) {
				t.Fatalf("status %+v", st)
			}
			fromMu.Lock()
			defer fromMu.Unlock()
			if len(fromScan) > 0 {
				t.Fatalf("the scan sampler wrote to the evidence ledger: %v", fromScan)
			}
			noSamplesInLedger(t, r)
		})
	}
}

// Until the first sweep the status says when it is due: scanFirst after the start at the earliest.
func TestScanSamplerSaysWhenTheFirstSweepIsDue(t *testing.T) {
	r, sc, _ := scanRig(t, nil)
	r.m.conns.scanFirst = time.Hour
	started := time.Now()
	stop := r.start(t)
	waitFor(t, "the first sweep scheduled", 10*time.Second, func() bool { return connStatus(t, r).ScanNext != "" })
	st := connStatus(t, r)
	next, _ := parseTS(st.ScanNext)
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	if d := next.Sub(started); d < 59*time.Minute || d > 61*time.Minute || st.ScanAt != "" || len(sc.sweeps()) != 0 {
		t.Fatalf("the first sweep due %v after the start; status %+v", d, st)
	}
}

// ---------------------------------------------------------------------------- the evidence first

// No sweep while an incident is open or being closed, after a bad cycle or while the newest snapshot
// found the gateway unreachable: the round says why, and looks again busyRetry later; once the hold
// ends the sweep is made.
func TestScanSamplerLeavesTheNetworkToTheEvidence(t *testing.T) {
	ctx := context.Background()
	r, sc, scans := scanRig(t, func(c *config.Config) { c.Connections.ScanInterval = config.D(time.Hour) })
	r.m.conns.busyRetry = time.Minute
	for _, tc := range []struct {
		name    string
		prepare func()
		want    string
	}{
		{"the gateway did not answer the latest poll", func() {
			r.m.locked(func() { r.m.st.lastSnap = &snapObs{At: time.Now(), Snap: &model.GatewaySnapshot{}} })
		}, "skipped: the gateway did not answer the monitor's latest poll"},
		{"a bad cycle", func() {
			r.m.locked(func() { r.m.st.lastSnap = nil })
			r.m.processCycle(ctx, time.Now(), time.Millisecond, outageCycle())
		}, connSkipFailing},
		{"an incident is open", func() { openIncident(t, r) }, connSkipIncident},
	} {
		tc.prepare()
		began := time.Now()
		wantNext(t, tc.name, began, r.m.sampleScan(ctx), time.Minute)
		if p := scanProblem(r); !strings.HasPrefix(p, tc.want) {
			t.Fatalf("%s: problem %q, want %q", tc.name, p, tc.want)
		}
		if n := len(sc.sweeps()); n != 0 {
			t.Fatalf("%s: %d sweeps", tc.name, n)
		}
	}
	// The hold ends: the next round sweeps, and the next is an interval later.
	r2, sc2, scans2 := scanRig(t, func(c *config.Config) { c.Connections.ScanInterval = config.D(time.Hour) })
	r2.m.conns.busyRetry = time.Minute
	r2.m.processCycle(ctx, time.Now(), time.Millisecond, outageCycle())
	r2.m.sampleScan(ctx)
	if scanProblem(r2) != connSkipFailing || len(sc2.sweeps()) != 0 {
		t.Fatalf("after a bad cycle: problem %q, %d sweeps", scanProblem(r2), len(sc2.sweeps()))
	}
	for range 9 { // the loss window keeps the first good cycles PACKET_LOSS
		r2.m.processCycle(ctx, time.Now(), time.Millisecond, healthy())
	}
	began := time.Now()
	wantNext(t, "after the hold ended", began, r2.m.sampleScan(ctx), time.Hour)
	if st := connStatus(t, r2); st.ScanProblem != "" || st.ScanHosts != 3 || len(scans2.kept()) != 1 {
		t.Fatalf("after the hold ended: %+v, %d kept", st, len(scans2.kept()))
	}
	if len(scans.kept()) != 0 {
		t.Fatal("a held round kept a sweep")
	}
}

// A sweep in progress is stopped as soon as the gateway is needed for evidence - here a cycle fails -
// and is not kept (part of a sweep would make the devices it did not reach look silent); the round
// says so and looks again shortly. It is not a failure.
func TestScanSamplerStopsForTheEvidence(t *testing.T) {
	ctx := context.Background()
	r, sc, scans := scanRig(t, func(c *config.Config) { c.Connections.ScanInterval = config.D(time.Hour) })
	r.m.conns.busyRetry = time.Minute
	entered := make(chan struct{})
	sc.answer(func(ctx context.Context) (model.LANScan, error) {
		close(entered)
		<-ctx.Done()
		partial := testScan()
		partial.Hosts = partial.Hosts[:1]
		return partial, fmt.Errorf("lanscan: the sweep was stopped before it ended: %w", ctx.Err())
	})
	done := make(chan struct{})
	var next time.Time
	began := time.Now()
	go func() {
		defer close(done)
		next = r.m.sampleScan(ctx)
	}()
	<-entered
	r.m.processCycle(ctx, time.Now(), time.Millisecond, outageCycle())
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the sweep was not stopped")
	}
	wantNext(t, "after the stopped sweep", began, next, time.Minute)
	if st := connStatus(t, r); st.ScanProblem != connSkipFailing || st.ScanAt != "" || st.ScanHosts != 0 {
		t.Fatalf("status %+v", st)
	}
	if len(scans.kept()) != 0 {
		t.Fatal("the stopped sweep was kept")
	}
	if rec, _, _ := r.m.conns.scanLog.ok(); rec {
		t.Fatal("a sweep stopped for the evidence counted as a failure")
	}
}

// ---------------------------------------------------------------------------- failures

// A sweep that fails says why and is tried again an interval later; the failures are logged when they
// start (not at every round) and when they end, and the first sweep that works is logged. A sweep
// that stopped short is kept, and its Problem is the round's; a sweep the store refuses still counts
// as made, and the problem says that it was not kept.
func TestScanSamplerFailures(t *testing.T) {
	ctx := context.Background()
	r, sc, scans := scanRig(t, func(c *config.Config) { c.Connections.ScanInterval = config.D(time.Hour) })
	h := &captureHandler{}
	r.m.log = slog.New(h)
	sc.answer(func(context.Context) (model.LANScan, error) {
		return model.LANScan{}, errors.New("lanscan: no network interface of this PC that is up is on the gateway's network (192.168.1.254): this PC is not connected to the home network")
	})
	for range 3 {
		began := time.Now()
		wantNext(t, "after a failed sweep", began, r.m.sampleScan(ctx), time.Hour)
	}
	if p := scanProblem(r); p != "the home network could not be swept: lanscan: no network interface of this PC that is up is on the gateway's network (192.168.1.254): this PC is not connected to the home network" {
		t.Fatalf("problem %q", p)
	}
	if n := h.count(slog.LevelWarn, "cannot sweep the home network for the Network page"); n != 1 || len(scans.kept()) != 0 {
		t.Fatalf("%d warnings for 3 failed sweeps, %d kept", n, len(scans.kept()))
	}

	// The scanner stopped short: kept, with what it says.
	short := testScan()
	short.Hosts, short.Asked = short.Hosts[:2], 120
	short.Problem = "the sweep was stopped after 2m0s with 120 of 254 addresses asked: what answered by then is kept"
	sc.answer(func(context.Context) (model.LANScan, error) { return short, nil })
	r.m.sampleScan(ctx)
	st := connStatus(t, r)
	if st.ScanProblem != short.Problem || st.ScanHosts != 2 || st.ScanAt == "" || len(scans.kept()) != 1 || scans.kept()[0].scan.Problem != short.Problem {
		t.Fatalf("a sweep that stopped short: %+v", st)
	}
	if h.count(slog.LevelInfo, "sweeps of the home network for the Network page work again") != 1 ||
		h.count(slog.LevelInfo, "the home network is swept by ARP for the Network page") != 1 {
		t.Fatal("the recovery and the first sweep are each logged once")
	}

	// The store refuses a sweep: made, not kept.
	scans.setErr(errors.New("connstore: disk full"))
	sc.answer(nil)
	r.m.sampleScan(ctx)
	st = connStatus(t, r)
	if st.ScanProblem != "the home network was swept, but the connection store could not keep the sweep: connstore: disk full" || st.ScanHosts != 3 {
		t.Fatalf("a sweep the store refused: %+v", st)
	}
	if h.count(slog.LevelWarn, "cannot keep the sweeps of the home network for the Network page") != 1 {
		t.Fatal("the store's refusal is logged")
	}
	scans.setErr(nil)
	r.m.sampleScan(ctx)
	if st := connStatus(t, r); st.ScanProblem != "" || len(scans.kept()) != 2 {
		t.Fatalf("after the store took the sweep again: %+v", st)
	}
	if h.count(slog.LevelInfo, "the home network is swept by ARP for the Network page") != 1 {
		t.Fatal("only the first sweep is logged at Info")
	}
	noSamplesInLedger(t, r)
}

// A sweep in progress ends with Run, says nothing and is not kept, and no goroutine of the sampler
// is left when Run returns.
func TestScanSamplerEndsWithRun(t *testing.T) {
	r, sc, scans := scanRig(t, nil)
	in := make(chan struct{})
	var once sync.Once
	sc.answer(func(ctx context.Context) (model.LANScan, error) {
		once.Do(func() { close(in) })
		<-ctx.Done()
		return testScan(), fmt.Errorf("lanscan: the sweep was stopped before it ended: %w", ctx.Err())
	})
	r.m.conns.scanTimeout = time.Hour
	stop := r.start(t)
	await(t, "a sweep in progress", in)
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	if st := connStatus(t, r); st.ScanProblem != "" || len(scans.kept()) != 0 {
		t.Fatalf("a sweep ended by the stop: %+v, %d kept", st, len(scans.kept()))
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		buf := make([]byte, 1<<20)
		n := runtime.Stack(buf, true)
		var leaked []string
		for _, g := range strings.Split(string(buf[:n]), "\n\n") {
			if strings.Contains(g, "internal/monitor.(*Monitor)") {
				leaked = append(leaked, g)
			}
		}
		if len(leaked) == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d goroutines still running monitor code after Run returned:\n%s", len(leaked), strings.Join(leaked, "\n\n"))
		}
		time.Sleep(20 * time.Millisecond)
	}
}
