package monitor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"attmonitor/internal/config"
	"attmonitor/internal/contracts"
	"attmonitor/internal/model"
)

// The Network page's samplers (connections.go): the gateway's NAT table, read under the guard of
// every authenticated request, and its Device List, into the connection store - never into the
// evidence ledger.

// ---------------------------------------------------------------------------- fake connection store

// fakeConnStore is an in-memory contracts.ConnStore: it keeps every read appended (refusing them
// with err while it is set) and reports usage.
type fakeConnStore struct {
	mu      sync.Mutex
	nat     []natAppend
	devices []devicesAppend
	err     error
	usage   model.ConnStoreUsage
	prunes  atomic.Int64 // Prune calls
}

// natAppend and devicesAppend are reads appended to the fake connection store, with their times.
type natAppend struct {
	t     time.Time
	table model.NATTable
}

type devicesAppend struct {
	t       time.Time
	devices []model.LANDevice
}

func (s *fakeConnStore) AppendNAT(t time.Time, nat model.NATTable) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return s.err
	}
	nat.Sessions = slices.Clone(nat.Sessions)
	s.nat = append(s.nat, natAppend{t: t, table: nat})
	return nil
}

func (s *fakeConnStore) AppendDevices(t time.Time, devices []model.LANDevice) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return s.err
	}
	s.devices = append(s.devices, devicesAppend{t: t, devices: slices.Clone(devices)})
	return nil
}

func (s *fakeConnStore) Aggregate(context.Context, contracts.ConnQuery) (model.ConnAggregate, error) {
	return model.ConnAggregate{}, errors.New("fake connection store: Aggregate is not part of these tests")
}

func (s *fakeConnStore) Devices() ([]model.LANDevice, time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if n := len(s.devices); n > 0 {
		return slices.Clone(s.devices[n-1].devices), s.devices[n-1].t
	}
	return nil, time.Time{}
}

func (s *fakeConnStore) Prune(time.Time) error {
	s.prunes.Add(1)
	return nil
}

func (s *fakeConnStore) SetRetention(keepDays, keepMB int) {
	s.mu.Lock()
	s.usage.KeepDays, s.usage.KeepMB = keepDays, keepMB
	s.mu.Unlock()
}

func (s *fakeConnStore) Usage() model.ConnStoreUsage {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.usage
}

// setErr makes the appends fail with err (nil: succeed again).
func (s *fakeConnStore) setErr(err error) {
	s.mu.Lock()
	s.err = err
	s.mu.Unlock()
}

// reads returns what was appended.
func (s *fakeConnStore) reads() ([]natAppend, []devicesAppend) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.nat), slices.Clone(s.devices)
}

var _ contracts.ConnStore = (*fakeConnStore)(nil)

// ---------------------------------------------------------------------------- the rig

// The pages of these tests: documentation addresses only (RFC 5737, RFC 7042 MAC addresses).
var (
	testNATPage     = []byte(`<html><title>NAT Table</title><table><tr><td>tcp</td><td>198.51.100.7</td></tr></table></html>`)
	testDevicesPage = []byte(`<html><title>Device List</title><p>test-laptop 00:00:5e:00:53:01</p></html>`)
)

// testNATTable is what the gateway client reads from testNATPage.
func testNATTable() model.NATTable {
	return model.NATTable{
		Sessions: []model.NATSession{
			{Proto: "tcp", State: "ESTABLISHED", Src: "192.168.1.64", SrcPort: 50123, Dst: "198.51.100.7", DstPort: 443},
			{Proto: "udp", Src: "192.168.1.65", SrcPort: 53000, Dst: "203.0.113.80", DstPort: 443},
		},
		InUse:     2,
		Available: 8190,
	}
}

// testDevices is what the gateway client reads from testDevicesPage.
func testDevices() []model.LANDevice {
	return []model.LANDevice{
		{MAC: "00:00:5e:00:53:01", Name: "test-laptop", IPv4: "192.168.1.64", Status: "on", Connection: "Wi-Fi 5 GHz"},
		{MAC: "00:00:5e:00:53:02", Name: "test-printer", IPv4: "192.168.1.65", Status: "on", Connection: "Ethernet"},
	}
}

// connRig is a rig with a connection store and the gateway access code stored, whose samplers
// read the NAT table every 60 ms and the Device List every 60 ms (cfg, when given, may change the
// configuration first), the first time 10 ms after the start, answered by the fake gateway with
// testNATTable and testDevices. Its pauses are short.
func connRig(t *testing.T, cfg func(*config.Config)) (*rig, *fakeConnStore) {
	t.Helper()
	c := testConfig()
	c.Connections.Interval = config.D(60 * time.Millisecond)
	c.Connections.DevicesInterval = config.D(60 * time.Millisecond)
	if cfg != nil {
		cfg(c)
	}
	store := &fakeConnStore{usage: model.ConnStoreUsage{Bytes: 4096, Files: 1, KeepDays: 30, KeepMB: 200}}
	r := newRigWith(t, c, nil, func(o *Options) { o.Conns = store })
	r.cfg.Gateway.AccessCodeProtected = "protected-blob"
	if s := r.m.conns; s != nil {
		s.natFirst, s.devFirst, s.busyRetry, s.holdPoll = 10*time.Millisecond, 10*time.Millisecond, 20*time.Millisecond, 2*time.Millisecond
	}
	answerNAT(r.gw, testNATTable(), testNATPage, nil)
	answerDevices(r.gw, testDevices(), testDevicesPage, nil)
	return r, store
}

// answerNAT makes the fake gateway answer NATTable with table, raw and err.
func answerNAT(g *fakeGateway, table model.NATTable, raw []byte, err error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.nat, g.natCtx = func() (model.NATTable, []byte, error) { return table, raw, err }, nil
}

// answerDevices makes the fake gateway answer Devices with devices, raw and err.
func answerDevices(g *fakeGateway, devices []model.LANDevice, raw []byte, err error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.devices, g.devicesCtx = func() ([]model.LANDevice, []byte, error) { return slices.Clone(devices), raw, err }, nil
}

// natCalls and devicesCalls count the fake gateway's NATTable and Devices calls.
func natCalls(r *rig) int {
	nat, _ := r.gw.networkReads()
	return len(nat)
}

func devicesCalls(r *rig) int {
	_, dev := r.gw.networkReads()
	return len(dev)
}

// connStatus is Status.Connections, which must be there.
func connStatus(t *testing.T, r *rig) model.ConnSamplerStatus {
	t.Helper()
	s := r.m.Status().Connections
	if s == nil {
		t.Fatal("Status.Connections is nil")
	}
	return *s
}

// openIncident opens an incident in r: three cycles of an AT&T outage, a second apart, from a
// minute ago. It returns the start of the first.
func openIncident(t *testing.T, r *rig) time.Time {
	t.Helper()
	start := time.Now().Add(-time.Minute)
	for i := range 3 {
		r.m.processCycle(context.Background(), start.Add(time.Duration(i)*time.Second), time.Millisecond, outageCycle())
	}
	if !r.m.incidentOpen() {
		t.Fatal("the incident did not open")
	}
	return start
}

// closingIncident opens an incident in r and lets it recover: it waits in the closing list for
// the close procedure (which no worker runs here), and the latest cycle is good.
func closingIncident(t *testing.T, r *rig) {
	t.Helper()
	start := openIncident(t, r)
	for i := range 9 { // the loss window keeps the first good cycles PACKET_LOSS
		r.m.processCycle(context.Background(), start.Add(time.Duration(3+i)*time.Second), time.Millisecond, healthy())
	}
	if r.m.incidentOpen() || r.m.nextClosing() == nil || isBad(r.m.Status().Verdict.State) {
		t.Fatal("the incident is not being closed after good cycles")
	}
}

// heldElsewhere reports whether mu is held, without keeping it.
func heldElsewhere(mu *sync.Mutex) bool {
	if mu.TryLock() {
		mu.Unlock()
		return false
	}
	return true
}

// certMuHeld says how certMu is held, without keeping it: "exclusive" (TrustCert, also while it
// waits for the NAT reads to leave), "shared" (NAT reads) or "" (not at all).
func certMuHeld(r *rig) string {
	mu := &r.m.certMu
	if mu.TryLock() {
		mu.Unlock()
		return ""
	}
	if mu.TryRLock() {
		mu.RUnlock()
		return "shared"
	}
	return "exclusive"
}

// waitingForALock reports whether a goroutine waits for a sync.Mutex, or for a sync.RWMutex to
// write, in the monitor's method in, called (directly or not) by each of the methods by: found in
// the goroutines' stacks, so that the test does not touch the locks (a TryLock of the test's own
// could make an operator's change that tries the lock at that moment busy).
func waitingForALock(in string, by ...string) bool {
	buf := make([]byte, 1<<20)
	n := runtime.Stack(buf, true)
	for _, g := range strings.Split(string(buf[:n]), "\n\n") {
		if !strings.Contains(g, "[sync.Mutex.Lock") && !strings.Contains(g, "[sync.RWMutex.Lock") {
			continue
		}
		if !slices.ContainsFunc(append([]string{in}, by...), func(fn string) bool { return !strings.Contains(g, ")."+fn+"(") }) {
			return true
		}
	}
	return false
}

// natRoundWaitsForTheGatewayLock reports whether a NAT round waits for the gateway lock.
func natRoundWaitsForTheGatewayLock() bool { return waitingForALock("withGatewayAuth", "readNAT") }

// natProblem is the NAT sampler's problem as Status.Connections shows it, read without Status
// (which asks the ledger for its head).
func natProblem(r *rig) string {
	var p string
	r.m.conns.locked(func() { p = r.m.conns.nat.problem })
	return p
}

// problemTime returns the time a problem names after prefix ("2006-01-02 15:04:05 UTC").
func problemTime(t *testing.T, problem, prefix string) time.Time {
	t.Helper()
	_, rest, ok := strings.Cut(problem, prefix)
	if !ok || len(rest) < len("2006-01-02 15:04:05 UTC") {
		t.Fatalf("%q does not name a time after %q", problem, prefix)
	}
	at, err := time.Parse("2006-01-02 15:04:05 MST", rest[:len("2006-01-02 15:04:05 UTC")])
	if err != nil {
		t.Fatalf("%q: %v", problem, err)
	}
	return at
}

// noSamplesInLedger fails when a record or a blob of the ledger holds anything of the samplers'
// reads: their remote addresses, MAC addresses, device names or pages.
func noSamplesInLedger(t *testing.T, r *rig) {
	t.Helper()
	for _, b := range r.led.records("") {
		for _, s := range []string{"198.51.100.7", "203.0.113.80", "00:00:5e:00:53:", "test-laptop", "test-printer", "NAT Table"} {
			if strings.Contains(string(b.Data), s) {
				t.Fatalf("record #%d (%s) holds %q of the samplers' reads: %s", b.Seq, b.Type, s, b.Data)
			}
		}
	}
	r.led.mu.Lock()
	defer r.led.mu.Unlock()
	for id, blob := range r.led.blobs {
		if bytes.Equal(blob, testNATPage) || bytes.Equal(blob, testDevicesPage) {
			t.Fatalf("blob %s is a page the samplers read", id)
		}
	}
}

// wantNext checks that a round's next is due d after began (within a second).
func wantNext(t *testing.T, what string, began, next time.Time, d time.Duration) {
	t.Helper()
	if off := next.Sub(began.Add(d)); off < -time.Second || off > time.Second {
		t.Fatalf("%s: the next round is due %v after the round began, want %v", what, next.Sub(began), d)
	}
}

// ---------------------------------------------------------------------------- configuration

// Without a connection store there are no samplers: no status, no worker, no read of either page
// (connections.enabled is on by default). With a store but connections.enabled off, the status
// says so with the store's volume, and nothing is read either.
func TestConnSamplersNeedAStoreAndConnectionsEnabled(t *testing.T) {
	none := newRig(t, nil, nil)
	none.cfg.Gateway.AccessCodeProtected = "protected-blob"
	answerNAT(none.gw, testNATTable(), testNATPage, nil)
	answerDevices(none.gw, testDevices(), testDevicesPage, nil)
	if !none.cfg.Connections.Enabled || none.m.conns != nil || none.m.Status().Connections != nil {
		t.Fatal("without a connection store: no samplers, no status")
	}
	off, store := connRig(t, func(c *config.Config) { c.Connections.Enabled = false })

	for _, r := range []*rig{none, off} {
		stop := r.start(t)
		waitFor(t, "samples", 10*time.Second, func() bool { return len(ofType(r.led.records(""), model.TypeSample)) > 5 })
		if err := stop(); err != nil {
			t.Fatal(err)
		}
		if nat, dev := natCalls(r), devicesCalls(r); nat != 0 || dev != 0 {
			t.Fatalf("NAT table read %d times, Device List %d times, by samplers that do not run", nat, dev)
		}
	}
	if nat, dev := store.reads(); len(nat) != 0 || len(dev) != 0 {
		t.Fatalf("appended %d NAT and %d Device List reads", len(nat), len(dev))
	}
	want := model.ConnSamplerStatus{Enabled: false, Interval: "60ms", DevicesInterval: "60ms", InUse: -1, Available: -1,
		Store: &model.ConnStoreUsage{Bytes: 4096, Files: 1, KeepDays: 30, KeepMB: 200}}
	if got := connStatus(t, off); !reflect.DeepEqual(got, want) {
		t.Fatalf("status of samplers switched off:\n got %+v\nwant %+v", got, want)
	}
}

// A configuration without intervals (hand-built) reads at the defaults; the timeouts follow the
// gateway's request timeout.
func TestConnSamplersDefaults(t *testing.T) {
	cfg := testConfig()
	cfg.Connections = config.ConnectionsConfig{Enabled: true}
	cfg.Gateway.Timeout = config.D(10 * time.Second)
	r := newRigWith(t, cfg, nil, func(o *Options) { o.Conns = &fakeConnStore{} })
	c := r.m.conns
	if c.interval != 4*time.Minute || c.devInterval != 15*time.Minute || c.natTimeout != 30*time.Second || c.devTimeout != 15*time.Second ||
		c.natFirst != time.Minute || c.devFirst != 30*time.Second || c.authRetry != time.Hour || c.rawEvery != time.Hour {
		t.Fatalf("samplers %+v", c)
	}
	if st := connStatus(t, r); st.Interval != "4m0s" || st.DevicesInterval != "15m0s" || !st.Enabled || st.NATNext != "" {
		t.Fatalf("status %+v", st)
	}
}

// ---------------------------------------------------------------------------- reads and status

// Run reads the NAT table every connections.interval and the Device List every
// connections.devices_interval, natFirst and devFirst after the start, and appends every read to
// the connection store with the monitor's time; Status.Connections follows the newest reads. The
// evidence ledger gets nothing of it.
func TestConnSamplersReadAtTheirIntervals(t *testing.T) {
	const interval, devInterval = 80 * time.Millisecond, 200 * time.Millisecond
	r, store := connRig(t, func(c *config.Config) {
		c.Connections.Interval = config.D(interval)
		c.Connections.DevicesInterval = config.D(devInterval)
	})
	r.m.conns.natFirst, r.m.conns.devFirst = 150*time.Millisecond, 50*time.Millisecond
	// Whatever the other workers record, nothing comes from the samplers' goroutines.
	var fromSamplers []string
	var fromMu sync.Mutex
	bySampler := func(what string) {
		buf := make([]byte, 64<<10)
		stack := string(buf[:runtime.Stack(buf, false)])
		if strings.Contains(stack, ").natLoop(") || strings.Contains(stack, ").devicesLoop(") {
			fromMu.Lock()
			fromSamplers = append(fromSamplers, what)
			fromMu.Unlock()
		}
	}
	r.led.onAppend = func(b model.Body) { bySampler("a " + b.Type + " record") }
	r.led.setOnPut(func([]byte) { bySampler("a blob") })
	var selfChecked atomic.Bool // the check sees a sampler's goroutine: the NAT read runs on one
	r.gw.mu.Lock()
	r.gw.nat = func() (model.NATTable, []byte, error) {
		if selfChecked.CompareAndSwap(false, true) {
			bySampler("self-check")
		}
		return testNATTable(), testNATPage, nil
	}
	r.gw.mu.Unlock()
	started := time.Now()
	stop := r.start(t)
	var wg sync.WaitGroup
	var done atomic.Bool
	wg.Go(func() { // the dashboard asks for the status meanwhile
		for !done.Load() {
			_ = r.m.Status()
			time.Sleep(time.Millisecond)
		}
	})
	waitFor(t, "four NAT and three Device List reads", 20*time.Second, func() bool {
		nat, dev := store.reads()
		return len(nat) >= 4 && len(dev) >= 3
	})
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	done.Store(true)
	wg.Wait()

	natTimes, devTimes := r.gw.networkReads()
	if natTimes[0].Sub(started) < 150*time.Millisecond || devTimes[0].Sub(started) < 50*time.Millisecond {
		t.Fatalf("first reads %v (NAT) and %v (Device List) after the start", natTimes[0].Sub(started), devTimes[0].Sub(started))
	}
	// A round is due an interval after the previous one began; its read may have waited a little
	// for the gateway lock (a poll).
	for i := 1; i < len(natTimes); i++ {
		if gap := natTimes[i].Sub(natTimes[i-1]); gap < interval*3/4 {
			t.Fatalf("NAT reads %v apart, the interval is %v", gap, interval)
		}
	}
	for i := 1; i < len(devTimes); i++ {
		if gap := devTimes[i].Sub(devTimes[i-1]); gap < devInterval*3/4 {
			t.Fatalf("Device List reads %v apart, the interval is %v", gap, devInterval)
		}
	}
	// Every read is appended - but the last one of each, which the stop may have ended (a read that
	// ends with Run says nothing, and is not kept).
	nat, dev := store.reads()
	if n := len(natTimes) - len(nat); n < 0 || n > 1 {
		t.Fatalf("%d of %d NAT reads appended", len(nat), len(natTimes))
	}
	if n := len(devTimes) - len(dev); n < 0 || n > 1 {
		t.Fatalf("%d of %d Device List reads appended", len(dev), len(devTimes))
	}
	for i, a := range nat {
		if !reflect.DeepEqual(a.table, testNATTable()) || (i > 0 && !a.t.After(nat[i-1].t)) {
			t.Fatalf("NAT read %d: %+v at %v", i, a.table, a.t)
		}
	}
	for _, a := range dev {
		if !reflect.DeepEqual(a.devices, testDevices()) {
			t.Fatalf("Device List read %+v", a.devices)
		}
	}
	st := connStatus(t, r)
	last, lastDev := nat[len(nat)-1], dev[len(dev)-1]
	next, ok := parseTS(st.NATNext)
	if !st.Enabled || st.Interval != "80ms" || st.DevicesInterval != "200ms" || st.NATAt != fmtTS(last.t) || st.Sessions != 2 ||
		st.InUse != 2 || st.Available != 8190 || st.NATProblem != "" || !ok || !next.After(last.t) ||
		st.DevicesAt != fmtTS(lastDev.t) || st.Devices != 2 || st.DevicesProblem != "" || st.Store == nil || st.Store.Bytes != 4096 {
		t.Fatalf("status %+v", st)
	}
	fromMu.Lock()
	defer fromMu.Unlock()
	if !slices.Equal(fromSamplers, []string{"self-check"}) {
		t.Fatalf("the samplers wrote to the evidence ledger: %v", fromSamplers)
	}
	noSamplesInLedger(t, r)
}

// Every outcome of a round - a read, a skip, a failure, a page not understood, a refusal of the
// login policy, a rejected access code, a store that refuses - leaves the ledger as it was: no
// record, no blob.
func TestConnSamplersNeverWriteTheLedger(t *testing.T) {
	ctx := context.Background()
	r, store := connRig(t, func(c *config.Config) { c.Connections.Interval = config.D(time.Hour) })
	r.cfg.SetDataDir(t.TempDir()) // raw page copies too
	recs := len(r.led.records(""))
	r.led.mu.Lock()
	blobs := len(r.led.blobs)
	r.led.mu.Unlock()
	rounds := []func(){
		func() { answerNAT(r.gw, testNATTable(), testNATPage, nil) },
		func() {
			answerNAT(r.gw, model.NATTable{}, testNATPage, errors.New("gateway: NAT table page not understood: no table"))
		},
		func() {
			answerNAT(r.gw, model.NATTable{}, nil, errors.New("gateway: GET nattable.ha: connection refused"))
		},
		func() { answerNAT(r.gw, model.NATTable{}, nil, &cooldownErr{err: contracts.ErrGatewaySessionsFull}) },
		func() { store.setErr(errors.New("disk full")); answerNAT(r.gw, testNATTable(), testNATPage, nil) },
		func() {
			store.setErr(nil)
			answerNAT(r.gw, model.NATTable{}, nil, fmt.Errorf("gateway login: %w", contracts.ErrGatewayAuth))
		},
		func() {}, // stopped by the rejected access code
	}
	for i, prepare := range rounds {
		prepare()
		r.m.sampleNAT(ctx)
		answerDevices(r.gw, testDevices(), testDevicesPage, nil)
		if i%2 == 1 {
			answerDevices(r.gw, nil, testDevicesPage, errors.New("gateway: Device List page not understood"))
		}
		r.m.sampleDevices(ctx)
	}
	if nat, dev := natCalls(r), devicesCalls(r); nat != 6 || dev != len(rounds) {
		t.Fatalf("%d NAT and %d Device List reads", nat, dev)
	}
	r.led.mu.Lock()
	newBlobs := len(r.led.blobs) - blobs
	r.led.mu.Unlock()
	if n := len(r.led.records("")) - recs; n != 0 || newBlobs != 0 {
		t.Fatalf("the samplers wrote %d records and %d blobs: %v", n, newBlobs, r.led.types(""))
	}
	noSamplesInLedger(t, r)
}

// ---------------------------------------------------------------------------- the NAT read's guard

// No NAT read without an access code, while a changed certificate waits for confirmation, during an
// incident, after a bad cycle, while the gateway does not answer, or half-way through the operator's
// confirmation of a changed certificate (TrustCert holds certMu exclusively: never waited for). Each
// round that leaves the gateway alone says why, and is tried again at the next interval - or
// shortly, when what kept it is short.
func TestNATSamplerGuard(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T, r *rig) (release func())
		want  string
		soon  bool // tried again after busyRetry, not an interval
	}{
		{"no access code", func(t *testing.T, r *rig) func() {
			r.cfg.Gateway.AccessCodeProtected = ""
			return nil
		}, natSkipNoCode, false},
		{"a changed certificate waits for confirmation", func(t *testing.T, r *rig) func() {
			r.cfg.Gateway.PinnedCertSHA256, r.cfg.Gateway.PendingCertSHA256 = "aaaa", "bbbb"
			return nil
		}, natSkipCert, false},
		{"an incident is open", func(t *testing.T, r *rig) func() {
			openIncident(t, r)
			return nil
		}, connSkipIncident, false},
		{"an incident is being closed", func(t *testing.T, r *rig) func() {
			closingIncident(t, r)
			return nil
		}, connSkipIncident, false},
		{"the latest cycle was bad", func(t *testing.T, r *rig) func() {
			r.m.processCycle(context.Background(), time.Now(), time.Millisecond, outageCycle())
			return nil
		}, connSkipFailing, true},
		{"the gateway did not answer the latest poll", func(t *testing.T, r *rig) func() {
			r.m.locked(func() { r.m.st.lastSnap = &snapObs{At: time.Now(), Snap: &model.GatewaySnapshot{}} })
			return nil
		}, "skipped: the gateway did not answer the monitor's latest poll", false},
		{"the operator confirms a changed certificate", func(t *testing.T, r *rig) func() {
			r.m.certMu.Lock() // as TrustCert holds it from moving the pin until the change is recorded
			return r.m.certMu.Unlock
		}, natSkipConfirm, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, store := connRig(t, func(c *config.Config) { c.Connections.Interval = config.D(time.Hour) })
			r.m.conns.busyRetry = time.Minute
			release := tc.setup(t, r)
			if release != nil {
				release = sync.OnceFunc(release) // also when the test fails: nothing is left waiting
				defer release()
			}
			recs := len(r.led.records(""))
			// A round the guard keeps from reading does not even wait for the gateway lock.
			r.m.gwMu.Lock()
			unlocked := false
			unlock := func() {
				if !unlocked {
					unlocked = true
					r.m.gwMu.Unlock()
				}
			}
			defer unlock()
			began := time.Now()
			var next time.Time
			done := make(chan struct{})
			go func() {
				defer close(done)
				next = r.m.sampleNAT(ctx)
			}()
			select {
			case <-done:
			case <-time.After(10 * time.Second):
				t.Fatal("the round waits for the gateway lock")
			}
			unlock()
			if release != nil {
				release()
			}
			if n := natCalls(r); n != 0 {
				t.Fatalf("the NAT table was read %d times", n)
			}
			if nat, _ := store.reads(); len(nat) != 0 {
				t.Fatal("a read was appended")
			}
			wait := time.Hour
			if tc.soon {
				wait = time.Minute
			}
			wantNext(t, tc.name, began, next, wait)
			if st := connStatus(t, r); !strings.Contains(st.NATProblem, tc.want) || st.NATAt != "" || st.InUse != -1 {
				t.Fatalf("status %+v, want the problem %q", st, tc.want)
			}
			if n := len(r.led.records("")) - recs; n != 0 {
				t.Fatalf("the round wrote %d records", n)
			}
			if heldElsewhere(&r.m.notifMu) || heldElsewhere(&r.m.gwMu) || r.m.gwAuth.Load() || certMuHeld(r) != "" {
				t.Fatal("a lock was left held")
			}
		})
	}
}

// The settings check and the operator's changes of a gateway setting hold notifMu across their
// requests to the gateway. The NAT read does not need it: notifMu held, as one of them holds it,
// keeps no read from being made, and the round says nothing went wrong.
func TestNATSamplerReadsWhileNotifMuIsHeld(t *testing.T) {
	ctx := context.Background()
	r, store := connRig(t, func(c *config.Config) { c.Connections.Interval = config.D(time.Hour) })
	r.m.notifMu.Lock()
	defer r.m.notifMu.Unlock()
	began := time.Now()
	wantNext(t, "a round while notifMu is held", began, r.m.sampleNAT(ctx), time.Hour)
	if nat, _ := store.reads(); natCalls(r) != 1 || len(nat) != 1 {
		t.Fatalf("%d reads, %d appended, while notifMu was held", natCalls(r), len(nat))
	}
	if st := connStatus(t, r); st.NATProblem != "" || st.NATAt == "" || st.Sessions != 2 {
		t.Fatalf("status %+v", st)
	}
}

// The NAT read runs holding certMu shared and the gateway lock, with gwAuth raised - and without
// notifMu: a changed certificate that its TLS handshake meets is refused (and held pending) before
// any login data is sent, and the rounds that follow do not read.
func TestNATSamplerIsAnAuthenticatedRequest(t *testing.T) {
	ctx := context.Background()
	r, store := connRig(t, nil)
	r.cfg.Gateway.PinnedCertSHA256 = "aaaa"
	var (
		cert                    string
		notifHeld, gwHeld, auth bool
	)
	r.gw.mu.Lock()
	observe := r.gw.observer
	r.gw.nat = func() (model.NATTable, []byte, error) {
		cert, notifHeld, gwHeld, auth = certMuHeld(r), heldElsewhere(&r.m.notifMu), heldElsewhere(&r.m.gwMu), r.m.gwAuth.Load()
		return testNATTable(), testNATPage, nil
	}
	r.gw.mu.Unlock()
	r.m.sampleNAT(ctx)
	if cert != "shared" || notifHeld || !gwHeld || !auth {
		t.Fatalf("during the read: certMu held %q (want shared), notifMu held %v, gateway lock held %v, gwAuth %v", cert, notifHeld, gwHeld, auth)
	}
	if r.m.gwAuth.Load() || heldElsewhere(&r.m.notifMu) || heldElsewhere(&r.m.gwMu) || certMuHeld(r) != "" {
		t.Fatal("the guard was not released")
	}

	// The gateway presents another certificate during the read: the observer refuses it.
	var accepted atomic.Bool
	r.gw.mu.Lock()
	r.gw.nat = func() (model.NATTable, []byte, error) {
		if observe("aaaa", "cccc") {
			accepted.Store(true)
			return testNATTable(), testNATPage, nil
		}
		return model.NATTable{}, nil, fmt.Errorf("gateway: GET nattable.ha: tls: %w", contracts.ErrGatewayCertRejected)
	}
	r.gw.mu.Unlock()
	r.m.sampleNAT(ctx)
	if accepted.Load() || r.m.pendingCert() != "cccc" {
		t.Fatalf("a changed certificate during the NAT read: accepted %v, pending %q", accepted.Load(), r.m.pendingCert())
	}
	if st := connStatus(t, r); st.NATProblem != natSkipCert {
		t.Fatalf("problem %q", st.NATProblem)
	}
	calls := natCalls(r)
	r.m.sampleNAT(ctx)
	if natCalls(r) != calls {
		t.Fatal("read while the changed certificate waits for confirmation")
	}
	if nat, _ := store.reads(); len(nat) != 1 {
		t.Fatalf("%d reads appended", len(nat))
	}
}

// A round waits for the gateway lock (a status read, or an authenticated operation, holds it) -
// holding certMu shared, not notifMu - and reads once it is free - unless meanwhile a changed
// certificate became pending (withGatewayAuth checks under the lock) or an incident opened.
func TestNATSamplerWaitsForTheGatewayLock(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name  string
		while func(t *testing.T, r *rig) // done while the round waits
		read  bool
		want  string
	}{
		{"free again", func(*testing.T, *rig) {}, true, ""},
		{"a certificate became pending", func(t *testing.T, r *rig) {
			r.m.cfgMu.Lock()
			r.cfg.Gateway.PendingCertSHA256 = "bbbb"
			r.m.cfgMu.Unlock()
		}, false, natSkipCert},
		{"an incident opened", func(t *testing.T, r *rig) { openIncident(t, r) }, false, connSkipIncident},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, store := connRig(t, nil)
			r.m.gwMu.Lock()
			r.m.gwAuth.Store(true) // as an authenticated operation would
			free := sync.OnceFunc(func() {
				r.m.gwAuth.Store(false)
				r.m.gwMu.Unlock()
			})
			defer free() // also when the test fails: nothing is left waiting
			done := make(chan struct{})
			go func() {
				defer close(done)
				r.m.sampleNAT(ctx)
			}()
			waitFor(t, "the round to wait for the gateway lock", 10*time.Second, natRoundWaitsForTheGatewayLock)
			if natCalls(r) != 0 || certMuHeld(r) != "shared" || heldElsewhere(&r.m.notifMu) {
				t.Fatalf("read while the gateway lock was held, or waiting without certMu held shared (%q) or with notifMu", certMuHeld(r))
			}
			tc.while(t, r)
			free()
			await(t, "the round", done)
			nat, _ := store.reads()
			if got := natCalls(r) == 1 && len(nat) == 1; got != tc.read {
				t.Fatalf("read %v (%d calls, %d appended), want %v", got, natCalls(r), len(nat), tc.read)
			}
			if st := connStatus(t, r); st.NATProblem != tc.want {
				t.Fatalf("problem %q, want %q", st.NATProblem, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------- among the other authenticated operations

// networkRig is a connRig (NAT reads every hour) whose monitor also keeps the gateway's settings:
// the redirect is on, the Syslog page is the owner's real one (off), and this computer's address
// toward the gateway is 192.168.1.71.
func networkRig(t *testing.T) (*rig, *fakeConnStore, *syslogSim) {
	t.Helper()
	r, store := connRig(t, func(c *config.Config) { c.Connections.Interval = config.D(time.Hour) })
	ip := &atomic.Value{}
	ip.Store("192.168.1.71")
	linkAt(r, ip)
	r.m.checkLocalLink(context.Background(), false)
	sim := newSyslogSim(r.gw, realSyslogOff(), realSyslogPage(t))
	r.gw.mu.Lock()
	r.gw.notif = true
	r.gw.mu.Unlock()
	return r, store, sim
}

// gate returns a channel and the function that closes it, once however often it is called: what
// waits for the channel goes on when the test opens the gate - or ends, when the test defers it, so
// that a test that fails leaves nothing waiting.
func gate() (ch chan struct{}, open func()) {
	ch = make(chan struct{})
	var once sync.Once
	return ch, func() { once.Do(func() { close(ch) }) }
}

// holdNATRead makes r's NAT reads wait until release is called (or their context ends), then
// answer testNATTable; entered is closed once the first has begun. Such a read holds certMu shared
// and the gateway lock until then.
func holdNATRead(r *rig) (entered chan struct{}, release func()) {
	entered, enter := gate()
	released, release := gate()
	r.m.conns.natTimeout = time.Hour
	r.gw.mu.Lock()
	defer r.gw.mu.Unlock()
	r.gw.natCtx = func(ctx context.Context) (model.NATTable, []byte, error) {
		enter()
		select {
		case <-released:
			return testNATTable(), testNATPage, nil
		case <-ctx.Done():
			return model.NATTable{}, nil, fmt.Errorf("gateway: GET nattable.ha: %w", ctx.Err())
		}
	}
	return entered, release
}

// await returns what ch delivers - the zero value once it is closed - failing the test after 10 s.
func await[T any](t *testing.T, what string, ch chan T) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(10 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
		panic("unreachable")
	}
}

// A NAT read holds the gateway lock and certMu shared, not notifMu: an operator's change of a
// gateway setting - the redirect, the Syslog page - or a settings check that starts while a read is
// in progress is not refused as busy (the dashboard would answer 409): it waits for the read at the
// gateway lock, asking the gateway nothing meanwhile, and is made once the read has ended. The read
// is kept.
func TestGatewayChangesWaitForANATRead(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name   string
		by     string // the method that waits for the gateway lock
		change func(r *rig) error
		made   func(t *testing.T, r *rig, sim *syslogSim)
	}{
		{"the operator turns the redirect off", "SetGatewayNotification", func(r *rig) error {
			cc, err := r.m.SetGatewayNotification(ctx, false, "operator via web")
			if err == nil && cc.Result != "verified" {
				err = fmt.Errorf("the change %+v", cc)
			}
			return err
		}, func(t *testing.T, r *rig, _ *syslogSim) {
			r.gw.mu.Lock()
			defer r.gw.mu.Unlock()
			if !slices.Equal(r.gw.setCalls, []bool{false}) || r.gw.notif {
				t.Fatalf("the redirect changed %v, now on: %v", r.gw.setCalls, r.gw.notif)
			}
		}},
		{"the operator points the Syslog page at this computer", "SetGatewaySyslog", func(r *rig) error {
			cc, err := r.m.SetGatewaySyslog(ctx, true, "web")
			if err == nil && cc.Result != "verified" {
				err = fmt.Errorf("the change %+v", cc)
			}
			return err
		}, func(t *testing.T, r *rig, sim *syslogSim) {
			if got, posts := sim.current(); posts != 1 || !got.Enabled || got.Server != "192.168.1.71" {
				t.Fatalf("the Syslog page %+v after %d changes", got, posts)
			}
		}},
		{"a settings check", "checkSettings", func(r *rig) error { return r.m.checkNotification(ctx) }, func(t *testing.T, r *rig, sim *syslogSim) {
			r.gw.mu.Lock()
			reads, sets := r.gw.notifCalls, slices.Clone(r.gw.setCalls)
			r.gw.mu.Unlock()
			if got, posts := sim.current(); reads != 1 || !slices.Equal(sets, []bool{false}) || posts != 1 || !got.Enabled {
				t.Fatalf("%d reads of the redirect, changes %v; the Syslog page %+v after %d changes", reads, sets, got, posts)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, store, sim := networkRig(t)
			entered, release := holdNATRead(r)
			defer release()
			round := make(chan struct{})
			go func() {
				defer close(round)
				r.m.sampleNAT(ctx)
			}()
			await(t, "the NAT read", entered)
			recs := len(r.led.records(""))
			changed := make(chan error, 1)
			go func() { changed <- tc.change(r) }()
			waitFor(t, "the change to wait for the gateway lock", 10*time.Second, func() bool {
				select {
				case err := <-changed:
					t.Fatalf("the change ended while the NAT read was in progress: %v", err)
				default:
				}
				return waitingForALock("withGatewayAuth", tc.by)
			})
			r.gw.mu.Lock()
			asked := r.gw.notifCalls + len(r.gw.setCalls) + r.gw.syslogCalls + len(r.gw.setSyslogWants)
			r.gw.mu.Unlock()
			if n := len(r.led.records("")) - recs; asked != 0 || n != 0 {
				t.Fatalf("during the NAT read the change made %d requests to the gateway and %d records", asked, n)
			}
			release()
			await(t, "the end of the NAT round", round)
			if err := await(t, "the change", changed); err != nil {
				t.Fatalf("the change after the NAT read: %v", err)
			}
			tc.made(t, r, sim)
			if nat, _ := store.reads(); len(nat) != 1 || natProblem(r) != "" {
				t.Fatalf("%d NAT reads appended, problem %q", len(nat), natProblem(r))
			}
		})
	}
}

// pinGuard makes every NAT read of r note what is wrong with the certificate it runs with: one
// waiting for confirmation, or fpB - the certificate the operator confirms in these tests - before
// the config_change that trusts it is in the ledger (the fake ledger reports every record as it is
// appended). It returns a check that fails the test when a read did.
func pinGuard(r *rig) (checkPins func(t *testing.T)) {
	var (
		mu       sync.Mutex
		notes    []string
		recorded atomic.Bool
	)
	r.led.mu.Lock()
	r.led.onAppend = func(b model.Body) {
		var cc model.ConfigChange
		if b.Type == model.TypeConfigChange && json.Unmarshal(b.Data, &cc) == nil && cc.After == fpB {
			recorded.Store(true)
		}
	}
	r.led.mu.Unlock()
	r.gw.mu.Lock()
	r.gw.nat = func() (model.NATTable, []byte, error) {
		pinned, pending := pins(r)
		if pending != "" || (pinned == fpB && !recorded.Load()) {
			mu.Lock()
			notes = append(notes, fmt.Sprintf("a NAT read with the pin %.8s (pending %.8s; the change trusting it recorded: %v)", pinned, pending, recorded.Load()))
			mu.Unlock()
		}
		return testNATTable(), testNATPage, nil
	}
	r.gw.mu.Unlock()
	return func(t *testing.T) {
		t.Helper()
		mu.Lock()
		defer mu.Unlock()
		if len(notes) > 0 {
			t.Fatalf("%d NAT reads ran with a certificate they must not use; the first: %s", len(notes), notes[0])
		}
	}
}

// confirmRig is a connRig (NAT reads every hour) whose pinned gateway certificate is fpA while fpB
// waits for the operator's confirmation, as certRig leaves it; its NAT reads are watched by
// pinGuard.
func confirmRig(t *testing.T) (*rig, *fakeConnStore, func(t *testing.T)) {
	t.Helper()
	r, store := connRig(t, func(c *config.Config) { c.Connections.Interval = config.D(time.Hour) })
	r.cfg.Gateway.PinnedCertSHA256 = fpA
	if !r.gw.observer(fpA, fpB) {
		t.Fatal("a status page must keep being read")
	}
	return r, store, pinGuard(r)
}

// TrustCert moves the pin before it records the change, and moves it back when the record fails.
// In between nothing is pending, so withGatewayAuth would let an authenticated request through:
// TrustCert holds certMu exclusively throughout, and the NAT read - which does not take notifMu -
// holds it shared, never waiting for it. A round that comes during a confirmation is skipped and
// tried again shortly, no NAT read ever runs with a pin whose change is not recorded, and a
// confirmation waits for a read in progress rather than move the pin under it.
func TestNATReadNeverUsesAnUnrecordedPin(t *testing.T) {
	ctx := context.Background()
	trust := func(r *rig) chan error {
		done := make(chan error, 1)
		go func() {
			cc, err := r.m.TrustCert(ctx, "operator via web", fpB)
			if err == nil && (cc.After != fpB || cc.Result != "applied") {
				err = fmt.Errorf("the change %+v", cc)
			}
			done <- err
		}()
		return done
	}
	// moved waits until TrustCert has moved (and saved) the pin and waits for stMu, which the test
	// holds, to record the change.
	moved := func(t *testing.T, r *rig) {
		t.Helper()
		waitFor(t, "the pin to move", 10*time.Second, func() bool {
			pinned, pending := pins(r)
			return pinned == fpB && pending == "" && waitingForALock("appendApply", "TrustCert")
		})
	}
	// duringConfirmation makes a NAT round while TrustCert waits to record, which must not wait for
	// it, and returns when the next round is due.
	duringConfirmation := func(t *testing.T, r *rig) time.Time {
		t.Helper()
		var next time.Time
		round := make(chan struct{})
		go func() {
			defer close(round)
			next = r.m.sampleNAT(ctx)
		}()
		await(t, "a NAT round during the confirmation, which must not wait for it", round)
		return next
	}

	t.Run("while it saves the configuration", func(t *testing.T) {
		r, _, checkPins := confirmRig(t)
		saving, saved := gate()
		released, release := gate()
		defer release()
		r.m.opts.SaveConfig = func(*config.Config) error {
			saved()
			<-released
			return nil
		}
		done := trust(r)
		await(t, "TrustCert to save the configuration", saving)
		// The pin has moved in memory and nothing is recorded; TrustCert holds the configuration
		// lock, which the read would wait for in withGatewayAuth: it must be refused before that.
		read := make(chan error, 1)
		go func() {
			_, _, _, err := r.m.readNAT(ctx)
			read <- err
		}()
		if err := await(t, "a NAT read during the confirmation, which must not wait for it", read); !errors.Is(err, errCertConfirming) {
			t.Fatalf("a NAT read during the confirmation: %v", err)
		}
		if n := natCalls(r); n != 0 {
			t.Fatalf("the NAT table was read %d times during the confirmation", n)
		}
		// A round that comes now waits for the configuration lock (natPaused), then finds the
		// confirmation still in progress - or reads after the change was recorded.
		round := make(chan struct{})
		go func() {
			defer close(round)
			r.m.sampleNAT(ctx)
		}()
		release()
		if err := await(t, "TrustCert", done); err != nil {
			t.Fatal(err)
		}
		await(t, "the round", round)
		if n, p := natCalls(r), natProblem(r); (n != 0 || p != natSkipConfirm) && (n != 1 || p != "") {
			t.Fatalf("a round during the confirmation: %d reads, problem %q", n, p)
		}
		r.m.sampleNAT(ctx)
		checkPins(t)
		if n, p := natCalls(r), natProblem(r); n == 0 || p != "" {
			t.Fatalf("after the confirmation: %d reads, problem %q", n, p)
		}
	})

	t.Run("while it records the change", func(t *testing.T) {
		r, store, checkPins := confirmRig(t)
		r.m.stMu.Lock() // TrustCert moves the pin, saves it, and waits here to record the change
		held := true
		defer func() {
			if held {
				r.m.stMu.Unlock()
			}
		}()
		done := trust(r)
		moved(t, r)
		began := time.Now()
		next := duringConfirmation(t, r)
		wantNext(t, "a round during the confirmation", began, next, r.m.conns.busyRetry)
		if n, p := natCalls(r), natProblem(r); n != 0 || p != natSkipConfirm {
			t.Fatalf("a round during the confirmation: %d reads, problem %q", n, p)
		}
		if n := len(ofType(r.led.records(""), model.TypeConfigChange)); n != 0 {
			t.Fatalf("%d config_change records before TrustCert wrote its own", n)
		}
		held = false
		r.m.stMu.Unlock()
		if err := await(t, "TrustCert", done); err != nil {
			t.Fatal(err)
		}
		r.m.sampleNAT(ctx) // recorded: the authenticated requests resume
		if nat, _ := store.reads(); natCalls(r) != 1 || len(nat) != 1 || natProblem(r) != "" {
			t.Fatalf("after the confirmation: %d reads, %d appended, problem %q", natCalls(r), len(nat), natProblem(r))
		}
		checkPins(t)
	})

	t.Run("the change cannot be recorded", func(t *testing.T) {
		r, store, checkPins := confirmRig(t)
		r.m.stMu.Lock()
		held := true
		defer func() {
			if held {
				r.m.stMu.Unlock()
			}
		}()
		done := trust(r)
		moved(t, r)
		setAppendErr(r.led, errors.New("disk full"))
		duringConfirmation(t, r)
		if n, p := natCalls(r), natProblem(r); n != 0 || p != natSkipConfirm {
			t.Fatalf("a round during the confirmation: %d reads, problem %q", n, p)
		}
		held = false
		r.m.stMu.Unlock()
		if err := await(t, "TrustCert", done); err == nil {
			t.Fatal("the certificate was trusted without a record")
		}
		if pinned, pending := pins(r); pinned != fpA || pending != fpB {
			t.Fatalf("after the failed record: pin %.8s, pending %.8s (the move is undone)", pinned, pending)
		}
		setAppendErr(r.led, nil)
		r.m.sampleNAT(ctx) // the certificate waits for confirmation again
		if nat, _ := store.reads(); natCalls(r) != 0 || len(nat) != 0 || natProblem(r) != natSkipCert {
			t.Fatalf("after the failed confirmation: %d reads, %d appended, problem %q", natCalls(r), len(nat), natProblem(r))
		}
		checkPins(t)
	})

	t.Run("a NAT read in progress is waited for", func(t *testing.T) {
		r, _ := connRig(t, func(c *config.Config) { c.Connections.Interval = config.D(time.Hour) })
		r.cfg.Gateway.PinnedCertSHA256 = fpA
		r.m.conns.natTimeout = time.Hour
		entered, enter := gate()
		released, release := gate()
		defer release()
		var (
			accepted                    bool
			duringPinned, duringPending string // the certificates when the read ended
		)
		r.gw.mu.Lock()
		observe := r.gw.observer
		r.gw.natCtx = func(context.Context) (model.NATTable, []byte, error) {
			// The read's TLS handshake meets a changed certificate: the observer refuses it and
			// holds it pending - the operator now confirms it while the read goes on.
			accepted = observe(fpA, fpB)
			enter()
			<-released
			duringPinned, duringPending = pins(r)
			return model.NATTable{}, nil, fmt.Errorf("gateway: GET nattable.ha: tls: %w", contracts.ErrGatewayCertRejected)
		}
		r.gw.mu.Unlock()
		round := make(chan struct{})
		go func() {
			defer close(round)
			r.m.sampleNAT(ctx)
		}()
		await(t, "the NAT read", entered)
		done := trust(r)
		waitFor(t, "TrustCert to wait for the NAT read", 10*time.Second, func() bool {
			select {
			case err := <-done:
				t.Fatalf("TrustCert did not wait for the NAT read in progress: %v", err)
			default:
			}
			return waitingForALock("TrustCert")
		})
		if pinned, pending := pins(r); pinned != fpA || pending != fpB {
			t.Fatalf("during the NAT read: pin %.8s, pending %.8s", pinned, pending)
		}
		release()
		await(t, "the NAT round", round)
		if err := await(t, "TrustCert", done); err != nil {
			t.Fatal(err)
		}
		if accepted || duringPinned != fpA || duringPending != fpB {
			t.Fatalf("the changed certificate accepted by the read: %v; at the end of the read: pin %.8s, pending %.8s", accepted, duringPinned, duringPending)
		}
		if pinned, pending := pins(r); pinned != fpB || pending != "" || natProblem(r) != natSkipCert {
			t.Fatalf("pin %.8s, pending %.8s, problem %q", pinned, pending, natProblem(r))
		}
	})

	t.Run("concurrently", func(t *testing.T) {
		for range 20 {
			r, _, checkPins := confirmRig(t)
			// The rounds run without pause while the operator confirms; the record takes a moment,
			// which widens the window between the move of the pin and its record.
			r.led.setRejectRecord(func(typ string) error {
				if typ == model.TypeConfigChange {
					time.Sleep(time.Millisecond)
				}
				return nil
			})
			stop := make(chan struct{})
			var wg sync.WaitGroup
			wg.Go(func() {
				for {
					select {
					case <-stop:
						return
					default:
					}
					r.m.sampleNAT(ctx)
					runtime.Gosched()
				}
			})
			_, err := r.m.TrustCert(ctx, "operator via web", fpB)
			close(stop)
			wg.Wait()
			if err != nil {
				t.Fatal(err)
			}
			r.m.sampleNAT(ctx)
			checkPins(t)
			if natCalls(r) == 0 {
				t.Fatal("no NAT read after the confirmation")
			}
		}
	})
}

// The settings check and the operator's changes of a gateway setting still exclude each other
// (notifMu), whatever the NAT reads do: an operator's change that comes while a check runs is
// refused as busy at once and asks the gateway nothing - while a NAT round that comes then is not
// refused: it waits for the check's request in progress at the gateway lock and reads after it -
// and a check that comes while an operator's change runs - here between the change's read of the
// Syslog page and its change of it, when the change holds no lock but notifMu - makes its first
// request only once the change has ended, and finds what the operator set.
func TestSettingsCheckAndOperatorChangesNeverInterleave(t *testing.T) {
	ctx := context.Background()
	r, store, sim := networkRig(t)
	r.cfg.Gateway.EnforceSyslog = false // the operator switched the Syslog page off earlier
	readIn, readEntered := gate()
	readOut, readGo := gate()
	routeIn, routeEntered := gate()
	routeOut, routeGo := gate()
	defer readGo()
	defer routeGo()
	r.gw.mu.Lock()
	r.gw.notif = false
	read := r.gw.syslog
	r.gw.syslog = func() (model.SyslogSetting, []byte, error) { // the first read waits for readGo
		readEntered()
		<-readOut
		return read()
	}
	r.gw.mu.Unlock()
	// The route to the gateway is looked up when the Syslog page is to be set, between its read and
	// its change (syslogLocalAddr): once armed, the next lookup waits for routeGo.
	var routeArmed atomic.Bool
	route := r.m.route
	r.m.route = func(dst netip.Addr) (routeInfo, error) {
		if routeArmed.CompareAndSwap(true, false) {
			routeEntered()
			<-routeOut
		}
		return route(dst)
	}
	gwCalls := func() (notifReads, notifSets, syslogReads, syslogSets int) {
		r.gw.mu.Lock()
		defer r.gw.mu.Unlock()
		return r.gw.notifCalls, len(r.gw.setCalls), r.gw.syslogCalls, len(r.gw.setSyslogWants)
	}
	// busy makes an operator's change that must be refused at once, as busy.
	busy := func(what string, change func() error) {
		t.Helper()
		done := make(chan error, 1)
		go func() { done <- change() }()
		if err := await(t, what+", which must be refused at once", done); !errors.Is(err, contracts.ErrBusy) {
			t.Fatalf("%s: %v", what, err)
		}
	}
	setRedirect := func() error {
		_, err := r.m.SetGatewayNotification(ctx, true, "operator via web")
		return err
	}

	// A settings check has read the redirect setting and waits in its read of the Syslog page,
	// holding notifMu (and, for that request, the gateway lock).
	checked := make(chan error, 1)
	go func() { checked <- r.m.checkNotification(ctx) }()
	await(t, "the check's read of the Syslog page", readIn)
	recs := len(r.led.records(""))
	busy("a change of the redirect during the settings check", setRedirect)
	busy("a change of the Syslog page during the settings check", func() error {
		_, err := r.m.SetGatewaySyslog(ctx, true, "web")
		return err
	})
	if nr, ns, sr, ss := gwCalls(); nr != 1 || ns != 0 || sr != 1 || ss != 0 {
		t.Fatalf("during the check: %d reads and %d changes of the redirect, %d reads and %d changes of the Syslog page", nr, ns, sr, ss)
	}
	if enforce, _ := r.m.syslogConfig(); enforce || len(r.led.records("")) != recs {
		t.Fatal("an operator's change refused as busy changed something")
	}
	round := make(chan struct{})
	go func() {
		defer close(round)
		r.m.sampleNAT(ctx)
	}()
	waitFor(t, "the NAT round to wait for the gateway lock", 10*time.Second, func() bool {
		select {
		case <-round:
			t.Fatalf("the NAT round ended during the check's request: %d reads, problem %q", natCalls(r), natProblem(r))
		default:
		}
		return natRoundWaitsForTheGatewayLock()
	})
	if n := natCalls(r); n != 0 {
		t.Fatalf("the NAT table was read %d times during the check's request", n)
	}
	readGo()
	await(t, "the NAT round", round)
	if err := await(t, "the settings check", checked); err != nil {
		t.Fatal(err)
	}
	if nat, _ := store.reads(); natCalls(r) != 1 || len(nat) != 1 || natProblem(r) != "" {
		t.Fatalf("the NAT round after the check's request: %d reads, %d appended, problem %q", natCalls(r), len(nat), natProblem(r))
	}

	// The operator points the Syslog page at this computer: the choice is recorded and the page
	// read; the change waits before it sets the page, holding notifMu and no other lock.
	routeArmed.Store(true)
	changed := make(chan error, 1)
	go func() {
		cc, err := r.m.SetGatewaySyslog(ctx, true, "web")
		if err == nil && cc.Result != "verified" {
			err = fmt.Errorf("the change %+v", cc)
		}
		changed <- err
	}()
	await(t, "the operator's change of the Syslog page", routeIn)
	checked = make(chan error, 1)
	go func() { checked <- r.m.checkNotification(ctx) }()
	waitFor(t, "the settings check to wait for the change", 10*time.Second, func() bool {
		select {
		case err := <-checked:
			t.Fatalf("the settings check ran during the operator's change: %v", err)
		default:
		}
		return waitingForALock("checkSettings")
	})
	busy("a change of the redirect during the change of the Syslog page", setRedirect)
	if nr, ns, sr, ss := gwCalls(); nr != 1 || ns != 0 || sr != 2 || ss != 0 {
		t.Fatalf("during the operator's change: %d reads and %d changes of the redirect, %d reads and %d changes of the Syslog page", nr, ns, sr, ss)
	}
	routeGo()
	if err := await(t, "the operator's change", changed); err != nil {
		t.Fatal(err)
	}
	if err := await(t, "the settings check", checked); err != nil {
		t.Fatal(err)
	}
	// The check came after the change: it read the page the operator had set, and set nothing.
	got, posts := sim.current()
	if nr, ns, sr, ss := gwCalls(); nr != 2 || ns != 0 || sr != 3 || ss != 1 || posts != 1 || !got.Enabled || got.Server != "192.168.1.71" {
		t.Fatalf("after both: %d reads and %d changes of the redirect, %d reads and %d changes of the Syslog page; the page %+v after %d posts",
			nr, ns, sr, ss, got, posts)
	}
}

// ---------------------------------------------------------------------------- the login policy

// cooldownErr is a refusal of the gateway client's login policy as the client returns it
// (gateway.CooldownError): it matches the contracts sentinel and, with until set, says when the
// next login attempt is allowed.
type cooldownErr struct {
	err   error
	until time.Time
}

func (e *cooldownErr) Error() string {
	return fmt.Sprintf("%v (no login attempt before %s)", e.err, e.until.UTC().Format(time.RFC3339))
}

func (e *cooldownErr) Unwrap() error            { return e.err }
func (e *cooldownErr) CooldownUntil() time.Time { return e.until }

// A refusal of the login policy waits until its cooldown ends - what the refusal says, else the
// policy's longest of that kind, never more than an hour - and at least an interval.
func TestNATSamplerFollowsTheLoginPolicy(t *testing.T) {
	ctx := context.Background()
	const interval = 10 * time.Minute
	in := func(d time.Duration) time.Time { return time.Now().Add(d) }
	for _, tc := range []struct {
		name string
		err  error
		want string
		wait time.Duration
	}{
		{"a login throttled until within the interval", &cooldownErr{contracts.ErrGatewayLoginThrottled, in(30 * time.Second)},
			"a login was attempted less than a minute before", interval},
		{"sessions full until beyond the interval", &cooldownErr{contracts.ErrGatewaySessionsFull, in(20 * time.Minute)},
			"the gateway's web sessions are all in use", 20 * time.Minute},
		{"sessions full, the end not said", fmt.Errorf("gateway: %w", contracts.ErrGatewaySessionsFull),
			"the gateway's web sessions are all in use", interval},
		{"logins paused until", &cooldownErr{contracts.ErrGatewayAuthLocked, in(45 * time.Minute)},
			"logins are paused after 3 rejected attempts within an hour", 45 * time.Minute},
		{"logins paused, the end not said", fmt.Errorf("gateway: %w", contracts.ErrGatewayAuthLocked),
			"logins are paused after 3 rejected attempts within an hour", time.Hour},
		{"a cooldown beyond the policy's longest", &cooldownErr{contracts.ErrGatewayAuthLocked, in(5 * time.Hour)},
			"logins are paused", time.Hour},
		{"a cooldown in the past", &cooldownErr{contracts.ErrGatewaySessionsFull, in(-time.Hour)},
			"the gateway's web sessions are all in use", interval},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, store := connRig(t, func(c *config.Config) { c.Connections.Interval = config.D(interval) })
			answerNAT(r.gw, model.NATTable{}, nil, tc.err)
			began := time.Now()
			next := r.m.sampleNAT(ctx)
			wantNext(t, tc.name, began, next, tc.wait)
			st := connStatus(t, r)
			if !strings.Contains(st.NATProblem, tc.want) {
				t.Fatalf("problem %q", st.NATProblem)
			}
			if at := problemTime(t, st.NATProblem, "the next NAT read is at "); at.Sub(next).Abs() > 2*time.Second {
				t.Fatalf("the problem says the next read is at %v, it is due at %v", at, next)
			}
			if nat, _ := store.reads(); len(nat) != 0 || st.NATAt != "" {
				t.Fatal("a refused read was kept")
			}
		})
	}
}

// After a rejected access code (or one that could not be used) the NAT reads stop - the rounds go
// on every interval but only look whether the stored code changed - until the code is stored anew,
// in the configuration or as the keys file, or authRetry has passed; the status says when the next
// read is at the latest.
func TestNATSamplerStopsAfterARejectedAccessCode(t *testing.T) {
	ctx := context.Background()
	rejected := fmt.Errorf("gateway: login rejected: redirected back to login.ha (1 of 3 allowed failures within an hour): %w", contracts.ErrGatewayAuth)
	for _, tc := range []struct {
		name    string
		err     error
		want    string
		keyFile bool // the code is stored in keys\gateway-access-code.dpapi
	}{
		{"rejected", rejected, "the gateway rejected the access code at ", false},
		{"rejected, the code in the keys file", rejected, "the gateway rejected the access code at ", true},
		{"unusable", fmt.Errorf("gateway: no access code available: DPAPI: %w", contracts.ErrGatewayNoAccessCode),
			"the stored gateway access code could not be used (gateway: no access code available: DPAPI", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const interval = 10 * time.Minute
			r, store := connRig(t, func(c *config.Config) { c.Connections.Interval = config.D(interval) })
			storeCode := func(blob string) {
				r.m.cfgMu.Lock()
				defer r.m.cfgMu.Unlock()
				if !tc.keyFile {
					r.cfg.Gateway.AccessCodeProtected = blob
					return
				}
				path := config.AccessCodeFile(r.cfg.DataDir())
				if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(blob), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if tc.keyFile {
				r.cfg.SetDataDir(t.TempDir())
				r.cfg.Gateway.AccessCodeProtected = ""
				storeCode("dpapi-blob-1")
			}
			answerNAT(r.gw, model.NATTable{}, nil, tc.err)
			began := time.Now()
			next := r.m.sampleNAT(ctx)
			wantNext(t, "after the rejection", began, next, interval) // the rounds go on, to see a new code
			st := connStatus(t, r)
			mustContain(t, "the problem", st.NATProblem, tc.want, "NAT reads stop until it is stored anew (att-monitor set-access-code)", "at the latest")
			if at, ok := parseTS(st.NATNext); !ok || at.Sub(began) < time.Hour-time.Second || at.Sub(began) > time.Hour+time.Second {
				t.Fatalf("the next read %q, want an hour after the rejection", st.NATNext)
			}
			// The same code: no read, the same problem.
			r.m.sampleNAT(ctx)
			if n := natCalls(r); n != 1 {
				t.Fatalf("%d reads with the rejected code", n)
			}
			if p := connStatus(t, r).NATProblem; p != st.NATProblem {
				t.Fatalf("problem %q, want %q", p, st.NATProblem)
			}
			// A code stored anew: read (and rejected again).
			storeCode("dpapi-blob-2-longer")
			r.m.sampleNAT(ctx)
			if n := natCalls(r); n != 2 {
				t.Fatalf("%d reads after a new code was stored", n)
			}
			r.m.sampleNAT(ctx)
			if n := natCalls(r); n != 2 {
				t.Fatalf("%d reads: the new code was rejected too", n)
			}
			// An hour later the same code is tried again; the read works this time.
			r.m.conns.locked(func() { r.m.conns.nat.stopUntil = time.Now().Add(-time.Millisecond) })
			answerNAT(r.gw, testNATTable(), testNATPage, nil)
			r.m.sampleNAT(ctx)
			if nat, _ := store.reads(); natCalls(r) != 3 || len(nat) != 1 {
				t.Fatalf("%d reads, %d appended, after the pause", natCalls(r), len(nat))
			}
			if st := connStatus(t, r); st.NATProblem != "" || st.NATAt == "" {
				t.Fatalf("status %+v", st)
			}
		})
	}
}

// ---------------------------------------------------------------------------- failures

// A failed read says why and is tried again at the next interval; a page that was not understood
// says so; a read that the connection store refuses still counts as a read - the table was read -
// and its note says that it was not kept.
func TestNATSamplerFailures(t *testing.T) {
	ctx := context.Background()
	r, store := connRig(t, func(c *config.Config) { c.Connections.Interval = config.D(time.Hour) })
	answerNAT(r.gw, model.NATTable{}, nil, errors.New("gateway: GET nattable.ha: connection refused"))
	began := time.Now()
	wantNext(t, "after a failed read", began, r.m.sampleNAT(ctx), time.Hour)
	if st := connStatus(t, r); st.NATProblem != "the NAT table could not be read: gateway: GET nattable.ha: connection refused" || st.NATAt != "" {
		t.Fatalf("status %+v", st)
	}
	answerNAT(r.gw, model.NATTable{}, []byte("<html>?</html>"), errors.New("gateway: NAT table page not understood: no session table"))
	r.m.sampleNAT(ctx)
	if p := connStatus(t, r).NATProblem; !strings.HasPrefix(p, "the NAT table could not be read: gateway: NAT table page not understood: no session table; 2 reads in a row failed") ||
		strings.Contains(p, "copy") {
		t.Fatalf("problem %q (no data directory: no copy)", p)
	}
	store.setErr(errors.New("connstore: disk full"))
	answerNAT(r.gw, testNATTable(), testNATPage, nil)
	r.m.sampleNAT(ctx)
	st := connStatus(t, r)
	if st.NATProblem != "" || st.NATNote != "the connection store could not keep the newest read: connstore: disk full" || st.NATAt == "" || st.Sessions != 2 {
		t.Fatalf("status %+v", st)
	}
	store.setErr(nil)
	r.m.sampleNAT(ctx)
	if st := connStatus(t, r); st.NATProblem != "" || st.NATNote != "" {
		t.Fatalf("problem %q, note %q after a read that was kept", st.NATProblem, st.NATNote)
	}
	if nat, _ := store.reads(); len(nat) != 1 {
		t.Fatalf("%d reads appended", len(nat))
	}
}

// A read is bounded by natTimeout (devTimeout for the Device List) and ends with its context; the
// locks are released either way.
func TestConnSamplersHonourTheTimeout(t *testing.T) {
	ctx := context.Background()
	r, _ := connRig(t, nil)
	c := r.m.conns
	c.natTimeout, c.devTimeout = 50*time.Millisecond, 50*time.Millisecond
	r.gw.mu.Lock()
	r.gw.natCtx = func(ctx context.Context) (model.NATTable, []byte, error) {
		<-ctx.Done()
		return model.NATTable{}, nil, fmt.Errorf("gateway: GET nattable.ha: %w", ctx.Err())
	}
	r.gw.devicesCtx = func(ctx context.Context) ([]model.LANDevice, []byte, error) {
		<-ctx.Done()
		return nil, nil, fmt.Errorf("gateway: GET devices.ha: %w", ctx.Err())
	}
	r.gw.mu.Unlock()
	start := time.Now()
	r.m.sampleNAT(ctx)
	r.m.sampleDevices(ctx)
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("the reads took %v", d)
	}
	st := connStatus(t, r)
	mustContain(t, "the NAT problem", st.NATProblem, "the NAT table could not be read", "deadline exceeded")
	mustContain(t, "the Device List problem", st.DevicesProblem, "the Device List could not be read", "deadline exceeded")
	if heldElsewhere(&r.m.notifMu) || heldElsewhere(&r.m.gwMu) || r.m.gwAuth.Load() || certMuHeld(r) != "" {
		t.Fatal("a lock was left held")
	}

	// A read stopped by the end of its context (the monitor stops) says nothing.
	cctx, cancel := context.WithCancel(ctx)
	c.natTimeout = time.Hour
	r.gw.mu.Lock()
	r.gw.natCtx = func(ctx context.Context) (model.NATTable, []byte, error) {
		cancel()
		<-ctx.Done()
		return model.NATTable{}, nil, ctx.Err()
	}
	r.gw.mu.Unlock()
	r.m.sampleNAT(cctx)
	if p := connStatus(t, r).NATProblem; p != st.NATProblem {
		t.Fatalf("problem %q after a read the stop ended", p)
	}
}

// A read in progress is stopped as soon as the gateway is needed for evidence - here a cycle fails,
// the first sign of an incident that may be opening - and the round says so (and is tried again
// shortly); it is not a failure.
func TestConnSamplersStopForTheEvidence(t *testing.T) {
	ctx := context.Background()
	t.Run("a cycle fails during the NAT read", func(t *testing.T) {
		r, store := connRig(t, func(c *config.Config) { c.Connections.Interval = config.D(time.Hour) })
		r.m.conns.natTimeout, r.m.conns.busyRetry = time.Hour, time.Minute
		entered := make(chan struct{})
		r.gw.mu.Lock()
		r.gw.natCtx = func(ctx context.Context) (model.NATTable, []byte, error) {
			close(entered)
			<-ctx.Done()
			return model.NATTable{}, nil, fmt.Errorf("gateway: GET nattable.ha: %w", ctx.Err())
		}
		r.gw.mu.Unlock()
		done := make(chan struct{})
		var next time.Time
		began := time.Now()
		go func() {
			defer close(done)
			next = r.m.sampleNAT(ctx)
		}()
		<-entered
		r.m.processCycle(ctx, time.Now(), time.Millisecond, outageCycle())
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Fatal("the NAT read was not stopped")
		}
		wantNext(t, "after the stopped read", began, next, time.Minute)
		if st := connStatus(t, r); st.NATProblem != connSkipFailing {
			t.Fatalf("problem %q", st.NATProblem)
		}
		if nat, _ := store.reads(); len(nat) != 0 || !r.m.gwMu.TryLock() {
			t.Fatal("the stopped read was kept, or the gateway lock left held")
		}
		r.m.gwMu.Unlock()
		if rec, _, _ := r.m.conns.natLog.ok(); rec {
			t.Fatal("a read stopped for the evidence counted as a failure")
		}
	})
	t.Run("a cycle fails during the Device List read", func(t *testing.T) {
		r, store := connRig(t, nil)
		r.m.conns.devTimeout = time.Hour
		entered := make(chan struct{})
		r.gw.mu.Lock()
		r.gw.devicesCtx = func(ctx context.Context) ([]model.LANDevice, []byte, error) {
			close(entered)
			<-ctx.Done()
			return nil, nil, fmt.Errorf("gateway: GET devices.ha: %w", ctx.Err())
		}
		r.gw.mu.Unlock()
		done := make(chan struct{})
		go func() {
			defer close(done)
			r.m.sampleDevices(ctx)
		}()
		<-entered
		r.m.processCycle(ctx, time.Now(), time.Millisecond, outageCycle())
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Fatal("the Device List read was not stopped")
		}
		if st := connStatus(t, r); st.DevicesProblem != connSkipFailing {
			t.Fatalf("problem %q", st.DevicesProblem)
		}
		if _, dev := store.reads(); len(dev) != 0 {
			t.Fatal("the stopped read was kept")
		}
	})
}

// ---------------------------------------------------------------------------- the Device List

// The Device List needs neither the access code nor a confirmed certificate (it is read without a
// login, like the status pages), holds the gateway lock without gwAuth (nor notifMu or certMu), and
// is skipped while the gateway is needed for evidence. Its failures and pages not understood say so.
func TestDevicesSampler(t *testing.T) {
	ctx := context.Background()
	r, store := connRig(t, nil)
	r.cfg.Gateway.AccessCodeProtected = ""
	r.cfg.Gateway.PinnedCertSHA256, r.cfg.Gateway.PendingCertSHA256 = "aaaa", "bbbb"
	var (
		gwHeld, auth, notifHeld bool
		cert                    string
	)
	r.gw.mu.Lock()
	r.gw.devices = func() ([]model.LANDevice, []byte, error) {
		gwHeld, auth, notifHeld, cert = heldElsewhere(&r.m.gwMu), r.m.gwAuth.Load(), heldElsewhere(&r.m.notifMu), certMuHeld(r)
		return testDevices(), testDevicesPage, nil
	}
	r.gw.mu.Unlock()
	r.m.sampleDevices(ctx)
	if !gwHeld || auth || notifHeld || cert != "" {
		t.Fatalf("during the read: gateway lock held %v, gwAuth %v, notifMu held %v, certMu held %q", gwHeld, auth, notifHeld, cert)
	}
	_, dev := store.reads()
	if len(dev) != 1 || !reflect.DeepEqual(dev[0].devices, testDevices()) {
		t.Fatalf("appended %+v", dev)
	}
	st := connStatus(t, r)
	if st.DevicesAt != fmtTS(dev[0].t) || st.Devices != 2 || st.DevicesProblem != "" {
		t.Fatalf("status %+v", st)
	}

	for _, tc := range []struct {
		name    string
		prepare func(r *rig)
		want    string
		read    bool // the gateway is asked
	}{
		{"a failed read", func(r *rig) {
			answerDevices(r.gw, nil, nil, errors.New("gateway: GET devices.ha: connection refused"))
		}, "the Device List could not be read: gateway: GET devices.ha: connection refused", true},
		{"a page not understood", func(r *rig) {
			answerDevices(r.gw, nil, []byte("<html>?</html>"), errors.New("gateway: Device List page not understood: no device table"))
		}, "the Device List could not be read: gateway: Device List page not understood: no device table", true},
		{"the gateway's sessions all in use", func(r *rig) { // the client returns the page with it
			answerDevices(r.gw, nil, []byte("<html>all web server sessions are in use</html>"),
				fmt.Errorf("gateway: GET devices.ha: %w", &cooldownErr{err: contracts.ErrGatewaySessionsFull}))
		}, "the Device List could not be read: gateway: GET devices.ha: gateway: all web server sessions are in use", true},
		{"a page that lists no device", func(r *rig) {
			answerDevices(r.gw, nil, []byte("<html>?</html>"), nil)
		}, "the Device List page listed no device that was understood", true},
		{"a store that refuses it", func(r *rig) {
			answerDevices(r.gw, testDevices(), testDevicesPage, nil)
			store.setErr(errors.New("connstore: disk full"))
		}, "the Device List was read, but the connection store could not keep it: connstore: disk full", true},
		{"the gateway did not answer the latest poll", func(r *rig) {
			store.setErr(nil)
			r.m.locked(func() { r.m.st.lastSnap = &snapObs{At: time.Now(), Snap: &model.GatewaySnapshot{}} })
		}, "skipped: the gateway did not answer the monitor's latest poll", false},
		{"an incident is open", func(r *rig) {
			r.m.locked(func() { r.m.st.lastSnap = nil })
			openIncident(t, r)
		}, connSkipIncident, false},
	} {
		calls := devicesCalls(r)
		tc.prepare(r)
		r.m.sampleDevices(ctx)
		if asked := devicesCalls(r) > calls; asked != tc.read {
			t.Fatalf("%s: the gateway asked %v, want %v", tc.name, asked, tc.read)
		}
		if p := connStatus(t, r).DevicesProblem; !strings.HasPrefix(p, tc.want) {
			t.Fatalf("%s: problem %q, want %q", tc.name, p, tc.want)
		}
	}
	if _, dev := store.reads(); len(dev) != 2 {
		t.Fatalf("%d Device List reads appended (the read that listed none counts)", len(dev))
	}
}

// ---------------------------------------------------------------------------- raw page copies

// The page of the first read that worked since the start, of a read whose page was not understood
// and of a read that left out rows is copied to the data directory's connections folder, replacing
// the copy atomically, at most once an hour for each page; the problems say where the copy is.
// Without a data directory nothing is written.
func TestConnRawPageCopies(t *testing.T) {
	ctx := context.Background()
	r, _ := connRig(t, nil)
	dir := t.TempDir()
	r.cfg.SetDataDir(dir)
	folder := filepath.Join(dir, "connections")
	natFile, devFile := filepath.Join(folder, natRawFile), filepath.Join(folder, devicesRawFile)
	page := func(n int) []byte { return []byte(fmt.Sprintf("<html><title>NAT Table</title>read %d</html>", n)) }
	copyIs := func(path string, want []byte) {
		t.Helper()
		got, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("%s holds %q (%v), want %q", path, got, err, want)
		}
	}
	hourLater := func() { // the hourly limit has passed
		r.m.conns.locked(func() {
			r.m.conns.nat.raw.written = r.m.conns.nat.raw.written.Add(-time.Hour)
			r.m.conns.dev.raw.written = r.m.conns.dev.raw.written.Add(-time.Hour)
		})
	}
	// natRound makes a round and returns what the status says of it: the problem of a read that
	// failed, else the note of the read that worked.
	natRound := func(table model.NATTable, raw []byte, err error) string {
		t.Helper()
		answerNAT(r.gw, table, raw, err)
		r.m.sampleNAT(ctx)
		st := connStatus(t, r)
		if st.NATProblem != "" && st.NATNote != "" {
			t.Fatalf("a problem %q and a note %q", st.NATProblem, st.NATNote)
		}
		return st.NATProblem + st.NATNote
	}
	notUnderstood := errors.New("gateway: NAT table page not understood")

	if p := natRound(testNATTable(), page(1), nil); p != "" {
		t.Fatalf("problem %q", p)
	}
	copyIs(natFile, page(1)) // the first read that worked since the start
	natRound(testNATTable(), page(2), nil)
	copyIs(natFile, page(1)) // a read that worked: not again
	p := natRound(model.NATTable{}, page(3), notUnderstood)
	copyIs(natFile, page(1)) // within the hour
	mustContain(t, "the problem", p, "the NAT table could not be read: gateway: NAT table page not understood", "; a copy of the page read at ", " is in "+natFile)
	hourLater()
	skipped := testNATTable()
	skipped.Skipped = 2
	p = natRound(skipped, page(4), nil)
	copyIs(natFile, page(4)) // rows left out
	mustContain(t, "the problem", p, "2 rows of the NAT table page left out (not understood); a copy of the page read at ", natFile)
	hourLater()
	natRound(testNATTable(), page(5), nil)
	copyIs(natFile, page(4)) // only the first read that worked is copied
	hourLater()
	natRound(model.NATTable{InUse: 3, Available: 8189}, page(6), nil)
	copyIs(natFile, page(6)) // counts sessions, but no row was understood

	answerDevices(r.gw, testDevices(), testDevicesPage, nil)
	r.m.sampleDevices(ctx)
	copyIs(devFile, testDevicesPage)
	answerDevices(r.gw, nil, []byte("<html>devices ?</html>"), errors.New("gateway: Device List page not understood"))
	r.m.sampleDevices(ctx)
	copyIs(devFile, testDevicesPage) // within the hour
	hourLater()
	r.m.sampleDevices(ctx)
	copyIs(devFile, []byte("<html>devices ?</html>"))

	entries, err := os.ReadDir(folder)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	if !slices.Equal(names, []string{devicesRawFile, natRawFile}) {
		t.Fatalf("the connections folder holds %v (temporary files left?)", names)
	}

	// Without a data directory: nothing written, nothing said about a copy.
	r2, _ := connRig(t, nil)
	answerNAT(r2.gw, model.NATTable{}, page(7), notUnderstood)
	r2.m.sampleNAT(ctx)
	r2.m.sampleDevices(ctx)
	if p := connStatus(t, r2).NATProblem; strings.Contains(p, "copy") {
		t.Fatalf("problem %q", p)
	}
	if _, err := os.Stat(filepath.Join(r2.m.opts.DataDir, "connections")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a connections folder without a configured data directory: %v", err)
	}
}

// ---------------------------------------------------------------------------- shutdown

// A read in progress ends with Run (both samplers' reads hold the gateway lock, so one is in
// progress at a time: here the NAT read, which hangs until its context ends), and every goroutine
// of the samplers has finished when Run returns.
func TestConnSamplersEndWithRun(t *testing.T) {
	r, store := connRig(t, nil)
	var natIn atomic.Bool
	r.gw.mu.Lock()
	r.gw.natCtx = func(ctx context.Context) (model.NATTable, []byte, error) {
		natIn.Store(true)
		<-ctx.Done()
		return model.NATTable{}, nil, fmt.Errorf("gateway: GET nattable.ha: %w", ctx.Err())
	}
	r.gw.mu.Unlock()
	r.m.conns.natTimeout = time.Hour
	stop := r.start(t)
	waitFor(t, "a NAT read in progress", 20*time.Second, natIn.Load)
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	if st := connStatus(t, r); strings.Contains(st.NATProblem, "could not be read") {
		t.Fatalf("a read ended by the stop counted as a failure: %+v", st)
	}
	if nat, _ := store.reads(); len(nat) != 0 {
		t.Fatal("a read ended by the stop was kept")
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
