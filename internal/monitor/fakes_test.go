package monitor

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"reflect"
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

// ---------------------------------------------------------------------------- fake ledger

// fakeLedger is an in-memory contracts.Ledger + contracts.LedgerReader that keeps records in
// append order and really JSON-encodes payloads (so tests decode what a verifier would see).
type fakeLedger struct {
	mu        sync.Mutex
	run       string
	start     time.Time
	now       func() time.Time
	envs      []model.Envelope
	bodies    []model.Body
	blobs     map[string][]byte
	onAppend  func(model.Body)
	onPut     func([]byte) // called (outside the lock) before a blob is stored
	appendErr error
	putErr    error
	compress  atomic.Int32
	closed    bool
	// segments simulates daily segments like the real ledger: a segment_open record is written
	// just before the first record of a later UTC date.
	segments bool
	segDay   string
	// rejectRecord (optional) fails the append of a record after the segment logic, like a write
	// failure of the record itself: a segment_open written for it stays (as in the real ledger).
	rejectRecord func(typ string) error
}

func (l *fakeLedger) setRejectRecord(f func(typ string) error) {
	l.mu.Lock()
	l.rejectRecord = f
	l.mu.Unlock()
}

func newFakeLedger(run string) *fakeLedger {
	return newFakeLedgerAt(run, time.Now().Add(-time.Hour))
}

// newFakeLedgerAt creates a fake ledger whose genesis record has the given ts.
func newFakeLedgerAt(run string, genesis time.Time) *fakeLedger {
	l := &fakeLedger{run: run, start: time.Now(), now: time.Now, blobs: map[string][]byte{}}
	l.appendAs(run, genesis, model.TypeGenesis, model.Genesis{Fingerprint: "fp-test", Statement: "test"})
	return l
}

// appendAs adds a record as if written by another run at a given time (test setup).
func (l *fakeLedger) appendAs(run string, ts time.Time, typ string, data any, blobs ...string) model.Ref {
	raw, err := json.Marshal(data)
	if err != nil {
		panic(err)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.appendLocked(run, ts, typ, raw, blobs)
}

func (l *fakeLedger) appendLocked(run string, ts time.Time, typ string, raw []byte, blobs []string) model.Ref {
	prev := model.ZeroHash
	if n := len(l.envs); n > 0 {
		prev = l.envs[n-1].H
	}
	body := model.Body{V: model.FormatVersion, Seq: uint64(len(l.bodies)), Prev: prev, TS: fmtTS(ts),
		Mono: int64(time.Since(l.start)), Run: run, Type: typ, Blobs: blobs, Data: raw}
	b, err := json.Marshal(body)
	if err != nil {
		panic(err)
	}
	env := model.Envelope{H: sha256Hex(b), S: "sig", B: string(b)}
	l.envs = append(l.envs, env)
	l.bodies = append(l.bodies, body)
	return model.Ref{Seq: body.Seq, Hash: env.H, TS: body.TS}
}

func (l *fakeLedger) Append(typ string, data any, blobs ...string) (model.Ref, error) {
	raw, err := json.Marshal(data)
	if err != nil {
		return model.Ref{}, err
	}
	l.mu.Lock()
	if l.appendErr != nil {
		err := l.appendErr
		l.mu.Unlock()
		return model.Ref{}, err
	}
	if l.closed {
		l.mu.Unlock()
		return model.Ref{}, errors.New("ledger closed")
	}
	for _, id := range blobs {
		if _, ok := l.blobs[id]; !ok {
			l.mu.Unlock()
			return model.Ref{}, fmt.Errorf("blob %s referenced before it was stored", id)
		}
	}
	now := l.now()
	if l.segments {
		day := now.UTC().Format("2006-01-02")
		if l.segDay == "" {
			last, _ := parseTS(l.bodies[len(l.bodies)-1].TS)
			l.segDay = last.UTC().Format("2006-01-02")
		}
		if day > l.segDay {
			so, _ := json.Marshal(model.SegmentOpen{Segment: "ledger-" + day, PrevSegment: "ledger-" + l.segDay})
			l.appendLocked(l.run, now, model.TypeSegmentOpen, so, nil)
			l.segDay = day
		}
	}
	if l.rejectRecord != nil {
		if err := l.rejectRecord(typ); err != nil {
			l.mu.Unlock()
			return model.Ref{}, err
		}
	}
	ref := l.appendLocked(l.run, now, typ, raw, blobs)
	body := l.bodies[len(l.bodies)-1]
	cb := l.onAppend
	l.mu.Unlock()
	if cb != nil {
		cb(body)
	}
	return ref, nil
}

func (l *fakeLedger) PutBlob(content []byte) (string, error) {
	id := sha256Hex(content)
	l.mu.Lock()
	hook := l.onPut
	l.mu.Unlock()
	if hook != nil {
		hook(content)
	}
	l.mu.Lock()
	if l.putErr != nil {
		err := l.putErr
		l.mu.Unlock()
		return "", err
	}
	l.blobs[id] = bytes.Clone(content)
	l.mu.Unlock()
	return id, nil
}

func (l *fakeLedger) setOnPut(f func([]byte)) {
	l.mu.Lock()
	l.onPut = f
	l.mu.Unlock()
}

func (l *fakeLedger) GetBlob(id string) ([]byte, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.blobs[id]
	if !ok {
		return nil, contracts.ErrNotFound
	}
	return bytes.Clone(b), nil
}

func (l *fakeLedger) HasBlob(id string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	_, ok := l.blobs[id]
	return ok
}

func (l *fakeLedger) Head() model.Ref {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := len(l.bodies)
	return model.Ref{Seq: l.bodies[n-1].Seq, Hash: l.envs[n-1].H, TS: l.bodies[n-1].TS}
}

func (l *fakeLedger) GenesisTS() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.bodies[0].TS
}

func (l *fakeLedger) PublicKey() ed25519.PublicKey {
	return make(ed25519.PublicKey, ed25519.PublicKeySize)
}
func (l *fakeLedger) Fingerprint() string { return "fp-test" }
func (l *fakeLedger) RunID() string       { return l.run }
func (l *fakeLedger) MonoNow() int64      { return int64(time.Since(l.start)) }
func (l *fakeLedger) Close() error {
	l.mu.Lock()
	l.closed = true
	l.mu.Unlock()
	return nil
}

func (l *fakeLedger) CompressSealed(time.Duration) (int, error) {
	l.compress.Add(1)
	return 0, nil
}

func (l *fakeLedger) snapshot() ([]model.Envelope, []model.Body) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]model.Envelope(nil), l.envs...), append([]model.Body(nil), l.bodies...)
}

func (l *fakeLedger) Scan(fromSeq uint64, fn func(model.Envelope, model.Body) error) error {
	envs, bodies := l.snapshot()
	for i := range bodies {
		if bodies[i].Seq < fromSeq {
			continue
		}
		if err := fn(envs[i], bodies[i]); err != nil {
			if errors.Is(err, contracts.ErrStop) {
				return nil
			}
			return err
		}
	}
	return nil
}

func (l *fakeLedger) ScanTime(from, to time.Time, fn func(model.Envelope, model.Body) error) error {
	envs, bodies := l.snapshot()
	for i := range bodies {
		ts, _ := parseTS(bodies[i].TS)
		if ts.Before(from) || !ts.Before(to) {
			continue
		}
		if err := fn(envs[i], bodies[i]); err != nil {
			if errors.Is(err, contracts.ErrStop) {
				return nil
			}
			return err
		}
	}
	return nil
}

func (l *fakeLedger) Record(seq uint64) (model.Envelope, model.Body, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if seq >= uint64(len(l.bodies)) {
		return model.Envelope{}, model.Body{}, contracts.ErrNotFound
	}
	return l.envs[seq], l.bodies[seq], nil
}

func (l *fakeLedger) Segments() ([]contracts.SegmentInfo, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return []contracts.SegmentInfo{{Name: "ledger-test", Records: len(l.bodies), LastSeq: uint64(len(l.bodies) - 1), Active: true}}, nil
}

func (l *fakeLedger) OpenSegment(name string) (io.ReadCloser, error) {
	envs, _ := l.snapshot()
	var buf bytes.Buffer
	for _, e := range envs {
		b, _ := json.Marshal(e)
		buf.Write(b)
		buf.WriteByte('\n')
	}
	return io.NopCloser(&buf), nil
}

// records returns the bodies appended with the given run id (or all with run "").
func (l *fakeLedger) records(run string) []model.Body {
	_, bodies := l.snapshot()
	var out []model.Body
	for _, b := range bodies {
		if run == "" || b.Run == run {
			out = append(out, b)
		}
	}
	return out
}

func (l *fakeLedger) types(run string) []string {
	var out []string
	for _, b := range l.records(run) {
		out = append(out, b.Type)
	}
	return out
}

func ofType(bodies []model.Body, typ string) []model.Body {
	var out []model.Body
	for _, b := range bodies {
		if b.Type == typ {
			out = append(out, b)
		}
	}
	return out
}

func decode[T any](t testing.TB, b model.Body) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(b.Data, &v); err != nil {
		t.Fatalf("decode %s seq %d: %v", b.Type, b.Seq, err)
	}
	return v
}

var _ contracts.Ledger = (*fakeLedger)(nil)
var _ contracts.LedgerReader = (*fakeLedger)(nil)

// ---------------------------------------------------------------------------- fake gateway

const eventsPageOn = `<html><body><form><input id="broadband"  type="checkbox" name="bbevent" checked="checked" /></form></body></html>`
const eventsPageOff = `<html><body><form><input id="broadband"  type="checkbox" name="bbevent"  /></form></body></html>`

type fakeGateway struct {
	mu   sync.Mutex
	snap func(call int, pages []string, trigger string) (model.GatewaySnapshot, map[string][]byte, error)
	// snapCtx, when set, answers Snapshot in place of snap, with the request's context.
	snapCtx    func(ctx context.Context, call int, pages []string, trigger string) (model.GatewaySnapshot, map[string][]byte, error)
	calls      int
	triggers   []string
	pageSets   [][]string
	observer   contracts.CertObserver
	pinned     string
	notif      bool
	notifErr   error
	notifCalls int
	notifTimes []time.Time
	setCalls   []bool
	setErr     error
	// syslog answers Syslog (nil: the page cannot be read, errNoSyslogPage) and setSyslog answers
	// SetSyslog (nil: refused, errNoSetSyslog); syslogCalls counts the reads (syslogTimes: when)
	// and setSyslogWants lists what each SetSyslog asked for (setSyslogTimes: when). newSyslogSim
	// installs both as a simulated page.
	syslog         func() (model.SyslogSetting, []byte, error)
	syslogCalls    int
	syslogTimes    []time.Time
	setSyslog      func(want model.SyslogTarget) (before, after []byte, err error)
	setSyslogWants []model.SyslogTarget
	setSyslogTimes []time.Time
}

// errNoSyslogPage and errNoSetSyslog are the fake gateway's answers to Syslog and SetSyslog
// unless a test sets them.
var (
	errNoSyslogPage = errors.New("fake gateway: the Syslog page is not part of this test")
	errNoSetSyslog  = errors.New("fake gateway: setting the Syslog page is not part of this test")
)

func (g *fakeGateway) Snapshot(ctx context.Context, pages []string, trigger string) (model.GatewaySnapshot, map[string][]byte, error) {
	g.mu.Lock()
	g.calls++
	call := g.calls
	g.triggers = append(g.triggers, trigger)
	g.pageSets = append(g.pageSets, append([]string(nil), pages...))
	fn, fnCtx := g.snap, g.snapCtx
	g.mu.Unlock()
	switch {
	case fnCtx != nil:
		return fnCtx(ctx, call, pages, trigger)
	case fn == nil:
		return okSnapshot(pages, time.Now()), pageBodies(pages, "ok"), nil
	}
	return fn(call, pages, trigger)
}

func (g *fakeGateway) Notification(ctx context.Context) (bool, []byte, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.notifCalls++
	g.notifTimes = append(g.notifTimes, time.Now())
	if g.notifErr != nil {
		return false, nil, g.notifErr
	}
	if g.notif {
		return true, []byte(eventsPageOn), nil
	}
	return false, []byte(eventsPageOff), nil
}

func (g *fakeGateway) SetNotification(ctx context.Context, enabled bool) ([]byte, []byte, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.setCalls = append(g.setCalls, enabled)
	before := []byte(eventsPageOff)
	if g.notif {
		before = []byte(eventsPageOn)
	}
	if g.setErr != nil {
		return before, nil, g.setErr
	}
	g.notif = enabled
	after := []byte(eventsPageOff)
	if enabled {
		after = []byte(eventsPageOn)
	}
	return before, after, nil
}

func (g *fakeGateway) Syslog(ctx context.Context) (model.SyslogSetting, []byte, error) {
	g.mu.Lock()
	g.syslogCalls++
	g.syslogTimes = append(g.syslogTimes, time.Now())
	fn := g.syslog
	g.mu.Unlock()
	if fn == nil {
		return model.SyslogSetting{}, nil, errNoSyslogPage
	}
	return fn()
}

// SetSyslog is recorded and answered by setSyslog (refused without one: nothing posted).
func (g *fakeGateway) SetSyslog(ctx context.Context, want model.SyslogTarget) ([]byte, []byte, error) {
	g.mu.Lock()
	g.setSyslogWants = append(g.setSyslogWants, want)
	g.setSyslogTimes = append(g.setSyslogTimes, time.Now())
	fn := g.setSyslog
	g.mu.Unlock()
	if fn == nil {
		return nil, nil, errNoSetSyslog
	}
	return fn(want)
}

// syslogReads returns how often the Syslog page was read and asked to change.
func (g *fakeGateway) syslogReads() (reads, sets int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.syslogCalls, len(g.setSyslogWants)
}

// syslogSets returns what SetSyslog was asked for, in order, and when.
func (g *fakeGateway) syslogSets() ([]model.SyslogTarget, []time.Time) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return slices.Clone(g.setSyslogWants), slices.Clone(g.setSyslogTimes)
}

// syslogSim simulates the gateway's Syslog page behind the fake gateway: Syslog reads it, and
// SetSyslog changes it as the gateway client does - only the syslog controls, a level by its
// label (case aside) and never one the page does not offer, nothing posted when the page already
// shows the request or the request is not valid - and reads it back, returning the pages before
// and after. Until something is posted the page is the one it started with (e.g. the real page);
// every page after that is rendered with a new nonce, as the gateway does. Tests make reads fail
// (readErr), changes fail before anything is posted (setErr: the page before only), or changes
// that the page read back does not show (ignore: both pages and an error).
type syslogSim struct {
	mu      sync.Mutex
	setting model.SyslogSetting
	page    []byte
	renders int
	readErr error
	setErr  error
	ignore  bool
	posts   int // SetSyslog calls that posted a change
}

// newSyslogSim installs a simulated Syslog page showing s - as page until something is posted
// (nil: rendered) - as g's Syslog and SetSyslog.
func newSyslogSim(g *fakeGateway, s model.SyslogSetting, page []byte) *syslogSim {
	sim := &syslogSim{setting: cloneSetting(s), page: page}
	g.mu.Lock()
	g.syslog, g.setSyslog = sim.read, sim.set
	g.mu.Unlock()
	return sim
}

func cloneSetting(s model.SyslogSetting) model.SyslogSetting {
	s.Levels = slices.Clone(s.Levels)
	return s
}

// update changes the simulation under its lock.
func (s *syslogSim) update(f func(s *syslogSim)) {
	s.mu.Lock()
	f(s)
	s.mu.Unlock()
}

// current returns the setting the page shows now and how many changes were posted.
func (s *syslogSim) current() (model.SyslogSetting, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return cloneSetting(s.setting), s.posts
}

// pageLocked returns the page as the gateway would serve it now. Caller holds mu.
func (s *syslogSim) pageLocked() []byte {
	if s.page != nil && s.posts == 0 {
		return bytes.Clone(s.page)
	}
	s.renders++
	return renderSyslogPage(s.setting, s.renders)
}

func (s *syslogSim) read() (model.SyslogSetting, []byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.readErr != nil {
		return model.SyslogSetting{}, nil, s.readErr
	}
	return cloneSetting(s.setting), s.pageLocked(), nil
}

func (s *syslogSim) set(want model.SyslogTarget) ([]byte, []byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.readErr != nil {
		return nil, nil, s.readErr
	}
	if want.Enabled {
		if a, err := netip.ParseAddr(want.Server); err != nil || !a.Is4() {
			return nil, nil, fmt.Errorf("gateway: syslog server %q is not an IPv4 address", want.Server)
		}
		if want.Port < 1 || want.Port > 65535 {
			return nil, nil, fmt.Errorf("gateway: syslog port %d is not a port number (1-65535)", want.Port)
		}
	}
	before := s.pageLocked()
	if s.setErr != nil {
		return before, nil, s.setErr
	}
	next := cloneSetting(s.setting) // switching off changes only the switch
	next.Enabled = want.Enabled
	if want.Enabled {
		next.Server, next.Port = want.Server, want.Port
		if want.Level != "" {
			i := slices.IndexFunc(next.Levels, func(l string) bool { return strings.EqualFold(l, want.Level) })
			if i < 0 {
				return before, nil, fmt.Errorf("gateway: Syslog page not understood: %q has no option %q: nothing posted", "Log Level", want.Level)
			}
			next.Level = next.Levels[i]
		}
	}
	if reflect.DeepEqual(next, s.setting) {
		return before, before, nil // already as requested: nothing posted
	}
	s.posts++
	if s.ignore {
		return before, s.pageLocked(), fmt.Errorf("gateway: setting not applied: Syslog reads %s (wanted %s) after saving", onOff(s.setting.Enabled), onOff(want.Enabled))
	}
	s.setting = next
	return before, s.pageLocked(), nil
}

// renderSyslogPage renders a Syslog page in the shape of the gateway's (the monitor stores it,
// it never parses it), with nonce n.
func renderSyslogPage(s model.SyslogSetting, n int) []byte {
	const selected = ` selected="selected"`
	var b strings.Builder
	fmt.Fprintf(&b, `<html><body><form method="post" action="/cgi-bin/syslog.ha"><input type="hidden" name="nonce" value="%064x" />`, n)
	off, selOff, selOn := ` disabled="disabled"`, selected, ""
	if s.Enabled {
		off, selOff, selOn = "", "", selected
	}
	fmt.Fprintf(&b, `<label for="syslog">Syslog</label><select name="syslog" id="syslog"><option value="off"%s>Off</option><option value="on"%s>On</option></select>`,
		selOff, selOn)
	fmt.Fprintf(&b, `<label for="serverip">Server IP Address</label><input id="serverip" type="text" name="location" value="%s"%s />`, s.Server, off)
	fmt.Fprintf(&b, `<label for="serverport">Server Port</label><input id="serverport" type="text" name="port" value="%d"%s />`, s.Port, off)
	fmt.Fprintf(&b, `<label for="loglevel">Log Level</label><select name="level" id="loglevel"%s>`, off)
	for _, l := range s.Levels {
		sel := ""
		if l == s.Level {
			sel = selected
		}
		fmt.Fprintf(&b, `<option value="%s"%s>%s</option>`, l, sel, l)
	}
	b.WriteString(`</select><input type="submit" name="Save" value="Save" /></form></body></html>`)
	return []byte(b.String())
}

// realSyslogLevels are the Log Level options of the owner's gateway (BGW320-505, firmware 6.34.7):
// no Informational, no Debug.
var realSyslogLevels = []string{"Emergency", "Alert", "Critical", "Error", "Warning", "Notice"}

// realSyslogOff is what the gateway client reads from testdata/gateway/syslog_real_off.html, the
// owner's gateway's Syslog page with Syslog off: its fields keep port 514 and level Error.
func realSyslogOff() model.SyslogSetting {
	return model.SyslogSetting{Enabled: false, Server: "", Port: 514, Level: "Error", Levels: slices.Clone(realSyslogLevels)}
}

// realSyslogPage returns the owner's gateway's Syslog page with Syslog off (the fixture).
func realSyslogPage(t testing.TB) []byte {
	t.Helper()
	b, err := os.ReadFile("../../testdata/gateway/syslog_real_off.html")
	if err != nil {
		t.Fatalf("the real Syslog page: %v", err)
	}
	return b
}

func (g *fakeGateway) SetCertObserver(o contracts.CertObserver) {
	g.mu.Lock()
	g.observer = o
	g.mu.Unlock()
}

func (g *fakeGateway) PinnedCert() string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.pinned
}

func (g *fakeGateway) Host() string { return "192.168.1.254" }

func (g *fakeGateway) snapshotCalls() (int, []string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.calls, append([]string(nil), g.triggers...)
}

var _ contracts.Gateway = (*fakeGateway)(nil)

func boolp(b bool) *bool  { return &b }
func i64p(v int64) *int64 { return &v }
func pageBodies(pages []string, tag string) map[string][]byte {
	out := map[string][]byte{}
	for _, p := range pages {
		out[p] = []byte("<html><title>" + p + "</title>" + tag + "</html>")
	}
	return out
}

// okSnapshot is a healthy gateway snapshot (WAN up, PON O5, optical up, Rx low alarm flagged).
func okSnapshot(pages []string, at time.Time) model.GatewaySnapshot {
	s := model.GatewaySnapshot{
		System:    &model.SystemInfo{Model: "BGW320-505", SoftwareVersion: "6.34.7", UptimeSec: 274686, UptimeRaw: "274686", GatewayTimeRaw: "2026-10-04T22:10:44"},
		Broadband: &model.BroadbandStatus{Connection: "Up", IPv4: "203.0.113.5", GatewayIPv4: "203.0.113.1", PrimaryDNS: "68.94.156.9", PONLinkStatus: "OPERATION (O5)", Counters: map[string]int64{"IPv4 Statistics/Receive Packets": 1000, "IPv4 Statistics/Transmit Packets": 900}},
		Fiber:     &model.FiberStatus{OpticalStatus: "Up", LastChangeUnix: 1791151188, Measures: []model.DMIMeasure{{Name: "Rx Power", CurrentRaw: "-315", Current: i64p(-315), Unit: "0.1dBm", LowAlarm: model.Threshold{Active: true, Raw: "1 (Threshold -295)", Threshold: i64p(-295)}, LowWarn: model.Threshold{Active: true, Raw: "1 (Threshold -292)", Threshold: i64p(-292)}}}},
		Derived: model.GatewayDerived{
			Reachable: true, BroadbandUp: boolp(true), PONOperational: boolp(true), OpticalUp: boolp(true),
			WANIPv4: "203.0.113.5", ISPNextHop: "203.0.113.1", ISPDNS: "68.94.156.9",
			RxPowerX10: i64p(-315), TxPowerX10: i64p(37), RxLowAlarmX10: i64p(-295), RxLowWarnX10: i64p(-292),
			Alarms:    []string{"OPTICAL_RX_LOW_ALARM", "OPTICAL_RX_LOW_WARNING"},
			UptimeSec: 274686, BootTimeEstimate: fmtTS(at.Add(-274686 * time.Second)),
			Firmware: "6.34.7", Model: "BGW320-505", FiberLastChange: 1791151188,
		},
	}
	for _, p := range pages {
		s.Pages = append(s.Pages, model.PageCapture{Page: p, URL: "https://192.168.1.254/cgi-bin/" + p + ".ha", Status: 200, FetchedAt: fmtTS(at), Bytes: 10})
	}
	return s
}

// downSnapshot: gateway reachable, broadband WAN down (blank clock, no WAN IP).
func downSnapshot(pages []string, at time.Time) model.GatewaySnapshot {
	s := okSnapshot(pages, at)
	s.Broadband.Connection = "Down"
	s.Broadband.IPv4 = ""
	s.Derived.BroadbandUp = boolp(false)
	s.Derived.WANIPv4 = ""
	s.Derived.GatewayClockBlank = true
	s.System.GatewayTimeRaw = ""
	return s
}

// ---------------------------------------------------------------------------- fake prober

type fakeProber struct {
	mu     sync.Mutex
	ping   func(target string) model.ProbeResult
	tcp    func(target string) model.ProbeResult
	dns    func(server, name string) model.DNSResult
	http   func(name, url string) model.HTTPResult
	trace  func(target string) model.Traceroute
	sntp   func(server string) model.ClockResult
	link   func() (model.LocalLink, []byte, error)
	counts map[string]int
}

func newFakeProber() *fakeProber { return &fakeProber{counts: map[string]int{}} }

func (p *fakeProber) count(k string) {
	p.mu.Lock()
	p.counts[k]++
	p.mu.Unlock()
}

func (p *fakeProber) calls(k string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.counts[k]
}

func (p *fakeProber) Ping(ctx context.Context, target string, timeout time.Duration) model.ProbeResult {
	p.count("ping")
	if p.ping != nil {
		return p.ping(target)
	}
	return model.ProbeResult{OK: true, RTTus: 1900, Status: "IP_SUCCESS", ReplyFrom: target, TTL: 64}
}

func (p *fakeProber) TCP(ctx context.Context, target string, timeout time.Duration) model.ProbeResult {
	p.count("tcp")
	if p.tcp != nil {
		return p.tcp(target)
	}
	return model.ProbeResult{OK: true, RTTus: 2300, Status: "connected"}
}

func (p *fakeProber) DNS(ctx context.Context, server, name string, timeout time.Duration) model.DNSResult {
	p.count("dns")
	if p.dns != nil {
		return p.dns(server, name)
	}
	if isInvalidName(name) {
		return model.DNSResult{Server: server + ":53", Name: name, QType: "A", OK: true, RCode: "NXDOMAIN", RTTus: 900}
	}
	return model.DNSResult{Server: server + ":53", Name: name, QType: "A", OK: true, RCode: "NOERROR", Answers: []string{"142.250.72.36"}, RTTus: 1200}
}

func (p *fakeProber) HTTP(ctx context.Context, name, url string, expectStatus int, expectBody string, timeout time.Duration) model.HTTPResult {
	p.count("http")
	if p.http != nil {
		return p.http(name, url)
	}
	return model.HTTPResult{Name: name, URL: url, OK: true, Status: expectStatus, RemoteAddr: "23.200.0.1:80"}
}

func (p *fakeProber) Traceroute(ctx context.Context, target string, maxHops int, perHop time.Duration) model.Traceroute {
	p.count("trace")
	if p.trace != nil {
		return p.trace(target)
	}
	return model.Traceroute{Target: target, Hops: []model.Hop{{TTL: 1, Addr: "192.168.1.254", RTTus: 1000, Status: "IP_TTL_EXPIRED_TRANSIT"}, {TTL: 2, Addr: target, RTTus: 9000, Status: "IP_SUCCESS"}}, Reached: true, DurMs: 12}
}

func (p *fakeProber) SNTP(ctx context.Context, server string, timeout time.Duration) model.ClockResult {
	p.count("sntp")
	if p.sntp != nil {
		return p.sntp(server)
	}
	return model.ClockResult{Server: server, OK: true, OffsetMs: 3, RTTms: 20, Stratum: 2}
}

func (p *fakeProber) LocalLink(ctx context.Context, gatewayIP string) (model.LocalLink, []byte, error) {
	p.count("link")
	if p.link != nil {
		return p.link()
	}
	return model.LocalLink{Interface: "Wi-Fi", Type: "wifi", State: "connected", SSID: "home", BSSID: "aa:bb:cc:dd:ee:ff", SignalPct: 90, Channel: 149},
		[]byte("Name : Wi-Fi\nState : connected\n"), nil
}

var _ contracts.Prober = (*fakeProber)(nil)

// ---------------------------------------------------------------------------- fake anchorer

type fakeAnchorer struct {
	mu    sync.Mutex
	urls  []string
	fail  bool
	calls int
}

func (a *fakeAnchorer) Timestamp(ctx context.Context, digest []byte) []contracts.TimestampResult {
	a.mu.Lock()
	a.calls++
	n, fail := a.calls, a.fail
	a.mu.Unlock()
	var out []contracts.TimestampResult
	for _, u := range a.urls {
		if fail {
			out = append(out, contracts.TimestampResult{URL: u, Err: errors.New("tsa unreachable")})
			continue
		}
		tok := []byte(fmt.Sprintf("TSR|%s|%s|%d", u, hex.EncodeToString(digest), n))
		out = append(out, contracts.TimestampResult{URL: u, Token: tok, Info: fakeInfo(u, n)})
	}
	return out
}

func fakeInfo(u string, n int) contracts.TokenInfo {
	return contracts.TokenInfo{GenTime: time.Date(2026, 10, 5, 3, 20, 0, 0, time.UTC).Add(time.Duration(n) * time.Second),
		Serial: fmt.Sprintf("%x", n), Policy: "2.16.840.1.114412.7.1", Nonce: "c0ffee", TSAName: "CN=" + u, ChainOK: true}
}

func (a *fakeAnchorer) VerifyToken(token, digest []byte) (contracts.TokenInfo, error) {
	parts := strings.Split(string(token), "|")
	if len(parts) != 4 || parts[0] != "TSR" || parts[2] != hex.EncodeToString(digest) {
		return contracts.TokenInfo{}, errors.New("imprint mismatch")
	}
	var n int
	fmt.Sscanf(parts[3], "%d", &n)
	return fakeInfo(parts[1], n), nil
}

func (a *fakeAnchorer) timestampCalls() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.calls
}

var _ contracts.Anchorer = (*fakeAnchorer)(nil)

// chainlessAnchorer issues tokens that verify (signature, imprint) but whose TSA certificate
// does not chain to a trusted root, for the TSAs untrusted names.
type chainlessAnchorer struct {
	*fakeAnchorer
	untrusted func(url string) bool
}

func (c chainlessAnchorer) VerifyToken(token, digest []byte) (contracts.TokenInfo, error) {
	info, err := c.fakeAnchorer.VerifyToken(token, digest)
	if parts := strings.Split(string(token), "|"); err == nil && len(parts) == 4 && c.untrusted(parts[1]) {
		info.ChainOK, info.ChainNote = false, "system roots: x509: certificate signed by unknown authority"
	}
	return info, err
}

// fakeClock is a settable wall clock (no monotonic reading) for the monitor and the ledger.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Set(t time.Time) {
	c.mu.Lock()
	c.t = t
	c.mu.Unlock()
}

// clockRig is a rig with the default 10 s fast interval whose monitor and ledger run on a fake
// clock starting at start (no workers: tests drive processCycle, takeSnapshot, finishClose).
func clockRig(t *testing.T, start time.Time) (*rig, *fakeClock) {
	t.Helper()
	cfg := testConfig()
	cfg.Probes.FastInterval = config.D(10 * time.Second)
	cfg.Probes.Timeout = config.D(2 * time.Second)
	cfg.Probes.LocalLinkInterval = config.D(60 * time.Second)
	clk := &fakeClock{t: start}
	led := newFakeLedgerAt("run-current", start.Add(-time.Minute))
	led.now = clk.Now
	r := newRig(t, cfg, led)
	r.m.now = clk.Now
	return r, clk
}

// ---------------------------------------------------------------------------- fake verifier

type fakeVerifier struct{ rep model.VerifyReport }

func (v *fakeVerifier) Verify(ctx context.Context) (model.VerifyReport, error) { return v.rep, nil }

// ---------------------------------------------------------------------------- config & monitor helpers

// testConfig returns a configuration with intervals scaled for fast tests (built directly,
// without Validate).
func testConfig() *config.Config {
	c := config.Default()
	c.Probes.FastInterval = config.D(40 * time.Millisecond)
	c.Probes.Timeout = config.D(20 * time.Millisecond)
	c.Gateway.PollInterval = config.D(80 * time.Millisecond)
	c.Gateway.IncidentPollInterval = config.D(40 * time.Millisecond)
	c.Gateway.LANStatsInterval = config.D(time.Hour)
	c.Gateway.RawStoreInterval = config.D(time.Hour)
	c.Gateway.NotificationCheckInterval = config.D(time.Hour)
	c.Probes.ServiceInterval = config.D(80 * time.Millisecond)
	c.Probes.ServiceIncidentInterval = config.D(40 * time.Millisecond)
	c.Probes.LocalLinkInterval = config.D(80 * time.Millisecond)
	c.Probes.LocalLinkRecordEvery = config.D(time.Hour)
	c.Probes.TracerouteInterval = config.D(time.Hour)
	c.Clock.Interval = config.D(time.Hour)
	c.HeartbeatInterval = config.D(150 * time.Millisecond)
	c.Anchoring.Interval = config.D(time.Hour)
	c.Anchoring.Enabled = true
	c.Anchoring.TSAURLs = []string{"http://tsa.test/a", "http://tsa.test/b"}
	return c
}

type rig struct {
	cfg   *config.Config
	led   *fakeLedger
	gw    *fakeGateway
	pr    *fakeProber
	anc   *fakeAnchorer
	saved atomic.Int32
	m     *Monitor
}

func newRig(t *testing.T, cfg *config.Config, led *fakeLedger) *rig {
	t.Helper()
	return newRigWith(t, cfg, led, nil)
}

// newRigWith is newRig with a hook that may change the options before New.
func newRigWith(t *testing.T, cfg *config.Config, led *fakeLedger, opt func(*Options)) *rig {
	t.Helper()
	if cfg == nil {
		cfg = testConfig()
	}
	if led == nil {
		led = newFakeLedger("run-current")
	}
	r := &rig{cfg: cfg, led: led, gw: &fakeGateway{}, pr: newFakeProber(), anc: &fakeAnchorer{urls: cfg.Anchoring.TSAURLs}}
	opts := Options{
		Config:     cfg,
		SaveConfig: func(*config.Config) error { r.saved.Add(1); return nil },
		Ledger:     led,
		Gateway:    r.gw,
		Prober:     r.pr,
		Anchorer:   r.anc,
		Software:   model.SoftwareInfo{Name: "att-monitor", Version: "test"},
		Host:       model.HostInfo{Hostname: "test-host"},
		Mode:       "console",
		Listen:     "127.0.0.1:8320",
		DataDir:    t.TempDir(),
		StateDir:   t.TempDir(),
	}
	if opt != nil {
		opt(&opts)
	}
	m, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	m.compressFirst = 10 * time.Millisecond
	m.notifMinInterval = 50 * time.Millisecond
	m.anchorRetry = 50 * time.Millisecond
	m.dnsRetryPause = time.Millisecond
	m.route = viaGatewayRoute
	m.diskFree = func(string) (uint64, uint64, error) { return 100 << 30, 500 << 30, nil }
	r.m = m
	return r
}

// viaGatewayRoute is a routing table in which this computer reaches every destination through
// the AT&T gateway 192.168.1.254 on its Wi-Fi adapter (interface 12).
func viaGatewayRoute(dst netip.Addr) (routeInfo, error) {
	gw := netip.MustParseAddr(gwIP)
	if dst == gw {
		return routeInfo{IfIndex: 12, IfName: "Wi-Fi"}, nil
	}
	return routeInfo{IfIndex: 12, IfName: "Wi-Fi", NextHop: gw}, nil
}

// vpnRoute is a routing table with a full-tunnel VPN that keeps LAN access: the gateway is
// reached on the Wi-Fi adapter, everything else through the tunnel adapter "NordLynx".
func vpnRoute(dst netip.Addr) (routeInfo, error) {
	if dst == netip.MustParseAddr(gwIP) {
		return routeInfo{IfIndex: 12, IfName: "Wi-Fi"}, nil
	}
	return routeInfo{IfIndex: 23, IfName: "NordLynx", NextHop: netip.MustParseAddr("10.5.0.1")}, nil
}

// start runs Run in the background; stop cancels it and waits for Run to return (also done
// automatically when the test ends).
func (r *rig) start(t *testing.T) (stop func() error) {
	t.Helper()
	ctx, cancel := context.WithCancelCause(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.m.Run(ctx) }()
	var once sync.Once
	var result error
	stop = func() error {
		once.Do(func() {
			cancel(errors.New("test stop"))
			select {
			case result = <-done:
			case <-time.After(20 * time.Second):
				result = errors.New("Run did not return within 20 s after cancel")
			}
		})
		return result
	}
	// A test that fails before calling stop must not leave Run running for later tests.
	t.Cleanup(func() { _ = stop() })
	return stop
}

// waitFor polls cond until it is true or the deadline passes.
func waitFor(t *testing.T, what string, d time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}
