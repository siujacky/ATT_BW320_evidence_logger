package monitor

// Tests of what the fixes of the attribution, evidence and operations review added (rules
// 2026.10-4): the egress route check, the ledger health and free-space conditions, Run's exit
// when the ledger stays unusable, and the helpers behind the restart, clock and traffic rules.

import (
	"context"
	"errors"
	"math"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"attmonitor/internal/config"
	"attmonitor/internal/model"
)

// ---------------------------------------------------------------------------- finding 5: egress

// checkEgress: a destination is reached through the gateway when its route uses the gateway's
// interface and the gateway (or the router of this network the gateway is reached through) as
// its first hop.
func TestCheckEgress(t *testing.T) {
	dests := []string{"1.1.1.1", "8.8.8.8", "2606:4700::1111"}
	if e := checkEgress(viaGatewayRoute, gwIP, dests); e.Err != "" || e.Bypass || len(e.Routes) != 2 || !e.Routes[0].ViaGateway ||
		e.GatewayIfName != "Wi-Fi" || e.GatewayNextHop != "" || e.Routes[0].NextHop != gwIP {
		t.Fatalf("via the gateway: %+v", e)
	}
	e := checkEgress(vpnRoute, gwIP, dests)
	if !e.Bypass || bypassRoute(e) == nil || e.Routes[0].IfName != "NordLynx" ||
		bypassText(e) != `this computer's route to 1.1.1.1 leaves through "NordLynx" (interface 23) via 10.5.0.1, not through the AT&T gateway 192.168.1.254 (reached through "Wi-Fi" (interface 12))` {
		t.Fatalf("VPN: %+v %q", e, bypassText(e))
	}
	// The gateway behind a mesh router of this network: internet traffic takes the same router.
	mesh := func(dst netip.Addr) (routeInfo, error) {
		return routeInfo{IfIndex: 12, IfName: "Wi-Fi", NextHop: netip.MustParseAddr("192.168.86.1")}, nil
	}
	if e := checkEgress(mesh, gwIP, dests); e.Bypass || e.GatewayNextHop != "192.168.86.1" {
		t.Fatalf("mesh: %+v", e)
	}
	// A second adapter holding the default route (a phone hotspot): another interface.
	hotspot := func(dst netip.Addr) (routeInfo, error) {
		if dst == netip.MustParseAddr(gwIP) {
			return routeInfo{IfIndex: 12, IfName: "Wi-Fi"}, nil
		}
		return routeInfo{IfIndex: 31, IfName: "Ethernet 3", NextHop: netip.MustParseAddr("172.20.10.1")}, nil
	}
	if e := checkEgress(hotspot, gwIP, dests); !e.Bypass {
		t.Fatalf("hotspot: %+v", e)
	}
	// Ethernet and Wi-Fi both on the gateway's LAN: the gateway is the first hop either way.
	twoAdapters := func(dst netip.Addr) (routeInfo, error) {
		if dst == netip.MustParseAddr(gwIP) {
			return routeInfo{IfIndex: 12, IfName: "Wi-Fi"}, nil
		}
		return routeInfo{IfIndex: 7, IfName: "Ethernet", NextHop: netip.MustParseAddr(gwIP)}, nil
	}
	if e := checkEgress(twoAdapters, gwIP, dests); e.Bypass {
		t.Fatalf("two adapters on the gateway's LAN: %+v", e)
	}
	// A tunnel adapter routed on-link (WireGuard style): no first hop at all.
	onLink := func(dst netip.Addr) (routeInfo, error) {
		if dst == netip.MustParseAddr(gwIP) {
			return routeInfo{IfIndex: 12, IfName: "Wi-Fi"}, nil
		}
		return routeInfo{IfIndex: 40, IfName: "wg0"}, nil
	}
	if e := checkEgress(onLink, gwIP, dests); !e.Bypass || !strings.Contains(bypassText(e), `"wg0" (interface 40) directly (on-link)`) {
		t.Fatalf("on-link tunnel: %+v %s", e, bypassText(e))
	}
	// Failures conclude nothing.
	broken := func(netip.Addr) (routeInfo, error) {
		return routeInfo{}, errors.New("GetBestRoute2: Element not found.")
	}
	if e := checkEgress(broken, gwIP, dests); e.Err == "" || e.Bypass || bypassText(e) != "" {
		t.Fatalf("lookup failure: %+v", e)
	}
	if e := checkEgress(viaGatewayRoute, "gateway.local", dests); e.Err == "" || e.Bypass {
		t.Fatalf("no IPv4 gateway: %+v", e)
	}
	if egressChanged(checkEgress(viaGatewayRoute, gwIP, dests), checkEgress(viaGatewayRoute, gwIP, dests)) ||
		!egressChanged(checkEgress(viaGatewayRoute, gwIP, dests), checkEgress(vpnRoute, gwIP, dests)) || !egressChanged(nil, e) {
		t.Fatal("egressChanged")
	}
}

// Rules 2 and 3 blame AT&T only for probes that leave through its gateway (rules 2026.10-4).
func TestClassifyEgressBypass(t *testing.T) {
	cfg := config.Default().Incident
	link := &model.LocalLink{Interface: "Wi-Fi", Type: "wifi", State: "connected"}
	vpn := checkEgress(vpnRoute, gwIP, []string{"1.1.1.1", "8.8.8.8", "9.9.9.9"})
	outage := cyc(gwICMP(true, 1900), gwTCP(true, 2300), hopICMP(false, 0), inet(false, false, 0))
	// A stalled tunnel: no internet probe answers, the gateway reports its WAN up.
	v := Classify(ClassifyInput{Cycle: outage, Snapshot: snapWith(nil), SnapshotAge: 10 * time.Second, Link: link, Egress: vpn, LinkSeq: 9}, cfg)
	if v.State != model.StateLocalFault || v.Cause != model.CauseLocalRoute || v.Attribution != model.AttrUndetermined || v.Inputs.LocalLinkSeq != 9 ||
		!strings.Contains(strings.Join(v.Reasons, "\n"), `leaves through "NordLynx"`) || strings.Contains(strings.Join(v.Reasons, "\n"), "provider side") {
		t.Fatalf("tunnel stall: %s/%s/%s %q", v.State, v.Cause, v.Attribution, v.Reasons)
	}
	// The gateway itself reports its WAN down: that is AT&T's, whatever route the probes took.
	down := snapWith(func(s *model.GatewaySnapshot) { s.Broadband.Connection, s.Derived.BroadbandUp = "Down", boolp(false) })
	if v := Classify(ClassifyInput{Cycle: outage, Snapshot: down, Link: link, Egress: vpn}, cfg); v.State != model.StateISPOutage ||
		v.Cause != model.CauseWANDown || v.Attribution != model.AttrProvider {
		t.Fatalf("WAN down: %s/%s/%s", v.State, v.Cause, v.Attribution)
	}
	// A distant VPN endpoint: high latency, not AT&T's.
	slow := cyc(gwICMP(true, 2000), gwTCP(true, 2000), inet(true, true, 180000))
	if v := Classify(ClassifyInput{Cycle: slow, Link: link, Egress: vpn}, cfg); v.State != model.StateDegraded || v.Cause != model.CauseHighLatency ||
		v.Attribution != model.AttrUndetermined {
		t.Fatalf("distant endpoint: %s/%s/%s %q", v.State, v.Cause, v.Attribution, v.Reasons)
	}
	// A stale local link (and its route check) is not used.
	if v := Classify(ClassifyInput{Cycle: outage, Link: link, LinkAge: 151 * time.Second, Egress: vpn}, cfg); v.State != model.StateISPOutage {
		t.Fatalf("stale route check: %s/%s", v.State, v.Cause)
	}
	// Through the gateway: unchanged.
	via := checkEgress(viaGatewayRoute, gwIP, []string{"1.1.1.1"})
	if v := Classify(ClassifyInput{Cycle: outage, Link: link, Egress: via}, cfg); v.State != model.StateISPOutage || v.Attribution != model.AttrProvider {
		t.Fatalf("via the gateway: %s/%s/%s", v.State, v.Cause, v.Attribution)
	}
}

// The monitor checks the route with every local-link reading, records it in the local_link
// record ("egress") on change, classifies with it and warns on the dashboard; when the VPN is
// switched off the change is recorded at the next reading and AT&T is accountable again.
func TestEgressBypassThroughTheMonitor(t *testing.T) {
	base := time.Date(2026, 10, 5, 3, 0, 0, 0, time.UTC)
	r, clk := clockRig(t, base)
	m, ctx := r.m, context.Background()
	m.route = vpnRoute
	clk.Set(base.Add(-time.Second))
	m.takeSnapshot(ctx, trigStartup, nil)
	m.checkLocalLink(ctx, false)
	rec := decode[model.LocalLink](t, lastOfType(t, r, model.TypeLocalLink))
	if rec.Interface != "Wi-Fi" || rec.Egress == nil || !rec.Egress.Bypass || len(rec.Egress.Routes) < 3 {
		t.Fatalf("local_link record %+v egress %+v", rec, rec.Egress)
	}
	st := m.Status()
	if c := findCondition(st, condEgressNotViaGateway); c == nil || c.Severity != "warning" || c.Seq == 0 || !strings.Contains(c.Message, "VPN") {
		t.Fatalf("condition %+v", c)
	}
	if st.LocalLink == nil || st.LocalLink.Egress == nil || !st.LocalLink.Egress.Bypass {
		t.Fatalf("the status shows the route check of the latest reading: %+v", st.LocalLink)
	}
	for i := 0; i < 4; i++ { // the tunnel stalls
		cycleAt(r, clk, base, i, outageCycle())
	}
	opened := incidentsOfType(t, r, model.TypeIncidentOpen)
	if len(opened) != 1 || opened[0].State != model.StateLocalFault || opened[0].Cause != model.CauseLocalRoute || opened[0].Attribution != model.AttrUndetermined {
		t.Fatalf("incident %+v", opened)
	}
	// The VPN is switched off: recorded at the next reading; the outage is AT&T's again.
	m.route = viaGatewayRoute
	clk.Set(base.Add(45 * time.Second))
	m.checkLocalLink(ctx, false)
	if rec := decode[model.LocalLink](t, lastOfType(t, r, model.TypeLocalLink)); rec.Egress == nil || rec.Egress.Bypass {
		t.Fatalf("after the VPN: %+v", rec.Egress)
	}
	cycleAt(r, clk, base, 5, outageCycle())
	if v := decode[model.Sample](t, lastOfType(t, r, model.TypeSample)).Verdict; v.State != model.StateISPOutage || v.Attribution != model.AttrProvider {
		t.Fatalf("after the VPN: %s/%s/%s", v.State, v.Cause, v.Attribution)
	}
	if c := findCondition(m.Status(), condEgressNotViaGateway); c != nil {
		t.Fatalf("condition after the VPN %+v", c)
	}
}

// ---------------------------------------------------------------------------- finding 7: Run, disk

// A ledger that refuses every record (a failed write that could not be rolled back leaves the
// store unusable until it is reopened) ends Run with an error after ledgerFailExit, so the
// Windows service ends and is restarted, which reopens the ledger - unless the data volume is
// full, which a restart cannot fix: then the monitor keeps running and keeps the conditions shown.
func TestRunEndsWhenTheLedgerStaysUnusable(t *testing.T) {
	run := func(free uint64) (*rig, func() error, chan error, context.CancelFunc) {
		r := newRig(t, nil, nil)
		r.m.ledgerFailExit = 300 * time.Millisecond
		r.m.diskFree = func(string) (uint64, uint64, error) { return free, 500 << 30, nil }
		var started atomic.Bool
		r.led.onAppend = func(b model.Body) {
			if b.Type == model.TypeMonitorStart {
				started.Store(true)
			}
		}
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- r.m.Run(ctx) }()
		waitFor(t, "monitor_start", 5*time.Second, started.Load)
		setAppendErr(r.led, errors.New("ledger: unusable after a failed write that could not be rolled back (reopen to recover)"))
		return r, nil, done, cancel
	}
	_, _, done, cancel := run(100 << 30)
	defer cancel()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "evidence ledger has refused every record") {
			t.Fatalf("Run returned %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("Run did not end although the ledger stayed unusable")
	}

	r2, _, done2, cancel2 := run(100 << 20) // 100 MB free
	select {
	case err := <-done2:
		t.Fatalf("Run ended (%v) although a restart cannot free space", err)
	case <-time.After(1500 * time.Millisecond):
	}
	st := r2.m.Status()
	if c := findCondition(st, condDiskSpaceLow); c == nil || c.Severity != "critical" || !strings.Contains(c.Message, "100 MB free") {
		t.Fatalf("disk condition %+v", c)
	}
	if c := findCondition(st, condLedgerWriteFailing); c == nil || c.Severity != "critical" {
		t.Fatalf("ledger condition %+v", c)
	}
	cancel2()
	select {
	case <-done2:
	case <-time.After(20 * time.Second):
		t.Fatal("Run did not return after its context was done")
	}
}

func TestDiskCondition(t *testing.T) {
	at := time.Date(2026, 10, 5, 3, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		free uint64
		sev  string
	}{{3 << 30, ""}, {1 << 30, "warning"}, {100 << 20, "critical"}} {
		c, ok := diskCondition(diskSpace{known: true, free: tc.free, total: 500 << 30, at: at}, `C:\ProgramData\ATTMonitor`)
		if ok != (tc.sev != "") || c.Severity != tc.sev {
			t.Errorf("free %d: %+v %v", tc.free, c, ok)
		}
	}
	if _, ok := diskCondition(diskSpace{}, "x"); ok {
		t.Error("an unknown free space shows nothing")
	}
}

// ---------------------------------------------------------------------------- helpers of the rules

// leadOf: what the cycles before an incident's first cycle say about a restart window.
func TestLeadOf(t *testing.T) {
	type pt struct {
		at          time.Duration
		unreachable bool
		inet        bool
	}
	lead := func(cs []pt, boot, first time.Duration) restartLead {
		return leadOf(len(cs), func(i int) time.Time { return t0.Add(cs[i].at) }, func(i int) bool { return cs[i].unreachable },
			func(i int) bool { return cs[i].inet }, t0.Add(boot), t0.Add(first), 30*time.Second)
	}
	s := time.Second
	if l := lead(nil, 20*s, 60*s); !l.known || l.end != endOpen || !l.from.Equal(t0.Add(20*s)) || l.back {
		t.Fatalf("no cycle between the boot and the incident (computer off): %+v", l)
	}
	if l := lead([]pt{{30 * s, false, true}}, 20*s, 60*s); l.end != endInternet || !l.to.Equal(t0.Add(30*s)) {
		t.Fatalf("a cycle reached the Internet before the incident: %+v", l)
	}
	if l := lead(nil, 0, 11*time.Minute); l.end != endCap || !l.to.Equal(t0.Add(10*time.Minute)) {
		t.Fatalf("the incident began after the cap: %+v", l)
	}
	if l := lead([]pt{{0, true, false}, {10 * s, true, false}}, 15*s, 60*s); l.end != endOpen || !l.back || !l.from.Equal(t0) {
		t.Fatalf("unreachable cycles before the boot: %+v", l)
	}
	if l := lead(nil, 60*s, 60*s); l.known {
		t.Fatalf("a boot at the first cycle has no lead: %+v", l)
	}
}

// elapsedBetween measures the time between two observations with a clock both share.
func TestElapsedBetween(t *testing.T) {
	a, b := obsOf(1, t0, nil), obsOf(2, t0.Add(time.Minute), nil)
	if d, ok := elapsedBetween(a, b); !ok || d != time.Minute {
		t.Fatalf("same process: %v %v", d, ok)
	}
	// Across runs: this computer's clock was 10 min fast at the second reading.
	p := ledgerObs(1, t0, i64p(0), nil)
	c := ledgerObs(2, t0.Add(40*time.Minute), i64p(-600000), nil)
	c.live = true
	if d, ok := elapsedBetween(p, c); !ok || d != 30*time.Minute {
		t.Fatalf("gateway clock: %v %v", d, ok)
	}
	c.Snap.Derived.GatewayClockOffsetMs = nil
	if _, ok := elapsedBetween(p, c); ok {
		t.Fatal("two runs' wall clocks are no measure")
	}
	if _, ok := elapsedBetween(nil, c); ok {
		t.Fatal("nil")
	}
}

// wanTrafficOf: rates from the gateway's counters, 32-bit byte counter wraps, resets.
func TestWANTraffic(t *testing.T) {
	at := t0
	snap := func(seq uint64, at time.Time, rxB, rxP, txB, txP int64, up int64) *snapObs {
		s := okSnapshot(allPages, at)
		s.System.UptimeSec = up
		s.Broadband.Counters = map[string]int64{ctrRxBytes: rxB, ctrRxPkts: rxP, ctrTxBytes: txB, ctrTxPkts: txP}
		return &snapObs{Seq: seq, At: at, Snap: &s, live: true}
	}
	w := wanTrafficOf(snap(1, at, 1000, 10, 2000, 20, 100), snap(2, at.Add(time.Minute), 1000+75_000_000, 60_010, 2000+7_500_000, 10_020, 160))
	if w.Err != "" || math.Abs(w.RxMbps-10) > 1e-9 || math.Abs(w.TxMbps-1) > 1e-9 || w.RxAtLeast || w.heavy() || w.RxPPS != 1000 {
		t.Fatalf("plain: %+v", w)
	}
	// The 32-bit byte counter wrapped once: 4 294 967 000 → 1 000 is 1 296 bytes.
	w = wanTrafficOf(snap(1, at, 4_294_967_000, 10, 0, 0, 100), snap(2, at.Add(time.Minute), 1000, 20, 0, 0, 160))
	if w.Err != "" || math.Abs(w.RxMbps-1296.0*8/60/1e6) > 1e-12 {
		t.Fatalf("wrap: %+v", w)
	}
	// Five million full-size packets in a minute could have wrapped the byte counter again:
	// at least what it shows, and heavy.
	w = wanTrafficOf(snap(1, at, 0, 0, 0, 0, 100), snap(2, at.Add(time.Minute), 1_000_000_000, 5_000_000, 0, 0, 160))
	if !w.RxAtLeast || !w.heavy() || !strings.Contains(w.trafficText(), "at least 133.3 Mb/s") {
		t.Fatalf("ambiguous: %+v %s", w, w.trafficText())
	}
	// A restart of the gateway resets its counters.
	if w = wanTrafficOf(snap(1, at, 5000, 50, 0, 0, 100), snap(2, at.Add(time.Minute), 100, 1, 0, 0, 30)); w.Err == "" {
		t.Fatalf("reset by a restart: %+v", w)
	}
	// Snapshots too far apart.
	if w = wanTrafficOf(snap(1, at, 0, 0, 0, 0, 100), snap(2, at.Add(10*time.Minute), 1, 1, 1, 1, 700)); w.Err == "" {
		t.Fatalf("10 minutes apart: %+v", w)
	}
	if d, ok := counterDelta(10, 5); !ok || d != 1<<32-5 {
		t.Fatalf("counterDelta wrap %d %v", d, ok)
	}
	if _, ok := counterDelta(1<<40, 5); ok {
		t.Fatal("a 64-bit counter that decreased was reset")
	}
}

// The sentences an incident was closed with survive its rebuild from the ledger (reboot watch).
func TestSummaryExtraNotes(t *testing.T) {
	s := "ISP outage from a to b (1m0s), cause WAN_DOWN. Attributed to the provider (AT&T). Measured time: 1m0s without Internet (ISP_OUTAGE cycles). Monitoring was interrupted for 8h0m2s (for example system sleep) while this incident was ongoing; it was closed at the last observation and the outcome during the interruption is unknown."
	if got := summaryExtraNotes(s); len(got) != 1 || !strings.HasPrefix(got[0], "Monitoring was interrupted for 8h0m2s") || strings.Contains(got[0], "Measured time") {
		t.Fatalf("%q", got)
	}
	stale := "ISP outage from a to b (50s). Attributed to the provider (AT&T). The monitor stopped while this incident was open (last sample at x); the incident is closed at that time and the outcome after the monitor stopped is unknown. Measured time: 40s without Internet (ISP_OUTAGE cycles). Statistics cover the 6 cycles recorded from the first bad cycle to that last sample."
	if got := summaryExtraNotes(stale); len(got) != 1 || strings.Contains(got[0], "Measured time") ||
		!strings.HasSuffix(got[0], "to that last sample.") || !strings.HasPrefix(got[0], "The monitor stopped") {
		t.Fatalf("%q", got)
	}
	if summaryExtraNotes("Local fault from a to b (30s). Attribution undetermined.") != nil {
		t.Fatal("no extra notes")
	}
}

// Only incidents of earlier runs that no readable gateway uptime followed wait on the watch:
// a later snapshot with the uptime decided them (a restart would have been found then).
func TestWatchUndecidedIncidentsOnlyUndecided(t *testing.T) {
	base := time.Date(2026, 10, 5, 3, 0, 0, 0, time.UTC)
	for _, laterUptime := range []bool{false, true} {
		r1, clk := clockRig(t, base)
		m1, ctx := r1.m, context.Background()
		r1.gw.snap = func(int, []string, string) (model.GatewaySnapshot, map[string][]byte, error) {
			s := okSnapshot(allPages, clk.Now())
			s.Derived.BootTimeEstimate = fmtTS(base.Add(-274686 * time.Second))
			s.System.UptimeSec = 274686 + int64(clk.Now().Sub(base)/time.Second)
			return s, pageBodies(allPages, "x"), nil
		}
		clk.Set(base.Add(-time.Second))
		m1.takeSnapshot(ctx, trigStartup, nil)
		for i := 0; i < 3; i++ {
			cycleAt(r1, clk, base, i, lanDownCycle())
		}
		for i := 3; i < 6; i++ {
			cycleAt(r1, clk, base, i, healthy())
		}
		m1.finishClosings(ctx) // closed without a close snapshot
		if laterUptime {
			clk.Set(base.Add(2 * time.Minute))
			m1.takeSnapshot(ctx, trigPeriodic, nil)
		}
		r1.led.mu.Lock()
		r1.led.run = "run-next"
		r1.led.mu.Unlock()
		r2 := newRig(t, r1.cfg, r1.led)
		r2.m.now = clk.Now
		clk.Set(base.Add(5 * time.Minute))
		r2.m.rebuild(clk.Now())
		r2.m.watchUndecidedIncidents()
		r2.m.mu.Lock()
		n := len(r2.m.st.rebootWatch)
		r2.m.mu.Unlock()
		if want := map[bool]int{false: 1, true: 0}[laterUptime]; n != want {
			t.Fatalf("later uptime %v: %d watched, want %d", laterUptime, n, want)
		}
	}
}

// A cycle that took longer than its probes may take was interrupted (sleep, stall).
func TestMaxCycleDur(t *testing.T) {
	r, _ := clockRig(t, t0)
	if got := r.m.maxCycleDur(); got != 9*time.Second { // 2 s timeout + 2 s grace + half of 10 s
		t.Fatalf("limit %v", got)
	}
	v := interruptedVerdict(8*time.Hour, 9*time.Second)
	if v.State != model.StateUnknown || v.Attribution != model.AttrUndetermined || v.Rules != RulesVersion || v.Inputs == nil {
		t.Fatalf("%+v", v)
	}
}
