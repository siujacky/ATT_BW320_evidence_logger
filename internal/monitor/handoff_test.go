package monitor

// Tests of the hand-offs after the final review (rules 2026.10-4): Run's prompt exit on
// contracts.ErrLedgerBroken, the egress route check as model.LocalLink.Egress, the optional
// verdict inputs (previous service check, traffic snapshots), monitor_start's signed gap and the
// CLOCK_OFFSET condition.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"attmonitor/internal/config"
	"attmonitor/internal/contracts"
	"attmonitor/internal/model"
)

// brokenLedgerErr is what a ledger that could not roll back a failed write answers to every
// later record (it wraps contracts.ErrLedgerBroken).
func brokenLedgerErr() error {
	return fmt.Errorf("ledger: unusable after a failed write that could not be rolled back (reopen to recover): %w",
		fmt.Errorf("write failed (disk I/O error) and truncating the partial line failed (access denied): %w", contracts.ErrLedgerBroken))
}

// ---------------------------------------------------------------------------- 1. ErrLedgerBroken

// A ledger that reports contracts.ErrLedgerBroken refuses every further record until it is
// reopened: Run ends at once - not after ledgerFailExit of refused records - with an error that
// says so and wraps the sentinel, so the Windows service stops and is restarted, which reopens
// the ledger (crash recovery).
func TestRunStopsAtOnceWhenTheLedgerIsBroken(t *testing.T) {
	r := newRig(t, nil, nil)
	if r.m.ledgerFailExit < time.Minute {
		t.Fatalf("ledgerFailExit %v: the test needs the default", r.m.ledgerFailExit)
	}
	var started atomic.Bool
	r.led.onAppend = func(b model.Body) {
		if b.Type == model.TypeMonitorStart {
			started.Store(true)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- r.m.Run(ctx) }()
	waitFor(t, "monitor_start", 5*time.Second, started.Load)
	setAppendErr(r.led, brokenLedgerErr())
	select {
	case err := <-done:
		if !errors.Is(err, contracts.ErrLedgerBroken) {
			t.Fatalf("Run returned %v; want an error wrapping contracts.ErrLedgerBroken", err)
		}
		for _, want := range []string{"evidence ledger is unusable", "restart"} {
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("Run's error %q does not say %q", err, want)
			}
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop although the ledger reported contracts.ErrLedgerBroken")
	}
	if c := findCondition(r.m.Status(), condLedgerWriteFailing); c == nil || c.Severity != "critical" || !strings.Contains(c.Message, "unusable") {
		t.Fatalf("condition %+v", c)
	}

	// Refused already at monitor_start: Run cannot start, and says why.
	r2 := newRig(t, nil, nil)
	setAppendErr(r2.led, brokenLedgerErr())
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	go func() { done <- r2.m.Run(ctx2) }()
	select {
	case err := <-done:
		if !errors.Is(err, contracts.ErrLedgerBroken) || !strings.Contains(err.Error(), "monitor_start") {
			t.Fatalf("Run returned %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return although monitor_start could not be recorded")
	}
}

// ---------------------------------------------------------------------------- 3. verdict inputs

// The verdict names the previous service check when the DNS rule compared the current one with
// it (whether or not it confirmed the failure), and the two snapshots of the traffic rate when
// the attribution consulted them - and only then.
func TestVerdictInputsNamePreviousCheckAndTrafficSnapshots(t *testing.T) {
	cfg := config.Default().Incident
	ispFail := model.DNSResult{Server: "68.94.156.9:53", ServerRole: "isp", Name: "www.google.com", OK: true, RCode: "SERVFAIL"}
	failing := svc(dnsOK("gateway", gwIP), ispFail, dnsOK("public", "1.1.1.1"))
	fine := svc(dnsOK("gateway", gwIP), dnsOK("isp", "68.94.156.9"), dnsOK("public", "1.1.1.1"))
	dns := ClassifyInput{Cycle: healthy(), Service: failing, ServiceAge: 30 * time.Second, ServiceSeq: 42,
		PrevService: failing, PrevServiceGap: time.Minute, PrevServiceSeq: 41}
	check := func(name string, in ClassifyInput, state, cause string, want model.VerdictInputs) {
		t.Helper()
		v := Classify(in, cfg)
		if v.State != state || v.Cause != cause || v.Inputs == nil || *v.Inputs != want {
			var got any = v.Inputs
			if v.Inputs != nil {
				got = *v.Inputs
			}
			t.Errorf("%s: %s/%s inputs %+v, want %s/%s %+v; reasons %q", name, v.State, v.Cause, got, state, cause, want, v.Reasons)
		}
	}
	check("DNS failure confirmed by the previous check", dns, model.StateDegraded, model.CauseISPDNSFailure,
		model.VerdictInputs{ServiceCheckSeq: 42, PrevServiceCheckSeq: 41, WindowCycles: 1})
	in := dns
	in.PrevService = fine
	check("DNS failure the previous check does not confirm", in, model.StateOnline, "",
		model.VerdictInputs{ServiceCheckSeq: 42, PrevServiceCheckSeq: 41, WindowCycles: 1})
	in = dns
	in.PrevServiceGap = 151 * time.Second
	check("previous check too old to compare", in, model.StateOnline, "",
		model.VerdictInputs{ServiceCheckSeq: 42, WindowCycles: 1})
	in = dns
	in.Service = fine
	check("no DNS failure: the previous check is not consulted", in, model.StateOnline, "",
		model.VerdictInputs{ServiceCheckSeq: 42, WindowCycles: 1})
	slow := cyc(gwICMP(true, 2000), gwTCP(true, 2300), inet(true, true, 250000))
	in = dns
	in.Cycle = slow
	check("latency outranks the DNS rule", in, model.StateDegraded, model.CauseHighLatency,
		model.VerdictInputs{ServiceCheckSeq: 42, WindowCycles: 1})

	light := &WANTraffic{FromSeq: 10, ToSeq: 19, Dur: time.Minute, RxMbps: 3, TxMbps: 0.4, RxPPS: 300, TxPPS: 40}
	tr := ClassifyInput{Cycle: slow, Traffic: light, TrafficAge: 20 * time.Second}
	check("light traffic", tr, model.StateDegraded, model.CauseHighLatency,
		model.VerdictInputs{TrafficFromSeq: 10, TrafficToSeq: 19, WindowCycles: 1})
	heavy := *light
	heavy.RxMbps = 500
	in = tr
	in.Traffic = &heavy
	check("heavy traffic", in, model.StateDegraded, model.CauseHighLatency,
		model.VerdictInputs{TrafficFromSeq: 10, TrafficToSeq: 19, WindowCycles: 1})
	failed := WANTraffic{FromSeq: 10, ToSeq: 19, Dur: time.Minute, Err: "the gateway restarted between the two snapshots (its counters were reset)"}
	in = tr
	in.Traffic = &failed
	check("no rate from the two snapshots", in, model.StateDegraded, model.CauseHighLatency,
		model.VerdictInputs{TrafficFromSeq: 10, TrafficToSeq: 19, WindowCycles: 1})
	in = tr
	in.TrafficAge = 151 * time.Second
	check("stale traffic", in, model.StateDegraded, model.CauseHighLatency, model.VerdictInputs{WindowCycles: 1})
	in = tr
	in.Cycle = healthy()
	check("online: the traffic is not consulted", in, model.StateOnline, "", model.VerdictInputs{WindowCycles: 1})
	in = tr
	in.Window = win(cyc(gwICMP(false, 0), gwTCP(true, 2300), inet(true, true, 250000)), slow)
	check("gateway loss decides first", in, model.StateDegraded, model.CauseHighLatency, model.VerdictInputs{WindowCycles: 2})
}

// Through the monitor: the samples name the recorded service checks and snapshots they used.
func TestVerdictInputsNameRecordedPreviousCheckAndTrafficSnapshots(t *testing.T) {
	base := time.Date(2026, 10, 5, 3, 0, 0, 0, time.UTC)
	r, clk := clockRig(t, base)
	m, ctx := r.m, context.Background()
	var call atomic.Int32
	r.gw.snap = func(int, []string, string) (model.GatewaySnapshot, map[string][]byte, error) {
		s := okSnapshot(allPages, clk.Now())
		s.Derived.BootTimeEstimate = fmtTS(base.Add(-274686 * time.Second))
		n := int64(call.Add(1) - 1)
		s.System.UptimeSec, s.Derived.UptimeSec = 274686+60*n, 274686+60*n
		s.Broadband.Counters = map[string]int64{
			ctrRxBytes: 100_000_000 + n*22_500_000, ctrRxPkts: 1_000_000 + n*30_000,
			ctrTxBytes: 50_000_000 + n*3_000_000, ctrTxPkts: 900_000 + n*20_000,
		}
		return s, pageBodies(allPages, fmt.Sprint(n)), nil
	}
	clk.Set(base.Add(-60 * time.Second))
	first := m.takeSnapshot(ctx, trigStartup, nil)
	clk.Set(base)
	second := m.takeSnapshot(ctx, trigPeriodic, nil)
	if first == nil || second == nil {
		t.Fatal("snapshots not recorded")
	}
	slow := cyc(gwICMP(true, 2000), gwTCP(true, 2300), inet(true, true, 250000))
	cycleAt(r, clk, base, 1, slow)
	v := decode[model.Sample](t, lastOfType(t, r, model.TypeSample)).Verdict
	if v.Cause != model.CauseHighLatency || v.Attribution != model.AttrProvider || v.Inputs == nil ||
		v.Inputs.TrafficFromSeq != first.Seq || v.Inputs.TrafficToSeq != second.Seq || v.Inputs.SnapshotSeq != second.Seq {
		t.Fatalf("%s/%s/%s inputs %+v (snapshots #%d, #%d)", v.State, v.Cause, v.Attribution, v.Inputs, first.Seq, second.Seq)
	}

	// The AT&T resolver fails in two consecutive service checks.
	r.pr.dns = func(server, name string) model.DNSResult {
		if isInvalidName(name) {
			return model.DNSResult{Server: server + ":53", Name: name, QType: "A", OK: true, RCode: "NXDOMAIN"}
		}
		if server == "68.94.156.9" {
			return model.DNSResult{Server: server + ":53", Name: name, QType: "A", OK: true, RCode: "SERVFAIL"}
		}
		return model.DNSResult{Server: server + ":53", Name: name, QType: "A", OK: true, RCode: "NOERROR", Answers: []string{"142.250.72.36"}}
	}
	clk.Set(base.Add(20 * time.Second))
	m.runServiceCheck(ctx)
	prevCheck := lastOfType(t, r, model.TypeServiceCheck)
	clk.Set(base.Add(80 * time.Second))
	m.runServiceCheck(ctx)
	check := lastOfType(t, r, model.TypeServiceCheck)
	cycleAt(r, clk, base, 9, healthy())
	v = decode[model.Sample](t, lastOfType(t, r, model.TypeSample)).Verdict
	if v.Cause != model.CauseISPDNSFailure || v.Inputs == nil || v.Inputs.ServiceCheckSeq != check.Seq || v.Inputs.PrevServiceCheckSeq != prevCheck.Seq {
		t.Fatalf("%s/%s inputs %+v (service checks #%d, #%d): %q", v.State, v.Cause, v.Inputs, prevCheck.Seq, check.Seq, v.Reasons)
	}
}

// ---------------------------------------------------------------------------- 4. monitor_start gap

// monitor_start states the real time since the newest record, also when this computer's clock
// is behind it (a negative gap is evidence of a clock set back, never clamped to 0).
func TestMonitorStartRecordsTheSignedGap(t *testing.T) {
	base := time.Date(2026, 10, 5, 3, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name   string
		newest time.Time // ts of the newest record before the start
		want   int64
	}{
		{"clock behind the newest record", base.Add(90 * time.Second), -90},
		{"clock behind by less than a second", base.Add(400 * time.Millisecond), 0},
		{"after a stop", base.Add(-9 * time.Minute), 540},
	} {
		t.Run(tc.name, func(t *testing.T) {
			led := newFakeLedgerAt("run-current", base.Add(-time.Hour))
			led.appendAs("run-prev", tc.newest, model.TypeMonitorStop, model.MonitorStop{Reason: "service stop"})
			clk := &fakeClock{t: base}
			led.now = clk.Now
			r := newRig(t, nil, led)
			r.m.now = clk.Now
			if err := r.m.recordStart(clk.Now()); err != nil {
				t.Fatal(err)
			}
			if ms := decode[model.MonitorStart](t, lastOfType(t, r, model.TypeMonitorStart)); ms.GapSeconds != tc.want {
				t.Fatalf("gap_seconds %d, want %d", ms.GapSeconds, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------- 2. egress in model.LocalLink

// The route check is model.LocalLink's Egress member: the local_link record keeps the members it
// had when the monitor wrote the check beside the reading (same names, same nesting), its
// "egress" object is byte for byte what it was, and records written before read back unchanged.
func TestLocalLinkRecordKeepsItsFormat(t *testing.T) {
	// The payload types the monitor wrote before model held the route check.
	type oldRoute struct {
		Target     string `json:"target"`
		If         uint32 `json:"if,omitempty"`
		IfName     string `json:"if_name,omitempty"`
		NextHop    string `json:"next_hop,omitempty"`
		ViaGateway bool   `json:"via_gateway"`
		Err        string `json:"err,omitempty"`
	}
	type oldEgress struct {
		Gateway        string     `json:"gateway"`
		GatewayIf      uint32     `json:"gateway_if,omitempty"`
		GatewayIfName  string     `json:"gateway_if_name,omitempty"`
		GatewayNextHop string     `json:"gateway_next_hop,omitempty"`
		Routes         []oldRoute `json:"routes,omitempty"`
		Bypass         bool       `json:"bypass"`
		Err            string     `json:"err,omitempty"`
	}
	type oldRecord struct {
		model.LocalLink
		Egress *oldEgress `json:"egress,omitempty"`
	}
	lookup := func(dst netip.Addr) (routeInfo, error) {
		if dst == netip.MustParseAddr("9.9.9.9") {
			return routeInfo{}, errors.New("GetBestRoute2: Element not found.")
		}
		return vpnRoute(dst)
	}
	var e *model.EgressCheck = checkEgress(lookup, gwIP, []string{"1.1.1.1", "8.8.8.8", "9.9.9.9"})
	newEgress, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	var old oldEgress
	if err := json.Unmarshal(newEgress, &old); err != nil {
		t.Fatal(err)
	}
	if oldEgressJSON, _ := json.Marshal(old); string(oldEgressJSON) != string(newEgress) {
		t.Fatalf("egress JSON changed:\nbefore %s\nnow    %s", oldEgressJSON, newEgress)
	}

	reading := model.LocalLink{Interface: "Wi-Fi", Type: "wifi", State: "connected", SSID: "home", BSSID: "aa:bb:cc:dd:ee:ff",
		SignalPct: 90, Channel: 149, RawSHA256: strings.Repeat("ab", 32)}
	rec := reading
	rec.Egress = e
	newJSON, _ := json.Marshal(rec)
	oldJSON, _ := json.Marshal(oldRecord{LocalLink: reading, Egress: &old})
	var nm, om map[string]any
	if json.Unmarshal(newJSON, &nm) != nil || json.Unmarshal(oldJSON, &om) != nil || !reflect.DeepEqual(nm, om) {
		t.Fatalf("local_link members changed:\nbefore %s\nnow    %s", oldJSON, newJSON)
	}
	var back model.LocalLink
	if err := json.Unmarshal(oldJSON, &back); err != nil || !reflect.DeepEqual(back, rec) {
		t.Fatalf("a record written before reads back as %+v (%v)", back, err)
	}
	if b, _ := json.Marshal(reading); strings.Contains(string(b), "egress") {
		t.Fatalf("a reading without a route check has no egress member: %s", b)
	}
}

// Classify finds the route check in the local link itself when the input names none apart.
func TestClassifyUsesTheLinksOwnRouteCheck(t *testing.T) {
	link := &model.LocalLink{Interface: "Wi-Fi", Type: "wifi", State: "connected",
		Egress: checkEgress(vpnRoute, gwIP, []string{"1.1.1.1", "8.8.8.8", "9.9.9.9"})}
	outage := cyc(gwICMP(true, 1900), gwTCP(true, 2300), inet(false, false, 0))
	v := Classify(ClassifyInput{Cycle: outage, Snapshot: snapWith(nil), Link: link, LinkSeq: 9}, config.Default().Incident)
	if v.State != model.StateLocalFault || v.Cause != model.CauseLocalRoute || v.Attribution != model.AttrUndetermined || v.Inputs.LocalLinkSeq != 9 {
		t.Fatalf("%s/%s/%s %q", v.State, v.Cause, v.Attribution, v.Reasons)
	}
}

// ---------------------------------------------------------------------------- 5. CLOCK_OFFSET

const clockOffsetWords = "compared with internet time servers; evidence timestamps rely on it — fix the Windows time settings"

func TestClockOffsetCondition(t *testing.T) {
	if _, ok := clockOffsetCondition(nil); ok {
		t.Fatal("no clock check, no condition")
	}
	for _, tc := range []struct {
		offMs int64 // server - local
		sev   string
		words []string
	}{
		{0, "", nil},
		{60_000, "", nil},
		{-60_000, "", nil},
		{60_001, "warning", []string{"This computer's clock is off by about 60 s " + clockOffsetWords, "behind them", "median of 3 answers", "clock check #7"}},
		{75_400, "warning", []string{"off by about 75 s ", "behind them"}},
		{-75_600, "warning", []string{"off by about 76 s ", "ahead of them"}},
		{300_000, "warning", []string{"off by about 300 s (5m0s) "}},
		{300_001, "critical", []string{"off by about 300 s", "RFC 3161", "ts_contradiction"}},
		{-3_600_000, "critical", []string{"off by about 3600 s (1h0m0s) ", "ahead of them", "RFC 3161"}},
		{math.MinInt64, "critical", []string{"ahead of them"}}, // nonsense from a damaged cache: no overflow
		{math.MaxInt64, "critical", []string{"behind them"}},
	} {
		ref := &clockRef{Seq: 7, TS: "2026-10-05T03:00:00Z", OffsetMs: tc.offMs, Answered: 3, OffSince: "2026-10-05T01:00:00Z"}
		c, ok := clockOffsetCondition(ref)
		if ok != (tc.sev != "") || c.Severity != tc.sev {
			t.Errorf("offset %d ms: %+v %v, want severity %q", tc.offMs, c, ok, tc.sev)
			continue
		}
		if !ok {
			continue
		}
		if c.Code != condClockOffset || c.Seq != 7 || c.Since != "2026-10-05T01:00:00Z" || !strings.HasPrefix(c.Message, "This computer's clock is off by about ") {
			t.Errorf("offset %d ms: %+v", tc.offMs, c)
		}
		for _, w := range tc.words {
			if !strings.Contains(c.Message, w) {
				t.Errorf("offset %d ms: %q lacks %q", tc.offMs, c.Message, w)
			}
		}
		if (tc.sev == "warning") == strings.Contains(c.Message, "RFC 3161") {
			t.Errorf("offset %d ms: only the critical condition notes the time-stamp check: %q", tc.offMs, c.Message)
		}
	}
}

// The condition follows the latest clock check with an answer; since when it holds is the first
// check of the current run of offsets beyond the threshold; a restarted monitor shows it again
// from the ledger or its state cache.
func TestClockOffsetThroughTheMonitor(t *testing.T) {
	base := time.Date(2026, 10, 5, 3, 0, 0, 0, time.UTC)
	r, clk := clockRig(t, base)
	m, ctx := r.m, context.Background()
	var off atomic.Int64
	var down atomic.Bool
	r.pr.sntp = func(server string) model.ClockResult {
		if down.Load() || server == "pool.ntp.org" {
			return model.ClockResult{Server: server, Err: "i/o timeout"}
		}
		return model.ClockResult{Server: server, OK: true, OffsetMs: off.Load(), RTTms: 20, Stratum: 2}
	}
	measure := func(at time.Duration, ms int64) model.Body {
		t.Helper()
		off.Store(ms)
		clk.Set(base.Add(at))
		m.clockCheck(ctx)
		return lastOfType(t, r, model.TypeClockCheck)
	}
	measure(0, 2_000)
	if c := findCondition(m.Status(), condClockOffset); c != nil {
		t.Fatalf("2 s off: %+v", c)
	}
	first := measure(time.Hour, 75_000)
	c := findCondition(m.Status(), condClockOffset)
	if c == nil || c.Severity != "warning" || c.Seq != first.Seq || c.Since != first.TS ||
		!strings.HasPrefix(c.Message, "This computer's clock is off by about 75 s "+clockOffsetWords) || !strings.Contains(c.Message, "median of 2 answers") {
		t.Fatalf("75 s off: %+v", c)
	}
	second := measure(2*time.Hour, 400_000)
	want := model.Condition{Code: condClockOffset, Severity: "critical", Seq: second.Seq, Since: first.TS}
	if c = findCondition(m.Status(), condClockOffset); c == nil || c.Severity != want.Severity || c.Seq != want.Seq || c.Since != want.Since ||
		!strings.Contains(c.Message, "RFC 3161") {
		t.Fatalf("400 s off: %+v", c)
	}
	want.Message = c.Message
	// No time server answers: the latest measurement stands.
	down.Store(true)
	measure(3*time.Hour, 0)
	if c = findCondition(m.Status(), condClockOffset); c == nil || *c != want {
		t.Fatalf("unanswered check: %+v", c)
	}
	// A restarted monitor shows it from the ledger, and from its state cache.
	r.m.writeCache()
	for _, cached := range []bool{false, true} {
		r2 := newRig(t, r.cfg, r.led)
		r2.m.now = clk.Now
		if cached {
			r2.m.opts.StateDir = r.m.opts.StateDir
		}
		r2.m.rebuild(clk.Now())
		if c := findCondition(r2.m.Status(), condClockOffset); c == nil || *c != want {
			t.Fatalf("rebuilt (cache %v): %+v, want %+v", cached, c, want)
		}
	}
	// The clock is set right: the condition ends.
	down.Store(false)
	measure(4*time.Hour, 1_500)
	if c := findCondition(m.Status(), condClockOffset); c != nil {
		t.Fatalf("clock set right: %+v", c)
	}
}

// A step of this computer's clock (a clock_jump between cycles) changes its offset to the time
// servers: it is measured again at once - though not sooner than clockRecheckMin after the
// previous check, however often the clock steps - so CLOCK_OFFSET does not keep describing the
// clock as it was before the step until the next hourly check.
func TestClockStepIsMeasuredAgain(t *testing.T) {
	r := newRig(t, nil, nil) // hourly clock checks
	const floor = 500 * time.Millisecond
	r.m.clockRecheckMin = floor
	checks := func() []model.Body { return ofType(r.led.records(""), model.TypeClockCheck) }
	stop := r.start(t)
	waitFor(t, "the clock check at the start", 5*time.Second, func() bool { return len(checks()) == 1 })
	r.m.continuity(70*time.Second, 40*time.Millisecond) // stepped +70 s, then back
	r.m.continuity(-70*time.Second, 40*time.Millisecond)
	waitFor(t, "a clock check after the steps", 5*time.Second, func() bool { return len(checks()) == 2 })
	time.Sleep(2 * floor)
	cs := checks()
	if len(cs) != 2 {
		t.Fatalf("%d clock checks: steps within the floor are measured once", len(cs))
	}
	if d := mustTS(t, cs[1].TS).Sub(mustTS(t, cs[0].TS)); d < floor-100*time.Millisecond {
		t.Fatalf("re-measured %v after the previous check, sooner than the floor %v", d, floor)
	}
	if err := stop(); err != nil {
		t.Fatal(err)
	}
}
