package monitor

// Regression tests for the findings of the attribution, evidence and operations review of the
// monitor (rules 2026.10-4). Each one failed before its fix; they use only what the monitor had
// before, so they also run against the earlier code.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"attmonitor/internal/config"
	"attmonitor/internal/model"
)

// ---------------------------------------------------------------------------- helpers

// captureHandler records every log record (for the event-log flooding tests).
type captureHandler struct {
	mu   sync.Mutex
	recs []slog.Record
}

func (h *captureHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h *captureHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	h.recs = append(h.recs, r)
	h.mu.Unlock()
	return nil
}
func (h *captureHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *captureHandler) WithGroup(string) slog.Handler      { return h }

// count returns how many records with this message were logged at level or above.
func (h *captureHandler) count(level slog.Level, msg string) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	n := 0
	for _, r := range h.recs {
		if r.Level >= level && r.Message == msg {
			n++
		}
	}
	return n
}

func findCondition(st model.Status, code string) *model.Condition {
	for i := range st.Conditions {
		if st.Conditions[i].Code == code {
			return &st.Conditions[i]
		}
	}
	return nil
}

func incidentsOfType(t *testing.T, r *rig, typ string) []model.Incident {
	t.Helper()
	var out []model.Incident
	for _, b := range ofType(r.led.records(""), typ) {
		out = append(out, decode[model.Incident](t, b))
	}
	return out
}

var allPages = []string{"broadbandstatistics", "fiberstat", "sysinfo"}

// ---------------------------------------------------------------------------- finding 1

// A home power failure stops the gateway and this computer: the gateway boots at B, the
// computer's first cycle comes 40 s later, while the gateway's PON is still ranging. The
// incident those cycles open lies inside the restart window of B (no cycle between B and it
// reached the Internet) and must be recorded as a gateway restart - not as an AT&T fiber outage,
// which the statistics (applying the same window) would contradict with 0 s of provider outage.
func TestFindingRestartBeforeFirstObservedCycle(t *testing.T) {
	power := time.Date(2026, 10, 5, 3, 0, 0, 0, time.UTC) // power returns
	boot := power.Add(20 * time.Second)                   // the gateway boots
	first := power.Add(60 * time.Second)                  // this computer's first cycle
	r, clk := clockRig(t, first)
	m, ctx := r.m, context.Background()
	// The run before the power failure read the gateway's uptime for the last time hours earlier.
	before := power.Add(-3 * time.Hour)
	r.led.appendAs("run-prev", before, model.TypeMonitorStart, model.MonitorStart{})
	r.led.appendAs("run-prev", before.Add(time.Second), model.TypeGatewaySnapshot, okSnapshot(allPages, before))
	m.rebuild(clk.Now())
	var wanUp atomic.Bool
	r.gw.snap = func(int, []string, string) (model.GatewaySnapshot, map[string][]byte, error) {
		now := clk.Now()
		s := okSnapshot(allPages, now)
		up := int64(now.Sub(boot) / time.Second)
		s.System.UptimeSec, s.Derived.UptimeSec, s.Derived.BootTimeEstimate = up, up, fmtTS(boot)
		if !wanUp.Load() { // the PON is still ranging
			s.Broadband.PONLinkStatus, s.Derived.PONOperational = "POPUP (O6)", boolp(false)
		}
		return s, pageBodies(allPages, fmt.Sprint(now.UnixNano())), nil
	}
	clk.Set(first.Add(-2 * time.Second))
	if m.takeSnapshot(ctx, trigStartup, nil) == nil || len(rebootEvents(t, r)) != 1 {
		t.Fatal("the startup snapshot must record the gateway reboot")
	}
	for i := 0; i < 9; i++ { // 90 s: the gateway answers, its fiber link is not up yet
		cycleAt(r, clk, first, i, outageCycle())
	}
	opened := incidentsOfType(t, r, model.TypeIncidentOpen)
	if len(opened) != 1 {
		t.Fatalf("incident_open records %d", len(opened))
	}
	if o := opened[0]; o.State != model.StateLocalFault || o.Cause != model.CauseGatewayReboot || o.Attribution != model.AttrUndetermined ||
		!slices.Equal(o.GatewayRestarts, []string{fmtTS(boot)}) {
		t.Fatalf("open record %s/%s/%s restarts %v: %s", o.State, o.Cause, o.Attribution, o.GatewayRestarts, o.Summary)
	}
	wanUp.Store(true)
	for i := 9; i < 12; i++ {
		cycleAt(r, clk, first, i, healthy())
	}
	m.mu.Lock()
	if len(m.st.closing) != 1 {
		m.mu.Unlock()
		t.Fatal("the incident should be closing")
	}
	st := m.st.closing[0]
	m.mu.Unlock()
	clk.Set(first.Add(125 * time.Second))
	m.finishClose(ctx, st, true)
	closed := decode[model.Incident](t, lastOfType(t, r, model.TypeIncidentClose))
	if closed.State != model.StateLocalFault || closed.Cause != model.CauseGatewayReboot || closed.Attribution != model.AttrUndetermined ||
		closed.Stats.DowntimeSec != 0 || closed.Stats.RestartSec != 90 {
		t.Fatalf("close record %s/%s/%s %+v: %s", closed.State, closed.Cause, closed.Attribution, closed.Stats, closed.Summary)
	}
	if strings.Contains(closed.Summary, "Attributed to the provider") || !strings.Contains(closed.Summary, "when the Internet was reachable again") {
		t.Fatalf("summary %s", closed.Summary)
	}
	if day := m.Status().Stats[0]; day.ProviderOutageSec != 0 {
		t.Fatalf("statistics %+v", day)
	}
}

// ---------------------------------------------------------------------------- finding 2

// The owner power-cycles the gateway and this computer stops in the same minute (a crash, a
// shutdown): the run that saw the gateway come back without Internet never read its new uptime.
// The next run's first snapshot reveals the restart; the incident of the previous run - left
// open, or closed before the uptime could be read - must then be revised (incident_update), as
// it would have been had the computer kept running.
func TestFindingRestartRevisesIncidentOfPreviousRun(t *testing.T) {
	for _, leftOpen := range []bool{true, false} {
		t.Run(fmt.Sprintf("left_open=%v", leftOpen), func(t *testing.T) {
			base := time.Date(2026, 10, 5, 3, 0, 0, 0, time.UTC)
			r1, clk := clockRig(t, base)
			gw := &restartGateway{clk: clk, base: base, boot: base.Add(45 * time.Second)}
			r1.gw.snap = gw.snap
			m1, ctx := r1.m, context.Background()
			clk.Set(base.Add(-5 * time.Second))
			if m1.takeSnapshot(ctx, trigStartup, nil) == nil {
				t.Fatal("snapshot")
			}
			cycleAt(r1, clk, base, 0, healthy())
			cycleAt(r1, clk, base, 1, healthy())
			for i := 2; i <= 7; i++ {
				cycleAt(r1, clk, base, i, lanDownCycle()) // powered off, booting
			}
			for i := 8; i <= 12; i++ {
				cycleAt(r1, clk, base, i, outageCycle()) // LAN back, WAN still coming up
			}
			if !leftOpen {
				for i := 13; i <= 15; i++ {
					cycleAt(r1, clk, base, i, healthy())
				}
				m1.mu.Lock()
				st := m1.st.closing[0]
				m1.mu.Unlock()
				gw.sysinfoDown.Store(true) // the close snapshot cannot read the uptime
				clk.Set(base.Add(160 * time.Second))
				m1.finishClose(ctx, st, true)
			}
			id := incidentsOfType(t, r1, model.TypeIncidentOpen)[0].ID

			// This computer stops; the next run starts four minutes later.
			r1.led.mu.Lock()
			r1.led.run = "run-next"
			r1.led.mu.Unlock()
			clk.Set(base.Add(4 * time.Minute))
			gw.sysinfoDown.Store(false)
			gw.restarted.Store(true)
			r2 := newRig(t, r1.cfg, r1.led)
			r2.m.now = clk.Now
			r2.gw.snap = gw.snap
			stop := r2.start(t)
			var upd model.Incident
			waitFor(t, "the incident revised by the restart", 10*time.Second, func() bool {
				for _, b := range ofType(r1.led.records("run-next"), model.TypeIncidentUpdate) {
					if inc := decode[model.Incident](t, b); inc.ID == id {
						upd = inc
						return true
					}
				}
				return false
			})
			if err := stop(); err != nil {
				t.Fatal(err)
			}
			if upd.Open || upd.State != model.StateLocalFault || upd.Cause != model.CauseGatewayReboot || upd.Attribution != model.AttrUndetermined ||
				upd.Stats.DowntimeSec != 0 || upd.Stats.RestartSec == 0 || !slices.Equal(upd.GatewayRestarts, []string{fmtTS(gw.boot)}) {
				t.Fatalf("update %s/%s/%s open %v %+v restarts %v", upd.State, upd.Cause, upd.Attribution, upd.Open, upd.Stats, upd.GatewayRestarts)
			}
			if leftOpen && !strings.Contains(upd.Summary, "The monitor stopped while this incident was open") {
				t.Fatalf("the revision must keep how the incident was closed: %s", upd.Summary)
			}
		})
	}
}

// ---------------------------------------------------------------------------- finding 3

// One lost UDP datagram (or two in one check) to the AT&T resolver while the public resolver
// answers is not an ISP DNS failure: the query is retried within its check, and only a failure
// that persists over two consecutive checks makes cycles DEGRADED/ISP_DNS_FAILURE.
func TestFindingSingleLostDNSQueryIsNotAnISPFailure(t *testing.T) {
	base := time.Date(2026, 10, 5, 3, 0, 0, 0, time.UTC)
	r, clk := clockRig(t, base)
	m, ctx := r.m, context.Background()
	clk.Set(base.Add(-time.Second))
	m.takeSnapshot(ctx, trigStartup, nil) // the ISP resolver 68.94.156.9
	var lose atomic.Int32                 // ISP resolver queries still to be lost
	r.pr.dns = func(server, name string) model.DNSResult {
		if strings.HasPrefix(server, "68.94.156.9") && !isInvalidName(name) && lose.Add(-1) >= 0 {
			return model.DNSResult{Server: server + ":53", Name: name, QType: "A", Err: "timeout: no response within 2s"}
		}
		if isInvalidName(name) {
			return model.DNSResult{Server: server + ":53", Name: name, QType: "A", OK: true, RCode: "NXDOMAIN"}
		}
		return model.DNSResult{Server: server + ":53", Name: name, QType: "A", OK: true, RCode: "NOERROR", Answers: []string{"142.250.72.36"}}
	}
	cycle := 0
	runChecked := func(lost int32) []model.Verdict {
		lose.Store(lost)
		clk.Set(base.Add(time.Duration(cycle)*10*time.Second - 500*time.Millisecond))
		m.runServiceCheck(ctx)
		var vs []model.Verdict
		for i := 0; i < 6; i++ { // a minute of cycles using that check
			cycleAt(r, clk, base, cycle, healthy())
			cycle++
			vs = append(vs, decode[model.Sample](t, lastOfType(t, r, model.TypeSample)).Verdict)
		}
		return vs
	}
	for _, lost := range []int32{0, 1, 0, 2, 0} { // one lost datagram; then two lost in one check
		for _, v := range runChecked(lost) {
			if v.State != model.StateOnline {
				t.Fatalf("%d lost queries: %s/%s/%s %q", lost, v.State, v.Cause, v.Attribution, v.Reasons)
			}
		}
	}
	if m.incidentOpen() || len(ofType(r.led.records(""), model.TypeIncidentOpen)) != 0 {
		t.Fatal("lost DNS datagrams opened an incident")
	}
	// The resolver really fails: two consecutive checks without an answer.
	runChecked(2)
	vs := runChecked(2)
	if v := vs[0]; v.State != model.StateDegraded || v.Cause != model.CauseISPDNSFailure || v.Attribution != model.AttrProvider ||
		!strings.Contains(strings.Join(v.Reasons, "\n"), "as in the previous service check") {
		t.Fatalf("persistent failure: %s/%s/%s %q", v.State, v.Cause, v.Attribution, v.Reasons)
	}
}

// ---------------------------------------------------------------------------- finding 4

// The computer goes to sleep for 8 hours while a cycle's probes are in flight during an AT&T
// outage: the incident must close at its last observation before the sleep, not when the cut-short
// cycle was recorded after the resume (an 8-hour "outage"), and the cut-short cycle is UNKNOWN.
func TestFindingSleepWhileProbesInFlight(t *testing.T) {
	base := time.Date(2026, 10, 5, 1, 0, 0, 0, time.UTC)
	r, clk := clockRig(t, base)
	m, ctx := r.m, context.Background()
	for i := 0; i < 12; i++ { // two minutes of AT&T outage
		cycleAt(r, clk, base, i, outageCycle())
	}
	start := base.Add(120 * time.Second) // cycle 12 starts; the computer sleeps during its probes
	resumed := start.Add(8*time.Hour + 2*time.Second)
	clk.Set(resumed)
	m.processCycle(ctx, start, resumed.Sub(start), lanDownCycle()) // every probe timed out in the sleep
	clk.Set(resumed.Add(8 * time.Second))
	m.processCycle(ctx, resumed.Add(8*time.Second), 300*time.Millisecond, healthy())
	m.finishClosings(ctx)
	closes := incidentsOfType(t, r, model.TypeIncidentClose)
	if len(closes) != 1 {
		t.Fatalf("closes %d", len(closes))
	}
	inc := closes[0]
	if inc.Closed != fmtTS(start) || inc.DurationSec != 120 || inc.Stats.DowntimeSec != 120 || inc.Attribution != model.AttrProvider {
		t.Fatalf("closed %s duration %d %+v: %s", inc.Closed, inc.DurationSec, inc.Stats, inc.Summary)
	}
	if !strings.Contains(inc.Summary, "Monitoring was interrupted for 8h0m2s") || strings.Contains(inc.Summary, "(8h") {
		t.Fatalf("summary %s", inc.Summary)
	}
	samples := ofType(r.led.records(""), model.TypeSample)
	cut := decode[model.Sample](t, samples[12])
	if cut.Verdict.State != model.StateUnknown || cut.IncidentID != "" || !strings.Contains(strings.Join(cut.Verdict.Reasons, " "), "interrupted") {
		t.Fatalf("cut-short cycle %+v", cut.Verdict)
	}
	if v := decode[model.Sample](t, samples[13]).Verdict; v.State != model.StateOnline {
		t.Fatalf("the cycle after the resume: %s/%s", v.State, v.Cause)
	}
	if n := len(ofType(r.led.records(""), model.TypeIncidentOpen)); n != 1 {
		t.Fatalf("incident_open records %d: the sleep must not start another incident", n)
	}
}

// ---------------------------------------------------------------------------- findings 6, 8

// Periodic anchoring goes on while the Internet is reachable but degraded (DEGRADED: packet
// loss, high latency, DNS failures - for days, with the gateway's optical alarm); it is deferred
// only while no internet probe answers.
func TestFindingPeriodicAnchoringWhileDegraded(t *testing.T) {
	cfg := testConfig()
	cfg.Anchoring.Interval = config.D(120 * time.Millisecond)
	r := newRig(t, cfg, nil)
	m := r.m
	m.mu.Lock()
	m.st.lastVerdict = model.Verdict{State: model.StateDegraded, Cause: model.CauseHighLatency, Attribution: model.AttrProvider}
	m.st.lastSample = &model.Sample{Probes: cyc(gwICMP(true, 1900), inet(true, true, 250000)), Verdict: m.st.lastVerdict}
	m.mu.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { m.anchorLoop(ctx); close(done) }()
	defer func() { cancel(); <-done }()
	waitFor(t, "a periodic anchor while DEGRADED", 5*time.Second, func() bool {
		for _, b := range ofType(r.led.records(""), model.TypeAnchor) {
			if decode[model.Anchor](t, b).Reason == "periodic" {
				return true
			}
		}
		return false
	})
}

// ---------------------------------------------------------------------------- finding 7

// While the ledger refuses records (a full disk), the status must not keep showing the last
// recorded verdict (ONLINE) as if monitoring went on: it shows the state as unknown and a
// critical LEDGER_WRITE_FAILING condition, until records are written again.
func TestFindingLedgerFailureIsNotShownAsOnline(t *testing.T) {
	base := time.Date(2026, 10, 5, 3, 0, 0, 0, time.UTC)
	r, clk := clockRig(t, base)
	m := r.m
	for i := 0; i < 3; i++ {
		cycleAt(r, clk, base, i, healthy())
	}
	if st := m.Status(); st.Verdict.State != model.StateOnline || findCondition(st, "LEDGER_WRITE_FAILING") != nil {
		t.Fatalf("before: %+v", st.Verdict)
	}
	setAppendErr(r.led, errors.New("write ledger-2026-10-05.jsonl: There is not enough space on the disk."))
	for i := 3; i < 9; i++ { // an AT&T outage nobody can record
		cycleAt(r, clk, base, i, outageCycle())
	}
	st := m.Status()
	if st.Verdict.State != model.StateUnknown || !strings.Contains(strings.Join(st.Verdict.Reasons, " "), "no monitoring cycle has been recorded") {
		t.Fatalf("status while nothing is recorded: %s %q", st.Verdict.State, st.Verdict.Reasons)
	}
	c := findCondition(st, "LEDGER_WRITE_FAILING")
	if c == nil || c.Severity != "critical" || !strings.Contains(c.Message, "not enough space") || c.Since == "" {
		t.Fatalf("condition %+v", c)
	}
	setAppendErr(r.led, nil)
	cycleAt(r, clk, base, 9, healthy())
	if st := m.Status(); st.Verdict.State != model.StateOnline || findCondition(st, "LEDGER_WRITE_FAILING") != nil {
		t.Fatalf("after recovery: %+v %+v", st.Verdict, st.Conditions)
	}
}

// ---------------------------------------------------------------------------- findings 9, 12

// The monitor restarts with this computer's clock 10 minutes fast (a drifted clock at boot, or a
// time-service step): the gateway's uptime grew by exactly the time that really passed (its own
// clock, from AT&T's time service, shows it). That is no gateway reboot - nor is anything when
// the gateway's clock is not readable and the uptime grew. A real reboot (the uptime fell) is.
func TestFindingClockStepAcrossRestartIsNoGatewayReboot(t *testing.T) {
	prevAt := time.Date(2026, 10, 2, 3, 41, 54, 0, time.UTC)
	const uptime = 274686
	for _, tc := range []struct {
		name         string
		gwClock      bool
		upAfter      int64
		wantReboot   bool
		fastBySecond time.Duration
	}{
		{"gateway clock readable", true, uptime + 1800, false, 10 * time.Minute},
		{"gateway clock blank (WAN down)", false, uptime + 1800, false, 10 * time.Minute},
		{"real reboot", true, 300, true, 10 * time.Minute},
		{"real reboot, gateway clock blank", false, 300, true, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			led := newFakeLedgerAt("run-current", prevAt.Add(-time.Hour))
			prev := okSnapshot(allPages, prevAt)
			prev.Derived.GatewayClockOffsetMs = i64p(0)
			led.appendAs("run-prev", prevAt.Add(-time.Minute), model.TypeMonitorStart, model.MonitorStart{})
			led.appendAs("run-prev", prevAt, model.TypeGatewaySnapshot, prev)
			trueNow := prevAt.Add(30 * time.Minute)
			pcNow := trueNow.Add(tc.fastBySecond)
			clk := &fakeClock{t: pcNow}
			led.now = clk.Now
			cfg := testConfig()
			cfg.Probes.FastInterval = config.D(10 * time.Second)
			cfg.Probes.Timeout = config.D(2 * time.Second)
			r := newRig(t, cfg, led)
			r.m.now = clk.Now
			r.m.rebuild(clk.Now())
			r.gw.snap = func(int, []string, string) (model.GatewaySnapshot, map[string][]byte, error) {
				s := okSnapshot(allPages, clk.Now())
				s.System.UptimeSec, s.Derived.UptimeSec = tc.upAfter, tc.upAfter
				s.Derived.BootTimeEstimate = fmtTS(clk.Now().Add(-time.Duration(tc.upAfter) * time.Second))
				if tc.gwClock {
					s.Derived.GatewayClockOffsetMs = i64p(-tc.fastBySecond.Milliseconds()) // the gateway shows the true time
				} else {
					s.Derived.GatewayClockBlank, s.System.GatewayTimeRaw = true, ""
				}
				return s, pageBodies(allPages, "x"), nil
			}
			if r.m.takeSnapshot(context.Background(), trigStartup, nil) == nil {
				t.Fatal("snapshot")
			}
			if got := len(rebootEvents(t, r)) == 1; got != tc.wantReboot {
				t.Fatalf("reboot recorded: %v, want %v", got, tc.wantReboot)
			}
		})
	}
}

// A step of this computer's clock while the monitor was not running is recorded (clock_jump,
// between runs) once the new run's first clock check measures it, instead of reading only as
// a longer gap in monitor_start.
func TestFindingClockStepBetweenRunsIsRecorded(t *testing.T) {
	prevAt := time.Date(2026, 10, 2, 3, 41, 54, 0, time.UTC)
	led := newFakeLedgerAt("run-current", prevAt.Add(-time.Hour))
	led.appendAs("run-prev", prevAt.Add(-time.Minute), model.TypeMonitorStart, model.MonitorStart{})
	prevCheck := led.appendAs("run-prev", prevAt, model.TypeClockCheck, model.ClockCheck{Results: []model.ClockResult{
		{Server: "time.windows.com", OK: true, OffsetMs: -12}, {Server: "time.google.com", OK: true, OffsetMs: -10}, {Server: "pool.ntp.org", OK: true, OffsetMs: -14},
	}})
	pcNow := prevAt.Add(time.Second + 4*time.Minute) // restarted a second later, clock now 4 min fast
	clk := &fakeClock{t: pcNow}
	led.now = clk.Now
	r := newRig(t, nil, led)
	r.m.now = clk.Now
	r.pr.sntp = func(server string) model.ClockResult {
		return model.ClockResult{Server: server, OK: true, OffsetMs: -240012}
	}
	r.m.rebuild(clk.Now())
	r.m.mu.Lock()
	r.m.st.started = pcNow
	r.m.mu.Unlock()
	r.m.clockCheck(context.Background())
	jumps := ofType(led.records("run-current"), model.TypeClockJump)
	if len(jumps) != 1 {
		t.Fatalf("clock_jump records %d", len(jumps))
	}
	type runJump struct {
		model.ClockJump
		BetweenRuns  bool   `json:"between_runs"`
		PrevCheckSeq uint64 `json:"prev_clock_check_seq"`
		Detail       string `json:"detail"`
	}
	j := decode[runJump](t, jumps[0])
	if !j.BetweenRuns || j.PrevCheckSeq != prevCheck.Seq || j.JumpMs != 240000 || !strings.Contains(j.Detail, "+4m0s") {
		t.Fatalf("clock jump %+v", j)
	}
	// A second check of the same run compares nothing across runs.
	r.m.clockCheck(context.Background())
	if n := len(ofType(led.records("run-current"), model.TypeClockJump)); n != 1 {
		t.Fatalf("clock_jump records %d", n)
	}
}

// ---------------------------------------------------------------------------- finding 10

// The owner restarts the gateway from its web page: its WAN stops one cycle before its LAN
// goes down. That single ISP_OUTAGE cycle before the restart window is the restart's own
// shutdown - fewer provider-attributed cycles than open an incident - and must not make the
// owner's restart an AT&T outage. (It still counts as 10 s without Internet.)
func TestFindingSoftRebootShutdownCycleIsNotAnOutage(t *testing.T) {
	f := newFeeder(t, 3, 3)
	f.feed(vGood, vGood)           // 0-1
	f.feed(vWAN)                   // 2: the WAN stops first
	f.feed(vGwUnr, vGwUnr, vGwUnr) // 3-5: the gateway restarts
	st := f.acts[0].st
	f.feed(vFiber, vFiber, vFiber) // 6-8: the PON ranges
	f.feed(vGood, vGood, vGood)    // 9-11: closes at start(9)
	if !st.attachRestart(restartAt(startOf(4).Add(5*time.Second), "6.34.7", "6.34.7")) {
		t.Fatal("attach")
	}
	p := st.payload(t0, false)
	if p.State != model.StateLocalFault || p.Cause != model.CauseGatewayReboot || p.Attribution != model.AttrUndetermined ||
		p.Stats.DowntimeSec != 10 || p.Stats.RestartSec != 60 {
		t.Fatalf("%s/%s/%s %+v: %s", p.State, p.Cause, p.Attribution, p.Stats, p.Summary)
	}
}

// ---------------------------------------------------------------------------- finding 11

// High latency while the gateway answers quickly is what the household's own traffic filling
// the connection looks like. The gateway's own WAN counters show the traffic: heavy traffic
// leaves the degradation undetermined; light traffic keeps the provider attribution, and the
// verdict states the measured rates either way.
func TestFindingHouseholdTrafficIsNotProviderDegradation(t *testing.T) {
	for _, tc := range []struct {
		name     string
		rxBytes  int64 // received between the two snapshots, 60 s apart
		rxPkts   int64
		wantAttr string
		reason   string
	}{
		{"a large download fills the connection", 3_750_000_000, 2_500_000, model.AttrUndetermined, "receiving 500.0 Mb/s"},
		{"light traffic", 22_500_000, 30_000, model.AttrProvider, "receiving 3.0 Mb/s"},
	} {
		t.Run(tc.name, func(t *testing.T) {
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
					"IPv4 Statistics/Receive Bytes": 100_000_000 + n*tc.rxBytes, "IPv4 Statistics/Receive Packets": 1_000_000 + n*tc.rxPkts,
					"IPv4 Statistics/Transmit Bytes": 50_000_000 + n*3_000_000, "IPv4 Statistics/Transmit Packets": 900_000 + n*20_000,
				}
				return s, pageBodies(allPages, fmt.Sprint(n)), nil
			}
			clk.Set(base.Add(-60 * time.Second))
			m.takeSnapshot(ctx, trigStartup, nil)
			clk.Set(base)
			m.takeSnapshot(ctx, trigPeriodic, nil)
			slow := cyc(gwICMP(true, 2000), gwTCP(true, 2300), inet(true, true, 250000))
			for i := 0; i < 3; i++ {
				cycleAt(r, clk, base, i, slow)
			}
			v := decode[model.Sample](t, lastOfType(t, r, model.TypeSample)).Verdict
			if v.State != model.StateDegraded || v.Cause != model.CauseHighLatency || v.Attribution != tc.wantAttr ||
				!strings.Contains(strings.Join(v.Reasons, "\n"), tc.reason) {
				t.Fatalf("%s/%s/%s %q", v.State, v.Cause, v.Attribution, v.Reasons)
			}
		})
	}
}

// ---------------------------------------------------------------------------- finding 13

// A gateway that stays unreachable (unplugged, another network) must not log a warning per
// poll - every Warn reaches the Windows event log in service mode: the failure is reported when
// it starts, at most hourly while it lasts, and when it ends. Likewise ledger write failures.
func TestFindingRepeatedFailuresDoNotFloodTheLog(t *testing.T) {
	base := time.Date(2026, 10, 5, 3, 0, 0, 0, time.UTC)
	r, clk := clockRig(t, base)
	h := &captureHandler{}
	r.m.log = slog.New(h)
	var down atomic.Bool
	down.Store(true)
	r.gw.snap = func(int, []string, string) (model.GatewaySnapshot, map[string][]byte, error) {
		if down.Load() {
			return model.GatewaySnapshot{}, nil, errors.New("dial tcp 192.168.1.254:443: connectex: A connection attempt failed")
		}
		return okSnapshot(allPages, clk.Now()), pageBodies(allPages, "x"), nil
	}
	ctx := context.Background()
	for i := 0; i < 200; i++ { // 50 minutes of polls every 15 s
		clk.Set(base.Add(time.Duration(i) * 15 * time.Second))
		r.m.takeSnapshot(ctx, trigIncident, nil)
	}
	if n := h.count(slog.LevelWarn, "gateway snapshot failed"); n != 1 {
		t.Fatalf("%d warnings for 200 failed polls", n)
	}
	down.Store(false)
	clk.Set(base.Add(time.Hour))
	r.m.takeSnapshot(ctx, trigPeriodic, nil)
	if h.count(slog.LevelInfo, "gateway snapshots succeed again") != 1 {
		t.Fatal("the recovery is logged once")
	}
	setAppendErr(r.led, errors.New("disk full"))
	for i := 0; i < 100; i++ {
		clk.Set(base.Add(time.Hour + time.Duration(i)*time.Second))
		r.m.Note(ctx, "x", "", "test")
	}
	if n := h.count(slog.LevelError, "ledger append failed"); n != 1 {
		t.Fatalf("%d errors for 100 failed appends", n)
	}
}

// The same holds for a time-stamp authority whose certificate never chains on this computer
// (every anchoring round) and for the blob store on a full disk (every raw page, every 15 s
// during an incident): reported when it starts, then periodically - not per round or page.
func TestFindingAnchorAndBlobProblemsDoNotFloodTheLog(t *testing.T) {
	ctx := context.Background()
	r := newRig(t, nil, nil)
	h := &captureHandler{}
	r.m.log = slog.New(h)
	r.m.anchorer = chainlessAnchorer{r.anc, func(u string) bool { return u == "http://tsa.test/b" }}
	for i := 0; i < 20; i++ {
		if _, err := r.m.AnchorNow(ctx, "manual"); err != nil {
			t.Fatal(err)
		}
	}
	warnings := h.count(slog.LevelWarn, "time-stamp authority not chain-verified; recorded, but it does not count as proof of time") +
		h.count(slog.LevelWarn, "time-stamp authority problems in this anchoring round")
	if warnings != 1 {
		t.Fatalf("%d warnings for 20 rounds with one untrusted authority", warnings)
	}
	setPutErr(r.led, errors.New("disk full"))
	for i := 0; i < 30; i++ {
		r.m.putBlob([]byte{byte(i)})
	}
	if n := h.count(slog.LevelError, "blob store failed"); n != 1 {
		t.Fatalf("%d errors for 30 failed blob writes", n)
	}
}

// ---------------------------------------------------------------------------- finding 14

// The gateway's own optical alarm has been raised since the monitor first saw it: after a
// restart of the monitor the dashboard must still say since when (the optical_alarm event that
// first reported it), not since the last reading before the restart.
func TestFindingAlarmSinceSurvivesRestart(t *testing.T) {
	base := time.Date(2026, 10, 5, 3, 0, 0, 0, time.UTC)
	r1, clk := clockRig(t, base)
	ctx := context.Background()
	r1.gw.snap = func(int, []string, string) (model.GatewaySnapshot, map[string][]byte, error) {
		s := okSnapshot(allPages, clk.Now())
		s.Derived.BootTimeEstimate = fmtTS(base.Add(-274686 * time.Second))
		s.System.UptimeSec = 274686 + int64(clk.Now().Sub(base)/time.Second)
		return s, pageBodies(allPages, "x"), nil
	}
	r1.m.takeSnapshot(ctx, trigStartup, nil) // first observation: the alarm is already raised
	var raised model.Body
	for _, b := range ofType(r1.led.records(""), model.TypeGatewayEvent) {
		if decode[model.GatewayEvent](t, b).Kind == model.GwEvOpticalAlarm {
			raised = b
		}
	}
	if raised.Seq == 0 {
		t.Fatal("no optical_alarm event")
	}
	for i := 1; i <= 5; i++ {
		clk.Set(base.Add(time.Duration(i) * time.Hour))
		r1.m.takeSnapshot(ctx, trigPeriodic, nil)
	}
	// The monitor restarts.
	clk.Set(base.Add(6 * time.Hour))
	m2, err := New(Options{Config: r1.cfg, Ledger: r1.led, Gateway: &fakeGateway{}, Prober: newFakeProber(), Now: clk.Now})
	if err != nil {
		t.Fatal(err)
	}
	m2.rebuild(clk.Now())
	c := findCondition(m2.Status(), "OPTICAL_RX_LOW_ALARM")
	if c == nil || c.Since != raised.TS || c.Seq != raised.Seq {
		t.Fatalf("condition %+v, want since %s (record #%d)", c, raised.TS, raised.Seq)
	}
}
