package monitor

// Adversarial tests from the independent review of internal/monitor. Each test pins a defect
// that was found in the first implementation (it failed before the fix) or a property the
// evidence depends on.

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"attmonitor/internal/config"
	"attmonitor/internal/contracts"
	"attmonitor/internal/model"
)

// The dashboard prints "covers #<last_anchor_seq>": the field must name the record the
// time-stamp covers (the anchored head), never the anchor record itself, which no
// time-stamp covers yet.
func TestReviewLastAnchorSeqIsTheCoveredRecord(t *testing.T) {
	ctx := context.Background()
	r := newRig(t, nil, nil)
	for i := 0; i < 3; i++ {
		if _, err := r.m.Note(ctx, "n", "", "web"); err != nil {
			t.Fatal(err)
		}
	}
	covered := r.led.Head()
	anchors, err := r.m.AnchorNow(ctx, "manual")
	if err != nil || len(anchors) != 2 {
		t.Fatalf("anchors %v err %v", anchors, err)
	}
	st := r.m.Status()
	if st.Ledger.LastAnchorSeq != covered.Seq {
		t.Fatalf("last_anchor_seq %d, want the covered head %d (head is %d)", st.Ledger.LastAnchorSeq, covered.Seq, st.Ledger.HeadSeq)
	}
	if st.Ledger.UnanchoredCount != st.Ledger.HeadSeq-covered.Seq {
		t.Fatalf("unanchored %d, want head %d - covered %d", st.Ledger.UnanchoredCount, st.Ledger.HeadSeq, covered.Seq)
	}
}

// A periodic traceroute must never be recorded (and attributed to an incident) after that
// incident has closed: the loop used to keep the incident id it saw when it went to sleep.
func TestReviewNoPeriodicTracerouteAfterClose(t *testing.T) {
	cfg := testConfig()
	cfg.Probes.TracerouteInterval = config.D(300 * time.Millisecond)
	r := newRig(t, cfg, nil)
	m := r.m
	ctx := context.Background()
	start := time.Now()
	bad := cyc(gwICMP(true, 1900), gwTCP(true, 2300), inet(false, false, 0))
	for i := 0; i < 3; i++ {
		m.processCycle(ctx, start.Add(time.Duration(i)*40*time.Millisecond), time.Millisecond, bad)
	}
	if !m.incidentOpen() {
		t.Fatal("incident should be open")
	}
	lctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { m.tracerouteLoop(lctx); close(done) }()
	defer func() { cancel(); <-done }()
	waitFor(t, "incident_open traceroutes", 5*time.Second, func() bool {
		return len(ofType(r.led.records(""), model.TypeTraceroute)) == 2
	})
	// Recover right away (the loss window keeps four cycles PACKET_LOSS) and close.
	for i := 3; i < 13; i++ {
		m.processCycle(ctx, start.Add(time.Duration(i)*40*time.Millisecond), time.Millisecond, healthy())
	}
	if m.incidentOpen() {
		t.Fatal("incident should be closed")
	}
	m.finishClosings(ctx)
	time.Sleep(800 * time.Millisecond) // well past the 300 ms traceroute interval
	for _, b := range ofType(r.led.records(""), model.TypeTraceroute) {
		if tr := decode[model.Traceroute](t, b); tr.Trigger == "incident_periodic" {
			t.Fatalf("periodic traceroute seq %d recorded for incident %s after it closed", b.Seq, tr.Incident)
		}
	}
}

// A wall-clock step is not a monitoring interruption: the incident must not claim that
// monitoring was interrupted (e.g. by system sleep) when only the clock moved.
func TestReviewClockStepIsNotCalledSleep(t *testing.T) {
	r := newRig(t, nil, nil)
	m := r.m
	ctx := context.Background()
	start := time.Now()
	bad := cyc(gwICMP(true, 1900), inet(false, false, 0))
	for i := 0; i < 3; i++ {
		m.processCycle(ctx, start.Add(time.Duration(i)*40*time.Millisecond), time.Millisecond, bad)
	}
	m.continuity(70*time.Second, 40*time.Millisecond) // clock stepped +70 s, 40 ms really elapsed
	if m.incidentOpen() {
		t.Fatal("an incident must not span a clock discontinuity")
	}
	m.finishClosings(ctx)
	inc := decode[model.Incident](t, ofType(r.led.records(""), model.TypeIncidentClose)[0])
	if strings.Contains(inc.Summary, "system sleep") || strings.Contains(inc.Summary, "Monitoring was interrupted") {
		t.Fatalf("a clock step is described as an interruption: %q", inc.Summary)
	}
	if !strings.Contains(inc.Summary, "clock") {
		t.Fatalf("the summary must explain the clock discontinuity: %q", inc.Summary)
	}
	// A real interruption (the monotonic clock advanced too) keeps the interruption wording.
	r2 := newRig(t, nil, nil)
	for i := 0; i < 3; i++ {
		r2.m.processCycle(ctx, start.Add(time.Duration(i)*40*time.Millisecond), time.Millisecond, bad)
	}
	r2.m.continuity(2*time.Hour, 2*time.Hour)
	r2.m.finishClosings(ctx)
	inc2 := decode[model.Incident](t, ofType(r2.led.records(""), model.TypeIncidentClose)[0])
	if !strings.Contains(inc2.Summary, "Monitoring was interrupted for 2h0m0s") {
		t.Fatalf("summary %q", inc2.Summary)
	}
}

// A large backward clock step during an incident must not produce an incident that closes
// before it opened.
func TestReviewBackwardClockStep(t *testing.T) {
	// Tracker level: a close time before the open time is clamped, never negative.
	f := newFeeder(t, 3, 3)
	st := f.feed(vWAN, vWAN, vWAN)[0].st
	back := t0.Add(-time.Hour)
	for i := 0; i < 3; i++ {
		f.tr.observe(cycleObs{Start: back.Add(time.Duration(i) * 10 * time.Second), Seq: uint64(200 + i), Verdict: vGood})
	}
	p := st.payload(t0, false)
	if p.Open || p.DurationSec < 0 || mustTS(t, p.Closed).Before(mustTS(t, p.Opened)) {
		t.Fatalf("closed %s before opened %s (duration %d)", p.Closed, p.Opened, p.DurationSec)
	}

	// Monitor level: the backward step is a discontinuity that closes the open incident.
	r := newRig(t, nil, nil)
	m := r.m
	ctx := context.Background()
	start := time.Now()
	bad := cyc(gwICMP(true, 1900), inet(false, false, 0))
	for i := 0; i < 3; i++ {
		m.processCycle(ctx, start.Add(time.Duration(i)*40*time.Millisecond), time.Millisecond, bad)
	}
	m.continuity(-time.Hour, 40*time.Millisecond)
	if m.incidentOpen() {
		t.Fatal("a one-hour backward clock step must close the incident at its last observation")
	}
	if n := len(ofType(r.led.records(""), model.TypeClockJump)); n != 1 {
		t.Fatalf("clock_jump records %d", n)
	}
}

// A gateway restart inside an incident is a fact the record must state, whatever the
// classification (rules 2026.10-4): here the three provider-attributed cycles before the
// restart lie outside its window - as many as open an incident - so the provider classification
// stands, and only the cycle in the window becomes restart time. With two, they are stray
// cycles of the restart (its shutdown) by the same measure: the incident is the restart's, and
// the two cycles stay downtime.
func TestReviewRestartFactOnProviderIncident(t *testing.T) {
	f := newFeeder(t, 3, 3)
	st := f.feed(vWAN, vWAN, vWAN, vWAN)[0].st
	f.feed(vGood, vGood, vGood) // closes at start(4) = t0+40s
	if !st.attachRestart(restartAt(t0.Add(30*time.Second), "6.34.7", "6.34.7")) {
		t.Fatal("the restart lies inside the incident")
	}
	p := st.payload(t0, false)
	if p.State != model.StateISPOutage || p.Cause != model.CauseWANDown || p.Attribution != model.AttrProvider {
		t.Fatalf("classification must not change: %s/%s/%s", p.State, p.Cause, p.Attribution)
	}
	if p.Stats.DowntimeSec != 30 || p.Stats.RestartSec != 10 {
		t.Fatalf("stats %+v", p.Stats)
	}
	if !strings.Contains(strings.Join(p.Reasons, "\n"), "the AT&T gateway restarted at about 2026-10-05 03:20:30 UTC (uptime reset") {
		t.Fatalf("reasons lack the restart: %q", p.Reasons)
	}
	if !strings.Contains(p.Summary, "restarted") || !slices.Contains(p.Causes, model.CauseGatewayReboot) {
		t.Fatalf("summary lacks the restart: %q", p.Summary)
	}
	f3 := newFeeder(t, 3, 3)
	st3 := f3.feed(vWAN, vWAN, vWAN)[0].st
	f3.feed(vGood, vGood, vGood) // closes at start(3) = t0+30s
	if !st3.attachRestart(restartAt(t0.Add(20*time.Second), "6.34.7", "6.34.7")) {
		t.Fatal("the restart lies inside the incident")
	}
	if p := st3.payload(t0, false); p.Cause != model.CauseGatewayReboot || p.Attribution != model.AttrUndetermined ||
		p.Stats.DowntimeSec != 20 || p.Stats.RestartSec != 10 {
		t.Fatalf("two stray cycles: %s/%s/%s %+v", p.State, p.Cause, p.Attribution, p.Stats)
	}
	// A restart long before the incident: nothing is added.
	f2 := newFeeder(t, 3, 3)
	st2 := f2.feed(vWAN, vWAN, vWAN)[0].st
	f2.feed(vGood, vGood, vGood)
	if st2.attachRestart(restartAt(t0.Add(-2*time.Hour), "6.34.7", "6.34.7")) {
		t.Fatal("a restart long before the incident was attached")
	}
	if p := st2.payload(t0, false); strings.Contains(strings.Join(p.Reasons, "\n"), "restarted") || len(p.GatewayRestarts) != 0 {
		t.Fatalf("reasons %q", p.Reasons)
	}
}

// A cycle whose sample could not be recorded must not influence later verdicts: everything
// a verdict depends on has to be in the ledger, or the classification is not reproducible.
func TestReviewUnrecordedCycleDoesNotEnterTheWindow(t *testing.T) {
	r := newRig(t, nil, nil)
	m := r.m
	ctx := context.Background()
	start := time.Now()
	m.processCycle(ctx, start, time.Millisecond, healthy())
	setAppendErr(r.led, errors.New("disk full"))
	// Not a total outage (those are excluded from the window loss anyway): 1.1.1.1 and
	// 8.8.8.8 fail, 9.9.9.9 answers. Counted, it would make the next cycle PACKET_LOSS.
	partial := cyc(gwICMP(true, 1900), gwTCP(true, 2300), inet(false, false, 0))
	partial[4].OK, partial[4].RTTus, partial[4].Status = true, 9000, "IP_SUCCESS" // inet_icmp_quad9
	m.processCycle(ctx, start.Add(40*time.Millisecond), time.Millisecond, partial)
	setAppendErr(r.led, nil)
	m.processCycle(ctx, start.Add(80*time.Millisecond), time.Millisecond, healthy())
	samples := ofType(r.led.records(""), model.TypeSample)
	if len(samples) != 2 {
		t.Fatalf("samples %d", len(samples))
	}
	if v := decode[model.Sample](t, samples[1]).Verdict; v.State != model.StateOnline {
		t.Fatalf("verdict %s/%s depends on an unrecorded cycle: %q", v.State, v.Cause, v.Reasons)
	}
}

// Authenticated gateway requests must stay rare across restarts too (a service restart loop
// must not log in to the gateway at every start).
func TestReviewNotificationStartupRespectsFloor(t *testing.T) {
	led := newFakeLedger("run-current")
	led.appendAs("run-prev", time.Now().Add(-time.Minute), model.TypeMonitorStart, model.MonitorStart{})
	led.appendAs("run-prev", time.Now().Add(-30*time.Second), model.TypeGatewayEvent,
		model.GatewayEvent{Kind: model.GwEvNotificationSetting, After: "off"})
	r := newRig(t, nil, led)
	r.cfg.Gateway.AccessCodeProtected = "protected-blob"
	r.m.notifMinInterval = time.Hour
	r.m.rebuild(time.Now())
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	r.m.notificationLoop(ctx)
	r.gw.mu.Lock()
	calls := r.gw.notifCalls
	r.gw.mu.Unlock()
	if calls != 0 {
		t.Fatalf("checked %d time(s) only 30 s after the previous check (floor 1 h)", calls)
	}

	// A check long ago: the startup check runs at once, and its time is cached so that the
	// next start (e.g. after a crash) honours the floor.
	led2 := newFakeLedger("run-current")
	led2.appendAs("run-prev", time.Now().Add(-3*time.Hour), model.TypeGatewayEvent,
		model.GatewayEvent{Kind: model.GwEvNotificationSetting, After: "off"})
	r2 := newRig(t, nil, led2)
	r2.cfg.Gateway.AccessCodeProtected = "protected-blob"
	r2.m.notifMinInterval = time.Hour
	r2.m.rebuild(time.Now())
	ctx2, cancel2 := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel2()
	r2.m.notificationLoop(ctx2)
	r2.gw.mu.Lock()
	calls = r2.gw.notifCalls
	r2.gw.mu.Unlock()
	if calls != 1 {
		t.Fatalf("startup check after the floor: %d calls", calls)
	}
	c, ok := r2.m.loadCache()
	if !ok || c.Notification == nil || c.Notification.CheckedAt == "" {
		t.Fatalf("the check time must be cached right away: %+v %v", c, ok)
	}
	if at := mustTS(t, c.Notification.CheckedAt); time.Since(at) > time.Minute {
		t.Fatalf("cached check time %s is not the new check", c.Notification.CheckedAt)
	}
}

// An operator who turns the outage redirect ON must not have it switched back off by an
// enforcement check that runs at the same moment.
func TestReviewOperatorEnableNotUndoneByConcurrentEnforcement(t *testing.T) {
	ctx := context.Background()
	r := newRig(t, nil, nil)
	r.cfg.Gateway.AccessCodeProtected = "protected-blob"
	r.cfg.Gateway.EnforceNotificationOff = true
	paused := make(chan struct{})
	var first atomic.Bool
	r.led.setOnPut(func([]byte) {
		if first.CompareAndSwap(false, true) {
			close(paused)
			time.Sleep(300 * time.Millisecond) // the operator's change is between gateway call and record
		}
	})
	done := make(chan error, 1)
	go func() {
		_, err := r.m.SetGatewayNotification(ctx, true, "operator via web")
		done <- err
	}()
	<-paused
	if err := r.m.checkNotification(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	r.gw.mu.Lock()
	on, sets := r.gw.notif, append([]bool(nil), r.gw.setCalls...)
	r.gw.mu.Unlock()
	if !on {
		t.Fatalf("the monitor switched the setting back off right after the operator enabled it (set calls %v)", sets)
	}
	if r.cfg.Gateway.EnforceNotificationOff {
		t.Fatal("enforcement must be cleared")
	}
}

// A kick that arrives while the worker is busy must wake it exactly once.
func TestReviewSleepUntilConsumesPendingKick(t *testing.T) {
	k := newKicker()
	k.kick("cycle_failure")
	if !sleepUntil(context.Background(), time.Now().Add(-time.Second), k.ch) {
		t.Fatal("past deadline")
	}
	begin := time.Now()
	if !sleepUntil(context.Background(), time.Now().Add(80*time.Millisecond), k.ch) {
		t.Fatal("sleep")
	}
	if d := time.Since(begin); d < 60*time.Millisecond {
		t.Fatalf("a kick already served woke the worker again after %v", d)
	}
}

// The gateway's own optical alarm flags must stay on the dashboard when a later snapshot
// could not read fiberstat (the flags are unknown then, not cleared).
func TestReviewConditionsSurviveSnapshotWithoutFiber(t *testing.T) {
	r := newRig(t, nil, nil)
	at := time.Now()
	s1 := okSnapshot([]string{"broadbandstatistics", "fiberstat", "sysinfo"}, at)
	s2 := okSnapshot([]string{"broadbandstatistics", "sysinfo"}, at.Add(time.Minute))
	s2.Fiber = nil
	s2.Derived.Alarms, s2.Derived.RxPowerX10, s2.Derived.TxPowerX10 = nil, nil, nil
	s2.Derived.RxLowAlarmX10, s2.Derived.RxLowWarnX10, s2.Derived.OpticalUp = nil, nil, nil
	r.m.mu.Lock()
	r.m.applySnapshotLocked(&snapObs{Seq: 7, At: at, Snap: &s1}, nil, nil)
	r.m.applySnapshotLocked(&snapObs{Seq: 8, At: at.Add(time.Minute), Snap: &s2}, nil, nil)
	r.m.mu.Unlock()
	st := r.m.Status()
	st.Conditions = withoutCond(st.Conditions, condNoAccessCode)
	if len(st.Conditions) != 2 || st.Conditions[0].Code != "OPTICAL_RX_LOW_ALARM" || st.Conditions[0].Seq != 7 ||
		!strings.Contains(st.Conditions[0].Message, "-31.5 dBm") || st.Conditions[0].Since != fmtTS(at) {
		t.Fatalf("conditions %+v", st.Conditions)
	}
	if st.GatewayAt != fmtTS(at.Add(time.Minute)) {
		t.Fatal("the latest snapshot is still the status snapshot")
	}
	s, err := r.m.Series("1h")
	if err != nil || s.RxLowAlarmX10 == nil || *s.RxLowAlarmX10 != -295 {
		t.Fatalf("series thresholds %+v %v", s.RxLowAlarmX10, err)
	}
	// A fiberstat page that shows no flags clears them.
	s3 := okSnapshot([]string{"fiberstat"}, at.Add(2*time.Minute))
	s3.Derived.Alarms = nil
	r.m.mu.Lock()
	r.m.applySnapshotLocked(&snapObs{Seq: 9, At: at.Add(2 * time.Minute), Snap: &s3}, nil, nil)
	r.m.mu.Unlock()
	if st := r.m.Status(); len(withoutCond(st.Conditions, condNoAccessCode)) != 0 {
		t.Fatalf("cleared flags still shown: %+v", st.Conditions)
	}
}

// Free text reaching the ledger through the actions is bounded.
func TestReviewActionInputsAreBounded(t *testing.T) {
	ctx := context.Background()
	r := newRig(t, nil, nil)
	long := strings.Repeat("a", 10_000)
	if _, err := r.m.Note(ctx, "ticket 1", long, "web"); err == nil {
		t.Fatal("an author of 10 kB must be refused")
	}
	if _, err := r.m.Note(ctx, "ticket 1", "owner", long); err == nil {
		t.Fatal("a source of 10 kB must be refused")
	}
	if _, err := r.m.AnchorNow(ctx, long); err == nil {
		t.Fatal("an anchor reason of 10 kB must be refused")
	}
	if _, err := r.m.SetGatewayNotification(ctx, false, long); err == nil {
		t.Fatal("an actor of 10 kB must be refused")
	}
	r.gw.mu.Lock()
	sets := len(r.gw.setCalls)
	r.gw.mu.Unlock()
	if sets != 0 {
		t.Fatal("a refused request must not reach the gateway")
	}
	// Custody fields are recorded exactly as sent or not at all: the exporter keeps its own
	// copy next to the bundle, and a silently shortened record would contradict it.
	n := len(r.led.records(""))
	if _, err := r.m.RecordExport(ctx, model.CustodyExport{FileName: "att-evidence_x.zip", Notes: strings.Repeat("n", 100_000), Requester: "web"}); err == nil {
		t.Fatal("100 kB of notes must be refused")
	}
	if _, err := r.m.RecordExport(ctx, model.CustodyExport{FileName: "att-evidence_x.zip", PreparedBy: "a\xffb", Requester: "web"}); err == nil {
		t.Fatal("invalid UTF-8 must be refused")
	}
	if got := len(r.led.records("")); got != n {
		t.Fatalf("refused exports appended %d records", got-n)
	}
	// A 200-character name in a multi-byte script (up to 800 bytes, what the web layer
	// accepts) is not refused.
	name := strings.Repeat("蕭", 200)
	ref, err := r.m.RecordExport(ctx, model.CustodyExport{FileName: "att-evidence_x.zip", Notes: "ticket 1", PreparedBy: name, Requester: "web 127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	_, body, _ := r.led.Record(ref.Seq)
	if ce := decode[model.CustodyExport](t, body); ce.PreparedBy != name || ce.Notes != "ticket 1" {
		t.Fatalf("custody export not recorded exactly: %+v", ce)
	}
	if _, err := r.m.Note(ctx, "ticket 1", name, "web"); err != nil {
		t.Fatalf("a 200-character author must be accepted: %v", err)
	}
}

// Raw pages are kept when the gateway web interface answers again after being unreachable.
func TestReviewRawPagesStoredWhenGatewayReturns(t *testing.T) {
	r := newRig(t, nil, nil)
	m := r.m
	ctx := context.Background()
	var mode atomic.Int32 // 0 ok, 1 unreachable
	r.gw.snap = func(call int, pages []string, trigger string) (model.GatewaySnapshot, map[string][]byte, error) {
		if mode.Load() == 1 {
			return model.GatewaySnapshot{}, nil, errors.New("dial tcp 192.168.1.254:443: connect: no route to host")
		}
		s := okSnapshot(pages, time.Now())
		s.Derived.BootTimeEstimate = fmtTS(t0)
		return s, pageBodies(pages, "same"), nil
	}
	m.takeSnapshot(ctx, trigStartup, nil)
	mode.Store(1)
	m.takeSnapshot(ctx, trigPeriodic, nil)
	mode.Store(0)
	m.takeSnapshot(ctx, trigPeriodic, nil)
	recs := ofType(r.led.records(""), model.TypeGatewaySnapshot)
	last := decode[model.GatewaySnapshot](t, recs[len(recs)-1])
	stored := 0
	for _, p := range last.Pages {
		if p.Stored {
			stored++
		}
	}
	if stored != len(last.Pages) || len(recs[len(recs)-1].Blobs) != stored {
		t.Fatalf("first snapshot after the gateway came back stored %d of %d pages", stored, len(last.Pages))
	}
}

// Closed incidents that wait for a snapshot with a readable uptime (restart rules) are bounded.
func TestReviewRebootWatchIsBounded(t *testing.T) {
	r := newRig(t, nil, nil)
	m := r.m
	ctx := context.Background()
	for i := 0; i < 3*maxRebootWatch; i++ {
		st := closedLocal(model.CauseGatewayUnreachable)
		st.inc.ID = "INC-" + strings.Repeat("x", 3) + string(rune('a'+i%26)) + string(rune('a'+i/26))
		m.finishClose(ctx, st, false)
	}
	m.mu.Lock()
	n := len(m.st.rebootWatch)
	m.mu.Unlock()
	if n > maxRebootWatch {
		t.Fatalf("reboot watch holds %d incidents", n)
	}
}

// After a monitoring gap nothing is known about the state in between: the first cycle after
// the gap starts a new state history (state_change from UNKNOWN), and "since" restarts.
func TestReviewStateHistoryRestartsAfterGap(t *testing.T) {
	r := newRig(t, nil, nil)
	m := r.m
	ctx := context.Background()
	start := time.Date(2026, 10, 5, 3, 0, 0, 0, time.UTC)
	for i := 0; i < 3; i++ {
		m.processCycle(ctx, start.Add(time.Duration(i)*40*time.Millisecond), time.Millisecond, healthy())
	}
	resumed := start.Add(8 * time.Hour)
	m.processCycle(ctx, resumed, time.Millisecond, healthy())
	changes := ofType(r.led.records(""), model.TypeStateChange)
	if len(changes) != 2 {
		t.Fatalf("state changes %d, want UNKNOWN→ONLINE at start and again after the gap", len(changes))
	}
	sc := decode[model.StateChange](t, changes[1])
	if sc.FromState != model.StateUnknown || sc.ToState != model.StateOnline || sc.At != fmtTS(resumed) {
		t.Fatalf("state change after the gap %+v", sc)
	}
	if st := m.Status(); st.Since != fmtTS(resumed) {
		t.Fatalf("since %s: the state is only known since the monitor resumed at %s", st.Since, fmtTS(resumed))
	}
}

// The AT&T next hop and resolver survive a restart during an outage: the rebuild keeps the
// last ones the gateway reported, as the live monitor does, even when the latest reachable
// snapshot shows the WAN down without them.
func TestReviewRebuildKeepsLastKnownNextHop(t *testing.T) {
	for _, cached := range []bool{false, true} {
		led := newFakeLedger("run-current")
		base := time.Now().Add(-10 * time.Minute)
		led.appendAs("run-prev", base, model.TypeMonitorStart, model.MonitorStart{})
		led.appendAs("run-prev", base.Add(time.Second), model.TypeGatewaySnapshot, okSnapshot([]string{"broadbandstatistics"}, base))
		var stateDir string
		if cached {
			// A cache written before the outage; the WAN-down snapshot comes after it.
			r0 := newRig(t, nil, led)
			r0.m.rebuild(time.Now())
			r0.m.writeCache()
			stateDir = r0.m.opts.StateDir
		}
		down := downSnapshot([]string{"broadbandstatistics"}, base.Add(time.Minute))
		down.Broadband.GatewayIPv4, down.Broadband.PrimaryDNS = "0.0.0.0", "0.0.0.0"
		down.Derived.ISPNextHop, down.Derived.ISPDNS = "", ""
		led.appendAs("run-prev", base.Add(time.Minute), model.TypeGatewaySnapshot, down)
		r := newRig(t, nil, led)
		if cached {
			r.m.opts.StateDir = stateDir
		}
		r.m.rebuild(time.Now())
		r.m.mu.Lock()
		hop, dns, good := r.m.st.ispHop, r.m.st.ispDNS, r.m.st.lastGood
		r.m.mu.Unlock()
		if hop != "203.0.113.1" || dns != "68.94.156.9" {
			t.Fatalf("cached=%v: hop %q dns %q after a restart during the outage", cached, hop, dns)
		}
		if good == nil || good.Snap.Derived.BroadbandUp == nil || *good.Snap.Derived.BroadbandUp {
			t.Fatalf("cached=%v: the latest reachable snapshot (WAN down) stays the status snapshot", cached)
		}
	}
}

// While the WAN is down the gateway shows 0.0.0.0 for its DNS servers. That is not the ISP
// resolver: querying it fails, and once the internet is back the DNS rule would blame AT&T's
// resolver (DEGRADED/ISP_DNS_FAILURE, provider) for a query that never reached it.
func TestReviewUnspecifiedResolverIsNotTheISPResolver(t *testing.T) {
	r := newRig(t, nil, nil)
	m := r.m
	ctx := context.Background()
	at := time.Now()
	up := okSnapshot([]string{"broadbandstatistics"}, at)
	down := downSnapshot([]string{"broadbandstatistics"}, at.Add(time.Minute))
	down.Broadband.PrimaryDNS, down.Broadband.GatewayIPv4 = "0.0.0.0", "0.0.0.0"
	down.Derived.ISPDNS, down.Derived.ISPNextHop = "", "" // gateway.Derive rejects unspecified addresses
	m.mu.Lock()
	m.applySnapshotLocked(&snapObs{Seq: 1, At: at, Snap: &up}, nil, nil)
	m.applySnapshotLocked(&snapObs{Seq: 2, At: at.Add(time.Minute), Snap: &down}, nil, nil)
	m.mu.Unlock()
	var queried []string
	r.pr.dns = func(server, name string) model.DNSResult {
		r.pr.mu.Lock()
		queried = append(queried, server)
		r.pr.mu.Unlock()
		if server == "0.0.0.0" {
			return model.DNSResult{Err: "sendto: The requested address is not valid in its context."}
		}
		return model.DNSResult{OK: true, RCode: "NOERROR", Answers: []string{"142.250.72.36"}}
	}
	m.runServiceCheck(ctx)
	sc := decode[model.ServiceCheck](t, ofType(r.led.records(""), model.TypeServiceCheck)[0])
	for _, d := range sc.DNS {
		if d.ServerRole == "isp" && d.Server != "68.94.156.9" {
			t.Fatalf("ISP resolver query sent to %q (queried %v)", d.Server, queried)
		}
	}
	// The internet is back: the verdict must not blame the ISP resolver.
	m.processCycle(ctx, at.Add(2*time.Minute), time.Millisecond, healthy())
	if v := m.Status().Verdict; v.State != model.StateOnline {
		t.Fatalf("verdict %s/%s/%s: %q", v.State, v.Cause, v.Attribution, v.Reasons)
	}
}

// A step of this computer's wall clock moves every boot-time estimate (fetch time - uptime)
// computed after it. That is not a gateway reboot: the gateway's uptime grew exactly as much
// as the time that really elapsed (monotonic clock).
func TestReviewClockStepIsNotAGatewayReboot(t *testing.T) {
	at1 := time.Now()
	at2 := at1.Add(time.Minute) // monotonic: one minute between the polls
	prev := obsOf(10, at1, nil)
	cur := obsOf(11, at2, func(s *model.GatewaySnapshot) {
		s.System.UptimeSec, s.Derived.UptimeSec = 274686+60, 274686+60
		// Computed by the gateway client from a wall clock that was stepped +10 min.
		stepped := at2.Add(10 * time.Minute)
		s.Derived.BootTimeEstimate = fmtTS(stepped.Add(-time.Duration(274686+60) * time.Second))
		for i := range s.Pages {
			s.Pages[i].FetchedAt = fmtTS(stepped)
		}
	})
	if evs := gatewayEvents(prev, prev, prev, cur); len(evs) != 0 {
		t.Fatalf("events %v: %+v", eventKinds(evs), evs)
	}
	if el, ok := elapsedBetween(prev, cur); materialChange(prev.Snap, cur.Snap, el, ok) {
		t.Fatal("a clock step is not a material change of the gateway")
	}
	// A real reboot is still detected even when the estimates are computed from a wall clock
	// that does not move.
	rebooted := obsOf(12, at2, func(s *model.GatewaySnapshot) {
		s.System.UptimeSec, s.Derived.UptimeSec = 30, 30
		s.Derived.BootTimeEstimate = fmtTS(at2.Add(-30 * time.Second))
	})
	if evs := gatewayEvents(prev, prev, prev, rebooted); len(evs) != 1 || evs[0].Kind != model.GwEvReboot {
		t.Fatalf("events %v", eventKinds(evs))
	}
}

// An incident left open by a previous run is closed with statistics that cover the span it
// is closed with (first bad cycle to the last sample of that run), not the stale counts of
// its last incident_open/incident_update record.
func TestReviewStaleIncidentStatsAreRecounted(t *testing.T) {
	led := newFakeLedger("run-current")
	prev := "run-previous"
	base := time.Now().Add(-10 * time.Minute)
	led.appendAs(prev, base, model.TypeMonitorStart, model.MonitorStart{Mode: "service"})
	add := func(i int, state, id string) model.Ref {
		ts := base.Add(time.Duration(i) * 10 * time.Second)
		attr := model.AttrNone
		if state == model.StateISPOutage {
			attr = model.AttrProvider
		}
		return led.appendAs(prev, ts.Add(300*time.Millisecond), model.TypeSample, model.Sample{
			Cycle: uint64(i + 1), Started: fmtTS(ts), IncidentID: id,
			Probes: []model.ProbeResult{
				{Name: "gateway_icmp", Role: model.RoleGateway, OK: true},
				{Name: "inet_icmp_google", Role: model.RoleInet, OK: state == model.StateOnline},
			},
			Verdict: model.Verdict{State: state, Attribution: attr, Rules: RulesVersion},
		})
	}
	add(0, model.StateOnline, "")
	first := add(1, model.StateISPOutage, "")
	add(2, model.StateISPOutage, "")
	opened := base.Add(10 * time.Second)
	inc := model.Incident{ID: incidentID(opened), Opened: fmtTS(opened), Open: true, State: model.StateISPOutage,
		Cause: model.CauseWANDown, Attribution: model.AttrProvider, Rules: RulesVersion, FirstSeq: first.Seq,
		Stats: model.IncidentStats{Cycles: 3, BadCycles: 3, ProbeOK: map[string]int{"gateway_icmp": 3}, ProbeTotal: map[string]int{"gateway_icmp": 3}}}
	add(3, model.StateISPOutage, inc.ID)
	led.appendAs(prev, base.Add(31*time.Second), model.TypeIncidentOpen, inc)
	led.appendAs(prev, base.Add(32*time.Second), model.TypeGatewaySnapshot, downSnapshot([]string{"broadbandstatistics"}, base.Add(32*time.Second)))
	led.appendAs(prev, base.Add(33*time.Second), model.TypeServiceCheck, model.ServiceCheck{DNS: []model.DNSResult{{ServerRole: "gateway", Name: "www.google.com", Hijacked: true}}})
	led.appendAs("run-cli", base.Add(34*time.Second), model.TypeGatewaySnapshot, okSnapshot(nil, base)) // another writer: not counted
	add(4, model.StateISPOutage, inc.ID)
	add(5, model.StateOnline, inc.ID) // every probe ok: recovered
	last := add(6, model.StateOnline, inc.ID)

	cfg := testConfig()
	cfg.Probes.FastInterval = config.D(10 * time.Second)
	r := newRig(t, cfg, led)
	r.m.rebuild(time.Now())
	if err := r.m.recordStart(time.Now()); err != nil {
		t.Fatal(err)
	}
	r.m.closeStaleIncidents()
	closes := ofType(led.records("run-current"), model.TypeIncidentClose)
	if len(closes) != 1 {
		t.Fatalf("closes %d", len(closes))
	}
	got := decode[model.Incident](t, closes[0])
	if got.Closed != last.TS || got.Open {
		t.Fatalf("closed %s, want the last sample ts %s", got.Closed, last.TS)
	}
	// Samples 1..6: four ISP_OUTAGE cycles (40 s of downtime) and two good ones.
	s := got.Stats
	if s.Cycles != 6 || s.BadCycles != 4 || s.DowntimeSec != 40 || s.DegradedSec != 0 || s.ProbeTotal["gateway_icmp"] != 6 || s.ProbeOK["inet_icmp_google"] != 2 {
		t.Fatalf("stats %+v (recorded at open: %+v)", s, inc.Stats)
	}
	if s.GatewayFetches != 1 || !s.GatewayDownSeen || !s.DNSHijackSeen {
		t.Fatalf("gateway observations and checks in the span are not counted: %+v", s)
	}
	if got.RecoveredAt != fmtTS(base.Add(50*time.Second)) {
		t.Fatalf("recovered_at %s", got.RecoveredAt)
	}
	if !strings.Contains(got.Summary, "Measured time: 40s without Internet") || !strings.Contains(got.Summary, "the outcome after the monitor stopped is unknown") {
		t.Fatalf("summary %q", got.Summary)
	}
	found := false
	for _, e := range got.Evidence {
		found = found || (e.Seq == last.Seq && e.Type == model.TypeSample)
	}
	if !found {
		t.Fatalf("the last sample (seq %d) the close time comes from is not in the evidence: %+v", last.Seq, got.Evidence)
	}

	// FirstSeq that is not the incident's first bad sample: nothing is guessed.
	led2, inc2, _, _ := prevRunLedger(t, false)
	_ = inc2
	r2 := newRig(t, nil, led2)
	r2.m.mu.Lock()
	for id, x := range r2.m.st.incidents {
		x.FirstSeq = 0 // genesis
		r2.m.st.incidents[id] = x
	}
	r2.m.mu.Unlock()
	r2.m.rebuild(time.Now())
	r2.m.mu.Lock()
	for id, x := range r2.m.st.incidents {
		x.FirstSeq = 0
		r2.m.st.incidents[id] = x
	}
	r2.m.mu.Unlock()
	r2.m.closeStaleIncidents()
	if c := ofType(led2.records("run-current"), model.TypeIncidentClose); len(c) != 1 || decode[model.Incident](t, c[0]).Stats.Cycles != 3 {
		t.Fatalf("an unverifiable span must keep the recorded statistics")
	}
}

// The gateway certificate policy (DESIGN §2): pinned on first use; a changed certificate is
// recorded and held pending, status pages keep being read, authenticated requests are
// refused (even the TLS handshake of one in progress) until the operator confirms it.
func TestReviewCertPolicy(t *testing.T) {
	ctx := context.Background()
	r := newRig(t, nil, nil)
	r.cfg.Gateway.PinnedCertSHA256 = ""
	r.cfg.Gateway.AccessCodeProtected = "protected-blob"
	obs := r.gw.observer
	events := func() []model.GatewayEvent {
		var out []model.GatewayEvent
		for _, b := range ofType(r.led.records(""), model.TypeGatewayEvent) {
			out = append(out, decode[model.GatewayEvent](t, b))
		}
		return out
	}
	if !obs("", "aaaa") || r.cfg.Gateway.PinnedCertSHA256 != "aaaa" || r.cfg.Gateway.PendingCertSHA256 != "" {
		t.Fatal("trust on first use")
	}
	// A changed certificate met by a status page: accepted for reading, held pending.
	if !obs("aaaa", "BBBB") {
		t.Fatal("status pages keep being read")
	}
	if r.cfg.Gateway.PinnedCertSHA256 != "aaaa" || r.cfg.Gateway.PendingCertSHA256 != "bbbb" {
		t.Fatalf("pin %q pending %q", r.cfg.Gateway.PinnedCertSHA256, r.cfg.Gateway.PendingCertSHA256)
	}
	evs := events()
	if len(evs) != 2 || evs[1].Kind != model.GwEvCertChanged || evs[1].Before != "aaaa" || evs[1].After != "bbbb" || !strings.Contains(evs[1].Detail, "authenticated requests are paused") {
		t.Fatalf("events %+v", evs)
	}
	// The same pending certificate again: nothing new; refused inside an authenticated request.
	if !obs("bbbb", "bbbb") || len(events()) != 2 {
		t.Fatal("pending certificate seen again")
	}
	r.m.gwAuth.Store(true)
	if obs("aaaa", "bbbb") {
		t.Fatal("an unconfirmed certificate must be refused during an authenticated request")
	}
	r.m.gwAuth.Store(false)
	// Authenticated operations are paused without contacting the gateway.
	r.gw.notif = true
	err := r.m.checkNotification(ctx)
	if !errors.Is(err, contracts.ErrUnavailable) || !errors.Is(err, contracts.ErrGatewayCertRejected) || r.gw.notifCalls != 0 {
		t.Fatalf("check while pending: %v (calls %d)", err, r.gw.notifCalls)
	}
	if _, err := r.m.SetGatewayNotification(ctx, false, "operator via web"); !errors.Is(err, contracts.ErrUnavailable) ||
		!errors.Is(err, contracts.ErrGatewayCertRejected) || len(r.gw.setCalls) != 0 {
		t.Fatalf("set while pending: %v (calls %v)", err, r.gw.setCalls)
	}
	st := r.m.Status()
	var cond *model.Condition
	for i := range st.Conditions {
		if st.Conditions[i].Code == condGatewayCertChanged {
			cond = &st.Conditions[i]
		}
	}
	if cond == nil || cond.Severity != "critical" || !strings.Contains(cond.Message, "bbbb") || cond.Seq == 0 || cond.Since == "" {
		t.Fatalf("conditions %+v", st.Conditions)
	}
	if st.Notification == nil || !strings.Contains(st.Notification.Err, "trust-cert") {
		t.Fatalf("notification state %+v", st.Notification)
	}
	// A restart keeps the pending state and the condition (from the configuration and ledger).
	m2, err := New(Options{Config: r.cfg, Ledger: r.led, Gateway: &fakeGateway{}, Prober: newFakeProber()})
	if err != nil {
		t.Fatal(err)
	}
	m2.rebuild(time.Now())
	if c := m2.Status().Conditions; len(c) == 0 || c[len(c)-1].Code != condGatewayCertChanged || c[len(c)-1].Seq != cond.Seq || c[len(c)-1].Since == "" {
		t.Fatalf("after restart: %+v", c)
	}
	// The operator confirms: pinned, recorded, authenticated requests resume.
	saved := r.saved.Load()
	cc, err := r.m.TrustCert(ctx, "operator via web", "BBBB")
	if err != nil || cc.Before != "aaaa" || cc.After != "bbbb" || cc.Target != "monitor" || cc.Result != "applied" {
		t.Fatalf("trust: %+v %v", cc, err)
	}
	if r.cfg.Gateway.PinnedCertSHA256 != "bbbb" || r.cfg.Gateway.PendingCertSHA256 != "" || r.saved.Load() != saved+1 {
		t.Fatal("pin not updated and saved")
	}
	if c := ofType(r.led.records(""), model.TypeConfigChange); len(c) != 1 {
		t.Fatalf("config changes %d", len(c))
	}
	for _, c := range r.m.Status().Conditions {
		if c.Code == condGatewayCertChanged {
			t.Fatal("condition must clear")
		}
	}
	if _, err := r.m.TrustCert(ctx, "operator", ""); !errors.Is(err, contracts.ErrNotFound) {
		t.Fatalf("nothing pending: %v", err)
	}
	if err := r.m.checkNotification(ctx); err != nil || r.gw.notifCalls != 1 {
		t.Fatalf("check after trust: %v (calls %d)", err, r.gw.notifCalls)
	}
	// An unconfirmed certificate that goes away: the pinned one is presented again.
	if !obs("bbbb", "cccc") || r.cfg.Gateway.PendingCertSHA256 != "cccc" {
		t.Fatal("second change")
	}
	if !obs("cccc", "bbbb") || r.cfg.Gateway.PendingCertSHA256 != "" {
		t.Fatal("the pinned certificate is back: nothing to confirm")
	}
	if all := events(); all[len(all)-1].Kind != model.GwEvCertChanged || all[len(all)-1].Before != "cccc" || all[len(all)-1].After != "bbbb" || !strings.Contains(all[len(all)-1].Detail, "resume") {
		t.Fatalf("event %+v", all[len(all)-1])
	}
}

// AnchorNow follows contracts.Actions: partial success returns the anchors AND an error;
// a round already running is ErrBusy; anchoring disabled is ErrUnavailable.
func TestReviewAnchorNowContract(t *testing.T) {
	ctx := context.Background()
	r := newRig(t, nil, nil)
	r.m.anchorer = partialAnchorer{r.anc}
	anchors, err := r.m.AnchorNow(ctx, "")
	if len(anchors) != 1 || err == nil || !strings.Contains(err.Error(), "http://tsa.test/b") {
		t.Fatalf("partial: %d anchors, err %v", len(anchors), err)
	}
	if n := len(ofType(r.led.records(""), model.TypeAnchor)); n != 1 {
		t.Fatalf("anchor records %d", n)
	}
	r.m.anchorMu.Lock()
	_, err = r.m.AnchorNow(ctx, "manual")
	r.m.anchorMu.Unlock()
	if !errors.Is(err, contracts.ErrBusy) {
		t.Fatalf("busy: %v", err)
	}
	cfg := testConfig()
	cfg.Anchoring.Enabled = false
	r2 := newRig(t, cfg, nil)
	if _, err := r2.m.AnchorNow(ctx, "manual"); !errors.Is(err, contracts.ErrUnavailable) {
		t.Fatalf("disabled: %v", err)
	}
	// The periodic loop treats a partial success as success (no early retry).
	cfg3 := testConfig()
	cfg3.Anchoring.Interval = config.D(time.Hour)
	r3 := newRig(t, cfg3, nil)
	r3.m.anchorer = partialAnchorer{r3.anc}
	r3.m.anchorRetry = 20 * time.Millisecond
	r3.m.mu.Lock()
	r3.m.st.lastVerdict = model.Verdict{State: model.StateOnline} // retries would be allowed
	r3.m.mu.Unlock()
	lctx, cancel := context.WithTimeout(ctx, 300*time.Millisecond)
	defer cancel()
	r3.m.anchorLoop(lctx)
	if calls := r3.anc.timestampCalls(); calls != 1 {
		t.Fatalf("a round with one working TSA was retried: %d rounds", calls)
	}
}

// partialAnchorer: the second TSA fails.
type partialAnchorer struct{ *fakeAnchorer }

func (p partialAnchorer) Timestamp(ctx context.Context, digest []byte) []contracts.TimestampResult {
	res := p.fakeAnchorer.Timestamp(ctx, digest)
	res[1] = contracts.TimestampResult{URL: res[1].URL, Err: errors.New("tsa unreachable")}
	return res
}

// An operator change while a notification check holds the gateway session is busy (409),
// not queued behind a login for minutes.
func TestReviewNotificationChangeBusy(t *testing.T) {
	r := newRig(t, nil, nil)
	r.m.notifMu.Lock()
	_, err := r.m.SetGatewayNotification(context.Background(), false, "operator")
	r.m.notifMu.Unlock()
	if !errors.Is(err, contracts.ErrBusy) || len(r.gw.setCalls) != 0 {
		t.Fatalf("err %v calls %v", err, r.gw.setCalls)
	}
}

// monitor_start records the effective configuration without secrets (so reports can quote
// the exact thresholds); its SHA-256 is the recorded config_sha256. Status lists the probes.
func TestReviewMonitorStartConfigAndStatusProbes(t *testing.T) {
	r := newRig(t, nil, nil)
	r.cfg.Gateway.AccessCodeProtected = "c2VjcmV0LWRwYXBpLWJsb2I="
	if err := r.m.recordStart(time.Now()); err != nil {
		t.Fatal(err)
	}
	b := ofType(r.led.records(""), model.TypeMonitorStart)[0]
	ms := decode[model.MonitorStart](t, b)
	if len(ms.Config) == 0 || strings.Contains(string(ms.Config), "c2VjcmV0") || strings.Contains(string(b.Data), "c2VjcmV0") {
		t.Fatalf("config %s", ms.Config)
	}
	if sha256Hex(ms.Config) != ms.ConfigSHA256 || ms.ConfigSHA256 != r.cfg.RedactedSHA256() {
		t.Fatalf("sha256(config) %s, config_sha256 %s", sha256Hex(ms.Config), ms.ConfigSHA256)
	}
	var back config.Config
	if err := json.Unmarshal(ms.Config, &back); err != nil || back.Incident.LossDegradedPct != 20 || back.Probes.FastInterval.Duration != 40*time.Millisecond {
		t.Fatalf("config does not decode to the thresholds: %v %+v", err, back.Incident)
	}
	st := r.m.Status()
	if len(st.Probes) != 8 || st.Probes[0].Name != "gateway_icmp" || st.Probes[0].Target != gwIP || st.Probes[0].Label == "" {
		t.Fatalf("status probes %+v", st.Probes)
	}
}

// withoutCond drops the conditions with the given code.
func withoutCond(cs []model.Condition, code string) []model.Condition {
	var out []model.Condition
	for _, c := range cs {
		if c.Code != code {
			out = append(out, c)
		}
	}
	return out
}

// NO_ACCESS_CODE (info) is shown while the redirect setting cannot be checked (DESIGN §9).
func TestReviewNoAccessCodeCondition(t *testing.T) {
	r := newRig(t, nil, nil)
	has := func() *model.Condition {
		for _, c := range r.m.Status().Conditions {
			if c.Code == condNoAccessCode {
				return &c
			}
		}
		return nil
	}
	if c := has(); c == nil || c.Severity != "info" || !strings.Contains(c.Message, "set-access-code") {
		t.Fatalf("condition %+v", c)
	}
	r.m.cfgMu.Lock()
	r.cfg.Gateway.AccessCodeProtected = "protected-blob"
	r.m.cfgMu.Unlock()
	if c := has(); c != nil {
		t.Fatalf("access code present but %+v", c)
	}
}
