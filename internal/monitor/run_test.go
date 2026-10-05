package monitor

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"attmonitor/internal/model"
)

// TestRunEndToEnd drives a whole outage through Run with fakes: online, an AT&T WAN outage
// (gateway reachable, WAN down, internet unreachable), recovery. It checks the evidence the
// ledger ends up with, in order.
func TestRunEndToEnd(t *testing.T) {
	r := newRig(t, nil, nil)
	var phase atomic.Int32 // 0 online, 1 outage, 2 recovered
	inetDown := func(target string) bool { return phase.Load() == 1 && hostOnly(target) != gwIP }
	r.pr.ping = func(target string) model.ProbeResult {
		if inetDown(target) {
			return model.ProbeResult{Status: "IP_REQ_TIMED_OUT"}
		}
		return model.ProbeResult{OK: true, RTTus: 1900, Status: "IP_SUCCESS"}
	}
	r.pr.tcp = func(target string) model.ProbeResult {
		if inetDown(target) {
			return model.ProbeResult{Status: "timeout", Err: "dial tcp: i/o timeout"}
		}
		return model.ProbeResult{OK: true, RTTus: 2300, Status: "connected"}
	}
	r.gw.snap = func(call int, pages []string, trigger string) (model.GatewaySnapshot, map[string][]byte, error) {
		at := time.Now()
		if phase.Load() == 1 {
			s := downSnapshot(pages, at)
			return s, pageBodies(pages, fmt.Sprintf("down %d", call)), nil
		}
		return okSnapshot(pages, at), pageBodies(pages, fmt.Sprintf("up %d", call)), nil
	}

	var samples, afterOpen atomic.Int32
	var opened, closed, anchoredAfterClose atomic.Bool
	r.led.onAppend = func(b model.Body) {
		switch b.Type {
		case model.TypeSample:
			if samples.Add(1) == 5 {
				phase.Store(1)
			}
			if opened.Load() && afterOpen.Add(1) == 4 {
				phase.Store(2)
			}
		case model.TypeIncidentOpen:
			opened.Store(true)
		case model.TypeIncidentClose:
			closed.Store(true)
		case model.TypeAnchor:
			if closed.Load() && strings.Contains(string(b.Data), `"reason":"incident_close"`) {
				anchoredAfterClose.Store(true)
			}
		}
	}

	stop := r.start(t)
	waitFor(t, "incident closed and anchored", 20*time.Second, anchoredAfterClose.Load)
	waitFor(t, "a heartbeat", 5*time.Second, func() bool { return len(ofType(r.led.records("run-current"), model.TypeHeartbeat)) > 0 })
	if err := stop(); err != nil {
		t.Fatalf("Run: %v", err)
	}

	recs := r.led.records("run-current")
	types := r.led.types("run-current")
	if types[0] != model.TypeGenesis || types[1] != model.TypeMonitorStart || types[len(types)-1] != model.TypeMonitorStop {
		t.Fatalf("record order: first %v last %s", types[:2], types[len(types)-1])
	}
	ms := decode[model.MonitorStart](t, recs[1])
	if !ms.PrevStopped || ms.Mode != "console" || ms.Software.Rules != RulesVersion || ms.ConfigSHA256 != r.cfg.RedactedSHA256() || ms.PrevHead.Seq != 0 {
		t.Fatalf("monitor_start %+v", ms)
	}
	stopRec := decode[model.MonitorStop](t, recs[len(recs)-1])
	if stopRec.Reason != "test stop" {
		t.Fatalf("monitor_stop reason %q", stopRec.Reason)
	}

	idx := func(typ string) int { return slices.Index(types, typ) }
	iOpen, iClose := idx(model.TypeIncidentOpen), idx(model.TypeIncidentClose)
	if iOpen < 0 || iClose < iOpen || len(ofType(recs, model.TypeIncidentOpen)) != 1 || len(ofType(recs, model.TypeIncidentClose)) != 1 {
		t.Fatalf("incident records: %v", types)
	}
	if iSample := idx(model.TypeSample); iSample < 0 || iSample > iOpen {
		t.Fatal("samples must precede incident_open")
	}
	anchorAfterClose := -1
	for i := iClose + 1; i < len(recs); i++ {
		if recs[i].Type == model.TypeAnchor && decode[model.Anchor](t, recs[i]).Reason == "incident_close" {
			anchorAfterClose = i
			break
		}
	}
	if anchorAfterClose < 0 {
		t.Fatal("no anchor after incident_close")
	}
	if a := decode[model.Anchor](t, recs[anchorAfterClose]); !a.Verified || !a.ChainOK || a.HeadSeq < recs[iClose].Seq || !r.led.HasBlob(a.TokenSHA256) {
		t.Fatalf("anchor %+v", a)
	}
	if first := decode[model.Anchor](t, ofType(recs, model.TypeAnchor)[0]); first.Reason != "genesis" {
		t.Fatalf("first anchor of the first run: reason %q", first.Reason)
	}

	// Samples: find the first bad and the recovery cycle.
	var sampleBodies []model.Sample
	for _, b := range ofType(recs, model.TypeSample) {
		sampleBodies = append(sampleBodies, decode[model.Sample](t, b))
	}
	firstBad, lastBad := -1, -1
	for i, s := range sampleBodies {
		if s.Verdict.State != model.StateOnline {
			if firstBad < 0 {
				firstBad = i
			}
			lastBad = i
		}
	}
	if firstBad < 0 || lastBad+1 >= len(sampleBodies) {
		t.Fatalf("no bad/recovery samples (first %d last %d of %d)", firstBad, lastBad, len(sampleBodies))
	}
	// Bad cycles: exactly the outage. Rules 2026.10-2 exclude outage cycles from the window
	// loss, so the first cycle after the outage is ONLINE again (no PACKET_LOSS tail).
	for i := firstBad; i <= lastBad; i++ {
		v := sampleBodies[i].Verdict
		if v.State != model.StateISPOutage || v.Attribution != model.AttrProvider || v.Rules != RulesVersion || len(v.Reasons) == 0 {
			t.Fatalf("sample %d verdict %s/%s/%s %q", i, v.State, v.Cause, v.Attribution, v.Reasons)
		}
		for _, p := range sampleBodies[i].Probes {
			if p.Role == model.RoleInet && p.OK {
				t.Fatalf("sample %d: an outage cycle with a working internet probe", i)
			}
		}
	}
	incOpen := decode[model.Incident](t, recs[iOpen])
	incClose := decode[model.Incident](t, recs[iClose])
	if incOpen.Opened != sampleBodies[firstBad].Started || incClose.Opened != incOpen.Opened {
		t.Fatalf("opened %s, first bad cycle started %s", incOpen.Opened, sampleBodies[firstBad].Started)
	}
	if incClose.Closed != sampleBodies[lastBad+1].Started || incClose.Open || !incOpen.Open {
		t.Fatalf("closed %s, first good cycle started %s", incClose.Closed, sampleBodies[lastBad+1].Started)
	}
	if incOpen.ID != incidentID(mustTS(t, incOpen.Opened)) && !strings.HasPrefix(incOpen.ID, incidentID(mustTS(t, incOpen.Opened))) {
		t.Fatalf("id %s", incOpen.ID)
	}
	if sampleBodies[firstBad].IncidentID != "" || sampleBodies[firstBad+2].IncidentID != incOpen.ID || sampleBodies[lastBad].IncidentID != incOpen.ID {
		t.Fatal("samples must carry the incident id from the opening cycle on")
	}
	if incClose.State != model.StateISPOutage || incClose.Cause != model.CauseWANDown || incClose.Attribution != model.AttrProvider {
		t.Fatalf("incident headline %s/%s/%s causes %v", incClose.State, incClose.Cause, incClose.Attribution, incClose.Causes)
	}
	if incClose.Stats.BadCycles != lastBad-firstBad+1 || incClose.Stats.Cycles != incClose.Stats.BadCycles || !incClose.Stats.GatewayDownSeen || incClose.Stats.GatewayFetches == 0 {
		t.Fatalf("stats %+v (bad samples %d)", incClose.Stats, lastBad-firstBad+1)
	}
	if !strings.Contains(incClose.Summary, "ISP outage from") || !strings.Contains(incClose.Summary, "Attributed to the provider") {
		t.Fatalf("summary %q", incClose.Summary)
	}
	// recovered_at: the first cycle after the outage in which every probe succeeded.
	if incClose.RecoveredAt != sampleBodies[lastBad+1].Started ||
		!strings.Contains(incClose.Summary, "All probes succeeded again from "+fmtHuman(mustTS(t, incClose.RecoveredAt))) {
		t.Fatalf("recovered_at %s (first good cycle %s), summary %q", incClose.RecoveredAt, sampleBodies[lastBad+1].Started, incClose.Summary)
	}
	if incClose.FirstSeq != ofType(recs, model.TypeSample)[firstBad].Seq || incClose.LastSeq <= incClose.FirstSeq {
		t.Fatalf("first/last seq %d/%d", incClose.FirstSeq, incClose.LastSeq)
	}
	if incOpen.Rules != RulesVersion {
		t.Fatal("rules version")
	}

	// Raw gateway pages are stored while the incident is open, and at close.
	triggers := map[string]bool{}
	storedDuring := 0
	for _, b := range ofType(recs, model.TypeGatewaySnapshot) {
		s := decode[model.GatewaySnapshot](t, b)
		triggers[s.Trigger] = true
		var stored []string
		for _, p := range s.Pages {
			if p.Stored {
				stored = append(stored, p.SHA256)
				if !r.led.HasBlob(p.SHA256) {
					t.Fatalf("snapshot seq %d: page %s marked stored but blob missing", b.Seq, p.Page)
				}
			}
			if p.SHA256 == "" {
				t.Fatalf("snapshot seq %d: page %s without sha256", b.Seq, p.Page)
			}
		}
		if !slices.Equal(stored, b.Blobs) {
			t.Fatalf("snapshot seq %d: blobs %v but stored pages %v", b.Seq, b.Blobs, stored)
		}
		if b.Seq > recs[iOpen].Seq && b.Seq < recs[iClose].Seq {
			// Incident snapshots always keep their pages. (A routine poll that decided just
			// before incident_open was written may legitimately keep none.)
			if len(stored) == 0 && (s.Trigger == trigIncident || s.Trigger == trigIncidentClose) {
				t.Fatalf("snapshot seq %d (trigger %s) during the incident without raw pages", b.Seq, s.Trigger)
			}
			if len(stored) > 0 {
				storedDuring++
			}
		}
	}
	// (cycle_failure may merge into the incident trigger when the gateway worker was busy; it
	// is checked deterministically in TestFirstBadCycleKicksGatewayAndLink.)
	if storedDuring == 0 || !triggers[trigIncident] || !triggers[trigIncidentClose] || !triggers[trigStartup] {
		t.Fatalf("snapshots during incident %d, triggers %v", storedDuring, triggers)
	}

	// Gateway events tell the story from AT&T's own device.
	evKinds := map[string]int{}
	for _, b := range ofType(recs, model.TypeGatewayEvent) {
		evKinds[decode[model.GatewayEvent](t, b).Kind]++
	}
	if evKinds[model.GwEvBroadbandState] != 2 || evKinds[model.GwEvWANIPChange] != 2 || evKinds[model.GwEvGatewayClock] != 2 || evKinds[model.GwEvOpticalAlarm] != 1 {
		t.Fatalf("gateway events %v", evKinds)
	}

	// Supporting evidence of the open/close procedures.
	traceTriggers := map[string]int{}
	for _, b := range ofType(recs, model.TypeTraceroute) {
		tr := decode[model.Traceroute](t, b)
		traceTriggers[tr.Trigger]++
		if tr.Incident != incOpen.ID {
			t.Fatalf("traceroute incident %q", tr.Incident)
		}
	}
	if traceTriggers["incident_open"] != 2 || traceTriggers["incident_close"] != 2 {
		t.Fatalf("traceroutes %v", traceTriggers)
	}
	for _, typ := range []string{model.TypeServiceCheck, model.TypeLocalLink, model.TypeClockCheck, model.TypeHeartbeat, model.TypeStateChange} {
		if len(ofType(recs, typ)) == 0 {
			t.Errorf("no %s records", typ)
		}
	}
	links := ofType(recs, model.TypeLocalLink)
	if len(links) < 2 {
		t.Fatalf("local link recorded at start and at incident open, got %d", len(links))
	}
	if l := decode[model.LocalLink](t, links[0]); l.RawSHA256 == "" || !r.led.HasBlob(l.RawSHA256) || !slices.Contains(links[0].Blobs, l.RawSHA256) {
		t.Fatalf("local link raw output %+v", l)
	}
	changes := ofType(recs, model.TypeStateChange)
	first := decode[model.StateChange](t, changes[0])
	if first.FromState != model.StateUnknown || first.ToState != model.StateOnline {
		t.Fatalf("first state change %+v", first)
	}
	var path []string
	for _, b := range changes {
		sc := decode[model.StateChange](t, b)
		path = append(path, stateCause(sc.ToState, sc.ToCause))
		if sc.At == "" || sc.Cycle == 0 || len(sc.Reasons) == 0 {
			t.Fatalf("state change %+v", sc)
		}
	}
	// UNKNOWN → ONLINE → ISP_OUTAGE (next hop unreachable until a gateway snapshot shows the
	// WAN down — or WAN down at once when a poll lands first) → ONLINE.
	if path[0] != model.StateOnline || !strings.HasPrefix(path[1], model.StateISPOutage+"/") ||
		!slices.Contains(path, model.StateISPOutage+"/"+model.CauseWANDown) ||
		!strings.HasPrefix(path[len(path)-2], model.StateISPOutage+"/") || path[len(path)-1] != model.StateOnline {
		t.Fatalf("state change path %v", path)
	}
	if inc := incClose; !slices.ContainsFunc(inc.Evidence, func(e model.EvidenceRef) bool { return e.Type == model.TypeTraceroute }) ||
		!slices.ContainsFunc(inc.Evidence, func(e model.EvidenceRef) bool { return e.Type == model.TypeGatewaySnapshot && e.Blob != "" }) ||
		!slices.ContainsFunc(inc.Evidence, func(e model.EvidenceRef) bool { return e.Type == model.TypeGatewayEvent }) {
		t.Fatalf("incident evidence %+v", inc.Evidence)
	}
	if r.led.compress.Load() == 0 {
		t.Error("CompressSealed was not called")
	}

	// Views after the run.
	st := r.m.Status()
	if st.ActiveIncident != nil || st.Ledger.LastAnchorTime == "" || st.Monitor.Cycles == 0 || st.Verdict.State != model.StateOnline {
		t.Fatalf("status %+v", st)
	}
	incs := r.m.Incidents(time.Time{}, time.Time{})
	if len(incs) != 1 || incs[0].ID != incOpen.ID || incs[0].Open {
		t.Fatalf("incidents %+v", incs)
	}
	if got, ok := r.m.Incident(incOpen.ID); !ok || got.Closed != incClose.Closed {
		t.Fatalf("incident lookup %+v %v", got, ok)
	}
	if err := r.m.Run(context.Background()); err == nil {
		t.Fatal("Run must refuse to run twice")
	}
}

func mustTS(t *testing.T, s string) time.Time {
	t.Helper()
	ts, ok := parseTS(s)
	if !ok {
		t.Fatalf("bad ts %q", s)
	}
	return ts
}

// prevRunLedger builds a ledger whose previous run ended (without monitor_stop) while an
// incident was open.
func prevRunLedger(t *testing.T, stopped bool) (*fakeLedger, model.Incident, time.Time, uint64) {
	led := newFakeLedger("run-current")
	prev := "run-previous"
	base := time.Now().Add(-10 * time.Minute)
	led.appendAs(prev, base, model.TypeMonitorStart, model.MonitorStart{Mode: "service"})
	var lastTS time.Time
	var lastSeq uint64
	addSample := func(i int, state string, id string) {
		ts := base.Add(time.Duration(i) * 10 * time.Second)
		// The verdicts as the classifier records them (the incident's headline comes from them).
		v := model.Verdict{State: state, Attribution: model.AttrNone, Rules: RulesVersion, Reasons: []string{"5/5 internet probes succeeded"}}
		probes := healthy()
		if state == model.StateISPOutage {
			v.Cause, v.Attribution, v.Reasons = model.CauseWANDown, model.AttrProvider, []string{"AT&T gateway reports Broadband Connection: Down"}
			probes = outageCycle()
		}
		ref := led.appendAs(prev, ts.Add(300*time.Millisecond), model.TypeSample, model.Sample{
			Cycle: uint64(i + 1), Started: fmtTS(ts), Verdict: v, Probes: probes, IncidentID: id,
		})
		lastTS, lastSeq = ts.Add(300*time.Millisecond), ref.Seq
	}
	for i := 0; i < 3; i++ {
		addSample(i, model.StateOnline, "")
	}
	opened := base.Add(30 * time.Second)
	inc := model.Incident{ID: incidentID(opened), Opened: fmtTS(opened), Open: true, State: model.StateISPOutage,
		Cause: model.CauseWANDown, Attribution: model.AttrProvider, Rules: RulesVersion, Reasons: []string{"AT&T gateway reports Broadband Connection: Down"},
		Summary: "Ongoing ISP outage", Stats: model.IncidentStats{Cycles: 3, BadCycles: 3}}
	addSample(3, model.StateISPOutage, "")
	addSample(4, model.StateISPOutage, "")
	addSample(5, model.StateISPOutage, inc.ID)
	inc.FirstSeq = lastSeq - 2
	led.appendAs(prev, lastTS.Add(time.Millisecond), model.TypeIncidentOpen, inc)
	for i := 6; i < 9; i++ {
		addSample(i, model.StateISPOutage, inc.ID)
	}
	if stopped {
		led.appendAs(prev, lastTS.Add(time.Second), model.TypeMonitorStop, model.MonitorStop{Reason: "service stop"})
	}
	return led, inc, lastTS, lastSeq
}

func TestRunClosesIncidentLeftOpenByPreviousRun(t *testing.T) {
	led, inc, lastTS, lastSeq := prevRunLedger(t, false)
	prevHead := led.Head()
	r := newRig(t, nil, led)
	stop := r.start(t)
	waitFor(t, "a sample of this run", 10*time.Second, func() bool { return len(ofType(led.records("run-current"), model.TypeSample)) > 0 })
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	recs := led.records("run-current")
	if recs[1].Type != model.TypeMonitorStart || recs[2].Type != model.TypeIncidentClose {
		t.Fatalf("want monitor_start then incident_close, got %v", led.types("run-current")[:3])
	}
	ms := decode[model.MonitorStart](t, recs[1])
	if ms.PrevStopped {
		t.Fatal("the previous run did not stop cleanly")
	}
	if ms.PrevHead != prevHead || ms.GapSeconds < 9*60-100 || ms.GapSeconds > 9*60+100 {
		t.Fatalf("prev head %+v (want %+v) gap %d", ms.PrevHead, prevHead, ms.GapSeconds)
	}
	closed := decode[model.Incident](t, recs[2])
	if closed.ID != inc.ID || closed.Open || closed.Closed != fmtTS(lastTS) || closed.LastSeq != lastSeq {
		t.Fatalf("closed %+v", closed)
	}
	opened := mustTS(t, inc.Opened)
	if closed.DurationSec != int64(lastTS.Sub(opened)/time.Second) {
		t.Fatalf("duration %d", closed.DurationSec)
	}
	if !strings.Contains(closed.Summary, "the outcome after the monitor stopped is unknown") || !strings.HasPrefix(closed.Summary, "ISP outage from") {
		t.Fatalf("summary %q", closed.Summary)
	}
	// The headline is the one its samples support - the one recorded at the open.
	if closed.State != inc.State || closed.Cause != inc.Cause || closed.Attribution != inc.Attribution || !slices.Equal(closed.Reasons, inc.Reasons) {
		t.Fatalf("headline must be kept: %+v", closed)
	}
	if got := r.m.Incidents(time.Time{}, time.Time{}); len(got) != 1 || got[0].Open {
		t.Fatalf("incidents %+v", got)
	}
	if a := ofType(recs, model.TypeAnchor); len(a) == 0 || decode[model.Anchor](t, a[0]).Reason != "startup" {
		t.Fatal("restart anchors with reason startup")
	}
}

func TestRunAfterCleanStop(t *testing.T) {
	led, _, _, _ := prevRunLedger(t, true)
	r := newRig(t, nil, led)
	stop := r.start(t)
	waitFor(t, "a sample", 10*time.Second, func() bool { return len(ofType(led.records("run-current"), model.TypeSample)) > 0 })
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	recs := led.records("run-current")
	if !decode[model.MonitorStart](t, recs[1]).PrevStopped {
		t.Fatal("previous run stopped cleanly")
	}
	// The incident record of that run was still open: it is closed at its last sample.
	if recs[2].Type != model.TypeIncidentClose {
		t.Fatalf("got %v", led.types("run-current")[:3])
	}
}

func TestRunShutdownReasonAndPowerEvents(t *testing.T) {
	r := newRig(t, nil, nil)
	stop := r.start(t)
	waitFor(t, "a sample", 10*time.Second, func() bool { return len(ofType(r.led.records(""), model.TypeSample)) > 0 })
	r.m.PowerEvent("resume_automatic")
	r.m.PowerEvent("shutdown")
	r.m.PowerEvent("  ")
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	recs := r.led.records("")
	pe := ofType(recs, model.TypePowerEvent)
	if len(pe) != 2 || decode[model.PowerEvent](t, pe[0]).Kind != "resume_automatic" || decode[model.PowerEvent](t, pe[1]).Kind != "shutdown" {
		t.Fatalf("power events %v", pe)
	}
	if got := decode[model.MonitorStop](t, recs[len(recs)-1]).Reason; got != "system shutdown" {
		t.Fatalf("reason %q", got)
	}
}

func TestRunPlainCancelReason(t *testing.T) {
	r := newRig(t, nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.m.Run(ctx) }()
	waitFor(t, "a sample", 10*time.Second, func() bool { return len(ofType(r.led.records(""), model.TypeSample)) > 0 })
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	recs := r.led.records("")
	if got := decode[model.MonitorStop](t, recs[len(recs)-1]).Reason; got != "stopped" {
		t.Fatalf("reason %q", got)
	}
}

func TestRunFailsWhenLedgerRejectsStart(t *testing.T) {
	led := newFakeLedger("run-current")
	led.appendErr = errors.New("disk full")
	r := newRig(t, nil, led)
	if err := r.m.Run(context.Background()); err == nil || !strings.Contains(err.Error(), "disk full") {
		t.Fatalf("err %v", err)
	}
}

// TestGapClosesIncident: a monitoring gap (system sleep) closes an open incident at its last
// observation instead of stretching it over unmonitored time.
func TestGapClosesIncident(t *testing.T) {
	r := newRig(t, nil, nil)
	m := r.m
	ctx := context.Background()
	bad := cyc(gwICMP(true, 1900), gwTCP(true, 2300), inet(false, false, 0))
	start := time.Date(2026, 10, 5, 3, 0, 0, 0, time.UTC)
	for i := 0; i < 4; i++ {
		m.processCycle(ctx, start.Add(time.Duration(i)*40*time.Millisecond), time.Millisecond, bad)
	}
	if !m.incidentOpen() {
		t.Fatal("incident should be open")
	}
	m.processCycle(ctx, start.Add(time.Hour), time.Millisecond, healthy())
	if m.incidentOpen() {
		t.Fatal("the gap must close the incident")
	}
	m.mu.Lock()
	closing := len(m.st.closing)
	m.mu.Unlock()
	if closing != 1 {
		t.Fatalf("closing %d", closing)
	}
	m.finishClosings(ctx)
	recs := r.led.records("")
	closes := ofType(recs, model.TypeIncidentClose)
	if len(closes) != 1 {
		t.Fatalf("closes %d", len(closes))
	}
	// Closed at the end of what its last bad cycle covers (start + 1.5 fast intervals at most).
	inc := decode[model.Incident](t, closes[0])
	lastEnd := start.Add(3*40*time.Millisecond + 60*time.Millisecond)
	if inc.Closed != fmtTS(lastEnd) || !strings.Contains(inc.Summary, "Monitoring was interrupted for 1h0m0s") {
		t.Fatalf("closed %s (last bad cycle covers until %s) summary %q", inc.Closed, fmtTS(lastEnd), inc.Summary)
	}
}

func TestClockJumpOf(t *testing.T) {
	tests := []struct {
		wall, mono time.Duration
		jumpMs     int64
	}{
		{10 * time.Second, 10 * time.Second, 0},
		{12 * time.Second, 10 * time.Second, 0}, // exactly the threshold: not a jump
		{70 * time.Second, 10 * time.Second, 60000},
		{-50 * time.Second, 10 * time.Second, -60000},
		{10 * time.Second, 2 * time.Hour, -7190000}, // monotonic advanced, wall did not
	}
	for _, tc := range tests {
		cj := clockJumpOf(tc.wall, tc.mono)
		if (cj != nil) != (tc.jumpMs != 0) {
			t.Fatalf("wall %v mono %v: %+v", tc.wall, tc.mono, cj)
		}
		if cj != nil && (cj.JumpMs != tc.jumpMs || cj.WallDeltaMs != tc.wall.Milliseconds() || cj.MonoDeltaMs != tc.mono.Milliseconds()) {
			t.Fatalf("wall %v mono %v: %+v", tc.wall, tc.mono, cj)
		}
	}
}

func TestContinuityRecordsJumpAndGap(t *testing.T) {
	r := newRig(t, nil, nil)
	m := r.m
	ctx := context.Background()
	// Real times carry monotonic readings: no jump, no gap.
	t1 := time.Now()
	m.checkContinuity(t1)
	m.checkContinuity(t1.Add(40 * time.Millisecond))
	if n := len(ofType(r.led.records(""), model.TypeClockJump)); n != 0 {
		t.Fatalf("no jump expected, got %d", n)
	}
	// Open an incident, then the wall clock is stepped 70 s while 40 ms really elapsed: a
	// clock_jump is recorded and the incident is not stretched over the uncertain time.
	bad := cyc(gwICMP(true, 1900), inet(false, false, 0))
	for i := 0; i < 3; i++ {
		m.processCycle(ctx, t1.Add(time.Duration(i+2)*40*time.Millisecond), time.Millisecond, bad)
	}
	if !m.incidentOpen() {
		t.Fatal("incident should be open")
	}
	m.continuity(70*time.Second, 40*time.Millisecond)
	jumps := ofType(r.led.records(""), model.TypeClockJump)
	if len(jumps) != 1 || decode[model.ClockJump](t, jumps[0]).JumpMs != 69960 {
		t.Fatalf("jumps %v", jumps)
	}
	if m.incidentOpen() {
		t.Fatal("a wall-clock step beyond the gap limit closes the incident as interrupted")
	}
}

// TestNoGoroutineLeak: every goroutine started by Run has finished when Run returns.
func TestNoGoroutineLeak(t *testing.T) {
	r := newRig(t, nil, nil)
	r.cfg.Gateway.AccessCodeProtected = "protected-blob" // also run the notification loop
	stop := r.start(t)
	waitFor(t, "samples", 10*time.Second, func() bool { return len(ofType(r.led.records(""), model.TypeSample)) > 3 })
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	// Probe goroutines of the last cycle may still be returning; give them a moment.
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
