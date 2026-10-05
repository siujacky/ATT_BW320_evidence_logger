package monitor

// Tests of the integration round (rules 2026.10-3): gateway restart windows learned during,
// before and after an incident, verdict inputs, the daily incident_update, anchor trust,
// ErrNotRecorded, the daily notification confirmation, Run's lifetime and the gateway error
// sentinels. Most run on a fake clock with the default 10 s fast interval.

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"attmonitor/internal/contracts"
	"attmonitor/internal/model"
)

// restartGateway is a fake gateway for restart scenarios: before the restart it reports a boot
// 274686 s before base; with sysinfoDown it answers without a readable sysinfo page; once
// restarted it reports the boot at boot (firmware fw when set).
type restartGateway struct {
	clk         *fakeClock
	base, boot  time.Time
	fw          string
	sysinfoDown atomic.Bool
	restarted   atomic.Bool
}

func (g *restartGateway) snap(call int, pages []string, trigger string) (model.GatewaySnapshot, map[string][]byte, error) {
	now := g.clk.Now()
	s := okSnapshot(pages, now)
	switch {
	case g.sysinfoDown.Load():
		s.System = nil
		s.Derived.UptimeSec, s.Derived.BootTimeEstimate, s.Derived.Firmware = -1, "", ""
	case g.restarted.Load():
		up := int64(now.Sub(g.boot) / time.Second)
		s.System.UptimeSec, s.Derived.UptimeSec = up, up
		s.Derived.BootTimeEstimate = fmtTS(g.boot)
		if g.fw != "" {
			s.System.SoftwareVersion, s.Derived.Firmware = g.fw, g.fw
		}
	default:
		const old = 274686
		up := old + int64(now.Sub(g.base)/time.Second)
		s.System.UptimeSec, s.Derived.UptimeSec = up, up
		s.Derived.BootTimeEstimate = fmtTS(g.base.Add(-old * time.Second))
	}
	return s, pageBodies(pages, fmt.Sprint(now.UnixNano())), nil
}

// cycleAt runs fast cycle i (started at base + 10 s × i) on the rig's fake clock.
func cycleAt(r *rig, clk *fakeClock, base time.Time, i int, probes []model.ProbeResult) {
	start := base.Add(time.Duration(i) * 10 * time.Second)
	clk.Set(start.Add(300 * time.Millisecond))
	r.m.processCycle(context.Background(), start, 300*time.Millisecond, probes)
}

func lastOfType(t *testing.T, r *rig, typ string) model.Body {
	t.Helper()
	recs := ofType(r.led.records(""), typ)
	if len(recs) == 0 {
		t.Fatalf("no %s record", typ)
	}
	return recs[len(recs)-1]
}

func rebootEvents(t *testing.T, r *rig) []model.Body {
	var out []model.Body
	for _, b := range ofType(r.led.records(""), model.TypeGatewayEvent) {
		if decode[model.GatewayEvent](t, b).Kind == model.GwEvReboot {
			out = append(out, b)
		}
	}
	return out
}

// ---------------------------------------------------------------------------- 1. gateway restarts

// The owner power-cycles the gateway while the Internet works and the close snapshot cannot
// read sysinfo: the close record states an AT&T outage (all that was known), and the first
// snapshot that reads the uptime revises it with an incident_update - a gateway restart, no
// provider downtime, undetermined (or the provider's after a firmware change). The statistics,
// live and rebuilt from the ledger, count no provider outage either.
func TestRestartLearnedAfterCloseRevisesIncident(t *testing.T) {
	for _, fwChange := range []bool{false, true} {
		t.Run(fmt.Sprintf("firmware_change=%v", fwChange), func(t *testing.T) {
			base := time.Date(2026, 10, 5, 3, 0, 0, 0, time.UTC)
			r, clk := clockRig(t, base)
			m, ctx := r.m, context.Background()
			gw := &restartGateway{clk: clk, base: base, boot: base.Add(45 * time.Second)}
			if fwChange {
				gw.fw = "6.35.1"
			}
			r.gw.snap = gw.snap
			clk.Set(base.Add(-5 * time.Second))
			if m.takeSnapshot(ctx, trigStartup, nil) == nil {
				t.Fatal("startup snapshot not recorded")
			}
			cycleAt(r, clk, base, 0, healthy())
			cycleAt(r, clk, base, 1, healthy())
			for i := 2; i <= 7; i++ {
				cycleAt(r, clk, base, i, lanDownCycle()) // powered off, booting
			}
			for i := 8; i <= 12; i++ {
				cycleAt(r, clk, base, i, outageCycle()) // LAN back, WAN still coming up
			}
			for i := 13; i <= 15; i++ {
				cycleAt(r, clk, base, i, healthy()) // closes at start(13)
			}
			m.mu.Lock()
			if len(m.st.closing) != 1 {
				m.mu.Unlock()
				t.Fatalf("closing %d", len(m.st.closing))
			}
			st := m.st.closing[0]
			m.mu.Unlock()

			gw.sysinfoDown.Store(true)
			clk.Set(base.Add(160 * time.Second))
			m.finishClose(ctx, st, true)
			closed := decode[model.Incident](t, lastOfType(t, r, model.TypeIncidentClose))
			if closed.State != model.StateISPOutage || closed.Attribution != model.AttrProvider || closed.Stats.DowntimeSec != 50 || len(closed.GatewayRestarts) != 0 {
				t.Fatalf("close record before the restart is known: %s/%s/%s %+v", closed.State, closed.Cause, closed.Attribution, closed.Stats)
			}
			m.mu.Lock()
			watching := len(m.st.rebootWatch)
			m.mu.Unlock()
			if watching != 1 {
				t.Fatalf("an incident closed without a readable uptime waits for one (watch %d)", watching)
			}

			// The next snapshot reads the uptime. The snapshot before it had no sysinfo: the
			// restart is found against the latest readable uptime.
			gw.sysinfoDown.Store(false)
			gw.restarted.Store(true)
			clk.Set(base.Add(220 * time.Second))
			if m.takeSnapshot(ctx, trigPeriodic, nil) == nil {
				t.Fatal("snapshot not recorded")
			}
			reboots := rebootEvents(t, r)
			if len(reboots) != 1 || decode[model.GatewayEvent](t, reboots[0]).After != fmtTS(gw.boot) {
				t.Fatalf("reboot events %+v", reboots)
			}
			recs := r.led.records("")
			last := recs[len(recs)-1]
			if last.Type != model.TypeIncidentUpdate || last.Seq < reboots[0].Seq {
				t.Fatalf("the records end with %s, want the incident_update after the reboot event", last.Type)
			}
			upd := decode[model.Incident](t, last)
			wantAttr := model.AttrUndetermined
			if fwChange {
				wantAttr = model.AttrProvider
			}
			if upd.ID != closed.ID || upd.Open || upd.Closed != closed.Closed || upd.State != model.StateLocalFault ||
				upd.Cause != model.CauseGatewayReboot || upd.Attribution != wantAttr {
				t.Fatalf("update %s %s/%s/%s open %v closed %s", upd.ID, upd.State, upd.Cause, upd.Attribution, upd.Open, upd.Closed)
			}
			if upd.Stats.DowntimeSec != 0 || upd.Stats.RestartSec != 110 || !slices.Equal(upd.GatewayRestarts, []string{fmtTS(gw.boot)}) ||
				!hasEvidence(upd, model.TypeGatewayEvent, reboots[0].Seq) {
				t.Fatalf("update stats %+v restarts %v evidence %+v", upd.Stats, upd.GatewayRestarts, upd.Evidence)
			}
			if got := strings.Contains(strings.Join(upd.Reasons, "\n"), "AT&T-pushed firmware update"); got != fwChange {
				t.Fatalf("firmware reason %v: %q", got, upd.Reasons)
			}
			m.mu.Lock()
			watching = len(m.st.rebootWatch)
			m.mu.Unlock()
			if watching != 0 {
				t.Fatal("decided incidents leave the watch list")
			}
			if got, _ := m.Incident(upd.ID); got.Cause != model.CauseGatewayReboot {
				t.Fatalf("view %+v", got)
			}
			if day := m.Status().Stats[0]; day.ProviderOutageSec != 0 || day.MonitoredSec == 0 {
				t.Fatalf("24h stats count the restart window as provider downtime: %+v", day)
			}
			// A monitor rebuilt from the ledger knows the restart too.
			m2, err := New(Options{Config: r.cfg, Ledger: r.led, Gateway: &fakeGateway{}, Prober: newFakeProber(), Now: clk.Now})
			if err != nil {
				t.Fatal(err)
			}
			m2.rebuild(clk.Now())
			if day := m2.Status().Stats[0]; day.ProviderOutageSec != 0 || day.MonitoredSec == 0 {
				t.Fatalf("rebuilt 24h stats %+v", day)
			}
			m2.mu.Lock()
			rs := slices.Clone(m2.st.restarts)
			m2.mu.Unlock()
			if len(rs) != 1 || !rs[0].Boot.Equal(gw.boot) || rs[0].fwChanged() != fwChange || rs[0].EventSeq != reboots[0].Seq {
				t.Fatalf("rebuilt restarts %+v", rs)
			}
		})
	}
}

// A restart learned while the incident is open is recorded at once (incident_update); the
// cycles that follow inside the restart window change nothing, and the close record carries
// the restart and its accounting.
func TestRestartLearnedDuringIncident(t *testing.T) {
	base := time.Date(2026, 10, 5, 3, 0, 0, 0, time.UTC)
	r, clk := clockRig(t, base)
	m, ctx := r.m, context.Background()
	gw := &restartGateway{clk: clk, base: base, boot: base.Add(35 * time.Second)}
	r.gw.snap = gw.snap
	clk.Set(base.Add(-5 * time.Second))
	m.takeSnapshot(ctx, trigStartup, nil)
	cycleAt(r, clk, base, 0, healthy())
	cycleAt(r, clk, base, 1, healthy())
	for i := 2; i <= 4; i++ {
		cycleAt(r, clk, base, i, lanDownCycle()) // opens at cycle 4
	}
	cycleAt(r, clk, base, 5, outageCycle())
	gw.restarted.Store(true)
	clk.Set(base.Add(52 * time.Second))
	m.takeSnapshot(ctx, trigIncident, nil)
	upd := decode[model.Incident](t, lastOfType(t, r, model.TypeIncidentUpdate))
	if !upd.Open || upd.Cause != model.CauseGatewayReboot || upd.Attribution != model.AttrUndetermined || !slices.Equal(upd.GatewayRestarts, []string{fmtTS(gw.boot)}) {
		t.Fatalf("update of the open incident %s/%s open %v restarts %v", upd.Cause, upd.Attribution, upd.Open, upd.GatewayRestarts)
	}
	nUpdates := len(ofType(r.led.records(""), model.TypeIncidentUpdate))
	for i := 6; i <= 8; i++ {
		cycleAt(r, clk, base, i, outageCycle()) // still inside the restart window
	}
	for i := 9; i <= 11; i++ {
		cycleAt(r, clk, base, i, healthy())
	}
	if n := len(ofType(r.led.records(""), model.TypeIncidentUpdate)); n != nUpdates {
		t.Fatalf("cycles inside the restart window wrote %d more updates", n-nUpdates)
	}
	m.mu.Lock()
	st := m.st.closing[0]
	m.mu.Unlock()
	clk.Set(base.Add(130 * time.Second))
	m.finishClose(ctx, st, true)
	closed := decode[model.Incident](t, lastOfType(t, r, model.TypeIncidentClose))
	if closed.Cause != model.CauseGatewayReboot || closed.Attribution != model.AttrUndetermined || closed.Stats.RestartSec != 70 ||
		closed.Stats.DowntimeSec != 0 || closed.Closed != fmtTS(base.Add(90*time.Second)) || !strings.Contains(closed.Summary, "when the Internet was reachable again") {
		t.Fatalf("close %s/%s %+v closed %s: %s", closed.Cause, closed.Attribution, closed.Stats, closed.Closed, closed.Summary)
	}
	m.mu.Lock()
	watching := len(m.st.rebootWatch)
	m.mu.Unlock()
	if watching != 0 {
		t.Fatal("the close snapshot read the uptime: nothing to wait for")
	}
}

// A restart learned while the first bad cycles were still blips belongs to the incident that
// they then open: its incident_open already names the restart.
func TestRestartLearnedBeforeIncidentOpens(t *testing.T) {
	base := time.Date(2026, 10, 5, 3, 0, 0, 0, time.UTC)
	r, clk := clockRig(t, base)
	m, ctx := r.m, context.Background()
	gw := &restartGateway{clk: clk, base: base, boot: base.Add(25 * time.Second)}
	r.gw.snap = gw.snap
	clk.Set(base.Add(-5 * time.Second))
	m.takeSnapshot(ctx, trigStartup, nil)
	cycleAt(r, clk, base, 0, healthy())
	cycleAt(r, clk, base, 1, healthy())
	cycleAt(r, clk, base, 2, lanDownCycle())
	cycleAt(r, clk, base, 3, lanDownCycle())
	gw.restarted.Store(true)
	clk.Set(base.Add(38 * time.Second))
	m.takeSnapshot(ctx, trigCycleFailure, nil)
	if len(rebootEvents(t, r)) != 1 || m.incidentOpen() {
		t.Fatal("the restart is recorded before any incident")
	}
	cycleAt(r, clk, base, 4, outageCycle()) // third bad cycle: opens
	opened := decode[model.Incident](t, lastOfType(t, r, model.TypeIncidentOpen))
	if opened.Cause != model.CauseGatewayReboot || opened.Attribution != model.AttrUndetermined ||
		!slices.Equal(opened.GatewayRestarts, []string{fmtTS(gw.boot)}) || opened.Opened != fmtTS(base.Add(20*time.Second)) {
		t.Fatalf("open record %s/%s restarts %v opened %s", opened.Cause, opened.Attribution, opened.GatewayRestarts, opened.Opened)
	}
}

// The statistics window counts provider-attributed ISP_OUTAGE cycles inside restart windows as
// restart time, not provider outage; outages outside them still count.
func TestWindowStatsExcludeRestartWindows(t *testing.T) {
	fast := 10 * time.Second
	ps := newPointStore()
	gw := func(ok bool) model.ProbeResult {
		return model.ProbeResult{Name: "gateway_icmp", Role: model.RoleGateway, OK: ok}
	}
	inet := func(ok bool) model.ProbeResult {
		return model.ProbeResult{Name: "inet_icmp_google", Role: model.RoleInet, OK: ok}
	}
	states := []string{
		model.StateOnline, model.StateOnline, // 0-1
		model.StateLocalFault, model.StateLocalFault, model.StateLocalFault, // 2-4: power cycle
		model.StateISPOutage, model.StateISPOutage, model.StateISPOutage, model.StateISPOutage, // 5-8: WAN coming back
		model.StateOnline, model.StateOnline, model.StateOnline, // 9-11
		model.StateISPOutage, model.StateISPOutage, // 12-13: an AT&T outage
		model.StateOnline, // 14
	}
	for i, s := range states {
		attr := model.AttrNone
		switch s {
		case model.StateISPOutage:
			attr = model.AttrProvider
		case model.StateLocalFault:
			attr = model.AttrUndetermined
		}
		ps.addSample(t0.Add(time.Duration(i)*fast), sampleAttr(s, attr, false, gw(s != model.StateLocalFault), inet(s == model.StateOnline)))
	}
	now := t0.Add(150 * time.Second)
	without := ps.windowStats("1h", time.Hour, now, fast, nil, nil)
	iv := ps.restartIntervals([]time.Time{t0.Add(35 * time.Second)}, gapLimit(fast))
	with := ps.windowStats("1h", time.Hour, now, fast, nil, iv)
	if len(iv) != 1 || iv[0].start != t0.Add(20*time.Second).UnixNano() || iv[0].end != t0.Add(90*time.Second).UnixNano() {
		t.Fatalf("restart interval %+v", iv)
	}
	if without.ProviderOutageSec != 60 || with.ProviderOutageSec != 20 || with.MonitoredSec != without.MonitoredSec || with.AvailabilityPct != without.AvailabilityPct {
		t.Fatalf("without %+v\nwith %+v", without, with)
	}
}

// ---------------------------------------------------------------------------- 2. verdict inputs

// Every verdict names the records it was computed from, and uses exactly those: the latest
// recorded snapshot, service check and local link when fresh (0 otherwise) and the window.
func TestVerdictInputsNameTheRecordsUsed(t *testing.T) {
	base := time.Date(2026, 10, 5, 3, 0, 0, 0, time.UTC)
	r, clk := clockRig(t, base)
	m, ctx := r.m, context.Background()
	r.gw.snap = func(int, []string, string) (model.GatewaySnapshot, map[string][]byte, error) {
		pages := []string{"broadbandstatistics", "fiberstat", "sysinfo"}
		return okSnapshot(pages, clk.Now()), pageBodies(pages, "x"), nil
	}
	snap := m.takeSnapshot(ctx, trigStartup, nil)
	m.runServiceCheck(ctx)
	m.checkLocalLink(ctx, true)
	want := model.VerdictInputs{SnapshotSeq: snap.Seq, ServiceCheckSeq: lastOfType(t, r, model.TypeServiceCheck).Seq,
		LocalLinkSeq: lastOfType(t, r, model.TypeLocalLink).Seq}
	verdict := func() model.Verdict {
		v := decode[model.Sample](t, lastOfType(t, r, model.TypeSample)).Verdict
		if v.Inputs == nil {
			t.Fatal("verdict without inputs")
		}
		return v
	}
	cycleAt(r, clk, base, 1, healthy())
	if want.WindowCycles = 1; *verdict().Inputs != want {
		t.Fatalf("inputs %+v want %+v", *verdict().Inputs, want)
	}
	cycleAt(r, clk, base, 2, healthy())
	if want.WindowCycles = 2; *verdict().Inputs != want {
		t.Fatalf("inputs %+v want %+v", *verdict().Inputs, want)
	}
	// A newer local-link reading that was not recorded is not an input: the classification uses
	// the recorded link (connected), so the gateway is unreachable for an undetermined reason.
	m.mu.Lock()
	m.st.lastLink = &model.LocalLink{Interface: "Wi-Fi", Type: "wifi", State: "disconnected"}
	m.mu.Unlock()
	cycleAt(r, clk, base, 3, lanDownCycle())
	if v := verdict(); v.Cause != model.CauseGatewayUnreachable || v.Inputs.LocalLinkSeq != want.LocalLinkSeq {
		t.Fatalf("verdict %s/%s inputs %+v: %q", v.State, v.Cause, *v.Inputs, v.Reasons)
	}
	// 160 s after them the inputs are stale: not used, not named.
	for i := 4; i <= 16; i++ {
		cycleAt(r, clk, base, i, healthy())
	}
	if got := *verdict().Inputs; got != (model.VerdictInputs{WindowCycles: 6}) {
		t.Fatalf("stale inputs %+v", got)
	}
}

// Classify reports the inputs it used: fresh ones only; a stale local link is not used by rule 1.
func TestClassifyReportsFreshInputs(t *testing.T) {
	cfg := testConfig().Incident
	link := &model.LocalLink{Interface: "Wi-Fi", Type: "wifi", State: "disconnected"}
	in := ClassifyInput{Cycle: healthy(), Window: win(healthy(), healthy()), Snapshot: snapWith(nil), SnapshotAge: 10 * time.Second, SnapshotSeq: 7,
		Service: svc(dnsOK("gateway", gwIP)), ServiceAge: 20 * time.Second, ServiceSeq: 8, Link: link, LinkAge: 30 * time.Second, LinkSeq: 9}
	if got := *Classify(in, cfg).Inputs; got != (model.VerdictInputs{SnapshotSeq: 7, ServiceCheckSeq: 8, LocalLinkSeq: 9, WindowCycles: 2}) {
		t.Fatalf("fresh inputs %+v", got)
	}
	in.SnapshotAge, in.ServiceAge, in.LinkAge = 151*time.Second, 151*time.Second, 151*time.Second
	if got := *Classify(in, cfg).Inputs; got != (model.VerdictInputs{WindowCycles: 2}) {
		t.Fatalf("stale inputs %+v", got)
	}
	lan := ClassifyInput{Cycle: lanDownCycle(), Link: link, LinkAge: 151 * time.Second, LinkSeq: 9}
	if v := Classify(lan, cfg); v.Cause != model.CauseGatewayUnreachable || v.Inputs.LocalLinkSeq != 0 || v.Inputs.WindowCycles != 1 {
		t.Fatalf("stale link: %s %+v", v.Cause, *v.Inputs)
	}
	lan.LinkAge = time.Second
	if v := Classify(lan, cfg); v.Cause != model.CauseLocalLinkDown || v.Inputs.LocalLinkSeq != 9 {
		t.Fatalf("fresh link: %s %+v", v.Cause, *v.Inputs)
	}
}

// While an incident is open, an unchanged local link is recorded again before its record goes
// stale, so the classifier keeps a fresh recorded input; otherwise it is not.
func TestLocalLinkRefreshedWhileItMatters(t *testing.T) {
	base := time.Date(2026, 10, 5, 3, 0, 0, 0, time.UTC)
	r, clk := clockRig(t, base)
	m, ctx := r.m, context.Background()
	count := func() int { return len(ofType(r.led.records(""), model.TypeLocalLink)) }
	clk.Set(base)
	m.checkLocalLink(ctx, false)
	clk.Set(base.Add(100 * time.Second))
	m.checkLocalLink(ctx, false)
	if count() != 1 {
		t.Fatal("an unchanged link outside incidents is recorded only every 10 min")
	}
	for i := 11; i <= 13; i++ {
		cycleAt(r, clk, base, i, outageCycle()) // opens an incident
	}
	clk.Set(base.Add(140 * time.Second)) // 140 s after the record: within 60 s of going stale
	m.checkLocalLink(ctx, false)
	if count() != 2 {
		t.Fatalf("during an incident the unchanged link must be recorded before it goes stale (%d records)", count())
	}
	clk.Set(base.Add(200 * time.Second))
	m.checkLocalLink(ctx, false)
	if count() != 2 {
		t.Fatal("refreshed only when the record is about to go stale")
	}
}

// ---------------------------------------------------------------------------- 3. daily segments

// While an incident is open, the first record of every new UTC day (a new ledger segment, after
// its segment_open) is followed by the segment's config_state and an incident_update, once per
// segment.
func TestNewDailySegmentRecordsOpenIncident(t *testing.T) {
	base := time.Date(2026, 10, 5, 23, 59, 20, 0, time.UTC)
	r, clk := clockRig(t, base)
	r.led.mu.Lock()
	r.led.segments = true
	r.led.mu.Unlock()
	m, ctx := r.m, context.Background()
	for i := 0; i < 4; i++ {
		cycleAt(r, clk, base, i, outageCycle()) // opens at 23:59:40
	}
	id := m.openIncidentID()
	if id == "" {
		t.Fatal("incident should be open")
	}
	cycleAt(r, clk, base, 4, outageCycle()) // 00:00:00: the first record of the new day
	recs := r.led.records("")
	k := slices.IndexFunc(recs, func(b model.Body) bool { return b.Type == model.TypeSegmentOpen })
	if k < 0 || k+3 >= len(recs) || recs[k+1].Type != model.TypeSample || recs[k+2].Type != model.TypeConfigState ||
		recs[k+3].Type != model.TypeIncidentUpdate {
		t.Fatalf("records %v", r.led.types(""))
	}
	if upd := decode[model.Incident](t, recs[k+3]); upd.ID != id || !upd.Open {
		t.Fatalf("update %+v", upd)
	}
	for i := 5; i < 9; i++ {
		cycleAt(r, clk, base, i, outageCycle())
	}
	updatesSince := func(seq uint64) int {
		n := 0
		for _, b := range ofType(r.led.records(""), model.TypeIncidentUpdate) {
			if b.Seq > seq {
				n++
			}
		}
		return n
	}
	if n := updatesSince(recs[k].Seq); n != 1 {
		t.Fatalf("%d updates in the new segment, want exactly 1", n)
	}
	// The next day's first record (an operator note) is followed by the update as well.
	clk.Set(base.Add(24*time.Hour + time.Hour))
	ref, err := m.Note(ctx, "AT&T ticket 1", "owner", "test")
	if err != nil {
		t.Fatal(err)
	}
	recs = r.led.records("")
	if recs[ref.Seq-1].Type != model.TypeSegmentOpen || recs[ref.Seq+1].Type != model.TypeConfigState || recs[ref.Seq+2].Type != model.TypeIncidentUpdate {
		t.Fatalf("records around the note: %s, note, %s, %s", recs[ref.Seq-1].Type, recs[ref.Seq+1].Type, recs[ref.Seq+2].Type)
	}

	// An incident opened by the first cycle of a day needs no extra update: its incident_open is
	// in the new segment.
	base2 := time.Date(2026, 10, 6, 23, 59, 40, 0, time.UTC)
	r2, clk2 := clockRig(t, base2)
	r2.led.mu.Lock()
	r2.led.segments = true
	r2.led.mu.Unlock()
	for i := 0; i < 3; i++ {
		cycleAt(r2, clk2, base2, i, outageCycle()) // the third cycle (00:00:00) opens it
	}
	types := r2.led.types("")
	if !slices.Contains(types, model.TypeIncidentOpen) || slices.Contains(types, model.TypeIncidentUpdate) ||
		slices.Index(types, model.TypeSegmentOpen) > slices.Index(types, model.TypeIncidentOpen) {
		t.Fatalf("records %v", types)
	}
	// Without an open incident a new day adds nothing.
	r3, clk3 := clockRig(t, base2)
	r3.led.mu.Lock()
	r3.led.segments = true
	r3.led.mu.Unlock()
	cycleAt(r3, clk3, base2, 0, healthy())
	cycleAt(r3, clk3, base2, 2, healthy())
	if types := r3.led.types(""); slices.Contains(types, model.TypeIncidentUpdate) || !slices.Contains(types, model.TypeConfigState) {
		t.Fatalf("no incident: no update, but the configuration in force: %v", types)
	}
}

// ---------------------------------------------------------------------------- 5. ErrNotRecorded

// The gateway applied the operator's change but its config_change could not be written: the
// known state follows the gateway and the error wraps contracts.ErrNotRecorded and the ledger
// error; the next check records the setting it reads. A gateway failure is not ErrNotRecorded.
func TestSetGatewayNotificationNotRecorded(t *testing.T) {
	ctx := context.Background()
	r := newRig(t, nil, nil)
	r.cfg.Gateway.AccessCodeProtected = "protected-blob"
	r.gw.notif = true
	diskFull := errors.New("disk full")
	setAppendErr(r.led, diskFull)
	_, err := r.m.SetGatewayNotification(ctx, false, "operator via web")
	setAppendErr(r.led, nil)
	if !errors.Is(err, contracts.ErrNotRecorded) || !errors.Is(err, diskFull) {
		t.Fatalf("err %v", err)
	}
	if r.gw.notif {
		t.Fatal("the gateway change was applied")
	}
	st := r.m.Status()
	if st.Notification == nil || st.Notification.Enabled || st.Notification.Seq != 0 || !strings.Contains(st.Notification.Err, "could not be recorded") {
		t.Fatalf("notification state %+v", st.Notification)
	}
	if n := len(ofType(r.led.records(""), model.TypeConfigChange)); n != 0 {
		t.Fatalf("config changes %d", n)
	}
	if err := r.m.checkNotification(ctx); err != nil {
		t.Fatal(err)
	}
	if ev := decode[model.GatewayEvent](t, lastOfType(t, r, model.TypeGatewayEvent)); ev.Kind != model.GwEvNotificationSetting || ev.After != "off" {
		t.Fatalf("event %+v", ev)
	}
	r.gw.setErr = fmt.Errorf("gateway login: %w", contracts.ErrGatewayAuth)
	setAppendErr(r.led, diskFull)
	_, err = r.m.SetGatewayNotification(ctx, true, "operator via web")
	setAppendErr(r.led, nil)
	if !errors.Is(err, contracts.ErrGatewayAuth) || errors.Is(err, contracts.ErrNotRecorded) {
		t.Fatalf("gateway failure: %v", err)
	}
}

// ---------------------------------------------------------------------------- 6. anchor trust

// Only anchors whose token verified and whose TSA chained to a trusted root count: anchors
// without a trusted chain are recorded, never "last anchor", and while the newest rounds are
// all untrusted the dashboard warns (ANCHOR_UNTRUSTED). The rebuild agrees.
func TestAnchorTrust(t *testing.T) {
	ctx := context.Background()
	r := newRig(t, nil, nil)
	var mu sync.Mutex
	untrusted := map[string]bool{"http://tsa.test/a": true, "http://tsa.test/b": true}
	setUntrusted := func(u string, v bool) {
		mu.Lock()
		untrusted[u] = v
		mu.Unlock()
	}
	r.m.anchorer = chainlessAnchorer{r.anc, func(u string) bool { mu.Lock(); defer mu.Unlock(); return untrusted[u] }}
	cond := func(st model.Status) *model.Condition {
		for i := range st.Conditions {
			if st.Conditions[i].Code == condAnchorUntrusted {
				return &st.Conditions[i]
			}
		}
		return nil
	}
	anchors, err := r.m.AnchorNow(ctx, "manual")
	if err != nil || len(anchors) != 2 || !anchors[0].Verified || anchors[0].ChainOK {
		t.Fatalf("anchors %+v err %v", anchors, err)
	}
	first := ofType(r.led.records(""), model.TypeAnchor)
	st := r.m.Status()
	c := cond(st)
	if st.Ledger.LastAnchorTime != "" || st.Ledger.LastAnchorSeq != 0 || st.Ledger.UnanchoredCount != st.Ledger.HeadSeq+1 {
		t.Fatalf("untrusted anchors counted: %+v", st.Ledger)
	}
	if c == nil || c.Severity != "warning" || !strings.Contains(strings.ToLower(c.Message), "time-stamps obtained but their authority could not be verified") ||
		c.Seq != first[1].Seq || c.Since != first[0].TS {
		t.Fatalf("condition %+v", c)
	}
	r.m.heartbeat()
	if hb := decode[model.Heartbeat](t, lastOfType(t, r, model.TypeHeartbeat)); hb.LastAnchor != "" {
		t.Fatalf("heartbeat names an untrusted anchor: %+v", hb)
	}

	// A round with one trusted TSA: it is the last anchor, the warning clears.
	setUntrusted("http://tsa.test/b", false)
	covered := r.led.Head()
	if _, err := r.m.AnchorNow(ctx, "manual"); err != nil {
		t.Fatal(err)
	}
	st = r.m.Status()
	if st.Ledger.LastAnchorTSA != "CN=http://tsa.test/b" || st.Ledger.LastAnchorSeq != covered.Seq || st.Ledger.LastAnchorTime == "" || cond(st) != nil {
		t.Fatalf("after a trusted round: %+v %+v", st.Ledger, cond(st))
	}
	// The newest round untrusted again: the warning is back, the last anchor stays the trusted one.
	setUntrusted("http://tsa.test/b", true)
	if _, err := r.m.AnchorNow(ctx, "manual"); err != nil {
		t.Fatal(err)
	}
	st = r.m.Status()
	all := ofType(r.led.records(""), model.TypeAnchor)
	if c := cond(st); c == nil || c.Since != all[4].TS || st.Ledger.LastAnchorSeq != covered.Seq || st.Ledger.UnanchoredCount != st.Ledger.HeadSeq-covered.Seq {
		t.Fatalf("after an untrusted round: %+v %+v", st.Ledger, c)
	}
	m2, err := New(Options{Config: r.cfg, Ledger: r.led, Gateway: &fakeGateway{}, Prober: newFakeProber()})
	if err != nil {
		t.Fatal(err)
	}
	m2.rebuild(time.Now())
	st2 := m2.Status()
	if c2 := cond(st2); c2 == nil || c2.Since != all[4].TS || st2.Ledger.LastAnchorSeq != covered.Seq || st2.Ledger.LastAnchorTSA != "CN=http://tsa.test/b" {
		t.Fatalf("rebuilt: %+v %+v", st2.Ledger, c2)
	}
}

// ---------------------------------------------------------------------------- 7. notification confirmed daily

// A check that finds the setting unchanged records it (before == after, "confirmed
// unchanged") when the latest record about it is at least 24 h old, at most once per 24 h.
func TestNotificationConfirmedDaily(t *testing.T) {
	ctx := context.Background()
	r, clk := clockRig(t, time.Date(2026, 10, 5, 3, 0, 0, 0, time.UTC))
	r.cfg.Gateway.AccessCodeProtected = "protected-blob"
	events := func() []model.GatewayEvent {
		var out []model.GatewayEvent
		for _, b := range ofType(r.led.records(""), model.TypeGatewayEvent) {
			out = append(out, decode[model.GatewayEvent](t, b))
		}
		return out
	}
	start := clk.Now()
	if err := r.m.checkNotification(ctx); err != nil || len(events()) != 1 || events()[0].After != "off" || events()[0].Before != "" {
		t.Fatalf("first observation: %v %+v", err, events())
	}
	clk.Set(start.Add(23 * time.Hour))
	if err := r.m.checkNotification(ctx); err != nil || len(events()) != 1 {
		t.Fatalf("within 24 h: %v %d events", err, len(events()))
	}
	clk.Set(start.Add(24 * time.Hour))
	if err := r.m.checkNotification(ctx); err != nil {
		t.Fatal(err)
	}
	evs := events()
	confirm := lastOfType(t, r, model.TypeGatewayEvent)
	if len(evs) != 2 || evs[1].Kind != model.GwEvNotificationSetting || evs[1].Before != "off" || evs[1].After != "off" ||
		!strings.HasPrefix(evs[1].Detail, "confirmed unchanged") || len(confirm.Blobs) != 1 {
		t.Fatalf("confirmation %+v blobs %v", evs, confirm.Blobs)
	}
	if st := r.m.Status(); st.Notification == nil || st.Notification.Seq != confirm.Seq {
		t.Fatalf("state %+v", st.Notification)
	}
	clk.Set(start.Add(47 * time.Hour))
	if err := r.m.checkNotification(ctx); err != nil || len(events()) != 2 {
		t.Fatal("at most one confirmation per 24 h")
	}
	// A restarted monitor knows when the setting was last recorded.
	m2, err := New(Options{Config: r.cfg, Ledger: r.led, Gateway: r.gw, Prober: newFakeProber(), Now: clk.Now})
	if err != nil {
		t.Fatal(err)
	}
	m2.notifMinInterval = time.Millisecond
	m2.rebuild(clk.Now())
	if err := m2.checkNotification(ctx); err != nil || len(events()) != 2 {
		t.Fatal("the rebuilt monitor must not confirm again within 24 h")
	}
	clk.Set(start.Add(48 * time.Hour))
	if err := m2.checkNotification(ctx); err != nil || len(events()) != 3 {
		t.Fatalf("second confirmation: %v %d", err, len(events()))
	}
}

// ---------------------------------------------------------------------------- 8. Run's lifetime

// Run returns only once its context is done (a return makes the Windows service stop): failing
// probes, a panicking gateway client and a ledger that rejects records after monitor_start do
// not end it - short of ledgerFailExit (5 minutes) of refused records, which
// TestRunEndsWhenTheLedgerStaysUnusable covers.
func TestRunReturnsOnlyAfterContextDone(t *testing.T) {
	r := newRig(t, nil, nil)
	r.pr.ping = func(string) model.ProbeResult { panic("prober bug") }
	r.gw.snap = func(int, []string, string) (model.GatewaySnapshot, map[string][]byte, error) {
		panic("gateway client bug")
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
	setAppendErr(r.led, errors.New("disk full"))
	select {
	case err := <-done:
		t.Fatalf("Run returned (%v) before its context was done", err)
	case <-time.After(800 * time.Millisecond):
	}
	cancel()
	select {
	case <-done: // monitor_stop cannot be recorded: an error after the context is done is allowed
	case <-time.After(20 * time.Second):
		t.Fatal("Run did not return after its context was done")
	}
}

// ---------------------------------------------------------------------------- 9. gateway error sentinels

// The notification check backs off by what the gateway answered (errors.Is on the contracts
// sentinels, however they are wrapped), never sooner than the floor.
func TestNotificationBackoffBySentinel(t *testing.T) {
	r := newRig(t, nil, nil)
	r.m.notifMinInterval = time.Minute
	for _, tc := range []struct {
		err  error
		want time.Duration
	}{
		{fmt.Errorf("login: %w", contracts.ErrGatewayAuth), time.Hour},
		{fmt.Errorf("gateway: %w", contracts.ErrGatewayAuthLocked), time.Hour},
		{errors.Join(errors.New("events.ha"), contracts.ErrGatewaySessionsFull), 5 * time.Minute},
		{fmt.Errorf("x: %w", contracts.ErrGatewayLoginThrottled), 5 * time.Minute},
		{fmt.Errorf("x: %w", contracts.ErrGatewayNoAccessCode), time.Minute},
		{errors.New("all web server sessions are in use"), time.Minute}, // text alone is not trusted
	} {
		if got := r.m.notifRetryAfter(tc.err); got != tc.want {
			t.Errorf("%v: retry after %v, want %v", tc.err, got, tc.want)
		}
	}
	r.m.notifMinInterval = 2 * time.Hour
	if got := r.m.notifRetryAfter(fmt.Errorf("x: %w", contracts.ErrGatewayAuth)); got != 2*time.Hour {
		t.Errorf("the floor wins: %v", got)
	}
}

// The gateway client reporting that no usable access code is stored shows NO_ACCESS_CODE (the
// redirect setting cannot be checked) even though a code is configured; it clears once a
// check succeeds.
func TestNoUsableAccessCodeCondition(t *testing.T) {
	r := newRig(t, nil, nil)
	r.cfg.Gateway.AccessCodeProtected = "protected-blob"
	r.gw.notifErr = fmt.Errorf("cannot decrypt the stored access code: %w", contracts.ErrGatewayNoAccessCode)
	if err := r.m.checkNotification(context.Background()); !errors.Is(err, contracts.ErrGatewayNoAccessCode) {
		t.Fatalf("err %v", err)
	}
	find := func() *model.Condition {
		for _, c := range r.m.Status().Conditions {
			if c.Code == condNoAccessCode {
				return &c
			}
		}
		return nil
	}
	if c := find(); c == nil || !strings.Contains(c.Message, "could not be used") || !strings.Contains(c.Message, "cannot decrypt") {
		t.Fatalf("condition %+v", c)
	}
	r.gw.notifErr = nil
	if err := r.m.checkNotification(context.Background()); err != nil {
		t.Fatal(err)
	}
	if c := find(); c != nil {
		t.Fatalf("condition still shown: %+v", c)
	}
}
