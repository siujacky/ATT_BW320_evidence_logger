package monitor

import (
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"attmonitor/internal/config"
	"attmonitor/internal/model"
)

var t0 = time.Date(2026, 10, 5, 3, 20, 0, 0, time.UTC)

func vd(state, cause, attr string) model.Verdict {
	return model.Verdict{State: state, Cause: cause, Attribution: attr, Rules: RulesVersion, Reasons: []string{"reason for " + state + "/" + cause}}
}

var (
	vGood     = vd(model.StateOnline, "", model.AttrNone)
	vUnknown  = vd(model.StateUnknown, "", model.AttrUndetermined)
	vWAN      = vd(model.StateISPOutage, model.CauseWANDown, model.AttrProvider)
	vUpstream = vd(model.StateISPOutage, model.CauseUpstreamUnreachable, model.AttrProvider)
	vFiber    = vd(model.StateISPOutage, model.CauseFiberLinkDown, model.AttrProvider)
	vLossP    = vd(model.StateDegraded, model.CausePacketLoss, model.AttrProvider)
	vLossU    = vd(model.StateDegraded, model.CausePacketLoss, model.AttrUndetermined)
	vGwUnr    = vd(model.StateLocalFault, model.CauseGatewayUnreachable, model.AttrUndetermined)
	vLinkDown = vd(model.StateLocalFault, model.CauseLocalLinkDown, model.AttrLocal)
)

// feeder drives a tracker with cycles 10 s apart; cycle i starts at t0+10i s and its sample
// has seq 100+i.
type feeder struct {
	t    *testing.T
	tr   *tracker
	i    int
	acts []action
	tags []string
}

func newFeeder(t *testing.T, openAfter, closeAfter int) *feeder {
	return &feeder{t: t, tr: newTracker(openAfter, closeAfter, 6, 10*time.Second, nil)}
}

func startOf(i int) time.Time { return t0.Add(time.Duration(i) * 10 * time.Second) }

func (f *feeder) feed(vs ...model.Verdict) []action {
	var out []action
	for _, v := range vs {
		start := startOf(f.i)
		f.tags = append(f.tags, f.tr.peekTag(start, v))
		probes := []model.ProbeResult{
			{Name: "gateway_icmp", Role: model.RoleGateway, OK: v.State != model.StateLocalFault},
			{Name: "inet_icmp_google", Role: model.RoleInet, OK: v.State == model.StateOnline || v.State == model.StateDegraded},
		}
		acts := f.tr.observe(cycleObs{Start: start, TS: start.Add(400 * time.Millisecond), Seq: uint64(100 + f.i), Verdict: v, Probes: probes})
		out = append(out, acts...)
		f.acts = append(f.acts, acts...)
		f.i++
	}
	return out
}

func kinds(acts []action) []actionKind {
	var k []actionKind
	for _, a := range acts {
		k = append(k, a.kind)
	}
	return k
}

func TestTrackerBlips(t *testing.T) {
	f := newFeeder(t, 3, 3)
	// Two bad cycles, then six good ones: the bad cycles leave the 6-cycle window without a
	// third one joining them, so they never open an incident (blips).
	if acts := f.feed(vGood, vWAN, vWAN, vGood, vGood, vGood, vGood, vGood, vGood); len(acts) != 0 {
		t.Fatalf("two bad cycles must not open an incident: %v", kinds(acts))
	}
	if f.tr.blipCycles != 2 {
		t.Fatalf("blip cycles %d, want 2", f.tr.blipCycles)
	}
	// A third bad cycle more than 6 cycles after the first one does not open an incident either.
	f2 := newFeeder(t, 3, 3)
	if acts := f2.feed(vLossP, vGood, vGood, vGood, vGood, vGood, vWAN, vWAN); len(acts) != 0 {
		t.Fatalf("bad cycles 6 cycles apart: %v", kinds(acts))
	}
	if f2.tr.blipCycles != 1 {
		t.Fatalf("blip cycles %d, want 1 (the first bad cycle left the window)", f2.tr.blipCycles)
	}
	for i, tag := range append(f.tags, f2.tags...) {
		if tag != "" {
			t.Fatalf("cycle %d tagged %q without an incident", i, tag)
		}
	}
}

// TestTrackerFlapping: at least 3 bad cycles within the last 6 open an incident even when
// they are not consecutive (DESIGN §10); opened = the start of the earliest of them and the
// good cycles in between belong to the incident.
func TestTrackerFlapping(t *testing.T) {
	f := newFeeder(t, 3, 3)
	if acts := f.feed(vGood, vWAN, vGood, vLossP, vGood); len(acts) != 0 {
		t.Fatalf("two bad cycles: %v", kinds(acts))
	}
	if tag := f.tr.peekTag(startOf(5), vWAN); tag != incidentID(startOf(1)) {
		t.Fatalf("peekTag %q, want the id from the earliest bad cycle", tag)
	}
	acts := f.feed(vWAN) // cycle 5: bad cycles 1, 3, 5 within the last 6
	if len(acts) != 1 || acts[0].kind != actOpen {
		t.Fatalf("want open, got %v", kinds(acts))
	}
	if f.tags[5] != incidentID(startOf(1)) {
		t.Fatalf("tag of the opening cycle %q", f.tags[5])
	}
	inc := acts[0].st.payload(startOf(5), false)
	if inc.Opened != fmtTS(startOf(1)) || inc.FirstSeq != 101 || inc.Stats.Cycles != 5 || inc.Stats.BadCycles != 3 {
		t.Fatalf("opened %s first %d stats %+v", inc.Opened, inc.FirstSeq, inc.Stats)
	}
	if inc.State != model.StateISPOutage || inc.Cause != model.CauseWANDown || !slices.Equal(inc.Causes, []string{model.CauseWANDown, model.CausePacketLoss}) {
		t.Fatalf("headline %s/%s causes %v", inc.State, inc.Cause, inc.Causes)
	}
	var notes []string
	for _, e := range inc.Evidence {
		if e.Type == model.TypeSample {
			notes = append(notes, fmt.Sprintf("%d:%s", e.Seq, e.Note))
		}
	}
	if !slices.Equal(notes, []string{"101:first bad cycle", "103:bad cycle", "105:bad cycle that opened the incident"}) {
		t.Fatalf("sample evidence %v", notes)
	}
	// Flapping goes on: a bad cycle between good ones keeps the incident open.
	if acts := f.feed(vGood, vGood, vWAN, vGood, vGood); len(acts) != 0 {
		t.Fatalf("closed too early: %v", kinds(acts))
	}
	acts = f.feed(vGood)
	if len(acts) != 1 || acts[0].kind != actClose {
		t.Fatalf("want close, got %v", kinds(acts))
	}
	if inc := acts[0].st.payload(startOf(12), false); inc.Closed != fmtTS(startOf(9)) || inc.Stats.BadCycles != 4 || inc.Stats.Cycles != 8 {
		t.Fatalf("closed %s stats %+v", inc.Closed, inc.Stats)
	}
}

// TestTrackerTimeAccounting: each cycle covers the time until the next cycle started, capped
// at 1.5 × the fast interval; ISP_OUTAGE time is downtime and DEGRADED time degraded time.
func TestTrackerTimeAccounting(t *testing.T) {
	tr := newTracker(3, 3, 6, 10*time.Second, nil)
	feed := func(at time.Duration, seq uint64, v model.Verdict) []action {
		return tr.observe(cycleObs{Start: t0.Add(at), TS: t0.Add(at), Seq: seq, Verdict: v})
	}
	feed(0, 1, vWAN)
	feed(10*time.Second, 2, vGood)
	feed(20*time.Second, 3, vLossP)
	acts := feed(30*time.Second, 4, vWAN) // opens: bad cycles 1, 3, 4
	if len(acts) != 1 || acts[0].kind != actOpen {
		t.Fatalf("want open, got %v", kinds(acts))
	}
	st := acts[0].st
	if p := st.payload(t0, false); p.Stats.DowntimeSec != 10 || p.Stats.DegradedSec != 10 {
		t.Fatalf("at open: downtime %d degraded %d (the opening cycle is not settled yet)", p.Stats.DowntimeSec, p.Stats.DegradedSec)
	}
	feed(70*time.Second, 5, vWAN) // 40 s later: the previous cycle covers 15 s at most
	feed(80*time.Second, 6, vGood)
	feed(90*time.Second, 7, vGood)
	acts = feed(100*time.Second, 8, vGood)
	if len(acts) != 1 || acts[0].kind != actClose {
		t.Fatalf("want close, got %v", kinds(acts))
	}
	p := st.payload(t0, false)
	if p.Stats.DowntimeSec != 10+15+10 || p.Stats.DegradedSec != 10 {
		t.Fatalf("downtime %d degraded %d", p.Stats.DowntimeSec, p.Stats.DegradedSec)
	}
	if p.DurationSec != 80 || !strings.Contains(p.Summary, "Measured time: 35s without Internet (ISP_OUTAGE cycles), 10s degraded (DEGRADED cycles).") {
		t.Fatalf("duration %d summary %q", p.DurationSec, p.Summary)
	}
}

// TestTrackerRecoveredAt: recovered_at is the start of the first cycle after the last outage
// cycle in which every probe succeeded (DESIGN §10).
func TestTrackerRecoveredAt(t *testing.T) {
	allOK := []model.ProbeResult{{Name: "gateway_icmp", OK: true}, {Name: "inet_icmp_google", OK: true}}
	oneFailed := []model.ProbeResult{{Name: "gateway_icmp", OK: false}, {Name: "gateway_tcp", OK: true}, {Name: "inet_icmp_google", OK: true}}
	tr := newTracker(3, 3, 6, 10*time.Second, nil)
	i := 0
	feed := func(v model.Verdict, probes []model.ProbeResult) []action {
		at := startOf(i)
		i++
		return tr.observe(cycleObs{Start: at, TS: at, Seq: uint64(100 + i), Verdict: v, Probes: probes})
	}
	var acts []action
	for _, v := range []model.Verdict{vWAN, vWAN, vWAN} {
		acts = feed(v, nil)
	}
	st := acts[0].st
	feed(vGood, oneFailed)    // 3: good, but not every probe succeeded
	feed(vLossP, allOK)       // 4: DEGRADED (window loss) with every probe ok: recovered here
	feed(vWAN, nil)           // 5: an outage cycle again: recovery starts over
	feed(vGood, allOK)        // 6
	feed(vGood, allOK)        // 7
	acts = feed(vGood, allOK) // 8: closes at 6
	if len(acts) != 1 || acts[0].kind != actClose {
		t.Fatalf("want close, got %v", kinds(acts))
	}
	p := st.payload(t0, false)
	if p.RecoveredAt != fmtTS(startOf(6)) || p.Closed != fmtTS(startOf(6)) || !strings.Contains(p.Summary, "All probes succeeded again from "+fmtHuman(startOf(6))) {
		t.Fatalf("recovered %s closed %s summary %q", p.RecoveredAt, p.Closed, p.Summary)
	}
	// A DEGRADED-only incident has no outage cycle: no recovered_at.
	f := newFeeder(t, 3, 3)
	dst := f.feed(vLossP, vLossP, vLossP)[0].st
	f.feed(vGood, vGood, vGood)
	if p := dst.payload(t0, false); p.RecoveredAt != "" {
		t.Fatalf("recovered_at %q without an outage cycle", p.RecoveredAt)
	}
}

func TestTrackerOpenAndCloseBackdated(t *testing.T) {
	f := newFeeder(t, 3, 3)
	f.feed(vGood, vWAN, vWAN) // cycles 0..2
	acts := f.feed(vWAN)      // cycle 3 opens: first bad cycle was cycle 1
	if len(acts) != 1 || acts[0].kind != actOpen {
		t.Fatalf("want open, got %v", kinds(acts))
	}
	st := acts[0].st
	inc := st.payload(startOf(3), false)
	if inc.ID != "INC-20261005-032010Z" {
		t.Fatalf("id %q", inc.ID)
	}
	if inc.Opened != fmtTS(startOf(1)) || inc.FirstSeq != 101 || !inc.Open {
		t.Fatalf("opened %s first_seq %d open %v", inc.Opened, inc.FirstSeq, inc.Open)
	}
	if f.tags[2] != "" || f.tags[3] != inc.ID {
		t.Fatalf("tags %q: the opening cycle must carry the id, earlier ones not", f.tags)
	}
	if inc.State != model.StateISPOutage || inc.Cause != model.CauseWANDown || inc.Attribution != model.AttrProvider {
		t.Fatalf("headline %s/%s/%s", inc.State, inc.Cause, inc.Attribution)
	}
	if inc.Stats.Cycles != 3 || inc.Stats.BadCycles != 3 || inc.Stats.ProbeTotal["gateway_icmp"] != 3 || inc.Stats.ProbeOK["inet_icmp_google"] != 0 {
		t.Fatalf("stats %+v", inc.Stats)
	}
	var sampleRefs []uint64
	for _, e := range inc.Evidence {
		if e.Type == model.TypeSample {
			sampleRefs = append(sampleRefs, e.Seq)
		}
	}
	if !slices.Equal(sampleRefs, []uint64{101, 102, 103}) {
		t.Fatalf("evidence samples %v", sampleRefs)
	}
	if !strings.HasPrefix(inc.Summary, "Ongoing ISP outage since 2026-10-05 03:20:10 UTC, cause WAN_DOWN") ||
		!strings.Contains(inc.Summary, "Attributed to the provider (AT&T).") {
		t.Fatalf("summary %q", inc.Summary)
	}

	// Recovery: three good cycles 4, 5, 6 close it with closed = start of cycle 4.
	if acts := f.feed(vGood, vGood); len(acts) != 0 {
		t.Fatalf("closed too early: %v", kinds(acts))
	}
	if f.tags[4] != inc.ID || f.tags[5] != inc.ID {
		t.Fatal("cycles of the closing streak belong to the open incident")
	}
	acts = f.feed(vGood)
	if len(acts) != 1 || acts[0].kind != actClose {
		t.Fatalf("want close, got %v", kinds(acts))
	}
	closed := acts[0].st.payload(startOf(7), false)
	if closed.Closed != fmtTS(startOf(4)) || closed.Open || closed.DurationSec != 30 || closed.LastSeq != 106 {
		t.Fatalf("closed %s open %v dur %d last %d", closed.Closed, closed.Open, closed.DurationSec, closed.LastSeq)
	}
	if closed.Stats.Cycles != 3 || closed.Stats.BadCycles != 3 {
		t.Fatalf("closing streak must not count as incident cycles: %+v", closed.Stats)
	}
	if !strings.HasPrefix(closed.Summary, "ISP outage from 2026-10-05 03:20:10 UTC to 2026-10-05 03:20:40 UTC (30s), cause WAN_DOWN") {
		t.Fatalf("summary %q", closed.Summary)
	}
	if f.tr.open != nil || f.tr.blipCycles != 0 {
		t.Fatal("tracker state after close")
	}
	if tag := f.tr.peekTag(startOf(8), vGood); tag != "" {
		t.Fatalf("tag after close %q", tag)
	}
}

func TestTrackerInterruptedRecovery(t *testing.T) {
	f := newFeeder(t, 3, 3)
	f.feed(vWAN, vWAN, vWAN) // 0..2 open
	if acts := f.feed(vGood, vGood, vWAN); len(acts) != 0 {
		t.Fatalf("unexpected %v", kinds(acts))
	}
	acts := f.feed(vGood, vGood, vGood) // 6, 7, 8
	if len(acts) != 1 || acts[0].kind != actClose {
		t.Fatalf("want close, got %v", kinds(acts))
	}
	inc := acts[0].st.payload(startOf(9), false)
	if inc.Closed != fmtTS(startOf(6)) {
		t.Fatalf("closed %s, want start of the last good streak %s", inc.Closed, fmtTS(startOf(6)))
	}
	// Cycles 0..5 belong to the incident: 4 bad + 2 good that were followed by a bad cycle.
	if inc.Stats.Cycles != 6 || inc.Stats.BadCycles != 4 {
		t.Fatalf("stats %+v", inc.Stats)
	}
}

func TestTrackerEscalationAndCauses(t *testing.T) {
	f := newFeeder(t, 3, 3)
	acts := f.feed(vLossP, vLossP, vLossP)
	if len(acts) != 1 || acts[0].kind != actOpen {
		t.Fatalf("want open, got %v", kinds(acts))
	}
	st := acts[0].st
	if p := st.payload(t0, false); p.State != model.StateDegraded || p.Attribution != model.AttrProvider {
		t.Fatalf("headline %s/%s", p.State, p.Attribution)
	}
	acts = f.feed(vUpstream) // escalation DEGRADED -> ISP_OUTAGE
	if len(acts) != 1 || acts[0].kind != actUpdate {
		t.Fatalf("want update, got %v", kinds(acts))
	}
	if p := st.payload(t0, false); p.State != model.StateISPOutage || p.Cause != model.CauseUpstreamUnreachable || p.Attribution != model.AttrProvider {
		t.Fatalf("after escalation %s/%s/%s", p.State, p.Cause, p.Attribution)
	}
	if acts := f.feed(vLossU); len(acts) != 0 {
		t.Fatal("no de-escalation")
	}
	if acts := f.feed(vWAN); len(acts) != 1 || acts[0].kind != actUpdate {
		t.Fatal("WAN_DOWN is more specific than UPSTREAM_UNREACHABLE")
	}
	if acts := f.feed(vUpstream); len(acts) != 0 {
		t.Fatal("a less specific cause must not change the headline")
	}
	if acts := f.feed(vFiber); len(acts) != 1 {
		t.Fatal("FIBER_LINK_DOWN is the most specific outage cause")
	}
	p := st.payload(t0, false)
	if p.Cause != model.CauseFiberLinkDown {
		t.Fatalf("cause %s", p.Cause)
	}
	want := []string{model.CausePacketLoss, model.CauseUpstreamUnreachable, model.CauseWANDown, model.CauseFiberLinkDown}
	if !slices.Equal(p.Causes, want) {
		t.Fatalf("causes %v want %v", p.Causes, want)
	}
	if len(p.Reasons) != 1 || p.Reasons[0] != "reason for ISP_OUTAGE/FIBER_LINK_DOWN" {
		t.Fatalf("reasons of the headline verdict: %q", p.Reasons)
	}
	var headlineNotes int
	for _, e := range p.Evidence {
		if strings.HasPrefix(e.Note, "headline changed") {
			headlineNotes++
		}
	}
	if headlineNotes != 3 {
		t.Fatalf("headline change evidence %d, want 3: %+v", headlineNotes, p.Evidence)
	}
}

func TestTrackerDegradedAttributionMajority(t *testing.T) {
	f := newFeeder(t, 3, 3)
	st := f.feed(vLossP, vLossU, vLossU)[0].st
	p := st.payload(t0, false)
	if p.Attribution != model.AttrUndetermined || !strings.Contains(p.Summary, "1 of 3 degraded cycles had a loss-free path") {
		t.Fatalf("1/3 provider: %s %q", p.Attribution, p.Summary)
	}
	f.feed(vLossP, vLossP)
	if p := st.payload(t0, false); p.Attribution != model.AttrProvider {
		t.Fatalf("3/5 provider: %s", p.Attribution)
	}
}

func TestTrackerLocalAttribution(t *testing.T) {
	f := newFeeder(t, 3, 3)
	st := f.feed(vGwUnr, vGwUnr, vGwUnr)[0].st
	if p := st.payload(t0, false); p.Cause != model.CauseGatewayUnreachable || p.Attribution != model.AttrUndetermined {
		t.Fatalf("%s/%s", p.Cause, p.Attribution)
	}
	f.feed(vLinkDown)
	p := st.payload(t0, false)
	if p.Cause != model.CauseLocalLinkDown || p.Attribution != model.AttrLocal || !p.Stats.LocalLinkDown {
		t.Fatalf("%s/%s link_down=%v", p.Cause, p.Attribution, p.Stats.LocalLinkDown)
	}
	// An ISP outage later in the same incident outranks the local fault.
	f.feed(vWAN)
	if p := st.payload(t0, false); p.State != model.StateISPOutage || p.Attribution != model.AttrProvider {
		t.Fatalf("%s/%s", p.State, p.Attribution)
	}
}

func TestTrackerUnknownIsNeutral(t *testing.T) {
	f := newFeeder(t, 3, 3)
	if acts := f.feed(vWAN, vWAN, vUnknown); len(acts) != 0 {
		t.Fatal("UNKNOWN must not count as bad")
	}
	acts := f.feed(vWAN)
	if len(acts) != 1 || acts[0].kind != actOpen {
		t.Fatalf("third bad cycle opens: %v", kinds(acts))
	}
	if acts := f.feed(vGood, vUnknown, vGood); len(acts) != 0 {
		t.Fatal("UNKNOWN must not count as good")
	}
	if acts := f.feed(vGood); len(acts) != 1 || acts[0].kind != actClose {
		t.Fatal("third good cycle closes")
	}
}

func TestTrackerOneCycleThresholds(t *testing.T) {
	f := newFeeder(t, 1, 1)
	acts := f.feed(vWAN)
	if len(acts) != 1 || acts[0].kind != actOpen || f.tags[0] == "" {
		t.Fatalf("open after 1: %v tags %q", kinds(acts), f.tags)
	}
	acts = f.feed(vGood)
	if len(acts) != 1 || acts[0].kind != actClose {
		t.Fatalf("close after 1: %v", kinds(acts))
	}
	if inc := acts[0].st.payload(t0, false); inc.Closed != fmtTS(startOf(1)) || inc.DurationSec != 10 {
		t.Fatalf("closed %s dur %d", inc.Closed, inc.DurationSec)
	}
}

func TestTrackerInterrupt(t *testing.T) {
	f := newFeeder(t, 3, 3)
	f.feed(vWAN, vWAN, vWAN, vWAN) // cycles 0..3, last bad sample ts = start(3)+400ms
	acts := f.tr.interrupt(discontinuity{gap: 2 * time.Hour, elapsed: 2 * time.Hour})
	if len(acts) != 1 || acts[0].kind != actClose {
		t.Fatalf("want close, got %v", kinds(acts))
	}
	// Closed at the end of the time its last bad cycle covers (its start plus at most 1.5 fast
	// intervals, as in the time accounting), not at the time the sample was recorded.
	inc := acts[0].st.payload(t0, false)
	if inc.Closed != fmtTS(startOf(3).Add(15*time.Second)) || inc.Open || inc.Stats.DowntimeSec != 40-10+15 {
		t.Fatalf("closed %s downtime %d", inc.Closed, inc.Stats.DowntimeSec)
	}
	if !strings.Contains(inc.Summary, "Monitoring was interrupted for 2h0m0s") || !strings.Contains(inc.Summary, "outcome during the interruption is unknown") {
		t.Fatalf("summary %q", inc.Summary)
	}

	// Recovery seen but not confirmed: closed at the first good cycle.
	f2 := newFeeder(t, 3, 3)
	f2.feed(vWAN, vWAN, vWAN, vGood)
	acts = f2.tr.interrupt(discontinuity{gap: time.Hour})
	if inc := acts[0].st.payload(t0, false); inc.Closed != fmtTS(startOf(3)) || inc.LastSeq != 103 || !strings.Contains(inc.Summary, "Recovery was observed but not yet confirmed") {
		t.Fatalf("closed %s last %d summary %q", inc.Closed, inc.LastSeq, inc.Summary)
	}

	// Bad cycles of the window that did not open an incident end as blips.
	f3 := newFeeder(t, 3, 3)
	f3.feed(vWAN, vGood, vWAN)
	if acts := f3.tr.interrupt(discontinuity{gap: time.Hour}); len(acts) != 0 || f3.tr.blipCycles != 2 {
		t.Fatalf("acts %v blip cycles %d", kinds(acts), f3.tr.blipCycles)
	}
	if len(f3.tr.recent) != 0 {
		t.Fatal("the window restarts after a discontinuity")
	}
	// The last cycle before the gap covers at most 1.5 fast intervals.
	f4 := newFeeder(t, 3, 3)
	st := f4.feed(vWAN, vWAN, vWAN)[0].st
	f4.tr.interrupt(discontinuity{gap: time.Hour, elapsed: time.Hour})
	if p := st.payload(t0, false); p.Stats.DowntimeSec != 10+10+15 {
		t.Fatalf("downtime %d", p.Stats.DowntimeSec)
	}
}

func TestTrackerIDCollision(t *testing.T) {
	taken := map[string]bool{"INC-20261005-032000Z": true, "INC-20261005-032000Z-2": true}
	tr := newTracker(1, 1, 6, 10*time.Second, func(id string) bool { return taken[id] })
	if tag := tr.peekTag(t0, vWAN); tag != "INC-20261005-032000Z-3" {
		t.Fatalf("tag %q", tag)
	}
	acts := tr.observe(cycleObs{Start: t0, Seq: 1, Verdict: vWAN})
	if acts[0].st.inc.ID != "INC-20261005-032000Z-3" {
		t.Fatalf("id %q", acts[0].st.inc.ID)
	}
}

func TestEvidenceListCap(t *testing.T) {
	var e evidenceList
	for i := 0; i < 100; i++ {
		e.addGroup(model.TypeGatewaySnapshot, uint64(i), []model.EvidenceRef{
			{Seq: uint64(i), Type: model.TypeGatewaySnapshot},
			{Seq: uint64(i), Type: model.TypeGatewaySnapshot, Blob: "b" + string(rune('a'+i%26))},
		})
		e.add(model.EvidenceRef{Seq: uint64(1000 + i), Type: model.TypeSample})
	}
	e.add(model.EvidenceRef{Seq: 1000, Type: model.TypeSample}) // duplicate ignored
	seqs := map[string]map[uint64]bool{}
	for _, r := range e.refs {
		if seqs[r.Type] == nil {
			seqs[r.Type] = map[uint64]bool{}
		}
		seqs[r.Type][r.Seq] = true
	}
	for typ, s := range seqs {
		if len(s) != maxEvidenceSeqsPerType {
			t.Errorf("%s: %d seqs, want %d", typ, len(s), maxEvidenceSeqsPerType)
		}
	}
	if !seqs[model.TypeGatewaySnapshot][0] || !seqs[model.TypeGatewaySnapshot][99] || seqs[model.TypeGatewaySnapshot][50] {
		t.Error("cap must keep the first records and the most recent one")
	}
	sorted := e.sorted()
	if !slices.IsSortedFunc(sorted, func(a, b model.EvidenceRef) int { return int(a.Seq) - int(b.Seq) }) {
		t.Error("evidence not sorted by seq")
	}
}

// ---------------------------------------------------------------------------- gateway restarts (rules 2026.10-3)

// closedLocal is a closed LOCAL_FAULT incident: cycles 0-2 bad, closed at start(3) = t0+30s.
func closedLocal(cause string) *incState {
	f := newFeeder(nil, 3, 3)
	v := vd(model.StateLocalFault, cause, model.AttrUndetermined)
	if cause == model.CauseLocalLinkDown {
		v.Attribution = model.AttrLocal
	}
	st := f.feed(v, v, v)[0].st
	f.feed(vGood, vGood, vGood)
	return st
}

// restartAt is a recorded gateway restart at boot (reboot event #900, snapshots #899 → #901).
func restartAt(boot time.Time, fwBefore, fwAfter string) restartInfo {
	return restartInfo{Boot: boot, Detected: boot.Add(time.Minute), Uptime: 60, EventSeq: 900, SnapSeq: 901, PrevSeq: 899,
		FWBefore: fwBefore, FWAfter: fwAfter}
}

// derivedState is everything recompute derives from the cycles and restarts.
type derivedState struct {
	downtime, degraded, restart                                    time.Duration
	outState, outCause                                             string
	badOutside, badInWindows, providerOutside, degProvider, degTot int
	inWin                                                          []bool
}

func derivedOf(st *incState) derivedState {
	d := derivedState{downtime: st.downtime, degraded: st.degraded, restart: st.restartTime, outState: st.outState, outCause: st.outCause,
		badOutside: st.badOutside, badInWindows: st.badInWindows, providerOutside: st.providerOutside, degProvider: st.degProvider, degTot: st.degTotal}
	for _, c := range st.cycles {
		d.inWin = append(d.inWin, c.inWin)
	}
	return d
}

// checkIncremental: what the incident maintained cycle by cycle equals a full recompute.
func checkIncremental(t *testing.T, st *incState) {
	t.Helper()
	cp := *st
	cp.cycles, cp.wins = slices.Clone(st.cycles), slices.Clone(st.wins)
	cp.recompute()
	if got, want := derivedOf(st), derivedOf(&cp); !reflect.DeepEqual(got, want) {
		t.Fatalf("incremental state differs from a full recompute:\n got  %+v\n want %+v", got, want)
	}
}

func hasEvidence(inc model.Incident, typ string, seq uint64) bool {
	return slices.ContainsFunc(inc.Evidence, func(e model.EvidenceRef) bool { return e.Type == typ && e.Seq == seq })
}

// The owner power-cycles the gateway while the Internet works: the gateway is unreachable,
// then its WAN comes back (FIBER_LINK_DOWN while the PON ranges). Every bad cycle lies in the
// restart window, so the incident is a gateway restart - undetermined, no provider downtime -
// unless the firmware changed across the restart (an AT&T-pushed update: provider).
func TestRestartPowerCycleWhileOnline(t *testing.T) {
	for _, fwChange := range []bool{false, true} {
		f := newFeeder(t, 3, 3)
		f.feed(vGood, vGood)                                   // 0-1
		f.feed(vGwUnr, vGwUnr, vGwUnr, vGwUnr, vGwUnr, vGwUnr) // 2-7: powered off, booting
		st := f.acts[0].st
		f.feed(vFiber, vFiber, vFiber, vFiber, vFiber) // 8-12: LAN up, PON ranging
		if p := st.payload(t0, false); p.State != model.StateISPOutage || p.Cause != model.CauseFiberLinkDown || p.Attribution != model.AttrProvider {
			t.Fatalf("before the restart is known: %s/%s/%s", p.State, p.Cause, p.Attribution)
		}
		f.feed(vGood, vGood, vGood) // 13-15: closes at start(13)
		boot := startOf(4).Add(5 * time.Second)
		fwAfter := "6.34.7"
		if fwChange {
			fwAfter = "6.35.1"
		}
		if !st.attachRestart(restartAt(boot, "6.34.7", fwAfter)) {
			t.Fatal("the restart lies inside the incident")
		}
		p := st.payload(t0, false)
		wantAttr := model.AttrUndetermined
		if fwChange {
			wantAttr = model.AttrProvider
		}
		if p.State != model.StateLocalFault || p.Cause != model.CauseGatewayReboot || p.Attribution != wantAttr {
			t.Fatalf("fw change %v: %s/%s/%s", fwChange, p.State, p.Cause, p.Attribution)
		}
		if p.Stats.DowntimeSec != 0 || p.Stats.RestartSec != 110 || p.Stats.BadCycles != 11 {
			t.Fatalf("fw change %v: stats %+v", fwChange, p.Stats)
		}
		if !slices.Equal(p.GatewayRestarts, []string{fmtTS(boot)}) ||
			!slices.Equal(p.Causes, []string{model.CauseGatewayUnreachable, model.CauseFiberLinkDown, model.CauseGatewayReboot}) {
			t.Fatalf("restarts %v causes %v", p.GatewayRestarts, p.Causes)
		}
		for _, want := range []string{
			"Gateway restart from 2026-10-05 03:20:20 UTC to 2026-10-05 03:22:10 UTC (1m50s), cause GATEWAY_REBOOT",
			"Measured time: 1m50s in gateway restart windows (not counted as an AT&T outage).",
			"The AT&T gateway restarted at about 2026-10-05 03:20:45 UTC (uptime reset)",
			"the 1m50s of bad cycles from 2026-10-05 03:20:20 UTC, when the gateway stopped answering this computer, until 2026-10-05 03:22:10 UTC, when the Internet was reachable again, are counted as restart time, not as an AT&T outage.",
		} {
			if !strings.Contains(p.Summary, want) {
				t.Fatalf("fw change %v: summary lacks %q:\n%s", fwChange, want, p.Summary)
			}
		}
		if strings.Contains(p.Summary, "without Internet") || strings.Contains(p.Summary, "ISP outage") {
			t.Fatalf("a restart must not read as an outage: %s", p.Summary)
		}
		reasons := strings.Join(p.Reasons, "\n")
		if !strings.Contains(reasons, "the AT&T gateway restarted at about 2026-10-05 03:20:45 UTC (uptime reset: at 2026-10-05 03:21:45 UTC it reported 60 s of uptime)") {
			t.Fatalf("reasons %q", p.Reasons)
		}
		if fw := strings.Contains(reasons, "AT&T-pushed firmware update: the gateway firmware changed from 6.34.7 to 6.35.1 across the restart"); fw != fwChange {
			t.Fatalf("firmware reason %v: %q", fw, p.Reasons)
		}
		if fwChange && !strings.Contains(p.Summary, "AT&T-pushed firmware update), so the incident is attributed to the provider") {
			t.Fatalf("summary %s", p.Summary)
		}
		if !fwChange && !strings.Contains(p.Summary, "classified as a gateway restart (GATEWAY_REBOOT); whether the restart was caused locally") {
			t.Fatalf("summary %s", p.Summary)
		}
		if !hasEvidence(p, model.TypeGatewayEvent, 900) || !hasEvidence(p, model.TypeGatewaySnapshot, 901) || !hasEvidence(p, model.TypeGatewaySnapshot, 899) {
			t.Fatalf("evidence %+v", p.Evidence)
		}
		checkIncremental(t, st)
		// The same restart (seen again, e.g. from a later snapshot) changes nothing.
		if st.attachRestart(restartAt(boot.Add(30*time.Second), "", "")) {
			t.Fatal("the same restart was attached twice")
		}
	}
}

// The owner power-cycles the gateway during a real AT&T outage: the outage before the restart
// lies outside the restart window, so the incident stays the provider's, with the headline and
// reasons of that outage (not the FIBER_LINK_DOWN of the boot) and only its time as downtime.
func TestRestartDuringRealOutageStaysProvider(t *testing.T) {
	f := newFeeder(t, 3, 3)
	f.feed(vGood) // 0
	for i := 0; i < 12; i++ {
		f.feed(vWAN) // 1-12: AT&T outage
	}
	st := f.acts[0].st
	f.feed(vGwUnr, vGwUnr, vGwUnr, vGwUnr) // 13-16: the owner power-cycles the gateway
	f.feed(vFiber, vFiber, vFiber, vFiber) // 17-20: booting
	f.feed(vGood, vGood, vGood)            // 21-23: back; closes at start(21)
	if p := st.payload(t0, false); p.Cause != model.CauseFiberLinkDown {
		t.Fatalf("before the restart is known the boot phase is the most specific cause: %s", p.Cause)
	}
	if !st.attachRestart(restartAt(startOf(14).Add(2*time.Second), "6.34.7", "6.34.7")) {
		t.Fatal("attach")
	}
	p := st.payload(t0, false)
	if p.State != model.StateISPOutage || p.Cause != model.CauseWANDown || p.Attribution != model.AttrProvider {
		t.Fatalf("%s/%s/%s", p.State, p.Cause, p.Attribution)
	}
	if p.Stats.DowntimeSec != 120 || p.Stats.RestartSec != 80 {
		t.Fatalf("stats %+v", p.Stats)
	}
	if p.Reasons[0] != "reason for ISP_OUTAGE/WAN_DOWN" || !strings.Contains(strings.Join(p.Reasons, "\n"), "the AT&T gateway restarted at about") {
		t.Fatalf("reasons %q", p.Reasons)
	}
	if !strings.Contains(p.Summary, "12 provider-attributed bad cycles lie outside the restart window, so the classification rests on those cycles, not on the restart.") ||
		!strings.Contains(p.Summary, "Measured time: 2m0s without Internet (ISP_OUTAGE cycles), 1m20s in gateway restart windows") {
		t.Fatalf("summary %s", p.Summary)
	}
	checkIncremental(t, st)
}

// An outage that persists more than 10 minutes after the restart is the provider's: the
// restart window ends 10 minutes after the boot.
func TestRestartOutagePersistingBeyondTheWindowIsProvider(t *testing.T) {
	f := newFeeder(t, 3, 3)
	f.feed(vGood)                  // 0
	f.feed(vGwUnr, vGwUnr, vGwUnr) // 1-3: power cycle
	st := f.acts[0].st
	for i := 4; i <= 70; i++ {
		f.feed(vUpstream) // the Internet does not come back
	}
	f.feed(vGood, vGood, vGood) // 71-73
	boot := startOf(2).Add(5 * time.Second)
	if !st.attachRestart(restartAt(boot, "6.34.7", "6.34.7")) {
		t.Fatal("attach")
	}
	p := st.payload(t0, false)
	// Window: start(1) .. boot+10min (cycles 1-62); cycles 63-70 lie outside.
	if p.State != model.StateISPOutage || p.Cause != model.CauseUpstreamUnreachable || p.Attribution != model.AttrProvider ||
		p.Stats.DowntimeSec != 80 || p.Stats.RestartSec != 620 {
		t.Fatalf("%s/%s/%s stats %+v", p.State, p.Cause, p.Attribution, p.Stats)
	}
	if !strings.Contains(p.Summary, "(10 minutes after the restart, the longest a restart window lasts)") ||
		!strings.Contains(p.Summary, "8 provider-attributed bad cycles lie outside the restart window") {
		t.Fatalf("summary %s", p.Summary)
	}
	checkIncremental(t, st)
}

// A restart learned while the incident is open (its window still open): the cycles that follow
// inside the window are restart time without changing the headline. After the window, one or
// two provider-attributed bad cycles - fewer than the three that open an incident, e.g. one more
// WAN renegotiation right after the Internet first came back - are counted as downtime but leave
// the restart headline; a third makes it an outage of its own (rules 2026.10-4). The incremental
// state always equals a recompute.
func TestRestartLearnedWhileOpen(t *testing.T) {
	f := newFeeder(t, 3, 3)
	f.feed(vGood)                  // 0
	f.feed(vGwUnr, vGwUnr, vGwUnr) // 1-3: opens
	st := f.acts[0].st
	f.feed(vFiber, vFiber) // 4-5
	if !st.attachRestart(restartAt(startOf(2).Add(3*time.Second), "6.34.7", "6.34.7")) {
		t.Fatal("attach")
	}
	if p := st.payload(t0, false); p.Cause != model.CauseGatewayReboot || !strings.Contains(p.Summary, "so far") {
		t.Fatalf("%s %s", p.Cause, p.Summary)
	}
	checkIncremental(t, st)
	if acts := f.feed(vFiber, vFiber); len(acts) != 0 { // 6-7: inside the open window
		t.Fatalf("cycles inside the restart window changed the headline: %v", kinds(acts))
	}
	checkIncremental(t, st)
	f.feed(vGood)                                             // 8: the Internet is back, the window ends
	if acts := f.feed(vUpstream, vUpstream); len(acts) != 0 { // 9-10: the WAN bounces once more
		t.Fatalf("two stray provider cycles after the window changed the headline: %v", kinds(acts))
	}
	f.feed(vGood) // 11
	p := st.payload(t0, false)
	if p.State != model.StateLocalFault || p.Cause != model.CauseGatewayReboot || p.Attribution != model.AttrUndetermined ||
		p.Stats.RestartSec != 70 || p.Stats.DowntimeSec != 20 {
		t.Fatalf("after a bounce: %s/%s/%s %+v", p.State, p.Cause, p.Attribution, p.Stats)
	}
	if !strings.Contains(p.Summary, "2 provider-attributed bad cycles lie outside the restart window - fewer than the 3 it takes to open an incident") ||
		!strings.Contains(p.Summary, "so they are counted in the measured time but not taken as an AT&T outage. The incident is classified as a gateway restart (GATEWAY_REBOOT)") ||
		!strings.Contains(p.Summary, "20s without Internet (ISP_OUTAGE cycles)") {
		t.Fatalf("summary %s", p.Summary)
	}
	checkIncremental(t, st)
	acts := f.feed(vUpstream) // 12: the third provider cycle outside the window
	if len(acts) != 1 || acts[0].kind != actUpdate {
		t.Fatalf("a third provider cycle after the window must update the headline: %v", kinds(acts))
	}
	if p := st.payload(t0, false); p.State != model.StateISPOutage || p.Cause != model.CauseUpstreamUnreachable || p.Attribution != model.AttrProvider || p.Stats.RestartSec != 70 {
		t.Fatalf("%s/%s/%s %+v", p.State, p.Cause, p.Attribution, p.Stats)
	}
	checkIncremental(t, st)
}

// leadFrom computes a restart's lead from the cycles recorded before an incident's first cycle
// (pre: offsets from t0 of cycles that reached the Internet; none were unreachable).
func leadFrom(r restartInfo, first time.Time, pre ...time.Duration) restartInfo {
	r.lead = leadOf(len(pre), func(i int) time.Time { return t0.Add(pre[i]) }, func(int) bool { return false },
		func(int) bool { return true }, r.Boot, first, 30*time.Second)
	return r
}

// Restarts whose window holds none of the incident's bad cycles, and whose boot lies outside
// it, are not attached; a restart whose window holds no bad cycle explains nothing and leaves
// the classification alone.
func TestRestartOutsideOrIrrelevant(t *testing.T) {
	st := closedLocal(model.CauseGatewayUnreachable) // t0 .. t0+30s
	for _, r := range []restartInfo{
		restartAt(t0.Add(-time.Hour), "", ""), // its window ended (10-minute cap) long before
		// 21 s before the first bad cycle, and a cycle at t0-10s reached the Internet: the
		// window ended there, before the incident.
		leadFrom(restartAt(t0.Add(-21*time.Second), "", ""), t0, -10*time.Second),
		restartAt(t0.Add(41*time.Second), "", ""), // after the close: its window holds good cycles only
		restartAt(t0.Add(time.Hour), "", ""),
	} {
		if st.attachRestart(r) {
			t.Fatalf("boot at %v attached to an incident from t0 to t0+30s", r.Boot.Sub(t0))
		}
	}
	if p := st.payload(t0, false); p.Cause != model.CauseGatewayUnreachable || len(p.GatewayRestarts) != 0 {
		t.Fatalf("%+v", p)
	}
	// Boot within the slack before the first failed probe: attached, the gateway restart.
	if !st.attachRestart(restartAt(t0.Add(-15*time.Second), "", "")) {
		t.Fatal("a boot just before the first failed probe belongs to the incident")
	}
	if p := st.payload(t0, false); p.Cause != model.CauseGatewayReboot || p.Attribution != model.AttrUndetermined || p.Stats.RestartSec != 30 {
		t.Fatalf("%s/%s %+v", p.Cause, p.Attribution, p.Stats)
	}

	f := newFeeder(t, 3, 3)
	dst := f.feed(vLossU, vLossU, vLossU)[0].st // the Internet stayed reachable throughout
	f.feed(vGood, vGood, vGood)
	if !dst.attachRestart(restartAt(startOf(1).Add(5*time.Second), "", "")) {
		t.Fatal("attach")
	}
	if p := dst.payload(t0, false); p.State != model.StateDegraded || p.Cause != model.CausePacketLoss || p.Stats.RestartSec != 0 || p.Stats.DegradedSec != 30 {
		t.Fatalf("a restart window without bad cycles must not reclassify: %s/%s %+v", p.State, p.Cause, p.Stats)
	}
}

// restartSpan: the window starts at the boot, extended back over the unreachable cycles just
// before it (not across a monitoring gap), and ends at the first cycle after the boot that
// reached the Internet, at most 10 minutes after the boot.
func TestRestartSpan(t *testing.T) {
	type pt struct {
		at          time.Duration
		unreachable bool
		inet        bool
	}
	span := func(cs []pt, boot time.Duration) restartWin {
		return restartSpan(len(cs), func(i int) time.Time { return t0.Add(cs[i].at) },
			func(i int) bool { return cs[i].unreachable }, func(i int) bool { return cs[i].inet }, t0.Add(boot), 30*time.Second)
	}
	s := time.Second
	cases := []struct {
		name     string
		cycles   []pt
		boot     time.Duration
		from, to time.Duration
		end      winEnd
		back     bool
	}{
		{"unreachable run before the boot", []pt{{0, false, true}, {10 * s, true, false}, {20 * s, true, false}, {30 * s, false, false}, {40 * s, false, true}},
			25 * s, 10 * s, 40 * s, endInternet, true},
		{"no extension across a monitoring gap", []pt{{0, true, false}, {10 * s, true, false}, {60 * s, true, false}, {70 * s, false, true}},
			62 * s, 60 * s, 70 * s, endInternet, true},
		{"no extension when the cycle before the boot is long ago", []pt{{0, true, false}, {100 * s, false, true}},
			40 * s, 40 * s, 100 * s, endInternet, false},
		{"a reachable cycle before the boot stops the extension", []pt{{0, true, false}, {10 * s, false, false}, {20 * s, false, true}},
			15 * s, 15 * s, 20 * s, endInternet, false},
		{"capped 10 minutes after the boot", []pt{{0, true, false}, {300 * s, false, false}, {700 * s, false, false}, {800 * s, false, true}},
			5 * s, 0, 605 * s, endCap, true},
		{"still open", []pt{{0, true, false}, {10 * s, false, false}},
			5 * s, 0, 605 * s, endOpen, true},
		{"no cycles", nil, 5 * s, 5 * s, 605 * s, endOpen, false},
	}
	for _, tc := range cases {
		w := span(tc.cycles, tc.boot)
		if !w.from.Equal(t0.Add(tc.from)) || !w.to.Equal(t0.Add(tc.to)) || w.end != tc.end || w.back != tc.back {
			t.Errorf("%s: window %v..%v end %d back %v, want %v..%v end %d back %v", tc.name,
				w.from.Sub(t0), w.to.Sub(t0), w.end, w.back, tc.from, tc.to, tc.end, tc.back)
		}
	}
}

func TestSummarize(t *testing.T) {
	inc := model.Incident{Opened: fmtTS(t0), Closed: fmtTS(t0.Add(90 * time.Second)), DurationSec: 90,
		State: model.StateLocalFault, Cause: model.CauseGatewayUnreachable, Attribution: model.AttrUndetermined}
	got := summarize(inc, []string{"Extra note."})
	want := "Local fault from 2026-10-05 03:20:00 UTC to 2026-10-05 03:21:30 UTC (1m30s), cause GATEWAY_UNREACHABLE: this computer could not reach the AT&T gateway. Attribution undetermined. Extra note."
	if got != want {
		t.Fatalf("got  %q\nwant %q", got, want)
	}
	inc.Open, inc.State, inc.Cause, inc.Attribution = true, model.StateDegraded, model.CauseHighLatency, model.AttrProvider
	if got := summarize(inc, nil); !strings.HasPrefix(got, "Ongoing degraded service since 2026-10-05 03:20:00 UTC, cause HIGH_LATENCY") {
		t.Fatalf("got %q", got)
	}
}

// TestOutageCyclesDoNotStretchIncidents pins how the rules 2026.10-2 treat short total
// outages (DESIGN §9-§10): outage cycles are excluded from the window loss, so the cycles
// after an outage are ONLINE again at once. One or two failed cycles stay blips; three open
// an incident that closes at the first good cycle, recovered at that cycle, with exactly the
// outage cycles as downtime. (Rules 2026.10-1 counted the outage cycles as loss for the next
// 4 cycles: every outage was stretched by 40 s and a 20 s outage became a 60 s incident.)
func TestOutageCyclesDoNotStretchIncidents(t *testing.T) {
	good := cyc(gwICMP(true, 1900), gwTCP(true, 2300), inet(true, true, 12000))
	down := cyc(gwICMP(true, 1900), gwTCP(true, 2300), inet(false, false, 0))
	run := func(outage int) (*tracker, []action, []cycleObs) {
		tr := newTracker(3, 3, 6, 10*time.Second, nil)
		var acts []action
		var obs []cycleObs
		var window [][]model.ProbeResult
		cycles := [][]model.ProbeResult{good, good, good, good, good, good}
		for i := 0; i < outage; i++ {
			cycles = append(cycles, down)
		}
		for i := 0; i < 8; i++ {
			cycles = append(cycles, good)
		}
		for i, c := range cycles {
			window = append(window, c)
			if len(window) > 6 {
				window = window[len(window)-6:]
			}
			v := Classify(ClassifyInput{Cycle: c, Window: window}, config.Default().Incident)
			o := cycleObs{Start: startOf(i), TS: startOf(i), Seq: uint64(i), Verdict: v, Probes: c}
			obs = append(obs, o)
			acts = append(acts, tr.observe(o)...)
		}
		return tr, acts, obs
	}

	for _, outage := range []int{1, 2} {
		tr, acts, obs := run(outage)
		if len(acts) != 0 || tr.blipCycles != outage {
			t.Fatalf("%d failed cycles: acts %v blip cycles %d", outage, kinds(acts), tr.blipCycles)
		}
		if v := obs[6+outage].Verdict; v.State != model.StateOnline {
			t.Fatalf("%d failed cycles: the next cycle is %s/%s, want ONLINE: %q", outage, v.State, v.Cause, v.Reasons)
		}
	}

	tr, acts, obs := run(3)
	if got := kinds(acts); !slices.Equal(got, []actionKind{actOpen, actClose}) {
		t.Fatalf("three failed cycles: acts %v (blip cycles %d)", got, tr.blipCycles)
	}
	for i := 9; i < len(obs); i++ {
		if v := obs[i].Verdict; v.State != model.StateOnline {
			t.Fatalf("cycle %d after the outage: %s/%s, want ONLINE", i, v.State, v.Cause)
		}
	}
	inc := acts[1].st.payload(t0, false)
	if inc.Opened != fmtTS(startOf(6)) || inc.Closed != fmtTS(startOf(9)) || inc.DurationSec != 30 || inc.State != model.StateISPOutage {
		t.Fatalf("incident %s..%s (%d s) %s", inc.Opened, inc.Closed, inc.DurationSec, inc.State)
	}
	if inc.RecoveredAt != fmtTS(startOf(9)) || inc.Stats.DowntimeSec != 30 || inc.Stats.DegradedSec != 0 || inc.Stats.Cycles != 3 {
		t.Fatalf("recovered %s stats %+v", inc.RecoveredAt, inc.Stats)
	}
}

// Long incidents keep a bounded number of cycle records (the oldest are folded into fixed
// totals): an incident folded many times reports exactly what an unfolded one does - restart
// windows settled before the fold, and a restart learned after it, included.
func TestIncidentCycleRecordsAreBounded(t *testing.T) {
	run := func(limit int) *incState {
		old := maxIncCycles
		maxIncCycles = limit
		defer func() { maxIncCycles = old }()
		f := newFeeder(t, 3, 3)
		f.feed(vGood)            // 0
		f.feed(vWAN, vWAN, vWAN) // 1-3: opens
		st := f.acts[0].st
		f.feed(vGwUnr, vGwUnr, vGwUnr, vFiber, vFiber) // 4-8: a power cycle during the outage
		if !st.attachRestart(restartAt(startOf(5).Add(2*time.Second), "6.34.7", "6.34.7")) {
			t.Fatal("attach")
		}
		for i := 0; i < 60; i++ { // 9-68: flapping degradation and outages
			f.feed([]model.Verdict{vLossP, vLossU, vGood, vUpstream}[i%4])
		}
		f.feed(vGwUnr, vGwUnr, vFiber) // 69-71: another power cycle, learned late
		if !st.attachRestart(restartInfo{Boot: startOf(70).Add(time.Second), Uptime: -1, EventSeq: 950}) {
			t.Fatal("attach late")
		}
		f.feed(vGood, vGood, vGood) // 72-74: closes
		return st
	}
	whole, folded := run(1<<30), run(16)
	if len(folded.cycles) > 16 || folded.folded.badOutside == 0 || len(folded.folded.wins) == 0 {
		t.Fatalf("not folded: %d records, %+v", len(folded.cycles), folded.folded)
	}
	pw, pf := whole.payload(t0, false), folded.payload(t0, false)
	if !reflect.DeepEqual(pw, pf) {
		t.Fatalf("folded incident differs:\n whole  %+v\n folded %+v", pw, pf)
	}
	if pw.Stats.RestartSec != 80 || len(pw.GatewayRestarts) != 2 || pw.Attribution != model.AttrProvider {
		t.Fatalf("whole %+v %v %s", pw.Stats, pw.GatewayRestarts, pw.Attribution)
	}
	checkIncremental(t, folded)
}
