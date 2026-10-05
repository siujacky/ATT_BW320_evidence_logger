package monitor

import (
	"math"
	"testing"
	"time"

	"attmonitor/internal/model"
)

func sampleAt(state string, tagged bool, probes ...model.ProbeResult) *model.Sample {
	s := &model.Sample{Probes: probes, Verdict: model.Verdict{State: state}}
	if tagged {
		s.IncidentID = "INC-x"
	}
	return s
}

func sampleAttr(state, attr string, tagged bool, probes ...model.ProbeResult) *model.Sample {
	s := sampleAt(state, tagged, probes...)
	s.Verdict.Attribution = attr
	return s
}

func pr(name string, ok bool, rttUs int64) model.ProbeResult {
	return model.ProbeResult{Name: name, OK: ok, RTTus: rttUs}
}

func TestSeriesBucketing(t *testing.T) {
	ps := newPointStore()
	now := t0.Add(time.Hour) // 04:20:00
	// Bucket 04:19:00-04:19:10 (1h range, 10 s buckets) gets three cycles.
	b := now.Add(-time.Minute)
	ps.addSample(b, sampleAt(model.StateOnline, false, pr("gw", true, 1000), pr("cf", true, 10000)))
	ps.addSample(b.Add(3*time.Second), sampleAt(model.StateDegraded, false, pr("gw", true, 3000), pr("cf", false, 0)))
	ps.addSample(b.Add(6*time.Second), sampleAt(model.StateOnline, false, pr("gw", true, 2000), pr("cf", true, 20000)))
	// One ISP outage cycle in the next bucket, one cycle outside the range.
	ps.addSample(b.Add(10*time.Second), sampleAt(model.StateISPOutage, true, pr("gw", true, 1500), pr("cf", false, 0)))
	ps.addSample(now.Add(-2*time.Hour), sampleAt(model.StateLocalFault, false, pr("gw", false, 0)))
	rx := int64(-315)
	ps.addOptical(b.Add(time.Second), model.GatewayDerived{RxPowerX10: &rx, TxPowerX10: i64p(37), Alarms: []string{"OPTICAL_RX_LOW_ALARM"}})
	rx2 := int64(-320)
	ps.addOptical(b.Add(5*time.Second), model.GatewayDerived{RxPowerX10: &rx2, Alarms: []string{"OPTICAL_RX_LOW_WARNING"}})
	ps.addOptical(b.Add(-30*time.Minute), model.GatewayDerived{}) // no readings: ignored

	latest := okSnapshot(nil, now)
	s, err := ps.buildSeries("1h", now, []model.ProbeSpec{{Name: "gw"}, {Name: "cf"}}, &latest)
	if err != nil {
		t.Fatal(err)
	}
	if s.StepSec != 10 || len(s.Points) != 361 || s.From != fmtTS(t0) || s.To != fmtTS(now) || len(s.Probes) != 2 {
		t.Fatalf("step %d points %d from %s to %s", s.StepSec, len(s.Points), s.From, s.To)
	}
	idx := int(b.Sub(t0) / (10 * time.Second))
	p := s.Points[idx]
	if p.T != fmtTS(b) || p.State != model.StateDegraded {
		t.Fatalf("bucket %d: %+v", idx, p)
	}
	if p.RTTms["gw"] != 2 || p.RTTms["cf"] != 15 {
		t.Fatalf("mean RTT of successes: %v", p.RTTms)
	}
	if math.Abs(p.Loss["cf"]-1.0/3) > 1e-9 || p.Loss["gw"] != 0 {
		t.Fatalf("loss %v", p.Loss)
	}
	if n := s.Points[idx+1]; n.State != model.StateISPOutage || n.Loss["cf"] != 1 {
		t.Fatalf("next bucket %+v", n)
	}
	if e := s.Points[0]; e.State != "" || e.RTTms != nil || e.Loss != nil {
		t.Fatalf("empty bucket must have no data: %+v", e)
	}
	if len(s.Optical) != 1 {
		t.Fatalf("optical points %d", len(s.Optical))
	}
	o := s.Optical[0]
	if *o.RxX10 != -320 || o.TxX10 != nil || !o.RxLowAlarm || !o.RxLowWarn || o.T != fmtTS(b.Add(5*time.Second)) {
		t.Fatalf("optical %+v (latest reading per bucket, flags OR-ed)", o)
	}
	if *s.RxLowAlarmX10 != -295 || *s.RxLowWarnX10 != -292 {
		t.Fatal("thresholds from the latest snapshot")
	}

	for rng, want := range map[string]struct{ step, n int }{"6h": {60, 361}, "24h": {300, 289}, "7d": {1800, 337}} {
		s, err := ps.buildSeries(rng, now, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if s.StepSec != want.step || len(s.Points) != want.n {
			t.Errorf("%s: step %d points %d, want %d/%d", rng, s.StepSec, len(s.Points), want.step, want.n)
		}
	}
	if _, err := ps.buildSeries("2d", now, nil, nil); err == nil {
		t.Fatal("unknown range must fail")
	}
}

func TestSeriesUnalignedNow(t *testing.T) {
	ps := newPointStore()
	now := t0.Add(time.Hour + 7*time.Second)
	ps.addSample(now.Add(-time.Second), sampleAt(model.StateOnline, false, pr("gw", true, 1000)))
	s, err := ps.buildSeries("1h", now, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if s.From != fmtTS(t0) || len(s.Points) != 361 || s.Points[360].State != model.StateOnline {
		t.Fatalf("from %s points %d last %+v", s.From, len(s.Points), s.Points[len(s.Points)-1])
	}
}

func TestWindowStats(t *testing.T) {
	fast := 10 * time.Second
	ps := newPointStore()
	// One hour of samples every 10 s, starting at t0.
	states := make([]string, 360)
	for i := range states {
		states[i] = model.StateOnline
	}
	// Blip: 2 untagged DEGRADED cycles.
	states[10], states[11] = model.StateDegraded, model.StateDegraded
	// Incident a: 4 ISP_OUTAGE cycles, only the 3rd and 4th tagged (the first ones were
	// recorded before the incident opened).
	for i := 20; i < 24; i++ {
		states[i] = model.StateISPOutage
	}
	// Incident e (flapping, no tags at all): ISP_OUTAGE, ONLINE, DEGRADED.
	states[40], states[42] = model.StateISPOutage, model.StateDegraded
	// Unknown cycles are neither good nor bad.
	states[30] = model.StateUnknown
	for i, s := range states {
		tagged := i == 22 || i == 23
		ps.addSample(t0.Add(time.Duration(i)*fast), sampleAttr(s, model.AttrProvider, tagged, pr("gw", s != model.StateLocalFault, 1000)))
	}
	// After a 2 h gap, one bad cycle that ends at the gap... and one more two hours later.
	ps.addSample(t0.Add(3*time.Hour), sampleAt(model.StateLocalFault, false))
	ps.addSample(t0.Add(5*time.Hour), sampleAt(model.StateOnline, false))
	now := t0.Add(5*time.Hour + 5*time.Second)

	incidents := []model.Incident{
		{ID: "a", Opened: fmtTS(t0.Add(200 * time.Second)), Closed: fmtTS(t0.Add(240 * time.Second)), State: model.StateISPOutage, Attribution: model.AttrProvider},
		{ID: "b", Opened: fmtTS(t0.Add(-48 * time.Hour)), Closed: fmtTS(t0.Add(-47 * time.Hour)), State: model.StateISPOutage, Attribution: model.AttrProvider},
		{ID: "c", Opened: fmtTS(t0.Add(time.Hour)), Closed: fmtTS(t0.Add(2 * time.Hour)), State: model.StateDegraded, Attribution: model.AttrProvider},
		{ID: "d", Opened: fmtTS(t0.Add(4 * time.Hour)), Open: true, State: model.StateLocalFault, Attribution: model.AttrUndetermined},
		{ID: "e", Opened: fmtTS(t0.Add(400 * time.Second)), Closed: fmtTS(t0.Add(430 * time.Second)), State: model.StateISPOutage, Attribution: model.AttrProvider},
	}
	spans := spansOf(t, incidents)
	ws := ps.windowStats("24h", 24*time.Hour, now, fast, spans, nil)
	// Each sample covers the time until the next one, capped at 1.5 × 10 s: 359 samples
	// × 10 s, the last regular one and the isolated one before a gap 15 s each, and the
	// latest one min(now - t, 15 s) = 5 s.
	if ws.MonitoredSec != 3590+15+15+5 {
		t.Fatalf("monitored %d", ws.MonitoredSec)
	}
	if want := round3(100 * float64(3625*time.Second) / float64(24*time.Hour)); ws.CoveragePct != want {
		t.Fatalf("coverage %v want %v", ws.CoveragePct, want)
	}
	// Known cycles: 362 - 1 unknown = 361; online: 360 - 2 - 4 - 2 - 1 unknown + 1 = 352.
	if want := round3(100 * 352.0 / 361.0); ws.AvailabilityPct != want {
		t.Fatalf("availability %v want %v", ws.AvailabilityPct, want)
	}
	// Blips: cycles 10-11, and the single LOCAL_FAULT cycle ended by the gap. The cycles of
	// incidents a (partly tagged) and e (not tagged at all) are not blips.
	if ws.Blips != 2 {
		t.Fatalf("blips %d", ws.Blips)
	}
	if ws.Incidents != 4 { // a, c, d, e overlap the window; b ended before it
		t.Fatalf("incidents %d", ws.Incidents)
	}
	// Time accounting counts cycles (DESIGN §10): provider ISP_OUTAGE cycles 20-23 and 40;
	// DEGRADED cycles 10, 11 and 42.
	if ws.ProviderOutageSec != 50 || ws.DegradedSec != 30 {
		t.Fatalf("provider outage %d degraded %d", ws.ProviderOutageSec, ws.DegradedSec)
	}

	// The 7-day window also counts incident b; its time had no samples in memory.
	ws7 := ps.windowStats("7d", 7*24*time.Hour, now, fast, spans, nil)
	if ws7.Incidents != 5 || ws7.ProviderOutageSec != 50 {
		t.Fatalf("7d: incidents %d outage %d", ws7.Incidents, ws7.ProviderOutageSec)
	}
	// An ISP_OUTAGE cycle not attributed to the provider is not provider outage time.
	ps2 := newPointStore()
	ps2.addSample(t0, sampleAttr(model.StateISPOutage, model.AttrUndetermined, true))
	ps2.addSample(t0.Add(fast), sampleAttr(model.StateISPOutage, model.AttrProvider, true))
	if w := ps2.windowStats("1h", time.Hour, t0.Add(fast+5*time.Second), fast, nil, nil); w.ProviderOutageSec != 5 || w.MonitoredSec != 15 {
		t.Fatalf("provider attribution %+v", w)
	}
	// Empty store.
	empty := newPointStore().windowStats("24h", 24*time.Hour, now, fast, nil, nil)
	if empty.MonitoredSec != 0 || empty.CoveragePct != 0 || empty.AvailabilityPct != 0 || empty.Blips != 0 {
		t.Fatalf("empty %+v", empty)
	}
}

// TestMergedSpans: incident spans overlapping after a clock step are merged; an open
// incident includes now.
func TestMergedSpans(t *testing.T) {
	now := t0.Add(time.Hour)
	spans := sortedSpans([]incSpan{
		{opened: t0, closed: t0.Add(100 * time.Second)},
		{opened: t0.Add(10 * time.Second), closed: t0.Add(20 * time.Second)}, // nested
		{opened: t0.Add(50 * time.Second), closed: t0.Add(200 * time.Second)},
		{opened: t0.Add(30 * time.Minute), open: true},
		{opened: t0.Add(10 * time.Minute), closed: t0.Add(10 * time.Minute)}, // empty
	}, now)
	iv := mergedSpans(spans, now)
	if len(iv) != 2 || iv[0].start != t0.UnixNano() || iv[0].end != t0.Add(200*time.Second).UnixNano() {
		t.Fatalf("merged %+v", iv)
	}
	for _, tc := range []struct {
		at   time.Time
		want bool
	}{
		{t0.Add(-time.Second), false}, {t0, true}, {t0.Add(150 * time.Second), true}, {t0.Add(200 * time.Second), false},
		{t0.Add(10 * time.Minute), false}, {t0.Add(30 * time.Minute), true}, {now, true}, {now.Add(time.Second), false},
	} {
		if got := contains(iv, tc.at.UnixNano()); got != tc.want {
			t.Errorf("contains(%v) = %v", tc.at.Sub(t0), got)
		}
	}
}
func TestPointStorePrune(t *testing.T) {
	ps := newPointStore()
	for i := 0; i < 10; i++ {
		ps.addSample(t0.Add(time.Duration(i)*time.Hour), sampleAt(model.StateOnline, false))
		ps.addOptical(t0.Add(time.Duration(i)*time.Hour), model.GatewayDerived{RxPowerX10: i64p(-300)})
	}
	ps.prune(t0.Add(5 * time.Hour))
	if len(ps.pts) != 5 || len(ps.opt) != 5 || ps.pts[0].t != t0.Add(5*time.Hour).UnixNano() {
		t.Fatalf("after prune: %d points, %d optical", len(ps.pts), len(ps.opt))
	}
}

func TestGapLimit(t *testing.T) {
	if gapLimit(10*time.Second) != 30*time.Second {
		t.Fatal("3x fast interval")
	}
	if gapLimit(40*time.Millisecond) != 2*time.Second {
		t.Fatal("floor for tiny intervals")
	}
}

func spansOf(t *testing.T, incs []model.Incident) []incSpan {
	t.Helper()
	var out []incSpan
	for _, inc := range incs {
		s, ok := spanOf(inc)
		if !ok {
			t.Fatalf("bad incident %+v", inc)
		}
		out = append(out, s)
	}
	return out
}

func TestSpanOf(t *testing.T) {
	if _, ok := spanOf(model.Incident{Opened: "garbage"}); ok {
		t.Fatal("unparseable opened")
	}
	s, ok := spanOf(model.Incident{Opened: fmtTS(t0), Closed: fmtTS(t0.Add(time.Minute)), State: model.StateISPOutage, Attribution: model.AttrProvider})
	if !ok || s.open || !s.closed.Equal(t0.Add(time.Minute)) || s.state != model.StateISPOutage {
		t.Fatalf("%+v", s)
	}
	// A closed incident without a parseable close time counts until now, like an open one.
	ps := newPointStore()
	s, _ = spanOf(model.Incident{Opened: fmtTS(t0), Closed: "?", State: model.StateISPOutage, Attribution: model.AttrProvider})
	if ws := ps.windowStats("1h", time.Hour, t0.Add(10*time.Minute), 10*time.Second, []incSpan{s}, nil); ws.Incidents != 1 {
		t.Fatalf("%+v", ws)
	}
}
