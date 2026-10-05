package export

import (
	"context"
	"encoding/base64"
	"fmt"
	"math"
	"strings"
	"testing"
	"time"

	"attmonitor/internal/contracts"
	"attmonitor/internal/model"
)

func TestFormatHelpers(t *testing.T) {
	durs := []struct {
		in   int64
		want string
	}{{-5, "0s"}, {0, "0s"}, {59, "59s"}, {60, "1m 00s"}, {125, "2m 05s"}, {3600, "1h 00m 00s"}, {3725, "1h 02m 05s"}, {90061, "1d 01h 01m"}}
	for _, tc := range durs {
		if got := fmtDur(tc.in); got != tc.want {
			t.Errorf("fmtDur(%d) = %q, want %q", tc.in, got, tc.want)
		}
	}
	x10 := []struct {
		in   int64
		want string
	}{{-315, "-31.5"}, {-5, "-0.5"}, {0, "0.0"}, {5, "0.5"}, {56, "5.6"}, {-295, "-29.5"}, {1000, "100.0"}}
	for _, tc := range x10 {
		if got := fmtX10(tc.in); got != tc.want {
			t.Errorf("fmtX10(%d) = %q, want %q", tc.in, got, tc.want)
		}
	}
	if fmtX10p(nil) != "n/a" || fmtPctp(nil) != "n/a" {
		t.Error("nil formatting")
	}
	ints := []struct {
		in   any
		want string
	}{{0, "0"}, {999, "999"}, {1000, "1,000"}, {-1234567, "-1,234,567"}, {int64(123456), "123,456"}, {uint64(1 << 40), "1,099,511,627,776"},
		{(*int64)(nil), "n/a"}, {ip(12345), "12,345"}}
	for _, tc := range ints {
		if got := fmtInt(tc.in); got != tc.want {
			t.Errorf("fmtInt(%v) = %q, want %q", tc.in, got, tc.want)
		}
	}
	fp := strings.Repeat("0123456789abcdef", 4)
	if got := groupFingerprint(fp); got != strings.TrimSpace(strings.Repeat("0123 4567 89ab cdef ", 4)) || len(strings.Fields(got)) != 16 {
		t.Errorf("groupFingerprint = %q", got)
	}
	seqs := []struct {
		in   []uint64
		want string
	}{{nil, ""}, {[]uint64{5}, "5"}, {[]uint64{1, 2, 3, 7, 9, 10}, "1-3, 7, 9-10"}}
	for _, tc := range seqs {
		if got := fmtSeqs(tc.in); got != tc.want {
			t.Errorf("fmtSeqs(%v) = %q, want %q", tc.in, got, tc.want)
		}
	}
	var many []uint64
	for i := uint64(0); i < 40; i += 2 {
		many = append(many, i)
	}
	if got := fmtSeqs(many); !strings.Contains(got, "(20 seqs in report.json)") {
		t.Errorf("long fmtSeqs = %q", got)
	}
	if got := fmtUTC("2026-10-03T12:05:10.5Z"); got != "2026-10-03 12:05:10 UTC" {
		t.Errorf("fmtUTC = %q", got)
	}
	if got := fmtUTC("garbage"); got != "garbage" {
		t.Errorf("fmtUTC(garbage) = %q", got)
	}
	if z := zoneLabel(time.Local, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)); !strings.Contains(z, "(UTC") {
		t.Errorf("zoneLabel = %q", z)
	}
	if codeLabel("OPTICAL_RX_LOW_ALARM") != "Rx power low alarm" || codeLabel("SOME_NEW_CODE") != "Some new code" {
		t.Error("codeLabel")
	}
	if codeSeverity("OPTICAL_RX_LOW_ALARM") != "critical" || codeSeverity("OPTICAL_RX_LOW_WARNING") != "warning" || codeSeverity("X") != "info" {
		t.Error("codeSeverity")
	}
}

func TestValidName(t *testing.T) {
	for _, ok := range []string{"att-evidence_20261003T1150Z_20261003T1222Z_0a1b2c3d.zip", "a.zip", "A_b-c.1.zip", "comx.zip", "console.zip"} {
		if err := validName(ok); err != nil {
			t.Errorf("validName(%q) = %v", ok, err)
		}
	}
	for _, bad := range []string{"", "x", "x.ZIP.txt", "../x.zip", "a/b.zip", `a\b.zip`, "x.zip:y", "x..zip", "-x.zip", "CON.zip", "aux.zip", "Com3.zip", "LPT1.zip", "nul.tar.zip"} {
		if err := validName(bad); err == nil {
			t.Errorf("validName(%q) accepted", bad)
		}
	}
}

func optAt(min int, rx int64, alarms ...string) optPoint {
	return optPoint{t: time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC).Add(time.Duration(min) * time.Minute), seq: uint64(min), rx: ip(rx), alarms: alarms}
}

func TestAlarmPeriods(t *testing.T) {
	A, W := codeRxLowAlarm, codeRxLowWarn
	pts := []optPoint{
		optAt(0, -310, W),
		optAt(1, -300, A, W),
		optAt(2, -305, A, W),
		optAt(40, -306, A, W), // 38 min without readings: new periods
		optAt(41, -280),       // cleared
		optAt(42, -299, A),    // until the end
	}
	got := alarmPeriods(pts)
	type want struct {
		code, reason string
		first, last  uint64
		n            int
	}
	exp := []want{
		{W, "observation gap", 0, 2, 3},
		{A, "observation gap", 1, 2, 2},
		{A, "cleared", 40, 40, 1},
		{W, "cleared", 40, 40, 1},
		{A, "end of period", 42, 42, 1},
	}
	if len(got) != len(exp) {
		t.Fatalf("periods = %+v", got)
	}
	for i, e := range exp {
		g := got[i]
		if g.Code != e.code || g.EndReason != e.reason || g.FirstSeq != e.first || g.LastSeq != e.last || g.Snapshots != e.n {
			t.Errorf("period %d = %+v, want %+v", i, g, e)
		}
	}
	if got[0].ObservedS != 120 || *got[1].RxMinX10 != -305 || *got[1].RxMaxX10 != -300 || got[1].Severity != "critical" {
		t.Errorf("period details = %+v / %+v", got[0], got[1])
	}
	if got[2].ClearedAt != pts[4].t.UTC().Format(time.RFC3339Nano) {
		t.Errorf("cleared at = %s", got[2].ClearedAt)
	}
	if len(alarmPeriods(nil)) != 0 {
		t.Error("no points, no periods")
	}
}

func lite(startMin float64, n int, every time.Duration, state string) []sampleLite {
	base := time.Date(2026, 10, 3, 0, 0, 0, 0, time.UTC).Add(time.Duration(startMin * float64(time.Minute)))
	var out []sampleLite
	for i := 0; i < n; i++ {
		out = append(out, sampleLite{t: base.Add(time.Duration(i) * every).UnixNano(), seq: uint64(i), state: state})
	}
	return out
}

// acct wraps samples of the period for the time accounting, all with cycle interval fast.
func acct(samples []sampleLite, fast time.Duration) []acctSample {
	out := make([]acctSample, len(samples))
	for i, s := range samples {
		out[i] = acctSample{sampleLite: s, fast: fast, inPeriod: true}
	}
	return out
}

func TestCadence(t *testing.T) {
	if d, assumed := cadence(nil); d != defaultCadence || !assumed {
		t.Errorf("cadence(nil) = %v %v", d, assumed)
	}
	if d, assumed := cadence(lite(0, 1, 0, "")); d != defaultCadence || !assumed {
		t.Errorf("cadence(1) = %v %v", d, assumed)
	}
	if d, assumed := cadence(lite(0, 30, 15*time.Second, "")); d != 15*time.Second || assumed {
		t.Errorf("cadence(15s) = %v %v", d, assumed)
	}
	if d, _ := cadence(lite(0, 3, time.Hour, "")); d != 10*time.Minute {
		t.Errorf("cadence is capped at 10m, got %v", d)
	}
}

func TestGapsAndExplanations(t *testing.T) {
	day := time.Date(2026, 10, 3, 0, 0, 0, 0, time.UTC)
	c := newCollector(&buildParams{from: day, to: day.Add(time.Hour), now: day.Add(48 * time.Hour)})
	samples := append(lite(5, 30, 10*time.Second, model.StateOnline), lite(30, 30, 10*time.Second, model.StateOnline)...)
	c.agg.marks = []mark{
		{t: day.Add(9*time.Minute + 55*time.Second), seq: 100, typ: model.TypeMonitorStop, text: "monitor stopped (service stop)"},
		{t: day.Add(29*time.Minute + 50*time.Second), seq: 101, typ: model.TypeMonitorStart, text: "monitor started", clean: false},
	}
	gaps := c.gaps(acct(samples, 10*time.Second), 10*time.Second)
	if len(gaps) != 3 {
		t.Fatalf("gaps = %+v", gaps)
	}
	if gaps[0].Seconds != 300 || !strings.Contains(gaps[0].Explanation, "unexplained") {
		t.Errorf("leading gap = %+v", gaps[0])
	}
	if !strings.Contains(gaps[1].Explanation, "monitor stopped (service stop)") || !strings.Contains(gaps[1].Explanation, "unclean stop") ||
		len(gaps[1].Evidence) != 2 {
		t.Errorf("middle gap = %+v", gaps[1])
	}
	if !strings.HasSuffix(gaps[2].To, "T01:00:00Z") {
		t.Errorf("trailing gap = %+v", gaps[2])
	}
	if g := c.gaps(nil, 10*time.Second); len(g) != 1 || g[0].Seconds != 3600 {
		t.Errorf("no samples: %+v", g)
	}
}

func TestSummarizeBlipsAndCoverage(t *testing.T) {
	day := time.Date(2026, 10, 3, 0, 0, 0, 0, time.UTC)
	c := newCollector(&buildParams{from: day, to: day.Add(10 * time.Minute), now: day.Add(time.Hour)})
	var s []sampleLite
	add := func(state string, n int, incident bool) {
		for i := 0; i < n; i++ {
			s = append(s, sampleLite{t: day.Add(time.Duration(len(s)) * 10 * time.Second).UnixNano(), seq: uint64(len(s)), state: state, incident: incident})
		}
	}
	add(model.StateOnline, 10, false)
	add(model.StateDegraded, 2, false) // blip
	add(model.StateOnline, 5, false)
	add(model.StateISPOutage, 4, true) // incident, not a blip
	add(model.StateOnline, 5, false)
	add(model.StateLocalFault, 1, false) // blip
	add(model.StateOnline, 3, false)
	add(model.StateISPOutage, 2, false) // trailing streak without a good cycle: not counted
	c.agg.samples = s
	r := &report{}
	c.summarize(r)
	sm := r.Summary
	if sm.Blips != 2 || sm.BlipCycles != 3 || len(sm.BlipsByState) != 2 {
		t.Errorf("blips = %d/%d %+v", sm.Blips, sm.BlipCycles, sm.BlipsByState)
	}
	// 32 cycles 10 s apart; the last one covers 1.5 x 10 s (the period ends long after it).
	// Percentages are truncated, never rounded up: 54.1666... % is 54.166.
	if sm.Cycles != 32 || sm.MonitoredSec != 325 || sm.WindowSec != 600 || sm.CoveragePct != 54.166 {
		t.Errorf("coverage = %+v", sm)
	}
	if sm.AvailabilityPct == nil || math.Abs(*sm.AvailabilityPct-round3(100*23.0/32.0)) > 1e-9 {
		t.Errorf("availability = %v", sm.AvailabilityPct)
	}
	if sm.CyclesByState[0].State != model.StateOnline || sm.CyclesByState[0].Count != 23 {
		t.Errorf("cycles by state = %+v", sm.CyclesByState)
	}
}

func TestSummarizeIncidentClasses(t *testing.T) {
	day := time.Date(2026, 10, 3, 0, 0, 0, 0, time.UTC)
	at := func(h, m int) time.Time { return day.Add(time.Duration(h)*time.Hour + time.Duration(m)*time.Minute) }
	// Period 01:00-05:00, exported at 04:00: statistics stop at 04:00.
	c := newCollector(&buildParams{from: at(1, 0), to: at(5, 0), now: at(4, 0)})
	add := func(id, state, cause, attr string, opened, closed time.Time) {
		inc := model.Incident{ID: id, Opened: opened.Format(time.RFC3339Nano), State: state, Cause: cause, Attribution: attr, Open: closed.IsZero()}
		acc := &incAcc{haveOpen: true, openSeq: 1, records: []uint64{1}}
		if !closed.IsZero() {
			inc.Closed = closed.Format(time.RFC3339Nano)
			acc.haveClose, acc.closeSeq = true, 2
		}
		acc.latest = inc
		c.agg.incidents[id] = acc
		c.agg.incOrder = append(c.agg.incOrder, id)
	}
	add("A", model.StateDegraded, model.CausePacketLoss, model.AttrProvider, at(1, 10), at(1, 40))
	add("B", model.StateLocalFault, model.CauseGatewayUnreachable, model.AttrUndetermined, at(2, 0), at(2, 50))
	add("C", model.StateISPOutage, model.CauseWANDown, model.AttrProvider, at(0, 30), at(1, 30))             // starts before the period
	add("D", model.StateISPOutage, model.CauseFiberLinkDown, model.AttrProvider, at(3, 30), time.Time{})     // still open
	add("E", model.StateISPOutage, model.CauseUpstreamUnreachable, model.AttrProvider, at(4, 30), at(4, 40)) // after the export time
	r := &report{}
	c.summarize(r)
	s := r.Summary
	if s.Incidents != 4 || len(r.Incidents) != 4 {
		t.Fatalf("incidents = %d: %+v", s.Incidents, r.Incidents)
	}
	var order []string
	for _, e := range r.Incidents {
		order = append(order, e.Incident.ID)
	}
	if strings.Join(order, "") != "CABD" {
		t.Errorf("incident order = %v", order)
	}
	var classes []string
	for _, ic := range s.IncidentsByClass {
		classes = append(classes, ic.State+"/"+ic.Cause)
	}
	want := "ISP_OUTAGE/FIBER_LINK_DOWN,ISP_OUTAGE/WAN_DOWN,LOCAL_FAULT/GATEWAY_UNREACHABLE,DEGRADED/PACKET_LOSS"
	if strings.Join(classes, ",") != want {
		t.Errorf("classes = %v", classes)
	}
	// Provider time is cycle time from the samples (there are none here), never the span of
	// provider-attributed incidents: format 1 reported 3600 s down and 1800 s degraded.
	if s.ProviderIncidents != 3 || s.ProviderOutageSec != 0 || s.ProviderDowntimeSec != 0 || s.ProviderDegradedSec != 0 {
		t.Errorf("provider: %d incidents, %ds outage, %ds down, %ds degraded", s.ProviderIncidents, s.ProviderOutageSec, s.ProviderDowntimeSec, s.ProviderDegradedSec)
	}
	if s.LongestOutage == nil || s.LongestOutage.ID != "C" || s.LongestOutage.Seconds != 3600 {
		t.Errorf("longest = %+v", s.LongestOutage)
	}
	d := r.Incidents[3]
	if !d.Ongoing || d.DurationSec != 1800 || d.InPeriodSec != 1800 || d.CloseSeq != nil || !strings.HasPrefix(d.EffectiveEnd, "2026-10-03T04:00:00") {
		t.Errorf("ongoing incident = %+v", d)
	}
	if c0 := r.Incidents[0]; c0.DurationSec != 3600 || c0.InPeriodSec != 1800 {
		t.Errorf("clipped incident = %+v", c0)
	}
}

func TestBuildNotesUninterpretableRecords(t *testing.T) {
	f := newFakeLedger(t)
	d := time.Date(2026, 10, 3, 10, 0, 0, 0, time.UTC)
	f.append(d, model.TypeGenesis, model.Genesis{PublicKey: base64.StdEncoding.EncodeToString(f.pub), Fingerprint: f.fingerprint(),
		Created: d.Format(time.RFC3339Nano), Host: testHost, Software: testSoftware})
	f.append(d.Add(time.Second), model.TypeSample, "not a sample object")
	f.append(d.Add(2*time.Second), model.TypeIncidentOpen, []int{1, 2})
	f.append(d.Add(3*time.Second), "future_record_type", map[string]int{"x": 1})
	s := &scenario{f: f, now: d.Add(time.Hour)}
	e, _ := newTestExporter(t, s, t.TempDir())
	info, err := e.Build(context.Background(), contracts.ExportRequest{})
	if err != nil {
		t.Fatal(err)
	}
	r := readReportJSON(t, readZip(t, info.Path))
	if !r.Verification.Bundle.OK {
		t.Errorf("valid records must verify: %+v", r.Verification.Bundle.Failures)
	}
	notes := strings.Join(r.Notes, "\n")
	if !strings.Contains(notes, "seq 1 (sample)") || !strings.Contains(notes, "seq 2 (incident_open)") {
		t.Errorf("notes = %q", notes)
	}
	if r.Ledger.TypeCounts["future_record_type"] != 1 || r.Summary.Cycles != 0 || r.Summary.Incidents != 0 {
		t.Errorf("type counts %v, summary %+v", r.Ledger.TypeCounts, r.Summary)
	}
}

func TestTimeTicks(t *testing.T) {
	from := time.Date(2026, 10, 3, 12, 3, 0, 0, time.UTC)
	tests := []struct {
		span time.Duration
		min  int
	}{{30 * time.Minute, 3}, {2 * time.Hour, 4}, {26 * time.Hour, 4}, {10 * 24 * time.Hour, 3}, {200 * 24 * time.Hour, 1}}
	for _, tc := range tests {
		ticks := timeTicks(from, from.Add(tc.span), time.Local)
		if len(ticks) < tc.min || len(ticks) > 9 {
			t.Errorf("span %v: %d ticks", tc.span, len(ticks))
		}
		for i, tk := range ticks {
			if tk.t.Before(from) || tk.t.After(from.Add(tc.span)) || tk.label == "" {
				t.Errorf("span %v: tick %d = %+v out of range", tc.span, i, tk)
			}
			if i > 0 && !tk.t.After(ticks[i-1].t) {
				t.Errorf("span %v: ticks not increasing", tc.span)
			}
		}
	}
	if timeTicks(from, from, time.Local) != nil {
		t.Error("empty span must have no ticks")
	}
}

func TestNiceStepAndDiv(t *testing.T) {
	if niceStep(3) != 1 || niceStep(10) != 2 || niceStep(25) != 5 || niceStep(100) != 20 || niceStep(100000) != 1000 {
		t.Error("niceStep")
	}
	if floorDiv(-7, 2) != -4 || floorDiv(7, 2) != 3 || ceilDiv(-7, 2) != -3 || ceilDiv(7, 2) != 4 || floorDiv(-6, 2) != -3 {
		t.Error("floorDiv/ceilDiv")
	}
}

func TestBuildOpticalChart(t *testing.T) {
	from := time.Date(2026, 10, 3, 0, 0, 0, 0, time.UTC)
	if buildOpticalChart(nil, nil, from, from.Add(time.Hour), nil, nil, time.Local) != nil {
		t.Error("chart without readings")
	}
	noRx := []optPoint{{t: from.Add(time.Minute)}}
	if buildOpticalChart(noRx, nil, from, from.Add(time.Hour), nil, nil, time.Local) != nil {
		t.Error("chart without Rx values")
	}

	// Raw mode: a run, a gap, an isolated reading.
	pts := []optPoint{optAt(0, -315, codeRxLowAlarm), optAt(1, -316, codeRxLowAlarm), optAt(2, -314), optAt(30, -300)}
	periods := alarmPeriods(pts)
	ch := buildOpticalChart(pts, periods, pts[0].t, pts[0].t.Add(time.Hour), ip(-295), ip(-292), time.Local)
	if ch == nil || ch.Bucketed || len(ch.Lines) != 1 || len(ch.Dots) != 1 || len(ch.Hits) != 4 || len(ch.Refs) != 2 ||
		!ch.HasAlarmBand || ch.End == nil || len(ch.YTicks) < 2 || len(ch.XTicks) < 2 {
		t.Fatalf("raw chart = %+v", ch)
	}
	if !strings.Contains(ch.Hits[0].Title, "Rx -31.5 dBm") || !strings.Contains(ch.Hits[0].Title, "Rx power low alarm") {
		t.Errorf("hit title = %q", ch.Hits[0].Title)
	}
	// The warning threshold (-29.2) is above the alarm threshold (-29.5): its label goes above its line.
	for _, r := range ch.Refs {
		y, ly := parseF(t, r.Y), parseF(t, r.LY)
		if r.Class == "warning" && ly >= y || r.Class == "alarm" && ly <= y {
			t.Errorf("label placement %+v", r)
		}
	}

	// Bucketed mode: 2000 readings every minute with a 3-hour hole.
	var many []optPoint
	for i := 0; i < 2000; i++ {
		m := i
		if i >= 1000 {
			m += 180
		}
		p := optAt(m, -315+int64(i%7))
		many = append(many, p)
	}
	end := many[len(many)-1].t.Add(time.Minute)
	ch = buildOpticalChart(many, nil, many[0].t, end, ip(-295), nil, time.Local)
	if ch == nil || !ch.Bucketed || len(ch.Lines) != 2 || len(ch.Bands) != 2 || len(ch.Hits) > maxChartPoints || ch.BucketLabel == "" {
		t.Fatalf("bucketed chart: lines %d bands %d hits %d", len(ch.Lines), len(ch.Bands), len(ch.Hits))
	}
	for _, p := range append(append([]string{}, ch.Lines...), ch.Bands...) {
		if strings.Contains(p, "NaN") || strings.Contains(p, "Inf") {
			t.Fatal("NaN in path")
		}
	}
	for _, h := range ch.Hits {
		x, w := parseF(t, h.X), parseF(t, h.W)
		if x < plotX0-0.05 || x+w > plotX1+1.05 || w <= 0 {
			t.Errorf("hit rect outside plot: %+v", h)
		}
	}
}

func parseF(t *testing.T, s string) float64 {
	t.Helper()
	var f float64
	if _, err := fmt.Sscan(s, &f); err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return f
}

func TestSelectSegments(t *testing.T) {
	seg := func(day int) contracts.SegmentInfo {
		d := time.Date(2026, 10, day, 0, 0, 0, 0, time.UTC)
		return contracts.SegmentInfo{Name: "ledger-" + d.Format("2006-01-02")}
	}
	all := sortedSegments([]contracts.SegmentInfo{seg(5), seg(1), seg(3)}) // dates parsed from names
	if all[0].Name != "ledger-2026-10-01" || all[2].Name != "ledger-2026-10-05" {
		t.Fatalf("sorted = %+v", all)
	}
	at := func(day, h int) time.Time { return time.Date(2026, 10, day, h, 0, 0, 0, time.UTC) }
	tests := []struct {
		from, to time.Time
		want     string
	}{
		{at(2, 0), at(2, 12), "ledger-2026-10-01"},                                    // day 2 is still covered by segment 1
		{at(3, 0), at(4, 0), "ledger-2026-10-01,ledger-2026-10-03"},                   // exactly segment 3
		{at(4, 0), at(9, 0), "ledger-2026-10-01,ledger-2026-10-03,ledger-2026-10-05"}, // 3 spans until 5
		{at(6, 0), at(7, 0), "ledger-2026-10-01,ledger-2026-10-05"},                   // last one is open-ended
		{at(1, 5), at(1, 6), "ledger-2026-10-01"},
	}
	for _, tc := range tests {
		var got []string
		for _, s := range selectSegments(all, tc.from, tc.to) {
			got = append(got, s.info.Name)
		}
		if strings.Join(got, ",") != tc.want {
			t.Errorf("%v..%v = %v, want %s", tc.from, tc.to, got, tc.want)
		}
	}
}
