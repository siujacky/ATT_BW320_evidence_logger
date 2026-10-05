package monitor

import (
	"fmt"
	"math"
	"slices"
	"sort"
	"time"

	"attmonitor/internal/model"
)

// seriesKeep is how much cycle history is kept in memory (the longest chart/stat window).
const seriesKeep = 7 * 24 * time.Hour

// seriesRanges maps the chart ranges of contracts.StatusSource.Series to (span, bucket).
var seriesRanges = map[string]struct{ span, step time.Duration }{
	"1h":  {time.Hour, 10 * time.Second},
	"6h":  {6 * time.Hour, time.Minute},
	"24h": {24 * time.Hour, 5 * time.Minute},
	"7d":  {7 * 24 * time.Hour, 30 * time.Minute},
}

// State codes ordered by severity so that "worst" is the maximum.
const (
	stNone uint8 = iota
	stUnknown
	stOnline
	stDegraded
	stLocalFault
	stISPOutage
)

func stateCode(s string) uint8 {
	switch s {
	case model.StateOnline:
		return stOnline
	case model.StateDegraded:
		return stDegraded
	case model.StateLocalFault:
		return stLocalFault
	case model.StateISPOutage:
		return stISPOutage
	case "":
		return stNone
	}
	return stUnknown
}

func stateName(c uint8) string {
	switch c {
	case stOnline:
		return model.StateOnline
	case stDegraded:
		return model.StateDegraded
	case stLocalFault:
		return model.StateLocalFault
	case stISPOutage:
		return model.StateISPOutage
	case stUnknown:
		return model.StateUnknown
	}
	return ""
}

// probeObs is a compact probe outcome.
type probeObs struct {
	id    uint16 // interned probe name
	ok    bool
	rttUs int32
}

// cyclePoint is a compact sample (≈100 bytes; 7 days at 10 s ≈ 6 MB).
type cyclePoint struct {
	t        int64 // cycle start, unix ns
	state    uint8
	tagged   bool // the sample carried an incident id
	provider bool // the verdict was attributed to the provider
	inet     bool // the Internet was reachable (DESIGN §9 INET_ANY; ends a restart window)
	lanDown  bool // the gateway did not answer (DESIGN §9 rule 1; a restart window extends back over it)
	obs      []probeObs
}

type opticalObs struct {
	t          int64
	rx, tx     int64
	hasRx      bool
	hasTx      bool
	rxLowAlarm bool
	rxLowWarn  bool
}

// pointStore keeps recent samples and optical readings for charts and statistics.
type pointStore struct {
	names []string
	index map[string]uint16
	pts   []cyclePoint
	opt   []opticalObs
}

func newPointStore() *pointStore { return &pointStore{index: map[string]uint16{}} }

func (ps *pointStore) intern(name string) uint16 {
	if id, ok := ps.index[name]; ok {
		return id
	}
	if len(ps.names) >= math.MaxUint16 {
		return math.MaxUint16 // absurd number of probe names; lump the rest together
	}
	id := uint16(len(ps.names))
	ps.names = append(ps.names, name)
	ps.index[name] = id
	return id
}

func clampRTT(us int64) int32 {
	if us > math.MaxInt32 {
		return math.MaxInt32
	}
	if us < 0 {
		return 0
	}
	return int32(us)
}

func (ps *pointStore) addSample(start time.Time, s *model.Sample) {
	p := cyclePoint{t: start.UnixNano(), state: stateCode(s.Verdict.State), tagged: s.IncidentID != "",
		provider: s.Verdict.Attribution == model.AttrProvider, inet: inetReachable(s.Verdict.State, s.Probes),
		lanDown: lanDown(s.Verdict, s.Probes)}
	p.obs = make([]probeObs, 0, len(s.Probes))
	for _, r := range s.Probes {
		p.obs = append(p.obs, probeObs{id: ps.intern(r.Name), ok: r.OK, rttUs: clampRTT(r.RTTus)})
	}
	ps.pts = append(ps.pts, p)
}

func (ps *pointStore) addOptical(t time.Time, d model.GatewayDerived) {
	if d.RxPowerX10 == nil && d.TxPowerX10 == nil {
		return
	}
	o := opticalObs{t: t.UnixNano()}
	if d.RxPowerX10 != nil {
		o.rx, o.hasRx = *d.RxPowerX10, true
	}
	if d.TxPowerX10 != nil {
		o.tx, o.hasTx = *d.TxPowerX10, true
	}
	for _, a := range d.Alarms {
		switch a {
		case "OPTICAL_RX_LOW_ALARM":
			o.rxLowAlarm = true
		case "OPTICAL_RX_LOW_WARNING":
			o.rxLowWarn = true
		}
	}
	ps.opt = append(ps.opt, o)
}

// prune drops history older than cutoff (points are appended in time order; a clock step
// backwards only delays pruning).
func (ps *pointStore) prune(cutoff time.Time) {
	c := cutoff.UnixNano()
	i := 0
	for i < len(ps.pts) && ps.pts[i].t < c {
		i++
	}
	ps.pts = dropFront(ps.pts, i)
	j := 0
	for j < len(ps.opt) && ps.opt[j].t < c {
		j++
	}
	ps.opt = dropFront(ps.opt, j)
}

// dropFront removes the first n elements without copying (usually one per cycle). The dropped
// slots are cleared so what they reference can be collected; the dead prefix of the backing
// array is released when append next reallocates, so it never exceeds the live size.
func dropFront[T any](s []T, n int) []T {
	if n <= 0 {
		return s
	}
	clear(s[:n])
	return s[n:]
}

// buildSeries aggregates the stored history into chart buckets.
func (ps *pointStore) buildSeries(rangeName string, now time.Time, probes []model.ProbeSpec, latest *model.GatewaySnapshot) (model.Series, error) {
	r, ok := seriesRanges[rangeName]
	if !ok {
		return model.Series{}, fmt.Errorf("unknown range %q (want 1h, 6h, 24h or 7d)", rangeName)
	}
	first := now.Add(-r.span).Truncate(r.step)
	n := int(now.Sub(first)/r.step) + 1
	type acc struct {
		sum      map[uint16]int64
		ok, tot  map[uint16]int
		worst    uint8
		anyProbe bool
	}
	buckets := make([]acc, n)
	f, step := first.UnixNano(), int64(r.step)
	for _, p := range ps.pts {
		if p.t < f {
			continue
		}
		bi := int((p.t - f) / step)
		if bi >= n {
			continue
		}
		b := &buckets[bi]
		if p.state > b.worst {
			b.worst = p.state
		}
		if b.tot == nil {
			b.sum, b.ok, b.tot = map[uint16]int64{}, map[uint16]int{}, map[uint16]int{}
		}
		for _, o := range p.obs {
			b.tot[o.id]++
			b.anyProbe = true
			if o.ok {
				b.ok[o.id]++
				b.sum[o.id] += int64(o.rttUs)
			}
		}
	}
	s := model.Series{
		Range:   rangeName,
		From:    fmtTS(first),
		To:      fmtTS(now),
		StepSec: int(r.step / time.Second),
		Probes:  probes,
		Points:  make([]model.SeriesPoint, n),
		Optical: []model.OpticalPoint{},
	}
	for i := range buckets {
		b := &buckets[i]
		pt := model.SeriesPoint{T: fmtTS(first.Add(time.Duration(i) * r.step)), State: stateName(b.worst)}
		if b.anyProbe {
			pt.RTTms, pt.Loss = map[string]float64{}, map[string]float64{}
			for id, tot := range b.tot {
				name := ps.names[id]
				okN := b.ok[id]
				pt.Loss[name] = float64(tot-okN) / float64(tot)
				if okN > 0 {
					pt.RTTms[name] = math.Round(float64(b.sum[id])/float64(okN)) / 1000
				}
			}
		}
		s.Points[i] = pt
	}

	// Optical readings: the latest reading per bucket, alarm flags OR-ed over the bucket.
	type optAcc struct {
		o    opticalObs
		have bool
	}
	ob := map[int]*optAcc{}
	var order []int
	for _, o := range ps.opt {
		if o.t < f {
			continue
		}
		bi := int((o.t - f) / step)
		if bi >= n {
			continue
		}
		a := ob[bi]
		if a == nil {
			a = &optAcc{}
			ob[bi] = a
			order = append(order, bi)
		}
		alarm, warn := a.o.rxLowAlarm || o.rxLowAlarm, a.o.rxLowWarn || o.rxLowWarn
		if !a.have || o.t >= a.o.t {
			a.o = o
		}
		a.o.rxLowAlarm, a.o.rxLowWarn, a.have = alarm, warn, true
	}
	for _, bi := range order {
		o := ob[bi].o
		op := model.OpticalPoint{T: fmtTS(time.Unix(0, o.t)), RxLowAlarm: o.rxLowAlarm, RxLowWarn: o.rxLowWarn}
		if o.hasRx {
			v := o.rx
			op.RxX10 = &v
		}
		if o.hasTx {
			v := o.tx
			op.TxX10 = &v
		}
		s.Optical = append(s.Optical, op)
	}
	if latest != nil {
		s.RxLowAlarmX10 = latest.Derived.RxLowAlarmX10
		s.RxLowWarnX10 = latest.Derived.RxLowWarnX10
	}
	return s, nil
}

// gapLimit is the spacing between samples above which the time between them is a monitor
// gap (docs/DESIGN.md §6: > 3× the fast interval), with a floor for very short test intervals.
func gapLimit(fast time.Duration) time.Duration {
	g := 3 * fast
	if g < 2*time.Second {
		g = 2 * time.Second
	}
	return g
}

// restartIntervals returns the restart windows (DESIGN §10, rules 2026.10-3) of the given
// gateway boots over the stored cycles, merged into disjoint intervals.
func (ps *pointStore) restartIntervals(boots []time.Time, gap time.Duration) []interval {
	if len(boots) == 0 || len(ps.pts) == 0 {
		return nil
	}
	pts := ps.pts
	var iv []interval
	for _, b := range boots {
		w := restartSpan(len(pts),
			func(i int) time.Time { return time.Unix(0, pts[i].t) },
			func(i int) bool { return pts[i].lanDown },
			func(i int) bool { return pts[i].inet },
			b, gap)
		if w.to.After(w.from) {
			iv = append(iv, interval{w.from.UnixNano(), w.to.UnixNano()})
		}
	}
	slices.SortFunc(iv, func(a, b interval) int { return cmpInt64(a.start, b.start) })
	var out []interval
	for _, x := range iv {
		if n := len(out); n > 0 && x.start <= out[n-1].end {
			out[n-1].end = max(out[n-1].end, x.end)
			continue
		}
		out = append(out, x)
	}
	return out
}

// restartLead computes the lead of a restart window for an incident whose first cycle started
// at first: the window over the stored cycles before first (see restartLead).
func (ps *pointStore) restartLead(boot, first time.Time, gap time.Duration) restartLead {
	pts := ps.pts
	return leadOf(len(pts),
		func(i int) time.Time { return time.Unix(0, pts[i].t) },
		func(i int) bool { return pts[i].lanDown },
		func(i int) bool { return pts[i].inet },
		boot, first, gap)
}

func cmpInt64(a, b int64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// windowStats computes the statistics of docs/DESIGN.md §10 over [now-span, now]:
//
//   - time accounting counts cycles: each sample covers the time until the next sample
//     started, capped at 1.5 × the fast interval (time beyond that is a monitoring gap);
//     monitored time is the sum, provider_outage_s the time of provider-attributed ISP_OUTAGE
//     cycles outside gateway restart windows (restarts: restartIntervals) and degraded_s the
//     time of DEGRADED cycles;
//   - availability: ONLINE cycles / cycles with a known state;
//   - incidents: incidents overlapping the window;
//   - blips: runs of bad cycles outside every incident (and not tagged with one), ended by a
//     good cycle, an incident cycle or a monitoring gap (a run still going is not counted yet).
func (ps *pointStore) windowStats(name string, span time.Duration, now time.Time, fast time.Duration, incidents []incSpan, restarts []interval) model.WindowStats {
	ws := model.WindowStats{Window: name}
	from := now.Add(-span)
	f, nowNs := from.UnixNano(), now.UnixNano()
	maxCover := int64(coverCap(fast))
	limit := int64(gapLimit(fast))
	spans := sortedSpans(incidents, now)
	busy := mergedSpans(spans, now)
	var monitored, providerOutage, degraded int64
	known, online, blips := 0, 0, 0
	inRun := false
	var prevT int64
	havePrev := false
	for i := range ps.pts {
		p := &ps.pts[i]
		if p.t < f || p.t > nowNs {
			continue
		}
		// Coverage: until the next sample started (or now), capped.
		end := nowNs
		if i+1 < len(ps.pts) && ps.pts[i+1].t <= nowNs {
			end = ps.pts[i+1].t
		}
		d := min(max(end-p.t, 0), maxCover)
		monitored += d
		switch p.state {
		case stISPOutage:
			if p.provider && !contains(restarts, p.t) { // restart time is not provider downtime
				providerOutage += d
			}
		case stDegraded:
			degraded += d
		}

		if havePrev && (p.t-prevT > limit || p.t < prevT) {
			if inRun {
				blips++ // a monitor gap ends a run
			}
			inRun = false
		}
		prevT, havePrev = p.t, true
		switch {
		case p.state == stOnline:
			known++
			online++
			if inRun {
				blips++
			}
			inRun = false
		case p.state >= stDegraded:
			known++
			if p.tagged || contains(busy, p.t) {
				inRun = false // part of an incident: the run before it was not a blip either
				continue
			}
			inRun = true
		}
	}
	ws.MonitoredSec = monitored / int64(time.Second)
	ws.ProviderOutageSec = providerOutage / int64(time.Second)
	ws.DegradedSec = degraded / int64(time.Second)
	if span > 0 {
		ws.CoveragePct = min(round3(100*float64(monitored)/float64(span)), 100)
	}
	if known > 0 {
		ws.AvailabilityPct = round3(100 * float64(online) / float64(known))
	}
	ws.Blips = blips

	for _, inc := range spans {
		if inc.opened.Before(now) && inc.end.After(from) {
			ws.Incidents++
		}
	}
	return ws
}

// incSpan is the part of an incident the statistics need (no evidence lists to copy).
type incSpan struct {
	opened, closed     time.Time // closed is zero while open
	open               bool
	state, attribution string
	end                time.Time // closed, or now while open (set by sortedSpans)
}

// sortedSpans returns the spans ordered by opened, each with its end resolved (an open
// incident, or one without a parseable close time, lasts until now).
func sortedSpans(in []incSpan, now time.Time) []incSpan {
	out := slices.Clone(in)
	for i := range out {
		out[i].end = out[i].closed
		if out[i].open || out[i].end.IsZero() {
			out[i].end = now
		}
	}
	slices.SortFunc(out, func(a, b incSpan) int { return a.opened.Compare(b.opened) })
	return out
}

// interval is [start, end) in unix ns.
type interval struct{ start, end int64 }

// mergedSpans returns the union of the incidents' time spans as disjoint intervals, sorted
// (incidents may overlap after a wall-clock step). An open incident includes now.
func mergedSpans(spans []incSpan, now time.Time) []interval {
	var iv []interval
	for _, s := range spans { // sorted by opened
		end := s.end.UnixNano()
		if s.open || s.closed.IsZero() {
			end = now.UnixNano() + 1
		}
		start := s.opened.UnixNano()
		if end <= start {
			continue
		}
		if n := len(iv); n > 0 && start <= iv[n-1].end {
			iv[n-1].end = max(iv[n-1].end, end)
			continue
		}
		iv = append(iv, interval{start, end})
	}
	return iv
}

// contains reports whether t (unix ns) lies in one of the intervals.
func contains(iv []interval, t int64) bool {
	i := sort.Search(len(iv), func(i int) bool { return iv[i].start > t }) - 1
	return i >= 0 && t < iv[i].end
}

// spanOf converts an incident; ok is false when its opened time cannot be parsed.
func spanOf(inc model.Incident) (incSpan, bool) {
	opened, ok := parseTS(inc.Opened)
	if !ok {
		return incSpan{}, false
	}
	s := incSpan{opened: opened, open: inc.Open, state: inc.State, attribution: inc.Attribution}
	if !inc.Open {
		s.closed, _ = parseTS(inc.Closed)
	}
	return s, true
}

func round3(f float64) float64 { return math.Round(f*1000) / 1000 }
