package ticket

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"attmonitor/internal/model"
)

// Analysis constants (docs/DESIGN.md §6, §9, §10).
const (
	defaultFast = 10 * time.Second
	// bootSameWithin: boot-time estimates closer than this are the same boot (the monitor
	// reports a restart only when the estimate moves by more than 120 s).
	bootSameWithin = 120 * time.Second
	// restartNear: a link change this close after a boot is the boot's own link bring-up.
	restartNear = 15 * time.Minute
	// futureSlack tolerates clock differences when a Last Change reading is compared with the
	// time it was observed.
	futureSlack = 2 * time.Minute
)

var minPlausible = time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)

// Gateway alarm codes (internal/gateway Derive).
const (
	codeRxLowAlarm = "OPTICAL_RX_LOW_ALARM"
	codeRxLowWarn  = "OPTICAL_RX_LOW_WARNING"
)

func isBad(state string) bool {
	return state != "" && state != model.StateOnline && state != model.StateUnknown
}

// analyze computes every part of the report from the collected records.
func (c *collector) analyze(rep *Report, o Options) {
	fast, basis := c.fastInterval()
	c.computeCovers(fast)
	rep.Coverage = c.coverage(fast, basis)
	rep.Avail = c.availability(fast)
	rep.Home = c.home()
	setup := c.setupCapture()
	rep.Optical = c.optical(setup)
	rep.Link = c.link(setup)
	rep.Gateway = c.gatewayInfo(setup)
	rep.Events, rep.EventsOther = c.eventRows()
	rep.Incidents, rep.IncidentsUnlisted = c.incidentRows()
	rep.Evidence = c.evidence(o, setup)
	if setup != nil && setup.LastChange != 0 && setup.Fiber != nil {
		setup.Change = c.interpret(setup.LastChange, time.Time{}, setup.Fiber.Time, setup.Offset)
	}
	op := &rep.Optical
	op.Chart = buildChart(rep)
	// With a chart, the table lists the readings that matter; the chart shows the rest.
	rows := MaxTableRows
	if op.Chart != nil {
		rows = MaxChartTableRows
	}
	op.Rows, op.RowsNote = pickRows(op.Readings, rows)
}

// ---------------------------------------------------------------- cycles and coverage

// fastInterval is the measurement cycle interval: from the latest configuration record of the
// window, else the median spacing of one process's samples, else the default.
func (c *collector) fastInterval() (time.Duration, string) {
	for i := len(c.configs) - 1; i >= 0; i-- {
		if f := c.configs[i].fast; f > 0 {
			return f, "the configuration record " + seqRef(c.configs[i].seq)
		}
	}
	var ds []time.Duration
	prev := map[string]*sampleRec{}
	for _, s := range c.samples {
		if p := prev[s.run]; p != nil {
			if d := s.start.Sub(p.start); d > 0 && d < 10*time.Minute {
				ds = append(ds, d)
			}
		}
		prev[s.run] = s
	}
	if len(ds) >= 3 {
		slices.Sort(ds)
		if med := ds[len(ds)/2].Round(time.Second); med >= time.Second {
			return med, "the median spacing of the samples, as no configuration record is in the window"
		}
	}
	return defaultFast, "the default, as no configuration record is in the window"
}

// computeCovers sets each cycle's cover (docs/DESIGN.md §10): until the next cycle of the same
// process started, at most 1.5 cycle intervals; the last cycle of a process that ended (it
// stopped, or another process took over) only until its record was written; the last cycle of
// the window until the window's end (capped likewise). Covers are clipped to the window.
func (c *collector) computeCovers(fast time.Duration) {
	limit := fast * 3 / 2
	n := len(c.samples)
	next := make([]int, n)
	lastOf := map[string]int{}
	for i, s := range c.samples {
		next[i] = -1
		if j, ok := lastOf[s.run]; ok {
			next[j] = i
		}
		lastOf[s.run] = i
	}
	// otherAfter[i]: a sample of another process follows sample i.
	otherAfter := make([]bool, n)
	runsAfter := map[string]bool{}
	for i := n - 1; i >= 0; i-- {
		r := c.samples[i].run
		otherAfter[i] = len(runsAfter) > 1 || (len(runsAfter) == 1 && !runsAfter[r])
		runsAfter[r] = true
	}
	for i, s := range c.samples {
		var d time.Duration
		switch {
		case next[i] >= 0:
			d = c.samples[next[i]].start.Sub(s.start)
		case otherAfter[i] || c.runEndedAfter(s):
			d = s.rec.Sub(s.start)
		default:
			d = c.to.Sub(s.start)
		}
		d = min(max(d, 0), limit)
		s.end = s.start.Add(d)
		from, to := s.start, s.end
		if from.Before(c.from) {
			from = c.from
		}
		if to.After(c.to) {
			to = c.to
		}
		s.cover = max(to.Sub(from), 0)
	}
}

// runEndedAfter reports whether the process of sample s stopped (monitor_stop), or another
// process started, after it.
func (c *collector) runEndedAfter(s *sampleRec) bool {
	for _, m := range c.marks {
		if m.seq <= s.seq {
			continue
		}
		if (m.typ == model.TypeMonitorStop && m.run == s.run) || (m.typ == model.TypeMonitorStart && m.run != s.run) {
			return true
		}
	}
	return false
}

// timeOrder returns the samples sorted by cycle start.
func (c *collector) timeOrder() []*sampleRec {
	out := slices.Clone(c.samples)
	sort.SliceStable(out, func(i, j int) bool { return out[i].start.Before(out[j].start) })
	return out
}

func (c *collector) coverage(fast time.Duration, basis string) Coverage {
	cv := Coverage{Window: c.to.Sub(c.from), FastInterval: fast, FastBasis: basis, Cycles: len(c.samples)}
	var mon time.Duration
	for _, s := range c.samples {
		mon += s.cover
	}
	cv.MonitoredSec = int64(mon / time.Second)
	if len(c.samples) == 0 {
		cv.Gaps = []Gap{c.gap(c.from, c.to, "whole")}
		return cv
	}
	order := c.timeOrder()
	first, last := order[0], order[len(order)-1]
	cv.FirstSample, cv.FirstSampleSeq = first.start, first.seq
	cv.LastSample, cv.LastSampleSeq = last.start, last.seq
	limit := 3 * fast
	if first.start.Sub(c.from) > limit {
		cv.Gaps = append(cv.Gaps, c.gap(c.from, first.start, "leading"))
	}
	for k := 1; k < len(order); k++ {
		a, b := order[k-1], order[k]
		if b.start.Sub(a.start) > limit {
			cv.Gaps = append(cv.Gaps, c.gap(a.end, b.start, "inner"))
		}
	}
	if end := maxTime(last.end, last.start); c.to.Sub(end) > limit {
		cv.Gaps = append(cv.Gaps, c.gap(end, c.to, "trailing"))
	}
	return cv
}

func maxTime(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

// gap builds a gap and explains it from the records around it.
func (c *collector) gap(from, to time.Time, kind string) Gap {
	if from.Before(c.from) {
		from = c.from
	}
	if to.After(c.to) {
		to = c.to
	}
	g := Gap{From: from, To: to, Sec: int64(max(to.Sub(from), 0) / time.Second), Kind: kind}
	var why []string
	if gen := c.genesis; gen != nil && (kind == "leading" || kind == "whole") && !gen.ts.Before(from) {
		if gen.ts.After(to.Add(time.Minute)) {
			why = append(why, fmt.Sprintf("the evidence ledger did not exist yet (it was created at %s, genesis %s)", fmtUTC(gen.ts), seqRef(gen.seq)))
		} else {
			why = append(why, fmt.Sprintf("the evidence ledger was created only at %s (genesis %s), so the monitor was not installed before then", fmtUTC(gen.ts), seqRef(gen.seq)))
		}
	}
	slack := 30 * time.Second
	n := 0
	for _, m := range c.marks {
		if m.ts.Before(from.Add(-slack)) || m.ts.After(to.Add(slack)) {
			continue
		}
		if n == 3 {
			why = append(why, "and further records")
			break
		}
		why = append(why, fmt.Sprintf("%s at %s (record %s)", m.text, fmtUTC(m.ts), seqRef(m.seq)))
		n++
	}
	switch {
	case len(why) > 0:
		g.Why, g.Brief = strings.Join(why, "; "), why[0]
	case kind == "trailing":
		g.Why = "no measurement cycles after this in the evidence (the monitor was not running, or the evidence ends here)"
	default:
		g.Why = "no record in the window explains it"
	}
	if g.Brief == "" {
		g.Brief = g.Why
	}
	return g
}

// ---------------------------------------------------------------- availability & blips

type span struct{ from, to time.Time }

// incidentSpans are the time spans of the window's incidents (to the latest record while open).
func (c *collector) incidentSpans() []span {
	var out []span
	for _, ir := range c.incs {
		o, ok := parseTS(ir.inc.Opened)
		if !ok {
			continue
		}
		end, ok := parseTS(ir.inc.Closed)
		if !ok {
			end = c.to
		}
		out = append(out, span{o, end})
	}
	return out
}

func (c *collector) availability(fast time.Duration) Availability {
	a := Availability{ByState: map[string]int{}}
	for _, s := range c.samples {
		st := s.state
		if st == "" {
			st = model.StateUnknown
		}
		a.Cycles++
		a.ByState[st]++
		if st != model.StateUnknown {
			a.Classified++
		}
		if st == model.StateOnline {
			a.Online++
		}
	}
	a.Pct = "n/a"
	if a.Classified > 0 {
		a.Pct = fmtShare(int64(a.Online), int64(a.Classified))
	}
	spans := c.incidentSpans()
	inIncident := func(s *sampleRec) bool {
		if s.incident != "" {
			return true
		}
		for _, sp := range spans {
			if !s.start.Before(sp.from) && !s.start.After(sp.to) {
				return true
			}
		}
		return false
	}
	var prev *sampleRec
	inBlip := false
	for _, s := range c.timeOrder() {
		cont := prev != nil && prev.run == s.run && s.start.Sub(prev.start) <= 3*fast
		if isBad(s.state) && !inIncident(s) {
			if !inBlip || !cont {
				a.Blips++
			}
			inBlip = true
			a.BlipCycles++
			a.BlipSec += int64(s.cover / time.Second)
			if s.state == model.StateISPOutage {
				a.BlipOutageSec += int64(s.cover / time.Second)
			}
		} else {
			inBlip = false
		}
		prev = s
	}
	return a
}

// ---------------------------------------------------------------- home network

func (c *collector) home() Home {
	h := Home{LatencyOKMs: 20}
	for i := len(c.configs) - 1; i >= 0; i-- {
		if v := c.configs[i].latencyOK; v > 0 {
			h.LatencyOKMs = v
			break
		}
	}
	var rtts []int64
	for _, s := range c.samples {
		h.Cycles++
		if s.gwICMP >= 0 {
			h.GwProbes++
			if s.gwICMP == 1 {
				h.GwOK++
				rtts = append(rtts, s.gwRTT)
			}
		}
		if s.lan >= 0 {
			h.LANKnown++
			if s.lan == 1 {
				h.LANUp++
			} else {
				h.LANDown++
			}
		}
	}
	if len(rtts) > 0 {
		slices.Sort(rtts)
		m := len(rtts) / 2
		h.GwMedianUs = rtts[m]
		if len(rtts)%2 == 0 {
			h.GwMedianUs = (rtts[m-1] + rtts[m]) / 2
		}
	}
	for i := range c.links {
		lr := &c.links[i]
		h.Links++
		l := lr.l
		if l.Type == "wifi" && l.SignalPct > 0 {
			if h.SignalMin == 0 || l.SignalPct < h.SignalMin {
				h.SignalMin = l.SignalPct
			}
			h.SignalMax = max(h.SignalMax, l.SignalPct)
		}
		if st := strings.ToLower(strings.TrimSpace(l.State)); st != "" && st != "connected" {
			h.Disconnected++
		}
		if e := l.Egress; e != nil && e.Err == "" {
			h.EgressChecks++
			if e.Bypass {
				if h.EgressBypass == 0 {
					h.BypassSeq = lr.seq
				}
				h.EgressBypass++
			}
		}
		h.Latest, h.LatestSeq = &lr.l, lr.seq
	}
	lossOK := h.GwProbes > 0 && (h.GwProbes-h.GwOK)*100 <= h.GwProbes
	rttOK := len(rtts) > 0 && float64(h.GwMedianUs) < h.LatencyOKMs*1000
	lanOK := h.LANKnown > 0 && h.LANDown*1000 <= h.LANKnown
	h.Healthy = lossOK && rttOK && lanOK && h.Disconnected == 0 && h.EgressBypass == 0
	return h
}

// ---------------------------------------------------------------- optical readings

func hasCode(codes []string, code string) bool { return slices.Contains(codes, code) }

func readingFromDerived(d model.GatewayDerived, t time.Time, seq uint64) (Reading, bool) {
	if d.RxPowerX10 == nil {
		return Reading{}, false
	}
	linkDown := (d.OpticalUp != nil && !*d.OpticalUp) || (d.PONOperational != nil && !*d.PONOperational)
	return Reading{T: t, Seq: seq, RxX10: *d.RxPowerX10, TxX10: d.TxPowerX10, AlarmThr: d.RxLowAlarmX10, WarnThr: d.RxLowWarnX10,
		Codes: d.Alarms, Alarm: hasCode(d.Alarms, codeRxLowAlarm), Warn: hasCode(d.Alarms, codeRxLowWarn),
		NoLight: *d.RxPowerX10 == 0 && linkDown}, true
}

func (c *collector) optical(setup *Setup) Optical {
	op := Optical{MinI: -1, MaxI: -1, LatestI: -1, OtherCodes: map[string]int{}}
	for _, s := range c.snaps {
		if rd, ok := readingFromDerived(s.d, s.fiberTime(), s.seq); ok {
			op.Readings = append(op.Readings, rd)
		}
	}
	if setup != nil && setup.Rx != nil {
		if setup.InWindow {
			op.Readings = append(op.Readings, *setup.Rx)
		} else {
			rx := *setup.Rx
			op.SetupOutside = &rx
		}
	}
	sort.SliceStable(op.Readings, func(i, j int) bool { return op.Readings[i].T.Before(op.Readings[j].T) })
	for i, rd := range op.Readings {
		if rd.Alarm {
			op.AlarmN++
		}
		if rd.Warn {
			op.WarnN++
		}
		if rd.NoLight {
			op.NoLightN++
		} else {
			op.Levels++
			if op.MinI < 0 || rd.RxX10 < op.Readings[op.MinI].RxX10 {
				op.MinI = i
			}
			if op.MaxI < 0 || rd.RxX10 > op.Readings[op.MaxI].RxX10 {
				op.MaxI = i
			}
		}
		for _, code := range rd.Codes {
			if code != codeRxLowAlarm && code != codeRxLowWarn {
				op.OtherCodes[code]++
			}
		}
	}
	op.LatestI = len(op.Readings) - 1
	for i := len(op.Readings) - 1; i >= 0; i-- {
		rd := op.Readings[i]
		if rd.AlarmThr != nil || rd.WarnThr != nil {
			op.AlarmThr, op.WarnThr = rd.AlarmThr, rd.WarnThr
			break
		}
	}
	for _, rd := range op.Readings {
		if (rd.AlarmThr != nil && !eqPtr(rd.AlarmThr, op.AlarmThr)) || (rd.WarnThr != nil && !eqPtr(rd.WarnThr, op.WarnThr)) {
			op.ThrVaried = true
		}
	}
	for _, p := range stepPairs(op.Readings) {
		st := Step{From: op.Readings[p[0]], To: op.Readings[p[1]]}
		for _, rd := range op.Readings[p[0]+1 : p[1]] {
			st.NoLight = append(st.NoLight, rd.Seq) // only no-light readings lie between them
		}
		op.Steps = append(op.Steps, st)
	}
	c.alarmRuns(&op)
	return op
}

// stepPairs returns the index pairs of consecutive readings with a level whose levels differ by
// StepMinX10 or more (no-light readings between them are skipped).
func stepPairs(rs []Reading) [][2]int {
	var out [][2]int
	prev := -1
	for i, rd := range rs {
		if rd.NoLight {
			continue
		}
		if prev >= 0 {
			if d := rd.RxX10 - rs[prev].RxX10; d >= StepMinX10 || d <= -StepMinX10 {
				out = append(out, [2]int{prev, i})
			}
		}
		prev = i
	}
	return out
}

// alarmRuns finds the runs of readings with the gateway's low-Rx ALARM flag set and the last
// clearing of the flag, with the gateway_event optical_alarm that reported it. Only readings with
// a level count: what the gateway flags while it shows no receive level says nothing about the
// level.
func (c *collector) alarmRuns(op *Optical) {
	var start, prev *Reading
	inRun := false
	for i := range op.Readings {
		rd := &op.Readings[i]
		if rd.NoLight {
			continue
		}
		switch {
		case rd.Alarm && !inRun:
			inRun, start = true, rd
			op.AlarmRuns++
		case !rd.Alarm && inRun:
			inRun = false
			op.Clear = &AlarmClear{SetFrom: *start, LastSet: *prev, Cleared: *rd}
		}
		prev = rd
	}
	if inRun || op.Clear == nil {
		op.Clear = nil
		return
	}
	cl := op.Clear
	for _, e := range c.events {
		if e.e.Kind != model.GwEvOpticalAlarm || e.ts.Before(cl.LastSet.T) || e.ts.After(cl.Cleared.T.Add(futureSlack)) {
			continue
		}
		if strings.Contains(e.e.Before, codeRxLowAlarm) && !strings.Contains(e.e.After, codeRxLowAlarm) {
			cl.EventSeq = e.seq
			break
		}
	}
}

func eqPtr(a, b *int64) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

// pickRows downsamples the readings for the table: at most maxRows rows. It always keeps the
// first, the latest, the lowest and the setup capture; then every change of the gateway's flags
// and every reading taken while the fiber link was down (an even selection of each, in
// proportion, when they do not all fit), the highest, and readings filling the largest
// stretches between kept rows. The note says exactly which readings are listed.
func pickRows(rs []Reading, maxRows int) ([]ReadingRow, string) {
	n := len(rs)
	if n == 0 {
		return nil, ""
	}
	why := map[int][]string{}
	add := func(i int, w string) {
		if w != "" && slices.Contains(why[i], w) {
			return
		}
		if w == "" {
			if _, ok := why[i]; !ok {
				why[i] = nil
			}
			return
		}
		why[i] = append(why[i], w)
	}
	kept := func(i int) bool { _, ok := why[i]; return ok }
	minI, maxI := -1, -1
	for i, rd := range rs {
		if rd.NoLight {
			continue
		}
		if minI < 0 || rd.RxX10 < rs[minI].RxX10 {
			minI = i
		}
		if maxI < 0 || rd.RxX10 > rs[maxI].RxX10 {
			maxI = i
		}
	}
	add(0, "first")
	add(n-1, "latest")
	if minI >= 0 {
		add(minI, "lowest")
	}
	var dark, setup []int
	for i, rd := range rs {
		if rd.Setup {
			add(i, "setup capture")
			setup = append(setup, i)
		}
		if rd.NoLight {
			dark = append(dark, i)
		}
	}
	// Both readings of a step change of the level, while there is room.
	steps, stepsListed := stepPairs(rs), 0
	for _, p := range steps {
		if len(why)+2 > maxRows {
			break
		}
		add(p[0], "before a step change")
		add(p[1], "after a step change")
		stepsListed++
	}
	var changes []int
	for i := 1; i < n; i++ {
		if rs[i].Alarm != rs[i-1].Alarm || rs[i].Warn != rs[i-1].Warn {
			changes = append(changes, i)
		}
	}
	// The flag changes and the link-down readings not kept yet share the room left, in
	// proportion, when they do not all fit.
	notKept := func(idx []int) []int {
		var out []int
		for _, i := range idx {
			if !kept(i) {
				out = append(out, i)
			}
		}
		return out
	}
	nc, nd := notKept(changes), notKept(dark)
	room := max(maxRows-len(why), 0)
	kc, kd := len(nc), len(nd)
	if kc+kd > room {
		kc = min(len(nc), (room*len(nc)+(len(nc)+len(nd))/2)/(len(nc)+len(nd)))
		kd = min(len(nd), room-kc)
		kc = min(len(nc), room-kd)
	}
	for _, i := range evenly(nc, kc) {
		add(i, "")
	}
	for _, i := range evenly(nd, kd) {
		add(i, "")
	}
	for _, i := range changes {
		if kept(i) {
			add(i, "flag change")
		}
	}
	for _, i := range dark {
		if kept(i) {
			add(i, "fiber link down")
		}
	}
	highest := false
	if maxI >= 0 && (kept(maxI) || len(why) < maxRows) {
		add(maxI, "highest")
		highest = true
	}
	categorized := len(why)
	// Fill: repeatedly take the middle of the largest stretch between kept rows.
	for len(why) < maxRows && len(why) < n {
		keys := sortedKeys(why)
		bestGap, at := 1, -1
		for k := 1; k < len(keys); k++ {
			if g := keys[k] - keys[k-1]; g > bestGap {
				bestGap, at = g, keys[k-1]+g/2
			}
		}
		if at < 0 {
			break
		}
		add(at, "")
	}
	keys := sortedKeys(why)
	rows := make([]ReadingRow, 0, len(keys))
	for _, i := range keys {
		rows = append(rows, ReadingRow{Reading: rs[i], Why: strings.Join(why[i], ", ")})
	}
	if len(rows) == n {
		return rows, ""
	}
	listed := func(idx []int) int {
		k := 0
		for _, i := range idx {
			if kept(i) {
				k++
			}
		}
		return k
	}
	parts := []string{"the first", "the latest"}
	if minI >= 0 {
		parts = append(parts, "the lowest")
	}
	if highest {
		parts = append(parts, "the highest")
	}
	if len(setup) > 0 {
		parts = append(parts, "the setup capture")
	}
	if len(steps) > 0 {
		if stepsListed == len(steps) {
			parts = append(parts, fmt.Sprintf("both readings of every step change of %s dB or more (%d)", fmtX10(StepMinX10), len(steps)))
		} else {
			parts = append(parts, fmt.Sprintf("both readings of %d of the %d step changes of %s dB or more", stepsListed, len(steps), fmtX10(StepMinX10)))
		}
	}
	if len(changes) > 0 {
		if k := listed(changes); k == len(changes) {
			parts = append(parts, fmt.Sprintf("every change of the gateway's flags (%d)", k))
		} else {
			parts = append(parts, fmt.Sprintf("%d of the %d changes of the gateway's flags, evenly chosen", k, len(changes)))
		}
	}
	if len(dark) > 0 {
		if k := listed(dark); k == len(dark) {
			parts = append(parts, fmt.Sprintf("every reading taken while the fiber link was down (%d)", k))
		} else {
			parts = append(parts, fmt.Sprintf("%d of the %d readings taken while the fiber link was down, evenly chosen", k, len(dark)))
		}
	}
	note := fmt.Sprintf("%d of %d readings are listed: %s", len(rows), n, joinAnd(parts))
	if len(rows) > categorized {
		note += "; the others fill the largest stretches between them"
	}
	return rows, note + ". Every reading is in the gateway_snapshot records of the bundle."
}

// evenly picks k of idx, spread evenly and including the first and the last when k >= 2.
func evenly(idx []int, k int) []int {
	switch {
	case k <= 0:
		return nil
	case k >= len(idx):
		return idx
	case k == 1:
		return idx[:1]
	}
	out := make([]int, 0, k)
	for j := 0; j < k; j++ {
		out = append(out, idx[j*(len(idx)-1)/(k-1)])
	}
	return out
}

func sortedKeys(m map[int][]string) []int {
	keys := make([]int, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

// ---------------------------------------------------------------- fiber link & restarts

// clockOffset derives the gateway clock's UTC offset from its zone-less local time raw (sysinfo
// "Current Date/Time") and the time the page was fetched: the difference rounded to 15 minutes,
// provided the clock is within 3 minutes of that. A time ending in "Z" is UTC (the gateway shows
// "Z" when no time zone is set).
func clockOffset(raw string, fetched time.Time) (time.Duration, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" || fetched.IsZero() {
		return 0, false
	}
	if t, err := time.Parse(time.RFC3339, raw); err == nil {
		// The gateway states its zone ("Z" = no zone set: UTC); trust it only when its clock
		// agrees with the fetch time.
		if d := t.Sub(fetched); d < -3*time.Minute || d > 3*time.Minute {
			return 0, false
		}
		_, off := t.Zone()
		return time.Duration(off) * time.Second, true
	}
	var wall time.Time
	ok := false
	for _, layout := range []string{"2006-01-02T15:04:05", "2006-01-02 15:04:05"} {
		if t, err := time.ParseInLocation(layout, raw, time.UTC); err == nil {
			wall, ok = t, true
			break
		}
	}
	if !ok {
		return 0, false
	}
	diff := wall.Sub(fetched)
	r := diff.Round(15 * time.Minute)
	if d := diff - r; d < -3*time.Minute || d > 3*time.Minute || r < -14*time.Hour || r > 14*time.Hour {
		return 0, false
	}
	return r, true
}

// gatewayOffset returns the gateway clock's UTC offset from the latest snapshot that states the
// clock, else from the setup-time capture.
func (c *collector) gatewayOffset(setup *Setup) (*time.Duration, string) {
	for i := len(c.snaps) - 1; i >= 0; i-- {
		s := c.snaps[i]
		if s.sys == nil {
			continue
		}
		if off, ok := clockOffset(s.sys.GatewayTimeRaw, s.sysTime()); ok {
			return &off, fmt.Sprintf("its clock read %s when snapshot %s fetched it at %s", strings.TrimSpace(s.sys.GatewayTimeRaw), seqRef(s.seq), fmtUTC(s.sysTime()))
		}
	}
	if setup != nil && setup.Offset != nil {
		return setup.Offset, fmt.Sprintf("its clock read %s in %s", setup.ClockRaw, setupRef(setup.Seq))
	}
	return nil, ""
}

// interpret reads a fiberstat Last Change value both ways the gateway may mean it. A reading
// is possible when it lies between the last observation of the previous value (after; zero when
// unknown) and the first observation of this value (observed), give or take futureSlack: the
// gateway can only report a change that has happened, and one that happened after the value
// before it was read.
func (c *collector) interpret(v int64, after, observed time.Time, off *time.Duration) LinkChange {
	ch := LinkChange{Value: v, Observed: observed, PrevObserved: after}
	if v <= 0 || v > 1<<40 {
		return ch
	}
	t := time.Unix(v, 0).UTC()
	if t.Before(minPlausible) || t.After(observed.Add(24*time.Hour)) {
		return ch
	}
	possible := func(x time.Time) bool {
		return !x.After(observed.Add(futureSlack)) && (after.IsZero() || !x.Before(after.Add(-futureSlack)))
	}
	ch.Plausible = true
	ch.AsUTC = t
	ch.UTCPossible = possible(t)
	if off != nil {
		ch.AsLocal = t.Add(-*off)
		ch.LocalPossible = possible(ch.AsLocal)
	}
	in := func(x time.Time) bool { return !x.IsZero() && !x.Before(c.from) && x.Before(c.to) }
	ch.InWindow = (ch.UTCPossible && in(ch.AsUTC)) || (ch.LocalPossible && in(ch.AsLocal))
	return ch
}

// possibleTimes are the readings of a change that are possible (not after its observation).
func (ch LinkChange) possibleTimes() []time.Time {
	var out []time.Time
	if ch.UTCPossible {
		out = append(out, ch.AsUTC)
	}
	if ch.LocalPossible && !ch.AsLocal.Equal(ch.AsUTC) {
		out = append(out, ch.AsLocal)
	}
	return out
}

type lcObs struct {
	t     time.Time
	v     int64
	raw   string
	seq   uint64
	setup bool
}

type upObs struct {
	t      time.Time
	boot   time.Time
	uptime int64
	seq    uint64
	setup  bool
}

func (c *collector) link(setup *Setup) Link {
	lk := Link{UptimeSec: -1}
	lk.Offset, lk.OffsetSrc = c.gatewayOffset(setup)

	snapBySeq := map[uint64]*snapRec{}
	for _, s := range c.snaps {
		snapBySeq[s.seq] = s
	}
	var obs []lcObs
	if setup != nil && setup.InWindow && setup.Fiber != nil && setup.LastChange != 0 {
		obs = append(obs, lcObs{t: setup.Fiber.Time, v: setup.LastChange, seq: setup.Seq, setup: true})
	}
	for _, s := range c.snaps {
		if s.fiber == nil || strings.TrimSpace(s.fiber.LastChangeRaw) == "" {
			continue
		}
		v := s.fiber.LastChangeUnix
		if v == 0 {
			v = s.d.FiberLastChange
		}
		if v == 0 {
			continue
		}
		obs = append(obs, lcObs{t: s.fiberTime(), v: v, raw: s.fiber.LastChangeRaw, seq: s.seq})
	}
	sort.SliceStable(obs, func(i, j int) bool { return obs[i].t.Before(obs[j].t) })
	lk.Observations = len(obs)
	seen := map[int64]bool{}
	if len(obs) > 0 {
		f := obs[0]
		lk.First = c.interpret(f.v, time.Time{}, f.t, lk.Offset)
		lk.First.Seq = f.seq
		if f.setup {
			lk.First.Source = setupRef(f.seq)
		} else {
			lk.First.Source = "snapshot " + seqRef(f.seq)
		}
		if lk.First.InWindow {
			lk.Changes = append(lk.Changes, lk.First)
		}
		seen[f.v] = true
		for _, o := range obs[1:] {
			if o.v == f.v {
				lk.Unchanged++
			}
		}
	}
	for _, e := range c.events {
		if e.e.Kind != model.GwEvOpticalLinkChange {
			continue
		}
		v, err := strconv.ParseInt(strings.TrimSpace(e.e.After), 10, 64)
		if err != nil {
			c.note(fmt.Sprintf("gateway_event %s (optical_link_change) has an unreadable value %q.", seqRef(e.seq), truncate(e.e.After, 40)))
			continue
		}
		// The snapshots the event compares bracket the change.
		after, observed := time.Time{}, e.ts
		if len(e.e.Evidence) == 2 {
			if s := snapBySeq[e.e.Evidence[0]]; s != nil {
				after = s.fiberTime()
			}
			if s := snapBySeq[e.e.Evidence[1]]; s != nil {
				observed = s.fiberTime()
			}
		}
		ch := c.interpret(v, after, observed, lk.Offset)
		ch.Event, ch.Prev, ch.Seq, ch.Evidence = true, strings.TrimSpace(e.e.Before), e.seq, e.e.Evidence
		ch.Source = "gateway_event optical_link_change " + seqRef(e.seq)
		ch.InWindow = true // the event itself lies in the window: the change happened between the snapshots it compares
		lk.Changes = append(lk.Changes, ch)
		seen[v] = true
	}
	for k := 1; k < len(obs); k++ {
		a, b := obs[k-1], obs[k]
		if b.v == a.v || seen[b.v] {
			continue
		}
		seen[b.v] = true
		ch := c.interpret(b.v, a.t, b.t, lk.Offset)
		ch.Prev, ch.Seq, ch.Evidence = strconv.FormatInt(a.v, 10), b.seq, []uint64{a.seq, b.seq}
		ch.Source = "snapshot " + seqRef(b.seq)
		ch.InWindow = true
		lk.Changes = append(lk.Changes, ch)
	}

	// A bracketed change (both observations known) of which only one reading is possible shows
	// which clock the gateway counts Last Change in.
	if lk.Offset != nil && *lk.Offset != 0 {
		for _, ch := range lk.Changes {
			if ch.PrevObserved.IsZero() || !ch.Plausible || ch.UTCPossible == ch.LocalPossible {
				continue
			}
			lk.Confirmed, lk.ConfirmedBy = "UTC", ch.Source
			if ch.LocalPossible {
				lk.Confirmed = "local"
			}
			break
		}
	}

	// Uptime: boot times and restarts.
	var ups []upObs
	if setup != nil && setup.InWindow && setup.UptimeSec >= 0 && !setup.Boot.IsZero() {
		ups = append(ups, upObs{t: setup.Boot.Add(time.Duration(setup.UptimeSec) * time.Second), boot: setup.Boot, uptime: setup.UptimeSec, seq: setup.Seq, setup: true})
	}
	for _, s := range c.snaps {
		if s.sys == nil || s.sys.UptimeSec < 0 {
			continue
		}
		boot, ok := parseTS(s.d.BootTimeEstimate)
		if !ok {
			continue
		}
		ups = append(ups, upObs{t: s.sysTime(), boot: boot, uptime: s.sys.UptimeSec, seq: s.seq})
	}
	sort.SliceStable(ups, func(i, j int) bool { return ups[i].t.Before(ups[j].t) })
	lk.UptimeReadings = len(ups)
	if len(ups) > 0 {
		l := ups[len(ups)-1]
		lk.Boot, lk.BootSeq, lk.UptimeSec, lk.UptimeAt = l.boot, l.seq, l.uptime, l.t
		lk.BootSrc = "snapshot " + seqRef(l.seq)
		if l.setup {
			lk.BootSrc = setupRef(l.seq)
		}
	}
	var groupBoot time.Time
	for _, u := range ups {
		if !groupBoot.IsZero() && absDur(u.boot.Sub(groupBoot)) <= bootSameWithin {
			continue
		}
		groupBoot = u.boot
		if !u.boot.Before(c.from) && u.boot.Before(c.to) {
			src := "uptime reading of snapshot " + seqRef(u.seq)
			if u.setup {
				src = "uptime reading of the setup-time capture"
			}
			lk.Restarts = append(lk.Restarts, Restart{Boot: u.boot, Seq: u.seq, Source: src})
		}
	}
	for _, e := range c.events {
		if e.e.Kind != model.GwEvReboot {
			continue
		}
		boot, ok := parseTS(e.e.After)
		if !ok {
			boot = e.ts
		}
		dup := false
		for i := range lk.Restarts {
			if absDur(lk.Restarts[i].Boot.Sub(boot)) <= bootSameWithin {
				lk.Restarts[i].Source += " and gateway_event reboot " + seqRef(e.seq)
				dup = true
				break
			}
		}
		if !dup {
			lk.Restarts = append(lk.Restarts, Restart{Boot: boot, Seq: e.seq, Source: "gateway_event reboot " + seqRef(e.seq)})
		}
	}
	sort.SliceStable(lk.Restarts, func(i, j int) bool { return lk.Restarts[i].Boot.Before(lk.Restarts[j].Boot) })
	for i := range lk.Changes {
		ch := &lk.Changes[i]
		for _, t := range ch.possibleTimes() {
			for _, r := range lk.Restarts {
				if d := t.Sub(r.Boot); d >= -futureSlack && d <= restartNear {
					ch.Restart = fmt.Sprintf("a gateway restart at about %s (%s)", fmtUTC(r.Boot), r.Source)
				}
			}
		}
	}
	return lk
}

func absDur(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}

// ---------------------------------------------------------------- gateway identity

func (c *collector) gatewayInfo(setup *Setup) GatewayInfo {
	gi := GatewayInfo{UptimeSec: -1}
	var sysS, bbS, fiS *snapRec
	for i := len(c.snaps) - 1; i >= 0; i-- {
		s := c.snaps[i]
		if sysS == nil && s.sys != nil {
			sysS = s
		}
		if bbS == nil && s.bb != nil {
			bbS = s
		}
		if fiS == nil && s.fiber != nil {
			fiS = s
		}
	}
	var sys *model.SystemInfo
	var bb *model.BroadbandStatus
	var fi *model.FiberStatus
	var d model.GatewayDerived
	switch {
	case sysS != nil || bbS != nil || fiS != nil:
		gi.Known = true
		for _, s := range []*snapRec{sysS, bbS, fiS} {
			if s != nil && s.seq >= gi.SourceSeq {
				gi.SourceSeq, gi.At = s.seq, s.rec
			}
		}
		gi.Source = "snapshot " + seqRef(gi.SourceSeq)
		if sysS != nil {
			sys = sysS.sys
			d = sysS.d
			gi.BootTime, _ = parseTS(sysS.d.BootTimeEstimate)
		}
		if bbS != nil {
			bb = bbS.bb
			if sysS == nil {
				d = bbS.d
			}
		}
		if fiS != nil {
			fi = fiS.fiber
			gi.RxX10, gi.TxX10 = fiS.d.RxPowerX10, fiS.d.TxPowerX10
			if rd, ok := readingFromDerived(fiS.d, fiS.fiberTime(), fiS.seq); ok {
				gi.RxNoLight = rd.NoLight
			}
		}
		if seqs := distinctSeqs(sysS, bbS, fiS); len(seqs) > 1 {
			gi.Source = "snapshots " + fmtSeqList(seqs, 3)
		}
	case setup != nil && (setup.sys != nil || setup.bb != nil || setup.fiber != nil):
		gi.Known, gi.SourceSeq, gi.At = true, setup.Seq, setup.captureTime()
		gi.Source = setupRef(setup.Seq)
		sys, bb, fi, d = setup.sys, setup.bb, setup.fiber, setup.derived
		gi.BootTime = setup.Boot
		gi.RxX10, gi.TxX10 = d.RxPowerX10, d.TxPowerX10
	default:
		return gi
	}
	if sys != nil {
		gi.Manufacturer, gi.Model, gi.Serial = sys.Manufacturer, sys.Model, sys.Serial
		gi.Firmware, gi.Hardware, gi.UptimeSec = sys.SoftwareVersion, sys.HardwareVersion, sys.UptimeSec
	}
	if bb != nil {
		gi.Broadband, gi.NetworkType, gi.PON, gi.UNI = bb.Connection, bb.NetworkType, bb.PONLinkStatus, bb.UNIStatus
		gi.WANIPv4, gi.NextHop = d.WANIPv4, d.ISPNextHop
		if gi.WANIPv4 == "" {
			gi.WANIPv4 = bb.IPv4
		}
		if gi.NextHop == "" {
			gi.NextHop = bb.GatewayIPv4
		}
		gi.DNS = strings.Trim(strings.Join([]string{bb.PrimaryDNS, bb.SecondaryDNS}, ", "), ", ")
	}
	if fi != nil {
		gi.OpticalStatus, gi.LinkState, gi.LastChangeRaw = fi.OpticalStatus, fi.LinkState, fi.LastChangeRaw
		gi.ModuleVendor, gi.ModulePN, gi.Wave = fi.VendorName, fi.VendorPN, fi.WaveLength
		gi.RxLOS, gi.OptLOS, gi.TxFault = fi.RxLOSState, fi.OptLOS, fi.TxFaultState
		for _, m := range fi.Measures {
			if strings.EqualFold(strings.TrimSpace(m.Name), "Temperature") && m.Current != nil {
				v := *m.Current
				gi.TempC = &v
			}
		}
	}
	return gi
}

func distinctSeqs(ss ...*snapRec) []uint64 {
	var out []uint64
	for _, s := range ss {
		if s != nil && !slices.Contains(out, s.seq) {
			out = append(out, s.seq)
		}
	}
	slices.Sort(out)
	return out
}

// ---------------------------------------------------------------- events & incidents

var eventLabels = map[string]string{
	model.GwEvReboot:            "Gateway restart",
	model.GwEvFirmwareChange:    "Firmware change",
	model.GwEvWANIPChange:       "WAN IPv4 address",
	model.GwEvBroadbandState:    "Broadband connection",
	model.GwEvPONState:          "PON link state",
	model.GwEvOpticalAlarm:      "Optical alarm flags",
	model.GwEvOpticalLinkChange: "Fiber link change",
	model.GwEvCountersReset:     "WAN counters reset",
	model.GwEvCertChanged:       "Gateway TLS certificate changed",
	model.GwEvGatewayClock:      "Gateway clock blank/set",
	model.GwEvUnreachable:       "Gateway web interface reachability",
}

// housekeeping events are not listed (they concern this monitor, not the service).
func housekeeping(kind string) bool {
	return kind == model.GwEvCertPinned || kind == model.GwEvNotificationSetting
}

func (c *collector) eventRows() ([]EventRow, int) {
	var rows []EventRow
	other := 0
	for _, e := range c.events {
		if housekeeping(e.e.Kind) {
			other++
			continue
		}
		label := eventLabels[e.e.Kind]
		if label == "" {
			label = e.e.Kind
		}
		change := ""
		if b, a := strings.TrimSpace(e.e.Before), strings.TrimSpace(e.e.After); e.e.Kind == model.GwEvOpticalAlarm {
			// Flag codes, comma-joined by the monitor: shown as a list ("none" when no flag is set).
			before := "none"
			if len(e.e.Evidence) < 2 && b == "" {
				before = "first observation"
			}
			change = truncate(codesText(b, before), 120) + " → " + truncate(codesText(a, "none"), 120)
		} else if b != "" || a != "" {
			change = truncate(orNA(b), 70) + " → " + truncate(orNA(a), 70)
		}
		rows = append(rows, EventRow{T: e.ts, Seq: e.seq, Kind: e.e.Kind, Label: label, Change: change,
			Detail: truncate(oneLine(e.e.Detail), 260), Evidence: e.e.Evidence})
	}
	return rows, other
}

// codesText renders a comma-joined list of gateway flag codes as "A, B" (empty when blank).
func codesText(s, empty string) string {
	var out []string
	for _, c := range strings.Split(s, ",") {
		if c = strings.TrimSpace(c); c != "" {
			out = append(out, c)
		}
	}
	if len(out) == 0 {
		return empty
	}
	return strings.Join(out, ", ")
}

func (c *collector) incidentRows() ([]IncidentRow, []string) {
	var rows []IncidentRow
	for _, ir := range c.incs {
		row := IncidentRow{Incident: ir.inc, RecSeq: ir.seq, RecType: ir.typ, RecTS: ir.ts}
		row.OpenedT, _ = parseTS(ir.inc.Opened)
		closed, ok := parseTS(ir.inc.Closed)
		if ok && ir.typ == model.TypeIncidentClose {
			row.ClosedT = closed
		}
		row.OpenAtEnd = row.ClosedT.IsZero()
		switch {
		case ir.inc.DurationSec > 0:
			row.DurationSec = ir.inc.DurationSec
		case !row.ClosedT.IsZero() && !row.OpenedT.IsZero():
			row.DurationSec = int64(row.ClosedT.Sub(row.OpenedT) / time.Second)
		case !row.OpenedT.IsZero():
			row.DurationSec = int64(max(ir.ts.Sub(row.OpenedT), 0) / time.Second)
		}
		row.StartedBefore = !row.OpenedT.IsZero() && row.OpenedT.Before(c.from)
		rows = append(rows, row)
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if !rows[i].OpenedT.Equal(rows[j].OpenedT) {
			return rows[i].OpenedT.Before(rows[j].OpenedT)
		}
		return rows[i].ID < rows[j].ID
	})
	var unlisted []string
	for _, s := range c.samples {
		if id := s.incident; id != "" && c.incs[id] == nil && !slices.Contains(unlisted, id) {
			unlisted = append(unlisted, id)
		}
	}
	return rows, unlisted
}

// ---------------------------------------------------------------- evidence

// tsaLabel names the time-stamp authority of an anchor: the organization of its certificate,
// else its common name, else the host of its URL.
func tsaLabel(a model.Anchor) string {
	if o := dnAttr(a.TSAName, "O"); o != "" {
		return o
	}
	if cn := dnAttr(a.TSAName, "CN"); cn != "" {
		return cn
	}
	if u, err := url.Parse(a.TSAURL); err == nil && u.Host != "" {
		return u.Host
	}
	return orNA(a.TSAURL)
}

func (c *collector) anchorInfo(a anchorRec) *AnchorInfo {
	ai := &AnchorInfo{Seq: a.seq, TS: a.ts, TSA: tsaLabel(a.a), HeadSeq: a.a.HeadSeq, HeadHash: a.a.HeadHash, Token: a.a.TokenSHA256, Reason: a.a.Reason}
	ai.GenTime, _ = parseTS(a.a.GenTime)
	for _, s := range c.seqs {
		if s <= a.a.HeadSeq {
			ai.Covered++
		} else {
			ai.Uncovered++
		}
	}
	return ai
}

// genTime is the anchor's genTime (zero when unreadable: it then never wins a tie).
func (a *anchorRec) genTime() time.Time {
	t, _ := parseTS(a.a.GenTime)
	return t
}

// earlierGen reports whether a's genTime is known and earlier than b's (or b's is unknown).
func earlierGen(a, b *anchorRec) bool {
	ta, tb := a.genTime(), b.genTime()
	return !ta.IsZero() && (tb.IsZero() || ta.Before(tb))
}

// bestAnchor is the trusted anchor covering the most records from seq lo on (the earliest
// such time-stamp on a tie); nil when none covers lo.
func bestAnchor(list []anchorRec, lo uint64) *anchorRec {
	var best *anchorRec
	for i := range list {
		a := &list[i]
		if !a.trusted() || a.a.HeadSeq < lo {
			continue
		}
		if best == nil || a.a.HeadSeq > best.a.HeadSeq || (a.a.HeadSeq == best.a.HeadSeq && earlierGen(a, best)) {
			best = a
		}
	}
	return best
}

// earliestAnchor is the trusted anchor with the earliest genTime covering record seq.
func earliestAnchor(list []anchorRec, seq uint64) *anchorRec {
	var best *anchorRec
	for i := range list {
		a := &list[i]
		if !a.trusted() || a.a.HeadSeq < seq {
			continue
		}
		if best == nil || earlierGen(a, best) {
			best = a
		}
	}
	return best
}

func (c *collector) evidence(o Options, setup *Setup) Evidence {
	ev := Evidence{BundleName: strings.TrimSpace(o.BundleName), BundleSHA256: strings.ToLower(strings.TrimSpace(o.BundleSHA256)),
		Verification: strings.TrimSpace(o.Verification), Setup: setup}
	if g := c.genesis; g != nil {
		ev.HasGenesis, ev.GenesisSeq, ev.GenesisTS = true, g.seq, g.ts
		ev.Fingerprint = strings.ToLower(strings.TrimSpace(g.g.Fingerprint))
		if pk, err := base64.StdEncoding.DecodeString(g.g.PublicKey); err == nil && len(pk) == 32 {
			sum := sha256.Sum256(pk)
			ev.FingerprintOK = hex.EncodeToString(sum[:]) == ev.Fingerprint
		}
		if !ev.FingerprintOK {
			c.note("The genesis record's fingerprint does not match the SHA-256 of its public key.")
		}
		ev.Host = g.g.Host.Hostname
		ev.Software = strings.TrimSpace(g.g.Software.Name + " " + g.g.Software.Version)
	}
	ev.WindowRecords, ev.WindowFirstSeq, ev.WindowLastSeq = c.records, c.firstSeq, c.lastSeq
	for _, a := range c.anchors {
		ev.AnchorsSeen++
		if !a.trusted() {
			ev.AnchorsUntrusted++
		}
	}
	if c.records > 0 {
		if best := bestAnchor(c.anchors, c.firstSeq); best != nil {
			ev.Anchor = c.anchorInfo(*best)
		}
	}
	if setup != nil {
		all := append(slices.Clone(c.startAnchors), c.anchors...)
		if a := earliestAnchor(all, setup.Seq); a != nil {
			setup.Anchor = c.anchorInfo(*a)
			setup.Anchor.Covered, setup.Anchor.Uncovered = 0, 0
		}
	}
	return ev
}

// setupRef names the setup-time capture as a source: "the setup-time capture, bootstrap_import #1".
func setupRef(seq uint64) string { return "the setup-time capture, bootstrap_import " + seqRef(seq) }
