package export

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"attmonitor/internal/model"
)

// Time accounting (docs/DESIGN.md §10, rules 2026.10-4), computed from the sample records of
// the bundle, never from incident spans: each cycle covers the time until the next cycle of
// the same process started, at most 1.5 × the cycle interval; bad cycles inside gateway-restart
// windows are restart time, not downtime and not provider outage time.
//
// The next cycle is the next sample of the same process in ledger order (not in wall-clock
// order: a clock stepped back would interleave the cycles before and after the step), and the
// time between the two cycles is corrected for a wall-clock step between their records
// (linkSample). The last cycle of a process that ended (monitor_stop, a crash and restart)
// covers only until its last observation, the time its sample record was written - as the
// monitor closes an incident left open by a stopped process at that time - not until the next
// process's first cycle.

// acctSample is a sample with what the time accounting needs.
type acctSample struct {
	sampleLite
	fast      time.Duration // cycle interval of the process that wrote it
	cover     time.Duration // time this cycle covers (in-period samples only)
	inPeriod  bool
	inRestart bool
}

// restartWindow is one gateway-restart window.
type restartWindow struct {
	boot      time.Time
	from, to  time.Time
	endReason string
	sources   []string
	seqs      []uint64
	firmware  string
	badCycles int
	restart   time.Duration // bad cycles of the period inside the window
}

// runInterval is the cycle interval one configuration record of a process states.
type runInterval struct {
	t    time.Time
	tsOK bool
	fast time.Duration
}

// runIntervals returns, per process (run), the cycle intervals its configuration records
// (monitor_start, config_state) state, in ledger order.
func (c *collector) runIntervals() map[int32][]runInterval {
	out := map[int32][]runInterval{}
	for _, r := range c.agg.configs {
		if r.params != nil {
			out[r.run] = append(out[r.run], runInterval{t: r.ts, tsOK: r.tsOK, fast: r.params.fast})
		}
	}
	return out
}

// intervalAt returns the cycle interval of a process at t (Unix ns): the one its latest
// configuration record at or before t states, else its first record's (a monitor process keeps
// the configuration it started with, so a config_state written later in the day still states it).
func intervalAt(list []runInterval, t int64) (time.Duration, bool) {
	if len(list) == 0 {
		return 0, false
	}
	at := time.Unix(0, t)
	f := list[0].fast
	for _, ri := range list[1:] {
		if ri.tsOK && !ri.t.After(at) {
			f = ri.fast
		}
	}
	return f, true
}

// timeline returns the samples kept for the period (those shortly before it included, for
// restart windows reaching into it) in time order, each with the cycle interval of the process
// that wrote it and its cover. The interval comes from the configuration that process recorded
// (its monitor_start or config_state records); without one, from the median spacing of the
// samples (or the default when it cannot be measured). basis describes which was used.
func (c *collector) timeline(base params) (tl []acctSample, basis string, firstFast time.Duration) {
	a := &c.agg
	runFast := c.runIntervals()
	tl = make([]acctSample, 0, len(a.preSamples)+len(a.samples))
	for _, s := range a.preSamples {
		tl = append(tl, acctSample{sampleLite: s})
	}
	for _, s := range a.samples {
		tl = append(tl, acctSample{sampleLite: s, inPeriod: true})
	}
	fillSuccessors(tl)
	sort.SliceStable(tl, func(i, j int) bool { return tl[i].t < tl[j].t })

	var inPeriod []sampleLite
	for _, x := range tl {
		if x.inPeriod {
			inPeriod = append(inPeriod, x.sampleLite)
		}
	}
	fallback, fbBasis := base.fast, "default cycle interval (too few samples to measure it; the configuration is not in this bundle)"
	if med, assumed := cadence(inPeriod); !assumed {
		fallback, fbBasis = med, "median interval between samples (the configuration of the process that wrote them is not in this bundle)"
	}
	known, unknown := 0, 0
	end := c.end.UnixNano()
	first := true
	for i := range tl {
		x := &tl[i]
		f, ok := intervalAt(runFast[x.run], x.t)
		if !ok {
			f = fallback
		}
		x.fast = f
		// Every cycle gets its cover (those before the period too: an incident in progress
		// when the period starts is recomputed from all of its cycles).
		x.cover = coverOf(&x.sampleLite, f, end)
		if !x.inPeriod {
			continue
		}
		if ok {
			known++
		} else {
			unknown++
		}
		if first {
			firstFast, first = f, false
		}
	}
	switch {
	case unknown == 0 && known > 0:
		basis = "configuration recorded by the process that wrote the samples (its monitor_start or config_state records)"
	case known == 0:
		basis = fbBasis
		if len(inPeriod) == 0 {
			firstFast = base.fast
			basis = "configuration in force at the start of the period (no samples in the period)"
		}
	default:
		basis = "configuration recorded by the process that wrote the samples (monitor_start or config_state) where available, otherwise the " + fbBasis
	}
	return tl, basis, firstFast
}

// fillSuccessors settles what follows each sample whose successor was not seen while the
// records streamed by (samples built directly, or a successor without a usable start time):
// the next sample in ledger order, of the same process or not.
func fillSuccessors(tl []acctSample) {
	order := make([]int, len(tl))
	for i := range order {
		order[i] = i
	}
	sort.SliceStable(order, func(i, j int) bool { return tl[order[i]].seq < tl[order[j]].seq })
	for k := 0; k+1 < len(order); k++ {
		x, y := &tl[order[k]], &tl[order[k+1]]
		if x.nextKind != nextUnknown {
			continue
		}
		if x.run == y.run {
			x.next, x.nextKind = y.t-x.t, nextSameRun
		} else {
			x.nextKind = nextRunEnded
		}
	}
}

// coverOf is the time a cycle covers (docs/DESIGN.md §10), at most 1.5 × its cycle interval and
// never beyond the end of the period: until the next cycle of its process started; until its
// last observation (its record's time) when its process ended after it; until the end of the
// period when nothing follows it in the bundle.
func coverOf(x *sampleLite, fast time.Duration, end int64) time.Duration {
	var d int64
	switch x.nextKind {
	case nextSameRun:
		d = x.next
	case nextRunEnded:
		if x.rec != 0 {
			d = x.rec - x.t
		}
	default:
		d = end - x.t
	}
	cover := min(max(time.Duration(d), 0), coverCap(fast))
	if rest := time.Duration(end - x.t); cover > rest {
		cover = max(rest, 0)
	}
	return cover
}

// restartWindows derives the gateway-restart windows from the boot times named by records
// (gateway reboot events and the gateway_restarts lists of incident records) and marks the
// samples inside them. Boot times within restartMoveThreshold of each other are one restart.
func (c *collector) restartWindows(tl []acctSample) []*restartWindow {
	boots := append([]bootObs(nil), c.agg.boots...)
	sort.SliceStable(boots, func(i, j int) bool { return boots[i].t.Before(boots[j].t) })
	var out []*restartWindow
	for i := 0; i < len(boots); {
		j := i + 1
		for j < len(boots) && boots[j].t.Sub(boots[i].t) <= restartMoveThreshold {
			j++
		}
		group := boots[i:j]
		i = j
		w := &restartWindow{boot: group[0].t}
		for _, o := range group {
			if o.event { // the monitor's own estimate from its reboot detection
				w.boot = o.t
				break
			}
		}
		for _, o := range group {
			w.sources = appendUnique(w.sources, o.source, 20)
			w.seqs = appendSeqs(w.seqs, 20, append([]uint64{o.seq}, o.evidence...)...)
		}
		w.firmware = c.firmwareAcross(w.boot, group)
		windowBounds(w, tl)
		out = append(out, w)
	}
	// Mark the samples inside a window; the first window containing a sample gets its time.
	for _, w := range out {
		from, to := w.from.UnixNano(), w.to.UnixNano()
		for i := sort.Search(len(tl), func(i int) bool { return tl[i].t >= from }); i < len(tl) && tl[i].t < to; i++ {
			x := &tl[i]
			if x.inRestart {
				continue
			}
			x.inRestart = true
			if x.inPeriod && isBad(x.state) {
				w.badCycles++
				w.restart += x.cover
			}
		}
	}
	return out
}

// windowBounds sets a restart window the way the monitor does (internal/monitor restartSpan): from
// the boot time B, extended back over the consecutive cycles just before B that were classified
// by rule 1 - the gateway did not answer this computer (the power-off and boot period) - up to a
// monitoring gap, until the first cycle after B in which the Internet was reachable, at most
// B + 10 minutes.
func windowBounds(w *restartWindow, tl []acctSample) {
	b := w.boot.UnixNano()
	k := sort.Search(len(tl), func(i int) bool { return tl[i].t >= b })
	from, prev := b, b
	for j := k - 1; j >= 0; j-- {
		x := &tl[j]
		if !x.lanDown() || time.Duration(prev-x.t) > gapLimit(x.fast) {
			break
		}
		from, prev = x.t, x.t
	}
	capEnd := w.boot.Add(restartWindowCap).UnixNano()
	to, reason := capEnd, "10-minute cap"
	for j := k; j < len(tl) && tl[j].t < capEnd; j++ {
		if tl[j].inetReachable() {
			to, reason = tl[j].t, "internet reachable again"
			break
		}
	}
	w.from, w.to, w.endReason = time.Unix(0, from).UTC(), time.Unix(0, to).UTC(), reason
}

// lanDown reports a cycle classified by rule 1 (docs/DESIGN.md §9: the gateway did not answer
// this computer), the cycles a restart window extends back over, as the monitor tells them
// (internal/monitor lanDown): a LOCAL_FAULT verdict whose gateway probes all failed. Without
// gateway probe results the verdict decides, except LOCAL_ROUTE, which the classifier gives only
// when the gateway answered. A cycle of another state (an UNKNOWN cycle cut short by system
// sleep, whose probes all timed out) is not one.
func (x *sampleLite) lanDown() bool {
	if x.state != model.StateLocalFault {
		return false
	}
	if x.lan >= 0 {
		return x.lan == 0
	}
	return !x.localRoute
}

// inetReachable is INET_ANY of a recorded cycle as the monitor tells it (internal/monitor
// inetReachable): an internet probe succeeded, or the verdict is one of rule 3, which implies it
// (results recorded without roles).
func (x *sampleLite) inetReachable() bool {
	return x.inet || x.state == model.StateOnline || x.state == model.StateDegraded
}

// firmwareAcross returns "A -> B" when a firmware change was detected across the restart: a
// firmware_change event comparing the same snapshots as a reboot event of the group, or
// recorded within 30 minutes after the boot.
func (c *collector) firmwareAcross(boot time.Time, group []bootObs) string {
	ev := map[uint64]bool{}
	for _, o := range group {
		for _, s := range o.evidence {
			ev[s] = true
		}
	}
	for _, f := range c.agg.fwChanges {
		match := !f.t.Before(boot) && f.t.Sub(boot) <= 30*time.Minute
		for _, s := range f.evidence {
			match = match || ev[s]
		}
		if match {
			return fmt.Sprintf("%s -> %s (gateway_event firmware_change seq %d)", orNone(f.before), orNone(f.after), f.seq)
		}
	}
	return ""
}

// appendSeqs adds seqs not yet present, keeping at most max entries, sorted.
func appendSeqs(list []uint64, max int, seqs ...uint64) []uint64 {
	for _, s := range seqs {
		if len(list) >= max {
			break
		}
		found := false
		for _, x := range list {
			if x == s {
				found = true
				break
			}
		}
		if !found {
			list = append(list, s)
		}
	}
	sort.Slice(list, func(i, j int) bool { return list[i] < list[j] })
	return list
}

// cycleTimes are the cycle-time figures of the period.
type cycleTimes struct {
	monitored, downtime, degraded, restart, providerOutage, providerDegraded time.Duration
	byState                                                                  map[string]time.Duration
}

// account sums the cycle time of the samples of the period.
func account(tl []acctSample) cycleTimes {
	ct := cycleTimes{byState: map[string]time.Duration{}}
	for _, x := range tl {
		if !x.inPeriod {
			continue
		}
		ct.monitored += x.cover
		st := x.state
		if st == "" {
			st = model.StateUnknown
		}
		ct.byState[st] += x.cover
		if isBad(x.state) && x.inRestart {
			ct.restart += x.cover
			continue
		}
		switch x.state {
		case model.StateISPOutage:
			ct.downtime += x.cover
			if x.attr == model.AttrProvider {
				ct.providerOutage += x.cover
			}
		case model.StateDegraded:
			ct.degraded += x.cover
			if x.attr == model.AttrProvider {
				ct.providerDegraded += x.cover
			}
		}
	}
	return ct
}

// restartEntries lists the restart windows that touch the period.
func (c *collector) restartEntries(ws []*restartWindow) []restartEntry {
	out := []restartEntry{}
	for _, w := range ws {
		inPeriod := !w.boot.Before(c.from) && w.boot.Before(c.end)
		touches := w.from.Before(c.end) && w.to.After(c.from)
		if !inPeriod && !touches {
			continue
		}
		out = append(out, restartEntry{
			BootTime:   w.boot.UTC().Format(time.RFC3339Nano),
			WindowFrom: w.from.Format(time.RFC3339Nano),
			WindowTo:   w.to.Format(time.RFC3339Nano),
			WindowEnd:  w.endReason,
			Sources:    nonNil(w.sources),
			Evidence:   w.seqs,
			Firmware:   w.firmware,
			BadCycles:  w.badCycles,
			RestartSec: int64(w.restart / time.Second),
		})
	}
	return out
}

// restartFact explains, for an incident recorded under rules that had no restart windows, the
// part of its bad cycles that lies inside a restart window found in the records.
func restartFact(inc model.Incident, d time.Duration, boots []string) string {
	return fmt.Sprintf("%s of its bad cycles fall inside a gateway-restart window found in the records (gateway boot at %s). "+
		"It was recorded under rules %s, which did not separate restart time: its recorded figures and attribution include "+
		"that time; this report's summary does not count it as provider outage time.",
		fmtDur(int64(d/time.Second)), strings.Join(boots, ", "), orNone(inc.Rules))
}

// restartTolerance absorbs the differences between the monitor's cycle cover (its monotonic
// clock) and this report's (record times corrected for clock steps beyond clockStepTolerance)
// and the truncation to whole seconds, when an incident's recorded times are compared with the
// ones its cycles give: a cycle in or out of a restart window moves them by a whole cycle.
const restartTolerance = 3 * time.Second

// windowAt returns the first restart window containing t (Unix ns), or nil.
func windowAt(ws []*restartWindow, t int64) *restartWindow {
	for _, w := range ws {
		if t >= w.from.UnixNano() && t < w.to.UnixNano() {
			return w
		}
	}
	return nil
}

// incidentFigures are what an incident's cycles in the bundle give with the restart windows of
// this report (docs/DESIGN.md §10, rules 2026.10-4), counted like the monitor (internal/monitor
// incState): bad cycles inside a window are restart time; the others are the headline, the
// attribution counts and the time without Internet.
type incidentFigures struct {
	cycles, bad, badInWindows, providerOutside int
	degTotal, degProvider                      int    // DEGRADED cycles outside the windows
	worstOutside                               string // most severe state of the bad cycles outside the windows
	linkDownOutside                            bool   // a LOCAL_LINK_DOWN cycle outside the windows
	downtime, degraded, restart                time.Duration
	windows                                    []*restartWindow // the restarts that belong to the incident
}

// figuresOf counts an incident's cycles (opened..end is its span). A restart belongs to the
// incident when its window holds one of its bad cycles, or its boot lies within the incident's
// span (the monitor's slack: one cycle interval plus 10 s before, 10 s after).
func figuresOf(cyc []*acctSample, ws []*restartWindow, opened, end time.Time, fast time.Duration) incidentFigures {
	var f incidentFigures
	held := map[*restartWindow]bool{}
	for _, x := range cyc {
		f.cycles++
		if !isBad(x.state) {
			continue
		}
		f.bad++
		if w := windowAt(ws, x.t); w != nil {
			f.badInWindows++
			f.restart += x.cover
			held[w] = true
			continue
		}
		if x.attr == model.AttrProvider {
			f.providerOutside++
		}
		switch x.state {
		case model.StateISPOutage:
			f.downtime += x.cover
		case model.StateDegraded:
			f.degraded += x.cover
			f.degTotal++
			if x.attr == model.AttrProvider {
				f.degProvider++
			}
		}
		if f.worstOutside == "" || stateRank(x.state) < stateRank(f.worstOutside) {
			f.worstOutside = x.state
		}
		f.linkDownOutside = f.linkDownOutside || x.linkDown
	}
	lo, hi := opened.Add(-(fast + 10*time.Second)), end.Add(10*time.Second)
	for _, w := range ws {
		if held[w] || (!w.boot.Before(lo) && !w.boot.After(hi)) {
			f.windows = append(f.windows, w)
		}
	}
	return f
}

// gatewayRestart: the restart rule decides the incident (docs/DESIGN.md §10, rules 2026.10-4): a
// restart belongs to it, bad cycles lie inside its window, and fewer than open (OpenAfterCycles)
// provider-attributed bad cycles lie outside the windows.
func (f *incidentFigures) gatewayRestart(open int) bool {
	return len(f.windows) > 0 && f.badInWindows > 0 && f.providerOutside < max(open, 1)
}

func (f *incidentFigures) firmwareChanged() bool {
	for _, w := range f.windows {
		if w.firmware != "" {
			return true
		}
	}
	return false
}

// attribution is the incident's attribution under the rules described here: a gateway restart is
// undetermined, or the provider's when the firmware changed across it; otherwise, over the bad
// cycles outside the restart windows, provider for an ISP_OUTAGE headline and for a DEGRADED one
// when most DEGRADED cycles were provider-attributed, local for a local-link fault, undetermined
// otherwise ("" without bad cycles).
func (f *incidentFigures) attribution(open int) string {
	switch {
	case f.gatewayRestart(open) && f.firmwareChanged():
		return model.AttrProvider
	case f.gatewayRestart(open):
		return model.AttrUndetermined
	}
	switch f.worstOutside {
	case "":
		return ""
	case model.StateISPOutage:
		return model.AttrProvider
	case model.StateDegraded:
		if f.degTotal > 0 && 2*f.degProvider > f.degTotal {
			return model.AttrProvider
		}
	case model.StateLocalFault:
		if f.linkDownOutside {
			return model.AttrLocal
		}
	}
	return model.AttrUndetermined
}

// boots lists the boot times of the incident's restarts for prose.
func (f *incidentFigures) boots() []string {
	out := make([]string, 0, len(f.windows))
	for _, w := range f.windows {
		out = append(out, fmtUTC(w.boot.UTC().Format(time.RFC3339Nano)))
	}
	return out
}

// closedIncidentCycles returns the cycles of an incident with a close record: those of the
// process that recorded it from its first bad cycle (first_seq, the sample that started at
// opened) to its last cycle (last_seq), in ledger order - or, for a record that does not name
// them, the cycles that started in its span. complete: every one of them is in the bundle
// (before the end of the period).
func (c *collector) closedIncidentCycles(inc model.Incident, opened, closed time.Time, tl []acctSample, ix *seqIndex) ([]*acctSample, bool) {
	var cyc []*acctSample
	if k, ok := ix.pos[inc.FirstSeq]; ok && inc.FirstSeq != 0 && inc.LastSeq >= inc.FirstSeq {
		if first := &tl[ix.order[k]]; plausibleTime(opened) && first.t == opened.UnixNano() {
			_, lastIn := ix.pos[inc.LastSeq]
			for _, i := range ix.order[k:] {
				x := &tl[i]
				if x.seq > inc.LastSeq {
					break
				}
				if x.run == first.run { // a record of another process in between is not the incident's
					cyc = append(cyc, x)
				}
			}
			return cyc, lastIn
		}
	}
	o, e := clampNs(opened), clampNs(closed)
	for i := sort.Search(len(tl), func(i int) bool { return tl[i].t >= o }); i < len(tl) && tl[i].t < e; i++ {
		cyc = append(cyc, &tl[i])
	}
	return cyc, plausibleTime(opened) && !closed.After(c.end) && len(tl) > 0 && tl[0].t <= o
}

// clampNs returns t in Unix nanoseconds, clamped to the times the exporter handles (1970..2261):
// a record's time outside them must not wrap around onto the samples.
func clampNs(t time.Time) int64 {
	switch {
	case t.Before(minPeriodTime):
		return minPeriodTime.UnixNano()
	case !t.Before(maxPeriodTime):
		return maxPeriodTime.UnixNano() - 1
	}
	return t.UnixNano()
}

// openAfterOf returns the OpenAfterCycles of the process that wrote a sample (its configuration
// records, as for the cycle interval), else the value of the thresholds shown.
func (c *collector) openAfterOf(x *acctSample, shown int) int {
	open, at := shown, time.Unix(0, x.t)
	found := false
	for _, r := range c.agg.configs {
		if r.params == nil || r.run != x.run {
			continue
		}
		if !found || (r.tsOK && !r.ts.After(at)) {
			open, found = r.params.open, true
		}
	}
	return open
}

// restartCheckOf compares the record of an incident (with a close record) with what its cycles
// give with the restart windows of this report, and words every conflict: an attribution the
// restart rule contradicts, and restart time (and with it time without Internet) that differs.
// It returns nil when no restart concerns the incident.
func (c *collector) restartCheckOf(acc *incAcc, f incidentFigures, complete bool, open int) *restartCheck {
	inc := acc.latest
	relevant := len(f.windows) > 0 || f.badInWindows > 0 || inc.Cause == model.CauseGatewayReboot || len(inc.GatewayRestarts) > 0 ||
		(acc.hasRestart && inc.Stats.RestartSec > 0)
	if !relevant {
		return nil
	}
	rc := &restartCheck{Complete: complete, Cycles: f.cycles, BadCycles: f.bad, BadInWindows: f.badInWindows,
		ProviderOutside: f.providerOutside, OpenAfterCycles: open, FirmwareChange: f.firmwareChanged(),
		DowntimeSec: int64(f.downtime / time.Second), DegradedSec: int64(f.degraded / time.Second), RestartSec: int64(f.restart / time.Second),
		Boots: []string{}, GatewayRestart: f.gatewayRestart(open), Attribution: f.attribution(open)}
	for _, w := range f.windows {
		rc.Boots = append(rc.Boots, w.boot.UTC().Format(time.RFC3339Nano))
	}
	if !complete {
		return rc
	}
	boots := strings.Join(f.boots(), ", ")
	if boots == "" {
		boots = "none"
	}
	outside := plural(f.providerOutside, "provider-attributed bad cycle lies", "provider-attributed bad cycles lie")
	// Only a difference the restart windows make is theirs to flag: the restart rule decides the
	// incident, the windows hold some of its bad cycles, or its record applied the restart rule.
	windowsDecide := rc.GatewayRestart || f.badInWindows > 0 || inc.Cause == model.CauseGatewayReboot
	if a := rc.Attribution; windowsDecide && a != "" && a != inc.Attribution {
		var s string
		switch {
		case rc.GatewayRestart:
			fw := ""
			if rc.FirmwareChange {
				fw = " (the gateway firmware changed across the restart: an AT&T-pushed update)"
			}
			s = fmt.Sprintf("its record classifies it as %s / %s with attribution %s, but %d of its %d bad cycles lie inside the "+
				"gateway-restart windows computed from the records (gateway boot at %s) and %s outside them, fewer than the %d that "+
				"open an incident: under rules %s it is a gateway restart (LOCAL_FAULT / GATEWAY_REBOOT) with attribution %s%s.",
				orNone(inc.State), orNone(inc.Cause), orNone(inc.Attribution), f.badInWindows, f.bad, boots, outside, open, rulesDescribed, a, fw)
		case inc.Cause == model.CauseGatewayReboot && f.badInWindows == 0:
			s = fmt.Sprintf("its record classifies it as a gateway restart (GATEWAY_REBOOT) with attribution %s, but none of its bad "+
				"cycles lies inside a gateway-restart window computed from the records: under rules %s its attribution is %s.",
				orNone(inc.Attribution), rulesDescribed, a)
		default:
			s = fmt.Sprintf("its record gives attribution %s (%s / %s), but with the gateway-restart windows computed from the records "+
				"(gateway boot at %s) %d of its %d bad cycles lie inside them and %s outside them (%d open an incident): under "+
				"rules %s its attribution is %s.", orNone(inc.Attribution), orNone(inc.State), orNone(inc.Cause), boots,
				f.badInWindows, f.bad, outside, open, rulesDescribed, a)
		}
		rc.Conflicts = append(rc.Conflicts, "Conflict with the gateway-restart windows: "+s)
	}
	// Whole seconds on both sides (a recorded value is whatever the record holds: no Duration overflow).
	tol := int64(restartTolerance / time.Second)
	if rec := inc.Stats.RestartSec; acc.hasRestart && (rec < 0 || rec-rc.RestartSec > tol || rc.RestartSec-rec > tol) {
		down := ""
		if acc.hasDowntime {
			down = fmt.Sprintf(" and %s without Internet (downtime_s)", fmtDur(inc.Stats.DowntimeSec))
		}
		computed := fmt.Sprintf("the restart windows computed from the records (gateway boot at %s) hold %s of its bad cycles, and its "+
			"ISP_OUTAGE cycles outside them cover %s", boots, fmtDur(rc.RestartSec), fmtDur(rc.DowntimeSec))
		if len(f.windows) == 0 {
			computed = fmt.Sprintf("no gateway-restart window computed from the records concerns it, and its ISP_OUTAGE cycles cover %s",
				fmtDur(rc.DowntimeSec))
		}
		rc.Conflicts = append(rc.Conflicts, fmt.Sprintf("Conflict with the gateway-restart windows: its record counts %s of bad "+
			"cycles in gateway-restart windows (restart_s)%s, but %s.", fmtDur(rec), down, computed))
	}
	return rc
}
