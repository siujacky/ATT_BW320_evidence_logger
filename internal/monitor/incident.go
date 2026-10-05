package monitor

import (
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"attmonitor/internal/model"
)

// ---------------------------------------------------------------------------- ordering

// stateRank orders states by severity for incident headlines (docs/DESIGN.md §10):
// ISP_OUTAGE > LOCAL_FAULT > DEGRADED.
func stateRank(s string) int {
	switch s {
	case model.StateISPOutage:
		return 3
	case model.StateLocalFault:
		return 2
	case model.StateDegraded:
		return 1
	}
	return 0
}

// causeOrder ranks causes within a state from most to least specific. It follows the rule
// precedence of docs/DESIGN.md §9 (the first matching rule is the most specific diagnosis);
// GATEWAY_REBOOT, assigned after the fact by the restart rules, is the most specific local cause.
var causeOrder = map[string]int{
	model.CauseFiberLinkDown:       0,
	model.CauseWANDown:             1,
	model.CauseISPEdgeUnreachable:  2,
	model.CauseUpstreamUnreachable: 3,

	model.CauseGatewayReboot:      0,
	model.CauseLocalLinkDown:      1,
	model.CauseGatewayUnreachable: 2,
	model.CauseLocalRoute:         3,

	model.CausePacketLoss:        0,
	model.CauseHighLatency:       1,
	model.CauseISPDNSFailure:     2,
	model.CauseGatewayDNSFailure: 3,
}

func causeRank(c string) int {
	if r, ok := causeOrder[c]; ok {
		return r
	}
	return 99
}

// moreSpecific reports whether cause a is more specific than b.
func moreSpecific(a, b string) bool { return causeRank(a) < causeRank(b) }

// isBad: a cycle is bad when its state is not ONLINE (§10). UNKNOWN (no information, e.g. no
// probes configured) is neither good nor bad.
func isBad(state string) bool {
	return state != "" && state != model.StateOnline && state != model.StateUnknown
}

func isGood(state string) bool { return state == model.StateOnline }

// incidentID formats "INC-YYYYMMDD-HHMMSSZ" from the opened time (UTC).
func incidentID(opened time.Time) string {
	return "INC-" + opened.UTC().Format("20060102-150405") + "Z"
}

// ---------------------------------------------------------------------------- evidence

// maxEvidenceSeqsPerType bounds the evidence list of long incidents: per record type the
// first refs are kept and the last slot always holds the most recent record.
const maxEvidenceSeqsPerType = 30

type evidenceList struct {
	refs []model.EvidenceRef
}

// addGroup adds the refs belonging to one ledger record (several refs when a record carries
// several blobs).
func (e *evidenceList) addGroup(typ string, seq uint64, refs []model.EvidenceRef) {
	if len(refs) == 0 {
		return
	}
	seqs := map[uint64]bool{}
	var latest uint64
	for _, r := range e.refs {
		if r.Type != typ {
			continue
		}
		if r.Seq == seq {
			return // already present
		}
		seqs[r.Seq] = true
		if r.Seq > latest {
			latest = r.Seq
		}
	}
	if len(seqs) >= maxEvidenceSeqsPerType {
		e.refs = slices.DeleteFunc(e.refs, func(r model.EvidenceRef) bool { return r.Type == typ && r.Seq == latest })
	}
	e.refs = append(e.refs, refs...)
}

func (e *evidenceList) add(r model.EvidenceRef) { e.addGroup(r.Type, r.Seq, []model.EvidenceRef{r}) }

func (e *evidenceList) sorted() []model.EvidenceRef {
	out := slices.Clone(e.refs)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Seq != out[j].Seq {
			return out[i].Seq < out[j].Seq
		}
		return out[i].Blob < out[j].Blob
	})
	return out
}

// ---------------------------------------------------------------------------- tracker

// cycleObs is one classified, recorded fast cycle as seen by the incident logic.
type cycleObs struct {
	Start   time.Time // cycle start
	TS      time.Time // ts of the sample record
	Seq     uint64    // seq of the sample record
	Verdict model.Verdict
	Probes  []model.ProbeResult
	Refs    []model.EvidenceRef // other records produced by this cycle (state_change)

	// Cover is the time this cycle covers (until the next cycle started, capped); it is only
	// known once the next cycle has started. Set by the tracker.
	Cover time.Duration
}

type actionKind int

const (
	actOpen actionKind = iota + 1
	actUpdate
	actClose
)

type action struct {
	kind actionKind
	st   *incState
}

// Where the tracker put the latest cycle (for its time accounting, settled at the next cycle).
const (
	placedNowhere = iota
	placedRecent
	placedIncident
)

// tracker is the incident state machine of docs/DESIGN.md §10 (rules 2026.10-3). It is
// pure: it only sees cycles (with the seqs of their sample records) and returns what to record.
//
//   - Open when at least openAfter bad cycles fall within the last `window` cycles (a
//     continuous outage or flapping connectivity); opened = start of the earliest of them.
//   - Close after closeAfter consecutive good cycles; closed = start of the first of them.
//   - Time accounting: each cycle covers the time until the next cycle started, capped at
//     maxCover (1.5 × FastInterval); ISP_OUTAGE time is downtime, DEGRADED time is degraded,
//     and bad cycles inside gateway restart windows are restart time instead (incState).
type tracker struct {
	openAfter, closeAfter, window int
	fast, maxCover                time.Duration
	idTaken                       func(string) bool
	recent                        []cycleObs // the last `window` cycles while no incident is open
	open                          *incState
	// blipCycles counts bad cycles that never led to an incident: they left the window, or
	// a discontinuity ended the window, without an incident opening.
	blipCycles int

	last      cycleObs // the latest cycle, whose coverage is settled when the next one starts
	lastWhere int      // placed* constant for last
	haveLast  bool
}

func newTracker(openAfter, closeAfter, window int, fast time.Duration, idTaken func(string) bool) *tracker {
	openAfter, closeAfter, window = max(openAfter, 1), max(closeAfter, 1), max(window, 1)
	if window < openAfter {
		window = openAfter // a window shorter than the threshold could never open an incident
	}
	if fast <= 0 {
		fast = 10 * time.Second
	}
	return &tracker{openAfter: openAfter, closeAfter: closeAfter, window: window, fast: fast, maxCover: coverCap(fast), idTaken: idTaken}
}

// coverCap is the longest time one cycle covers in the time accounting (DESIGN §10): time
// beyond 1.5 × FastInterval until the next cycle is a monitoring gap.
func coverCap(fast time.Duration) time.Duration {
	if fast <= 0 {
		fast = 10 * time.Second
	}
	return fast * 3 / 2
}

func (t *tracker) nextID(first time.Time) string {
	base := incidentID(first)
	id := base
	for n := 2; t.idTaken != nil && t.idTaken(id); n++ {
		id = fmt.Sprintf("%s-%d", base, n)
	}
	return id
}

// openFrom returns the index in cycles of the earliest bad cycle when at least openAfter of
// cycles are bad, else -1.
func (t *tracker) openFrom(cycles []cycleObs) int {
	first, bad := -1, 0
	for i, c := range cycles {
		if isBad(c.Verdict.State) {
			bad++
			if first < 0 {
				first = i
			}
		}
	}
	if bad >= t.openAfter {
		return first
	}
	return -1
}

// withNext returns the window as it will be once a cycle is added (oldest cycles dropped).
func (t *tracker) withNext(o cycleObs) []cycleObs {
	w := append(slices.Clone(t.recent), o)
	if len(w) > t.window {
		w = w[len(w)-t.window:]
	}
	return w
}

// peekTag returns the incident id the sample of a cycle with this verdict should carry: the
// open incident, or the incident this cycle is about to open. It does not change state.
func (t *tracker) peekTag(start time.Time, v model.Verdict) string {
	if t.open != nil {
		return t.open.inc.ID
	}
	if !isBad(v.State) {
		return ""
	}
	w := t.withNext(cycleObs{Start: start, Verdict: v})
	if i := t.openFrom(w); i >= 0 {
		return t.nextID(w[i].Start)
	}
	return ""
}

// settle assigns the latest cycle its coverage now that the next cycle (starting at next)
// is known. A clock stepped backwards gives no coverage rather than a negative one.
func (t *tracker) settle(next time.Time) {
	if !t.haveLast {
		return
	}
	t.haveLast = false
	d := min(max(next.Sub(t.last.Start), 0), t.maxCover)
	switch t.lastWhere {
	case placedRecent:
		if n := len(t.recent); n > 0 && t.recent[n-1].Seq == t.last.Seq {
			t.recent[n-1].Cover = d
		}
	case placedIncident:
		if t.open != nil {
			t.open.settleLast(t.last.Seq, d)
		}
	}
}

func (t *tracker) place(o cycleObs, where int) {
	t.last, t.lastWhere, t.haveLast = o, where, true
}

// pushRecent adds a cycle to the open-rule window; a bad cycle that leaves the window without
// having opened an incident is a blip.
func (t *tracker) pushRecent(o cycleObs) {
	t.recent = append(t.recent, o)
	if n := len(t.recent) - t.window; n > 0 {
		for _, c := range t.recent[:n] {
			t.blipCycles += b2i(isBad(c.Verdict.State))
		}
		t.recent = slices.Clone(t.recent[n:])
	}
}

// observe feeds one recorded cycle to the state machine.
func (t *tracker) observe(o cycleObs) []action {
	t.settle(o.Start)
	st := t.open
	if st == nil {
		t.pushRecent(o)
		if !isBad(o.Verdict.State) {
			t.place(o, placedRecent)
			return nil
		}
		i := t.openFrom(t.recent)
		if i < 0 {
			t.place(o, placedRecent)
			return nil
		}
		st = newIncState(t.nextID(t.recent[i].Start), t.recent[i:], t.fast, t.openAfter)
		t.recent = nil
		t.open = st
		t.place(o, placedIncident)
		return []action{{kind: actOpen, st: st}}
	}
	switch {
	case isBad(o.Verdict.State):
		st.flushGood()
		st.trackRecovery(o)
		changed := st.addCycle(o)
		t.place(o, placedIncident)
		if changed {
			st.ev.add(model.EvidenceRef{Seq: o.Seq, Type: model.TypeSample,
				Note: fmt.Sprintf("headline changed to %s/%s", st.inc.State, st.inc.Cause)})
			for _, r := range o.Refs {
				st.ev.add(r)
			}
			return []action{{kind: actUpdate, st: st}}
		}
		return nil
	case isGood(o.Verdict.State):
		st.trackRecovery(o)
		st.good = append(st.good, o)
		st.addCycle(o) // kept for the restart windows; counted only if a bad cycle follows
		t.place(o, placedIncident)
		if len(st.good) < t.closeAfter {
			return nil
		}
		st.closeAt(st.good[0].Start, o.Seq)
		t.open = nil
		t.haveLast = false
		return []action{{kind: actClose, st: st}}
	default:
		st.addCycle(o) // UNKNOWN inside an incident carries no information either way
		t.place(o, placedIncident)
		return nil
	}
}

// discontinuity describes a break in the time line between two cycles.
type discontinuity struct {
	gap     time.Duration // monitoring really stopped for this long (system sleep, stall); 0: clock step
	step    time.Duration // the wall clock moved this much more than the monotonic clock
	elapsed time.Duration // monotonic time since the previous cycle started
}

// note returns the summary sentence for an incident closed by d: at its last observation
// (recovering=false) or at its first good cycle (recovering=true).
func (d discontinuity) note(recovering bool) string {
	if d.gap > 0 {
		if recovering {
			return fmt.Sprintf("Recovery was observed but not yet confirmed when monitoring was interrupted for %s (for example system sleep); the incident was closed at the first good cycle.",
				d.gap.Round(time.Second))
		}
		return fmt.Sprintf("Monitoring was interrupted for %s (for example system sleep) while this incident was ongoing; it was closed at the last observation and the outcome during the interruption is unknown.",
			d.gap.Round(time.Second))
	}
	step := d.step.Round(time.Second).String()
	if d.step > 0 {
		step = "+" + step
	}
	if recovering {
		return fmt.Sprintf("Recovery was observed but not yet confirmed when the computer's clock was stepped by %s (see the clock_jump record); the incident was closed at the first good cycle so that its times do not straddle the step.", step)
	}
	return fmt.Sprintf("The computer's clock was stepped by %s while this incident was ongoing (see the clock_jump record); monitoring continued, but the incident was closed at its last observation before the step so that its times do not straddle it.", step)
}

// interrupt handles a discontinuity: monitoring stopped (system sleep, stall), or the wall
// clock was stepped so far that incident times would straddle the step. An open incident is
// closed at its last observation - the end of the time its last bad cycle covers (its start
// plus its settled coverage, at most 1.5 fast intervals), never the time its record was
// written, which may lie after a system sleep - since nothing is known about unmonitored time;
// bad cycles of the open-rule window become blips.
func (t *tracker) interrupt(d discontinuity) []action {
	if t.haveLast && t.lastWhere == placedIncident && t.open != nil {
		// The last cycle covers the time until the next cycle, capped (a gap is not covered).
		t.open.settleLast(t.last.Seq, min(max(d.elapsed, 0), t.maxCover))
	}
	t.haveLast = false
	var acts []action
	if st := t.open; st != nil {
		t.open = nil
		closed := st.lastBadEnd()
		note := d.note(false)
		if len(st.good) > 0 {
			closed = st.good[0].Start
			note = d.note(true)
		}
		last := st.lastSeq
		if n := len(st.good); n > 0 && st.good[n-1].Seq > last {
			last = st.good[n-1].Seq
		}
		st.closeAt(closed, last)
		st.notes = append(st.notes, note)
		acts = append(acts, action{kind: actClose, st: st})
	}
	for _, c := range t.recent {
		t.blipCycles += b2i(isBad(c.Verdict.State))
	}
	t.recent = nil
	return acts
}

// ---------------------------------------------------------------------------- incident state

// incCycle is the compact record of one cycle of an incident: what the time accounting and
// the restart rules need to be recomputed when a restart is learned after the fact.
type incCycle struct {
	start    time.Time
	seq      uint64
	cover    time.Duration // time covered until the next cycle (capped); valid when settled
	cause    string
	state    uint8 // stateCode
	provider bool  // the verdict was attributed to the provider
	inet     bool  // the Internet was reachable in this cycle (DESIGN §9 INET_ANY)
	lanDown  bool  // the gateway did not answer this computer (DESIGN §9 rule 1)
	settled  bool
	inWin    bool // inside a gateway restart window
}

func (c *incCycle) bad() bool { return isBad(stateName(c.state)) }

// maxIncCycles bounds the cycle records one incident keeps (7 days at the default fast
// interval, a few MB): beyond it the oldest quarter is folded into fixed totals, which a
// restart learned afterwards no longer reshapes (restarts are learned within minutes, from the
// next snapshot that reads the gateway's uptime). A variable so tests can lower it.
var maxIncCycles = 7 * 24 * 360

// foldedCycles is the accounting of the cycle records folded out of an incident.
type foldedCycles struct {
	badOutside, badInWindows, providerOutside, degProvider, degTotal int
	downtime, degraded, restart                                      time.Duration
	latest                                                           map[string]uint64       // latest folded bad cycle outside restart windows, per state/cause
	winBad                                                           map[int64]time.Duration // folded restart time per restart (boot, unix ns)
	wins                                                             map[int64]restartWin    // restart windows settled when cycles were folded
	lastInet                                                         time.Time               // start of the latest folded cycle that reached the Internet
}

// seqReasons are the verdict reasons of one sample.
type seqReasons struct {
	seq     uint64
	reasons []string
}

// incState is the working state of one incident (open or closing).
type incState struct {
	inc    model.Incident // ID, Opened, Rules, FirstSeq, Stats counts, Causes; State/Cause = headline
	opened time.Time
	fast   time.Duration // fast interval (restart slack and monitoring gaps)
	// openAfter is OpenAfterCycles: the provider-attributed bad cycles outside the restart
	// windows it takes to make an incident with a gateway restart the provider's (DESIGN §10).
	openAfter int

	cycles       []incCycle   // every cycle since the first bad one, in order (the oldest may be folded)
	folded       foldedCycles // accounting of the cycle records folded out of cycles (maxIncCycles)
	good         []cycleObs   // good cycles of a possible closing streak (not yet counted)
	ev           evidenceList
	lastBadStart time.Time // start of the latest bad cycle
	lastSeq      uint64    // seq of the latest sample counted in the incident

	// Gateway restarts inside the incident and their windows (same order, by boot time).
	restarts []restartInfo
	wins     []restartWin

	// The headline over the bad cycles outside restart windows (all bad cycles while no
	// restart is known), with the verdict reasons of its latest cycle. needReasons names a
	// sample whose reasons the headline needs but memory no longer holds (read from the ledger).
	outState, outCause string
	outReasons         []string
	outReasonsSeq      uint64
	needReasons        uint64
	lastReasons        map[string]seqReasons // latest verdict reasons per state/cause

	badOutside, badInWindows, providerOutside int
	degProvider, degTotal                     int // DEGRADED cycles outside restart windows

	// Time accounting (DESIGN §10): ISP_OUTAGE and DEGRADED cycles outside restart windows,
	// and bad cycles inside them.
	downtime, degraded, restartTime time.Duration

	// recovered_at (DESIGN §10): start of the first cycle after the last outage cycle (rule 1
	// or 2) in which every probe succeeded.
	sawOutage   bool
	recoveredAt time.Time

	// Closing.
	closed         time.Time
	closeSeq       uint64
	notes          []string // extra summary sentences (interruption, ...)
	restartDecided bool     // a snapshot with a readable uptime was taken after the close
}

// outageState: the verdict of a cycle classified by rule 1 (LOCAL_FAULT) or rule 2 (ISP_OUTAGE).
func outageState(state string) bool {
	return state == model.StateLocalFault || state == model.StateISPOutage
}

// allProbesOK: the cycle ran probes and every one of them succeeded.
func allProbesOK(probes []model.ProbeResult) bool {
	for _, p := range probes {
		if !p.OK {
			return false
		}
	}
	return len(probes) > 0
}

// trackRecovery maintains recovered_at over the cycles of the incident, in order.
func (st *incState) trackRecovery(o cycleObs) {
	switch {
	case outageState(o.Verdict.State):
		st.sawOutage, st.recoveredAt = true, time.Time{}
	case st.sawOutage && st.recoveredAt.IsZero() && (isGood(o.Verdict.State) || isBad(o.Verdict.State)) && allProbesOK(o.Probes):
		st.recoveredAt = o.Start
	}
}

// newIncState opens an incident from the open-rule window, cycles[0] being its earliest bad
// cycle and the last one the cycle that opened it. Good cycles in between belong to it.
func newIncState(id string, cycles []cycleObs, fast time.Duration, openAfter int) *incState {
	first := cycles[0]
	st := &incState{
		opened:    first.Start,
		fast:      fast,
		openAfter: openAfter,
		inc: model.Incident{
			ID:       id,
			Opened:   fmtTS(first.Start),
			Open:     true,
			Rules:    RulesVersion,
			FirstSeq: first.Seq,
			Stats:    model.IncidentStats{ProbeOK: map[string]int{}, ProbeTotal: map[string]int{}},
		},
	}
	for i, c := range cycles {
		st.trackRecovery(c)
		if isGood(c.Verdict.State) {
			st.count(c, false)
		}
		st.addCycle(c)
		if i < len(cycles)-1 {
			st.settleLast(c.Seq, c.Cover) // the last cycle's coverage is not known yet
		}
		if !isBad(c.Verdict.State) {
			continue
		}
		note := "bad cycle"
		switch {
		case i == len(cycles)-1:
			note = "bad cycle that opened the incident"
		case i == 0:
			note = "first bad cycle"
		}
		st.ev.add(model.EvidenceRef{Seq: c.Seq, Type: model.TypeSample, Note: note})
		for _, r := range c.Refs {
			st.ev.add(r)
		}
	}
	return st
}

func (st *incState) count(o cycleObs, bad bool) {
	s := &st.inc.Stats
	s.Cycles++
	if bad {
		s.BadCycles++
	}
	for _, p := range o.Probes {
		s.ProbeTotal[p.Name]++
		s.ProbeOK[p.Name] += b2i(p.OK)
	}
	if o.Verdict.Cause == model.CauseLocalLinkDown {
		s.LocalLinkDown = true
	}
	if o.Seq > st.lastSeq {
		st.lastSeq = o.Seq
	}
}

func headKey(state, cause string) string { return state + "/" + cause }

// addCycle records one cycle of the incident. A bad cycle is counted and updates the headline;
// good and UNKNOWN cycles are only kept for the restart windows (a good cycle is counted when a
// bad one follows, see flushGood). It reports whether the headline (state or cause) changed.
func (st *incState) addCycle(o cycleObs) bool {
	v := o.Verdict
	c := incCycle{start: o.Start, seq: o.Seq, cause: v.Cause, state: stateCode(v.State),
		provider: v.Attribution == model.AttrProvider, inet: inetReachable(v.State, o.Probes), lanDown: lanDown(v, o.Probes)}
	beforeState, beforeCause := st.inc.State, st.inc.Cause
	bad := isBad(v.State)
	if bad {
		st.count(o, true)
		if v.Cause != "" && !slices.Contains(st.inc.Causes, v.Cause) {
			st.inc.Causes = append(st.inc.Causes, v.Cause)
		}
		st.lastBadStart = o.Start
		if st.lastReasons == nil {
			st.lastReasons = map[string]seqReasons{}
		}
		st.lastReasons[headKey(v.State, v.Cause)] = seqReasons{seq: o.Seq, reasons: v.Reasons}
	}
	st.cycles = append(st.cycles, c)
	if st.windowsMayChange(c.start) {
		st.recompute()
	} else if bad {
		st.addOutside(&st.cycles[len(st.cycles)-1], v.Reasons, true)
	}
	st.syncHeadline()
	if len(st.cycles) > maxIncCycles {
		st.fold()
	}
	return st.inc.State != beforeState || st.inc.Cause != beforeCause
}

// fold moves the oldest quarter of the cycle records into fixed totals (bounded memory for
// long incidents). The live totals do not change; recompute starts from the folded ones.
// Restart windows already settled are frozen as they are, and the cycles of a window still
// waiting for its end are kept.
func (st *incState) fold() {
	k := len(st.cycles) / 4
	for _, w := range st.wins {
		if w.end == endOpen {
			for k > 0 && !st.cycles[k-1].start.Before(w.from) {
				k--
			}
		}
	}
	if k == 0 {
		return
	}
	f := &st.folded
	if f.latest == nil {
		f.latest, f.winBad, f.wins = map[string]uint64{}, map[int64]time.Duration{}, map[int64]restartWin{}
	}
	for j, w := range st.wins {
		if w.end != endOpen {
			f.wins[st.restarts[j].Boot.UnixNano()] = w
		}
	}
	for i := 0; i < k; i++ {
		c := &st.cycles[i]
		if c.inet && c.start.After(f.lastInet) {
			f.lastInet = c.start
		}
		if !c.bad() {
			continue
		}
		if c.inWin {
			f.badInWindows++
			if c.settled {
				f.restart += c.cover
				for j, w := range st.wins {
					if w.contains(c.start) {
						f.winBad[st.restarts[j].Boot.UnixNano()] += c.cover
						break
					}
				}
			}
			continue
		}
		state := stateName(c.state)
		f.badOutside++
		if c.provider {
			f.providerOutside++
		}
		if state == model.StateDegraded {
			f.degTotal++
			if c.provider {
				f.degProvider++
			}
		}
		f.latest[headKey(state, c.cause)] = c.seq
		if c.settled {
			switch state {
			case model.StateISPOutage:
				f.downtime += c.cover
			case model.StateDegraded:
				f.degraded += c.cover
			}
		}
	}
	st.cycles = slices.Clone(st.cycles[k:])
}

// windowsMayChange: a cycle starting at start could change a restart window or fall inside
// one (a window still waiting for its end, or a cycle that began before a window's end, e.g.
// one already running when the restart was learned): recompute instead of adding.
func (st *incState) windowsMayChange(start time.Time) bool {
	for _, w := range st.wins {
		if w.end == endOpen || start.Before(w.to) {
			return true
		}
	}
	return false
}

// addOutside adds a bad cycle outside every restart window to the headline and the
// attribution counts. With reasons, a cycle matching the headline also provides its reasons.
func (st *incState) addOutside(c *incCycle, reasons []string, withReasons bool) {
	state := stateName(c.state)
	st.badOutside++
	if c.provider {
		st.providerOutside++
	}
	if state == model.StateDegraded {
		st.degTotal++
		if c.provider {
			st.degProvider++
		}
	}
	st.mergeHeadline(state, c.cause)
	if withReasons && state == st.outState && c.cause == st.outCause {
		st.outReasons, st.outReasonsSeq, st.needReasons = reasons, c.seq, 0
	}
}

// mergeHeadline folds a bad cycle's state and cause into the headline: the most severe state,
// and at that state the most specific cause (DESIGN §10).
func (st *incState) mergeHeadline(state, cause string) {
	if r := stateRank(state); r > stateRank(st.outState) {
		st.outState, st.outCause = state, cause
	} else if state == st.outState && cause != st.outCause && moreSpecific(cause, st.outCause) {
		st.outCause = cause
	}
}

// account adds a settled cycle's coverage to the time accounting.
func (st *incState) account(c *incCycle) {
	if !c.settled || !c.bad() {
		return
	}
	if c.inWin {
		st.restartTime += c.cover
		return
	}
	switch stateName(c.state) {
	case model.StateISPOutage:
		st.downtime += c.cover
	case model.StateDegraded:
		st.degraded += c.cover
	}
}

// lastBadEnd is the end of the time the incident's latest bad cycle covers: its start plus its
// settled coverage (DESIGN §10 time accounting), or its start while the coverage is not known.
func (st *incState) lastBadEnd() time.Time {
	for i := len(st.cycles) - 1; i >= 0; i-- {
		if c := &st.cycles[i]; c.bad() {
			if c.settled {
				return c.start.Add(c.cover)
			}
			return c.start
		}
	}
	return st.lastBadStart // folded out of the cycle records (only after days of other cycles)
}

// settleLast sets the coverage of the latest cycle (seq) once the next cycle has started.
func (st *incState) settleLast(seq uint64, d time.Duration) {
	n := len(st.cycles)
	if n == 0 {
		return
	}
	c := &st.cycles[n-1]
	if c.seq != seq || c.settled {
		return
	}
	c.cover, c.settled = d, true
	st.account(c)
}

// recompute derives the restart windows, the headline over the bad cycles outside them, the
// attribution counts and the time accounting from the recorded cycles (after a restart was
// learned, or when a cycle may change a window).
func (st *incState) recompute() {
	f := &st.folded
	st.wins = st.wins[:0]
	for _, r := range st.restarts {
		st.wins = append(st.wins, st.windowOf(r))
	}
	prevSeq, prevReasons := st.outReasonsSeq, st.outReasons
	st.outState, st.outCause = "", ""
	for _, k := range sortedKeys(f.latest) {
		state, cause, _ := strings.Cut(k, "/")
		st.mergeHeadline(state, cause)
	}
	st.badOutside, st.badInWindows, st.providerOutside, st.degProvider, st.degTotal = f.badOutside, f.badInWindows, f.providerOutside, f.degProvider, f.degTotal
	st.downtime, st.degraded, st.restartTime = f.downtime, f.degraded, f.restart
	for i := range st.cycles {
		c := &st.cycles[i]
		c.inWin = inRestartWindow(st.wins, c.start)
		if !c.bad() {
			continue
		}
		if c.inWin {
			st.badInWindows++
		} else {
			st.addOutside(c, nil, false)
		}
		st.account(c)
	}
	// The reasons of the headline are those of its latest cycle outside the windows.
	st.outReasons, st.outReasonsSeq, st.needReasons = nil, 0, 0
	if st.outState == "" {
		return
	}
	key := headKey(st.outState, st.outCause)
	seq, found := f.latest[key] // a folded cycle, unless a kept one is later
	for i := len(st.cycles) - 1; i >= 0; i-- {
		if c := &st.cycles[i]; c.bad() && !c.inWin && stateName(c.state) == st.outState && c.cause == st.outCause {
			seq, found = c.seq, true
			break
		}
	}
	if !found {
		return
	}
	switch lr, ok := st.lastReasons[key]; {
	case ok && lr.seq == seq:
		st.outReasons, st.outReasonsSeq = lr.reasons, seq
	case prevSeq == seq && prevSeq != 0:
		st.outReasons, st.outReasonsSeq = prevReasons, seq
	default:
		st.needReasons = seq
	}
}

// windowOf is the restart window of r over the incident's cycles (DESIGN §10): the same window
// the statistics compute over every recorded cycle. The cycles before the incident's first
// cycle enter through r.lead (computed from the monitor's cycle history when r was attached).
func (st *incState) windowOf(r restartInfo) restartWin {
	f := &st.folded
	if w, ok := f.wins[r.Boot.UnixNano()]; ok {
		return w // settled before its cycles were folded
	}
	if !f.lastInet.IsZero() && !f.lastInet.Before(r.Boot) {
		// Learned after its cycles were folded, and the Internet was reachable again among
		// them: the window ended there, before every kept cycle.
		return restartWin{from: r.Boot, to: r.Boot, end: endInternet}
	}
	cs := st.cycles
	if l := r.lead; l.known && r.Boot.Before(l.firstPre) && l.firstPre.Equal(st.opened) {
		if l.end != endOpen {
			// The window ended before the incident's first cycle: it holds none of its cycles.
			return restartWin{from: l.from, to: l.to, end: l.end, back: l.back}
		}
		// No cycle between the boot and the incident reached the Internet: the window reaches
		// into the incident and ends at its first cycle that did (or at the cap).
		w := restartWin{from: l.from, back: l.back, to: r.Boot.Add(restartCap), end: endOpen}
		for i := range cs {
			if !cs[i].start.Before(w.to) {
				w.end = endCap
				break
			}
			if cs[i].inet {
				w.to, w.end = cs[i].start, endInternet
				break
			}
		}
		return w
	}
	return restartSpan(len(cs),
		func(i int) time.Time { return cs[i].start },
		func(i int) bool { return cs[i].lanDown },
		func(i int) bool { return cs[i].inet },
		r.Boot, gapLimit(st.fast))
}

// windowHoldsBadCycle reports whether the window of r contains one of the incident's (kept)
// bad cycles.
func (st *incState) windowHoldsBadCycle(r restartInfo) bool {
	w := st.windowOf(r)
	for i := range st.cycles {
		if c := &st.cycles[i]; c.bad() && w.contains(c.start) {
			return true
		}
	}
	return false
}

// minProviderOutside is the number of provider-attributed bad cycles outside the restart
// windows that makes an incident with a gateway restart the provider's: OpenAfterCycles, the
// number that opens an incident. Fewer are stray cycles of the restart's own shutdown or
// bring-up (the WAN stopping a cycle before the LAN, one more WAN renegotiation after the first
// cycle with Internet) - blips by the rules' own measure, which must not turn an owner's power
// cycle into an AT&T outage. They still count as time without Internet (downtime_s).
func (st *incState) minProviderOutside() int { return max(st.openAfter, 1) }

// rebootHeadline: the incident is a gateway restart (DESIGN §10): it has a restart, bad
// cycles inside the restart windows, and fewer than minProviderOutside provider-attributed bad
// cycles outside them.
func (st *incState) rebootHeadline() bool {
	return len(st.restarts) > 0 && st.providerOutside < st.minProviderOutside() && st.badInWindows > 0
}

// syncHeadline sets inc.State/Cause from the derived headline.
func (st *incState) syncHeadline() {
	if st.rebootHeadline() {
		st.inc.State, st.inc.Cause = model.StateLocalFault, model.CauseGatewayReboot
		return
	}
	st.inc.State, st.inc.Cause = st.outState, st.outCause
}

func (st *incState) firmwareChanged() bool {
	for _, r := range st.restarts {
		if r.fwChanged() {
			return true
		}
	}
	return false
}

// bootInside: a boot at this time lies within the incident's span (with restartSlack).
func (st *incState) bootInside(boot time.Time) bool {
	before, after := restartSlack(st.fast)
	if boot.Before(st.opened.Add(-before)) {
		return false
	}
	return st.closed.IsZero() || !boot.After(st.closed.Add(after))
}

// attachRestart adds a gateway restart that belongs to the incident and re-derives the
// headline, attribution and time accounting. It reports whether the restart was added.
//
// A restart belongs to the incident when its window (DESIGN §10, over every recorded cycle:
// r.lead carries the cycles before the incident) contains one of the incident's bad cycles - also
// when the boot came before the incident's first observed cycle, e.g. after a power failure
// that stopped this computer too, or while it was asleep - or when the boot lies within the
// incident's span (a restart whose window holds no bad cycle is listed but changes nothing).
func (st *incState) attachRestart(r restartInfo) bool {
	for _, x := range st.restarts {
		if sameRestart(x, r) {
			return false
		}
	}
	if !st.bootInside(r.Boot) && !st.windowHoldsBadCycle(r) {
		return false
	}
	st.restarts = append(st.restarts, r)
	slices.SortStableFunc(st.restarts, func(a, b restartInfo) int { return a.Boot.Compare(b.Boot) })
	if !slices.Contains(st.inc.Causes, model.CauseGatewayReboot) {
		st.inc.Causes = append(st.inc.Causes, model.CauseGatewayReboot)
	}
	st.recompute()
	st.syncHeadline()
	if r.EventSeq != 0 {
		st.ev.add(model.EvidenceRef{Seq: r.EventSeq, Type: model.TypeGatewayEvent,
			Note: fmt.Sprintf("gateway restart at about %s (uptime reset)", fmtHuman(r.Boot))})
	}
	if r.PrevSeq != 0 {
		st.ev.add(model.EvidenceRef{Seq: r.PrevSeq, Type: model.TypeGatewaySnapshot, Note: "latest uptime reading before the restart"})
	}
	if r.SnapSeq != 0 {
		st.ev.add(model.EvidenceRef{Seq: r.SnapSeq, Type: model.TypeGatewaySnapshot, Note: "snapshot showing the uptime reset"})
	}
	if r.FWEventSeq != 0 {
		st.ev.add(model.EvidenceRef{Seq: r.FWEventSeq, Type: model.TypeGatewayEvent,
			Note: fmt.Sprintf("firmware changed from %s to %s across the restart", r.FWBefore, r.FWAfter)})
	}
	return true
}

// flushGood counts the pending good cycles as part of the incident (a bad cycle followed).
func (st *incState) flushGood() {
	for _, g := range st.good {
		st.count(g, false)
	}
	st.good = nil
}

func (st *incState) closeAt(closed time.Time, seq uint64) {
	if closed.Before(st.opened) {
		// Only possible after the wall clock was stepped back by less than the discontinuity
		// limit: never record an incident that ends before it began.
		closed = st.opened
	}
	st.closed = closed
	st.closeSeq = seq
	for _, g := range st.good {
		st.ev.add(model.EvidenceRef{Seq: g.Seq, Type: model.TypeSample, Note: "recovery cycle"})
	}
	st.good = nil
}

// attribution applies §10: a gateway restart without provider-attributed bad cycles outside
// its window is undetermined, or the provider's when the firmware changed across it (an
// AT&T-pushed update). Otherwise, over the bad cycles outside restart windows: provider for
// ISP_OUTAGE and for a DEGRADED headline when most DEGRADED cycles were provider-attributed;
// local for a local-link fault; undetermined otherwise.
func (st *incState) attribution() string {
	if st.rebootHeadline() {
		if st.firmwareChanged() {
			return model.AttrProvider
		}
		return model.AttrUndetermined
	}
	switch st.inc.State {
	case model.StateISPOutage:
		return model.AttrProvider
	case model.StateDegraded:
		if st.degTotal > 0 && 2*st.degProvider > st.degTotal {
			return model.AttrProvider
		}
	case model.StateLocalFault:
		if st.inc.Cause == model.CauseLocalLinkDown {
			return model.AttrLocal
		}
	}
	return model.AttrUndetermined
}

// reasons lists the incident's reasons: those of the verdict behind the headline (none for a
// gateway restart headline), then the facts of every restart.
func (st *incState) reasons() []string {
	var out []string
	if !st.rebootHeadline() {
		if st.needReasons != 0 {
			out = append(out, fmt.Sprintf("the verdict behind this classification is the one recorded in sample #%d", st.needReasons))
		} else {
			out = append(out, st.outReasons...)
		}
	}
	for _, r := range st.restarts {
		out = append(out, restartReasons(r)...)
	}
	return out
}

// windowBadTime is the settled time of the bad cycles in restart window i (a cycle in several
// overlapping windows counts for the first), folded cycles included.
func (st *incState) windowBadTime(i int) time.Duration {
	d := st.folded.winBad[st.restarts[i].Boot.UnixNano()]
	for j := range st.cycles {
		c := &st.cycles[j]
		if !c.settled || !c.inWin || !c.bad() || !st.wins[i].contains(c.start) {
			continue
		}
		first := i
		for k := 0; k < i; k++ {
			if st.wins[k].contains(c.start) {
				first = k
				break
			}
		}
		if first == i {
			d += c.cover
		}
	}
	return d
}

// restartNotes states, in the summary, every restart, how its window was accounted and on
// what the attribution rests.
func (st *incState) restartNotes() []string {
	if len(st.restarts) == 0 {
		return nil
	}
	var notes []string
	for i, r := range st.restarts {
		w := st.wins[i]
		s := fmt.Sprintf("The AT&T gateway restarted at about %s (uptime reset)", fmtHuman(r.Boot))
		if r.fwChanged() {
			s += fmt.Sprintf(" and came back with firmware %s instead of %s", r.FWAfter, r.FWBefore)
		}
		from := fmtHuman(w.from)
		if w.back {
			from += ", when the gateway stopped answering this computer,"
		}
		bad := st.windowBadTime(i).Round(time.Second)
		switch w.end {
		case endInternet:
			s += fmt.Sprintf("; the %s of bad cycles from %s until %s, when the Internet was reachable again, are counted as restart time, not as an AT&T outage.",
				bad, from, fmtHuman(w.to))
		case endCap:
			s += fmt.Sprintf("; the %s of bad cycles from %s until %s (10 minutes after the restart, the longest a restart window lasts) are counted as restart time, not as an AT&T outage; later bad cycles are not.",
				bad, from, fmtHuman(w.to))
		default:
			s += fmt.Sprintf("; the bad cycles since %s are counted as restart time, not as an AT&T outage, until the Internet is reachable again (at most until %s; %s so far).",
				from, fmtHuman(w.to), bad)
		}
		notes = append(notes, s)
	}
	// Provider-attributed bad cycles outside the windows that are too few to decide (DESIGN §10).
	stray := ""
	if st.providerOutside > 0 {
		it := "it is"
		if st.providerOutside > 1 {
			it = "they are"
		}
		stray = fmt.Sprintf("%s outside the restart window - fewer than the %d it takes to open an incident, as when the WAN stops a cycle before the gateway shuts down or renegotiates once more after the Internet first came back - so %s counted in the measured time but not taken as an AT&T outage. ",
			plural(st.providerOutside, "provider-attributed bad cycle lies", "provider-attributed bad cycles lie"), st.minProviderOutside(), it)
	}
	switch {
	case st.rebootHeadline() && st.firmwareChanged() && stray == "":
		notes = append(notes, "No provider-attributed bad cycle lies outside the restart window, but the gateway firmware changed across the restart (an AT&T-pushed firmware update), so the incident is attributed to the provider.")
	case st.rebootHeadline() && st.firmwareChanged():
		notes = append(notes, stray+"The gateway firmware changed across the restart (an AT&T-pushed firmware update), so the incident is attributed to the provider.")
	case st.rebootHeadline() && stray == "":
		notes = append(notes, "No provider-attributed bad cycle lies outside the restart window, so the incident is classified as a gateway restart (GATEWAY_REBOOT); whether the restart was caused locally (for example by a power cycle) or by AT&T is undetermined.")
	case st.rebootHeadline():
		notes = append(notes, stray+"The incident is classified as a gateway restart (GATEWAY_REBOOT); whether the restart was caused locally (for example by a power cycle) or by AT&T is undetermined.")
	case st.providerOutside > 0:
		notes = append(notes, fmt.Sprintf("%s outside the restart window, so the classification rests on those cycles, not on the restart.",
			plural(st.providerOutside, "provider-attributed bad cycle lies", "provider-attributed bad cycles lie")))
	}
	return notes
}

// payload builds the Incident as recorded in the ledger (live=false) or shown by the API
// (live=true: an open incident also reports its duration so far).
func (st *incState) payload(now time.Time, live bool) model.Incident {
	inc := cloneIncident(st.inc)
	inc.Attribution = st.attribution()
	inc.Rules = RulesVersion
	inc.Evidence = st.ev.sorted()
	inc.Reasons = st.reasons()
	inc.GatewayRestarts = nil
	for _, r := range st.restarts {
		inc.GatewayRestarts = append(inc.GatewayRestarts, fmtTS(r.Boot))
	}
	inc.Stats.DowntimeSec = int64(st.downtime / time.Second)
	inc.Stats.DegradedSec = int64(st.degraded / time.Second)
	inc.Stats.RestartSec = int64(st.restartTime / time.Second)
	inc.RecoveredAt = ""
	if !st.recoveredAt.IsZero() {
		inc.RecoveredAt = fmtTS(st.recoveredAt)
	}
	var notes []string
	if inc.State == model.StateDegraded && st.degTotal > 0 {
		notes = append(notes, fmt.Sprintf("%d of %d degraded cycles had a loss-free path to the gateway.", st.degProvider, st.degTotal))
	}
	if n := timeNote(st.downtime, st.degraded, st.restartTime); n != "" {
		notes = append(notes, n)
	}
	if !st.recoveredAt.IsZero() {
		notes = append(notes, fmt.Sprintf("All probes succeeded again from %s.", fmtHuman(st.recoveredAt)))
	}
	notes = append(notes, st.restartNotes()...)
	notes = append(notes, st.notes...)
	if !st.closed.IsZero() {
		inc.Open = false
		inc.Closed = fmtTS(st.closed)
		inc.DurationSec = int64(st.closed.Sub(st.opened) / time.Second)
		inc.LastSeq = st.closeSeq
	} else {
		inc.Open = true
		inc.LastSeq = st.lastSeq
		if live && now.After(st.opened) {
			inc.DurationSec = int64(now.Sub(st.opened) / time.Second)
		}
	}
	inc.Summary = summarize(inc, notes)
	return inc
}

// timeNote states the measured time accounting of an incident (DESIGN §10): the cycles
// classified ISP_OUTAGE (no Internet) and DEGRADED outside restart windows, and the bad cycles
// inside them - not the wall-clock span.
func timeNote(downtime, degraded, restart time.Duration) string {
	var parts []string
	if downtime > 0 {
		parts = append(parts, fmt.Sprintf("%s without Internet (ISP_OUTAGE cycles)", downtime.Round(time.Second)))
	}
	if degraded > 0 {
		parts = append(parts, fmt.Sprintf("%s degraded (DEGRADED cycles)", degraded.Round(time.Second)))
	}
	if restart > 0 {
		parts = append(parts, fmt.Sprintf("%s in gateway restart windows (not counted as an AT&T outage)", restart.Round(time.Second)))
	}
	if len(parts) == 0 {
		return ""
	}
	return "Measured time: " + strings.Join(parts, ", ") + "."
}

// cloneIncident deep-copies the slices and maps of an incident.
func cloneIncident(in model.Incident) model.Incident {
	out := in
	out.Causes = slices.Clone(in.Causes)
	out.Reasons = slices.Clone(in.Reasons)
	out.Evidence = slices.Clone(in.Evidence)
	out.GatewayRestarts = slices.Clone(in.GatewayRestarts)
	out.Stats.ProbeOK = cloneIntMap(in.Stats.ProbeOK)
	out.Stats.ProbeTotal = cloneIntMap(in.Stats.ProbeTotal)
	return out
}

func cloneIntMap(m map[string]int) map[string]int {
	if m == nil {
		return nil
	}
	out := make(map[string]int, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// ---------------------------------------------------------------------------- summary

// stateWords names a headline state for summaries, capitalized or not.
func stateWords(state string, capital bool) string {
	switch state {
	case model.StateISPOutage:
		return "ISP outage"
	case model.StateLocalFault:
		if capital {
			return "Local fault"
		}
		return "local fault"
	case model.StateDegraded:
		if capital {
			return "Degraded service"
		}
		return "degraded service"
	}
	if capital {
		return "Incident"
	}
	return "incident"
}

// headlineWords names an incident's headline: a gateway restart is not called a local fault.
func headlineWords(inc model.Incident, capital bool) string {
	if inc.Cause == model.CauseGatewayReboot {
		if capital {
			return "Gateway restart"
		}
		return "gateway restart"
	}
	return stateWords(inc.State, capital)
}

func causeFact(cause string) string {
	switch cause {
	case model.CauseFiberLinkDown:
		return "the AT&T gateway reported its fiber/PON link down"
	case model.CauseWANDown:
		return "the AT&T gateway reported its broadband (WAN) connection down"
	case model.CauseISPEdgeUnreachable:
		return "the AT&T next-hop router stopped answering while the gateway was reachable"
	case model.CauseUpstreamUnreachable:
		return "no internet target answered while the gateway was reachable"
	case model.CauseGatewayUnreachable:
		return "this computer could not reach the AT&T gateway"
	case model.CauseLocalLinkDown:
		return "this computer's Wi-Fi link to the gateway was down"
	case model.CauseLocalRoute:
		return "this computer's internet traffic did not go through the AT&T gateway (a VPN or another network connection), so its failed probes say nothing about AT&T's network"
	case model.CauseGatewayReboot:
		return "the AT&T gateway restarted (its uptime was reset) during the incident"
	case model.CausePacketLoss:
		return "internet probes lost packets"
	case model.CauseHighLatency:
		return "internet latency was high while the gateway answered quickly"
	case model.CauseISPDNSFailure:
		return "the AT&T DNS resolver failed while a public resolver answered"
	case model.CauseGatewayDNSFailure:
		return "the gateway's DNS service failed while the AT&T resolver answered"
	}
	return ""
}

func attributionSentence(attr string) string {
	switch attr {
	case model.AttrProvider:
		return "Attributed to the provider (AT&T)."
	case model.AttrLocal:
		return "Attributed to the local side (this computer or its link to the gateway)."
	default:
		return "Attribution undetermined."
	}
}

// summarize writes the one-paragraph human summary of an incident.
func summarize(inc model.Incident, notes []string) string {
	var b strings.Builder
	opened, _ := parseTS(inc.Opened)
	if inc.Open {
		fmt.Fprintf(&b, "Ongoing %s since %s", headlineWords(inc, false), fmtHuman(opened))
	} else {
		closed, _ := parseTS(inc.Closed)
		fmt.Fprintf(&b, "%s from %s to %s (%s)", headlineWords(inc, true), fmtHuman(opened), fmtHuman(closed),
			(time.Duration(inc.DurationSec) * time.Second).String())
	}
	if inc.Cause != "" {
		fmt.Fprintf(&b, ", cause %s", inc.Cause)
		if f := causeFact(inc.Cause); f != "" {
			fmt.Fprintf(&b, ": %s", f)
		}
	}
	b.WriteString(". ")
	b.WriteString(attributionSentence(inc.Attribution))
	for _, n := range notes {
		b.WriteString(" ")
		b.WriteString(n)
	}
	return b.String()
}
