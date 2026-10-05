package ticket

import (
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"attmonitor/internal/model"
)

// The texts of the report. Each sentence is generated from the figures computed by analyze
// and only when the records support it; where they do not, the text says what is unknown.

func (r *Report) buildSummary() {
	r.Summary = []Bullet{r.opticalBullet(), r.linkBullet(), r.outageBullet(), r.homeBullet()}
	r.Action = r.actionBullet()
	r.Coverage.Statement = r.coverageStatement()
	r.Evidence.Facts = r.facts()
}

func (r *Report) both(t time.Time) string    { return fmtBoth(t, r.loc) }
func (r *Report) bothMin(t time.Time) string { return fmtBothMin(t, r.loc) }

// flagsPhrase describes the Rx low flags of one reading: "with the gateway's low-Rx ALARM and
// WARNING flags set".
func flagsPhrase(rd Reading) string {
	switch {
	case rd.Alarm && rd.Warn:
		return " with the gateway's low-Rx ALARM and WARNING flags set"
	case rd.Alarm:
		return " with the gateway's low-Rx ALARM flag set"
	case rd.Warn:
		return " with the gateway's low-Rx WARNING flag set"
	}
	return " with no low-Rx flag set"
}

// ---------------------------------------------------------------- (a) optical level

func (r *Report) opticalBullet() Bullet {
	op := &r.Optical
	b := Bullet{Key: "optical"}
	n := len(op.Readings)
	if n == 0 {
		b.Lead = "Optical signal: no readings in this window."
		b.Text = "No optical readings from the gateway's fiber diagnostics were recorded in this window."
		if s := op.SetupOutside; s != nil {
			b.Text += fmt.Sprintf(" The setup-time capture of %s, outside this window (bootstrap_import %s), showed Rx %s%s.",
				r.bothMin(s.T), seqRef(s.Seq), fmtDBm(s.RxX10), flagsPhrase(*s))
		}
		return b
	}
	first, latest := op.Readings[0], op.Readings[op.LatestI]
	cl := op.Clear
	switch {
	case latest.Alarm && r.To.Sub(latest.T) <= latestIsCurrent:
		b.Lead = "The gateway's own low-Rx optical ALARM is active."
	case latest.Alarm:
		b.Lead = "The gateway's own low-Rx optical ALARM was set at the latest reading, " + r.bothMin(latest.T) + "."
	case cl != nil && op.AlarmRuns == 1 && cl.SetFrom.T.Equal(op.firstLevel().T):
		b.Lead = "The gateway's own low-Rx optical ALARM was set from the first reading until it cleared at " + r.bothMin(cl.Cleared.T) + "."
	case cl != nil && op.AlarmRuns == 1:
		b.Lead = fmt.Sprintf("The gateway's own low-Rx optical ALARM was set from %s until it cleared at %s.", r.bothMin(cl.SetFrom.T), r.bothMin(cl.Cleared.T))
	case cl != nil:
		b.Lead = fmt.Sprintf("The gateway raised its own low-Rx optical ALARM %s; it last cleared at %s.", timesWord(op.AlarmRuns), r.bothMin(cl.Cleared.T))
	case op.AlarmN > 0:
		b.Lead = fmt.Sprintf("The gateway raised its own low-Rx optical ALARM in %s of the readings.", fmtShare(int64(op.AlarmN), int64(n)))
	case latest.Warn:
		b.Lead = "The gateway's own low-Rx optical WARNING is active."
	case op.WarnN > 0:
		b.Lead = fmt.Sprintf("The gateway raised its own low-Rx optical WARNING in %s of the readings.", fmtShare(int64(op.WarnN), int64(n)))
	default:
		b.Lead = "Optical receive level within the gateway's own thresholds."
	}
	var t strings.Builder
	latestText := fmtDBm(latest.RxX10)
	if latest.NoLight {
		latestText = "no receive level, fiber link down"
	}
	switch {
	case op.Levels == 0:
		fmt.Fprintf(&t, "In %s from %s to %s the gateway showed no receive level (Rx 0) while reporting its own fiber link down.",
			plural(n, "reading", "readings"), r.bothMin(first.T), r.bothMin(latest.T))
	default:
		lo, hi := op.Readings[op.MinI].RxX10, op.Readings[op.MaxI].RxX10
		level := "of " + fmtDBm(lo)
		if lo != hi {
			level = "between " + fmtX10(lo) + " and " + fmtDBm(hi)
		}
		if n == 1 {
			fmt.Fprintf(&t, "AT&T's gateway reported an optical receive (Rx) power %s at %s (%s).", level, r.bothMin(first.T), first.Source())
		} else {
			fmt.Fprintf(&t, "AT&T's gateway reported an optical receive (Rx) power %s in %s from %s to %s; the latest, %s, is %s.",
				level, plural(op.Levels, "reading", "readings"), r.bothMin(first.T), r.bothMin(latest.T), latestText, latest.Source())
		}
		if op.NoLightN > 0 {
			var seqs []uint64
			for _, rd := range op.Readings {
				if rd.NoLight {
					seqs = append(seqs, rd.Seq)
				}
			}
			fmt.Fprintf(&t, " In %s, taken while the gateway reported its own fiber link down (snapshots %s), it showed no receive level (Rx 0).",
				plural(op.NoLightN, "further reading", "further readings"), fmtSeqList(seqs, 4))
		}
	}
	if first.Setup && n > 1 {
		t.WriteString(" The first is the setup-time capture, made before monitoring began.")
	}
	// The flag counts; a single run of the ALARM flag that cleared is stated by clearText instead,
	// which says in which readings the flags were set.
	counts := fmt.Sprintf(" the ALARM flag was set in %d of %d readings (%s) and the WARNING flag in %d of %d (%s).",
		op.AlarmN, n, fmtShare(int64(op.AlarmN), int64(n)), op.WarnN, n, fmtShare(int64(op.WarnN), int64(n)))
	if cl != nil && op.AlarmRuns == 1 && r.bothFlagsCleared() {
		counts = ""
	}
	switch {
	case op.AlarmThr != nil || op.WarnThr != nil:
		var thr []string
		if op.AlarmThr != nil {
			thr = append(thr, "low-Rx ALARM threshold is "+fmtDBm(*op.AlarmThr))
		}
		if op.WarnThr != nil {
			thr = append(thr, "WARNING threshold is "+fmtDBm(*op.WarnThr))
		}
		if counts == "" {
			fmt.Fprintf(&t, " Its own %s.", strings.Join(thr, " and its "))
		} else {
			fmt.Fprintf(&t, " Its own %s:%s", strings.Join(thr, " and its "), counts)
		}
	case counts == "":
		t.WriteString(" The gateway stated no low-Rx thresholds in these readings.")
	default:
		t.WriteString(" The gateway stated no low-Rx thresholds in these readings:" + counts)
	}
	if op.Levels > 0 && op.AlarmThr != nil && op.WarnThr != nil && op.Readings[op.MaxI].RxX10 < min(*op.AlarmThr, *op.WarnThr) && !op.ThrVaried {
		switch {
		case op.Levels == 1:
			t.WriteString(" The level is below both thresholds.")
		case op.NoLightN > 0:
			t.WriteString(" Every measured level was below both thresholds.")
		default:
			t.WriteString(" Every reading was below both thresholds.")
		}
	}
	if op.ThrVaried {
		t.WriteString(" The thresholds the gateway stated changed during the window (see the readings table).")
	}
	if cl != nil {
		t.WriteString(r.clearText())
	}
	t.WriteString(r.stepText())
	if len(op.OtherCodes) > 0 {
		var parts []string
		for _, code := range sortedCodeKeys(op.OtherCodes) {
			parts = append(parts, fmt.Sprintf("%s (%s)", code, plural(op.OtherCodes[code], "reading", "readings")))
		}
		t.WriteString(" Other flags the gateway raised: " + strings.Join(parts, ", ") + ".")
	}
	b.Text = t.String()
	return b
}

// latestIsCurrent: a flag of a reading this close to the end of the window is stated as present
// ("is active"); an older one as the state at that reading.
const latestIsCurrent = 15 * time.Minute

// firstLevel is the first reading with a receive level (the zero Reading when none).
func (op *Optical) firstLevel() Reading {
	for _, rd := range op.Readings {
		if !rd.NoLight {
			return rd
		}
	}
	return Reading{}
}

// clearText states the run of readings with the ALARM flag set that ended with the last clearing,
// and the records of the clearing.
func (r *Report) clearText() string {
	op, cl := &r.Optical, r.Optical.Clear
	every := "every reading"
	for _, rd := range op.Readings {
		if !rd.T.Before(cl.SetFrom.T) && !rd.T.After(cl.LastSet.T) && !rd.Alarm {
			every = "every reading with a level"
			break
		}
	}
	flags, it, both := "The ALARM flag was", "it", r.bothFlagsCleared()
	if both {
		flags, it = "Both low-Rx flags were", "them"
	}
	s := fmt.Sprintf(" %s set in %s from %s to %s; the gateway cleared %s in %s",
		flags, every, r.bothMin(cl.SetFrom.T), r.bothMin(cl.LastSet.T), it, cl.Cleared.Source())
	if cl.EventSeq != 0 {
		s += ", recorded as gateway_event optical_alarm " + seqRef(cl.EventSeq)
	}
	after, again := 0, 0
	for _, rd := range op.Readings {
		if rd.T.After(cl.Cleared.T) {
			after++
			if rd.Alarm || (both && rd.Warn) {
				again++
			}
		}
	}
	if after > 0 && again == 0 {
		s += fmt.Sprintf(", and did not set %s again in the %s since", it, plural(after, "reading", "readings"))
	}
	s += "."
	if latest := op.Readings[op.LatestI]; latest.Warn {
		s += " Its WARNING flag is set at the latest reading."
	}
	return s
}

// bothFlagsCleared: the gateway set its low-Rx WARNING flag in exactly the readings in which it
// set its ALARM flag, so the ALARM's run and clearing are those of both flags.
func (r *Report) bothFlagsCleared() bool {
	op := &r.Optical
	if op.Clear == nil || op.AlarmN != op.WarnN {
		return false
	}
	for _, rd := range op.Readings {
		if rd.Alarm != rd.Warn {
			return false
		}
	}
	return true
}

// maxSteps bounds the step changes stated in the summary; the readings table lists both readings
// of each.
const maxSteps = 2

// stepText states the step changes of the receive level: the largest maxSteps, in time order. A
// step across a loss of light is a change of the fiber connection at that moment; the text says
// so, and that the records cannot tell who made it.
func (r *Report) stepText() string {
	steps := r.Optical.Steps
	if len(steps) == 0 {
		return ""
	}
	shown := steps
	if len(shown) > maxSteps {
		idx := make([]int, len(steps))
		for i := range idx {
			idx[i] = i
		}
		sort.SliceStable(idx, func(a, b int) bool { return absI(steps[idx[a]].DeltaX10()) > absI(steps[idx[b]].DeltaX10()) })
		idx = idx[:maxSteps]
		sort.Ints(idx)
		shown = nil
		for _, i := range idx {
			shown = append(shown, steps[i])
		}
	}
	var b strings.Builder
	dark := 0
	for _, st := range shown {
		dir := "rose"
		if st.DeltaX10() < 0 {
			dir = "fell"
		}
		change := fmt.Sprintf("the level %s by %s dB: from %s in %s at %s to %s in %s at %s.", dir, fmtX10(absI(st.DeltaX10())),
			fmtDBm(st.From.RxX10), st.From.Source(), r.bothMin(st.From.T), fmtDBm(st.To.RxX10), st.To.Source(), r.bothMin(st.To.T))
		switch gap := st.To.T.Sub(st.From.T); {
		case len(st.NoLight) > 0:
			dark++
			fmt.Fprintf(&b, " Across a loss of light (no receive level in %s %s), %s",
				noun(len(st.NoLight), "snapshot", "snapshots"), fmtSeqList(st.NoLight, 2), change)
		case gap > 10*time.Minute:
			fmt.Fprintf(&b, " Between two consecutive readings %s apart, %s", fmtDur(int64(gap/time.Second)), change)
		default:
			fmt.Fprintf(&b, " Between two consecutive readings, %s", change)
		}
	}
	if n := len(steps) - len(shown); n > 0 {
		fmt.Fprintf(&b, " The readings hold %s of %s dB or more.", plural(n, "further step change", "further step changes"), fmtX10(StepMinX10))
	}
	switch {
	case dark == 1:
		b.WriteString(" A step change like this across a loss of light usually means the fiber connection changed at that moment (for example a connector reseated or cleaned, or work on the line); these records cannot show who made the change.")
	case dark > 1:
		b.WriteString(" Step changes like these across a loss of light usually mean the fiber connection changed at those moments (for example a connector reseated or cleaned, or work on the line); these records cannot show who made the changes.")
	}
	return b.String()
}

// stepAtClear is the step change across a loss of light that ends at the reading in which the
// ALARM flag cleared, if any.
func (r *Report) stepAtClear() *Step {
	cl := r.Optical.Clear
	if cl == nil {
		return nil
	}
	for i := range r.Optical.Steps {
		if st := &r.Optical.Steps[i]; len(st.NoLight) > 0 && st.To.Seq == cl.Cleared.Seq && st.To.T.Equal(cl.Cleared.T) {
			return st
		}
	}
	return nil
}

func absI(v int64) int64 {
	if v < 0 {
		return -v
	}
	return v
}

func sortedCodeKeys(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// ---------------------------------------------------------------- (b) fiber link & restarts

// changeTimes states both readings of a Last Change value and which of them lie in the window.
func (r *Report) changeTimes(ch LinkChange, off *time.Duration) string {
	if !ch.Plausible {
		return fmt.Sprintf("the value %d does not read as a plausible time, so the change cannot be dated", ch.Value)
	}
	asUTC := fmtUTC(ch.AsUTC)
	var s string
	switch {
	case off == nil:
		s = fmt.Sprintf("%s if the gateway counts in UTC, or %s in its local time zone, which the records do not state; the gateway does not say which",
			asUTC, ch.AsUTC.Format(layoutSec))
	case *off == 0:
		s = fmt.Sprintf("that is %s (the gateway's clock runs on UTC, so both possible readings agree)", asUTC)
	default:
		s = fmt.Sprintf("%s if the gateway counts in UTC, or %s if in its local time (%s per its own clock); the gateway does not say which",
			asUTC, fmtUTC(ch.AsLocal), fmtOffset(*off))
	}
	in := func(t time.Time) bool { return !t.IsZero() && !t.Before(r.From) && t.Before(r.To) }
	utcIn, localIn := ch.UTCPossible && in(ch.AsUTC), ch.LocalPossible && in(ch.AsLocal)
	switch {
	case off != nil && *off == 0:
		if utcIn {
			s += "; it lies inside this window"
		}
	case off == nil:
		if utcIn {
			s += "; the UTC reading lies inside this window"
		}
	case utcIn && localIn:
		s += "; either way it lies inside this window"
	case utcIn:
		s += "; the UTC reading lies inside this window"
	case localIn:
		s += "; the local-time reading lies inside this window"
	}
	if off != nil && *off != 0 {
		switch {
		case !ch.UTCPossible && ch.LocalPossible:
			s += " (the UTC reading would lie after the observation, so only the local-time reading is possible)"
		case ch.UTCPossible && !ch.LocalPossible:
			s += " (the local-time reading would lie after the observation, so only the UTC reading is possible)"
		}
	}
	return s
}

func (r *Report) linkBullet() Bullet {
	lk := &r.Link
	b := Bullet{Key: "link"}
	if lk.Observations == 0 && len(lk.Changes) == 0 && lk.UptimeReadings == 0 && len(lk.Restarts) == 0 {
		b.Lead = "Fiber link state and gateway restarts: no readings in this window."
		b.Text = "No fiber status (Last Change) or uptime readings from the gateway were recorded in this window, so link state changes and gateway restarts cannot be assessed for it."
		return b
	}
	changes := lk.Changes
	var withoutRestart []LinkChange
	for _, ch := range changes {
		if ch.Restart == "" {
			withoutRestart = append(withoutRestart, ch)
		}
	}
	noRestartKnown := lk.UptimeReadings > 0 && len(lk.Restarts) == 0
	changesText := func(n int) string {
		if n == 1 {
			return "Fiber link state change"
		}
		return fmt.Sprintf("%d fiber link state changes", n)
	}
	switch {
	case len(changes) > 0 && noRestartKnown:
		b.Lead = changesText(len(changes)) + " without a gateway restart."
		during := 0
		for _, g := range r.groupChanges(changes) {
			if g.inc != nil {
				during++
			}
		}
		if during > 0 {
			b.Lead = strings.TrimSuffix(b.Lead, ".") + ", including during " + noun(during, "an outage", "outages") + "."
		}
	case len(withoutRestart) > 0 && len(lk.Restarts) > 0:
		b.Lead = fmt.Sprintf("%s not at a gateway restart; the gateway also restarted %s.", changesText(len(withoutRestart)), timesWord(len(lk.Restarts)))
	case len(changes) > 0 && len(lk.Restarts) > 0:
		if len(changes) == 1 {
			b.Lead = "Fiber link state change at a gateway restart."
		} else {
			b.Lead = changesText(len(changes)) + ", each at a gateway restart."
		}
	case len(changes) > 0:
		b.Lead = changesText(len(changes)) + "."
	case len(lk.Restarts) > 0:
		if len(lk.Restarts) == 1 {
			b.Lead = "Gateway restart; no other fiber link state change."
		} else {
			b.Lead = fmt.Sprintf("%d gateway restarts; no other fiber link state change.", len(lk.Restarts))
		}
	case lk.Observations > 0:
		b.Lead = "No fiber link state change in this window."
	default:
		b.Lead = "Fiber link state: not observed in this window."
	}
	var t strings.Builder
	sentence := func(s string) {
		if t.Len() > 0 {
			t.WriteByte(' ')
		}
		t.WriteString(s)
	}
	// The first observed value (a change before or around the start of monitoring) is stated with
	// both of its readings; the changes seen later are grouped by the outage they fall in.
	var later []LinkChange
	for _, ch := range changes {
		if ch.Event || ch.Prev != "" {
			later = append(later, ch)
			continue
		}
		s := fmt.Sprintf("The gateway's fiber status page dates the optical link's last state change \"Last Change\" = %d (first seen %s, %s): %s.",
			ch.Value, fmtUTC(ch.Observed), ch.Source, r.changeTimes(ch, lk.Offset))
		if lk.Unchanged > 0 && len(later) == 0 && len(changes) == 1 {
			s += fmt.Sprintf(" The value stayed the same in the %s after it.", plural(lk.Unchanged, "reading", "readings"))
		}
		if ch.Restart != "" {
			s += " This coincides with " + ch.Restart + "."
		}
		sentence(s)
	}
	// Up to two groups are stated on page 1, change by change; more are summarised in one
	// sentence, and the gateway events table lists the changes with their times.
	groups := r.groupChanges(later)
	// bracketStated: a group sentence already says that the confirming change can only be read
	// as UTC ("the only reading that falls between the gateway readings around it").
	bracketStated := false
	if len(groups) <= 2 {
		for _, g := range groups {
			s, utcOnly := r.changeGroupSentence(g, lk.Offset)
			sentence(s)
			for _, ch := range g.chs {
				bracketStated = bracketStated || (utcOnly && lk.Confirmed == "UTC" && ch.Source == lk.ConfirmedBy)
			}
		}
	} else {
		sentence(r.changeGroupsSummary(groups))
	}
	if lk.Confirmed != "" && len(changes) > 0 {
		as, reading := "UTC", "UTC"
		if lk.Confirmed == "local" {
			as, reading = "the gateway's local time", "local-time"
		}
		if bracketStated {
			sentence("That supports the UTC reading of all these Last Change values.")
		} else {
			sentence(fmt.Sprintf("As the change in %s can only be read as %s, the records support the %s reading of these values.",
				lk.ConfirmedBy, as, reading))
		}
	}
	if len(changes) == 0 && lk.Observations > 0 {
		f := lk.First
		if f.Plausible && len(f.possibleTimes()) > 0 {
			sentence(fmt.Sprintf("The gateway's fiber status page dates the optical link's last state change before this window (\"Last Change\" = %d: %s), and the value stayed the same in all %s: no link state change from the start of the window until %s.",
				f.Value, r.changeTimes(f, lk.Offset), plural(lk.Observations, "reading", "readings"), r.bothMin(r.lastLinkObservation())))
		} else {
			sentence(fmt.Sprintf("The gateway's Last Change value (%d) does not read as a plausible time before its observation, so link state changes cannot be dated from it.", f.Value))
		}
	}
	switch {
	case lk.UptimeReadings == 0:
		sentence("No uptime reading of the gateway was recorded in this window, so whether it restarted cannot be told.")
	case len(lk.Restarts) == 0:
		s := fmt.Sprintf("The gateway did not restart: its uptime (%s) puts its last boot at %s, before this window",
			lk.BootSrc, fmtUTC(lk.Boot))
		if len(changes) > 0 && r.changesAfterBoot() {
			s += ", so the link changed state while the gateway kept running"
		}
		sentence(s + ".")
	default:
		var parts []string
		for i, rs := range lk.Restarts {
			if i == 3 {
				parts = append(parts, fmt.Sprintf("and %d more", len(lk.Restarts)-3))
				break
			}
			parts = append(parts, fmt.Sprintf("%s, from the %s", r.bothMin(rs.Boot), rs.Source))
		}
		sentence(fmt.Sprintf("The gateway restarted in this window at about %s.", strings.Join(parts, "; ")))
	}
	b.Text = t.String()
	return b
}

// changeGroupsSummary states many groups of link changes in one sentence of bounded length.
func (r *Report) changeGroupsSummary(groups []changeGroup) string {
	var all []LinkChange
	var incIDs []string
	inInc, outages := 0, true
	for _, g := range groups {
		all = append(all, g.chs...)
		if g.inc != nil {
			inInc += len(g.chs)
			incIDs = append(incIDs, g.inc.ID)
			outages = outages && g.inc.State == model.StateISPOutage
		}
	}
	var b strings.Builder
	var evSeqs, snapSeqs []uint64
	for _, ch := range all {
		if ch.Event {
			evSeqs = append(evSeqs, ch.Seq)
		} else {
			snapSeqs = append(snapSeqs, ch.Seq)
		}
	}
	var refs []string
	if len(evSeqs) > 0 {
		refs = append(refs, "gateway_event optical_link_change "+fmtSeqList(evSeqs, 3))
	}
	if len(snapSeqs) > 0 {
		refs = append(refs, "snapshot "+fmtSeqList(snapSeqs, 3))
	}
	fmt.Fprintf(&b, "During monitoring the optical link changed state %s (%s)", timesWord(len(all)), strings.Join(refs, "; "))
	if inInc > 0 {
		what := noun(len(incIDs), "incident", "incidents")
		if outages {
			what = noun(len(incIDs), "outage", "outages")
		}
		if len(incIDs) <= 2 {
			fmt.Fprintf(&b, ", %d of them during the %s %s", inInc, what, joinAnd(incIDs))
		} else {
			fmt.Fprintf(&b, ", %d of them during %d %s", inInc, len(incIDs), what)
		}
	}
	b.WriteString(".")
	listed := r.listedEventSeqs()
	all1 := true
	for _, ch := range all {
		all1 = all1 && ch.Event && listed[ch.Seq]
	}
	if all1 {
		b.WriteString(" The gateway events table lists each with its time.")
	} else {
		b.WriteString(" The gateway events table lists those it has room for; every one is in the bundle's records.")
	}
	return b.String()
}

// changeGroup is a run of link changes that fall in the same incident (inc nil: in none).
type changeGroup struct {
	inc *IncidentRow
	chs []LinkChange
}

// incidentOf returns the incident whose span (two minutes either side) holds a possible time of
// the change, or nil.
func (r *Report) incidentOf(ch LinkChange) *IncidentRow {
	ts := ch.possibleTimes()
	if len(ts) == 0 {
		ts = []time.Time{ch.Observed}
	}
	for i := range r.Incidents {
		inc := &r.Incidents[i]
		if inc.OpenedT.IsZero() {
			continue
		}
		end := inc.ClosedT
		if end.IsZero() {
			end = inc.RecTS
		}
		for _, t := range ts {
			if !t.Before(inc.OpenedT.Add(-2*time.Minute)) && !t.After(end.Add(2*time.Minute)) {
				return inc
			}
		}
	}
	return nil
}

// groupChanges groups changes by incident, in order of first appearance.
func (r *Report) groupChanges(chs []LinkChange) []changeGroup {
	var out []changeGroup
	idx := map[*IncidentRow]int{}
	for _, ch := range chs {
		inc := r.incidentOf(ch)
		if k, ok := idx[inc]; ok {
			out[k].chs = append(out[k].chs, ch)
			continue
		}
		idx[inc] = len(out)
		out = append(out, changeGroup{inc: inc, chs: []LinkChange{ch}})
	}
	return out
}

func timesWord(n int) string {
	switch n {
	case 1:
		return "once"
	case 2:
		return "twice"
	}
	return fmt.Sprintf("%d times", n)
}

// causeText explains an incident cause in plain words.
func causeText(cause string) string {
	switch cause {
	case model.CauseFiberLinkDown:
		return cause + ": the gateway itself reported its fiber (PON) link down"
	case model.CauseWANDown:
		return cause + ": the gateway itself reported its broadband connection down"
	case model.CauseISPEdgeUnreachable:
		return cause + ": AT&T's next hop did not answer"
	case model.CauseUpstreamUnreachable:
		return cause + ": no Internet destination answered beyond AT&T's next hop"
	case model.CausePacketLoss:
		return cause + ": packet loss to independent destinations"
	case model.CauseHighLatency:
		return cause + ": high latency to independent destinations"
	case model.CauseISPDNSFailure:
		return cause + ": AT&T's DNS resolver failed"
	case model.CauseGatewayDNSFailure:
		return cause + ": the gateway's DNS failed"
	case model.CauseGatewayReboot:
		return cause + ": gateway restart"
	case "":
		return "cause not recorded"
	}
	return cause
}

// changeGroupSentence states a group of link changes seen during monitoring; utcOnly reports that
// it states every change as readable only as UTC.
func (r *Report) changeGroupSentence(g changeGroup, off *time.Duration) (text string, utcOnly bool) {
	var b strings.Builder
	if g.inc != nil {
		what := "incident"
		if g.inc.State == model.StateISPOutage {
			what = "outage"
		}
		fmt.Fprintf(&b, "During the %s %s the optical link changed state %s", what, g.inc.ID, timesWord(len(g.chs)))
	} else {
		fmt.Fprintf(&b, "During monitoring the optical link changed state %s", timesWord(len(g.chs)))
	}
	utcOnly = off != nil && *off != 0
	for _, ch := range g.chs {
		utcOnly = utcOnly && ch.Plausible && ch.UTCPossible && !ch.LocalPossible
	}
	var vals, when, evRefs, snapRefs []string
	restarts := 0
	for i, ch := range g.chs {
		if ch.Restart != "" {
			restarts++
		}
		if ch.Event {
			evRefs = append(evRefs, seqRef(ch.Seq))
		} else {
			snapRefs = append(snapRefs, seqRef(ch.Seq))
		}
		if i >= 3 {
			continue
		}
		vals = append(vals, fmt.Sprint(ch.Value))
		switch {
		case utcOnly:
			when = append(when, fmtUTC(ch.AsUTC))
		case !ch.Plausible || len(ch.possibleTimes()) == 0:
			when = append(when, "not datable")
		case ch.UTCPossible && !ch.LocalPossible:
			when = append(when, fmtUTC(ch.AsUTC)+" as UTC")
		case ch.LocalPossible && !ch.UTCPossible:
			when = append(when, fmtUTC(ch.AsLocal)+" as local time")
		case ch.AsLocal.IsZero():
			when = append(when, fmtUTC(ch.AsUTC)+" as UTC; the local-time reading is unknown")
		case ch.AsLocal.Equal(ch.AsUTC):
			when = append(when, fmtUTC(ch.AsUTC))
		default:
			when = append(when, fmtUTC(ch.AsUTC)+" as UTC or "+fmtUTC(ch.AsLocal)+" as local time")
		}
	}
	more := ""
	if n := len(g.chs) - len(vals); n > 0 {
		more = fmt.Sprintf(" and %d more", n)
	}
	if utcOnly {
		// One date for the list when all the times share it: "13:04:51, 13:05:07 and 13:05:27 UTC on 2026-10-05".
		day, same := "", true
		var clock []string
		for _, ch := range g.chs[:len(vals)] {
			d := ch.AsUTC.UTC().Format("2006-01-02")
			same = same && (day == "" || d == day)
			day = d
			clock = append(clock, ch.AsUTC.UTC().Format("15:04:05"))
		}
		list := joinAnd(when)
		if same {
			list = joinAnd(clock) + " UTC on " + day
		}
		each := "each"
		if len(g.chs) == 1 {
			each = "it"
		}
		fmt.Fprintf(&b, ": Last Change %s%s = %s, the only reading that falls between the gateway readings around %s",
			joinAnd(vals), more, list, each)
	} else {
		items := make([]string, len(vals))
		for i := range vals {
			items[i] = vals[i] + " (" + when[i] + ")"
		}
		fmt.Fprintf(&b, ": Last Change %s%s", joinAnd(items), more)
	}
	var refs []string
	if len(evRefs) > 0 {
		refs = append(refs, "gateway_event optical_link_change "+strings.Join(evRefs, ", "))
	}
	if len(snapRefs) > 0 {
		refs = append(refs, "snapshot "+strings.Join(snapRefs, ", "))
	}
	fmt.Fprintf(&b, " (%s)", strings.Join(refs, "; "))
	if restarts > 0 {
		fmt.Fprintf(&b, "; %d of them at a gateway restart", restarts)
	}
	return b.String() + ".", utcOnly
}

// changesAfterBoot: every possible time of every change lies after the gateway's last boot.
func (r *Report) changesAfterBoot() bool {
	if r.Link.Boot.IsZero() {
		return false
	}
	for _, ch := range r.Link.Changes {
		ts := ch.possibleTimes()
		if len(ts) == 0 {
			return false
		}
		for _, t := range ts {
			if !t.After(r.Link.Boot.Add(restartNear)) {
				return false
			}
		}
	}
	return true
}

// lastLinkObservation is the time of the latest fiberstat reading of the window.
func (r *Report) lastLinkObservation() time.Time {
	var last time.Time
	for _, rd := range r.Optical.Readings {
		if rd.T.After(last) {
			last = rd.T
		}
	}
	if last.IsZero() {
		last = r.Link.First.Observed
	}
	return last
}

// ---------------------------------------------------------------- (c) outages

func (r *Report) outageBullet() Bullet {
	b := Bullet{Key: "outages"}
	cv, av := &r.Coverage, &r.Avail
	var prov, other []IncidentRow
	for _, inc := range r.Incidents {
		if inc.Attribution == model.AttrProvider {
			prov = append(prov, inc)
		} else {
			other = append(other, inc)
		}
	}
	mon := fmtHours(cv.MonitoredSec)
	if cv.Cycles == 0 && len(r.Incidents) == 0 {
		b.Lead = "Outages: not measured in this window."
		b.Text = "The monitor recorded no measurement cycles in this window, so no outage can be measured or excluded for it."
		return b
	}
	var t strings.Builder
	switch {
	case len(prov) > 0:
		var down, deg int64
		longest := prov[0]
		for _, inc := range prov {
			down += inc.Stats.DowntimeSec
			deg += inc.Stats.DegradedSec
			if inc.Stats.DowntimeSec > longest.Stats.DowntimeSec {
				longest = inc
			}
		}
		b.Lead = fmt.Sprintf("Outages measured by the monitor: %s attributed to AT&T.", plural(len(prov), "incident", "incidents"))
		var ids []string
		for _, inc := range prov {
			ids = append(ids, inc.ID)
		}
		if len(prov) == 1 {
			fmt.Fprintf(&t, "During the %s of monitoring in this window the monitor recorded the incident %s attributed to AT&T: %s without Internet (%s %s, downtime_s)",
				mon, longest.ID, fmtDur(down), longest.RecType, seqRef(longest.RecSeq))
		} else {
			idsText := joinAnd(ids)
			if len(ids) > 3 {
				idsText = fmt.Sprintf("%s to %s; see Incidents", ids[0], ids[len(ids)-1])
			}
			fmt.Fprintf(&t, "During the %s of monitoring in this window the monitor recorded %s attributed to AT&T (%s): %s without Internet in total",
				mon, plural(len(prov), "incident", "incidents"), idsText, fmtDur(down))
			if longest.Stats.DowntimeSec > 0 {
				fmt.Fprintf(&t, ", the longest %s (%s, %s %s)", fmtDur(longest.Stats.DowntimeSec), longest.ID, longest.RecType, seqRef(longest.RecSeq))
			}
			t.WriteString(", as stated by the incident records (downtime_s)")
		}
		if deg > 0 {
			fmt.Fprintf(&t, ", plus %s of degraded service", fmtDur(deg))
		}
		t.WriteString(".")
		var causes []string
		for _, inc := range prov {
			if c := causeText(inc.Cause); !slices.Contains(causes, c) {
				causes = append(causes, c)
			}
		}
		if len(causes) == 1 {
			fmt.Fprintf(&t, " Recorded cause: %s.", causes[0])
		} else {
			fmt.Fprintf(&t, " Recorded causes: %s.", strings.Join(causes, "; "))
		}
		var before, open []string
		for _, inc := range prov {
			if inc.StartedBefore {
				before = append(before, inc.ID)
			}
			if inc.OpenAtEnd {
				open = append(open, inc.ID)
			}
		}
		if len(before) > 0 {
			fmt.Fprintf(&t, " %s began before this window; %s figures include that time.", joinAndMore(before, 3), noun(len(before), "its", "their"))
		}
		if len(open) > 0 {
			fmt.Fprintf(&t, " Still open at the end of the window: %s.", joinAndMore(open, 3))
		}
		if len(other) > 0 {
			fmt.Fprintf(&t, " %s not attributed to AT&T (local or undetermined) %s listed in the details and not counted here.",
				plural(len(other), "further incident", "further incidents"), isAre(len(other)))
		}
	case len(other) > 0:
		b.Lead = "No outage attributed to AT&T was measured."
		fmt.Fprintf(&t, "No outage attributed to the provider was measured during the %s of monitoring in this window; %s attributed local or undetermined %s listed in the details and not counted against AT&T.",
			mon, plural(len(other), "incident", "incidents"), isAre(len(other)))
	case av.Blips > 0:
		b.Lead = "No outage incident during monitoring."
		fmt.Fprintf(&t, "No outage incident (3 or more failed cycles within 6) was measured during the %s of monitoring in this window (%s).", mon, plural(cv.Cycles, "cycle", "cycles"))
	default:
		b.Lead = "No outage during monitoring."
		fmt.Fprintf(&t, "No Internet outage was measured during the %s of monitoring in this window", mon)
		if cv.Cycles > 0 && av.Online == cv.Cycles {
			fmt.Fprintf(&t, " (all %s ONLINE)", plural(cv.Cycles, "measurement cycle", "measurement cycles"))
		} else if cv.Cycles > 0 {
			fmt.Fprintf(&t, " (%s; %d ONLINE, %d without a classification)", plural(cv.Cycles, "measurement cycle", "measurement cycles"), av.Online, av.ByState[model.StateUnknown])
		}
		t.WriteString(".")
	}
	if av.Blips > 0 {
		verb := "were"
		if av.Blips == 1 {
			verb = "was"
		}
		fmt.Fprintf(&t, " %s outside incidents %s recorded (%s, %s", plural(av.Blips, "brief interruption", "brief interruptions"), verb,
			plural(av.BlipCycles, "failed cycle", "failed cycles"), fmtDur(av.BlipSec))
		if av.BlipOutageSec > 0 {
			fmt.Fprintf(&t, ", %s of it without Internet", fmtDur(av.BlipOutageSec))
		}
		t.WriteString(").")
	}
	if cv.Cycles > 0 && cv.MonitoredSec*100 < int64(cv.Window/time.Second)*90 {
		fmt.Fprintf(&t, " Monitoring covered only %s of the %s window (see Monitoring coverage).", mon, fmtWindowHours(cv.Window))
	}
	b.Text = t.String()
	return b
}

func seqRefs(seqs []uint64) []string {
	out := make([]string, len(seqs))
	for i, s := range seqs {
		out[i] = seqRef(s)
	}
	return out
}

func isAre(n int) string {
	if n == 1 {
		return "is"
	}
	return "are"
}

// ---------------------------------------------------------------- (d) home network

func (r *Report) homeBullet() Bullet {
	h := &r.Home
	b := Bullet{Key: "home"}
	if h.Cycles == 0 && h.Links == 0 {
		b.Lead = "Home network: not measured in this window."
		b.Text = "No measurements of the home network (pings to the gateway, Wi-Fi or Ethernet link) were recorded in this window, so its health is unknown."
		return b
	}
	var facts []string
	if h.GwProbes > 0 {
		lost := h.GwProbes - h.GwOK
		s := fmt.Sprintf("this computer reached the gateway in %s of %s pings (%s lost)", fmtInt(int64(h.GwOK)), fmtInt(int64(h.GwProbes)), fmtInt(int64(lost)))
		if h.GwOK > 0 {
			s += ", median round-trip " + fmtMs(h.GwMedianUs)
		}
		if h.LANKnown > 0 && h.LANDown > 0 {
			s += fmt.Sprintf("; the gateway did not answer at all in %s of %s cycles", fmtInt(int64(h.LANDown)), fmtInt(int64(h.LANKnown)))
		}
		facts = append(facts, s)
	} else if h.Cycles > 0 {
		facts = append(facts, "no ping results to the gateway were recorded")
	}
	if l := h.Latest; l != nil {
		switch l.Type {
		case "wifi":
			s := "Wi-Fi"
			var det []string
			if l.Band != "" {
				det = append(det, l.Band)
			}
			if l.RadioType != "" {
				det = append(det, l.RadioType)
			}
			if l.Channel > 0 {
				det = append(det, fmt.Sprintf("channel %d", l.Channel))
			}
			if len(det) > 0 {
				s += " " + strings.Join(det, ", ")
			}
			if h.SignalMax > 0 {
				if h.SignalMin == h.SignalMax {
					s += fmt.Sprintf(", signal %d%%", h.SignalMax)
				} else {
					s += fmt.Sprintf(", signal %d-%d%%", h.SignalMin, h.SignalMax)
				}
			}
			s += fmt.Sprintf(" (%s, latest local_link %s)", plural(h.Links, "link reading", "link readings"), seqRef(h.LatestSeq))
			facts = append(facts, s)
		case "ethernet":
			s := "wired Ethernet"
			if l.LinkMbps > 0 {
				s += fmt.Sprintf(" at %d Mb/s", l.LinkMbps)
			}
			facts = append(facts, s+fmt.Sprintf(" (latest local_link %s)", seqRef(h.LatestSeq)))
		}
		if h.Disconnected > 0 {
			facts = append(facts, fmt.Sprintf("the local link was reported not connected in %s", plural(h.Disconnected, "reading", "readings")))
		}
	}
	switch {
	case h.EgressBypass > 0:
		facts = append(facts, fmt.Sprintf("in %d of %d route checks traffic to at least one destination did not go through the AT&T gateway (VPN or another network, first in local_link %s); the monitor attributes nothing to AT&T while that is so",
			h.EgressBypass, h.EgressChecks, seqRef(h.BypassSeq)))
	case h.EgressChecks > 0:
		facts = append(facts, fmt.Sprintf("every route check (%d) sent the monitored Internet destinations through the AT&T gateway (no VPN or second network)", h.EgressChecks))
	}
	body := capitalize(strings.Join(facts, "; ")) + "."
	if h.Healthy {
		b.Lead = "The home network was healthy."
		if len(r.Optical.Readings) > 0 && (r.Optical.AlarmN > 0 || r.Optical.WarnN > 0) {
			body += " The optical receive level is measured by the gateway on the fiber from AT&T's network, which the home network cannot affect."
		}
	} else {
		b.Lead = "Home network observations."
		var issues []string
		switch {
		case h.GwProbes == 0:
			issues = append(issues, "without pings to the gateway the home network's health is unknown")
		case (h.GwProbes-h.GwOK)*100 > h.GwProbes:
			issues = append(issues, "more than 1% of the pings to the gateway were lost")
		}
		if h.GwOK > 0 && float64(h.GwMedianUs) >= h.LatencyOKMs*1000 {
			issues = append(issues, fmt.Sprintf("the median round-trip to the gateway was not below %g ms", h.LatencyOKMs))
		}
		if h.LANKnown > 0 && h.LANDown*1000 > h.LANKnown {
			issues = append(issues, "the gateway was unreachable from this computer in some cycles")
		}
		if h.Disconnected > 0 {
			issues = append(issues, "the local link was not always connected")
		}
		if h.EgressBypass > 0 {
			issues = append(issues, "some traffic bypassed the gateway")
		}
		if len(issues) > 0 {
			body += " Not shown to be healthy: " + strings.Join(issues, "; ") + "."
		}
	}
	b.Text = body
	return b
}

func capitalize(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// ---------------------------------------------------------------- requested action

// deviceText names the gateway for the requested action.
func (r *Report) deviceText() string {
	g := &r.Gateway
	if !g.Known || (g.Model == "" && g.Serial == "") {
		return "The gateway's model and serial number were not recorded in this window."
	}
	name := strings.TrimSpace(g.Manufacturer + " " + g.Model)
	s := "Gateway: " + orNA(name)
	if g.Serial != "" {
		s += ", serial number " + g.Serial
	}
	if g.Firmware != "" {
		s += ", firmware " + g.Firmware
	}
	return s + " (from " + g.Source + ")."
}

func (r *Report) actionBullet() Bullet {
	b := Bullet{Key: "action"}
	op := &r.Optical
	rxFlag := op.AlarmN > 0 || op.WarnN > 0
	var prov int
	var provIncs []IncidentRow
	for _, inc := range r.Incidents {
		if inc.Attribution == model.AttrProvider {
			prov++
			provIncs = append(provIncs, inc)
		}
	}
	// The gateway's flags at the latest reading: a cleared alarm is not "reported" any more.
	flaggedNow := len(op.Readings) > 0 && (op.Readings[op.LatestI].Alarm || op.Readings[op.LatestI].Warn)
	var linkTimes []string
	for _, ch := range r.Link.Changes {
		if ch.Restart == "" && ch.Plausible {
			linkTimes = append(linkTimes, fmtUTC(ch.AsUTC))
		}
	}
	dev := r.deviceText()
	switch {
	case len(op.Readings) == 0 && r.Coverage.Cycles == 0 && r.Link.Observations == 0 && len(r.Incidents) == 0:
		b.Lead = "No measurements in this window."
		b.Text = "This window contains no measurements from the gateway or from the monitor, so this report alone cannot support a repair request. " + dev
	case rxFlag && !flaggedNow:
		return r.clearedAction(dev, provIncs)
	case rxFlag:
		b.Lead = "Please dispatch a technician to check the fiber connection."
		b.Text = "The gateway reports a received optical level below its own low-Rx threshold. Please measure the optical light level at the gateway's fiber port and at the fiber terminal / NID, and clean or repair the fiber connection, jumper or drop as needed until the gateway's low-Rx alarm clears."
		var during []string // provider outages during which the link changed state
		if len(linkTimes) > 0 {
			for _, g := range r.groupChanges(r.Link.Changes) {
				if g.inc != nil && g.inc.Attribution == model.AttrProvider && !slices.Contains(during, g.inc.ID) {
					during = append(during, g.inc.ID)
				}
			}
			switch {
			case len(during) > 2:
				b.Text += fmt.Sprintf(" The fiber link also changed state without a gateway restart, including during %d outages attributed to AT&T (see the summary).", len(during))
			case len(during) > 0:
				b.Text += fmt.Sprintf(" The fiber link also changed state without a gateway restart, including during the %s %s attributed to AT&T (see the summary).",
					noun(len(during), "outage", "outages"), joinAnd(during))
			default:
				b.Text += " The fiber link also changed state without a gateway restart (see the summary)."
			}
		}
		if others := prov - len(during); others > 0 {
			further := ""
			if len(during) > 0 {
				further = "further "
			}
			b.Text += fmt.Sprintf(" The monitor also measured %s attributed to AT&T in this window.", plural(others, further+"outage incident", further+"outage incidents"))
		}
		b.Text += " " + dev + " AT&T should be able to confirm the low receive level and the link events in its own telemetry for this device."
	case prov > 0 || len(linkTimes) > 0:
		b.Lead = "Please investigate the fiber service."
		var why []string
		if prov > 0 {
			why = append(why, fmt.Sprintf("%s attributed to AT&T", plural(prov, "outage incident", "outage incidents")))
		}
		if len(linkTimes) > 0 {
			why = append(why, "fiber link state changes without a gateway restart")
		}
		b.Text = fmt.Sprintf("The records of this window show %s (details below, times in UTC). Please check the line and the fiber connection to this gateway and send a technician if needed. %s",
			strings.Join(why, " and "), dev)
	default:
		b.Lead = "No provider-side fault is shown by this window's records."
		b.Text = "The records of this window show no gateway optical alarm, no fiber link state change and no outage attributed to AT&T, so this report alone does not support a repair request. " + dev
	}
	return b
}

// clearedAction is the requested action when the gateway raised its low-Rx flags in the window but
// no longer shows them at the latest reading: the alarm is not current, so the request is to find
// out what changed and to repair the cause of the losses of light unless that change did.
func (r *Report) clearedAction(dev string, prov []IncidentRow) Bullet {
	op := &r.Optical
	b := Bullet{Key: "action", Lead: "Please check the fiber line and send a technician unless the cause has been repaired."}
	var t strings.Builder
	var when string // the moment of the change, for the question about work on the line
	if cl := op.Clear; cl != nil {
		if op.AlarmRuns == 1 && cl.SetFrom.T.Equal(op.firstLevel().T) {
			fmt.Fprintf(&t, "The gateway's low-Rx alarm, set since the first reading, cleared at %s", r.bothMin(cl.Cleared.T))
		} else {
			fmt.Fprintf(&t, "The gateway's low-Rx alarm was set from %s until it cleared at %s", r.bothMin(cl.SetFrom.T), r.bothMin(cl.Cleared.T))
		}
		if st := r.stepAtClear(); st != nil {
			dir := "higher"
			if st.DeltaX10() < 0 {
				dir = "lower"
			}
			fmt.Fprintf(&t, ", when the fiber link came back from a loss of light with the receive level %s dB %s", fmtX10(absI(st.DeltaX10())), dir)
			when = "between " + r.bothMin(st.From.T) + " and " + r.bothMin(st.To.T)
		} else {
			when = "around " + r.bothMin(cl.Cleared.T)
		}
		t.WriteString(".")
	} else {
		latest := op.Readings[op.LatestI]
		fmt.Fprintf(&t, "The gateway's low-Rx flags were set in %s of the readings, but not at the latest, %s.",
			fmtShare(int64(max(op.AlarmN, op.WarnN)), int64(len(op.Readings))), r.bothMin(latest.T))
	}
	if len(prov) > 0 {
		fiber := true
		ids := make([]string, len(prov))
		for i, inc := range prov {
			fiber = fiber && inc.Cause == model.CauseFiberLinkDown
			ids[i] = inc.ID
		}
		what := fmt.Sprintf("%d outages", len(prov))
		if len(prov) <= 2 {
			what = noun(len(prov), "the outage ", "the outages ") + joinAnd(ids)
		}
		if fiber {
			fmt.Fprintf(&t, " The fiber link went down in %s attributed to AT&T.", what)
		} else {
			fmt.Fprintf(&t, " The monitor also measured %s attributed to AT&T.", what)
		}
	}
	if when != "" {
		fmt.Fprintf(&t, " Please confirm whether any work was done on this line or at the fiber terminal %s. Unless that work repaired the cause, please dispatch", when)
	} else {
		t.WriteString(" Please dispatch")
	}
	t.WriteString(" a technician to measure the light level at the gateway's fiber port and at the fiber terminal / NID and to clean or repair the fiber connection, jumper or drop as needed.")
	t.WriteString(" " + dev + " AT&T should be able to confirm the receive levels and the link events in its own telemetry for this device.")
	b.Text = t.String()
	return b
}

// ---------------------------------------------------------------- monitoring coverage

func (r *Report) coverageStatement() string {
	cv := &r.Coverage
	win := fmtWindowHours(cv.Window)
	var t strings.Builder
	if cv.Cycles == 0 {
		fmt.Fprintf(&t, "The monitor recorded no measurement cycles in this window (0 h of %s).", win)
		if len(cv.Gaps) > 0 && cv.Gaps[0].Brief != "" {
			fmt.Fprintf(&t, " Reason on record: %s.", cv.Gaps[0].Brief)
		}
	} else {
		fmt.Fprintf(&t, "Continuous monitoring (%s cycles) covered %s of this %s window (%s), from %s to %s",
			fmtDur(int64(cv.FastInterval/time.Second)), fmtHours(cv.MonitoredSec), win,
			fmtShare(cv.MonitoredSec, int64(cv.Window/time.Second)), r.both(cv.FirstSample), r.both(cv.LastSample))
		var inner []Gap
		for _, g := range cv.Gaps {
			if g.Kind == "inner" {
				inner = append(inner, g)
			}
		}
		if len(inner) == 0 {
			t.WriteString(", without gaps.")
		} else {
			var total, longest int64
			for _, g := range inner {
				total += g.Sec
				longest = max(longest, g.Sec)
			}
			fmt.Fprintf(&t, ", with %s (%s in total, the longest %s; listed in the details).",
				plural(len(inner), "gap", "gaps"), fmtDur(total), fmtDur(longest))
		}
		for _, g := range cv.Gaps {
			switch g.Kind {
			case "leading":
				fmt.Fprintf(&t, " Before %s: %s.", r.bothMin(g.To), g.Brief)
			case "trailing":
				fmt.Fprintf(&t, " After %s: %s.", r.bothMin(g.From), g.Brief)
			}
		}
	}
	// What covers the unmonitored time, when it matters (monitoring covered less than 90 %).
	if cv.MonitoredSec*10 < int64(cv.Window/time.Second)*9 {
		var rest []string
		lk := &r.Link
		if lk.UptimeReadings > 0 {
			if len(lk.Restarts) == 0 {
				rest = append(rest, fmt.Sprintf("its uptime (no restart since %s)", fmtUTC(lk.Boot)))
			} else {
				rest = append(rest, "its uptime readings (restarts listed above)")
			}
		}
		if lk.First.Plausible {
			rest = append(rest, "its fiber Last Change value")
		}
		if s := r.Evidence.Setup; s != nil && s.InWindow && s.Rx != nil {
			rest = append(rest, fmt.Sprintf("the setup-time capture of %s (bootstrap_import %s)", fmtUTC(s.Rx.T), seqRef(s.Seq)))
		}
		if len(rest) > 0 {
			fmt.Fprintf(&t, " For the time without monitoring the evidence is the gateway's own record: %s.", joinAnd(rest))
		} else {
			t.WriteString(" No other record covers the time without monitoring.")
		}
	}
	return t.String()
}

func joinAnd(parts []string) string {
	switch len(parts) {
	case 0:
		return ""
	case 1:
		return parts[0]
	case 2:
		return parts[0] + " and " + parts[1]
	}
	return strings.Join(parts[:len(parts)-1], ", ") + " and " + parts[len(parts)-1]
}

// ---------------------------------------------------------------- key facts

func (r *Report) facts() []Fact {
	// Facts whose records the other tables already name (the ledger and window records, the
	// covering time-stamp, the gateway identity, incidents, the local link) are not repeated.
	var out []Fact
	add := func(what, ref string) { out = append(out, Fact{What: what, Ref: ref}) }
	if s := r.Evidence.Setup; s != nil && s.Fiber != nil {
		add("Setup-time capture of the fiber status page", fmt.Sprintf("bootstrap_import %s, %s (SHA-256 %s)", seqRef(s.Seq), s.Fiber.Path, s.Fiber.SHA256))
	}
	op := &r.Optical
	if n := len(op.Readings); n > 0 {
		// The latest and the lowest reading are rows of the readings table, with their records.
		var alarmSeqs []uint64
		for _, rd := range op.Readings {
			if rd.Alarm && !rd.Setup {
				alarmSeqs = append(alarmSeqs, rd.Seq)
			}
		}
		if len(alarmSeqs) > 0 {
			add("Snapshots with the gateway's low-Rx ALARM flag set", fmtSeqList(alarmSeqs, 6))
		}
		if cl := op.Clear; cl != nil {
			ref := cl.Cleared.Source()
			if cl.EventSeq != 0 {
				ref += "; gateway_event optical_alarm " + seqRef(cl.EventSeq)
			}
			add("The gateway's low-Rx ALARM flag cleared at "+fmtUTC(cl.Cleared.T), ref)
		}
		for i, st := range op.Steps {
			if i == 2*maxSteps {
				add(fmt.Sprintf("%s of the receive level", plural(len(op.Steps)-i, "further step change", "further step changes")), "gateway_snapshot records")
				break
			}
			what := fmt.Sprintf("Receive level step of %s dB", fmtSignedX10(st.DeltaX10()))
			if len(st.NoLight) > 0 {
				what += " across a loss of light"
			}
			add(what+" at "+fmtUTC(st.To.T), st.From.Source()+" → "+st.To.Source())
		}
	}
	// The first Last Change observation and the uptime reading are named in the summary itself.
	lk := &r.Link
	var evSeqs, snapSeqs []uint64
	for _, ch := range lk.Changes {
		switch {
		case ch.Event:
			evSeqs = append(evSeqs, ch.Seq)
		case ch.Prev != "":
			snapSeqs = append(snapSeqs, ch.Seq)
		}
	}
	if len(evSeqs) > 0 {
		add("Fiber link state changes seen during monitoring", "gateway_event optical_link_change "+fmtSeqList(evSeqs, 8))
	}
	if len(snapSeqs) > 0 {
		add("Fiber link state changes seen in snapshots", "snapshots "+fmtSeqList(snapSeqs, 8))
	}
	if lk.Offset != nil {
		add("Gateway clock offset "+fmtOffset(*lk.Offset), lk.OffsetSrc)
	}
	for _, rs := range lk.Restarts {
		add("Gateway restart at "+fmtUTC(rs.Boot), rs.Source)
	}
	return slices.Clip(out)
}
