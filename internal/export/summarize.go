package export

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"attmonitor/internal/model"
)

const (
	codeRxLowAlarm = "OPTICAL_RX_LOW_ALARM"
	codeRxLowWarn  = "OPTICAL_RX_LOW_WARNING"

	// alarmGapBreak ends an alarm period when no gateway reading was taken for this long:
	// the report never claims a flag was active while nobody was looking.
	alarmGapBreak = 15 * time.Minute

	defaultCadence = defaultFastInterval
)

// finish completes the integrity checks and computes the whole report.
func (c *collector) finish() *report {
	a := &c.agg
	c.checkAnchors()
	if c.pub == nil {
		c.addFailure(model.VerifyFailure{Problem: "bad_signature",
			Detail: "no valid genesis record in the bundle: the ledger public key is unknown, so signatures could not be verified"})
	}
	c.chk.BlobsReferenced = len(c.blobRefs)
	c.chk.OK = c.chk.FailuresTotal == 0

	// The local zone the report shows times in: the exporting computer's, recorded in the
	// report (a verifier renders with that record, not with its own zone).
	zone := c.p.zone
	if zone == nil {
		times := []time.Time{c.from, c.to, c.now, c.minTS, c.maxTS}
		for _, b := range a.boots {
			times = append(times, b.t)
		}
		lo, hi := zoneRange(times...)
		zone = zoneSpans(time.Local, lo, hi)
	}
	loc, err := zoneLocation(zone)
	if err != nil {
		c.zoneErr = err
		loc = time.UTC
		if c.p.zone == nil { // the computer's zone cannot be recorded: show and record UTC
			zone = []zoneSpan{{From: zone[0].From, Abbrev: "UTC"}}
			c.notes = append(c.notes, "The exporting computer's time zone could not be recorded ("+err.Error()+"); local times are shown in UTC.")
		}
	}
	c.loc = loc

	r := &report{
		Format:      reportFormat,
		GeneratedAt: c.now.UTC().Format(time.RFC3339Nano),
		Generator:   validSoftware(c.p.software),
		Period: period{
			From:         c.from.UTC().Format(time.RFC3339Nano),
			To:           c.to.UTC().Format(time.RFC3339Nano),
			EffectiveEnd: c.end.UTC().Format(time.RFC3339Nano),
			Scope:        "period",
			LocalZone:    zoneLabel(loc, c.from),
		},
		LocalTime: localTimeZone{Note: zoneNote, Spans: zone},
		Request: requestInfo{
			PreparedBy: validUTF8(strings.TrimSpace(c.p.req.PreparedBy)),
			Notes:      validUTF8(strings.TrimSpace(c.p.req.Notes)),
			Requester:  validUTF8(strings.TrimSpace(c.p.req.Requester)),
		},
		Host:          a.host,
		GatewayEvents: a.events,
		Bootstrap:     a.bootstrap,
	}
	if c.p.incident != nil {
		r.Period.Scope = "incident"
		r.Period.IncidentID = c.p.incident.inc.ID
	}
	r.Gateway = make([]gatewayIdentity, 0, len(a.identities))
	for _, id := range a.identities {
		r.Gateway = append(r.Gateway, *id)
	}
	if len(r.Gateway) == 0 && a.preIdentity != nil {
		r.Gateway = append(r.Gateway, *a.preIdentity)
	}

	// Ledger.
	r.Ledger = ledgerInfo{Records: c.chk.Records, TypeCounts: c.typeCounts, Omitted: c.omitted, Head: c.head}
	for _, s := range c.segs {
		r.Ledger.Segments = append(r.Ledger.Segments, *s)
	}
	for i := c.lastSegIdx + 1; c.lastSegIdx >= 0 && i < len(c.p.all); i++ {
		o := c.p.all[i]
		r.Ledger.Later = append(r.Ledger.Later, omittedSegment{Name: o.Name, FirstSeq: o.FirstSeq, LastSeq: o.LastSeq, Records: o.Records})
	}
	if g := c.gen; g != nil {
		ref := g.ref
		r.Ledger.Genesis = &ref
		r.Ledger.PublicKey = g.g.PublicKey
		r.Ledger.Fingerprint = g.fingerprint
		r.Ledger.Created = g.g.Created
		r.Ledger.Statement = g.g.Statement
		r.Ledger.GenesisVerified = c.pub != nil
	}

	// Verification. A full-ledger verification that did not complete in the time an export
	// allows it is reported as such, not as a failure: the bundle's own records are verified.
	r.Verification = verification{Bundle: c.chk, FullError: c.p.fullErr, FullIncomplete: c.p.fullIncomplete}
	if c.p.full != nil {
		f := *c.p.full
		f.FingerprintMatches = f.Fingerprint != "" && f.Fingerprint == r.Ledger.Fingerprint
		f.KeyMismatch = f.Fingerprint != "" && r.Ledger.Fingerprint != "" && f.Fingerprint != r.Ledger.Fingerprint
		r.Verification.Full = &f
	}
	r.Verification.Overall = "pass"
	if f := r.Verification.Full; !c.chk.OK || c.p.fullErr != "" || (f != nil && (!f.OK || f.KeyMismatch)) {
		r.Verification.Overall = "fail"
	}

	c.summarize(r)
	c.opticalSummary(r)
	r.GatewayStatus = a.gw
	r.GatewayStatus.PONStatus = a.ponCounts.list()
	r.GatewayStatus.OpticalStatus = a.optCounts.list()
	r.GatewayStatus.WANIPv4 = nonNil(a.wanIPs)
	c.serviceAndLink(r)
	c.methodology(r)
	r.Anchors = a.anchors
	if r.Anchors == nil {
		r.Anchors = []anchorEntry{}
	}
	if r.GatewayEvents == nil {
		r.GatewayEvents = []gatewayEventEntry{}
	}
	if r.Bootstrap == nil {
		r.Bootstrap = []bootstrapEntry{}
	}
	r.Custody = c.custodyLog(r.Summary.Gaps)
	r.Notes = c.notes
	if c.dataNotes > 20 {
		r.Notes = append(r.Notes, fmt.Sprintf("... and %d more records whose payload could not be interpreted", c.dataNotes-20))
	}
	c.rep = r
	return r
}

// validSoftware makes the generator's description valid UTF-8 (see validUTF8).
func validSoftware(s model.SoftwareInfo) model.SoftwareInfo {
	for _, f := range []*string{&s.Name, &s.Version, &s.Commit, &s.GoVersion, &s.ExePath, &s.ExeSHA256, &s.Rules} {
		*f = validUTF8(*f)
	}
	return s
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// summarizeFull summarizes a full-ledger verification for the report (finish sets the
// comparison with the bundle's key).
func summarizeFull(f *model.VerifyReport) *fullVerification {
	v := &fullVerification{
		OK: f.OK, At: f.At, Records: f.Records, Segments: len(f.Segments), FirstTS: f.FirstTS, LastTS: f.LastTS,
		HeadHash: f.HeadHash, Fingerprint: f.Fingerprint,
		BlobsChecked: f.BlobsChecked, FailuresTotal: f.FailuresTotal, Anchors: len(f.Anchors), TokensChecked: f.TokensChecked,
		LastAnchoredSeq: f.LastAnchoredSeq, UnanchoredTail: f.UnanchoredTail, Gaps: len(f.Gaps), ClockJumps: f.ClockJumps,
		Notes: f.Notes,
	}
	if v.FailuresTotal < len(f.Failures) {
		v.FailuresTotal = len(f.Failures)
	}
	for i, x := range f.Failures {
		if i == 20 {
			break
		}
		x.Segment, x.Problem, x.Detail = validUTF8(x.Segment), validUTF8(x.Problem), validUTF8(x.Detail)
		v.Failures = append(v.Failures, x)
	}
	// The verification comes from outside the bundle's records: report.json states it, and
	// report verification reads it back, so its text must be valid UTF-8.
	v.At, v.FirstTS, v.LastTS = validUTF8(v.At), validUTF8(v.FirstTS), validUTF8(v.LastTS)
	v.HeadHash, v.Fingerprint = validUTF8(v.HeadHash), validUTF8(v.Fingerprint)
	if f.Notes != nil {
		v.Notes = make([]string, len(f.Notes))
		for i, n := range f.Notes {
			v.Notes[i] = validUTF8(n)
		}
	}
	for _, an := range f.Anchors {
		if an.OK {
			v.AnchorsOK++
			if an.ChainOK {
				v.AnchorsProofOfTime++
			}
		}
	}
	return v
}

// ------------------------------------------------------------------ executive summary

// cadence estimates the fast-cycle interval as the median gap between consecutive samples.
func cadence(samples []sampleLite) (time.Duration, bool) {
	var ds []int64
	for i := 1; i < len(samples); i++ {
		if d := samples[i].t - samples[i-1].t; d > 0 {
			ds = append(ds, d)
		}
	}
	if len(ds) == 0 {
		return defaultCadence, true
	}
	sort.Slice(ds, func(i, j int) bool { return ds[i] < ds[j] })
	d := time.Duration(ds[len(ds)/2])
	if len(ds)%2 == 0 {
		d = time.Duration((ds[len(ds)/2-1] + ds[len(ds)/2]) / 2)
	}
	d = max(d, time.Second)
	d = min(d, 10*time.Minute)
	return d, false
}

var stateOrder = []string{model.StateOnline, model.StateDegraded, model.StateISPOutage, model.StateLocalFault, model.StateUnknown}

func stateRank(s string) int {
	switch s {
	case model.StateISPOutage:
		return 0
	case model.StateLocalFault:
		return 1
	case model.StateDegraded:
		return 2
	}
	return 3
}

func isBad(state string) bool {
	return state != "" && state != model.StateOnline && state != model.StateUnknown
}

func (c *collector) summarize(r *report) {
	a := &c.agg
	s := &r.Summary
	win := c.end.Sub(c.from)
	s.WindowSec = int64(win / time.Second)

	// Thresholds in force (the configuration recorded by config_state or monitor_start records)
	// and the cycle-time accounting.
	th, base, src := c.resolveThresholds()
	r.Methodology.Thresholds, r.Methodology.ConfigSource = th, src
	tl, basis, fast := c.timeline(base)
	windows := c.restartWindows(tl)
	c.tl, c.windows = tl, windows
	var samples []acctSample // samples of the period, time order
	for _, x := range tl {
		if x.inPeriod {
			samples = append(samples, x)
		}
	}
	lite := make([]sampleLite, len(samples))
	for i, x := range samples {
		lite[i] = x.sampleLite
	}
	interval, assumed := cadence(lite)
	s.CadenceSec, s.CadenceAssumed = interval.Seconds(), assumed
	s.FastIntervalSec, s.FastIntervalBasis = fast.Seconds(), basis

	ct := account(tl)
	s.MonitoredSec = int64(ct.monitored / time.Second)
	if win > 0 && ct.monitored > 0 {
		// Percentages are truncated, never rounded up (fmtPct): 99.9996 % is not 100 %.
		s.CoveragePct = floorPct3(uint64(ct.monitored), uint64(win))
	}
	s.DowntimeSec = int64(ct.downtime / time.Second)
	s.DegradedSec = int64(ct.degraded / time.Second)
	s.RestartSec = int64(ct.restart / time.Second)
	s.ProviderOutageSec = int64(ct.providerOutage / time.Second)
	s.ProviderDowntimeSec = s.ProviderOutageSec
	s.ProviderDegradedSec = int64(ct.providerDegraded / time.Second)
	s.TimeByState = []stateTime{}
	for _, sc := range orderedStateCounts(durCounts(ct.byState)) {
		s.TimeByState = append(s.TimeByState, stateTime{State: sc.State, Seconds: int64(ct.byState[sc.State] / time.Second)})
	}
	s.GatewayRestarts = c.restartEntries(windows)

	// Cycles by state; availability = ONLINE cycles / cycles with a known state.
	s.Cycles = len(samples)
	counts := map[string]int{}
	for _, x := range samples {
		st := x.state
		if st == "" {
			st = model.StateUnknown
		}
		counts[st]++
	}
	s.CyclesByState = orderedStateCounts(counts)
	s.CyclesKnown = len(samples) - counts[model.StateUnknown]
	if s.CyclesKnown > 0 {
		// Truncated, so that one bad cycle in any number of cycles never reads 100 %.
		av := floorPct3(uint64(counts[model.StateOnline]), uint64(s.CyclesKnown))
		s.AvailabilityPct = &av
	}
	if len(samples) > 0 {
		s.FirstSample = time.Unix(0, samples[0].t).UTC().Format(time.RFC3339Nano)
		s.LastSample = time.Unix(0, samples[len(samples)-1].t).UTC().Format(time.RFC3339Nano)
	}

	// Monitoring gaps.
	s.Gaps = c.gaps(samples, base.fast)
	for _, g := range s.Gaps {
		s.GapSec += g.Seconds
	}

	// Incidents (their own records) and the incident classes.
	r.Incidents = c.incidentEntries(tl, windows, base)
	s.Incidents = len(r.Incidents)
	classes := map[[3]string]*incidentClass{}
	var classKeys [][3]string
	for _, e := range r.Incidents {
		inc := e.Incident
		k := [3]string{inc.State, inc.Cause, inc.Attribution}
		ic := classes[k]
		if ic == nil {
			ic = &incidentClass{State: inc.State, Cause: inc.Cause, Attribution: inc.Attribution}
			classes[k] = ic
			classKeys = append(classKeys, k)
		}
		ic.Count++
		ic.Seconds += e.InPeriodSec
		if inc.Attribution == model.AttrProvider {
			s.ProviderIncidents++
		}
		if inc.State == model.StateISPOutage || inc.State == model.StateLocalFault {
			if s.LongestOutage == nil || e.DurationSec > s.LongestOutage.Seconds {
				s.LongestOutage = &incidentRef{ID: inc.ID, State: inc.State, Cause: inc.Cause,
					Attribution: inc.Attribution, Seconds: e.DurationSec, Ongoing: e.Ongoing, DowntimeSec: e.Recorded.DowntimeSec,
					RestartConflict: e.RestartCheck != nil && len(e.RestartCheck.Conflicts) > 0}
				if e.Computed != nil {
					s.LongestOutage.DowntimeSec, s.LongestOutage.DowntimeComputed = ptr(e.Computed.Stats.DowntimeSec), true
				}
			}
		}
	}
	// Samples of the period tagged with an incident that has no record in the bundle: the
	// cycles are counted above, but the incident cannot be described.
	for _, id := range a.tagOrder {
		if _, ok := a.incidents[id]; !ok {
			s.IncidentsWithoutRecords = append(s.IncidentsWithoutRecords, id)
			c.notes = append(c.notes, fmt.Sprintf("%s of this period carry incident id %s, but none of that incident's records "+
				"(incident_open, incident_update, incident_close) is in this bundle, so the incident is not described in this report.",
				plural(a.tags[id], "sample", "samples"), id))
		}
	}
	sort.SliceStable(classKeys, func(i, j int) bool {
		x, y := classKeys[i], classKeys[j]
		if stateRank(x[0]) != stateRank(y[0]) {
			return stateRank(x[0]) < stateRank(y[0])
		}
		if x[1] != y[1] {
			return x[1] < y[1]
		}
		return x[2] < y[2]
	})
	s.IncidentsByClass = []incidentClass{}
	for _, k := range classKeys {
		s.IncidentsByClass = append(s.IncidentsByClass, *classes[k])
	}

	// Blips: bad streaks that ended with a good cycle without becoming an incident.
	blipStates := map[string]int{}
	spans := c.incidentSpans()
	for i := 0; i < len(samples); {
		if !isBad(samples[i].state) {
			i++
			continue
		}
		j, withIncident := i, false
		for j < len(samples) && isBad(samples[j].state) && (j == i || time.Duration(samples[j].t-samples[j-1].t) <= gapLimit(samples[j-1].fast)) {
			withIncident = withIncident || samples[j].incident
			j++
		}
		endedGood := j < len(samples) && !isBad(samples[j].state) && time.Duration(samples[j].t-samples[j-1].t) <= gapLimit(samples[j-1].fast)
		if endedGood && !withIncident && !overlapsAny(spans, samples[i].t, samples[j-1].t) {
			s.Blips++
			s.BlipCycles += j - i
			blipStates[samples[i].state]++
		}
		i = j
	}
	if len(blipStates) > 0 {
		s.BlipsByState = orderedStateCounts(blipStates)
	}

	s.LastRecordInPeriod = a.lastInWindow
	if a.lastInWindow != nil {
		s.LastRecordAnchor = c.anchorCovering(a.lastInWindow.Seq)
	}
}

// durCounts turns durations per state into counts usable by orderedStateCounts (which only
// orders the keys; states with zero time are kept when they have samples).
func durCounts(m map[string]time.Duration) map[string]int {
	out := make(map[string]int, len(m))
	for k := range m {
		out[k] = 1
	}
	return out
}

func orderedStateCounts(m map[string]int) []stateCount {
	out := []stateCount{}
	seen := map[string]bool{}
	for _, st := range stateOrder {
		if n := m[st]; n > 0 {
			out = append(out, stateCount{State: st, Count: n})
		}
		seen[st] = true
	}
	var rest []string
	for st := range m {
		if !seen[st] {
			rest = append(rest, st)
		}
	}
	sort.Strings(rest)
	for _, st := range rest {
		out = append(out, stateCount{State: st, Count: m[st]})
	}
	return out
}

func round3(f float64) float64 { return math.Round(f*1000) / 1000 }

// gaps lists periods without samples longer than the gap limit (docs/DESIGN.md §6: > 3x the
// cycle interval of the sample before the gap), including before the first and after the last
// sample of the period. fast is the cycle interval assumed where no sample says otherwise.
func (c *collector) gaps(samples []acctSample, fast time.Duration) []gapEntry {
	out := []gapEntry{}
	add := func(from, to time.Time, interval time.Duration) {
		if !to.After(from) {
			return
		}
		g := gapEntry{From: from.UTC().Format(time.RFC3339Nano), To: to.UTC().Format(time.RFC3339Nano), Seconds: int64(to.Sub(from) / time.Second)}
		g.Explanation, g.Evidence = c.explainGap(from, to, interval)
		out = append(out, g)
	}
	if len(samples) == 0 {
		add(c.from, c.end, fast)
		return out
	}
	if first := time.Unix(0, samples[0].t); first.Sub(c.from) > gapLimit(samples[0].fast) {
		add(c.from, first, samples[0].fast)
	}
	for i := 1; i < len(samples); i++ {
		if time.Duration(samples[i].t-samples[i-1].t) > gapLimit(samples[i-1].fast) {
			add(time.Unix(0, samples[i-1].t), time.Unix(0, samples[i].t), samples[i-1].fast)
		}
	}
	last := samples[len(samples)-1]
	if lt := time.Unix(0, last.t); c.end.Sub(lt) > gapLimit(last.fast) {
		add(lt, c.end, last.fast)
	}
	return out
}

// explainGap names the custody records (stops, starts, power events, recovery, genesis) found
// around a gap. It never guesses: without such records the gap is "unexplained".
func (c *collector) explainGap(from, to time.Time, interval time.Duration) (string, []uint64) {
	lo, hi := from.Add(-2*interval), to.Add(2*interval)
	var parts []string
	var seqs []uint64
	extra := 0
	for _, m := range c.agg.marks {
		if m.t.Before(lo) || m.t.After(hi) {
			continue
		}
		if len(parts) == 6 {
			extra++
			continue
		}
		text := m.text
		if m.typ == model.TypeMonitorStart && !m.clean {
			text = "monitor started after an unclean stop (crash, power loss or forced termination)"
		}
		text = fmt.Sprintf("%s at %s (seq %d)", text, m.t.UTC().Format("2006-01-02 15:04:05Z"), m.seq)
		seqs = append(seqs, m.seq)
		if m.typ == model.TypeMonitorStart {
			// The clock facts of the process that started: a step of the clock between the runs
			// changes the gap's length as this computer's clock measured it.
			if st, ok := c.agg.runStep[m.run]; ok {
				text += fmt.Sprintf(", and this computer's clock moved %s against the time servers between the runs (clock_jump seq %d), "+
					"so the length of this gap as its clock measured it includes that step", fmtSignedMs(st.jumpMs), st.seq)
				seqs = append(seqs, st.seq)
			}
			if seq, ok := c.agg.runBehind[m.run]; ok {
				text += fmt.Sprintf(", and when it opened the ledger this computer's clock was behind the newest ledger record "+
					"(integrity_alert seq %d)", seq)
				seqs = append(seqs, seq)
			}
		}
		parts = append(parts, text)
	}
	if len(parts) == 0 {
		return "unexplained: no stop, start, power or recovery record near this gap", nil
	}
	if extra > 0 {
		parts = append(parts, fmt.Sprintf("and %d more", extra))
	}
	return strings.Join(parts, "; "), appendSeqs(nil, len(seqs), seqs...)
}

type span struct{ from, to int64 }

func (c *collector) incidentSpans() []span {
	var out []span
	for _, id := range c.agg.incOrder {
		acc := c.agg.incidents[id]
		o, ok := parseTS(acc.latest.Opened)
		if !ok {
			continue
		}
		e := c.end
		if cl, ok := parseTS(acc.latest.Closed); ok && !acc.latest.Open {
			e = cl
		}
		// Spans only matter for the samples of the period: clamp them to it, so that record
		// times outside 1970..2261 cannot wrap around in Unix nanoseconds.
		o, e = maxTime(o, c.from), minTime(e, c.end)
		if e.Before(o) {
			continue
		}
		out = append(out, span{o.UnixNano(), e.UnixNano()})
	}
	return out
}

func maxTime(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

func overlapsAny(spans []span, from, to int64) bool {
	for _, s := range spans {
		if from <= s.to && to >= s.from {
			return true
		}
	}
	return false
}

// anchorCovering returns the first anchor at or after seq that is proof of time (see
// decideProof): its head record is in the bundle with the anchored hash, its token is
// included and valid over that hash, and its TSA certificate chain is trusted. The time
// reported is the token's genTime, not the record's copy of it.
func (c *collector) anchorCovering(seq uint64) *anchorRef {
	for _, an := range c.agg.anchors {
		if an.HeadSeq >= seq && an.ProofOfTime {
			tsa := an.TokenTSAName
			if tsa == "" {
				tsa = an.TSAName
			}
			if tsa == "" {
				tsa = an.TSAURL
			}
			return &anchorRef{Seq: an.Seq, TSA: tsa, GenTime: an.TokenGenTime, HeadSeq: an.HeadSeq, ProofBasis: an.ProofBasis}
		}
	}
	return nil
}

// ------------------------------------------------------------------ incidents

func (c *collector) incidentEntries(tl []acctSample, windows []*restartWindow, base params) []incidentEntry {
	a := &c.agg
	out := []incidentEntry{}
	var ix *seqIndex
	for _, id := range a.incOrder {
		acc := a.incidents[id]
		inc := acc.latest
		opened, ok := parseTS(inc.Opened)
		if !ok {
			c.notes = append(c.notes, fmt.Sprintf("incident %s has no valid opened time and is not summarised", id))
			continue
		}
		closed, okc := parseTS(inc.Closed)
		ongoing := !(okc && (!inc.Open || acc.haveClose))
		end := closed
		if ongoing {
			end = c.end
			if end.Before(opened) {
				end = opened
			}
		}
		if !(opened.Before(c.end) && (end.After(c.from) || !opened.Before(c.from))) {
			continue
		}
		e := incidentEntry{
			Incident:     inc,
			Ongoing:      ongoing,
			EffectiveEnd: end.UTC().Format(time.RFC3339Nano),
			DurationSec:  int64(end.Sub(opened) / time.Second),
			InPeriodSec:  int64(overlap(opened, end, c.from, c.end) / time.Second),
			RecordSeqs:   acc.records,
			RecordedSeq:  acc.latestSeq,
			RecordedTS:   acc.latestTS,
		}
		if ix == nil {
			ix = newSeqIndex(tl)
		}
		var cyc []*acctSample
		complete := false
		if ongoing {
			// Its latest record states the figures only as of when it was written (an
			// incident_update is written only when the classification changes): recompute them
			// from the samples.
			e.Computed, cyc = c.computeIncident(inc, tl, ix, base.close)
		} else {
			cyc, complete = c.closedIncidentCycles(inc, opened, closed, tl, ix)
		}
		// Its cycles with the gateway-restart windows of this report (rules 2026.10-4), counted
		// over the whole incident in this bundle, for comparison with its record.
		fast, open := base.fast, base.open
		if len(cyc) > 0 {
			fast, open = cyc[0].fast, c.openAfterOf(cyc[0], base.open)
		}
		figs := figuresOf(cyc, windows, opened, end, fast)
		e.ComputedRestartSec = int64(figs.restart / time.Second)
		if !ongoing {
			e.RestartCheck = c.restartCheckOf(acc, figs, complete, open)
		}
		e.KeyFacts = c.incidentFacts(inc, &e, opened, end)
		if acc.haveOpen {
			v := acc.openSeq
			e.OpenSeq = &v
		}
		if acc.haveClose {
			v := acc.closeSeq
			e.CloseSeq = &v
		}
		seqSet := map[uint64]bool{}
		blobSet := map[string]bool{}
		for _, ev := range inc.Evidence {
			seqSet[ev.Seq] = true
			if ev.Blob != "" {
				blobSet[ev.Blob] = true
			}
		}
		for _, s := range []uint64{inc.FirstSeq, inc.LastSeq} {
			if s != 0 {
				seqSet[s] = true
			}
		}
		e.EvidenceSeqs = sortedSeqs(seqSet)
		for b := range blobSet {
			e.EvidenceBlobs = append(e.EvidenceBlobs, b)
		}
		sort.Strings(e.EvidenceBlobs)
		last := max(acc.latestSeq, acc.closeSeq, inc.LastSeq)
		e.Anchor = c.anchorCovering(last)
		if acc.hasDowntime {
			e.Recorded.DowntimeSec = ptr(inc.Stats.DowntimeSec)
		}
		if acc.hasDegraded {
			e.Recorded.DegradedSec = ptr(inc.Stats.DegradedSec)
		}
		if acc.hasRestart {
			e.Recorded.RestartSec = ptr(inc.Stats.RestartSec)
		}
		if figs.restart > 0 && !acc.hasRestart {
			e.KeyFacts = append(e.KeyFacts, restartFact(inc, figs.restart, figs.boots()))
		}
		if rc := e.RestartCheck; rc != nil {
			e.KeyFacts = append(e.KeyFacts, rc.Conflicts...)
		}
		out = append(out, e)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Incident.Opened != out[j].Incident.Opened {
			ti, _ := parseTS(out[i].Incident.Opened)
			tj, _ := parseTS(out[j].Incident.Opened)
			return ti.Before(tj)
		}
		return out[i].Incident.ID < out[j].Incident.ID
	})
	return out
}

func sortedSeqs(m map[uint64]bool) []uint64 {
	out := make([]uint64, 0, len(m))
	for s := range m {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func overlap(a0, a1, b0, b1 time.Time) time.Duration {
	s, e := a0, a1
	if b0.After(s) {
		s = b0
	}
	if b1.Before(e) {
		e = b1
	}
	if e.After(s) {
		return e.Sub(s)
	}
	return 0
}

// incidentFacts turns an incident's statistics and reasons into short sentences: those of its
// latest record, or for an incident still open at the end of the period (e.Computed) those
// computed from the samples, with the record's own figures named as of that record. Conditions
// that the gateway reports permanently (an optical low alarm) or AT&T's NXDOMAIN redirection are
// stated against what was observed before the incident opened, so that a standing condition is
// not presented as a fact of this incident.
func (c *collector) incidentFacts(inc model.Incident, e *incidentEntry, opened, end time.Time) []string {
	f := []string{}
	st := inc.Stats
	during := "during the incident"
	if comp := e.Computed; comp != nil {
		st = comp.Stats
		through := fmtUTC(comp.Through)
		from := fmt.Sprintf("its first bad cycle (sample seq %d)", comp.FromSeq)
		if !comp.Complete {
			from = fmt.Sprintf("sample seq %d (its first bad cycles are not in this bundle, so these figures are incomplete)", comp.FromSeq)
		}
		f = append(f, fmt.Sprintf("Still open at %s (no close record in this bundle). Figures computed by this report from the samples "+
			"from %s through %s: %s without Internet (ISP_OUTAGE cycles), %s degraded, %s in gateway-restart windows.",
			through, from, through, fmtDur(st.DowntimeSec), fmtDur(st.DegradedSec), fmtDur(st.RestartSec)))
		if comp.ClosingAt != "" {
			f = append(f, fmt.Sprintf("The samples show it recovering: consecutive ONLINE cycles from %s close it under the rules; "+
				"its close record is not in this bundle.", fmtUTC(comp.ClosingAt)))
		}
		if comp.InterruptedAt != "" {
			f = append(f, fmt.Sprintf("The samples show monitoring interrupted while it was open (a monitoring gap, or a cycle cut "+
				"short by system sleep): under the rules it closes at %s, the end of the time its last bad cycle covers (or the first "+
				"cycle of a closing streak already under way), and later cycles are not counted; its close record is not in this "+
				"bundle.", fmtUTC(comp.InterruptedAt)))
		}
		during = "so far"
		if inc.Summary != "" {
			f = append(f, fmt.Sprintf("Its latest record (seq %d, %s), written when it opened or last changed, says: %s",
				e.RecordedSeq, fmtUTC(e.RecordedTS), inc.Summary))
		}
	} else if inc.Summary != "" {
		f = append(f, inc.Summary)
	}
	if st.Cycles > 0 {
		f = append(f, fmt.Sprintf("%d of %d monitoring cycles %s were not ONLINE", st.BadCycles, st.Cycles, during))
	}
	if p := probeSummary(st.ProbeOK, st.ProbeTotal); p != "" {
		f = append(f, "Probe successes: "+p)
	}
	if st.GatewayDownSeen {
		f = append(f, "The AT&T gateway itself reported Broadband Connection: Down")
	}
	if st.PONDownSeen {
		f = append(f, "The AT&T gateway reported its PON (fiber) link outside the operational state O5")
	}
	if st.OpticalAlarm {
		f = append(f, c.opticalFact(opened, end))
	}
	if st.DNSHijackSeen {
		f = append(f, c.dnsFact(opened, end))
	}
	if st.HTTPHijackSeen {
		f = append(f, "An HTTP check was redirected or answered by the gateway (hijack detected)")
	}
	if st.LocalLinkDown {
		f = append(f, "The monitoring PC's own network link reported disconnected")
	}
	if st.GatewayFetches > 0 {
		f = append(f, fmt.Sprintf("%d gateway status page fetches recorded %s", st.GatewayFetches, during))
	}
	if len(inc.Causes) > 1 {
		f = append(f, "Causes observed: "+strings.Join(inc.Causes, ", "))
	}
	for i, r := range inc.Reasons {
		if i == 6 {
			f = append(f, fmt.Sprintf("(%d more reasons in report.json)", len(inc.Reasons)-6))
			break
		}
		f = append(f, r)
	}
	return f
}

// opticalFact states the gateway's own alarm flags of an incident against the gateway's last
// fiber reading before it opened: at this kind of site the Rx low alarm can be a standing
// condition of the line, which then says nothing about what caused the incident.
func (c *collector) opticalFact(opened, end time.Time) string {
	var before *fiberObs
	var codes []string
	for i := range c.agg.fibers {
		fo := &c.agg.fibers[i]
		switch {
		case fo.t.Before(opened):
			if before == nil || !fo.t.Before(before.t) {
				before = fo
			}
		case !fo.t.After(end):
			codes = append(codes, fo.alarms...)
		}
	}
	codes = uniqueSorted(codes)
	what, was := "The AT&T gateway's own optical alarm flag", "was"
	if len(codes) > 0 {
		var labels []string
		for _, code := range codes {
			labels = append(labels, codeLabel(code))
		}
		what, was = fmt.Sprintf("The AT&T gateway's own alarm flags (%s)", strings.Join(labels, ", ")), "were"
	}
	switch {
	case before == nil:
		return fmt.Sprintf("%s %s set during the incident; no reading of the gateway's fiber module from before the incident is in this "+
			"bundle, so whether the condition already existed before it is not shown here.", what, was)
	case len(before.alarms) > 0 && (len(codes) == 0 || overlapsCodes(before.alarms, codes)):
		return fmt.Sprintf("%s %s set during the incident, but %s already active before the incident began (the gateway's last "+
			"reading before it, %s, record seq %d, shows %s): a standing condition of the line that predates the incident, not "+
			"evidence of what caused it.", what, was, was, fmtUTC(before.t.UTC().Format(time.RFC3339Nano)), before.seq,
			strings.Join(before.alarms, ", "))
	default:
		return fmt.Sprintf("%s %s set during the incident and not in the gateway's last reading before it (%s, record seq %d).",
			what, was, fmtUTC(before.t.UTC().Format(time.RFC3339Nano)), before.seq)
	}
}

func overlapsCodes(a, b []string) bool {
	for _, x := range a {
		if hasCode(b, x) {
			return true
		}
	}
	return false
}

// dnsFact states the DNS redirection seen during an incident, telling AT&T's NXDOMAIN
// redirection (an answer for a non-existent .invalid name) from redirected answers for real
// names, and whether it was also observed before the incident opened.
func (c *collector) dnsFact(opened, end time.Time) string {
	var realIn, invalidIn, realBefore, invalidBefore *hijackObs
	for i := range c.agg.hijacks {
		h := &c.agg.hijacks[i]
		before := h.t.Before(opened)
		if !before && h.t.After(end) {
			continue
		}
		switch {
		case h.dnsReal && before:
			realBefore = h
		case h.dnsReal && realIn == nil:
			realIn = h
		}
		switch {
		case h.dnsInvalid && before:
			invalidBefore = h
		case h.dnsInvalid && invalidIn == nil:
			invalidIn = h
		}
	}
	switch {
	case realIn != nil:
		s := fmt.Sprintf("DNS answers for real names were redirected (hijack detected; service check seq %d)", realIn.seq)
		if realBefore != nil {
			s += fmt.Sprintf("; such redirection was also recorded before the incident opened (service check seq %d)", realBefore.seq)
		}
		return s
	case invalidIn != nil:
		s := fmt.Sprintf("The gateway's DNS answered a query for a non-existent name under the reserved .invalid domain with an address "+
			"(NXDOMAIN redirection; service check seq %d); answers for real names were not redirected in the service checks recorded during "+
			"the incident", invalidIn.seq)
		if invalidBefore != nil {
			s += fmt.Sprintf(". It was also recorded before the incident opened (service check seq %d): a standing behaviour of the resolver, "+
				"not an effect of the incident", invalidBefore.seq)
		}
		return s
	}
	return "DNS answers were redirected (hijack detected, as recorded; the service checks that observed it are not in this bundle)"
}

// seqIndex orders the timeline's samples by seq (ledger order) and finds a sample by seq.
type seqIndex struct {
	order []int          // indices into the timeline, by seq
	pos   map[uint64]int // seq -> position in order (the first sample with that seq)
}

func newSeqIndex(tl []acctSample) *seqIndex {
	ix := &seqIndex{order: make([]int, len(tl)), pos: make(map[uint64]int, len(tl))}
	for i := range tl {
		ix.order[i] = i
	}
	sort.SliceStable(ix.order, func(i, j int) bool { return tl[ix.order[i]].seq < tl[ix.order[j]].seq })
	for k, i := range ix.order {
		if _, ok := ix.pos[tl[i].seq]; !ok {
			ix.pos[tl[i].seq] = k
		}
	}
	return ix
}

// computeIncident recomputes the figures of an incident that is still open at the end of the
// period from the samples of the bundle, as the monitor counts them (internal/monitor incState):
// every cycle of the process that recorded it from its first bad cycle (first_seq), a good cycle
// counted only when a bad one follows, UNKNOWN cycles not at all; the time of ISP_OUTAGE and
// DEGRADED cycles from their cover, bad cycles inside gateway-restart windows as restart time;
// gateway observations from that process's snapshots and service checks. Counting stops when
// close_after_cycles consecutive ONLINE cycles close the incident, when monitoring was interrupted
// (a monitoring gap after a cycle, or a cycle cut short by system sleep: the rules close the
// incident at the end of its last bad cycle's coverage, or at the first cycle of a closing streak
// already under way) or when the process ends. It also returns the cycles it examined.
func (c *collector) computeIncident(inc model.Incident, tl []acctSample, ix *seqIndex, closeAfter int) (*incidentComputed, []*acctSample) {
	a := &c.agg
	start, complete := -1, false
	if k, ok := ix.pos[inc.FirstSeq]; ok && inc.FirstSeq != 0 {
		start, complete = k, true
	}
	if start < 0 { // its first bad cycle is not in this bundle: start at its first tagged sample
		tag, ok := a.incIdx[inc.ID]
		if !ok {
			return nil, nil
		}
		for k, i := range ix.order {
			if tl[i].inc == tag+1 {
				start = k
				break
			}
		}
		if start < 0 {
			return nil, nil
		}
	}
	first := &tl[ix.order[start]]
	run := first.run
	comp := &incidentComputed{Through: c.end.UTC().Format(time.RFC3339Nano), FromSeq: first.seq, ToSeq: first.seq, Complete: complete}
	st := &comp.Stats
	st.ProbeOK, st.ProbeTotal = map[string]int{}, map[string]int{}
	count := func(x *acctSample, bad bool) {
		st.Cycles++
		if bad {
			st.BadCycles++
		}
		for b, name := range a.probeNames {
			if x.probes&(1<<b) != 0 {
				st.ProbeTotal[name]++
				if x.okProbes&(1<<b) != 0 {
					st.ProbeOK[name]++
				}
			}
		}
		if x.linkDown {
			st.LocalLinkDown = true
		}
	}
	var downtime, degraded, restart time.Duration
	var pending, examined []*acctSample
	var lastBad *acctSample
	lastSeq := first.seq
	// interrupted closes the incident the way the monitor does when monitoring is interrupted
	// (internal/monitor tracker.interrupt): at the first good cycle of a closing streak under way,
	// else at the end of the time its last bad cycle covers.
	interrupted := func() {
		var at int64
		switch {
		case len(pending) > 0:
			at = pending[0].t
		case lastBad != nil:
			at = lastBad.t + int64(lastBad.cover)
		default:
			at = first.t
		}
		comp.InterruptedAt = time.Unix(0, at).UTC().Format(time.RFC3339Nano)
	}
cycles:
	for _, i := range ix.order[start:] {
		x := &tl[i]
		if x.run != run {
			break // the process ended: the next one closes the incident at its last observation
		}
		if x.interrupted && x != first {
			interrupted() // cut short by system sleep: a monitoring gap before this cycle
			break
		}
		lastSeq = x.seq
		examined = append(examined, x)
		switch {
		case isBad(x.state):
			for _, g := range pending {
				count(g, false)
			}
			pending = pending[:0]
			count(x, true)
			lastBad = x
			switch {
			case x.inRestart:
				restart += x.cover
			case x.state == model.StateISPOutage:
				downtime += x.cover
			case x.state == model.StateDegraded:
				degraded += x.cover
			}
		case x.state == model.StateOnline:
			pending = append(pending, x)
			if len(pending) >= max(closeAfter, 1) {
				// Closed under the rules: later cycles are not the incident's.
				comp.ClosingAt = time.Unix(0, pending[0].t).UTC().Format(time.RFC3339Nano)
				break cycles
			}
		}
		if x.nextKind == nextSameRun && time.Duration(x.next) > gapLimit(x.fast) {
			interrupted() // a monitoring gap follows this cycle
			break
		}
	}
	comp.ToSeq = lastSeq
	st.DowntimeSec, st.DegradedSec, st.RestartSec = int64(downtime/time.Second), int64(degraded/time.Second), int64(restart/time.Second)
	endNs := c.end.UnixNano()
	closed := comp.ClosingAt != "" || comp.InterruptedAt != "" // records after its last cycle are not the incident's
	for _, s := range a.snaps {
		if s.run != run || s.seq < comp.FromSeq || (closed && s.seq > lastSeq) || (s.t != 0 && s.t >= endNs) {
			continue
		}
		st.GatewayFetches++
		st.GatewayDownSeen = st.GatewayDownSeen || s.bbDown
		st.PONDownSeen = st.PONDownSeen || s.ponDown
		st.OpticalAlarm = st.OpticalAlarm || s.alarm
	}
	for _, h := range a.hijacks {
		if h.run != run || h.seq < comp.FromSeq || (closed && h.seq > lastSeq) || !h.t.Before(c.end) {
			continue
		}
		st.DNSHijackSeen = st.DNSHijackSeen || h.dnsReal || h.dnsInvalid
		st.HTTPHijackSeen = st.HTTPHijackSeen || h.http
	}
	return comp, examined
}

func probeSummary(ok, total map[string]int) string {
	if len(total) == 0 {
		return ""
	}
	names := make([]string, 0, len(total))
	for n := range total {
		names = append(names, n)
	}
	sort.Strings(names)
	parts := make([]string, 0, len(names))
	for _, n := range names {
		parts = append(parts, fmt.Sprintf("%s %d/%d", n, ok[n], total[n]))
	}
	return strings.Join(parts, ", ")
}

// ------------------------------------------------------------------ optical

func hasCode(codes []string, code string) bool {
	for _, c := range codes {
		if c == code {
			return true
		}
	}
	return false
}

func codeSeverity(code string) string {
	switch {
	case code == "GATEWAY_CERT_CHANGED", code == "LEDGER_WRITE_FAILING":
		return "critical"
	case code == "NOTIFICATION_REDIRECT_ON", code == "ANCHOR_UNTRUSTED", code == "EGRESS_NOT_VIA_GATEWAY",
		code == "DISK_SPACE_LOW", code == "CLOCK_OFFSET":
		return "warning"
	case strings.HasSuffix(code, "_ALARM"):
		return "critical"
	case strings.HasSuffix(code, "_WARNING"), strings.HasSuffix(code, "_WARN"):
		return "warning"
	}
	return "info"
}

func (c *collector) sortedOptPoints() []optPoint {
	pts := append([]optPoint(nil), c.agg.optPoints...)
	sort.SliceStable(pts, func(i, j int) bool { return pts[i].t.Before(pts[j].t) })
	return pts
}

func (c *collector) opticalSummary(r *report) {
	a := &c.agg
	o := &r.Optical
	pts := c.sortedOptPoints()
	o.Snapshots = a.optSnapshots
	flags := newCounter()
	var rxs []int64
	var txMin, txMax *int64
	type thr struct{ alarm, warn string }
	var lastThr *thr
	for _, p := range pts {
		if p.rx != nil {
			rxs = append(rxs, *p.rx)
			o.RxLastX10 = ptr(*p.rx)
		}
		if p.tx != nil {
			if txMin == nil || *p.tx < *txMin {
				txMin = ptr(*p.tx)
			}
			if txMax == nil || *p.tx > *txMax {
				txMax = ptr(*p.tx)
			}
		}
		for _, code := range uniqueSorted(p.alarms) {
			flags.add(code)
		}
		if hasCode(p.alarms, codeRxLowAlarm) {
			o.LowAlarmN++
		}
		if hasCode(p.alarms, codeRxLowWarn) {
			o.LowWarnN++
		}
		if p.alarmThr != nil || p.warnThr != nil {
			t := thr{alarm: fmtX10p(p.alarmThr), warn: fmtX10p(p.warnThr)}
			if lastThr == nil || *lastThr != t {
				o.ThresholdsSeen = append(o.ThresholdsSeen, fmt.Sprintf("low alarm %s dBm, low warning %s dBm (from %s)",
					t.alarm, t.warn, p.t.UTC().Format(time.RFC3339)))
				lastThr = &t
			}
			if p.alarmThr != nil {
				o.LowAlarmThrX10 = ptr(*p.alarmThr)
			}
			if p.warnThr != nil {
				o.LowWarnThrX10 = ptr(*p.warnThr)
			}
		}
	}
	if len(o.ThresholdsSeen) <= 1 {
		o.ThresholdsSeen = nil
	}
	o.Readings = len(rxs)
	if len(rxs) > 0 {
		sorted := append([]int64(nil), rxs...)
		sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
		o.RxMinX10, o.RxMaxX10 = ptr(sorted[0]), ptr(sorted[len(sorted)-1])
		o.RxMedianX10 = ptr(sorted[(len(sorted)-1)/2])
	}
	o.TxMinX10, o.TxMaxX10 = txMin, txMax
	o.FlagCounts = flags.list()
	o.Periods = alarmPeriods(pts)
	c.periods = o.Periods
	o.RowUnit, o.Rows = c.opticalRows(pts)
	if lf := a.latestFiber; lf != nil {
		o.LatestSource = &opticalSource{Seq: lf.seq, TS: lf.ts, PageSHA256: lf.pageSHA, PageStored: lf.stored}
		for _, m := range lf.measures {
			o.LatestDMI = append(o.LatestDMI, dmiRow{Name: m.Name, Current: m.CurrentRaw, Unit: m.Unit,
				LowAlarm: m.LowAlarm.Raw, HighAlrm: m.HighAlarm.Raw, LowWarn: m.LowWarn.Raw, HighWarn: m.HighWarn.Raw})
		}
	}
}

func ptr[T any](v T) *T { return &v }

func uniqueSorted(in []string) []string {
	m := map[string]bool{}
	var out []string
	for _, s := range in {
		if s != "" && !m[s] {
			m[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

// alarmPeriods groups consecutive gateway readings that carry the same alarm flag.
func alarmPeriods(pts []optPoint) []alarmPeriod {
	active := map[string]*alarmPeriod{}
	var done []alarmPeriod
	closeRun := func(code, reason string, cleared time.Time) {
		p := active[code]
		p.EndReason = reason
		if !cleared.IsZero() {
			p.ClearedAt = cleared.UTC().Format(time.RFC3339Nano)
		}
		done = append(done, *p)
		delete(active, code)
	}
	activeCodes := func() []string {
		var codes []string
		for code := range active {
			codes = append(codes, code)
		}
		sort.Strings(codes)
		return codes
	}
	for i, p := range pts {
		if i > 0 && p.t.Sub(pts[i-1].t) > alarmGapBreak {
			for _, code := range activeCodes() {
				closeRun(code, "observation gap", time.Time{})
			}
		}
		for _, code := range activeCodes() {
			if !hasCode(p.alarms, code) {
				closeRun(code, "cleared", p.t)
			}
		}
		for _, code := range uniqueSorted(p.alarms) {
			ap := active[code]
			if ap == nil {
				ap = &alarmPeriod{Code: code, Severity: codeSeverity(code), FirstSeen: p.t.UTC().Format(time.RFC3339Nano),
					FirstSeq: p.seq, FirstIndex: i}
				active[code] = ap
			}
			ap.LastSeen, ap.LastSeq, ap.LastIndex = p.t.UTC().Format(time.RFC3339Nano), p.seq, i
			ap.Snapshots++
			if f, ok := parseTS(ap.FirstSeen); ok {
				ap.ObservedS = int64(p.t.Sub(f) / time.Second)
			}
			if p.rx != nil {
				if ap.RxMinX10 == nil || *p.rx < *ap.RxMinX10 {
					ap.RxMinX10 = ptr(*p.rx)
				}
				if ap.RxMaxX10 == nil || *p.rx > *ap.RxMaxX10 {
					ap.RxMaxX10 = ptr(*p.rx)
				}
			}
		}
	}
	for _, code := range activeCodes() {
		closeRun(code, "end of period", time.Time{})
	}
	sort.SliceStable(done, func(i, j int) bool {
		if done[i].FirstIndex != done[j].FirstIndex {
			return done[i].FirstIndex < done[j].FirstIndex
		}
		return done[i].Code < done[j].Code
	})
	if done == nil {
		done = []alarmPeriod{}
	}
	return done
}

// opticalRows aggregates readings per local hour (periods up to 2 days) or per local day.
func (c *collector) opticalRows(pts []optPoint) (string, []opticalRow) {
	unit := "hour"
	if c.end.Sub(c.from) > 48*time.Hour {
		unit = "day"
	}
	rows := []opticalRow{}
	var cur *opticalRow
	var curKey time.Time
	var vals []int64
	var txSum float64 // float: a garbage value must not wrap an integer sum into a plausible mean
	var txN int64
	flush := func() {
		if cur == nil {
			return
		}
		if len(vals) > 0 {
			sort.Slice(vals, func(i, j int) bool { return vals[i] < vals[j] })
			cur.RxMinX10, cur.RxMaxX10 = ptr(vals[0]), ptr(vals[len(vals)-1])
			cur.RxMedX10 = ptr(vals[(len(vals)-1)/2])
		}
		if txN > 0 {
			cur.TxMeanX10 = ptr(int64(math.Round(txSum / float64(txN))))
		}
		rows = append(rows, *cur)
	}
	for _, p := range pts {
		lt := p.t.In(c.loc)
		var key time.Time
		if unit == "hour" {
			key = time.Date(lt.Year(), lt.Month(), lt.Day(), lt.Hour(), 0, 0, 0, c.loc)
		} else {
			key = time.Date(lt.Year(), lt.Month(), lt.Day(), 0, 0, 0, 0, c.loc)
		}
		if cur == nil || !key.Equal(curKey) {
			flush()
			cur, curKey, vals, txSum, txN = &opticalRow{Start: key.UTC().Format(time.RFC3339)}, key, nil, 0, 0
		}
		cur.Readings++
		if p.rx != nil {
			vals = append(vals, *p.rx)
		}
		if p.tx != nil {
			txSum += float64(*p.tx)
			txN++
		}
		if hasCode(p.alarms, codeRxLowAlarm) {
			cur.LowAlarm++
		}
		if hasCode(p.alarms, codeRxLowWarn) {
			cur.LowWarn++
		}
	}
	flush()
	return unit, rows
}

// ------------------------------------------------------------------ service, link, methodology, custody

func (c *collector) serviceAndLink(r *report) {
	a := &c.agg
	r.Service = a.service
	r.Service.DNS = []dnsStat{}
	for _, k := range a.dnsOrder {
		r.Service.DNS = append(r.Service.DNS, *a.dns[k])
	}
	for _, k := range a.invOrd {
		r.Service.InvalidName = append(r.Service.InvalidName, *a.invalid[k])
	}
	r.Service.HTTP = []httpStat{}
	for _, k := range a.httpOrd {
		r.Service.HTTP = append(r.Service.HTTP, *a.http[k])
	}
	r.LocalLink = a.link
	r.LocalLink.Types = a.linkTypes.list()
	if len(a.signals) > 0 {
		s := append([]int(nil), a.signals...)
		sort.Ints(s)
		r.LocalLink.SignalMinPct, r.LocalLink.SignalMaxPct = ptr(s[0]), ptr(s[len(s)-1])
		r.LocalLink.SignalMedPct = ptr(s[(len(s)-1)/2])
	}
	r.Clock = a.clock
	r.Clock.GatewayMaxAbsOffsetMs = a.gwOffsetMax
}

func (c *collector) methodology(r *report) {
	a := &c.agg
	m := &r.Methodology
	m.Probes = []probeStat{}
	for _, n := range a.probeOrder {
		ps := *a.probes[n]
		if ps.Attempts > 0 {
			ps.SuccessPct = floorPct3(uint64(ps.OK), uint64(ps.Attempts))
		}
		if ps.rttN > 0 {
			ps.MeanRTTms = ptr(round3(float64(ps.rttSumUs) / float64(ps.rttN) / 1000))
		}
		m.Probes = append(m.Probes, ps)
	}
	m.CadenceSec = r.Summary.CadenceSec
	if len(a.snapTimes) > 1 {
		var ds []int64
		for i := 1; i < len(a.snapTimes); i++ {
			if d := a.snapTimes[i] - a.snapTimes[i-1]; d > 0 {
				ds = append(ds, d)
			}
		}
		if len(ds) > 0 {
			sort.Slice(ds, func(i, j int) bool { return ds[i] < ds[j] })
			m.SnapshotCadence = round3(time.Duration(ds[len(ds)/2]).Seconds())
		}
	}
	m.RulesVersions = []string{}
	for v := range a.rules {
		m.RulesVersions = append(m.RulesVersions, v)
	}
	sort.Strings(m.RulesVersions)
	m.RulesDescribed = rulesDescribed
	for _, v := range m.RulesVersions {
		m.RulesMismatch = m.RulesMismatch || v != rulesDescribed
	}
	m.RulesNotes = c.rulesNotes()
	m.Providers = []string{}
	for p := range a.providers {
		m.Providers = append(m.Providers, p)
	}
	sort.Strings(m.Providers)
	if len(m.Providers) == 0 {
		m.Providers = providersOf(m.Thresholds.InternetTargets)
	}
	m.SamplesInputs = a.samplesInputs
	m.Software = a.software
	if m.Software == nil {
		m.Software = []softwareSeen{}
	}
	m.Heartbeats, m.Traceroutes, m.StateChanges = a.heartbeats, a.traceroutes, a.stateChanges
}

// custodyLog merges the custody records of the bundle with the computed monitoring gaps of the
// period, in time order.
func (c *collector) custodyLog(gaps []gapEntry) []custodyEntry {
	out := append([]custodyEntry{}, c.agg.custody...)
	for _, g := range gaps {
		out = append(out, custodyEntry{TS: g.From, Type: "gap", InPeriod: true,
			Summary: fmt.Sprintf("No samples were recorded from %s to %s (%s): %s.",
				fmtUTC(g.From), fmtUTC(g.To), fmtDur(g.Seconds), g.Explanation)})
	}
	sort.SliceStable(out, func(i, j int) bool {
		ti, oki := parseTS(out[i].TS)
		tj, okj := parseTS(out[j].TS)
		if oki != okj {
			return oki
		}
		if oki && !ti.Equal(tj) {
			return ti.Before(tj)
		}
		return seqOf(out[i].Seq) < seqOf(out[j].Seq)
	})
	return out
}

func seqOf(p *uint64) uint64 {
	if p == nil {
		return 0
	}
	return *p
}
