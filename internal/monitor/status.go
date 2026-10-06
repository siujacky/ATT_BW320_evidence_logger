package monitor

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	"attmonitor/internal/model"
)

// Status returns the live view served at /api/status.
func (m *Monitor) Status() model.Status {
	now := m.now()
	// Ledger accessors first: never call into the ledger while holding mu.
	head := m.led.Head()
	runID, fp, genesis := m.runID, m.led.Fingerprint(), m.led.GenesisTS()
	probes := m.displaySpecs()
	pinned, pending := m.certPins()
	hasCode := m.hasAccessCode()
	enforceSyslog, syslogLevel := m.syslogConfig()
	var mongo *model.MongoStatus
	if f := m.opts.MongoStatus; f != nil {
		ms := f()
		mongo = &ms
	}
	// The syslog receiver and store have locks of their own: never called while holding mu.
	var (
		rxAddr string
		rxErr  error
		usage  *model.SyslogUsage
	)
	if m.syslogOn {
		rxAddr, rxErr = m.opts.Syslog.Listening()
	}
	if st := m.opts.SyslogStore; st != nil {
		u := st.Usage()
		usage = &u
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	s := model.Status{
		Probes: probes,
		Now:    fmtTS(now),
		Mongo:  mongo,
		Monitor: model.MonitorInfo{
			Version: m.opts.Software.Version,
			RunID:   runID,
			Cycles:  m.st.cycles,
			Mode:    m.opts.Mode,
			Listen:  m.opts.Listen,
			Rules:   RulesVersion,
		},
		Verdict: m.st.lastVerdict,
	}
	if !m.st.started.IsZero() {
		s.Monitor.Started = fmtTS(m.st.started)
		s.Monitor.UptimeSec = int64(now.Sub(m.st.started) / time.Second)
	}
	stale := false
	switch {
	case s.Verdict.State == "":
		s.Verdict = model.Verdict{State: model.StateUnknown, Attribution: model.AttrUndetermined,
			Reasons: []string{"no monitoring cycle has completed yet"}, Rules: RulesVersion}
	case m.st.lastSample != nil && !m.st.lastSampleRecAt.IsZero() && now.Sub(m.st.lastSampleRecAt) > gapLimit(m.set.fast):
		// No cycle has been recorded for longer than a monitoring gap (the ledger refuses
		// records, the cycle worker is stuck, the computer just resumed): the last verdict no
		// longer describes the present.
		stale = true
		s.Verdict = staleVerdict(m.st.lastVerdict, m.st.lastSampleRecAt, now, m.st.appendFails > 0)
	}
	if !m.st.since.IsZero() && !stale {
		s.Since = fmtTS(m.st.since)
	}
	if o := m.st.tracker.open; o != nil {
		inc := o.payload(now, true)
		s.ActiveIncident = &inc
	}
	if v := m.st.lastSample; v != nil {
		cp := *v
		s.LastSample = &cp
	}
	if g := m.st.lastGood; g != nil {
		cp := *g.Snap
		s.Gateway, s.GatewayAt = &cp, fmtTS(g.At)
	}
	if n := m.st.notif; n != nil {
		cp := *n
		s.Notification = &cp
	}
	if v := m.st.lastService; v != nil {
		cp := *v
		s.LastService = &cp
	}
	if l := m.st.lastLink; l != nil {
		cp := *l
		s.LocalLink = &cp
	}
	if c := m.st.lastClock; c != nil {
		cp := *c
		s.Clock = &cp
	}
	// Alarm flags come from the latest snapshot that read fiberstat: a later snapshot whose
	// fiberstat fetch failed says nothing about them.
	s.Conditions = buildConditions(m.st.lastFiber, m.st.alarms, m.st.notif, m.st.started)
	if m.st.appendFails > 0 {
		s.Conditions = append(s.Conditions, ledgerFailingCondition(m.st.appendFailSince, m.st.appendFails, m.st.appendFailErr, m.st.appendBroken))
	}
	if c, ok := diskCondition(m.st.disk, m.opts.DataDir); ok {
		s.Conditions = append(s.Conditions, c)
	}
	if c, ok := egressCondition(linkEgress(m.st.lastLinkRec), m.st.egressSince, m.st.lastLinkRecSeq); ok {
		s.Conditions = append(s.Conditions, c)
	}
	if c, ok := clockOffsetCondition(m.st.lastClockRef); ok {
		s.Conditions = append(s.Conditions, c)
	}
	// The gateway certificate pin; while a changed certificate awaits confirmation, since when
	// and which cert_changed record reported it (the condition names the same record).
	certSince, certSeq := m.pendingCertRecordLocked(pending)
	if pending != "" {
		s.Conditions = append(s.Conditions, certChangedCondition(pending, certSince, certSeq))
	}
	if pinned != "" || pending != "" {
		s.GatewayCert = &model.GatewayCertState{Pinned: pinned, Pending: pending, Seq: certSeq}
		if !certSince.IsZero() {
			s.GatewayCert.Since = fmtTS(certSince)
		}
	}
	if anchorsUntrusted(m.st.lastAnchor, m.st.lastUntrusted) {
		s.Conditions = append(s.Conditions, anchorUntrustedCondition(m.st.lastUntrusted, m.st.untrustedSince))
	}
	s.Syslog = m.syslogStatusLocked(rxAddr, rxErr, usage, hasCode, enforceSyslog, syslogLevel)
	s.Conditions = append(s.Conditions, m.syslogConditionsLocked(rxAddr, rxErr, now)...)
	switch {
	case !hasCode:
		s.Conditions = append(s.Conditions, noAccessCodeCondition(""))
	case m.st.notifNoCode != "":
		s.Conditions = append(s.Conditions, noAccessCodeCondition(m.st.notifNoCode))
	}

	s.Ledger = model.LedgerStatus{
		HeadSeq:         head.Seq,
		HeadHash:        head.Hash,
		HeadTS:          head.TS,
		Fingerprint:     fp,
		GenesisTS:       genesis,
		DataDir:         m.opts.DataDir,
		UnanchoredCount: head.Seq + 1,
	}
	// Only a trusted anchor (Verified && ChainOK) is the last anchor: an anchor whose authority
	// could not be verified is recorded but proves nothing (ANCHOR_UNTRUSTED above).
	if a := m.st.lastAnchor; a != nil && anchorTrusted(a.Anchor) {
		s.Ledger.LastAnchorTime = a.Anchor.GenTime
		s.Ledger.LastAnchorTSA = a.Anchor.TSAName
		if s.Ledger.LastAnchorTSA == "" {
			s.Ledger.LastAnchorTSA = a.Anchor.TSAURL
		}
		// The record the time-stamp covers (the dashboard prints "covers #N"); the anchor
		// record itself (a.Seq) is not covered by any time-stamp yet.
		s.Ledger.LastAnchorSeq = a.Anchor.HeadSeq
		s.Ledger.UnanchoredCount = 0
		if head.Seq > a.Anchor.HeadSeq {
			s.Ledger.UnanchoredCount = head.Seq - a.Anchor.HeadSeq
		}
	}
	if v := m.st.lastVerify; v != nil {
		cp := *v
		s.Ledger.LastVerify = &cp
	}

	spans := m.incidentSpansLocked()
	restarts := m.st.points.restartIntervals(m.restartBootsLocked(), gapLimit(m.set.fast))
	s.Stats = []model.WindowStats{
		m.st.points.windowStats("24h", 24*time.Hour, now, m.set.fast, spans, restarts),
		m.st.points.windowStats("7d", 7*24*time.Hour, now, m.set.fast, spans, restarts),
	}
	return s
}

// incidentSpansLocked lists every incident (recorded, closing, open) as statistics spans,
// without copying evidence lists. Caller holds mu.
func (m *Monitor) incidentSpansLocked() []incSpan {
	live := map[string]incSpan{}
	for _, st := range m.st.closing {
		live[st.inc.ID] = incSpan{opened: st.opened, closed: st.closed, state: st.inc.State, attribution: st.attribution()}
	}
	if o := m.st.tracker.open; o != nil {
		live[o.inc.ID] = incSpan{opened: o.opened, open: true, state: o.inc.State, attribution: o.attribution()}
	}
	out := make([]incSpan, 0, len(m.st.incidents)+len(live))
	for id, inc := range m.st.incidents {
		if _, ok := live[id]; ok {
			continue
		}
		if sp, ok := spanOf(inc); ok {
			out = append(out, sp)
		}
	}
	for _, sp := range live {
		out = append(out, sp)
	}
	return out
}

// displaySpecs lists the configured probes with their runtime targets where known (the ISP
// hop keeps an empty target until the gateway has reported it).
func (m *Monitor) displaySpecs() []model.ProbeSpec {
	m.mu.Lock()
	hop := m.st.ispHop
	m.mu.Unlock()
	resolved := map[string]string{}
	for _, sp := range m.probeSpecs() {
		resolved[sp.Name] = sp.Target
	}
	out := slices.Clone(m.set.targets)
	for i := range out {
		if t, ok := resolved[out[i].Name]; ok {
			out[i].Target = t
		} else if out[i].Role == model.RoleISPHop && out[i].Target == "" {
			out[i].Target = hop
		}
	}
	return out
}

// Series returns chart data for "1h", "6h", "24h" or "7d".
func (m *Monitor) Series(rangeName string) (model.Series, error) {
	now := m.now()
	specs := m.displaySpecs()
	m.mu.Lock()
	defer m.mu.Unlock()
	var latest *model.GatewaySnapshot // thresholds: from the latest fiberstat reading
	if g := m.st.lastFiber; g != nil {
		latest = g.Snap
	}
	return m.st.points.buildSeries(rangeName, now, specs, latest)
}

// incidentViewsLocked returns every incident known: the recorded payloads overlaid with the
// live view of the open incident and of incidents whose close record is pending. Deep copies.
func (m *Monitor) incidentViewsLocked(now time.Time) []model.Incident {
	views := make(map[string]model.Incident, len(m.st.incidents)+2)
	for id, inc := range m.st.incidents {
		views[id] = cloneIncident(inc)
	}
	for _, st := range m.st.closing {
		views[st.inc.ID] = st.payload(now, true)
	}
	if o := m.st.tracker.open; o != nil {
		views[o.inc.ID] = o.payload(now, true)
	}
	out := make([]model.Incident, 0, len(views))
	for _, inc := range views {
		out = append(out, inc)
	}
	return out
}

// Incidents returns incidents overlapping [from, to), newest first. A zero from or to leaves
// that side unbounded.
func (m *Monitor) Incidents(from, to time.Time) []model.Incident {
	now := m.now()
	var views []model.Incident
	m.locked(func() { views = m.incidentViewsLocked(now) })
	out := []model.Incident{}
	for _, inc := range views {
		opened, ok := parseTS(inc.Opened)
		if !ok {
			continue
		}
		if !to.IsZero() && !opened.Before(to) {
			continue
		}
		if !from.IsZero() && !inc.Open {
			if closed, ok := parseTS(inc.Closed); ok && !closed.After(from) {
				continue
			}
		}
		out = append(out, inc)
	}
	slices.SortFunc(out, func(a, b model.Incident) int {
		ta, _ := parseTS(a.Opened)
		tb, _ := parseTS(b.Opened)
		if c := tb.Compare(ta); c != 0 {
			return c
		}
		return strings.Compare(b.ID, a.ID)
	})
	return out
}

// Incident returns one incident by id.
func (m *Monitor) Incident(id string) (model.Incident, bool) {
	now := m.now()
	m.mu.Lock()
	defer m.mu.Unlock()
	if st := m.incidentByIDLocked(id); st != nil {
		return st.payload(now, true), true
	}
	if inc, ok := m.st.incidents[id]; ok {
		return cloneIncident(inc), true
	}
	return model.Incident{}, false
}

// Verify runs the configured Verifier and remembers the outcome for Status (ledger
// "last verify"). Wire the monitor as the web server's Verifier to keep the status current.
func (m *Monitor) Verify(ctx context.Context) (model.VerifyReport, error) {
	if m.opts.Verifier == nil {
		return model.VerifyReport{}, errors.New("monitor: no verifier configured")
	}
	rep, err := m.opts.Verifier.Verify(ctx)
	if err != nil {
		return rep, err
	}
	sum := model.VerifySummary{At: rep.At, OK: rep.OK, Records: rep.Records, Failures: rep.FailuresTotal}
	if sum.At == "" {
		sum.At = fmtTS(m.now())
	}
	if sum.Failures == 0 {
		sum.Failures = len(rep.Failures)
	}
	m.mu.Lock()
	m.st.lastVerify = &sum
	m.mu.Unlock()
	return rep, nil
}
