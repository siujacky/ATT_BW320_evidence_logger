package monitor

import (
	"context"
	"fmt"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"attmonitor/internal/model"
)

// parallel runs fns concurrently and waits for all of them; a panic in one is logged.
func (m *Monitor) parallel(what string, fns []func()) {
	var wg sync.WaitGroup
	for _, f := range fns {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					m.log.Error("check panic recovered", "check", what, "panic", fmt.Sprint(r))
				}
			}()
			f()
		}()
	}
	wg.Wait()
}

// ---------------------------------------------------------------------------- service checks

func (m *Monitor) serviceLoop(ctx context.Context) {
	next := time.Now()
	for {
		if !sleepUntil(ctx, next, m.kService.ch) {
			return
		}
		m.kService.take()
		began := time.Now()
		m.safely("service", func() { m.runServiceCheck(ctx) })
		interval := m.set.service
		if m.incidentOpen() {
			interval = m.set.serviceIncident
		}
		next = began.Add(interval)
	}
}

type dnsJob struct{ server, role, name string }

// serviceJobs lists the DNS queries of docs/DESIGN.md §8: the test name via the gateway, the
// ISP resolver (when known) and each public resolver, plus a random "<16 hex>.invalid" query
// via the gateway that must not resolve (wildcard hijack detector).
func (m *Monitor) serviceJobs(ispDNS string) []dnsJob {
	var jobs []dnsJob
	jobs = append(jobs, dnsJob{m.set.gwHost, "gateway", m.set.dnsName})
	if ispDNS != "" {
		jobs = append(jobs, dnsJob{ispDNS, "isp", m.set.dnsName})
	}
	for _, p := range m.set.publicResolvers {
		jobs = append(jobs, dnsJob{p, "public", m.set.dnsName})
	}
	jobs = append(jobs, dnsJob{m.set.gwHost, "gateway", randomHex(8) + ".invalid"})
	return jobs
}

func (m *Monitor) runServiceCheck(ctx context.Context) {
	start := m.now()
	m.mu.Lock()
	ispDNS := m.st.ispDNS
	m.mu.Unlock()
	jobs := m.serviceJobs(ispDNS)
	dnsTimeout := m.set.probeTimeout
	httpTimeout := max(m.set.probeTimeout, 5*time.Second)

	sc := model.ServiceCheck{HTTP: make([]model.HTTPResult, len(m.set.httpChecks))}
	dns := make([][]model.DNSResult, len(jobs)) // per job: the query, and its retry if any
	var fns []func()
	for i, j := range jobs {
		dns[i] = []model.DNSResult{{Server: j.server, ServerRole: j.role, Name: j.name, QType: "A", Err: "check did not complete"}}
		query := func() model.DNSResult {
			r := m.prober.DNS(ctx, j.server, j.name, dnsTimeout)
			r.ServerRole = j.role
			if r.Name == "" {
				r.Name = j.name
			}
			if r.Server == "" {
				r.Server = j.server
			}
			if r.QType == "" {
				r.QType = "A"
			}
			if hij, why := detectDNSHijack(j.name, r.Answers, m.set.gwHost); hij && !r.Hijacked {
				r.Hijacked, r.HijackWhy = true, why
			}
			return r
		}
		fns = append(fns, func() {
			r := query()
			dns[i] = []model.DNSResult{r}
			// A resolution query that got no valid response (lost or late datagram, network
			// error, SERVFAIL) is asked once more, as any DNS client would, before the check
			// records the resolver as failing (DESIGN §9 rule 3). Both answers are recorded.
			if isInvalidName(j.name) || !dnsRetryable(r) || !sleepCtx(ctx, m.dnsRetryPause) {
				return
			}
			dns[i] = append(dns[i], query())
		})
	}
	for i, c := range m.set.httpChecks {
		sc.HTTP[i] = model.HTTPResult{Name: c.Name, URL: c.URL, Err: "check did not complete"}
		fns = append(fns, func() {
			r := m.prober.HTTP(ctx, c.Name, c.URL, c.ExpectStatus, c.ExpectBody, httpTimeout)
			if r.Name == "" {
				r.Name = c.Name
			}
			if r.URL == "" {
				r.URL = c.URL
			}
			if hij, why := detectHTTPHijack(r, m.set.gwHost); hij && !r.Hijacked {
				r.Hijacked, r.HijackWhy = true, why
			}
			sc.HTTP[i] = r
		})
	}
	m.parallel("service", fns)
	if ctx.Err() != nil {
		return
	}
	dnsHijack, httpHijack := false, false
	var problems []string
	for _, rs := range dns {
		sc.DNS = append(sc.DNS, rs...)
		failed := false
		for _, r := range rs {
			dnsHijack = dnsHijack || r.Hijacked
			failed = failed || r.Hijacked
		}
		if last := rs[len(rs)-1]; failed || (!isInvalidName(last.Name) && !dnsAnswered(last)) {
			problems = append(problems, "dns "+last.ServerRole)
		}
	}
	for _, r := range sc.HTTP {
		httpHijack = httpHijack || r.Hijacked
		if !r.OK {
			problems = append(problems, "http "+r.Name)
		}
	}
	note := "all checks passed"
	if len(problems) > 0 {
		note = "failed: " + strings.Join(problems, ", ")
	}
	m.appendApply(model.TypeServiceCheck, sc, nil, func(ref model.Ref) {
		m.st.prevService, m.st.prevServiceAt, m.st.prevServiceSeq = m.st.lastService, m.st.lastServiceAt, m.st.lastServiceSeq
		m.st.lastService, m.st.lastServiceAt, m.st.lastServiceSeq = &sc, start, ref.Seq
		for _, st := range m.evidenceTargetsLocked(nil) {
			st.inc.Stats.DNSHijackSeen = st.inc.Stats.DNSHijackSeen || dnsHijack
			st.inc.Stats.HTTPHijackSeen = st.inc.Stats.HTTPHijackSeen || httpHijack
			st.ev.add(model.EvidenceRef{Seq: ref.Seq, Type: model.TypeServiceCheck, Note: note})
		}
	})
}

// dnsRetryable: the query got no valid response or a server failure - a lost or late datagram
// or a transient error, which one retry tells apart from a failing resolver. A definite answer
// (including a hijacked one or NXDOMAIN) is not asked again.
func dnsRetryable(r model.DNSResult) bool {
	return r.Err != "" || !r.OK || strings.EqualFold(strings.TrimSpace(r.RCode), "SERVFAIL")
}

// sleepCtx waits d or until ctx is done; it reports whether the wait completed.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// detectDNSHijack implements the hijack rule of docs/DESIGN.md §8: any answer for the
// random ".invalid" name, or an answer for a public name that is the gateway's address or a
// private, loopback, link-local or unspecified address.
func detectDNSHijack(name string, answers []string, gatewayIP string) (bool, string) {
	if isInvalidName(name) {
		if len(answers) > 0 {
			return true, fmt.Sprintf("resolver answered %s for the non-existent name %s", strings.Join(answers, ", "), name)
		}
		return false, ""
	}
	for _, a := range answers {
		ip, err := netip.ParseAddr(strings.TrimSpace(a))
		if err != nil {
			continue // CNAME or other non-address answer
		}
		ip = ip.Unmap()
		switch {
		case gatewayIP != "" && ip.String() == gatewayIP:
			return true, fmt.Sprintf("answer %s for %s is the gateway's own address", a, name)
		case ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified():
			return true, fmt.Sprintf("answer %s for public name %s is a private, loopback or link-local address", a, name)
		}
	}
	return false, ""
}

// detectHTTPHijack: a response or redirect from the gateway (or another private address)
// to a request for a public URL is the gateway's outage redirect (docs/DESIGN.md §8).
func detectHTTPHijack(r model.HTTPResult, gatewayIP string) (bool, string) {
	if h := hostOnly(r.RemoteAddr); gatewayIP != "" && h == gatewayIP {
		return true, "the response came from the gateway itself (" + h + ")"
	}
	if r.Location == "" {
		return false, ""
	}
	u, err := url.Parse(r.Location)
	if err != nil {
		return false, ""
	}
	h := u.Hostname()
	if gatewayIP != "" && h == gatewayIP {
		return true, "redirected to the gateway: " + truncate(r.Location, 200)
	}
	if ip, err := netip.ParseAddr(h); err == nil {
		ip = ip.Unmap()
		if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
			return true, "redirected to a private address: " + truncate(r.Location, 200)
		}
	}
	return false, ""
}

// ---------------------------------------------------------------------------- local link

func (m *Monitor) localLinkLoop(ctx context.Context) {
	next := time.Now()
	for {
		if !sleepUntil(ctx, next, m.kLink.ch) {
			return
		}
		force := hasReason(m.kLink.take(), "incident")
		began := time.Now()
		m.safely("locallink", func() { m.checkLocalLink(ctx, force) })
		next = began.Add(m.set.linkInterval)
	}
}

// linkChanged: type/state/SSID/BSSID/channel/interface changed, the reading started or
// stopped failing, or the signal moved by 15 points or more.
func linkChanged(a, b *model.LocalLink) bool {
	if a.Type != b.Type || a.State != b.State || a.SSID != b.SSID || !strings.EqualFold(a.BSSID, b.BSSID) ||
		a.Channel != b.Channel || a.Interface != b.Interface || (a.Err == "") != (b.Err == "") {
		return true
	}
	d := a.SignalPct - b.SignalPct
	if d < 0 {
		d = -d
	}
	return d >= 15
}

// checkLocalLink reads the local link every LocalLinkInterval and records it at start, on a
// change, every LocalLinkRecordEvery and when forced (incident open). The classifier uses only
// the recorded link, and only while it is fresh (DESIGN §9: ≤ 150 s), so while it matters - an
// incident is open, or the Wi-Fi link is down - an unchanged reading is recorded again before
// the latest record goes stale.
func (m *Monitor) checkLocalLink(ctx context.Context, force bool) {
	at := m.now()
	lctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	link, raw, err := m.prober.LocalLink(lctx, m.set.gwHost)
	cancel()
	if ctx.Err() != nil {
		return
	}
	if err != nil && link.Err == "" {
		link.Err = errText(err)
	}
	if link.Type == "" {
		link.Type = "unknown"
	}
	// The route this computer's internet probes take (DESIGN §9 egress, rules 2026.10-4),
	// recorded with the reading as its Egress member.
	if m.route != nil {
		m.mu.Lock()
		hop, dns := m.st.ispHop, m.st.ispDNS
		m.mu.Unlock()
		link.Egress = checkEgress(m.route, m.set.gwHost, m.egressDests(hop, dns))
	}
	egress := link.Egress
	view := link
	var (
		prev     *model.LocalLink
		prevAt   time.Time
		incident bool
		movedIP  string // this computer's address toward the gateway changed from it
		foundIP  bool   // the gateway's Syslog page waits for this computer's address, known now
	)
	m.locked(func() {
		prev, prevAt = m.st.lastLinkRec, m.st.lastLinkRecAt
		m.st.lastLink, m.st.lastLinkAt = &view, at
		m.trafficLinkLocked(at, &view)
		incident = m.st.tracker.open != nil
		if wifiDown(&view) {
			for _, st := range m.evidenceTargetsLocked(nil) {
				st.inc.Stats.LocalLinkDown = true
			}
		}
		if ip := view.LocalIP; ip != "" {
			if m.st.localIP != "" && ip != m.st.localIP {
				movedIP = m.st.localIP
			}
			foundIP = m.st.syslogNeedAddr && usableIPv4(ip) != ""
			if foundIP {
				m.st.syslogNeedAddr = false
			}
			m.st.localIP = ip
		}
	})
	switch {
	case movedIP != "":
		// The gateway's Syslog setting names the address it sends to: it is read (and with
		// gateway.enforce_syslog set) again soon.
		m.log.Info("this computer's address toward the gateway changed", "from", movedIP, "to", view.LocalIP)
		m.kNotif.kick(kickAddressChange)
	case foundIP:
		// The latest settings check could not set the gateway's Syslog page without it.
		m.log.Info("this computer's address toward the gateway is known now", "addr", view.LocalIP)
		m.kNotif.kick(kickAddressChange)
	}
	fresh := m.set.incident.SnapshotFreshness.Duration
	refresh := (incident || wifiDown(&link) || bypassRoute(egress) != nil) && at.Sub(prevAt) >= max(fresh-m.set.linkInterval, fresh/2)
	if !force && !refresh && prev != nil && !linkChanged(prev, &link) && !egressChanged(prev.Egress, egress) && at.Sub(prevAt) < m.set.linkRecordEvery {
		return
	}
	var blobs []string
	if len(raw) > 0 {
		if id, err := m.putBlob(raw); err == nil {
			link.RawSHA256 = id
			blobs = append(blobs, id)
		}
	}
	rec := link
	m.appendApply(model.TypeLocalLink, rec, blobs, func(ref model.Ref) {
		m.st.lastLinkRec, m.st.lastLinkRecAt, m.st.lastLinkRecSeq = &rec, at, ref.Seq
		switch {
		case bypassRoute(egress) == nil:
			m.st.egressSince = time.Time{}
		case m.st.egressSince.IsZero():
			m.st.egressSince = at
		}
		if m.st.lastLinkAt.Equal(at) {
			m.st.lastLink = &rec
		}
		refs := []model.EvidenceRef{{Seq: ref.Seq, Type: model.TypeLocalLink, Note: rec.Type + " " + rec.State}}
		if rec.RawSHA256 != "" {
			refs = append(refs, model.EvidenceRef{Seq: ref.Seq, Type: model.TypeLocalLink, Blob: rec.RawSHA256, Note: "raw adapter output"})
		}
		m.addEvidenceLocked(nil, model.TypeLocalLink, ref.Seq, refs...)
	})
}

// ---------------------------------------------------------------------------- clock

// kickClockJump asks the clock worker to measure again after a step of this computer's clock.
const kickClockJump = "clock_jump"

// clockLoop checks the clock at the start, every ClockInterval and when kicked: at once after a
// resume, and after a step of this computer's clock (clock_jump, which changed its offset to the
// time servers, so CLOCK_OFFSET would otherwise describe the clock before the step until the
// next periodic check) - but then not sooner than clockRecheckMin after the previous check, so a
// clock that keeps stepping cannot flood the time servers.
func (m *Monitor) clockLoop(ctx context.Context) {
	next := time.Now()
	var last time.Time // when the latest check began
	for {
		if !sleepUntil(ctx, next, m.kClock.ch) {
			return
		}
		if onlyReason(m.kClock.take(), kickClockJump) && !last.IsZero() {
			if early := last.Add(m.clockRecheckMin); time.Now().Before(early) {
				if early.Before(next) {
					next = early
				}
				continue
			}
		}
		began := time.Now()
		last = began
		m.safely("clock", func() { m.clockCheck(ctx) })
		next = began.Add(m.set.clockInterval)
	}
}

// clockCheck measures the local clock against the SNTP servers and records the gateway's own
// clock offset from the latest fresh snapshot.
func (m *Monitor) clockCheck(ctx context.Context) {
	timeout := max(m.set.probeTimeout, 3*time.Second)
	results := make([]model.ClockResult, len(m.set.clockServers))
	var fns []func()
	for i, s := range m.set.clockServers {
		results[i] = model.ClockResult{Server: s, Err: "check did not complete"}
		fns = append(fns, func() {
			r := m.prober.SNTP(ctx, s, timeout)
			if r.Server == "" {
				r.Server = s
			}
			results[i] = r
		})
	}
	m.parallel("clock", fns)
	if ctx.Err() != nil {
		return
	}
	cc := model.ClockCheck{Results: results}
	now := m.now()
	m.mu.Lock()
	if g := m.st.lastGood; g != nil && now.Sub(g.At) <= m.set.incident.SnapshotFreshness.Duration && g.Snap.Derived.GatewayClockOffsetMs != nil {
		v := *g.Snap.Derived.GatewayClockOffsetMs
		cc.GatewayOffsetMs = &v
	}
	m.mu.Unlock()
	if len(cc.Results) == 0 && cc.GatewayOffsetMs == nil {
		return
	}
	var cur, prevRun *clockRef
	var started time.Time
	_, err := m.appendApply(model.TypeClockCheck, cc, nil, func(ref model.Ref) {
		m.st.lastClock = &cc
		// A check that a time server answered becomes the clock reference (CLOCK_OFFSET, the
		// comparison across runs); one that none answered measured nothing and leaves it.
		if cur = nextClockRef(m.st.lastClockRef, ref.Seq, ref.TS, cc); cur != nil {
			prevRun, started = m.st.prevRunClock, m.st.started
			m.st.prevRunClock = nil
			m.st.lastClockRef = cur
		}
	})
	if err != nil || cur == nil || prevRun == nil || now.Sub(started) > runClockCompareWindow {
		return
	}
	m.recordRunClockStep(*prevRun, *cur)
}

// runClockCompareWindow: this run's first answered clock check is compared with the previous
// run's last one only when it is taken this soon after the start (later, a step of the clock
// during this run is a cycle clock_jump instead).
const runClockCompareWindow = 10 * time.Minute

// runClockJump is a clock_jump found between two runs of the monitor: model.ClockJump with what
// it was measured from. Between the previous run's last clock check and this run's first, this
// computer's clock moved against the time servers by JumpMs: times recorded across the restart
// (monitor_start's gap_seconds, boot-time estimates) include that step. WallDeltaMs is the time
// between the two checks by this computer's clock, MonoDeltaMs the same span by the time
// servers (there is no monotonic clock across runs).
type runClockJump struct {
	model.ClockJump
	BetweenRuns  bool   `json:"between_runs"`
	PrevCheckSeq uint64 `json:"prev_clock_check_seq"`
	CheckSeq     uint64 `json:"clock_check_seq"`
	Detail       string `json:"detail"`
}

// recordRunClockStep appends a clock_jump when this computer's clock moved against the time
// servers by more than clockJumpThreshold between the previous run's last clock check and this
// run's first (DESIGN §7: steps are recorded, not left to read as gaps).
func (m *Monitor) recordRunClockStep(prev, cur clockRef) {
	pt, ok1 := parseTS(prev.TS)
	ct, ok2 := parseTS(cur.TS)
	step := time.Duration(prev.OffsetMs-cur.OffsetMs) * time.Millisecond // + : the clock moved ahead
	if !ok1 || !ok2 || absDur(step) <= clockJumpThreshold {
		return
	}
	wall := ct.Sub(pt)
	sign := ""
	if step > 0 {
		sign = "+"
	}
	j := runClockJump{
		ClockJump:    model.ClockJump{WallDeltaMs: wall.Milliseconds(), MonoDeltaMs: (wall - step).Milliseconds(), JumpMs: step.Milliseconds()},
		BetweenRuns:  true,
		PrevCheckSeq: prev.Seq,
		CheckSeq:     cur.Seq,
		Detail: fmt.Sprintf("between the clock check of the previous run (#%d, offset to the time servers %d ms) and this run's first (#%d, offset %d ms) this computer's clock moved %s%s against the time servers; times recorded across the restart (for example monitor_start's gap_seconds) include that step",
			prev.Seq, prev.OffsetMs, cur.Seq, cur.OffsetMs, sign, step.Round(time.Millisecond)),
	}
	if _, err := m.appendApply(model.TypeClockJump, j, nil, nil); err == nil {
		m.log.Warn("this computer's clock was stepped while the monitor was not running", "step", step)
	}
}

// ---------------------------------------------------------------------------- traceroutes

func (m *Monitor) requestTraceroute(trigger, incident string) {
	select {
	case m.traceReqs <- traceReq{trigger: trigger, incident: incident}:
	default:
		m.log.Warn("traceroute request dropped: queue full", "trigger", trigger)
	}
}

// tracerouteLoop runs requested traceroutes (incident open) and, while an incident is open,
// one every TracerouteInterval.
func (m *Monitor) tracerouteLoop(ctx context.Context) {
	var last time.Time // start of the periodic schedule of the open incident
	lastIncident := ""
	for {
		openID := m.openIncidentID()
		var periodic, recheck <-chan time.Time
		var timer *time.Timer
		if openID != "" {
			if openID != lastIncident {
				// New incident: its open traceroute arrives as a request; periodic ones follow.
				lastIncident, last = openID, time.Now()
			}
			timer = time.NewTimer(max(0, time.Until(last.Add(m.set.traceInterval))))
			periodic = timer.C
		} else {
			// Re-check regularly whether an incident has opened.
			timer = time.NewTimer(m.set.fast)
			recheck = timer.C
		}
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case req := <-m.traceReqs:
			timer.Stop()
			if req.incident != "" && req.incident == openID {
				last = time.Now()
			}
			m.safely("traceroute", func() { m.runTraceroutes(ctx, req.trigger, req.incident, nil) })
		case <-periodic:
			// The incident may have closed while this loop slept: a traceroute taken now is
			// not evidence of it (and must not be recorded as such).
			if m.openIncidentID() != openID {
				continue
			}
			last = time.Now()
			m.safely("traceroute", func() { m.runTraceroutes(ctx, "incident_periodic", openID, nil) })
		case <-recheck:
		}
	}
}

// openIncidentID returns the id of the open incident ("" if none).
func (m *Monitor) openIncidentID() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if o := m.st.tracker.open; o != nil {
		return o.inc.ID
	}
	return ""
}

func (m *Monitor) incidentByIDLocked(id string) *incState {
	if o := m.st.tracker.open; o != nil && o.inc.ID == id {
		return o
	}
	for _, c := range m.st.closing {
		if c.inc.ID == id {
			return c
		}
	}
	return nil
}

// runTraceroutes traces every configured target concurrently and records each result.
func (m *Monitor) runTraceroutes(ctx context.Context, trigger, incident string, target *incState) {
	targets := m.set.traceTargets
	if len(targets) == 0 {
		return
	}
	results := make([]model.Traceroute, len(targets))
	done := make([]bool, len(targets))
	var fns []func()
	for i, t := range targets {
		fns = append(fns, func() {
			results[i] = m.prober.Traceroute(ctx, t, m.set.traceMaxHops, time.Second)
			done[i] = true
		})
	}
	m.parallel("traceroute", fns)
	if ctx.Err() != nil {
		return
	}
	for i, tr := range results {
		if !done[i] {
			continue
		}
		if tr.Target == "" {
			tr.Target = targets[i]
		}
		tr.Trigger, tr.Incident = trigger, incident
		if tr.Hops == nil {
			tr.Hops = []model.Hop{}
		}
		m.appendApply(model.TypeTraceroute, tr, nil, func(ref model.Ref) {
			st := target
			if st == nil && incident != "" {
				st = m.incidentByIDLocked(incident)
			}
			if st != nil {
				st.ev.add(model.EvidenceRef{Seq: ref.Seq, Type: model.TypeTraceroute,
					Note: fmt.Sprintf("%s %s (%d hops, reached=%t)", trigger, tr.Target, len(tr.Hops), tr.Reached)})
			}
		})
	}
}
