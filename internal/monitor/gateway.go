package monitor

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strings"
	"time"
	"unicode"

	"golang.org/x/net/html"

	"attmonitor/internal/contracts"
	"attmonitor/internal/model"
)

// Snapshot triggers recorded in gateway_snapshot.trigger.
const (
	trigPeriodic      = "periodic"
	trigStartup       = "startup"
	trigCycleFailure  = "cycle_failure"
	trigIncident      = "incident"
	trigIncidentClose = "incident_close"
)

const bbeventWhat = "events.bbevent (Broadband Status Notification)"

func (m *Monitor) gatewayLoop(ctx context.Context) {
	next := time.Now()
	first := true
	for {
		if !sleepUntil(ctx, next, m.kGateway.ch) {
			return
		}
		reasons := m.kGateway.take()
		trigger := trigPeriodic
		switch {
		case hasReason(reasons, "incident"):
			trigger = trigIncident
		case hasReason(reasons, "cycle_failure"):
			trigger = trigCycleFailure
		case first:
			trigger = trigStartup
		}
		first = false
		began := time.Now()
		m.safely("gateway", func() { m.takeSnapshot(ctx, trigger, nil) })
		interval := m.set.poll
		if m.incidentOpen() {
			interval = m.set.incidentPoll
		}
		next = began.Add(interval)
	}
}

// pagesFor returns the pages of the next snapshot: the configured pages, plus the slow
// lanstatistics page every LANStatsInterval on routine polls.
func (m *Monitor) pagesFor(trigger string, at time.Time) []string {
	pages := slices.Clone(m.set.pages)
	if trigger != trigPeriodic && trigger != trigStartup {
		return pages
	}
	m.mu.Lock()
	due := m.st.lastLANStats.IsZero() || at.Sub(m.st.lastLANStats) >= m.set.lanStats
	if due {
		m.st.lastLANStats = at
	}
	m.mu.Unlock()
	if due && !slices.Contains(pages, "lanstatistics") {
		pages = append(pages, "lanstatistics")
	}
	return pages
}

// takeSnapshot fetches, stores (per the raw storage policy) and records one gateway snapshot,
// then records the gateway events it reveals. target is the incident whose close procedure
// asked for it (nil for routine polls). It returns nil when nothing was recorded.
func (m *Monitor) takeSnapshot(ctx context.Context, trigger string, target *incState) *snapObs {
	m.lockGateway(gwUseSnapshot)
	defer m.unlockGateway()
	if ctx.Err() != nil {
		return nil
	}
	at := m.now()
	pages := m.pagesFor(trigger, at)
	sctx, cancel := context.WithTimeout(ctx, time.Duration(len(pages))*m.set.gwTimeout+5*time.Second)
	snap, bodies, err := m.gw.Snapshot(sctx, pages, trigger)
	cancel()
	if ctx.Err() != nil {
		return nil // shutting down: an aborted fetch is not evidence of anything
	}
	if err != nil {
		// Unreachable gateways fail every poll (every 15 s during an incident): reported when
		// it starts, hourly while it lasts and when it ends (logGate), not per poll.
		if loud, n, since := m.snapFailLog.fail(m.now(), snapFailReport); loud {
			m.log.Warn("gateway snapshot failed", "trigger", trigger, "err", err, "failures", n, "since", since)
		} else {
			m.log.Debug("gateway snapshot failed", "trigger", trigger, "err", err, "failures", n)
		}
	} else if rec, n, since := m.snapFailLog.ok(); rec {
		m.log.Info("gateway snapshots succeed again", "failures", n, "since", since)
	}
	if len(snap.Pages) == 0 {
		msg := "no page fetched"
		if err != nil {
			msg = errText(err)
		}
		for _, p := range pages {
			snap.Pages = append(snap.Pages, model.PageCapture{Page: p, FetchedAt: fmtTS(at), Err: msg})
		}
	}
	snap.Trigger = trigger

	m.mu.Lock()
	incidentActive := target != nil || m.st.tracker.open != nil || len(m.st.closing) > 0
	prevGood, prevAttempt, prevUp := m.st.lastGood, m.st.lastSnap, m.st.lastUp
	lastStored := maps.Clone(m.st.lastStored)
	m.mu.Unlock()

	cur := &snapObs{At: at, Snap: &snap, live: true}
	var prevSnap *model.GatewaySnapshot
	if prevGood != nil {
		prevSnap = prevGood.Snap
	}
	// The previous good snapshot is the baseline for the fields; reachability changes are
	// relative to the previous attempt (the first answer after an unreachable period is kept).
	elapsed, known := elapsedBetween(prevGood, cur)
	material := materialChange(prevSnap, &snap, elapsed, known) ||
		(prevAttempt != nil && prevAttempt.reachable() != snap.Derived.Reachable)

	var blobs []string
	stored := map[string]bool{}
	for i := range snap.Pages {
		p := &snap.Pages[i]
		body, ok := bodies[p.Page]
		if !ok || len(body) == 0 {
			continue
		}
		sum := sha256Hex(body)
		if p.SHA256 == "" {
			p.SHA256 = sum
		}
		if !shouldStoreRaw(incidentActive, material, lastStored[p.Page], at, m.set.rawStore) {
			continue
		}
		if !strings.EqualFold(p.SHA256, sum) {
			m.log.Error("gateway page hash does not match its body; raw page not stored", "page", p.Page)
			continue
		}
		id, err := m.putBlob(body)
		if err != nil {
			continue
		}
		p.Stored = true
		blobs = append(blobs, id)
		stored[p.Page] = true
	}

	if _, err := m.appendApply(model.TypeGatewaySnapshot, &snap, blobs, func(ref model.Ref) {
		cur.Seq = ref.Seq
		m.applySnapshotLocked(cur, stored, target)
	}); err != nil {
		return nil
	}

	// A gateway restart revealed by the uptime (DESIGN §10) counts only once its gateway_event
	// "reboot" is recorded: everything the incidents say about it must be in the ledger.
	rs := restartOf(prevUp, cur)
	for _, ev := range gatewayEvents(prevAttempt, prevGood, prevUp, cur) {
		note := ev.Kind
		if ev.After != "" {
			note += ": " + truncate(ev.After, 80)
		}
		if _, err := m.appendApply(model.TypeGatewayEvent, ev, nil, func(ref model.Ref) {
			m.addEvidenceLocked(target, model.TypeGatewayEvent, ref.Seq,
				model.EvidenceRef{Seq: ref.Seq, Type: model.TypeGatewayEvent, Note: note})
			if ev.Kind == model.GwEvOpticalAlarm {
				m.st.alarms = applyAlarmEvent(m.st.alarms, ev, ref)
			}
			if rs != nil {
				switch ev.Kind {
				case model.GwEvReboot:
					rs.EventSeq = ref.Seq
				case model.GwEvFirmwareChange:
					rs.FWEventSeq = ref.Seq
				}
			}
		}); err == nil {
			m.log.Info("gateway event", "kind", ev.Kind, "before", ev.Before, "after", ev.After)
		}
	}
	if rs != nil && rs.EventSeq == 0 {
		rs = nil
	}
	m.learnFromSnapshot(cur, rs)
	return cur
}

// applySnapshotLocked updates the in-memory view with a recorded snapshot. Caller holds mu.
func (m *Monitor) applySnapshotLocked(cur *snapObs, stored map[string]bool, target *incState) {
	m.st.lastSnap = cur
	d := cur.Snap.Derived
	if hasUptime(cur) {
		m.st.lastUp = cur
	}
	if cur.reachable() {
		m.st.lastGood = cur
		// The last usable next hop and resolver are kept: while the WAN is down the gateway
		// shows 0.0.0.0 for them, and probing that as "AT&T's" hop or resolver would blame
		// the provider for queries that never left this computer.
		if hop, dns := ispAddrs(cur.Snap); hop != "" || dns != "" {
			if hop != "" {
				m.st.ispHop = hop
			}
			if dns != "" {
				m.st.ispDNS = dns
			}
		}
		m.st.points.addOptical(cur.At, d)
		if cur.Snap.Fiber != nil { // alarm flags are only known when fiberstat was parsed
			m.st.lastFiber = cur
			// A flag raised now is first reported by this snapshot until its optical_alarm event
			// is recorded (applyAlarmEvent); one still raised keeps its first report.
			for code := range m.st.alarms {
				if !slices.Contains(d.Alarms, code) {
					delete(m.st.alarms, code)
				}
			}
			for _, a := range d.Alarms {
				if _, ok := m.st.alarms[a]; !ok {
					m.st.alarms[a] = alarmMark{Since: cur.At, Seq: cur.Seq}
				}
			}
		}
		if b := cur.Snap.Broadband; b != nil && len(b.Counters) > 0 {
			m.st.prevCtr, m.st.lastCtr = m.st.lastCtr, cur
			m.trafficSnapshotLocked(cur)
		}
	}
	for page := range stored {
		m.st.lastStored[page] = cur.At
	}
	for _, st := range m.evidenceTargetsLocked(target) {
		s := &st.inc.Stats
		s.GatewayFetches++
		if d.BroadbandUp != nil && !*d.BroadbandUp {
			s.GatewayDownSeen = true
		}
		if d.PONOperational != nil && !*d.PONOperational {
			s.PONDownSeen = true
		}
		if len(d.Alarms) > 0 {
			s.OpticalAlarm = true
		}
		refs := []model.EvidenceRef{{Seq: cur.Seq, Type: model.TypeGatewaySnapshot, Note: "trigger=" + cur.Snap.Trigger}}
		for _, p := range cur.Snap.Pages {
			if p.Stored {
				refs = append(refs, model.EvidenceRef{Seq: cur.Seq, Type: model.TypeGatewaySnapshot, Blob: p.SHA256, Note: p.Page})
			}
		}
		st.ev.addGroup(model.TypeGatewaySnapshot, cur.Seq, refs)
	}
}

// maxRestarts bounds the remembered gateway restarts (each is a reboot record).
const maxRestarts = 512

// learnFromSnapshot applies what a recorded snapshot says about gateway restarts (DESIGN §10,
// rules 2026.10-3): a restart it revealed (rs, its reboot event recorded) is remembered and
// attached to every incident whose window contains it, and a readable uptime decides the
// closed incidents that waited for one (often the restart is only learned from the first
// successful snapshot after the close). Every open or closed incident that changed is
// recorded at once (incident_update); an incident whose close record is still to be written
// gets the restart in that record.
func (m *Monitor) learnFromSnapshot(cur *snapObs, rs *restartInfo) {
	usable := hasUptime(cur)
	if rs == nil && !usable {
		return
	}
	m.stMu.Lock()
	defer m.stMu.Unlock()
	var changed []*incState
	m.locked(func() {
		if rs != nil {
			m.rememberRestartLocked(*rs)
			if o := m.st.tracker.open; o != nil && m.attachRestartLocked(o, *rs) {
				if _, recorded := m.st.incidents[o.inc.ID]; recorded { // else its open record carries it
					changed = append(changed, o)
				}
			}
		}
		for _, c := range m.st.closing {
			if rs != nil {
				m.attachRestartLocked(c, *rs)
			}
			if usable && !cur.At.Before(c.closed) {
				c.restartDecided = true
			}
		}
		var keep []*incState
		for _, w := range m.st.rebootWatch {
			if rs != nil && m.attachRestartLocked(w, *rs) {
				changed = append(changed, w)
			}
			if usable && !cur.At.Before(w.closed) {
				w.restartDecided = true
				continue
			}
			keep = append(keep, w)
		}
		m.st.rebootWatch = keep
	})
	for _, st := range changed {
		if inc, err := m.appendIncidentLocked(model.TypeIncidentUpdate, st, nil); err == nil {
			m.log.Warn("incident revised: the AT&T gateway restarted during it", "id", inc.ID,
				"state", inc.State, "cause", inc.Cause, "attribution", inc.Attribution, "restart_s", inc.Stats.RestartSec)
		}
	}
}

// attachRestartLocked attaches a gateway restart to an incident when it belongs to it (see
// incState.attachRestart), with the lead of its window computed from the recorded cycles before
// the incident's first cycle: the same window the statistics compute over every cycle (DESIGN
// §10). Caller holds mu (and stMu, so no incident record can miss the restart).
func (m *Monitor) attachRestartLocked(st *incState, r restartInfo) bool {
	r.lead = m.st.points.restartLead(r.Boot, st.opened, gapLimit(m.set.fast))
	return st.attachRestart(r)
}

// rememberRestartLocked adds a restart to the known restarts (statistics windows, incidents
// opening later), dropping those older than the statistics horizon. Caller holds mu.
func (m *Monitor) rememberRestartLocked(r restartInfo) {
	for _, x := range m.st.restarts {
		if sameRestart(x, r) {
			return
		}
	}
	m.st.restarts = append(m.st.restarts, r)
	slices.SortStableFunc(m.st.restarts, func(a, b restartInfo) int { return a.Boot.Compare(b.Boot) })
	m.st.restarts = pruneRestarts(m.st.restarts, m.now())
}

// pruneRestarts keeps the restarts within the statistics horizon (at most maxRestarts).
func pruneRestarts(rs []restartInfo, now time.Time) []restartInfo {
	cutoff := now.Add(-seriesKeep - time.Hour)
	rs = slices.DeleteFunc(rs, func(r restartInfo) bool { return r.Boot.Before(cutoff) })
	if n := len(rs); n > maxRestarts {
		rs = slices.Clone(rs[n-maxRestarts:])
	}
	return rs
}

// restartBoots lists the boot times of the known restarts. Caller holds mu.
func (m *Monitor) restartBootsLocked() []time.Time {
	out := make([]time.Time, 0, len(m.st.restarts))
	for _, r := range m.st.restarts {
		out = append(out, r.Boot)
	}
	return out
}

// What the monitor uses the gateway for while it holds the gateway lock (lockGateway), in the
// words of the reason a flow-meter read skipped meanwhile gives: "the monitor was <use>"
// (errLiveBusy). The snapshots and the settings are recorded in the ledger; the Network page's
// reads never are, so their words do not speak of the evidence.
const (
	gwUseSnapshot  = "taking a snapshot of the gateway for its evidence"
	gwUseNotif     = "checking the gateway's outage-redirect setting"
	gwUseSetNotif  = "changing the gateway's outage-redirect setting"
	gwUseSyslog    = "checking the gateway's Syslog setting"
	gwUseSetSyslog = "changing the gateway's Syslog setting"
	gwUseNAT       = "reading the gateway's NAT table for the Network page"
	gwUseDevices   = "reading the gateway's Device List for the Network page"
)

// lockGateway takes the gateway lock (gwMu: one request to the gateway at a time) for use - one of
// the gwUse words - and names that use (Monitor.gwUse) until unlockGateway releases the lock.
// Every holder of the lock takes it here except the flow meter, which never waits for it: a
// flow-meter read skipped because the lock is held says what holds it (errLiveBusy), which may be
// a snapshot for the evidence, a settings check or a read for the Network page - a NAT read holds
// the lock for up to natTimeout, a login included.
func (m *Monitor) lockGateway(use string) {
	m.gwMu.Lock()
	m.gwUse.Store(&use)
}

// unlockGateway releases the gateway lock that lockGateway took. The use is cleared before the
// lock is released, so that it never clears the use of the next holder.
func (m *Monitor) unlockGateway() {
	m.gwUse.Store(nil)
	m.gwMu.Unlock()
}

// withGatewayAuth runs an authenticated gateway operation holding the gateway lock (one
// gateway session at a time; released even if the gateway client panics), taken for use
// (lockGateway: what the operation is). While it runs, the certificate observer knows that a
// TLS handshake belongs to a login: a changed certificate is then refused, so the login hash
// never reaches an unconfirmed host.
//
// While a changed gateway certificate waits for the operator's confirmation the operation is
// refused (errCertPending) and f does not run, whatever its caller checked before: a status
// read that meets a changed certificate has it accepted (the observer holds it pending) and
// pinned by the gateway client, whose later requests then never ask the observer again - so
// it must not be followed by an authenticated request. That is checked holding the gateway
// lock, which every request to the gateway holds, so such a status read has recorded the
// certificate by then; and the flag is raised in the same cfgMu critical section as the
// pending certificate is read, in which the observer reads the flag: a certificate accepted
// for a status read is pending by the check, and one met later is refused.
func (m *Monitor) withGatewayAuth(use string, f func()) error {
	m.lockGateway(use)
	defer m.unlockGateway()
	m.cfgMu.Lock()
	m.gwAuth.Store(true)
	pending := m.cfg.Gateway.PendingCertSHA256
	m.cfgMu.Unlock()
	defer m.gwAuth.Store(false)
	if pending != "" {
		return errCertPending(pending)
	}
	f()
	return nil
}

// pendingCert returns the changed gateway certificate waiting for the operator's
// confirmation ("" if none).
func (m *Monitor) pendingCert() string {
	_, pending := m.certPins()
	return pending
}

// certPins returns the pinned gateway certificate and the changed one waiting for the
// operator's confirmation, read together.
func (m *Monitor) certPins() (pinned, pending string) {
	m.cfgMu.Lock()
	defer m.cfgMu.Unlock()
	return m.cfg.Gateway.PinnedCertSHA256, m.cfg.Gateway.PendingCertSHA256
}

// pendingCertRecordLocked returns when the pending certificate was first seen and the
// cert_changed gateway_event that recorded it - only if that record is about this very
// certificate (zero when unknown, e.g. its record could not be written or is still being
// written). Caller holds mu.
func (m *Monitor) pendingCertRecordLocked(pending string) (time.Time, uint64) {
	if pending == "" || m.st.certPendingSeq == 0 || !strings.EqualFold(m.st.certPendingFP, pending) {
		return time.Time{}, 0
	}
	return m.st.certPendingSince, m.st.certPendingSeq
}

// errCertPending is returned by authenticated operations while a changed gateway
// certificate waits for confirmation (DESIGN §2 certificate policy).
func errCertPending(pending string) error { return &certPendingError{pending: pending} }

// certPendingError: an authenticated gateway operation was refused because a changed gateway
// certificate waits for the operator's confirmation. It matches contracts.ErrGatewayCertRejected
// (the web answers 409 "confirm the gateway certificate first") and contracts.ErrUnavailable
// (the operation is paused, not failed).
type certPendingError struct{ pending string }

func (e *certPendingError) Error() string {
	return fmt.Sprintf("authenticated gateway requests are paused: the gateway presented an unconfirmed TLS certificate (SHA-256 %s); confirm it with trust-cert", e.pending)
}

func (e *certPendingError) Unwrap() []error {
	return []error{contracts.ErrGatewayCertRejected, contracts.ErrUnavailable}
}

// certMismatchError: TrustCert refused because the certificate waiting for confirmation is not
// the one the operator reviewed (it changed meanwhile). It matches contracts.ErrBusy (the web
// answers 409); its text names both fingerprints and not the sentinel's ("already running").
type certMismatchError struct{ pending, expected string }

func (e *certMismatchError) Error() string {
	return fmt.Sprintf("the certificate was not trusted: the gateway certificate waiting for confirmation is SHA-256 %s, not the one reviewed (SHA-256 %s); review the new fingerprint and confirm it only if you recognise it",
		e.pending, e.expected)
}

func (e *certMismatchError) Unwrap() error { return contracts.ErrBusy }

// normalizeFingerprint brings a certificate fingerprint as an operator may copy it ("AB:CD:..",
// spaces) to the lowercase hex form the monitor stores.
func normalizeFingerprint(s string) string {
	return strings.ToLower(strings.Map(func(r rune) rune {
		if r == ':' || unicode.IsSpace(r) {
			return -1
		}
		return r
	}, s))
}

// certDecision applies the certificate policy of DESIGN §2 to an observed certificate and
// returns the gateway_event to record (nil: nothing new) and whether to accept the TLS
// connection. Caller holds cfgMu.
//
//   - no pin yet: trust on first use (cert_pinned);
//   - the pinned certificate: accepted; if another one was pending it is no longer presented,
//     so the pause ends (cert_changed back to the pinned certificate);
//   - any other certificate: recorded once as pending (cert_changed). Status pages keep being
//     read, but authenticated requests are refused until the operator confirms it.
func (m *Monitor) certDecision(observed string, authenticated bool) (*model.GatewayEvent, bool) {
	g := &m.cfg.Gateway
	pinned, pending := g.PinnedCertSHA256, g.PendingCertSHA256
	host := m.set.gwHost
	switch {
	case observed == "":
		return nil, !authenticated
	case pinned == "":
		g.PinnedCertSHA256, g.PendingCertSHA256 = observed, ""
		return &model.GatewayEvent{Kind: model.GwEvCertPinned, After: observed,
			Detail: fmt.Sprintf("first TLS certificate seen from gateway %s (SHA-256 %s) was pinned (trust on first use)", host, observed)}, true
	case strings.EqualFold(observed, pinned):
		if pending == "" {
			return nil, true
		}
		g.PendingCertSHA256 = ""
		return &model.GatewayEvent{Kind: model.GwEvCertChanged, Before: pending, After: pinned,
			Detail: fmt.Sprintf("gateway %s presents its pinned TLS certificate (SHA-256 %s) again; the unconfirmed certificate %s is no longer presented, so authenticated requests resume", host, pinned, pending)}, true
	case strings.EqualFold(observed, pending):
		return nil, !authenticated
	}
	g.PendingCertSHA256 = observed
	detail := fmt.Sprintf("gateway %s presented a TLS certificate (SHA-256 %s) different from the pinned one (%s); status pages are still read, but authenticated requests are paused until the operator confirms the new certificate (trust-cert)", host, observed, pinned)
	if authenticated {
		detail += "; the authenticated request that met it was refused before any login data was sent"
	}
	return &model.GatewayEvent{Kind: model.GwEvCertChanged, Before: pinned, After: observed, Detail: detail}, !authenticated
}

// observeCert is the TLS pin policy installed on the gateway client (see certDecision). Every
// decision that changes the pin state is persisted with SaveConfig and recorded as a
// gateway_event.
func (m *Monitor) observeCert(previous, observed string) bool {
	m.cfgMu.Lock()
	// Read under cfgMu, where withGatewayAuth raises it and reads the pending certificate.
	authenticated := m.gwAuth.Load()
	ev, accept := m.certDecision(strings.ToLower(strings.TrimSpace(observed)), authenticated)
	var saveErr error
	pending := m.cfg.Gateway.PendingCertSHA256
	if ev != nil && m.opts.SaveConfig != nil {
		saveErr = m.opts.SaveConfig(m.cfg)
	}
	m.cfgMu.Unlock()
	if ev == nil {
		if !accept {
			m.log.Warn("gateway TLS certificate not confirmed yet; authenticated request refused", "observed", observed)
		}
		return accept
	}
	if saveErr != nil {
		ev.Detail += "; the new certificate state could not be saved: " + errText(saveErr)
		m.log.Error("cannot save gateway certificate state", "err", saveErr)
	}
	now := m.now()
	if _, err := m.appendApply(model.TypeGatewayEvent, *ev, nil, func(ref model.Ref) {
		m.st.certEvent = &certEventRec{Seq: ref.Seq, TS: ref.TS, After: ev.After}
		if pending != "" {
			// First seen: the time of the record that reports it (as the rebuild finds it).
			since, ok := parseTS(ref.TS)
			if !ok {
				since = now
			}
			m.st.certPendingSince, m.st.certPendingSeq, m.st.certPendingFP = since, ref.Seq, pending
		} else {
			m.st.certPendingSince, m.st.certPendingSeq, m.st.certPendingFP = time.Time{}, 0, ""
		}
		m.addEvidenceLocked(nil, model.TypeGatewayEvent, ref.Seq, model.EvidenceRef{Seq: ref.Seq, Type: model.TypeGatewayEvent, Note: ev.Kind})
	}); err == nil {
		m.log.Warn("gateway certificate event", "kind", ev.Kind, "sha256", observed, "client_pin", previous, "accepted", accept)
	}
	return accept
}

// TrustCert implements contracts.Actions.TrustCert: it confirms the changed gateway certificate
// that waits for the operator (DESIGN §2, "trust-cert"), which becomes the pin, and
// authenticated requests resume. The change is recorded as a config_change; nothing changes
// when it cannot be recorded. contracts.ErrNotFound when no certificate is pending.
//
// expectedSHA256 is the fingerprint of the pending certificate the operator reviewed (any case,
// ':' separators and spaces allowed). It is compared with the pending certificate in the same
// cfgMu critical section that moves the pin, so a certificate that became pending meanwhile is
// never trusted in its place: such a mismatch changes nothing and matches contracts.ErrBusy,
// naming both fingerprints. "" trusts whatever is pending (the CLI without the service, older
// clients).
//
// The pin moves before its config_change is written, and moves back when that record fails: in
// between, no authenticated request may start, or the login could go to the new certificate
// before the ledger says it was trusted - or when it never will, once the move is undone.
// withGatewayAuth cannot tell (nothing is pending any more), so TrustCert keeps the requests out
// with locks, both held until the change is recorded or undone: notifMu keeps out the settings
// check and the operator's changes of a gateway setting, certMu - held exclusively - the NAT
// sampler's reads (connections.go), which hold it shared and never wait for it. A NAT read in
// progress is waited for: the pin never moves under it. TrustCert never takes the gateway lock,
// which such a read may hold or wait for.
func (m *Monitor) TrustCert(ctx context.Context, actor, expectedSHA256 string) (model.ConfigChange, error) {
	actor, err := label("actor", actor)
	if err != nil {
		return model.ConfigChange{}, err
	}
	if actor == "" {
		actor = "operator"
	}
	expected := normalizeFingerprint(expectedSHA256)
	m.notifMu.Lock() // no settings check or operator change may run half-way through the change
	defer m.notifMu.Unlock()
	m.certMu.Lock() // nor may a NAT read (which does not take notifMu)
	defer m.certMu.Unlock()
	m.cfgMu.Lock()
	pinned, pending := m.cfg.Gateway.PinnedCertSHA256, m.cfg.Gateway.PendingCertSHA256
	if pending == "" {
		m.cfgMu.Unlock()
		return model.ConfigChange{}, fmt.Errorf("no changed gateway certificate is waiting for confirmation: %w", contracts.ErrNotFound)
	}
	if expected != "" && expected != normalizeFingerprint(pending) {
		m.cfgMu.Unlock()
		merr := &certMismatchError{pending: normalizeFingerprint(pending), expected: truncate(expected, 128)}
		m.log.Warn("gateway certificate confirmation refused: another certificate is pending than the one reviewed",
			"pending", merr.pending, "reviewed", merr.expected, "actor", actor)
		return model.ConfigChange{}, merr
	}
	m.cfg.Gateway.PinnedCertSHA256, m.cfg.Gateway.PendingCertSHA256 = pending, ""
	var saveErr error
	if m.opts.SaveConfig != nil {
		saveErr = m.opts.SaveConfig(m.cfg)
	}
	m.cfgMu.Unlock()
	cc := model.ConfigChange{Target: "monitor", What: "gateway.pinned_cert_sha256 (trusted gateway TLS certificate)",
		Before: pinned, After: pending, Actor: actor, Result: "applied"}
	if saveErr != nil {
		cc.Result = "applied until the monitor restarts: the configuration could not be saved: " + errText(saveErr)
	}
	if _, err := m.appendApply(model.TypeConfigChange, cc, nil, func(ref model.Ref) {
		// The trusted certificate is no longer pending (a newer one recorded meanwhile stays).
		if strings.EqualFold(m.st.certPendingFP, pending) {
			m.st.certPendingSince, m.st.certPendingSeq, m.st.certPendingFP = time.Time{}, 0, ""
		}
		m.addEvidenceLocked(nil, model.TypeConfigChange, ref.Seq, model.EvidenceRef{Seq: ref.Seq, Type: model.TypeConfigChange, Note: "gateway certificate trusted"})
	}); err != nil {
		// Not recorded: undo, so the pin never changes without a ledger record. A certificate
		// that became pending meanwhile (the observer runs concurrently) stays pending.
		m.cfgMu.Lock()
		if m.cfg.Gateway.PinnedCertSHA256 == pending {
			m.cfg.Gateway.PinnedCertSHA256 = pinned
		}
		if m.cfg.Gateway.PendingCertSHA256 == "" {
			m.cfg.Gateway.PendingCertSHA256 = pending
		}
		if m.opts.SaveConfig != nil {
			_ = m.opts.SaveConfig(m.cfg)
		}
		m.cfgMu.Unlock()
		return model.ConfigChange{}, err
	}
	m.log.Warn("gateway certificate confirmed by the operator", "sha256", pending, "actor", actor)
	return cc, saveErr
}

// ---------------------------------------------------------------------------- notification setting

func (m *Monitor) hasAccessCode() bool {
	m.cfgMu.Lock()
	defer m.cfgMu.Unlock()
	return m.cfg.HasAccessCode()
}

func (m *Monitor) enforceNotificationOff() bool {
	m.cfgMu.Lock()
	defer m.cfgMu.Unlock()
	return m.cfg.Gateway.EnforceNotificationOff
}

// notificationLoop checks the gateway's settings - the outage-redirect setting, then the Syslog
// setting - at startup and every NotificationCheckInterval (authenticated requests: never more
// often than notifMinInterval). When this computer's address toward the gateway changes
// (kickAddressChange) the check runs again within minutes: once notifMinInterval has passed
// since this run's latest check - after a failed one, once its back-off (notifRetryAfter) has -
// and never before the startup check, which reads the current settings anyway. The first NAT read
// for the Network page waits for the startup check (startupCheckDone), whose login session it then
// reuses; a check whose login the gateway rejected stops the NAT reads as their own rejection would
// (natStopAfterRejection).
func (m *Monitor) notificationLoop(ctx context.Context) {
	next := time.Now().Add(m.notificationStartDelay())
	var (
		last    time.Time // when this run's latest check ended (zero: none yet)
		lastErr error
		recheck bool // an address change asked for the next check
	)
	for {
		if !sleepUntil(ctx, next, m.kNotif.ch) {
			return
		}
		if hasReason(m.kNotif.take(), kickAddressChange) && !last.IsZero() {
			recheck = true
			early := last.Add(m.notifMinInterval)
			if lastErr != nil {
				early = last.Add(m.notifRetryAfter(lastErr))
			}
			if early.Before(next) {
				next = early
			}
		}
		if time.Now().Before(next) {
			continue // woken early: wait for the (possibly earlier) check time
		}
		interval := max(m.set.notifInterval, m.notifMinInterval)
		if !m.hasAccessCode() {
			next, recheck = time.Now().Add(interval), false
			m.startupCheckDone() // nothing to check: the NAT reads need not wait for it
			continue
		}
		why := ""
		if recheck {
			why = "again after this computer's address toward the gateway changed"
		}
		recheck = false
		var err error
		m.safely("notification", func() { err = m.checkSettings(ctx, why) })
		if ctx.Err() != nil {
			return
		}
		// Persist the check time now: a restart (even after a crash) must honour the floor.
		m.writeCache()
		if errors.Is(err, contracts.ErrGatewayAuth) {
			m.natStopAfterRejection(err) // the NAT reads would only use up the login attempts left
		}
		m.startupCheckDone()
		last, lastErr = time.Now(), err
		if err != nil {
			interval = m.notifRetryAfter(err) // retry later, but never sooner than the floor
		}
		next = time.Now().Add(interval)
	}
}

// Back-off after a failed notification check, by what the gateway answered.
const (
	notifAuthRetry = time.Hour       // a rejected or paused login: logins are limited per hour
	notifBusyRetry = 5 * time.Minute // "all web server sessions are in use" (DESIGN §2: ≥ 5 min)
)

// notifRetryAfter is the wait after a failed notification check, chosen with errors.Is on the
// contracts gateway sentinels: never sooner than notifMinInterval; an access code the gateway
// rejected (or a login paused after rejections) does not fix itself and every attempt uses up
// the login budget, so it waits an hour; a full session pool or a throttled login at least 5 min.
func (m *Monitor) notifRetryAfter(err error) time.Duration {
	switch {
	case errors.Is(err, contracts.ErrGatewayAuth), errors.Is(err, contracts.ErrGatewayAuthLocked):
		return max(m.notifMinInterval, notifAuthRetry)
	case errors.Is(err, contracts.ErrGatewaySessionsFull), errors.Is(err, contracts.ErrGatewayLoginThrottled):
		return max(m.notifMinInterval, notifBusyRetry)
	}
	return m.notifMinInterval
}

// notifConfirmEvery spaces the records confirming an unchanged notification setting: daily
// evidence that the outage redirect stayed as recorded (at most one per 24 h).
const notifConfirmEvery = 24 * time.Hour

// startupCheckDone notes that this run's startup settings check has been made, or that there was
// nothing to check (startupChecked); the later checks change nothing.
func (m *Monitor) startupCheckDone() {
	m.startupCheckedOnce.Do(func() { close(m.startupChecked) })
}

// notificationStartDelay keeps the floor between authenticated gateway requests across
// restarts: the startup check waits until notifMinInterval has passed since the last check
// known from the ledger or the state cache (at most notifMinInterval, whatever the clock says).
func (m *Monitor) notificationStartDelay() time.Duration {
	m.mu.Lock()
	n := m.st.notif
	m.mu.Unlock()
	if n == nil {
		return 0
	}
	last, ok := parseTS(n.CheckedAt)
	if !ok {
		return 0
	}
	wait := last.Add(m.notifMinInterval).Sub(m.now())
	return min(max(wait, 0), m.notifMinInterval)
}

// checkNotification is the regular settings check (checkSettings).
func (m *Monitor) checkNotification(ctx context.Context) error { return m.checkSettings(ctx, "") }

// checkSettings checks the gateway's settings: the outage-redirect setting (readNotification)
// and, after a successful read of it and in the same login session, the Syslog setting
// (checkSyslogSetting: read, and with gateway.enforce_syslog set to send to this computer). The
// returned error is the notification check's: it sets the loop's back-off. A failed read of the
// Syslog page, or a failed attempt to set it, waits for the next check (Status.Syslog and
// SYSLOG_SETTING_FAILED say why), so that it never adds logins. why (may be "") says what asked
// for the check. It holds notifMu so that an operator's SetGatewayNotification or
// SetGatewaySyslog cannot interleave with the read-then-enforce sequence (nor TrustCert). A NAT
// read for the Network page does not take notifMu - it changes no setting - so the check waits
// for one in progress at the gateway lock, and one may run between the check's requests. While a
// changed gateway certificate waits for confirmation - also one a status read met after the check
// began, which pauses the authenticated requests that follow (withGatewayAuth) - the settings
// are not checked further.
func (m *Monitor) checkSettings(ctx context.Context, why string) error {
	m.notifMu.Lock()
	defer m.notifMu.Unlock()
	if pending := m.pendingCert(); pending != "" {
		return m.settingsPaused(errCertPending(pending))
	}
	read, err := m.readNotification(ctx)
	var paused *certPendingError
	switch {
	case ctx.Err() != nil:
	case errors.As(err, &paused):
		return m.settingsPaused(err)
	case read:
		m.checkSyslogSetting(ctx, why)
	default:
		m.locked(func() {
			m.st.syslogErr = "the gateway's Syslog setting was not checked: the notification setting, read first in the same login session, could not be read: " + errText(err)
		})
	}
	return err
}

// settingsPaused notes a settings check that authenticated requests were refused to (err: a
// changed gateway certificate waits for confirmation): the notification and Syslog settings
// keep what is known of them, with why they were not checked. It returns err.
func (m *Monitor) settingsPaused(err error) error {
	m.locked(func() {
		ns := model.NotificationState{Err: errText(err)}
		if p := m.st.notif; p != nil {
			ns.Enabled, ns.Seq, ns.CheckedAt = p.Enabled, p.Seq, p.CheckedAt
		}
		m.st.notif = &ns
		m.st.syslogErr = "the gateway's Syslog setting was not checked: " + errText(err)
	})
	return err
}

// readNotification reads the bbevent setting, records it on first observation or change, and
// turns it off when EnforceNotificationOff is set. read reports whether the setting could be
// read (err may still report a failure after that). A read refused because a changed gateway
// certificate waits for confirmation changes nothing (checkSettings says why). Caller holds
// notifMu.
func (m *Monitor) readNotification(ctx context.Context) (read bool, err error) {
	var (
		enabled bool
		raw     []byte
	)
	if aerr := m.withGatewayAuth(gwUseNotif, func() {
		nctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		defer cancel()
		enabled, raw, err = m.gw.Notification(nctx)
	}); aerr != nil {
		return false, aerr
	}
	if ctx.Err() != nil {
		return false, ctx.Err()
	}
	now := m.now()
	if err != nil {
		if loud, n, since := m.notifFailLog.fail(now, notifFailReport); loud {
			m.log.Warn("cannot read the gateway notification setting; will retry later", "err", err, "failures", n, "since", since)
		} else {
			m.log.Debug("cannot read the gateway notification setting; will retry later", "err", err, "failures", n)
		}
		m.mu.Lock()
		ns := model.NotificationState{CheckedAt: fmtTS(now), Err: errText(err)}
		if m.st.notif != nil {
			ns.Enabled, ns.Seq = m.st.notif.Enabled, m.st.notif.Seq
		}
		m.st.notif = &ns
		m.st.notifNoCode = ""
		if errors.Is(err, contracts.ErrGatewayNoAccessCode) {
			m.st.notifNoCode = errText(err)
		}
		m.mu.Unlock()
		return false, err
	}
	if rec, n, since := m.notifFailLog.ok(); rec {
		m.log.Info("the gateway notification setting can be read again", "failures", n, "since", since)
	}
	var blobs []string
	if len(raw) > 0 {
		if id, err := m.putBlob(raw); err == nil {
			blobs = append(blobs, id)
		}
	}
	m.mu.Lock()
	prev, recAt := m.st.notif, m.st.notifRecAt
	m.st.notifNoCode = ""
	m.mu.Unlock()
	known := prev != nil && prev.Seq != 0
	record := func(ev model.GatewayEvent) error {
		_, err := m.appendApply(model.TypeGatewayEvent, ev, blobs, func(ref model.Ref) {
			m.st.notif = &model.NotificationState{Enabled: enabled, CheckedAt: fmtTS(now), Seq: ref.Seq}
			m.st.notifRecAt = now
		})
		return err
	}
	switch {
	case !known || prev.Enabled != enabled:
		ev := model.GatewayEvent{Kind: model.GwEvNotificationSetting, After: onOff(enabled),
			Detail: fmt.Sprintf("Broadband Status Notification (bbevent) observed %s; when on, the gateway redirects web browsing to AT&T pages while the WAN is down", onOff(enabled))}
		if known {
			ev.Before = onOff(prev.Enabled)
		}
		if err := record(ev); err != nil {
			return true, err
		}
	case !now.Before(recAt.Add(notifConfirmEvery)):
		// Daily evidence that the setting stayed as recorded (before == after).
		ev := model.GatewayEvent{Kind: model.GwEvNotificationSetting, Before: onOff(enabled), After: onOff(enabled),
			Detail: fmt.Sprintf("confirmed unchanged: Broadband Status Notification (bbevent) is still %s, as recorded in #%d (read from the gateway's events page; when on, the gateway redirects web browsing to AT&T pages while the WAN is down)",
				onOff(enabled), prev.Seq)}
		if err := record(ev); err != nil {
			return true, err
		}
	default:
		m.mu.Lock()
		m.st.notif = &model.NotificationState{Enabled: enabled, CheckedAt: fmtTS(now), Seq: prev.Seq}
		m.mu.Unlock()
	}
	if enabled && m.enforceNotificationOff() {
		_, err := m.setNotification(ctx, false, "monitor (enforce_notification_off)", nil)
		return true, err
	}
	return true, nil
}

// setNotification changes the gateway setting and records a config_change with the pages
// before and after. extra (optional) adds text to the record's result. A change refused
// because a changed gateway certificate waits for confirmation (withGatewayAuth) is a failed
// attempt like one the gateway client refused.
func (m *Monitor) setNotification(ctx context.Context, enabled bool, actor string, extra func(err error) string) (model.ConfigChange, error) {
	var (
		before, after []byte
		err           error
	)
	if aerr := m.withGatewayAuth(gwUseSetNotif, func() {
		sctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		defer cancel()
		before, after, err = m.gw.SetNotification(sctx, enabled)
	}); aerr != nil {
		err = aerr
	}

	var blobs []string
	for _, page := range [][]byte{before, after} {
		if len(page) == 0 {
			continue
		}
		if id, perr := m.putBlob(page); perr == nil && !slices.Contains(blobs, id) {
			blobs = append(blobs, id)
		}
	}
	m.mu.Lock()
	prev := m.st.notif
	m.mu.Unlock()
	cc := model.ConfigChange{Target: "gateway", What: bbeventWhat, Before: "unknown", After: onOff(enabled), Actor: actor}
	if checked, ok := bbeventChecked(before); ok {
		cc.Before = onOff(checked)
	} else if prev != nil && prev.Seq != 0 {
		cc.Before = onOff(prev.Enabled)
	}
	switch {
	case err != nil:
		cc.Result = "failed: " + errText(err)
	default:
		if checked, ok := bbeventChecked(after); ok {
			if checked == enabled {
				cc.Result = "verified"
			} else {
				cc.Result = fmt.Sprintf("failed: the gateway page after saving still shows the setting %s", onOff(checked))
				err = fmt.Errorf("gateway still reports Broadband Status Notification %s after saving", onOff(checked))
			}
		} else {
			cc.Result = "applied"
		}
	}
	if extra != nil {
		if s := extra(err); s != "" {
			cc.Result += "; " + s
		}
	}
	now := m.now()
	_, aerr := m.appendApply(model.TypeConfigChange, cc, blobs, func(ref model.Ref) {
		if err == nil {
			m.st.notif = &model.NotificationState{Enabled: enabled, CheckedAt: fmtTS(now), Seq: ref.Seq}
			m.st.notifRecAt = now
		}
		m.addEvidenceLocked(nil, model.TypeConfigChange, ref.Seq, model.EvidenceRef{Seq: ref.Seq, Type: model.TypeConfigChange, Note: "bbevent " + cc.After})
	})
	if err != nil {
		m.log.Error("changing the gateway notification setting failed", "enabled", enabled, "actor", actor, "err", err)
		if aerr != nil { // nothing was applied, and not even the attempt could be recorded
			err = errors.Join(err, fmt.Errorf("the failed attempt could not be recorded: %w", aerr))
		}
		return cc, err
	}
	if aerr != nil {
		// The gateway applied the change, so the known state follows the gateway; the missing
		// record is stated there and returned (contracts.ErrNotRecorded). With no supporting
		// record (Seq 0) the next check records the setting it reads.
		m.locked(func() {
			m.st.notif = &model.NotificationState{Enabled: enabled, CheckedAt: fmtTS(now),
				Err: "the gateway applied the change, but it could not be recorded in the evidence ledger: " + errText(aerr)}
		})
		m.log.Error("gateway notification setting changed but not recorded", "enabled", enabled, "actor", actor, "err", aerr)
		return cc, fmt.Errorf("the gateway's Broadband Status Notification was set %s, but the change could not be recorded: %w: %w",
			onOff(enabled), contracts.ErrNotRecorded, aerr)
	}
	m.log.Warn("gateway notification setting changed", "enabled", enabled, "actor", actor, "result", cc.Result)
	return cc, nil
}

// bbeventChecked reports the state of the "bbevent" checkbox in an events.ha page.
func bbeventChecked(page []byte) (checked, found bool) {
	if len(page) == 0 {
		return false, false
	}
	z := html.NewTokenizer(bytes.NewReader(page))
	for {
		switch z.Next() {
		case html.ErrorToken:
			return false, false
		case html.StartTagToken, html.SelfClosingTagToken:
			name, hasAttr := z.TagName()
			if !hasAttr || !strings.EqualFold(string(name), "input") {
				continue
			}
			isBB, isChecked := false, false
			for more := true; more; {
				var k, v []byte
				k, v, more = z.TagAttr()
				switch strings.ToLower(string(k)) {
				case "name":
					isBB = string(v) == "bbevent"
				case "checked":
					isChecked = true
				}
			}
			if isBB {
				return isChecked, true
			}
		}
	}
}

// ispAddrs returns the AT&T next hop and ISP resolver a snapshot reports, each only when it
// is a usable unicast address ("" otherwise, e.g. 0.0.0.0 while the WAN is down). The derived
// fields are preferred; the raw broadband fields are a fallback for snapshots without them.
func ispAddrs(s *model.GatewaySnapshot) (hop, dns string) {
	if s == nil {
		return "", ""
	}
	hop, dns = usableAddr(s.Derived.ISPNextHop), usableAddr(s.Derived.ISPDNS)
	if b := s.Broadband; b != nil {
		if hop == "" {
			hop = usableAddr(b.GatewayIPv4)
		}
		if dns == "" {
			dns = usableAddr(b.PrimaryDNS)
		}
	}
	return hop, dns
}

// usableAddr returns s normalized when it is a unicast address another host can answer from
// (not unspecified, loopback, multicast, link-local or broadcast), else "".
func usableAddr(s string) string {
	a, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil || a.Zone() != "" {
		return ""
	}
	a = a.Unmap()
	if !a.IsGlobalUnicast() {
		return ""
	}
	return a.String()
}
