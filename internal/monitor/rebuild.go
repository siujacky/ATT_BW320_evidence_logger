package monitor

import (
	"cmp"
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"attmonitor/internal/model"
)

// The state cache (StateDir/monitor-state.json) holds what the startup rebuild would otherwise
// have to scan the whole ledger for. It is not evidence: it names the ledger record it is
// current up to (seq + hash) and is ignored when that record does not match, when it cannot
// be parsed, or when it belongs to another ledger key.
const (
	// cacheVersion 3: the gateway alarm flags' first reports and the latest clock check are
	// cached (2: only trusted anchors are "last anchor"; restarts, the uptime baseline,
	// untrusted anchors and the notification record time are cached).
	cacheVersion  = 3
	cacheFileName = "monitor-state.json"
)

type stateCache struct {
	Version         int                      `json:"version"`
	Fingerprint     string                   `json:"fingerprint"`
	Seq             uint64                   `json:"seq"`
	Hash            string                   `json:"hash"`
	Written         string                   `json:"written"`
	Incidents       []model.Incident         `json:"incidents"`
	LastAnchor      *anchorRec               `json:"last_anchor,omitempty"` // trusted (Verified && ChainOK)
	Notification    *model.NotificationState `json:"notification,omitempty"`
	LastStartRun    string                   `json:"last_start_run,omitempty"`
	LastStopRun     string                   `json:"last_stop_run,omitempty"`
	LastSampleTS    string                   `json:"last_sample_ts,omitempty"`
	LastSampleSeq   uint64                   `json:"last_sample_seq,omitempty"`
	LastSnapSeq     *uint64                  `json:"last_snapshot_seq,omitempty"`
	LastGoodSnapSeq *uint64                  `json:"last_good_snapshot_seq,omitempty"`
	// LastFiberSnapSeq: latest reachable snapshot with fiberstat parsed (absent in caches
	// written before it existed; the rebuild then falls back to the last good snapshot).
	LastFiberSnapSeq *uint64       `json:"last_fiber_snapshot_seq,omitempty"`
	CertEvent        *certEventRec `json:"cert_event,omitempty"`
	// ISPHop/ISPDNS: the last usable AT&T next hop and resolver any snapshot reported.
	ISPHop string `json:"isp_hop,omitempty"`
	ISPDNS string `json:"isp_dns,omitempty"`
	// LastUpSnapSeq: latest reachable snapshot with a readable uptime (restart baseline).
	LastUpSnapSeq *uint64 `json:"last_uptime_snapshot_seq,omitempty"`
	// Restarts: gateway restarts (reboot events) within the statistics horizon.
	Restarts []restartInfo `json:"restarts,omitempty"`
	// LastUntrusted/UntrustedSince: the newest anchor that does not count as proof of time and
	// the ts of the first untrusted anchor after the newest trusted one.
	LastUntrusted  *anchorRec `json:"last_untrusted_anchor,omitempty"`
	UntrustedSince string     `json:"untrusted_since,omitempty"`
	// NotificationRecordedAt: ts of the latest record about the notification setting.
	NotificationRecordedAt string `json:"notification_recorded_at,omitempty"`
	// Alarms: per raised gateway alarm flag, its first report in the current raised period.
	Alarms map[string]alarmMark `json:"alarms,omitempty"`
	// LastClock: the latest clock check with an SNTP answer (a step of this computer's clock
	// between two runs is measured against it; CLOCK_OFFSET is shown from it).
	LastClock *clockRef `json:"last_clock,omitempty"`
}

// clockRef is a recorded clock check that got an SNTP answer: its seq, ts, the median offset of
// its answers (server - local) and their number, and - while its offset exceeds the CLOCK_OFFSET
// threshold - the ts of the first check of the current run of such offsets (Answered and
// OffSince are absent from state caches written before they existed).
type clockRef struct {
	Seq      uint64 `json:"seq"`
	TS       string `json:"ts"`
	OffsetMs int64  `json:"offset_ms"`
	Answered int    `json:"answered,omitempty"`
	OffSince string `json:"off_since,omitempty"`
}

// nextClockRef returns the clockRef of a recorded clock check (nil when no time server
// answered: it measured nothing), continuing the run of offsets beyond the CLOCK_OFFSET
// threshold of prev, the latest earlier clock check that got an answer.
func nextClockRef(prev *clockRef, seq uint64, ts string, cc model.ClockCheck) *clockRef {
	off, ok := medianOffset(cc)
	if !ok {
		return nil
	}
	ref := &clockRef{Seq: seq, TS: ts, OffsetMs: off}
	for _, r := range cc.Results {
		ref.Answered += b2i(r.OK)
	}
	if clockOffsetExceeds(off) {
		ref.OffSince = ts
		if prev != nil && clockOffsetExceeds(prev.OffsetMs) {
			ref.OffSince = cmp.Or(prev.OffSince, prev.TS)
		}
	}
	return ref
}

// medianOffset returns the median offset of the answered SNTP measurements of a clock check.
func medianOffset(cc model.ClockCheck) (int64, bool) {
	var offs []int64
	for _, r := range cc.Results {
		if r.OK {
			offs = append(offs, r.OffsetMs)
		}
	}
	if len(offs) == 0 {
		return 0, false
	}
	slices.Sort(offs)
	n := len(offs)
	if n%2 == 1 {
		return offs[n/2], true
	}
	return (offs[n/2-1] + offs[n/2]) / 2, true
}

// certEventRec is the latest gateway certificate event (for the GATEWAY_CERT_CHANGED condition).
type certEventRec struct {
	Seq   uint64 `json:"seq"`
	TS    string `json:"ts"`
	After string `json:"after"`
}

// rebuildState accumulates what the startup scan finds.
type rebuildState struct {
	runID           string
	incidents       map[string]model.Incident
	lastAnchor      *anchorRec // trusted
	lastUntrusted   *anchorRec
	untrustedSince  string
	notif           *model.NotificationState
	notifRecAt      string
	lastStartRun    string
	lastStopRun     string
	lastSampleTS    string
	lastSampleSeq   uint64
	lastSnapSeq     *uint64
	lastGoodSnapSeq *uint64
	lastFiberSeq    *uint64
	lastUpSeq       *uint64
	ispHop, ispDNS  string
	certEvent       *certEventRec // latest cert_pinned / cert_changed event
	restarts        []restartInfo
	alarms          map[string]alarmMark
	lastClock       *clockRef
	points          *pointStore
	records         int
}

func (rb *rebuildState) fromCache(c *stateCache) {
	for _, inc := range c.Incidents {
		rb.incidents[inc.ID] = inc
	}
	rb.lastAnchor, rb.notif = c.LastAnchor, c.Notification
	if rb.lastAnchor != nil && !anchorTrusted(rb.lastAnchor.Anchor) {
		rb.lastAnchor = nil // never trust a cache for what counts as proof of time
	}
	rb.lastUntrusted, rb.untrustedSince = c.LastUntrusted, c.UntrustedSince
	rb.notifRecAt = c.NotificationRecordedAt
	rb.lastStartRun, rb.lastStopRun = c.LastStartRun, c.LastStopRun
	rb.lastSampleTS, rb.lastSampleSeq = c.LastSampleTS, c.LastSampleSeq
	rb.lastSnapSeq, rb.lastGoodSnapSeq, rb.lastFiberSeq = c.LastSnapSeq, c.LastGoodSnapSeq, c.LastFiberSnapSeq
	rb.lastUpSeq = c.LastUpSnapSeq
	rb.ispHop, rb.ispDNS = usableAddr(c.ISPHop), usableAddr(c.ISPDNS)
	rb.certEvent = c.CertEvent
	rb.restarts = slices.Clone(c.Restarts)
	rb.alarms = maps.Clone(c.Alarms)
	if rb.alarms == nil {
		rb.alarms = map[string]alarmMark{}
	}
	rb.lastClock = c.LastClock
}

// addRestart remembers a restart from a reboot event (in ledger order).
func (rb *rebuildState) addRestart(r restartInfo) {
	for _, x := range rb.restarts {
		if sameRestart(x, r) {
			return
		}
	}
	rb.restarts = append(rb.restarts, r)
}

func u64p(v uint64) *uint64 { return &v }

// apply updates the custody state from one record (decoding only the types it needs).
func (rb *rebuildState) apply(body model.Body) {
	rb.records++
	switch body.Type {
	case model.TypeIncidentOpen, model.TypeIncidentUpdate, model.TypeIncidentClose:
		var inc model.Incident
		if json.Unmarshal(body.Data, &inc) == nil && inc.ID != "" {
			rb.incidents[inc.ID] = inc
		}
	case model.TypeMonitorStart:
		if body.Run != rb.runID {
			rb.lastStartRun = body.Run
		}
	case model.TypeMonitorStop:
		rb.lastStopRun = body.Run
	case model.TypeSample:
		rb.lastSampleTS, rb.lastSampleSeq = body.TS, body.Seq
	case model.TypeGatewaySnapshot:
		rb.lastSnapSeq = u64p(body.Seq)
		var d struct {
			Fiber     json.RawMessage `json:"fiber"`
			Broadband *struct {
				GatewayIPv4 string `json:"gateway_ipv4"`
				PrimaryDNS  string `json:"primary_dns"`
			} `json:"broadband"` // only what ispAddrs needs (rebuilds scan every snapshot)
			System *struct {
				UptimeSec int64 `json:"uptime_s"`
			} `json:"system"`
			Derived struct {
				Reachable  bool   `json:"reachable"`
				ISPNextHop string `json:"isp_next_hop"`
				ISPDNS     string `json:"isp_dns"`
			} `json:"derived"`
		}
		if json.Unmarshal(body.Data, &d) == nil && d.Derived.Reachable {
			rb.lastGoodSnapSeq = u64p(body.Seq)
			if len(d.Fiber) > 0 && string(d.Fiber) != "null" {
				rb.lastFiberSeq = u64p(body.Seq)
			}
			if d.System != nil && d.System.UptimeSec >= 0 {
				rb.lastUpSeq = u64p(body.Seq)
			}
			s := &model.GatewaySnapshot{}
			if b := d.Broadband; b != nil {
				s.Broadband = &model.BroadbandStatus{GatewayIPv4: b.GatewayIPv4, PrimaryDNS: b.PrimaryDNS}
			}
			s.Derived.ISPNextHop, s.Derived.ISPDNS = d.Derived.ISPNextHop, d.Derived.ISPDNS
			if hop, dns := ispAddrs(s); hop != "" || dns != "" {
				if hop != "" {
					rb.ispHop = hop
				}
				if dns != "" {
					rb.ispDNS = dns
				}
			}
		}
	case model.TypeAnchor:
		var a model.Anchor
		if json.Unmarshal(body.Data, &a) == nil {
			rb.lastAnchor, rb.lastUntrusted, rb.untrustedSince =
				nextAnchorTrust(rb.lastAnchor, rb.lastUntrusted, rb.untrustedSince, anchorRec{Seq: body.Seq, TS: body.TS, Anchor: a})
		}
	case model.TypeGatewayEvent:
		var ev model.GatewayEvent
		if json.Unmarshal(body.Data, &ev) != nil {
			return
		}
		switch {
		case ev.Kind == model.GwEvNotificationSetting && (ev.After == "on" || ev.After == "off"):
			rb.notif = &model.NotificationState{Enabled: ev.After == "on", CheckedAt: body.TS, Seq: body.Seq}
			rb.notifRecAt = body.TS
		case ev.Kind == model.GwEvCertChanged || ev.Kind == model.GwEvCertPinned:
			rb.certEvent = &certEventRec{Seq: body.Seq, TS: body.TS, After: ev.After}
		case ev.Kind == model.GwEvOpticalAlarm:
			rb.alarms = applyAlarmEvent(rb.alarms, ev, model.Ref{Seq: body.Seq, TS: body.TS})
		case ev.Kind == model.GwEvReboot:
			// After is the estimated boot time when both uptimes were readable (always, for a
			// reboot detected from the uptime).
			if boot, ok := parseTS(ev.After); ok {
				r := restartInfo{Boot: boot, Uptime: -1, EventSeq: body.Seq}
				r.Detected, _ = parseTS(body.TS)
				if n := len(ev.Evidence); n >= 2 {
					r.PrevSeq, r.SnapSeq = ev.Evidence[0], ev.Evidence[n-1]
				}
				rb.addRestart(r)
			}
		case ev.Kind == model.GwEvFirmwareChange:
			// Recorded right after the reboot event of the same snapshot.
			if n := len(ev.Evidence); n > 0 {
				for i := range rb.restarts {
					if r := &rb.restarts[i]; r.SnapSeq == ev.Evidence[n-1] {
						r.FWBefore, r.FWAfter, r.FWEventSeq = ev.Before, ev.After, body.Seq
					}
				}
			}
		}
	case model.TypeClockCheck:
		var cc model.ClockCheck
		if json.Unmarshal(body.Data, &cc) == nil {
			if ref := nextClockRef(rb.lastClock, body.Seq, body.TS, cc); ref != nil {
				rb.lastClock = ref
			}
		}
	case model.TypeConfigChange:
		var cc model.ConfigChange
		if json.Unmarshal(body.Data, &cc) == nil && cc.Target == "gateway" && strings.Contains(cc.What, "bbevent") &&
			!strings.HasPrefix(cc.Result, "failed") && (cc.After == "on" || cc.After == "off") {
			rb.notif = &model.NotificationState{Enabled: cc.After == "on", CheckedAt: body.TS, Seq: body.Seq}
			rb.notifRecAt = body.TS
		}
	}
}

// collectPoint adds a recent sample or snapshot to the chart/statistics history.
func (rb *rebuildState) collectPoint(body model.Body) {
	switch body.Type {
	case model.TypeSample:
		var s model.Sample
		if json.Unmarshal(body.Data, &s) != nil {
			return
		}
		start, ok := parseTS(s.Started)
		if !ok {
			if start, ok = parseTS(body.TS); !ok {
				return
			}
		}
		rb.points.addSample(start, &s)
	case model.TypeGatewaySnapshot:
		var d struct {
			Derived model.GatewayDerived `json:"derived"`
		}
		if json.Unmarshal(body.Data, &d) != nil || !d.Derived.Reachable {
			return
		}
		if ts, ok := parseTS(body.TS); ok {
			rb.points.addOptical(ts, d.Derived)
		}
	}
}

// rebuild restores incidents, custody facts, the latest snapshots, anchor and notification
// state, and 7 days of samples from the ledger (docs/PACKAGES.md "internal/monitor").
// Failures are logged: the monitor still starts, with whatever could be read.
func (m *Monitor) rebuild(now time.Time) {
	if m.reader == nil {
		m.log.Warn("no ledger reader: monitor state not rebuilt")
		return
	}
	t0 := time.Now()
	rb := &rebuildState{runID: m.runID, incidents: map[string]model.Incident{}, points: newPointStore(), alarms: map[string]alarmMark{}}
	cutoff := now.Add(-seriesKeep)
	cache, cached := m.loadCache()
	from := uint64(0)
	if cached {
		rb.fromCache(cache)
		from = cache.Seq + 1
	}
	err := m.reader.Scan(from, func(_ model.Envelope, body model.Body) error {
		rb.apply(body)
		if !cached {
			if ts, ok := parseTS(body.TS); ok && !ts.Before(cutoff) {
				rb.collectPoint(body)
			}
		}
		return nil
	})
	if err != nil {
		m.log.Error("ledger scan for state rebuild failed; state may be incomplete", "err", err)
	}
	if cached {
		if err := m.reader.ScanTime(cutoff, now.Add(24*time.Hour), func(_ model.Envelope, body model.Body) error {
			rb.collectPoint(body)
			return nil
		}); err != nil {
			m.log.Error("ledger scan for recent samples failed", "err", err)
		}
	}
	pending := m.pendingCert()
	lastSnap := m.loadSnapshot(rb.lastSnapSeq)
	lastGood := m.loadSnapshot(rb.lastGoodSnapSeq)
	lastFiber := lastGood
	if s := rb.lastFiberSeq; s != nil && (lastGood == nil || *s != lastGood.Seq) {
		lastFiber = m.loadSnapshot(s)
	}
	if !lastFiber.reachable() || lastFiber.Snap.Fiber == nil {
		lastFiber = nil
	}
	lastUp := lastGood
	if s := rb.lastUpSeq; s != nil && (lastGood == nil || *s != lastGood.Seq) {
		lastUp = m.loadSnapshot(s)
	}
	if !hasUptime(lastUp) {
		lastUp = nil
	}
	slices.SortStableFunc(rb.restarts, func(a, b restartInfo) int { return a.Boot.Compare(b.Boot) })

	m.mu.Lock()
	m.st.incidents = rb.incidents
	m.st.lastAnchor, m.st.notif = rb.lastAnchor, rb.notif
	m.st.lastUntrusted, m.st.untrustedSince = rb.lastUntrusted, rb.untrustedSince
	m.st.notifRecAt, _ = parseTS(rb.notifRecAt)
	m.st.lastUp = lastUp
	m.st.restarts = pruneRestarts(rb.restarts, now)
	m.st.lastStartRun, m.st.lastStopRun = rb.lastStartRun, rb.lastStopRun
	m.st.lastSampleTS, m.st.lastSampleSeq = rb.lastSampleTS, rb.lastSampleSeq
	m.st.points = rb.points
	m.st.lastSnap = lastSnap
	if lastGood != nil && lastGood.reachable() {
		m.st.lastGood = lastGood
		if hop, dns := ispAddrs(lastGood.Snap); rb.ispHop == "" || rb.ispDNS == "" {
			// A state cache from before these fields were cached, and no snapshot since.
			rb.ispHop, rb.ispDNS = cmp.Or(rb.ispHop, hop), cmp.Or(rb.ispDNS, dns)
		}
	}
	m.st.ispHop, m.st.ispDNS = rb.ispHop, rb.ispDNS
	m.st.certEvent = rb.certEvent
	if ce := rb.certEvent; ce != nil && pending != "" && strings.EqualFold(ce.After, pending) {
		m.st.certPendingSince, _ = parseTS(ce.TS)
		m.st.certPendingSeq, m.st.certPendingFP = ce.Seq, pending
	}
	m.st.lastFiber = lastFiber
	m.st.alarms = map[string]alarmMark{}
	if lastFiber != nil {
		// The flags the latest reading shows were first reported by the optical_alarm events
		// in the ledger; without one (it could not be recorded) the latest reading is all that
		// is known.
		for _, a := range lastFiber.Snap.Derived.Alarms {
			mk, ok := rb.alarms[a]
			if !ok || mk.Since.IsZero() {
				mk = alarmMark{Since: lastFiber.At, Seq: lastFiber.Seq}
			}
			m.st.alarms[a] = mk
		}
	}
	m.st.prevRunClock, m.st.lastClockRef = rb.lastClock, rb.lastClock
	nPts, nInc := len(rb.points.pts), len(rb.incidents)
	m.mu.Unlock()
	m.log.Info("monitor state rebuilt from the ledger", "from_seq", from, "cache", cached, "records_scanned", rb.records,
		"incidents", nInc, "samples_7d", nPts, "took", time.Since(t0))
}

// loadSnapshot reads one gateway_snapshot record.
func (m *Monitor) loadSnapshot(seq *uint64) *snapObs {
	if seq == nil {
		return nil
	}
	_, body, err := m.reader.Record(*seq)
	if err != nil || body.Type != model.TypeGatewaySnapshot {
		return nil
	}
	var s model.GatewaySnapshot
	if json.Unmarshal(body.Data, &s) != nil {
		return nil
	}
	at, ok := parseTS(body.TS)
	for _, p := range s.Pages { // the request time is closer to the observation than the record time
		if t, ok2 := parseTS(p.FetchedAt); ok2 && (!ok || t.Before(at)) {
			at, ok = t, true
		}
	}
	return &snapObs{Seq: *seq, At: at, Snap: &s}
}

func (m *Monitor) cachePath() string { return filepath.Join(m.opts.StateDir, cacheFileName) }

func (m *Monitor) loadCache() (*stateCache, bool) {
	if m.opts.StateDir == "" {
		return nil, false
	}
	b, err := os.ReadFile(m.cachePath())
	if err != nil {
		return nil, false
	}
	var c stateCache
	if err := json.Unmarshal(b, &c); err != nil || c.Version != cacheVersion {
		m.log.Warn("ignoring unreadable monitor state cache", "err", err)
		return nil, false
	}
	if c.Fingerprint != m.led.Fingerprint() {
		m.log.Warn("ignoring monitor state cache of another ledger key")
		return nil, false
	}
	env, _, err := m.reader.Record(c.Seq)
	if err != nil || env.H != c.Hash {
		m.log.Warn("ignoring monitor state cache that does not match the ledger", "seq", c.Seq)
		return nil, false
	}
	return &c, true
}

// writeCache saves the state cache (best effort; never evidence).
func (m *Monitor) writeCache() {
	if m.opts.StateDir == "" {
		return
	}
	fp := m.led.Fingerprint()
	c, gen := m.cacheSnapshot(fp)
	sort.Slice(c.Incidents, func(i, j int) bool { return c.Incidents[i].ID < c.Incidents[j].ID })

	b, err := json.Marshal(&c)
	if err != nil {
		m.log.Warn("cannot encode monitor state cache", "err", err)
		return
	}
	m.cacheMu.Lock()
	defer m.cacheMu.Unlock()
	if gen <= m.cacheWritten {
		return // a newer state was written meanwhile; never replace it with an older one
	}
	if err := writeFileAtomic(m.cachePath(), b); err != nil {
		if loud, n, since := m.cacheFailLog.fail(m.now(), cacheFailReport); loud {
			m.log.Warn("cannot write monitor state cache", "err", err, "failures", n, "since", since)
		} else {
			m.log.Debug("cannot write monitor state cache", "err", err, "failures", n)
		}
		return
	}
	m.cacheFailLog.ok()
	m.cacheWritten = gen
}

// cacheSnapshot copies the cached state together with the ledger head it is current up to.
// stMu guarantees that no append is half-applied while the state is copied.
func (m *Monitor) cacheSnapshot(fp string) (stateCache, uint64) {
	m.stMu.Lock()
	defer m.stMu.Unlock()
	m.cacheGen++
	gen := m.cacheGen
	head := m.led.Head()
	var c stateCache
	m.locked(func() {
		c = stateCache{
			Version:       cacheVersion,
			Fingerprint:   fp,
			Seq:           head.Seq,
			Hash:          head.Hash,
			Written:       fmtTS(m.now()),
			LastAnchor:    m.st.lastAnchor,
			Notification:  m.st.notif,
			LastStartRun:  m.st.lastStartRun,
			LastStopRun:   m.st.lastStopRun,
			LastSampleTS:  m.st.lastSampleTS,
			LastSampleSeq: m.st.lastSampleSeq,
		}
		for _, inc := range m.st.incidents {
			c.Incidents = append(c.Incidents, cloneIncident(inc))
		}
		if s := m.st.lastSnap; s != nil {
			c.LastSnapSeq = u64p(s.Seq)
		}
		if s := m.st.lastGood; s != nil {
			c.LastGoodSnapSeq = u64p(s.Seq)
		}
		if s := m.st.lastFiber; s != nil {
			c.LastFiberSnapSeq = u64p(s.Seq)
		}
		if s := m.st.lastUp; s != nil {
			c.LastUpSnapSeq = u64p(s.Seq)
		}
		c.ISPHop, c.ISPDNS = m.st.ispHop, m.st.ispDNS
		c.CertEvent = m.st.certEvent
		c.Restarts = slices.Clone(m.st.restarts)
		c.LastUntrusted, c.UntrustedSince = m.st.lastUntrusted, m.st.untrustedSince
		if !m.st.notifRecAt.IsZero() {
			c.NotificationRecordedAt = fmtTS(m.st.notifRecAt)
		}
		c.Alarms = maps.Clone(m.st.alarms)
		c.LastClock = m.st.lastClockRef
	})
	return c, gen
}

func writeFileAtomic(path string, b []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	if _, err := f.Write(b); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}
