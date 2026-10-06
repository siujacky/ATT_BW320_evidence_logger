package monitor

import (
	"context"
	"errors"
	"fmt"
	"time"

	"attmonitor/internal/model"
)

// The flow meter (docs/syslog-snmp-traffic.md §3.3): the dashboard's current download and upload
// rates while it is open. LiveTraffic reads the gateway's WAN counters on demand - its
// unauthenticated Broadband Status page, the page every gateway poll reads - at most once every
// liveEvery after the previous read ended, whoever asks (callers that arrive during a read wait
// for it and all get its outcome), and computes the rates against the previous read with the
// traffic math of the household-traffic rule (wanTrafficOf: a 32-bit byte counter that wrapped,
// counters that were reset, "at least" when a wrap is ambiguous). This computer's rates come from
// the newest local-link readings the monitor already has. It is a display, not evidence: nothing
// of it is recorded, stored or fed into the monitor's state, and while nobody asks the gateway
// gets no extra request. The evidence comes first: a read never waits for the gateway lock (it
// is skipped while a poll or another gateway operation holds it), holds it for at most
// liveTimeout, and is not made while the newest recorded snapshot found the gateway unreachable.
// (The gateway client's TLS pin policy applies to these reads as to any other: a changed
// certificate is reported by the first request that meets it.)

// trigLive is the trigger of the flow meter's gateway reads (never recorded).
const trigLive = "live"

const (
	// liveMinInterval is the shortest time from the end of a flow-meter read of the gateway to
	// the start of the next (Monitor.liveEvery).
	liveMinInterval = 5 * time.Second
	// liveReadTimeout bounds a flow-meter read of the gateway (Monitor.liveTimeout): an evidence
	// snapshot that needs the gateway lock meanwhile waits at most this long. The Broadband
	// Status page normally answers within a second.
	liveReadTimeout = 5 * time.Second
	// liveHistory is how long the flow meter keeps its readings (Monitor.liveKeep).
	liveHistory = 15 * time.Minute
	// maxLivePoints bounds the flow meter's history whatever the read interval.
	maxLivePoints = 256
	// liveMaxSpan bounds the time between the two counter readings a live rate comes from. A live
	// read has no uptime to tell a gateway restart (counters reset) from a wrap, as the recorded
	// snapshots have; over this short a time a reset implies more packets per second than any
	// line carries (maxPacketRate), so wanTrafficOf still tells it.
	liveMaxSpan = 2 * time.Minute
)

// liveCall is a flow-meter read in progress; done is closed when it has finished.
type liveCall struct{ done chan struct{} }

// livePoint is a reading of the flow meter's history with its time.
type livePoint struct {
	at time.Time
	p  model.LivePoint
}

// liveState is the flow meter's state (guarded by liveMu).
type liveState struct {
	call    *liveCall         // the read in progress (nil: none)
	ended   time.Time         // when the latest read ended (monotonic)
	prev    *snapObs          // the latest read that gave the gateway's counters
	view    model.LiveTraffic // the newest readings (History aside)
	history []livePoint       // oldest first
}

// LiveTraffic implements contracts.LiveTrafficSource: the flow meter's newest readings and their
// recent history (about liveKeep, oldest first). When the latest read of the gateway ended at
// least liveEvery ago a new one starts; a caller that arrives while a read is in progress waits
// for it; otherwise the latest readings are returned at once. A read that fails or is skipped
// (liveSnapshot) keeps the previous readings (At says when they were taken) and says why in Err.
// When ctx ends before the read, the latest readings are returned with ctx's error (the read goes
// on for later callers).
func (m *Monitor) LiveTraffic(ctx context.Context) (model.LiveTraffic, error) {
	m.liveMu.Lock()
	call := m.live.call
	if call == nil && (m.live.ended.IsZero() || time.Since(m.live.ended) >= m.liveEvery) {
		call = &liveCall{done: make(chan struct{})}
		m.live.call = call
		go m.liveRead(call)
	}
	m.liveMu.Unlock()
	if call != nil {
		select {
		case <-call.done:
		case <-ctx.Done():
			return m.liveView(), ctx.Err()
		}
	}
	return m.liveView(), nil
}

// liveRead makes the read call stands for and publishes its outcome.
func (m *Monitor) liveRead(call *liveCall) {
	defer func() {
		m.liveMu.Lock()
		m.live.call, m.live.ended = nil, time.Now()
		m.liveMu.Unlock()
		close(call.done)
	}()
	m.safely("live-traffic", func() {
		snap, err := m.liveSnapshot()
		m.liveUpdate(snap, err)
	})
}

// errLiveBusy: the flow meter left the gateway alone because the monitor itself was reading it.
var errLiveBusy = errors.New("skipped: the monitor was reading the gateway for its evidence, which comes first; the next reading follows within seconds")

// liveSnapshot reads the gateway's Broadband Status page for the flow meter. Like every gateway
// request it holds the gateway lock (one request at a time, never during an authenticated
// operation), but it never waits for it: while a poll or another gateway operation holds the
// lock the read is skipped (errLiveBusy), and it holds the lock for at most liveTimeout, so the
// evidence snapshots - every 15 s during an incident - are delayed by liveTimeout at most. It is
// not made at all while the newest recorded snapshot found the gateway unreachable: it would
// only wait for its timeout, and the next poll tells when the gateway answers again. The reads
// end with Run. The page is neither stored nor recorded.
func (m *Monitor) liveSnapshot() (model.GatewaySnapshot, error) {
	ctx := context.Background()
	if p := m.runCtx.Load(); p != nil {
		ctx = *p
	}
	if err := ctx.Err(); err != nil {
		return model.GatewaySnapshot{}, fmt.Errorf("the monitor has stopped: %w", err)
	}
	var last *snapObs
	m.locked(func() { last = m.st.lastSnap })
	if last != nil && !last.reachable() {
		return model.GatewaySnapshot{}, fmt.Errorf("not read: the gateway did not answer the monitor's latest poll (%s); the flow meter reads it again once a poll reaches it",
			fmtHuman(last.At))
	}
	if !m.gwMu.TryLock() {
		return model.GatewaySnapshot{}, errLiveBusy
	}
	defer m.gwMu.Unlock()
	if err := ctx.Err(); err != nil {
		return model.GatewaySnapshot{}, fmt.Errorf("the monitor has stopped: %w", err)
	}
	sctx, cancel := context.WithTimeout(ctx, m.liveTimeout)
	defer cancel()
	snap, _, err := m.gw.Snapshot(sctx, []string{"broadbandstatistics"}, trigLive)
	return snap, err
}

// liveUpdate turns a flow-meter read into readings: the WAN rates against the previous read -
// or, when that gives none (no read within liveMaxSpan, counters reset), against the newest
// snapshot with counters the monitor recorded, which is only read - this computer's rates from
// its newest local-link readings, and a point of the history. A failed read only sets Err.
func (m *Monitor) liveUpdate(snap model.GatewaySnapshot, err error) {
	now := m.now()
	if err == nil && (snap.Broadband == nil || len(snap.Broadband.Counters) == 0) {
		err = fmt.Errorf("the gateway's Broadband Status page showed no WAN counters%s", pageErrors(&snap))
	}
	var (
		recorded   *snapObs
		pcRx, pcTx *float64
	)
	m.locked(func() {
		recorded = m.st.lastCtr
		pcRx, pcTx = m.st.points.latestPC(now, 2*m.set.linkInterval)
	})
	m.liveMu.Lock()
	defer m.liveMu.Unlock()
	if err != nil {
		m.live.view.Err = errText(err)
		return
	}
	cur := &snapObs{At: now, Snap: &snap}
	at := ctrAt(cur)
	v := model.LiveTraffic{At: fmtTS(at), PCRx: pcRx, PCTx: pcTx}
	for _, base := range []*snapObs{m.live.prev, recorded} {
		if base == nil || at.Sub(ctrAt(base)) > liveMaxSpan {
			continue
		}
		if w := wanTrafficOf(base, cur); w.Err == "" {
			v.IntervalS = round3(w.Dur.Seconds())
			v.WANRx, v.WANTx = chartRate(w.RxMbps), chartRate(w.TxMbps)
			v.AtLeast = w.RxAtLeast || w.TxAtLeast
			break
		}
	}
	m.live.prev, m.live.view = cur, v
	m.addLivePointLocked(at, v)
}

// addLivePointLocked adds readings with a rate to the history and drops the points more than
// liveKeep older than them, keeping at most maxLivePoints. Caller holds liveMu.
func (m *Monitor) addLivePointLocked(at time.Time, v model.LiveTraffic) {
	if v.WANRx == nil && v.WANTx == nil && v.PCRx == nil && v.PCTx == nil {
		return
	}
	h := append(m.live.history, livePoint{at: at, p: model.LivePoint{T: v.At, WANRx: v.WANRx, WANTx: v.WANTx, PCRx: v.PCRx, PCTx: v.PCTx}})
	drop := 0
	for drop < len(h) && (len(h)-drop > maxLivePoints || at.Sub(h[drop].at) > m.liveKeep) {
		drop++
	}
	m.live.history = dropFront(h, drop)
}

// liveView copies the flow meter's newest readings with their history.
func (m *Monitor) liveView() model.LiveTraffic {
	m.liveMu.Lock()
	defer m.liveMu.Unlock()
	v := m.live.view
	if len(m.live.history) > 0 {
		v.History = make([]model.LivePoint, len(m.live.history))
		for i, p := range m.live.history {
			v.History[i] = p.p
		}
	}
	return v
}

// latestPC returns this computer's rates over the newest interval of its counters, when that
// interval is known and ended no more than maxAge before now.
func (ps *pointStore) latestPC(now time.Time, maxAge time.Duration) (rx, tx *float64) {
	n := len(ps.pc)
	if n == 0 {
		return nil, nil
	}
	iv := ps.pc[n-1]
	if age := now.UnixNano() - iv.to; !iv.known || age < 0 || age > int64(maxAge) {
		return nil, nil
	}
	return chartRate(iv.rxMbps), chartRate(iv.txMbps)
}
