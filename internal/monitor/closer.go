package monitor

import (
	"context"
	"slices"

	"attmonitor/internal/model"
)

// closerLoop runs the close procedure of docs/DESIGN.md §10 for incidents the state machine
// has closed: snapshot (which may reveal a gateway restart), traceroute, incident_close, then
// an immediate anchor.
func (m *Monitor) closerLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-m.kClose.ch:
		}
		m.kClose.take()
		for ctx.Err() == nil {
			st := m.nextClosing()
			if st == nil {
				break
			}
			m.safely("closer", func() { m.finishClose(ctx, st, true) })
			m.dropClosing(st) // no-op unless finishClose panicked before removing it
		}
	}
}

// finishClosings finalizes, without network I/O, every incident still waiting for its close
// record (used when the monitor stops).
func (m *Monitor) finishClosings(ctx context.Context) {
	for st := m.nextClosing(); st != nil; st = m.nextClosing() {
		m.safely("closer", func() { m.finishClose(ctx, st, false) })
		m.dropClosing(st)
	}
}

func (m *Monitor) nextClosing() *incState {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.st.closing) == 0 {
		return nil
	}
	return m.st.closing[0]
}

func (m *Monitor) dropClosing(st *incState) {
	m.locked(func() {
		m.st.closing = slices.DeleteFunc(m.st.closing, func(x *incState) bool { return x == st })
	})
}

// boundWatch drops the oldest watched incidents beyond maxRebootWatch incidents or twice
// maxIncCycles cycle records in all (the newest one is always kept).
func boundWatch(w []*incState) []*incState {
	total := 0
	for _, st := range w {
		total += len(st.cycles)
	}
	drop := 0
	for len(w)-drop > 1 && (len(w)-drop > maxRebootWatch || total > 2*maxIncCycles) {
		total -= len(w[drop].cycles)
		drop++
	}
	if drop == 0 {
		return w
	}
	return slices.Clone(w[drop:])
}

// finishClose writes incident_close for st. With withIO it first takes the close snapshot
// and traceroutes (evidence of the recovered state; a readable uptime in the snapshot also
// tells whether the gateway restarted during the incident, DESIGN §10) and anchors
// afterwards. st always leaves the closing list.
func (m *Monitor) finishClose(ctx context.Context, st *incState, withIO bool) {
	if withIO && ctx.Err() == nil {
		m.safely("close-evidence", func() {
			m.takeSnapshot(ctx, trigIncidentClose, st) // learns restarts (st is in the closing list)
			m.runTraceroutes(ctx, "incident_close", st.inc.ID, st)
		})
	}
	inc, err := m.appendIncident(model.TypeIncidentClose, st, nil, func(model.Incident) {
		m.st.closing = slices.DeleteFunc(m.st.closing, func(x *incState) bool { return x == st })
		if !st.restartDecided {
			// No readable uptime since the incident ended: a restart during it is often learned
			// only from the next successful snapshot, which then records an incident_update.
			// Bounded: if sysinfo stays unreadable, the oldest undecided incidents are dropped
			// (they keep the classification of their close record).
			m.st.rebootWatch = boundWatch(append(m.st.rebootWatch, st))
		}
	})
	if err != nil {
		// Not recorded (ledger failure). Drop it from memory anyway so shutdown cannot loop; the
		// next start closes the incident from its open/update record.
		m.dropClosing(st)
		return
	}
	m.log.Warn("incident closed", "id", inc.ID, "state", inc.State, "cause", inc.Cause,
		"attribution", inc.Attribution, "duration_s", inc.DurationSec)
	if withIO && ctx.Err() == nil {
		m.writeCache()
		if m.anchorer != nil {
			if anchors, err := m.anchor(ctx, "incident_close"); len(anchors) == 0 {
				m.log.Warn("anchoring after incident close failed; the next anchor will cover it", "err", err)
			}
		}
	}
}
