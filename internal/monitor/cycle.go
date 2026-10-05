package monitor

import (
	"context"
	"fmt"
	"net"
	"slices"
	"time"

	"attmonitor/internal/model"
)

// clockJumpThreshold: wall and monotonic time diverging by more than this between two cycles
// is recorded as a clock_jump (docs/DESIGN.md §7).
const clockJumpThreshold = 2 * time.Second

func (m *Monitor) cycleLoop(ctx context.Context) {
	next := time.Now()
	for {
		if !sleepUntil(ctx, next, nil) {
			return
		}
		m.safely("cycle", func() { m.runCycle(ctx) })
		next = next.Add(m.set.fast)
		if now := time.Now(); next.Before(now) {
			next = now // fell behind (sleep, stall): run now, do not replay missed cycles
		}
	}
}

func (m *Monitor) runCycle(ctx context.Context) {
	specs := m.probeSpecs()
	start := m.now()
	results := m.runProbes(ctx, specs)
	if ctx.Err() != nil {
		return // shutting down: cancelled probes say nothing about the network
	}
	m.processCycle(ctx, start, m.now().Sub(start), results)
}

// probeSpecs resolves runtime targets (docs/DESIGN.md §8): gateway probes use the gateway
// host (TCP port 443, or 80 for http), the ISP hop uses the last next hop reported by the
// gateway and is omitted while unknown.
func (m *Monitor) probeSpecs() []model.ProbeSpec {
	m.mu.Lock()
	hop := m.st.ispHop
	m.mu.Unlock()
	out := make([]model.ProbeSpec, 0, len(m.set.targets))
	for _, sp := range m.set.targets {
		if sp.Target == "" {
			switch sp.Role {
			case model.RoleGateway:
				if sp.Kind == model.KindTCP {
					port := "443"
					if m.set.gwScheme == "http" {
						port = "80"
					}
					sp.Target = net.JoinHostPort(m.set.gwHost, port)
				} else {
					sp.Target = m.set.gwHost
				}
			case model.RoleISPHop:
				if hop == "" || sp.Kind != model.KindICMP {
					continue
				}
				sp.Target = hop
			default:
				continue // an internet probe needs an explicit target
			}
		}
		out = append(out, sp)
	}
	return out
}

// runProbes runs every probe concurrently. A probe that does not return within its timeout
// plus a margin is recorded as failed so that one misbehaving probe cannot stall the cycle.
func (m *Monitor) runProbes(ctx context.Context, specs []model.ProbeSpec) []model.ProbeResult {
	timeout := m.set.probeTimeout
	type res struct {
		i int
		r model.ProbeResult
	}
	ch := make(chan res, len(specs)) // buffered: late probes never block
	pctx, cancel := context.WithTimeout(ctx, timeout+time.Second)
	defer cancel()
	for i, sp := range specs {
		go func() {
			var r model.ProbeResult
			defer func() {
				if p := recover(); p != nil {
					m.log.Error("probe panic recovered", "probe", sp.Name, "panic", fmt.Sprint(p))
					r = model.ProbeResult{Err: fmt.Sprintf("probe panicked: %v", p)}
				}
				ch <- res{i, r}
			}()
			switch sp.Kind {
			case model.KindTCP:
				r = m.prober.TCP(pctx, sp.Target, timeout)
			case model.KindICMP:
				r = m.prober.Ping(pctx, sp.Target, timeout)
			default:
				r = model.ProbeResult{Err: "unsupported probe kind " + sp.Kind}
			}
		}()
	}
	results := make([]model.ProbeResult, len(specs))
	done := make([]bool, len(specs))
	deadline := time.NewTimer(timeout + m.probeGrace)
	defer deadline.Stop()
collect:
	for got := 0; got < len(specs); {
		select {
		case x := <-ch:
			results[x.i], done[x.i] = x.r, true
			got++
		case <-deadline.C:
			for i := range specs {
				if !done[i] {
					results[i] = model.ProbeResult{Err: "probe did not complete in time"}
				}
			}
			break collect
		}
	}
	for i, sp := range specs {
		r := &results[i]
		r.Name, r.Kind, r.Role = sp.Name, sp.Kind, sp.Role
		if r.Target == "" {
			r.Target = sp.Target
		}
		if !r.OK {
			r.RTTus = 0
		}
	}
	return results
}

// maxCycleDur is the longest a cycle may take before it counts as interrupted (system sleep, a
// stall of this computer): its probe deadline (timeout + grace, after which runProbes returns
// whatever it has) plus a margin of half a fast interval, at least one second.
func (m *Monitor) maxCycleDur() time.Duration {
	return m.set.probeTimeout + m.probeGrace + max(m.set.fast/2, time.Second)
}

// interruptedVerdict is the verdict of a cycle that took longer than maxCycleDur (DESIGN §9,
// rules 2026.10-4): its probes were cut short by system sleep or a stall of this computer, so
// they say nothing about the network - UNKNOWN, neither good nor bad.
func interruptedVerdict(dur, limit time.Duration) model.Verdict {
	return model.Verdict{State: model.StateUnknown, Attribution: model.AttrUndetermined,
		Reasons: []string{fmt.Sprintf("this cycle took %s, longer than the %s its probes may take: monitoring was interrupted while they were in flight (for example by system sleep), so their results say nothing about the network",
			dur.Round(time.Millisecond), limit)},
		Inputs: &model.VerdictInputs{WindowCycles: 1}, Rules: RulesVersion}
}

// processCycle classifies and records one cycle and drives the incident state machine.
//
// A cycle that took longer than maxCycleDur (dur is measured with the monotonic clock, which on
// Windows includes system sleep) was interrupted while its probes were in flight: the
// interruption is handled like a monitoring gap before the cycle - an open incident is closed at
// its last observation, the window and the state history restart - and the cycle is recorded
// as UNKNOWN, so neither its timed-out probes nor the time it was recorded (after the
// interruption) become part of any incident.
func (m *Monitor) processCycle(ctx context.Context, start time.Time, dur time.Duration, results []model.ProbeResult) {
	prevStart := m.checkContinuity(start)
	limit := m.maxCycleDur()
	interrupted := dur > limit
	if interrupted {
		elapsed := time.Duration(0)
		if !prevStart.IsZero() {
			elapsed = start.Sub(prevStart)
		}
		m.interruption(discontinuity{gap: dur, elapsed: elapsed})
		// The time after this cycle is not a gap again for the next cycle's continuity check.
		m.locked(func() { m.st.prevCycleStart = start.Add(dur) })
	}

	m.mu.Lock()
	// The window is committed only when the sample is recorded (below): a verdict may depend
	// only on cycles a verifier can find in the ledger. Likewise the snapshot, service check
	// and local link are the latest *recorded* ones, taken together with their seqs in this one
	// critical section: Classify reports exactly the ones it used in Verdict.Inputs.
	window := append(slices.Clone(m.st.window), results)
	if n := m.set.incident.WindowCycles; len(window) > n {
		window = window[len(window)-n:]
	}
	in := m.classifyInputLocked(start, results, window)
	m.mu.Unlock()

	var v model.Verdict
	if interrupted {
		v = interruptedVerdict(dur, limit)
		window = nil // cut-short probes never enter the loss window
	} else {
		v = Classify(in, m.set.incident)
	}

	var (
		cycleNo    uint64
		tag        string
		prevV      model.Verdict
		openBefore bool
	)
	m.locked(func() {
		m.st.cycles++
		cycleNo = m.st.cycles
		tag = m.st.tracker.peekTag(start, v)
		prevV = m.st.lastVerdict
		openBefore = m.st.tracker.open != nil
	})

	sample := model.Sample{
		Cycle:      cycleNo,
		Started:    fmtTS(start),
		DurMs:      dur.Milliseconds(),
		Probes:     results,
		Verdict:    v,
		IncidentID: tag,
	}
	sref, err := m.appendApply(model.TypeSample, sample, nil, func(ref model.Ref) {
		s := sample
		m.st.window = window
		m.st.lastSample = &s
		m.st.lastVerdict = v
		m.st.lastSampleTS, m.st.lastSampleSeq = ref.TS, ref.Seq
		m.st.lastSampleRecAt = m.now()
		m.st.points.addSample(start, &s)
		m.st.points.prune(start.Add(-seriesKeep))
	})
	if err != nil {
		return // nothing can be built on a cycle that is not in the ledger
	}

	var refs []model.EvidenceRef
	from := prevV.State
	if from == "" {
		from = model.StateUnknown
	}
	if (v.State != prevV.State || v.Cause != prevV.Cause) && !(from == v.State && prevV.Cause == v.Cause) {
		sc := model.StateChange{FromState: from, FromCause: prevV.Cause, ToState: v.State, ToCause: v.Cause,
			At: fmtTS(start), Cycle: cycleNo, Reasons: v.Reasons}
		r, err := m.appendApply(model.TypeStateChange, sc, nil, func(model.Ref) {
			if v.State != prevV.State { // "since" is when the current state (not cause) began
				m.st.since = start
			}
		})
		if err == nil {
			refs = append(refs, model.EvidenceRef{Seq: r.Seq, Type: model.TypeStateChange,
				Note: fmt.Sprintf("%s → %s", stateCause(from, prevV.Cause), stateCause(v.State, v.Cause))})
		}
	}

	ts, ok := parseTS(sref.TS)
	if !ok {
		ts = start
	}
	obs := cycleObs{Start: start, TS: ts, Seq: sref.Seq, Verdict: v, Probes: results, Refs: refs}
	var acts []action
	m.locked(func() {
		acts = m.st.tracker.observe(obs)
		if o := m.st.tracker.open; o != nil && openBefore {
			for _, r := range refs {
				o.ev.add(r)
			}
		}
	})
	m.handleActions(acts)

	// "Gateway snapshot immediately when a cycle first goes bad" (§8); a fresh look at the
	// local link helps the next cycles tell a Wi-Fi drop from a gateway failure.
	if isBad(v.State) && !isBad(prevV.State) && !openBefore {
		m.kGateway.kick("cycle_failure")
		m.kLink.kick("cycle_failure")
	}
}

func stateCause(state, cause string) string {
	if cause == "" {
		return state
	}
	return state + "/" + cause
}

// checkContinuity records clock jumps and handles monitoring gaps between cycles. It returns
// the previous cycle's start (zero for the first cycle).
func (m *Monitor) checkContinuity(start time.Time) time.Time {
	m.mu.Lock()
	prev := m.st.prevCycleStart
	m.st.prevCycleStart = start
	m.mu.Unlock()
	if prev.IsZero() {
		return prev
	}
	wall := start.Round(0).Sub(prev.Round(0)) // wall clock only
	mono := start.Sub(prev)                   // monotonic when both readings have it
	m.continuity(wall, mono)
	return prev
}

// classifyInputLocked assembles the classifier's input for a cycle that started at start: the
// cycle, its window and the latest recorded snapshot, service checks and local link (with their
// seqs and ages). Caller holds mu.
func (m *Monitor) classifyInputLocked(start time.Time, results []model.ProbeResult, window [][]model.ProbeResult) ClassifyInput {
	in := ClassifyInput{Cycle: results, Window: window}
	if g := m.st.lastGood; g != nil {
		in.Snapshot, in.SnapshotAge, in.SnapshotSeq = g.Snap, start.Sub(g.At), g.Seq
	}
	if m.st.lastService != nil {
		in.Service, in.ServiceAge, in.ServiceSeq = m.st.lastService, start.Sub(m.st.lastServiceAt), m.st.lastServiceSeq
		if p := m.st.prevService; p != nil {
			in.PrevService, in.PrevServiceGap, in.PrevServiceSeq = p, m.st.lastServiceAt.Sub(m.st.prevServiceAt), m.st.prevServiceSeq
		}
	}
	if m.st.lastLinkRec != nil {
		in.Link, in.LinkAge, in.LinkSeq = m.st.lastLinkRec, start.Sub(m.st.lastLinkRecAt), m.st.lastLinkRecSeq
		in.Egress = m.st.lastLinkRec.Egress
	}
	if a, b := m.st.prevCtr, m.st.lastCtr; a != nil && b != nil {
		in.Traffic = wanTrafficOf(a, b)
		in.TrafficAge = start.Sub(b.At)
	}
	return in
}

// clockJumpOf returns the clock_jump payload when the wall clock and the monotonic clock
// advanced differently by more than clockJumpThreshold, else nil.
func clockJumpOf(wall, mono time.Duration) *model.ClockJump {
	if absDur(wall-mono) <= clockJumpThreshold {
		return nil
	}
	return &model.ClockJump{WallDeltaMs: wall.Milliseconds(), MonoDeltaMs: mono.Milliseconds(), JumpMs: (wall - mono).Milliseconds()}
}

// continuity acts on the wall and monotonic time elapsed since the previous cycle.
//
//   - The monotonic clock advancing beyond the gap limit means monitoring really stopped
//     (Go's monotonic clock on Windows is the interrupt time, which includes system sleep):
//     the open incident is closed as interrupted, the loss window and the state history
//     restart (nothing is known about the state in between).
//   - Otherwise a wall-clock step beyond the gap limit, forward or backward, means
//     monitoring went on but the record times jump: the open incident is closed at its last
//     observation so that no incident straddles the step (its duration would be wrong, even
//     negative), and the summary says that the clock was stepped, not that monitoring stopped.
func (m *Monitor) continuity(wall, mono time.Duration) {
	if cj := clockJumpOf(wall, mono); cj != nil {
		if _, err := m.appendApply(model.TypeClockJump, cj, nil, nil); err == nil {
			m.log.Warn("clock jump", "wall_delta", wall, "mono_delta", mono)
		}
		// The step moved this computer's clock against the time servers: measure it again
		// (CLOCK_OFFSET), within the clock worker's floor between checks.
		m.kClock.kick(kickClockJump)
	}
	limit := gapLimit(m.set.fast)
	d := discontinuity{elapsed: mono}
	switch {
	case mono > limit:
		d.gap = mono
	case wall > limit || absDur(wall-mono) > limit:
		d.step = wall - mono
	default:
		return
	}
	m.interruption(d)
}

// interruption acts on a discontinuity: a monitoring gap (between cycles, or inside a cycle
// whose probes were cut short) restarts the loss window and the state history; any
// discontinuity closes the open incident at its last observation (tracker.interrupt).
func (m *Monitor) interruption(d discontinuity) {
	var acts []action
	m.locked(func() {
		if d.gap > 0 {
			m.st.window = nil
			m.st.lastVerdict = model.Verdict{} // the next cycle starts a new state history
		}
		acts = m.st.tracker.interrupt(d)
	})
	if d.gap > 0 {
		m.log.Warn("monitoring gap", "gap", d.gap)
	} else {
		m.log.Warn("wall clock stepped between cycles; open incident closed at the step", "step", d.step)
	}
	m.handleActions(acts)
}

// handleActions records what the incident state machine decided.
func (m *Monitor) handleActions(acts []action) {
	for _, a := range acts {
		switch a.kind {
		case actOpen:
			m.recordOpen(a.st)
		case actUpdate:
			if inc, err := m.appendIncident(model.TypeIncidentUpdate, a.st, nil, nil); err == nil {
				m.log.Warn("incident updated", "id", inc.ID, "state", inc.State, "cause", inc.Cause)
			}
		case actClose:
			m.locked(func() { m.st.closing = append(m.st.closing, a.st) })
			m.kClose.kick("close")
		}
	}
}

func (m *Monitor) recordOpen(st *incState) {
	// A gateway restart learned while the first bad cycles were still blips belongs to the
	// incident as well (DESIGN §10): it is attached before the open record is built.
	inc, err := m.appendIncident(model.TypeIncidentOpen, st, func() {
		for _, r := range m.st.restarts {
			m.attachRestartLocked(st, r)
		}
	}, nil)
	if err != nil {
		return
	}
	m.log.Warn("incident opened", "id", inc.ID, "state", inc.State, "cause", inc.Cause, "attribution", inc.Attribution)
	// §10 "On open": immediate snapshot (raw stored), service check, local link, traceroutes.
	m.kGateway.kick("incident")
	m.kService.kick("incident")
	m.kLink.kick("incident")
	m.requestTraceroute("incident_open", inc.ID)
}
