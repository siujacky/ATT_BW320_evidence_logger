package monitor

import (
	"fmt"
	"sort"
	"time"

	"attmonitor/internal/model"
)

// Gateway restarts (docs/DESIGN.md §10, rules 2026.10-4).
//
// A restart is detected from the gateway's own uptime and recorded as gateway_event "reboot"
// (boot time B = fetch time - uptime moved by more than rebootMoveThreshold, or the uptime
// fell). Its restart window runs from B, extended back over the cycles in which the gateway was
// unreachable just before B (the power-off/boot period), until the first cycle after B in
// which the Internet was reachable again, capped at B + restartCap - over every recorded cycle,
// the same window for incident records and statistics. A restart belongs to every incident with
// a bad cycle inside its window (also when the boot came before the incident's first observed
// cycle, e.g. after a power failure that also stopped this computer) or whose span contains the
// boot. Bad cycles inside a restart window are restart time, never provider downtime; an
// incident with a restart is the provider's only through at least OpenAfterCycles
// provider-attributed bad cycles outside every restart window (as many as it takes to open an
// incident: fewer are stray cycles of the restart's own shutdown or bring-up), or through a
// firmware change across the restart (an AT&T-pushed update). Samples keep their real-time
// verdicts: the restart rules only shape incident records and statistics.

// restartCap bounds a restart window after the boot (DESIGN §10: B + 10 min).
const restartCap = 10 * time.Minute

// restartInfo is one gateway restart detected from the gateway's uptime.
type restartInfo struct {
	Boot       time.Time `json:"boot"`                        // estimated boot time B
	Detected   time.Time `json:"detected"`                    // fetch time of the page that revealed it
	Uptime     int64     `json:"uptime_s"`                    // uptime that page reported (-1: unknown)
	EventSeq   uint64    `json:"event_seq,omitempty"`         // gateway_event "reboot"
	SnapSeq    uint64    `json:"snapshot_seq,omitempty"`      // gateway_snapshot that revealed it
	PrevSeq    uint64    `json:"prev_snapshot_seq,omitempty"` // latest earlier snapshot with a readable uptime
	FWBefore   string    `json:"fw_before,omitempty"`
	FWAfter    string    `json:"fw_after,omitempty"`
	FWEventSeq uint64    `json:"fw_event_seq,omitempty"` // gateway_event "firmware_change", if recorded

	// lead is what the cycles recorded before the first cycle of the incident this copy is
	// attached to say about the restart window (set by Monitor.attachRestartLocked; never cached).
	lead restartLead
}

// restartLead is the part of a restart window that lies before an incident's first cycle.
// DESIGN §10 defines the window over every recorded cycle, while an incident keeps only its own
// cycles: when the boot precedes the incident, the cycles between the boot and the incident
// decide where the window starts (the unreachable cycles just before the boot) and whether it
// already ended (the Internet was reachable again, or the 10-minute cap passed) before the
// incident began. Those cycles never change after the incident opened, so the lead is computed
// once, from the monitor's cycle history, when the restart is attached. A zero lead (no history,
// e.g. in a test) means that no cycle is known between the boot and the incident.
type restartLead struct {
	known    bool
	from     time.Time // window start (the boot, or the first of the unreachable cycles before it)
	back     bool      // from was extended back over unreachable cycles
	end      winEnd    // endOpen: the window reaches the incident's first cycle
	to       time.Time // window end when end != endOpen
	firstPre time.Time // start of the incident's first cycle the lead was computed for
}

// leadOf computes the restart lead of a boot over the cycles recorded before an incident's first
// cycle (first), ordered by start (the same rules as restartSpan; unreachable reports a rule-1
// cycle, inet one that reached the Internet). A boot at or after first has no lead.
func leadOf(n int, start func(int) time.Time, unreachable, inet func(int) bool, boot, first time.Time, gap time.Duration) restartLead {
	if !boot.Before(first) {
		return restartLead{}
	}
	k := sort.Search(n, func(i int) bool { return !start(i).Before(first) }) // cycles before the incident
	w := restartSpan(k, start, unreachable, inet, boot, gap)
	l := restartLead{known: true, from: w.from, back: w.back, end: w.end, to: w.to, firstPre: first}
	if l.end == endOpen && !first.Before(boot.Add(restartCap)) {
		// No cycle between the boot and the cap, and the incident began after the cap.
		l.end, l.to = endCap, boot.Add(restartCap)
	}
	return l
}

// fwChanged: the gateway came back from the restart with another firmware version.
func (r restartInfo) fwChanged() bool {
	return r.FWBefore != "" && r.FWAfter != "" && r.FWBefore != r.FWAfter
}

// sameRestart: the same reboot record, or boot estimates too close to be two restarts.
func sameRestart(a, b restartInfo) bool {
	if a.EventSeq != 0 && a.EventSeq == b.EventSeq {
		return true
	}
	return absDur(a.Boot.Sub(b.Boot)) <= rebootMoveThreshold
}

// restartSlack bounds how far a boot may lie outside an incident's span and still belong to
// it: the gateway can go down up to one fast interval before the first failed probe, and the
// boot estimate (fetch time - whole seconds of uptime) is only accurate to a few seconds.
func restartSlack(fast time.Duration) (before, after time.Duration) {
	return fast + 10*time.Second, 10 * time.Second
}

// winEnd says how a restart window ends.
type winEnd uint8

const (
	endOpen     winEnd = iota // no cycle after the boot reached the Internet yet and the cap is not reached
	endInternet               // the first cycle after the boot in which the Internet was reachable
	endCap                    // B + restartCap
)

// restartWin is the restart window [from, to) of one restart.
type restartWin struct {
	from, to time.Time
	end      winEnd
	back     bool // from was extended back over unreachable cycles before the boot
}

func (w restartWin) contains(t time.Time) bool { return !t.Before(w.from) && t.Before(w.to) }

// restartSpan computes the restart window of a boot over cycles ordered by start: unreachable
// reports a cycle classified by rule 1 (no LAN), inet one in which the Internet was reachable.
// The extension back from the boot stops at a monitoring gap (gap), since nothing is known
// about unmonitored time.
func restartSpan(n int, start func(int) time.Time, unreachable, inet func(int) bool, boot time.Time, gap time.Duration) restartWin {
	k := sort.Search(n, func(i int) bool { return !start(i).Before(boot) })
	w := restartWin{from: boot, to: boot.Add(restartCap), end: endOpen}
	next := boot
	for i := k - 1; i >= 0; i-- {
		s := start(i)
		if next.Sub(s) > gap || !unreachable(i) {
			break
		}
		w.from, w.back, next = s, true, s
	}
	for i := k; i < n; i++ {
		s := start(i)
		if !s.Before(w.to) {
			w.end = endCap
			break
		}
		if inet(i) {
			w.to, w.end = s, endInternet
			break
		}
	}
	return w
}

// inRestartWindow reports whether t lies in one of the windows.
func inRestartWindow(wins []restartWin, t time.Time) bool {
	for _, w := range wins {
		if w.contains(t) {
			return true
		}
	}
	return false
}

// inetReachable is DESIGN §9 INET_ANY for a recorded cycle: an internet probe succeeded (a
// verdict of rule 3 implies it, also for results recorded without roles).
func inetReachable(state string, probes []model.ProbeResult) bool {
	if state == model.StateOnline || state == model.StateDegraded {
		return true
	}
	for _, p := range probes {
		if p.Role == model.RoleInet && p.OK {
			return true
		}
	}
	return false
}

// lanDown reports a cycle classified by rule 1 (DESIGN §9: the gateway did not answer this
// computer), the cycles a restart window extends back over: a LOCAL_FAULT verdict whose gateway
// probes all failed. Without gateway probe results (hand-built records) the verdict decides,
// except a LOCAL_ROUTE verdict, which the classifier gives only when the gateway answered.
func lanDown(v model.Verdict, probes []model.ProbeResult) bool {
	if v.State != model.StateLocalFault {
		return false
	}
	if n := countCycle(probes); n.gwTotal > 0 {
		return n.gwAnswered == 0
	}
	return v.Cause != model.CauseLocalRoute
}

// hasUptime: a reachable snapshot whose sysinfo uptime could be read.
func hasUptime(s *snapObs) bool {
	return s.reachable() && s.Snap.System != nil && s.Snap.System.UptimeSec >= 0
}

// restartOf returns the gateway restart cur reveals (nil if none): the uptime cur reports is
// inconsistent with the time elapsed since prevUp, the latest earlier snapshot with a readable
// uptime (the same test as the gateway_event "reboot").
func restartOf(prevUp, cur *snapObs) *restartInfo {
	if !hasUptime(prevUp) || !hasUptime(cur) {
		return nil
	}
	elapsed, known := elapsedBetween(prevUp, cur)
	if jumped, ok := uptimeJumped(prevUp.Snap, cur.Snap, elapsed, known); !ok || !jumped {
		return nil
	}
	boot, ok := bootTime(cur.Snap, cur.At)
	if !ok {
		return nil
	}
	detected, ok := pageFetchedAt(cur.Snap, "sysinfo")
	if !ok {
		detected = cur.At
	}
	return &restartInfo{
		Boot:     boot,
		Detected: detected.UTC(),
		Uptime:   cur.Snap.System.UptimeSec,
		SnapSeq:  cur.Seq,
		PrevSeq:  prevUp.Seq,
		FWBefore: firmwareOf(prevUp.Snap),
		FWAfter:  firmwareOf(cur.Snap),
	}
}

// restartReasons states one restart as reasons of an incident.
func restartReasons(r restartInfo) []string {
	s := fmt.Sprintf("the AT&T gateway restarted at about %s (uptime reset", fmtHuman(r.Boot))
	if r.Uptime >= 0 && !r.Detected.IsZero() {
		s += fmt.Sprintf(": at %s it reported %d s of uptime", fmtHuman(r.Detected), r.Uptime)
	}
	s += ")"
	out := []string{s}
	if r.fwChanged() {
		out = append(out, fmt.Sprintf("AT&T-pushed firmware update: the gateway firmware changed from %s to %s across the restart", r.FWBefore, r.FWAfter))
	}
	return out
}

// plural renders "1 thing" / "n things".
func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}
