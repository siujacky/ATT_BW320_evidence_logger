package monitor

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"attmonitor/internal/model"
)

// snapObs is a recorded gateway snapshot.
type snapObs struct {
	Seq  uint64
	At   time.Time // when the snapshot was taken (request start)
	Snap *model.GatewaySnapshot
	// live: taken by this process, so At carries this process's clock (monotonic in production,
	// immune to steps of the wall clock); false for a snapshot read back from the ledger.
	live bool
}

func (s *snapObs) reachable() bool { return s != nil && s.Snap != nil && s.Snap.Derived.Reachable }

// rebootMoveThreshold: a boot-time estimate that moves by more than this between two
// snapshots means the gateway rebooted (docs/DESIGN.md §7).
const rebootMoveThreshold = 120 * time.Second

// gatewayClockAt returns the gateway's own clock (as UTC) when the snapshot read sysinfo: the
// fetch time plus GatewayClockOffsetMs (gateway clock - this computer's clock). The gateway sets
// its clock from AT&T's time service, so it does not move when this computer's clock is stepped.
func gatewayClockAt(o *snapObs) (time.Time, bool) {
	off := o.Snap.Derived.GatewayClockOffsetMs
	if off == nil {
		return time.Time{}, false
	}
	at, ok := pageFetchedAt(o.Snap, "sysinfo")
	if !ok {
		at = o.At
	}
	if at.IsZero() {
		return time.Time{}, false
	}
	return at.Round(0).Add(time.Duration(*off) * time.Millisecond), true
}

// elapsedBetween is the time between two gateway observations, measured by a clock both share:
// this process's clock when both were taken by it (monotonic: a step of the wall clock does not
// count), otherwise the gateway's own clock when both snapshots report it. ok is false when
// neither is available: the wall-clock difference of observations made by two runs of the
// monitor is no measure, since this computer's clock may have been stepped between them (a
// boot with a drifted clock, a time-service correction).
func elapsedBetween(p, c *snapObs) (time.Duration, bool) {
	if p == nil || c == nil || p.Snap == nil || c.Snap == nil {
		return 0, false
	}
	if p.live && c.live && !p.At.IsZero() && !c.At.IsZero() {
		return c.At.Sub(p.At), true
	}
	pg, okP := gatewayClockAt(p)
	cg, okC := gatewayClockAt(c)
	if okP && okC {
		return cg.Sub(pg), true
	}
	return 0, false
}

// uptimeJumped reports whether the gateway's uptime is inconsistent with the time that
// elapsed between two observations: it decreased, or - when the elapsed time is known (see
// elapsedBetween) - it differs from the previous uptime plus the elapsed time by more than
// rebootMoveThreshold (the boot time moved: a reboot, e.g. one that happened while the monitor
// was not running). A step of this computer's wall clock (which moves every "fetch time -
// uptime" estimate) is therefore never taken for a reboot. ok is false when an uptime is
// unknown.
func uptimeJumped(p, c *model.GatewaySnapshot, elapsed time.Duration, known bool) (jumped, ok bool) {
	if p == nil || c == nil || p.System == nil || c.System == nil || p.System.UptimeSec < 0 || c.System.UptimeSec < 0 {
		return false, false
	}
	if c.System.UptimeSec < p.System.UptimeSec {
		return true, true
	}
	if !known {
		return false, true
	}
	expected := time.Duration(p.System.UptimeSec)*time.Second + elapsed
	drift := time.Duration(c.System.UptimeSec)*time.Second - expected
	return absDur(drift) > rebootMoveThreshold, true
}

// pageFetchedAt returns the request time of a page capture, if recorded.
func pageFetchedAt(s *model.GatewaySnapshot, page string) (time.Time, bool) {
	for _, p := range s.Pages {
		if p.Page == page {
			return parseTS(p.FetchedAt)
		}
	}
	return time.Time{}, false
}

// bootTime estimates when the gateway booted: the gateway's own estimate when present,
// otherwise sysinfo fetch time minus uptime. fallback is used when the fetch time is unknown.
func bootTime(s *model.GatewaySnapshot, fallback time.Time) (time.Time, bool) {
	if s == nil || s.System == nil || s.System.UptimeSec < 0 {
		return time.Time{}, false
	}
	if t, ok := parseTS(s.Derived.BootTimeEstimate); ok {
		return t, true
	}
	at, ok := pageFetchedAt(s, "sysinfo")
	if !ok {
		at = fallback
	}
	if at.IsZero() {
		return time.Time{}, false
	}
	return at.Add(-time.Duration(s.System.UptimeSec) * time.Second).UTC(), true
}

func firmwareOf(s *model.GatewaySnapshot) string {
	if s.Derived.Firmware != "" {
		return s.Derived.Firmware
	}
	if s.System != nil {
		return s.System.SoftwareVersion
	}
	return ""
}

func wanIPOf(s *model.GatewaySnapshot) string {
	if s.Derived.WANIPv4 != "" {
		return s.Derived.WANIPv4
	}
	if s.Broadband != nil {
		return s.Broadband.IPv4
	}
	return ""
}

func dbm(x10 *int64) string {
	if x10 == nil {
		return "unknown"
	}
	return fmt.Sprintf("%.1f dBm", float64(*x10)/10)
}

func eqBoolPtr(a, b *bool) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

func boolWord(b *bool, yes, no string) string {
	if b == nil {
		return "unknown"
	}
	if *b {
		return yes
	}
	return no
}

// diffSets returns the elements added to and removed from a set (order of first appearance).
func diffSets(before, after []string) (added, removed []string) {
	for _, a := range after {
		if !slices.Contains(before, a) && !slices.Contains(added, a) {
			added = append(added, a)
		}
	}
	for _, b := range before {
		if !slices.Contains(after, b) && !slices.Contains(removed, b) {
			removed = append(removed, b)
		}
	}
	return added, removed
}

func sameSet(a, b []string) bool {
	added, removed := diffSets(a, b)
	return len(added) == 0 && len(removed) == 0
}

func sortedJoin(xs []string) string {
	s := slices.Clone(xs)
	slices.Sort(s)
	return strings.Join(s, ",")
}

// countersReset decides whether the WAN counters were reset. One decreasing counter can be a
// 32-bit wrap; a reset makes most counters drop at once, so at least two counters and at
// least half of the non-zero ones must have decreased.
func countersReset(prev, cur map[string]int64) (bool, []string) {
	considered, decreased := 0, 0
	var detail []string
	for _, k := range sortedKeys(prev) {
		pv := prev[k]
		cv, ok := cur[k]
		if !ok || pv <= 0 {
			continue
		}
		considered++
		if cv < pv {
			decreased++
			detail = append(detail, fmt.Sprintf("%s %d→%d", k, pv, cv))
		}
	}
	return decreased >= 2 && 2*decreased >= considered, detail
}

// gatewayEvents derives the gateway_event records of docs/DESIGN.md §7 from a new snapshot:
// reachability is compared with the previous attempt; the sysinfo facts (reboot from the
// uptime, firmware) with prevUp, the latest earlier snapshot whose uptime could be read (a
// reachable snapshot without sysinfo must not hide a restart); everything else with the
// previous successful snapshot. Evidence = the seqs of the two snapshots compared. Pure.
func gatewayEvents(prevAttempt, prevGood, prevUp, cur *snapObs) []model.GatewayEvent {
	var evs []model.GatewayEvent
	if cur == nil || cur.Snap == nil {
		return nil
	}
	curOK := cur.reachable()

	if prevAttempt != nil && prevAttempt.Snap != nil && prevAttempt.reachable() != curOK {
		e := model.GatewayEvent{Kind: model.GwEvUnreachable, Evidence: []uint64{prevAttempt.Seq, cur.Seq}}
		if curOK {
			e.Before, e.After = "unreachable", "reachable"
			e.Detail = "the gateway web interface answered again"
		} else {
			e.Before, e.After = "reachable", "unreachable"
			e.Detail = "no gateway status page could be fetched" + pageErrors(cur.Snap)
		}
		evs = append(evs, e)
	}
	if !curOK {
		return evs
	}
	c := cur.Snap
	if prevGood == nil || prevGood.Snap == nil {
		// First observation ever: make alarm flags that are already raised explicit.
		if c.Fiber != nil && len(c.Derived.Alarms) > 0 {
			evs = append(evs, model.GatewayEvent{
				Kind: model.GwEvOpticalAlarm, After: sortedJoin(c.Derived.Alarms),
				Detail: fmt.Sprintf("alarm flags already raised at the first gateway observation by this monitor; Rx %s, Tx %s",
					dbm(c.Derived.RxPowerX10), dbm(c.Derived.TxPowerX10)),
				Evidence: []uint64{cur.Seq},
			})
		}
		return evs
	}
	p := prevGood.Snap
	ev := func() []uint64 { return []uint64{prevGood.Seq, cur.Seq} }
	up := prevUp
	if up == nil || up.Snap == nil || up.Snap.System == nil {
		up = prevGood
	}
	pu := up.Snap
	upEv := func() []uint64 { return []uint64{up.Seq, cur.Seq} }

	// Reboot: uptime decreased, or the boot time moved.
	rebooted := false
	elapsed, known := elapsedBetween(up, cur)
	if jumped, _ := uptimeJumped(pu, c, elapsed, known); jumped {
		rebooted = true
		e := model.GatewayEvent{Kind: model.GwEvReboot, Evidence: upEv(),
			Before: fmt.Sprintf("uptime %d s", pu.System.UptimeSec),
			After:  fmt.Sprintf("uptime %d s", c.System.UptimeSec)}
		e.Detail = fmt.Sprintf("gateway uptime went from %d s to %d s", pu.System.UptimeSec, c.System.UptimeSec)
		pb, okP := bootTime(pu, up.At)
		cb, okC := bootTime(c, cur.At)
		if okP && okC {
			e.Before, e.After = fmtTS(pb), fmtTS(cb)
			e.Detail += fmt.Sprintf("; estimated boot time moved from %s to %s", fmtHuman(pb), fmtHuman(cb))
		}
		evs = append(evs, e)
	}

	if pf, cf := firmwareOf(pu), firmwareOf(c); pf != "" && cf != "" && pf != cf {
		evs = append(evs, model.GatewayEvent{Kind: model.GwEvFirmwareChange, Before: pf, After: cf, Evidence: upEv(),
			Detail: fmt.Sprintf("gateway firmware changed from %s to %s", pf, cf)})
	}

	if p.Broadband != nil && c.Broadband != nil {
		if pi, ci := wanIPOf(p), wanIPOf(c); pi != ci {
			detail := fmt.Sprintf("WAN IPv4 address changed from %s to %s", pi, ci)
			switch {
			case ci == "":
				detail = fmt.Sprintf("WAN IPv4 address %s removed", pi)
			case pi == "":
				detail = fmt.Sprintf("WAN IPv4 address %s assigned", ci)
			}
			evs = append(evs, model.GatewayEvent{Kind: model.GwEvWANIPChange, Before: pi, After: ci, Detail: detail, Evidence: ev()})
		}
	}

	if pu, cu := p.Derived.BroadbandUp, c.Derived.BroadbandUp; pu != nil && cu != nil && *pu != *cu {
		evs = append(evs, model.GatewayEvent{Kind: model.GwEvBroadbandState,
			Before: broadbandText(p), After: broadbandText(c), Evidence: ev(),
			Detail: fmt.Sprintf("AT&T gateway Broadband Connection changed from %s to %s", broadbandText(p), broadbandText(c))})
	}

	if p.Broadband != nil && c.Broadband != nil {
		pp, cp := p.Broadband.PONLinkStatus, c.Broadband.PONLinkStatus
		if pp != cp && ((pp != "" && cp != "") || !eqBoolPtr(p.Derived.PONOperational, c.Derived.PONOperational)) {
			evs = append(evs, model.GatewayEvent{Kind: model.GwEvPONState, Before: pp, After: cp, Evidence: ev(),
				Detail: fmt.Sprintf("AT&T gateway PON Link Status changed from %q to %q (operational: %s → %s)", pp, cp,
					boolWord(p.Derived.PONOperational, "yes", "no"), boolWord(c.Derived.PONOperational, "yes", "no"))})
		}
	}

	if p.Fiber != nil && c.Fiber != nil {
		added, removed := diffSets(p.Derived.Alarms, c.Derived.Alarms)
		if len(added)+len(removed) > 0 {
			var parts []string
			if len(added) > 0 {
				parts = append(parts, "raised: "+strings.Join(added, ", "))
			}
			if len(removed) > 0 {
				parts = append(parts, "cleared: "+strings.Join(removed, ", "))
			}
			parts = append(parts, fmt.Sprintf("Rx %s, Tx %s", dbm(c.Derived.RxPowerX10), dbm(c.Derived.TxPowerX10)))
			evs = append(evs, model.GatewayEvent{Kind: model.GwEvOpticalAlarm,
				Before: sortedJoin(p.Derived.Alarms), After: sortedJoin(c.Derived.Alarms),
				Detail: strings.Join(parts, "; "), Evidence: ev()})
		}
	}

	if pl, cl := p.Derived.FiberLastChange, c.Derived.FiberLastChange; pl != 0 && cl != 0 && pl != cl {
		evs = append(evs, model.GatewayEvent{Kind: model.GwEvOpticalLinkChange,
			Before: fmt.Sprint(pl), After: fmt.Sprint(cl), Evidence: ev(),
			Detail: fmt.Sprintf("fiberstat Last Change moved from %d to %d: the optical link changed state since the previous poll (this reveals flaps shorter than the poll interval; epoch semantics as reported by the gateway)", pl, cl)})
	}

	if !rebooted && p.Broadband != nil && c.Broadband != nil {
		if reset, detail := countersReset(p.Broadband.Counters, c.Broadband.Counters); reset {
			evs = append(evs, model.GatewayEvent{Kind: model.GwEvCountersReset, Evidence: ev(),
				Detail: "WAN counters decreased without a gateway reboot: " + strings.Join(detail, "; ")})
		}
	}

	if p.System != nil && c.System != nil && p.Derived.GatewayClockBlank != c.Derived.GatewayClockBlank {
		e := model.GatewayEvent{Kind: model.GwEvGatewayClock, Evidence: ev()}
		if c.Derived.GatewayClockBlank {
			e.Before, e.After = "set", "blank"
			e.Detail = "the gateway's Current Date/Time became blank (the gateway shows a blank clock while its WAN is down)"
		} else {
			e.Before, e.After = "blank", "set"
			e.Detail = "the gateway's Current Date/Time is set again: " + c.System.GatewayTimeRaw
		}
		evs = append(evs, e)
	}
	return evs
}

func pageErrors(s *model.GatewaySnapshot) string {
	var parts []string
	for _, p := range s.Pages {
		switch {
		case p.Err != "":
			parts = append(parts, p.Page+": "+truncate(p.Err, 100))
		case p.LoginPage:
			parts = append(parts, p.Page+": login page")
		case p.Status != 0 && p.Status != 200:
			parts = append(parts, fmt.Sprintf("%s: HTTP %d", p.Page, p.Status))
		}
	}
	if len(parts) == 0 {
		return ""
	}
	return " (" + strings.Join(parts, "; ") + ")"
}

// ---------------------------------------------------------------------------- raw storage policy

// materialChange reports whether cur differs from the previous successful snapshot in a field
// that makes its raw pages worth keeping (docs/DESIGN.md §8): broadband state, PON state,
// optical flags, WAN IP, uptime reset, firmware, fiber Last Change — plus reachability. elapsed
// (known) is the time between the two, from elapsedBetween.
func materialChange(prev, cur *model.GatewaySnapshot, elapsed time.Duration, known bool) bool {
	if prev == nil || cur == nil {
		return true
	}
	p, c := prev.Derived, cur.Derived
	if p.Reachable != c.Reachable {
		return true
	}
	if !eqBoolPtr(p.BroadbandUp, c.BroadbandUp) || !eqBoolPtr(p.PONOperational, c.PONOperational) || !eqBoolPtr(p.OpticalUp, c.OpticalUp) {
		return true
	}
	if prev.Broadband != nil && cur.Broadband != nil &&
		(prev.Broadband.Connection != cur.Broadband.Connection || prev.Broadband.PONLinkStatus != cur.Broadband.PONLinkStatus) {
		return true
	}
	if !sameSet(p.Alarms, c.Alarms) {
		return true
	}
	if prev.Fiber != nil && cur.Fiber != nil {
		pf, cf := prev.Fiber, cur.Fiber
		if pf.RxLOSState != cf.RxLOSState || pf.OptLOS != cf.OptLOS || pf.TxFaultState != cf.TxFaultState ||
			pf.LinkState != cf.LinkState || pf.OpticalStatus != cf.OpticalStatus {
			return true
		}
	}
	if wanIPOf(prev) != wanIPOf(cur) {
		return true
	}
	if jumped, _ := uptimeJumped(prev, cur, elapsed, known); jumped {
		return true
	}
	if firmwareOf(prev) != firmwareOf(cur) {
		return true
	}
	return p.FiberLastChange != c.FiberLastChange
}

// shouldStoreRaw is the per-page storage decision of docs/DESIGN.md §8.
func shouldStoreRaw(incidentActive, material bool, lastStored, now time.Time, interval time.Duration) bool {
	return incidentActive || material || lastStored.IsZero() || now.Sub(lastStored) >= interval
}
