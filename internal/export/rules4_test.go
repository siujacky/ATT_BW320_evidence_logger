package export

// Rules 2026.10-4 (docs/DESIGN.md §9-§10): the report describes them, explains how records of
// rules 2026.10-3 differ, computes the gateway-restart windows the way the monitor does (rule-1
// cycles only), flags incident records the windows contradict (with the OpenAfterCycles provider
// threshold), stops incidents where monitoring was interrupted, explains monitor_start gaps with
// the clock facts the ledger holds, and counts a DNS query as successful only when it resolved.

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"attmonitor/internal/contracts"
	"attmonitor/internal/model"
)

// rv4Sample appends one sample with the given verdict and probes, the cycle starting at start.
func rv4Sample(f *fakeLedger, start time.Time, v model.Verdict, probes []model.ProbeResult, incident string) model.Ref {
	if v.Rules == "" {
		v.Rules = rulesDescribed
	}
	return f.append(start.Add(1500*time.Millisecond), model.TypeSample, model.Sample{Started: start.UTC().Format(time.RFC3339Nano),
		DurMs: 1500, Probes: probes, Verdict: v, IncidentID: incident})
}

// excerpt returns the part of s around the longest prefix of want that it contains (for
// failure messages).
func excerpt(s, want string) string {
	for n := len(want); n > 8; n-- {
		if i := strings.Index(s, want[:n]); i >= 0 {
			return s[i:min(len(s), i+len(want)+120)]
		}
	}
	return ""
}

// interruptedReason is the reason the monitor records for a cycle cut short by system sleep.
const interruptedReason = "this cycle took 1h0m0s, longer than the 9s its probes may take: monitoring was interrupted while they " +
	"were in flight (for example by system sleep), so their results say nothing about the network"

// noRoleProbes are probe results recorded without roles (hand-built or older records).
func noRoleProbes() []model.ProbeResult {
	return []model.ProbeResult{{Name: "probe_a", Kind: model.KindICMP, Target: "192.0.2.1", Status: "IP_REQ_TIMED_OUT"}}
}

func TestRules4MethodologyAndDifferences(t *testing.T) {
	if rulesDescribed != "2026.10-4" {
		t.Fatalf("rules described = %s", rulesDescribed)
	}
	d := func(m int) time.Time { return time.Date(2026, 10, 3, 12, m, 0, 0, time.UTC) }
	f := cfgLedger(t, d(0), testConfigJSON(t, "10s", "2m30s", 3, 3, 6, 20, 150, 20))
	next := d(1)
	for i := 0; i < 6; i++ {
		rv4Sample(f, next, model.Verdict{State: model.StateOnline, Attribution: model.AttrNone, Rules: "2026.10-3"}, testProbes(true, true, false), "")
		next = next.Add(10 * time.Second)
	}
	rvSamples(f, next, 6, 10*time.Second, model.StateOnline, "", model.AttrNone, "")
	_, z, r := rvExport(t, f, d(30), contracts.ExportRequest{From: d(0), To: d(10)})
	var note *rulesNote
	for i := range r.Methodology.RulesNotes {
		if r.Methodology.RulesNotes[i].Version == "2026.10-3" {
			note = &r.Methodology.RulesNotes[i]
		}
	}
	if note == nil || !note.Known || note.Samples != 6 {
		t.Fatalf("rules notes = %+v", r.Methodology.RulesNotes)
	}
	diffs := strings.Join(note.Differences, "\n")
	for _, want := range []string{"two consecutive service checks", "LOCAL_FAULT / LOCAL_ROUTE", "80 Mb/s", "UNKNOWN",
		"before the incident's first observed cycle", "at least open_after_cycles", "end of the time its last bad cycle covers"} {
		if !strings.Contains(diffs, want) {
			t.Errorf("2026.10-3 differences lack %q:\n%s", want, diffs)
		}
	}
	html := string(z.files["REPORT.html"])
	for _, want := range []string{
		"Classification rules (version 2026.10-4",
		"the same failure appears in two consecutive service checks (at most 150 s apart)",
		"LOCAL_FAULT / LOCAL_ROUTE, attribution <em>undetermined</em>, unless the gateway itself reports its fiber or WAN connection down",
		"80 Mb/s or more in either direction",
		"monitoring was interrupted while its probes were in flight",
		"also when the boot came before the incident's first observed cycle",
		"only if at least 3 provider-attributed bad cycles",
		"closes an open incident at the end of the time its last bad cycle covers",
		`<td class="mono">LOCAL_ROUTE</td><td>LOCAL_FAULT</td>`,
		"EGRESS_NOT_VIA_GATEWAY (warning)", "LEDGER_WRITE_FAILING (critical)", "DISK_SPACE_LOW (warning below 2 GiB free, critical below 512 MiB)",
		"CLOCK_OFFSET (warning beyond 60 s, critical beyond 5 minutes)", "ANCHOR_UNTRUSTED",
		"IPv6 destinations are not checked",
		"Records produced under rules 2026.10-3</strong> (6 samples of the period",
	} {
		if !strings.Contains(html, want) {
			t.Errorf("REPORT.html lacks %q: %s", want, excerpt(html, want))
		}
	}
	for code, sev := range map[string]string{"LEDGER_WRITE_FAILING": "critical", "DISK_SPACE_LOW": "warning", "EGRESS_NOT_VIA_GATEWAY": "warning",
		"CLOCK_OFFSET": "warning", "ANCHOR_UNTRUSTED": "warning"} {
		if codeSeverity(code) != sev || codeLabel(code) == strings.ToLower(code) || !strings.Contains(codeLabels[code], " ") {
			t.Errorf("%s: severity %s, label %q", code, codeSeverity(code), codeLabel(code))
		}
	}
}

// A restart window extends back over rule-1 cycles only (state LOCAL_FAULT, gateway probes all
// failed), like the monitor's: not over an UNKNOWN cycle whose probes timed out in system sleep,
// nor over a LOCAL_ROUTE cycle; without gateway probe results the verdict decides.
func TestRestartWindowExtendsBackOverRuleOneCyclesOnly(t *testing.T) {
	d := func(m, s int) time.Time { return time.Date(2026, 10, 3, 12, m, s, 0, time.UTC) }
	unknownCut := model.Verdict{State: model.StateUnknown, Attribution: model.AttrUndetermined, Reasons: []string{interruptedReason}}

	t.Run("interrupted cycle before the boot", func(t *testing.T) {
		f := cfgLedger(t, d(0, 0), testConfigJSON(t, "10s", "2m30s", 3, 3, 6, 20, 150, 20))
		next := rvSamples(f, d(1, 0), 6, 10*time.Second, model.StateOnline, "", model.AttrNone, "")
		next = rvSamples(f, next, 2, 10*time.Second, model.StateLocalFault, model.CauseGatewayUnreachable, model.AttrUndetermined, "")
		rv4Sample(f, next, unknownCut, testProbes(false, false, false), "") // every probe timed out: lan 0, but not rule 1
		next = next.Add(10 * time.Second)
		boot := next.Add(-2 * time.Second)
		next = rvSamples(f, next, 3, 10*time.Second, model.StateISPOutage, model.CauseWANDown, model.AttrProvider, "")
		back := next
		f.append(next, model.TypeGatewayEvent, model.GatewayEvent{Kind: model.GwEvReboot, After: boot.Format(time.RFC3339Nano)})
		rvSamples(f, next, 6, 10*time.Second, model.StateOnline, "", model.AttrNone, "")
		_, _, r := rvExport(t, f, d(30, 0), contracts.ExportRequest{From: d(0, 0), To: d(10, 0)})
		rs := r.Summary.GatewayRestarts
		if len(rs) != 1 || rs[0].WindowFrom != boot.Format(time.RFC3339Nano) || rs[0].WindowTo != back.Format(time.RFC3339Nano) ||
			rs[0].BadCycles != 3 || r.Summary.RestartSec != 30 {
			t.Fatalf("restarts %+v, restart %d s: the window must not extend back over the UNKNOWN cycle", rs, r.Summary.RestartSec)
		}
	})

	t.Run("verdicts without gateway probe results", func(t *testing.T) {
		f := cfgLedger(t, d(0, 0), testConfigJSON(t, "10s", "2m30s", 3, 3, 6, 20, 150, 20))
		next := rvSamples(f, d(1, 0), 6, 10*time.Second, model.StateOnline, "", model.AttrNone, "")
		for i := 0; i < 2; i++ { // the gateway answered, the route bypassed it: not rule 1
			rv4Sample(f, next, model.Verdict{State: model.StateLocalFault, Cause: model.CauseLocalRoute, Attribution: model.AttrUndetermined},
				noRoleProbes(), "")
			next = next.Add(10 * time.Second)
		}
		ruleOne := next
		for i := 0; i < 2; i++ { // rule 1, recorded without roles: the verdict decides
			rv4Sample(f, next, model.Verdict{State: model.StateLocalFault, Cause: model.CauseGatewayUnreachable, Attribution: model.AttrUndetermined},
				noRoleProbes(), "")
			next = next.Add(10 * time.Second)
		}
		boot := next.Add(-3 * time.Second)
		next = rvSamples(f, next, 3, 10*time.Second, model.StateISPOutage, model.CauseWANDown, model.AttrProvider, "")
		f.append(next, model.TypeGatewayEvent, model.GatewayEvent{Kind: model.GwEvReboot, After: boot.Format(time.RFC3339Nano)})
		rvSamples(f, next, 6, 10*time.Second, model.StateOnline, "", model.AttrNone, "")
		_, _, r := rvExport(t, f, d(30, 0), contracts.ExportRequest{From: d(0, 0), To: d(10, 0)})
		rs := r.Summary.GatewayRestarts
		if len(rs) != 1 || rs[0].WindowFrom != ruleOne.Format(time.RFC3339Nano) || rs[0].BadCycles != 5 || r.Summary.RestartSec != 50 {
			t.Fatalf("restarts %+v, restart %d s", rs, r.Summary.RestartSec)
		}
	})
}

// restartScenario builds an incident around a gateway restart.
//
// pcOff: the gateway and this computer lose power together; the gateway boots while the computer
// is off, and when the computer is back the gateway answers but its WAN needs 5 more cycles. The
// default record is one of rules 2026.10-3, which attached no restart whose boot preceded the
// incident's first observed cycle: ISP_OUTAGE / WAN_DOWN, provider, 50 s without Internet.
//
// Otherwise the owner power-cycles the gateway during an outage: pre provider-attributed
// ISP_OUTAGE cycles, 3 cycles with the gateway off (rule 1), the boot, 5 cycles without WAN. The
// default record is one of rules 2026.10-3 (a single provider-attributed bad cycle outside the
// restart window made it the provider's): ISP_OUTAGE / UPSTREAM_UNREACHABLE, provider, 80 s of
// restart time.
//
// rec, when set, edits the record.
func restartScenario(t *testing.T, pcOff bool, pre int, rec func(inc *model.Incident)) (contracts.ExportInfo, zipContent, *report) {
	t.Helper()
	f := restartLedger(t, pcOff, pre, rec)
	return rvExport(t, f, rv4Day(40, 0), contracts.ExportRequest{From: rv4Day(0, 0), To: rv4Day(30, 0)})
}

// rv4Day is the day of restartLedger: 2026-10-03 12:m:s UTC.
func rv4Day(m, s int) time.Time { return time.Date(2026, 10, 3, 12, m, s, 0, time.UTC) }

// restartLedger writes the ledger of restartScenario.
func restartLedger(t *testing.T, pcOff bool, pre int, rec func(inc *model.Incident)) *fakeLedger {
	t.Helper()
	d := rv4Day
	f := cfgLedger(t, d(0, 0), testConfigJSON(t, "10s", "2m30s", 3, 3, 6, 20, 150, 20))
	next := rvSamples(f, d(1, 0), 6, 10*time.Second, model.StateOnline, "", model.AttrNone, "")
	const id = "INC-20261003-120200Z"
	var opened time.Time
	var first uint64
	bad := 0
	// cycle appends one bad cycle of the incident (the third and later ones carry its id).
	cycle := func(state, cause, attr string) {
		tag := ""
		if bad >= 2 {
			tag = id
		}
		if bad == 0 {
			opened, first = next, f.head.Seq+1
		}
		bad++
		next = rvSamples(f, next, 1, 10*time.Second, state, cause, attr, tag)
	}
	for i := 0; i < pre; i++ {
		cycle(model.StateISPOutage, model.CauseUpstreamUnreachable, model.AttrProvider)
	}
	var boot time.Time
	if pcOff {
		f.append(next.Add(-8*time.Second), model.TypeMonitorStop, model.MonitorStop{Reason: "system shutdown", UptimeSec: 120})
		boot = next.Add(2 * time.Minute) // while this computer is off
		restart := next.Add(4 * time.Minute)
		f.append(restart, model.TypeMonitorStart, model.MonitorStart{Software: testSoftware, Host: testHost, Mode: "service", GapSeconds: 248,
			PrevHead: f.head})
		next = restart.Add(10 * time.Second)
	} else {
		for i := 0; i < 3; i++ {
			cycle(model.StateLocalFault, model.CauseGatewayUnreachable, model.AttrUndetermined)
		}
		boot = next.Add(-3 * time.Second)
	}
	for i := 0; i < 5; i++ {
		cycle(model.StateISPOutage, model.CauseWANDown, model.AttrProvider)
	}
	closed := next
	var lastSeq uint64
	for i := 0; i < 3; i++ {
		next = rvSamples(f, next, 1, 10*time.Second, model.StateOnline, "", model.AttrNone, id)
		lastSeq = f.head.Seq
	}
	f.append(next, model.TypeGatewayEvent, model.GatewayEvent{Kind: model.GwEvReboot, After: boot.Format(time.RFC3339Nano)})
	inc := model.Incident{ID: id, Opened: opened.Format(time.RFC3339Nano), Closed: closed.Format(time.RFC3339Nano),
		DurationSec: int64(closed.Sub(opened) / time.Second), State: model.StateISPOutage, Cause: model.CauseWANDown, Attribution: model.AttrProvider,
		Causes: []string{model.CauseWANDown}, Rules: "2026.10-3", FirstSeq: first, LastSeq: lastSeq, Summary: "ISP outage",
		Stats: model.IncidentStats{Cycles: bad, BadCycles: bad, DowntimeSec: 50}}
	if !pcOff {
		inc.Cause, inc.Causes = model.CauseUpstreamUnreachable, []string{model.CauseUpstreamUnreachable, model.CauseGatewayUnreachable, model.CauseWANDown}
		inc.Stats.DowntimeSec, inc.Stats.RestartSec = int64(pre*10), 80
		inc.GatewayRestarts = []string{boot.Format(time.RFC3339Nano)}
	}
	if rec != nil {
		rec(&inc)
	}
	f.append(next.Add(time.Second), model.TypeIncidentClose, inc)
	rvSamples(f, next.Add(10*time.Second), 6, 10*time.Second, model.StateOnline, "", model.AttrNone, "")
	return f
}

func TestIncidentRecordContradictedByRestartWindows(t *testing.T) {
	t.Run("boot before the first observed cycle", func(t *testing.T) {
		_, z, r := restartScenario(t, true, 0, nil)
		if len(r.Incidents) != 1 {
			t.Fatalf("incidents %+v", r.Incidents)
		}
		e := r.Incidents[0]
		rc := e.RestartCheck
		if rc == nil || !rc.Complete || rc.BadCycles != 5 || rc.BadInWindows != 5 || rc.ProviderOutside != 0 || rc.OpenAfterCycles != 3 ||
			!rc.GatewayRestart || rc.Attribution != model.AttrUndetermined || rc.RestartSec != 50 || rc.DowntimeSec != 0 || len(rc.Boots) != 1 {
			t.Fatalf("restart check %+v", rc)
		}
		if e.ComputedRestartSec != 50 || len(rc.Conflicts) != 2 {
			t.Fatalf("computed restart %d, conflicts %q", e.ComputedRestartSec, rc.Conflicts)
		}
		facts := strings.Join(e.KeyFacts, "\n")
		for _, want := range []string{
			"its record classifies it as ISP_OUTAGE / WAN_DOWN with attribution provider, but 5 of its 5 bad cycles lie inside the gateway-restart windows",
			"0 provider-attributed bad cycles lie outside them, fewer than the 3 that open an incident: under rules 2026.10-4 it is a gateway restart (LOCAL_FAULT / GATEWAY_REBOOT) with attribution undetermined",
			"its record counts 0s of bad cycles in gateway-restart windows (restart_s) and 50s without Internet (downtime_s), but the restart windows computed from the records",
			"hold 50s of its bad cycles, and its ISP_OUTAGE cycles outside them cover 0s",
		} {
			if !strings.Contains(facts, want) {
				t.Errorf("key facts lack %q:\n%s", want, facts)
			}
		}
		if lo := r.Summary.LongestOutage; lo == nil || !lo.RestartConflict {
			t.Errorf("longest outage %+v does not say that its record is contradicted", lo)
		}
		html := string(z.files["REPORT.html"])
		for _, want := range []string{"restart windows computed from the records: 50s", "contradicted by the restart windows",
			"1 incident record is contradicted by the gateway-restart windows this report computes from the records (rules 2026.10-4)",
			"its record is contradicted by the gateway-restart windows computed from the records (see its key facts)",
			"outside the restart windows computed from the records: 0s"} {
			if !strings.Contains(html, want) {
				t.Errorf("REPORT.html lacks %q", want)
			}
		}
		// The summary's provider outage time never counted the restart window.
		if r.Summary.ProviderOutageSec != 0 || r.Summary.RestartSec != 50 {
			t.Errorf("provider outage %d, restart %d", r.Summary.ProviderOutageSec, r.Summary.RestartSec)
		}
	})

	t.Run("fewer provider cycles outside than open_after_cycles", func(t *testing.T) {
		_, _, r := restartScenario(t, false, 2, nil)
		e := r.Incidents[0]
		rc := e.RestartCheck
		if rc == nil || !rc.Complete || rc.BadCycles != 10 || rc.BadInWindows != 8 || rc.ProviderOutside != 2 || !rc.GatewayRestart ||
			rc.Attribution != model.AttrUndetermined || rc.RestartSec != 80 || rc.DowntimeSec != 20 || len(rc.Conflicts) != 1 || e.RestartDiffers() {
			t.Fatalf("restart check %+v", rc)
		}
		if !strings.Contains(rc.Conflicts[0], "2 provider-attributed bad cycles lie outside them, fewer than the 3 that open an incident") {
			t.Errorf("conflict %q", rc.Conflicts[0])
		}
	})

	t.Run("enough provider cycles outside", func(t *testing.T) {
		_, z, r := restartScenario(t, false, 3, nil)
		e := r.Incidents[0]
		if rc := e.RestartCheck; rc == nil || rc.ProviderOutside != 3 || rc.GatewayRestart || rc.Attribution != model.AttrProvider ||
			rc.RestartSec != 80 || len(rc.Conflicts) != 0 || e.RestartDiffers() {
			t.Fatalf("restart check %+v", rc)
		}
		if strings.Contains(string(z.files["REPORT.html"]), "contradicted by") {
			t.Error("REPORT.html flags a record that agrees with the restart windows")
		}
	})

	t.Run("restart whose window holds none of its bad cycles", func(t *testing.T) {
		// The gateway restarted during a DEGRADED incident and came back within one cycle: its
		// window holds no cycle, so whatever the record's attribution rests on, it is not the
		// restart windows' to contradict.
		d := func(m, s int) time.Time { return time.Date(2026, 10, 3, 12, m, s, 0, time.UTC) }
		f := cfgLedger(t, d(0, 0), testConfigJSON(t, "10s", "2m30s", 3, 3, 6, 20, 150, 20))
		next := rvSamples(f, d(1, 0), 6, 10*time.Second, model.StateOnline, "", model.AttrNone, "")
		const id = "INC-20261003-120200Z"
		opened, first := next, f.head.Seq+1
		var boot time.Time
		for i, attr := range []string{model.AttrProvider, model.AttrUndetermined, model.AttrProvider, model.AttrUndetermined} {
			tag := ""
			if i >= 2 {
				tag = id
			}
			if i == 1 {
				boot = next.Add(4 * time.Second)
			}
			next = rvSamples(f, next, 1, 10*time.Second, model.StateDegraded, model.CausePacketLoss, attr, tag)
		}
		closed := next
		var lastSeq uint64
		for i := 0; i < 3; i++ {
			next = rvSamples(f, next, 1, 10*time.Second, model.StateOnline, "", model.AttrNone, id)
			lastSeq = f.head.Seq
		}
		f.append(next, model.TypeGatewayEvent, model.GatewayEvent{Kind: model.GwEvReboot, After: boot.Format(time.RFC3339Nano)})
		f.append(next.Add(time.Second), model.TypeIncidentClose, model.Incident{ID: id, Opened: opened.Format(time.RFC3339Nano),
			Closed: closed.Format(time.RFC3339Nano), State: model.StateDegraded, Cause: model.CausePacketLoss, Attribution: model.AttrProvider,
			Rules: rulesDescribed, FirstSeq: first, LastSeq: lastSeq, GatewayRestarts: []string{boot.Format(time.RFC3339Nano)},
			Stats: model.IncidentStats{Cycles: 4, BadCycles: 4, DegradedSec: 40}})
		_, z, r := rvExport(t, f, d(40, 0), contracts.ExportRequest{From: d(0, 0), To: d(30, 0)})
		rc := r.Incidents[0].RestartCheck
		if rc == nil || rc.BadInWindows != 0 || rc.GatewayRestart || len(rc.Boots) != 1 || len(rc.Conflicts) != 0 {
			t.Fatalf("restart check %+v", rc)
		}
		if strings.Contains(string(z.files["REPORT.html"]), "contradicted by") {
			t.Error("REPORT.html flags a difference the restart windows do not make")
		}
	})

	t.Run("period ends during the incident", func(t *testing.T) {
		// Only the cycles up to the end of the period are examined: the computed restart time is
		// shown with that caveat, and nothing is flagged.
		f := restartLedger(t, true, 0, nil)
		_, z, r := rvExport(t, f, rv4Day(40, 0), contracts.ExportRequest{From: rv4Day(0, 0), To: rv4Day(6, 40)})
		e := r.Incidents[0]
		if rc := e.RestartCheck; rc == nil || rc.Complete || rc.RestartSec != 30 || len(rc.Conflicts) != 0 || e.ComputedRestartSec != 30 {
			t.Fatalf("restart check %+v, computed %d", rc, e.ComputedRestartSec)
		}
		html := string(z.files["REPORT.html"])
		if !strings.Contains(html, "restart windows computed from the records: 30s (from its cycles in this bundle up to the end of the period)") ||
			strings.Contains(html, "contradicted by") {
			t.Error("REPORT.html does not qualify the partial restart time, or flags a partial comparison")
		}
	})

	t.Run("record agrees", func(t *testing.T) {
		_, z, r := restartScenario(t, true, 0, func(inc *model.Incident) {
			inc.Rules, inc.State, inc.Cause, inc.Attribution = rulesDescribed, model.StateLocalFault, model.CauseGatewayReboot, model.AttrUndetermined
			inc.Stats.DowntimeSec, inc.Stats.RestartSec = 0, 50
		})
		e := r.Incidents[0]
		if rc := e.RestartCheck; rc == nil || len(rc.Conflicts) != 0 || e.RestartDiffers() {
			t.Fatalf("restart check %+v", rc)
		}
		if html := string(z.files["REPORT.html"]); strings.Contains(html, "contradicted by") || strings.Contains(html, "restart windows computed from the records") {
			t.Error("REPORT.html flags a record that agrees with the restart windows")
		}
	})
}

// An incident without a close record whose samples show monitoring interrupted (a gap, or a cycle
// cut short by sleep) closes, under the rules, at the end of its last bad cycle's coverage: the
// cycles after the interruption are not its own.
func TestOngoingIncidentStopsWhereMonitoringWasInterrupted(t *testing.T) {
	d := func(m int) time.Time { return time.Date(2026, 10, 5, 8, m, 0, 0, time.UTC) }
	build := func(t *testing.T, interruptedCycle bool) (*report, zipContent, time.Time) {
		f := cfgLedger(t, d(0), testConfigJSON(t, "10s", "2m30s", 3, 3, 6, 20, 150, 20))
		next := rvSamples(f, d(1), 6, 10*time.Second, model.StateOnline, "", model.AttrNone, "")
		const id = "INC-20261005-080200Z"
		opened, first := next, f.head.Seq+1
		var lastBad time.Time
		for i := 0; i < 6; i++ {
			tag := ""
			if i >= 2 {
				tag = id
			}
			lastBad = next
			next = rvSamples(f, next, 1, 10*time.Second, model.StateISPOutage, model.CauseUpstreamUnreachable, model.AttrProvider, tag)
			if i == 2 {
				f.append(next.Add(-8*time.Second), model.TypeIncidentOpen, model.Incident{ID: id, Opened: opened.Format(time.RFC3339Nano), Open: true,
					State: model.StateISPOutage, Cause: model.CauseUpstreamUnreachable, Attribution: model.AttrProvider, Rules: rulesDescribed,
					FirstSeq: first, Stats: model.IncidentStats{Cycles: 3, BadCycles: 3, DowntimeSec: 20}})
			}
		}
		if interruptedCycle {
			rv4Sample(f, next, model.Verdict{State: model.StateUnknown, Attribution: model.AttrUndetermined, Reasons: []string{interruptedReason}},
				testProbes(false, false, false), "")
		}
		next = next.Add(20 * time.Minute) // asleep; the incident's close record is not in the bundle
		next = rvSamples(f, next, 3, 10*time.Second, model.StateISPOutage, model.CauseUpstreamUnreachable, model.AttrProvider, "INC-20261005-082100Z")
		rvSamples(f, next, 6, 10*time.Second, model.StateOnline, "", model.AttrNone, "")
		_, z, r := rvExport(t, f, d(40), contracts.ExportRequest{From: d(0), To: d(30)})
		return r, z, lastBad
	}
	for _, tc := range []struct {
		name        string
		interrupted bool
		lastCover   time.Duration // the last bad cycle covers until the next cycle (capped)
	}{{"monitoring gap", false, 15 * time.Second}, {"cycle cut short by sleep", true, 10 * time.Second}} {
		t.Run(tc.name, func(t *testing.T) {
			r, z, lastBad := build(t, tc.interrupted)
			var e *incidentEntry
			for i := range r.Incidents {
				if r.Incidents[i].Incident.ID == "INC-20261005-080200Z" {
					e = &r.Incidents[i]
				}
			}
			if e == nil || e.Computed == nil {
				t.Fatalf("incidents %+v", r.Incidents)
			}
			c := e.Computed
			wantDown := int64((50*time.Second + tc.lastCover) / time.Second)
			if c.InterruptedAt != lastBad.Add(tc.lastCover).Format(time.RFC3339Nano) || c.ClosingAt != "" || c.Stats.BadCycles != 6 ||
				c.Stats.Cycles != 6 || c.Stats.DowntimeSec != wantDown || e.ComputedRestartSec != 0 {
				t.Fatalf("computed %+v (want interrupted at %s, %d s without Internet)", c, lastBad.Add(tc.lastCover).Format(time.RFC3339Nano), wantDown)
			}
			row := tableRow(string(z.files["REPORT.html"]), `<td class="mono">INC-20261005-080200Z</td>`)
			if !strings.Contains(row, "monitoring interrupted while it was open") || !strings.Contains(row, fmtUTC(c.InterruptedAt)) {
				t.Errorf("incident row does not say where monitoring was interrupted:\n%s", row)
			}
		})
	}
}

// monitor_start gaps are explained with the clock facts of the ledger: a negative gap_seconds is
// a clock behind the previous record, the ledger writer's clock-behind integrity_alert and a
// between-run clock_jump say how the clock moved.
func TestMonitorStartGapExplainedByClockFacts(t *testing.T) {
	d := func(m, s int) time.Time { return time.Date(2026, 10, 3, 12, m, s, 0, time.UTC) }
	cfg := testConfigJSON(t, "10s", "2m30s", 3, 3, 6, 20, 150, 20)

	t.Run("clock set back between the runs", func(t *testing.T) {
		f := cfgLedger(t, d(0, 0), cfg)
		next := rvSamples(f, d(10, 0), 6, 10*time.Second, model.StateOnline, "", model.AttrNone, "")
		f.append(next, model.TypeMonitorStop, model.MonitorStop{Reason: "service stop", UptimeSec: 60})
		last := f.head
		// Restarted 3 minutes later by real time; the clock reads 7 minutes earlier than the stop.
		// The new process's ledger writer appends the integrity_alert before its monitor_start: the
		// fake gives a monitor_start record the run id of its seq + 1, so the alert gets it too.
		start := next.Add(-7 * time.Minute)
		f.run = fmt.Sprintf("%032x", f.next+2)
		alert := f.append(start, model.TypeIntegrityAlert, model.IntegrityAlert{Problem: "integrity problems found while opening the ledger (1)",
			Details: []string{clockBehindPrefix + ": it reads " + start.Format(time.RFC3339Nano) + " when the ledger is opened, 7m0s before the ts of the newest record"}})
		ms := f.append(start.Add(time.Second), model.TypeMonitorStart, model.MonitorStart{Software: testSoftware, Host: testHost, Mode: "service",
			ConfigSHA256: sha256Hex(cfg), Config: cfg, PrevHead: last, GapSeconds: -419, PrevStopped: true})
		jump := f.append(start.Add(30*time.Second), model.TypeClockJump, clockJumpRecord{ClockJump: model.ClockJump{JumpMs: -600000},
			BetweenRuns: true, PrevCheckSeq: 2, CheckSeq: ms.Seq + 1})
		rvSamples(f, start.Add(40*time.Second), 6, 10*time.Second, model.StateOnline, "", model.AttrNone, "")
		_, z, r := rvExport(t, f, d(30, 0), contracts.ExportRequest{From: d(0, 0), To: d(20, 0)})
		var entry *custodyEntry
		for i := range r.Custody {
			if c := &r.Custody[i]; c.Seq != nil && *c.Seq == ms.Seq {
				entry = c
			}
		}
		if entry == nil {
			t.Fatalf("no custody entry for the monitor_start record")
		}
		for _, want := range []string{"this computer's clock read 6m 59s earlier than that record's time (gap_seconds -419: the clock was behind it)",
			fmt.Sprintf("the ledger writer recorded that this computer's clock was behind the newest ledger record (integrity_alert seq %d)", alert.Seq),
			fmt.Sprintf("Between the runs this computer's clock moved -10m 00s against the time servers (clock_jump seq %d)", jump.Seq)} {
			if !strings.Contains(entry.Summary, want) {
				t.Errorf("monitor_start custody entry lacks %q:\n%s", want, entry.Summary)
			}
		}
		if strings.Contains(entry.Summary, "time since it: 0s") {
			t.Errorf("a negative gap reads as no gap:\n%s", entry.Summary)
		}
		if html := string(z.files["REPORT.html"]); !strings.Contains(html, "-10m 00s against the time servers") {
			t.Error("REPORT.html does not show the between-run clock step")
		}
	})

	t.Run("clock moved ahead between the runs", func(t *testing.T) {
		f := cfgLedger(t, d(0, 0), cfg)
		next := rvSamples(f, d(1, 0), 6, 10*time.Second, model.StateOnline, "", model.AttrNone, "")
		f.append(next, model.TypeMonitorStop, model.MonitorStop{Reason: "service stop", UptimeSec: 60})
		last := f.head
		start := next.Add(13 * time.Minute) // 3 minutes later by real time, the clock 10 minutes ahead
		ms := f.append(start, model.TypeMonitorStart, model.MonitorStart{Software: testSoftware, Host: testHost, Mode: "service",
			ConfigSHA256: sha256Hex(cfg), Config: cfg, PrevHead: last, GapSeconds: 780, PrevStopped: true})
		jump := f.append(start.Add(5*time.Second), model.TypeClockJump, clockJumpRecord{ClockJump: model.ClockJump{JumpMs: 600000},
			BetweenRuns: true, PrevCheckSeq: 2, CheckSeq: ms.Seq + 1})
		rvSamples(f, start.Add(10*time.Second), 6, 10*time.Second, model.StateOnline, "", model.AttrNone, "")
		_, _, r := rvExport(t, f, d(30, 0), contracts.ExportRequest{From: d(0, 0), To: d(20, 0)})
		want := fmt.Sprintf("and this computer's clock moved +10m 00s against the time servers between the runs (clock_jump seq %d), "+
			"so the length of this gap as its clock measured it includes that step", jump.Seq)
		var gap *gapEntry
		for i := range r.Summary.Gaps {
			if strings.Contains(r.Summary.Gaps[i].Explanation, want) {
				gap = &r.Summary.Gaps[i]
			}
		}
		if gap == nil {
			t.Fatalf("no gap explained by the clock step: %+v", r.Summary.Gaps)
		}
		found := false
		for _, s := range gap.Evidence {
			found = found || s == jump.Seq
		}
		if !found {
			t.Errorf("gap evidence %v lacks the clock_jump record", gap.Evidence)
		}
	})
}

func TestDNSSuccessfulOnlyWhenResolved(t *testing.T) {
	d := func(m int) time.Time { return time.Date(2026, 10, 3, 12, m, 0, 0, time.UTC) }
	f := rvLedger(t, d(0))
	q := func(role, server, name string, ok bool, rcode string, answers []string, hijacked bool, err string) model.DNSResult {
		return model.DNSResult{Server: server, ServerRole: role, Name: name, QType: "A", OK: ok, RCode: rcode, Answers: answers, Hijacked: hijacked, Err: err}
	}
	const gw, isp, pub, name = "192.168.1.254:53", "68.94.156.9:53", "1.1.1.1:53", "www.google.com"
	a := []string{"142.250.72.4"}
	f.append(d(1), model.TypeServiceCheck, model.ServiceCheck{DNS: []model.DNSResult{
		q("gateway", gw, name, true, "NOERROR", a, false, ""),
		q("isp", isp, name, true, "SERVFAIL", nil, false, ""), q("isp", isp, name, true, "NOERROR", a, false, ""), // retried, resolved
		q("public", pub, name, false, "", nil, false, "timeout"), q("public", pub, name, false, "", nil, false, "timeout"), // failed twice
		q("gateway", gw, "0123456789abcdef.invalid", true, "NXDOMAIN", nil, false, ""),
	}})
	f.append(d(2), model.TypeServiceCheck, model.ServiceCheck{DNS: []model.DNSResult{
		q("gateway", gw, name, true, "NOERROR", nil, false, ""),                   // well-formed, no answer
		q("isp", isp, name, true, "NOERROR", []string{"192.168.1.254"}, true, ""), // redirected
		q("public", pub, name, true, "NOERROR", a, false, ""),                     // resolved
		q("gateway", gw, "fedcba9876543210.invalid", true, "NOERROR", []string{"192.168.1.254"}, true, ""),
	}})
	_, z, r := rvExport(t, f, d(30), contracts.ExportRequest{From: d(0), To: d(10)})
	got := map[string]dnsStat{}
	for _, s := range r.Service.DNS {
		got[s.Role] = s
	}
	for role, want := range map[string]dnsStat{
		"gateway": {Role: "gateway", Server: gw, Checks: 2, Resolved: 1, Retried: 0, Queries: 2, OK: 1, Hijacked: 0},
		"isp":     {Role: "isp", Server: isp, Checks: 2, Resolved: 1, Retried: 1, Queries: 3, OK: 1, Hijacked: 1},
		"public":  {Role: "public", Server: pub, Checks: 2, Resolved: 1, Retried: 1, Queries: 3, OK: 1, Hijacked: 0},
	} {
		if got[role] != want {
			t.Errorf("%s: %+v, want %+v", role, got[role], want)
		}
	}
	if len(r.Service.DNS) != 3 || len(r.Service.InvalidName) != 1 ||
		r.Service.InvalidName[0] != (invalidNameStat{Role: "gateway", Server: gw, Queries: 2, NXDomain: 1, Redirected: 1}) || r.Service.DNSHijacks != 2 {
		t.Fatalf("dns %+v, invalid-name test %+v, hijacks %d", r.Service.DNS, r.Service.InvalidName, r.Service.DNSHijacks)
	}
	html := string(z.files["REPORT.html"])
	for _, want := range []string{"Successful (any attempt)", "Failed (all attempts)",
		"counts as <em>successful</em> only when the resolver answered NOERROR with at least one answer that was not redirected",
		"counted as successful in a check when any of its attempts succeeded, and as failed only when all of them failed",
		`answered "no such name" (NXDOMAIN) 1 time and with an address (redirected) 1 time`} {
		if !strings.Contains(html, want) {
			t.Errorf("REPORT.html lacks %q: %s", want, excerpt(html, want))
		}
	}
}

func TestEgressRouteChecksCounted(t *testing.T) {
	d := func(m int) time.Time { return time.Date(2026, 10, 3, 12, m, 0, 0, time.UTC) }
	f := rvLedger(t, d(0))
	via := &model.EgressCheck{Gateway: "192.168.1.254", GatewayIf: 12, GatewayIfName: "Wi-Fi",
		Routes: []model.EgressRoute{{Target: "1.1.1.1", If: 12, IfName: "Wi-Fi", NextHop: "192.168.1.254", ViaGateway: true}}}
	vpn := &model.EgressCheck{Gateway: "192.168.1.254", GatewayIf: 12, GatewayIfName: "Wi-Fi", Bypass: true,
		Routes: []model.EgressRoute{{Target: "1.1.1.1", If: 23, IfName: "NordLynx", NextHop: "10.5.0.1"}}}
	f.append(d(1), model.TypeLocalLink, model.LocalLink{Interface: "Wi-Fi", Type: "wifi", State: "connected", Egress: via})
	bypass := f.append(d(2), model.TypeLocalLink, model.LocalLink{Interface: "Wi-Fi", Type: "wifi", State: "connected", Egress: vpn})
	f.append(d(3), model.TypeLocalLink, model.LocalLink{Interface: "Wi-Fi", Type: "wifi", State: "connected",
		Egress: &model.EgressCheck{Gateway: "192.168.1.254", Bypass: true, Err: "route to the gateway: not found"}}) // nothing concluded
	f.append(d(4), model.TypeLocalLink, model.LocalLink{Interface: "Wi-Fi", Type: "wifi", State: "connected"})
	_, z, r := rvExport(t, f, d(30), contracts.ExportRequest{From: d(0), To: d(10)})
	ll := r.LocalLink
	if ll.Observations != 4 || ll.EgressChecks != 3 || ll.EgressBypass != 1 || len(ll.EgressBypassSeqs) != 1 || ll.EgressBypassSeqs[0] != bypass.Seq {
		t.Fatalf("local link %+v", ll)
	}
	if html := string(z.files["REPORT.html"]); !strings.Contains(html, fmt.Sprintf("in 1 observation a destination was routed past the gateway</strong> (a VPN tunnel, another network adapter or a hotspot; local_link record seq %d)", bypass.Seq)) {
		t.Error("REPORT.html does not report the route check that bypassed the gateway")
	}
}
