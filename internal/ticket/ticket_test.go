package ticket

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"

	"attmonitor/internal/model"
)

func mustBuild(t *testing.T, s *scenario, o Options) *Report {
	t.Helper()
	rep, err := Build(context.Background(), s.f, o)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	return rep
}

func wantContains(t *testing.T, what, got string, subs ...string) {
	t.Helper()
	for _, s := range subs {
		if !strings.Contains(got, s) {
			t.Errorf("%s: missing %q in:\n%s", what, s, got)
		}
	}
}

func wantNotContains(t *testing.T, what, got string, subs ...string) {
	t.Helper()
	for _, s := range subs {
		if strings.Contains(got, s) {
			t.Errorf("%s: must not contain %q:\n%s", what, s, got)
		}
	}
}

// TestRealSituation checks the report for the situation the ticket is written for.
func TestRealSituation(t *testing.T) {
	s := realScenario(t)
	rep := mustBuild(t, s, s.options())

	// The title names the window (finding: every report had the same, relative title).
	if rep.Title != "AT&T Fiber service problem evidence: 24 hours to 2026-10-05 09:00 CDT" {
		t.Errorf("title = %q", rep.Title)
	}
	if len(rep.Summary) != 4 {
		t.Fatalf("summary has %d bullets", len(rep.Summary))
	}
	for i, key := range []string{"optical", "link", "outages", "home"} {
		if rep.Summary[i].Key != key {
			t.Errorf("bullet %d key = %q, want %q", i, rep.Summary[i].Key, key)
		}
	}

	// (a) the gateway's own optical level and flags: every snapshot plus the setup capture.
	n := len(s.snaps) + 1
	op := rep.Optical
	if len(op.Readings) != n || op.AlarmN != n || op.WarnN != n {
		t.Fatalf("readings %d alarm %d warn %d, want %d each", len(op.Readings), op.AlarmN, op.WarnN, n)
	}
	if !op.Readings[0].Setup || op.Readings[0].RxX10 != -315 || op.Readings[0].Seq != s.boot {
		t.Errorf("first reading = %+v, want the setup capture (-315, bootstrap_import #%d)", op.Readings[0], s.boot)
	}
	a := rep.Bullet("optical").String()
	wantContains(t, "optical bullet", a,
		"The gateway's own low-Rx optical ALARM is active.",
		"between -31.5 and -30.9 dBm",
		fmt.Sprintf("in %d readings", n),
		"low-Rx ALARM threshold is -29.5 dBm and its WARNING threshold is -29.2 dBm",
		fmt.Sprintf("the ALARM flag was set in %d of %d readings (100%%)", n, n),
		fmt.Sprintf("the WARNING flag in %d of %d (100%%)", n, n),
		"Every reading was below both thresholds.",
		"setup-time capture",
		fmt.Sprintf("snapshot #%d", s.snaps[len(s.snaps)-1]))
	wantContains(t, "link bullet", rep.Bullet("link").String(), fmt.Sprintf("The value stayed the same in the %d readings after it.", len(s.snaps)))

	// (b) Last Change with both readings, no restart.
	b := rep.Bullet("link")
	wantContains(t, "link bullet", b.String(),
		"Fiber link state change without a gateway restart.",
		"\"Last Change\" = 1791151188",
		"(first seen 2026-10-05 03:10:46 UTC, the setup-time capture, bootstrap_import #1)",
		"2026-10-04 21:59:48 UTC if the gateway counts in UTC",
		"or 2026-10-05 02:59:48 UTC if in its local time (UTC-05:00 per its own clock)",
		"the gateway does not say which",
		"either way it lies inside this window",
		"The gateway did not restart",
		fmt.Sprintf("its uptime (snapshot #%d) puts its last boot at 2026-10-01 22:52:37 UTC", s.snaps[len(s.snaps)-1]),
		"before this window",
		"while the gateway kept running")
	if len(rep.Link.Changes) != 1 || rep.Link.Restarts != nil {
		t.Errorf("changes %d restarts %v", len(rep.Link.Changes), rep.Link.Restarts)
	}
	if rep.Link.Offset == nil || *rep.Link.Offset != -5*time.Hour {
		t.Errorf("gateway offset = %v", rep.Link.Offset)
	}

	// (c) no outage, with the monitored time.
	c := rep.Bullet("outages").String()
	wantContains(t, "outage bullet", c, "No outage during monitoring.", "No Internet outage was measured during the 1.2 h of monitoring in this window",
		fmt.Sprintf("(all %d measurement cycles ONLINE)", len(s.samples)), "Monitoring covered only 1.2 h of the 24 h window")

	// (d) home network healthy.
	d := rep.Bullet("home").String()
	wantContains(t, "home bullet", d, "The home network was healthy.",
		fmt.Sprintf("reached the gateway in %d of %d pings (0 lost)", len(s.samples), len(s.samples)),
		"median round-trip 2.", "Wi-Fi 5 GHz, 802.11ax, channel 149, signal 82-84%",
		"every route check (8) sent the monitored Internet destinations through the AT&T gateway",
		"measured by the gateway on the fiber from AT&T's network")

	// Requested action cites the device.
	wantContains(t, "action", rep.Action.String(), "dispatch a technician", "fiber terminal / NID", "clean or repair",
		"NOKIA BGW320-505, serial number N00SERIAL00000, firmware 6.34.7", "The fiber link also changed state without a gateway restart")

	// Coverage.
	cv := rep.Coverage
	if cv.Cycles != len(s.samples) || cv.FastInterval != 10*time.Second {
		t.Errorf("cycles %d fast %v", cv.Cycles, cv.FastInterval)
	}
	// 12:45:47.645 .. 14:00:00: every cycle covers 10 s, the last one until the window's end.
	want := int64(s.to.Sub(s.start) / time.Second)
	if cv.MonitoredSec < want-1 || cv.MonitoredSec > want {
		t.Errorf("monitored %d s, want about %d s", cv.MonitoredSec, want)
	}
	if len(cv.Gaps) != 1 || cv.Gaps[0].Kind != "leading" {
		t.Fatalf("gaps = %+v", cv.Gaps)
	}
	wantContains(t, "coverage", cv.Statement, "covered 1.2 h of this 24 h window (5.15%)",
		"from 2026-10-05 07:45:47 CDT (12:45:47 UTC) to 2026-10-05 08:59:57 CDT (13:59:57 UTC), without gaps",
		"the evidence ledger was created only at 2026-10-05 12:45:47 UTC (genesis #0), so the monitor was not installed before then",
		"its uptime (no restart since 2026-10-01 22:52:37 UTC)", "its fiber Last Change value",
		"the setup-time capture of 2026-10-05 03:10:46 UTC (bootstrap_import #1)")

	// Gateway identity from the latest snapshot.
	g := rep.Gateway
	if g.Model != fixModel || g.Serial != fixSerial || g.Firmware != fixFirmware || g.PON != "OPERATION (O5)" || g.SourceSeq != s.snaps[len(s.snaps)-1] {
		t.Errorf("gateway = %+v", g)
	}

	// Evidence: fingerprint, latest trusted anchor, setup tokens.
	ev := rep.Evidence
	if !ev.HasGenesis || !ev.FingerprintOK || ev.GenesisSeq != 0 {
		t.Errorf("genesis: %+v", ev)
	}
	if ev.Anchor == nil || ev.Anchor.TSA != "Free TSA" || ev.Anchor.Uncovered == 0 || ev.Anchor.Covered == 0 {
		t.Errorf("anchor = %+v", ev.Anchor)
	}
	st := ev.Setup
	if st == nil || st.Seq != s.boot || !st.InWindow || st.UptimeSec != 274686 || st.Boot != ts("2026-10-01T22:52:38Z") {
		t.Fatalf("setup = %+v", st)
	}
	if st.Anchor == nil || st.Anchor.HeadSeq != 2 || st.Anchor.TSA != "DigiCert, Inc." {
		t.Errorf("setup anchor = %+v", st.Anchor)
	}
	if len(st.Tokens) != 2 {
		t.Fatalf("tokens = %+v", st.Tokens)
	}
	for _, tk := range st.Tokens {
		if tk.Covers != "BOOTSTRAP-MANIFEST.sha256" || !tk.GenTime.Equal(ts("2026-10-05T03:19:57Z")) || !tk.Granted {
			t.Errorf("token %+v", tk)
		}
	}
	// The capture's manifest lists the captured pages' SHA-256 (TestSetupRealTokens covers a
	// manifest that does not).
	if st.Fiber == nil || len(st.Fiber.ListedIn) != 1 || st.Fiber.ListedIn[0] != "BOOTSTRAP-MANIFEST.sha256" {
		t.Errorf("fiber page listed in %v", st.Fiber)
	}
	// The capture's Last Change is read both ways, with its own clock's offset.
	if ch := st.Change; !ch.Plausible || !ch.AsUTC.Equal(ts("2026-10-04T21:59:48Z")) || !ch.AsLocal.Equal(ts("2026-10-05T02:59:48Z")) {
		t.Errorf("setup change = %+v", ch)
	}
	if len(rep.Notes) != 0 {
		t.Errorf("notes: %v", rep.Notes)
	}
	// Housekeeping events are not listed, the optical alarm event is.
	if len(rep.Events) != 1 || rep.Events[0].Kind != model.GwEvOpticalAlarm || rep.EventsOther != 1 {
		t.Errorf("events = %+v other %d", rep.Events, rep.EventsOther)
	}
}

// TestEmptyWindow: a window without records states that there is no data - no claim at all.
func TestEmptyWindow(t *testing.T) {
	s := realScenario(t)
	o := s.options()
	o.From, o.To = ts("2026-10-03T00:00:00Z"), ts("2026-10-04T00:00:00Z")
	rep := mustBuild(t, s, o)
	if rep.Title != "AT&T Fiber service problem evidence: 24 hours to 2026-10-03 19:00 CDT" {
		t.Errorf("title = %q", rep.Title)
	}
	all := rep.Action.String() + "\n" + rep.Coverage.Statement
	for _, b := range rep.Summary {
		all += "\n" + b.String()
	}
	wantContains(t, "empty window", all,
		"No optical readings from the gateway's fiber diagnostics were recorded in this window.",
		"outside this window",
		"cannot be assessed for it",
		"The monitor recorded no measurement cycles in this window, so no outage can be measured or excluded for it.",
		"No measurements of the home network",
		"its health is unknown",
		"No measurements in this window.",
		"this report alone cannot support a repair request",
		"0 h of 24 h",
		"the evidence ledger did not exist yet")
	wantNotContains(t, "empty window", all, "ALARM flag was set", "did not restart", "No Internet outage was measured",
		"was healthy", "dispatch a technician", "kept running")
	if len(rep.Optical.Readings) != 0 || rep.Optical.Chart != nil || rep.Coverage.Cycles != 0 || rep.Evidence.Anchor != nil {
		t.Errorf("empty window computed data: %+v", rep.Optical)
	}
	if rep.Optical.SetupOutside == nil {
		t.Errorf("the setup capture outside the window should still be mentioned")
	}
	html, err := rep.HTML()
	if err != nil {
		t.Fatal(err)
	}
	wantContains(t, "empty html", string(html), "No optical readings were recorded in this window.", "No measurement cycles were recorded in this window",
		"Records of this window</th><td>none")

	// A ledger with no records at all.
	empty := newFake(t)
	rep, err = Build(context.Background(), empty, Options{Now: func() time.Time { return s.now }, Location: cdt})
	if err != nil {
		t.Fatal(err)
	}
	all = rep.Coverage.Statement
	for _, b := range rep.Summary {
		all += "\n" + b.String()
	}
	wantContains(t, "no ledger", all, "no readings in this window", "not measured in this window", "0 h of 24 h")
	if rep.Evidence.HasGenesis || rep.Evidence.Setup != nil || rep.Gateway.Known {
		t.Errorf("no ledger: %+v", rep.Evidence)
	}
	if _, err := rep.HTML(); err != nil {
		t.Fatal(err)
	}
}

// TestNoClaimsWithoutRecords: each bullet speaks only from its own kind of records.
func TestNoClaimsWithoutRecords(t *testing.T) {
	base := ts("2026-10-05T10:00:00Z")
	t.Run("snapshots only", func(t *testing.T) {
		f := newFake(t)
		for i := 0; i < 5; i++ {
			at := base.Add(time.Duration(i) * time.Minute)
			f.add(at, model.TypeGatewaySnapshot, snapshot(at, -312, true, true, 300000+int64(i*60), lastChange))
		}
		rep, err := Build(context.Background(), f, Options{To: base.Add(time.Hour), From: base.Add(-23 * time.Hour), Now: func() time.Time { return base.Add(time.Hour) }, Location: cdt})
		if err != nil {
			t.Fatal(err)
		}
		wantContains(t, "outages", rep.Bullet("outages").String(), "no measurement cycles", "no outage can be measured or excluded")
		wantContains(t, "home", rep.Bullet("home").String(), "not measured")
		wantContains(t, "optical", rep.Bullet("optical").String(), "ALARM flag was set in 5 of 5 readings (100%)")
		wantNotContains(t, "home", rep.Bullet("home").String(), "healthy.")
		wantNotContains(t, "optical", rep.Bullet("optical").String(), "setup-time capture")
	})
	t.Run("samples only", func(t *testing.T) {
		f := newFake(t)
		for i := 0; i < 30; i++ {
			at := base.Add(time.Duration(i) * 10 * time.Second)
			f.add(at, model.TypeSample, sample(uint64(i+1), at, model.StateOnline, model.AttrNone, true, 2500, true, ""))
		}
		rep, err := Build(context.Background(), f, Options{From: base.Add(-time.Hour), To: base.Add(time.Hour), Now: func() time.Time { return base.Add(time.Hour) }, Location: cdt})
		if err != nil {
			t.Fatal(err)
		}
		wantContains(t, "optical", rep.Bullet("optical").String(), "no readings in this window")
		wantContains(t, "link", rep.Bullet("link").String(), "cannot be assessed")
		wantContains(t, "outages", rep.Bullet("outages").String(), "No Internet outage was measured during the 5 min of monitoring", "(all 30 measurement cycles ONLINE)")
		wantNotContains(t, "action", rep.Action.String(), "dispatch")
		if rep.Title != "AT&T Fiber service problem evidence: 2 hours to 2026-10-05 06:00 CDT" {
			t.Errorf("title = %q", rep.Title)
		}
	})
}

// TestCoverageMath checks cycle covers, gaps and their explanations.
func TestCoverageMath(t *testing.T) {
	f := newFake(t)
	from := ts("2026-10-05T00:00:00Z")
	to := from.Add(2 * time.Hour)
	f.add(from.Add(-time.Hour), model.TypeGenesis, genesisData())
	run1 := from.Add(10 * time.Minute)
	f.add(run1, model.TypeMonitorStart, model.MonitorStart{Mode: "service", Config: testConfig})
	cyc := uint64(0)
	// 30 cycles from 00:10:00, then the monitor stops.
	var last time.Time
	for i := 0; i < 30; i++ {
		cyc++
		last = run1.Add(time.Duration(i) * 10 * time.Second)
		f.add(last.Add(20*time.Millisecond), model.TypeSample, sample(cyc, last, model.StateOnline, model.AttrNone, true, 2000, true, ""))
	}
	f.add(last.Add(5*time.Second), model.TypeMonitorStop, model.MonitorStop{Reason: "service stop"})
	// A new process 20 minutes later, 60 cycles, then the window ends 1 h 10 min later.
	f.run = "ffffffffffffffffffffffffffffffff"
	run2 := last.Add(20 * time.Minute)
	f.add(run2, model.TypeMonitorStart, model.MonitorStart{Mode: "service", Config: testConfig})
	for i := 0; i < 60; i++ {
		cyc++
		at := run2.Add(time.Duration(i) * 10 * time.Second)
		f.add(at.Add(20*time.Millisecond), model.TypeSample, sample(cyc, at, model.StateOnline, model.AttrNone, true, 2000, true, ""))
	}
	rep, err := Build(context.Background(), f, Options{From: from, To: to, Now: func() time.Time { return to }, Location: time.UTC})
	if err != nil {
		t.Fatal(err)
	}
	cv := rep.Coverage
	// Run 1 (stopped): 29 cycles of 10 s + its last cycle only until its record (20 ms); run 2:
	// 59 cycles of 10 s + its last cycle, which nothing follows in the window: 1.5 x 10 s.
	if cv.MonitoredSec != 290+590+15 {
		t.Errorf("monitored %d s, want 895", cv.MonitoredSec)
	}
	if cv.Cycles != 90 {
		t.Errorf("cycles = %d", cv.Cycles)
	}
	if len(cv.Gaps) != 3 {
		t.Fatalf("gaps = %+v", cv.Gaps)
	}
	if g := cv.Gaps[0]; g.Kind != "leading" || g.Sec != 600 || !strings.Contains(g.Why, "monitor started (service mode)") {
		t.Errorf("leading gap %+v", g)
	}
	// From the end of run 1's last cycle (00:14:50.020) to run 2's first (00:34:50).
	if g := cv.Gaps[1]; g.Kind != "inner" || g.Sec != 20*60-1 || !strings.Contains(g.Why, "monitor stopped (service stop)") ||
		!strings.Contains(g.Why, "monitor started (service mode)") {
		t.Errorf("inner gap %+v", g)
	}
	if g := cv.Gaps[2]; g.Kind != "trailing" || g.Sec != int64(to.Sub(run2.Add(59*10*time.Second+15*time.Second))/time.Second) ||
		!strings.Contains(g.Why, "no measurement cycles after this") {
		t.Errorf("trailing gap %+v", g)
	}
	wantContains(t, "coverage", cv.Statement, "covered 14 min of this 2 h window (12.43%)", "with 1 gap (19 min 59 s in total",
		"After 2026-10-05 00:44 UTC: no measurement cycles after this")
	if rep.Avail.Pct != "100%" || rep.Avail.Blips != 0 {
		t.Errorf("avail %+v", rep.Avail)
	}
}

// TestIncidentsAndBlips: provider incidents with their recorded downtime, blips, availability.
func TestIncidentsAndBlips(t *testing.T) {
	f := newFake(t)
	from := ts("2026-10-05T00:00:00Z")
	to := from.Add(24 * time.Hour)
	f.add(from.Add(time.Minute), model.TypeMonitorStart, model.MonitorStart{Mode: "service", Config: testConfig})
	at := from.Add(2 * time.Minute)
	cyc := uint64(0)
	add := func(state, attr, inc string, n int) {
		for i := 0; i < n; i++ {
			cyc++
			ok := state == model.StateOnline
			f.add(at.Add(10*time.Millisecond), model.TypeSample, sample(cyc, at, state, attr, true, 2500, ok, inc))
			at = at.Add(10 * time.Second)
		}
	}
	add(model.StateOnline, model.AttrNone, "", 20)
	add(model.StateISPOutage, model.AttrProvider, "", 2) // a blip: 2 bad cycles, no incident
	add(model.StateOnline, model.AttrNone, "", 20)
	opened := at
	add(model.StateISPOutage, model.AttrProvider, "", 2) // the bad cycles before the incident opens
	add(model.StateISPOutage, model.AttrProvider, "INC-1", 28)
	closed := at
	add(model.StateOnline, model.AttrNone, "", 3)
	inc := model.Incident{ID: "INC-20261005-000522Z", Opened: opened.Format(time.RFC3339Nano), Closed: closed.Format(time.RFC3339Nano),
		DurationSec: 300, State: model.StateISPOutage, Cause: model.CauseFiberLinkDown, Attribution: model.AttrProvider, Rules: "2026.10-4",
		Summary: "No Internet: the gateway reported PON not O5", Stats: model.IncidentStats{DowntimeSec: 300}}
	f.add(opened.Add(30*time.Second), model.TypeIncidentOpen, inc)
	closeSeq := f.add(closed.Add(30*time.Second), model.TypeIncidentClose, inc)
	add(model.StateOnline, model.AttrNone, "", 10)
	local := model.Incident{ID: "INC-20261005-001500Z", Opened: at.Format(time.RFC3339Nano), State: model.StateLocalFault,
		Cause: model.CauseLocalLinkDown, Attribution: model.AttrLocal, Rules: "2026.10-4", Open: true, Stats: model.IncidentStats{}}
	add(model.StateLocalFault, model.AttrLocal, "INC-L", 3)
	f.add(at, model.TypeIncidentOpen, local)
	rep, err := Build(context.Background(), f, Options{From: from, To: to, Now: func() time.Time { return to.Add(time.Hour) }, Location: time.UTC})
	if err != nil {
		t.Fatal(err)
	}
	c := rep.Bullet("outages").String()
	wantContains(t, "outages", c, "1 incident attributed to AT&T",
		fmt.Sprintf("recorded the incident INC-20261005-000522Z attributed to AT&T: 5 min 00 s without Internet (incident_close #%d, downtime_s)", closeSeq),
		"Recorded cause: FIBER_LINK_DOWN: the gateway itself reported its fiber (PON) link down.",
		"1 further incident not attributed to AT&T", "1 brief interruption outside incidents was recorded (2 failed cycles, 20 s, 20 s of it without Internet)")
	if len(rep.Incidents) != 2 || !rep.Incidents[1].OpenAtEnd || rep.Incidents[0].OpenAtEnd {
		t.Fatalf("incidents = %+v", rep.Incidents)
	}
	av := rep.Avail
	if av.Blips != 1 || av.BlipCycles != 2 || av.BlipOutageSec != 20 {
		t.Errorf("blips %+v", av)
	}
	// 53 ONLINE of 88 classified cycles = 60.227...% -> truncated.
	if av.Cycles != 88 || av.Online != 53 || av.Pct != "60.22%" {
		t.Errorf("availability %+v", av)
	}
	wantContains(t, "action", rep.Action.String(), "Please investigate the fiber service.", "1 outage incident attributed to AT&T")
	if rep.IncidentsUnlisted == nil || rep.IncidentsUnlisted[0] != "INC-1" {
		t.Errorf("unlisted = %v", rep.IncidentsUnlisted)
	}
}

// TestLinkEventsAndRestart: an optical_link_change event, a reboot and an uptime reset.
func TestLinkEventsAndRestart(t *testing.T) {
	f := newFake(t)
	from := ts("2026-10-05T00:00:00Z")
	to := from.Add(24 * time.Hour)
	at := from.Add(time.Hour)
	s1 := f.add(at, model.TypeGatewaySnapshot, snapshot(at, -310, true, true, 400000, lastChange))
	at2 := at.Add(time.Minute)
	newChange := at2.Add(-20 * time.Second).Unix() // a flap between the two polls (UTC epoch)
	s2 := f.add(at2, model.TypeGatewaySnapshot, snapshot(at2, -312, true, true, 400060, newChange))
	ev := f.add(at2.Add(time.Millisecond), model.TypeGatewayEvent, model.GatewayEvent{Kind: model.GwEvOpticalLinkChange,
		Before: fmt.Sprint(lastChange), After: fmt.Sprint(newChange), Evidence: []uint64{s1, s2}})
	// Hours later the gateway restarts: uptime resets.
	at3 := at.Add(5 * time.Hour)
	s3 := f.add(at3, model.TypeGatewaySnapshot, snapshot(at3, -305, true, true, 120, at3.Add(-60*time.Second).Unix()))
	reboot := f.add(at3.Add(time.Millisecond), model.TypeGatewayEvent, model.GatewayEvent{Kind: model.GwEvReboot,
		Before: "2026-09-30T13:53:20Z", After: at3.Add(-1200*time.Millisecond - 120*time.Second).UTC().Format(time.RFC3339), Evidence: []uint64{s2, s3}})
	rep, err := Build(context.Background(), f, Options{From: from, To: to, Now: func() time.Time { return to }, Location: cdt})
	if err != nil {
		t.Fatal(err)
	}
	lk := rep.Link
	if len(lk.Restarts) != 1 || !strings.Contains(lk.Restarts[0].Source, fmt.Sprintf("gateway_event reboot #%d", reboot)) {
		t.Fatalf("restarts = %+v", lk.Restarts)
	}
	if len(lk.Changes) != 2 {
		t.Fatalf("changes = %+v", lk.Changes)
	}
	evCh, resetCh := lk.Changes[0], lk.Changes[1]
	if !evCh.Event || evCh.Seq != ev || evCh.Restart != "" || !evCh.AsUTC.Equal(time.Unix(newChange, 0)) {
		t.Errorf("event change = %+v", evCh)
	}
	if resetCh.Restart == "" || resetCh.Seq != s3 {
		t.Errorf("change at the restart = %+v", resetCh)
	}
	b := rep.Bullet("link").String()
	v3 := at3.Add(-60 * time.Second).Unix()
	wantContains(t, "link", b, "Fiber link state change not at a gateway restart; the gateway also restarted once.",
		fmt.Sprintf("During monitoring the optical link changed state twice: Last Change %d and %d = 01:00:40 and 05:59:00 UTC on 2026-10-05", newChange, v3),
		fmt.Sprintf("(gateway_event optical_link_change #%d; snapshot #%d); 1 of them at a gateway restart", ev, s3),
		"That supports the UTC reading of all these Last Change values.",
		"from the uptime reading of snapshot",
		"The gateway restarted in this window at about")
	wantNotContains(t, "link", b, "(s)")
	// The event is bracketed by the two snapshots it compares: only the UTC reading lies between them.
	if !evCh.UTCPossible || evCh.LocalPossible || evCh.PrevObserved.IsZero() || rep.Link.Confirmed != "UTC" {
		t.Errorf("bracketing: %+v confirmed %q", evCh, rep.Link.Confirmed)
	}
	// The first observed value predates the window: it is not a change in the window.
	if lk.First.InWindow || lk.First.Value != lastChange {
		t.Errorf("first = %+v", lk.First)
	}
}

// TestInterpret checks the two readings of a Last Change value.
func TestInterpret(t *testing.T) {
	c := &collector{from: ts("2026-10-04T12:47:00Z"), to: ts("2026-10-05T12:47:00Z")}
	obs := ts("2026-10-05T03:10:46Z")
	minus5 := -5 * time.Hour
	ch := c.interpret(lastChange, time.Time{}, obs, &minus5)
	if !ch.Plausible || !ch.AsUTC.Equal(ts("2026-10-04T21:59:48Z")) || !ch.AsLocal.Equal(ts("2026-10-05T02:59:48Z")) ||
		!ch.UTCPossible || !ch.LocalPossible || !ch.InWindow {
		t.Errorf("interpret = %+v", ch)
	}
	// Observed 03:00 UTC: the local reading (02:59:48 UTC) is still possible, 03:20 would not be.
	early := ts("2026-10-05T02:00:00Z")
	if ch := c.interpret(lastChange, time.Time{}, early, &minus5); !ch.UTCPossible || ch.LocalPossible {
		t.Errorf("a reading after the observation must be impossible: %+v", ch)
	}
	zero := time.Duration(0)
	if ch := c.interpret(lastChange, time.Time{}, obs, &zero); !ch.AsLocal.Equal(ch.AsUTC) {
		t.Errorf("offset 0: %+v", ch)
	}
	if ch := c.interpret(lastChange, time.Time{}, obs, nil); !ch.AsLocal.IsZero() || !ch.InWindow {
		t.Errorf("unknown offset: %+v", ch)
	}
	if ch := c.interpret(3600, time.Time{}, obs, &minus5); ch.Plausible || ch.InWindow {
		t.Errorf("an accumulated-seconds value is not a time: %+v", ch)
	}
	// clockOffset from the gateway's zone-less clock.
	for _, tc := range []struct {
		raw     string
		fetched string
		want    time.Duration
		ok      bool
	}{
		{"2026-10-04T22:10:44", "2026-10-05T03:10:44.2Z", -5 * time.Hour, true},
		{"2026-10-05T07:46:49", "2026-10-05T12:46:49.382Z", -5 * time.Hour, true},
		{"2026-10-05T12:46:49Z", "2026-10-05T12:46:50Z", 0, true},
		{"2026-10-05T18:16:49", "2026-10-05T12:46:49Z", 5*time.Hour + 30*time.Minute, true},
		{"2026-10-05T07:38:00", "2026-10-05T12:46:49Z", 0, false}, // 8 min off a quarter hour
		{"", "2026-10-05T12:46:49Z", 0, false},
		{"garbage", "2026-10-05T12:46:49Z", 0, false},
	} {
		got, ok := clockOffset(tc.raw, ts(tc.fetched))
		if ok != tc.ok || got != tc.want {
			t.Errorf("clockOffset(%q) = %v, %v; want %v, %v", tc.raw, got, ok, tc.want, tc.ok)
		}
	}
}

// TestDownsampling: at most 30 rows; first, last, min and every flag change are kept.
func TestDownsampling(t *testing.T) {
	base := ts("2026-10-05T00:00:00Z")
	var rs []Reading
	for i := 0; i < 200; i++ {
		rd := Reading{T: base.Add(time.Duration(i) * time.Minute), Seq: uint64(100 + i), RxX10: -310 - int64(i%5), Alarm: true, Warn: true}
		if i >= 90 && i < 95 {
			rd.Alarm = false // the alarm clears for 5 readings
		}
		if i >= 150 && i < 152 {
			rd.Warn = false
		}
		rs = append(rs, rd)
	}
	rs[137].RxX10 = -350 // the minimum
	rows, note := pickRows(rs, MaxTableRows)
	if len(rows) != MaxTableRows {
		t.Fatalf("%d rows", len(rows))
	}
	kept := map[uint64]string{}
	for i, r := range rows {
		kept[r.Seq] = r.Why
		if i > 0 && !rows[i-1].T.Before(r.T) {
			t.Errorf("rows not in time order at %d", i)
		}
	}
	for _, want := range []struct {
		seq uint64
		why string
	}{{100, "first"}, {299, "latest"}, {237, "lowest"}, {190, "flag change"}, {195, "flag change"}, {250, "flag change"}, {252, "flag change"}} {
		if w, ok := kept[want.seq]; !ok || !strings.Contains(w, want.why) {
			t.Errorf("reading #%d kept=%v why=%q, want %q", want.seq, ok, w, want.why)
		}
	}
	if !strings.Contains(note, "30 of 200 readings are listed") {
		t.Errorf("note = %q", note)
	}
	// Few readings: all listed, no note.
	rows, note = pickRows(rs[:12], MaxTableRows)
	if len(rows) != 12 || note != "" {
		t.Errorf("12 readings: %d rows, note %q", len(rows), note)
	}
	// Flapping beyond the table: still at most 30 rows, and said so.
	var flap []Reading
	for i := 0; i < 100; i++ {
		flap = append(flap, Reading{T: base.Add(time.Duration(i) * time.Minute), Seq: uint64(i), RxX10: -300, Alarm: i%2 == 0})
	}
	rows, note = pickRows(flap, MaxTableRows)
	if len(rows) > MaxTableRows || !strings.Contains(note, "29 of the 99 changes of the gateway's flags, evenly chosen") {
		t.Errorf("flapping: %d rows, note %q", len(rows), note)
	}
	if rows[0].Seq != 0 || rows[len(rows)-1].Seq != 99 {
		t.Errorf("flapping: first/last not kept")
	}
}

func mustFloat(t *testing.T, s string) float64 {
	t.Helper()
	var v float64
	if _, err := fmt.Sscan(s, &v); err != nil {
		t.Fatalf("%q: %v", s, err)
	}
	return v
}

// TestBuildErrors: invalid inputs fail cleanly.
func TestBuildErrors(t *testing.T) {
	s := realScenario(t)
	if _, err := Build(context.Background(), nil, Options{}); err == nil {
		t.Error("nil reader accepted")
	}
	o := s.options()
	o.From, o.To = o.To, o.From
	if _, err := Build(context.Background(), s.f, o); err == nil {
		t.Error("inverted window accepted")
	}
	o = s.options()
	o.From = o.To.Add(-40 * 24 * time.Hour)
	if _, err := Build(context.Background(), s.f, o); err == nil {
		t.Error("40-day window accepted")
	}
	s.f.scanErr = errors.New("segment damaged")
	if _, err := Build(context.Background(), s.f, s.options()); err == nil || !strings.Contains(err.Error(), "segment damaged") {
		t.Errorf("scan error = %v", err)
	}
	s.f.scanErr = nil
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Build(ctx, s.f, s.options()); !errors.Is(err, context.Canceled) {
		t.Errorf("canceled: %v", err)
	}
}

// TestUndecodableRecords: damaged record data is noted, never used.
func TestUndecodableRecords(t *testing.T) {
	f := newFake(t)
	at := ts("2026-10-05T10:00:00Z")
	f.addRaw(at, model.TypeGatewaySnapshot, `{"derived":"not an object"}`)
	f.addRaw(at.Add(time.Second), model.TypeSample, `[1,2,3]`)
	rep, err := Build(context.Background(), f, Options{From: at.Add(-time.Hour), To: at.Add(time.Hour), Now: func() time.Time { return at }, Location: time.UTC})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Notes) != 2 || !strings.Contains(rep.Notes[0], "could not be decoded") {
		t.Errorf("notes = %v", rep.Notes)
	}
	if len(rep.Optical.Readings) != 0 || rep.Coverage.Cycles != 0 {
		t.Error("undecodable records were used")
	}
}

func TestFormat(t *testing.T) {
	for _, tc := range []struct {
		n, d int64
		want string
	}{{1, 1, "100%"}, {9999, 10000, "99.99%"}, {99999, 100000, "99.99%"}, {1, 3, "33.33%"}, {2, 3, "66.66%"}, {1, 1000000, "< 0.01%"},
		{0, 5, "0%"}, {1, 2, "50%"}, {5, 0, "n/a"}} {
		if got := fmtShare(tc.n, tc.d); got != tc.want {
			t.Errorf("fmtShare(%d, %d) = %q, want %q", tc.n, tc.d, got, tc.want)
		}
	}
	for v, want := range map[int64]string{-315: "-31.5", -309: "-30.9", 48: "4.8", 0: "0.0", -5: "-0.5"} {
		if got := fmtX10(v); got != want {
			t.Errorf("fmtX10(%d) = %q", v, got)
		}
	}
	for sec, want := range map[int64]string{0: "0 h", 30: "less than 1 min", 1799: "29 min", 3600: "1.0 h", 4452: "1.2 h", 86399: "23.9 h"} {
		if got := fmtHours(sec); got != want {
			t.Errorf("fmtHours(%d) = %q, want %q", sec, got, want)
		}
	}
	if got := groupFingerprint("6961b23fea2d3b8d"); got != "6961 b23f ea2d 3b8d" {
		t.Errorf("groupFingerprint = %q", got)
	}
	if got := fmtBoth(ts("2026-10-05T02:59:48Z"), cdt); got != "2026-10-04 21:59:48 CDT (2026-10-05 02:59:48 UTC)" {
		t.Errorf("fmtBoth = %q", got)
	}
	if got := dnAttr(`CN=DigiCert SHA256 RSA4096 Timestamp Responder 2026 1,O=DigiCert\, Inc.,C=US`, "O"); got != "DigiCert, Inc." {
		t.Errorf("dnAttr = %q", got)
	}
	if !regexp.MustCompile(`^\d+\.\d ms$`).MatchString(fmtMs(2605)) || fmtMs(2605) != "2.6 ms" {
		t.Errorf("fmtMs = %q", fmtMs(2605))
	}
}
