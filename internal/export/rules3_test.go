package export

// Integration round: the report for rules 2026.10-3 - thresholds quoted from monitor_start
// records, gateway-restart windows, cycle-time accounting from the samples, incident columns
// and the notes about records of older rules versions.

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"testing"
	"time"

	"attmonitor/internal/contracts"
	"attmonitor/internal/model"
)

// testConfigJSON renders a recorded configuration (the JSON of internal/config.Config) with
// the given probe and incident settings.
func testConfigJSON(t testing.TB, fast, freshness string, open, close, window int, loss, lat, gwLat float64, targets ...model.ProbeSpec) json.RawMessage {
	t.Helper()
	if targets == nil {
		targets = []model.ProbeSpec{
			{Name: "gateway_icmp", Kind: model.KindICMP, Role: model.RoleGateway},
			{Name: "inet_icmp_cloudflare", Kind: model.KindICMP, Role: model.RoleInet, Target: "1.1.1.1"},
			{Name: "inet_tcp_cloudflare", Kind: model.KindTCP, Role: model.RoleInet, Target: "1.1.1.1:443"},
			{Name: "inet_icmp_quad9", Kind: model.KindICMP, Role: model.RoleInet, Target: "9.9.9.9"},
		}
	}
	cfg := map[string]any{
		"version": 1,
		"gateway": map[string]any{"host": "192.168.1.254", "scheme": "https", "pinned_cert_sha256": "", "poll_interval": "1m0s"},
		"probes":  map[string]any{"fast_interval": fast, "timeout": "2s", "targets": targets, "dns_name": "www.google.com"},
		"incident": map[string]any{"open_after_cycles": open, "close_after_cycles": close, "window_cycles": window,
			"loss_degraded_pct": loss, "latency_degraded_ms": lat, "gateway_latency_ok_ms": gwLat, "snapshot_freshness": freshness},
		"web": map[string]any{"listen": "127.0.0.1:8320"},
	}
	b, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// cfgLedger starts a ledger whose monitor_start records the given configuration.
func cfgLedger(t *testing.T, t0 time.Time, cfg json.RawMessage) *fakeLedger {
	t.Helper()
	f := newFakeLedger(t)
	f.append(t0, model.TypeGenesis, model.Genesis{PublicKey: base64.StdEncoding.EncodeToString(f.pub), Fingerprint: f.fingerprint(),
		Created: t0.Format(time.RFC3339Nano), Host: testHost, Software: testSoftware, Statement: "rules 2026.10-3 test ledger"})
	f.append(t0.Add(time.Second), model.TypeMonitorStart, model.MonitorStart{Software: testSoftware, Host: testHost, Mode: "service",
		ConfigSHA256: sha256Hex(cfg), Config: cfg})
	return f
}

// ---------------------------------------------------------------- thresholds

func TestThresholdsFromMonitorStart(t *testing.T) {
	d := func(m int) time.Time { return time.Date(2026, 10, 3, 12, m, 0, 0, time.UTC) }
	cfg1 := testConfigJSON(t, "5s", "1m30s", 4, 2, 8, 25, 200, 30)
	f := cfgLedger(t, d(0), cfg1)
	firstStart := f.head.Seq
	next := rvSamples(f, d(1), 12*25, 5*time.Second, model.StateOnline, "", model.AttrNone, "") // 12:01 .. 12:26
	// A restart with another configuration inside the period.
	cfg2 := testConfigJSON(t, "10s", "1m30s", 4, 2, 6, 25, 200, 30)
	f.append(next, model.TypeMonitorStart, model.MonitorStart{Software: testSoftware, Host: testHost, Mode: "service",
		ConfigSHA256: sha256Hex(cfg2), Config: cfg2})
	second := f.head.Seq
	rvSamples(f, next.Add(10*time.Second), 30, 10*time.Second, model.StateOnline, "", model.AttrNone, "")

	_, z, r := rvExport(t, f, d(59), contracts.ExportRequest{From: d(10), To: d(40)})
	th := r.Methodology.Thresholds
	if th.Source != "monitor_start" || th.Seq == nil || *th.Seq != firstStart || th.ConfigSHA256 != sha256Hex(cfg1) || th.Note != "" {
		t.Fatalf("thresholds source = %+v", th)
	}
	if th.FastIntervalSec != 5 || th.OpenAfterCycles != 4 || th.CloseAfterCycles != 2 || th.WindowCycles != 8 || th.LossDegradedPct != 25 ||
		th.LatencyDegradedMs != 200 || th.GatewayLatencyOkMs != 30 || th.SnapshotFreshnessSec != 90 || th.CoverCapSec != 7.5 ||
		th.GapLimitSec != 15 || th.RestartMoveSec != 120 || th.RestartCapSec != 600 ||
		strings.Join(th.InternetTargets, ",") != "1.1.1.1,1.1.1.1:443,9.9.9.9" {
		t.Errorf("thresholds = %+v", th)
	}
	if len(th.Changes) != 1 || th.Changes[0].Seq != second ||
		strings.Join(th.Changes[0].Changes, "; ") != "fast_interval 5s -> 10s; window_cycles 8 -> 6" {
		t.Errorf("changes = %+v", th.Changes)
	}
	// Each process's samples are accounted with its own cycle interval: 12:10-12:26 every
	// 5 s, the last one of that process only until its record was written (1.5 s; the process
	// ended after it), then every 10 s.
	sm := r.Summary
	if sm.FastIntervalSec != 5 || !strings.Contains(sm.FastIntervalBasis, "recorded by the process that wrote the samples") {
		t.Errorf("fast interval %v (%s)", sm.FastIntervalSec, sm.FastIntervalBasis)
	}
	if want := int64((191*5*time.Second + 1500*time.Millisecond + 29*10*time.Second + 15*time.Second) / time.Second); sm.MonitoredSec != want {
		t.Errorf("monitored = %d, want %d", sm.MonitoredSec, want)
	}
	html := string(z.files["REPORT.html"])
	for _, want := range []string{
		"An incident opens when at least 4 of the last 8 measurement cycles are not ONLINE",
		"closes after 2 consecutive ONLINE cycles", "window loss of at least 25%", "exceeded 200 ms", "under 30 ms",
		"each used only if at most 90 s old", "at most 7.5 s (1.5 &times; the cycle interval)", "more than 15 s without a cycle",
		fmt.Sprintf("monitor_start record seq %d", firstStart), "fast_interval 5s -&gt; 10s; window_cycles 8 -&gt; 6",
		"Providers</em> = the distinct internet target addresses (1.1.1.1, 8.8.8.8 in this period)",
	} {
		if !strings.Contains(html, want) {
			t.Errorf("REPORT.html lacks %q", want)
		}
	}
	if strings.Contains(html, "Documented defaults") {
		t.Error("REPORT.html claims defaults although the configuration is recorded")
	}
}

func TestThresholdsNormalizedLikeTheMonitor(t *testing.T) {
	p, err := parseRecordedConfig(testConfigJSON(t, "0s", "-5s", 5, 0, 2, -1, 0, 0))
	if err != nil {
		t.Fatal(err)
	}
	// Non-positive values mean the defaults; a window shorter than the open threshold is
	// widened to it (internal/monitor effectiveIncident and newTracker).
	if p.fast != 10*time.Second || p.fresh != 150*time.Second || p.open != 5 || p.close != 3 || p.window != 5 ||
		p.loss != 20 || p.lat != 150 || p.gwLat != 20 {
		t.Errorf("params = %+v", p)
	}
	// Absent fields keep the defaults; integer durations are nanoseconds.
	p, err = parseRecordedConfig(json.RawMessage(`{"probes":{"fast_interval":15000000000},"incident":{"window_cycles":9}}`))
	if err != nil || p.fast != 15*time.Second || p.window != 9 || p.open != 3 || len(p.targets) != len(defaultInternetTargets) {
		t.Errorf("params = %+v, %v", p, err)
	}
	if _, err := parseRecordedConfig(json.RawMessage(`{"probes":{"fast_interval":"ten seconds"}}`)); err == nil {
		t.Error("an unreadable duration was accepted")
	}
}

func TestThresholdsDefaultsWithNote(t *testing.T) {
	day := func(dd, h int) time.Time { return time.Date(2026, 10, dd, h, 0, 0, 0, time.UTC) }
	cfg := testConfigJSON(t, "10s", "2m30s", 3, 3, 6, 20, 150, 20)

	t.Run("process restarted in omitted segments", func(t *testing.T) {
		f := cfgLedger(t, day(1, 10), cfg) // run A
		rvSamples(f, day(1, 11), 6, 10*time.Second, model.StateOnline, "", model.AttrNone, "")
		f.append(day(2, 8), model.TypeMonitorStart, model.MonitorStart{Software: testSoftware, Host: testHost, Mode: "service",
			ConfigSHA256: sha256Hex(cfg), Config: cfg}) // run B, in the omitted day 2
		rvSamples(f, day(2, 9), 6, 10*time.Second, model.StateOnline, "", model.AttrNone, "")
		rvSamples(f, day(3, 9), 6, 10*time.Second, model.StateOnline, "", model.AttrNone, "")
		_, z, r := rvExport(t, f, day(4, 0), contracts.ExportRequest{From: day(3, 0), To: day(3, 12)})
		th := r.Methodology.Thresholds
		if th.Source != "defaults" || !strings.Contains(th.Note, "written by another monitor process") || th.Seq != nil {
			t.Errorf("thresholds = %+v", th)
		}
		if !strings.Contains(string(z.files["REPORT.html"]), "Documented defaults of rules "+rulesDescribed) {
			t.Error("REPORT.html does not say that defaults are shown")
		}
	})

	t.Run("same process across omitted segments", func(t *testing.T) {
		f := cfgLedger(t, day(1, 10), cfg) // run A keeps running for three days
		start := f.head.Seq
		rvSamples(f, day(1, 11), 6, 10*time.Second, model.StateOnline, "", model.AttrNone, "")
		rvSamples(f, day(2, 9), 6, 10*time.Second, model.StateOnline, "", model.AttrNone, "")
		rvSamples(f, day(3, 9), 6, 10*time.Second, model.StateOnline, "", model.AttrNone, "")
		_, _, r := rvExport(t, f, day(4, 0), contracts.ExportRequest{From: day(3, 0), To: day(3, 12)})
		if len(r.Ledger.Omitted) != 1 {
			t.Fatalf("omitted = %+v", r.Ledger.Omitted)
		}
		if th := r.Methodology.Thresholds; th.Source != "monitor_start" || th.Seq == nil || *th.Seq != start {
			t.Errorf("thresholds = %+v", th)
		}
	})

	t.Run("no monitor_start before the period", func(t *testing.T) {
		cfg := testConfigJSON(t, "10s", "2m30s", 3, 3, 6, 20, 150, 20, defaultTargetSpecs()...)
		f := newFakeLedger(t)
		// The genesis record of the period was written by another process than the monitor_start
		// below, so that record's configuration does not describe it.
		f.append(day(3, 1), model.TypeGenesis, model.Genesis{PublicKey: base64.StdEncoding.EncodeToString(f.pub), Fingerprint: f.fingerprint()})
		f.append(day(3, 2), model.TypeMonitorStart, model.MonitorStart{Software: testSoftware, Mode: "service", ConfigSHA256: sha256Hex(cfg), Config: cfg})
		rvSamples(f, day(3, 3), 6, 10*time.Second, model.StateOnline, "", model.AttrNone, "")
		_, _, r := rvExport(t, f, day(4, 0), contracts.ExportRequest{From: day(3, 0), To: day(3, 12)})
		th := r.Methodology.Thresholds
		if th.Source != "defaults" || !strings.Contains(th.Note, "No configuration record (monitor_start or config_state) written at or before the start of the period") {
			t.Errorf("thresholds = %+v", th)
		}
		// The process that started inside the period confirms the values shown.
		if len(th.Changes) != 1 || !strings.Contains(th.Changes[0].Changes[0], "has the values shown above") {
			t.Errorf("changes = %+v", th.Changes)
		}
		if r.Summary.FastIntervalSec != 10 || !strings.Contains(r.Summary.FastIntervalBasis, "monitor_start") {
			t.Errorf("fast interval %v (%s)", r.Summary.FastIntervalSec, r.Summary.FastIntervalBasis)
		}
	})

	t.Run("ledger created in the period", func(t *testing.T) {
		cfg := testConfigJSON(t, "5s", "2m30s", 3, 3, 6, 20, 150, 20)
		f := newFakeLedger(t)
		f.run = fmt.Sprintf("%032x", 2) // the run id the fake gives the monitor_start below: one process writes both
		f.append(day(3, 1), model.TypeGenesis, model.Genesis{PublicKey: base64.StdEncoding.EncodeToString(f.pub), Fingerprint: f.fingerprint()})
		start := f.append(day(3, 1).Add(time.Second), model.TypeMonitorStart, model.MonitorStart{Software: testSoftware, Mode: "service",
			ConfigSHA256: sha256Hex(cfg), Config: cfg})
		rvSamples(f, day(3, 3), 6, 5*time.Second, model.StateOnline, "", model.AttrNone, "")
		_, _, r := rvExport(t, f, day(4, 0), contracts.ExportRequest{From: day(3, 0), To: day(3, 12)})
		th, src := r.Methodology.Thresholds, r.Methodology.ConfigSource
		if th.Source != "monitor_start" || th.FastIntervalSec != 5 || len(th.Changes) != 0 || src.Seq == nil || *src.Seq != start.Seq ||
			src.Basis != basisFirstInPeriod || !strings.Contains(th.Note, "No configuration record") {
			t.Errorf("thresholds = %+v, source %+v", th, src)
		}
	})

	t.Run("monitor_start without configuration", func(t *testing.T) {
		f := rvLedger(t, day(3, 1)) // its monitor_start has no config
		rvSamples(f, day(3, 3), 6, 30*time.Second, model.StateOnline, "", model.AttrNone, "")
		_, _, r := rvExport(t, f, day(4, 0), contracts.ExportRequest{From: day(3, 2), To: day(3, 12)})
		th := r.Methodology.Thresholds
		if th.Source != "defaults" || !strings.Contains(th.Note, "does not contain the configuration") {
			t.Errorf("thresholds = %+v", th)
		}
		// Without a recorded configuration the cycle interval is measured from the samples.
		if r.Summary.FastIntervalSec != 30 || !strings.Contains(r.Summary.FastIntervalBasis, "median interval between samples") {
			t.Errorf("fast interval %v (%s)", r.Summary.FastIntervalSec, r.Summary.FastIntervalBasis)
		}
	})
}

// defaultTargetSpecs are the internet probes of the default configuration, in its order.
func defaultTargetSpecs() []model.ProbeSpec {
	var out []model.ProbeSpec
	for i, tg := range defaultInternetTargets {
		kind := model.KindICMP
		if strings.Contains(tg, ":") {
			kind = model.KindTCP
		}
		out = append(out, model.ProbeSpec{Name: fmt.Sprintf("inet_%d", i), Kind: kind, Role: model.RoleInet, Target: tg})
	}
	return out
}

// ---------------------------------------------------------------- restart windows

// rvBootSnapshot appends a gateway snapshot reporting the given uptime and firmware.
func rvBootSnapshot(f *fakeLedger, at time.Time, uptime int64, firmware string) model.Ref {
	return f.append(at, model.TypeGatewaySnapshot, model.GatewaySnapshot{
		Pages:   []model.PageCapture{{Page: "sysinfo", Status: 200, FetchedAt: at.Format(time.RFC3339Nano)}},
		System:  &model.SystemInfo{Model: "BGW320-505", Serial: "TESTSERIAL0001", SoftwareVersion: firmware, UptimeSec: uptime},
		Derived: model.GatewayDerived{Reachable: true, UptimeSec: uptime, Firmware: firmware, Serial: "TESTSERIAL0001", Model: "BGW320-505"},
		Trigger: "periodic"})
}

func TestRestartWindowPowerCycle(t *testing.T) {
	d := func(m, s int) time.Time { return time.Date(2026, 10, 3, 12, m, s, 0, time.UTC) }
	cfg := testConfigJSON(t, "10s", "2m30s", 3, 3, 6, 20, 150, 20)
	f := cfgLedger(t, d(0, 0), cfg)
	before := rvBootSnapshot(f, d(0, 30), 900000, "6.34.7")
	next := rvSamples(f, d(1, 0), 6, 10*time.Second, model.StateOnline, "", model.AttrNone, "")
	// The outage exists before the owner power-cycles the gateway (provider time) ...
	next = rvSamples(f, next, 6, 10*time.Second, model.StateISPOutage, model.CauseUpstreamUnreachable, model.AttrProvider, "")
	powerOff := next
	// ... the gateway is off (3 cycles), boots at B, is still unreachable (2 cycles), answers
	// but has no WAN yet (5 cycles), then the Internet is back.
	next = rvSamples(f, next, 3, 10*time.Second, model.StateLocalFault, model.CauseGatewayUnreachable, model.AttrUndetermined, "")
	boot := next.Add(-2 * time.Second)
	next = rvSamples(f, next, 2, 10*time.Second, model.StateLocalFault, model.CauseGatewayUnreachable, model.AttrUndetermined, "")
	next = rvSamples(f, next, 5, 10*time.Second, model.StateISPOutage, model.CauseWANDown, model.AttrProvider, "")
	back := next
	snapAt := back.Add(-4 * time.Second) // during the last cycle without WAN
	after := rvBootSnapshot(f, snapAt, int64(snapAt.Sub(boot)/time.Second), "6.34.7")
	ev := f.append(snapAt.Add(time.Second), model.TypeGatewayEvent, model.GatewayEvent{Kind: model.GwEvReboot,
		Before: d(0, 30).Add(-900000 * time.Second).Format(time.RFC3339Nano), After: boot.Format(time.RFC3339Nano),
		Detail: "gateway uptime went from 900000 s to 60 s", Evidence: []uint64{before.Seq, after.Seq}})
	next = rvSamples(f, next, 6, 10*time.Second, model.StateOnline, "", model.AttrNone, "")
	inc := model.Incident{ID: "INC-20261003-120200Z", Opened: d(2, 0).Format(time.RFC3339Nano), Closed: back.Format(time.RFC3339Nano),
		RecoveredAt: back.Format(time.RFC3339Nano), GatewayRestarts: []string{boot.Format(time.RFC3339)}, DurationSec: 220,
		State: model.StateISPOutage, Cause: model.CauseUpstreamUnreachable, Attribution: model.AttrProvider, Rules: rulesDescribed,
		Stats: model.IncidentStats{Cycles: 16, BadCycles: 16, DowntimeSec: 60, RestartSec: 100}}
	closeRef := f.append(next, model.TypeIncidentClose, inc)

	_, z, r := rvExport(t, f, d(30, 0), contracts.ExportRequest{From: d(0, 0), To: d(10, 0)})
	sm := r.Summary
	// Provider time: only the 6 outage cycles before the power-off. Restart time: the 3 cycles
	// with the gateway off, the 2 booting and the 5 without WAN.
	if sm.ProviderOutageSec != 60 || sm.DowntimeSec != 60 || sm.RestartSec != 100 || sm.ProviderDowntimeSec != 60 {
		t.Errorf("provider outage %d, downtime %d, restart %d", sm.ProviderOutageSec, sm.DowntimeSec, sm.RestartSec)
	}
	if len(sm.GatewayRestarts) != 1 {
		t.Fatalf("restarts = %+v", sm.GatewayRestarts)
	}
	rs := sm.GatewayRestarts[0]
	if rs.BootTime != boot.Format(time.RFC3339Nano) || rs.WindowFrom != powerOff.Format(time.RFC3339Nano) ||
		rs.WindowTo != back.Format(time.RFC3339Nano) || rs.WindowEnd != "internet reachable again" || rs.BadCycles != 10 ||
		rs.RestartSec != 100 || rs.Firmware != "" {
		t.Errorf("restart = %+v", rs)
	}
	srcs := strings.Join(rs.Sources, "; ")
	if !strings.Contains(srcs, fmt.Sprintf("gateway_event reboot (seq %d)", ev.Seq)) || !strings.Contains(srcs, "gateway_restarts of incident INC-20261003-120200Z") {
		t.Errorf("sources = %q", srcs)
	}
	for _, seq := range []uint64{ev.Seq, before.Seq, after.Seq, closeRef.Seq} {
		found := false
		for _, s := range rs.Evidence {
			found = found || s == seq
		}
		if !found {
			t.Errorf("evidence %v lacks seq %d", rs.Evidence, seq)
		}
	}
	if len(r.Incidents) != 1 {
		t.Fatalf("incidents = %+v", r.Incidents)
	}
	ie := r.Incidents[0]
	if ie.Recorded.DowntimeSec == nil || *ie.Recorded.DowntimeSec != 60 || ie.Recorded.RestartSec == nil || *ie.Recorded.RestartSec != 100 ||
		ie.Recorded.DegradedSec == nil || ie.ComputedRestartSec != 100 {
		t.Errorf("incident times = %+v computed %d", ie.Recorded, ie.ComputedRestartSec)
	}
	for _, kf := range ie.KeyFacts {
		if strings.Contains(kf, "did not separate restart time") {
			t.Errorf("a 2026.10-3 incident got the older-rules restart fact: %q", kf)
		}
	}
	html := string(z.files["REPORT.html"])
	for _, want := range []string{"<h3>Gateway restarts</h3>", "internet reachable again", fmtUTC(boot.Format(time.RFC3339Nano)),
		"Gateway restart time", "under rules " + rulesDescribed + " that time is restart time, not provider outage time"} {
		if !strings.Contains(html, want) {
			t.Errorf("REPORT.html lacks %q", want)
		}
	}
}

func TestRestartWindowCappedAtTenMinutes(t *testing.T) {
	start := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	f := cfgLedger(t, start, testConfigJSON(t, "10s", "2m30s", 3, 3, 6, 20, 150, 20))
	next := rvSamples(f, start.Add(time.Minute), 6, 10*time.Second, model.StateOnline, "", model.AttrNone, "")
	next = rvSamples(f, next, 3, 10*time.Second, model.StateLocalFault, model.CauseGatewayUnreachable, model.AttrUndetermined, "")
	boot := next
	next = rvSamples(f, next, 6, 10*time.Second, model.StateLocalFault, model.CauseGatewayUnreachable, model.AttrUndetermined, "")
	// The outage persists for 15 minutes after the boot: everything after boot + 10 min is
	// provider time again.
	next = rvSamples(f, next, 84, 10*time.Second, model.StateISPOutage, model.CauseFiberLinkDown, model.AttrProvider, "")
	f.append(next, model.TypeGatewayEvent, model.GatewayEvent{Kind: model.GwEvReboot, After: boot.Format(time.RFC3339Nano)})
	rvSamples(f, next, 6, 10*time.Second, model.StateOnline, "", model.AttrNone, "")
	_, _, r := rvExport(t, f, start.Add(time.Hour), contracts.ExportRequest{From: start, To: start.Add(30 * time.Minute)})
	sm := r.Summary
	if len(sm.GatewayRestarts) != 1 || sm.GatewayRestarts[0].WindowEnd != "10-minute cap" ||
		sm.GatewayRestarts[0].WindowTo != boot.Add(10*time.Minute).Format(time.RFC3339Nano) {
		t.Fatalf("restarts = %+v", sm.GatewayRestarts)
	}
	// In the window: 9 LOCAL_FAULT cycles and the outage cycles from boot+60 s to boot+590 s
	// (54). Outside: the outage cycles from boot+600 s to boot+890 s (30).
	if sm.RestartSec != 630 || sm.ProviderOutageSec != 300 || sm.DowntimeSec != 300 {
		t.Errorf("restart %d, provider outage %d, downtime %d", sm.RestartSec, sm.ProviderOutageSec, sm.DowntimeSec)
	}
}

func TestRestartBootTimeFromSnapshotAndFirmware(t *testing.T) {
	start := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	f := cfgLedger(t, start, testConfigJSON(t, "10s", "2m30s", 3, 3, 6, 20, 150, 20))
	prev := rvBootSnapshot(f, start.Add(10*time.Second), 500000, "6.34.7")
	next := rvSamples(f, start.Add(time.Minute), 3, 10*time.Second, model.StateOnline, "", model.AttrNone, "")
	boot := next.Add(3 * time.Second)
	next = rvSamples(f, next, 4, 10*time.Second, model.StateLocalFault, model.CauseGatewayUnreachable, model.AttrUndetermined, "")
	next = rvSamples(f, next, 3, 10*time.Second, model.StateISPOutage, model.CauseWANDown, model.AttrProvider, "")
	snapAt := next.Add(-5 * time.Second) // during the last cycle without WAN
	uptime := int64(snapAt.Sub(boot) / time.Second)
	cur := rvBootSnapshot(f, snapAt, uptime, "6.35.1")
	// The monitor could not state the boot times: the event names the snapshots it compared.
	f.append(snapAt.Add(time.Second), model.TypeGatewayEvent, model.GatewayEvent{Kind: model.GwEvReboot, Before: "uptime 500000 s",
		After: fmt.Sprintf("uptime %d s", uptime), Evidence: []uint64{prev.Seq, cur.Seq}})
	fw := f.append(snapAt.Add(2*time.Second), model.TypeGatewayEvent, model.GatewayEvent{Kind: model.GwEvFirmwareChange, Before: "6.34.7",
		After: "6.35.1", Evidence: []uint64{prev.Seq, cur.Seq}})
	rvSamples(f, next, 6, 10*time.Second, model.StateOnline, "", model.AttrNone, "")
	_, z, r := rvExport(t, f, start.Add(time.Hour), contracts.ExportRequest{From: start, To: start.Add(20 * time.Minute)})
	if len(r.Summary.GatewayRestarts) != 1 {
		t.Fatalf("restarts = %+v", r.Summary.GatewayRestarts)
	}
	if html := string(z.files["REPORT.html"]); !strings.Contains(html, "1 gateway restart coincided with a gateway firmware change (an AT&amp;T-pushed update)") {
		t.Error("REPORT.html does not explain the firmware change across the restart")
	}
	rs := r.Summary.GatewayRestarts[0]
	if rs.BootTime != boot.Format(time.RFC3339Nano) || rs.Firmware != fmt.Sprintf("6.34.7 -> 6.35.1 (gateway_event firmware_change seq %d)", fw.Seq) ||
		rs.BadCycles != 7 || r.Summary.ProviderOutageSec != 0 {
		t.Errorf("restart = %+v, provider outage %d", rs, r.Summary.ProviderOutageSec)
	}
}

// Incidents recorded under rules 2026.10-2 counted the time after a gateway restart as
// provider downtime: the report shows the recorded figures, says what differs, and keeps
// that time out of its own provider outage time.
func TestOlderRulesIncidentWithRestart(t *testing.T) {
	start := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	f := rvLedger(t, start)
	at := start.Add(time.Minute)
	sample := func(state, cause, attr, rules string) {
		v := model.Verdict{State: state, Cause: cause, Attribution: attr, Rules: rules}
		gw, inet := state != model.StateLocalFault, state == model.StateOnline
		f.append(at.Add(time.Second), model.TypeSample, model.Sample{Started: at.Format(time.RFC3339Nano), Probes: testProbes(gw, inet, false), Verdict: v})
		at = at.Add(10 * time.Second)
	}
	for i := 0; i < 6; i++ {
		sample(model.StateOnline, "", model.AttrNone, "2026.10-1")
	}
	boot := at
	for i := 0; i < 3; i++ {
		sample(model.StateLocalFault, model.CauseGatewayUnreachable, model.AttrUndetermined, "2026.10-2")
	}
	for i := 0; i < 6; i++ {
		sample(model.StateISPOutage, model.CauseWANDown, model.AttrProvider, "2026.10-2")
	}
	recovered := at
	f.append(at, model.TypeGatewayEvent, model.GatewayEvent{Kind: model.GwEvReboot, After: boot.Format(time.RFC3339Nano)})
	for i := 0; i < 6; i++ {
		sample(model.StateOnline, "", model.AttrNone, "2026.10-2")
	}
	// A record written by rules 2026.10-2: no restart_s, no gateway_restarts, no recovered_at.
	f.append(at, model.TypeIncidentClose, map[string]any{"id": "INC-20261003-120130Z", "opened": boot.Format(time.RFC3339Nano),
		"closed": recovered.Format(time.RFC3339Nano), "open": false, "state": model.StateISPOutage, "cause": model.CauseWANDown,
		"attribution": model.AttrProvider, "rules": "2026.10-2", "first_seq": 0, "summary": "WAN down",
		"stats": map[string]any{"cycles": 9, "bad_cycles": 9, "downtime_s": 60, "degraded_s": 0}})
	_, z, r := rvExport(t, f, start.Add(time.Hour), contracts.ExportRequest{From: start, To: start.Add(20 * time.Minute)})
	if r.Summary.ProviderOutageSec != 0 || r.Summary.RestartSec != 90 {
		t.Errorf("provider outage %d, restart %d", r.Summary.ProviderOutageSec, r.Summary.RestartSec)
	}
	if len(r.Incidents) != 1 {
		t.Fatalf("incidents = %+v", r.Incidents)
	}
	ie := r.Incidents[0]
	if ie.Recorded.DowntimeSec == nil || *ie.Recorded.DowntimeSec != 60 || ie.Recorded.RestartSec != nil || ie.ComputedRestartSec != 90 {
		t.Errorf("incident times = %+v computed %d", ie.Recorded, ie.ComputedRestartSec)
	}
	facts := strings.Join(ie.KeyFacts, "\n")
	if !strings.Contains(facts, "1m 30s of its bad cycles fall inside a gateway-restart window") || !strings.Contains(facts, "rules 2026.10-2") {
		t.Errorf("key facts = %s", facts)
	}
	notes := map[string]rulesNote{}
	for _, n := range r.Methodology.RulesNotes {
		notes[n.Version] = n
	}
	if n := notes["2026.10-2"]; !n.Known || n.Samples != 15 || n.IncidentRecords != 1 || !strings.Contains(strings.Join(n.Differences, " "), "Gateway restarts were not treated specially") {
		t.Errorf("2026.10-2 note = %+v", n)
	}
	if n := notes["2026.10-1"]; !n.Known || n.Samples != 6 || n.IncidentRecords != 0 || !strings.Contains(strings.Join(n.Differences, " "), "refused TCP connection") {
		t.Errorf("2026.10-1 note = %+v", n)
	}
	html := string(z.files["REPORT.html"])
	for _, want := range []string{"Records produced under rules 2026.10-2</strong> (15 samples of the period, 1 incident record in this bundle)",
		"Records produced under rules 2026.10-1", "not recorded", "restart windows computed from the records: 1m 30s", "did not separate restart time"} {
		if !strings.Contains(html, want) {
			t.Errorf("REPORT.html lacks %q", want)
		}
	}
}

// ---------------------------------------------------------------- accounting details

// Provider outage time is the time of the outage cycles, not the span of a provider-attributed
// incident: an intermittent incident spanning 10 minutes with 4 outage cycles counts 40 s.
func TestProviderOutageFromCyclesNotSpans(t *testing.T) {
	start := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	f := rvLedger(t, start)
	const id = "INC-20261003-120100Z"
	next := start.Add(time.Minute)
	for i := 0; i < 4; i++ {
		next = rvSamples(f, next, 1, 10*time.Second, model.StateISPOutage, model.CauseUpstreamUnreachable, model.AttrProvider, id)
		next = rvSamples(f, next, 14, 10*time.Second, model.StateDegraded, model.CausePacketLoss, model.AttrUndetermined, id)
	}
	f.append(next, model.TypeIncidentClose, model.Incident{ID: id, Opened: start.Add(time.Minute).Format(time.RFC3339Nano),
		Closed: next.Format(time.RFC3339Nano), State: model.StateISPOutage, Cause: model.CauseUpstreamUnreachable,
		Attribution: model.AttrProvider, Rules: rulesDescribed, Stats: model.IncidentStats{DowntimeSec: 40, DegradedSec: 560}})
	rvSamples(f, next, 6, 10*time.Second, model.StateOnline, "", model.AttrNone, "")
	_, _, r := rvExport(t, f, start.Add(time.Hour), contracts.ExportRequest{From: start, To: start.Add(30 * time.Minute)})
	sm := r.Summary
	if sm.ProviderIncidents != 1 || sm.ProviderOutageSec != 40 || sm.DowntimeSec != 40 || sm.DegradedSec != 560 || sm.ProviderDegradedSec != 0 {
		t.Errorf("summary = incidents %d, provider outage %d, downtime %d, degraded %d (provider %d)",
			sm.ProviderIncidents, sm.ProviderOutageSec, sm.DowntimeSec, sm.DegradedSec, sm.ProviderDegradedSec)
	}
	if r.Incidents[0].InPeriodSec != 600 || sm.TimeByState[len(sm.TimeByState)-1].State != model.StateISPOutage {
		t.Errorf("incident span %d, time by state %+v", r.Incidents[0].InPeriodSec, sm.TimeByState)
	}
}

func TestAvailabilityExcludesUnknownCycles(t *testing.T) {
	start := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	f := rvLedger(t, start)
	next := rvSamples(f, start.Add(time.Minute), 6, 10*time.Second, model.StateOnline, "", model.AttrNone, "")
	next = rvSamples(f, next, 4, 10*time.Second, model.StateUnknown, "", model.AttrNone, "")
	rvSamples(f, next, 2, 10*time.Second, model.StateDegraded, model.CausePacketLoss, model.AttrUndetermined, "")
	_, _, r := rvExport(t, f, start.Add(time.Hour), contracts.ExportRequest{From: start, To: start.Add(10 * time.Minute)})
	sm := r.Summary
	if sm.Cycles != 12 || sm.CyclesKnown != 8 || sm.AvailabilityPct == nil || *sm.AvailabilityPct != 75 {
		t.Errorf("cycles %d known %d availability %v", sm.Cycles, sm.CyclesKnown, sm.AvailabilityPct)
	}
}

func TestPagesNotAttemptedAreNotFetches(t *testing.T) {
	start := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	f := rvLedger(t, start)
	at := start.Add(time.Minute)
	f.append(at, model.TypeGatewaySnapshot, model.GatewaySnapshot{Pages: []model.PageCapture{
		{Page: "broadbandstatistics", FetchedAt: at.Format(time.RFC3339Nano), Err: "connect: timeout"},
		{Page: "fiberstat", NotAttempted: true}, {Page: "sysinfo", NotAttempted: true}}, Trigger: "cycle_failure"})
	_, _, r := rvExport(t, f, start.Add(time.Hour), contracts.ExportRequest{From: start, To: start.Add(10 * time.Minute)})
	if gs := r.GatewayStatus; gs.PageFetches != 1 || gs.PageErrors != 1 || gs.PagesNotAttempted != 2 {
		t.Errorf("gateway status = %+v", gs)
	}
}

// The methodology says how many samples name the records their verdict used (rules 2026.10-3).
func TestVerdictInputsCounted(t *testing.T) {
	start := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	f := rvLedger(t, start)
	for i := 0; i < 4; i++ {
		at := start.Add(time.Minute + time.Duration(i)*10*time.Second)
		v := model.Verdict{State: model.StateOnline, Attribution: model.AttrNone, Rules: rulesDescribed}
		if i%2 == 0 {
			v.Inputs = &model.VerdictInputs{SnapshotSeq: 1, WindowCycles: 6}
		}
		f.append(at.Add(time.Second), model.TypeSample, model.Sample{Started: at.Format(time.RFC3339Nano), Probes: testProbes(true, true, false), Verdict: v})
	}
	_, z, r := rvExport(t, f, start.Add(time.Hour), contracts.ExportRequest{From: start, To: start.Add(10 * time.Minute)})
	if r.Methodology.SamplesInputs != 2 {
		t.Errorf("samples with inputs = %d", r.Methodology.SamplesInputs)
	}
	if !strings.Contains(string(z.files["REPORT.html"]), "(2 of the 4 samples of this period do)") {
		t.Error("REPORT.html does not count the samples that name their inputs")
	}
}

// Boot times a damaged record could carry (outside 1970..2261) never become restart windows:
// the accounting works in Unix nanoseconds, where they would wrap around.
func TestImplausibleBootTimesIgnored(t *testing.T) {
	start := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	f := rvLedger(t, start)
	next := rvSamples(f, start.Add(time.Minute), 6, 10*time.Second, model.StateISPOutage, model.CauseWANDown, model.AttrProvider, "")
	// 2^64 ns after the second outage cycle: its UnixNano wraps around onto that cycle.
	wraps := start.Add(time.Minute + 10*time.Second).Add(math.MaxInt64).Add(math.MaxInt64).Add(2)
	if wraps.UnixNano() != start.Add(time.Minute+10*time.Second).UnixNano() {
		t.Fatalf("test setup: %s does not wrap", wraps)
	}
	for _, b := range []string{wraps.Format(time.RFC3339Nano), "9999-12-31T23:59:59Z", "0001-01-01T00:00:00Z", "1600-01-01T00:00:00Z"} {
		f.append(next, model.TypeGatewayEvent, model.GatewayEvent{Kind: model.GwEvReboot, After: b})
	}
	f.append(next, model.TypeIncidentUpdate, model.Incident{ID: "INC-20261003-120100Z", Opened: start.Add(time.Minute).Format(time.RFC3339Nano),
		Open: true, State: model.StateISPOutage, Attribution: model.AttrProvider, Rules: rulesDescribed, GatewayRestarts: []string{"2300-01-01T00:00:00Z"}})
	rvSamples(f, next, 6, 10*time.Second, model.StateOnline, "", model.AttrNone, "")
	_, _, r := rvExport(t, f, start.Add(time.Hour), contracts.ExportRequest{From: start, To: start.Add(10 * time.Minute)})
	if len(r.Summary.GatewayRestarts) != 0 || r.Summary.RestartSec != 0 || r.Summary.ProviderOutageSec != 60 {
		t.Errorf("restarts %+v, restart %d, provider outage %d", r.Summary.GatewayRestarts, r.Summary.RestartSec, r.Summary.ProviderOutageSec)
	}
}

// An incident record with an absurd opened time (whose Unix nanoseconds wrap around onto the
// period) must not hide a blip of the period or acquire restart time.
func TestImplausibleIncidentTimesIgnored(t *testing.T) {
	start := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	f := rvLedger(t, start)
	next := rvSamples(f, start.Add(time.Minute), 6, 10*time.Second, model.StateOnline, "", model.AttrNone, "")
	blip := next
	next = rvSamples(f, next, 2, 10*time.Second, model.StateDegraded, model.CausePacketLoss, model.AttrUndetermined, "")
	rvSamples(f, next, 6, 10*time.Second, model.StateOnline, "", model.AttrNone, "")
	wraps := blip.Add(-time.Second).Add(math.MaxInt64).Add(math.MaxInt64).Add(2)
	f.append(next.Add(time.Minute), model.TypeIncidentUpdate, model.Incident{ID: "INC-X", Opened: wraps.Format(time.RFC3339Nano), Open: true,
		State: model.StateDegraded, Attribution: model.AttrUndetermined, Rules: rulesDescribed})
	_, _, r := rvExport(t, f, start.Add(time.Hour), contracts.ExportRequest{From: start, To: start.Add(10 * time.Minute)})
	if r.Summary.Blips != 1 || r.Summary.BlipCycles != 2 || len(r.Incidents) != 0 {
		t.Errorf("blips %d (%d cycles), incidents %+v", r.Summary.Blips, r.Summary.BlipCycles, r.Incidents)
	}
}
