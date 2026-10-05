package export

// Thresholds quoted by the report come from the configuration records contained in the bundle:
// the latest config_state (written at the start of every daily segment) or monitor_start
// (written at every process start) at or before the start of the period. Other configurations
// recorded inside the period are listed with the time each one applied from and until; the
// documented defaults are shown, with a note, only when no usable configuration record is in
// the bundle. Anchors whose TSA certificate chain did not verify when they were obtained show
// the anchor record's chain note.

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"attmonitor/internal/contracts"
	"attmonitor/internal/model"
)

func cfgDay(dd, h, m int) time.Time { return time.Date(2026, 10, dd, h, m, 0, 0, time.UTC) }

// withGatewaySetting returns cfg with one gateway setting replaced: a configuration change that
// is not a threshold (like a new certificate pin).
func withGatewaySetting(t testing.TB, cfg json.RawMessage, key string, value any) json.RawMessage {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(cfg, &m); err != nil {
		t.Fatal(err)
	}
	gw, ok := m["gateway"].(map[string]any)
	if !ok {
		t.Fatal("configuration without gateway object")
	}
	gw[key] = value
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// rawConfigSource returns methodology.config_source of report.json exactly as written.
func rawConfigSource(t *testing.T, z zipContent) map[string]any {
	t.Helper()
	var doc struct {
		Methodology struct {
			ConfigSource map[string]any `json:"config_source"`
		} `json:"methodology"`
	}
	if err := json.Unmarshal(z.files["report.json"], &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Methodology.ConfigSource == nil {
		t.Fatal("report.json has no methodology.config_source")
	}
	return doc.Methodology.ConfigSource
}

// twoProcessLedger: process A starts on day 1 with cfgA; process B starts on day 2 with cfgB and
// runs through day 3, whose segment begins with segment_open, B's first sample and B's
// config_state. It returns the ledger and day 3's config_state record.
func twoProcessLedger(t *testing.T, cfgA, cfgB json.RawMessage) (*fakeLedger, model.Ref) {
	t.Helper()
	f := cfgLedger(t, cfgDay(1, 10, 0), cfgA)
	f.cfgState = cfgA
	rvSamples(f, cfgDay(1, 11, 0), 6, 10*time.Second, model.StateOnline, "", model.AttrNone, "")
	f.cfgState = cfgB
	f.append(cfgDay(2, 8, 0), model.TypeMonitorStart, model.MonitorStart{Software: testSoftware, Host: testHost, Mode: "service",
		ConfigSHA256: sha256Hex(cfgB), Config: cfgB})
	rvSamples(f, cfgDay(2, 9, 0), 6, 5*time.Second, model.StateOnline, "", model.AttrNone, "")
	rvSamples(f, cfgDay(3, 9, 0), 360, 5*time.Second, model.StateOnline, "", model.AttrNone, "") // 09:00 .. 09:30
	cs := f.recordsOfType(model.TypeConfigState)
	if len(cs) != 2 || !strings.HasPrefix(cs[1].TS, "2026-10-03T09:00:01") {
		t.Fatalf("config_state records = %+v", cs)
	}
	return f, cs[1]
}

func checkCfgB(t *testing.T, th thresholds) {
	t.Helper()
	if th.FastIntervalSec != 5 || th.OpenAfterCycles != 4 || th.CloseAfterCycles != 2 || th.WindowCycles != 8 || th.LossDegradedPct != 30 ||
		th.LatencyDegradedMs != 200 || th.GatewayLatencyOkMs != 25 || th.SnapshotFreshnessSec != 90 || th.CoverCapSec != 7.5 || th.GapLimitSec != 15 {
		t.Errorf("thresholds are not those of the configuration record: %+v", th)
	}
}

// The daily config_state at the start of the period's segment states the thresholds although the
// process's monitor_start lies in a segment the bundle leaves out (before config_state records
// existed, such a bundle could only show the documented defaults).
func TestConfigSourceConfigStateBeforePeriod(t *testing.T) {
	cfgA := testConfigJSON(t, "10s", "2m30s", 3, 3, 6, 20, 150, 20)
	cfgB := testConfigJSON(t, "5s", "1m30s", 4, 2, 8, 30, 200, 25)
	f, cs := twoProcessLedger(t, cfgA, cfgB)
	_, z, r := rvExport(t, f, cfgDay(4, 0, 0), contracts.ExportRequest{From: cfgDay(3, 9, 5), To: cfgDay(3, 12, 0)})
	if len(r.Ledger.Omitted) != 1 || r.Ledger.Omitted[0].Name != "ledger-2026-10-02" {
		t.Fatalf("omitted segments = %+v (the test needs B's monitor_start outside the bundle)", r.Ledger.Omitted)
	}

	src := r.Methodology.ConfigSource
	if src.Type != model.TypeConfigState || src.Seq == nil || *src.Seq != cs.Seq || src.TS != cs.TS ||
		src.ConfigSHA256 != sha256Hex(cfgB) || src.Basis != basisAtOrBefore {
		t.Errorf("config_source = %+v, want config_state seq %d at %s", src, cs.Seq, cs.TS)
	}
	th := r.Methodology.Thresholds
	if th.Source != model.TypeConfigState || th.Seq != nil || th.TS != "" || th.ConfigSHA256 != sha256Hex(cfgB) || th.Note != "" ||
		len(th.Changes) != 0 || th.AppliesUntil != r.Period.EffectiveEnd {
		t.Errorf("thresholds = %+v", th)
	}
	checkCfgB(t, th)
	// The time accounting uses B's recorded cycle interval (from its config_state).
	if r.Summary.FastIntervalSec != 5 || !strings.Contains(r.Summary.FastIntervalBasis, "config_state") {
		t.Errorf("fast interval %v (%s)", r.Summary.FastIntervalSec, r.Summary.FastIntervalBasis)
	}

	raw := rawConfigSource(t, z)
	if raw["type"] != "config_state" || raw["seq"] != float64(cs.Seq) || raw["ts"] != cs.TS || raw["config_sha256"] != sha256Hex(cfgB) {
		t.Errorf("report.json methodology.config_source = %v", raw)
	}
	html := string(z.files["REPORT.html"])
	for _, want := range []string{fmt.Sprintf("config_state record seq %d", cs.Seq), "the latest configuration record at or before the start of the period",
		"window loss of at least 30%", "No other configuration is recorded in the period"} {
		if !strings.Contains(html, want) {
			t.Errorf("REPORT.html lacks %q", want)
		}
	}
	if strings.Contains(html, "Documented defaults") {
		t.Error("REPORT.html shows defaults although a config_state record is in the bundle")
	}
}

// A period that starts at midnight begins before the day's config_state (written right after the
// day's first record). No configuration record at or before the start applies (the process that
// wrote the last one was replaced in the left-out day 2), but every record of the period up to
// the config_state was written by the process that wrote it: its thresholds applied from the start.
func TestConfigSourceFirstRecordInPeriod(t *testing.T) {
	cfgA := testConfigJSON(t, "10s", "2m30s", 3, 3, 6, 20, 150, 20)
	cfgB := testConfigJSON(t, "5s", "1m30s", 4, 2, 8, 30, 200, 25)
	f, cs := twoProcessLedger(t, cfgA, cfgB)
	_, z, r := rvExport(t, f, cfgDay(4, 0, 0), contracts.ExportRequest{From: cfgDay(3, 0, 0), To: cfgDay(4, 0, 0)})

	src := r.Methodology.ConfigSource
	if src.Type != model.TypeConfigState || src.Seq == nil || *src.Seq != cs.Seq || src.Basis != basisFirstInPeriod {
		t.Errorf("config_source = %+v, want config_state seq %d (first in the period)", src, cs.Seq)
	}
	th := r.Methodology.Thresholds
	if th.Source != model.TypeConfigState || !strings.Contains(th.Note, "written by another monitor process") ||
		!strings.Contains(th.Note, "first configuration record in the period") || len(th.Changes) != 0 {
		t.Errorf("thresholds = %+v", th)
	}
	checkCfgB(t, th)
	if html := string(z.files["REPORT.html"]); !strings.Contains(html, fmt.Sprintf("config_state record seq %d", cs.Seq)) ||
		strings.Contains(html, "Documented defaults") {
		t.Error("REPORT.html does not quote the config_state record")
	}

	// Records of another process before the first configuration record of the period: its
	// configuration does not describe them, so the defaults are shown and it is listed as a change.
	g := rvLedger(t, cfgDay(3, 1, 0)) // process A: monitor_start without configuration
	rvSamples(g, cfgDay(3, 2, 0), 6, 10*time.Second, model.StateOnline, "", model.AttrNone, "")
	b := g.append(cfgDay(3, 3, 0), model.TypeMonitorStart, model.MonitorStart{Software: testSoftware, Host: testHost, Mode: "service",
		ConfigSHA256: sha256Hex(cfgB), Config: cfgB}) // process B
	rvSamples(g, cfgDay(3, 3, 0).Add(5*time.Second), 6, 5*time.Second, model.StateOnline, "", model.AttrNone, "")
	_, _, r = rvExport(t, g, cfgDay(4, 0, 0), contracts.ExportRequest{From: cfgDay(3, 1, 30), To: cfgDay(3, 12, 0)})
	th = r.Methodology.Thresholds
	if r.Methodology.ConfigSource.Type != "defaults" || th.Source != "defaults" || !strings.Contains(th.Note, "does not contain the configuration") {
		t.Errorf("source %+v, thresholds %+v", r.Methodology.ConfigSource, th)
	}
	if len(th.Changes) != 1 || th.Changes[0].Seq != b.Seq || th.Changes[0].Type != model.TypeMonitorStart ||
		!strings.Contains(strings.Join(th.Changes[0].Changes, "; "), "differs from the values shown above in: fast_interval 10s -> 5s") {
		t.Errorf("changes = %+v", th.Changes)
	}
}

// The same process across a left-out day: its monitor_start applies; a later config_state of
// the same process with another configuration hash (a new certificate pin, the thresholds
// unchanged) is listed as a different configuration, with what differs.
func TestConfigSourceSettingChangedSameProcess(t *testing.T) {
	cfg := testConfigJSON(t, "10s", "2m30s", 3, 3, 6, 20, 150, 20)
	pin := strings.Repeat("5a1f", 16)
	pinned := withGatewaySetting(t, cfg, "pinned_cert_sha256", pin)
	f := cfgLedger(t, cfgDay(1, 10, 0), cfg)
	start := f.head
	f.cfgState = cfg
	rvSamples(f, cfgDay(1, 11, 0), 6, 10*time.Second, model.StateOnline, "", model.AttrNone, "")
	rvSamples(f, cfgDay(2, 9, 0), 6, 10*time.Second, model.StateOnline, "", model.AttrNone, "")
	f.append(cfgDay(2, 12, 0), model.TypeConfigChange, model.ConfigChange{Target: "monitor", What: "gateway.pinned_cert_sha256",
		After: pin, Actor: "operator via web", Result: "applied"})
	f.cfgState = pinned
	rvSamples(f, cfgDay(3, 9, 0), 30, 10*time.Second, model.StateOnline, "", model.AttrNone, "")
	cs := f.recordsOfType(model.TypeConfigState)
	day3 := cs[len(cs)-1]

	_, z, r := rvExport(t, f, cfgDay(4, 0, 0), contracts.ExportRequest{From: cfgDay(3, 0, 0), To: cfgDay(3, 12, 0)})
	src := r.Methodology.ConfigSource
	if src.Type != model.TypeMonitorStart || src.Seq == nil || *src.Seq != start.Seq || src.Basis != basisAtOrBefore ||
		src.ConfigSHA256 != sha256Hex(cfg) {
		t.Errorf("config_source = %+v, want monitor_start seq %d", src, start.Seq)
	}
	th := r.Methodology.Thresholds
	if th.Source != model.TypeMonitorStart || th.Seq == nil || *th.Seq != start.Seq || th.TS != src.TS {
		t.Errorf("thresholds source = %+v", th)
	}
	if len(th.Changes) != 1 {
		t.Fatalf("changes = %+v", th.Changes)
	}
	ch := th.Changes[0]
	joined := strings.Join(ch.Changes, "; ")
	if ch.Type != model.TypeConfigState || ch.Seq != day3.Seq || ch.MonitorStartSeq != nil || ch.TS != day3.TS ||
		ch.ConfigSHA256 != sha256Hex(pinned) || ch.AppliesUntil != r.Period.EffectiveEnd || th.AppliesUntil != day3.TS {
		t.Errorf("change = %+v (thresholds applies until %s)", ch, th.AppliesUntil)
	}
	for _, want := range []string{"the thresholds quoted in this report are unchanged",
		fmt.Sprintf(`gateway.pinned_cert_sha256 "" -> "%s`, pin[:32])} {
		if !strings.Contains(joined, want) {
			t.Errorf("change description %q lacks %q", joined, want)
		}
	}
	html := string(z.files["REPORT.html"])
	for _, want := range []string{"The configuration changed during the period", fmt.Sprintf("config_state seq %d", day3.Seq),
		"pinned_cert_sha256", "start of the period"} {
		if !strings.Contains(html, want) {
			t.Errorf("REPORT.html lacks %q", want)
		}
	}
}

// A restart with other thresholds inside the period: the configuration in force at the start
// (the day's config_state) applies until the new process's monitor_start, which applies until the
// end of the period; each process's samples are accounted with its own cycle interval.
func TestConfigSourceChangeWithinPeriod(t *testing.T) {
	cfg1 := testConfigJSON(t, "10s", "2m30s", 3, 3, 6, 20, 150, 20)
	cfg2 := testConfigJSON(t, "5s", "2m30s", 3, 3, 6, 30, 150, 20)
	f := cfgLedger(t, cfgDay(2, 10, 0), cfg1)
	f.cfgState = cfg1
	rvSamples(f, cfgDay(2, 11, 0), 6, 10*time.Second, model.StateOnline, "", model.AttrNone, "")
	rvSamples(f, cfgDay(3, 5, 0), 60, 10*time.Second, model.StateOnline, "", model.AttrNone, "")
	cs := f.recordsOfType(model.TypeConfigState)[0]
	rvSamples(f, cfgDay(3, 6, 0), 180, 10*time.Second, model.StateOnline, "", model.AttrNone, "") // 06:00 .. 06:29:50
	f.cfgState = cfg2
	b := f.append(cfgDay(3, 12, 0), model.TypeMonitorStart, model.MonitorStart{Software: testSoftware, Host: testHost, Mode: "service",
		ConfigSHA256: sha256Hex(cfg2), Config: cfg2})
	rvSamples(f, cfgDay(3, 12, 0).Add(5*time.Second), 120, 5*time.Second, model.StateOnline, "", model.AttrNone, "")

	_, z, r := rvExport(t, f, cfgDay(4, 0, 0), contracts.ExportRequest{From: cfgDay(3, 6, 0), To: cfgDay(3, 18, 0)})
	src := r.Methodology.ConfigSource
	if src.Type != model.TypeConfigState || src.Seq == nil || *src.Seq != cs.Seq || src.Basis != basisAtOrBefore {
		t.Errorf("config_source = %+v, want config_state seq %d", src, cs.Seq)
	}
	th := r.Methodology.Thresholds
	if th.FastIntervalSec != 10 || th.LossDegradedPct != 20 || th.AppliesUntil != b.TS {
		t.Errorf("thresholds = %+v, want cfg1 until %s", th, b.TS)
	}
	if len(th.Changes) != 1 {
		t.Fatalf("changes = %+v", th.Changes)
	}
	ch := th.Changes[0]
	if ch.Type != model.TypeMonitorStart || ch.Seq != b.Seq || ch.MonitorStartSeq == nil || *ch.MonitorStartSeq != b.Seq || ch.TS != b.TS ||
		ch.ConfigSHA256 != sha256Hex(cfg2) || ch.AppliesUntil != "2026-10-03T18:00:00Z" ||
		strings.Join(ch.Changes, "; ") != "fast_interval 10s -> 5s; loss_degraded_pct 20 -> 30" {
		t.Errorf("change = %+v", ch)
	}
	// 179 cycles of 10 s; the last one of process 1 covers only until its record was written
	// (1.5 s): the process ended after it (the next record is another process's monitor_start),
	// so nothing was observed until process 2 started. Then 119 cycles of 5 s and the last one
	// capped at 7.5 s.
	if want := int64((179*10*time.Second + 1500*time.Millisecond + 119*5*time.Second + 7500*time.Millisecond) / time.Second); r.Summary.MonitoredSec != want {
		t.Errorf("monitored = %d, want %d", r.Summary.MonitoredSec, want)
	}
	html := string(z.files["REPORT.html"])
	for _, want := range []string{"The configuration changed during the period", "fast_interval 10s -&gt; 5s; loss_degraded_pct 20 -&gt; 30",
		fmtUTC(b.TS), "2026-10-03 18:00:00 UTC", fmt.Sprintf("monitor_start seq %d", b.Seq), fmt.Sprintf("config_state record seq %d", cs.Seq)} {
		if !strings.Contains(html, want) {
			t.Errorf("REPORT.html lacks %q", want)
		}
	}
}

// Without any configuration record in the bundle the documented defaults are shown with a note,
// and config_source says so (no record named).
func TestConfigSourceDefaultsWhenNone(t *testing.T) {
	f := newFakeLedger(t)
	f.append(cfgDay(3, 1, 0), model.TypeGenesis, model.Genesis{PublicKey: base64.StdEncoding.EncodeToString(f.pub), Fingerprint: f.fingerprint()})
	rvSamples(f, cfgDay(3, 3, 0), 6, 10*time.Second, model.StateOnline, "", model.AttrNone, "")
	_, z, r := rvExport(t, f, cfgDay(4, 0, 0), contracts.ExportRequest{From: cfgDay(3, 2, 0), To: cfgDay(3, 12, 0)})
	th := r.Methodology.Thresholds
	if th.Source != "defaults" || !strings.Contains(th.Note, "No configuration record (monitor_start or config_state)") ||
		th.FastIntervalSec != 10 || th.LossDegradedPct != 20 || len(th.Changes) != 0 {
		t.Errorf("thresholds = %+v", th)
	}
	raw := rawConfigSource(t, z)
	if len(raw) != 1 || raw["type"] != "defaults" {
		t.Errorf("report.json methodology.config_source = %v, want only type defaults", raw)
	}
	if !strings.Contains(string(z.files["REPORT.html"]), "Documented defaults of rules "+rulesDescribed) {
		t.Error("REPORT.html does not say that defaults are shown")
	}
}

func TestSettingsDiff(t *testing.T) {
	old := json.RawMessage(`{"gateway":{"host":"192.168.1.254","pinned_cert_sha256":"","pages":["a","b"]},"web":{"listen":"127.0.0.1:8320"},` +
		`"probes":{"fast_interval":"10s","targets":[{"name":"gateway_icmp","label":"AT&T gateway","role":"gateway"}]},"empty":{}}`)
	// The same configuration serialized differently (key order, spacing) is not a change.
	same := json.RawMessage(`{ "web": {"listen": "127.0.0.1:8320"}, "empty": {}, "probes": {"targets": [{"role":"gateway","label":"AT&T gateway",` +
		`"name":"gateway_icmp"}], "fast_interval": "10s"}, "gateway": {"pages": ["a","b"], "pinned_cert_sha256": "", "host": "192.168.1.254"} }`)
	if d := settingsDiff(old, same, false); len(d) != 0 {
		t.Errorf("reformatted configuration: %q", d)
	}
	cur := json.RawMessage(`{"gateway":{"host":"192.168.1.254","pinned_cert_sha256":"` + strings.Repeat("ab", 32) + `",` +
		`"pending_cert_sha256":"cd","pages":["a"]},"web":{"listen":"127.0.0.1:8320"},` +
		`"probes":{"fast_interval":"5s","targets":[{"name":"gateway_icmp","label":"AT&T gateway","role":"gateway","target":"192.168.1.254"}]},"empty":{}}`)
	got := strings.Join(settingsDiff(old, cur, false), "; ")
	want := `gateway.pages ["a","b"] -> ["a"]; gateway.pending_cert_sha256 (absent) -> "cd"; ` +
		`gateway.pinned_cert_sha256 "" -> "` + strings.Repeat("ab", 19) + `a...; probes.targets changed`
	if got != want {
		t.Errorf("settingsDiff =\n%s\nwant\n%s", got, want)
	}
	// probes.targets is left out when its internet targets are described as a threshold change;
	// thresholds (fast_interval) never appear here.
	if got := strings.Join(settingsDiff(old, cur, true), "; "); strings.Contains(got, "probes.") {
		t.Errorf("settingsDiff with described targets = %s", got)
	}
	var many strings.Builder
	many.WriteString(`{"y":1,"x":{`)
	for i := 0; i < 13; i++ {
		if i > 0 {
			many.WriteString(",")
		}
		fmt.Fprintf(&many, `"k%02d":%d`, i, i)
	}
	many.WriteString(`}}`)
	if d := settingsDiff(json.RawMessage(`{"y":1}`), json.RawMessage(many.String()), false); len(d) != 11 || d[10] != "and 3 more settings" ||
		d[0] != "x.k00 (absent) -> 0" {
		t.Errorf("capped list = %q", d)
	}
	if settingsDiff(old, json.RawMessage(`{"broken"`), false) != nil || settingsDiff(nil, cur, false) != nil {
		t.Error("an unreadable configuration produced differences")
	}
	if s := abbreviate(strings.Repeat("é", 30), 41); s != strings.Repeat("é", 20)+"..." {
		t.Errorf("abbreviate split a UTF-8 sequence: %q", s)
	}
}

// Two records of one process with the same configuration content but different recorded hashes
// (another serialization) are not a configuration change; a monitor_start without configuration
// whose hash differs ends what is known.
func TestConfigChangesByContent(t *testing.T) {
	cfg := testConfigJSON(t, "10s", "2m30s", 3, 3, 6, 20, 150, 20)
	var m map[string]any
	if err := json.Unmarshal(cfg, &m); err != nil {
		t.Fatal(err)
	}
	indented, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	f := cfgLedger(t, cfgDay(2, 10, 0), cfg)
	f.cfgState = indented
	rvSamples(f, cfgDay(2, 11, 0), 6, 10*time.Second, model.StateOnline, "", model.AttrNone, "")
	rvSamples(f, cfgDay(3, 1, 0), 6, 10*time.Second, model.StateOnline, "", model.AttrNone, "") // config_state: same content, other hash
	old := f.append(cfgDay(3, 2, 0), model.TypeMonitorStart, model.MonitorStart{Software: testSoftware, Host: testHost, Mode: "service",
		ConfigSHA256: strings.Repeat("0", 64)}) // older software: hash only
	rvSamples(f, cfgDay(3, 2, 0).Add(10*time.Second), 6, 10*time.Second, model.StateOnline, "", model.AttrNone, "")
	_, _, r := rvExport(t, f, cfgDay(4, 0, 0), contracts.ExportRequest{From: cfgDay(2, 12, 0), To: cfgDay(3, 12, 0)})
	th := r.Methodology.Thresholds
	if th.Source != model.TypeMonitorStart || len(th.Changes) != 1 || th.Changes[0].Seq != old.Seq ||
		!strings.Contains(th.Changes[0].Changes[0], "does not contain the configuration") ||
		!strings.Contains(th.Changes[0].Changes[0], "thresholds in force from here on are not known") {
		t.Errorf("thresholds = %+v", th)
	}
}

// ---------------------------------------------------------------- anchors: chain note at issue

func TestAnchorChainNoteAtIssueShown(t *testing.T) {
	const note = "system roots: x509: certificate signed by unknown authority (FreeTSA root not installed)"
	d := func(m int) time.Time { return time.Date(2026, 10, 3, 12, m, 0, 0, time.UTC) }
	f := rvLedger(t, d(0))
	rvSamples(f, d(1), 3, 10*time.Second, model.StateOnline, "", model.AttrNone, "")
	digest, _ := hex.DecodeString(f.head.Hash)
	tok := f.putBlob(f.tsa.stamp(t, digest, d(2)))
	noChain := f.append(d(2), model.TypeAnchor, model.Anchor{TSAURL: "https://freetsa.org/tsr", TSAName: "CN=www.freetsa.org",
		HeadSeq: f.head.Seq, HeadHash: f.head.Hash, TokenSHA256: tok, GenTime: d(2).Format(time.RFC3339), Verified: true,
		ChainOK: false, ChainNote: note, Reason: "periodic"}, tok)
	rvSamples(f, d(3), 3, 10*time.Second, model.StateOnline, "", model.AttrNone, "")
	good, _ := rvAnchor(t, f, d(4), nil, "", true)

	for _, tc := range []struct {
		name     string
		verifier contracts.TokenVerifier
		proof    bool // the chain_ok=false anchor is proof of time
	}{
		{"issue-time flags decide", nil, false},
		{"token verifier at export", &fakeTokenVerifier{chainOK: true, tsaName: "CN=Test TSA"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, z, r := rvExport(t, f, d(30), contracts.ExportRequest{From: d(0), To: d(10)}, func(o *Options) { o.TokenVerifier = tc.verifier })
			a := findAnchor(r, noChain.Seq)
			if a == nil || a.ChainOK || a.ChainNoteRec != note || a.ProofOfTime != tc.proof {
				t.Fatalf("anchor = %+v", a)
			}
			if !tc.proof && (!strings.Contains(a.ProofNote, "verified=true, chain_ok=false") || strings.Contains(a.ProofNote, note)) {
				t.Errorf("proof note %q: want the issue-time flags, without repeating the chain note shown next to it", a.ProofNote)
			}
			sec := anchorsInPeriodHTML(string(z.files["REPORT.html"]))
			row := tableRow(sec, fmt.Sprintf(`<td class="mono">%d<br>`, noChain.Seq))
			if !strings.Contains(row, "TSA certificate chain not verified") || strings.Count(row, note) != 1 || !strings.Contains(row, "chain note at issue") {
				t.Errorf("anchor row lacks the chain note at issue (once):\n%s", row)
			}
			okRow := tableRow(sec, fmt.Sprintf(`<td class="mono">%d<br>`, good.Seq))
			if !strings.Contains(okRow, "TSA certificate chain OK") || strings.Contains(okRow, "chain note at issue") {
				t.Errorf("trusted anchor row:\n%s", okRow)
			}
		})
	}
}

// tableRow returns the <tr> of html that contains marker ("" if none).
func tableRow(html, marker string) string {
	i := strings.Index(html, marker)
	if i < 0 {
		return ""
	}
	start := strings.LastIndex(html[:i], "<tr>")
	end := strings.Index(html[i:], "</tr>")
	if start < 0 || end < 0 {
		return ""
	}
	return html[start : i+end]
}

// The Python verifier mentions an anchor whose record says its TSA certificate chain did not
// verify when it was obtained, with the record's chain note on one line.
func TestPythonVerifierChainNoteAtIssue(t *testing.T) {
	py := findPython(t)
	d := func(m int) time.Time { return time.Date(2026, 10, 3, 12, m, 0, 0, time.UTC) }
	f := rvLedger(t, d(0))
	rvSamples(f, d(1), 3, 10*time.Second, model.StateOnline, "", model.AttrNone, "")
	digest, _ := hex.DecodeString(f.head.Hash)
	tok := f.putBlob(f.tsa.stamp(t, digest, d(2)))
	f.append(d(2), model.TypeAnchor, model.Anchor{TSAURL: "https://freetsa.org/tsr", HeadSeq: f.head.Seq, HeadHash: f.head.Hash,
		TokenSHA256: tok, GenTime: d(2).Format(time.RFC3339), Verified: true, ChainOK: false,
		ChainNote: "system roots:\x1b[31m unknown\nauthority", Reason: "periodic"}, tok)
	info, _, _ := rvExport(t, f, d(30), contracts.ExportRequest{From: d(0), To: d(10)})
	out, code := runPython(t, py, shippedScript(t, info.Path), "--openssl-limit", "0", info.Path)
	if code != 0 {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	if !strings.Contains(out, "chain_ok=false") || !strings.Contains(out, "system roots: [31m unknown authority") || strings.Contains(out, "\x1b") {
		t.Errorf("output does not show the sanitized chain note:\n%s", out)
	}
}
