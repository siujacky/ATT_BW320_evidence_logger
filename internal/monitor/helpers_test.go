package monitor

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"attmonitor/internal/model"
)

func TestTruncate(t *testing.T) {
	if truncate("short", 10) != "short" {
		t.Fatal("unchanged")
	}
	got := truncate("ab€cd", 4) // € is 3 bytes at offset 2: must not be split
	if !utf8.ValidString(got) || got != "ab…" {
		t.Fatalf("%q", got)
	}
	if errText(nil) != "" || errText(errors.New("  boom  ")) != "boom" || len(errText(errors.New(strings.Repeat("x", 500)))) > 310 {
		t.Fatal("errText")
	}
}

func TestSnapshotTextFallbacks(t *testing.T) {
	if broadbandText(nil) != "unknown" || ponText(nil) != "not O5 (operational)" || opticalText(nil) != "not Up" {
		t.Fatal("nil snapshot")
	}
	s := &model.GatewaySnapshot{Derived: model.GatewayDerived{BroadbandUp: boolp(false)}}
	if broadbandText(s) != "Down" {
		t.Fatal("derived down")
	}
	s.Derived.BroadbandUp = boolp(true)
	if broadbandText(s) != "Up" {
		t.Fatal("derived up")
	}
	s.Broadband = &model.BroadbandStatus{Connection: "Connecting"}
	if broadbandText(s) != "Connecting" {
		t.Fatal("raw text wins")
	}
	if noWANIPv4(nil) || noWANIPv4(&model.GatewaySnapshot{Broadband: &model.BroadbandStatus{}}) {
		t.Fatal("absence is only claimed for an understood page")
	}
	ok := &model.GatewaySnapshot{Broadband: &model.BroadbandStatus{IPv4: "N/A"}, Derived: model.GatewayDerived{BroadbandUp: boolp(true)}}
	if !noWANIPv4(ok) {
		t.Fatal("N/A is no address")
	}
	ok.Broadband.IPv4 = "203.0.113.5"
	if noWANIPv4(ok) {
		t.Fatal("address present")
	}
	ok.Broadband.IPv4, ok.Broadband.Values = "", map[string]string{"Broadband IPv4 Address": ""}
	if !noWANIPv4(ok) {
		t.Fatal("empty row present")
	}
}

func TestWordingHelpers(t *testing.T) {
	for _, c := range []string{model.CauseFiberLinkDown, model.CauseWANDown, model.CauseISPEdgeUnreachable, model.CauseUpstreamUnreachable,
		model.CauseGatewayUnreachable, model.CauseLocalLinkDown, model.CauseGatewayReboot, model.CausePacketLoss,
		model.CauseHighLatency, model.CauseISPDNSFailure, model.CauseGatewayDNSFailure, model.CauseLocalRoute} {
		if causeFact(c) == "" || causeRank(c) == 99 {
			t.Errorf("cause %s lacks wording or rank", c)
		}
	}
	if causeFact("NEW_CAUSE") != "" || causeRank("NEW_CAUSE") != 99 {
		t.Error("unknown cause")
	}
	for state, want := range map[string][2]string{
		model.StateISPOutage:  {"ISP outage", "ISP outage"},
		model.StateLocalFault: {"Local fault", "local fault"},
		model.StateDegraded:   {"Degraded service", "degraded service"},
		"OTHER":               {"Incident", "incident"},
	} {
		if stateWords(state, true) != want[0] || stateWords(state, false) != want[1] {
			t.Errorf("stateWords %s", state)
		}
	}
	for attr, want := range map[string]string{model.AttrProvider: "provider (AT&T)", model.AttrLocal: "local side", model.AttrUndetermined: "undetermined"} {
		if !strings.Contains(attributionSentence(attr), want) {
			t.Errorf("attribution %s", attr)
		}
	}
	if fmtNum(150) != "150" || fmtNum(12.5) != "12.5" || fmtMs(1949) != "1.9 ms" {
		t.Error("number formatting")
	}
	if probeSubject(model.ProbeResult{Name: "x", Role: model.RoleInet}) != "x" || probeSubject(model.ProbeResult{Target: "1.1.1.1", Role: model.RoleInet}) != "1.1.1.1" {
		t.Error("probe subject")
	}
	if failText(model.ProbeResult{}) != "no reply" || failText(model.ProbeResult{Status: "timeout", Err: "dial: i/o timeout"}) != "timeout: dial: i/o timeout" {
		t.Error("fail text")
	}
	if dnsServer(model.DNSResult{}) != "(unknown)" || dnsServer(model.DNSResult{Server: "[::1]:53"}) != "::1" {
		t.Error("dns server")
	}
	for _, tc := range []struct {
		r    model.DNSResult
		want string
	}{
		{model.DNSResult{OK: true, RCode: "NOERROR", Answers: []string{"1.2.3.4"}, Hijacked: true}, "hijacked answer"},
		{model.DNSResult{OK: false, RCode: "NOERROR"}, "no valid response"},
		{model.DNSResult{OK: true, RCode: "NXDOMAIN"}, "NXDOMAIN"},
	} {
		if got := dnsFailText(tc.r); got != tc.want {
			t.Errorf("dnsFailText %+v = %q", tc.r, got)
		}
	}
	if !isInvalidName("invalid") || !isInvalidName("ABC.INVALID.") || isInvalidName("invalid.example.com") {
		t.Error("isInvalidName")
	}
	if quoteOr("", "(unnamed)") != "(unnamed)" || quoteOr("Wi-Fi", "") != `"Wi-Fi"` {
		t.Error("quoteOr")
	}
	if linkSummary(&model.LocalLink{}) != "" {
		t.Error("empty link summary")
	}
}

func TestMeasureFormatting(t *testing.T) {
	tests := []struct {
		v          int64
		unit, name string
		want       string
	}{
		{-315, "0.1dBm", "Rx Power", "-31.5 dBm"},
		{-315, "", "Rx Power", "-31.5 dBm"},
		{35, "C", "Temperature", "35 °C"},
		{3, "V", "Vcc", "3 V"},
		{6, "mA", "Tx Bias", "6 mA"},
		{7, "", "Other", "7"},
		{7, "units", "Other", "7 units"},
	}
	for _, tc := range tests {
		if got := formatMeasure(tc.v, tc.unit, tc.name); got != tc.want {
			t.Errorf("formatMeasure(%d,%q,%q) = %q", tc.v, tc.unit, tc.name, got)
		}
	}
	if dbm(nil) != "unknown" {
		t.Error("dbm nil")
	}
}

func TestPageErrorsAndBootTime(t *testing.T) {
	s := &model.GatewaySnapshot{Pages: []model.PageCapture{
		{Page: "a", Err: "timeout"}, {Page: "b", LoginPage: true}, {Page: "c", Status: 503}, {Page: "d", Status: 200},
	}}
	if got := pageErrors(s); got != " (a: timeout; b: login page; c: HTTP 503)" {
		t.Fatalf("%q", got)
	}
	if pageErrors(&model.GatewaySnapshot{}) != "" {
		t.Fatal("no errors")
	}
	// bootTime falls back to the snapshot time when sysinfo carries no fetch time.
	at := t0
	s2 := &model.GatewaySnapshot{System: &model.SystemInfo{UptimeSec: 60}}
	if bt, ok := bootTime(s2, at); !ok || !bt.Equal(at.Add(-time.Minute)) {
		t.Fatalf("%v %v", bt, ok)
	}
	if _, ok := bootTime(s2, time.Time{}); ok {
		t.Fatal("no time at all")
	}
	s2.System.UptimeSec = -1
	if _, ok := bootTime(s2, at); ok {
		t.Fatal("unparseable uptime")
	}
	if firmwareOf(&model.GatewaySnapshot{System: &model.SystemInfo{SoftwareVersion: "1.0"}}) != "1.0" || firmwareOf(&model.GatewaySnapshot{}) != "" {
		t.Fatal("firmwareOf")
	}
	if wanIPOf(&model.GatewaySnapshot{Broadband: &model.BroadbandStatus{IPv4: "1.2.3.4"}}) != "1.2.3.4" || wanIPOf(&model.GatewaySnapshot{}) != "" {
		t.Fatal("wanIPOf")
	}
}

func TestClampRTTAndStateCodes(t *testing.T) {
	if clampRTT(-5) != 0 || clampRTT(1<<40) != 1<<31-1 || clampRTT(1500) != 1500 {
		t.Fatal("clampRTT")
	}
	for _, s := range []string{model.StateOnline, model.StateDegraded, model.StateLocalFault, model.StateISPOutage, model.StateUnknown, ""} {
		if stateName(stateCode(s)) != s {
			t.Errorf("round trip %q", s)
		}
	}
	if stateCode("SOMETHING") != stUnknown {
		t.Error("unknown states map to UNKNOWN")
	}
}

func TestKickerAndSleepUntil(t *testing.T) {
	k := newKicker()
	for i := 0; i < 100; i++ {
		k.kick("r")
	}
	if got := k.take(); len(got) != 64 {
		t.Fatalf("reasons are bounded: %d", len(got))
	}
	if len(k.take()) != 0 {
		t.Fatal("take clears")
	}
	ctx := context.Background()
	if !sleepUntil(ctx, time.Now().Add(-time.Second), nil) {
		t.Fatal("past deadline returns at once")
	}
	start := time.Now()
	k.kick("wake") // pending signal from before
	if !sleepUntil(ctx, time.Now().Add(time.Hour), k.ch) || time.Since(start) > time.Second {
		t.Fatal("a kick wakes the sleeper")
	}
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if sleepUntil(cctx, time.Now().Add(time.Hour), nil) || sleepUntil(cctx, time.Now().Add(-time.Hour), nil) {
		t.Fatal("cancelled context")
	}
	if !hasReason([]string{"a", "b"}, "b") || hasReason(nil, "a") {
		t.Fatal("hasReason")
	}
}

func TestMiscUtil(t *testing.T) {
	if len(randomHex(8)) != 16 || randomHex(8) == randomHex(8) {
		t.Fatal("randomHex")
	}
	if hostOnly("1.2.3.4:80") != "1.2.3.4" || hostOnly("1.2.3.4") != "1.2.3.4" {
		t.Fatal("hostOnly")
	}
	if _, ok := parseTS(""); ok {
		t.Fatal("empty ts")
	}
	if _, ok := parseTS("2026-10-05T03:20:00Z"); !ok {
		t.Fatal("ts without fraction")
	}
	if onOff(true) != "on" || onOff(false) != "off" {
		t.Fatal("onOff")
	}
	if b2i(true) != 1 || b2i(false) != 0 {
		t.Fatal("b2i")
	}
}
