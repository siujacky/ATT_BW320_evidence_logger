package export

// Hostile strings in recorded values (gateway pages, HTTP responses, operator notes, TSA
// names...) must be inert text in REPORT.html and exact in report.json.

import (
	"bytes"
	"context"
	"encoding/hex"
	"html/template"
	"strings"
	"testing"
	"time"

	"attmonitor/internal/contracts"
	"attmonitor/internal/model"
)

func TestHostileStringsEscapedInReportExactInJSON(t *testing.T) {
	const (
		gwModel    = `<script>alert("model")</script>`
		gwSerial   = `<img src=x onerror=alert('serial')>`
		gwFirmware = `"><script>fw()</script>`
		gwMaker    = `<svg onload=alert(1)>NOKIA`
		pon        = `<script>pon()</script> (O5)`
		optical    = `<img src=x onerror=optical()>`
		wanIP      = `<b onmouseover=alert('wan')>198.51.100.7</b>`
		dmiName    = `Rx Power<script>dmi()</script>`
		dmiRaw     = `1 (Threshold <img src=x onerror=thr()>)`
		alarmCode  = `OPTICAL_RX_<script>alarm()</script>`
		evDetail   = `uptime <script>event()</script> moved`
		evBefore   = `<img src=x onerror=before()>`
		body       = "<html><head><script>alert('body')</script></head><body><img src=x onerror=alert(2)>AT&T redirect</body></html>"
		location   = `http://192.168.1.254/<script>loc()</script>`
		why        = `<script>why()</script>`
		dnsAnswer  = `<img src=x onerror=dns()>`
		noteText   = "AT&T ticket <script>alert('note')</script> <img src=x onerror=alert(3)>"
		noteAuthor = `<img src=x onerror=author()>`
		tsaName    = `CN=<script>tsa()</script>`
		tokenTSA   = `CN=<img src=x onerror=alert('tsa')>`
		chainNote  = `system roots: <script>chain()</script>`
		preparedBy = `<script>prep()</script>`
		reqNotes   = "line 1 <img src=x onerror=req()>\nline 2"
		incReason  = `<script>reason()</script>`
		ssid       = `<script>ssid()</script>`
		ccWhat     = `<img src=x onerror=cc()>`
	)
	d := func(m int) time.Time { return time.Date(2026, 10, 3, 12, m, 0, 0, time.UTC) }
	f := rvLedger(t, d(0))
	rvSamples(f, d(1), 6, 10*time.Second, model.StateOnline, "", model.AttrNone, "")
	page := f.putBlob([]byte("fiberstat " + dmiRaw))
	f.append(d(2), model.TypeGatewaySnapshot, model.GatewaySnapshot{
		Pages:     []model.PageCapture{{Page: "fiberstat", Status: 200, FetchedAt: d(2).Format(time.RFC3339Nano), SHA256: page, Stored: true}},
		System:    &model.SystemInfo{Manufacturer: gwMaker, Model: gwModel, Serial: gwSerial, SoftwareVersion: gwFirmware, UptimeSec: 100},
		Broadband: &model.BroadbandStatus{Connection: "Up", PONLinkStatus: pon, IPv4: wanIP},
		Fiber: &model.FiberStatus{OpticalStatus: optical, Measures: []model.DMIMeasure{{Name: dmiName, CurrentRaw: "-315", Current: ip(-315),
			Unit: "0.1dBm", LowAlarm: model.Threshold{Active: true, Raw: dmiRaw, Threshold: ip(-295)}}}},
		Derived: model.GatewayDerived{Reachable: true, BroadbandUp: bp(true), WANIPv4: wanIP, RxPowerX10: ip(-315), RxLowAlarmX10: ip(-295),
			Alarms: []string{alarmCode}, Model: gwModel, Serial: gwSerial, Firmware: gwFirmware, UptimeSec: 100},
		Trigger: "periodic"}, page)
	f.append(d(3), model.TypeGatewayEvent, model.GatewayEvent{Kind: model.GwEvBroadbandState, Before: evBefore, After: "Up", Detail: evDetail})
	f.append(d(4), model.TypeServiceCheck, model.ServiceCheck{
		DNS: []model.DNSResult{{Server: "192.168.1.254:53", ServerRole: "gateway", Name: "www.google.com", QType: "A", OK: true,
			Answers: []string{dnsAnswer}, Hijacked: true, HijackWhy: why}},
		HTTP: []model.HTTPResult{{Name: "msft_connecttest", URL: "http://www.msftconnecttest.com/connecttest.txt", Status: 302,
			Location: location, RemoteAddr: "192.168.1.254:80", BodyPrefix: body, Hijacked: true, HijackWhy: why,
			TLSCertSHA256: strings.Repeat("ab", 32)}},
	})
	f.append(d(5), model.TypeLocalLink, model.LocalLink{Interface: "Wi-Fi", Type: "wifi", State: "connected", SSID: ssid})
	f.append(d(6), model.TypeOperatorNote, model.OperatorNote{Text: noteText, Author: noteAuthor, Source: "web"})
	f.append(d(7), model.TypeConfigChange, model.ConfigChange{Target: "gateway", What: ccWhat, Before: "on", After: "off", Actor: "web", Result: "verified"})
	f.append(d(8), model.TypeIncidentOpen, model.Incident{ID: "INC-20261003-120800Z", Opened: d(8).Format(time.RFC3339Nano), Open: true,
		State: model.StateISPOutage, Cause: model.CauseWANDown, Attribution: model.AttrProvider, Rules: rulesDescribed,
		Summary: incReason, Reasons: []string{incReason}})
	digest, _ := hex.DecodeString(f.head.Hash)
	tok := f.putBlob(f.tsa.stamp(t, digest, d(9)))
	f.append(d(9), model.TypeAnchor, model.Anchor{TSAURL: "https://tsa.example/tsr", TSAName: tsaName, HeadSeq: f.head.Seq, HeadHash: f.head.Hash,
		TokenSHA256: tok, GenTime: d(9).Format(time.RFC3339), Verified: true, ChainOK: false, ChainNote: chainNote, Reason: "periodic"}, tok)
	f.append(d(10), model.TypeBootstrapImport, model.BootstrapImport{SourceDir: `C:\evidence\<script>dir()</script>`, Notes: noteText})

	v := &fakeTokenVerifier{chainOK: false, note: chainNote, tsaName: tokenTSA}
	e, _ := newTestExporter(t, &scenario{f: f, now: d(30)}, t.TempDir(), func(o *Options) { o.TokenVerifier = v })
	info, err := e.Build(context.Background(), contracts.ExportRequest{From: d(0), To: d(20), PreparedBy: preparedBy, Notes: reqNotes})
	if err != nil {
		t.Fatal(err)
	}
	z := readZip(t, info.Path)
	html := string(z.files["REPORT.html"])

	// 1. Nothing hostile survives as markup.
	lower := strings.ToLower(html)
	for _, bad := range []string{"<script", "<img", "<svg onload", "<b onmouseover", "onerror=alert(2)>"} {
		if strings.Contains(lower, bad) {
			i := strings.Index(lower, bad)
			t.Errorf("REPORT.html contains raw %q: ...%s...", bad, html[max(0, i-80):min(len(html), i+80)])
		}
	}
	// 2. Each value is shown, escaped.
	for _, s := range []string{gwModel, gwSerial, gwFirmware, gwMaker, pon, optical, wanIP, dmiName, dmiRaw, evDetail, evBefore,
		body, why, dnsAnswer, noteText, noteAuthor, tsaName, tokenTSA, chainNote, preparedBy, incReason, ssid, ccWhat} {
		if esc := template.HTMLEscapeString(s); !strings.Contains(html, esc) {
			t.Errorf("REPORT.html does not show %q escaped as %q", s, esc)
		}
	}
	if !strings.Contains(html, template.HTMLEscapeString("line 1 <img src=x onerror=req()>")) {
		t.Error("request notes not shown escaped")
	}

	// 3. report.json holds the exact values (no HTML escaping, no rewriting).
	js := z.files["report.json"]
	if !bytes.Contains(js, []byte(`<script>alert(\"model\")</script>`)) || bytes.Contains(js, []byte(`\u003c`)) {
		t.Error("report.json escapes or loses markup characters")
	}
	r := readReportJSON(t, z)
	if len(r.Gateway) != 1 || r.Gateway[0].Model != gwModel || r.Gateway[0].Serial != gwSerial || r.Gateway[0].Firmware != gwFirmware ||
		r.Gateway[0].Manufacturer != gwMaker {
		t.Errorf("gateway identity = %+v", r.Gateway)
	}
	gs := r.GatewayStatus
	if len(gs.PONStatus) != 1 || gs.PONStatus[0].Value != pon || len(gs.OpticalStatus) != 1 || gs.OpticalStatus[0].Value != optical ||
		len(gs.WANIPv4) != 1 || gs.WANIPv4[0] != wanIP {
		t.Errorf("gateway status = %+v", gs)
	}
	if len(r.Optical.LatestDMI) != 1 || r.Optical.LatestDMI[0].Name != dmiName || r.Optical.LatestDMI[0].LowAlarm != dmiRaw {
		t.Errorf("dmi = %+v", r.Optical.LatestDMI)
	}
	if len(r.Optical.Periods) != 1 || r.Optical.Periods[0].Code != alarmCode {
		t.Errorf("alarm periods = %+v", r.Optical.Periods)
	}
	if len(r.GatewayEvents) != 1 || r.GatewayEvents[0].Detail != evDetail || r.GatewayEvents[0].Before != evBefore {
		t.Errorf("events = %+v", r.GatewayEvents)
	}
	var httpEx, dnsEx *hijackExample
	for i := range r.Service.HijackExamples {
		switch x := &r.Service.HijackExamples[i]; x.Kind {
		case "http":
			httpEx = x
		case "dns":
			dnsEx = x
		}
	}
	if httpEx == nil || httpEx.BodyPrefix != body || httpEx.Location != location || httpEx.Why != why || httpEx.Status != 302 ||
		httpEx.TLSCertSHA256 != strings.Repeat("ab", 32) || httpEx.RemoteAddr != "192.168.1.254:80" {
		t.Errorf("http hijack = %+v", httpEx)
	}
	if dnsEx == nil || len(dnsEx.Answers) != 1 || dnsEx.Answers[0] != dnsAnswer || dnsEx.Why != why {
		t.Errorf("dns hijack = %+v", dnsEx)
	}
	if len(r.Anchors) != 1 || r.Anchors[0].TSAName != tsaName || r.Anchors[0].TokenTSAName != tokenTSA || r.Anchors[0].ChainNote != chainNote ||
		r.Anchors[0].ChainNoteRec != chainNote || r.Anchors[0].ProofOfTime {
		t.Errorf("anchor = %+v", r.Anchors)
	}
	if r.Request.PreparedBy != preparedBy || r.Request.Notes != reqNotes {
		t.Errorf("request = %+v", r.Request)
	}
	if len(r.Incidents) != 1 || r.Incidents[0].Incident.Summary != incReason || r.Incidents[0].Incident.Reasons[0] != incReason {
		t.Errorf("incident = %+v", r.Incidents)
	}
	if len(r.LocalLink.SSIDs) != 1 || r.LocalLink.SSIDs[0] != ssid {
		t.Errorf("local link = %+v", r.LocalLink)
	}
	if len(r.Bootstrap) != 1 || r.Bootstrap[0].Notes != noteText {
		t.Errorf("bootstrap = %+v", r.Bootstrap)
	}
	custody := ""
	for _, c := range r.Custody {
		custody += c.Summary + "\n"
	}
	for _, s := range []string{noteText, noteAuthor, ccWhat} {
		if !strings.Contains(custody, s) {
			t.Errorf("custody log does not quote %q exactly", s)
		}
	}
	// The ledger itself is in the bundle byte for byte, hostile strings included.
	if seg := z.files["ledger/ledger-2026-10-03.jsonl"]; !bytes.Equal(seg, f.segmentBytes("ledger-2026-10-03")) {
		t.Error("ledger segment altered")
	}
}

// The chain note of a token verifier (it quotes certificate fields of the token) is kept on one
// line and bounded.
func TestChainNoteFlattenedAndBounded(t *testing.T) {
	s := buildScenario(t)
	note := "line1\nline2\r\n\t" + strings.Repeat("x", 2000)
	e, _ := newTestExporter(t, s, t.TempDir(), func(o *Options) { o.TokenVerifier = &fakeTokenVerifier{chainOK: false, note: note} })
	info, err := e.Build(context.Background(), contracts.ExportRequest{IncidentID: s.incidentID})
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range readReportJSON(t, readZip(t, info.Path)).Anchors {
		if strings.ContainsAny(a.ChainNote, "\r\n\t") || len(a.ChainNote) > 403 || !strings.HasPrefix(a.ChainNote, "line1 line2 x") {
			t.Errorf("chain note = %q (%d bytes)", a.ChainNote[:min(len(a.ChainNote), 40)], len(a.ChainNote))
		}
	}
}
