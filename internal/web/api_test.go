package web

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"attmonitor/internal/contracts"
	"attmonitor/internal/model"
)

func ptrInt64(v int64) *int64 { return &v }

// ----------------------------------------------------------------------------- status & series

func TestStatusEndpoint(t *testing.T) {
	hs := newHarness(t)
	hs.status.status = model.Status{
		Now:         "2026-10-05T03:20:00Z",
		Verdict:     model.Verdict{State: model.StateISPOutage, Cause: model.CauseFiberLinkDown, Attribution: model.AttrProvider, Reasons: []string{"0/5 internet probes succeeded"}, Rules: "2026.10-1"},
		Conditions:  []model.Condition{{Code: "OPTICAL_RX_LOW_ALARM", Severity: "critical", Message: "Rx -31.5 dBm"}},
		GatewayCert: &model.GatewayCertState{Pinned: testPinnedCert, Pending: testNewCert, Since: "2026-10-05T03:19:00.5Z", Seq: 41},
		Ledger:      model.LedgerStatus{HeadSeq: 9, Fingerprint: strings.Repeat("ab", 32)},
		Stats:       []model.WindowStats{{Window: "24h", AvailabilityPct: 99.5}},
	}
	rec := hs.get("/api/status")
	wantStatus(t, rec, http.StatusOK)
	if ct := rec.Header().Get("Content-Type"); ct != "application/json; charset=utf-8" {
		t.Errorf("Content-Type = %q", ct)
	}
	st := decode[model.Status](t, rec)
	if st.Verdict.Cause != model.CauseFiberLinkDown || len(st.Conditions) != 1 || st.Ledger.HeadSeq != 9 {
		t.Errorf("unexpected status: %+v", st)
	}
	// The dashboard draws the certificate banner and the Gateway page's certificate card from
	// these fields (static/app.js certState).
	if !strings.Contains(rec.Body.String(), `"gateway_cert":{"pinned":"`+testPinnedCert+`","pending":"`+testNewCert+`","since":"2026-10-05T03:19:00.5Z","seq":41}`) {
		t.Errorf("gateway_cert not passed through as the dashboard reads it: %s", rec.Body.String())
	}
	// Nothing pending: only the pin.
	hs.status.status.GatewayCert = &model.GatewayCertState{Pinned: testPinnedCert}
	if body := hs.get("/api/status").Body.String(); !strings.Contains(body, `"gateway_cert":{"pinned":"`+testPinnedCert+`"}`) {
		t.Errorf("gateway_cert without a pending certificate: %s", body)
	}
	// The syslog receiver and the gateway's Syslog setting (static/app.js cardSyslog).
	hs.status.status.Syslog = &model.SyslogStatus{Enabled: true, Listening: true, Listen: "0.0.0.0:514", Received: 3, Recorded: 3,
		LastAt: "2026-10-05T03:19:58.5Z", Last: "<30>Oct  5 03:19:58 BGW320 dhcpd: DHCPACK", State: "off",
		Gateway: &model.SyslogSetting{Enabled: false, Levels: []string{"Error", "Informational"}}, GatewayAt: "2026-10-05T03:00:00Z", GatewaySeq: 12}
	rec = hs.get("/api/status")
	if got := decode[model.Status](t, rec).Syslog; got == nil || !jsonEqual(*got, *hs.status.status.Syslog) {
		t.Errorf("syslog status not passed through: %+v", got)
	}
	if body := rec.Body.String(); !strings.Contains(body, `"syslog":{"enabled":true,"listening":true,"listen":"0.0.0.0:514","received":3,"recorded":3,"dropped":0,"rejected":0,"last_at":`) ||
		!strings.Contains(body, `"gateway":{"enabled":false,"levels":["Error","Informational"]},"gateway_at":"2026-10-05T03:00:00Z","gateway_seq":12,"enforce":false,"state":"off"}`) {
		t.Errorf("syslog status not encoded as the dashboard reads it: %s", body)
	}
	// The syslog store's volume and limits (static/app.js syslogStorePanel).
	hs.status.status.Syslog.Store = &model.SyslogUsage{Bytes: 39_007_846, Chunks: 412, Messages: 98_765, OpenMessages: 12,
		Oldest: "2026-10-01T04:15:00.5Z", Newest: "2026-10-05T03:19:58.5Z", KeepMB: 100, KeepDays: 30}
	if body := hs.get("/api/status").Body.String(); !strings.Contains(body, `"store":{"bytes":39007846,"chunks":412,"messages":98765,"open_messages":12,`+
		`"oldest":"2026-10-01T04:15:00.5Z","newest":"2026-10-05T03:19:58.5Z","keep_mb":100,"keep_days":30}`) {
		t.Errorf("syslog store not encoded as the dashboard reads it: %s", body)
	}

	none := newHarness(t)
	none.srv.status = nil
	wantJSONError(t, none.get("/api/status"), http.StatusServiceUnavailable)
}

func TestSeriesEndpoint(t *testing.T) {
	hs := newHarness(t)
	hs.status.series = map[string]model.Series{
		"6h": {Range: "6h", From: "2026-10-04T21:20:00Z", To: "2026-10-05T03:20:00Z", StepSec: 120,
			Probes:  []model.ProbeSpec{{Name: "gateway_icmp", Role: model.RoleGateway, Kind: model.KindICMP}},
			Points:  []model.SeriesPoint{{T: "2026-10-04T21:20:00Z", State: "ONLINE", RTTms: map[string]float64{"gateway_icmp": 1.9}, Loss: map[string]float64{"gateway_icmp": 0}}},
			Optical: []model.OpticalPoint{{T: "2026-10-04T21:20:00Z", RxX10: ptrInt64(-315), RxLowAlarm: true}}, RxLowAlarmX10: ptrInt64(-295)},
	}
	for _, rng := range []string{"1h", "6h", "24h", "7d"} {
		rec := hs.get("/api/series?range=" + rng)
		wantStatus(t, rec, http.StatusOK)
		s := decode[model.Series](t, rec)
		if s.Range != rng {
			t.Errorf("range %s: got %q", rng, s.Range)
		}
		if s.Points == nil || s.Optical == nil || s.Probes == nil {
			t.Errorf("range %s: nil slices must be []", rng)
		}
	}
	if s := decode[model.Series](t, hs.get("/api/series?range=6h")); len(s.Points) != 1 || *s.RxLowAlarmX10 != -295 {
		t.Errorf("6h series not passed through: %+v", s)
	}
	// Traffic (docs/syslog-snmp-traffic.md §3.3): the dashboard's Traffic chart and daily totals.
	mbps := func(v float64) *float64 { return &v }
	ser := hs.status.series["6h"]
	ser.Traffic = []model.TrafficPoint{{T: "2026-10-04T21:20:00Z", WANRx: mbps(32.8), WANTx: mbps(5), WANRxPeak: mbps(612.5), AtLeast: true, PCRx: mbps(3.25)}}
	ser.TrafficDays = []model.TrafficDay{{Day: "2026-10-04", RxBytes: 41_000_000_000, TxBytes: 6_000_000_000, CoveredS: 86000}}
	ser.HeavyTrafficMbps = 80
	hs.status.series["6h"] = ser
	rec := hs.get("/api/series?range=6h")
	if s := decode[model.Series](t, rec); len(s.Traffic) != 1 || *s.Traffic[0].WANRxPeak != 612.5 || s.Traffic[0].WANTxPeak != nil || len(s.TrafficDays) != 1 || s.HeavyTrafficMbps != 80 {
		t.Errorf("traffic not passed through: %+v", s)
	}
	for _, want := range []string{`"wan_rx_mbps":32.8`, `"wan_rx_peak_mbps":612.5`, `"at_least":true`, `"pc_rx_mbps":3.25`,
		`"traffic_days":[{"day":"2026-10-04","rx_bytes":41000000000,"tx_bytes":6000000000,"covered_s":86000,"complete":false}]`, `"heavy_traffic_mbps":80`} {
		if !strings.Contains(rec.Body.String(), want) {
			t.Errorf("series JSON lacks %s: %s", want, rec.Body.String())
		}
	}
	if s := decode[model.Series](t, hs.get("/api/series")); s.Range != DefaultSeriesRange {
		t.Errorf("default range = %q", s.Range)
	}
	for _, bad := range []string{"2h", "30d", "1H", "%00", "24h;drop"} {
		wantJSONError(t, hs.get("/api/series?range="+url.QueryEscape(bad)), http.StatusBadRequest)
	}
	hs.status.seriesErr = errors.New("series cache unavailable")
	wantJSONError(t, hs.get("/api/series?range=1h"), http.StatusInternalServerError)
	hs.status.seriesErr = contracts.ErrNotFound
	wantJSONError(t, hs.get("/api/series?range=1h"), http.StatusNotFound)
}

// ----------------------------------------------------------------------------- incidents

func testIncidents() []model.Incident {
	return []model.Incident{
		{ID: "INC-20261003-101500Z", Opened: "2026-10-03T10:15:00Z", Closed: "2026-10-03T10:40:00Z", State: "ISP_OUTAGE", Cause: "WAN_DOWN", Attribution: "provider", Rules: "2026.10-1"},
		{ID: "INC-20261005-030000Z", Opened: "2026-10-05T03:00:00.5Z", Open: true, State: "ISP_OUTAGE", Cause: "FIBER_LINK_DOWN", Attribution: "provider", Rules: "2026.10-1",
			FirstSeq: 2, LastSeq: 7, Evidence: []model.EvidenceRef{{Seq: 3, Type: "gateway_snapshot", Note: "gateway reports Down"}, {Seq: 5, Type: "anchor"}, {Seq: 3, Type: "gateway_snapshot"}, {Seq: 999, Type: "sample"}}},
		{ID: "INC-20261004-120000Z", Opened: "2026-10-04T12:00:00Z", Closed: "2026-10-04T12:05:00Z", State: "DEGRADED", Cause: "PACKET_LOSS", Attribution: "undetermined", Rules: "2026.10-1"},
	}
}

func TestIncidentsEndpoint(t *testing.T) {
	hs := newHarness(t)
	hs.status.incidents = testIncidents()
	original := append([]model.Incident(nil), hs.status.incidents...)

	rec := hs.get("/api/incidents")
	wantStatus(t, rec, http.StatusOK)
	list := decode[[]model.Incident](t, rec)
	var ids []string
	for _, i := range list {
		ids = append(ids, i.ID)
	}
	want := []string{"INC-20261005-030000Z", "INC-20261004-120000Z", "INC-20261003-101500Z"}
	if strings.Join(ids, ",") != strings.Join(want, ",") {
		t.Errorf("order = %v, want newest first %v", ids, want)
	}
	for i := range original {
		if hs.status.incidents[i].ID != original[i].ID {
			t.Fatal("handler mutated the slice owned by the StatusSource")
		}
	}
	// Defaults: from = Unix epoch, to = now + 24h.
	if !hs.status.gotFrom.Equal(time.Unix(0, 0)) || !hs.status.gotTo.Equal(time.Date(2026, 10, 6, 3, 20, 0, 0, time.UTC)) {
		t.Errorf("default window = %v .. %v", hs.status.gotFrom, hs.status.gotTo)
	}

	params := []struct {
		q        string
		code     int
		from, to time.Time
	}{
		{"from=2026-10-04T00:00:00Z&to=2026-10-05T00:00:00Z", 200, time.Date(2026, 10, 4, 0, 0, 0, 0, time.UTC), time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC)},
		{"from=2026-10-04T02:00:00%2B02:00", 200, time.Date(2026, 10, 4, 0, 0, 0, 0, time.UTC), time.Time{}},
		{"from=2026-10-04", 200, time.Date(2026, 10, 4, 0, 0, 0, 0, time.UTC), time.Time{}},
		{"from=1791151188", 200, time.Unix(1791151188, 0), time.Time{}},
		{"from=2026-10-04T05:06Z", 200, time.Date(2026, 10, 4, 5, 6, 0, 0, time.UTC), time.Time{}},
		{"from=yesterday", 400, time.Time{}, time.Time{}},
		{"to=2026-13-01", 400, time.Time{}, time.Time{}},
		{"from=2026-10-05&to=2026-10-04", 400, time.Time{}, time.Time{}},
		{"from=2026-10-05&to=2026-10-05", 400, time.Time{}, time.Time{}},
	}
	for _, p := range params {
		t.Run(p.q, func(t *testing.T) {
			rec := hs.get("/api/incidents?" + p.q)
			if p.code != 200 {
				wantJSONError(t, rec, p.code)
				return
			}
			wantStatus(t, rec, 200)
			if !hs.status.gotFrom.Equal(p.from) {
				t.Errorf("from = %v, want %v", hs.status.gotFrom, p.from)
			}
			if !p.to.IsZero() && !hs.status.gotTo.Equal(p.to) {
				t.Errorf("to = %v, want %v", hs.status.gotTo, p.to)
			}
		})
	}

	hs.status.incidents = nil
	rec = hs.get("/api/incidents")
	wantStatus(t, rec, 200)
	if strings.TrimSpace(rec.Body.String()) != "[]" {
		t.Errorf("empty list encoded as %s", rec.Body.String())
	}
}

func TestIncidentDetailEndpoint(t *testing.T) {
	hs := newHarness(t)
	hs.status.incidents = testIncidents()
	hs.reader.recordErr = map[uint64]error{7: errors.New("disk error")}

	rec := hs.get("/api/incidents/INC-20261005-030000Z")
	wantStatus(t, rec, http.StatusOK)
	d := decode[IncidentDetail](t, rec)
	if d.Incident.ID != "INC-20261005-030000Z" {
		t.Fatalf("incident = %+v", d.Incident)
	}
	var seqs []uint64
	for _, r := range d.Records {
		seqs = append(seqs, r.Seq)
		envs, _ := hs.reader.snapshot()
		if r.Envelope != envs[r.Seq] || r.Hash != envs[r.Seq].H {
			t.Errorf("record %d: envelope not passed through exactly", r.Seq)
		}
	}
	if got := toString(seqs); got != "2,3,5" {
		t.Errorf("record seqs = %s, want 2,3,5 (first_seq, evidence de-duplicated, ascending)", got)
	}
	if got := toString(d.Missing); got != "7,999" {
		t.Errorf("missing = %s, want 7,999", got)
	}
	if d.Truncated {
		t.Error("unexpected truncation")
	}

	wantJSONError(t, hs.get("/api/incidents/INC-19990101-000000Z"), http.StatusNotFound)
	for _, bad := range []string{"..%2Fetc", "-INC", "INC%20X", strings.Repeat("A", 65), "%2E%2E"} {
		wantJSONError(t, hs.get("/api/incidents/"+bad), http.StatusBadRequest)
	}

	// Without a reader the incident is still served.
	hs.srv.reader = nil
	d = decode[IncidentDetail](t, hs.get("/api/incidents/INC-20261005-030000Z"))
	if d.Records == nil || len(d.Records) != 0 {
		t.Errorf("records without reader = %v, want []", d.Records)
	}
}

func TestIncidentSeqsTruncation(t *testing.T) {
	inc := model.Incident{FirstSeq: 1}
	for i := 0; i < MaxIncidentRecords+50; i++ {
		inc.Evidence = append(inc.Evidence, model.EvidenceRef{Seq: uint64(1000 - i)})
	}
	seqs, total := incidentSeqs(inc)
	if total != MaxIncidentRecords+51 || len(seqs) != MaxIncidentRecords {
		t.Fatalf("len = %d total = %d", len(seqs), total)
	}
	for i := 1; i < len(seqs); i++ {
		if seqs[i] <= seqs[i-1] {
			t.Fatal("seqs not ascending/unique")
		}
	}
	if seqs[0] != 1 {
		t.Errorf("first seq = %d, want 1", seqs[0])
	}
}

func toString(v []uint64) string {
	var parts []string
	for _, x := range v {
		parts = append(parts, strconv.FormatUint(x, 10))
	}
	return strings.Join(parts, ",")
}

// ----------------------------------------------------------------------------- records

func TestRecordsEndpoint(t *testing.T) {
	hs := newHarness(t)
	envs, bodies := hs.reader.snapshot()

	rec := hs.get("/api/records")
	wantStatus(t, rec, http.StatusOK)
	list := decode[[]RecordView](t, rec)
	if len(list) != len(envs) {
		t.Fatalf("got %d records, want %d", len(list), len(envs))
	}
	if rec.Header().Get("X-Next-Seq") != "" {
		t.Error("X-Next-Seq set although the ledger end was reached")
	}
	for i, r := range list {
		if r.Seq != bodies[i].Seq || r.TS != bodies[i].TS || r.Type != bodies[i].Type || r.Hash != envs[i].H {
			t.Errorf("record %d metadata mismatch: %+v", i, r)
		}
		if r.Envelope != envs[i] {
			t.Errorf("record %d: envelope not exact", i)
		}
		// body is the signed JSON as a JSON value: re-compacting envelope.b must give the same.
		var a, b bytes.Buffer
		if err := json.Compact(&a, r.Body); err != nil {
			t.Fatal(err)
		}
		if err := json.Compact(&b, []byte(envs[i].B)); err != nil {
			t.Fatal(err)
		}
		var x, y any
		json.Unmarshal(a.Bytes(), &x)
		json.Unmarshal(b.Bytes(), &y)
		if !jsonEqual(x, y) {
			t.Errorf("record %d: body differs from envelope.b", i)
		}
		sum := sha256.Sum256([]byte(r.Envelope.B))
		if hex.EncodeToString(sum[:]) != r.Hash {
			t.Errorf("record %d: hash does not cover envelope.b", i)
		}
	}

	tests := []struct {
		q        string
		wantSeqs string
		next     string
	}{
		{"from_seq=5", "5,6,7", ""},
		{"limit=3", "0,1,2", "3"},
		{"from_seq=2&limit=2", "2,3", "4"},
		{"type=sample", "2,4,7", ""},
		{"type=sample&limit=2", "2,4", "5"},
		{"type=sample,anchor", "2,4,5,7", ""},
		{"type=+sample+,,anchor", "2,4,5,7", ""},
		{"exclude=sample", "0,1,3,5,6", ""},
		{"type=sample&exclude=sample", "", ""},
		{"type=custody_export", "", ""},
		{"from_seq=100", "", ""},
		{"limit=100000", "0,1,2,3,4,5,6,7", ""},
	}
	for _, tc := range tests {
		t.Run(tc.q, func(t *testing.T) {
			rec := hs.get("/api/records?" + tc.q)
			wantStatus(t, rec, 200)
			var seqs []uint64
			for _, r := range decode[[]RecordView](t, rec) {
				seqs = append(seqs, r.Seq)
			}
			if got := toString(seqs); got != tc.wantSeqs {
				t.Errorf("seqs = %q, want %q", got, tc.wantSeqs)
			}
			if got := rec.Header().Get("X-Next-Seq"); got != tc.next {
				t.Errorf("X-Next-Seq = %q, want %q", got, tc.next)
			}
		})
	}

	for _, bad := range []string{"from_seq=-1", "from_seq=abc", "limit=0", "limit=-5", "limit=x", "type=Sample", "type=a-b", "type=" + strings.Repeat("a", 41), "exclude=../x"} {
		t.Run("bad "+bad, func(t *testing.T) {
			wantJSONError(t, hs.get("/api/records?"+bad), http.StatusBadRequest)
		})
	}

	hs.reader.scanErr = errors.New("segment unreadable")
	wantJSONError(t, hs.get("/api/records"), http.StatusInternalServerError)
	hs.reader.scanErr = nil

	hs.srv.reader = nil
	wantJSONError(t, hs.get("/api/records"), http.StatusServiceUnavailable)
}

func TestRecordsLimitClampedTo500(t *testing.T) {
	types := make([]string, 620)
	for i := range types {
		types[i] = "heartbeat"
	}
	hs := newHarness(t)
	hs.reader = newTestLedger(types...)
	hs.srv.reader = hs.reader
	rec := hs.get("/api/records?limit=10000")
	wantStatus(t, rec, 200)
	if n := len(decode[[]RecordView](t, rec)); n != MaxRecordLimit {
		t.Fatalf("got %d records, want %d", n, MaxRecordLimit)
	}
	if got := rec.Header().Get("X-Next-Seq"); got != "500" {
		t.Errorf("X-Next-Seq = %q", got)
	}
	if n := len(decode[[]RecordView](t, hs.get("/api/records"))); n != DefaultRecordLimit {
		t.Errorf("default limit gave %d records", n)
	}
}

func TestRecordsScanBudget(t *testing.T) {
	old := recordScanBudget
	recordScanBudget = 3
	defer func() { recordScanBudget = old }()
	hs := newHarness(t)
	rec := hs.get("/api/records?type=operator_note") // the only note is seq 6
	wantStatus(t, rec, 200)
	if n := len(decode[[]RecordView](t, rec)); n != 0 {
		t.Errorf("got %d records within a 3-record budget", n)
	}
	if got := rec.Header().Get("X-Next-Seq"); got != "3" {
		t.Errorf("X-Next-Seq = %q, want 3 (continue after the budget)", got)
	}
	// Following X-Next-Seq visits every record exactly once and finds the note.
	var found []uint64
	from, pages := "0", 0
	for ; from != "" && pages < 10; pages++ {
		rec := hs.get("/api/records?type=operator_note&from_seq=" + from)
		wantStatus(t, rec, 200)
		for _, r := range decode[[]RecordView](t, rec) {
			found = append(found, r.Seq)
		}
		from = rec.Header().Get("X-Next-Seq")
	}
	if toString(found) != "6" || pages != 3 {
		t.Errorf("found %v in %d pages, want [6] in 3 pages", found, pages)
	}
}

func TestRecordsInvalidBodyJSONStillEncodes(t *testing.T) {
	hs := newHarness(t)
	hs.reader.mu.Lock()
	hs.reader.envs[1].B = "{not json"
	hs.reader.mu.Unlock()
	rec := hs.get("/api/records")
	wantStatus(t, rec, 200)
	list := decode[[]RecordView](t, rec)
	var b model.Body
	if err := json.Unmarshal(list[1].Body, &b); err != nil || b.Seq != 1 || b.Type != "monitor_start" {
		t.Errorf("fallback body = %s (%v)", list[1].Body, err)
	}
	if list[1].Envelope.B != "{not json" {
		t.Error("damaged envelope must still be returned exactly")
	}
}

func jsonEqual(a, b any) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return bytes.Equal(x, y)
}

// ----------------------------------------------------------------------------- blobs

func TestBlobDownload(t *testing.T) {
	hs := newHarness(t)
	content := []byte("<html><body>Rx Power Currently -315 \xa9 2026</body></html>\r\n\x00\xff")
	id := hs.reader.addBlob(content)

	rec := hs.get("/api/blobs/" + id)
	wantStatus(t, rec, http.StatusOK)
	if !bytes.Equal(rec.Body.Bytes(), content) {
		t.Fatal("blob bytes not exact")
	}
	h := rec.Header()
	if got := h.Get("Content-Type"); got != "application/octet-stream" {
		t.Errorf("Content-Type = %q", got)
	}
	if got := h.Get("Content-Disposition"); got != `attachment; filename="`+id+`.bin"` {
		t.Errorf("Content-Disposition = %q", got)
	}
	if got := h.Get("X-Content-SHA256"); got != id {
		t.Errorf("X-Content-SHA256 = %q", got)
	}
	if got := h.Get("Content-Length"); got != strconv.Itoa(len(content)) {
		t.Errorf("Content-Length = %q", got)
	}
	assertSecurityHeaders(t, h, false)

	// HEAD and Range work like for any static resource.
	head := hs.serve(hs.request(http.MethodHead, "/api/blobs/"+id, nil, nil))
	wantStatus(t, head, http.StatusOK)
	if head.Body.Len() != 0 {
		t.Error("HEAD returned a body")
	}
	rng := hs.serve(hs.request(http.MethodGet, "/api/blobs/"+id, nil, map[string]string{"Range": "bytes=0-5"}))
	wantStatus(t, rng, http.StatusPartialContent)
	if rng.Body.String() != "<html>" {
		t.Errorf("range body = %q", rng.Body.String())
	}

	for _, bad := range []string{
		strings.ToUpper(id), id[:63], id + "0", strings.Repeat("g", 64), "..%2F" + id[:59], "%2E%2E", id[:60] + "%2Fab",
	} {
		t.Run("bad id "+bad[:min(len(bad), 12)], func(t *testing.T) {
			wantJSONError(t, hs.get("/api/blobs/"+bad), http.StatusBadRequest)
			wantJSONError(t, hs.get("/api/blobs/"+bad+"/view"), http.StatusBadRequest)
		})
	}
	wantJSONError(t, hs.get("/api/blobs/"+strings.Repeat("0", 64)), http.StatusNotFound)

	// A blob whose content does not hash to its id is never served.
	bogus := strings.Repeat("1", 64)
	hs.reader.mu.Lock()
	hs.reader.blobs[bogus] = []byte("tampered")
	hs.reader.mu.Unlock()
	msg := wantJSONError(t, hs.get("/api/blobs/"+bogus), http.StatusInternalServerError)
	if !strings.Contains(msg, "does not match") {
		t.Errorf("message = %q", msg)
	}

	hs.reader.blobErr = errors.New("gzip: invalid header")
	wantJSONError(t, hs.get("/api/blobs/"+id), http.StatusInternalServerError)
	hs.reader.blobErr = nil

	hs.srv.reader = nil
	wantJSONError(t, hs.get("/api/blobs/"+id), http.StatusServiceUnavailable)
}

func TestBlobViewIsSandboxed(t *testing.T) {
	hs := newHarness(t)
	page := []byte("<html><head><script>alert(1)</script></head><body onload=\"x()\">Copyright \xa9 AT&T<img src=\"http://evil/x.png\"></body></html>")
	id := hs.reader.addBlob(page)
	rec := hs.get("/api/blobs/" + id + "/view")
	wantStatus(t, rec, http.StatusOK)
	if !bytes.Equal(rec.Body.Bytes(), page) {
		t.Fatal("view must serve the exact bytes")
	}
	h := rec.Header()
	if got := h.Get("Content-Type"); got != "text/html; charset=windows-1252" {
		t.Errorf("Content-Type = %q", got)
	}
	if got := h.Values("Content-Security-Policy"); len(got) != 1 || got[0] != "sandbox; default-src 'none'; img-src data:; style-src 'unsafe-inline'" {
		t.Errorf("CSP = %q", got)
	}
	if h.Get("Content-Disposition") != "" {
		t.Error("view must render inline")
	}
	assertSecurityHeaders(t, h, true)
}

// ----------------------------------------------------------------------------- verify

func TestVerifyEndpoint(t *testing.T) {
	hs := newHarness(t)
	hs.verifier.report = model.VerifyReport{
		OK: false, Records: 8, FailuresTotal: 1, Fingerprint: strings.Repeat("cd", 32),
		Failures: []model.VerifyFailure{{Seq: 4, Segment: "ledger-2026-10-05", Line: 5, Problem: "hash_mismatch", Detail: "h does not match b"}},
	}
	rec := hs.post("/api/verify", "")
	wantStatus(t, rec, http.StatusOK)
	rep := decode[model.VerifyReport](t, rec)
	if rep.OK || len(rep.Failures) != 1 || rep.Failures[0].Problem != "hash_mismatch" {
		t.Errorf("report = %+v", rep)
	}
	for _, k := range []string{`"segments":[]`, `"anchors":[]`, `"gaps":[]`, `"type_counts":{}`} {
		if !strings.Contains(rec.Body.String(), k) {
			t.Errorf("missing %s in %s", k, rec.Body.String())
		}
	}

	hs.verifier.err = errors.New("ledger directory missing")
	wantJSONError(t, hs.post("/api/verify", ""), http.StatusInternalServerError)
	hs.verifier.err = nil

	wantJSONError(t, hs.get("/api/verify"), http.StatusMethodNotAllowed)

	hs.srv.verifier = nil
	wantJSONError(t, hs.post("/api/verify", ""), http.StatusServiceUnavailable)
}

func TestVerifyIsSingleFlight(t *testing.T) {
	hs := newHarness(t)
	hs.verifier.started = make(chan struct{}, 1)
	hs.verifier.release = make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	var first int
	go func() {
		defer wg.Done()
		first = hs.post("/api/verify", "").Code
	}()
	<-hs.verifier.started
	wantJSONError(t, hs.post("/api/verify", ""), http.StatusConflict)
	close(hs.verifier.release)
	wg.Wait()
	if first != http.StatusOK {
		t.Fatalf("first verify = %d", first)
	}
	if n := hs.verifier.calls.Load(); n != 1 {
		t.Errorf("Verify called %d times", n)
	}
}

// ----------------------------------------------------------------------------- exports

func TestExportListEndpoint(t *testing.T) {
	hs := newHarness(t)
	t0 := time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC)
	hs.exporter.list = []contracts.ExportInfo{
		{FileName: "a.zip", Created: t0, Path: `C:\secret\a.zip`},
		{FileName: "c.zip", Created: t0.Add(2 * time.Hour)},
		{FileName: "b.zip", Created: t0.Add(time.Hour)},
	}
	rec := hs.get("/api/exports")
	wantStatus(t, rec, 200)
	if strings.Contains(rec.Body.String(), "secret") {
		t.Error("local path leaked in export list")
	}
	list := decode[[]contracts.ExportInfo](t, rec)
	if len(list) != 3 || list[0].FileName != "c.zip" || list[2].FileName != "a.zip" {
		t.Errorf("order = %+v", list)
	}
	if hs.exporter.list[0].FileName != "a.zip" {
		t.Error("handler mutated the exporter's slice")
	}

	hs.exporter.list = nil
	if body := strings.TrimSpace(hs.get("/api/exports").Body.String()); body != "[]" {
		t.Errorf("empty list = %s", body)
	}
	hs.exporter.listErr = errors.New("exports dir unreadable")
	wantJSONError(t, hs.get("/api/exports"), http.StatusInternalServerError)
	hs.srv.exporter = nil
	wantJSONError(t, hs.get("/api/exports"), http.StatusServiceUnavailable)
}

func TestExportCreateEndpoint(t *testing.T) {
	hs := newHarness(t)
	rec := hs.serve(hs.request(http.MethodPost, "/api/exports", strings.NewReader(`{"from":"2026-10-05T03:00:00Z","to":"2026-10-05T05:00:00+01:00","prepared_by":"Alex Example","notes":"AT&T ticket 123\nsecond line"}`), map[string]string{"Origin": testOrigin}))
	wantStatus(t, rec, http.StatusCreated)
	info := decode[contracts.ExportInfo](t, rec)
	if info.FileName == "" || info.SHA256 == "" || info.CustodySeq != 43 {
		t.Errorf("info = %+v", info)
	}
	if got := rec.Header().Get("Location"); got != "/api/exports/"+info.FileName {
		t.Errorf("Location = %q", got)
	}
	req := hs.exporter.lastReq
	if !req.From.Equal(time.Date(2026, 10, 5, 3, 0, 0, 0, time.UTC)) || !req.To.Equal(time.Date(2026, 10, 5, 4, 0, 0, 0, time.UTC)) {
		t.Errorf("from/to = %v %v", req.From, req.To)
	}
	// Same instant for from and to is rejected.
	wantJSONError(t, hs.post("/api/exports", `{"from":"2026-10-05T03:00:00Z","to":"2026-10-05T04:00:00+01:00"}`), http.StatusBadRequest)
	if req.PreparedBy != "Alex Example" || req.Notes != "AT&T ticket 123\nsecond line" || req.Requester != "web 127.0.0.1" {
		t.Errorf("request = %+v", req)
	}
	if hs.exporter.ctxErr != nil {
		t.Errorf("Build got a cancelled context: %v", hs.exporter.ctxErr)
	}

	// Incident-only export; client "cli".
	rec = hs.post("/api/exports", `{"incident_id":"INC-20261005-030000Z","client":"cli"}`)
	wantStatus(t, rec, http.StatusCreated)
	if r := hs.exporter.lastReq; r.IncidentID != "INC-20261005-030000Z" || !r.From.IsZero() || r.Requester != "cli 127.0.0.1" {
		t.Errorf("incident export request = %+v", r)
	}

	bad := []struct {
		name, body, ctype string
		code              int
	}{
		{"no range", `{}`, "", 400},
		{"only from", `{"from":"2026-10-05"}`, "", 400},
		{"from after to", `{"from":"2026-10-06","to":"2026-10-05"}`, "", 400},
		{"bad time", `{"from":"5 Oct","to":"2026-10-05"}`, "", 400},
		{"bad incident", `{"incident_id":"../../etc"}`, "", 400},
		{"prepared_by newline", `{"incident_id":"INC-1","prepared_by":"a\nb"}`, "", 400},
		{"prepared_by too long", `{"incident_id":"INC-1","prepared_by":"` + strings.Repeat("x", 201) + `"}`, "", 400},
		{"notes too long", `{"incident_id":"INC-1","notes":"` + strings.Repeat("é", 4001) + `"}`, "", 400},
		{"notes control char", `{"incident_id":"INC-1","notes":"bell\u0007"}`, "", 400},
		{"notes bidi override", `{"incident_id":"INC-1","notes":"abc\u202edef"}`, "", 400},
		{"bad client", `{"incident_id":"INC-1","client":"monitor"}`, "", 400},
		{"unknown field", `{"incident_id":"INC-1","path":"C:/x"}`, "", 400},
		{"not an object", `["INC-1"]`, "", 400},
		{"trailing data", `{"incident_id":"INC-1"}{"x":1}`, "", 400},
		{"empty body", ``, "", 400},
		{"form content type", `incident_id=INC-1`, "application/x-www-form-urlencoded", 415},
		{"text content type", `{"incident_id":"INC-1"}`, "text/plain", 415},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			before := hs.exporter.builds
			hdr := map[string]string{}
			if tc.ctype != "" {
				hdr["Content-Type"] = tc.ctype
			}
			rec := hs.serve(hs.request(http.MethodPost, "/api/exports", strings.NewReader(tc.body), hdr))
			wantJSONError(t, rec, tc.code)
			if hs.exporter.builds != before {
				t.Error("invalid request reached Exporter.Build")
			}
		})
	}

	// JSON with a charset parameter is fine; a missing Content-Type is accepted (CLI clients).
	wantStatus(t, hs.serve(hs.request(http.MethodPost, "/api/exports", strings.NewReader(`{"incident_id":"INC-1"}`), map[string]string{"Content-Type": "application/json; charset=utf-8"})), http.StatusCreated)
	wantStatus(t, hs.serve(hs.request(http.MethodPost, "/api/exports", strings.NewReader(`{"incident_id":"INC-1"}`), map[string]string{"Content-Type": ""})), http.StatusCreated)

	hs.exporter.buildErr = contracts.ErrNotFound
	wantJSONError(t, hs.post("/api/exports", `{"incident_id":"INC-404"}`), http.StatusNotFound)
	hs.exporter.buildErr = errors.New("disk full")
	msg := wantJSONError(t, hs.post("/api/exports", `{"incident_id":"INC-1"}`), http.StatusInternalServerError)
	if !strings.Contains(msg, "disk full") {
		t.Errorf("message = %q", msg)
	}
	hs.exporter.buildErr = context.DeadlineExceeded
	wantJSONError(t, hs.post("/api/exports", `{"incident_id":"INC-1"}`), http.StatusGatewayTimeout)

	hs.srv.exporter = nil
	wantJSONError(t, hs.post("/api/exports", `{"incident_id":"INC-1"}`), http.StatusServiceUnavailable)
}

func TestExportCreateIsSingleFlight(t *testing.T) {
	hs := newHarness(t)
	hs.exporter.in = make(chan struct{}, 1)
	hs.exporter.gate = make(chan struct{})
	done := make(chan int, 1)
	go func() { done <- hs.post("/api/exports", `{"incident_id":"INC-1"}`).Code }()
	<-hs.exporter.in
	wantJSONError(t, hs.post("/api/exports", `{"incident_id":"INC-2"}`), http.StatusConflict)
	close(hs.exporter.gate)
	if code := <-done; code != http.StatusCreated {
		t.Fatalf("first export = %d", code)
	}
}

func TestExportDownloadEndpoint(t *testing.T) {
	for _, seekable := range []bool{true, false} {
		t.Run("seekable="+strconv.FormatBool(seekable), func(t *testing.T) {
			hs := newHarness(t)
			hs.exporter.seekable = seekable
			info := decode[contracts.ExportInfo](t, hs.post("/api/exports", `{"incident_id":"INC-1"}`))
			want := hs.exporter.files[info.FileName]

			rec := hs.get("/api/exports/" + url.PathEscape(info.FileName))
			wantStatus(t, rec, http.StatusOK)
			if !bytes.Equal(rec.Body.Bytes(), want) {
				t.Fatal("bundle bytes differ")
			}
			h := rec.Header()
			if h.Get("Content-Type") != "application/zip" {
				t.Errorf("Content-Type = %q", h.Get("Content-Type"))
			}
			if h.Get("Content-Disposition") != `attachment; filename="`+info.FileName+`"` {
				t.Errorf("Content-Disposition = %q", h.Get("Content-Disposition"))
			}
			if h.Get("X-Content-SHA256") != info.SHA256 {
				t.Errorf("X-Content-SHA256 = %q", h.Get("X-Content-SHA256"))
			}
			assertSecurityHeaders(t, h, false)
			head := hs.serve(hs.request(http.MethodHead, "/api/exports/"+info.FileName, nil, nil))
			wantStatus(t, head, http.StatusOK)
			if head.Body.Len() != 0 {
				t.Error("HEAD returned a body")
			}
		})
	}

	hs := newHarness(t)
	traversal := []string{
		"..%2F..%2Fconfig.zip", "..%5C..%5Cconfig.zip", "a%2Fb.zip", "a%5Cb.zip", "x.txt", ".zip", "..zip",
		".hidden.zip", "CON.zip", "nul.zip", "Com1.zip", "x.zip%3Aads", "x%00.zip", "a%20b.zip", "-rf.zip",
		"C%3A%5CWindows%5Cx.zip", "%2E%2E%2Fx.zip", strings.Repeat("a", 197) + ".zip",
	}
	for _, name := range traversal {
		t.Run("reject "+name[:min(len(name), 20)], func(t *testing.T) {
			wantJSONError(t, hs.get("/api/exports/"+name), http.StatusBadRequest)
		})
	}
	wantJSONError(t, hs.get("/api/exports/missing.zip"), http.StatusNotFound)
	hs.exporter.openErr = errors.New("permission denied")
	wantJSONError(t, hs.get("/api/exports/any.zip"), http.StatusInternalServerError)
	hs.srv.exporter = nil
	wantJSONError(t, hs.get("/api/exports/any.zip"), http.StatusServiceUnavailable)
}

func TestValidExportName(t *testing.T) {
	for name, ok := range map[string]bool{
		"att-evidence_20261005T0300Z_20261005T0400Z_abcd1234.zip": true,
		"bundle+v2.zip": true, "a.zip": true, "A_B-c.1.zip": true,
		"": false, ".zip": false, "a.ZIP": false, "a.zip.txt": false, "a/b.zip": false, `a\b.zip`: false,
		"../a.zip": false, "a..b.zip": false, "aux.zip": false, "LPT9.zip": false, "a b.zip": false,
		"a:b.zip": false, "é.zip": false, strings.Repeat("a", 196) + ".zip": true, strings.Repeat("a", 197) + ".zip": false,
	} {
		if got := validExportName(name); got != ok {
			t.Errorf("validExportName(%q) = %v, want %v", name, got, ok)
		}
	}
}

// ----------------------------------------------------------------------------- notes

func TestNotesEndpoint(t *testing.T) {
	hs := newHarness(t)
	rec := hs.serve(hs.request(http.MethodPost, "/api/notes", strings.NewReader(`{"text":"  Called AT&T, ticket 0123456789.\nTech visit Tuesday.  ","author":" Alex "}`), map[string]string{"Origin": testOrigin}))
	wantStatus(t, rec, http.StatusCreated)
	ref := decode[model.Ref](t, rec)
	if ref.Seq != 101 || ref.Hash == "" {
		t.Errorf("ref = %+v", ref)
	}
	n := hs.actions.notes[0]
	if n.text != "Called AT&T, ticket 0123456789.\nTech visit Tuesday." || n.author != "Alex" || n.source != "web" {
		t.Errorf("note = %+v", n)
	}
	wantStatus(t, hs.post("/api/notes", `{"text":"from the command line","client":"cli"}`), http.StatusCreated)
	if got := hs.actions.notes[1].source; got != "cli" {
		t.Errorf("source = %q", got)
	}
	// Without "client" the source is inferred: browsers send Origin / Sec-Fetch-Site, the CLI does not.
	for _, tc := range []struct {
		hdr  map[string]string
		body string
		want string
	}{
		{nil, `{"text":"no origin"}`, "cli"},
		{map[string]string{"Sec-Fetch-Site": "same-origin"}, `{"text":"fetch metadata only"}`, "web"},
		{map[string]string{"Origin": testOrigin}, `{"text":"explicit wins","client":"cli"}`, "cli"},
		{nil, `{"text":"explicit web","client":"web"}`, "web"},
	} {
		before := len(hs.actions.notes)
		wantStatus(t, hs.serve(hs.request(http.MethodPost, "/api/notes", strings.NewReader(tc.body), tc.hdr)), http.StatusCreated)
		if got := hs.actions.notes[before].source; got != tc.want {
			t.Errorf("%s: source = %q, want %q", tc.body, got, tc.want)
		}
	}

	bad := []struct{ name, body string }{
		{"empty", `{"text":""}`},
		{"whitespace", `{"text":" \n\t "}`},
		{"missing text", `{"author":"x"}`},
		{"too long", `{"text":"` + strings.Repeat("a", MaxNoteChars+1) + `"}`},
		{"nul", `{"text":"a\u0000b"}`},
		{"escape char", `{"text":"\u001b[31mred"}`},
		{"line separator", `{"text":"a\u2028b"}`},
		{"bidi isolate", `{"text":"a\u2067b"}`},
		{"author newline", `{"text":"x","author":"a\nb"}`},
		{"author too long", `{"text":"x","author":"` + strings.Repeat("a", MaxNameChars+1) + `"}`},
		{"invalid utf8 escaped", "{\"text\":\"\xff\"}"},
		{"unknown field", `{"text":"x","source":"monitor"}`},
		{"bad client", `{"text":"x","client":"root"}`},
		{"null", `null`},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			before := len(hs.actions.notes)
			wantJSONError(t, hs.post("/api/notes", tc.body), http.StatusBadRequest)
			if len(hs.actions.notes) != before {
				t.Error("invalid note reached Actions.Note")
			}
		})
	}
	// Tabs and exactly MaxNoteChars runes are fine.
	wantStatus(t, hs.post("/api/notes", `{"text":"a\tb"}`), http.StatusCreated)
	wantStatus(t, hs.post("/api/notes", `{"text":"`+strings.Repeat("é", MaxNoteChars)+`"}`), http.StatusCreated)

	hs.actions.noteErr = errors.New("ledger closed")
	wantJSONError(t, hs.post("/api/notes", `{"text":"x"}`), http.StatusInternalServerError)
	hs.srv.actions = nil
	wantJSONError(t, hs.post("/api/notes", `{"text":"x"}`), http.StatusServiceUnavailable)
}

func TestCheckText(t *testing.T) {
	tests := []struct {
		in        string
		max       int
		multiline bool
		ok        bool
	}{
		{"plain", 10, false, true},
		{"tab\there", 10, false, true},
		{"two\nlines", 10, true, true},
		{"two\r\nlines", 12, true, true},
		{"two\nlines", 10, false, false},
		{"exactly10!", 10, false, true},
		{"eleven chr!", 10, false, false},
		{"日本語テキスト", 7, false, true},
		{"\x7f", 5, false, false},
		{"\u0085", 5, true, false},
		{"\u202a", 5, true, false},
		{"\u2069", 5, true, false},
		{"\u200e", 5, true, true}, // LRM is not an override
		{string([]byte{0xc3}), 5, true, false},
	}
	for _, tc := range tests {
		err := checkText(tc.in, tc.max, tc.multiline)
		if (err == nil) != tc.ok {
			t.Errorf("checkText(%q, %d, %v) = %v, want ok=%v", tc.in, tc.max, tc.multiline, err, tc.ok)
		}
	}
}

// ----------------------------------------------------------------------------- gateway notification

func TestNotificationEndpoint(t *testing.T) {
	hs := newHarness(t)
	rec := hs.serve(hs.request(http.MethodPost, "/api/gateway/notification", strings.NewReader(`{"enabled":false}`), map[string]string{"Origin": testOrigin}))
	wantStatus(t, rec, http.StatusOK)
	cc := decode[model.ConfigChange](t, rec)
	if cc.After != "off" || cc.Actor != "operator via web" {
		t.Errorf("change = %+v", cc)
	}
	wantStatus(t, hs.post("/api/gateway/notification", `{"enabled":true,"client":"cli"}`), http.StatusOK)
	if got := strings.Join(hs.actions.notifCalls, ";"); got != "off|operator via web;on|operator via cli" {
		t.Errorf("calls = %s", got)
	}

	for _, body := range []string{`{}`, `{"enabled":null}`, `{"enabled":"false"}`, `{"enabled":0}`, `{"enabled":false,"x":1}`, `{"enabled":false,"client":"x"}`} {
		wantJSONError(t, hs.post("/api/gateway/notification", body), http.StatusBadRequest)
	}
	if len(hs.actions.notifCalls) != 2 {
		t.Fatal("invalid requests reached the gateway")
	}

	hs.actions.notifErr = errors.New("gateway: all web server sessions are in use")
	hs.actions.notifChange = model.ConfigChange{Target: "gateway", What: "events.bbevent", Result: "failed: sessions full"}
	rec = hs.post("/api/gateway/notification", `{"enabled":false}`)
	wantStatus(t, rec, http.StatusBadGateway)
	ne := decode[NotificationError](t, rec)
	if !strings.Contains(ne.Error, "sessions are in use") || ne.Change == nil || ne.Change.Result != "failed: sessions full" {
		t.Errorf("error body = %+v", ne)
	}
	hs.actions.notifChange = model.ConfigChange{}
	hs.actions.notifErr = nil

	hs.srv.actions = nil
	wantJSONError(t, hs.post("/api/gateway/notification", `{"enabled":false}`), http.StatusServiceUnavailable)
}

func TestNotificationErrorWithoutChange(t *testing.T) {
	hs := newHarness(t)
	// The fake fills in a default change; the wrapper reports none, as a monitor would when
	// it failed before touching the gateway.
	hs.srv.actions = emptyChangeActions{&fakeActions{notifErr: errors.New("no access code configured")}}
	rec := hs.post("/api/gateway/notification", `{"enabled":false}`)
	wantStatus(t, rec, http.StatusBadGateway)
	if strings.Contains(rec.Body.String(), `"change"`) {
		t.Errorf("empty change must be omitted: %s", rec.Body.String())
	}
}

type emptyChangeActions struct{ *fakeActions }

func (e emptyChangeActions) SetGatewayNotification(ctx context.Context, enabled bool, actor string) (model.ConfigChange, error) {
	_, err := e.fakeActions.SetGatewayNotification(ctx, enabled, actor)
	return model.ConfigChange{}, err
}

func TestNotificationIsSingleFlight(t *testing.T) {
	hs := newHarness(t)
	hs.actions.notifIn = make(chan struct{}, 2)
	hs.actions.notifGate = make(chan struct{})
	done := make(chan int, 1)
	go func() { done <- hs.post("/api/gateway/notification", `{"enabled":false}`).Code }()
	<-hs.actions.notifIn
	wantJSONError(t, hs.post("/api/gateway/notification", `{"enabled":true}`), http.StatusConflict)
	close(hs.actions.notifGate)
	if code := <-done; code != http.StatusOK {
		t.Fatalf("first change = %d", code)
	}
}

// ----------------------------------------------------------------------------- anchor

func TestAnchorEndpoint(t *testing.T) {
	hs := newHarness(t)
	hs.actions.anchors = []model.Anchor{{TSAURL: "http://timestamp.digicert.com", HeadSeq: 7, GenTime: "2026-10-05T03:20:01Z", Verified: true, ChainOK: true, Reason: "manual"}}
	rec := hs.post("/api/anchor", "")
	wantStatus(t, rec, http.StatusOK)
	ar := decode[[]model.Anchor](t, rec)
	if len(ar) != 1 || ar[0].HeadSeq != 7 || rec.Header().Get(WarningHeader) != "" || hs.actions.anchorCalls[0] != "manual" {
		t.Errorf("anchor response = %+v calls=%v", ar, hs.actions.anchorCalls)
	}

	// One TSA failed: still 200 with the anchors obtained; the failure is in the warning header.
	hs.actions.anchorErr = errors.New("freetsa.org: timeout\nretry later — ünicode")
	rec = hs.post("/api/anchor", "")
	wantStatus(t, rec, http.StatusOK)
	if ar := decode[[]model.Anchor](t, rec); len(ar) != 1 {
		t.Errorf("partial = %+v", ar)
	}
	if got := rec.Header().Get(WarningHeader); got != "freetsa.org: timeout?retry later ? ?nicode" {
		t.Errorf("warning header = %q", got)
	}

	// Every TSA failed (offline): 502 with the standard error object.
	hs.actions.anchors = nil
	msg := wantJSONError(t, hs.post("/api/anchor", ""), http.StatusBadGateway)
	if !strings.Contains(msg, "freetsa.org: timeout") {
		t.Errorf("failure message = %q", msg)
	}

	hs.srv.actions = nil
	wantJSONError(t, hs.post("/api/anchor", ""), http.StatusServiceUnavailable)
}

func TestAnchorIsSingleFlight(t *testing.T) {
	hs := newHarness(t)
	if !hs.srv.anchorMu.TryLock() {
		t.Fatal("lock busy")
	}
	wantJSONError(t, hs.post("/api/anchor", ""), http.StatusConflict)
	hs.srv.anchorMu.Unlock()
	wantStatus(t, hs.post("/api/anchor", ""), http.StatusOK)
}

// ----------------------------------------------------------------------------- helpers

func TestParseTimeParam(t *testing.T) {
	tests := []struct {
		in   string
		want time.Time
		ok   bool
	}{
		{"", time.Time{}, true},
		{"2026-10-05T03:20:00Z", time.Date(2026, 10, 5, 3, 20, 0, 0, time.UTC), true},
		{"2026-10-05T03:20:00.123456789Z", time.Date(2026, 10, 5, 3, 20, 0, 123456789, time.UTC), true},
		{"2026-10-04T22:20:00-05:00", time.Date(2026, 10, 5, 3, 20, 0, 0, time.UTC), true},
		{"2026-10-05T03:20Z", time.Date(2026, 10, 5, 3, 20, 0, 0, time.UTC), true},
		{"2026-10-05", time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC), true},
		{"  2026-10-05  ", time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC), true},
		{"1791151188", time.Unix(1791151188, 0).UTC(), true},
		{"2026-10-05T03:20:00", time.Time{}, false}, // no zone: ambiguous
		{"10/05/2026", time.Time{}, false},
		{"99999999999999999999", time.Time{}, false},
		{"now", time.Time{}, false},
	}
	for _, tc := range tests {
		got, err := parseTimeParam(tc.in)
		if (err == nil) != tc.ok || !got.Equal(tc.want) {
			t.Errorf("parseTimeParam(%q) = %v, %v; want %v ok=%v", tc.in, got, err, tc.want, tc.ok)
		}
	}
}

func TestIDValidators(t *testing.T) {
	for id, ok := range map[string]bool{
		"INC-20261005-031000Z": true, "INC-20261005-031000Z-2": true, "a": true, "A.b_c-1": true,
		"": false, "-a": false, ".a": false, "a/b": false, "a b": false, "a%2f": false, strings.Repeat("a", 64): true, strings.Repeat("a", 65): false,
	} {
		if got := validIncidentID(id); got != ok {
			t.Errorf("validIncidentID(%q) = %v", id, got)
		}
	}
	good := strings.Repeat("0123456789abcdef", 4)
	for id, ok := range map[string]bool{good: true, strings.ToUpper(good): false, good[:63]: false, good + "a": false, strings.Replace(good, "0", "z", 1): false} {
		if got := validBlobID(id); got != ok {
			t.Errorf("validBlobID(%q) = %v", id, got)
		}
	}
	for v, ok := range map[string]bool{"sample": true, "custody_export": true, "Sample": false, "a-b": false, "": false} {
		if got := validRecordType(v); got != ok {
			t.Errorf("validRecordType(%q) = %v", v, got)
		}
	}
}

// TestJSONShapes decodes every endpoint strictly into the model/contract types.
func TestJSONShapes(t *testing.T) {
	hs := newHarness(t)
	hs.status.incidents = testIncidents()
	hs.actions.anchors = []model.Anchor{{TSAURL: "https://freetsa.org/tsr"}}
	blob := hs.reader.addBlob([]byte("x"))
	_ = blob

	decode[model.Status](t, hs.get("/api/status"))
	decode[model.Series](t, hs.get("/api/series?range=7d"))
	decode[[]model.Incident](t, hs.get("/api/incidents"))
	decode[IncidentDetail](t, hs.get("/api/incidents/INC-20261005-030000Z"))
	decode[[]RecordView](t, hs.get("/api/records?limit=2"))
	decode[model.SyslogList](t, hs.get("/api/syslog"))
	decode[model.ConfigChange](t, hs.post("/api/syslog/retention", `{"keep_mb":100,"keep_days":7}`))
	decode[model.LiveTraffic](t, hs.get("/api/traffic/live"))
	decode[model.VerifyReport](t, hs.post("/api/verify", ""))
	decode[contracts.ExportInfo](t, hs.post("/api/exports", `{"incident_id":"INC-1"}`))
	decode[[]contracts.ExportInfo](t, hs.get("/api/exports"))
	decode[model.Ref](t, hs.post("/api/notes", `{"text":"x"}`))
	decode[model.ConfigChange](t, hs.post("/api/gateway/notification", `{"enabled":false}`))
	decode[model.ConfigChange](t, hs.post("/api/gateway/syslog", `{"enabled":true}`))
	decode[model.ConfigChange](t, hs.post("/api/gateway/trust-cert", `{}`))
	decode[[]model.Anchor](t, hs.post("/api/anchor", ""))
	decode[ErrorResponse](t, hs.get("/api/nope"))
}
