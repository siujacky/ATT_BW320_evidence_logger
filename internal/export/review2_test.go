package export

// Regression tests for the findings of the second independent review of internal/export. Each
// test failed before the corresponding fix:
//
//   - forged REPORT.html / report.json / README.txt figures passed both verifiers;
//   - records of the period in a later-dated segment were left out of the bundle;
//   - an incident still open at export showed the stale figures of its opening record;
//   - verify_bundle.py accepted tokens that chain only to a root added to keys/tsa-roots.pem and
//     labelled them with the record's (unauthenticated) tsa_url;
//   - a backward wall-clock step roughly halved the reported AT&T downtime;
//   - percentages were rounded, so a period with an outage could read "100.00%";
//   - incident key facts presented a standing optical alarm or AT&T's NXDOMAIN redirect as facts
//     of the incident;
//   - every export waited for an unbounded full-ledger verification;
//   - the last cycle before a monitor stop was credited more time than the incident record.

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"attmonitor/internal/contracts"
	"attmonitor/internal/model"
)

// ---------------------------------------------------------------- report bound to the ledger

// forgeZip rewrites the named entries of a bundle with replace(old -> new) applied and
// recomputes MANIFEST.sha256, as anyone handling the zip can.
func forgeZip(t *testing.T, path string, edits map[string][2]string) string {
	t.Helper()
	return rewriteZip(t, path, zipEdit{fixManifest: true, edit: func(n string, d []byte) ([]byte, bool) {
		if e, ok := edits[n]; ok {
			if !bytes.Contains(d, []byte(e[0])) {
				t.Fatalf("%s does not contain %q", n, e[0])
			}
			return bytes.Replace(d, []byte(e[0]), []byte(e[1]), 1), true
		}
		return d, true
	}})
}

func TestForgedReportFiguresFailVerification(t *testing.T) {
	_, info := buildIncidentBundle(t)
	if err := VerifyManifest(info.Path); err != nil {
		t.Fatalf("genuine bundle: %v", err)
	}
	z := readZip(t, info.Path)
	r := readReportJSON(t, z)
	if r.Summary.ProviderOutageSec != 120 {
		t.Fatalf("test setup: provider outage %d", r.Summary.ProviderOutageSec)
	}
	tile := `Provider-attributed outage time</div><div class="value">2m 00s</div>`
	cases := []struct {
		name  string
		edits map[string][2]string
		want  string
	}{
		{"report.json and REPORT.html forged together", map[string][2]string{
			"report.json": {`"provider_outage_s": 120,`, `"provider_outage_s": 15120,`},
			"REPORT.html": {tile, strings.Replace(tile, "2m 00s", "4h 12m 00s", 1)},
		}, "report.json"},
		{"only REPORT.html forged", map[string][2]string{
			"REPORT.html": {tile, strings.Replace(tile, "2m 00s", "4h 12m 00s", 1)},
		}, "REPORT.html"},
		{"only README.txt forged", map[string][2]string{
			"README.txt": {"Provider-attributed outage time in the period: 2m 00s", "Provider-attributed outage time in the period: 4h 12m 00s"},
		}, "README.txt"},
		{"incident removed from report.json", map[string][2]string{
			"report.json": {`"provider_incidents": 1,`, `"provider_incidents": 0,`},
		}, "provider_incidents"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := forgeZip(t, info.Path, tc.edits)
			err := VerifyManifest(path)
			if err == nil || !errors.Is(err, ErrManifest) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("VerifyManifest of a forged report = %v, want an error naming %s", err, tc.want)
			}
		})
	}
}

// A report whose format the verifier cannot recompute is not silently accepted.
func TestReportOfUnknownFormatNotAccepted(t *testing.T) {
	_, info := buildIncidentBundle(t)
	path := forgeZip(t, info.Path, map[string][2]string{"report.json": {`"format": "` + reportFormat + `"`, `"format": "att-monitor-report/1"`}})
	if err := VerifyManifest(path); err == nil || !strings.Contains(err.Error(), "att-monitor-report/1") {
		t.Fatalf("VerifyManifest = %v, want a failure naming the unknown format", err)
	}
}

// Report verification re-renders the local times with the exporting computer's zone recorded in
// the bundle, not with the verifying computer's zone.
func TestReportVerificationIndependentOfLocalZone(t *testing.T) {
	saved := time.Local
	defer func() { time.Local = saved }()
	time.Local = time.FixedZone("XST", 5*3600+1800)
	_, info := buildIncidentBundle(t)
	time.Local = time.FixedZone("YST", -7*3600)
	if err := VerifyManifest(info.Path); err != nil {
		t.Fatalf("verified in another time zone: %v", err)
	}
	time.Local = saved
	if html := string(readZip(t, info.Path).files["REPORT.html"]); !strings.Contains(html, "XST") {
		t.Error("REPORT.html does not show the exporting computer's zone")
	}
}

// The texts a recipient reads first say what is and is not verified about the report.
func TestReportVerificationWording(t *testing.T) {
	_, info := buildIncidentBundle(t)
	z := readZip(t, info.Path)
	readme, html := string(z.files["README.txt"]), string(z.files["REPORT.html"])
	if !strings.Contains(readme, "att-monitor verify-bundle recomputes") || !strings.Contains(readme, "does not protect") {
		t.Errorf("README.txt does not explain how the report is verified:\n%s", readme)
	}
	if !strings.Contains(html, "att-monitor verify-bundle</code> recomputes") {
		t.Error("REPORT.html does not explain how its figures are verified")
	}
}

func TestPythonVerifierSaysReportNotVerified(t *testing.T) {
	py := findPython(t)
	_, info := buildIncidentBundle(t)
	script := shippedScript(t, info.Path)
	out, code := runPython(t, py, script, "--openssl-limit", "0", info.Path)
	if code != 0 || !strings.Contains(out, "REPORT.html, report.json and README.txt were NOT verified") {
		t.Fatalf("exit %d, want a statement that the report files were not verified:\n%s", code, out)
	}
	// A report.json describing other records than the bundle's is caught.
	r := readReportJSON(t, readZip(t, info.Path))
	path := forgeZip(t, info.Path, map[string][2]string{"report.json": {`"records": ` + fmt.Sprint(r.Ledger.Records) + `,`, `"records": 999999,`}})
	out, code = runPython(t, py, script, "--openssl-limit", "0", path)
	if code != 1 || !strings.Contains(out, "report.json does not describe the ledger records of this bundle") {
		t.Errorf("exit %d, want a failure for a report.json of other records:\n%s", code, out)
	}
}

// ---------------------------------------------------------------- segments chosen by record time

// After a wall clock that ran weeks ahead was corrected, the writer keeps appending correctly
// time-stamped records to the future-dated segment (it never reopens an older one).
func futureSegmentLedger(t *testing.T) (*fakeLedger, string, func(int, int) time.Time) {
	t.Helper()
	d := func(h, m int) time.Time { return time.Date(2026, 10, 5, h, m, 0, 0, time.UTC) }
	f := rvLedger(t, d(8, 0)) // run A
	next := rvSamples(f, d(8, 1), 6, 10*time.Second, model.StateOnline, "", model.AttrNone, "")
	f.append(next, model.TypeMonitorStop, model.MonitorStop{Reason: "console run duration elapsed", UptimeSec: 60})
	ahead := time.Date(2026, 11, 14, 8, 15, 0, 0, time.UTC) // a process with the clock 40 days fast
	f.append(ahead, model.TypeMonitorStart, model.MonitorStart{Software: testSoftware, Host: testHost, Mode: "console"})
	rvSamples(f, ahead.Add(10*time.Second), 3, 10*time.Second, model.StateOnline, "", model.AttrNone, "")
	f.append(ahead.Add(time.Minute), model.TypeMonitorStop, model.MonitorStop{Reason: "console", UptimeSec: 60})
	// The next process has the right time again: its records land in ledger-2026-11-14.
	f.append(d(8, 16), model.TypeMonitorStart, model.MonitorStart{Software: testSoftware, Host: testHost, Mode: "console"})
	next = rvSamples(f, d(8, 17), 6, 10*time.Second, model.StateOnline, "", model.AttrNone, "")
	const id = "INC-20261005-081800Z"
	opened := next
	first := f.head.Seq + 1
	for i := 0; i < 6; i++ {
		tag := ""
		if i >= 2 {
			tag = id
		}
		next = rvSamples(f, next, 1, 10*time.Second, model.StateISPOutage, model.CauseUpstreamUnreachable, model.AttrProvider, tag)
		if i == 2 {
			f.append(next.Add(-8*time.Second), model.TypeIncidentOpen, model.Incident{ID: id, Opened: opened.Format(time.RFC3339Nano), Open: true,
				State: model.StateISPOutage, Cause: model.CauseUpstreamUnreachable, Attribution: model.AttrProvider, Rules: rulesDescribed, FirstSeq: first,
				Stats: model.IncidentStats{Cycles: 3, BadCycles: 3, DowntimeSec: 20}})
		}
	}
	closed := next
	next = rvSamples(f, next, 3, 10*time.Second, model.StateOnline, "", model.AttrNone, id)
	f.append(next, model.TypeIncidentClose, model.Incident{ID: id, Opened: opened.Format(time.RFC3339Nano), Closed: closed.Format(time.RFC3339Nano),
		DurationSec: 60, State: model.StateISPOutage, Cause: model.CauseUpstreamUnreachable, Attribution: model.AttrProvider, Rules: rulesDescribed,
		FirstSeq: first, LastSeq: f.head.Seq, Stats: model.IncidentStats{Cycles: 6, BadCycles: 6, DowntimeSec: 60}})
	rvSamples(f, next.Add(10*time.Second), 6, 10*time.Second, model.StateOnline, "", model.AttrNone, "")
	if len(f.segs) != 2 || f.segs[1].name != "ledger-2026-11-14" {
		t.Fatalf("test setup: segments %v", segNamesOf(f))
	}
	return f, id, d
}

func segNamesOf(f *fakeLedger) []string {
	var out []string
	for _, s := range f.segs {
		out = append(out, s.name)
	}
	return out
}

func TestBuildIncludesRecordsInLaterDatedSegment(t *testing.T) {
	f, id, d := futureSegmentLedger(t)
	t.Run("period", func(t *testing.T) {
		_, z, r := rvExport(t, f, d(13, 0), contracts.ExportRequest{From: d(0, 0), To: d(12, 0)})
		if names := segNames(z); strings.Join(names, ",") != "ledger-2026-10-05,ledger-2026-11-14" {
			t.Fatalf("segments %v: the period's records in ledger-2026-11-14 were left out", names)
		}
		// 6 cycles of run A, 6 + 6 + 3 + 6 of the corrected process; the 3 future-dated ones are
		// outside the period.
		if r.Summary.Cycles != 27 || r.Summary.ProviderOutageSec != 60 || len(r.Incidents) != 1 || r.Incidents[0].Incident.ID != id {
			t.Errorf("summary cycles %d, provider outage %d, incidents %+v", r.Summary.Cycles, r.Summary.ProviderOutageSec, r.Incidents)
		}
		for _, s := range r.Ledger.Segments {
			if s.Name == "ledger-2026-11-14" && !s.OverlapsPeriod {
				t.Errorf("segment entry %+v: it holds records of the period", s)
			}
		}
	})
	t.Run("incident", func(t *testing.T) {
		_, z, r := rvExport(t, f, d(13, 0), contracts.ExportRequest{IncidentID: id})
		if names := segNames(z); strings.Join(names, ",") != "ledger-2026-10-05,ledger-2026-11-14" {
			t.Fatalf("segments %v", names)
		}
		if len(r.Incidents) != 1 || r.Incidents[0].OpenSeq == nil || r.Incidents[0].CloseSeq == nil || r.Summary.Cycles == 0 {
			t.Errorf("incidents %+v, cycles %d", r.Incidents, r.Summary.Cycles)
		}
	})
}

// ---------------------------------------------------------------- incident open at export time

func TestOngoingIncidentFiguresComputedFromSamples(t *testing.T) {
	d := func(m int) time.Time { return time.Date(2026, 10, 5, 8, m, 0, 0, time.UTC) }
	f := cfgLedger(t, d(0), testConfigJSON(t, "10s", "2m30s", 3, 3, 6, 20, 150, 20))
	next := rvSamples(f, d(1), 6, 10*time.Second, model.StateOnline, "", model.AttrNone, "")
	const id = "INC-20261005-080200Z"
	opened, first := next, f.head.Seq+1
	for i := 0; i < 180; i++ { // 30 minutes without Internet
		tag := ""
		if i >= 2 {
			tag = id
		}
		next = rvSamples(f, next, 1, 10*time.Second, model.StateISPOutage, model.CauseUpstreamUnreachable, model.AttrProvider, tag)
		if i == 2 { // the open record: 3 cycles, 20 s so far; nothing changes afterwards, so no update record
			f.append(next.Add(-8*time.Second), model.TypeIncidentOpen, model.Incident{ID: id, Opened: opened.Format(time.RFC3339Nano), Open: true,
				State: model.StateISPOutage, Cause: model.CauseUpstreamUnreachable, Attribution: model.AttrProvider, Rules: rulesDescribed,
				FirstSeq: first, LastSeq: f.head.Seq, Summary: "Ongoing ISP outage",
				Stats: model.IncidentStats{Cycles: 3, BadCycles: 3, DowntimeSec: 20, ProbeOK: map[string]int{"gateway_icmp": 3, "inet_icmp_cloudflare": 0},
					ProbeTotal: map[string]int{"gateway_icmp": 3, "inet_icmp_cloudflare": 3}}})
		}
	}
	now := next.Add(5 * time.Second) // exported while the outage goes on
	_, z, r := rvExport(t, f, now, contracts.ExportRequest{IncidentID: id})
	if len(r.Incidents) != 1 || !r.Incidents[0].Ongoing {
		t.Fatalf("incidents %+v", r.Incidents)
	}
	// 179 cycles of 10 s, and the last one until the export 15 s after it started (the cap).
	const want = 179*10 + 15
	if r.Summary.ProviderOutageSec != want {
		t.Fatalf("test setup: provider outage %d", r.Summary.ProviderOutageSec)
	}
	if lo := r.Summary.LongestOutage; lo == nil || lo.DowntimeSec == nil || *lo.DowntimeSec != want {
		t.Errorf("longest outage %+v: the stale 20 s of the open record is shown", lo)
	}
	var raw struct {
		Incidents []map[string]json.RawMessage `json:"incidents"`
	}
	if err := json.Unmarshal(z.files["report.json"], &raw); err != nil {
		t.Fatal(err)
	}
	if _, ok := raw.Incidents[0]["computed"]; !ok {
		t.Errorf("report.json incident lacks the figures computed from the samples: %v", keysOf(raw.Incidents[0]))
	}
	row := tableRow(string(z.files["REPORT.html"]), `<td class="mono">`+id+`</td>`)
	if !strings.Contains(row, fmtDur(want)) || !strings.Contains(row, "180 of 180 monitoring cycles") {
		t.Errorf("incident row does not show the current figures:\n%s", row)
	}
	if strings.Contains(row, "3 of 3 monitoring cycles during the incident were not ONLINE") {
		t.Errorf("incident row presents the open record's cycle counts as current:\n%s", row)
	}
}

func keysOf(m map[string]json.RawMessage) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

// ---------------------------------------------------------------- wall-clock steps

func TestBackwardClockStepKeepsDowntime(t *testing.T) {
	t0 := time.Date(2026, 10, 5, 8, 0, 0, 0, time.UTC)
	f := cfgLedger(t, t0, testConfigJSON(t, "10s", "2m30s", 3, 3, 6, 20, 150, 20))
	next := rvSamples(f, t0.Add(time.Minute), 6, 10*time.Second, model.StateOnline, "", model.AttrNone, "")
	next = rvSamples(f, next, 30, 10*time.Second, model.StateISPOutage, model.CauseUpstreamUnreachable, model.AttrProvider, "")
	// w32time steps the clock back by 5 minutes; the monotonic clock runs on.
	const step = 5 * time.Minute
	f.monoShift += step
	next = next.Add(-step)
	f.append(next.Add(-500*time.Millisecond), model.TypeClockJump, model.ClockJump{WallDeltaMs: -290000, MonoDeltaMs: 10000, JumpMs: -300000})
	next = rvSamples(f, next, 30, 10*time.Second, model.StateISPOutage, model.CauseUpstreamUnreachable, model.AttrProvider, "")
	rvSamples(f, next, 6, 10*time.Second, model.StateOnline, "", model.AttrNone, "")
	_, _, r := rvExport(t, f, t0.Add(time.Hour), contracts.ExportRequest{From: t0, To: t0.Add(30 * time.Minute)})
	// 60 outage cycles of 10 s each: 10 minutes without Internet.
	if sm := r.Summary; sm.ProviderOutageSec != 600 || sm.DowntimeSec != 600 {
		t.Errorf("provider outage %d s, downtime %d s, want 600 (60 cycles of 10 s)", sm.ProviderOutageSec, sm.DowntimeSec)
	}
}

// ---------------------------------------------------------------- monitor stop ends an incident

func TestStopEndedIncidentNotInflated(t *testing.T) {
	t0 := time.Date(2026, 10, 5, 5, 0, 0, 0, time.UTC)
	f := cfgLedger(t, t0, testConfigJSON(t, "10s", "2m30s", 3, 3, 6, 20, 150, 20))
	next := rvSamples(f, t0.Add(time.Minute), 6, 10*time.Second, model.StateOnline, "", model.AttrNone, "")
	const id = "INC-20261005-050100Z"
	opened, first := next, f.head.Seq+1
	var last time.Time
	for i := 0; i < 18; i++ {
		tag := ""
		if i >= 2 {
			tag = id
		}
		last = next
		next = rvSamples(f, next, 1, 10*time.Second, model.StateISPOutage, model.CauseUpstreamUnreachable, model.AttrProvider, tag)
	}
	lastSample := f.head
	// The service is stopped 9.8 s after the last cycle started; the next run closes the incident
	// at that last observation (the sample's record time) with 17 x 10 s + 1.5 s without Internet.
	f.append(last.Add(9800*time.Millisecond), model.TypeMonitorStop, model.MonitorStop{Reason: "service stop", UptimeSec: 300})
	restart := last.Add(5 * time.Minute)
	f.append(restart, model.TypeMonitorStart, model.MonitorStart{Software: testSoftware, Host: testHost, Mode: "service"})
	f.append(restart.Add(time.Second), model.TypeIncidentClose, model.Incident{ID: id, Opened: opened.Format(time.RFC3339Nano),
		Closed: lastSample.TS, DurationSec: int64(mustTS(t, lastSample.TS).Sub(opened) / time.Second), State: model.StateISPOutage,
		Cause: model.CauseUpstreamUnreachable, Attribution: model.AttrProvider, Rules: rulesDescribed, FirstSeq: first, LastSeq: lastSample.Seq,
		Stats: model.IncidentStats{Cycles: 18, BadCycles: 18, DowntimeSec: 171}})
	rvSamples(f, restart.Add(10*time.Second), 6, 10*time.Second, model.StateOnline, "", model.AttrNone, "")
	_, _, r := rvExport(t, f, t0.Add(time.Hour), contracts.ExportRequest{From: t0, To: t0.Add(30 * time.Minute)})
	if len(r.Incidents) != 1 || r.Incidents[0].Recorded.DowntimeSec == nil || *r.Incidents[0].Recorded.DowntimeSec != 171 {
		t.Fatalf("incidents %+v", r.Incidents)
	}
	if got := r.Summary.ProviderOutageSec; got != 171 {
		t.Errorf("provider outage %d s, but the only incident's own figure is 171 s", got)
	}
}

// ---------------------------------------------------------------- percentages

func TestPercentagesTruncatedNeverRoundedUp(t *testing.T) {
	for in, want := range map[float64]string{
		99.999: "99.99%", 99.996: "99.99%", 99.995: "99.99%", 100: "100%", 0.004: "< 0.01%", 0: "0.00%",
		47.618: "47.61%", 0.29: "0.29%", 12.5: "12.50%", 50: "50.00%", 0.01: "0.01%",
	} {
		if got := fmtPct(in); got != want {
			t.Errorf("fmtPct(%v) = %q, want %q", in, got, want)
		}
	}
	// 1 ISP_OUTAGE cycle in 30,000: the availability must not read 100.
	day := time.Date(2026, 10, 3, 0, 0, 0, 0, time.UTC)
	c := newCollector(&buildParams{from: day, to: day.Add(4 * 24 * time.Hour), now: day.Add(5 * 24 * time.Hour)})
	for i := 0; i < 30000; i++ {
		st := model.StateOnline
		if i == 15000 {
			st = model.StateISPOutage
		}
		c.agg.samples = append(c.agg.samples, sampleLite{t: day.Add(time.Duration(i) * 10 * time.Second).UnixNano(), seq: uint64(i), state: st})
	}
	r := &report{}
	c.summarize(r)
	if a := r.Summary.AvailabilityPct; a == nil || *a >= 100 || fmtPctp(a) != "99.99%" {
		t.Fatalf("availability %v (%s)", a, fmtPctp(a))
	}
	if h := strings.Join(highlights(r), "\n"); !strings.Contains(h, "99.99% of the measurement cycles") || strings.Contains(h, "100.00%") {
		t.Errorf("highlights:\n%s", h)
	}
}

// ---------------------------------------------------------------- standing conditions in key facts

func TestKeyFactsQualifyStandingConditions(t *testing.T) {
	d := func(m, s int) time.Time { return time.Date(2026, 10, 5, 9, m, s, 0, time.UTC) }
	f := cfgLedger(t, d(0, 0), testConfigJSON(t, "10s", "2m30s", 3, 3, 6, 20, 150, 20))
	sc := &scenario{f: f}
	alarms := []string{codeRxLowAlarm, codeRxLowWarn}
	sc.snapshot(d(0, 30), -315, true, "OPERATION (O5)", alarms, "periodic") // the line's standing low alarm
	next := rvSamples(f, d(1, 0), 6, 10*time.Second, model.StateOnline, "", model.AttrNone, "")

	// A Wi-Fi drop of the monitoring PC.
	const local = "INC-20261005-090200Z"
	opened, first := next, f.head.Seq+1
	for i := 0; i < 6; i++ {
		tag := ""
		if i >= 2 {
			tag = local
		}
		next = rvSamples(f, next, 1, 10*time.Second, model.StateLocalFault, model.CauseLocalLinkDown, model.AttrLocal, tag)
	}
	closed := next
	next = rvSamples(f, next, 3, 10*time.Second, model.StateOnline, "", model.AttrNone, local)
	sc.snapshot(next, -316, true, "OPERATION (O5)", alarms, "incident_close")
	f.append(next.Add(5*time.Second), model.TypeIncidentClose, model.Incident{ID: local, Opened: opened.Format(time.RFC3339Nano),
		Closed: closed.Format(time.RFC3339Nano), DurationSec: 60, State: model.StateLocalFault, Cause: model.CauseLocalLinkDown,
		Attribution: model.AttrLocal, Rules: rulesDescribed, FirstSeq: first, Stats: model.IncidentStats{Cycles: 6, BadCycles: 6,
			OpticalAlarm: true, LocalLinkDown: true, GatewayFetches: 1}})
	next = rvSamples(f, next.Add(10*time.Second), 6, 10*time.Second, model.StateOnline, "", model.AttrNone, "")

	// An outage during which only the gateway's answer for a non-existent .invalid name was
	// redirected (NXDOMAIN redirection); real names were not.
	const outage = "INC-20261005-090500Z"
	opened, first = next, f.head.Seq+1
	for i := 0; i < 6; i++ {
		tag := ""
		if i >= 2 {
			tag = outage
		}
		next = rvSamples(f, next, 1, 10*time.Second, model.StateISPOutage, model.CauseUpstreamUnreachable, model.AttrProvider, tag)
		if i == 3 {
			f.append(next.Add(-5*time.Second), model.TypeServiceCheck, model.ServiceCheck{DNS: []model.DNSResult{
				{Server: "192.168.1.254:53", ServerRole: "gateway", Name: "www.google.com", QType: "A", OK: true, RCode: "NOERROR", Answers: []string{"142.250.72.4"}},
				{Server: "192.168.1.254:53", ServerRole: "gateway", Name: "0123456789abcdef.invalid", QType: "A", OK: true, RCode: "NOERROR",
					Answers: []string{"104.239.207.44"}, Hijacked: true, HijackWhy: "reserved name 0123456789abcdef.invalid must not resolve (RFC 6761) but got: 104.239.207.44"},
			}})
		}
	}
	closed = next
	next = rvSamples(f, next, 3, 10*time.Second, model.StateOnline, "", model.AttrNone, outage)
	f.append(next, model.TypeIncidentClose, model.Incident{ID: outage, Opened: opened.Format(time.RFC3339Nano), Closed: closed.Format(time.RFC3339Nano),
		DurationSec: 60, State: model.StateISPOutage, Cause: model.CauseUpstreamUnreachable, Attribution: model.AttrProvider, Rules: rulesDescribed,
		FirstSeq: first, Stats: model.IncidentStats{Cycles: 6, BadCycles: 6, DNSHijackSeen: true, DowntimeSec: 60}})
	rvSamples(f, next.Add(10*time.Second), 6, 10*time.Second, model.StateOnline, "", model.AttrNone, "")

	_, _, r := rvExport(t, f, d(30, 0), contracts.ExportRequest{From: d(0, 0), To: d(20, 0)})
	facts := map[string]string{}
	for _, e := range r.Incidents {
		facts[e.Incident.ID] = strings.Join(e.KeyFacts, "\n")
		for _, kf := range e.KeyFacts {
			if kf == "The AT&T gateway's own optical alarm flag was active" || kf == "DNS answers were redirected (hijack detected)" {
				t.Errorf("%s: unqualified key fact %q", e.Incident.ID, kf)
			}
		}
	}
	if lf := facts[local]; !strings.Contains(lf, "already active") || !strings.Contains(lf, "before the incident") {
		t.Errorf("local incident: the standing optical alarm is not qualified:\n%s", lf)
	}
	if of := facts[outage]; !strings.Contains(of, ".invalid") || !strings.Contains(of, "real names were not redirected") {
		t.Errorf("outage: the NXDOMAIN redirect is not told apart from a hijack of real names:\n%s", of)
	}
}

// ---------------------------------------------------------------- full-ledger verification cost

// blockingVerifier simulates a full verification of a very large ledger: it does not finish
// before its context ends, unless release is closed.
type blockingVerifier struct {
	release chan struct{}
	rep     model.VerifyReport
}

func (v *blockingVerifier) Verify(ctx context.Context) (model.VerifyReport, error) {
	select {
	case <-ctx.Done():
		return model.VerifyReport{}, ctx.Err()
	case <-v.release:
		return v.rep, nil
	}
}

func TestFullVerificationDoesNotBlockExport(t *testing.T) {
	s := buildScenario(t)
	t.Run("budget", func(t *testing.T) {
		v := &blockingVerifier{release: make(chan struct{})} // never finishes
		e, _ := newTestExporter(t, s, t.TempDir(), func(o *Options) { o.Verifier = v })
		ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
		defer cancel()
		var info contracts.ExportInfo
		var err error
		withTimeout(t, 20*time.Second, "Build", func() { info, err = e.Build(ctx, contracts.ExportRequest{IncidentID: s.incidentID}) })
		if err != nil {
			t.Fatalf("Build with a full verification that cannot finish in time: %v", err)
		}
		r := readReportJSON(t, readZip(t, info.Path))
		if r.Verification.Overall != "pass" || r.Verification.Full != nil {
			t.Errorf("verification %+v", r.Verification)
		}
		raw := string(readZip(t, info.Path).files["report.json"])
		if !strings.Contains(raw, `"full_ledger_incomplete"`) {
			t.Error("report.json does not say that the full-ledger verification was not completed")
		}
	})
	t.Run("concurrent", func(t *testing.T) {
		// The verification finishes only once the bundle is being written: it must run alongside.
		v := &blockingVerifier{release: make(chan struct{}), rep: okVerifyReport(s)}
		r := &releaseOnOpen{fakeLedger: s.f, release: v.release}
		e, _ := newTestExporter(t, s, t.TempDir(), func(o *Options) { o.Verifier, o.Reader = v, r })
		ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
		defer cancel()
		var info contracts.ExportInfo
		var err error
		withTimeout(t, 20*time.Second, "Build", func() { info, err = e.Build(ctx, contracts.ExportRequest{IncidentID: s.incidentID}) })
		if err != nil {
			t.Fatalf("Build: %v", err)
		}
		if rep := readReportJSON(t, readZip(t, info.Path)); rep.Verification.Full == nil || !rep.Verification.Full.OK {
			t.Errorf("full verification %+v", rep.Verification)
		}
	})
}

// releaseOnOpen closes release the first time a segment is opened.
type releaseOnOpen struct {
	*fakeLedger
	release chan struct{}
	once    sync.Once
}

func (r *releaseOnOpen) OpenSegment(name string) (io.ReadCloser, error) {
	r.once.Do(func() { close(r.release) })
	return r.fakeLedger.OpenSegment(name)
}

// ---------------------------------------------------------------- Python verifier: TSA roots

func TestPythonVerifierTrustsOnlyKnownRoots(t *testing.T) {
	py := findPython(t)
	findOpenSSL(t)
	d := func(m int) time.Time { return time.Date(2026, 10, 5, 8, m, 0, 0, time.UTC) }
	f := rvLedger(t, d(0))
	rvSamples(f, d(1), 3, 10*time.Second, model.StateOnline, "", model.AttrNone, "")
	// The record claims DigiCert; the token is signed by a self-made TSA whose root the producer
	// added to keys/tsa-roots.pem.
	digest := mustHex(t, f.head.Hash)
	tok := f.putBlob(f.tsa.stamp(t, digest, d(2)))
	f.append(d(2), model.TypeAnchor, model.Anchor{TSAURL: "http://timestamp.digicert.com", TSAName: "CN=DigiCert Timestamp 2025",
		HeadSeq: f.head.Seq, HeadHash: f.head.Hash, TokenSHA256: tok, GenTime: d(2).Format(time.RFC3339), Verified: true, ChainOK: true,
		Reason: "periodic"}, tok)
	info, _, _ := rvExport(t, f, d(30), contracts.ExportRequest{From: d(0), To: d(10)},
		func(o *Options) { o.ExtraFiles = map[string][]byte{tsaRootsPath: f.tsa.rootPEM()} })
	script := shippedScript(t, info.Path)

	out, code := runPython(t, py, script, info.Path)
	if code != 0 || strings.Contains(out, "existed no later than") || strings.Contains(out, "(http://timestamp.digicert.com; TSA signature") ||
		!strings.Contains(out, "NOT verified as proof of time") || !strings.Contains(out, "not proof of time") {
		t.Errorf("exit %d: a token chaining only to a root added to the bundle was accepted as proof of time:\n%s", code, out)
	}
	fp := sha256Hex(f.tsa.cert.Raw)
	out, code = runPython(t, py, script, "--trust-root", colonHex(fp), info.Path)
	if code != 0 || !strings.Contains(out, "existed no later than") || !strings.Contains(out, "CN=att-monitor test TSA") ||
		strings.Contains(out, "(http://timestamp.digicert.com; TSA signature") {
		t.Errorf("exit %d with --trust-root: want proof of time labelled with the token's signer:\n%s", code, out)
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
