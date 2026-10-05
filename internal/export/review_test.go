package export

// Adversarial tests written during the independent review of internal/export. Each one pins
// down a way the bundle or its report could become misleading, incomplete, unverifiable or
// stuck, and failed before the corresponding fix.

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/digitorus/timestamp"

	"attmonitor/internal/contracts"
	"attmonitor/internal/model"
)

// ---------------------------------------------------------------- helpers

// rvLedger starts a ledger with a genesis record and a monitor_start record at t0.
func rvLedger(t *testing.T, t0 time.Time) *fakeLedger {
	t.Helper()
	f := newFakeLedger(t)
	f.append(t0, model.TypeGenesis, model.Genesis{PublicKey: base64.StdEncoding.EncodeToString(f.pub), Fingerprint: f.fingerprint(),
		Created: t0.Format(time.RFC3339Nano), Host: testHost, Software: testSoftware, Statement: "review test ledger"})
	f.append(t0.Add(time.Second), model.TypeMonitorStart, model.MonitorStart{Software: testSoftware, Host: testHost, Mode: "service"})
	return f
}

// rvSamples appends n samples, one every `every` from start, all with the same verdict and
// incident tag, and returns the start of the next cycle.
func rvSamples(f *fakeLedger, start time.Time, n int, every time.Duration, state, cause, attr, incident string) time.Time {
	s := &scenario{f: f}
	for i := 0; i < n; i++ {
		s.sample(start, uint64(i+1), state, cause, attr, incident)
		start = start.Add(every)
	}
	return start
}

// rvExport builds a bundle of f at now and returns it with its parsed report.json.
func rvExport(t *testing.T, f *fakeLedger, now time.Time, req contracts.ExportRequest, mods ...func(*Options)) (contracts.ExportInfo, zipContent, *report) {
	t.Helper()
	e, _ := newTestExporter(t, &scenario{f: f, now: now}, t.TempDir(), mods...)
	info, err := e.Build(context.Background(), req)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	mustVerifyReport(t, info.Path)
	z := readZip(t, info.Path)
	return info, z, readReportJSON(t, z)
}

// mustVerifyReport fails the test unless the report files of a freshly built bundle are exactly
// what its records give (VerifyReport): the report must be reproducible from the bundle.
func mustVerifyReport(t *testing.T, path string) {
	t.Helper()
	chk, err := VerifyReport(path)
	if err != nil {
		t.Fatalf("VerifyReport of a genuine bundle: %v", err)
	}
	if !chk.Verified || len(chk.Stated) == 0 {
		t.Fatalf("VerifyReport = %+v", chk)
	}
}

// rvAnchor appends an anchor record over the current head. The token is issued by the test
// TSA over digest (nil = the head hash) at `at`; the record may claim another gen_time
// (recordGenTime "" = the token's) and may leave the token out of its "blobs" list.
func rvAnchor(t *testing.T, f *fakeLedger, at time.Time, digest []byte, recordGenTime string, listBlob bool) (model.Ref, string) {
	t.Helper()
	if digest == nil {
		var err error
		if digest, err = hex.DecodeString(f.head.Hash); err != nil {
			t.Fatal(err)
		}
	}
	token := f.tsa.stamp(t, digest, at)
	id := f.putBlob(token)
	if recordGenTime == "" {
		recordGenTime = at.UTC().Truncate(time.Second).Format(time.RFC3339)
	}
	var blobs []string
	if listBlob {
		blobs = []string{id}
	}
	ref := f.append(at, model.TypeAnchor, model.Anchor{TSAURL: "https://tsa.example/tsr", TSAName: "CN=att-monitor test TSA",
		HeadSeq: f.head.Seq, HeadHash: f.head.Hash, TokenSHA256: id, GenTime: recordGenTime, Serial: "01", Policy: "1.2.3.4.1",
		Verified: true, ChainOK: true, Reason: "periodic"}, blobs...)
	return ref, id
}

func findAnchor(r *report, seq uint64) *anchorEntry {
	for i := range r.Anchors {
		if r.Anchors[i].Seq == seq {
			return &r.Anchors[i]
		}
	}
	return nil
}

// withTimeout fails the test instead of hanging the whole suite when f does not return.
func withTimeout(t *testing.T, d time.Duration, what string, f func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		f()
	}()
	select {
	case <-done:
	case <-time.After(d):
		t.Fatalf("%s did not finish within %v", what, d)
	}
}

// ---------------------------------------------------------------- incidents across the period

// A long outage that started before the period and has no incident record inside it (the
// monitor writes incident_update only on changes) must still be reported: the bundle has to
// contain the incident's open record and the report has to list the incident.
func TestBuildPeriodInsideLongIncident(t *testing.T) {
	d := func(day, h, m int) time.Time { return time.Date(2026, 10, day, h, m, 0, 0, time.UTC) }
	const id = "INC-20261002-220000Z"
	f := rvLedger(t, d(1, 10, 0))
	rvSamples(f, d(1, 10, 1), 5, time.Minute, model.StateOnline, "", model.AttrNone, "")
	next := rvSamples(f, d(2, 21, 50), 10, time.Minute, model.StateOnline, "", model.AttrNone, "")
	next = rvSamples(f, next, 2, time.Minute, model.StateISPOutage, model.CauseWANDown, model.AttrProvider, "")
	next = rvSamples(f, next, 1, time.Minute, model.StateISPOutage, model.CauseWANDown, model.AttrProvider, id)
	f.append(next.Add(-50*time.Second), model.TypeIncidentOpen, model.Incident{ID: id, Opened: d(2, 22, 0).Format(time.RFC3339Nano),
		Open: true, State: model.StateISPOutage, Cause: model.CauseWANDown, Attribution: model.AttrProvider, Rules: rulesDescribed,
		Summary: "AT&T gateway reports Broadband Connection: Down"})
	for ts := next; ts.Before(d(4, 1, 0)); ts = ts.Add(2 * time.Minute) {
		rvSamples(f, ts, 1, 0, model.StateISPOutage, model.CauseWANDown, model.AttrProvider, id)
	}
	f.append(d(4, 1, 0).Add(30*time.Second), model.TypeIncidentClose, model.Incident{ID: id, Opened: d(2, 22, 0).Format(time.RFC3339Nano),
		Closed: d(4, 1, 0).Format(time.RFC3339Nano), State: model.StateISPOutage, Cause: model.CauseWANDown, Attribution: model.AttrProvider,
		Rules: rulesDescribed})
	rvSamples(f, d(4, 1, 1), 5, time.Minute, model.StateOnline, "", model.AttrNone, "")

	info, z, r := rvExport(t, f, d(5, 0, 0), contracts.ExportRequest{From: d(3, 0, 0), To: d(4, 0, 0)})
	if got := strings.Join(segNames(z), ","); got != "ledger-2026-10-01,ledger-2026-10-02,ledger-2026-10-03" {
		t.Errorf("segments = %s, want the genesis day, the day the incident opened, and the period", got)
	}
	if r.Summary.Incidents != 1 || len(r.Incidents) != 1 || r.Incidents[0].Incident.ID != id {
		t.Fatalf("incidents = %d %+v, want %s", r.Summary.Incidents, r.Incidents, id)
	}
	ie := r.Incidents[0]
	// The samples are 2 minutes apart, on odd minutes: the first cycle of the period starts at
	// 00:01 and the last one covers 23:59-24:00, so the period's cycles cover 23h 59m.
	if !ie.Ongoing || ie.InPeriodSec != 86400 || ie.OpenSeq == nil || r.Summary.ProviderOutageSec != 86340 || r.Summary.ProviderDowntimeSec != 86340 {
		t.Errorf("incident entry = %+v, provider downtime %d", ie, r.Summary.ProviderDowntimeSec)
	}
	if len(r.Summary.IncidentsWithoutRecords) != 0 {
		t.Errorf("incidents without records = %v", r.Summary.IncidentsWithoutRecords)
	}
	var day2 *segmentEntry
	for i := range r.Ledger.Segments {
		if r.Ledger.Segments[i].Name == "ledger-2026-10-02" {
			day2 = &r.Ledger.Segments[i]
		}
	}
	if day2 == nil || day2.OverlapsPeriod || !strings.Contains(day2.IncludedFor, id) {
		t.Errorf("day-2 segment = %+v, want it marked as included for %s", day2, id)
	}
	html := string(z.files["REPORT.html"])
	if !strings.Contains(html, "in progress when the period starts") {
		t.Error("REPORT.html does not say why the extra segment is included")
	}
	if strings.Count(html, "included for the public key") != 0 {
		t.Error("REPORT.html still labels segments as 'included for the public key'")
	}
	if !r.Verification.Bundle.OK {
		t.Errorf("bundle check: %+v", r.Verification.Bundle.Failures)
	}
	if err := VerifyManifest(info.Path); err != nil {
		t.Error(err)
	}
}

// Samples tagged with an incident whose records are not in the bundle at all (for example the
// open record could not be written) must not silently disappear from the report.
func TestBuildReportsIncidentTagsWithoutRecords(t *testing.T) {
	d := func(day, h, m int) time.Time { return time.Date(2026, 10, day, h, m, 0, 0, time.UTC) }
	const ghost = "INC-20261002-230000Z"
	f := rvLedger(t, d(1, 10, 0))
	rvSamples(f, d(2, 22, 0), 3, time.Minute, model.StateOnline, "", model.AttrNone, "")
	rvSamples(f, d(3, 0, 0), 30, time.Minute, model.StateISPOutage, model.CauseUpstreamUnreachable, model.AttrProvider, ghost)
	_, z, r := rvExport(t, f, d(4, 0, 0), contracts.ExportRequest{From: d(3, 0, 0), To: d(3, 12, 0)})
	if len(r.Summary.IncidentsWithoutRecords) != 1 || r.Summary.IncidentsWithoutRecords[0] != ghost {
		t.Errorf("incidents without records = %v", r.Summary.IncidentsWithoutRecords)
	}
	if !strings.Contains(string(z.files["REPORT.html"]), ghost) {
		t.Error("REPORT.html does not mention the incident the samples refer to")
	}
}

// Incident ids may carry a uniqueness suffix ("-2"); they must still be found through the
// time window encoded in the id instead of a scan of the whole ledger.
func TestFindIncidentWithSuffixUsesTimeWindow(t *testing.T) {
	d := func(h, m int) time.Time { return time.Date(2026, 10, 3, h, m, 0, 0, time.UTC) }
	const id = "INC-20261003-120000Z-2"
	f := rvLedger(t, d(10, 0))
	rvSamples(f, d(12, 0), 5, 10*time.Second, model.StateISPOutage, model.CauseWANDown, model.AttrProvider, id)
	inc := model.Incident{ID: id, Opened: d(12, 0).Format(time.RFC3339Nano), Open: true, State: model.StateISPOutage,
		Cause: model.CauseWANDown, Attribution: model.AttrProvider, Rules: rulesDescribed}
	f.append(d(12, 1), model.TypeIncidentOpen, inc)
	inc.Open, inc.Closed = false, d(12, 2).Format(time.RFC3339Nano)
	f.append(d(12, 3), model.TypeIncidentClose, inc)
	r := &noFullScan{fakeLedger: f}
	e := New(Options{Dir: t.TempDir(), Reader: r, Software: testSoftware, Now: func() time.Time { return d(23, 0) }})
	info, err := e.Build(context.Background(), contracts.ExportRequest{IncidentID: id})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if !strings.HasPrefix(info.FileName, "att-evidence_20261003T1145Z_20261003T1217Z_") {
		t.Errorf("FileName = %s", info.FileName)
	}
}

// noFullScan is a reader whose Scan from the start of the ledger fails (it would be slow on a
// real ledger).
type noFullScan struct{ *fakeLedger }

func (n *noFullScan) Scan(fromSeq uint64, fn func(model.Envelope, model.Body) error) error {
	if fromSeq == 0 {
		return errors.New("full ledger scan")
	}
	return n.fakeLedger.Scan(fromSeq, fn)
}

// ---------------------------------------------------------------- period validation

func TestBuildRejectsUnusablePeriods(t *testing.T) {
	s := buildScenario(t)
	tests := []struct {
		name     string
		from, to time.Time
	}{
		{"before 1970", time.Date(1900, 1, 1, 0, 0, 0, 0, time.UTC), s.now},
		{"after 2261", s.now.Add(-time.Hour), time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC)},
		{"starts in the future", s.now.Add(time.Hour), s.now.Add(2 * time.Hour)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			e, act := newTestExporter(t, s, dir)
			if _, err := e.Build(context.Background(), contracts.ExportRequest{From: tc.from, To: tc.to}); err == nil {
				t.Fatal("Build accepted the period")
			}
			if ents, _ := os.ReadDir(dir); len(ents) != 0 || len(act.exports) != 0 {
				t.Errorf("files %v / custody %d left behind", ents, len(act.exports))
			}
		})
	}
}

// ---------------------------------------------------------------- chart robustness

// Absurd gateway values (a parser glitch or a damaged record) must not hang the export or
// produce an unbounded SVG.
func TestOpticalChartExtremeValues(t *testing.T) {
	from := time.Date(2026, 10, 3, 0, 0, 0, 0, time.UTC)
	cases := []struct {
		name        string
		vals        []int64
		alarm, warn *int64
		noChart     bool // nothing plausible to draw
	}{
		{"int64 extremes", []int64{math.MinInt64, math.MaxInt64, -315}, ip(-295), ip(-292), false},
		{"int64 extreme thresholds", []int64{-315, -316}, ip(math.MinInt64), ip(math.MaxInt64), false},
		{"huge range", []int64{-4_000_000_000_000, 4_000_000_000_000}, ip(-295), ip(-292), true},
		{"one huge reading", []int64{-315, -316, 1 << 50}, ip(-295), nil, false},
		{"wide but sane", []int64{-400, 50}, ip(-295), ip(-292), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var pts []optPoint
			for i, v := range tc.vals {
				pts = append(pts, optPoint{t: from.Add(time.Duration(i+1) * time.Minute), seq: uint64(i), rx: ip(v)})
			}
			var ch *opticalChart
			withTimeout(t, 5*time.Second, "buildOpticalChart", func() {
				ch = buildOpticalChart(pts, nil, from, from.Add(time.Hour), tc.alarm, tc.warn, time.Local)
			})
			if tc.noChart {
				if ch != nil {
					t.Errorf("chart drawn from impossible values only: %+v", ch)
				}
				return
			}
			if ch == nil {
				t.Fatal("no chart")
			}
			if len(ch.YTicks) < 2 || len(ch.YTicks) > 12 {
				t.Errorf("%d y ticks", len(ch.YTicks))
			}
			for _, s := range append(append([]string{}, ch.Lines...), ch.Bands...) {
				if strings.Contains(s, "NaN") || strings.Contains(s, "Inf") {
					t.Fatalf("bad path %q", s)
				}
			}
			for _, tk := range ch.YTicks {
				if y := parseF(t, tk.Y); y < plotY0-0.5 || y > plotY1+0.5 {
					t.Errorf("y tick %+v outside the plot", tk)
				}
			}
			implausible := 0
			for _, v := range tc.vals {
				if v < -plausibleX10 || v > plausibleX10 {
					implausible++
				}
			}
			if (implausible > 0) != strings.Contains(ch.Desc, "not plotted") {
				t.Errorf("description %q (implausible values: %d)", ch.Desc, implausible)
			}
		})
	}
	if got := fmtX10(math.MinInt64); got != "-922337203685477580.8" {
		t.Errorf("fmtX10(MinInt64) = %q", got)
	}
	if got := fmtInt(int64(math.MinInt64)); got != "-9,223,372,036,854,775,808" {
		t.Errorf("fmtInt(MinInt64) = %q", got)
	}
}

// ---------------------------------------------------------------- optical semantics

func rvFiberSnapshot(f *fakeLedger, at time.Time, rx *int64, alarms []string, measures bool) {
	fib := &model.FiberStatus{OpticalStatus: "Up"}
	if measures {
		fib.Measures = []model.DMIMeasure{{Name: "Rx Power", CurrentRaw: "x", Current: rx, Unit: "0.1dBm",
			LowAlarm: model.Threshold{Active: len(alarms) > 0, Raw: "1 (Threshold -295)", Threshold: ip(-295)},
			LowWarn:  model.Threshold{Raw: "0 (Threshold -292)", Threshold: ip(-292)}}}
	}
	d := model.GatewayDerived{Reachable: true, RxPowerX10: rx, Alarms: alarms}
	if measures {
		d.RxLowAlarmX10, d.RxLowWarnX10 = ip(-295), ip(-292)
	}
	f.append(at, model.TypeGatewaySnapshot, model.GatewaySnapshot{Fiber: fib, Derived: d, Trigger: "periodic",
		Pages: []model.PageCapture{{Page: "fiberstat", Status: 200, FetchedAt: at.Format(time.RFC3339Nano)}}})
}

// A fiberstat capture without any DMI data (page format drift, partial parse) says nothing
// about the gateway's alarm flags; it must not be reported as the alarm having cleared.
func TestOpticalCaptureWithoutDMIDoesNotClearAlarm(t *testing.T) {
	d := func(m int) time.Time { return time.Date(2026, 10, 3, 12, m, 0, 0, time.UTC) }
	f := rvLedger(t, d(0))
	rvFiberSnapshot(f, d(1), ip(-315), []string{codeRxLowAlarm}, true)
	rvFiberSnapshot(f, d(2), nil, nil, false)
	rvFiberSnapshot(f, d(3), ip(-316), []string{codeRxLowAlarm}, true)
	_, _, r := rvExport(t, f, d(30), contracts.ExportRequest{From: d(0), To: d(10)})
	o := r.Optical
	if len(o.Periods) != 1 || o.Periods[0].Snapshots != 2 || o.Periods[0].EndReason != "end of period" {
		t.Errorf("alarm periods = %+v", o.Periods)
	}
	if o.Snapshots != 2 || o.LowAlarmN != 2 {
		t.Errorf("optical snapshots %d, low-alarm readings %d; want 2 and 2", o.Snapshots, o.LowAlarmN)
	}
}

// The alarm sentence must count flags and readings over the same set of fiber readings.
func TestHighlightAlarmDenominator(t *testing.T) {
	r := &report{}
	r.Optical = optical{Readings: 1, Snapshots: 3, LowAlarmN: 3, RxMinX10: ip(-315), RxMaxX10: ip(-315), LowAlarmThrX10: ip(-295)}
	joined := strings.Join(highlights(r), "\n")
	if !strings.Contains(joined, "in 3 of 3 fiber status readings") {
		t.Errorf("highlights = %s", joined)
	}
}

// ---------------------------------------------------------------- time-stamp tokens

// The report's time-stamp claims must rest on the tokens themselves: a token over another
// digest is an integrity failure and never "covers" anything, and the time shown is the
// token's genTime, not the monitor's transcription of it.
func TestBundleChecksAnchorTokens(t *testing.T) {
	d := func(h, m, s int) time.Time { return time.Date(2026, 10, 3, h, m, s, 0, time.UTC) }
	f := rvLedger(t, d(10, 0, 0))
	rvSamples(f, d(10, 1, 0), 3, 10*time.Second, model.StateOnline, "", model.AttrNone, "")
	good, _ := rvAnchor(t, f, d(10, 2, 0), nil, "", true)
	rvSamples(f, d(10, 3, 0), 3, 10*time.Second, model.StateOnline, "", model.AttrNone, "")
	lastInPeriod := f.head
	bad, _ := rvAnchor(t, f, d(10, 4, 0), bytes.Repeat([]byte{9}, 32), "", true) // token over another digest
	rvSamples(f, d(10, 5, 0), 3, 10*time.Second, model.StateOnline, "", model.AttrNone, "")
	skew, _ := rvAnchor(t, f, d(10, 6, 0), nil, "2026-10-03T00:00:00Z", false) // record misstates genTime, token not in "blobs"

	lastTS, _ := parseTS(lastInPeriod.TS)
	_, z, r := rvExport(t, f, d(23, 0, 0), contracts.ExportRequest{From: d(0, 0, 0), To: lastTS.Add(time.Millisecond)})
	if !hasProblem(r, "anchor_invalid") || r.Verification.Bundle.OK || r.Verification.Overall != "fail" {
		t.Errorf("a token over another digest must fail the bundle check: %+v", r.Verification.Bundle)
	}
	if a := findAnchor(r, good.Seq); a == nil || a.TokenCheck != "ok" || a.TokenGenTime != "2026-10-03T10:02:00Z" {
		t.Errorf("good anchor = %+v", a)
	}
	if a := findAnchor(r, bad.Seq); a == nil || a.TokenCheck == "ok" || !strings.Contains(a.TokenCheck, "imprint") {
		t.Errorf("bad anchor = %+v", a)
	}
	a := findAnchor(r, skew.Seq)
	if a == nil || a.TokenCheck != "ok" || a.TokenGenTime != "2026-10-03T10:06:00Z" || !a.TokenIncluded {
		t.Errorf("skewed anchor = %+v", a)
	}
	if b := r.Verification.Bundle; b.AnchorTokensOK != 2 || b.AnchorTokensInvalid != 1 {
		t.Errorf("token counters ok=%d invalid=%d", b.AnchorTokensOK, b.AnchorTokensInvalid)
	}
	cov := r.Summary.LastRecordAnchor
	if cov == nil || cov.Seq != skew.Seq || cov.GenTime != "2026-10-03T10:06:00Z" {
		t.Errorf("coverage = %+v, want anchor %d with the token's genTime", cov, skew.Seq)
	}
	if !strings.Contains(strings.Join(r.Verification.Bundle.Notes, "\n"), "differs from the genTime") {
		t.Errorf("notes do not mention the misstated genTime: %v", r.Verification.Bundle.Notes)
	}
	if html := string(z.files["REPORT.html"]); !strings.Contains(html, "imprint") {
		t.Error("REPORT.html does not show the token problem")
	}
}

// A tampered anchor record (edited gen_time, re-hashed) must not move the time shown in the
// report: the time comes from the TSA's token.
func TestTamperedAnchorRecordTimeNotTrusted(t *testing.T) {
	s := buildScenario(t)
	lines := bytes.Split(bytes.TrimSuffix(s.f.segs[2].data, []byte("\n")), []byte("\n"))
	var idx = -1
	var tokenTime string
	for i, line := range lines {
		_, body, err := parseLine(line)
		if err == nil && body.Type == model.TypeAnchor {
			var a model.Anchor
			json.Unmarshal(body.Data, &a)
			if a.Reason == "incident_close" {
				idx, tokenTime = i, a.GenTime
			}
		}
	}
	if idx < 0 {
		t.Fatal("no incident_close anchor")
	}
	s.f.segs[2].data = replaceRecord(t, s.f.segs[2].data, idx, func(b *model.Body) {
		var a model.Anchor
		json.Unmarshal(b.Data, &a)
		a.GenTime = "2026-10-03T00:00:00Z" // back-dated
		b.Data, _ = json.Marshal(a)
	})
	e, _ := newTestExporter(t, s, t.TempDir())
	info, err := e.Build(context.Background(), contracts.ExportRequest{IncidentID: s.incidentID})
	if err != nil {
		t.Fatal(err)
	}
	r := readReportJSON(t, readZip(t, info.Path))
	if r.Verification.Bundle.OK {
		t.Error("tampered anchor record not detected")
	}
	if len(r.Incidents) != 1 || r.Incidents[0].Anchor == nil {
		t.Fatalf("incidents = %+v", r.Incidents)
	}
	want, _ := parseTS(tokenTime)
	if got := r.Incidents[0].Anchor.GenTime; got != want.UTC().Format(time.RFC3339Nano) {
		t.Errorf("incident time-stamp shown as %s, the token says %s", got, tokenTime)
	}
}

// The real DigiCert and FreeTSA responses in testdata/tsa pass the bundle's token check.
func TestCheckTokenRealTSAResponses(t *testing.T) {
	const digest = "0bb4c71bfeddf27eb9647853d1e5aa8f981f222fe4ffac0c7d1d8db73f1d443b"
	for _, name := range []string{"digicert.tsr", "freetsa.tsr"} {
		der, err := os.ReadFile(filepath.Join("..", "..", "testdata", "tsa", name))
		if err != nil {
			t.Skipf("%s: %v", name, err)
		}
		res := checkToken(der, digest)
		if res.problem != "" || res.genTime.UTC().Format(time.RFC3339) != "2026-10-05T03:19:57Z" || !res.signed {
			t.Errorf("%s: %+v", name, res)
		}
		if res := checkToken(der, strings.Repeat("ab", 32)); !strings.Contains(res.problem, "imprint") {
			t.Errorf("%s with the wrong digest: %+v", name, res)
		}
		if res := checkToken(der[:len(der)-10], digest); res.problem == "" {
			t.Errorf("%s truncated: accepted", name)
		}
	}
	if res := checkToken([]byte("not DER"), "00"); res.problem == "" {
		t.Error("garbage token accepted")
	}
}

// ---------------------------------------------------------------- verification summary

// A full-ledger verification of a ledger with another key does not vouch for this bundle.
func TestFullVerificationOfAnotherLedgerFails(t *testing.T) {
	s := buildScenario(t)
	rep := okVerifyReport(s)
	rep.Fingerprint = strings.Repeat("ab", 32)
	e, _ := newTestExporter(t, s, t.TempDir(), func(o *Options) { o.Verifier = &fakeVerifier{rep: rep} })
	info, err := e.Build(context.Background(), contracts.ExportRequest{IncidentID: s.incidentID})
	if err != nil {
		t.Fatal(err)
	}
	z := readZip(t, info.Path)
	r := readReportJSON(t, z)
	if r.Verification.Overall != "fail" {
		t.Errorf("overall = %s with a full verification of another key", r.Verification.Overall)
	}
	if !strings.Contains(string(z.files["REPORT.html"]), "different ledger key") {
		t.Error("REPORT.html does not explain the fingerprint mismatch")
	}
}

// public-key.txt must not present an unverified genesis key as the ledger key without warning.
func TestPublicKeyFileWarnsAboutInvalidGenesis(t *testing.T) {
	s := buildScenario(t)
	s.f.segs[0].data = bytes.Replace(s.f.segs[0].data, []byte("Evidence ledger"), []byte("Evidance ledger"), 1)
	e, _ := newTestExporter(t, s, t.TempDir())
	info, err := e.Build(context.Background(), contracts.ExportRequest{IncidentID: s.incidentID})
	if err != nil {
		t.Fatal(err)
	}
	key := string(readZip(t, info.Path).files["keys/public-key.txt"])
	if !strings.Contains(key, "WARNING") || !strings.Contains(key, "Public key (base64): ") {
		t.Errorf("public-key.txt:\n%s", key)
	}
}

// When the records were classified with another rules version than the one the report
// explains, the report must say so.
func TestRulesVersionMismatchIsFlagged(t *testing.T) {
	d := func(m int) time.Time { return time.Date(2026, 10, 3, 12, m, 0, 0, time.UTC) }
	f := rvLedger(t, d(0))
	for i := 0; i < 3; i++ {
		f.append(d(i+1), model.TypeSample, model.Sample{Cycle: uint64(i), Started: d(i + 1).Format(time.RFC3339Nano),
			Probes: testProbes(true, true, false), Verdict: model.Verdict{State: model.StateOnline, Attribution: model.AttrNone, Rules: "2027.01-1"}})
	}
	_, z, _ := rvExport(t, f, d(30), contracts.ExportRequest{From: d(0), To: d(10)})
	if html := string(z.files["REPORT.html"]); !strings.Contains(html, "do not match the rules described here") {
		t.Error("REPORT.html does not flag the rules version mismatch")
	}
}

// ---------------------------------------------------------------- commit

// The final move never replaces a file that appeared under the bundle's name.
func TestCommitBundleNeverOverwrites(t *testing.T) {
	dir := t.TempDir()
	tmp, final := filepath.Join(dir, ".tmp"), filepath.Join(dir, "b.zip")
	os.WriteFile(tmp, []byte("new"), 0o644)
	os.WriteFile(final, []byte("old"), 0o644)
	err := commitBundle(tmp, final)
	if !errors.Is(err, fs.ErrExist) {
		t.Fatalf("commitBundle over an existing file: %v", err)
	}
	if b, _ := os.ReadFile(final); string(b) != "old" {
		t.Errorf("existing bundle overwritten: %q", b)
	}
	os.Remove(final)
	if err := commitBundle(tmp, final); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(final); string(b) != "new" {
		t.Errorf("committed content = %q", b)
	}
	if _, err := os.Stat(tmp); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("temp file still present: %v", err)
	}
}

// ---------------------------------------------------------------- anchors with unsorted seqs

func TestHashOfUnsorted(t *testing.T) {
	c := newCollector(&buildParams{})
	c.seqHashes = []seqHash{{5, "e"}, {3, "c"}, {9, "i"}, {3, "c2"}}
	c.seqSorted = false
	for seq, want := range map[uint64]string{5: "e", 9: "i", 3: "c2"} {
		if h, ok := c.hashOf(seq); !ok || h != want {
			t.Errorf("hashOf(%d) = %q %v, want %q", seq, h, ok, want)
		}
	}
	if _, ok := c.hashOf(4); ok {
		t.Error("hashOf(4) found")
	}
}

// ---------------------------------------------------------------- Python verifier

// The exporter always writes the genesis segment plus one contiguous run of segments, so a
// segment missing between two included non-genesis segments can only mean that it was removed
// from the bundle afterwards; and an anchor token must be the exact file its record names.
func TestPythonVerifierReviewCases(t *testing.T) {
	py := findPython(t)

	t.Run("segment removed from the middle", func(t *testing.T) {
		s := buildScenario(t)
		e, _ := newTestExporter(t, s, t.TempDir())
		info, err := e.Build(context.Background(), contracts.ExportRequest{
			From: time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC), To: time.Date(2026, 10, 4, 10, 0, 0, 0, time.UTC)})
		if err != nil {
			t.Fatal(err)
		}
		script := shippedScript(t, info.Path)
		if out, code := runPython(t, py, script, "--openssl-limit", "0", info.Path); code != 0 {
			t.Fatalf("intact bundle: exit %d\n%s", code, out)
		}
		path := rewriteZip(t, info.Path, zipEdit{fixManifest: true, edit: func(n string, d []byte) ([]byte, bool) {
			return d, n != "ledger/ledger-2026-10-03.jsonl"
		}})
		out, code := runPython(t, py, script, "--openssl-limit", "0", path)
		if code != 1 || !strings.Contains(out, "missing from the middle of the bundle") {
			t.Errorf("exit %d, want 1 with a missing-segment failure:\n%s", code, out)
		}
	})

	t.Run("token replaced by another token over the same digest", func(t *testing.T) {
		d := func(m int) time.Time { return time.Date(2026, 10, 3, 12, m, 0, 0, time.UTC) }
		f := rvLedger(t, d(0))
		rvSamples(f, d(1), 3, 10*time.Second, model.StateOnline, "", model.AttrNone, "")
		head, _ := hex.DecodeString(f.head.Hash)
		_, tok := rvAnchor(t, f, d(2), nil, "", false) // token not in the record's "blobs" list
		info, _, _ := rvExport(t, f, d(30), contracts.ExportRequest{From: d(0), To: d(10)})
		script := shippedScript(t, info.Path)
		if out, code := runPython(t, py, script, "--openssl-limit", "0", info.Path); code != 0 {
			t.Fatalf("intact bundle: exit %d\n%s", code, out)
		}
		other := f.tsa.stamp(t, head, d(2).Add(time.Hour)) // genuine, same digest, other time
		path := rewriteZip(t, info.Path, zipEdit{fixManifest: true, edit: func(n string, data []byte) ([]byte, bool) {
			if n == "blobs/"+tok {
				return other, true
			}
			return data, true
		}})
		out, code := runPython(t, py, script, "--openssl-limit", "0", path)
		if code != 1 || !strings.Contains(out, "does not match token_sha256") {
			t.Errorf("exit %d, want 1 with a token hash failure:\n%s", code, out)
		}
	})
}

// VerifyManifest (the first step of att-monitor verify-bundle) must catch a segment removed
// from the middle of a bundle even when MANIFEST.sha256 was re-computed, like the Python
// verifier; removing the first or the last segment of the run leaves a legitimate shape.
func TestVerifyManifestLayout(t *testing.T) {
	s := buildScenario(t)
	e, _ := newTestExporter(t, s, t.TempDir())
	info, err := e.Build(context.Background(), contracts.ExportRequest{
		From: time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC), To: time.Date(2026, 10, 4, 10, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyManifest(info.Path); err != nil {
		t.Fatalf("intact bundle: %v", err)
	}
	drop := func(seg string) string {
		return rewriteZip(t, info.Path, zipEdit{fixManifest: true, edit: func(n string, d []byte) ([]byte, bool) {
			return d, n != "ledger/"+seg+".jsonl"
		}})
	}
	if err := VerifyManifest(drop("ledger-2026-10-03")); !errors.Is(err, ErrManifest) || !strings.Contains(err.Error(), "missing from the middle") {
		t.Errorf("middle segment removed: %v", err)
	}
	for _, seg := range []string{"ledger-2026-10-02", "ledger-2026-10-04"} {
		// A legitimate shape for the layout check; but the report still describes the removed
		// segment's records, so the report check rejects the bundle.
		path := drop(seg)
		if p := zipLayoutProblems(t, path); len(p) != 0 {
			t.Errorf("%s removed (a legitimate shape): layout problems %v", seg, p)
		}
		if err := VerifyManifest(path); !errors.Is(err, ErrReportMismatch) || strings.Contains(err.Error(), "missing from the middle") {
			t.Errorf("%s removed: VerifyManifest = %v, want a report mismatch", seg, err)
		}
	}
}

// zipLayoutProblems runs the segment layout check of VerifyManifest on a bundle.
func zipLayoutProblems(t *testing.T, path string) []string {
	t.Helper()
	zr, err := zip.OpenReader(path)
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()
	files := map[string]*zip.File{}
	for _, f := range zr.File {
		files[f.Name] = f
	}
	return layoutProblems(files)
}

// A reader that lists a segment twice must not produce a bundle with duplicate entries.
func TestBuildDuplicateSegmentListing(t *testing.T) {
	s := buildScenario(t)
	r := &dupSegments{fakeLedger: s.f}
	e, _ := newTestExporter(t, s, t.TempDir(), func(o *Options) { o.Reader = r })
	info, err := e.Build(context.Background(), contracts.ExportRequest{}) // the whole ledger
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyManifest(info.Path); err != nil {
		t.Errorf("bundle from a duplicate listing: %v", err)
	}
	b, err := OpenBundle(info.Path)
	if err != nil {
		t.Fatalf("OpenBundle: %v", err)
	}
	b.Close()
}

type dupSegments struct{ *fakeLedger }

func (d *dupSegments) Segments() ([]contracts.SegmentInfo, error) {
	segs, err := d.fakeLedger.Segments()
	return append(segs, segs...), err
}

// ---------------------------------------------------------------- remaining branches

func TestCheckTokenVariants(t *testing.T) {
	tsa := newTestTSA(t)
	digest := bytes.Repeat([]byte{0x42}, 32)
	hexDigest := hex.EncodeToString(digest)
	at := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	stamp := func(mod func(*timestamp.Timestamp)) []byte {
		ts := &timestamp.Timestamp{HashAlgorithm: crypto.SHA256, HashedMessage: digest, Time: at,
			Policy: asn1.ObjectIdentifier{1, 2, 3, 4, 1}, AddTSACertificate: true}
		if mod != nil {
			mod(ts)
		}
		der, err := ts.CreateResponseWithOpts(tsa.cert, tsa.key, crypto.SHA256)
		if err != nil {
			t.Fatal(err)
		}
		return der
	}
	good := stamp(nil)
	if r := checkToken(good, hexDigest); r.problem != "" || r.warn != "" || !r.signed || !r.genTime.Equal(at) {
		t.Errorf("good token: %+v", r)
	}
	parsed, err := timestamp.ParseResponse(good)
	if err != nil {
		t.Fatal(err)
	}
	if r := checkToken(parsed.RawToken, hexDigest); r.problem != "" || r.warn != "" {
		t.Errorf("bare TimeStampToken: %+v", r)
	}
	sha384 := stamp(func(ts *timestamp.Timestamp) {
		ts.HashAlgorithm, ts.HashedMessage = crypto.SHA384, bytes.Repeat(digest, 2)[:48]
	})
	if r := checkToken(sha384, hexDigest); !strings.Contains(r.problem, "not SHA-256") {
		t.Errorf("SHA-384 token: %+v", r)
	}
	noCert := stamp(func(ts *timestamp.Timestamp) { ts.AddTSACertificate = false })
	if r := checkToken(noCert, hexDigest); r.problem != "" || !strings.Contains(r.warn, "no TSA certificate") || r.signed {
		t.Errorf("token without certificate: %+v", r)
	}
	if r := checkToken(good, "not hex"); !strings.Contains(r.problem, "imprint") {
		t.Errorf("non-hex head hash: %+v", r)
	}
	// A token whose signed content was altered (one byte of the imprint flipped).
	bad := append([]byte(nil), good...)
	i := bytes.Index(bad, digest)
	bad[i] ^= 0xff
	if r := checkToken(bad, hexDigest); r.problem == "" {
		t.Errorf("tampered token accepted: %+v", r)
	}
}

// An anchor whose token cannot vouch for its time (no TSA certificate) is reported, is not an
// integrity failure, and is never used as proof of time.
func TestAnchorTokenWithoutCertificate(t *testing.T) {
	d := func(m int) time.Time { return time.Date(2026, 10, 3, 12, m, 0, 0, time.UTC) }
	f := rvLedger(t, d(0))
	rvSamples(f, d(1), 3, 10*time.Second, model.StateOnline, "", model.AttrNone, "")
	last := f.head
	digest, _ := hex.DecodeString(f.head.Hash)
	ts := &timestamp.Timestamp{HashAlgorithm: crypto.SHA256, HashedMessage: digest, Time: d(2),
		Policy: asn1.ObjectIdentifier{1, 2, 3, 4, 1}}
	token, err := ts.CreateResponseWithOpts(f.tsa.cert, f.tsa.key, crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	id := f.putBlob(token)
	ref := f.append(d(2), model.TypeAnchor, model.Anchor{TSAURL: "https://tsa.example/tsr", HeadSeq: f.head.Seq, HeadHash: f.head.Hash,
		TokenSHA256: id, GenTime: d(2).Format(time.RFC3339), Verified: true, Reason: "periodic"}, id)
	lastTS, _ := parseTS(last.TS)
	_, _, r := rvExport(t, f, d(30), contracts.ExportRequest{From: d(0), To: lastTS.Add(time.Millisecond)})
	a := findAnchor(r, ref.Seq)
	if a == nil || !strings.Contains(a.TokenCheck, "no TSA certificate") || !r.Verification.Bundle.OK || a.ProofOfTime ||
		!strings.HasPrefix(a.ProofNote, "its time-stamp token cannot be checked: the token carries no TSA certificate") {
		t.Errorf("anchor = %+v, bundle ok = %v", a, r.Verification.Bundle.OK)
	}
	if r.Summary.LastRecordAnchor != nil {
		t.Errorf("an unsigned token was used as proof of time: %+v", r.Summary.LastRecordAnchor)
	}
	if !strings.Contains(strings.Join(r.Verification.Bundle.Notes, "\n"), "not used as proof of time") {
		t.Errorf("notes = %v", r.Verification.Bundle.Notes)
	}
}

func TestIncidentAtStartPaths(t *testing.T) {
	d := func(day, h int) time.Time { return time.Date(2026, 10, day, h, 0, 0, 0, time.UTC) }
	f := rvLedger(t, d(1, 10))
	const odd = "outage-42" // an id without the time format: found through its records
	inc := model.Incident{ID: odd, Opened: d(2, 20).Format(time.RFC3339Nano), Open: true, State: model.StateISPOutage,
		Cause: model.CauseWANDown, Attribution: model.AttrProvider, Rules: rulesDescribed}
	rvSamples(f, d(2, 20), 3, time.Minute, model.StateISPOutage, model.CauseWANDown, model.AttrProvider, odd)
	f.append(d(2, 20).Add(3*time.Minute), model.TypeIncidentOpen, inc)
	rvSamples(f, d(3, 0), 30, time.Minute, model.StateISPOutage, model.CauseWANDown, model.AttrProvider, odd)
	e := New(Options{Dir: t.TempDir(), Reader: f, Now: func() time.Time { return d(4, 0) }})
	si, err := e.incidentAtStart(context.Background(), d(3, 0), d(3, 12), d(4, 0))
	if err != nil || si == nil || si.id != odd || !si.opened.Equal(d(2, 20)) {
		t.Errorf("incidentAtStart = %+v, %v", si, err)
	}
	if si, err := e.incidentAtStart(context.Background(), d(1, 0), d(1, 12), d(4, 0)); si != nil || err != nil {
		t.Errorf("untagged start: %+v, %v", si, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := e.incidentAtStart(ctx, d(3, 0), d(3, 12), d(4, 0)); !errors.Is(err, context.Canceled) {
		t.Errorf("canceled: %v", err)
	}
	broken := New(Options{Dir: t.TempDir(), Reader: &failingScanTime{f}, Now: func() time.Time { return d(4, 0) }})
	if _, err := broken.Build(context.Background(), contracts.ExportRequest{From: d(3, 0), To: d(3, 12)}); err == nil ||
		!strings.Contains(err.Error(), "read the start of the period") {
		t.Errorf("reader failure: %v", err)
	}
	// The period export then contains the open record and lists the incident.
	_, z, r := rvExport(t, f, d(4, 0), contracts.ExportRequest{From: d(3, 0), To: d(3, 12)})
	if len(r.Incidents) != 1 || r.Incidents[0].Incident.ID != odd || len(segNames(z)) != 3 {
		t.Errorf("incidents %+v, segments %v", r.Incidents, segNames(z))
	}
}

type failingScanTime struct{ *fakeLedger }

func (f *failingScanTime) ScanTime(time.Time, time.Time, func(model.Envelope, model.Body) error) error {
	return errors.New("disk error")
}

func TestCommitBundleBadPath(t *testing.T) {
	dir := t.TempDir()
	if err := commitBundle(filepath.Join(dir, "a\x00b"), filepath.Join(dir, "x.zip")); err == nil || errors.Is(err, fs.ErrExist) {
		t.Errorf("bad source: %v", err)
	}
	if err := commitBundle(filepath.Join(dir, "missing"), filepath.Join(dir, "x\x00.zip")); err == nil || errors.Is(err, fs.ErrExist) {
		t.Errorf("bad target: %v", err)
	}
	if err := commitBundle(filepath.Join(dir, "missing"), filepath.Join(dir, "x.zip")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("missing source: %v", err)
	}
}

func TestMaxAbsSaturates(t *testing.T) {
	if p := maxAbs(nil, math.MinInt64); p == nil || *p != math.MaxInt64 {
		t.Errorf("maxAbs(MinInt64) = %v", p)
	}
	if p := maxAbs(ip(5), -7); *p != 7 {
		t.Errorf("maxAbs = %d", *p)
	}
}

// A segment whose first line cannot be read is left to the ledger verification (it is a
// record problem, not a missing segment).
func TestVerifyManifestLayoutUnreadableFirstLine(t *testing.T) {
	s := buildScenario(t)
	e, _ := newTestExporter(t, s, t.TempDir())
	info, err := e.Build(context.Background(), contracts.ExportRequest{
		From: time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC), To: time.Date(2026, 10, 4, 10, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatal(err)
	}
	path := rewriteZip(t, info.Path, zipEdit{fixManifest: true, edit: func(n string, d []byte) ([]byte, bool) {
		if n == "ledger/ledger-2026-10-04.jsonl" {
			return append([]byte("garbage\n"), d...), true
		}
		return d, true
	}})
	// Not a layout problem; the inserted line is a record problem, which the report check (the
	// report no longer matches the records) and the ledger verification report.
	if p := zipLayoutProblems(t, path); len(p) != 0 {
		t.Errorf("layout problems %v", p)
	}
	if err := VerifyManifest(path); !errors.Is(err, ErrReportMismatch) || strings.Contains(err.Error(), "missing from the middle") {
		t.Errorf("VerifyManifest: %v", err)
	}
}
