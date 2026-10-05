package export

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"attmonitor/internal/contracts"
	"attmonitor/internal/model"
)

// ----------------------------------------------------------------- helpers

func okVerifyReport(s *scenario) model.VerifyReport {
	var names []string
	for _, seg := range s.f.segs {
		names = append(names, seg.name)
	}
	return model.VerifyReport{OK: true, At: s.now.Format(time.RFC3339Nano), Records: s.f.next, Segments: names,
		HeadHash: s.f.head.Hash, Fingerprint: s.f.fingerprint(), TypeCounts: map[string]int{}, Failures: []model.VerifyFailure{},
		Anchors: []model.AnchorCheck{{Seq: 3, OK: true}}, Gaps: []model.Gap{}}
}

func newTestExporter(t *testing.T, s *scenario, dir string, mods ...func(*Options)) (*Exporter, *fakeActions) {
	t.Helper()
	act := &fakeActions{}
	opts := Options{Dir: dir, Reader: s.f, Verifier: &fakeVerifier{rep: okVerifyReport(s)}, Actions: act,
		Software: testSoftware, Now: func() time.Time { return s.now }}
	for _, m := range mods {
		m(&opts)
	}
	return New(opts), act
}

type zipContent struct {
	names   []string
	files   map[string][]byte
	hdrs    map[string]*zip.FileHeader
	comment string
}

func readZip(t *testing.T, path string) zipContent {
	t.Helper()
	zr, err := zip.OpenReader(path)
	if err != nil {
		t.Fatalf("open zip: %v", err)
	}
	defer zr.Close()
	z := zipContent{files: map[string][]byte{}, hdrs: map[string]*zip.FileHeader{}, comment: zr.Comment}
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		b, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			t.Fatalf("read %s: %v", f.Name, err)
		}
		z.names = append(z.names, f.Name)
		z.files[f.Name] = b
		h := f.FileHeader
		z.hdrs[f.Name] = &h
	}
	return z
}

// blobRefsOf lists the blob ids referenced by the "blobs" field of every record in the named
// fake segments (plus anchor tokens), i.e. what an export of those segments must contain.
func blobRefsOf(t *testing.T, f *fakeLedger, segs ...string) map[string]bool {
	t.Helper()
	want := map[string]bool{}
	for _, name := range segs {
		for _, line := range bytes.Split(bytes.TrimSuffix(f.segmentBytes(name), []byte("\n")), []byte("\n")) {
			_, body, err := parseLine(line)
			if err != nil {
				t.Fatal(err)
			}
			for _, id := range body.Blobs {
				want[id] = true
			}
		}
	}
	return want
}

func readReportJSON(t *testing.T, z zipContent) *report {
	t.Helper()
	var r report
	if err := json.Unmarshal(z.files["report.json"], &r); err != nil {
		t.Fatalf("report.json: %v", err)
	}
	return &r
}

// anchorsOf returns the anchor payloads of a segment.
func anchorsOf(t *testing.T, seg []byte) []model.Anchor {
	t.Helper()
	var out []model.Anchor
	for _, line := range bytes.Split(bytes.TrimSuffix(seg, []byte("\n")), []byte("\n")) {
		_, body, err := parseLine(line)
		if err != nil || body.Type != model.TypeAnchor {
			continue
		}
		var a model.Anchor
		if err := json.Unmarshal(body.Data, &a); err != nil {
			t.Fatal(err)
		}
		out = append(out, a)
	}
	return out
}

func hasProblem(r *report, kind string) bool {
	for _, f := range r.Verification.Bundle.Failures {
		if f.Problem == kind {
			return true
		}
	}
	return false
}

// externalRefRE matches attributes that would load or link anything outside the document.
var externalRefRE = regexp.MustCompile(`(?i)\b(?:src|href|xlink:href|action|poster|data)\s*=\s*["']?\s*(?:[a-z][a-z0-9+.-]*:|//)`)

// ----------------------------------------------------------------- incident export

func TestBuildIncidentBundle(t *testing.T) {
	s := buildScenario(t)
	dir := t.TempDir()
	e, act := newTestExporter(t, s, dir)
	info, err := e.Build(context.Background(), contracts.ExportRequest{IncidentID: s.incidentID, PreparedBy: "Homeowner",
		Notes: "For AT&T ticket 12345", Requester: "test-suite"})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	// Range and name.
	from, to := s.opened.Add(-IncidentMargin), s.closed.Add(IncidentMargin)
	day3 := s.f.segs[2]
	_, lastBody, err := parseLine(bytes.TrimSuffix(day3.data[bytes.LastIndexByte(day3.data[:len(day3.data)-1], '\n')+1:], []byte("\n")))
	if err != nil {
		t.Fatal(err)
	}
	lastEnv, _, _ := s.f.Record(lastBody.Seq)
	wantName := fmt.Sprintf("att-evidence_%s_%s_%s.zip", from.Format(nameTimeLayout), to.Format(nameTimeLayout), lastEnv.H[:8])
	if info.FileName != wantName {
		t.Errorf("FileName = %s, want %s", info.FileName, wantName)
	}
	if info.Path != filepath.Join(dir, wantName) {
		t.Errorf("Path = %s", info.Path)
	}
	raw, err := os.ReadFile(info.Path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size != int64(len(raw)) || info.SHA256 != sha256Hex(raw) {
		t.Errorf("Size/SHA256 = %d/%s, file %d/%s", info.Size, info.SHA256, len(raw), sha256Hex(raw))
	}
	if !info.Created.Equal(s.now) {
		t.Errorf("Created = %v, want %v", info.Created, s.now)
	}

	z := readZip(t, info.Path)

	// Ledger segments: the genesis segment plus the incident's day, exact bytes; days 2 and 4 left out.
	for _, name := range []string{"ledger-2026-10-01", "ledger-2026-10-03"} {
		got, ok := z.files["ledger/"+name+".jsonl"]
		if !ok {
			t.Fatalf("missing ledger/%s.jsonl; entries %v", name, z.names)
		}
		if !bytes.Equal(got, s.f.segmentBytes(name)) {
			t.Errorf("ledger/%s.jsonl differs from the ledger bytes", name)
		}
	}
	for _, name := range []string{"ledger-2026-10-02", "ledger-2026-10-04"} {
		if _, ok := z.files["ledger/"+name+".jsonl"]; ok {
			t.Errorf("%s must not be in an incident bundle for 2026-10-03", name)
		}
	}

	// Blobs: exactly the referenced ones, exact bytes.
	wantBlobs := blobRefsOf(t, s.f, "ledger-2026-10-01", "ledger-2026-10-03")
	gotBlobs := map[string]bool{}
	for _, n := range z.names {
		if id, ok := strings.CutPrefix(n, "blobs/"); ok {
			gotBlobs[id] = true
			if !bytes.Equal(z.files[n], s.f.blobs[id]) {
				t.Errorf("blob %s bytes differ", id)
			}
		}
	}
	if len(gotBlobs) != len(wantBlobs) {
		t.Errorf("blobs: got %d, want %d", len(gotBlobs), len(wantBlobs))
	}
	for id := range wantBlobs {
		if !gotBlobs[id] {
			t.Errorf("referenced blob %s missing", id)
		}
	}
	if gotBlobs[s.day2Blob] {
		t.Error("a blob referenced only by an omitted segment was included")
	}

	// Fixed files.
	for _, n := range []string{"README.txt", "REPORT.html", "report.json", "keys/public-key.txt", "tools/verify_bundle.py", manifestName} {
		if _, ok := z.files[n]; !ok {
			t.Errorf("missing %s", n)
		}
	}
	if !bytes.Equal(z.files["tools/verify_bundle.py"], verifyScript) {
		t.Error("tools/verify_bundle.py is not the embedded verifier")
	}
	if want := 2 + len(wantBlobs) + 6; len(z.names) != want {
		t.Errorf("zip has %d entries, want %d: %v", len(z.names), want, z.names)
	}
	if z.names[len(z.names)-1] != manifestName {
		t.Errorf("last entry = %s, want %s", z.names[len(z.names)-1], manifestName)
	}
	for _, n := range z.names {
		if strings.ContainsAny(n, `\:`) || strings.HasPrefix(n, "/") || strings.Contains(n, "..") {
			t.Errorf("unsafe entry name %q", n)
		}
		if h := z.hdrs[n]; !h.Modified.Equal(s.now) {
			t.Errorf("%s modified %v, want %v", n, h.Modified, s.now)
		}
	}
	if !strings.Contains(z.comment, "verify_bundle.py") {
		t.Errorf("zip comment %q", z.comment)
	}

	// Manifest: sorted, covers every other file, correct hashes.
	var listed []string
	for _, line := range strings.Split(strings.TrimSuffix(string(z.files[manifestName]), "\n"), "\n") {
		m := manifestLineRE.FindStringSubmatch(line)
		if m == nil || strings.Contains(line, "\r") {
			t.Fatalf("bad manifest line %q", line)
		}
		if sha256Hex(z.files[m[2]]) != m[1] {
			t.Errorf("manifest hash wrong for %s", m[2])
		}
		listed = append(listed, m[2])
	}
	if !sort.StringsAreSorted(listed) {
		t.Error("manifest not sorted")
	}
	if len(listed) != len(z.names)-1 {
		t.Errorf("manifest lists %d files, zip has %d others", len(listed), len(z.names)-1)
	}
	if info.ManifestSHA256 != sha256Hex(z.files[manifestName]) {
		t.Error("ManifestSHA256 mismatch")
	}
	if err := VerifyManifest(info.Path); err != nil {
		t.Errorf("VerifyManifest: %v", err)
	}

	// Counts and custody.
	wantRecords := s.f.segs[0].records + s.f.segs[2].records
	if info.Records != wantRecords || info.Blobs != len(wantBlobs) || info.CustodySeq != 4242 {
		t.Errorf("info records/blobs/custody = %d/%d/%d, want %d/%d/4242", info.Records, info.Blobs, info.CustodySeq, wantRecords, len(wantBlobs))
	}
	if len(act.exports) != 1 {
		t.Fatalf("RecordExport calls = %d", len(act.exports))
	}
	ce := act.exports[0]
	if ce.FileName != info.FileName || ce.BundleSHA256 != info.SHA256 || ce.ManifestSHA256 != info.ManifestSHA256 ||
		ce.IncidentID != s.incidentID || ce.From != from.Format(time.RFC3339Nano) || ce.To != to.Format(time.RFC3339Nano) ||
		ce.Records != wantRecords || ce.Blobs != len(wantBlobs) || ce.PreparedBy != "Homeowner" || ce.Requester != "test-suite" ||
		ce.Notes != "For AT&T ticket 12345" {
		t.Errorf("custody export = %+v", ce)
	}
	sc, err := readSidecar(info.Path + sidecarSuffix)
	if err != nil {
		t.Fatalf("sidecar: %v", err)
	}
	if sc.CustodyRecord.Seq != 4242 || sc.BundleSHA256 != info.SHA256 || sc.CustodyExport != ce {
		t.Errorf("sidecar = %+v", sc)
	}

	// report.json.
	r := readReportJSON(t, z)
	if r.Format != reportFormat || r.Period.Scope != "incident" || r.Period.IncidentID != s.incidentID ||
		r.Period.From != from.Format(time.RFC3339Nano) || r.Period.To != to.Format(time.RFC3339Nano) || r.Bundle.FileName != info.FileName {
		t.Errorf("report header = %+v / %+v", r.Period, r.Bundle)
	}
	sm := r.Summary
	// 59 cycles 10 s apart; the last one before the suspend gap covers 1.5 x 10 s.
	if sm.Cycles != 59 || sm.MonitoredSec != 595 || sm.WindowSec != 1920 || sm.Incidents != 1 || sm.ProviderIncidents != 1 ||
		sm.ProviderOutageSec != 120 || sm.ProviderDowntimeSec != 120 || sm.DowntimeSec != 120 || sm.DegradedSec != 20 ||
		sm.RestartSec != 0 || sm.Blips != 1 || sm.BlipCycles != 2 || len(sm.Gaps) != 2 {
		t.Errorf("summary = %+v", sm)
	}
	if sm.AvailabilityPct == nil || *sm.AvailabilityPct != round3(100*45.0/59.0) {
		t.Errorf("availability = %v", sm.AvailabilityPct)
	}
	if sm.LongestOutage == nil || sm.LongestOutage.ID != s.incidentID || sm.LongestOutage.Seconds != 120 {
		t.Errorf("longest outage = %+v", sm.LongestOutage)
	}
	if !strings.Contains(sm.Gaps[0].Explanation, "monitor started") || !strings.Contains(sm.Gaps[1].Explanation, "power event suspend") {
		t.Errorf("gap explanations = %q / %q", sm.Gaps[0].Explanation, sm.Gaps[1].Explanation)
	}
	if sm.LastRecordAnchor == nil {
		t.Error("last record of the period should be covered by an anchor")
	}
	if len(r.Incidents) != 1 {
		t.Fatalf("incidents = %d", len(r.Incidents))
	}
	ie := r.Incidents[0]
	if ie.Incident.ID != s.incidentID || ie.Ongoing || ie.DurationSec != 120 || ie.InPeriodSec != 120 || ie.OpenSeq == nil ||
		ie.CloseSeq == nil || ie.Anchor == nil || ie.Anchor.TSA == "" || len(ie.KeyFacts) == 0 || len(ie.EvidenceSeqs) == 0 {
		t.Errorf("incident entry = %+v", ie)
	}
	o := r.Optical
	if o.Readings != 7 || o.LowAlarmN != 7 || o.LowWarnN != 7 || *o.RxMinX10 != -402 || *o.RxMaxX10 != -315 ||
		*o.LowAlarmThrX10 != -295 || *o.LowWarnThrX10 != -292 || len(o.Periods) != 2 || len(o.LatestDMI) != 2 {
		t.Errorf("optical = %+v", o)
	}
	if len(r.GatewayEvents) != 3 || r.GatewayStatus.BroadbandDown != 1 || r.GatewayStatus.Snapshots != 7 {
		t.Errorf("gateway events/status = %d / %+v", len(r.GatewayEvents), r.GatewayStatus)
	}
	if len(r.Gateway) != 1 || r.Gateway[0].Serial != "TESTSERIAL0001" || r.Gateway[0].Firmware != "6.34.7" || r.Gateway[0].Snapshots != 7 {
		t.Errorf("gateway identity = %+v", r.Gateway)
	}
	if r.Host == nil || r.Host.Hostname != "TESTHOST" {
		t.Errorf("host = %+v", r.Host)
	}
	b := r.Verification.Bundle
	if !b.OK || b.FailuresTotal != 0 || b.BlobsIncluded != len(wantBlobs) || b.AnchorsChecked != 3 || b.AnchorsHeadOK != 3 ||
		b.SignaturesOK != wantRecords || b.HashesOK != wantRecords || r.Verification.Overall != "pass" {
		t.Errorf("bundle check = %+v (overall %s)", b, r.Verification.Overall)
	}
	if r.Verification.Full == nil || !r.Verification.Full.FingerprintMatches {
		t.Errorf("full verification = %+v", r.Verification.Full)
	}
	if len(r.Ledger.Omitted) != 1 || r.Ledger.Omitted[0].Name != "ledger-2026-10-02" {
		t.Errorf("omitted = %+v", r.Ledger.Omitted)
	}
	if r.Ledger.Fingerprint != s.f.fingerprint() || r.Ledger.Genesis == nil || r.Ledger.Genesis.Seq != 0 {
		t.Errorf("ledger = %+v", r.Ledger)
	}
	types := map[string]int{}
	for _, c := range r.Custody {
		types[c.Type]++
	}
	for _, typ := range []string{model.TypeGenesis, model.TypeBootstrapImport, model.TypeMonitorStart, model.TypeMonitorStop,
		model.TypeConfigChange, model.TypeOperatorNote, model.TypeCustodyExport, model.TypePowerEvent, "gap"} {
		if types[typ] == 0 {
			t.Errorf("custody log lacks %s: %v", typ, types)
		}
	}
	if len(r.Bootstrap) != 1 || !strings.Contains(r.Bootstrap[0].Notes, "CAPTURE NOTES") {
		t.Errorf("bootstrap = %+v", r.Bootstrap)
	}
	if r.Service.Checks != 6 || r.Service.DNSHijacks != 1 || r.Service.HTTPHijacks != 1 || len(r.Service.HijackExamples) != 2 ||
		len(r.Service.DNS) != 1 || r.Service.DNS[0].Hijacked != 1 || r.Service.HTTP[0].OK != 5 {
		t.Errorf("service checks = %+v", r.Service)
	}
	if r.LocalLink.Observations != 1 || r.LocalLink.SignalMinPct == nil || *r.LocalLink.SignalMinPct != 80 || r.Clock.Checks != 1 ||
		r.Clock.MaxAbsOffsetMs == nil || *r.Clock.MaxAbsOffsetMs != 12 {
		t.Errorf("local link / clock = %+v / %+v", r.LocalLink, r.Clock)
	}

	// REPORT.html.
	html := string(z.files["REPORT.html"])
	for _, want := range []string{
		s.incidentID, "AT&amp;T gateway optical levels", "Source: the AT&amp;T gateway itself", "OPTICAL_RX_LOW_ALARM",
		"Gateway low-alarm threshold -29.5 dBm", "Gateway low-warning threshold -29.2 dBm", "<svg", "BGW320-505", "TESTSERIAL0001",
		"6.34.7", groupFingerprint(s.f.fingerprint()), "ISP_OUTAGE", "FIBER_LINK_DOWN", "provider", "UPSTREAM_UNREACHABLE",
		"&lt;script&gt;alert(1)&lt;/script&gt;", "&lt;b&gt;at the owner", "PASS", "Custody log", "tools/verify_bundle.py",
		"openssl ts -verify", "att-monitor verify-bundle", "Homeowner", "LOS (O1)", "power event suspend",
		"Hijack observations", "redirect to the gateway", "Redirection of DNS or web traffic (hijacking) was detected in 2 observations (DNS 1, HTTP 1)",
	} {
		if !strings.Contains(html, want) {
			t.Errorf("REPORT.html lacks %q", want)
		}
	}
	for _, bad := range []string{"<script", "<link", "@import", "url(", "<iframe", "<img", "<object", "<embed"} {
		if strings.Contains(strings.ToLower(html), bad) {
			t.Errorf("REPORT.html contains %q", bad)
		}
	}
	if m := externalRefRE.FindString(html); m != "" {
		t.Errorf("REPORT.html references an external resource: %q", m)
	}
	if strings.Contains(html, "NaN") || strings.Contains(html, "Inf") {
		t.Error("REPORT.html contains NaN/Inf")
	}

	// README and key file.
	readme := string(z.files["README.txt"])
	for _, want := range []string{"START HERE", info.FileName, groupFingerprint(s.f.fingerprint()), "python tools/verify_bundle.py", "sha256sum -c MANIFEST.sha256"} {
		if !strings.Contains(readme, want) {
			t.Errorf("README.txt lacks %q", want)
		}
	}
	key := string(z.files["keys/public-key.txt"])
	for _, want := range []string{"Public key (base64): " + r.Ledger.PublicKey, groupFingerprint(s.f.fingerprint())[:39], s.f.fingerprint()} {
		if !strings.Contains(key, want) {
			t.Errorf("public-key.txt lacks %q:\n%s", want, key)
		}
	}
}

func TestBuildDeterministic(t *testing.T) {
	s := buildScenario(t)
	dirA, dirB := t.TempDir(), t.TempDir()
	ea, _ := newTestExporter(t, s, dirA)
	eb, _ := newTestExporter(t, s, dirB)
	req := contracts.ExportRequest{IncidentID: s.incidentID, PreparedBy: "x"}
	ia, err := ea.Build(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	ib, err := eb.Build(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := os.ReadFile(ia.Path)
	b, _ := os.ReadFile(ib.Path)
	if ia.FileName != ib.FileName || !bytes.Equal(a, b) || ia.SHA256 != ib.SHA256 {
		t.Fatalf("two builds differ: %s %s vs %s %s", ia.FileName, ia.SHA256, ib.FileName, ib.SHA256)
	}
	// A second build into the same directory never overwrites the first.
	ic, err := ea.Build(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if want := strings.TrimSuffix(ia.FileName, ".zip") + "-2.zip"; ic.FileName != want {
		t.Errorf("second build name = %s, want %s", ic.FileName, want)
	}
	if again, _ := os.ReadFile(ia.Path); !bytes.Equal(again, a) {
		t.Error("first bundle was modified by the second build")
	}
}

func segNames(z zipContent) []string {
	var out []string
	for _, n := range z.names {
		if m := bundleSegRE.FindStringSubmatch(n); m != nil {
			out = append(out, m[1])
		}
	}
	return out
}

func TestBuildPeriodSelectsSegments(t *testing.T) {
	s := buildScenario(t)
	d := func(day, h int) time.Time { return time.Date(2026, 10, day, h, 0, 0, 0, time.UTC) }
	tests := []struct {
		name     string
		from, to time.Time
		want     []string
		omitted  []string
	}{
		{"day 3 exactly", d(3, 0), d(4, 0), []string{"ledger-2026-10-01", "ledger-2026-10-03"}, []string{"ledger-2026-10-02"}},
		{"spanning days 2-3", d(2, 12), d(3, 1), []string{"ledger-2026-10-01", "ledger-2026-10-02", "ledger-2026-10-03"}, nil},
		{"genesis day only", d(1, 0), d(1, 12), []string{"ledger-2026-10-01"}, nil},
		{"last day", d(4, 10), d(6, 0), []string{"ledger-2026-10-01", "ledger-2026-10-04"}, []string{"ledger-2026-10-02", "ledger-2026-10-03"}},
		{"before genesis", time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC), time.Date(2026, 9, 2, 0, 0, 0, 0, time.UTC), []string{"ledger-2026-10-01"}, nil},
		{"everything (zero from/to)", time.Time{}, time.Time{}, []string{"ledger-2026-10-01", "ledger-2026-10-02", "ledger-2026-10-03", "ledger-2026-10-04"}, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e, _ := newTestExporter(t, s, t.TempDir())
			info, err := e.Build(context.Background(), contracts.ExportRequest{From: tc.from, To: tc.to})
			if err != nil {
				t.Fatal(err)
			}
			z := readZip(t, info.Path)
			if got := segNames(z); strings.Join(got, ",") != strings.Join(tc.want, ",") {
				t.Errorf("segments = %v, want %v", got, tc.want)
			}
			r := readReportJSON(t, z)
			var om []string
			for _, o := range r.Ledger.Omitted {
				om = append(om, o.Name)
			}
			if strings.Join(om, ",") != strings.Join(tc.omitted, ",") {
				t.Errorf("omitted = %v, want %v", om, tc.omitted)
			}
			if !r.Verification.Bundle.OK {
				t.Errorf("bundle check failed: %+v", r.Verification.Bundle.Failures)
			}
			if tc.from.IsZero() {
				if r.Period.From != s.f.segs[0].date.Add(10*time.Hour).Format(time.RFC3339Nano) {
					t.Errorf("zero From should start at genesis, got %s", r.Period.From)
				}
				if r.Summary.Incidents != 1 {
					t.Errorf("incidents = %d", r.Summary.Incidents)
				}
			}
			if err := VerifyManifest(info.Path); err != nil {
				t.Error(err)
			}
		})
	}
}

func TestBuildErrors(t *testing.T) {
	s := buildScenario(t)
	empty := newFakeLedger(t)
	tests := []struct {
		name    string
		mod     func(*Options)
		req     contracts.ExportRequest
		ctx     func() context.Context
		wantErr error
	}{
		{name: "unknown incident", req: contracts.ExportRequest{IncidentID: "INC-20261003-000000Z"}, wantErr: contracts.ErrNotFound},
		{name: "malformed incident id", req: contracts.ExportRequest{IncidentID: "nope"}, wantErr: contracts.ErrNotFound},
		{name: "inverted range", req: contracts.ExportRequest{From: s.now, To: s.now.Add(-time.Hour)}},
		{name: "empty range", req: contracts.ExportRequest{From: s.now, To: s.now}},
		{name: "no reader", mod: func(o *Options) { o.Reader = nil }, req: contracts.ExportRequest{From: s.now.Add(-time.Hour)}},
		{name: "no segments", mod: func(o *Options) { o.Reader = empty }, req: contracts.ExportRequest{From: s.now.Add(-time.Hour), To: s.now}},
		{name: "canceled", req: contracts.ExportRequest{IncidentID: s.incidentID}, ctx: func() context.Context {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			return ctx
		}, wantErr: context.Canceled},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			e, act := newTestExporter(t, s, dir, func(o *Options) {
				if tc.mod != nil {
					tc.mod(o)
				}
			})
			ctx := context.Background()
			if tc.ctx != nil {
				ctx = tc.ctx()
			}
			_, err := e.Build(ctx, tc.req)
			if err == nil {
				t.Fatal("Build succeeded")
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Errorf("err = %v, want %v", err, tc.wantErr)
			}
			if ents, _ := os.ReadDir(dir); len(ents) != 0 {
				t.Errorf("files left behind: %v", ents)
			}
			if len(act.exports) != 0 {
				t.Error("custody recorded for a failed build")
			}
		})
	}
	t.Run("no dir", func(t *testing.T) {
		e, _ := newTestExporter(t, s, "")
		if _, err := e.Build(context.Background(), contracts.ExportRequest{IncidentID: s.incidentID}); err == nil {
			t.Fatal("Build without Dir succeeded")
		}
	})
}

func TestBuildWithoutActionsOrVerifier(t *testing.T) {
	s := buildScenario(t)
	dir := t.TempDir()
	e, _ := newTestExporter(t, s, dir, func(o *Options) { o.Actions = nil; o.Verifier = nil })
	info, err := e.Build(context.Background(), contracts.ExportRequest{IncidentID: s.incidentID})
	if err != nil {
		t.Fatal(err)
	}
	if info.CustodySeq != 0 {
		t.Errorf("CustodySeq = %d", info.CustodySeq)
	}
	if _, err := os.Stat(info.Path + sidecarSuffix); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("sidecar written without Actions: %v", err)
	}
	z := readZip(t, info.Path)
	r := readReportJSON(t, z)
	if r.Verification.Full != nil || r.Verification.FullError != "" || r.Verification.Overall != "pass" {
		t.Errorf("verification = %+v", r.Verification)
	}
	if !strings.Contains(string(z.files["REPORT.html"]), "not performed") {
		t.Error("REPORT.html should say the full verification was not performed")
	}
}

func TestBuildVerifierResults(t *testing.T) {
	s := buildScenario(t)
	bad := okVerifyReport(s)
	bad.OK = false
	bad.FailuresTotal = 1
	bad.Failures = []model.VerifyFailure{{Seq: 7, Segment: "ledger-2026-10-01", Line: 8, Problem: "prev_mismatch", Detail: "edited"}}
	tests := []struct {
		name     string
		v        *fakeVerifier
		overall  string
		inReport string
	}{
		{"verifier failure", &fakeVerifier{rep: bad}, "fail", "prev_mismatch"},
		{"verifier error", &fakeVerifier{err: errors.New("ledger unreadable")}, "fail", "ledger unreadable"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e, _ := newTestExporter(t, s, t.TempDir(), func(o *Options) { o.Verifier = tc.v })
			info, err := e.Build(context.Background(), contracts.ExportRequest{IncidentID: s.incidentID})
			if err != nil {
				t.Fatal(err)
			}
			z := readZip(t, info.Path)
			r := readReportJSON(t, z)
			if r.Verification.Overall != tc.overall {
				t.Errorf("overall = %s", r.Verification.Overall)
			}
			html := string(z.files["REPORT.html"])
			if !strings.Contains(html, tc.inReport) || !strings.Contains(html, "FAIL") && !strings.Contains(html, "ERROR") {
				t.Errorf("REPORT.html does not show %q", tc.inReport)
			}
		})
	}
}

func TestBuildCustodyFailure(t *testing.T) {
	s := buildScenario(t)
	e, act := newTestExporter(t, s, t.TempDir())
	act.err = errors.New("ledger closed")
	info, err := e.Build(context.Background(), contracts.ExportRequest{IncidentID: s.incidentID})
	if !errors.Is(err, ErrCustodyNotRecorded) {
		t.Fatalf("err = %v, want ErrCustodyNotRecorded", err)
	}
	if info.FileName == "" || info.SHA256 == "" {
		t.Fatalf("info should describe the written bundle: %+v", info)
	}
	if _, err := os.Stat(info.Path); err != nil {
		t.Errorf("bundle should exist: %v", err)
	}
	if _, err := os.Stat(info.Path + sidecarSuffix); !errors.Is(err, os.ErrNotExist) {
		t.Error("sidecar written although the custody record failed")
	}
}

func TestBuildActiveSegmentPartialTail(t *testing.T) {
	s := buildScenario(t)
	s.f.lastActive = true
	s.f.tail = []byte(`{"h":"0000","s":"AAAA","b":"{\"v\":1,\"seq\":`)
	e, _ := newTestExporter(t, s, t.TempDir())
	info, err := e.Build(context.Background(), contracts.ExportRequest{From: time.Date(2026, 10, 4, 0, 0, 0, 0, time.UTC), To: s.now})
	if err != nil {
		t.Fatal(err)
	}
	z := readZip(t, info.Path)
	if got := z.files["ledger/ledger-2026-10-04.jsonl"]; !bytes.Equal(got, s.f.segs[3].data) {
		t.Errorf("active segment should be exported without the partial line (%d vs %d bytes)", len(got), len(s.f.segs[3].data))
	}
	r := readReportJSON(t, z)
	if !r.Verification.Bundle.OK {
		t.Errorf("bundle check failed: %+v", r.Verification.Bundle.Failures)
	}
	found := false
	for _, n := range r.Verification.Bundle.Notes {
		found = found || strings.Contains(n, fmt.Sprintf("%d trailing bytes", len(s.f.tail)))
	}
	if !found {
		t.Errorf("notes do not mention the excluded tail: %v", r.Verification.Bundle.Notes)
	}
}

// TestBuildReportsDamagedLedger: a damaged or tampered ledger is still exported (evidence is
// never hidden), but the bundle checks and the report say so.
func TestBuildReportsDamagedLedger(t *testing.T) {
	day3 := time.Date(2026, 10, 3, 0, 0, 0, 0, time.UTC)
	tests := []struct {
		name     string
		damage   func(s *scenario)
		want     string
		from, to time.Time // zero: day 3
	}{
		{name: "corrupted genesis record", damage: func(s *scenario) {
			s.f.segs[0].data = bytes.Replace(s.f.segs[0].data, []byte("Evidence ledger"), []byte("Evidance ledger"), 1)
		}, want: "bad_signature"},
		{name: "previous segment edited (segment_open hash)", damage: func(s *scenario) {
			s.f.segs[1].data = bytes.Replace(s.f.segs[1].data, []byte(`Wi-Fi`), []byte(`Wi-Fy`), 1)
		}, want: "segment_hash", from: time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC), to: time.Date(2026, 10, 3, 1, 0, 0, 0, time.UTC)},
		{name: "edited body", damage: func(s *scenario) {
			s.f.segs[2].data = bytes.Replace(s.f.segs[2].data, []byte(`TestNet`), []byte(`EvilNet`), 1)
		}, want: "hash_mismatch"},
		{name: "re-hashed body (signature and chain catch it)", damage: func(s *scenario) {
			lines := bytes.Split(s.f.segs[2].data, []byte("\n"))
			env, body, err := parseLine(lines[5])
			if err != nil {
				t.Fatal(err)
			}
			body.Type = model.TypeHeartbeat
			b, _ := json.Marshal(body)
			env.B, env.H = string(b), sha256Hex(b)
			lines[5], _ = json.Marshal(env)
			s.f.segs[2].data = bytes.Join(lines, []byte("\n"))
		}, want: "bad_signature"},
		{name: "deleted record", damage: func(s *scenario) {
			lines := bytes.Split(s.f.segs[2].data, []byte("\n"))
			s.f.segs[2].data = bytes.Join(append(lines[:7:7], lines[8:]...), []byte("\n"))
		}, want: "seq_gap"},
		{name: "missing blob", damage: func(s *scenario) { s.f.hidden[s.pageBlob] = true }, want: "blob_missing"},
		{name: "missing time-stamp token", damage: func(s *scenario) {
			for _, a := range anchorsOf(t, s.f.segs[2].data) {
				s.f.hidden[a.TokenSHA256] = true
			}
		}, want: "anchor_invalid"},
		{name: "anchor names a different head", damage: func(s *scenario) {
			lines := bytes.Split(bytes.TrimSuffix(s.f.segs[2].data, []byte("\n")), []byte("\n"))
			for i, line := range lines {
				env, body, err := parseLine(line)
				if err != nil || body.Type != model.TypeAnchor {
					continue
				}
				var a model.Anchor
				json.Unmarshal(body.Data, &a)
				a.HeadHash = strings.Repeat("ab", 32)
				body.Data, _ = json.Marshal(a)
				b, _ := json.Marshal(body)
				env.B, env.H = string(b), sha256Hex(b)
				lines[i], _ = json.Marshal(env)
				break
			}
			s.f.segs[2].data = append(bytes.Join(lines, []byte("\n")), '\n')
		}, want: "anchor_invalid"},
		{name: "truncated sealed segment", damage: func(s *scenario) {
			s.f.segs[2].data = append(s.f.segs[2].data, []byte(`{"h":"abc"`)...)
		}, want: "parse_error"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := buildScenario(t)
			before := fmt.Sprint(len(s.f.hidden), sha256Hex(bytes.Join([][]byte{s.f.segs[0].data, s.f.segs[1].data, s.f.segs[2].data}, nil)))
			tc.damage(s)
			if after := fmt.Sprint(len(s.f.hidden), sha256Hex(bytes.Join([][]byte{s.f.segs[0].data, s.f.segs[1].data, s.f.segs[2].data}, nil))); after == before {
				t.Fatal("the damage function did not change anything")
			}
			e, _ := newTestExporter(t, s, t.TempDir())
			from, to := tc.from, tc.to
			if from.IsZero() {
				from, to = day3, day3.Add(24*time.Hour)
			}
			info, err := e.Build(context.Background(), contracts.ExportRequest{From: from, To: to})
			if err != nil {
				t.Fatalf("Build: %v", err)
			}
			z := readZip(t, info.Path)
			r := readReportJSON(t, z)
			if r.Verification.Bundle.OK || r.Verification.Overall != "fail" || !hasProblem(r, tc.want) {
				t.Errorf("want failure %s, got %+v", tc.want, r.Verification.Bundle.Failures)
			}
			for _, seg := range r.Ledger.Segments {
				if !bytes.Equal(z.files[seg.Path], s.f.segmentBytes(seg.Name)) {
					t.Errorf("%s must be exported byte-exact", seg.Path)
				}
			}
			if tc.name == "corrupted genesis record" {
				if r.Verification.Bundle.SignaturesOK != 0 || r.Verification.Bundle.SignaturesUnchecked == 0 || r.Ledger.PublicKey == "" {
					t.Errorf("a corrupted genesis key must not be used: %+v", r.Verification.Bundle)
				}
			}
			if html := string(z.files["REPORT.html"]); !strings.Contains(html, "FAIL") || !strings.Contains(html, tc.want) {
				t.Error("REPORT.html does not show the failure")
			}
		})
	}
}

// ----------------------------------------------------------------- list / open

func TestListAndOpen(t *testing.T) {
	s := buildScenario(t)
	dir := t.TempDir()
	e, _ := newTestExporter(t, s, dir)
	first, err := e.Build(context.Background(), contracts.ExportRequest{IncidentID: s.incidentID})
	if err != nil {
		t.Fatal(err)
	}
	s.now = s.now.Add(time.Hour)
	second, err := e.Build(context.Background(), contracts.ExportRequest{From: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatal(err)
	}
	// Junk that List must ignore.
	os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("x"), 0o644)
	os.Mkdir(filepath.Join(dir, "sub.zip"), 0o755)

	list, err := New(Options{Dir: dir}).List() // fresh exporter: no cache, hashes recomputed
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 || list[0].FileName != second.FileName || list[1].FileName != first.FileName {
		t.Fatalf("List = %+v", list)
	}
	for i, want := range []contracts.ExportInfo{second, first} {
		got := list[i]
		if got.SHA256 != want.SHA256 || got.Size != want.Size || !got.Created.Equal(want.Created) || got.CustodySeq != 4242 ||
			got.ManifestSHA256 != want.ManifestSHA256 || got.Records != want.Records || got.Blobs != want.Blobs {
			t.Errorf("List[%d] = %+v, want %+v", i, got, want)
		}
	}

	rc, info, err := e.Open(first.FileName)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(rc)
	rc.Close()
	want, _ := os.ReadFile(first.Path)
	if !bytes.Equal(got, want) || info.SHA256 != first.SHA256 {
		t.Error("Open returned different content")
	}

	empty, err := New(Options{Dir: filepath.Join(dir, "missing")}).List()
	if err != nil || len(empty) != 0 {
		t.Errorf("List of a missing dir = %v, %v", empty, err)
	}
}

func TestOpenNameValidation(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "good.zip"), []byte("PK"), 0o644); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, "secret.txt"), []byte("x"), 0o644)
	e := New(Options{Dir: dir})
	tests := []struct {
		name    string
		invalid bool
	}{
		{"good.zip", false},
		{"absent.zip", false},
		{"../good.zip", true},
		{"..\\good.zip", true},
		{"sub/good.zip", true},
		{`sub\good.zip`, true},
		{"/good.zip", true},
		{`C:\good.zip`, true},
		{"good.zip:stream", true},
		{"good.zip:stream.zip", true},
		{"secret.txt", true},
		{"", true},
		{".zip", true},
		{".hidden.zip", true},
		{"NUL.zip", true},
		{"com1.zip", true},
		{"lpt9.zip", true},
		{"a..zip", true},
		{"bad\x00.zip", true},
		{"spaces in name.zip", true},
		{strings.Repeat("a", 300) + ".zip", true},
	}
	for _, tc := range tests {
		t.Run(fmt.Sprintf("%q", tc.name), func(t *testing.T) {
			rc, _, err := e.Open(tc.name)
			if rc != nil {
				rc.Close()
			}
			switch {
			case tc.invalid:
				if !errors.Is(err, ErrInvalidName) || !errors.Is(err, contracts.ErrNotFound) {
					t.Errorf("err = %v, want ErrInvalidName and ErrNotFound", err)
				}
			case tc.name == "absent.zip":
				if !errors.Is(err, contracts.ErrNotFound) || errors.Is(err, ErrInvalidName) {
					t.Errorf("err = %v, want ErrNotFound", err)
				}
			default:
				if err != nil {
					t.Errorf("err = %v", err)
				}
			}
		})
	}
	// A directory with a bundle-like name is not a bundle.
	os.Mkdir(filepath.Join(dir, "dir.zip"), 0o755)
	if _, _, err := e.Open("dir.zip"); !errors.Is(err, contracts.ErrNotFound) {
		t.Errorf("Open(dir) = %v", err)
	}
}

func TestBuildConcurrent(t *testing.T) {
	s := buildScenario(t)
	e, act := newTestExporter(t, s, t.TempDir())
	errs := make(chan error, 4)
	names := make(chan string, 4)
	for i := 0; i < 4; i++ {
		go func() {
			info, err := e.Build(context.Background(), contracts.ExportRequest{IncidentID: s.incidentID})
			errs <- err
			names <- info.FileName
		}()
	}
	seen := map[string]bool{}
	for i := 0; i < 4; i++ {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
		n := <-names
		if seen[n] {
			t.Errorf("duplicate bundle name %s", n)
		}
		seen[n] = true
	}
	if len(act.exports) != 4 {
		t.Errorf("custody records = %d", len(act.exports))
	}
	if list, err := e.List(); err != nil || len(list) != 4 {
		t.Errorf("List = %d entries, %v", len(list), err)
	}
}
