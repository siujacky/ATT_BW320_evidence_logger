package export

// The report of every genuine bundle must be exactly reproducible from the bundle (VerifyReport),
// whatever happened while it was written and whatever time zone the verifier runs in.

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"
	_ "time/tzdata" // tests export in a zone with daylight saving time (Windows has no IANA database)

	"attmonitor/internal/contracts"
	"attmonitor/internal/model"
)

// corruptBlobReader serves one blob with wrong content (a damaged blob store).
type corruptBlobReader struct {
	*fakeLedger
	id string
}

func (c *corruptBlobReader) GetBlob(id string) ([]byte, error) {
	if id == c.id {
		return []byte("damaged on disk"), nil
	}
	return c.fakeLedger.GetBlob(id)
}

// Damaged ledgers, partial tails, missing or corrupt blobs, every outcome of the token verifier
// and of the full-ledger verification: the report must still verify, or genuine evidence would
// fail verification.
func TestGenuineBundlesVerifyReport(t *testing.T) {
	day3 := time.Date(2026, 10, 3, 0, 0, 0, 0, time.UTC)
	period := contracts.ExportRequest{From: day3, To: day3.Add(24 * time.Hour), PreparedBy: "Owner <owner@example.com>",
		Notes: "line 1\nline 2 & more"}
	cases := []struct {
		name string
		prep func(s *scenario, o *Options)
		req  func(s *scenario) contracts.ExportRequest
	}{
		{"incident", nil, func(s *scenario) contracts.ExportRequest { return contracts.ExportRequest{IncidentID: s.incidentID} }},
		{"whole ledger", nil, func(s *scenario) contracts.ExportRequest { return contracts.ExportRequest{} }},
		{"partial tail of the active segment", func(s *scenario, o *Options) {
			s.f.lastActive, s.f.tail = true, []byte(`{"h":"0000","s":"AAAA","b":"{\"v\":1,\"seq\":`)
		}, func(s *scenario) contracts.ExportRequest {
			return contracts.ExportRequest{From: day3.Add(24 * time.Hour), To: s.now}
		}},
		{"edited record", func(s *scenario, o *Options) {
			s.f.segs[2].data = bytes.Replace(s.f.segs[2].data, []byte(`TestNet`), []byte(`EvilNet`), 1)
		}, nil},
		{"deleted record", func(s *scenario, o *Options) {
			lines := bytes.Split(s.f.segs[2].data, []byte("\n"))
			s.f.segs[2].data = bytes.Join(append(lines[:7:7], lines[8:]...), []byte("\n"))
		}, nil},
		{"corrupted genesis", func(s *scenario, o *Options) {
			s.f.segs[0].data = bytes.Replace(s.f.segs[0].data, []byte("Evidence ledger"), []byte("Evidance ledger"), 1)
		}, nil},
		{"truncated sealed segment", func(s *scenario, o *Options) {
			s.f.segs[2].data = append(s.f.segs[2].data, []byte(`{"h":"abc"`)...)
		}, nil},
		{"missing blob", func(s *scenario, o *Options) { s.f.hidden[s.pageBlob] = true }, nil},
		{"corrupt blob in the store", func(s *scenario, o *Options) { o.Reader = &corruptBlobReader{fakeLedger: s.f, id: s.pageBlob} }, nil},
		{"missing time-stamp tokens", func(s *scenario, o *Options) {
			for _, a := range anchorsOf(t, s.f.segs[2].data) {
				s.f.hidden[a.TokenSHA256] = true
			}
		}, nil},
		{"token verifier, chain trusted", func(s *scenario, o *Options) {
			o.TokenVerifier = &fakeTokenVerifier{chainOK: true, tsaName: "CN=Test TSA, O=Example"}
		}, nil},
		{"token verifier, chain not trusted", func(s *scenario, o *Options) {
			o.TokenVerifier = &fakeTokenVerifier{note: strings.Repeat("x509: certificate signed by unknown authority <b> ", 20)}
		}, nil},
		{"token verifier fails", func(s *scenario, o *Options) {
			o.TokenVerifier = &fakeTokenVerifier{err: errors.New("CMS: bad\nsignature")}
		}, nil},
		{"token verifier panics", func(s *scenario, o *Options) { o.TokenVerifier = &fakeTokenVerifier{panics: true} }, nil},
		{"roots file", func(s *scenario, o *Options) { o.ExtraFiles = map[string][]byte{tsaRootsPath: s.f.tsa.rootPEM()} }, nil},
		{"full verification failed", func(s *scenario, o *Options) {
			bad := okVerifyReport(s)
			bad.OK, bad.FailuresTotal = false, 1
			bad.Failures = []model.VerifyFailure{{Seq: 7, Segment: "ledger-2026-10-01", Line: 8, Problem: "prev_mismatch", Detail: "edited"}}
			o.Verifier = &fakeVerifier{rep: bad}
		}, nil},
		{"full verification error", func(s *scenario, o *Options) { o.Verifier = &fakeVerifier{err: errors.New("ledger unreadable")} }, nil},
		{"full verification of another key", func(s *scenario, o *Options) {
			other := okVerifyReport(s)
			other.Fingerprint = strings.Repeat("ab", 32)
			o.Verifier = &fakeVerifier{rep: other}
		}, nil},
		{"full verification not completed", func(s *scenario, o *Options) {
			o.Verifier, o.FullVerifyTimeout = &blockingVerifier{release: make(chan struct{})}, 50*time.Millisecond
		}, nil},
		{"no full verification", func(s *scenario, o *Options) { o.Verifier = nil }, nil},
		// Text from outside the records is stated in report.json and must read back exactly:
		// multi-byte characters at a truncation point and invalid UTF-8.
		{"token verifier note with multi-byte text and invalid UTF-8", func(s *scenario, o *Options) {
			o.TokenVerifier = &fakeTokenVerifier{note: "\xff" + strings.Repeat("é", 300), tsaName: "CN=T\xc3SA"}
		}, nil},
		{"token verifier error with invalid UTF-8", func(s *scenario, o *Options) {
			o.TokenVerifier = &fakeTokenVerifier{err: errors.New(strings.Repeat("ü", 199) + "\xe2\x82")}
		}, nil},
		{"full verification text with invalid UTF-8", func(s *scenario, o *Options) {
			bad := okVerifyReport(s)
			bad.OK, bad.FailuresTotal, bad.Notes = false, 1, []string{"note \xff"}
			bad.Failures = []model.VerifyFailure{{Seq: 7, Segment: "ledger-2026-10-01", Line: 8, Problem: "prev_mismatch", Detail: "edited \xc3"}}
			o.Verifier = &fakeVerifier{rep: bad}
		}, nil},
		{"full verification error with invalid UTF-8", func(s *scenario, o *Options) { o.Verifier = &fakeVerifier{err: errors.New("disk \xff")} }, nil},
		{"request and software with invalid UTF-8", func(s *scenario, o *Options) { o.Software.ExePath = `C:\Program Files\at\xff` },
			func(s *scenario) contracts.ExportRequest {
				return contracts.ExportRequest{IncidentID: s.incidentID, PreparedBy: "Own\xffer", Notes: "n\xc3", Requester: "web \xe2"}
			}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := buildScenario(t)
			e, _ := newTestExporter(t, s, t.TempDir(), func(o *Options) {
				if tc.prep != nil {
					tc.prep(s, o)
				}
			})
			req := period
			if tc.req != nil {
				req = tc.req(s)
			}
			info, err := e.Build(context.Background(), req)
			if err != nil {
				t.Fatalf("Build: %v", err)
			}
			mustVerifyReport(t, info.Path)
			if err := VerifyManifest(info.Path); err != nil {
				t.Errorf("VerifyManifest: %v", err)
			}
		})
	}
}

// Exported in a zone with daylight saving time, verified in another zone.
func TestReportVerificationAcrossDaylightSavingZone(t *testing.T) {
	la, err := time.LoadLocation("America/Los_Angeles")
	if err != nil {
		t.Skipf("no time zone data: %v", err)
	}
	saved := time.Local
	defer func() { time.Local = saved }()
	// A period across the end of daylight saving time (2026-11-01 09:00 UTC).
	d := func(dd, h int) time.Time { return time.Date(2026, 11, dd, h, 0, 0, 0, time.UTC) }
	f := rvLedger(t, d(1, 6))
	sc := &scenario{f: f}
	for h := 7; h <= 11; h++ {
		sc.snapshot(d(1, h), -315, true, "OPERATION (O5)", []string{codeRxLowAlarm}, "periodic")
	}
	rvSamples(f, d(1, 7), 30, 10*time.Minute, model.StateOnline, "", model.AttrNone, "")
	time.Local = la
	info, z, r := rvExport(t, f, d(2, 12), contracts.ExportRequest{From: d(1, 6), To: d(2, 6)})
	if len(r.LocalTime.Spans) < 2 {
		t.Errorf("zone record %+v lacks the DST change", r.LocalTime.Spans)
	}
	html := string(z.files["REPORT.html"])
	if !strings.Contains(html, " PDT") || !strings.Contains(html, " PST") {
		t.Error("REPORT.html does not show both PDT and PST local times")
	}
	time.Local = time.UTC
	if err := VerifyManifest(info.Path); err != nil {
		t.Fatalf("verified in UTC: %v", err)
	}
}

func TestZoneRecordRoundTrip(t *testing.T) {
	la, err := time.LoadLocation("America/Los_Angeles")
	if err != nil {
		t.Skipf("no time zone data: %v", err)
	}
	lo, hi := time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC), time.Date(2028, 6, 1, 0, 0, 0, 0, time.UTC)
	for _, src := range []*time.Location{la, time.UTC, time.FixedZone("XST", 5*3600+1800), time.FixedZone("", -4*3600)} {
		spans := zoneSpans(src, lo, hi)
		loc, err := zoneLocation(spans)
		if err != nil {
			t.Fatalf("%s: %v", src, err)
		}
		for at := lo; at.Before(hi); at = at.Add(97 * time.Minute) {
			n1, o1 := at.In(src).Zone()
			n2, o2 := at.In(loc).Zone()
			if n1 != n2 || o1 != o2 {
				t.Fatalf("%s at %s: %s %d, rebuilt %s %d", src, at, n1, o1, n2, o2)
			}
		}
		if src == la && len(spans) != 7 {
			t.Errorf("LA spans = %d, want 7 (3 years)", len(spans))
		}
	}
	for _, bad := range [][]zoneSpan{nil, {{From: "x", Abbrev: "A"}}, {{From: "2026-01-01T00:00:00Z", Abbrev: "A B"}},
		{{From: "2026-01-01T00:00:00Z", Abbrev: "A", Offset: 30 * 3600}},
		{{From: "2026-01-01T00:00:00Z", Abbrev: "A"}, {From: "2025-01-01T00:00:00Z", Abbrev: "B"}}} {
		if _, err := zoneLocation(bad); !errors.Is(err, errZone) {
			t.Errorf("zone %+v accepted: %v", bad, err)
		}
	}
}
