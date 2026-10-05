package web

// Adversarial tests added by the independent review of this package. Each test names the
// defect it guards against.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"attmonitor/internal/contracts"
	"attmonitor/internal/model"
)

// ----------------------------------------------------------------------------- ServeContent errors

// http.ServeContent answers an unsatisfiable Range (416) and a failed precondition (412)
// itself, in plain text, and since Go 1.23 it deletes Cache-Control from those answers. Every
// response of this server must still carry the security headers and every error must be JSON;
// headers that describe the content (attachment name, SHA-256) must not be sent with an error.
func TestServeContentErrorsAreJSONWithSecurityHeaders(t *testing.T) {
	hs := newHarness(t)
	hs.exporter.seekable = true
	id := hs.reader.addBlob([]byte("0123456789"))
	info := decode[contracts.ExportInfo](t, hs.post("/api/exports", `{"incident_id":"INC-1"}`))

	tests := []struct {
		name, path   string
		hdr          map[string]string
		code         int
		sandbox      bool
		contentRange string
	}{
		{"blob range beyond end", "/api/blobs/" + id, map[string]string{"Range": "bytes=100-200"}, 416, false, "bytes */10"},
		{"blob malformed range", "/api/blobs/" + id, map[string]string{"Range": "bytes=z-"}, 416, false, ""},
		{"blob failed precondition", "/api/blobs/" + id, map[string]string{"If-Match": `"abc"`}, 412, false, ""},
		{"blob view range beyond end", "/api/blobs/" + id + "/view", map[string]string{"Range": "bytes=100-"}, 416, true, "bytes */10"},
		{"static range beyond end", "/static/favicon.svg", map[string]string{"Range": "bytes=999999-"}, 416, false, ""},
		{"index range beyond end", "/", map[string]string{"Range": "bytes=999999-"}, 416, false, ""},
		{"export range beyond end", "/api/exports/" + info.FileName, map[string]string{"Range": "bytes=999999-"}, 416, false, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			for _, method := range []string{http.MethodGet, http.MethodHead} {
				rec := hs.serve(hs.request(method, tc.path, nil, tc.hdr))
				if method == http.MethodGet {
					wantJSONError(t, rec, tc.code)
				} else {
					wantStatus(t, rec, tc.code)
				}
				h := rec.Header()
				assertSecurityHeaders(t, h, tc.sandbox)
				for _, k := range []string{"Content-Disposition", "X-Content-SHA256", "Last-Modified"} {
					if v := h.Get(k); v != "" {
						t.Errorf("%s %s: error response carries %s: %q", method, tc.path, k, v)
					}
				}
				if tc.contentRange != "" && h.Get("Content-Range") != tc.contentRange {
					t.Errorf("Content-Range = %q, want %q", h.Get("Content-Range"), tc.contentRange)
				}
			}
		})
	}

	// Satisfiable ranges are unaffected.
	rec := hs.serve(hs.request(http.MethodGet, "/api/blobs/"+id, nil, map[string]string{"Range": "bytes=2-4"}))
	wantStatus(t, rec, http.StatusPartialContent)
	if rec.Body.String() != "234" || rec.Header().Get("X-Content-SHA256") != id {
		t.Errorf("partial content: %q, sha header %q", rec.Body.String(), rec.Header().Get("X-Content-SHA256"))
	}
	assertSecurityHeaders(t, rec.Header(), false)
}

// ----------------------------------------------------------------------------- incident evidence

// countingReader counts the calls a handler makes into the ledger.
type countingReader struct {
	*fakeReader
	recordCalls atomic.Int64
	scanCalls   atomic.Int64
}

func (c *countingReader) Record(seq uint64) (model.Envelope, model.Body, error) {
	c.recordCalls.Add(1)
	return c.fakeReader.Record(seq)
}

func (c *countingReader) Scan(fromSeq uint64, fn func(model.Envelope, model.Body) error) error {
	c.scanCalls.Add(1)
	return c.fakeReader.Scan(fromSeq, fn)
}

// repeatTypes returns n copies of typ.
func repeatTypes(typ string, n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = typ
	}
	return out
}

// dropRecord removes the record with the given seq from a fake ledger (an unreadable or
// deleted line: the ledger's lenient Scan skips such lines and Record cannot find them).
func dropRecord(r *fakeReader, seq uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := range r.bodies {
		if r.bodies[i].Seq == seq {
			r.envs = slices.Delete(r.envs, i, i+1)
			r.bodies = slices.Delete(r.bodies, i, i+1)
			return
		}
	}
}

func seqsOf(views []RecordView) []uint64 {
	out := make([]uint64, len(views))
	for i, v := range views {
		out[i] = v.Seq
	}
	return out
}

// A long incident references more records than one response carries. Keeping only the
// lowest seqs dropped the end of the incident (its close, the final gateway state) from the
// timeline; the start and the end must both be shown.
func TestIncidentDetailLongIncidentShowsStartAndEnd(t *testing.T) {
	hs := newHarness(t)
	hs.reader = newTestLedger(repeatTypes("sample", 3000)...)
	hs.srv.reader = hs.reader
	inc := model.Incident{ID: "INC-20261005-030000Z", Opened: "2026-10-05T03:00:00Z", State: model.StateISPOutage,
		Cause: model.CauseWANDown, Attribution: model.AttrProvider, Rules: "2026.10-1", FirstSeq: 100, LastSeq: 2900}
	for q := uint64(101); q < 2900; q += 5 {
		inc.Evidence = append(inc.Evidence, model.EvidenceRef{Seq: q, Type: "sample"})
	}
	referenced := len(inc.Evidence) + 2
	hs.status.incidents = []model.Incident{inc}

	d := decode[IncidentDetail](t, hs.get("/api/incidents/"+inc.ID))
	got := seqsOf(d.Records)
	if len(got) != MaxIncidentRecords || !d.Truncated || d.Referenced != referenced {
		t.Fatalf("records=%d truncated=%v referenced=%d, want %d true %d", len(got), d.Truncated, d.Referenced, MaxIncidentRecords, referenced)
	}
	if !slices.IsSorted(got) || len(slices.Compact(slices.Clone(got))) != len(got) {
		t.Fatalf("records not ascending/unique: %v", got)
	}
	for _, want := range []uint64{100, 101, 2896, 2900} {
		if !slices.Contains(got, want) {
			t.Errorf("record #%d (start or end of the incident) missing from the detail", want)
		}
	}
	if len(d.Missing) != 0 {
		t.Errorf("missing = %v", d.Missing)
	}
}

func TestIncidentSeqsSelection(t *testing.T) {
	tests := []struct {
		name           string
		inc            model.Incident
		wantLen, total int
		mustHave       []uint64
	}{
		{"small", model.Incident{FirstSeq: 5, LastSeq: 9, Evidence: []model.EvidenceRef{{Seq: 7}, {Seq: 7}, {Seq: 5}}}, 3, 3, []uint64{5, 7, 9}},
		{"no last seq yet (open)", model.Incident{FirstSeq: 5, Evidence: []model.EvidenceRef{{Seq: 6}}}, 2, 2, []uint64{5, 6}},
		{"exactly the cap", model.Incident{FirstSeq: 1, LastSeq: MaxIncidentRecords}, 2, 2, []uint64{1, MaxIncidentRecords}},
	}
	big := model.Incident{FirstSeq: 10_000, LastSeq: 20_000}
	for q := uint64(10_001); q < 20_000; q += 7 {
		big.Evidence = append(big.Evidence, model.EvidenceRef{Seq: q})
	}
	// Evidence before first_seq (e.g. a snapshot compared by a gateway event) is kept too.
	big.Evidence = append(big.Evidence, model.EvidenceRef{Seq: 42})
	tests = append(tests, struct {
		name           string
		inc            model.Incident
		wantLen, total int
		mustHave       []uint64
	}{"long", big, MaxIncidentRecords, len(big.Evidence) + 2, []uint64{42, 10_000, 10_001, 19_997, 20_000}})

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			seqs, total := incidentSeqs(tc.inc)
			if len(seqs) != tc.wantLen || total != tc.total {
				t.Fatalf("len=%d total=%d, want %d %d", len(seqs), total, tc.wantLen, tc.total)
			}
			if !slices.IsSorted(seqs) {
				t.Fatalf("not ascending: %v", seqs)
			}
			for i := 1; i < len(seqs); i++ {
				if seqs[i] == seqs[i-1] {
					t.Fatalf("duplicate %d", seqs[i])
				}
			}
			for _, q := range tc.mustHave {
				if !slices.Contains(seqs, q) {
					t.Errorf("seq %d not selected", q)
				}
			}
		})
	}
}

// Reading each evidence record with Record re-reads a day segment from its start every time
// (seconds of I/O for a long incident, repeated by the dashboard's 30 s refresh while the
// incident is open). Neighbouring records must be read in one forward pass.
func TestIncidentDetailReadsEvidenceInFewPasses(t *testing.T) {
	base := newTestLedger(repeatTypes("sample", 5000)...)
	dropRecord(base, 1200) // unreadable line inside the incident
	inc := model.Incident{ID: "INC-20261005-030000Z", Opened: "2026-10-05T03:00:00Z", State: model.StateISPOutage,
		Cause: model.CauseWANDown, Attribution: model.AttrProvider, Rules: "2026.10-1", FirstSeq: 1000, LastSeq: 1400}
	for q := uint64(1000); q <= 1400; q += 4 {
		inc.Evidence = append(inc.Evidence, model.EvidenceRef{Seq: q, Type: "sample"})
	}
	inc.Evidence = append(inc.Evidence, model.EvidenceRef{Seq: 4800, Type: "anchor"}, model.EvidenceRef{Seq: 9999, Type: "anchor"})

	run := func(t *testing.T, cr *countingReader) IncidentDetail {
		t.Helper()
		hs := newHarness(t)
		hs.srv.reader = cr
		hs.status.incidents = []model.Incident{inc}
		rec := hs.get("/api/incidents/" + inc.ID)
		wantStatus(t, rec, http.StatusOK)
		d := decode[IncidentDetail](t, rec)
		var want []uint64
		for q := uint64(1000); q <= 1400; q += 4 {
			if q != 1200 {
				want = append(want, q)
			}
		}
		want = append(want, 4800)
		if got := seqsOf(d.Records); !slices.Equal(got, want) {
			t.Fatalf("records = %v\nwant %v", got, want)
		}
		if !slices.Equal(d.Missing, []uint64{1200, 9999}) {
			t.Errorf("missing = %v, want [1200 9999]", d.Missing)
		}
		for _, r := range d.Records {
			if !r.HashOK {
				t.Errorf("record %d: hash_ok false on an intact record", r.Seq)
			}
		}
		return d
	}

	t.Run("one scan for the dense part", func(t *testing.T) {
		cr := &countingReader{fakeReader: base}
		before := base.callbacks.Load()
		run(t, cr)
		if n := cr.recordCalls.Load(); n > 3 {
			t.Errorf("%d Record calls, want at most 3 (isolated seqs only)", n)
		}
		if n := cr.scanCalls.Load(); n > 2 {
			t.Errorf("%d scans", n)
		}
		if n := base.callbacks.Load() - before; n > 600 {
			t.Errorf("scanned %d records for an incident spanning 401", n)
		}
	})
	t.Run("scan budget falls back to Record", func(t *testing.T) {
		old := incidentScanBudget
		incidentScanBudget = 10
		defer func() { incidentScanBudget = old }()
		run(t, &countingReader{fakeReader: base})
	})
	t.Run("scan error falls back to Record", func(t *testing.T) {
		broken := &fakeReader{envs: base.envs, bodies: base.bodies, scanErr: errors.New("segment unreadable")}
		run(t, &countingReader{fakeReader: broken})
	})
}

// ----------------------------------------------------------------------------- records integrity

// rewrite replaces the body of the record with the given seq. With rehash the envelope's h is
// recomputed (a re-hashed forgery), otherwise h is left as it was (an edited line).
func rewrite(r *fakeReader, seq uint64, rehash bool, mutate func(*model.Body)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := range r.bodies {
		if r.bodies[i].Seq != seq {
			continue
		}
		mutate(&r.bodies[i])
		b, err := json.Marshal(r.bodies[i])
		if err != nil {
			panic(err)
		}
		r.envs[i].B = string(b)
		if rehash {
			sum := sha256.Sum256(b)
			r.envs[i].H = hex.EncodeToString(sum[:])
		}
		return
	}
	panic(fmt.Sprintf("no record %d", seq))
}

// The ledger reader is lenient: a line that does not parse is skipped and an edited line is
// returned as found. The raw records browser must not silently hide a missing record or show
// an altered one as if it were intact.
func TestRecordsFlagsLedgerIntegrityProblems(t *testing.T) {
	clean := newHarness(t)
	rec := clean.get("/api/records")
	wantStatus(t, rec, http.StatusOK)
	if w := rec.Header().Get(WarningHeader); w != "" {
		t.Errorf("warning on an intact ledger: %q", w)
	}
	for _, v := range decode[[]RecordView](t, rec) {
		if !v.HashOK {
			t.Errorf("record %d: hash_ok false on an intact ledger", v.Seq)
		}
	}

	hs := newHarness(t)
	dropRecord(hs.reader, 3)
	rewrite(hs.reader, 5, false, func(b *model.Body) { b.Data = json.RawMessage(`{"edited":true}`) })
	rewrite(hs.reader, 7, true, func(b *model.Body) { b.Prev = model.ZeroHash })

	rec = hs.get("/api/records")
	wantStatus(t, rec, http.StatusOK)
	warn := rec.Header().Get(WarningHeader)
	for _, want := range []string{"#3", "#5", "#7", "Verify"} {
		if !strings.Contains(warn, want) {
			t.Errorf("warning %q does not mention %s", warn, want)
		}
	}
	for _, v := range decode[[]RecordView](t, rec) {
		if wantOK := v.Seq != 5; v.HashOK != wantOK {
			t.Errorf("record %d: hash_ok = %v, want %v", v.Seq, v.HashOK, wantOK)
		}
	}

	// A type filter does not hide the gap: the scan still sees every record.
	rec = hs.get("/api/records?type=operator_note")
	if w := rec.Header().Get(WarningHeader); !strings.Contains(w, "#3") {
		t.Errorf("filtered page: warning %q does not mention the missing record #3", w)
	}
	// Starting at the missing record.
	rec = hs.get("/api/records?from_seq=3&limit=1")
	if w := rec.Header().Get(WarningHeader); !strings.Contains(w, "#3") {
		t.Errorf("from_seq=3: warning %q does not mention #3", w)
	}
	if got := toString(seqsOf(decode[[]RecordView](t, rec))); got != "4" {
		t.Errorf("from_seq=3 returned %s", got)
	}
	// A page that does not touch the damage stays quiet.
	rec = hs.get("/api/records?limit=2")
	if w := rec.Header().Get(WarningHeader); w != "" {
		t.Errorf("records 0-1: unexpected warning %q", w)
	}

	// A duplicated line (same seq twice) is reported.
	dup := newHarness(t)
	dup.reader.mu.Lock()
	dup.reader.envs = slices.Insert(dup.reader.envs, 3, dup.reader.envs[2])
	dup.reader.bodies = slices.Insert(dup.reader.bodies, 3, dup.reader.bodies[2])
	dup.reader.mu.Unlock()
	rec = dup.get("/api/records")
	if w := rec.Header().Get(WarningHeader); !strings.Contains(w, "#2") {
		t.Errorf("duplicate seq: warning %q", w)
	}
}

// The warning header is bounded however damaged the ledger is.
func TestRecordsIntegrityWarningIsBounded(t *testing.T) {
	hs := newHarness(t)
	hs.reader = newTestLedger(repeatTypes("sample", 400)...)
	hs.srv.reader = hs.reader
	for q := uint64(1); q < 400; q += 2 {
		dropRecord(hs.reader, q)
	}
	rec := hs.get("/api/records?limit=500")
	wantStatus(t, rec, http.StatusOK)
	w := rec.Header().Get(WarningHeader)
	if w == "" || len(w) > 512 {
		t.Fatalf("warning length %d: %q", len(w), w)
	}
	if !strings.Contains(w, "more") {
		t.Errorf("truncated warning should say there are more problems: %q", w)
	}
}

// ----------------------------------------------------------------------------- gateway notification

// When the gateway change itself succeeded ("verified") but recording it failed, the failure
// is on this PC: answering 502 Bad Gateway (and the dashboard's "not changed") would misstate
// what happened to the gateway.
func TestNotificationErrorStatusFollowsRecordedResult(t *testing.T) {
	tests := []struct {
		result   string
		code     int
		contains string
	}{
		{"verified", http.StatusInternalServerError, "changed"},
		{"applied; monitor setting enforce_notification_off changed from true to false", http.StatusInternalServerError, "changed"},
		{"failed: gateway: all web server sessions are in use", http.StatusBadGateway, "disk full"},
		{"", http.StatusBadGateway, "disk full"},
	}
	for _, tc := range tests {
		t.Run(tc.result, func(t *testing.T) {
			hs := newHarness(t)
			hs.srv.actions = fixedChangeActions{fakeActions: &fakeActions{},
				change: model.ConfigChange{Target: "gateway", Before: "on", After: "off", Result: tc.result},
				err:    errors.New("ledger: append config_change: disk full")}
			rec := hs.post("/api/gateway/notification", `{"enabled":false}`)
			wantStatus(t, rec, tc.code)
			ne := decode[NotificationError](t, rec)
			if !strings.Contains(ne.Error, tc.contains) || !strings.Contains(ne.Error, "disk full") {
				t.Errorf("error = %q", ne.Error)
			}
			if tc.result != "" && (ne.Change == nil || ne.Change.Result != tc.result) {
				t.Errorf("change = %+v", ne.Change)
			}
		})
	}
}

// fixedChangeActions answers SetGatewayNotification with a fixed change and error.
type fixedChangeActions struct {
	*fakeActions
	change model.ConfigChange
	err    error
}

func (f fixedChangeActions) SetGatewayNotification(ctx context.Context, enabled bool, actor string) (model.ConfigChange, error) {
	return f.change, f.err
}

// ----------------------------------------------------------------------------- request decoding

// esc returns the JSON escape backslash-u-h. The sequences are assembled at run time so that
// they never appear literally in this file (tools that treat source text as JSON would decode
// them).
func esc(h string) string { return string(rune(0x5c)) + "u" + h }

// note returns a POST /api/notes body whose text is the concatenation of parts.
func noteBody(parts ...string) string { return `{"text":"` + strings.Join(parts, "") + `"}` }

// encoding/json turns an unpaired UTF-16 surrogate escape into U+FFFD without an error, so
// operator text would be recorded differently from what was sent.
func TestNotesRejectUnpairedSurrogateEscapes(t *testing.T) {
	hs := newHarness(t)
	bs := string(rune(0x5c)) // a backslash
	for _, body := range []string{
		noteBody("a", esc("d800"), "b"),
		noteBody(esc("dc00")),
		`{"text":"x","author":"` + esc("d83d") + `"}`,
		noteBody(esc("d800"), esc("0041")),
		noteBody(esc("D800")),
		noteBody("end ", esc("d83d")),
		noteBody(esc("d83d"), bs, bs, "ude00"), // the low half is an escaped backslash + text
	} {
		t.Run(body, func(t *testing.T) {
			before := len(hs.actions.notes)
			msg := wantJSONError(t, hs.post("/api/notes", body), http.StatusBadRequest)
			if !strings.Contains(msg, "surrogate") {
				t.Errorf("message = %q", msg)
			}
			if len(hs.actions.notes) != before {
				t.Error("note with an unpaired surrogate reached Actions.Note")
			}
		})
	}
	smile := string(rune(0x1F600))
	for _, tc := range []struct{ body, want string }{
		{noteBody("smile ", esc("d83d"), esc("de00")), "smile " + smile},
		{noteBody("smile ", esc("D83D"), esc("DE00")), "smile " + smile},
		{noteBody("literal ", bs, bs, "ud800"), "literal " + bs + "ud800"},
		{noteBody("literal ", bs, bs, bs, bs, esc("d83d"), esc("de00")), "literal " + bs + bs + smile},
		{noteBody("sent on purpose ", esc("fffd")), "sent on purpose " + string(rune(0xFFFD))},
		{noteBody("tab", bs, "tand ", esc("00e9")), "tab\tand " + string(rune(0xE9))},
	} {
		t.Run(tc.body, func(t *testing.T) {
			wantStatus(t, hs.post("/api/notes", tc.body), http.StatusCreated)
			if got := hs.actions.notes[len(hs.actions.notes)-1].text; got != tc.want {
				t.Errorf("recorded %q, want %q", got, tc.want)
			}
		})
	}
}

func TestValidJSONEscapes(t *testing.T) {
	bs := string(rune(0x5c))
	obj := func(parts ...string) string { return `{"a":"` + strings.Join(parts, "") + `"}` }
	for _, tc := range []struct {
		in string
		ok bool
	}{
		{`{}`, true},
		{obj("plain"), true},
		{obj(bs, "n", bs, "t", bs, `"`, bs, bs, bs, "/"), true},
		{obj(esc("d83d"), esc("de00")), true},
		{obj(esc("dbff"), esc("dfff")), true},
		{obj(bs, bs, "ud800"), true},                        // escaped backslash, then plain text
		{obj(bs, bs, esc("d83d"), esc("de00")), true},       // escaped backslash, then a valid pair
		{obj(esc("00e9"), esc("fffd")), true},               // BMP escapes, including U+FFFD itself
		{obj(esc("d800")), false},                           // lone high surrogate at the end
		{obj(esc("de00")), false},                           // lone low surrogate
		{obj(esc("d83d"), esc("0041")), false},              // high surrogate + non-surrogate
		{obj(esc("d83d"), esc("d83d"), esc("de00")), false}, // high, high, low
		{obj(esc("d83d"), bs, bs, "ude00"), false},          // high + escaped backslash
		{obj(esc("12")), true},                              // malformed: left to the JSON decoder
	} {
		if got := validJSONEscapes([]byte(tc.in)); got != tc.ok {
			t.Errorf("validJSONEscapes(%s) = %v, want %v", tc.in, got, tc.ok)
		}
	}
}

// ----------------------------------------------------------------------------- misc

func TestRecordViewHashOK(t *testing.T) {
	r := newTestLedger("genesis")
	env, body := r.envs[0], r.bodies[0]
	if v := newRecordView(env, body); !v.HashOK {
		t.Error("intact record: hash_ok false")
	}
	env.H = strings.Repeat("0", 64)
	if v := newRecordView(env, body); v.HashOK {
		t.Error("altered record: hash_ok true")
	}
	env.H = strings.ToUpper(r.envs[0].H) // the format is lowercase hex
	if v := newRecordView(env, body); v.HashOK {
		t.Error("uppercase h accepted")
	}
}

// ----------------------------------------------------------------------------- incidents list

// The dashboard polls the incident list every minute for a handful of rows, and every
// incident carries its evidence list; limit keeps the response small.
func TestIncidentsLimit(t *testing.T) {
	hs := newHarness(t)
	hs.status.incidents = testIncidents()
	for q, want := range map[string]string{
		"limit=1":                           "INC-20261005-030000Z",
		"limit=2":                           "INC-20261005-030000Z,INC-20261004-120000Z",
		"limit=99":                          "INC-20261005-030000Z,INC-20261004-120000Z,INC-20261003-101500Z",
		"limit=1&from=2026-10-01T00:00:00Z": "INC-20261005-030000Z",
	} {
		rec := hs.get("/api/incidents?" + q)
		wantStatus(t, rec, http.StatusOK)
		var ids []string
		for _, inc := range decode[[]model.Incident](t, rec) {
			ids = append(ids, inc.ID)
		}
		if got := strings.Join(ids, ","); got != want {
			t.Errorf("%s: %s, want %s", q, got, want)
		}
	}
	for _, bad := range []string{"limit=0", "limit=-1", "limit=x", "limit=1.5"} {
		wantJSONError(t, hs.get("/api/incidents?"+bad), http.StatusBadRequest)
	}
}

// ----------------------------------------------------------------------------- dashboard script

// Every alarm/warning flag the gateway package derives from the fiberstat DMI table
// (<MEASURE>_<LOW|HIGH>_<ALARM|WARNING> for five measures) must be presented as the AT&T
// gateway's own flag, with a title; the dashboard used to know only three of the measures.
func TestAppJSKnowsEveryGatewayFlag(t *testing.T) {
	js, err := staticFS.ReadFile("static/app.js")
	if err != nil {
		t.Fatal(err)
	}
	src := string(js)
	re := regexp.MustCompile(`const GATEWAY_FLAG_RE = /\^\(([A-Z_|]+)\)_/;`)
	m := re.FindStringSubmatch(src)
	if m == nil {
		t.Fatal("GATEWAY_FLAG_RE not found in app.js")
	}
	inRE := map[string]bool{}
	for _, k := range strings.Split(m[1], "|") {
		inRE[k] = true
	}
	for _, measure := range []string{"OPTICAL_RX", "OPTICAL_TX", "TX_BIAS", "TEMPERATURE", "VCC"} {
		if !inRE[measure] {
			t.Errorf("GATEWAY_FLAG_RE does not cover %s", measure)
		}
		for _, flag := range []string{"LOW_ALARM", "LOW_WARNING", "HIGH_ALARM", "HIGH_WARNING"} {
			if code := measure + "_" + flag; !strings.Contains(src, "    "+code+": '") {
				t.Errorf("COND_TITLES has no title for %s", code)
			}
		}
	}
}

// offByOneReader returns the record after the one asked for, a reader bug that must not make
// the incident view present the wrong record as the referenced evidence.
type offByOneReader struct{ *fakeReader }

func (o offByOneReader) Record(seq uint64) (model.Envelope, model.Body, error) {
	return o.fakeReader.Record(seq + 1)
}

func TestIncidentDetailRejectsWrongRecordFromReader(t *testing.T) {
	hs := newHarness(t)
	// Isolated seqs (further apart than one scan reads through) are read with Record.
	hs.reader = newTestLedger(repeatTypes("sample", 3*evidenceClusterGap)...)
	hs.srv.reader = offByOneReader{hs.reader}
	inc := model.Incident{ID: "INC-20261005-030000Z", Opened: "2026-10-05T03:00:00Z", State: model.StateISPOutage, Rules: "2026.10-1",
		FirstSeq: 10, LastSeq: 10 + 2*evidenceClusterGap}
	hs.status.incidents = []model.Incident{inc}
	d := decode[IncidentDetail](t, hs.get("/api/incidents/"+inc.ID))
	if len(d.Records) != 0 || !slices.Equal(d.Missing, []uint64{inc.FirstSeq, inc.LastSeq}) {
		t.Errorf("records %v missing %v: a record with another seq was accepted", seqsOf(d.Records), d.Missing)
	}
}

// Paging with X-Next-Seq must reach the end of the ledger even when a damaged line carries a
// bogus seq far beyond the head, and every real record must be listed exactly once.
func TestRecordsPagingSurvivesBogusSeq(t *testing.T) {
	hs := newHarness(t)
	hs.reader = newTestLedger(repeatTypes("sample", 12)...)
	hs.srv.reader = hs.reader
	bogus := hs.reader.bodies[5]
	bogus.Seq = 1_000_000_000
	hs.reader.mu.Lock()
	hs.reader.envs = slices.Insert(hs.reader.envs, 6, sealRecord(testKey, bogus))
	hs.reader.bodies = slices.Insert(hs.reader.bodies, 6, bogus)
	hs.reader.mu.Unlock()

	seen := map[uint64]int{}
	from, pages := "0", 0
	warned := false
	for ; from != "" && pages < 50; pages++ {
		rec := hs.get("/api/records?limit=3&from_seq=" + from)
		wantStatus(t, rec, http.StatusOK)
		for _, v := range decode[[]RecordView](t, rec) {
			seen[v.Seq]++
		}
		warned = warned || strings.Contains(rec.Header().Get(WarningHeader), "out of order")
		from = rec.Header().Get("X-Next-Seq")
	}
	if from != "" {
		t.Fatalf("paging did not reach the end after %d pages", pages)
	}
	for q := uint64(0); q < 12; q++ {
		if seen[q] != 1 {
			t.Errorf("record #%d listed %d times", q, seen[q])
		}
	}
	if !warned {
		t.Error("the out-of-order line was never reported")
	}
}

func TestIntegrityCheckReports(t *testing.T) {
	type rec struct {
		seq    uint64
		hashOK bool
		badPrv bool // prev does not match the h of the record before
	}
	ok := func(seqs ...uint64) []rec {
		out := make([]rec, len(seqs))
		for i, q := range seqs {
			out[i] = rec{seq: q, hashOK: true}
		}
		return out
	}
	tests := []struct {
		name string
		from uint64
		recs []rec
		want []string
	}{
		{"clean", 0, ok(0, 1, 2, 3), nil},
		{"clean from the middle", 5, ok(5, 6, 7), nil},
		{"one missing", 0, ok(0, 1, 3, 4), []string{"#2 missing or unreadable"}},
		{"range missing", 0, ok(0, 4, 5), []string{"#1-#3 missing or unreadable"}},
		{"first wanted missing", 3, ok(4, 5), []string{"#3 missing or unreadable"}},
		{"jump at the end is a gap", 0, ok(0, 1, 5), []string{"#2-#4 missing or unreadable"}},
		{"line out of place ahead", 5, ok(5, 9, 6, 7, 8, 10, 11), []string{"#9 out of order"}},
		{"bogus huge seq", 0, ok(0, 1, 1_000_000_000, 2, 3), []string{"#1000000000 out of order"}},
		{"repeated line", 0, ok(0, 1, 2, 2, 3), []string{"#2 repeated or out of order"}},
		{"line moved back", 0, ok(0, 1, 3, 4, 2, 5), []string{"#2 missing or unreadable", "#2 repeated or out of order"}},
		{"altered line", 0, []rec{{0, true, false}, {1, false, false}, {2, true, false}}, []string{"#1 h does not match b"}},
		{"broken link", 0, []rec{{0, true, false}, {1, true, true}}, []string{"#1 prev does not match h of #0"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := integrityCheck{next: tc.from}
			prevHash := ""
			for _, r := range tc.recs {
				h := fmt.Sprintf("h%d", r.seq)
				prev := prevHash
				if r.badPrv {
					prev = "other"
				}
				c.add(r.seq, h, r.hashOK, prev)
				prevHash = h
			}
			w := c.warning()
			if len(tc.want) == 0 {
				if w != "" {
					t.Fatalf("warning %q on intact records", w)
				}
				return
			}
			want := "ledger integrity: " + strings.Join(tc.want, "; ") + " (run Verify for a full check)"
			if w != want {
				t.Errorf("warning\n got %q\nwant %q", w, want)
			}
		})
	}
}
