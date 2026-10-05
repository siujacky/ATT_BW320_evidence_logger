package export

// Integration round: proof of time (Options.TokenVerifier or the anchor records' issue-time
// flags), Options.ExtraFiles (keys/tsa-roots.pem) and the OpenSSL check of tools/verify_bundle.py.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/digitorus/timestamp"

	"attmonitor/internal/contracts"
	"attmonitor/internal/model"
)

// fakeTokenVerifier checks the token's imprint like a real verifier and reports a configurable
// chain result.
type fakeTokenVerifier struct {
	mu      sync.Mutex
	chainOK bool
	note    string
	tsaName string
	err     error
	panics  bool
	calls   int
}

func (v *fakeTokenVerifier) VerifyToken(token, digest []byte) (contracts.TokenInfo, error) {
	v.mu.Lock()
	v.calls++
	v.mu.Unlock()
	if v.panics {
		panic("verifier exploded")
	}
	if v.err != nil {
		return contracts.TokenInfo{}, v.err
	}
	ts, err := timestamp.ParseResponse(token)
	if err != nil {
		return contracts.TokenInfo{}, err
	}
	if !bytes.Equal(ts.HashedMessage, digest) {
		return contracts.TokenInfo{}, errors.New("message imprint mismatch")
	}
	info := contracts.TokenInfo{GenTime: ts.Time, TSAName: v.tsaName, ChainOK: v.chainOK}
	if !v.chainOK {
		info.ChainNote = v.note
	}
	return info, nil
}

var _ contracts.TokenVerifier = (*fakeTokenVerifier)(nil)

func anchorsInPeriodHTML(html string) string {
	i := strings.Index(html, "Independent time-stamps (RFC 3161)")
	j := strings.Index(html, "How to verify this bundle independently")
	if i < 0 || j < i {
		return ""
	}
	return html[i:j]
}

// ---------------------------------------------------------------- proof of time

func TestProofOfTimeWithTokenVerifier(t *testing.T) {
	const note = "system roots: x509: certificate signed by unknown authority <b>"
	tests := []struct {
		name      string
		v         *fakeTokenVerifier
		proof     bool
		bundleOK  bool
		wantNote  string // in every anchor's proof_note
		wantInRep string // in REPORT.html
	}{
		{"chain trusted", &fakeTokenVerifier{chainOK: true, tsaName: "CN=Test TSA from token"}, true, true, "", "TSA certificate chain checked at export"},
		{"chain not trusted", &fakeTokenVerifier{chainOK: false, note: note}, false, true, "does not chain to a trusted root (" + note + ")",
			"does not chain to a trusted root (system roots: x509: certificate signed by unknown authority &lt;b&gt;)"},
		{"token rejected", &fakeTokenVerifier{err: errors.New("two signers")}, false, false, "its time-stamp token is not valid: rejected by the token verifier: two signers",
			"rejected by the token verifier: two signers"},
		{"verifier panics", &fakeTokenVerifier{panics: true}, false, false, "verifier exploded", "token verifier failed"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := buildScenario(t) // anchor records say verified=true, chain_ok=true at issue
			e, _ := newTestExporter(t, s, t.TempDir(), func(o *Options) { o.TokenVerifier = tc.v })
			info, err := e.Build(context.Background(), contracts.ExportRequest{IncidentID: s.incidentID})
			if err != nil {
				t.Fatal(err)
			}
			z := readZip(t, info.Path)
			r := readReportJSON(t, z)
			if tc.v.calls != 3 {
				t.Errorf("verifier called %d times, want once per anchor (3)", tc.v.calls)
			}
			b := r.Verification.Bundle
			if !b.TokenVerifier || b.OK != tc.bundleOK || b.AnchorsChecked != 3 {
				t.Errorf("bundle check = %+v", b)
			}
			for _, an := range r.Anchors {
				if an.ProofOfTime != tc.proof || !an.VerifierChecked {
					t.Errorf("anchor %d: proof=%v checked=%v note=%q", an.Seq, an.ProofOfTime, an.VerifierChecked, an.ProofNote)
				}
				if tc.proof && (an.ProofBasis != "token_verifier" || an.ChainTrusted == nil || !*an.ChainTrusted || an.TokenTSAName != tc.v.tsaName) {
					t.Errorf("anchor %d: %+v", an.Seq, an)
				}
				if !tc.proof && !strings.Contains(an.ProofNote, tc.wantNote) {
					t.Errorf("anchor %d proof note %q, want %q", an.Seq, an.ProofNote, tc.wantNote)
				}
			}
			if tc.proof {
				if b.AnchorsProofOfTime != 3 || r.Summary.LastRecordAnchor == nil || r.Summary.LastRecordAnchor.ProofBasis != "token_verifier" ||
					r.Summary.LastRecordAnchor.TSA != tc.v.tsaName || r.Incidents[0].Anchor == nil {
					t.Errorf("proof-of-time coverage: %+v / %+v", r.Summary.LastRecordAnchor, r.Incidents[0].Anchor)
				}
			} else {
				// The records claim chain_ok at issue, but the verifier at export decides.
				if b.AnchorsProofOfTime != 0 || r.Summary.LastRecordAnchor != nil || r.Incidents[0].Anchor != nil {
					t.Errorf("an anchor that is not proof of time was used: %+v / %+v", r.Summary.LastRecordAnchor, r.Incidents[0].Anchor)
				}
				if !strings.Contains(string(z.files["README.txt"]), "No time-stamp in this bundle that is accepted as proof of time") {
					t.Error("README.txt does not say that no time-stamp is proof of time")
				}
			}
			if !tc.bundleOK && !hasProblem(r, "anchor_invalid") {
				t.Errorf("a rejected token must be an integrity failure: %+v", b.Failures)
			}
			html := string(z.files["REPORT.html"])
			if !strings.Contains(anchorsInPeriodHTML(html), tc.wantInRep) {
				t.Errorf("REPORT.html time-stamp section lacks %q", tc.wantInRep)
			}
		})
	}
}

// Without a token verifier the anchor records' issue-time flags decide, and the report says so.
func TestProofOfTimeIssueTimeFlags(t *testing.T) {
	d := func(m int) time.Time { return time.Date(2026, 10, 3, 12, m, 0, 0, time.UTC) }
	f := rvLedger(t, d(0))
	rvSamples(f, d(1), 3, 10*time.Second, model.StateOnline, "", model.AttrNone, "")
	covered := f.head
	// An anchor whose TSA certificate did not chain when it was obtained ...
	digest, _ := hex.DecodeString(f.head.Hash)
	tok := f.putBlob(f.tsa.stamp(t, digest, d(2)))
	noChain := f.append(d(2), model.TypeAnchor, model.Anchor{TSAURL: "https://freetsa.org/tsr", TSAName: "CN=www.freetsa.org",
		HeadSeq: f.head.Seq, HeadHash: f.head.Hash, TokenSHA256: tok, GenTime: d(2).Format(time.RFC3339), Verified: true,
		ChainOK: false, ChainNote: "system roots: certificate signed by unknown authority", Reason: "periodic"}, tok)
	rvSamples(f, d(3), 3, 10*time.Second, model.StateOnline, "", model.AttrNone, "")
	// ... and a later one whose chain was trusted.
	good, _ := rvAnchor(t, f, d(4), nil, "", true)
	lastTS, _ := parseTS(covered.TS)
	_, z, r := rvExport(t, f, d(30), contracts.ExportRequest{From: d(0), To: lastTS.Add(time.Millisecond)})

	a := findAnchor(r, noChain.Seq)
	// The record's chain note is reported with the anchor (chain_note_at_issue), not repeated in the proof note.
	if a == nil || a.ProofOfTime || a.ProofBasis != "issue_time_flags" || a.VerifierChecked || a.TokenCheck != "ok" ||
		!strings.Contains(a.ProofNote, "verified=true, chain_ok=false") ||
		a.ChainNoteRec != "system roots: certificate signed by unknown authority" {
		t.Errorf("anchor without chain at issue = %+v", a)
	}
	if g := findAnchor(r, good.Seq); g == nil || !g.ProofOfTime || g.ProofBasis != "issue_time_flags" {
		t.Errorf("anchor with chain at issue = %+v", g)
	}
	cov := r.Summary.LastRecordAnchor
	if cov == nil || cov.Seq != good.Seq || cov.ProofBasis != "issue_time_flags" {
		t.Errorf("coverage = %+v, want the later anchor %d whose chain was trusted", cov, good.Seq)
	}
	b := r.Verification.Bundle
	if !b.OK || b.TokenVerifier || b.AnchorsProofOfTime != 1 || b.AnchorsNotProof != 1 {
		t.Errorf("bundle check = %+v", b)
	}
	notes := strings.Join(b.Notes, "\n")
	if !strings.Contains(notes, "No token verifier checked the TSA certificate chains at export") ||
		!strings.Contains(notes, "issue-time flags") {
		t.Errorf("notes do not say what decided proof of time: %s", notes)
	}
	html := string(z.files["REPORT.html"])
	for _, want := range []string{"per the record's issue-time flags", "no token verifier was available at export",
		"verified=true, chain_ok=false", "chain note at issue: system roots: certificate signed by unknown authority"} {
		if !strings.Contains(html, want) {
			t.Errorf("REPORT.html lacks %q", want)
		}
	}
	if !strings.Contains(string(z.files["README.txt"]), "its record states it verified and chained when obtained") {
		t.Error("README.txt does not state the basis of the time-stamp")
	}
}

// The full-ledger verification summary counts only anchors that are proof of time and says
// whether the tokens were checked cryptographically.
func TestFullVerificationProofOfTime(t *testing.T) {
	s := buildScenario(t)
	rep := okVerifyReport(s)
	rep.Anchors = []model.AnchorCheck{{Seq: 3, OK: true, ChainOK: true}, {Seq: 86, OK: true, ChainOK: false}, {Seq: 113, OK: false}}
	rep.TokensChecked = false
	e, _ := newTestExporter(t, s, t.TempDir(), func(o *Options) { o.Verifier = &fakeVerifier{rep: rep} })
	info, err := e.Build(context.Background(), contracts.ExportRequest{IncidentID: s.incidentID})
	if err != nil {
		t.Fatal(err)
	}
	z := readZip(t, info.Path)
	f := readReportJSON(t, z).Verification.Full
	if f == nil || f.Anchors != 3 || f.AnchorsOK != 2 || f.AnchorsProofOfTime != 1 || f.TokensChecked {
		t.Errorf("full verification = %+v", f)
	}
	if html := string(z.files["REPORT.html"]); !strings.Contains(html, "1 of 3 time-stamps accepted as proof of time (tokens not cryptographically re-checked") {
		t.Error("REPORT.html does not report the full verification's proof-of-time count")
	}
}

// ---------------------------------------------------------------- extra files

func TestExtraFilesWrittenAndListed(t *testing.T) {
	s := buildScenario(t)
	roots, err := os.ReadFile(filepath.Join("..", "..", "testdata", "export", "tsa-roots.pem"))
	if err != nil {
		t.Fatal(err)
	}
	extra := map[string][]byte{tsaRootsPath: roots, "docs/notes-for-att.txt": []byte("plain\r\nnotes")}
	e, _ := newTestExporter(t, s, t.TempDir(), func(o *Options) { o.ExtraFiles = extra })
	// The exporter keeps its own copy: later changes by the caller do not reach the bundle.
	extra["docs/notes-for-att.txt"][0] = 'X'
	extra["late.txt"] = []byte("added after New")
	info, err := e.Build(context.Background(), contracts.ExportRequest{IncidentID: s.incidentID})
	if err != nil {
		t.Fatal(err)
	}
	z := readZip(t, info.Path)
	if !bytes.Equal(z.files[tsaRootsPath], roots) || string(z.files["docs/notes-for-att.txt"]) != "plain\r\nnotes" {
		t.Error("extra files are not stored verbatim")
	}
	if _, ok := z.files["late.txt"]; ok {
		t.Error("a file added to the caller's map after New was exported")
	}
	if z.names[len(z.names)-1] != manifestName {
		t.Errorf("last entry = %s", z.names[len(z.names)-1])
	}
	manifest := string(z.files[manifestName])
	for _, n := range []string{tsaRootsPath, "docs/notes-for-att.txt"} {
		if !strings.Contains(manifest, sha256Hex(z.files[n])+"  "+n+"\n") {
			t.Errorf("MANIFEST.sha256 does not list %s", n)
		}
	}
	if err := VerifyManifest(info.Path); err != nil {
		t.Errorf("VerifyManifest: %v", err)
	}
	b, err := OpenBundle(info.Path)
	if err != nil {
		t.Fatalf("OpenBundle: %v", err)
	}
	b.Close()

	r := readReportJSON(t, z)
	if len(r.Bundle.ExtraFiles) != 2 || r.Bundle.ExtraFiles[0].Path != "docs/notes-for-att.txt" || r.Bundle.ExtraFiles[1].Path != tsaRootsPath ||
		r.Bundle.ExtraFiles[1].SHA256 != sha256Hex(roots) || r.Bundle.ExtraFiles[1].Bytes != len(roots) {
		t.Errorf("extra files = %+v", r.Bundle.ExtraFiles)
	}
	// The two default TSA roots, with the fingerprints the TSAs publish.
	want := map[string]string{
		"552f7bdcf1a7af9e6ce672017f4f12abf77240c78e761ac203d1d9d20ac89988": "CN=DigiCert Trusted Root G4",
		"a6379e7cecc05faa3cbf076013d745e327bbbaa38c0b9af22469d4701d18aabc": "CN=www.freetsa.org",
	}
	if len(r.Bundle.TSARoots) != 2 || r.Bundle.TSARootsNote != "" {
		t.Fatalf("tsa roots = %+v (%s)", r.Bundle.TSARoots, r.Bundle.TSARootsNote)
	}
	for _, rc := range r.Bundle.TSARoots {
		if cn, ok := want[rc.SHA256]; !ok || !strings.HasPrefix(rc.Subject, cn) {
			t.Errorf("root %+v", rc)
		}
	}
	readme := string(z.files["README.txt"])
	html := string(z.files["REPORT.html"])
	for _, want := range []string{"keys/tsa-roots.pem", "55:2F:7B:DC:F1:A7:AF:9E:6C:E6:72:01:7F:4F:12:AB:F7:72:40:C7:8E:76:1A:C2:03:D1:D9:D2:0A:C8:99:88",
		"A6:37:9E:7C:EC:C0:5F:AA:3C:BF:07:60:13:D7:45:E3:27:BB:BA:A3:8C:0B:9A:F2:24:69:D4:70:1D:18:AA:BC", "CN=DigiCert Trusted Root G4"} {
		if !strings.Contains(readme, want) {
			t.Errorf("README.txt lacks %q", want)
		}
		if !strings.Contains(html, want) {
			t.Errorf("REPORT.html lacks %q", want)
		}
	}
	if strings.Contains(readme, "This bundle contains no keys/tsa-roots.pem") || strings.Contains(html, "This bundle contains no keys/tsa-roots.pem") {
		t.Error("the bundle claims it has no roots file")
	}
	// The exact OpenSSL command for every example anchor: -attime = the token's genTime in
	// Unix seconds, -CAfile keys/tsa-roots.pem.
	examples := anchorExamples(r.Anchors)
	if len(examples) != 2 {
		t.Fatalf("examples = %+v", examples)
	}
	for _, an := range examples {
		gt, ok := parseTS(an.TokenGenTime)
		if !ok {
			t.Fatalf("token genTime %q", an.TokenGenTime)
		}
		cmd := fmt.Sprintf("openssl ts -verify -attime %d -digest %s -in blobs/%s -CAfile keys/tsa-roots.pem", gt.Unix(), an.HeadHash, an.Token)
		if !strings.Contains(readme, cmd) {
			t.Errorf("README.txt lacks %q", cmd)
		}
		if !strings.Contains(html, cmd) {
			t.Errorf("REPORT.html lacks %q", cmd)
		}
	}
	if !strings.Contains(readme, "-attime <genTime> -digest <head_hash> -in blobs/<token_sha256> -CAfile keys/tsa-roots.pem") {
		t.Error("README.txt lacks the general openssl command")
	}
	if !strings.Contains(html, "openssl ts -verify -attime GENTIME -digest HEAD_HASH -in blobs/TOKEN -CAfile keys/tsa-roots.pem") {
		t.Error("REPORT.html lacks the general openssl command")
	}
}

// Without keys/tsa-roots.pem the instructions say where the roots come from.
func TestNoRootsFileInstructions(t *testing.T) {
	s, info := buildIncidentBundle(t)
	_ = s
	z := readZip(t, info.Path)
	if !strings.Contains(string(z.files["README.txt"]), "This bundle contains no keys/tsa-roots.pem") ||
		!strings.Contains(string(z.files["REPORT.html"]), "This bundle contains no keys/tsa-roots.pem") {
		t.Error("the instructions do not say that the roots file is missing")
	}
	if !strings.Contains(string(z.files["README.txt"]), "-attime ") {
		t.Error("README.txt openssl command lacks -attime")
	}
}

func TestExtraFilesRejected(t *testing.T) {
	s := buildScenario(t)
	bad := []string{
		"", "/abs.pem", "../up.pem", "keys/../up.pem", "a//b.pem", "./a.pem", "keys/./a.pem", `keys\a.pem`, "C:/x.pem", "c:x.pem",
		"keys/", "a b.pem", "a\x00.pem", "a\n.pem", "trailing.", "keys/con.pem", "NUL", "lpt1.txt", ".hidden",
		"README.txt", "readme.TXT", "Report.HTML", "MANIFEST.sha256", "manifest.SHA256", "keys/public-key.txt", "KEYS/Public-Key.txt",
		"tools/verify_bundle.py", "ledger/ledger-2026-10-09.jsonl", "ledger", "Blobs/" + strings.Repeat("a", 64), "blobs/x",
		"keys", "tools", "report.json/x", strings.Repeat("a", 201),
	}
	for _, name := range bad {
		t.Run(fmt.Sprintf("%q", name), func(t *testing.T) {
			dir := t.TempDir()
			e, act := newTestExporter(t, s, dir, func(o *Options) { o.ExtraFiles = map[string][]byte{name: []byte("x")} })
			_, err := e.Build(context.Background(), contracts.ExportRequest{IncidentID: s.incidentID})
			if !errors.Is(err, ErrInvalidExtraFile) {
				t.Fatalf("err = %v, want ErrInvalidExtraFile", err)
			}
			if ents, _ := os.ReadDir(dir); len(ents) != 0 || len(act.exports) != 0 {
				t.Errorf("files %v / custody %d left behind", ents, len(act.exports))
			}
		})
	}
	// Two extra files whose names differ only in case, or that are a file and a directory.
	for _, pair := range [][2]string{{"keys/TSA-roots.pem", "keys/tsa-roots.pem"}, {"docs", "docs/a.txt"}} {
		e, _ := newTestExporter(t, s, t.TempDir(), func(o *Options) {
			o.ExtraFiles = map[string][]byte{pair[0]: []byte("1"), pair[1]: []byte("2")}
		})
		if _, err := e.Build(context.Background(), contracts.ExportRequest{IncidentID: s.incidentID}); !errors.Is(err, ErrInvalidExtraFile) {
			t.Errorf("%v: err = %v", pair, err)
		}
	}
	// Accepted: plain relative paths.
	for _, ok := range []string{"keys/tsa-roots.pem", "notes.txt", "docs/2026/ticket-12345_v2.pdf", "comx.txt"} {
		if err := checkExtraPath(ok); err != nil {
			t.Errorf("checkExtraPath(%q) = %v", ok, err)
		}
	}
}

func TestBuildDeterministicWithExtraFiles(t *testing.T) {
	s := buildScenario(t)
	extra := map[string][]byte{tsaRootsPath: s.f.tsa.rootPEM(), "b.txt": []byte("b"), "a.txt": []byte("a")}
	var sums []string
	for i := 0; i < 2; i++ {
		e, _ := newTestExporter(t, s, t.TempDir(), func(o *Options) { o.ExtraFiles = extra })
		info, err := e.Build(context.Background(), contracts.ExportRequest{IncidentID: s.incidentID})
		if err != nil {
			t.Fatal(err)
		}
		sums = append(sums, info.SHA256)
	}
	if sums[0] != sums[1] {
		t.Error("bundles with extra files are not reproducible")
	}
}

func TestParseRootCertsNotes(t *testing.T) {
	if roots, note := parseRootCerts([]byte("no pem here")); len(roots) != 0 || !strings.Contains(note, "contains no certificate") {
		t.Errorf("garbage: %v %q", roots, note)
	}
	key := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1, 2, 3}})
	broken := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{1, 2, 3}})
	tsa := newTestTSA(t)
	roots, note := parseRootCerts(append(append(append([]byte{}, key...), broken...), tsa.rootPEM()...))
	if len(roots) != 1 || roots[0].Subject != "CN=att-monitor test TSA" || roots[0].SHA256 != sha256Hex(tsa.cert.Raw) ||
		!strings.Contains(note, `PEM block 1 is a "PRIVATE KEY" block`) || !strings.Contains(note, "PEM block 2 is not a readable certificate") {
		t.Errorf("roots %+v, note %q", roots, note)
	}
}

// ---------------------------------------------------------------- Python verifier + OpenSSL

// findOpenSSL returns the openssl on PATH if it is OpenSSL 1.1.1 or newer (what
// tools/verify_bundle.py requires), or skips the test.
func findOpenSSL(t *testing.T) string {
	t.Helper()
	p, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl is not on PATH")
	}
	out, err := exec.Command(p, "version").Output()
	m := regexp.MustCompile(`^OpenSSL (\d+)\.(\d+)\.(\d+)`).FindStringSubmatch(string(out))
	if err != nil || m == nil {
		t.Skipf("openssl is not OpenSSL: %q %v", out, err)
	}
	v := [3]int{}
	for i := range v {
		v[i], _ = strconv.Atoi(m[i+1])
	}
	if v[0] < 1 || v[0] == 1 && (v[1] < 1 || v[1] == 1 && v[2] < 1) {
		t.Skipf("%s is older than 1.1.1", strings.TrimSpace(string(out)))
	}
	return p
}

func TestPythonVerifierOpenSSL(t *testing.T) {
	py := findPython(t)
	findOpenSSL(t)
	s := buildScenario(t)
	e, _ := newTestExporter(t, s, t.TempDir(), func(o *Options) { o.ExtraFiles = map[string][]byte{tsaRootsPath: s.f.tsa.rootPEM()} })
	info, err := e.Build(context.Background(), contracts.ExportRequest{IncidentID: s.incidentID})
	if err != nil {
		t.Fatal(err)
	}
	script := shippedScript(t, info.Path)
	r := readReportJSON(t, readZip(t, info.Path))
	okLine := regexp.MustCompile(`openssl ts -verify: OK  anchor seq (\d+) \(signed by CN=att-monitor test TSA\), genTime (\S+) \(-attime (\d+)\)`)
	// The test TSA's root is not one of the TSA roots the script knows: a recipient who checked
	// its fingerprint names it with --trust-root.
	trust := []string{"--trust-root", sha256Hex(s.f.tsa.cert.Raw)}

	t.Run("root not trusted without --trust-root", func(t *testing.T) {
		out, code := runPython(t, py, script, info.Path)
		if code != 0 || !strings.Contains(out, "RESULT: PASS (with warnings)") || okLine.MatchString(out) ||
			strings.Count(out, "verifies only against a certificate in keys/tsa-roots.pem that is not a TSA root known") != 3 ||
			!strings.Contains(out, "3 chain only to an untrusted root (not proof of time)") || !strings.Contains(out, "NOT verified as proof of time") ||
			strings.Contains(out, "existed no later than") {
			t.Errorf("exit %d: tokens chaining only to an untrusted root must not be proof of time:\n%s", code, out)
		}
		if !strings.Contains(out, "not one of the TSA roots known to this verifier") || !strings.Contains(out, colonHex(sha256Hex(s.f.tsa.cert.Raw))) {
			t.Errorf("unknown root not flagged:\n%s", out)
		}
	})

	t.Run("every token verified at its genTime", func(t *testing.T) {
		out, code := runPython(t, py, append(append([]string{script}, trust...), info.Path)...)
		if code != 0 || !strings.Contains(out, "RESULT: PASS") {
			t.Fatalf("exit %d:\n%s", code, out)
		}
		lines := okLine.FindAllStringSubmatch(out, -1)
		if len(lines) != 3 || !strings.Contains(out, "openssl verified 3 of 3") {
			t.Fatalf("want 3 verified tokens:\n%s", out)
		}
		for _, l := range lines {
			seq, _ := strconv.ParseUint(l[1], 10, 64)
			a := findAnchor(r, seq)
			gt, ok := parseTS(l[2])
			if a == nil || !ok || l[3] != strconv.FormatInt(gt.Unix(), 10) || !gt.Equal(mustTS(t, a.TokenGenTime)) {
				t.Errorf("line %q: anchor %+v", l[0], a)
			}
		}
		if !strings.Contains(out, "Latest anchor     records up to seq") || !strings.Contains(out, "(signed by CN=att-monitor test TSA; TSA signature and certificate chain verified by openssl against a trusted TSA root)") {
			t.Errorf("latest anchor not reported as proof of time:\n%s", out)
		}
		if !strings.Contains(out, "(trusted with --trust-root)") {
			t.Errorf("the root named with --trust-root is not shown as trusted:\n%s", out)
		}
	})

	t.Run("limit verifies the latest token of each TSA first", func(t *testing.T) {
		out, code := runPython(t, py, append(append([]string{script}, trust...), "--openssl-limit", "2", info.Path)...)
		lines := okLine.FindAllStringSubmatch(out, -1)
		if code != 0 || len(lines) != 2 || !strings.Contains(out, "1 of 3 time-stamp tokens were NOT verified with openssl because of --openssl-limit 2") {
			t.Fatalf("exit %d:\n%s", code, out)
		}
		latest := map[string]uint64{}
		for _, a := range r.Anchors {
			latest[a.TSAURL] = a.Seq
		}
		for _, l := range lines {
			seq, _ := strconv.ParseUint(l[1], 10, 64)
			if a := findAnchor(r, seq); a == nil || latest[a.TSAURL] != seq {
				t.Errorf("verified anchor %d is not the latest of its TSA", seq)
			}
		}
	})

	t.Run("roots of another TSA", func(t *testing.T) {
		other := newTestTSA(t)
		path := rewriteZip(t, info.Path, zipEdit{fixManifest: true, edit: func(n string, d []byte) ([]byte, bool) {
			if n == tsaRootsPath {
				return other.rootPEM(), true
			}
			return d, true
		}})
		out, code := runPython(t, py, script, path)
		if code != 1 || !strings.Contains(out, "RESULT: FAIL") || strings.Count(out, "this anchor is not proof of time") != 3 ||
			strings.Contains(out, "openssl ts -verify: OK") || !strings.Contains(out, "NOT verified as proof of time") {
			t.Errorf("exit %d, want 1 with 3 failed tokens:\n%s", code, out)
		}
	})

	t.Run("roots file without certificates", func(t *testing.T) {
		path := rewriteZip(t, info.Path, zipEdit{fixManifest: true, edit: func(n string, d []byte) ([]byte, bool) {
			if n == tsaRootsPath {
				return []byte("not a certificate\n"), true
			}
			return d, true
		}})
		if out, code := runPython(t, py, script, path); code != 1 || !strings.Contains(out, "contains no PEM certificate") ||
			!strings.Contains(out, "keys/tsa-roots.pem cannot be used (see the failures)") {
			t.Errorf("exit %d:\n%s", code, out)
		}
	})

	t.Run("no roots file", func(t *testing.T) {
		_, plain := buildIncidentBundle(t)
		out, code := runPython(t, py, script, plain.Path)
		if code != 0 || !strings.Contains(out, "keys/tsa-roots.pem is not in this bundle: the TSA signatures and certificate chains") ||
			!strings.Contains(out, "RESULT: PASS (with warnings)") || !strings.Contains(out, "imprint only; signatures and chains NOT verified") {
			t.Errorf("exit %d:\n%s", code, out)
		}
	})

	t.Run("openssl disabled", func(t *testing.T) {
		out, code := runPython(t, py, script, "--openssl-limit", "0", info.Path)
		if code != 0 || !strings.Contains(out, "openssl verification disabled") || strings.Contains(out, "openssl ts -verify: OK") {
			t.Errorf("exit %d:\n%s", code, out)
		}
	})
}

func mustTS(t *testing.T, s string) time.Time {
	t.Helper()
	ts, ok := parseTS(s)
	if !ok {
		t.Fatalf("bad time %q", s)
	}
	return ts
}

// The verifier checks a token at its own genTime: a TSA certificate that has expired since is
// still accepted, as it was valid when the time-stamp was made.
func TestPythonVerifierUsesAttime(t *testing.T) {
	py := findPython(t)
	openssl := findOpenSSL(t)
	d := func(m int) time.Time { return time.Date(2026, 10, 3, 12, m, 0, 0, time.UTC) }
	f := rvLedger(t, d(0))
	f.tsa = newTestTSAValid(t, "short-lived test TSA", d(0).Add(-time.Hour), d(0).Add(2*time.Hour))
	rvSamples(f, d(1), 3, 10*time.Second, model.StateOnline, "", model.AttrNone, "")
	_, tok := rvAnchor(t, f, d(2), nil, "", true)
	info, z, _ := rvExport(t, f, d(30), contracts.ExportRequest{From: d(0), To: d(10)},
		func(o *Options) { o.ExtraFiles = map[string][]byte{tsaRootsPath: f.tsa.rootPEM()} })
	script := shippedScript(t, info.Path)
	out, code := runPython(t, py, script, "--trust-root", sha256Hex(f.tsa.cert.Raw), info.Path)
	if code != 0 || !strings.Contains(out, fmt.Sprintf("(-attime %d)", d(2).Unix())) {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	if !time.Now().After(d(0).Add(2 * time.Hour)) {
		return // the computer's clock is before the certificate's expiry: nothing more to show
	}
	// Without -attime, OpenSSL checks the certificate now - and it has expired.
	dir := t.TempDir()
	tokFile, rootsFile := filepath.Join(dir, "t.tsr"), filepath.Join(dir, "r.pem")
	os.WriteFile(tokFile, z.files["blobs/"+tok], 0o644)
	os.WriteFile(rootsFile, f.tsa.rootPEM(), 0o644)
	head := findAnchorHead(t, z, tok)
	if err := exec.Command(openssl, "ts", "-verify", "-digest", head, "-in", tokFile, "-CAfile", rootsFile).Run(); err == nil {
		t.Error("without -attime the expired certificate was accepted; the test does not show what -attime changes")
	}
}

// findAnchorHead returns the head_hash of the anchor whose token is tok.
func findAnchorHead(t *testing.T, z zipContent, tok string) string {
	t.Helper()
	r := readReportJSON(t, z)
	for _, a := range r.Anchors {
		if a.Token == tok {
			return a.HeadHash
		}
	}
	t.Fatal("anchor not found")
	return ""
}

// The script's own OpenSSL check accepts the real DigiCert and FreeTSA tokens of testdata/tsa
// with the roots shipped by att-monitor, and recognises both roots by their fingerprints.
func TestPythonVerifierRealTokens(t *testing.T) {
	py := findPython(t)
	findOpenSSL(t)
	dir := t.TempDir()
	script := filepath.Join(dir, "verify_bundle.py")
	if err := os.WriteFile(script, verifyScript, 0o644); err != nil {
		t.Fatal(err)
	}
	roots, _ := filepath.Abs(filepath.Join("..", "..", "testdata", "export", "tsa-roots.pem"))
	tsaDir, _ := filepath.Abs(filepath.Join("..", "..", "testdata", "tsa"))
	const digest = "0bb4c71bfeddf27eb9647853d1e5aa8f981f222fe4ffac0c7d1d8db73f1d443b"
	code := fmt.Sprintf(`
import sys, shutil
sys.path.insert(0, %q)
import verify_bundle as v
openssl = shutil.which("openssl")
data = open(%q, "rb").read()
for der in v.pem_certificates(data):
    fp = v.sha256_hex(der)
    print("ROOT", fp, v.KNOWN_ROOTS.get(fp, "UNKNOWN"), "|", v.cert_subject(der))
for name in ("digicert.tsr", "freetsa.tsr"):
    path = %q + "/" + name
    info = v.parse_token(open(path, "rb").read())
    t = v.gen_time_unix(info["gen_time"])
    ok, why = v.openssl_verify(openssl, path, %q, t, %q, False)
    print("TOKEN", name, t, ok, why)
    bad, why = v.openssl_verify(openssl, path, "ab" * 32, t, %q, False)
    print("WRONGDIGEST", name, bad)
    print("SIGNER", name, v.token_signer(open(path, "rb").read()))
`, dir, roots, filepath.ToSlash(tsaDir), digest, roots, roots)
	out, rc := runPython(t, py, "-c", code)
	if rc != 0 {
		t.Fatalf("exit %d:\n%s", rc, out)
	}
	for _, want := range []string{
		"ROOT 552f7bdcf1a7af9e6ce672017f4f12abf77240c78e761ac203d1d9d20ac89988 DigiCert Trusted Root G4 | C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert Trusted Root G4",
		"ROOT a6379e7cecc05faa3cbf076013d745e327bbbaa38c0b9af22469d4701d18aabc FreeTSA root CA (www.freetsa.org) |",
		"TOKEN digicert.tsr 1791170397 True", "TOKEN freetsa.tsr 1791170397 True",
		"WRONGDIGEST digicert.tsr False", "WRONGDIGEST freetsa.tsr False",
		// The signer named by the token itself (not by the anchor record).
		"SIGNER digicert.tsr C=US, O=DigiCert, Inc., CN=DigiCert SHA256 RSA4096 Timestamp Responder 2026 1",
		"SIGNER freetsa.tsr O=Free TSA, OU=TSA, CN=www.freetsa.org, L=Wuerzburg, C=DE",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
}

// tools/verify_bundle.py must run on Python 3.9 and keep LF line endings (it is hashed into
// every bundle's manifest and run on any platform).
func TestVerifyScriptPortable(t *testing.T) {
	if bytes.Contains(verifyScript, []byte("\r")) {
		t.Error("verify_bundle.py contains CR characters")
	}
	if !bytes.HasPrefix(verifyScript, []byte("#!/usr/bin/env python3\n")) {
		t.Error("verify_bundle.py lost its shebang line")
	}
	py := findPython(t)
	path := filepath.Join(t.TempDir(), "verify_bundle.py")
	if err := os.WriteFile(path, verifyScript, 0o644); err != nil {
		t.Fatal(err)
	}
	out, code := runPython(t, py, "-c", fmt.Sprintf(`import ast; ast.parse(open(%q, encoding="utf-8").read(), feature_version=(3, 9)); print("ok")`, path))
	if code != 0 || !strings.Contains(out, "ok") {
		t.Errorf("not Python 3.9 syntax: exit %d\n%s", code, out)
	}
	sum := sha256.Sum256(verifyScript)
	t.Logf("verify_bundle.py sha256 %s", hex.EncodeToString(sum[:]))
}

// A roots file without certificates is still exported (it is what the software supplied), and
// the report says it cannot be used.
func TestUnusableRootsFileReported(t *testing.T) {
	s := buildScenario(t)
	e, _ := newTestExporter(t, s, t.TempDir(), func(o *Options) { o.ExtraFiles = map[string][]byte{tsaRootsPath: []byte("garbage")} })
	info, err := e.Build(context.Background(), contracts.ExportRequest{IncidentID: s.incidentID})
	if err != nil {
		t.Fatal(err)
	}
	z := readZip(t, info.Path)
	r := readReportJSON(t, z)
	if len(r.Bundle.TSARoots) != 0 || !strings.Contains(r.Bundle.TSARootsNote, "contains no certificate") {
		t.Errorf("roots %+v note %q", r.Bundle.TSARoots, r.Bundle.TSARootsNote)
	}
	if !strings.Contains(string(z.files["REPORT.html"]), "keys/tsa-roots.pem: keys/tsa-roots.pem contains no certificate") ||
		!strings.Contains(string(z.files["README.txt"]), "Note on keys/tsa-roots.pem: keys/tsa-roots.pem contains no certificate") {
		t.Error("the unusable roots file is not reported")
	}
}
