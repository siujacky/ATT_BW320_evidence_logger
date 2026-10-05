package ticket

import (
	"context"
	"crypto/sha256"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"strings"
	"testing"
	"time"

	"attmonitor/internal/model"
)

// The real setup-time tokens (testdata/tsa, from 2026-10-05T03:19:57Z) cover the SHA-256 of
// the real BOOTSTRAP-MANIFEST.sha256 (testdata/tsa/manifest.txt).
func TestParseRealTokens(t *testing.T) {
	manifest := sha256.Sum256(fixture(t, "tsa/manifest.txt"))
	for _, tc := range []struct {
		file, tsa string
	}{{"tsa/digicert.tsr", "DigiCert"}, {"tsa/freetsa.tsr", "Free TSA"}} {
		info, err := parseToken(fixture(t, tc.file))
		if err != nil {
			t.Fatalf("%s: %v", tc.file, err)
		}
		if !info.Granted || info.HashAlg != "SHA-256" || !info.GenTime.Equal(ts("2026-10-05T03:19:57Z")) {
			t.Errorf("%s: %+v", tc.file, info)
		}
		if info.Imprint != sha256Hex(fixture(t, "tsa/manifest.txt")) || info.Imprint != strings.ToLower(hexOf(manifest[:])) {
			t.Errorf("%s: imprint %s", tc.file, info.Imprint)
		}
		if !strings.Contains(info.TSA, tc.tsa) {
			t.Errorf("%s: TSA %q, want %q", tc.file, info.TSA, tc.tsa)
		}
	}
	for _, bad := range [][]byte{nil, []byte("not a token"), {0x30, 0x03, 0x02, 0x01, 0x00}, fixture(t, "tsa/manifest.txt")} {
		if _, err := parseToken(bad); err == nil {
			t.Errorf("parsed %q", bad)
		}
	}
}

func hexOf(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, 2*len(b))
	for _, c := range b {
		out = append(out, digits[c>>4], digits[c&15])
	}
	return string(out)
}

// syntheticToken builds an unsigned TimeStampResp stating genTime over imprint (enough for
// the reader, which never claims to verify a signature).
func syntheticToken(t testing.TB, imprint []byte, gen time.Time, status int) []byte {
	t.Helper()
	return syntheticTokenSerial(t, imprint, gen, status, 42)
}

// syntheticTokenSerial is syntheticToken with the given serial number.
func syntheticTokenSerial(t testing.TB, imprint []byte, gen time.Time, status int, serial int64) []byte {
	t.Helper()
	tst, err := asn1.Marshal(tsrTSTInfo{Version: 1, Policy: asn1.ObjectIdentifier{1, 2, 3},
		MessageImprint: tsrImprint{HashAlgorithm: pkix.AlgorithmIdentifier{Algorithm: oidSHA256}, HashedMessage: imprint},
		SerialNumber:   big.NewInt(serial), GenTime: gen.UTC()})
	if err != nil {
		t.Fatal(err)
	}
	octets, err := asn1.Marshal(tst)
	if err != nil {
		t.Fatal(err)
	}
	// [0] EXPLICIT wrappers are built by hand: asn1.Marshal writes a RawValue's FullBytes
	// verbatim, without the tag of its field.
	explicit0 := func(inner []byte) asn1.RawValue {
		return asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: inner}
	}
	type encap struct {
		EContentType asn1.ObjectIdentifier
		EContent     asn1.RawValue
	}
	type signedData struct {
		Version          int
		DigestAlgorithms asn1.RawValue
		EncapContentInfo encap
		SignerInfos      asn1.RawValue
	}
	set := asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true}
	sd, err := asn1.Marshal(signedData{Version: 3, DigestAlgorithms: set, SignerInfos: set,
		EncapContentInfo: encap{EContentType: oidTSTInfo, EContent: explicit0(octets)}})
	if err != nil {
		t.Fatal(err)
	}
	type contentInfo struct {
		ContentType asn1.ObjectIdentifier
		Content     asn1.RawValue
	}
	ci, err := asn1.Marshal(contentInfo{ContentType: oidSignedData, Content: explicit0(sd)})
	if err != nil {
		t.Fatal(err)
	}
	type resp struct {
		Status tsrPKIStatus
		Token  asn1.RawValue
	}
	der, err := asn1.Marshal(resp{Status: tsrPKIStatus{Status: status}, Token: asn1.RawValue{FullBytes: ci}})
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// TestSetupTokenCoverage: a time-stamped manifest that lists the captured page's SHA-256 links
// the page to the token; a manifest that does not, or a token over another file, does not.
func TestSetupTokenCoverage(t *testing.T) {
	f := newFake(t)
	fiber := fixture(t, "gateway/fiberstat.html")
	sys := fixture(t, "gateway/sysinfo.html")
	manifest := []byte(sha256Hex(fiber) + "  initial-snapshot/2026-10-05T03:10:46Z  fiberstat.anon.html\n")
	mSum := sha256.Sum256(manifest)
	gen := ts("2026-10-05T03:19:57Z")
	good := syntheticToken(t, mSum[:], gen, 0)
	other := sha256.Sum256([]byte("something else"))
	stray := syntheticToken(t, other[:], gen, 0)
	rejected := syntheticToken(t, mSum[:], gen, 2)
	file := func(path string, b []byte, mod string) model.BootstrapFile {
		return model.BootstrapFile{Path: path, SHA256: f.putBlob(b), Size: int64(len(b)), ModTime: mod}
	}
	files := []model.BootstrapFile{
		file("M.sha256", manifest, "2026-10-05T03:19:00Z"),
		file("M.good.tsr", good, "2026-10-05T03:19:57Z"),
		file("M.stray.tsr", stray, "2026-10-05T03:19:57Z"),
		file("M.rejected.tsr", rejected, "2026-10-05T03:19:57Z"),
		file("initial-snapshot/fiberstat.anon.html", fiber, "2026-10-05T03:10:46Z"),
		file("initial-snapshot/sysinfo.anon.html", sys, "2026-10-05T03:10:44Z"),
		{Path: "initial-snapshot/broadbandstatistics.anon.html", SHA256: sha256Hex([]byte("missing")), Size: 7, ModTime: "2026-10-05T03:10:45Z"},
	}
	f.add(ts("2026-10-05T12:00:00Z"), model.TypeGenesis, genesisData())
	f.add(ts("2026-10-05T12:00:01Z"), model.TypeBootstrapImport, model.BootstrapImport{Files: files})
	rep, err := Build(context.Background(), f, Options{From: ts("2026-10-04T13:00:00Z"), To: ts("2026-10-05T13:00:00Z"),
		Now: func() time.Time { return ts("2026-10-05T13:00:00Z") }, Location: time.UTC})
	if err != nil {
		t.Fatal(err)
	}
	st := rep.Evidence.Setup
	if st == nil || st.Fiber == nil {
		t.Fatalf("setup = %+v", st)
	}
	if len(st.Fiber.ListedIn) != 1 || st.Fiber.ListedIn[0] != "M.sha256" {
		t.Errorf("fiber page listed in %v", st.Fiber.ListedIn)
	}
	for _, p := range st.Pages {
		if p.Page == "sysinfo" && len(p.ListedIn) != 0 {
			t.Errorf("sysinfo is not in the manifest: %v", p.ListedIn)
		}
		if p.Page == "broadbandstatistics" && p.OK {
			t.Error("a missing blob must not be OK")
		}
	}
	byPath := map[string]SetupToken{}
	for _, tk := range st.Tokens {
		byPath[tk.Path] = tk
	}
	if tk := byPath["M.good.tsr"]; tk.Covers != "M.sha256" || !tk.Granted || !tk.GenTime.Equal(gen) || tk.TSA != "good" {
		t.Errorf("good token %+v", tk)
	}
	if tk := byPath["M.stray.tsr"]; tk.Covers != "" {
		t.Errorf("stray token %+v", tk)
	}
	if tk := byPath["M.rejected.tsr"]; tk.Granted {
		t.Errorf("rejected token %+v", tk)
	}
	if len(st.Problems) != 1 || !strings.Contains(st.Problems[0], "broadbandstatistics") {
		t.Errorf("problems = %v", st.Problems)
	}
	// The capture is the window's only reading: it is labelled as such.
	if len(rep.Optical.Readings) != 1 || !rep.Optical.Readings[0].Setup {
		t.Fatalf("readings %+v", rep.Optical.Readings)
	}
	wantContains(t, "optical", rep.Bullet("optical").String(), "(setup capture, bootstrap_import #1)", "the ALARM flag was set in 1 of 1 readings (100%)")
	// Without snapshots the gateway identity comes from the capture.
	if !rep.Gateway.Known || rep.Gateway.Serial != fixSerial || !strings.Contains(rep.Gateway.Source, "setup-time capture") {
		t.Errorf("gateway = %+v", rep.Gateway)
	}
	page, err := rep.HTML()
	if err != nil {
		t.Fatal(err)
	}
	wantContains(t, "html", pageText(t, page), "In a time-stamped manifest", "initial-snapshot/fiberstat.anon.html 2026-10-05 03:10:46 UTC",
		"listed in M.sha256", "not listed", "no imported file has its hash", "not a granted time-stamp")
}

// TestSetupRealTokens: the real tokens over the real manifest, with the sanitized fixture pages,
// which the real manifest does not list: the tokens are read, but no page is claimed as listed.
func TestSetupRealTokens(t *testing.T) {
	f := newFake(t)
	s := &scenario{f: f, now: ts("2026-10-05T14:00:00Z")}
	f.add(ts("2026-10-05T12:45:47Z"), model.TypeGenesis, genesisData())
	s.addRealBootstrap(ts("2026-10-05T12:45:47.1Z"))
	rep, err := Build(context.Background(), f, Options{Now: func() time.Time { return s.now }, Location: cdt})
	if err != nil {
		t.Fatal(err)
	}
	st := rep.Evidence.Setup
	if st == nil || len(st.Tokens) != 2 || len(st.Pages) != 3 {
		t.Fatalf("setup = %+v", st)
	}
	for _, tk := range st.Tokens {
		if tk.Covers != "BOOTSTRAP-MANIFEST.sha256" || !tk.GenTime.Equal(setupGenTime) || !tk.Granted ||
			(tk.TSA != "DigiCert, Inc." && tk.TSA != "Free TSA") {
			t.Errorf("token %+v", tk)
		}
	}
	for _, p := range st.Pages {
		if len(p.ListedIn) != 0 {
			t.Errorf("%s is not in the real manifest, but listed in %v", p.Path, p.ListedIn)
		}
	}
	page, err := rep.HTML()
	if err != nil {
		t.Fatal(err)
	}
	wantContains(t, "html", pageText(t, page), "initial-snapshot/fiberstat.anon.html 2026-10-05 03:10:46 UTC f618307d...7425 not listed",
		"-digest 0bb4c71bfeddf27eb9647853d1e5aa8f981f222fe4ffac0c7d1d8db73f1d443b")
}
