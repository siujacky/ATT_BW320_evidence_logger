package anchor

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/digitorus/pkcs7"
	"github.com/digitorus/timestamp"

	"attmonitor/internal/contracts"
)

func mustCore(t testing.TB, der, digest []byte) *verified {
	t.Helper()
	v, err := verifyCore(der, digest)
	if err != nil {
		t.Fatalf("verifyCore: %v", err)
	}
	return v
}

// sameContent compares everything VerifyToken asserts about a token except ChainOK and ChainNote.
func sameContent(a, b contracts.TokenInfo) bool {
	return a.GenTime.Equal(b.GenTime) && a.Serial == b.Serial && a.Policy == b.Policy &&
		a.Nonce == b.Nonce && a.TSAName == b.TSAName
}

// ------------------------------------------------------------------ real vectors

func TestVerifyTokenRealVectors(t *testing.T) {
	digest := vectorDigest(t)
	tests := []struct {
		file, serial, policy, tsaName string
		mustChain                     bool // asserted only where independent of the machine's root store
	}{
		{
			file:    "digicert.tsr",
			serial:  "a4c8151fc30b6d9b71ca72aaaa461dd8",
			policy:  "2.16.840.1.114412.7.1",
			tsaName: `CN=DigiCert SHA256 RSA4096 Timestamp Responder 2026 1,O=DigiCert\, Inc.,C=US`,
		},
		{
			file:   "freetsa.tsr",
			serial: "08e3867d",
			policy: "1.2.3.4.1",
			tsaName: "CN=www.freetsa.org,OU=TSA,O=Free TSA,L=Wuerzburg,ST=Bayern,C=DE," +
				"1.2.840.113549.1.9.1=busilezas@mailbox.org,2.5.4.13=This certificate digitally signs " +
				"documents and time stamp requests made using the freetsa.org online services",
			mustChain: true, // the embedded FreeTSA root
		},
	}
	for _, tt := range tests {
		t.Run(tt.file, func(t *testing.T) {
			der := readVector(t, tt.file)
			info, err := VerifyToken(der, digest, nil)
			if err != nil {
				t.Fatalf("VerifyToken: %v", err)
			}
			if !info.GenTime.Equal(vectorGenTime) || info.GenTime.Location() != time.UTC {
				t.Errorf("GenTime = %v, want %v UTC", info.GenTime, vectorGenTime)
			}
			if info.Serial != tt.serial {
				t.Errorf("Serial = %q, want %q", info.Serial, tt.serial)
			}
			if info.Policy != tt.policy {
				t.Errorf("Policy = %q, want %q", info.Policy, tt.policy)
			}
			if info.Nonce != "1b7dd452a63db4a8" {
				t.Errorf("Nonce = %q, want 1b7dd452a63db4a8", info.Nonce)
			}
			if info.TSAName != tt.tsaName {
				t.Errorf("TSAName = %q\n want %q", info.TSAName, tt.tsaName)
			}
			t.Logf("%s: ChainOK=%v ChainNote=%q (system + embedded roots)", tt.file, info.ChainOK, info.ChainNote)
			if tt.mustChain && !info.ChainOK {
				t.Error("ChainOK = false, want true")
			}
			// ChainNote explains a false ChainOK and is empty otherwise (where DigiCert's root is
			// not in the machine's root store, its note must name every source tried).
			if info.ChainOK && info.ChainNote != "" {
				t.Errorf("ChainNote = %q with ChainOK", info.ChainNote)
			}
			if !info.ChainOK {
				checkNoteForm(t, info.ChainNote, defaultLabels...)
			}
			// The Client method is the same verification with the client's extra roots.
			cinfo, err := New(Options{}).VerifyToken(der, digest)
			if err != nil || cinfo != info {
				t.Errorf("Client.VerifyToken = %+v, %v; want %+v", cinfo, err, info)
			}
		})
	}
}

// TestChainVerifySources isolates each trust source, so the assertions do not depend on the
// machine's root store.
func TestChainVerifySources(t *testing.T) {
	digest := vectorDigest(t)
	dc := mustCore(t, readVector(t, "digicert.tsr"), digest)
	ft := mustCore(t, readVector(t, "freetsa.tsr"), digest)

	// DigiCert's token carries "DigiCert Trusted Root G4" cross-signed by "DigiCert Assured ID
	// Root CA"; trusting that certificate must let the chain verify through the extra roots.
	var g4 *x509.Certificate
	for _, c := range dc.certs {
		if c.Subject.CommonName == "DigiCert Trusted Root G4" {
			g4 = c
		}
	}
	if g4 == nil {
		t.Fatal("DigiCert Trusted Root G4 not found in the DigiCert token")
	}
	embeddedOnly := []rootSource{{sourceEmbedded, embeddedRoots}}
	extraOnly := func(p *x509.CertPool) []rootSource {
		return []rootSource{{sourceExtra, func() (*x509.CertPool, error) { return p, nil }}}
	}
	broken := []rootSource{{"broken source", func() (*x509.CertPool, error) { return nil, errors.New("anchor: boom") }}}
	// The chain is checked at genTime: x509's "current time" is reported as genTime.
	invalid := func(when string, bound time.Time) string {
		return "x509: certificate has expired or is not yet valid: genTime is " + when + " " + bound.UTC().Format(time.RFC3339)
	}
	tests := []struct {
		name    string
		v       *verified
		at      time.Time
		sources []rootSource
		want    bool
		note    string // ChainNote of a false result (the diagnostic contains it too)
	}{
		{"freetsa via embedded root", ft, vectorGenTime, embeddedOnly, true, ""},
		{"digicert not via embedded root", dc, vectorGenTime, embeddedOnly, false, "embedded FreeTSA root: " + unknownCA},
		{"digicert via extra root", dc, vectorGenTime, extraOnly(poolOf(g4)), true, ""},
		{"freetsa not via DigiCert root", ft, vectorGenTime, extraOnly(poolOf(g4)), false, "extra roots: " + unknownCA},
		{"digicert, empty extra pool", dc, vectorGenTime, extraOnly(x509.NewCertPool()), false, "extra roots: " + unknownCA},
		{"digicert, nil extra pool", dc, vectorGenTime, extraOnly(nil), false, "extra roots: none"},
		{"no sources", dc, vectorGenTime, nil, false, "no trust anchors available"},
		{"broken source", dc, vectorGenTime, broken, false, "broken source: unavailable: boom"},
		// CurrentTime is the token's genTime, not "now": outside the certificates' validity
		// the chain must fail even with the right root.
		{"digicert before leaf validity", dc, time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC), extraOnly(poolOf(g4)), false,
			"extra roots: " + invalid("before", dc.signer.NotBefore)},
		{"digicert after cross-cert expiry", dc, time.Date(2032, 1, 1, 0, 0, 0, 0, time.UTC), extraOnly(poolOf(g4)), false,
			"extra roots: " + invalid("after", g4.NotAfter)},
		{"freetsa before leaf validity", ft, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), embeddedOnly, false,
			"embedded FreeTSA root: " + invalid("before", ft.signer.NotBefore)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ok, err := chainVerifyWith(tt.v.signer, tt.v.certs, tt.at, tt.sources)
			if ok != tt.want {
				t.Fatalf("ok = %v (%v), want %v", ok, err, tt.want)
			}
			if ok {
				if err != nil {
					t.Errorf("err = %v with ok", err)
				}
				return
			}
			if note := chainNote(err); note != tt.note {
				t.Errorf("ChainNote = %q\n      want %q", note, tt.note)
			}
			if !strings.Contains(err.Error(), tt.note) || strings.ContainsAny(err.Error(), "\r\n") {
				t.Errorf("diagnostic = %q, want one line containing %q", err, tt.note)
			}
		})
	}
	// Observation only: what this machine's Windows root store says on its own.
	for name, v := range map[string]*verified{"digicert": dc, "freetsa": ft} {
		ok, err := chainVerifyWith(v.signer, v.certs, v.info.GenTime, []rootSource{{sourceSystem, x509.SystemCertPool}})
		note := ""
		if !ok {
			note = chainNote(err)
		}
		t.Logf("system roots only: %s ChainOK=%v ChainNote=%q", name, ok, note)
	}
}

func TestVerifyTokenWrongDigest(t *testing.T) {
	digest := vectorDigest(t)
	empty := sha256.Sum256(nil)
	wrong := map[string][]byte{
		"zero digest":     make([]byte, 32),
		"first byte flip": flip(digest, 0, 0x01),
		"last bit flip":   flip(digest, 31, 0x01),
		"sha256 of empty": empty[:],
		"digest reversed": reversed(digest),
	}
	for _, file := range []string{"digicert.tsr", "freetsa.tsr"} {
		for name, d := range wrong {
			t.Run(file+"/"+name, func(t *testing.T) {
				info, err := VerifyToken(readVector(t, file), d, nil)
				if !errors.Is(err, errImprintMismatch) {
					t.Fatalf("err = %v, want errImprintMismatch", err)
				}
				if info != (contracts.TokenInfo{}) {
					t.Errorf("info = %+v returned with an error", info)
				}
			})
		}
	}
}

func reversed(b []byte) []byte {
	c := bytes.Clone(b)
	for i, j := 0, len(c)-1; i < j; i, j = i+1, j-1 {
		c[i], c[j] = c[j], c[i]
	}
	return c
}

func TestVerifyTokenDigestLength(t *testing.T) {
	der := readVector(t, "freetsa.tsr")
	for _, n := range []int{0, 20, 31, 33, 48, 64} {
		var d []byte
		if n > 0 {
			d = make([]byte, n)
		}
		if _, err := VerifyToken(der, d, nil); !errors.Is(err, errDigestLength) {
			t.Errorf("len %d: err = %v, want errDigestLength", n, err)
		}
	}
}

// signedAttrValue returns the offset in der of the DER value of signed attribute oid, located
// through the attribute's full encoding (type OID, SET header, value): values such as the
// id-ct-TSTInfo OID also occur elsewhere in the token.
func signedAttrValue(t testing.TB, der []byte, oid asn1.ObjectIdentifier) int {
	t.Helper()
	p7, err := pkcs7.Parse(tokenOf(t, der))
	if err != nil {
		t.Fatal(err)
	}
	val, present, err := signedAttribute(p7, oid)
	if err != nil || !present {
		t.Fatalf("signed attribute %v: present=%v err=%v", oid, present, err)
	}
	typeDER, err := asn1.Marshal(oid)
	if err != nil {
		t.Fatal(err)
	}
	set, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true, Bytes: val})
	if err != nil {
		t.Fatal(err)
	}
	pattern := append(typeDER, set...)
	return uniqueIndex(t, der, pattern) + len(pattern) - len(val)
}

func uniqueIndex(t testing.TB, haystack, needle []byte) int {
	t.Helper()
	if n := bytes.Count(haystack, needle); n != 1 {
		t.Fatalf("pattern %x found %d times, want exactly once", needle, n)
	}
	return bytes.Index(haystack, needle)
}

// TestVerifyTokenTamperedBytes flips one byte in each part of the token that carries meaning;
// every such change must make verification fail.
func TestVerifyTokenTamperedBytes(t *testing.T) {
	digest := vectorDigest(t)
	for _, file := range []string{"digicert.tsr", "freetsa.tsr"} {
		der := readVector(t, file)
		v := mustCore(t, der, digest)
		tst := tstInfoOf(t, der)
		tstAt := uniqueIndex(t, der, tst) // signed TSTInfo region
		inTST := func(pattern []byte) int {
			return tstAt + uniqueIndex(t, tst, pattern)
		}
		// Search certificate fields inside the signer certificate only: FreeTSA's TSTInfo also
		// carries the TSA's directory name.
		certAt := uniqueIndex(t, der, v.signer.Raw)
		inCert := func(pattern []byte) int {
			return certAt + uniqueIndex(t, v.signer.Raw, pattern)
		}
		notBefore := []byte(v.signer.NotBefore.UTC().Format("060102150405Z"))
		policyDER, err := asn1.Marshal(asn1.ObjectIdentifier(mustOID(t, v.info.Policy)))
		if err != nil {
			t.Fatal(err)
		}
		cases := map[string]int{
			"TSTInfo genTime":             inTST([]byte("20261005031957Z")) + 13,
			"TSTInfo message imprint":     inTST(digest) + 5,
			"TSTInfo nonce":               inTST(v.nonce.Bytes()) + 7,
			"TSTInfo serial":              inTST(mustBig(t, v.info.Serial)) + 1,
			"TSTInfo policy":              inTST(policyDER) + len(policyDER) - 1,
			"signed content-type":         signedAttrValue(t, der, oidContentType) + 3,
			"signed signingTime":          signedAttrValue(t, der, asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}) + 12,
			"signed messageDigest":        signedAttrValue(t, der, asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}) + 9,
			"signed ESS signingCert":      signedAttrValue(t, der, oidSigningCertificate) + 10,
			"signer certificate subject":  inCert(v.signer.RawSubject) + len(v.signer.RawSubject) - 2,
			"signer certificate key":      inCert(v.signer.RawSubjectPublicKeyInfo) + len(v.signer.RawSubjectPublicKeyInfo) - 3,
			"signer certificate validity": inCert(notBefore) + 9,
			"signer certificate serial":   inCert(v.signer.SerialNumber.Bytes()) + 1,
			"signature value (last byte)": len(der) - 1,
		}
		for name, off := range cases {
			for _, mask := range []byte{0x01, 0x40} {
				t.Run(file+"/"+name, func(t *testing.T) {
					if _, err := VerifyToken(flip(der, off, mask), digest, nil); err == nil {
						t.Fatalf("flipping byte %d (mask %#x) still verifies", off, mask)
					}
				})
			}
		}
	}
}

func mustOID(t testing.TB, s string) []int {
	t.Helper()
	var oid []int
	for _, p := range strings.Split(s, ".") {
		n := 0
		for _, c := range p {
			n = n*10 + int(c-'0')
		}
		oid = append(oid, n)
	}
	return oid
}

func mustBig(t testing.TB, hexStr string) []byte {
	t.Helper()
	n, ok := new(big.Int).SetString(hexStr, 16)
	if !ok {
		t.Fatalf("bad hex %q", hexStr)
	}
	return n.Bytes()
}

// TestVerifyTokenEveryBitFlip is a property test over the real tokens: after any single-bit
// change, verification either fails or still reports exactly the original content (the bit was
// in an unsigned envelope field, e.g. PKIStatus or a CA certificate). No change may yield a
// valid token that says something else. Every byte is tried with a low and a high bit, except
// under -short or the race detector, where a sample is used.
func TestVerifyTokenEveryBitFlip(t *testing.T) {
	digest := vectorDigest(t)
	stride := 1
	if testing.Short() || raceEnabled {
		stride = 13
	}
	for _, file := range []string{"digicert.tsr", "freetsa.tsr"} {
		t.Run(file, func(t *testing.T) {
			der := readVector(t, file)
			want := mustCore(t, der, digest).info
			var tried, accepted atomic.Int64
			offsets := make(chan int)
			var wg sync.WaitGroup
			for range runtime.GOMAXPROCS(0) {
				wg.Go(func() {
					for i := range offsets {
						for _, mask := range []byte{0x01, 0x80} {
							tried.Add(1)
							v, err := verifyCore(flip(der, i, mask), digest)
							if err != nil {
								if strings.Contains(err.Error(), "parser panic") {
									t.Errorf("byte %d mask %#x: %v", i, mask, err)
								}
								continue
							}
							accepted.Add(1)
							if !sameContent(v.info, want) {
								t.Errorf("byte %d mask %#x verified with different content:\n got %+v\nwant %+v", i, mask, v.info, want)
							}
						}
					}
				})
			}
			for i := 0; i < len(der); i += stride {
				offsets <- i
			}
			close(offsets)
			wg.Wait()
			t.Logf("%s: %d single-bit flips, %d still verify with identical content (unsigned envelope bytes)",
				file, tried.Load(), accepted.Load())
		})
	}
}

func TestVerifyTokenResponseForms(t *testing.T) {
	digest := vectorDigest(t)
	resp := readVector(t, "digicert.tsr")
	want, err := VerifyToken(resp, digest, nil)
	if err != nil {
		t.Fatal(err)
	}
	tok := tokenOf(t, resp)
	rejection, err := timestamp.CreateErrorResponse(timestamp.Rejection, timestamp.BadDataFormat)
	if err != nil {
		t.Fatal(err)
	}
	notSeq, _ := asn1.Marshal(42)
	seqOfInt, _ := asn1.Marshal(struct{ A int }{1})
	longText := strings.Repeat("x", 1000) + "\nINJECTED"

	ok := []struct {
		name string
		der  []byte
	}{
		{"granted response", resp},
		{"bare token", tok},
		{"grantedWithMods", wrapResp(t, statusGrantedWithMods, tok)},
		{"granted with status text", wrapResp(t, statusGranted, tok, "Operation Okay")},
	}
	for _, tt := range ok {
		t.Run("ok/"+tt.name, func(t *testing.T) {
			got, err := VerifyToken(tt.der, digest, nil)
			if err != nil {
				t.Fatalf("VerifyToken: %v", err)
			}
			if got != want {
				t.Errorf("info = %+v, want %+v", got, want)
			}
		})
	}

	bad := []struct {
		name     string
		der      []byte
		wantErr  []string
		isStatus bool // a *statusError is expected
		status   int  // its PKIStatus
	}{
		{"rejection (digitorus)", rejection, []string{"rejection (2)", "badDataFormat"}, true, 2},
		{"rejection with text", wrapResp(t, 2, nil, "bad request"), []string{"rejection", `"bad request"`}, true, 2},
		{"rejection carrying a token", wrapResp(t, 2, tok), []string{"rejection"}, true, 2},
		{"waiting", wrapResp(t, 3, nil), []string{"waiting (3)"}, true, 3},
		{"revocationWarning", wrapResp(t, 4, tok), []string{"revocationWarning (4)"}, true, 4},
		{"revocationNotification", wrapResp(t, 5, nil), []string{"revocationNotification (5)"}, true, 5},
		{"unknown status", wrapResp(t, 9, nil), []string{"unknown (9)"}, true, 9},
		{"negative status", wrapResp(t, -1, tok), []string{"unknown (-1)"}, true, -1},
		{"granted without token", wrapResp(t, statusGranted, nil), []string{"no time-stamp token"}, false, 0},
		{"trailing byte", append(bytes.Clone(resp), 0), []string{"trailing"}, false, 0},
		{"truncated", resp[:len(resp)-1], nil, false, 0},
		{"empty", nil, []string{"empty"}, false, 0},
		{"html", []byte("<html><body>AT&amp;T: your internet is down</body></html>"), nil, false, 0},
		{"INTEGER", notSeq, []string{"not a SEQUENCE"}, false, 0},
		{"SEQUENCE of INTEGER", seqOfInt, []string{"malformed TimeStampResp"}, false, 0},
	}
	for _, tt := range bad {
		t.Run("bad/"+tt.name, func(t *testing.T) {
			info, err := VerifyToken(tt.der, digest, nil)
			if err == nil {
				t.Fatalf("VerifyToken succeeded: %+v", info)
			}
			for _, s := range tt.wantErr {
				if !strings.Contains(err.Error(), s) {
					t.Errorf("err = %q, want containing %q", err, s)
				}
			}
			var se *statusError
			if errors.As(err, &se) != tt.isStatus {
				t.Fatalf("statusError = %v, want %v (err %v)", se != nil, tt.isStatus, err)
			}
			if se != nil && se.status != tt.status {
				t.Errorf("status = %d, want %d", se.status, tt.status)
			}
		})
	}

	t.Run("bad/status text is clipped and quoted", func(t *testing.T) {
		_, err := VerifyToken(wrapResp(t, 2, nil, longText, "b", "c", "d", "e", "f"), digest, nil)
		if err == nil {
			t.Fatal("no error")
		}
		msg := err.Error()
		if strings.Contains(msg, "\n") || len(msg) > 600 || !strings.Contains(msg, "...") {
			t.Errorf("error message not clipped/quoted (%d bytes): %q", len(msg), msg)
		}
	})
}

// ------------------------------------------------------------------ fake TSA tokens

func TestVerifyTokenFakeTSA(t *testing.T) {
	digest := randomDigest(t)
	now := time.Now()
	self := newCert(t, tsaSpec(t, "Test TSA (self-signed)"), nil)
	root := newCert(t, caSpec("Test Root CA"), nil)
	inter := newCert(t, caSpec("Test Intermediate CA"), &root)
	leaf := newCert(t, tsaSpec(t, "Test TSA (issued)"), &inter)
	profile := func(cn string, ku x509.KeyUsage, ext ...pkix.Extension) keyCert {
		return newCert(t, certSpec{cn: cn, keyUsage: ku, ext: ext}, &root)
	}
	nonce := big.NewInt(0x5eed)
	gen := now.Add(-time.Minute).Truncate(time.Second)

	// ChainNote expectations. The chain is checked at genTime, so validity messages name genTime.
	// No platform trusts a fake root, so the system roots report "unknown authority" — except for
	// expired certificates, where only the prefix is checked (Go's verifier reports the validity
	// period, the Windows chain engine an unknown authority).
	expiredAt := "x509: certificate has expired or is not yet valid: genTime is after "
	tests := []struct {
		name      string
		spec      tokenSpec
		noNonce   bool
		roots     *x509.CertPool
		wantErr   string // "" → success
		wantChain bool
		note      string   // exact ChainNote when !wantChain (or use noteHas)
		noteHas   []string // fragments ChainNote must contain, in order
	}{
		{name: "self-signed, untrusted", spec: tokenSpec{signer: self}, wantChain: false, note: note3(unknownCA, "none", unknownCA)},
		{name: "self-signed, trusted via extra roots", spec: tokenSpec{signer: self}, roots: poolOf(self.cert), wantChain: true},
		{name: "no nonce", spec: tokenSpec{signer: self}, noNonce: true, roots: poolOf(self.cert), wantChain: true},
		{name: "chain via intermediate", spec: tokenSpec{signer: leaf, chain: []*x509.Certificate{inter.cert}}, roots: poolOf(root.cert), wantChain: true},
		{name: "chain with root included", spec: tokenSpec{signer: leaf, chain: []*x509.Certificate{inter.cert, root.cert}}, roots: poolOf(root.cert), wantChain: true},
		{name: "intermediate missing", spec: tokenSpec{signer: leaf}, roots: poolOf(root.cert), wantChain: false, note: note3(unknownCA, unknownCA, unknownCA)},
		{name: "wrong root", spec: tokenSpec{signer: leaf, chain: []*x509.Certificate{inter.cert}}, roots: poolOf(self.cert), wantChain: false, note: note3(unknownCA, unknownCA, unknownCA)},
		// Two long validity messages and the system roots' verdict exceed 200 bytes: both are
		// shortened alike, every source stays named.
		{name: "genTime after certificate expiry", spec: tokenSpec{signer: self, genTime: now.Add(48 * time.Hour)}, roots: poolOf(self.cert), wantChain: false,
			noteHas: []string{"embedded FreeTSA root: x509: certificate has expired or is not yet", "...; extra roots: x509: certificate has expired or is not yet", "...; system roots: x509: certificate "}},
		{name: "genTime before certificate validity", spec: tokenSpec{signer: self, genTime: now.Add(-48 * time.Hour)}, roots: poolOf(self.cert), wantChain: false,
			noteHas: []string{"embedded FreeTSA root: x509: certificate has expired or is not yet", "...; extra roots: x509: certificate has expired or is not yet", "...; system roots: x509: certificate "}},
		// As in production (no extra roots): the validity message fits, phrased for genTime.
		{name: "genTime after certificate expiry, no extra roots", spec: tokenSpec{signer: self, genTime: now.Add(48 * time.Hour)}, wantChain: false,
			noteHas: []string{"embedded FreeTSA root: " + expiredAt + self.cert.NotAfter.UTC().Format(time.RFC3339), "; extra roots: none; system roots: x509: certificate "}},
		{name: "EKU not critical", spec: tokenSpec{signer: profile("noncrit", x509.KeyUsageDigitalSignature, ekuExt(t, false, oidEKUTimeStamping))}, roots: poolOf(root.cert), wantChain: false,
			note: profileNote("extended key usage is not marked critical")},
		{name: "EKU timeStamping+serverAuth", spec: tokenSpec{signer: profile("multi", x509.KeyUsageDigitalSignature, ekuExt(t, true, oidEKUTimeStamping, oidEKUServerAuth))}, roots: poolOf(root.cert), wantChain: false,
			note: profileNote("extended key usage is not exactly timeStamping")},
		{name: "EKU serverAuth only", spec: tokenSpec{signer: profile("tls", x509.KeyUsageDigitalSignature, ekuExt(t, true, oidEKUServerAuth))}, roots: poolOf(root.cert), wantChain: false,
			note: profileNote("extended key usage is not exactly timeStamping")},
		{name: "no EKU", spec: tokenSpec{signer: profile("noeku", x509.KeyUsageDigitalSignature)}, roots: poolOf(root.cert), wantChain: false,
			note: profileNote("has no extended key usage extension")},
		{name: "key usage certSign", spec: tokenSpec{signer: profile("ku", x509.KeyUsageDigitalSignature|x509.KeyUsageCertSign, ekuExt(t, true, oidEKUTimeStamping))}, roots: poolOf(root.cert), wantChain: false,
			note: profileNote("key usage must be digitalSignature and/or nonRepudiation only")},
		{name: "key usage nonRepudiation only", spec: tokenSpec{signer: profile("nr", x509.KeyUsageContentCommitment, ekuExt(t, true, oidEKUTimeStamping))}, roots: poolOf(root.cert), wantChain: true},
		{name: "no key usage extension", spec: tokenSpec{signer: profile("noku", 0, ekuExt(t, true, oidEKUTimeStamping))}, roots: poolOf(root.cert), wantChain: true},

		{name: "no certificates", spec: tokenSpec{signer: self, noCerts: true}, roots: poolOf(self.cert), wantErr: "carries no certificate"},
		{name: "SHA-512 imprint", spec: tokenSpec{signer: self, hash: crypto.SHA512, imprint: make([]byte, 64)}, wantErr: "SHA-512"},
		{name: "SHA-384 imprint", spec: tokenSpec{signer: self, hash: crypto.SHA384, imprint: make([]byte, 48)}, wantErr: "SHA-384"},
		{name: "SHA-512 label on the right digest", spec: tokenSpec{signer: self, hash: crypto.SHA512, imprint: digest}, wantErr: "expected SHA-256"},
		{name: "other digest", spec: tokenSpec{signer: self, imprint: randomDigest(t)}, wantErr: "does not cover"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec := tt.spec
			if spec.imprint == nil {
				spec.imprint = digest
			}
			if !tt.noNonce {
				spec.nonce = nonce
			}
			if spec.genTime.IsZero() {
				spec.genTime = gen
			}
			der := spec.mustSign(t)
			info, err := VerifyToken(der, digest, tt.roots)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("VerifyToken: %v", err)
			}
			if info.ChainOK != tt.wantChain {
				v := mustCore(t, der, digest)
				_, why := chainVerify(v.signer, v.certs, info.GenTime, tt.roots)
				t.Errorf("ChainOK = %v, want %v (%v)", info.ChainOK, tt.wantChain, why)
			}
			if info.ChainOK {
				if info.ChainNote != "" {
					t.Errorf("ChainNote = %q with ChainOK", info.ChainNote)
				}
			} else {
				if tt.note == "" && tt.noteHas == nil {
					t.Fatal("test case without a ChainNote expectation")
				}
				t.Logf("ChainNote: %s", info.ChainNote)
				checkNoteForm(t, info.ChainNote) // the labels are part of note / noteHas
				if tt.note != "" && info.ChainNote != tt.note {
					t.Errorf("ChainNote = %q\n      want %q", info.ChainNote, tt.note)
				}
				checkNoteHas(t, info.ChainNote, tt.noteHas...)
			}
			if !info.GenTime.Equal(spec.genTime.Truncate(time.Second)) {
				t.Errorf("GenTime = %v, want %v", info.GenTime, spec.genTime)
			}
			if info.TSAName != spec.signer.cert.Subject.String() {
				t.Errorf("TSAName = %q, want %q", info.TSAName, spec.signer.cert.Subject.String())
			}
			if info.Policy != testPolicy.String() || info.Serial == "" {
				t.Errorf("Policy = %q, Serial = %q", info.Policy, info.Serial)
			}
			wantNonce := ""
			if spec.nonce != nil {
				wantNonce = bigHex(spec.nonce)
			}
			if info.Nonce != wantNonce {
				t.Errorf("Nonce = %q, want %q", info.Nonce, wantNonce)
			}
		})
	}
}

// TestVerifyTokenCMSStructure re-signs a genuine TSTInfo so that the CMS signature is valid but
// the structure violates RFC 3161 / RFC 5652 in one specific way.
func TestVerifyTokenCMSStructure(t *testing.T) {
	digest := randomDigest(t)
	tsa := newCert(t, tsaSpec(t, "Test TSA"), nil)
	other := newCert(t, tsaSpec(t, "Other TSA"), nil)
	tst := tstInfoOf(t, tokenSpec{signer: tsa, imprint: digest, nonce: big.NewInt(7)}.mustSign(t))
	v2 := essV2Attr(t, tsa.cert, 0, nil)
	malformed := pkcs7.Attribute{Type: oidSigningCertificateV2, Value: asn1.RawValue{FullBytes: []byte{0x02, 0x01, 0x05}}}

	tests := []struct {
		name    string
		spec    resignSpec
		wantErr string // "" → success
	}{
		{"ESS v2 (default SHA-256)", resignSpec{attrs: []pkcs7.Attribute{v2}}, ""},
		{"ESS v2 explicit SHA-512", resignSpec{attrs: []pkcs7.Attribute{essV2Attr(t, tsa.cert, crypto.SHA512, essHashes[3].oid)}}, ""},
		{"ESS v1 only", resignSpec{attrs: []pkcs7.Attribute{essV1Attr(t, tsa.cert)}}, ""},
		{"ESS v1 and v2", resignSpec{attrs: []pkcs7.Attribute{essV1Attr(t, tsa.cert), v2}}, ""},
		{"no ESS attribute", resignSpec{}, "lacks the ESS"},
		{"ESS v2 names another certificate", resignSpec{attrs: []pkcs7.Attribute{essV2Attr(t, other.cert, 0, nil)}}, "does not identify"},
		{"ESS v1 names another certificate", resignSpec{attrs: []pkcs7.Attribute{v2, essV1Attr(t, other.cert)}}, "signingCertificate does not identify"},
		{"ESS v2 wrong algorithm label", resignSpec{attrs: []pkcs7.Attribute{essV2Attr(t, tsa.cert, crypto.SHA256, essHashes[3].oid)}}, "does not identify"},
		{"ESS v2 unsupported hash", resignSpec{attrs: []pkcs7.Attribute{essV2Attr(t, tsa.cert, crypto.SHA256, asn1.ObjectIdentifier{1, 2, 3, 4})}}, "unsupported hash"},
		{"ESS v2 twice", resignSpec{attrs: []pkcs7.Attribute{v2, v2}}, "appears 2 times"},
		{"ESS v2 malformed", resignSpec{attrs: []pkcs7.Attribute{malformed}}, "malformed ESS"},
		{"content type id-data", resignSpec{contentType: pkcs7.OIDData, attrs: []pkcs7.Attribute{v2}}, "not id-ct-TSTInfo"},
		{"two signers", resignSpec{attrs: []pkcs7.Attribute{v2}, signers: []keyCert{tsa, tsa}}, "2 signers"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec := tt.spec
			if spec.signers == nil {
				spec.signers = []keyCert{tsa}
			}
			tok := spec.sign(t, tst)
			for form, der := range map[string][]byte{"bare token": tok, "response": wrapResp(t, statusGranted, tok)} {
				info, err := VerifyToken(der, digest, poolOf(tsa.cert))
				if tt.wantErr == "" {
					if err != nil {
						t.Fatalf("%s: VerifyToken: %v", form, err)
					}
					if !info.ChainOK || info.Nonce != "07" {
						t.Errorf("%s: info = %+v", form, info)
					}
					continue
				}
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("%s: err = %v, want containing %q", form, err, tt.wantErr)
				}
			}
		})
	}
}

func TestESSBindingRealVectors(t *testing.T) {
	digest := vectorDigest(t)
	for _, file := range []string{"digicert.tsr", "freetsa.tsr"} {
		der := readVector(t, file)
		p7, err := pkcs7.Parse(tokenOf(t, der))
		if err != nil {
			t.Fatal(err)
		}
		v := mustCore(t, der, digest)
		if err := checkSigningCertificate(p7, v.signer); err != nil {
			t.Errorf("%s: signer: %v", file, err)
		}
		for _, c := range v.certs {
			if c.Equal(v.signer) {
				continue
			}
			if err := checkSigningCertificate(p7, c); err == nil {
				t.Errorf("%s: ESS accepted non-signer %q", file, c.Subject.CommonName)
			}
		}
	}
}

func TestCheckTSAProfileRealCertificates(t *testing.T) {
	digest := vectorDigest(t)
	for _, file := range []string{"digicert.tsr", "freetsa.tsr"} {
		v := mustCore(t, readVector(t, file), digest)
		if err := checkTSAProfile(v.signer); err != nil {
			t.Errorf("%s signer: %v", file, err)
		}
		for _, c := range v.certs {
			if !c.Equal(v.signer) && checkTSAProfile(c) == nil {
				t.Errorf("%s: CA certificate %q passes the TSA profile", file, c.Subject.CommonName)
			}
		}
	}
}

func TestBigHex(t *testing.T) {
	tests := []struct {
		in   *big.Int
		want string
	}{
		{nil, ""},
		{big.NewInt(0), "00"},
		{big.NewInt(1), "01"},
		{big.NewInt(255), "ff"},
		{big.NewInt(256), "0100"},
		{big.NewInt(0x08e3867d), "08e3867d"},
		{big.NewInt(-1), "-01"},
		{new(big.Int).SetUint64(0x1B7DD452A63DB4A8), "1b7dd452a63db4a8"},
	}
	for _, tt := range tests {
		if got := bigHex(tt.in); got != tt.want {
			t.Errorf("bigHex(%v) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// FuzzVerifyToken checks that arbitrary input never panics a parser and never verifies as a
// token with content other than one of the seeds'. `go test` runs the seeds only.
func FuzzVerifyToken(f *testing.F) {
	digest := vectorDigest(f)
	known := map[string]contracts.TokenInfo{}
	for _, file := range []string{"digicert.tsr", "freetsa.tsr"} {
		der := readVector(f, file)
		v := mustCore(f, der, digest)
		known[v.info.Serial] = v.info
		f.Add(der)
		f.Add(tokenOf(f, der))
	}
	f.Add([]byte{})
	f.Add([]byte{0x30, 0x80, 0x00, 0x00})
	f.Fuzz(func(t *testing.T, der []byte) {
		v, err := verifyCore(der, digest)
		if err != nil {
			if strings.Contains(err.Error(), "parser panic") {
				t.Fatalf("parser panic: %v", err)
			}
			return
		}
		want, ok := known[v.info.Serial]
		if !ok || !sameContent(v.info, want) {
			t.Fatalf("verified unexpected content %+v", v.info)
		}
	})
}
