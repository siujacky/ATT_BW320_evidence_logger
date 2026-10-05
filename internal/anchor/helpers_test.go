package anchor

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/digitorus/pkcs7"
	"github.com/digitorus/timestamp"
)

// ------------------------------------------------------------------ real vectors

// The vectors are real TimeStampResp DER from DigiCert and FreeTSA over
// sha256(testdata/tsa/manifest.txt), requested with `openssl ts -query -cert` (nonce
// 0x1B7DD452A63DB4A8) on 2026-10-05T03:19:57Z.
const vectorDigestHex = "0bb4c71bfeddf27eb9647853d1e5aa8f981f222fe4ffac0c7d1d8db73f1d443b"

var vectorGenTime = time.Date(2026, 10, 5, 3, 19, 57, 0, time.UTC)

func readVector(t testing.TB, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "testdata", "tsa", name))
	if err != nil {
		t.Fatalf("read vector: %v", err)
	}
	return b
}

// vectorDigest returns sha256(manifest.txt), checking it against the documented value.
func vectorDigest(t testing.TB) []byte {
	t.Helper()
	sum := sha256.Sum256(readVector(t, "manifest.txt"))
	if got := hex.EncodeToString(sum[:]); got != vectorDigestHex {
		t.Fatalf("sha256(manifest.txt) = %s, want %s", got, vectorDigestHex)
	}
	return sum[:]
}

// tokenOf returns the bare TimeStampToken inside a DER TimeStampResp.
func tokenOf(t testing.TB, resp []byte) []byte {
	t.Helper()
	tok, status, err := extractToken(resp)
	if err != nil || status != statusGranted {
		t.Fatalf("extractToken: status %d, err %v", status, err)
	}
	return tok
}

// certsOf returns the certificates embedded in a response or token.
func certsOf(t testing.TB, der []byte) []*x509.Certificate {
	t.Helper()
	tok, _, err := extractToken(der)
	if err != nil {
		t.Fatal(err)
	}
	p7, err := pkcs7.Parse(tok)
	if err != nil {
		t.Fatal(err)
	}
	return p7.Certificates
}

// ------------------------------------------------------------------ fake PKI

var (
	oidEKUTimeStamping = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 8}
	oidEKUServerAuth   = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1}
	testPolicy         = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 3161, 1}
)

// ekuExt builds an extended key usage extension.
func ekuExt(t testing.TB, critical bool, oids ...asn1.ObjectIdentifier) pkix.Extension {
	t.Helper()
	v, err := asn1.Marshal(oids)
	if err != nil {
		t.Fatal(err)
	}
	return pkix.Extension{Id: oidExtKeyUsage, Critical: critical, Value: v}
}

type keyCert struct {
	cert *x509.Certificate
	key  crypto.Signer
}

type certSpec struct {
	cn        string
	ca        bool
	keyUsage  x509.KeyUsage
	ext       []pkix.Extension
	dnsNames  []string  // subjectAltName dNSName entries
	notBefore time.Time // zero → now-1h
	notAfter  time.Time // zero → now+24h
}

// newCert creates an ECDSA P-256 certificate, self-signed when parent is nil.
func newCert(t testing.TB, spec certSpec, parent *keyCert) keyCert {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if spec.notBefore.IsZero() {
		spec.notBefore = now.Add(-time.Hour)
	}
	if spec.notAfter.IsZero() {
		spec.notAfter = now.Add(24 * time.Hour)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial.Add(serial, big.NewInt(1)),
		Subject:               pkix.Name{CommonName: spec.cn, Organization: []string{"att-monitor tests"}},
		NotBefore:             spec.notBefore,
		NotAfter:              spec.notAfter,
		KeyUsage:              spec.keyUsage,
		ExtraExtensions:       spec.ext,
		DNSNames:              spec.dnsNames,
		BasicConstraintsValid: true,
		IsCA:                  spec.ca,
	}
	issuer, issuerKey := tmpl, crypto.Signer(key)
	if parent != nil {
		issuer, issuerKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, issuer, key.Public(), issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return keyCert{cert: cert, key: key}
}

// tsaSpec is a conforming TSA certificate profile: critical EKU timeStamping only and key
// usage digitalSignature.
func tsaSpec(t testing.TB, cn string) certSpec {
	return certSpec{cn: cn, keyUsage: x509.KeyUsageDigitalSignature,
		ext: []pkix.Extension{ekuExt(t, true, oidEKUTimeStamping)}}
}

func caSpec(cn string) certSpec {
	return certSpec{cn: cn, ca: true, keyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
}

// poolOf returns a CertPool holding certs.
func poolOf(certs ...*x509.Certificate) *x509.CertPool {
	p := x509.NewCertPool()
	for _, c := range certs {
		p.AddCert(c)
	}
	return p
}

// ------------------------------------------------------------------ token signing

// tokenSpec describes a TimeStampResp to sign with digitorus/timestamp (status granted).
type tokenSpec struct {
	signer  keyCert
	chain   []*x509.Certificate // included after the signer certificate
	noCerts bool                // omit all certificates
	hash    crypto.Hash         // imprint algorithm; 0 → SHA-256
	imprint []byte
	nonce   *big.Int
	genTime time.Time // zero → now
	policy  asn1.ObjectIdentifier
}

func (s tokenSpec) sign() ([]byte, error) {
	if s.hash == 0 {
		s.hash = crypto.SHA256
	}
	if s.genTime.IsZero() {
		s.genTime = time.Now()
	}
	if s.policy == nil {
		s.policy = testPolicy
	}
	ts := timestamp.Timestamp{
		HashAlgorithm:     s.hash,
		HashedMessage:     s.imprint,
		Time:              s.genTime,
		Nonce:             s.nonce,
		Policy:            s.policy,
		AddTSACertificate: !s.noCerts,
		Certificates:      s.chain,
	}
	return ts.CreateResponseWithOpts(s.signer.cert, s.signer.key, crypto.SHA256)
}

func (s tokenSpec) mustSign(t testing.TB) []byte {
	t.Helper()
	der, err := s.sign()
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return der
}

// tstInfoOf returns the signed TSTInfo DER (eContent) of a response.
func tstInfoOf(t testing.TB, resp []byte) []byte {
	t.Helper()
	p7, err := pkcs7.Parse(tokenOf(t, resp))
	if err != nil {
		t.Fatal(err)
	}
	return p7.Content
}

// resignSpec re-signs a TSTInfo with full control over the CMS layer, to build tokens whose
// signature is valid but whose structure violates RFC 3161 in one specific way.
type resignSpec struct {
	contentType asn1.ObjectIdentifier // content-type attribute; nil → id-ct-TSTInfo
	attrs       []pkcs7.Attribute     // extra signed attributes (e.g. ESS)
	signers     []keyCert             // each adds one SignerInfo (and its certificate)
}

func (r resignSpec) sign(t testing.TB, tstInfo []byte) []byte {
	t.Helper()
	sd, err := pkcs7.NewSignedData(tstInfo)
	if err != nil {
		t.Fatal(err)
	}
	sd.SetDigestAlgorithm(pkcs7.OIDDigestAlgorithmSHA256)
	ct := r.contentType
	if ct == nil {
		ct = oidTSTInfo
	}
	sd.SetContentType(ct)
	for _, s := range r.signers {
		if err := sd.AddSigner(s.cert, s.key, pkcs7.SignerInfoConfig{ExtraSignedAttributes: r.attrs}); err != nil {
			t.Fatal(err)
		}
	}
	der, err := sd.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// essV2Attr builds a signingCertificateV2 attribute naming cert (hash nil → default SHA-256).
func essV2Attr(t testing.TB, cert *x509.Certificate, hash crypto.Hash, algOID asn1.ObjectIdentifier) pkcs7.Attribute {
	t.Helper()
	if hash == 0 {
		hash = crypto.SHA256
	}
	h := hash.New()
	h.Write(cert.Raw)
	id := essCertIDv2{CertHash: h.Sum(nil)}
	if algOID != nil {
		id.HashAlgorithm = pkix.AlgorithmIdentifier{Algorithm: algOID}
	}
	v, err := asn1.Marshal(signingCertificateV2{Certs: []essCertIDv2{id}})
	if err != nil {
		t.Fatal(err)
	}
	return pkcs7.Attribute{Type: oidSigningCertificateV2, Value: asn1.RawValue{FullBytes: v}}
}

// essV1Attr builds a signingCertificate (SHA-1) attribute naming cert.
func essV1Attr(t testing.TB, cert *x509.Certificate) pkcs7.Attribute {
	t.Helper()
	h := crypto.SHA1.New()
	h.Write(cert.Raw)
	v, err := asn1.Marshal(signingCertificate{Certs: []essCertID{{CertHash: h.Sum(nil)}}})
	if err != nil {
		t.Fatal(err)
	}
	return pkcs7.Attribute{Type: oidSigningCertificate, Value: asn1.RawValue{FullBytes: v}}
}

// wrapResp wraps a token in a TimeStampResp with the given status and PKIFreeText.
func wrapResp(t testing.TB, status int, token []byte, text ...string) []byte {
	t.Helper()
	type statusInfoOut struct {
		Status       int
		StatusString []asn1.RawValue `asn1:"optional"`
	}
	type respOut struct {
		Status         statusInfoOut
		TimeStampToken asn1.RawValue `asn1:"optional"`
	}
	resp := respOut{Status: statusInfoOut{Status: status}}
	for _, s := range text {
		resp.Status.StatusString = append(resp.Status.StatusString, asn1.RawValue{Tag: asn1.TagUTF8String, Bytes: []byte(s)})
	}
	if token != nil {
		resp.TimeStampToken = asn1.RawValue{FullBytes: token}
	}
	der, err := asn1.Marshal(resp)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// ------------------------------------------------------------------ fake TSA server

type capturedRequest struct {
	method string
	header http.Header
	body   []byte
}

// fakeTSA is an RFC 3161 responder for tests. By default it signs a token over the request's
// imprint that echoes the request nonce.
type fakeTSA struct {
	signer      keyCert
	chain       []*x509.Certificate
	noCerts     bool
	contentType string                                                    // "" → application/timestamp-reply
	nonce       func(*big.Int) *big.Int                                   // nil → echo
	imprint     func([]byte) []byte                                       // nil → echo
	tamper      func([]byte) []byte                                       // applied to the signed reply
	handler     func(w http.ResponseWriter, r *http.Request, body []byte) // replaces the default

	mu   sync.Mutex
	reqs []capturedRequest
	sent [][]byte
}

func (f *fakeTSA) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<16))
	f.mu.Lock()
	f.reqs = append(f.reqs, capturedRequest{method: r.Method, header: r.Header.Clone(), body: body})
	f.mu.Unlock()
	if f.handler != nil {
		f.handler(w, r, body)
		return
	}
	f.respond(w, body)
}

// respond is the default behaviour: sign a token for the request in body.
func (f *fakeTSA) respond(w http.ResponseWriter, body []byte) {
	req, err := timestamp.ParseRequest(body)
	if err != nil {
		http.Error(w, "bad time-stamp request", http.StatusBadRequest)
		return
	}
	spec := tokenSpec{signer: f.signer, chain: f.chain, noCerts: f.noCerts, hash: req.HashAlgorithm,
		imprint: req.HashedMessage, nonce: req.Nonce}
	if f.imprint != nil {
		spec.imprint = f.imprint(bytes.Clone(req.HashedMessage))
	}
	if f.nonce != nil {
		spec.nonce = f.nonce(req.Nonce)
	}
	der, err := spec.sign()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if f.tamper != nil {
		der = f.tamper(der)
	}
	f.mu.Lock()
	f.sent = append(f.sent, der)
	f.mu.Unlock()
	ct := f.contentType
	if ct == "" {
		ct = "application/timestamp-reply"
	}
	w.Header().Set("Content-Type", ct)
	w.Write(der)
}

func (f *fakeTSA) requests() []capturedRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]capturedRequest(nil), f.reqs...)
}

func (f *fakeTSA) replies() [][]byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([][]byte(nil), f.sent...)
}

// serve starts an httptest server for h, closed at test end.
func serve(t testing.TB, h http.Handler) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv
}

// randomDigest returns 32 random bytes.
func randomDigest(t testing.TB) []byte {
	t.Helper()
	d := make([]byte, sha256.Size)
	if _, err := rand.Read(d); err != nil {
		t.Fatal(err)
	}
	return d
}

// flip returns a copy of b with byte i XORed with mask.
func flip(b []byte, i int, mask byte) []byte {
	c := bytes.Clone(b)
	c[i] ^= mask
	return c
}
