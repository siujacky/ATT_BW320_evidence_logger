package probe

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// HTTPS checks record HTTPResult.TLSCertSHA256, the SHA-256 of the leaf certificate the
// server presented, whether or not it verifies: a certificate that fails verification is the
// evidence of interception. Verification itself is the standard library's and unchanged, so
// OK still requires a certificate that is valid for the URL's host. Tests trust their own
// roots through Prober.rootCAs; production code never sets it (system roots).

// testCert is a certificate of a throwaway test hierarchy and its key.
type testCert struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

var testSerial atomic.Int64

// issueCert creates a certificate from tmpl, signed by parent (self-signed when nil).
func issueCert(t *testing.T, tmpl *x509.Certificate, parent *testCert) *testCert {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl.SerialNumber = big.NewInt(testSerial.Add(1))
	signer, signerKey := tmpl, key
	if parent != nil {
		signer, signerKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signer, &key.PublicKey, signerKey)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &testCert{cert: c, key: key}
}

func caTmpl(name string) *x509.Certificate {
	now := time.Now()
	return &x509.Certificate{
		Subject:   pkix.Name{CommonName: name},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
}

// leafTmpl is a server certificate for probe.test and 127.0.0.1, valid in [from, until).
func leafTmpl(from, until time.Time) *x509.Certificate {
	return &x509.Certificate{
		Subject:     pkix.Name{CommonName: "probe.test"},
		DNSNames:    []string{"probe.test"},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
		NotBefore:   from, NotAfter: until,
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
}

func validLeafTmpl() *x509.Certificate {
	return leafTmpl(time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
}

func certPool(certs ...*x509.Certificate) *x509.CertPool {
	p := x509.NewCertPool()
	for _, c := range certs {
		p.AddCert(c)
	}
	return p
}

// startTLS starts an HTTPS server answering 204 that presents chain (leaf first; nil = the
// httptest certificate) with cfg's other settings. Handshake errors are expected in these
// tests and not logged.
func startTLS(t *testing.T, chain []*testCert, cfg *tls.Config) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	if cfg == nil {
		cfg = &tls.Config{}
	}
	if len(chain) > 0 {
		c := tls.Certificate{PrivateKey: chain[0].key, Leaf: chain[0].cert}
		for _, tc := range chain {
			c.Certificate = append(c.Certificate, tc.cert.Raw)
		}
		cfg.Certificates = []tls.Certificate{c}
	}
	srv.TLS = cfg
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func TestHTTPSValidCertificateRecordsLeaf(t *testing.T) {
	srv := startTLS(t, nil, nil)
	p := New(Options{})
	p.rootCAs = certPool(srv.Certificate()) // tests only: trust the httptest certificate

	r := p.HTTP(context.Background(), "google_204", srv.URL+"/generate_204", 204, "", 2*time.Second)
	if !r.OK || r.Status != 204 || r.Err != "" || r.Hijacked {
		t.Fatalf("got %+v", r)
	}
	if want := sha256Hex(srv.Certificate().Raw); r.TLSCertSHA256 != want {
		t.Fatalf("TLSCertSHA256 = %q, want %s", r.TLSCertSHA256, want)
	}
	if b, err := json.Marshal(r); err != nil || !strings.Contains(string(b), `"tls_cert_sha256":"`+r.TLSCertSHA256+`"`) {
		t.Fatalf("record %s (%v)", b, err)
	}
}

// TestHTTPSInvalidCertificateRecordsLeaf: whatever makes verification fail, the check fails
// (OK=false, no status, Err says why) and the certificate that was presented is recorded.
func TestHTTPSInvalidCertificateRecordsLeaf(t *testing.T) {
	root := issueCert(t, caTmpl("att-monitor test root"), nil)
	inter := issueCert(t, caTmpl("att-monitor test intermediate"), root)
	expired := issueCert(t, leafTmpl(time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour)), root)
	interLeaf := issueCert(t, validLeafTmpl(), inter)

	tests := []struct {
		name   string
		chain  []*testCert // nil: httptest certificate
		roots  []*testCert // trusted (none: system roots)
		public bool        // ask for https://www.google.com/ and route it to the test server
		errIn  string
	}{
		{name: "self-signed, system roots", errIn: "certificate signed by unknown authority"},
		{name: "trusted certificate for another host (interception)", roots: []*testCert{root},
			chain: []*testCert{issueCert(t, validLeafTmpl(), root)}, public: true,
			errIn: "certificate is valid for probe.test, not www.google.com"},
		{name: "expired", chain: []*testCert{expired}, roots: []*testCert{root}, errIn: "expired"},
		{name: "intermediate not sent", chain: []*testCert{interLeaf}, roots: []*testCert{root},
			errIn: "certificate signed by unknown authority"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := startTLS(t, tt.chain, nil)
			p := New(Options{})
			if len(tt.roots) > 0 {
				p.rootCAs = certPool(tt.roots[0].cert)
			}
			url := srv.URL + "/generate_204"
			if tt.public {
				routeDial(p, srv.Listener.Addr().String(), "")
				url = "https://www.google.com/generate_204"
			}
			r := p.HTTP(context.Background(), "google_204", url, 204, "", 2*time.Second)
			if r.OK || r.Status != 0 || r.RTTus != 0 || r.BodySHA256 != "" {
				t.Fatalf("an unverified server produced a result: %+v", r)
			}
			if !strings.Contains(r.Err, "tls: failed to verify certificate: ") || !strings.Contains(r.Err, tt.errIn) {
				t.Fatalf("Err = %q, want the verification failure containing %q", r.Err, tt.errIn)
			}
			if want := sha256Hex(srv.Certificate().Raw); r.TLSCertSHA256 != want {
				t.Fatalf("TLSCertSHA256 = %q, want the presented leaf %s", r.TLSCertSHA256, want)
			}
			if r.RemoteAddr != srv.Listener.Addr().String() || r.Hijacked != tt.public {
				t.Fatalf("peer/hijack: %+v", r)
			}
		})
	}
}

// TestHTTPSIntermediateFromHandshake: intermediates the server sends are used to build the
// chain, as in any TLS client, and the recorded hash is the leaf's, not another chain member's.
func TestHTTPSIntermediateFromHandshake(t *testing.T) {
	root := issueCert(t, caTmpl("att-monitor test root"), nil)
	inter := issueCert(t, caTmpl("att-monitor test intermediate"), root)
	leaf := issueCert(t, validLeafTmpl(), inter)
	srv := startTLS(t, []*testCert{leaf, inter}, nil)

	p := New(Options{})
	p.rootCAs = certPool(root.cert)
	r := p.HTTP(context.Background(), "google_204", srv.URL+"/generate_204", 204, "", 2*time.Second)
	if !r.OK || r.Err != "" {
		t.Fatalf("got %+v", r)
	}
	if r.TLSCertSHA256 != sha256Hex(leaf.cert.Raw) {
		t.Fatalf("TLSCertSHA256 = %q, want the leaf %s (intermediate %s, root %s)", r.TLSCertSHA256,
			sha256Hex(leaf.cert.Raw), sha256Hex(inter.cert.Raw), sha256Hex(root.cert.Raw))
	}
	// The same chain for a host it does not name fails, despite the trusted root.
	routeDial(p, srv.Listener.Addr().String(), "203.0.113.7:443")
	r = p.HTTP(context.Background(), "google_204", "https://www.google.com/generate_204", 204, "", 2*time.Second)
	if r.OK || !strings.Contains(r.Err, "not www.google.com") || r.TLSCertSHA256 != sha256Hex(leaf.cert.Raw) {
		t.Fatalf("wrong host: %+v", r)
	}
}

// TestHTTPSHandshakeFailureAfterVerification: the certificate verified, then the handshake
// failed (here the server demands a client certificate; an interceptor replaying a genuine
// certificate without its key fails at the same stage). The presented certificate is still
// recorded.
func TestHTTPSHandshakeFailureAfterVerification(t *testing.T) {
	srv := startTLS(t, nil, &tls.Config{MaxVersion: tls.VersionTLS12, ClientAuth: tls.RequireAnyClientCert})
	p := New(Options{})
	p.rootCAs = certPool(srv.Certificate())
	r := p.HTTP(context.Background(), "google_204", srv.URL+"/generate_204", 204, "", 2*time.Second)
	if r.OK || r.Status != 0 || !strings.Contains(r.Err, "remote error: tls: ") {
		t.Fatalf("got %+v", r)
	}
	if r.TLSCertSHA256 != sha256Hex(srv.Certificate().Raw) {
		t.Fatalf("TLSCertSHA256 = %q, want %s", r.TLSCertSHA256, sha256Hex(srv.Certificate().Raw))
	}
}

func TestHTTPPlainHasNoCertificate(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "Microsoft Connect Test")
	}))
	defer srv.Close()
	r := New(Options{}).HTTP(context.Background(), "msft_connecttest", srv.URL+"/connecttest.txt", 200, "Microsoft Connect Test", 2*time.Second)
	if !r.OK || r.TLSCertSHA256 != "" {
		t.Fatalf("got %+v", r)
	}
	if b, _ := json.Marshal(r); strings.Contains(string(b), "tls_cert_sha256") {
		t.Fatalf("plain HTTP record mentions a certificate: %s", b)
	}
	// A server that does not speak TLS on an https:// URL presents no certificate.
	r = New(Options{}).HTTP(context.Background(), "google_204", "https://"+srv.Listener.Addr().String()+"/", 204, "", 2*time.Second)
	if r.OK || r.TLSCertSHA256 != "" || r.Err == "" {
		t.Fatalf("plain server on https: %+v", r)
	}
}

// TestHTTPSConcurrentChecksKeepTheirOwnCertificate: every check records the certificate of
// its own connection, also when checks run at the same time, and the shared transport
// template is never modified.
func TestHTTPSConcurrentChecksKeepTheirOwnCertificate(t *testing.T) {
	root := issueCert(t, caTmpl("att-monitor test root"), nil)
	good := issueCert(t, validLeafTmpl(), root)
	rogue := issueCert(t, validLeafTmpl(), nil) // self-signed: does not verify
	goodSrv := startTLS(t, []*testCert{good}, nil)
	rogueSrv := startTLS(t, []*testCert{rogue}, nil)

	p := New(Options{})
	p.rootCAs = certPool(root.cert)
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		srv, leaf, wantOK := goodSrv, good, true
		if i%2 == 1 {
			srv, leaf, wantOK = rogueSrv, rogue, false
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := p.HTTP(context.Background(), "google_204", srv.URL+"/generate_204", 204, "", 5*time.Second)
			if r.OK != wantOK || r.TLSCertSHA256 != sha256Hex(leaf.cert.Raw) {
				t.Errorf("check against %s: OK %v cert %s, want OK %v cert %s (err %q)", srv.URL,
					r.OK, r.TLSCertSHA256, wantOK, sha256Hex(leaf.cert.Raw), r.Err)
			}
		}()
	}
	wg.Wait()
	if c := p.transport.TLSClientConfig; c.VerifyConnection != nil || c.RootCAs != nil || c.InsecureSkipVerify {
		t.Fatal("per-check TLS settings leaked into the shared transport template")
	}
}

// TestHTTPSAbandonedHandshakeIsClosed: net/http keeps dialing (and handshaking) after the
// request that started the dial gave up. A server that accepts but never answers the TLS
// ClientHello must not keep that connection - one per check - open after the check ended.
func TestHTTPSAbandonedHandshakeIsClosed(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	const serverPatience = 5 * time.Second
	closed := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			closed <- err
			return
		}
		defer c.Close()
		_ = c.SetReadDeadline(time.Now().Add(serverPatience))
		buf := make([]byte, 4096)
		for { // swallow the ClientHello, never answer
			if _, err := c.Read(buf); err != nil {
				closed <- err
				return
			}
		}
	}()

	start := time.Now()
	r := New(Options{}).HTTP(context.Background(), "google_204", "https://"+ln.Addr().String()+"/", 204, "", 300*time.Millisecond)
	if el := time.Since(start); el > 2*time.Second {
		t.Fatalf("check took %v with a 300ms timeout", el)
	}
	if r.OK || r.Err == "" || r.TLSCertSHA256 != "" {
		t.Fatalf("got %+v", r)
	}
	select {
	case err := <-closed:
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			t.Fatalf("the abandoned TLS handshake stayed open until the server gave up after %v", serverPatience)
		}
		if el := time.Since(start); el > 3*time.Second {
			t.Fatalf("connection closed only after %v", el)
		}
	case <-time.After(serverPatience + 2*time.Second):
		t.Fatal("the server never saw the connection end")
	}
}
