package probe

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"
)

// rep is U+FFFD, the replacement for invalid UTF-8.
const rep = string(utf8.RuneError)

func sha256Hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// remoteConn makes a connection report another peer address (to emulate a public server
// while actually talking to an httptest listener).
type remoteConn struct {
	net.Conn
	remote net.Addr
}

func (c remoteConn) RemoteAddr() net.Addr { return c.remote }

// routeDial sends every dial to target, records the requested addresses, and, when
// fakeRemote is set, wraps the connection so it reports that peer address.
func routeDial(p *Prober, target, fakeRemote string) func() []string {
	var mu sync.Mutex
	var seen []string
	var d net.Dialer
	p.dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		mu.Lock()
		seen = append(seen, address)
		mu.Unlock()
		c, err := d.DialContext(ctx, network, target)
		if err != nil || fakeRemote == "" {
			return c, err
		}
		return remoteConn{Conn: c, remote: net.TCPAddrFromAddrPort(netip.MustParseAddrPort(fakeRemote))}, nil
	}
	return func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), seen...)
	}
}

func TestHTTPChecks(t *testing.T) {
	big := bytes.Repeat([]byte("0123456789abcdef"), 200<<10/16) // 200 KiB
	latin1 := []byte("Copyright \xa9 2026 AT&T Intellectual Property")
	boundary := []byte(strings.Repeat("a", 511) + "é tail")
	var targetHits atomic.Int32

	mux := http.NewServeMux()
	mux.HandleFunc("/connecttest.txt", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "Microsoft Connect Test")
	})
	mux.HandleFunc("/generate_204", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })
	mux.HandleFunc("/redirect", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "/target")
		w.WriteHeader(http.StatusFound)
		io.WriteString(w, "<html>moved</html>")
	})
	mux.HandleFunc("/target", func(w http.ResponseWriter, r *http.Request) {
		targetHits.Add(1)
		io.WriteString(w, "Microsoft Connect Test")
	})
	mux.HandleFunc("/big", func(w http.ResponseWriter, r *http.Request) { w.Write(big) })
	mux.HandleFunc("/latin1", func(w http.ResponseWriter, r *http.Request) { w.Write(latin1) })
	mux.HandleFunc("/boundary", func(w http.ResponseWriter, r *http.Request) { w.Write(boundary) })
	srv := httptest.NewServer(mux)
	defer srv.Close()

	tests := []struct {
		name         string
		path         string
		expectStatus int
		expectBody   string
		wantOK       bool
		wantStatus   int
		wantLocation string
		wantSHA      string
		wantPrefix   string
	}{
		{"200 body match", "/connecttest.txt", 200, "Microsoft Connect Test", true, 200, "",
			sha256Hex([]byte("Microsoft Connect Test")), "Microsoft Connect Test"},
		{"200 body mismatch", "/connecttest.txt", 200, "Something Else", false, 200, "",
			sha256Hex([]byte("Microsoft Connect Test")), "Microsoft Connect Test"},
		{"204 expected", "/generate_204", 204, "", true, 204, "", sha256Hex(nil), ""},
		{"204 with any-2xx", "/generate_204", 0, "", true, 204, "", sha256Hex(nil), ""},
		{"200 when 204 expected", "/connecttest.txt", 204, "", false, 200, "", "", ""},
		{"302 captured, not followed", "/redirect", 200, "Microsoft Connect Test", false, 302, "/target",
			sha256Hex([]byte("<html>moved</html>")), "<html>moved</html>"},
		{"302 with any-2xx", "/redirect", 0, "", false, 302, "/target", "", ""},
		{"body cap", "/big", 200, "", true, 200, "", sha256Hex(big[:64<<10]), string(big[:512])},
		{"latin-1 body", "/latin1", 200, "", true, 200, "", sha256Hex(latin1),
			"Copyright " + rep + " 2026 AT&T Intellectual Property"},
		{"multi-byte char cut at 512", "/boundary", 200, "", true, 200, "", sha256Hex(boundary), strings.Repeat("a", 511)},
		{"404", "/missing", 0, "", false, 404, "", "", ""},
	}
	p := New(Options{UserAgent: "att-monitor-test/1"})
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := srv.URL + tt.path
			r := p.HTTP(context.Background(), "check_"+tt.name, u, tt.expectStatus, tt.expectBody, 2*time.Second)
			if r.Name != "check_"+tt.name || r.URL != u {
				t.Errorf("identity: %+v", r)
			}
			if r.OK != tt.wantOK || r.Status != tt.wantStatus || r.Location != tt.wantLocation {
				t.Errorf("OK/Status/Location = %v/%d/%q, want %v/%d/%q (err %q)",
					r.OK, r.Status, r.Location, tt.wantOK, tt.wantStatus, tt.wantLocation, r.Err)
			}
			if tt.wantSHA != "" && r.BodySHA256 != tt.wantSHA {
				t.Errorf("BodySHA256 = %s, want %s", r.BodySHA256, tt.wantSHA)
			}
			if tt.wantSHA != "" && r.BodyPrefix != tt.wantPrefix {
				t.Errorf("BodyPrefix = %q, want %q", r.BodyPrefix, tt.wantPrefix)
			}
			if !utf8.ValidString(r.BodyPrefix) || len(r.BodyPrefix) > 3*bodyPrefixLen {
				t.Errorf("BodyPrefix invalid or too long (%d bytes)", len(r.BodyPrefix))
			}
			if r.RemoteAddr != srv.Listener.Addr().String() {
				t.Errorf("RemoteAddr = %q, want %q", r.RemoteAddr, srv.Listener.Addr())
			}
			if r.RTTus <= 0 || r.Err != "" || r.Hijacked || r.TLSCertSHA256 != "" {
				t.Errorf("RTT/Err/Hijacked/TLSCertSHA256: %+v", r)
			}
		})
	}
	if n := targetHits.Load(); n != 0 {
		t.Fatalf("redirect was followed (%d hits on /target)", n)
	}
}

func TestHTTPRequestShape(t *testing.T) {
	var mu sync.Mutex
	var ua, ae string
	var conns atomic.Int32
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		ua, ae = r.UserAgent(), r.Header.Get("Accept-Encoding")
		mu.Unlock()
		// A gzip body the client did not ask for must be hashed as sent, not decoded.
		var buf bytes.Buffer
		zw := gzip.NewWriter(&buf)
		zw.Write([]byte("hello"))
		zw.Close()
		w.Header().Set("Content-Encoding", "gzip")
		w.Write(buf.Bytes())
	}))
	srv.Config.ConnState = func(c net.Conn, s http.ConnState) {
		if s == http.StateNew {
			conns.Add(1)
		}
	}
	srv.Start()
	defer srv.Close()

	p := New(Options{UserAgent: "att-monitor-test/2"})
	r1 := p.HTTP(context.Background(), "a", srv.URL, 0, "", 2*time.Second)
	r2 := p.HTTP(context.Background(), "b", srv.URL, 0, "", 2*time.Second)
	if !r1.OK || !r2.OK {
		t.Fatalf("r1 %+v r2 %+v", r1, r2)
	}
	mu.Lock()
	defer mu.Unlock()
	if ua != "att-monitor-test/2" {
		t.Errorf("User-Agent = %q", ua)
	}
	if ae != "" {
		t.Errorf("Accept-Encoding = %q, want none (exact bytes)", ae)
	}
	if r1.BodyPrefix == "hello" {
		t.Error("gzip body was transparently decoded")
	}
	if n := conns.Load(); n != 2 {
		t.Errorf("server saw %d connections for 2 checks, want 2 (keep-alive disabled)", n)
	}
	if New(Options{}).userAgent != "att-monitor" {
		t.Error("default User-Agent")
	}
}

func TestHTTPHijackViaLocation(t *testing.T) {
	// The gateway-style hijack: a public URL answered with a redirect to 192.168.1.254.
	t.Setenv("HTTP_PROXY", "http://192.0.2.1:3128") // must be ignored: direct measurement only
	t.Setenv("http_proxy", "http://192.0.2.1:3128")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "www.msftconnecttest.com" {
			t.Errorf("Host header %q", r.Host)
		}
		w.Header().Set("Location", "http://192.168.1.254/cgi-bin/redirect.ha?url=www.msftconnecttest.com")
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()
	p := New(Options{})
	seen := routeDial(p, srv.Listener.Addr().String(), "203.0.113.80:80")
	r := p.HTTP(context.Background(), "msft_connecttest", "http://www.msftconnecttest.com/connecttest.txt",
		200, "Microsoft Connect Test", 2*time.Second)
	if r.OK || r.Status != 302 || !r.Hijacked {
		t.Fatalf("got %+v", r)
	}
	if r.Location != "http://192.168.1.254/cgi-bin/redirect.ha?url=www.msftconnecttest.com" {
		t.Errorf("Location = %q", r.Location)
	}
	if !strings.Contains(r.HijackWhy, "redirected to http://192.168.1.254/") ||
		!strings.Contains(r.HijackWhy, "gateway's own address") || strings.Contains(r.HijackWhy, "connected to") {
		t.Errorf("HijackWhy = %q", r.HijackWhy)
	}
	if r.RemoteAddr != "203.0.113.80:80" {
		t.Errorf("RemoteAddr = %q", r.RemoteAddr)
	}
	if got := seen(); len(got) != 1 || got[0] != "www.msftconnecttest.com:80" {
		t.Errorf("dialed %v, want the origin directly (no proxy)", got)
	}
}

func TestHTTPHijackViaPeerAddress(t *testing.T) {
	// A public name answered from a non-public address (e.g. DNS hijacked to the gateway).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "Microsoft Connect Test")
	}))
	defer srv.Close()
	p := New(Options{})
	routeDial(p, srv.Listener.Addr().String(), "")
	r := p.HTTP(context.Background(), "msft_connecttest", "http://www.msftconnecttest.com/connecttest.txt",
		200, "Microsoft Connect Test", 2*time.Second)
	if !r.OK || !r.Hijacked || r.RemoteAddr != srv.Listener.Addr().String() {
		t.Fatalf("got %+v", r)
	}
	if !strings.Contains(r.HijackWhy, "connected to "+srv.Listener.Addr().String()+", a loopback address, for public host www.msftconnecttest.com") {
		t.Errorf("HijackWhy = %q", r.HijackWhy)
	}
}

func TestHTTPSFailureStillRecordsPeer(t *testing.T) {
	// A TLS interception (certificate not valid for the name) fails the check, but the
	// peer address is still captured from the TCP connect and judged.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	p := New(Options{})
	r := p.HTTP(context.Background(), "local_tls", srv.URL, 204, "", 2*time.Second)
	if r.OK || r.Status != 0 || !strings.Contains(r.Err, "certificate") {
		t.Fatalf("got %+v", r)
	}
	if r.RemoteAddr != srv.Listener.Addr().String() || r.Hijacked {
		t.Fatalf("peer/hijack: %+v", r)
	}
	if want := sha256Hex(srv.Certificate().Raw); r.TLSCertSHA256 != want {
		t.Fatalf("TLSCertSHA256 = %q, want the presented certificate %s", r.TLSCertSHA256, want)
	}

	routeDial(p, srv.Listener.Addr().String(), "")
	r = p.HTTP(context.Background(), "google_204", "https://www.google.com/generate_204", 204, "", 2*time.Second)
	if r.OK || !r.Hijacked || !strings.Contains(r.HijackWhy, "loopback") || r.RTTus != 0 {
		t.Fatalf("got %+v", r)
	}
}

func TestHTTPFailures(t *testing.T) {
	p := New(Options{})

	// Timeout while the server stalls.
	release := make(chan struct{})
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer slow.Close()
	defer close(release)
	start := time.Now()
	r := p.HTTP(context.Background(), "slow", slow.URL, 0, "", 200*time.Millisecond)
	if el := time.Since(start); el > time.Second {
		t.Errorf("timeout took %v", el)
	}
	if r.OK || r.Status != 0 || r.Err == "" || r.RTTus != 0 {
		t.Errorf("timeout: %+v", r)
	}

	// Refused.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closed := "http://" + ln.Addr().String() + "/"
	ln.Close()
	r = p.HTTP(context.Background(), "refused", closed, 0, "", 5*time.Second)
	if r.OK || !strings.Contains(r.Err, "refused") || r.RemoteAddr != "" {
		t.Errorf("refused: %+v", r)
	}

	// Bad URLs.
	for _, u := range []string{"ftp://example.com/x", "http://", "://bad", "not a url"} {
		if r := p.HTTP(context.Background(), "bad", u, 0, "", time.Second); r.OK || r.Err == "" {
			t.Errorf("HTTP(%q) = %+v, want error", u, r)
		}
	}

	// Pre-canceled.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if r := p.HTTP(ctx, "c", slow.URL, 0, "", time.Second); r.OK || !strings.HasPrefix(r.Err, "canceled") {
		t.Errorf("canceled: %+v", r)
	}
}

func TestPrefixUTF8(t *testing.T) {
	tests := []struct {
		in   string
		n    int
		want string
	}{
		{"hello", 512, "hello"},
		{"", 512, ""},
		{"hello", 3, "hel"},
		{"a\xc3\xa9", 2, "a"},                  // e-acute (2 bytes) cut after its first byte: dropped
		{"a\xc3\xa9", 3, "a\xc3\xa9"},          // fits exactly
		{"a\xe2\x82\xacb", 3, "a"},             // euro sign (3 bytes) cut after 2 bytes: dropped
		{"a\xe2\x82\xacb", 4, "a\xe2\x82\xac"}, // fits exactly
		{"a\xf0\x9f\x98\x80", 4, "a"},          // 4-byte rune cut after 3 bytes: dropped
		{"a\xa9b", 512, "a" + rep + "b"},       // Latin-1 copyright byte
		{"a\xa9bc", 2, "a" + rep},              // stray continuation byte at the cut: replaced
		{"ab\xff", 3, "ab" + rep},              // invalid byte
		{"ab\xe2\x82", 4, "ab" + rep},          // incomplete at the real end (not cut by n): replaced
		{"\xa9\xa9\xa9", 512, rep},             // a run of invalid bytes becomes one U+FFFD
		{strings.Repeat("x", 600), 512, strings.Repeat("x", 512)},
	}
	for _, tt := range tests {
		if got := prefixUTF8([]byte(tt.in), tt.n); got != tt.want {
			t.Errorf("prefixUTF8(%q, %d) = %q, want %q", tt.in, tt.n, got, tt.want)
		}
	}
}
