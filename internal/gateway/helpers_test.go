package gateway

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf16"
)

// Byte sequences that cannot be typed safely in source.
const (
	nbspUTF8   = "\xc2\xa0"     // U+00A0 NO-BREAK SPACE encoded as UTF-8
	nbspLatin1 = "\xa0"         // raw windows-1252 no-break space (invalid UTF-8)
	copyLatin1 = "\xa9"         // raw windows-1252 copyright sign (invalid UTF-8)
	replChar   = "\xef\xbf\xbd" // U+FFFD REPLACEMENT CHARACTER
)

// fixture returns a file from testdata/gateway.
func fixture(t testing.TB, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "testdata", "gateway", name))
	if err != nil {
		t.Fatalf("fixture %s: %v", name, err)
	}
	return b
}

// sub applies a regexp replacement and fails the test if the pattern does not match, so that
// fixture edits cannot silently become no-ops.
func sub(t testing.TB, body []byte, pattern, repl string) []byte {
	t.Helper()
	re := regexp.MustCompile(pattern)
	if !re.Match(body) {
		t.Fatalf("pattern %q does not match the fixture", pattern)
	}
	return re.ReplaceAll(body, []byte(repl))
}

func sha256hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func md5hex(s string) string {
	h := md5.Sum([]byte(s))
	return hex.EncodeToString(h[:])
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

// fakeClock is a manually advanced clock for the login policy.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{t: time.Date(2026, 10, 5, 3, 10, 43, 0, time.UTC)}
}

func (f *fakeClock) Now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.t
}

func (f *fakeClock) Advance(d time.Duration) {
	f.mu.Lock()
	f.t = f.t.Add(d)
	f.mu.Unlock()
}

// syncBuffer is a goroutine-safe log sink.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func debugLogger(buf *syncBuffer) *slog.Logger {
	return slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// ---------------------------------------------------------------- mock gateway

// mockGateway imitates the BGW320 web UI as observed on firmware 6.34.7 (docs/DESIGN.md §2):
// cookie handshake, nonce login with MD5(code+nonce), events.ha form with nonce and the
// bbevent checkbox, status pages readable without login.
type mockGateway struct {
	t    testing.TB
	code string

	mu       sync.Mutex
	sessions map[string]*mockSession
	bbevent  bool

	// behaviour switches
	sessionsFull    bool // every response is the "sessions in use" page
	fullOnLoginPost bool // only the login POST answers "sessions in use"
	neverNonce      bool // the login page never carries a nonce
	redirectToLogin bool // protected pages answer 302 -> /cgi-bin/login.ha
	rejectWith302   bool // a rejected login answers 302 -> /cgi-bin/login.ha (else 200 login page)
	rejectAs302Home bool // a rejected login answers 302 -> /cgi-bin/events.ha, exactly like a success
	ignoreSave      bool // POST events.ha does not change the setting
	pages           map[string][]byte

	// observations
	requests   int
	byPath     map[string]int
	loginForms []url.Values
	eventForms []url.Values
	referers   []string
	rawBodies  []string // raw POST bodies, in order
}

type mockSession struct {
	seen        int
	authed      bool
	justSaved   bool
	loginNonce  string
	eventsNonce string
}

func newMockGateway(t testing.TB, code string, bbevent bool) *mockGateway {
	return &mockGateway{
		t:        t,
		code:     code,
		bbevent:  bbevent,
		sessions: map[string]*mockSession{},
		byPath:   map[string]int{},
		pages: map[string][]byte{
			"sysinfo":             fixture(t, "sysinfo.html"),
			"broadbandstatistics": fixture(t, "broadbandstatistics.html"),
			"fiberstat":           fixture(t, "fiberstat.html"),
			"lanstatistics":       fixture(t, "lanstatistics.html"),
			"hiddenpage":          fixture(t, "hiddenpage.html"),
		},
	}
}

var reNonceValue = regexp.MustCompile(`(name="nonce" value=")[0-9a-f]+(")`)

func withNonce(page []byte, nonce string) []byte {
	return reNonceValue.ReplaceAll(page, []byte("${1}"+nonce+"${2}"))
}

// sessionsFullPage is the login page carrying the gateway's session-pool message.
func sessionsFullPage(t testing.TB) []byte {
	return bytes.Replace(fixture(t, "login_handshake1.html"), []byte("<h1 style=\"text-align:center;\">"),
		[]byte("<div id=\"error-message\"><div id=\"error-message-text\">\r\nAll web server sessions are in use.\r\n</div></div>\r\n<h1 style=\"text-align:center;\">"), 1)
}

func (m *mockGateway) counts() (requests int, loginPosts int, eventPosts int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.requests, len(m.loginForms), len(m.eventForms)
}

func (m *mockGateway) setting() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.bbevent
}

func (m *mockGateway) expireSessions() {
	m.mu.Lock()
	m.sessions = map[string]*mockSession{}
	m.mu.Unlock()
}

func (m *mockGateway) set(f func(m *mockGateway)) {
	m.mu.Lock()
	f(m)
	m.mu.Unlock()
}

// session returns the caller's session, creating one (and setting the cookie) if needed.
func (m *mockGateway) session(w http.ResponseWriter, r *http.Request) (*mockSession, bool) {
	if c, err := r.Cookie("SessionID"); err == nil {
		if s, ok := m.sessions[c.Value]; ok {
			return s, false
		}
	}
	id := randomHex(8)
	s := &mockSession{}
	m.sessions[id] = s
	http.SetCookie(w, &http.Cookie{Name: "SessionID", Value: id, Path: "/"})
	return s, true
}

func (m *mockGateway) write(w http.ResponseWriter, status int, body []byte) {
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

// loginPage answers a request that needs authentication.
func (m *mockGateway) loginPage(w http.ResponseWriter, s *mockSession, fresh bool) {
	s.seen++
	if fresh || m.neverNonce {
		m.write(w, http.StatusOK, fixture(m.t, "login_handshake1.html"))
		return
	}
	s.loginNonce = randomHex(32)
	m.write(w, http.StatusOK, withNonce(fixture(m.t, "login_nonce.html"), s.loginNonce))
}

func (m *mockGateway) eventsPage(w http.ResponseWriter, s *mockSession, saved bool) {
	s.eventsNonce = randomHex(32)
	name := "events_unchecked.html"
	if m.bbevent {
		name = "events_checked.html"
	}
	page := fixture(m.t, name)
	if !saved { // only the page right after a save carries "Changes saved"
		page = regexp.MustCompile(`(?s)<div id="error-message">.*?<div style="clear: both;"></div>\s*</div>`).ReplaceAll(page, nil)
	}
	m.write(w, http.StatusOK, withNonce(page, s.eventsNonce))
}

func (m *mockGateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.requests++
	m.byPath[r.Method+" "+r.URL.Path]++
	if m.sessionsFull {
		m.write(w, http.StatusOK, sessionsFullPage(m.t))
		return
	}
	page := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/cgi-bin/"), ".ha")
	switch {
	case r.Method == http.MethodGet && (page == "events" || page == "login"):
		s, fresh := m.session(w, r)
		if page == "events" && s.authed {
			saved := s.justSaved
			s.justSaved = false
			m.eventsPage(w, s, saved)
			return
		}
		if page == "events" && m.redirectToLogin {
			w.Header().Set("Location", "/cgi-bin/login.ha")
			m.write(w, http.StatusFound, nil)
			return
		}
		m.loginPage(w, s, fresh && !m.redirectToLogin)
	case r.Method == http.MethodPost && page == "login":
		body := readBody(r)
		m.rawBodies = append(m.rawBodies, body)
		form, _ := url.ParseQuery(body)
		m.loginForms = append(m.loginForms, form)
		m.referers = append(m.referers, r.Header.Get("Referer"))
		if m.fullOnLoginPost {
			m.write(w, http.StatusOK, sessionsFullPage(m.t))
			return
		}
		s, fresh := m.session(w, r)
		ok := !fresh && s.loginNonce != "" &&
			form.Get("nonce") == s.loginNonce &&
			// The gateway's hashpwd() masks the field with one '*' per UTF-16 code unit
			// (JavaScript String.length) and hashes the UTF-8 bytes of code+nonce.
			form.Get("password") == strings.Repeat("*", len(utf16.Encode([]rune(m.code)))) &&
			form.Get("hashpassword") == md5hex(m.code+s.loginNonce) &&
			form.Get("Continue") == "Continue" &&
			r.Header.Get("Content-Type") == "application/x-www-form-urlencoded" &&
			r.Header.Get("Referer") != ""
		s.loginNonce = "" // single use
		if !ok {
			if m.rejectWith302 {
				w.Header().Set("Location", "/cgi-bin/login.ha")
				m.write(w, http.StatusFound, nil)
				return
			}
			if m.rejectAs302Home {
				w.Header().Set("Location", "/cgi-bin/events.ha")
				m.write(w, http.StatusFound, nil)
				return
			}
			m.loginPage(w, s, false)
			return
		}
		s.authed = true
		w.Header().Set("Location", "/cgi-bin/events.ha")
		m.write(w, http.StatusFound, nil)
	case r.Method == http.MethodPost && page == "events":
		body := readBody(r)
		m.rawBodies = append(m.rawBodies, body)
		form, _ := url.ParseQuery(body)
		m.eventForms = append(m.eventForms, form)
		m.referers = append(m.referers, r.Header.Get("Referer"))
		s, fresh := m.session(w, r)
		if fresh || !s.authed {
			m.loginPage(w, s, fresh)
			return
		}
		if form.Get("nonce") == s.eventsNonce && form.Get("Save") == "Save" && !m.ignoreSave {
			m.bbevent = form.Get("bbevent") == "on"
		}
		s.eventsNonce = ""
		s.justSaved = true
		w.Header().Set("Location", "/cgi-bin/events.ha")
		m.write(w, http.StatusFound, nil)
	case r.Method == http.MethodGet && page == "securityoptions":
		w.Header().Set("Location", "/cgi-bin/hiddenpage.ha")
		m.write(w, http.StatusFound, nil)
	case r.Method == http.MethodGet && m.pages[page] != nil:
		m.write(w, http.StatusOK, m.pages[page])
	default:
		m.write(w, http.StatusNotFound, []byte("not found"))
	}
}

func readBody(r *http.Request) string {
	var b bytes.Buffer
	_, _ = b.ReadFrom(r.Body)
	return b.String()
}

// newTestClient returns a client for srv with fast handshake backoff.
func newTestClient(t testing.TB, srv *httptest.Server, clk *fakeClock, code string, log *syncBuffer) *Client {
	t.Helper()
	scheme := "http"
	if srv.TLS != nil {
		scheme = "https"
	}
	opts := Options{
		Host:      strings.TrimPrefix(strings.TrimPrefix(srv.URL, "https://"), "http://"),
		Scheme:    scheme,
		Timeout:   5 * time.Second,
		UserAgent: "att-monitor/test",
		Location:  time.FixedZone("CDT", -5*3600),
	}
	if code != "" {
		opts.AccessCode = func() (string, error) { return code, nil }
	}
	if clk != nil {
		opts.Now = clk.Now
	}
	if log != nil {
		opts.Logger = debugLogger(log)
	}
	c := New(opts)
	c.handshakeBackoff = time.Millisecond
	return c
}

// mustNotContainSecret fails if s contains the access code or any login hash.
func mustNotContainSecret(t testing.TB, what, s, code string, hashes []string) {
	t.Helper()
	if strings.Contains(s, code) {
		t.Errorf("%s contains the access code: %q", what, s)
	}
	for _, h := range hashes {
		if h != "" && strings.Contains(s, h) {
			t.Errorf("%s contains a login hashpassword: %q", what, s)
		}
	}
}

func (m *mockGateway) hashes() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []string
	for _, f := range m.loginForms {
		out = append(out, f.Get("hashpassword"))
	}
	return out
}

// selfSignedCert returns a fresh self-signed certificate for 127.0.0.1 (like the gateway's,
// it chains to nothing; only its fingerprint identifies it).
func selfSignedCert(t testing.TB) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "BGW320-505 test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}
