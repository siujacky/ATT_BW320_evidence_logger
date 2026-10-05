package gateway

// Adversarial tests added by the independent review of this package. Each one pins down a
// behaviour that matters for the evidence (what the ledger will say happened) or for the
// gateway's safety (no unexpected logins, no crash of the evidence service).

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf16"

	"attmonitor/internal/model"
)

// ---------------------------------------------------------------- certificate pin input

// colonPairs writes a hex digest as "AB:CD:..." (or with another separator).
func colonPairs(h, sep string) string {
	var parts []string
	for i := 0; i+1 < len(h); i += 2 {
		parts = append(parts, h[i:i+2])
	}
	return strings.Join(parts, sep)
}

// TestNormalizePinForms: the pin is typed by a person, usually copied from openssl or a
// certificate viewer. Every common spelling of the same SHA-256 must pin the same
// certificate; anything that is not a SHA-256 fingerprint is kept exactly as configured (it
// never matches, so the observer decides and sees what was configured).
func TestNormalizePinForms(t *testing.T) {
	const h = documentedCertSHA256
	up := strings.ToUpper(h)
	tests := []struct{ in, want string }{
		{h, h},
		{up, h},
		{colonPairs(up, ":"), h},
		{colonPairs(h, " "), h},
		{colonPairs(up, "-"), h},
		{"  " + h + "\t\r\n", h},
		{"SHA256:" + colonPairs(up, ":"), h}, // openssl 1.1: "SHA256 Fingerprint=" variants
		{"sha256 Fingerprint=" + colonPairs(up, ":"), h}, // openssl 3 x509 -fingerprint -sha256
		{"SHA256 Fingerprint: " + colonPairs(h, " "), h}, // certificate viewers
		{"SHA-256: " + h, h},
		{"sha256/" + h, h},
		{"", ""},
		{"   ", ""},
		{"not a fingerprint", "not a fingerprint"},
		{h[:62], h[:62]},
		{h + "00", h + "00"},
		{"sha256:" + h[:63] + "g", "sha256:" + h[:63] + "g"},
	}
	for _, tt := range tests {
		if got := normalizePin(tt.in); got != tt.want {
			t.Errorf("normalizePin(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// TestTLSPinWithOpensslPrefixMatches: a pin pasted from "openssl x509 -fingerprint -sha256"
// must match the certificate it describes. Before the fix it was compared as
// "sha25649cd..." and the genuine gateway was rejected (or, with the monitor's accepting
// observer, recorded as a bogus "cert_changed" event).
func TestTLSPinWithOpensslPrefixMatches(t *testing.T) {
	srv, _, certSHA := newTLSGateway(t)
	o := &observerLog{answer: false}
	c := tlsClient(srv, "sha256 Fingerprint="+colonPairs(strings.ToUpper(certSHA), ":"), o.observe)
	if c.PinnedCert() != certSHA {
		t.Fatalf("PinnedCert = %q, want %q", c.PinnedCert(), certSHA)
	}
	snap, _, err := c.Snapshot(context.Background(), []string{"sysinfo"}, "test")
	if err != nil || snap.Pages[0].Err != "" {
		t.Fatalf("err=%v capture=%+v", err, snap.Pages[0])
	}
	if calls := o.get(); len(calls) != 0 {
		t.Errorf("observer consulted although the pin matches: %v", calls)
	}
}

// TestInvalidPinFailsClosedAndIsReportedAsConfigured: a configured value that is not a
// fingerprint never matches; without an observer the certificate is rejected and the
// observer (when present) is shown the value exactly as configured.
func TestInvalidPinFailsClosedAndIsReportedAsConfigured(t *testing.T) {
	srv, h, certSHA := newTLSGateway(t)
	c := tlsClient(srv, "Gateway-Cert", nil)
	if _, _, err := c.Snapshot(context.Background(), []string{"sysinfo"}, "test"); !errors.Is(err, ErrCertRejected) && (err == nil || !strings.Contains(err.Error(), "does not match pinned")) {
		t.Fatalf("err = %v, want a certificate rejection", err)
	}
	if h.n.Load() != 0 {
		t.Errorf("%d requests reached the server", h.n.Load())
	}
	o := &observerLog{answer: true}
	c2 := tlsClient(srv, "Gateway-Cert", o.observe)
	if _, _, err := c2.Snapshot(context.Background(), []string{"sysinfo"}, "test"); err != nil {
		t.Fatal(err)
	}
	if calls := o.get(); len(calls) != 1 || calls[0] != [2]string{"Gateway-Cert", certSHA} {
		t.Errorf("observer calls = %v, want one (configured value, observed)", calls)
	}
}

// ---------------------------------------------------------------- certificate observer robustness

// TestObserverPanicFailsClosed: the observer runs inside the TLS handshake on a net/http
// transport goroutine, where a panic would crash the whole evidence service (a monitoring
// gap). A panicking observer must be treated as a rejection.
func TestObserverPanicFailsClosed(t *testing.T) {
	srv, h, certSHA := newTLSGateway(t)
	var logs syncBuffer
	c := New(Options{Host: strings.TrimPrefix(srv.URL, "https://"), Scheme: "https", Timeout: 5 * time.Second, Logger: debugLogger(&logs)})
	c.SetCertObserver(func(prev, observed string) bool { panic("observer bug") })
	snap, _, err := c.Snapshot(context.Background(), []string{"sysinfo", "fiberstat"}, "test")
	if err == nil {
		t.Fatal("Snapshot succeeded although the certificate decision failed")
	}
	pc := snap.Pages[0]
	if pc.TLSCertSHA256 != certSHA || !strings.Contains(pc.Err, "observer") {
		t.Errorf("capture = %+v", pc)
	}
	if c.PinnedCert() != "" {
		t.Errorf("PinnedCert = %q after a failed decision", c.PinnedCert())
	}
	if h.n.Load() != 0 {
		t.Errorf("%d requests reached the server", h.n.Load())
	}
	if !strings.Contains(logs.String(), "observer bug") {
		t.Error("the observer panic is not in the operational log")
	}
}

// slowAcceptListener delays every accepted connection, so the TLS handshake (done by the
// server on its first read) is held up for delay.
type slowAcceptListener struct {
	net.Listener
	delay time.Duration
}

func (l *slowAcceptListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err == nil {
		time.Sleep(l.delay)
	}
	return conn, err
}

// TestAbandonedHandshakeMakesNoPinDecision: when the caller gives up (service stop,
// snapshot deadline) while the TLS handshake is still running, the handshake must be
// abandoned too. Before the fix net/http's detached dial kept running for up to the full
// timeout, and the certificate observer was consulted - and the certificate pinned, i.e. a
// cert_pinned/cert_changed ledger record written - after Snapshot had already returned.
func TestAbandonedHandshakeMakesNoPinDecision(t *testing.T) {
	const delay = 600 * time.Millisecond
	srv := httptest.NewUnstartedServer(newMockGateway(t, "", false))
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.Listener = &slowAcceptListener{Listener: srv.Listener, delay: delay}
	srv.StartTLS()
	defer srv.Close()

	o := &observerLog{answer: true}
	c := tlsClient(srv, "", o.observe)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	snap, _, err := c.Snapshot(ctx, []string{"sysinfo"}, "test")
	if elapsed := time.Since(start); elapsed > delay-100*time.Millisecond {
		t.Errorf("Snapshot took %v after its context ended", elapsed)
	}
	if err == nil || snap.Pages[0].Status != 0 {
		t.Fatalf("err=%v capture=%+v", err, snap.Pages[0])
	}
	time.Sleep(delay + 600*time.Millisecond) // give an orphaned handshake every chance to finish
	if calls := o.get(); len(calls) != 0 {
		t.Errorf("observer consulted after Snapshot returned: %v", calls)
	}
	if pin := c.PinnedCert(); pin != "" {
		t.Errorf("certificate pinned after Snapshot returned: %q", pin)
	}
}

// ---------------------------------------------------------------- parsers: page identification

// TestParsersRejectOtherStatusPages: a parser must only accept its own page. Before the fix
// ParseSysInfo accepted broadbandstatistics (its "MAC Address" row), producing a SystemInfo
// with an empty Current Date/Time - which Derive reports as GatewayClockBlank, the gateway's
// own WAN-down indicator - and ParseBroadband accepted lanstatistics, presenting LAN-side
// counters and IPv6 addresses as the WAN's.
func TestParsersRejectOtherStatusPages(t *testing.T) {
	type parser struct {
		name string
		own  string
		fn   func([]byte) error
	}
	parsers := []parser{
		{"ParseSysInfo", "sysinfo.html", func(b []byte) error { _, err := ParseSysInfo(b); return err }},
		{"ParseBroadband", "broadbandstatistics.html", func(b []byte) error { _, err := ParseBroadband(b); return err }},
		{"ParseFiber", "fiberstat.html", func(b []byte) error { _, err := ParseFiber(b); return err }},
	}
	pages := []string{"sysinfo.html", "broadbandstatistics.html", "fiberstat.html", "lanstatistics.html", "home.html",
		"diag.html", "firewall.html", "sitemap.html", "broadbandconfig.html", "events_checked.html", "hiddenpage.html"}
	for _, p := range parsers {
		for _, page := range pages {
			err := p.fn(fixture(t, page))
			if page == p.own {
				if err != nil {
					t.Errorf("%s(%s) = %v", p.name, page, err)
				}
				continue
			}
			if !errors.Is(err, ErrUnexpectedPage) {
				t.Errorf("%s(%s) err = %v, want ErrUnexpectedPage", p.name, page, err)
			}
		}
	}
}

// TestSnapshotForeignPageRaisesNoClockBlank is the evidence-level consequence of the above: a
// sysinfo.ha answer that is not the System Information page must not make the snapshot claim
// that the gateway's clock is blank (the WAN-down indicator).
func TestSnapshotForeignPageRaisesNoClockBlank(t *testing.T) {
	m := newMockGateway(t, "", false)
	m.pages["sysinfo"] = fixture(t, "broadbandstatistics.html")
	srv := httptest.NewServer(m)
	defer srv.Close()
	c := newTestClient(t, srv, newFakeClock(), "", nil)
	snap, _, err := c.Snapshot(context.Background(), []string{"sysinfo"}, "test")
	if err != nil {
		t.Fatal(err)
	}
	if snap.System != nil || snap.Derived.GatewayClockBlank {
		t.Errorf("System=%+v GatewayClockBlank=%v", snap.System, snap.Derived.GatewayClockBlank)
	}
	if !strings.HasPrefix(snap.Pages[0].Err, "parse: ") {
		t.Errorf("Err = %q, want the parse failure recorded", snap.Pages[0].Err)
	}
}

// TestParseSysInfoPartialPagesStillParse: the stricter identification must not reject a real
// but incomplete System Information page.
func TestParseSysInfoPartialPagesStillParse(t *testing.T) {
	for _, label := range []string{"Model Number", "Serial Number", "Software Version", "Time Since Last Reboot", "Current Date/Time", "Hardware Version", "First Use Date"} {
		body := []byte(`<h1>System Information</h1><table><tr><th>MAC Address</th><td>00:00:5e:00:53:01</td></tr><tr><th>` + label + `</th><td>x</td></tr></table>`)
		if _, err := ParseSysInfo(body); err != nil {
			t.Errorf("page with %q: %v", label, err)
		}
	}
	for _, body := range []string{
		`<table><tr><th>MAC Address</th><td>00:00:5e:00:53:01</td></tr></table>`,
		`<table><tr><th>Manufacturer</th><td>NOKIA</td></tr><tr><th>MAC Address</th><td>x</td></tr></table>`,
	} {
		if _, err := ParseSysInfo([]byte(body)); !errors.Is(err, ErrUnexpectedPage) {
			t.Errorf("%s: err = %v, want ErrUnexpectedPage", body, err)
		}
	}
}

// TestParseBroadbandOutagePagesStillParse: the WAN-row requirement accepts every page that
// carries at least one row only the Broadband Status page has (e.g. an outage page that
// shows nothing but the connection state or the PON state).
func TestParseBroadbandOutagePagesStillParse(t *testing.T) {
	for _, label := range []string{"Broadband Connection Source", "Broadband Connection", "Broadband Network Type",
		"Broadband IPv4 Address", "Gateway IPv4 Address", "PON Link Status", "UNI Status"} {
		body := []byte(`<h2>Primary Broadband</h2><table><tr><th>` + label + `</th><td>Down</td></tr></table>`)
		bs, err := ParseBroadband(body)
		if err != nil {
			t.Errorf("page with %q: %v", label, err)
			continue
		}
		if bs.Values["Primary Broadband/"+label] != "Down" {
			t.Errorf("page with %q: Values = %v", label, bs.Values)
		}
	}
}

// ---------------------------------------------------------------- fiberstat completeness

// TestParseFiberKeepsEveryRowInDMISections: FiberStatus.Values is documented as "every
// label/value row". Rows inside a DMI block other than Alarm/Warning used to be dropped.
func TestParseFiberKeepsEveryRowInDMISections(t *testing.T) {
	page := []byte(`<table><tr><th>Optical WAN Operational Status</th><td>Up</td></tr></table>
<h1>Rx Power&nbsp;&nbsp;Currently -315</h1><table>
<tr><th>&nbsp;</th><th>Low</th><th>High</th></tr>
<tr><td>Alarm</td><td>1 (Threshold -295)</td><td>0 (Threshold -90)</td></tr>
<tr><td>Warning</td><td>1 (Threshold -292)</td><td>0 (Threshold -100)</td></tr>
<tr><td>Average</td><td>-310</td><td></td></tr>
</table>
<table><tr><th>Laser Age</th><td>12</td></tr></table>`)
	fs, err := ParseFiber(page)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range map[string]string{
		"Optical WAN Operational Status": "Up",
		"Rx Power/Current":               "-315",
		"Rx Power/Low Alarm":             "1 (Threshold -295)",
		"Rx Power/Average":               "-310",
		"Rx Power/Laser Age":             "12",
	} {
		if got, ok := fs.Values[k]; !ok || got != v {
			t.Errorf("Values[%q] = %q (present %v), want %q", k, got, ok, v)
		}
	}
	if len(fs.Measures) != 1 || !fs.Measures[0].LowAlarm.Active {
		t.Errorf("Measures = %+v", fs.Measures)
	}
}

// ---------------------------------------------------------------- login policy

// TestLoginVerifyRedirectCountsAsFailure: on firmware that redirects protected pages to
// login.ha (the handshake variant this client supports), a wrong access code answered with
// a success-looking 302 is only revealed by the verifying GET being redirected to login.ha.
// That is a rejected login and must count toward the 3-per-hour limit; before the fix it was
// an "unexpected HTTP status" and a wrong code was retried every minute forever.
func TestLoginVerifyRedirectCountsAsFailure(t *testing.T) {
	m := newMockGateway(t, "the-real-code", true)
	m.redirectToLogin = true
	m.rejectAs302Home = true
	srv := httptest.NewServer(m)
	defer srv.Close()
	clk := newFakeClock()
	c := newTestClient(t, srv, clk, testCode, nil)
	ctx := context.Background()
	for i := 1; i <= maxFailures; i++ {
		if _, _, err := c.Notification(ctx); !errors.Is(err, ErrAuth) {
			t.Fatalf("attempt %d: err = %v, want ErrAuth", i, err)
		}
		clk.Advance(loginSpacing + time.Second)
	}
	req, _, _ := m.counts()
	if _, _, err := c.Notification(ctx); !errors.Is(err, ErrAuthLocked) {
		t.Fatalf("after %d rejected logins: err = %v, want ErrAuthLocked", maxFailures, err)
	}
	if after, _, _ := m.counts(); after != req {
		t.Error("a locked client contacted the gateway")
	}
}

// TestLoginNonASCIIAccessCode: the password mask has one '*' per UTF-16 code unit and the
// hash covers the UTF-8 bytes of code+nonce, exactly as the gateway's JavaScript computes it.
func TestLoginNonASCIIAccessCode(t *testing.T) {
	const code = "Zq7#\U0001F600é" // 6 runes, 7 UTF-16 units, 11 UTF-8 bytes
	m := newMockGateway(t, code, false)
	srv := httptest.NewServer(m)
	defer srv.Close()
	c := newTestClient(t, srv, newFakeClock(), code, nil)
	if _, _, err := c.Notification(context.Background()); err != nil {
		t.Fatal(err)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if got, want := m.loginForms[0].Get("password"), strings.Repeat("*", len(utf16.Encode([]rune(code)))); got != want || len(want) != 7 {
		t.Errorf("password = %q, want %q", got, want)
	}
}

// ---------------------------------------------------------------- SetNotification evidence

// postInterceptor serves the mock gateway but lets a test take over POST /cgi-bin/events.ha.
type postInterceptor struct {
	m      *mockGateway
	onPost func(w http.ResponseWriter, r *http.Request) bool // true = handled
}

func (p *postInterceptor) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost && r.URL.Path == "/cgi-bin/events.ha" && p.onPost != nil && p.onPost(w, r) {
		return
	}
	p.m.ServeHTTP(w, r)
}

// TestSetNotificationPOSTAnswerLost: the gateway applies the change but its answer never
// arrives. The setting must be read back so that the result reflects what the gateway now
// says (before the fix: "failed", no after page, although the gateway had changed).
func TestSetNotificationPOSTAnswerLost(t *testing.T) {
	m := newMockGateway(t, testCode, true)
	h := &postInterceptor{m: m, onPost: func(w http.ResponseWriter, r *http.Request) bool {
		m.ServeHTTP(httptest.NewRecorder(), r) // applied...
		<-r.Context().Done()                   // ...but never answered
		return true
	}}
	srv := httptest.NewServer(h)
	defer srv.Close()
	c := newTestClient(t, srv, newFakeClock(), testCode, nil)
	c.timeout = time.Second // every request of the login flow must also fit
	before, after, err := c.SetNotification(context.Background(), false)
	if err != nil {
		t.Fatalf("err = %v; the read-back shows the requested setting", err)
	}
	if on, _ := ParseNotification(before); !on {
		t.Error("before page must show ON")
	}
	if on, perr := ParseNotification(after); perr != nil || on || m.setting() {
		t.Errorf("after page: on=%v err=%v gateway=%v", on, perr, m.setting())
	}
}

// TestSetNotificationPOSTRejectedIsReadBack: a POST answered with an error status leaves the
// setting unknown; the read-back decides and is returned as evidence.
func TestSetNotificationPOSTRejectedIsReadBack(t *testing.T) {
	m := newMockGateway(t, testCode, true)
	h := &postInterceptor{m: m, onPost: func(w http.ResponseWriter, r *http.Request) bool {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return true
	}}
	srv := httptest.NewServer(h)
	defer srv.Close()
	c := newTestClient(t, srv, newFakeClock(), testCode, nil)
	before, after, err := c.SetNotification(context.Background(), false)
	if !errors.Is(err, ErrNotApplied) || !strings.Contains(err.Error(), "500") {
		t.Fatalf("err = %v, want ErrNotApplied mentioning the HTTP 500", err)
	}
	if len(before) == 0 || len(after) == 0 {
		t.Fatal("before/after evidence missing")
	}
	if on, perr := ParseNotification(after); perr != nil || !on {
		t.Errorf("after page: on=%v err=%v, want the unchanged setting", on, perr)
	}
}

// dropNthListener closes the n-th accepted connection (1-based) before the TLS handshake.
type dropNthListener struct {
	net.Listener
	n     int32
	count atomic.Int32
}

func (l *dropNthListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if l.count.Add(1) == l.n {
			conn.Close()
			continue
		}
		return conn, nil
	}
}

// TestSetNotificationPOSTNeverDeliveredNoReadBack: when the POST's connection could not be
// established, the gateway cannot have received the form: report the failure and do not
// spend another authenticated request on a read-back.
func TestSetNotificationPOSTNeverDeliveredNoReadBack(t *testing.T) {
	m := newMockGateway(t, testCode, true)
	srv := httptest.NewUnstartedServer(m)
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	// Connections: 1-2 login handshake GETs, 3 login POST, 4 verifying GET (= before page),
	// 5 the events.ha POST.
	l := &dropNthListener{Listener: srv.Listener, n: 5}
	srv.Listener = l
	srv.StartTLS()
	defer srv.Close()
	c := newTestClient(t, srv, newFakeClock(), testCode, nil)
	before, after, err := c.SetNotification(context.Background(), false)
	if err == nil || !strings.Contains(err.Error(), "POST events.ha") || errors.Is(err, ErrNotApplied) {
		t.Fatalf("err = %v, want the POST failure", err)
	}
	if len(before) == 0 || after != nil {
		t.Errorf("before=%d bytes after=%v", len(before), after != nil)
	}
	if got := l.count.Load(); got != 5 {
		t.Errorf("%d connections, want 5 (no read-back after an undelivered POST)", got)
	}
	if !m.setting() {
		t.Error("setting changed although the POST was never delivered")
	}
}

// TestInvalidPinIsLogged: an unusable configured pin is pointed out to the operator.
func TestInvalidPinIsLogged(t *testing.T) {
	var logs syncBuffer
	New(Options{PinnedCertSHA256: "49:cd:29", Logger: debugLogger(&logs)})
	if !strings.Contains(logs.String(), "not a SHA-256 fingerprint") {
		t.Errorf("log = %q", logs.String())
	}
	logs = syncBuffer{}
	New(Options{PinnedCertSHA256: "SHA256:" + colonPairs(documentedCertSHA256, ":"), Logger: debugLogger(&logs)})
	if strings.Contains(logs.String(), "not a SHA-256 fingerprint") {
		t.Errorf("valid pin reported as invalid: %q", logs.String())
	}
}

// TestSetNotificationSessionLostAfterPOST: if the verifying GET is redirected to login.ha
// the session is gone. That is ErrLoginRequired (not "unexpected page") and the dead session
// must not be reused.
func TestSetNotificationSessionLostAfterPOST(t *testing.T) {
	m := newMockGateway(t, testCode, true)
	h := &postInterceptor{m: m, onPost: func(w http.ResponseWriter, r *http.Request) bool {
		m.ServeHTTP(w, r)
		m.expireSessions()
		m.set(func(m *mockGateway) { m.redirectToLogin = true })
		return true
	}}
	srv := httptest.NewServer(h)
	defer srv.Close()
	clk := newFakeClock()
	c := newTestClient(t, srv, clk, testCode, nil)
	_, after, err := c.SetNotification(context.Background(), false)
	if !errors.Is(err, ErrLoginRequired) {
		t.Fatalf("err = %v, want ErrLoginRequired", err)
	}
	if after == nil {
		t.Error("the verifying answer must be returned as evidence")
	}
	clk.Advance(10 * time.Second)
	req, _, _ := m.counts()
	if _, _, err := c.Notification(context.Background()); !errors.Is(err, ErrLoginThrottled) {
		t.Errorf("err = %v, want ErrLoginThrottled (dead session dropped, new login not yet allowed)", err)
	}
	if got, _, _ := m.counts(); got != req {
		t.Errorf("%d request(s) with a session known to be dead", got-req)
	}
}

// ---------------------------------------------------------------- snapshot evidence on slow bodies

// TestSnapshotTrickledBodyKeepsPartialEvidence: headers arrive, the body never completes.
// The page must report the timeout, never be parsed, and still return (and hash) the bytes
// that did arrive.
func TestSnapshotTrickledBodyKeepsPartialEvidence(t *testing.T) {
	full := fixture(t, "sysinfo.html")
	half := full[:len(full)/2]
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "100000")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(half)
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	defer srv.Close()
	c := newTestClient(t, srv, nil, "", nil)
	c.timeout = 600 * time.Millisecond
	snap, bodies, err := c.Snapshot(context.Background(), []string{"sysinfo"}, "test")
	if err != nil {
		t.Fatal(err)
	}
	pc := snap.Pages[0]
	if pc.Status != 200 || !strings.Contains(pc.Err, "reading response body") || snap.System != nil {
		t.Errorf("capture = %+v system=%v", pc, snap.System != nil)
	}
	if !bytes.Equal(bodies["sysinfo"], half) || pc.SHA256 != sha256hex(half) || pc.Bytes != len(half) {
		t.Errorf("partial body not kept exactly: %d bytes, sha %s", len(bodies["sysinfo"]), pc.SHA256)
	}
}

// TestDeriveReachableRequiresGatewayAnswer documents Reachable on capture combinations.
func TestDeriveReachableRequiresGatewayAnswer(t *testing.T) {
	tests := []struct {
		pages []model.PageCapture
		want  bool
	}{
		{[]model.PageCapture{{Status: 200}}, true},
		{[]model.PageCapture{{Status: 200, LoginPage: true}}, false},
		{[]model.PageCapture{{Status: 302, Location: "/cgi-bin/login.ha"}}, false},
		{[]model.PageCapture{{Err: "not attempted: no connection to the gateway (sysinfo failed)"}}, false},
		{[]model.PageCapture{{Status: 500}, {Status: 200, Err: "parse: x"}}, true},
		{nil, false},
	}
	for i, tt := range tests {
		if got := Derive(&model.GatewaySnapshot{Pages: tt.pages}, fetchedAt, cdt).Reachable; got != tt.want {
			t.Errorf("case %d: Reachable = %v, want %v", i, got, tt.want)
		}
	}
}
