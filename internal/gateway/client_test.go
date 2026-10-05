package gateway

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"attmonitor/internal/contracts"
	"attmonitor/internal/model"
)

var statusPages = []string{"broadbandstatistics", "fiberstat", "sysinfo"}

// countingHandler wraps h and counts requests.
type countingHandler struct {
	h http.Handler
	n atomic.Int64
}

func (c *countingHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	c.n.Add(1)
	c.h.ServeHTTP(w, r)
}

func TestSnapshotFixturesHTTP(t *testing.T) {
	m := newMockGateway(t, "", false)
	var ua, accEnc atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ua.Store(r.Header.Get("User-Agent"))
		accEnc.Store(r.Header.Get("Accept-Encoding"))
		m.ServeHTTP(w, r)
	}))
	defer srv.Close()
	clk := newFakeClock()
	c := newTestClient(t, srv, clk, "", nil)

	pages := append(append([]string{}, statusPages...), "lanstatistics")
	snap, bodies, err := c.Snapshot(context.Background(), pages, "periodic")
	if err != nil {
		t.Fatal(err)
	}
	if snap.Trigger != "periodic" || len(snap.Pages) != 4 {
		t.Fatalf("trigger=%q pages=%d", snap.Trigger, len(snap.Pages))
	}
	files := map[string]string{"broadbandstatistics": "broadbandstatistics.html", "fiberstat": "fiberstat.html",
		"sysinfo": "sysinfo.html", "lanstatistics": "lanstatistics.html"}
	for i, pc := range snap.Pages {
		want := fixture(t, files[pages[i]])
		if pc.Page != pages[i] || pc.URL != srv.URL+"/cgi-bin/"+pages[i]+".ha" {
			t.Errorf("page %d = %q %q", i, pc.Page, pc.URL)
		}
		if pc.Status != 200 || pc.Err != "" || pc.LoginPage || pc.Stored || pc.Location != "" || pc.TLSCertSHA256 != "" {
			t.Errorf("%s capture = %+v", pc.Page, pc)
		}
		if !bytes.Equal(bodies[pc.Page], want) {
			t.Errorf("%s body differs from what the server sent", pc.Page)
		}
		if pc.SHA256 != sha256hex(want) || pc.Bytes != len(want) {
			t.Errorf("%s sha256/bytes = %s/%d, want %s/%d", pc.Page, pc.SHA256, pc.Bytes, sha256hex(want), len(want))
		}
		ts, err := time.Parse(time.RFC3339Nano, pc.FetchedAt)
		if err != nil || !strings.HasSuffix(pc.FetchedAt, "Z") || !ts.Equal(clk.Now()) {
			t.Errorf("%s FetchedAt = %q", pc.Page, pc.FetchedAt)
		}
		if pc.DurMs < 0 {
			t.Errorf("%s DurMs = %d", pc.Page, pc.DurMs)
		}
	}
	if snap.System == nil || snap.Broadband == nil || snap.Fiber == nil || snap.LAN == nil {
		t.Fatalf("parsed = %v %v %v %v", snap.System != nil, snap.Broadband != nil, snap.Fiber != nil, snap.LAN != nil)
	}
	d := snap.Derived
	if !d.Reachable || d.UptimeSec != 274686 || d.Model != "BGW320-505" || d.WANIPv4 != "203.0.113.10" ||
		len(d.Alarms) != 2 || d.GatewayClockOffsetMs == nil || *d.GatewayClockOffsetMs != 1000 {
		t.Errorf("Derived = %+v", d)
	}
	if got := ua.Load(); got != "att-monitor/test" {
		t.Errorf("User-Agent = %v", got)
	}
	if got := accEnc.Load(); got != "" {
		t.Errorf("Accept-Encoding = %q; bodies must arrive exactly as served (no transparent gzip)", got)
	}
}

func TestSnapshotRedirectNotFollowed(t *testing.T) {
	m := newMockGateway(t, "", false)
	srv := httptest.NewServer(m)
	defer srv.Close()
	c := newTestClient(t, srv, nil, "", nil)
	snap, bodies, err := c.Snapshot(context.Background(), []string{"securityoptions"}, "test")
	if err != nil {
		t.Fatal(err)
	}
	pc := snap.Pages[0]
	if pc.Status != http.StatusFound || pc.Location != "/cgi-bin/hiddenpage.ha" {
		t.Errorf("capture = %+v", pc)
	}
	if !strings.Contains(pc.Err, "302") {
		t.Errorf("Err = %q, want the unexpected status", pc.Err)
	}
	if _, ok := bodies["securityoptions"]; !ok || pc.SHA256 != sha256hex(nil) {
		t.Errorf("the (empty) redirect body must be recorded: %+v", pc)
	}
	m.mu.Lock()
	hidden := m.byPath["GET /cgi-bin/hiddenpage.ha"]
	m.mu.Unlock()
	if hidden != 0 {
		t.Errorf("redirect target was fetched %d times; redirects must not be followed", hidden)
	}
	if snap.Derived.Reachable {
		t.Error("a redirect is not a reachable status page")
	}
}

func TestSnapshotBodyCap(t *testing.T) {
	const page = "bigpage"
	var size atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(bytes.Repeat([]byte("a"), int(size.Load())))
	}))
	defer srv.Close()
	c := newTestClient(t, srv, nil, "", nil)

	for _, tt := range []struct {
		size      int64
		truncated bool
	}{{MaxBodyBytes, false}, {MaxBodyBytes + 1, true}, {MaxBodyBytes + 1<<20, true}} {
		size.Store(tt.size)
		snap, bodies, err := c.Snapshot(context.Background(), []string{page}, "test")
		if err != nil {
			t.Fatal(err)
		}
		pc := snap.Pages[0]
		if pc.Bytes != MaxBodyBytes && tt.truncated || !tt.truncated && int64(pc.Bytes) != tt.size {
			t.Errorf("size %d: Bytes = %d", tt.size, pc.Bytes)
		}
		if got := strings.Contains(pc.Err, "exceeds 4194304 bytes"); got != tt.truncated {
			t.Errorf("size %d: Err = %q", tt.size, pc.Err)
		}
		if len(bodies[page]) != pc.Bytes || pc.SHA256 != sha256hex(bodies[page]) {
			t.Errorf("size %d: returned body does not match capture", tt.size)
		}
	}

	// A truncated status page is never parsed.
	m := newMockGateway(t, "", false)
	srv2 := httptest.NewServer(m)
	defer srv2.Close()
	c2 := newTestClient(t, srv2, nil, "", nil)
	c2.maxBody = 100
	snap, bodies, err := c2.Snapshot(context.Background(), []string{"sysinfo"}, "test")
	if err != nil {
		t.Fatal(err)
	}
	if snap.System != nil || len(bodies["sysinfo"]) != 100 || !strings.Contains(snap.Pages[0].Err, "truncated") {
		t.Errorf("truncated page: system=%v body=%d err=%q", snap.System, len(bodies["sysinfo"]), snap.Pages[0].Err)
	}
}

func TestSnapshotPartialFailures(t *testing.T) {
	m := newMockGateway(t, "", false)
	m.pages["sysinfo"] = fixture(t, "login_nonce.html")  // authentication demanded
	m.pages["fiberstat"] = fixture(t, "hiddenpage.html") // wrong page: parse error
	m.pages["lanstatistics"] = sessionsFullPage(t)       // session pool exhausted
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "broadbandstatistics") {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		m.ServeHTTP(w, r)
	}))
	defer srv.Close()
	clk := newFakeClock()
	c := newTestClient(t, srv, clk, "secret-code-123", nil)

	snap, bodies, err := c.Snapshot(context.Background(), []string{"sysinfo", "fiberstat", "broadbandstatistics", "lanstatistics", "../etc"}, "cycle_failure")
	if err != nil {
		t.Fatalf("pages answered, so Snapshot must not fail: %v", err)
	}
	byPage := map[string]model.PageCapture{}
	for _, pc := range snap.Pages {
		byPage[pc.Page] = pc
	}
	if pc := byPage["sysinfo"]; !pc.LoginPage || !strings.Contains(pc.Err, "login page") || snap.System != nil {
		t.Errorf("sysinfo = %+v", pc)
	}
	if pc := byPage["fiberstat"]; !strings.HasPrefix(pc.Err, "parse: ") || snap.Fiber != nil || pc.Status != 200 {
		t.Errorf("fiberstat = %+v", pc)
	}
	if pc := byPage["broadbandstatistics"]; pc.Status != 500 || pc.Err != "unexpected HTTP status 500 Internal Server Error" {
		t.Errorf("broadbandstatistics = %+v", pc)
	}
	if pc := byPage["lanstatistics"]; !strings.Contains(pc.Err, "sessions are in use") {
		t.Errorf("lanstatistics = %+v", pc)
	}
	if pc := byPage["../etc"]; pc.Err != "invalid page name" || pc.URL != "" {
		t.Errorf("invalid page = %+v", pc)
	}
	if _, ok := bodies["../etc"]; ok {
		t.Error("invalid page must not be requested")
	}
	// fiberstat answered 200 with a non-login page: the gateway web server is reachable.
	if !snap.Derived.Reachable {
		t.Error("Reachable = false")
	}
	// The sessions-full page starts the login cooldown: no request is made.
	before, _, _ := m.counts()
	_, _, err = c.Notification(context.Background())
	var ce *CooldownError
	if !errors.Is(err, ErrSessionsFull) || !errors.As(err, &ce) || !ce.Until.Equal(clk.Now().Add(5*time.Minute)) {
		t.Errorf("Notification err = %v", err)
	}
	if after, _, _ := m.counts(); after != before {
		t.Error("a login was attempted during the sessions-full cooldown")
	}
}

func TestSnapshotUnreachable(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close() // nothing listens here any more
	c := New(Options{Host: addr, Scheme: "http", Timeout: 2 * time.Second})
	snap, bodies, err := c.Snapshot(context.Background(), statusPages, "test")
	if err == nil || !strings.Contains(err.Error(), "no page could be fetched") {
		t.Fatalf("err = %v", err)
	}
	if len(snap.Pages) != 3 || len(bodies) != 0 || snap.Derived.Reachable {
		t.Fatalf("snapshot = %+v", snap)
	}
	var oe *net.OpError
	if !errors.As(err, &oe) || oe.Op != "dial" {
		t.Errorf("err = %v, want it to wrap the dial error", err)
	}
	for i, pc := range snap.Pages {
		if pc.Err == "" || pc.Status != 0 || pc.SHA256 != "" || pc.FetchedAt == "" || pc.URL == "" {
			t.Errorf("capture = %+v", pc)
		}
		if strings.Contains(pc.Err, "http://") {
			t.Errorf("Err repeats the URL: %q", pc.Err)
		}
		// One failed connection is enough: the other pages are recorded as not attempted.
		if skipped := strings.HasPrefix(pc.Err, "not attempted: no connection to the gateway (broadbandstatistics failed)"); skipped != (i > 0) {
			t.Errorf("page %d Err = %q", i, pc.Err)
		}
		if pc.NotAttempted != (i > 0) {
			t.Errorf("page %d NotAttempted = %v", i, pc.NotAttempted)
		}
	}
}

// TestSnapshotMarksSkippedPagesNotAttempted: pages skipped after a failed connection carry
// NotAttempted (and keep their explanation), so that one unreachable gateway is not counted as
// several failed fetches. Pages that were requested - or never could be - are not marked.
func TestSnapshotMarksSkippedPagesNotAttempted(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close() // nothing listens here any more
	c := New(Options{Host: addr, Scheme: "http", Timeout: 2 * time.Second})
	snap, _, err := c.Snapshot(context.Background(), []string{"sysinfo", "broadbandstatistics", "../x", "fiberstat"}, "test")
	if err == nil {
		t.Fatal("unreachable gateway: want an error")
	}
	const skipped = "not attempted: no connection to the gateway (sysinfo failed)"
	want := []struct {
		notAttempted bool
		err          string // "" = any non-empty error
	}{
		{false, ""}, // the failed connection itself
		{true, skipped},
		{false, "invalid page name"}, // never requested, whatever the gateway's state
		{true, skipped},
	}
	if len(snap.Pages) != len(want) {
		t.Fatalf("pages = %+v", snap.Pages)
	}
	for i, w := range want {
		pc := snap.Pages[i]
		if pc.NotAttempted != w.notAttempted || pc.Err == "" || (w.err != "" && pc.Err != w.err) || pc.Err == skipped && i == 0 {
			t.Errorf("page %d (%s): NotAttempted=%v Err=%q, want %v %q", i, pc.Page, pc.NotAttempted, pc.Err, w.notAttempted, w.err)
		}
		if pc.NotAttempted && (pc.URL == "" || pc.FetchedAt == "" || pc.Status != 0 || pc.SHA256 != "" || pc.DurMs != 0) {
			t.Errorf("page %d: not-attempted capture = %+v", i, pc)
		}
	}
	b, err := json.Marshal(snap.Pages)
	if err != nil {
		t.Fatal(err)
	}
	if n := bytes.Count(b, []byte(`"not_attempted":true`)); n != 2 {
		t.Errorf("recorded JSON has %d not_attempted pages, want 2: %s", n, b)
	}
}

// TestSnapshotClockRowMissingVsBlank: the snapshot records whether sysinfo had a "Current
// Date/Time" row, raises the WAN-down indicator only for a blank row, and Derive reproduces the
// derived facts from the recorded JSON alone.
func TestSnapshotClockRowMissingVsBlank(t *testing.T) {
	sys := fixture(t, "sysinfo.html")
	tests := []struct {
		name           string
		body           []byte
		present, blank bool
	}{
		{"row with the time", sys, true, false},
		{"blank row", sub(t, sys, reClockValue, "${1}"), true, true},
		{"missing row", sub(t, sys, reClockRow, ""), false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := newMockGateway(t, "", false)
			m.pages["sysinfo"] = tt.body
			srv := httptest.NewServer(m)
			defer srv.Close()
			c := newTestClient(t, srv, newFakeClock(), "", nil)
			snap, _, err := c.Snapshot(context.Background(), []string{"sysinfo"}, "test")
			if err != nil {
				t.Fatal(err)
			}
			if snap.System == nil || snap.System.GatewayTimePresent != tt.present || snap.Derived.GatewayClockBlank != tt.blank {
				t.Fatalf("System=%+v GatewayClockBlank=%v, want present=%v blank=%v", snap.System, snap.Derived.GatewayClockBlank, tt.present, tt.blank)
			}
			b, err := json.Marshal(snap)
			if err != nil {
				t.Fatal(err)
			}
			if want := fmt.Sprintf(`"gateway_time_present":%v`, tt.present); !bytes.Contains(b, []byte(want)) {
				t.Errorf("recorded JSON lacks %s", want)
			}
			var rec model.GatewaySnapshot
			if err := json.Unmarshal(b, &rec); err != nil {
				t.Fatal(err)
			}
			if again := Derive(&rec, c.deriveTime(&rec), c.loc); !reflect.DeepEqual(again, snap.Derived) {
				t.Errorf("Derive from the record =\n%+v\nwant\n%+v", again, snap.Derived)
			}
		})
	}
}

// TestSnapshotContinuesAfterPageSpecificFailure: a connection that was established but timed
// out (slow page) does not stop the remaining pages.
func TestSnapshotContinuesAfterPageSpecificFailure(t *testing.T) {
	m := newMockGateway(t, "", false)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "lanstatistics") {
			<-r.Context().Done() // never answers
			return
		}
		m.ServeHTTP(w, r)
	}))
	defer srv.Close()
	c := newTestClient(t, srv, nil, "", nil)
	c.timeout = 200 * time.Millisecond
	snap, _, err := c.Snapshot(context.Background(), []string{"lanstatistics", "sysinfo"}, "test")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(snap.Pages[0].Err, "deadline") || snap.Pages[1].Err != "" || snap.System == nil {
		t.Errorf("pages = %+v", snap.Pages)
	}
	for _, pc := range snap.Pages {
		if pc.NotAttempted {
			t.Errorf("%s: NotAttempted although it was requested", pc.Page)
		}
	}
}

func TestSnapshotEdgeCases(t *testing.T) {
	h := &countingHandler{h: newMockGateway(t, "", false)}
	srv := httptest.NewServer(h)
	defer srv.Close()
	c := newTestClient(t, srv, nil, "", nil)

	if _, _, err := c.Snapshot(context.Background(), nil, "test"); err == nil {
		t.Error("no pages: want an error")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	snap, _, err := c.Snapshot(ctx, statusPages, "test")
	if err == nil || len(snap.Pages) != 3 || !strings.HasPrefix(snap.Pages[0].Err, "not fetched") || !errors.Is(err, context.Canceled) {
		t.Errorf("canceled: err=%v pages=%+v", err, snap.Pages)
	}
	if h.n.Load() != 0 {
		t.Errorf("requests after cancel = %d", h.n.Load())
	}
	snap, bodies, err := c.Snapshot(context.Background(), []string{"sysinfo", "sysinfo"}, "test")
	if err != nil || len(snap.Pages) != 1 || len(bodies) != 1 || h.n.Load() != 1 {
		t.Errorf("duplicates: err=%v pages=%d requests=%d", err, len(snap.Pages), h.n.Load())
	}
}

func TestSnapshotTimeout(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	defer close(release)
	c := newTestClient(t, srv, nil, "", nil)
	c.timeout = 150 * time.Millisecond
	start := time.Now()
	snap, _, err := c.Snapshot(context.Background(), []string{"sysinfo"}, "test")
	if err == nil || !strings.Contains(snap.Pages[0].Err, "deadline") {
		t.Errorf("err=%v capture=%+v", err, snap.Pages[0])
	}
	if time.Since(start) > 3*time.Second {
		t.Error("per-request timeout not applied")
	}
}

// TestSnapshotReusesCookieSession: if the gateway hands out a session cookie on status
// pages, later polls send it back instead of opening a new web session every time.
func TestSnapshotReusesCookieSession(t *testing.T) {
	var mu sync.Mutex
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		ck, err := r.Cookie("SessionID")
		if err != nil {
			http.SetCookie(w, &http.Cookie{Name: "SessionID", Value: "s1", Path: "/"})
			seen = append(seen, "")
		} else {
			seen = append(seen, ck.Value)
		}
		_, _ = w.Write(fixture(t, "sysinfo.html"))
	}))
	defer srv.Close()
	c := newTestClient(t, srv, nil, "", nil)
	for i := 0; i < 3; i++ {
		if _, _, err := c.Snapshot(context.Background(), []string{"sysinfo"}, "test"); err != nil {
			t.Fatal(err)
		}
	}
	if want := []string{"", "s1", "s1"}; strings.Join(seen, ",") != strings.Join(want, ",") {
		t.Errorf("cookies seen = %q, want %q", seen, want)
	}
}

// ---------------------------------------------------------------- TLS pinning

type observerLog struct {
	mu     sync.Mutex
	calls  [][2]string
	answer bool
}

func (o *observerLog) observe(prev, obs string) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.calls = append(o.calls, [2]string{prev, obs})
	return o.answer
}

func (o *observerLog) get() [][2]string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([][2]string(nil), o.calls...)
}

func newTLSGateway(t *testing.T) (*httptest.Server, *countingHandler, string) {
	t.Helper()
	h := &countingHandler{h: newMockGateway(t, "", false)}
	srv := httptest.NewUnstartedServer(h)
	srv.Config.ErrorLog = log.New(io.Discard, "", 0) // rejected handshakes are expected
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv, h, sha256hex(srv.Certificate().Raw)
}

func tlsClient(srv *httptest.Server, pin string, obs contracts.CertObserver) *Client {
	c := New(Options{Host: strings.TrimPrefix(srv.URL, "https://"), Scheme: "https", PinnedCertSHA256: pin, Timeout: 5 * time.Second})
	if obs != nil {
		c.SetCertObserver(obs)
	}
	return c
}

func TestTLSTrustOnFirstUseWithObserver(t *testing.T) {
	srv, _, certSHA := newTLSGateway(t)
	o := &observerLog{answer: true}
	c := tlsClient(srv, "", o.observe)
	snap, _, err := c.Snapshot(context.Background(), statusPages, "startup")
	if err != nil {
		t.Fatal(err)
	}
	if got := o.get(); len(got) != 1 || got[0] != [2]string{"", certSHA} {
		t.Errorf("observer calls = %v, want one (\"\", %s)", got, certSHA)
	}
	if c.PinnedCert() != certSHA {
		t.Errorf("PinnedCert = %q, want %q", c.PinnedCert(), certSHA)
	}
	for _, pc := range snap.Pages {
		if pc.TLSCertSHA256 != certSHA || pc.Status != 200 || pc.Err != "" {
			t.Errorf("capture = %+v", pc)
		}
	}
	if snap.System == nil || !snap.Derived.Reachable {
		t.Error("TLS snapshot not parsed")
	}
	// Pinned now: further handshakes do not consult the observer.
	if _, _, err := c.Snapshot(context.Background(), statusPages, "periodic"); err != nil {
		t.Fatal(err)
	}
	if n := len(o.get()); n != 1 {
		t.Errorf("observer called %d times, want 1", n)
	}
}

func TestTLSTrustOnFirstUseWithoutObserver(t *testing.T) {
	srv, _, certSHA := newTLSGateway(t)
	c := tlsClient(srv, "", nil)
	if _, _, err := c.Snapshot(context.Background(), []string{"sysinfo"}, "test"); err != nil {
		t.Fatal(err)
	}
	if c.PinnedCert() != certSHA {
		t.Errorf("PinnedCert = %q", c.PinnedCert())
	}
}

func TestTLSPinMatches(t *testing.T) {
	srv, _, certSHA := newTLSGateway(t)
	// Upper case with colons, as copied from a certificate viewer.
	var parts []string
	for i := 0; i < len(certSHA); i += 2 {
		parts = append(parts, strings.ToUpper(certSHA[i:i+2]))
	}
	o := &observerLog{answer: false}
	c := tlsClient(srv, strings.Join(parts, ":"), o.observe)
	if c.PinnedCert() != certSHA {
		t.Fatalf("pin not normalized: %q", c.PinnedCert())
	}
	snap, _, err := c.Snapshot(context.Background(), []string{"sysinfo"}, "test")
	if err != nil || snap.Pages[0].TLSCertSHA256 != certSHA {
		t.Fatalf("err=%v capture=%+v", err, snap.Pages[0])
	}
	if len(o.get()) != 0 {
		t.Error("observer consulted although the pin matched")
	}
}

func TestTLSPinMismatch(t *testing.T) {
	wrong := strings.Repeat("ab", 32)
	tests := []struct {
		name     string
		observer *observerLog
		accept   bool
	}{
		{"observer rejects", &observerLog{answer: false}, false},
		{"no observer rejects", nil, false},
		{"observer accepts and re-pins", &observerLog{answer: true}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv, h, certSHA := newTLSGateway(t)
			var obs contracts.CertObserver
			if tt.observer != nil {
				obs = tt.observer.observe
			}
			c := tlsClient(srv, wrong, obs)
			snap, _, err := c.Snapshot(context.Background(), []string{"sysinfo", "fiberstat"}, "test")
			if tt.observer != nil {
				calls := tt.observer.get()
				if len(calls) == 0 || calls[0] != [2]string{wrong, certSHA} {
					t.Errorf("observer calls = %v", calls)
				}
				if tt.accept && len(calls) != 1 {
					t.Errorf("observer called %d times after accepting, want 1", len(calls))
				}
			}
			// The presented certificate is recorded even when it is rejected.
			if pc := snap.Pages[0]; pc.TLSCertSHA256 != certSHA {
				t.Errorf("TLSCertSHA256 = %q, want %q", pc.TLSCertSHA256, certSHA)
			}
			if tt.accept {
				if err != nil || c.PinnedCert() != certSHA || snap.System == nil || snap.Pages[1].TLSCertSHA256 != certSHA {
					t.Errorf("accept: err=%v pin=%q pages=%+v", err, c.PinnedCert(), snap.Pages)
				}
				return
			}
			if err == nil || !strings.Contains(snap.Pages[0].Err, "does not match pinned") {
				t.Errorf("reject: err=%v capture=%+v", err, snap.Pages[0])
			}
			// No connection could be made: the next page is not attempted (and the observer
			// is not asked again within the same snapshot).
			if pc := snap.Pages[1]; pc.Err != "not attempted: no connection to the gateway (sysinfo failed)" || !pc.NotAttempted || pc.TLSCertSHA256 != "" {
				t.Errorf("second page = %+v", pc)
			}
			if snap.Pages[0].NotAttempted {
				t.Error("the rejected page was attempted")
			}
			// The snapshot's error carries the cause (it is not only a message).
			var ce *CertError
			if !errors.Is(err, ErrCertRejected) || !errors.As(err, &ce) || ce.Observed != certSHA {
				t.Errorf("err = %v, want the certificate rejection", err)
			}
			if tt.observer != nil && len(tt.observer.get()) != 1 {
				t.Errorf("observer calls = %d, want 1", len(tt.observer.get()))
			}
			if c.PinnedCert() != wrong {
				t.Errorf("pin changed to %q after a rejection", c.PinnedCert())
			}
			if n := h.n.Load(); n != 0 {
				t.Errorf("%d HTTP requests reached a server whose certificate was rejected", n)
			}
		})
	}
}

// TestTLSLoginNeverSentToUnpinnedServer: with a pin mismatch the login form (and thus the
// hash of the access code) is never sent.
func TestTLSLoginNeverSentToUnpinnedServer(t *testing.T) {
	srv, h, _ := newTLSGateway(t)
	c := tlsClient(srv, strings.Repeat("cd", 32), nil)
	c.accessCode = func() (string, error) { return "secret-code-123", nil }
	_, _, err := c.Notification(context.Background())
	var ce *CertError
	if !errors.Is(err, ErrCertRejected) || !errors.As(err, &ce) {
		t.Fatalf("err = %v, want a certificate rejection", err)
	}
	if h.n.Load() != 0 {
		t.Errorf("%d requests reached the impostor", h.n.Load())
	}
}

func TestTLSConcurrentFirstUseObserverCalledOnce(t *testing.T) {
	srv, _, certSHA := newTLSGateway(t)
	o := &observerLog{answer: true}
	c := tlsClient(srv, "", o.observe)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, _, err := c.Snapshot(context.Background(), []string{"sysinfo"}, "test"); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if calls := o.get(); len(calls) != 1 || calls[0][1] != certSHA {
		t.Errorf("observer calls = %v, want exactly one", calls)
	}
}

func TestTLSCertificateChange(t *testing.T) {
	// The same client meets a second server presenting a different self-signed certificate
	// (as after a gateway factory reset): the observer sees (old, new) and the accepted
	// certificate is re-pinned; a rejected change keeps the old pin.
	srv1, _, sha1 := newTLSGateway(t)
	srv2 := httptest.NewUnstartedServer(newMockGateway(t, "", false))
	srv2.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv2.TLS = &tls.Config{Certificates: []tls.Certificate{selfSignedCert(t)}}
	srv2.StartTLS()
	defer srv2.Close()
	sha2 := sha256hex(srv2.Certificate().Raw)
	if sha1 == sha2 {
		t.Fatal("test certificates are identical")
	}
	for _, accept := range []bool{false, true} {
		o := &observerLog{answer: true}
		c := tlsClient(srv1, "", o.observe)
		if _, _, err := c.Snapshot(context.Background(), []string{"sysinfo"}, "test"); err != nil {
			t.Fatal(err)
		}
		o.mu.Lock()
		o.answer = accept
		o.mu.Unlock()
		c.host = strings.TrimPrefix(srv2.URL, "https://")
		snap, _, err := c.Snapshot(context.Background(), []string{"sysinfo"}, "test")
		calls := o.get()
		if len(calls) != 2 || calls[1] != [2]string{sha1, sha2} {
			t.Errorf("accept=%v: observer calls = %v", accept, calls)
		}
		if snap.Pages[0].TLSCertSHA256 != sha2 {
			t.Errorf("accept=%v: recorded certificate = %q, want %q", accept, snap.Pages[0].TLSCertSHA256, sha2)
		}
		wantPin := sha1
		if accept {
			wantPin = sha2
		}
		if (err == nil) != accept || c.PinnedCert() != wantPin {
			t.Errorf("accept=%v: err=%v pin=%q", accept, err, c.PinnedCert())
		}
	}
}

func TestNewDefaults(t *testing.T) {
	c := New(Options{})
	if c.Host() != DefaultHost || c.scheme != "https" || c.timeout != DefaultTimeout || c.userAgent != DefaultUserAgent ||
		c.loc != time.Local || c.log == nil || c.now == nil || c.PinnedCert() != "" {
		t.Errorf("defaults = %+v", c)
	}
	if got := c.pageURL("sysinfo"); got != "https://192.168.1.254/cgi-bin/sysinfo.ha" {
		t.Errorf("pageURL = %q", got)
	}
	c6 := New(Options{Host: "fe80::1", Scheme: "HTTP"})
	if got := c6.pageURL("fiberstat"); got != "http://[fe80::1]/cgi-bin/fiberstat.ha" {
		t.Errorf("pageURL = %q", got)
	}
	for _, p := range []string{"sysinfo", "broadband_statistics", "a-b"} {
		if !validPage(p) {
			t.Errorf("validPage(%q) = false", p)
		}
	}
	for _, p := range []string{"", "../x", "a/b", "a?b", "a.ha", strings.Repeat("a", 65)} {
		if validPage(p) {
			t.Errorf("validPage(%q) = true", p)
		}
	}
}

func TestCustomHTTPClientRedirectsStillRecorded(t *testing.T) {
	srv := httptest.NewServer(newMockGateway(t, "", false))
	defer srv.Close()
	followed := false
	hc := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { followed = true; return nil }}
	c := New(Options{Host: strings.TrimPrefix(srv.URL, "http://"), Scheme: "http", HTTPClient: hc})
	snap, _, err := c.Snapshot(context.Background(), []string{"securityoptions"}, "test")
	if err != nil {
		t.Fatal(err)
	}
	if followed || snap.Pages[0].Status != http.StatusFound {
		t.Errorf("custom client followed a redirect: %+v", snap.Pages[0])
	}
	if hc.CheckRedirect == nil {
		t.Error("caller's client was modified")
	}
}
