package web

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"attmonitor/internal/model"
)

func TestNewListenValidation(t *testing.T) {
	tests := []struct {
		listen  string
		wantErr bool
		port    uint32
	}{
		{"", false, 8320}, // config default
		{"127.0.0.1:8320", false, 8320},
		{"  127.0.0.1:9000 ", false, 9000},
		{"[::1]:8320", false, 8320},
		{"127.0.0.2:8320", false, 8320},
		{"127.0.0.1:0", false, 0},
		{"0.0.0.0:8320", true, 0},
		{"192.168.1.71:8320", true, 0},
		{"[::]:8320", true, 0},
		{"localhost:8320", true, 0}, // must be an IP literal
		{":8320", true, 0},
		{"127.0.0.1", true, 0},
		{"garbage", true, 0},
		{"[fe80::1%eth0]:8320", true, 0},
	}
	for _, tc := range tests {
		t.Run(tc.listen, func(t *testing.T) {
			s, err := New(Options{Listen: tc.listen})
			if tc.wantErr {
				if err == nil {
					t.Fatalf("New(%q) succeeded, want error", tc.listen)
				}
				return
			}
			if err != nil {
				t.Fatalf("New(%q): %v", tc.listen, err)
			}
			if got := s.port.Load(); got != tc.port {
				t.Errorf("port = %d, want %d", got, tc.port)
			}
		})
	}
}

func TestHostAllowList(t *testing.T) {
	hs := newHarness(t)
	tests := []struct {
		host string
		ok   bool
	}{
		{"127.0.0.1:8320", true},
		{"localhost:8320", true},
		{"LOCALHOST:8320", true},
		{"[::1]:8320", true},
		{"evil.com", false},
		{"evil.com:8320", false},
		{"127.0.0.1:9999", false},
		{"127.0.0.1", false},
		{"localhost", false},
		{"[::1]", false},
		{"localhost.:8320", false},
		{"127.0.0.1.nip.io:8320", false},
		{"192.168.1.71:8320", false},
		{"127.0.0.1:08320", false},
		{"", false},
	}
	for _, tc := range tests {
		t.Run(tc.host, func(t *testing.T) {
			req := hs.request(http.MethodGet, "/api/status", nil, nil)
			req.Host = tc.host
			rec := hs.serve(req)
			if tc.ok {
				wantStatus(t, rec, http.StatusOK)
				return
			}
			msg := wantJSONError(t, rec, http.StatusMisdirectedRequest)
			if !strings.Contains(msg, "host not allowed") {
				t.Errorf("message = %q", msg)
			}
			assertSecurityHeaders(t, rec.Header(), false)
		})
	}
}

func TestHostAllowListDefaultPortAndListenIP(t *testing.T) {
	s, err := New(Options{Listen: "127.0.0.2:80"})
	if err != nil {
		t.Fatal(err)
	}
	for host, ok := range map[string]bool{
		"127.0.0.2:80": true, "127.0.0.2": true, "localhost": true, "[::1]": true, "127.0.0.1:80": true,
		"127.0.0.3:80": false, "evil.com": false, "localhost:81": false,
	} {
		if got := s.hostAllowed(host); got != ok {
			t.Errorf("hostAllowed(%q) = %v, want %v", host, got, ok)
		}
	}
}

func TestCSRFProtection(t *testing.T) {
	tests := []struct {
		name string
		hdr  map[string]string
		code int
	}{
		{"header and same origin", map[string]string{"Origin": testOrigin}, http.StatusCreated},
		{"header, no origin (CLI client)", nil, http.StatusCreated},
		{"same origin, localhost host", map[string]string{"Origin": "http://localhost:8320", "Host": "localhost:8320"}, http.StatusCreated},
		{"same-origin fetch metadata", map[string]string{"Sec-Fetch-Site": "same-origin", "Origin": testOrigin}, http.StatusCreated},
		{"missing header", map[string]string{CSRFHeader: ""}, http.StatusForbidden},
		{"wrong header value", map[string]string{CSRFHeader: "true"}, http.StatusForbidden},
		{"cross origin", map[string]string{"Origin": "http://evil.com"}, http.StatusForbidden},
		{"other local port", map[string]string{"Origin": "http://127.0.0.1:9999"}, http.StatusForbidden},
		{"https scheme mismatch", map[string]string{"Origin": "https://127.0.0.1:8320"}, http.StatusForbidden},
		{"localhost origin vs 127.0.0.1 host", map[string]string{"Origin": "http://localhost:8320"}, http.StatusForbidden},
		{"null origin (sandboxed page)", map[string]string{"Origin": "null"}, http.StatusForbidden},
		{"cross-site fetch metadata", map[string]string{"Sec-Fetch-Site": "cross-site"}, http.StatusForbidden},
		{"same-site fetch metadata", map[string]string{"Sec-Fetch-Site": "same-site"}, http.StatusForbidden},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			hs := newHarness(t)
			hdr := map[string]string{}
			for k, v := range tc.hdr {
				if k != "Host" {
					hdr[k] = v
				}
			}
			req := hs.request(http.MethodPost, "/api/notes", strings.NewReader(`{"text":"ticket 123"}`), hdr)
			if h, ok := tc.hdr["Host"]; ok {
				req.Host = h
			}
			rec := hs.serve(req)
			if tc.code == http.StatusForbidden {
				wantJSONError(t, rec, http.StatusForbidden)
				if n := len(hs.actions.notes); n != 0 {
					t.Fatalf("rejected request still reached Actions.Note (%d calls)", n)
				}
				return
			}
			wantStatus(t, rec, tc.code)
		})
	}
}

func TestCSRFAppliesToEveryUnsafeMethod(t *testing.T) {
	hs := newHarness(t)
	for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch} {
		req := hs.request(m, "/api/status", nil, map[string]string{CSRFHeader: ""})
		wantJSONError(t, hs.serve(req), http.StatusForbidden)
	}
	// Safe methods do not need the header.
	wantStatus(t, hs.serve(hs.request(http.MethodHead, "/api/status", nil, nil)), http.StatusOK)
}

// assertSecurityHeaders checks the headers every response must carry.
func assertSecurityHeaders(t *testing.T, h http.Header, sandbox bool) {
	t.Helper()
	want := map[string]string{
		"Cache-Control":          "no-store",
		"X-Content-Type-Options": "nosniff",
		"Referrer-Policy":        "no-referrer",
		"Content-Security-Policy": "default-src 'self'; img-src 'self' data:; style-src 'self'; " +
			"script-src 'self'; frame-ancestors 'none'",
		"X-Frame-Options":              "DENY",
		"Cross-Origin-Resource-Policy": "same-origin",
	}
	if sandbox {
		want["Content-Security-Policy"] = "sandbox; default-src 'none'; img-src data:; style-src 'unsafe-inline'"
	}
	for k, v := range want {
		if got := h.Values(k); len(got) != 1 || got[0] != v {
			t.Errorf("header %s = %q, want exactly %q", k, got, v)
		}
	}
}

func TestSecurityHeadersOnEveryResponse(t *testing.T) {
	hs := newHarness(t)
	blob := hs.reader.addBlob([]byte("<html>gateway page \xa9</html>"))
	hs.status.panicMsg = ""
	tests := []struct {
		name    string
		req     func() *http.Request
		code    int
		sandbox bool
	}{
		{"index", func() *http.Request { return hs.request("GET", "/", nil, nil) }, 200, false},
		{"static js", func() *http.Request { return hs.request("GET", "/static/app.js", nil, nil) }, 200, false},
		{"status", func() *http.Request { return hs.request("GET", "/api/status", nil, nil) }, 200, false},
		{"head status", func() *http.Request { return hs.request("HEAD", "/api/status", nil, nil) }, 200, false},
		{"not found", func() *http.Request { return hs.request("GET", "/nope", nil, nil) }, 404, false},
		{"method not allowed", func() *http.Request { return hs.request("GET", "/api/verify", nil, nil) }, 405, false},
		{"options", func() *http.Request { return hs.request("OPTIONS", "/api/notes", nil, nil) }, 405, false},
		{"csrf rejected", func() *http.Request {
			return hs.request("POST", "/api/notes", strings.NewReader("{}"), map[string]string{CSRFHeader: ""})
		}, 403, false},
		{"bad request", func() *http.Request { return hs.request("POST", "/api/notes", strings.NewReader("{"), nil) }, 400, false},
		{"bad host", func() *http.Request {
			r := hs.request("GET", "/", nil, nil)
			r.Host = "evil.com"
			return r
		}, 421, false},
		{"blob download", func() *http.Request { return hs.request("GET", "/api/blobs/"+blob, nil, nil) }, 200, false},
		{"blob view", func() *http.Request { return hs.request("GET", "/api/blobs/"+blob+"/view", nil, nil) }, 200, true},
		{"blob view 404 keeps default CSP", func() *http.Request {
			return hs.request("GET", "/api/blobs/"+strings.Repeat("0", 64)+"/view", nil, nil)
		}, 404, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := hs.serve(tc.req())
			wantStatus(t, rec, tc.code)
			assertSecurityHeaders(t, rec.Header(), tc.sandbox)
		})
	}
}

func TestPanicIsRecoveredAsJSON500(t *testing.T) {
	hs := newHarness(t)
	hs.status.panicMsg = "boom"
	rec := hs.get("/api/status")
	msg := wantJSONError(t, rec, http.StatusInternalServerError)
	if strings.Contains(msg, "boom") {
		t.Errorf("panic value leaked to the client: %q", msg)
	}
	assertSecurityHeaders(t, rec.Header(), false)
}

func TestNotFoundAndMethodNotAllowedAreJSON(t *testing.T) {
	hs := newHarness(t)
	tests := []struct {
		method, path string
		code         int
		allow        string
	}{
		{"GET", "/does-not-exist", 404, ""},
		{"GET", "/api/nope", 404, ""},
		{"GET", "/api/exports/", 404, ""},
		{"GET", "/static/", 404, ""},
		{"GET", "/static/missing.js", 404, ""},
		{"GET", "/api/verify", 405, "POST"},
		{"GET", "/api/anchor", 405, "POST"},
		{"GET", "/api/notes", 405, "POST"},
		{"GET", "/api/gateway/notification", 405, "POST"},
		{"GET", "/api/gateway/trust-cert", 405, "POST"},
		{"POST", "/api/status", 405, "GET, HEAD"},
		{"PUT", "/api/exports", 405, "GET, HEAD, POST"},
		{"DELETE", "/api/blobs/" + strings.Repeat("a", 64), 405, "GET, HEAD"},
		{"POST", "/", 405, "GET, HEAD"},
		{"POST", "/static/app.js", 405, "GET, HEAD"},
	}
	for _, tc := range tests {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			var body io.Reader
			if tc.method != "GET" {
				body = strings.NewReader("{}")
			}
			rec := hs.serve(hs.request(tc.method, tc.path, body, map[string]string{CSRFHeader: CSRFHeaderValue}))
			wantJSONError(t, rec, tc.code)
			if got := rec.Header().Get("Allow"); got != tc.allow {
				t.Errorf("Allow = %q, want %q", got, tc.allow)
			}
		})
	}
}

func TestRequestBodyLimit(t *testing.T) {
	hs := newHarness(t)
	big := `{"text":"` + strings.Repeat("a", MaxBodyBytes) + `"}`

	// Declared length over the limit: rejected before the handler runs.
	rec := hs.post("/api/notes", big)
	wantJSONError(t, rec, http.StatusRequestEntityTooLarge)

	// Unknown length (chunked): the MaxBytesReader stops the decoder.
	req := hs.request(http.MethodPost, "/api/notes", io.MultiReader(strings.NewReader(big)), nil)
	req.ContentLength = -1
	rec = hs.serve(req)
	wantJSONError(t, rec, http.StatusRequestEntityTooLarge)
	if len(hs.actions.notes) != 0 {
		t.Fatal("oversized body reached Actions.Note")
	}
}

// startServer runs s.serve on an ephemeral loopback port. It returns the base URL and an
// idempotent stop function that cancels the server and returns serve's result.
func startServer(t *testing.T, s *Server) (string, func() error) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.serve(ctx, ln) }()
	var once sync.Once
	var result error
	stop := func() error {
		once.Do(func() {
			cancel()
			select {
			case result = <-done:
			case <-time.After(10 * time.Second):
				result = errors.New("server did not stop within 10s")
			}
		})
		return result
	}
	t.Cleanup(func() {
		if err := stop(); err != nil {
			t.Errorf("stopping server: %v", err)
		}
	})
	return "http://" + ln.Addr().String(), stop
}

func TestServeOverTCPAndGracefulShutdown(t *testing.T) {
	hs := newHarness(t)
	base, stop := startServer(t, hs.srv)
	client := &http.Client{Timeout: 5 * time.Second}

	resp, err := client.Get(base + "/api/status")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), `"ONLINE"`) {
		t.Fatalf("GET /api/status over TCP = %d %s", resp.StatusCode, body)
	}

	// localhost with the bound port is allowed; a rebinding Host is not.
	port := strings.TrimPrefix(base, "http://127.0.0.1:")
	for host, code := range map[string]int{"localhost:" + port: 200, "attacker.example:" + port: 421} {
		req, _ := http.NewRequest(http.MethodGet, base+"/api/status", nil)
		req.Host = host
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != code {
			t.Errorf("Host %s: status %d, want %d", host, resp.StatusCode, code)
		}
	}

	// A second serve on the same Server is refused.
	ln2, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if err := hs.srv.serve(context.Background(), ln2); err == nil {
		t.Error("second concurrent serve succeeded")
	}

	client.CloseIdleConnections()
	if err := stop(); err != nil {
		t.Fatalf("serve returned %v after graceful shutdown, want nil", err)
	}
	if _, err := client.Get(base + "/api/status"); err == nil {
		t.Error("server still answering after shutdown")
	}
}

// A connection that never sends a request (browser preconnect) must not turn a normal stop
// into an error; it is closed after the grace period.
func TestShutdownWithLingeringConnection(t *testing.T) {
	old := shutdownTimeout
	shutdownTimeout = 200 * time.Millisecond
	defer func() { shutdownTimeout = old }()

	hs := newHarness(t)
	base, stop := startServer(t, hs.srv)
	conn, err := net.Dial("tcp", strings.TrimPrefix(base, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	time.Sleep(50 * time.Millisecond) // let the server accept it
	start := time.Now()
	if err := stop(); err != nil {
		t.Fatalf("stop = %v, want nil", err)
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Errorf("stop took %v", d)
	}
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Error("lingering connection still open after stop")
	}
}

func TestRunListensOnConfiguredAddress(t *testing.T) {
	// Find a free port, then let Run bind it.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	s, err := New(Options{Listen: addr, Status: &fakeStatus{}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()

	var resp *http.Response
	deadline := time.Now().Add(5 * time.Second)
	for {
		resp, err = http.Get("http://" + addr + "/api/status")
		if err == nil || time.Now().After(deadline) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("Run never served: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}

	// A second Run on the same address fails to listen.
	s2, _ := New(Options{Listen: addr})
	if err := s2.Run(context.Background()); err == nil {
		t.Error("Run on a busy port succeeded")
	}

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Run = %v, want nil after cancel", err)
	}
}

func TestDetachedContext(t *testing.T) {
	hs := newHarness(t)
	reqCtx, cancelReq := context.WithCancel(context.Background())
	req := hs.request(http.MethodPost, "/api/notes", nil, nil).WithContext(reqCtx)
	cancelReq() // the browser went away

	ctx, cancel := hs.srv.detached(req, time.Minute)
	if ctx.Err() != nil {
		t.Fatal("detached context inherited the request cancellation")
	}
	cancel()
	if !errors.Is(ctx.Err(), context.Canceled) {
		t.Fatal("cancel func does not cancel")
	}

	// Server shutdown cancels detached operations.
	runCtx, stop := context.WithCancel(context.Background())
	hs.srv.runCtx.Store(&runCtx)
	ctx2, cancel2 := hs.srv.detached(req, time.Minute)
	defer cancel2()
	stop()
	select {
	case <-ctx2.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("detached context not cancelled by server shutdown")
	}
}

func TestNoteSurvivesClientDisconnect(t *testing.T) {
	hs := newHarness(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req := hs.request(http.MethodPost, "/api/notes", strings.NewReader(`{"text":"hello"}`), nil).WithContext(ctx)
	wantStatus(t, hs.serve(req), http.StatusCreated)
	if got := hs.actions.notes[0].ctxErr; got != nil {
		t.Fatalf("Note saw a cancelled context: %v", got)
	}
}

func TestStatusWriterDefaults(t *testing.T) {
	hs := newHarness(t)
	hs.status.status = model.Status{}
	rec := hs.get("/api/status")
	wantStatus(t, rec, 200)
	st := decode[model.Status](t, rec)
	if st.Conditions == nil || st.Stats == nil {
		t.Fatalf("nil slices must be encoded as []: %s", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"conditions":[]`) {
		t.Errorf("conditions not encoded as []: %s", rec.Body.String())
	}
}
