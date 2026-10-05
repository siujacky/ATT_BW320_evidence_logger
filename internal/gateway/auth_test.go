package gateway

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

const testCode = "Zq7#x9!Lm2" // access code used by the mock gateway

func TestLoginHandshakeAndNotification(t *testing.T) {
	m := newMockGateway(t, testCode, true)
	srv := httptest.NewServer(m)
	defer srv.Close()
	c := newTestClient(t, srv, newFakeClock(), testCode, nil)

	enabled, raw, err := c.Notification(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !enabled {
		t.Error("enabled = false, want true")
	}
	if !bytes.Contains(raw, []byte(`name="bbevent" checked="checked"`)) || IsLoginPage(raw) {
		t.Error("raw is not the authenticated events page")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	// 1st GET: handshake page without nonce; 2nd GET: nonce; POST; verifying GET.
	if got := m.byPath["GET /cgi-bin/events.ha"]; got != 3 {
		t.Errorf("GET events.ha = %d, want 3", got)
	}
	if len(m.loginForms) != 1 {
		t.Fatalf("login POSTs = %d, want 1", len(m.loginForms))
	}
	f := m.loginForms[0]
	if f.Get("password") != strings.Repeat("*", len(testCode)) || f.Get("Continue") != "Continue" ||
		len(f.Get("hashpassword")) != 32 || len(f.Get("nonce")) != 64 {
		t.Errorf("login form = %v", f)
	}
	if f.Get("hashpassword") != md5hex(testCode+f.Get("nonce")) {
		t.Error("hashpassword != md5(code+nonce)")
	}
	// Field order and encoding as a browser submits the form.
	want := "nonce=" + f.Get("nonce") + "&password=" + strings.Repeat("*", len(testCode)) +
		"&hashpassword=" + f.Get("hashpassword") + "&Continue=Continue"
	if m.rawBodies[0] != want {
		t.Errorf("login body = %q, want %q", m.rawBodies[0], want)
	}
	if m.referers[0] != srv.URL+"/cgi-bin/events.ha" {
		t.Errorf("Referer = %q", m.referers[0])
	}
}

func TestSetNotificationRoundTrips(t *testing.T) {
	m := newMockGateway(t, testCode, true)
	srv := httptest.NewServer(m)
	defer srv.Close()
	clk := newFakeClock()
	c := newTestClient(t, srv, clk, testCode, nil)

	// ON -> OFF
	before, after, err := c.SetNotification(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	if on, _ := ParseNotification(before); !on {
		t.Error("before page should show the setting ON")
	}
	if on, _ := ParseNotification(after); on {
		t.Error("after page should show the setting OFF")
	}
	if !bytes.Contains(after, []byte("Changes saved")) {
		t.Error("after page is not the page read after saving")
	}
	if m.setting() {
		t.Fatal("gateway setting still ON")
	}
	m.mu.Lock()
	off := m.eventForms[0]
	offBody := m.rawBodies[len(m.rawBodies)-1]
	m.mu.Unlock()
	if off.Has("bbevent") || off.Get("Save") != "Save" || off.Get("nonce") == "" {
		t.Errorf("disable form = %v", off)
	}
	if offBody != "nonce="+off.Get("nonce")+"&Save=Save" {
		t.Errorf("disable body = %q", offBody)
	}

	// OFF -> ON, within the session reuse window: no second login.
	clk.Advance(30 * time.Second)
	_, after, err = c.SetNotification(context.Background(), true)
	if err != nil {
		t.Fatal(err)
	}
	if on, _ := ParseNotification(after); !on || !m.setting() {
		t.Error("setting not ON after enabling")
	}
	m.mu.Lock()
	on := m.eventForms[1]
	onBody := m.rawBodies[len(m.rawBodies)-1]
	logins := len(m.loginForms)
	m.mu.Unlock()
	if on.Get("bbevent") != "on" || on.Get("Save") != "Save" {
		t.Errorf("enable form = %v", on)
	}
	if onBody != "nonce="+on.Get("nonce")+"&bbevent=on&Save=Save" {
		t.Errorf("enable body = %q", onBody)
	}
	if logins != 1 {
		t.Errorf("logins = %d, want 1 (session reused)", logins)
	}
}

func TestSetNotificationAlreadyAsRequested(t *testing.T) {
	m := newMockGateway(t, testCode, false)
	srv := httptest.NewServer(m)
	defer srv.Close()
	c := newTestClient(t, srv, newFakeClock(), testCode, nil)
	before, after, err := c.SetNotification(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) || len(before) == 0 {
		t.Error("after must be the same body as before when nothing is posted")
	}
	if _, _, posts := m.counts(); posts != 0 {
		t.Errorf("events POSTs = %d, want 0", posts)
	}
}

func TestSetNotificationNotApplied(t *testing.T) {
	m := newMockGateway(t, testCode, true)
	m.ignoreSave = true
	srv := httptest.NewServer(m)
	defer srv.Close()
	c := newTestClient(t, srv, newFakeClock(), testCode, nil)
	before, after, err := c.SetNotification(context.Background(), false)
	if !errors.Is(err, ErrNotApplied) {
		t.Fatalf("err = %v, want ErrNotApplied", err)
	}
	if len(before) == 0 || len(after) == 0 {
		t.Error("before/after evidence must be returned with the error")
	}
}

func TestSessionExpiryAndRelogin(t *testing.T) {
	m := newMockGateway(t, testCode, true)
	srv := httptest.NewServer(m)
	defer srv.Close()
	clk := newFakeClock()
	c := newTestClient(t, srv, clk, testCode, nil)
	if _, _, err := c.Notification(context.Background()); err != nil {
		t.Fatal(err)
	}
	// The gateway forgets the session; the next call detects the login page and logs in
	// again once the one-per-minute limit allows it.
	m.expireSessions()
	clk.Advance(20 * time.Second)
	_, _, err := c.Notification(context.Background())
	if !errors.Is(err, ErrLoginThrottled) {
		t.Fatalf("err = %v, want ErrLoginThrottled", err)
	}
	clk.Advance(41 * time.Second)
	if _, _, err := c.Notification(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, logins, _ := m.counts(); logins != 2 {
		t.Errorf("logins = %d, want 2", logins)
	}
	// After 5 idle minutes the session is not reused even if the gateway would accept it.
	clk.Advance(6 * time.Minute)
	if _, _, err := c.Notification(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, logins, _ := m.counts(); logins != 3 {
		t.Errorf("logins = %d, want 3", logins)
	}
}

func TestLoginRejectedPolicy(t *testing.T) {
	for _, with302 := range []bool{false, true} {
		t.Run(map[bool]string{false: "login page again", true: "302 to login.ha"}[with302], func(t *testing.T) {
			m := newMockGateway(t, "the-real-code", true)
			m.rejectWith302 = with302
			srv := httptest.NewServer(m)
			defer srv.Close()
			clk := newFakeClock()
			c := newTestClient(t, srv, clk, testCode, nil)
			ctx := context.Background()

			for i := 1; i <= 3; i++ {
				_, _, err := c.Notification(ctx)
				if !errors.Is(err, ErrAuth) {
					t.Fatalf("attempt %d: err = %v, want ErrAuth", i, err)
				}
				// Immediately afterwards the per-minute limit applies, without any request.
				req, _, _ := m.counts()
				_, _, err = c.Notification(ctx)
				if i < 3 && !errors.Is(err, ErrLoginThrottled) {
					t.Fatalf("attempt %d: err = %v, want ErrLoginThrottled", i, err)
				}
				if after, _, _ := m.counts(); after != req {
					t.Fatal("a throttled call reached the gateway")
				}
				clk.Advance(61 * time.Second)
			}
			// Three rejections within an hour: locked.
			req, _, _ := m.counts()
			_, _, err := c.Notification(ctx)
			var ce *CooldownError
			if !errors.Is(err, ErrAuthLocked) || !errors.As(err, &ce) {
				t.Fatalf("err = %v, want ErrAuthLocked", err)
			}
			if after, _, _ := m.counts(); after != req {
				t.Fatal("a locked call reached the gateway")
			}
			// One hour after the first failure, attempts resume (and the code is fixed).
			clk.Advance(time.Hour - 3*61*time.Second + time.Second)
			c.accessCode = func() (string, error) { return "the-real-code", nil }
			if _, _, err := c.Notification(ctx); err != nil {
				t.Fatalf("after the lock expired: %v", err)
			}
			c.mu.Lock()
			failures := len(c.auth.failures)
			c.mu.Unlock()
			if failures != 0 {
				t.Errorf("failures after success = %d, want 0", failures)
			}
		})
	}
}

func TestSessionsFullCooldown(t *testing.T) {
	for _, onPost := range []bool{false, true} {
		t.Run(map[bool]string{false: "on GET", true: "on login POST"}[onPost], func(t *testing.T) {
			m := newMockGateway(t, testCode, true)
			if onPost {
				m.fullOnLoginPost = true
			} else {
				m.sessionsFull = true
			}
			srv := httptest.NewServer(m)
			defer srv.Close()
			clk := newFakeClock()
			c := newTestClient(t, srv, clk, testCode, nil)
			ctx := context.Background()

			_, _, err := c.Notification(ctx)
			var ce *CooldownError
			if !errors.Is(err, ErrSessionsFull) || !errors.As(err, &ce) || !ce.Until.Equal(clk.Now().Add(5*time.Minute)) {
				t.Fatalf("err = %v, want ErrSessionsFull with a 5 minute cooldown", err)
			}
			req, _, _ := m.counts()
			for _, d := range []time.Duration{time.Minute, 3 * time.Minute} {
				clk.Advance(d)
				if _, _, err := c.SetNotification(ctx, false); !errors.Is(err, ErrSessionsFull) {
					t.Fatalf("during cooldown: err = %v", err)
				}
			}
			if after, _, _ := m.counts(); after != req {
				t.Fatalf("%d requests during the cooldown", after-req)
			}
			// Not an authentication failure.
			c.mu.Lock()
			failures := len(c.auth.failures)
			c.mu.Unlock()
			if failures != 0 {
				t.Errorf("failures = %d, want 0", failures)
			}
			clk.Advance(61 * time.Second) // cooldown over
			m.set(func(m *mockGateway) { m.sessionsFull, m.fullOnLoginPost = false, false })
			if _, _, err := c.Notification(ctx); err != nil {
				t.Fatalf("after the cooldown: %v", err)
			}
		})
	}
}

func TestLoginHandshakeVariants(t *testing.T) {
	t.Run("never offers a nonce", func(t *testing.T) {
		m := newMockGateway(t, testCode, true)
		m.neverNonce = true
		srv := httptest.NewServer(m)
		defer srv.Close()
		c := newTestClient(t, srv, newFakeClock(), testCode, nil)
		_, _, err := c.Notification(context.Background())
		if err == nil || !strings.Contains(err.Error(), "no login nonce after 6 requests") {
			t.Fatalf("err = %v", err)
		}
		if errors.Is(err, ErrAuth) {
			t.Error("a protocol failure is not an authentication failure")
		}
		m.mu.Lock()
		gets, posts := m.byPath["GET /cgi-bin/events.ha"], len(m.loginForms)
		m.mu.Unlock()
		if gets != 1+handshakeRetries || posts != 0 {
			t.Errorf("GETs=%d POSTs=%d, want %d/0", gets, posts, 1+handshakeRetries)
		}
	})
	t.Run("protected page redirects to login.ha", func(t *testing.T) {
		m := newMockGateway(t, testCode, true)
		m.redirectToLogin = true
		srv := httptest.NewServer(m)
		defer srv.Close()
		c := newTestClient(t, srv, newFakeClock(), testCode, nil)
		on, _, err := c.Notification(context.Background())
		if err != nil || !on {
			t.Fatalf("on=%v err=%v", on, err)
		}
		m.mu.Lock()
		ref := m.referers[0]
		m.mu.Unlock()
		if ref != srv.URL+"/cgi-bin/login.ha" {
			t.Errorf("Referer = %q", ref)
		}
	})
	t.Run("context canceled during backoff", func(t *testing.T) {
		m := newMockGateway(t, testCode, true)
		m.neverNonce = true
		srv := httptest.NewServer(m)
		defer srv.Close()
		c := newTestClient(t, srv, newFakeClock(), testCode, nil)
		c.handshakeBackoff = time.Hour
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		_, _, err := c.Notification(ctx)
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("gateway without access code", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write(fixture(t, "events_unchecked.html"))
		}))
		defer srv.Close()
		c := newTestClient(t, srv, newFakeClock(), testCode, nil)
		on, raw, err := c.Notification(context.Background())
		if err != nil || on || len(raw) == 0 {
			t.Fatalf("on=%v err=%v", on, err)
		}
	})
}

func TestNoAccessCode(t *testing.T) {
	m := newMockGateway(t, testCode, true)
	srv := httptest.NewServer(m)
	defer srv.Close()
	c := newTestClient(t, srv, newFakeClock(), "", nil)
	if _, _, err := c.Notification(context.Background()); !errors.Is(err, ErrNoAccessCode) {
		t.Errorf("nil provider: err = %v", err)
	}
	c.accessCode = func() (string, error) { return "", nil }
	if _, _, err := c.SetNotification(context.Background(), false); !errors.Is(err, ErrNoAccessCode) {
		t.Errorf("empty code: err = %v", err)
	}
	// A faulty provider that leaks the code into its error message is redacted.
	c.accessCode = func() (string, error) { return testCode, errors.New("decrypt failed for " + testCode) }
	_, _, err := c.Notification(context.Background())
	if !errors.Is(err, ErrNoAccessCode) || strings.Contains(err.Error(), testCode) {
		t.Errorf("err = %v", err)
	}
	if req, _, _ := m.counts(); req != 0 {
		t.Errorf("%d requests without an access code", req)
	}
}

func TestAuthenticatedOpsAreSerialized(t *testing.T) {
	m := newMockGateway(t, testCode, true)
	srv := httptest.NewServer(m)
	defer srv.Close()
	c := newTestClient(t, srv, newFakeClock(), testCode, nil)
	var wg sync.WaitGroup
	errs := make(chan error, 6)
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, err := c.Notification(context.Background())
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Error(err)
		}
	}
	if _, logins, _ := m.counts(); logins != 1 {
		t.Errorf("logins = %d, want 1 (one session shared by serialized calls)", logins)
	}
}

func TestAuthOverPinnedTLS(t *testing.T) {
	m := newMockGateway(t, testCode, true)
	srv := httptest.NewTLSServer(m)
	defer srv.Close()
	c := newTestClient(t, srv, newFakeClock(), testCode, nil)
	if c.scheme != "https" {
		t.Fatal("expected https")
	}
	_, after, err := c.SetNotification(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	if on, _ := ParseNotification(after); on || m.setting() {
		t.Error("setting not turned off over TLS")
	}
	if c.PinnedCert() != sha256hex(srv.Certificate().Raw) {
		t.Error("certificate not pinned on first use")
	}
}

// TestSecretsNeverLeak drives every authenticated path (success, wrong code, throttling,
// lockout, sessions full, protocol failure, not applied) with debug logging and checks that
// neither the access code nor any hashpassword appears in an error or in the log.
func TestSecretsNeverLeak(t *testing.T) {
	var logs syncBuffer
	var errs []string
	var hashes []string
	record := func(err error) {
		if err != nil {
			errs = append(errs, err.Error())
		}
	}
	scenario := func(setup func(m *mockGateway), code string, steps func(c *Client, clk *fakeClock)) {
		m := newMockGateway(t, testCode, true)
		if setup != nil {
			setup(m)
		}
		srv := httptest.NewServer(m)
		defer srv.Close()
		clk := newFakeClock()
		c := newTestClient(t, srv, clk, code, &logs)
		steps(c, clk)
		hashes = append(hashes, m.hashes()...)
	}
	ctx := context.Background()
	all := func(c *Client, clk *fakeClock) {
		for i := 0; i < 5; i++ {
			_, _, err := c.Notification(ctx)
			record(err)
			_, _, err = c.SetNotification(ctx, i%2 == 0)
			record(err)
			clk.Advance(61 * time.Second)
		}
	}
	scenario(nil, testCode, all)
	scenario(nil, testCode+"x", all) // wrong code: rejections, throttling, lockout
	scenario(func(m *mockGateway) { m.sessionsFull = true }, testCode, all)
	scenario(func(m *mockGateway) { m.fullOnLoginPost = true }, testCode, all)
	scenario(func(m *mockGateway) { m.neverNonce = true }, testCode, all)
	scenario(func(m *mockGateway) { m.ignoreSave = true }, testCode, all)
	scenario(func(m *mockGateway) { m.rejectWith302 = true }, testCode+"y", all)

	if len(hashes) == 0 || len(errs) == 0 {
		t.Fatalf("scenarios did not exercise logins (%d hashes, %d errors)", len(hashes), len(errs))
	}
	for _, e := range errs {
		mustNotContainSecret(t, "error", e, testCode, hashes)
	}
	mustNotContainSecret(t, "log", logs.String(), testCode, hashes)
	if !strings.Contains(logs.String(), "gateway login rejected") || !strings.Contains(logs.String(), "gateway login succeeded") {
		t.Error("expected login outcomes in the operational log")
	}
}

func TestEncodeForm(t *testing.T) {
	tests := []struct {
		kv   []string
		want string
	}{
		{[]string{"nonce", "ab12", "password", "**********", "Continue", "Continue"}, "nonce=ab12&password=**********&Continue=Continue"},
		{[]string{"a b", "c&d=e", "t", "~x-y_z."}, "a+b=c%26d%3De&t=%7Ex-y_z."},
		{[]string{"k", ""}, "k="},
		{nil, ""},
	}
	for _, tt := range tests {
		if got := encodeForm(tt.kv...); got != tt.want {
			t.Errorf("encodeForm(%q) = %q, want %q", tt.kv, got, tt.want)
		}
	}
}

func TestCooldownErrorMessage(t *testing.T) {
	e := &CooldownError{Err: ErrSessionsFull, Until: time.Date(2026, 10, 5, 3, 15, 43, 0, time.UTC)}
	if !errors.Is(e, ErrSessionsFull) || e.Error() != "gateway: all web server sessions are in use (no login attempt before 2026-10-05T03:15:43Z)" {
		t.Errorf("%v", e)
	}
	ce := &CertError{Pinned: "", Observed: "abc"}
	if !errors.Is(ce, ErrCertRejected) || !strings.Contains(ce.Error(), "no pin yet") {
		t.Errorf("%v", ce)
	}
}
