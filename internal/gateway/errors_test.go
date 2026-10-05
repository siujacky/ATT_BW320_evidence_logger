package gateway

// Every gateway error that has a counterpart in internal/contracts must match it with
// errors.Is, so that the monitor and the web layer can react to gateway conditions (pause
// logins, map to HTTP statuses, raise GATEWAY_CERT_CHANGED) without importing this package -
// while the gateway's own sentinels and error types keep working.

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"attmonitor/internal/contracts"
)

// contractSentinels are the gateway sentinels of internal/contracts.
var contractSentinels = map[string]error{
	"ErrGatewaySessionsFull":   contracts.ErrGatewaySessionsFull,
	"ErrGatewayAuth":           contracts.ErrGatewayAuth,
	"ErrGatewayAuthLocked":     contracts.ErrGatewayAuthLocked,
	"ErrGatewayLoginThrottled": contracts.ErrGatewayLoginThrottled,
	"ErrGatewayCertRejected":   contracts.ErrGatewayCertRejected,
	"ErrGatewayNoAccessCode":   contracts.ErrGatewayNoAccessCode,
}

// checkSentinels asserts that err matches both the gateway sentinel gw and the contracts
// sentinel contract, and no other contracts gateway sentinel.
func checkSentinels(t *testing.T, err, gw, contract error) {
	t.Helper()
	if err == nil {
		t.Fatal("no error returned")
	}
	if !errors.Is(err, gw) {
		t.Errorf("errors.Is(%q, gateway sentinel %q) = false", err, gw)
	}
	if !errors.Is(err, contract) {
		t.Errorf("errors.Is(%q, contracts sentinel %q) = false", err, contract)
	}
	for name, other := range contractSentinels {
		if other != contract && errors.Is(err, other) {
			t.Errorf("error %q also matches contracts.%s", err, name)
		}
	}
}

func TestGatewaySentinelsMatchContracts(t *testing.T) {
	tests := []struct {
		gw, contract error
		// The gateway's own messages are kept: they end up in recorded results
		// (NotificationState.Err, ConfigChange.Result "failed: ...").
		msg string
	}{
		{ErrSessionsFull, contracts.ErrGatewaySessionsFull, "gateway: all web server sessions are in use"},
		{ErrAuth, contracts.ErrGatewayAuth, "gateway: login rejected"},
		{ErrAuthLocked, contracts.ErrGatewayAuthLocked, "gateway: logins paused after 3 rejected attempts within an hour"},
		{ErrLoginThrottled, contracts.ErrGatewayLoginThrottled, "gateway: at most one login attempt per minute"},
		{ErrCertRejected, contracts.ErrGatewayCertRejected, "gateway: TLS certificate rejected by pin policy"},
		{ErrNoAccessCode, contracts.ErrGatewayNoAccessCode, "gateway: no access code available"},
	}
	for _, tt := range tests {
		t.Run(tt.msg, func(t *testing.T) {
			if got := tt.gw.Error(); got != tt.msg {
				t.Errorf("message = %q, want %q", got, tt.msg)
			}
			checkSentinels(t, tt.gw, tt.gw, tt.contract)
			checkSentinels(t, fmt.Errorf("context: %w", tt.gw), tt.gw, tt.contract)
			if errors.Is(tt.contract, tt.gw) {
				t.Error("the contracts sentinel must not match the gateway sentinel")
			}
		})
	}
	// The error types that carry the sentinels.
	until := time.Date(2026, 10, 5, 3, 15, 43, 0, time.UTC)
	for _, tt := range []struct{ gw, contract error }{
		{ErrSessionsFull, contracts.ErrGatewaySessionsFull},
		{ErrAuthLocked, contracts.ErrGatewayAuthLocked},
		{ErrLoginThrottled, contracts.ErrGatewayLoginThrottled},
	} {
		ce := &CooldownError{Err: tt.gw, Until: until}
		checkSentinels(t, ce, tt.gw, tt.contract)
		checkSentinels(t, fmt.Errorf("x: %w", ce), tt.gw, tt.contract)
	}
	for _, ce := range []*CertError{
		{Pinned: "", Observed: "ab"},
		{Pinned: "cd", Observed: "ab"},
		{Pinned: "cd", Observed: "ab", Reason: "the certificate observer failed"},
	} {
		checkSentinels(t, ce, ErrCertRejected, contracts.ErrGatewayCertRejected)
		checkSentinels(t, fmt.Errorf("x: %w", ce), ErrCertRejected, contracts.ErrGatewayCertRejected)
	}
	// Errors without a contracts counterpart match none of them.
	for _, err := range []error{ErrNotApplied, ErrLoginRequired, ErrUnexpectedPage} {
		for name, c := range contractSentinels {
			if errors.Is(err, c) {
				t.Errorf("%q matches contracts.%s", err, name)
			}
		}
	}
}

// fullAfterLogin serves the mock gateway until the login form has been posted; from then on
// every GET answers "all web server sessions are in use" (the verifying GET of a login).
type fullAfterLogin struct {
	m        *mockGateway
	loggedIn atomic.Bool
}

func (h *fullAfterLogin) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet && h.loggedIn.Load() {
		h.m.write(w, http.StatusOK, sessionsFullPage(h.m.t))
		return
	}
	h.m.ServeHTTP(w, r)
	if r.Method == http.MethodPost && r.URL.Path == "/cgi-bin/login.ha" {
		h.loggedIn.Store(true)
	}
}

// TestErrorPathsMatchContractSentinels drives every path that produces one of the errors with
// a contracts counterpart and checks that the returned error matches both sentinels.
func TestErrorPathsMatchContractSentinels(t *testing.T) {
	ctx := context.Background()
	// mock starts a mock gateway (access code gwCode, adjusted by setup) and a client using code.
	mock := func(t *testing.T, gwCode, code string, setup func(m *mockGateway)) (*mockGateway, *Client, *fakeClock) {
		m := newMockGateway(t, gwCode, true)
		if setup != nil {
			setup(m)
		}
		srv := httptest.NewServer(m)
		t.Cleanup(srv.Close)
		clk := newFakeClock()
		return m, newTestClient(t, srv, clk, code, nil), clk
	}
	// tlsGateway starts a TLS mock gateway whose certificate the client below does not accept.
	tlsGateway := func(t *testing.T, pin string, obs contracts.CertObserver) *Client {
		srv, _, _ := newTLSGateway(t)
		c := tlsClient(srv, pin, obs)
		c.accessCode = func() (string, error) { return testCode, nil }
		return c
	}
	wrongPin := strings.Repeat("ab", 32)
	decline := func(prev, observed string) bool { return false }

	tests := []struct {
		name     string
		gw       error
		contract error
		run      func(t *testing.T) error
	}{
		// ------------------------------------------------ sessions full (5 minute cooldown)
		{"sessions full: login handshake GET", ErrSessionsFull, contracts.ErrGatewaySessionsFull, func(t *testing.T) error {
			_, c, _ := mock(t, testCode, testCode, func(m *mockGateway) { m.sessionsFull = true })
			_, _, err := c.Notification(ctx)
			return err
		}},
		{"sessions full: login POST", ErrSessionsFull, contracts.ErrGatewaySessionsFull, func(t *testing.T) error {
			_, c, _ := mock(t, testCode, testCode, func(m *mockGateway) { m.fullOnLoginPost = true })
			_, _, err := c.Notification(ctx)
			return err
		}},
		{"sessions full: verifying GET after the login POST", ErrSessionsFull, contracts.ErrGatewaySessionsFull, func(t *testing.T) error {
			srv := httptest.NewServer(&fullAfterLogin{m: newMockGateway(t, testCode, true)})
			t.Cleanup(srv.Close)
			_, _, err := newTestClient(t, srv, newFakeClock(), testCode, nil).Notification(ctx)
			return err
		}},
		{"sessions full: reused session", ErrSessionsFull, contracts.ErrGatewaySessionsFull, func(t *testing.T) error {
			m, c, clk := mock(t, testCode, testCode, nil)
			if _, _, err := c.Notification(ctx); err != nil {
				t.Fatal(err)
			}
			m.set(func(m *mockGateway) { m.sessionsFull = true })
			clk.Advance(30 * time.Second) // the session is still reused
			_, _, err := c.Notification(ctx)
			return err
		}},
		{"sessions full: settings POST", ErrSessionsFull, contracts.ErrGatewaySessionsFull, func(t *testing.T) error {
			m := newMockGateway(t, testCode, true)
			srv := httptest.NewServer(&postInterceptor{m: m, onPost: func(w http.ResponseWriter, r *http.Request) bool {
				m.write(w, http.StatusOK, sessionsFullPage(m.t))
				return true
			}})
			t.Cleanup(srv.Close)
			_, _, err := newTestClient(t, srv, newFakeClock(), testCode, nil).SetNotification(ctx, false)
			return err
		}},
		{"sessions full: cooldown, no request", ErrSessionsFull, contracts.ErrGatewaySessionsFull, func(t *testing.T) error {
			m, c, clk := mock(t, testCode, testCode, func(m *mockGateway) { m.sessionsFull = true })
			_, _, _ = c.Notification(ctx)
			m.set(func(m *mockGateway) { m.sessionsFull = false })
			clk.Advance(time.Minute)
			_, _, err := c.SetNotification(ctx, false)
			return err
		}},
		{"sessions full: seen by a snapshot, then a login", ErrSessionsFull, contracts.ErrGatewaySessionsFull, func(t *testing.T) error {
			_, c, _ := mock(t, testCode, testCode, func(m *mockGateway) { m.pages["sysinfo"] = sessionsFullPage(t) })
			if _, _, err := c.Snapshot(ctx, []string{"sysinfo"}, "test"); err != nil {
				t.Fatal(err)
			}
			_, _, err := c.Notification(ctx)
			return err
		}},

		// ------------------------------------------------ login rejected
		{"login rejected: login page returned again", ErrAuth, contracts.ErrGatewayAuth, func(t *testing.T) error {
			_, c, _ := mock(t, "the-real-code", testCode, nil)
			_, _, err := c.Notification(ctx)
			return err
		}},
		{"login rejected: 302 back to login.ha", ErrAuth, contracts.ErrGatewayAuth, func(t *testing.T) error {
			_, c, _ := mock(t, "the-real-code", testCode, func(m *mockGateway) { m.rejectWith302 = true })
			_, _, err := c.SetNotification(ctx, false)
			return err
		}},
		{"login rejected: verifying GET redirected to login.ha", ErrAuth, contracts.ErrGatewayAuth, func(t *testing.T) error {
			_, c, _ := mock(t, "the-real-code", testCode, func(m *mockGateway) { m.redirectToLogin, m.rejectAs302Home = true, true })
			_, _, err := c.Notification(ctx)
			return err
		}},

		// ------------------------------------------------ lockout and spacing
		{"lockout after 3 rejected logins within an hour", ErrAuthLocked, contracts.ErrGatewayAuthLocked, func(t *testing.T) error {
			_, c, clk := mock(t, "the-real-code", testCode, nil)
			for i := 0; i < maxFailures; i++ {
				if _, _, err := c.Notification(ctx); !errors.Is(err, ErrAuth) {
					t.Fatalf("attempt %d: %v", i+1, err)
				}
				clk.Advance(loginSpacing + time.Second)
			}
			_, _, err := c.Notification(ctx)
			return err
		}},
		{"login within 60 s of the previous attempt", ErrLoginThrottled, contracts.ErrGatewayLoginThrottled, func(t *testing.T) error {
			_, c, clk := mock(t, "the-real-code", testCode, nil)
			if _, _, err := c.Notification(ctx); !errors.Is(err, ErrAuth) {
				t.Fatal(err)
			}
			clk.Advance(loginSpacing - time.Second)
			_, _, err := c.SetNotification(ctx, false)
			return err
		}},

		// ------------------------------------------------ certificate rejected by pin / observer
		{"certificate: login over TLS, pin mismatch", ErrCertRejected, contracts.ErrGatewayCertRejected, func(t *testing.T) error {
			_, _, err := tlsGateway(t, wrongPin, nil).Notification(ctx)
			return err
		}},
		{"certificate: observer declines first use", ErrCertRejected, contracts.ErrGatewayCertRejected, func(t *testing.T) error {
			_, _, err := tlsGateway(t, "", decline).SetNotification(ctx, false)
			return err
		}},
		{"certificate: observer panics", ErrCertRejected, contracts.ErrGatewayCertRejected, func(t *testing.T) error {
			_, _, err := tlsGateway(t, wrongPin, func(prev, observed string) bool { panic("observer bug") }).Notification(ctx)
			return err
		}},
		{"certificate: snapshot, pin mismatch", ErrCertRejected, contracts.ErrGatewayCertRejected, func(t *testing.T) error {
			_, _, err := tlsGateway(t, wrongPin, nil).Snapshot(ctx, []string{"sysinfo", "fiberstat"}, "test")
			return err
		}},
		{"certificate: snapshot, observer declines first use", ErrCertRejected, contracts.ErrGatewayCertRejected, func(t *testing.T) error {
			_, _, err := tlsGateway(t, "", decline).Snapshot(ctx, []string{"sysinfo"}, "test")
			return err
		}},
		{"certificate: reused session meets a new certificate", ErrCertRejected, contracts.ErrGatewayCertRejected, func(t *testing.T) error {
			srv1 := httptest.NewUnstartedServer(newMockGateway(t, testCode, true))
			srv1.Config.ErrorLog = log.New(io.Discard, "", 0)
			srv1.StartTLS()
			t.Cleanup(srv1.Close)
			srv2 := httptest.NewUnstartedServer(newMockGateway(t, testCode, true))
			srv2.Config.ErrorLog = log.New(io.Discard, "", 0)
			srv2.TLS = &tls.Config{Certificates: []tls.Certificate{selfSignedCert(t)}}
			srv2.StartTLS()
			t.Cleanup(srv2.Close)
			clk := newFakeClock()
			c := newTestClient(t, srv1, clk, testCode, nil) // trust on first use
			if _, _, err := c.Notification(ctx); err != nil {
				t.Fatal(err)
			}
			c.SetCertObserver(decline)
			c.host = strings.TrimPrefix(srv2.URL, "https://")
			clk.Advance(30 * time.Second) // the session is still reused
			_, _, err := c.Notification(ctx)
			return err
		}},

		// ------------------------------------------------ no access code
		{"no access code: none configured", ErrNoAccessCode, contracts.ErrGatewayNoAccessCode, func(t *testing.T) error {
			_, c, _ := mock(t, testCode, "", nil)
			_, _, err := c.Notification(ctx)
			return err
		}},
		{"no access code: empty code", ErrNoAccessCode, contracts.ErrGatewayNoAccessCode, func(t *testing.T) error {
			_, c, _ := mock(t, testCode, testCode, nil)
			c.accessCode = func() (string, error) { return "", nil }
			_, _, err := c.SetNotification(ctx, false)
			return err
		}},
		{"no access code: secret store failed", ErrNoAccessCode, contracts.ErrGatewayNoAccessCode, func(t *testing.T) error {
			_, c, _ := mock(t, testCode, testCode, nil)
			c.accessCode = func() (string, error) { return "", errors.New("DPAPI: the data is invalid") }
			_, _, err := c.Notification(ctx)
			return err
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checkSentinels(t, tt.run(t), tt.gw, tt.contract)
		})
	}
}
