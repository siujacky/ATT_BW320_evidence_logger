package gateway

import (
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"attmonitor/internal/config"
)

// The authenticated session across reads that fail (docs/DESIGN.md §2: logins must be rare). The
// NAT table is read every few minutes: a read that fails in a way that says nothing about the
// session - an error page, a redirect elsewhere, a page too large, a page that does not arrive in
// time, a read the caller stops - must not log in again, nor leave a session behind on the gateway.

// midBody is how long a test waits after the gateway began a stalled answer before it stops the
// read: the answer's head (its status) has arrived by then, so the read stops in the body.
const midBody = 100 * time.Millisecond

// natReads reads the NAT table n times, every apart on clk, and returns the errors.
func natReads(c *Client, clk *fakeClock, n int, every time.Duration) []error {
	var errs []error
	for range n {
		_, _, err := c.NATTable(context.Background())
		errs = append(errs, err)
		clk.Advance(every)
	}
	return errs
}

// TestNATReadFailuresKeepTheSession: after a read that worked, reads 4 minutes apart that fail -
// HTTP 500, a redirect to a page this firmware does not have, a page over the cap, a page whose
// body stalls until the request times out - cost no further login and leave one authenticated
// session on the gateway; the answer that came is returned with the error. The session is given up
// only when the gateway answers with its login page.
func TestNATReadFailuresKeepTheSession(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(g *networkGateway, c *Client)
		want  string // in each failed read's error
		raw   bool   // the answer comes with the error
	}{
		{"HTTP 500", func(g *networkGateway, c *Client) { g.natFault = "error" }, "unexpected HTTP status 500", true},
		{"a redirect elsewhere", func(g *networkGateway, c *Client) { g.natFault = "elsewhere" }, "unexpected HTTP status 302", false},
		{"a page over the cap", func(g *networkGateway, c *Client) {
			g.nat = bigNATPage(2000)
			c.natMaxBody = 64 << 10
		}, "truncated", true},
		{"a page that does not arrive in time", func(g *networkGateway, c *Client) {
			g.natFault = "stall"
			c.timeout = 300 * time.Millisecond
		}, "deadline exceeded", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := newNetworkGateway(t, testCode)
			clk := newFakeClock()
			c, _ := startNetwork(t, g, clk, nil)
			if _, _, err := c.NATTable(context.Background()); err != nil {
				t.Fatal(err)
			}
			clk.Advance(4 * time.Minute)
			g.mu.Lock()
			tc.setup(g, c)
			g.mu.Unlock()
			for i, err := range natReads(c, clk, 10, 4*time.Minute) {
				if err == nil || !strings.Contains(err.Error(), tc.want) {
					t.Fatalf("read %d: err = %v, want it to say %q", i+2, err, tc.want)
				}
			}
			if _, logins, _ := g.counts(); logins != 1 {
				t.Errorf("%d login POSTs for 11 reads, want 1 (the first read's)", logins)
			}
			if authed := g.authedSessions(); len(authed) != 1 {
				t.Errorf("%d authenticated sessions left on the gateway, want 1", len(authed))
			}
			if n := c.LoginAttempts(); n != 1 {
				t.Errorf("LoginAttempts = %d, want 1", n)
			}
			_, raw, _ := c.NATTable(context.Background())
			if tc.raw != (len(raw) > 0) {
				t.Errorf("raw = %d bytes with the error", len(raw))
			}
			onlyReads(t, g.requestLog(), 1)

			// The page comes again: the same session reads it.
			g.mu.Lock()
			g.natFault, g.nat = "", fixture(t, "nattable_synthetic.html")
			g.mu.Unlock()
			c.timeout = 5 * time.Second
			got, _, err := c.NATTable(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			compareNAT(t, got, wantNATSynthetic)
			if _, logins, _ := g.counts(); logins != 1 {
				t.Errorf("%d login POSTs once the page came again, want 1", logins)
			}
		})
	}
}

// TestNATReadStoppedMidBody: a read that the caller stops while the page arrives - as the monitor
// stops a read when the gateway is needed for evidence - keeps the session (the page was served),
// records no login attempt, and the next read, half a minute later, reuses the session: no login,
// so no refusal of the one-a-minute limit either.
func TestNATReadStoppedMidBody(t *testing.T) {
	g := newNetworkGateway(t, testCode)
	clk := newFakeClock()
	c, _ := startNetwork(t, g, clk, nil)
	if _, _, err := c.NATTable(context.Background()); err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	attempt := c.auth.lastAttempt
	c.mu.Unlock()
	for range 3 {
		clk.Advance(4 * time.Minute)
		g.mu.Lock()
		g.natFault, g.natStalled = "stall", make(chan struct{}, 1)
		stalled := g.natStalled
		g.mu.Unlock()
		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			<-stalled
			time.Sleep(midBody) // the answer's head has arrived: the read stops in its body
			cancel()
		}()
		if _, _, err := c.NATTable(ctx); !errors.Is(err, context.Canceled) {
			t.Fatalf("err = %v, want context.Canceled", err)
		}
		cancel()
		c.mu.Lock()
		same, kept := c.auth.lastAttempt.Equal(attempt), c.auth.sess != nil
		c.mu.Unlock()
		if !same || !kept {
			t.Fatalf("after the stopped read: login attempt recorded %v, session kept %v", !same, kept)
		}
		clk.Advance(30 * time.Second)
		g.mu.Lock()
		g.natFault = ""
		g.mu.Unlock()
		if _, _, err := c.NATTable(context.Background()); err != nil {
			t.Fatalf("the read half a minute later: %v", err)
		}
	}
	if _, logins, _ := g.counts(); logins != 1 {
		t.Errorf("%d login POSTs, want 1", logins)
	}
	if authed := g.authedSessions(); len(authed) != 1 {
		t.Errorf("%d authenticated sessions, want 1", len(authed))
	}
}

// TestLoginNotBegunForACallerThatGaveUp: a read whose context has ended before it logs in records no
// login attempt, keeps the session there is and sends nothing.
func TestLoginNotBegunForACallerThatGaveUp(t *testing.T) {
	g := newNetworkGateway(t, testCode)
	clk := newFakeClock()
	c, _ := startNetwork(t, g, clk, nil)
	if _, _, err := c.Notification(context.Background()); err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	attempt, sess := c.auth.lastAttempt, c.auth.sess
	c.mu.Unlock()
	clk.Advance(2 * time.Minute)
	g.expireSessions() // the next request would have to log in
	requests := len(g.requestLog())
	if _, _, err := c.login(canceledContext(), natPage); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.auth.lastAttempt.Equal(attempt) || c.auth.sess != sess {
		t.Error("a login the caller gave up on recorded an attempt or dropped the session")
	}
	if n := len(g.requestLog()) - requests; n != 0 {
		t.Errorf("%d requests for a login the caller gave up on", n)
	}
}

func canceledContext() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

// TestLoginKeptWhenItsPageDoesNotCome: the gateway accepts the login form, but the page that
// verifies it does not come - the caller stops the read during it, or the page is an error page.
// The new session is kept: the next read reuses it, with one GET and no second login.
func TestLoginKeptWhenItsPageDoesNotCome(t *testing.T) {
	for _, fault := range []string{"stall", "error"} {
		t.Run(fault, func(t *testing.T) {
			g := newNetworkGateway(t, testCode)
			clk := newFakeClock()
			c, _ := startNetwork(t, g, clk, nil)
			for range 3 {
				g.mu.Lock()
				g.natFault, g.natStalled = fault, make(chan struct{}, 1)
				stalled := g.natStalled
				g.mu.Unlock()
				ctx, cancel := context.WithCancel(context.Background())
				go func() {
					select {
					case <-stalled:
						time.Sleep(midBody)
						cancel()
					case <-ctx.Done():
					}
				}()
				if _, _, err := c.NATTable(ctx); err == nil {
					t.Fatal("the read worked")
				}
				cancel()
				clk.Advance(4 * time.Minute)
			}
			g.mu.Lock()
			g.natFault = ""
			g.mu.Unlock()
			if _, _, err := c.NATTable(context.Background()); err != nil {
				t.Fatal(err)
			}
			if _, logins, _ := g.counts(); logins != 1 {
				t.Errorf("%d login POSTs, want 1", logins)
			}
			if authed := g.authedSessions(); len(authed) != 1 {
				t.Errorf("%d authenticated sessions left on the gateway, want 1", len(authed))
			}
			c.mu.Lock()
			failures := len(c.auth.failures)
			c.mu.Unlock()
			if failures != 0 {
				t.Errorf("%d rejected logins counted", failures)
			}
		})
	}
}

// TestNATFailureBetweenSettingsRequests: the settings check reads the redirect setting, a NAT read
// in between fails with HTTP 500, and the change that enforces the setting follows seconds later:
// it reuses the session (a new login would be refused by the one-a-minute limit).
func TestNATFailureBetweenSettingsRequests(t *testing.T) {
	g := newNetworkGateway(t, testCode)
	g.bbevent = true
	clk := newFakeClock()
	c, _ := startNetwork(t, g, clk, nil)
	ctx := context.Background()
	if on, _, err := c.Notification(ctx); err != nil || !on {
		t.Fatalf("notification %v, %v", on, err)
	}
	g.mu.Lock()
	g.natFault = "error"
	g.mu.Unlock()
	clk.Advance(2 * time.Second)
	if _, _, err := c.NATTable(ctx); err == nil {
		t.Fatal("the NAT read worked")
	}
	clk.Advance(2 * time.Second)
	if _, _, err := c.SetNotification(ctx, false); err != nil {
		t.Fatalf("the change after the failed NAT read: %v", err)
	}
	if g.setting() {
		t.Error("the setting was not changed")
	}
	if _, logins, _ := g.counts(); logins != 1 {
		t.Errorf("%d login POSTs, want 1", logins)
	}
}

// TestSessionAnsweringOnlyErrorsIsRenewedHourly: a session that keeps getting answers that are
// neither the page nor the login page is relied on for an hour after it last served a page at
// most - should such an answer be some firmware's way of saying that the session is gone, the
// authenticated requests do not fail for good.
func TestSessionAnsweringOnlyErrorsIsRenewedHourly(t *testing.T) {
	g := newNetworkGateway(t, testCode)
	clk := newFakeClock()
	c, _ := startNetwork(t, g, clk, nil)
	if _, _, err := c.NATTable(context.Background()); err != nil {
		t.Fatal(err)
	}
	g.mu.Lock()
	g.natFault = "elsewhere"
	g.mu.Unlock()
	natReads(c, clk, 14, 4*time.Minute) // 56 minutes
	if _, logins, _ := g.counts(); logins != 1 {
		t.Fatalf("%d login POSTs within the hour, want 1", logins)
	}
	natReads(c, clk, 2, 4*time.Minute) // an hour after the last page: a new login
	if _, logins, _ := g.counts(); logins != 2 {
		t.Errorf("%d login POSTs after the hour, want 2", logins)
	}
}

// TestLoginAttemptsCountsLoginForms: every login form posted counts, rejected ones too; a read in
// a reused session and a refused login count nothing.
func TestLoginAttemptsCountsLoginForms(t *testing.T) {
	g := newNetworkGateway(t, "the-real-code")
	clk := newFakeClock()
	c, _ := startNetwork(t, g, clk, nil)
	ctx := context.Background()
	if _, _, err := c.NATTable(ctx); !errors.Is(err, ErrAuth) {
		t.Fatalf("err = %v, want ErrAuth", err)
	}
	if _, _, err := c.NATTable(ctx); !errors.Is(err, ErrLoginThrottled) {
		t.Fatalf("err = %v, want ErrLoginThrottled", err)
	}
	if n := c.LoginAttempts(); n != 1 {
		t.Fatalf("LoginAttempts = %d after a rejected and a refused login, want 1", n)
	}
	clk.Advance(loginSpacing)
	c.accessCode = func() (string, error) { return "the-real-code", nil }
	for range 3 {
		if _, _, err := c.NATTable(ctx); err != nil {
			t.Fatal(err)
		}
		clk.Advance(time.Minute)
	}
	if n := c.LoginAttempts(); n != 2 {
		t.Errorf("LoginAttempts = %d, want 2", n)
	}
}

// TestLoginPolicyOutlivesTheProcess: what OnLoginPolicy is given is what a new client restored
// from it enforces - three rejected logins lock the logins of the next process too, and an attempt
// a few seconds ago throttles it - without a request to the gateway. Times after now count as now.
func TestLoginPolicyOutlivesTheProcess(t *testing.T) {
	g := newNetworkGateway(t, "the-real-code")
	srv := httptest.NewServer(g)
	t.Cleanup(srv.Close)
	clk := newFakeClock()
	var saved LoginPolicy
	var saves int
	newClient := func(restore LoginPolicy) *Client {
		c := newTestClient(t, srv, clk, testCode, nil)
		c.onPolicy = func(p LoginPolicy) { saved, saves = p, saves+1 }
		c.restorePolicy(restore, clk.Now())
		return c
	}
	c := newClient(LoginPolicy{})
	for i := range maxFailures {
		if _, _, err := c.NATTable(context.Background()); !errors.Is(err, ErrAuth) {
			t.Fatalf("attempt %d: err = %v, want ErrAuth", i+1, err)
		}
		clk.Advance(loginSpacing)
	}
	if len(saved.Failures) != maxFailures || saved.LastAttempt.IsZero() || saves < 2*maxFailures {
		t.Fatalf("saved %+v after %d saves", saved, saves)
	}
	// The service restarts: the logins stay locked, and no request is made.
	requests := len(g.requestLog())
	c = newClient(saved)
	if _, _, err := c.NATTable(context.Background()); !errors.Is(err, ErrAuthLocked) {
		t.Fatalf("after a restart: err = %v, want ErrAuthLocked", err)
	}
	// So does a client made with the saved policy in its options.
	c = New(Options{Host: strings.TrimPrefix(srv.URL, "http://"), Scheme: "http", Now: clk.Now,
		AccessCode: func() (string, error) { return testCode, nil }, LoginPolicy: saved})
	if _, _, err := c.NATTable(context.Background()); !errors.Is(err, ErrAuthLocked) {
		t.Fatalf("New with Options.LoginPolicy: err = %v, want ErrAuthLocked", err)
	}
	if n := len(g.requestLog()) - requests; n != 0 {
		t.Errorf("%d requests after the restart", n)
	}
	// An attempt seconds before the restart throttles the next one.
	clk.Advance(2 * time.Hour)
	c = newClient(LoginPolicy{LastAttempt: clk.Now().Add(-10 * time.Second)})
	if _, _, err := c.NATTable(context.Background()); !errors.Is(err, ErrLoginThrottled) {
		t.Fatalf("err = %v, want ErrLoginThrottled", err)
	}
	// A clock set back: times after now count as now, so the pauses end on time.
	future := clk.Now().Add(48 * time.Hour)
	c = newClient(LoginPolicy{LastAttempt: future, Failures: []time.Time{future, future, future}, FullUntil: future})
	var ce *CooldownError
	if _, _, err := c.NATTable(context.Background()); !errors.As(err, &ce) {
		t.Fatalf("err = %v, want a cooldown", err)
	} else if limit := clk.Now().Add(failureWindow); ce.Until.After(limit) {
		t.Errorf("the cooldown ends %v, after %v", ce.Until, limit)
	}
	c.mu.Lock()
	full := c.auth.fullUntil
	c.mu.Unlock()
	if full.After(clk.Now().Add(sessionsFullCooldown)) {
		t.Errorf("sessions-full pause until %v", full)
	}
}

// TestNATReadsStayWithinTheSessionReuse: the longest NAT read interval the configuration accepts,
// with the half minute a round skipped for the evidence is tried again later, stays within the
// time the client reuses its session: the reads keep one session, and need no login each.
func TestNATReadsStayWithinTheSessionReuse(t *testing.T) {
	const retryMargin = 30 * time.Second
	if config.MaxConnInterval+retryMargin >= SessionReuse {
		t.Fatalf("connections.interval may be %v: with the retry after a skipped round (%v) that is not within the session reuse (%v)",
			config.MaxConnInterval, retryMargin, SessionReuse)
	}
	if d := config.Default().Connections.Interval.Duration; d > config.MaxConnInterval {
		t.Fatalf("the default interval %v exceeds the maximum %v", d, config.MaxConnInterval)
	}
}
