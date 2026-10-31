package gateway

import (
	"context"
	"errors"
	"testing"
	"time"

	"attmonitor/internal/contracts"
)

// TestNATTableWithoutLogin: in a context of contracts.WithoutGatewayLogin a NAT read reuses the
// client's session but makes no login: without a session to reuse it sends nothing, and when the
// gateway says that the session is gone it posts no login form; both fail with
// contracts.ErrGatewayLoginNeeded. Without the mark, a read logs in as usual.
func TestNATTableWithoutLogin(t *testing.T) {
	g := newNetworkGateway(t, testCode)
	clk := newFakeClock()
	c, _ := startNetwork(t, g, clk, nil)
	ctx := context.Background()
	noLogin := contracts.WithoutGatewayLogin(ctx)
	if !contracts.GatewayLoginForbidden(noLogin) || contracts.GatewayLoginForbidden(ctx) {
		t.Fatal("GatewayLoginForbidden does not tell the contexts apart")
	}

	// No session yet: nothing is sent.
	if _, _, err := c.NATTable(noLogin); !errors.Is(err, contracts.ErrGatewayLoginNeeded) {
		t.Fatalf("err = %v, want ErrGatewayLoginNeeded", err)
	}
	if log := g.requestLog(); len(log) != 0 {
		t.Fatalf("requests without a session to reuse: %q", log)
	}
	// A login (no mark), then reads in its session with the mark: one GET each.
	if _, _, err := c.NATTable(ctx); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		clk.Advance(4 * time.Minute)
		got, _, err := c.NATTable(noLogin)
		if err != nil {
			t.Fatal(err)
		}
		compareNAT(t, got, wantNATSynthetic)
	}
	if _, logins, _ := g.counts(); logins != 1 {
		t.Errorf("logins = %d, want 1", logins)
	}
	// The gateway forgets the session: the marked read finds the login page and posts nothing ...
	g.expireSessions()
	n := len(g.requestLog())
	clk.Advance(4 * time.Minute)
	if _, _, err := c.NATTable(noLogin); !errors.Is(err, contracts.ErrGatewayLoginNeeded) {
		t.Fatalf("err = %v, want ErrGatewayLoginNeeded", err)
	}
	if log := g.requestLog(); len(log) != n+1 {
		t.Errorf("requests after the session was forgotten: %q, want one GET", log[n:])
	}
	// ... and gives the session up: the next marked read sends nothing.
	if _, _, err := c.NATTable(noLogin); !errors.Is(err, contracts.ErrGatewayLoginNeeded) {
		t.Fatalf("err = %v, want ErrGatewayLoginNeeded", err)
	}
	if log := g.requestLog(); len(log) != n+1 {
		t.Errorf("requests without a session: %q", log[n:])
	}
	if _, logins, _ := g.counts(); logins != 1 || c.LoginAttempts() != 1 {
		t.Errorf("logins = %d, login attempts = %d, want 1 and 1", logins, c.LoginAttempts())
	}
	onlyReads(t, g.requestLog(), 1)
	// Without the mark the next read logs in.
	clk.Advance(2 * time.Minute)
	if _, _, err := c.NATTable(ctx); err != nil {
		t.Fatal(err)
	}
	if _, logins, _ := g.counts(); logins != 2 {
		t.Errorf("logins = %d, want 2", logins)
	}
}
