package probe

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestHostPort(t *testing.T) {
	tests := []struct {
		in, def          string
		wantHost, wantPt string
		wantErr          bool
	}{
		{"1.1.1.1", "53", "1.1.1.1", "53", false},
		{"1.1.1.1:5353", "53", "1.1.1.1", "5353", false},
		{"1.1.1.1:", "53", "1.1.1.1", "53", false},
		{" 192.168.1.254 ", "53", "192.168.1.254", "53", false},
		{"time.windows.com", "123", "time.windows.com", "123", false},
		{"time.windows.com:1123", "123", "time.windows.com", "1123", false},
		{"::1", "53", "::1", "53", false},
		{"2001:db8::53", "53", "2001:db8::53", "53", false},
		{"[2001:db8::53]:5353", "53", "2001:db8::53", "5353", false},
		{"[2001:db8::53]", "53", "2001:db8::53", "53", false},
		{"fe80::1%eth0", "53", "fe80::1%eth0", "53", false},
		{"", "53", "", "", true},
		{":53", "53", "", "", true},
		{"1.1.1.1:53:53", "53", "", "", true},
		{"[nonsense]", "53", "", "", true},
		{"has space", "53", "", "", true},
		{"a/b", "53", "", "", true},
	}
	for _, tt := range tests {
		h, p, err := hostPort(tt.in, tt.def)
		if (err != nil) != tt.wantErr || h != tt.wantHost || p != tt.wantPt {
			t.Errorf("hostPort(%q) = %q, %q, %v; want %q, %q, err=%v", tt.in, h, p, err, tt.wantHost, tt.wantPt, tt.wantErr)
		}
	}
}

func TestEffectiveTimeout(t *testing.T) {
	bg := context.Background()
	if got := effectiveTimeout(bg, 0); got != defaultTimeout {
		t.Errorf("default = %v", got)
	}
	if got := effectiveTimeout(bg, -time.Second); got != defaultTimeout {
		t.Errorf("negative = %v", got)
	}
	if got := effectiveTimeout(bg, 3*time.Second); got != 3*time.Second {
		t.Errorf("explicit = %v", got)
	}
	ctx, cancel := context.WithTimeout(bg, 500*time.Millisecond)
	defer cancel()
	if got := effectiveTimeout(ctx, 3*time.Second); got > 500*time.Millisecond || got < 400*time.Millisecond {
		t.Errorf("clipped = %v", got)
	}
	if got := effectiveTimeout(ctx, 100*time.Millisecond); got != 100*time.Millisecond {
		t.Errorf("shorter than deadline = %v", got)
	}
	past, cancel2 := context.WithDeadline(bg, time.Now().Add(-time.Second))
	defer cancel2()
	if got := effectiveTimeout(past, time.Second); got > 0 {
		t.Errorf("past deadline = %v", got)
	}
	if err := ctxErr(past); err == nil {
		t.Error("ctxErr of an expired context")
	}
}

// lapsedCtx reports a deadline in the past while Err is still nil, the moment between a
// deadline passing and the context noticing it.
type lapsedCtx struct{ context.Context }

func (lapsedCtx) Deadline() (time.Time, bool) { return time.Now().Add(-time.Millisecond), true }

func TestLapsedDeadlineRunsNothing(t *testing.T) {
	ctx := lapsedCtx{context.Background()}
	if err := ctxErr(ctx); err != errDeadline {
		t.Fatalf("ctxErr = %v", err)
	}
	f := &fakeEcho{byTTL: map[uint8]echoResult{}}
	p := newFakeProber(f)
	if r := p.Ping(ctx, "192.0.2.10", time.Second); r.Status != StatusCanceled || r.Err != errDeadline.Error() || len(f.calls) != 0 {
		t.Errorf("ping: %+v (calls %d)", r, len(f.calls))
	}
	if r := p.TCP(ctx, "192.0.2.10:443", time.Second); r.Status != StatusCanceled {
		t.Errorf("tcp: %+v", r)
	}
	if r := p.DNS(ctx, "192.0.2.10", "www.google.com", time.Second); !strings.HasPrefix(r.Err, "canceled") {
		t.Errorf("dns: %+v", r)
	}
	if r := p.HTTP(ctx, "x", "http://192.0.2.10/", 0, "", time.Second); !strings.HasPrefix(r.Err, "canceled") {
		t.Errorf("http: %+v", r)
	}
	if r := p.SNTP(ctx, "192.0.2.10", time.Second); !strings.HasPrefix(r.Err, "canceled") {
		t.Errorf("sntp: %+v", r)
	}
}

func TestNewDefaults(t *testing.T) {
	p := New(Options{})
	if p.log == nil || p.userAgent != defaultUserAgent || p.gatewayIP != DefaultGatewayIP {
		t.Fatalf("defaults: ua %q gw %q", p.userAgent, p.gatewayIP)
	}
	if p.dial == nil || p.lookupIP == nil || p.echo == nil || p.adapters == nil || p.bestIf == nil || p.runNetsh == nil || p.transport == nil {
		t.Fatal("a seam is not initialised")
	}
	if p.transport.Proxy != nil || !p.transport.DisableKeepAlives || !p.transport.DisableCompression {
		t.Fatal("transport must be direct, without keep-alive and without transparent gzip")
	}
	if c := p.transport.TLSClientConfig; p.rootCAs != nil || c == nil || c.RootCAs != nil || c.InsecureSkipVerify ||
		c.VerifyConnection != nil || c.VerifyPeerCertificate != nil {
		t.Fatal("HTTPS checks must verify against the system roots with the standard verification")
	}
	p = New(Options{UserAgent: " ua/1 ", GatewayIP: " 10.0.0.1 "})
	if p.userAgent != "ua/1" || p.gatewayIP != "10.0.0.1" {
		t.Fatalf("options not applied: %q %q", p.userAgent, p.gatewayIP)
	}
}
