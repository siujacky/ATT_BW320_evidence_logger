package ipintel

import (
	"context"
	"log/slog"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// panicTransport is an http.RoundTripper with a bug.
type panicTransport struct{}

func (panicTransport) RoundTrip(*http.Request) (*http.Response, error) { panic("transport bug") }

// TestDownloadPanicIsAFailedCheck checks that a panic during a download neither stops the
// service nor makes Run retry at once: it is a failed check, retried after the backoff.
func TestDownloadPanicIsAFailedCheck(t *testing.T) {
	clk := newFakeClock(t0)
	h := &captureHandler{}
	d := openTest(t, t.TempDir(), Options{
		Download: true, URLv4: "https://example.test/v4.gz", URLv6: "https://example.test/v6.gz",
		HTTPClient: &http.Client{Transport: panicTransport{}}, Now: clk.Now, Logger: slog.New(h),
	})
	d.after, d.tick = clk.After, 1000*time.Hour
	startRun(t, d)
	w := clk.next(t)
	st := d.Status()
	if w.d != time.Hour || !strings.Contains(st.Error, "internal error (download): transport bug") {
		t.Fatalf("wait %v, status %+v", w.d, st)
	}
	if h.count("internal error (recovered)") != 1 {
		t.Fatalf("logged: %v", h.msgs)
	}
	clk.fire(w)
	if w = clk.next(t); w.d != 2*time.Hour {
		t.Fatalf("second wait %v", w.d)
	}
}

// panicResolver is a Resolver with a bug.
type panicResolver struct{}

func (panicResolver) LookupAddr(context.Context, string) ([]string, error) { panic("resolver bug") }

func TestResolverPanic(t *testing.T) {
	clk := newFakeClock(t0)
	h := &captureHandler{}
	d := openTest(t, t.TempDir(), Options{ReverseDNS: true, Resolver: panicResolver{}, Now: clk.Now, Logger: slog.New(h)})
	d.after = clk.After
	stop := startRun(t, d)
	a := netip.MustParseAddr("8.8.8.8")
	d.PTR(a, true)
	waitFor(t, "the failed lookup", func() bool { return d.ptr.size() == 1 })
	if name, due := d.ptr.get(a, clk.Now()); name != "" || due {
		t.Fatalf("after the panic: %q, due %v", name, due)
	}
	if name, due := d.ptr.get(a, clk.Now().Add(ptrRetry)); name != "" || !due {
		t.Fatalf("an hour later: %q, due %v", name, due)
	}
	stop()
	if h.count("reverse DNS lookup (recovered)") != 1 {
		t.Fatalf("logged: %v", h.msgs)
	}
}

func TestSafely(t *testing.T) {
	h := &captureHandler{}
	d := openTest(t, t.TempDir(), Options{Logger: slog.New(h)})
	if p := d.safely("step", func() {}); p != "" {
		t.Fatalf("no panic: %q", p)
	}
	p := d.safely("step", func() { panic("bug") })
	if p != "internal error (step): bug" || d.Status().Error != p || h.count("internal error (recovered)") != 1 {
		t.Fatalf("panic: %q, status %q", p, d.Status().Error)
	}
}
