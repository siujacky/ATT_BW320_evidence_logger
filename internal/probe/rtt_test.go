package probe

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// checkMeasuredRTT asserts that every recorded RTT is an actual measurement: more than the
// 1 µs floor that micros() substitutes for a zero reading, and no longer than the interval
// the test measured around the whole call on the same high-resolution clock. A clock that
// only advances at the Windows timer tick fails both ways (0 → 1 µs, or a whole tick that
// exceeds the real duration of a loopback operation).
func checkMeasuredRTT(t *testing.T, what string, n int, call func() (rttUS int64, ok bool)) {
	t.Helper()
	for i := 0; i < n; i++ {
		start := hrNow()
		rtt, ok := call()
		outer := sinceHR(start)
		if !ok {
			t.Fatalf("%s #%d failed", what, i)
		}
		if rtt < 2 {
			t.Fatalf("%s #%d: RTT %d µs is the zero-reading floor, not a measurement (call took %v)", what, i, rtt, outer)
		}
		if time.Duration(rtt)*time.Microsecond > outer+time.Microsecond {
			t.Fatalf("%s #%d: RTT %d µs exceeds the %v the whole call took", what, i, rtt, outer)
		}
	}
}

func TestTCPRTTIsMeasured(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	p := New(Options{})
	checkMeasuredRTT(t, "tcp connect", 20, func() (int64, bool) {
		r := p.TCP(context.Background(), ln.Addr().String(), 2*time.Second)
		return r.RTTus, r.OK
	})
}

func TestDNSRTTIsMeasured(t *testing.T) {
	srv := startFakeDNS(t, func(q dnsmessage.Message) [][]byte {
		return [][]byte{dnsReply(t, q, dnsmessage.RCodeSuccess, nil, rrA("www.google.com.", "203.0.113.10"))}
	})
	p := New(Options{})
	checkMeasuredRTT(t, "dns query", 20, func() (int64, bool) {
		r := p.DNS(context.Background(), srv.addr(), "www.google.com", 2*time.Second)
		return r.RTTus, r.OK
	})
}

func TestHTTPRTTIsMeasured(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ok")
	}))
	defer srv.Close()
	p := New(Options{})
	checkMeasuredRTT(t, "http get", 10, func() (int64, bool) {
		r := p.HTTP(context.Background(), "local", srv.URL, 200, "ok", 2*time.Second)
		return r.RTTus, r.OK
	})
}

// TestTCPRTTExcludesNameResolution: RTT is the connect time (DESIGN §8 "RTT = connect
// time"). Time spent resolving a host name before connecting must not be counted, or a slow
// resolver would be recorded as a slow network path.
func TestTCPRTTExcludesNameResolution(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	p := New(Options{})
	realDial := p.dial
	const lookup = 150 * time.Millisecond
	p.dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		time.Sleep(lookup) // stands in for resolving "slow-dns.example"
		return realDial(ctx, network, ln.Addr().String())
	}
	r := p.TCP(context.Background(), "slow-dns.example:443", 2*time.Second)
	if !r.OK || r.ReplyFrom != ln.Addr().String() {
		t.Fatalf("got %+v", r)
	}
	if time.Duration(r.RTTus)*time.Microsecond >= lookup {
		t.Fatalf("RTT %d µs includes the %v spent before connecting", r.RTTus, lookup)
	}
}
