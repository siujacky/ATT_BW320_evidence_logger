//go:build windows

package probe

import (
	"context"
	"net/netip"
	"runtime"
	"strings"
	"testing"
	"time"
	"unsafe"
)

func TestICMPEchoReplyLayout(t *testing.T) {
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		t.Skip("layout numbers below are for 64-bit Windows")
	}
	var r icmpEchoReply
	checks := []struct {
		name      string
		got, want uintptr
	}{
		{"sizeof(ICMP_ECHO_REPLY)", unsafe.Sizeof(r), 40},
		{"Address", unsafe.Offsetof(r.Address), 0},
		{"Status", unsafe.Offsetof(r.Status), 4},
		{"RoundTripTime", unsafe.Offsetof(r.RoundTripTime), 8},
		{"DataSize", unsafe.Offsetof(r.DataSize), 12},
		{"Reserved", unsafe.Offsetof(r.Reserved), 14},
		{"Data", unsafe.Offsetof(r.Data), 16},
		{"Options", unsafe.Offsetof(r.Options), 24},
		{"sizeof(IP_OPTION_INFORMATION)", unsafe.Sizeof(r.Options), 16},
		{"Options.Ttl", unsafe.Offsetof(r.Options.TTL), 0},
		{"Options.Tos", unsafe.Offsetof(r.Options.TOS), 1},
		{"Options.Flags", unsafe.Offsetof(r.Options.Flags), 2},
		{"Options.OptionsSize", unsafe.Offsetof(r.Options.OptionsSize), 3},
		{"Options.OptionsData", unsafe.Offsetof(r.Options.OptionsData), 8},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %d, want %d", c.name, c.got, c.want)
		}
	}
	if len(icmpPayload) != 32 {
		t.Errorf("payload is %d bytes, want 32", len(icmpPayload))
	}
	if want := 40 + 32 + 8 + icmpReplyExtra; icmpReplyBufSize != want {
		t.Errorf("reply buffer %d, want %d", icmpReplyBufSize, want)
	}
}

func TestIPAddrConversion(t *testing.T) {
	a := netip.MustParseAddr("1.2.3.4")
	v := ipv4ToIPAddr(a)
	// In memory the octets must appear in network order: 01 02 03 04.
	b := (*[4]byte)(unsafe.Pointer(&v))
	if *b != [4]byte{1, 2, 3, 4} {
		t.Fatalf("memory layout %v", *b)
	}
	if got := ipAddrToIPv4(v); got != a {
		t.Fatalf("round trip %v", got)
	}
	if got := ipAddrToIPv4(0xFE01A8C0); got != netip.MustParseAddr("192.168.1.254") {
		t.Fatalf("0xFE01A8C0 -> %v", got)
	}
}

func TestPingLoopback(t *testing.T) {
	p := New(Options{})
	r := p.Ping(context.Background(), "127.0.0.1", 2*time.Second)
	if !r.OK || r.Status != "IP_SUCCESS" || r.ReplyFrom != "127.0.0.1" {
		t.Fatalf("ping 127.0.0.1: %+v", r)
	}
	if r.RTTus <= 0 || r.RTTus > 2_000_000 {
		t.Errorf("RTTus = %d", r.RTTus)
	}
	if r.TTL <= 0 {
		t.Errorf("TTL = %d, want the reply's TTL", r.TTL)
	}
	if r.Kind != "icmp" || r.Target != "127.0.0.1" || r.Err != "" {
		t.Errorf("result %+v", r)
	}
	t.Logf("127.0.0.1: %s in %d µs, TTL %d", r.Status, r.RTTus, r.TTL)
}

func TestPingLoopbackConcurrent(t *testing.T) {
	p := New(Options{})
	const n = 8
	results := make(chan bool, n)
	for i := 0; i < n; i++ {
		go func() {
			r := p.Ping(context.Background(), "127.0.0.1", 2*time.Second)
			results <- r.OK && r.ReplyFrom == "127.0.0.1"
		}()
	}
	for i := 0; i < n; i++ {
		if !<-results {
			t.Fatal("a concurrent loopback ping failed")
		}
	}
}

// timeoutish lists the outcomes acceptable for an unanswered ping: a timeout, or an
// immediate "no route" style failure when this machine is offline.
var timeoutish = map[string]bool{
	"IP_REQ_TIMED_OUT": true, "IP_DEST_NET_UNREACHABLE": true, "IP_DEST_HOST_UNREACHABLE": true,
	"IP_GENERAL_FAILURE": true, "IP_BAD_ROUTE": true, "IP_TTL_EXPIRED_TRANSIT": true,
	StatusTimeout: true,
}

func TestPingTestNetTimesOut(t *testing.T) {
	p := New(Options{})
	start := time.Now()
	r := p.Ping(context.Background(), "192.0.2.1", 300*time.Millisecond) // TEST-NET-1: never answers
	el := time.Since(start)
	if r.OK {
		t.Fatalf("192.0.2.1 answered: %+v", r)
	}
	if !timeoutish[r.Status] {
		t.Fatalf("status %q (err %q), want a timeout-like status", r.Status, r.Err)
	}
	if el > 300*time.Millisecond+icmpGuard+200*time.Millisecond {
		t.Fatalf("took %v with a 300ms timeout", el)
	}
	if r.Status == "IP_REQ_TIMED_OUT" && (r.ReplyFrom != "" || r.RTTus != 0) {
		t.Errorf("timeout must not carry a reply address or RTT: %+v", r)
	}
	t.Logf("192.0.2.1: %s after %v", r.Status, el)
}

func TestPingRealCancel(t *testing.T) {
	p := New(Options{})
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(100*time.Millisecond, cancel)
	start := time.Now()
	r := p.Ping(ctx, "192.0.2.1", 5*time.Second)
	el := time.Since(start)
	if el > time.Second {
		t.Fatalf("Ping with 5s timeout returned %v after cancel at 100ms", el)
	}
	if r.OK {
		t.Fatalf("unexpected success: %+v", r)
	}
	// Offline machines fail before the cancel; online ones must report the cancel.
	if r.Status != StatusCanceled && !timeoutish[r.Status] {
		t.Fatalf("status %q", r.Status)
	}
	t.Logf("status %q after %v", r.Status, el)
}

func TestTracerouteLoopback(t *testing.T) {
	p := New(Options{})
	tr := p.Traceroute(context.Background(), "127.0.0.1", 5, 500*time.Millisecond)
	if !tr.Reached || len(tr.Hops) != 1 {
		t.Fatalf("traceroute 127.0.0.1: %+v", tr)
	}
	h := tr.Hops[0]
	if h.TTL != 1 || h.Addr != "127.0.0.1" || h.Status != "IP_SUCCESS" || h.RTTus <= 0 {
		t.Fatalf("hop %+v", h)
	}
}

func TestPingLocalhostByName(t *testing.T) {
	// Exercises the real resolver seam; "localhost" resolves without the network.
	r := New(Options{}).Ping(context.Background(), "localhost", 2*time.Second)
	if !r.OK || r.ReplyFrom != "127.0.0.1" || r.Target != "localhost" {
		t.Fatalf("ping localhost: %+v", r)
	}
}

func TestBestInterfaceRejectsIPv6(t *testing.T) {
	if _, err := bestInterface(netip.MustParseAddr("::1")); err == nil {
		t.Fatal("IPv6 accepted")
	}
}

func TestSendEchoRejectsIPv6(t *testing.T) {
	r := sendEcho(netip.MustParseAddr("::1"), 0, time.Second)
	if r.err == nil || !strings.Contains(r.err.Error(), "IPv4") {
		t.Fatalf("err = %v", r.err)
	}
}
