//go:build windows

package probe

import (
	"context"
	"net/netip"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// TestPingNoRouteReal: Windows has no route to 0.0.0.0/8, so IcmpSendEcho fails at once with
// the Win32 error ERROR_NETWORK_UNREACHABLE (1231), the same failure every ICMP probe gets
// while the PC's link is down. No packet leaves the machine.
func TestPingNoRouteReal(t *testing.T) {
	p := New(Options{})
	r := p.Ping(context.Background(), "0.0.0.1", time.Second)
	if r.OK || r.Status != StatusUnreachable || !strings.Contains(r.Err, "IcmpSendEcho") {
		t.Fatalf("got %+v, want %q", r, StatusUnreachable)
	}
	// The TCP probe reports the same condition the same way.
	if tr := p.TCP(context.Background(), "0.0.0.1:443", time.Second); tr.Status != StatusUnreachable {
		t.Fatalf("tcp: %+v", tr)
	}
	trace := p.Traceroute(context.Background(), "0.0.0.1", 5, 200*time.Millisecond)
	if len(trace.Hops) != 1 || !strings.HasPrefix(trace.Hops[0].Status, StatusUnreachable+": ") || trace.Err != "" {
		t.Fatalf("traceroute: %+v", trace)
	}
	// 0.0.0.0 itself is an invalid destination (ERROR_INVALID_NETNAME): a local error.
	if r := p.Ping(context.Background(), "0.0.0.0", time.Second); r.Status != StatusError || r.OK {
		t.Fatalf("0.0.0.0: %+v", r)
	}
	// In a traceroute that local error is the trace's Err, not a hop.
	trace = p.Traceroute(context.Background(), "0.0.0.0", 5, 200*time.Millisecond)
	if len(trace.Hops) != 0 || trace.Reached || !strings.Contains(trace.Err, "local error at TTL 1: IcmpSendEcho") {
		t.Fatalf("traceroute 0.0.0.0: %+v", trace)
	}
}

// TestEchoReplyLayoutAgainstKernel performs a real loopback IcmpSendEcho and checks the
// buffer the kernel filled against the Go mirror of ICMP_ECHO_REPLY: if a field offset were
// wrong, Data would not point into our buffer at the echoed payload and DataSize, the
// sender and the TTL would not read back as the request's.
func TestEchoReplyLayoutAgainstKernel(t *testing.T) {
	if err := icmpProcsErr(); err != nil {
		t.Fatal(err)
	}
	reply := make([]uint64, icmpReplyWords)
	n, elapsed, callErr, err := icmpEcho(netip.MustParseAddr("127.0.0.1"), 0, time.Second, reply)
	if err != nil || n != 1 {
		t.Fatalf("n=%d err=%v callErr=%v", n, err, callErr)
	}
	base := uintptr(unsafe.Pointer(&reply[0]))
	buf := unsafe.Slice((*byte)(unsafe.Pointer(&reply[0])), len(reply)*8)
	rep := (*icmpEchoReply)(unsafe.Pointer(&reply[0]))
	if rep.Status != ipSuccess || ipAddrToIPv4(rep.Address) != netip.MustParseAddr("127.0.0.1") {
		t.Fatalf("status %d from %v", rep.Status, ipAddrToIPv4(rep.Address))
	}
	if int(rep.DataSize) != len(icmpPayload) {
		t.Fatalf("DataSize %d, want %d", rep.DataSize, len(icmpPayload))
	}
	off := rep.Data - base
	if rep.Data < base+icmpEchoReplySize || off+uintptr(rep.DataSize) > uintptr(len(buf)) {
		t.Fatalf("Data points at offset %d, outside the reply data area", int64(rep.Data)-int64(base))
	}
	if got := buf[off : off+uintptr(rep.DataSize)]; string(got) != string(icmpPayload[:]) {
		t.Fatalf("echoed payload %q", got)
	}
	if rep.Options.TTL == 0 || rep.Options.OptionsSize != 0 {
		t.Fatalf("Options %+v", rep.Options)
	}
	if elapsed <= 0 || elapsed > time.Second {
		t.Fatalf("elapsed %v", elapsed)
	}
	r := decodeEcho(n, elapsed, callErr, reply)
	if !r.answered() || r.code != ipSuccess || r.from != netip.MustParseAddr("127.0.0.1") || r.ttl != rep.Options.TTL {
		t.Fatalf("decoded %+v", r)
	}
}

// TestDecodeEcho covers the interpretation of IcmpSendEcho outcomes with synthetic buffers.
func TestDecodeEcho(t *testing.T) {
	mkReply := func(addr string, status uint32, ttl uint8) []uint64 {
		buf := make([]uint64, icmpReplyWords)
		rep := (*icmpEchoReply)(unsafe.Pointer(&buf[0]))
		rep.Address = ipv4ToIPAddr(netip.MustParseAddr(addr))
		rep.Status = status
		rep.Options.TTL = ttl
		return buf
	}
	errno := func(e syscall.Errno) error { return e }
	tests := []struct {
		name      string
		n         uint32
		callErr   error
		reply     []uint64
		wantCode  uint32
		wantFrom  string
		wantTTL   uint8
		wantErrIn string
		unreach   bool
	}{
		{name: "TTL expired from a router", n: 1, callErr: errno(0), reply: mkReply("192.168.1.254", ipTTLExpiredTransit, 64),
			wantCode: ipTTLExpiredTransit, wantFrom: "192.168.1.254", wantTTL: 64},
		{name: "timeout via GetLastError", n: 0, callErr: errno(ipReqTimedOut), reply: mkReply("10.9.9.9", ipSuccess, 1),
			wantCode: ipReqTimedOut}, // the stale buffer must not be read
		{name: "general failure via GetLastError", n: 0, callErr: errno(ipGeneralFailure), wantCode: ipGeneralFailure},
		{name: "no route (Win32 1231)", n: 0, callErr: errno(windows.ERROR_NETWORK_UNREACHABLE),
			wantErrIn: "IcmpSendEcho", unreach: true},
		{name: "host unreachable (Win32 1232)", n: 0, callErr: errno(windows.ERROR_HOST_UNREACHABLE),
			wantErrIn: "IcmpSendEcho", unreach: true},
		{name: "invalid destination (Win32 1214)", n: 0, callErr: errno(windows.ERROR_INVALID_NETNAME),
			wantErrIn: "IcmpSendEcho"},
		{name: "no reply and no code", n: 0, callErr: errno(0), wantErrIn: "no reply and no error code"},
		{name: "undersized buffer", n: 1, callErr: errno(0), reply: make([]uint64, 2), wantErrIn: "cannot hold a reply"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := decodeEcho(tt.n, 3*time.Millisecond, tt.callErr, tt.reply)
			if tt.wantErrIn != "" {
				if r.err == nil || !strings.Contains(r.err.Error(), tt.wantErrIn) {
					t.Fatalf("err %v, want containing %q", r.err, tt.wantErrIn)
				}
				if isUnreachable(r.err) != tt.unreach || (localErrStatus(r.err) == StatusUnreachable) != tt.unreach {
					t.Fatalf("unreachable classification of %v: want %v", r.err, tt.unreach)
				}
				return
			}
			if r.err != nil || r.code != tt.wantCode || r.elapsed != 3*time.Millisecond {
				t.Fatalf("got %+v", r)
			}
			if tt.wantFrom == "" {
				if r.answered() {
					t.Fatalf("no reply structure, yet answered: %+v", r)
				}
				return
			}
			if r.from != netip.MustParseAddr(tt.wantFrom) || r.ttl != tt.wantTTL || !r.answered() {
				t.Fatalf("got %+v", r)
			}
		})
	}
}
