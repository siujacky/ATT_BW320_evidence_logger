package probe

// Adversarial tests added during the independent review of this package. Each one pins a
// defect that was found (or a branch that had no test) so that it cannot come back.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"golang.org/x/net/dns/dnsmessage"

	"attmonitor/internal/model"
)

// ---------------------------------------------------------------- ICMP

// TestPingLocalNoRouteIsUnreachable: when the PC has no route (e.g. the Wi-Fi dropped and the
// default route went with it) IcmpSendEcho returns no reply and a Win32 "network
// unreachable" error, not an IP_STATUS code. That is a network condition, reported like the
// TCP probe reports it, not a malfunction of the tool.
func TestPingLocalNoRouteIsUnreachable(t *testing.T) {
	f := &fakeEcho{byTTL: map[uint8]echoResult{0: {err: fmt.Errorf("IcmpSendEcho: %w", unreachableErr())}}}
	r := newFakeProber(f).Ping(context.Background(), "192.0.2.10", time.Second)
	if r.OK || r.Status != StatusUnreachable || !strings.Contains(r.Err, "IcmpSendEcho") {
		t.Fatalf("got %+v, want status %q with the system error text", r, StatusUnreachable)
	}
	if r.RTTus != 0 || r.ReplyFrom != "" || r.TTL != 0 {
		t.Fatalf("no reply, yet RTT/peer/TTL set: %+v", r)
	}
	// Any other local failure is still a local error.
	f.byTTL[0] = echoResult{err: errors.New("IcmpCreateFile: access denied")}
	if r := newFakeProber(f).Ping(context.Background(), "192.0.2.10", time.Second); r.Status != StatusError {
		t.Fatalf("other local error: %+v", r)
	}
}

func TestTracerouteLocalNoRoute(t *testing.T) {
	f := &fakeEcho{byTTL: map[uint8]echoResult{1: {err: fmt.Errorf("IcmpSendEcho: %w", unreachableErr())}}}
	tr := newFakeProber(f).Traceroute(context.Background(), "192.0.2.10", 10, 10*time.Millisecond)
	if len(tr.Hops) != 1 || tr.Reached || !strings.HasPrefix(tr.Hops[0].Status, StatusUnreachable+": ") {
		t.Fatalf("hops %+v reached %v", tr.Hops, tr.Reached)
	}
}

// TestPingReplyWithoutSender: a reply structure without a usable sender address (e.g. an
// IP_REQ_TIMED_OUT structure with Address 0.0.0.0) is not an answer from the network, so it
// must not produce a ReplyFrom of "0.0.0.0" or an RTT.
func TestPingReplyWithoutSender(t *testing.T) {
	for _, er := range []echoResult{
		{replies: 1, code: ipReqTimedOut, from: netip.IPv4Unspecified(), elapsed: time.Second},
		{replies: 1, code: ipGeneralFailure, elapsed: time.Millisecond}, // zero (invalid) Addr
		{replies: 1, code: ipSuccess, from: netip.IPv4Unspecified(), elapsed: time.Millisecond},
	} {
		f := &fakeEcho{byTTL: map[uint8]echoResult{0: er}}
		r := newFakeProber(f).Ping(context.Background(), "192.0.2.10", time.Second)
		if r.OK || r.ReplyFrom != "" || r.RTTus != 0 || r.TTL != 0 {
			t.Errorf("echo %+v -> %+v; want no sender, RTT or TTL", er, r)
		}
		if r.Status != ICMPStatusName(er.code) {
			t.Errorf("status %q, want %q", r.Status, ICMPStatusName(er.code))
		}
	}
	// In a traceroute such a hop is a non-answer: the trace goes on.
	f := &fakeEcho{byTTL: map[uint8]echoResult{
		1: {replies: 1, code: ipSuccess, from: netip.IPv4Unspecified()},
		2: {replies: 1, code: ipSuccess, from: addrTarget, elapsed: time.Millisecond},
	}}
	tr := newFakeProber(f).Traceroute(context.Background(), "192.0.2.10", 5, 10*time.Millisecond)
	if !tr.Reached || len(tr.Hops) != 2 || tr.Hops[0].Addr != "" || tr.Hops[0].RTTus != 0 {
		t.Fatalf("trace %+v", tr)
	}
}

// TestPingNameResolutionBoundedByTimeout: resolving a host name counts against the probe's
// timeout, so a hung resolver cannot hold a probe (and a monitoring cycle) indefinitely.
func TestPingNameResolutionBoundedByTimeout(t *testing.T) {
	f := &fakeEcho{byTTL: map[uint8]echoResult{}}
	p := newFakeProber(f)
	p.lookupIP = func(ctx context.Context, host string) ([]netip.Addr, error) {
		<-ctx.Done()
		return nil, &net.DNSError{Err: "i/o timeout", Name: host, IsTimeout: true}
	}
	done := make(chan model.ProbeResult, 1)
	start := time.Now()
	go func() { done <- p.Ping(context.Background(), "hung-resolver.example", 100*time.Millisecond) }()
	select {
	case r := <-done:
		if el := time.Since(start); el > time.Second {
			t.Fatalf("returned after %v", el)
		}
		if r.OK || r.Status != StatusError || !strings.Contains(r.Err, "hung-resolver.example") || len(f.calls) != 0 {
			t.Fatalf("got %+v (echo calls %d)", r, len(f.calls))
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Ping did not bound name resolution by its timeout")
	}
}

// TestPingCanceledDuringResolution: a cancel while resolving is a cancel, not an error.
func TestPingCanceledDuringResolution(t *testing.T) {
	p := newFakeProber(&fakeEcho{byTTL: map[uint8]echoResult{}})
	ctx, cancel := context.WithCancel(context.Background())
	p.lookupIP = func(lctx context.Context, host string) ([]netip.Addr, error) {
		cancel()
		<-lctx.Done()
		return nil, lctx.Err()
	}
	if r := p.Ping(ctx, "name.example", time.Second); r.Status != StatusCanceled || r.OK {
		t.Fatalf("got %+v", r)
	}
}

// TestTracerouteHopTimeoutThenCancel covers a hop interrupted by the caller's deadline (a
// "timeout" hop) followed by the next hop finding the context already ended.
func TestTracerouteHopTimeoutThenCancel(t *testing.T) {
	f := &fakeEcho{byTTL: map[uint8]echoResult{}, delay: time.Second}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	tr := newFakeProber(f).Traceroute(ctx, "192.0.2.10", 10, 5*time.Second)
	if len(tr.Hops) != 2 || tr.Hops[0].Status != StatusTimeout || tr.Hops[1].Status != StatusCanceled || tr.Reached {
		t.Fatalf("hops %+v", tr.Hops)
	}
	if tr.Hops[0].Addr != "" || tr.Hops[0].RTTus != 0 {
		t.Fatalf("timed-out hop carries a reply: %+v", tr.Hops[0])
	}
}

// TestICMPStatusNameFullHeaderTable checks every IP_STATUS name of the Windows SDK
// ipexport.h, including the status indications 11019-11035 that the first version lacked.
func TestICMPStatusNameFullHeaderTable(t *testing.T) {
	header := map[uint32]string{
		11019: "IP_ADDR_DELETED", 11020: "IP_SPEC_MTU_CHANGE", 11021: "IP_MTU_CHANGE",
		11022: "IP_UNLOAD", 11023: "IP_ADDR_ADDED", 11024: "IP_MEDIA_CONNECT",
		11025: "IP_MEDIA_DISCONNECT", 11026: "IP_BIND_ADAPTER", 11027: "IP_UNBIND_ADAPTER",
		11028: "IP_DEVICE_DOES_NOT_EXIST", 11029: "IP_DUPLICATE_ADDRESS",
		11030: "IP_INTERFACE_METRIC_CHANGE", 11031: "IP_RECONFIG_SECFLTR",
		11032: "IP_NEGOTIATING_IPSEC", 11033: "IP_INTERFACE_WOL_CAPABILITY_CHANGE",
		11034: "IP_DUPLICATE_IPADD", 11035: "IP_NO_FURTHER_SENDS",
	}
	for code, want := range header {
		if got := ICMPStatusName(code); got != want {
			t.Errorf("ICMPStatusName(%d) = %q, want %q", code, got, want)
		}
	}
	for c := uint32(11001); c <= 11035; c++ {
		if strings.HasPrefix(ICMPStatusName(c), "IP_STATUS_") {
			t.Errorf("code %d has no name", c)
		}
	}
}

// ---------------------------------------------------------------- SNTP

// TestSNTPRejectsBogusServerTimestamps: a reply whose receive timestamp is zero (or whose
// transmit precedes its receive) would yield an offset of years recorded as a valid clock
// measurement.
func TestSNTPRejectsBogusServerTimestamps(t *testing.T) {
	p := New(Options{})
	for _, tc := range []struct {
		name  string
		srv   fakeNTP
		errIn string
	}{
		{"zero receive timestamp", fakeNTP{stratum: 2, zeroReceive: true}, "zero receive timestamp"},
		{"transmit before receive", fakeNTP{stratum: 2, backwards: true}, "before its receive"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := p.SNTP(context.Background(), startFakeNTP(t, tc.srv), 2*time.Second)
			if r.OK || !strings.Contains(r.Err, tc.errIn) || r.OffsetMs != 0 || r.RTTms != 0 {
				t.Fatalf("got %+v, want OK=false with %q and no offset", r, tc.errIn)
			}
			if r.Stratum != 2 {
				t.Errorf("stratum %d", r.Stratum)
			}
		})
	}
}

// ---------------------------------------------------------------- DNS

// shortReasonMax bounds a hijack reason ("a short reason", docs/PACKAGES.md).
const shortReasonMax = 300

// TestDetectDNSHijackReasonIsShort: the reason is a short summary (docs/PACKAGES.md); the full
// answers are in DNSResult.Answers. A hostile resolver must not be able to blow it up.
func TestDetectDNSHijackReasonIsShort(t *testing.T) {
	var many []string
	for i := 0; i < 40; i++ {
		many = append(many, fmt.Sprintf("203.0.113.%d", i))
	}
	longCNAME := "CNAME:" + strings.Repeat("a", 60) + "." + strings.Repeat("b", 60) + "." +
		strings.Repeat("c", 60) + "." + strings.Repeat("d", 50) + ".attlocal.net"
	for _, tc := range []struct {
		name, qname string
		answers     []string
		whyIn       string
	}{
		{"invalid with many answers", "x7f3k2.invalid", many, "(+37 more)"},
		{"invalid with a long alias", "x7f3k2.invalid", []string{longCNAME, longCNAME, longCNAME}, "must not resolve"},
		{"public name, long local alias", "www.google.com", []string{longCNAME}, "alias (CNAME)"},
		{"huge query name", strings.Repeat("q", 300) + ".invalid", many, "must not resolve"},
	} {
		hij, why := DetectDNSHijack(tc.qname, tc.answers, "192.168.1.254")
		if !hij || !strings.Contains(why, tc.whyIn) {
			t.Errorf("%s: %v %q, want hijack containing %q", tc.name, hij, why, tc.whyIn)
		}
		if len(why) > shortReasonMax {
			t.Errorf("%s: reason is %d bytes (max %d): %q", tc.name, len(why), shortReasonMax, why)
		}
	}
}

func TestParseDNSResponseTruncatedAnswerHeader(t *testing.T) {
	name := dnsmessage.MustNewName("www.google.com.")
	q := dnsmessage.Message{Header: dnsmessage.Header{ID: 9, RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}}
	one := dnsReply(t, q, dnsmessage.RCodeSuccess, nil, rrA("www.google.com.", "203.0.113.1"))
	two := dnsReply(t, q, dnsmessage.RCodeSuccess, nil, rrA("www.google.com.", "203.0.113.1"),
		rrA("www.google.com.", "203.0.113.2"))
	// Cut inside the second record's header (name pointer + type), after the first record.
	cut := two[:len(one)+3]
	_, answers, ansErr, why := parseDNSResponse(cut, 9, name)
	if why != "" || ansErr == nil || len(answers) != 1 || answers[0] != "203.0.113.1" {
		t.Fatalf("why %q ansErr %v answers %q", why, ansErr, answers)
	}
}

// ---------------------------------------------------------------- HTTP

// TestHTTPBodyReadErrorFailsCheck: a body cut short (server closed early) is not a
// successful check even when the status and the bytes received so far match; the hash
// covers exactly the bytes received.
func TestHTTPBodyReadErrorFailsCheck(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "100")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("Microsoft Connect Test"))
		w.(http.Flusher).Flush() // Hijack discards unflushed body bytes
		if hj, ok := w.(http.Hijacker); ok {
			if c, _, err := hj.Hijack(); err == nil {
				c.Close()
			}
		}
	}))
	defer srv.Close()
	r := New(Options{}).HTTP(context.Background(), "short", srv.URL, 200, "Microsoft Connect Test", 2*time.Second)
	if r.OK || r.Status != 200 || !strings.HasPrefix(r.Err, "reading body: ") {
		t.Fatalf("got %+v", r)
	}
	if r.BodySHA256 != sha256Hex([]byte("Microsoft Connect Test")) || r.BodyPrefix != "Microsoft Connect Test" {
		t.Fatalf("partial body evidence: %+v", r)
	}
}

// TestHTTPHijackReasonBounded: Location may be up to the 64 KiB header limit; the reason
// stays short (the full value is in HTTPResult.Location).
func TestHTTPHijackReasonBounded(t *testing.T) {
	loc := "http://192.168.1.254/cgi-bin/redirect.ha?u=" + strings.Repeat("x", 10_000)
	u, _ := http.NewRequest(http.MethodGet, "http://www.msftconnecttest.com/connecttest.txt", nil)
	hij, why := httpHijack(u.URL, "192.168.1.254:80", loc, "192.168.1.254")
	if !hij || !strings.Contains(why, "redirected to http://192.168.1.254/") || !strings.Contains(why, "connected to") {
		t.Fatalf("%v %q", hij, why)
	}
	if len(why) > 2*shortReasonMax {
		t.Fatalf("reason is %d bytes", len(why))
	}
}

// ---------------------------------------------------------------- netsh / link

func TestParseRateRejectsNonFinite(t *testing.T) {
	for _, s := range []string{"NaN", "nan", "+Inf", "-Inf", "inf", "Infinity"} {
		if got := parseRate(s); got != 0 {
			t.Errorf("parseRate(%q) = %d, want 0", s, got)
		}
	}
	for in, want := range map[string]int{"-3": 0, "+7": 7, "0": 0} {
		if got := parseInt(in); got != want {
			t.Errorf("parseInt(%q) = %d, want %d (negative counts are not valid readings)", in, got, want)
		}
	}
}

func TestParseNetshWLANColonOnlyLines(t *testing.T) {
	out := ": orphan value\r\n    Name : Wi-Fi\r\n   : stray\r\n    State : connected\r\n"
	l, err := ParseNetshWLAN([]byte(out), "")
	if err != nil || l.Interface != "Wi-Fi" || l.State != "connected" {
		t.Fatalf("got %+v, %v", l, err)
	}
}

func TestLinkMbpsNoOverflow(t *testing.T) {
	for speed, want := range map[uint64]int{
		math.MaxUint64 - 1:        0, // implausible (+ 500000 would even wrap around): unknown
		1 << 62:                   0, // 4.6e12 Mbps does not fit an int32: unknown, not wrapped
		400_000_000_000:           400_000,
		math.MaxInt32 * 1_000_000: math.MaxInt32,
		1_499_999:                 1,
		1_500_000:                 2,
		499_999:                   0,
	} {
		l := linkFromAdapter(adapterInfo{Name: "x", TxSpeed: speed}, gw254)
		if l.LinkMbps != want {
			t.Errorf("TxSpeed %d -> LinkMbps %d, want %d", speed, l.LinkMbps, want)
		}
	}
}

// ---------------------------------------------------------------- robustness

// TestEchoInFlightLimit: IcmpSendEcho calls abandoned by a canceled caller keep an OS thread
// until they return. If the ICMP service never returned, they must not pile up without
// bound: past maxICMPInFlight, probes fail at once with a local error naming the cause,
// and recover once the stuck calls finish.
func TestEchoInFlightLimit(t *testing.T) {
	release := make(chan struct{})
	entered := make(chan struct{}, maxICMPInFlight+1)
	calls := 0
	p := newFakeProber(&fakeEcho{})
	var mu sync.Mutex
	p.echo = func(dst netip.Addr, ttl uint8, timeout time.Duration) echoResult {
		mu.Lock()
		calls++
		mu.Unlock()
		entered <- struct{}{}
		<-release
		return echoResult{replies: 1, code: ipSuccess, from: dst, elapsed: time.Millisecond}
	}
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	for i := 0; i < maxICMPInFlight; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if r := p.Ping(ctx, "192.0.2.10", time.Minute); r.Status != StatusCanceled {
				t.Errorf("stuck ping: %+v", r)
			}
		}()
	}
	for i := 0; i < maxICMPInFlight; i++ {
		<-entered
	}
	cancel() // the callers return; their IcmpSendEcho calls stay "stuck"
	wg.Wait()

	r := p.Ping(context.Background(), "192.0.2.10", time.Second)
	if r.OK || r.Status != StatusError || !strings.Contains(r.Err, "have not returned") {
		t.Fatalf("past the limit: %+v", r)
	}
	mu.Lock()
	if calls != maxICMPInFlight {
		t.Fatalf("echo called %d times, want %d (no call past the limit)", calls, maxICMPInFlight)
	}
	mu.Unlock()

	close(release)
	deadline := time.Now().Add(5 * time.Second)
	for p.icmpInFlight.Load() != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("in-flight count stuck at %d", p.icmpInFlight.Load())
		}
		time.Sleep(time.Millisecond)
	}
	if r := p.Ping(context.Background(), "192.0.2.10", time.Second); !r.OK {
		t.Fatalf("after recovery: %+v", r)
	}
}

// TestEchoPanicContained: the echo goroutine is outside every caller's recover, so a panic
// there would end the whole service. It must become the probe's local error.
func TestEchoPanicContained(t *testing.T) {
	p := newFakeProber(&fakeEcho{})
	p.echo = func(netip.Addr, uint8, time.Duration) echoResult { panic("boom") }
	r := p.Ping(context.Background(), "192.0.2.10", time.Second)
	if r.OK || r.Status != StatusError || !strings.Contains(r.Err, "panicked: boom") {
		t.Fatalf("got %+v", r)
	}
	tr := p.Traceroute(context.Background(), "192.0.2.10", 5, time.Second)
	if len(tr.Hops) != 0 || !strings.Contains(tr.Err, "local error at TTL 1: ICMP request panicked: boom") {
		t.Fatalf("trace %+v", tr)
	}
	if n := p.icmpInFlight.Load(); n != 0 {
		t.Fatalf("in-flight count %d after panics", n)
	}
}

// TestTracerouteResolutionBounded: a hung resolver cannot hold a traceroute (which the
// monitor runs without a deadline) indefinitely.
func TestTracerouteResolutionBounded(t *testing.T) {
	old := traceResolveTimeout
	traceResolveTimeout = 100 * time.Millisecond
	defer func() { traceResolveTimeout = old }()
	f := &fakeEcho{byTTL: map[uint8]echoResult{}}
	p := newFakeProber(f)
	p.lookupIP = func(ctx context.Context, host string) ([]netip.Addr, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	done := make(chan model.Traceroute, 1)
	go func() { done <- p.Traceroute(context.Background(), "hung.example", 5, time.Second) }()
	select {
	case tr := <-done:
		if len(tr.Hops) != 0 || !strings.Contains(tr.Err, "resolving hung.example") || len(f.calls) != 0 {
			t.Fatalf("trace %+v", tr)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("traceroute name resolution is not bounded")
	}
}

func TestClipText(t *testing.T) {
	tests := []struct {
		in   string
		n    int
		want string
	}{
		{"short", 10, "short"},
		{"exactly10!", 10, "exactly10!"},
		{"0123456789abc", 10, "0123456..."},
		{"ééééé", 7, "éé..."},  // é is 2 bytes: never split a character
		{"aéééé", 6, "aé..."},  // a cut inside é backs up to its start
		{"€€€", 5, "..."},      // nothing fits before the mark
		{"anything", 2, "..."}, // n smaller than the mark itself
		{"", 0, ""},
	}
	for _, tt := range tests {
		got := clipText(tt.in, tt.n)
		if got != tt.want || !utf8.ValidString(got) {
			t.Errorf("clipText(%q, %d) = %q, want %q", tt.in, tt.n, got, tt.want)
		}
	}
	list, more := listForReason([]string{"a", "b", "c", "d", "e"})
	if list != "a, b, c" || more != " (+2 more)" {
		t.Errorf("listForReason = %q %q", list, more)
	}
	if list, more := listForReason([]string{strings.Repeat("x", 500)}); len(list) != maxReasonItem || more != "" {
		t.Errorf("long item not clipped: %d bytes, %q", len(list), more)
	}
	if got := boundedReason(strings.Repeat("y", 1000), " (+9 more)"); len(got) != maxReasonLen || !strings.HasSuffix(got, "... (+9 more)") {
		t.Errorf("boundedReason kept %d bytes: ...%q", len(got), got[len(got)-20:])
	}
}

func TestConnectStartsForPeer(t *testing.T) {
	v4 := &net.TCPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 443}
	v6 := &net.TCPAddr{IP: net.ParseIP("2001:db8::1"), Port: 443}
	var cs connectStarts
	if _, ok := cs.forPeer(v4); ok {
		t.Fatal("no attempts recorded, yet a start was found")
	}
	ctx := context.WithValue(context.Background(), connectStartsKey{}, &cs)
	if err := markConnectStart(ctx, "tcp6", v6.String(), nil); err != nil {
		t.Fatal(err)
	}
	only, ok := cs.forPeer(&net.TCPAddr{IP: net.IPv4(198, 51, 100, 9), Port: 1})
	if !ok {
		t.Fatal("a single recorded attempt must be used when the peer string does not match")
	}
	time.Sleep(time.Millisecond)
	_ = markConnectStart(ctx, "tcp4", v4.String(), nil)
	s4, ok := cs.forPeer(v4)
	if !ok || s4 <= only {
		t.Fatalf("IPv4 attempt start %v (ok %v) must be the later one, after %v", s4, ok, only)
	}
	if s6, ok := cs.forPeer(v6); !ok || s6 != only {
		t.Fatalf("IPv6 attempt start %v (ok %v), want %v", s6, ok, only)
	}
	if _, ok := cs.forPeer(&net.TCPAddr{IP: net.IPv4(198, 51, 100, 9), Port: 1}); ok {
		t.Fatal("an unknown peer among several attempts must not be guessed")
	}
	// A dial without the context key is untouched (HTTP checks share the dialer).
	if err := markConnectStart(context.Background(), "tcp4", "192.0.2.1:80", nil); err != nil {
		t.Fatal(err)
	}
}

// TestDNSTruncatedResponseIsFlagged: a response with the TC bit set is still a well-formed
// answer (OK), but its answer section may be incomplete; the evidence says so in
// DNSResult.Truncated. Err is reserved for real errors, so a truncated but otherwise
// normal answer is not recorded as a failure.
func TestDNSTruncatedResponseIsFlagged(t *testing.T) {
	srv := startFakeDNS(t, func(q dnsmessage.Message) [][]byte {
		return [][]byte{dnsReply(t, q, dnsmessage.RCodeSuccess, func(m *dnsmessage.Message) { m.Header.Truncated = true },
			rrA("www.google.com.", "203.0.113.10"))}
	})
	r := New(Options{}).DNS(context.Background(), srv.addr(), "www.google.com", 2*time.Second)
	if !r.OK || !r.Truncated || r.RCode != "NOERROR" || len(r.Answers) != 1 || r.Err != "" {
		t.Fatalf("got %+v, want OK, Truncated, the answer and no Err", r)
	}
	if b, err := json.Marshal(r); err != nil || !strings.Contains(string(b), `"truncated":true`) {
		t.Fatalf("record %s (%v) does not carry the truncation", b, err)
	}

	// Not truncated: not flagged (and omitted from the record).
	srv2 := startFakeDNS(t, func(q dnsmessage.Message) [][]byte {
		return [][]byte{dnsReply(t, q, dnsmessage.RCodeSuccess, nil, rrA("www.google.com.", "203.0.113.10"))}
	})
	r = New(Options{}).DNS(context.Background(), srv2.addr(), "www.google.com", 2*time.Second)
	if !r.OK || r.Truncated || r.Err != "" {
		t.Fatalf("got %+v", r)
	}
	if b, _ := json.Marshal(r); strings.Contains(string(b), "truncated") {
		t.Fatalf("untruncated record mentions truncation: %s", b)
	}

	// Truncated and malformed: Err reports the real error, Truncated the TC bit.
	srv3 := startFakeDNS(t, func(q dnsmessage.Message) [][]byte {
		b := dnsReply(t, q, dnsmessage.RCodeSuccess, func(m *dnsmessage.Message) { m.Header.Truncated = true },
			rrA("www.google.com.", "203.0.113.10"), rrA("www.google.com.", "203.0.113.11"))
		return [][]byte{b[:len(b)-2]}
	})
	r = New(Options{}).DNS(context.Background(), srv3.addr(), "www.google.com", 2*time.Second)
	if r.OK || !r.Truncated || !strings.HasPrefix(r.Err, "malformed answer section: ") || strings.Contains(r.Err, "truncated") {
		t.Fatalf("got %+v", r)
	}
	if len(r.Answers) != 1 || r.Answers[0] != "203.0.113.10" || r.RawB64 == "" {
		t.Fatalf("evidence before the damage must be kept: %+v", r)
	}
}

// TestLocalLinkNoAliasDoesNotBorrowAnotherInterface: netsh blocks are matched by interface
// alias. With no alias to match, ParseNetshWLAN("") would pick the first connected
// interface, which may be another adapter; its SSID and state must not be attributed to the
// selected one.
func TestLocalLinkNoAliasDoesNotBorrowAnotherInterface(t *testing.T) {
	usb := adapterInfo{Name: "{USB-GUID}", Friendly: "", Description: "USB Wi-Fi", IfIndex: 22,
		IfType: ifTypeIEEE80211, OperStatus: operDown, IPv4: []netip.Prefix{pfx("192.168.1.90/24")}}
	f := &fakeLink{adapters: []adapterInfo{usb}, best: 22, netshOut: readFixture(t, "netsh_two_interfaces.txt")}
	p := New(Options{})
	f.install(p)
	link, raw, err := p.LocalLink(context.Background(), "192.168.1.254")
	if err != nil || len(raw) == 0 {
		t.Fatalf("err %v raw %d", err, len(raw))
	}
	if link.SSID != "" || link.State != "disconnected" || link.Interface != "USB Wi-Fi" || !strings.Contains(link.Err, "alias") {
		t.Fatalf("got %+v", link)
	}
}
