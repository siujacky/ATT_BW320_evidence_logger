package probe

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeEcho scripts IcmpSendEcho outcomes per TTL (key 0 = default TTL used by Ping) and
// records the calls.
type fakeEcho struct {
	mu      sync.Mutex
	byTTL   map[uint8]echoResult
	delay   time.Duration // simulated blocking time per call
	calls   []uint8
	timeout []time.Duration
}

func (f *fakeEcho) echo(dst netip.Addr, ttl uint8, timeout time.Duration) echoResult {
	f.mu.Lock()
	f.calls = append(f.calls, ttl)
	f.timeout = append(f.timeout, timeout)
	r, ok := f.byTTL[ttl]
	f.mu.Unlock()
	if f.delay > 0 {
		time.Sleep(f.delay)
	}
	if !ok {
		return echoResult{code: ipReqTimedOut, elapsed: timeout}
	}
	return r
}

func newFakeProber(f *fakeEcho) *Prober {
	p := New(Options{})
	p.echo = f.echo
	p.lookupIP = func(ctx context.Context, host string) ([]netip.Addr, error) {
		switch host {
		case "dual.example":
			return []netip.Addr{netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("192.0.2.10")}, nil
		case "v6only.example":
			return []netip.Addr{netip.MustParseAddr("2001:db8::1")}, nil
		}
		return nil, errors.New("lookup " + host + ": no such host")
	}
	return p
}

var (
	addrTarget  = netip.MustParseAddr("192.0.2.10")
	addrGateway = netip.MustParseAddr("192.168.1.254")
	addrLocalPC = netip.MustParseAddr("192.168.1.71")
	addrRouter2 = netip.MustParseAddr("198.51.100.1")
)

func TestPingOutcomes(t *testing.T) {
	tests := []struct {
		name      string
		target    string
		reply     *echoResult // nil: lookup fails before any echo
		wantOK    bool
		wantStat  string
		wantFrom  string
		wantTTL   int
		wantRTT   bool
		wantErrIn string
	}{
		{
			name:   "success from target",
			target: "192.0.2.10",
			reply: &echoResult{replies: 1, code: ipSuccess, from: addrTarget, ttl: 57,
				elapsed: 12345 * time.Microsecond},
			wantOK: true, wantStat: "IP_SUCCESS", wantFrom: "192.0.2.10", wantTTL: 57, wantRTT: true,
		},
		{
			name:   "success from another address is not OK",
			target: "192.0.2.10",
			reply: &echoResult{replies: 1, code: ipSuccess, from: addrGateway, ttl: 64,
				elapsed: time.Millisecond},
			wantOK: false, wantStat: "IP_SUCCESS", wantFrom: "192.168.1.254", wantTTL: 64, wantRTT: true,
			wantErrIn: "not from the target",
		},
		{
			name:   "local host unreachable reply comes from this PC",
			target: "192.0.2.10",
			reply: &echoResult{replies: 1, code: ipDestHostUnreachable, from: addrLocalPC,
				elapsed: 3 * time.Second},
			wantOK: false, wantStat: "IP_DEST_HOST_UNREACHABLE", wantFrom: "192.168.1.71", wantRTT: true,
		},
		{
			name:     "timeout has no reply address and no RTT",
			target:   "192.0.2.10",
			reply:    &echoResult{replies: 0, code: ipReqTimedOut, elapsed: 2 * time.Second},
			wantOK:   false,
			wantStat: "IP_REQ_TIMED_OUT",
		},
		{
			name:     "general failure",
			target:   "192.0.2.10",
			reply:    &echoResult{replies: 0, code: ipGeneralFailure},
			wantStat: "IP_GENERAL_FAILURE",
		},
		{
			name:      "local error",
			target:    "192.0.2.10",
			reply:     &echoResult{err: errors.New("IcmpCreateFile: boom")},
			wantStat:  StatusError,
			wantErrIn: "IcmpCreateFile",
		},
		{
			name:   "host name resolves to first IPv4",
			target: "dual.example",
			reply: &echoResult{replies: 1, code: ipSuccess, from: addrTarget, ttl: 50,
				elapsed: time.Millisecond},
			wantOK: true, wantStat: "IP_SUCCESS", wantFrom: "192.0.2.10", wantTTL: 50, wantRTT: true,
		},
		{name: "IPv6 literal rejected", target: "2001:db8::1", wantStat: StatusError, wantErrIn: "IPv4"},
		{name: "IPv6-only name rejected", target: "v6only.example", wantStat: StatusError, wantErrIn: "no IPv4"},
		{name: "unresolvable", target: "nope.example", wantStat: StatusError, wantErrIn: "no such host"},
		{name: "empty", target: " ", wantStat: StatusError, wantErrIn: "empty"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &fakeEcho{byTTL: map[uint8]echoResult{}}
			if tt.reply != nil {
				f.byTTL[0] = *tt.reply
			}
			r := newFakeProber(f).Ping(context.Background(), tt.target, 2*time.Second)
			if r.Kind != "icmp" || r.Target != tt.target {
				t.Errorf("kind/target = %q/%q", r.Kind, r.Target)
			}
			if r.OK != tt.wantOK || r.Status != tt.wantStat {
				t.Errorf("OK/Status = %v/%q, want %v/%q (err %q)", r.OK, r.Status, tt.wantOK, tt.wantStat, r.Err)
			}
			if r.ReplyFrom != tt.wantFrom || r.TTL != tt.wantTTL {
				t.Errorf("ReplyFrom/TTL = %q/%d, want %q/%d", r.ReplyFrom, r.TTL, tt.wantFrom, tt.wantTTL)
			}
			if (r.RTTus > 0) != tt.wantRTT {
				t.Errorf("RTTus = %d, want set=%v", r.RTTus, tt.wantRTT)
			}
			if tt.wantErrIn == "" && r.Err != "" || !strings.Contains(r.Err, tt.wantErrIn) {
				t.Errorf("Err = %q, want containing %q", r.Err, tt.wantErrIn)
			}
			if tt.reply == nil && len(f.calls) != 0 {
				t.Errorf("echo called %d times for an unusable target", len(f.calls))
			}
		})
	}
}

func TestPingRTTFromElapsed(t *testing.T) {
	f := &fakeEcho{byTTL: map[uint8]echoResult{0: {replies: 1, code: ipSuccess, from: addrTarget,
		elapsed: 1500 * time.Microsecond}}}
	r := newFakeProber(f).Ping(context.Background(), "192.0.2.10", time.Second)
	if r.RTTus != 1500 {
		t.Fatalf("RTTus = %d, want 1500", r.RTTus)
	}
	// Sub-microsecond measurements still count as an answer.
	f.byTTL[0] = echoResult{replies: 1, code: ipSuccess, from: addrTarget, elapsed: 10 * time.Nanosecond}
	if r := newFakeProber(f).Ping(context.Background(), "192.0.2.10", time.Second); r.RTTus != 1 {
		t.Fatalf("RTTus = %d, want 1", r.RTTus)
	}
}

func TestPingTimeoutClippedToDeadline(t *testing.T) {
	f := &fakeEcho{byTTL: map[uint8]echoResult{0: {replies: 1, code: ipSuccess, from: addrTarget, elapsed: time.Millisecond}}}
	p := newFakeProber(f)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	p.Ping(ctx, "192.0.2.10", 5*time.Second)
	if len(f.timeout) != 1 || f.timeout[0] > 300*time.Millisecond || f.timeout[0] < 100*time.Millisecond {
		t.Fatalf("echo timeouts = %v, want ≈300ms", f.timeout)
	}
	// Default timeout when none is given.
	p.Ping(context.Background(), "192.0.2.10", 0)
	if got := f.timeout[1]; got != defaultTimeout {
		t.Fatalf("default timeout = %v, want %v", got, defaultTimeout)
	}
}

func TestPingCanceled(t *testing.T) {
	// Pre-canceled: no echo at all.
	f := &fakeEcho{byTTL: map[uint8]echoResult{}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := newFakeProber(f).Ping(ctx, "192.0.2.10", time.Second)
	if r.Status != StatusCanceled || r.OK || len(f.calls) != 0 {
		t.Fatalf("pre-canceled: status %q ok %v calls %d", r.Status, r.OK, len(f.calls))
	}

	// Canceled while the (simulated) syscall blocks: returns promptly.
	f = &fakeEcho{byTTL: map[uint8]echoResult{}, delay: 3 * time.Second}
	ctx, cancel = context.WithCancel(context.Background())
	time.AfterFunc(50*time.Millisecond, cancel)
	start := time.Now()
	r = newFakeProber(f).Ping(ctx, "192.0.2.10", 5*time.Second)
	if el := time.Since(start); el > time.Second {
		t.Fatalf("Ping returned after %v, want prompt return on cancel", el)
	}
	if r.Status != StatusCanceled || !strings.Contains(r.Err, "canceled") {
		t.Fatalf("status %q err %q, want canceled", r.Status, r.Err)
	}
}

func TestPingCallerDeadlineIsTimeout(t *testing.T) {
	f := &fakeEcho{byTTL: map[uint8]echoResult{}, delay: 3 * time.Second}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	r := newFakeProber(f).Ping(ctx, "192.0.2.10", 5*time.Second)
	if el := time.Since(start); el > time.Second {
		t.Fatalf("returned after %v", el)
	}
	if r.Status != StatusTimeout || r.OK || r.RTTus != 0 || !strings.Contains(r.Err, "deadline") {
		t.Fatalf("got %+v", r)
	}
	// An already-expired deadline means nothing was sent.
	r = newFakeProber(f).Ping(ctx, "192.0.2.10", time.Second)
	if r.Status != StatusCanceled {
		t.Fatalf("expired context: %+v", r)
	}
}

func TestPingGuardWhenSyscallOverruns(t *testing.T) {
	f := &fakeEcho{byTTL: map[uint8]echoResult{}, delay: 3 * time.Second}
	start := time.Now()
	r := newFakeProber(f).Ping(context.Background(), "192.0.2.10", 100*time.Millisecond)
	el := time.Since(start)
	if el < icmpGuard || el > icmpGuard+time.Second {
		t.Fatalf("returned after %v, want ≈ timeout+guard", el)
	}
	if r.Status != StatusTimeout || r.OK || r.RTTus != 0 || !strings.Contains(r.Err, "did not return") {
		t.Fatalf("got %+v", r)
	}
}

func TestTraceroutePath(t *testing.T) {
	f := &fakeEcho{byTTL: map[uint8]echoResult{
		1: {replies: 1, code: ipTTLExpiredTransit, from: addrGateway, elapsed: 2 * time.Millisecond},
		2: {replies: 0, code: ipReqTimedOut},
		3: {replies: 1, code: ipTTLExpiredTransit, from: addrRouter2, elapsed: 9 * time.Millisecond},
		4: {replies: 1, code: ipSuccess, from: addrTarget, elapsed: 12 * time.Millisecond},
		5: {replies: 1, code: ipSuccess, from: addrTarget}, // never reached
	}}
	tr := newFakeProber(f).Traceroute(context.Background(), "192.0.2.10", 15, time.Second)
	if !tr.Reached || len(tr.Hops) != 4 || tr.Target != "192.0.2.10" {
		t.Fatalf("reached %v hops %d: %+v", tr.Reached, len(tr.Hops), tr.Hops)
	}
	want := []struct {
		addr, status string
		rtt          bool
	}{
		{"192.168.1.254", "IP_TTL_EXPIRED_TRANSIT", true},
		{"", "IP_REQ_TIMED_OUT", false},
		{"198.51.100.1", "IP_TTL_EXPIRED_TRANSIT", true},
		{"192.0.2.10", "IP_SUCCESS", true},
	}
	for i, w := range want {
		h := tr.Hops[i]
		if h.TTL != i+1 || h.Addr != w.addr || h.Status != w.status || (h.RTTus > 0) != w.rtt {
			t.Errorf("hop %d = %+v, want ttl %d %+v", i, h, i+1, w)
		}
	}
	if got := f.calls; len(got) != 4 || got[0] != 1 || got[3] != 4 {
		t.Errorf("TTLs sent = %v, want 1..4", got)
	}
	if tr.DurMs < 0 {
		t.Errorf("DurMs = %d", tr.DurMs)
	}
}

func TestTracerouteStops(t *testing.T) {
	tests := []struct {
		name     string
		script   map[uint8]echoResult
		maxHops  int
		wantHops int
		reached  bool
		last     string
	}{
		{
			name: "destination unreachable ends the trace",
			script: map[uint8]echoResult{
				1: {replies: 1, code: ipTTLExpiredTransit, from: addrGateway},
				2: {replies: 1, code: ipDestNetUnreachable, from: addrRouter2},
			},
			maxHops: 10, wantHops: 2, last: "IP_DEST_NET_UNREACHABLE",
		},
		{
			name:    "max hops without reaching",
			script:  map[uint8]echoResult{1: {replies: 1, code: ipTTLExpiredTransit, from: addrGateway}},
			maxHops: 3, wantHops: 3, last: "IP_REQ_TIMED_OUT",
		},
		{
			name: "success from a different address is not reached",
			script: map[uint8]echoResult{
				1: {replies: 1, code: ipSuccess, from: addrGateway},
			},
			maxHops: 5, wantHops: 1, last: "IP_SUCCESS",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &fakeEcho{byTTL: tt.script}
			tr := newFakeProber(f).Traceroute(context.Background(), "192.0.2.10", tt.maxHops, 10*time.Millisecond)
			if len(tr.Hops) != tt.wantHops || tr.Reached != tt.reached || tr.Err != "" {
				t.Fatalf("hops %d reached %v err %q, want %d %v no err: %+v", len(tr.Hops), tr.Reached, tr.Err, tt.wantHops, tt.reached, tr.Hops)
			}
			if got := tr.Hops[len(tr.Hops)-1].Status; got != tt.last {
				t.Errorf("last status %q, want %q", got, tt.last)
			}
		})
	}
}

// TestTracerouteLocalFailureInErr: a local failure (ICMP handle, stuck ICMP service, bad
// destination) produced no network outcome for its TTL, so it is not a hop: it is recorded
// in Traceroute.Err, the hops end with the last TTL actually probed, and none is invented.
// "No route from this PC" stays a hop status, as for the fast-cycle probes.
func TestTracerouteLocalFailureInErr(t *testing.T) {
	tests := []struct {
		name      string
		script    map[uint8]echoResult
		wantHops  []string // statuses
		errIn     string   // "" = Err must be empty
		wantCalls int      // echo requests attempted
	}{
		{
			name:     "local error before anything was sent",
			script:   map[uint8]echoResult{1: {err: errors.New("IcmpCreateFile: denied")}},
			wantHops: nil, errIn: "local error at TTL 1: IcmpCreateFile: denied", wantCalls: 1,
		},
		{
			name: "local error after two hops",
			script: map[uint8]echoResult{
				1: {replies: 1, code: ipTTLExpiredTransit, from: addrGateway, elapsed: time.Millisecond},
				2: {replies: 0, code: ipReqTimedOut},
				3: {err: errors.New("IcmpCreateFile: out of handles")},
				4: {replies: 1, code: ipSuccess, from: addrTarget}, // never sent
			},
			wantHops:  []string{"IP_TTL_EXPIRED_TRANSIT", "IP_REQ_TIMED_OUT"},
			errIn:     "local error at TTL 3: IcmpCreateFile: out of handles",
			wantCalls: 3,
		},
		{
			name:      "no route stays a hop status",
			script:    map[uint8]echoResult{1: {err: fmt.Errorf("IcmpSendEcho: %w", unreachableErr())}},
			wantHops:  []string{StatusUnreachable + ": IcmpSendEcho: "},
			wantCalls: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &fakeEcho{byTTL: tt.script}
			tr := newFakeProber(f).Traceroute(context.Background(), "192.0.2.10", 10, 10*time.Millisecond)
			if tr.Reached || tr.Hops == nil || len(tr.Hops) != len(tt.wantHops) {
				t.Fatalf("reached %v hops %+v, want %d hops", tr.Reached, tr.Hops, len(tt.wantHops))
			}
			for i, want := range tt.wantHops {
				if h := tr.Hops[i]; h.TTL != i+1 || !strings.HasPrefix(h.Status, want) {
					t.Errorf("hop %d = %+v, want TTL %d status %q...", i, h, i+1, want)
				}
				if strings.HasPrefix(tr.Hops[i].Status, StatusError) {
					t.Errorf("hop %d carries a local error as its status: %+v", i, tr.Hops[i])
				}
			}
			if tt.errIn == "" && tr.Err != "" || !strings.Contains(tr.Err, tt.errIn) {
				t.Errorf("Err = %q, want containing %q", tr.Err, tt.errIn)
			}
			if len(f.calls) != tt.wantCalls {
				t.Errorf("echo called for TTLs %v, want %d calls", f.calls, tt.wantCalls)
			}
		})
	}
}

func TestTracerouteDefaultsAndErrors(t *testing.T) {
	f := &fakeEcho{byTTL: map[uint8]echoResult{}}
	p := newFakeProber(f)
	tr := p.Traceroute(context.Background(), "192.0.2.10", 0, 0)
	if len(tr.Hops) != defaultMaxHops {
		t.Errorf("default max hops: %d hops", len(tr.Hops))
	}
	for _, to := range f.timeout {
		if to != defaultPerHop {
			t.Fatalf("per-hop timeout %v, want %v", to, defaultPerHop)
		}
	}
	f.calls = nil
	if tr := p.Traceroute(context.Background(), "192.0.2.10", 1000, time.Millisecond); len(tr.Hops) != maxTTL {
		t.Errorf("maxHops capped: %d hops", len(tr.Hops))
	}

	// A target that cannot be resolved: nothing is sent, the reason is in Err and no
	// pseudo-hop is invented. Hops stays an empty (non-nil) list: "hops":[] in the record.
	f.calls = nil
	tr = p.Traceroute(context.Background(), "nope.example", 5, time.Second)
	if len(tr.Hops) != 0 || tr.Reached || !strings.Contains(tr.Err, "no such host") || len(f.calls) != 0 {
		t.Errorf("unresolvable target: %+v (echo calls %v)", tr, f.calls)
	}
	if tr.Hops == nil {
		t.Error("Hops must be non-nil")
	}
	b, err := json.Marshal(tr)
	if err != nil || !strings.Contains(string(b), `"hops":[]`) || !strings.Contains(string(b), `"err":"`) {
		t.Errorf("record %s (%v)", b, err)
	}
	for _, target := range []string{"", "2001:db8::1", "v6only.example"} {
		if tr := p.Traceroute(context.Background(), target, 5, time.Second); len(tr.Hops) != 0 || tr.Err == "" {
			t.Errorf("Traceroute(%q) = %+v, want Err and no hops", target, tr)
		}
	}
	if len(f.calls) != 0 {
		t.Errorf("echo called for unusable targets: %v", f.calls)
	}
}

// TestTracerouteCanceledDuringResolution: a cancel while resolving the target means nothing
// was sent; Err says it was canceled (the convention of results without a status field).
func TestTracerouteCanceledDuringResolution(t *testing.T) {
	f := &fakeEcho{byTTL: map[uint8]echoResult{}}
	p := newFakeProber(f)
	ctx, cancel := context.WithCancel(context.Background())
	p.lookupIP = func(lctx context.Context, host string) ([]netip.Addr, error) {
		cancel()
		<-lctx.Done()
		return nil, lctx.Err()
	}
	tr := p.Traceroute(ctx, "name.example", 5, time.Second)
	if len(tr.Hops) != 0 || tr.Hops == nil || tr.Reached || !strings.HasPrefix(tr.Err, StatusCanceled+": ") || len(f.calls) != 0 {
		t.Fatalf("got %+v (echo calls %v)", tr, f.calls)
	}
}

func TestTracerouteCanceled(t *testing.T) {
	f := &fakeEcho{byTTL: map[uint8]echoResult{
		1: {replies: 1, code: ipTTLExpiredTransit, from: addrGateway},
	}, delay: 100 * time.Millisecond}
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(150*time.Millisecond, cancel)
	start := time.Now()
	tr := newFakeProber(f).Traceroute(ctx, "192.0.2.10", 30, 5*time.Second)
	if el := time.Since(start); el > time.Second {
		t.Fatalf("returned after %v", el)
	}
	if len(tr.Hops) != 2 || tr.Hops[0].Status != "IP_TTL_EXPIRED_TRANSIT" || tr.Hops[1].Status != StatusCanceled {
		t.Fatalf("hops: %+v", tr.Hops)
	}
	if tr.Reached {
		t.Error("canceled trace must not be reached")
	}
}
