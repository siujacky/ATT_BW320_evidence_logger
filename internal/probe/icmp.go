package probe

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"attmonitor/internal/model"
)

// icmpGuard is how long past its own timeout an IcmpSendEcho call may run before the probe
// gives up waiting (Windows can overrun short timeouts, e.g. while ARP-resolving an on-link
// host). The call itself still finishes in its goroutine and releases its handle.
const icmpGuard = time.Second

// maxICMPInFlight bounds the IcmpSendEcho calls of one Prober that may be outstanding at
// once. Each blocked call holds an OS thread; normally a handful are in flight. If the
// Windows ICMP service ever stopped returning, calls abandoned by echoCtx would otherwise
// pile up until the process ran out of threads. Past the limit, probes fail at once with a
// local error that names the cause.
const maxICMPInFlight = 64

// traceResolveTimeout bounds the name resolution of a traceroute target (a variable so that
// tests can shorten it).
var traceResolveTimeout = 5 * time.Second

// echoResult is the outcome of one IcmpSendEcho call.
type echoResult struct {
	replies uint32        // ICMP_ECHO_REPLY structures returned (0: status from GetLastError)
	code    uint32        // IP_STATUS (valid when err == nil)
	from    netip.Addr    // replying address (valid when replies > 0)
	ttl     uint8         // TTL of the reply packet (valid when replies > 0)
	elapsed time.Duration // time around the call, on the high-resolution clock
	err     error         // local failure (handle creation, non-IP_STATUS error)
}

// answered reports whether the network answered: a reply structure came back with an
// actual sender address. Only then are ReplyFrom, TTL and RTT meaningful.
func (r echoResult) answered() bool {
	return r.err == nil && r.replies > 0 && r.from.IsValid() && !r.from.IsUnspecified()
}

// echoOutcome is an echoResult, or the reason none is available (local != "").
type echoOutcome struct {
	echoResult
	local    string // "" (echoResult valid), StatusCanceled or StatusTimeout
	localErr string
}

// echoCtx runs one echo request in a goroutine so that ctx cancellation returns promptly;
// the syscall itself is bounded by its timeout. The timeout is clipped to ctx's deadline.
// A context that has already ended is reported as StatusCanceled (nothing was sent); a
// deadline that expires while waiting is StatusTimeout, a cancellation StatusCanceled.
func (p *Prober) echoCtx(ctx context.Context, dst netip.Addr, ttl uint8, timeout time.Duration) echoOutcome {
	to := effectiveTimeout(ctx, timeout)
	if ctx.Err() != nil || to <= 0 {
		return echoOutcome{local: StatusCanceled, localErr: ctxErr(ctx).Error()}
	}
	if n := p.icmpInFlight.Add(1); n > maxICMPInFlight {
		p.icmpInFlight.Add(-1)
		return echoOutcome{echoResult: echoResult{err: fmt.Errorf(
			"%d earlier ICMP requests have not returned; not sending another (the Windows ICMP service may be stuck)", n-1)}}
	}
	ch := make(chan echoResult, 1) // buffered: the sender never blocks if we stop waiting
	echo := p.echo
	go func() {
		defer p.icmpInFlight.Add(-1)
		r := echoResult{err: errors.New("ICMP request did not complete")}
		defer func() {
			// This goroutine is outside every caller's recover: a panic here would end the
			// whole evidence logger, so it becomes this probe's local error instead.
			if v := recover(); v != nil {
				r = echoResult{err: fmt.Errorf("ICMP request panicked: %v", v)}
			}
			ch <- r
		}()
		r = echo(dst, ttl, to)
	}()
	guard := time.NewTimer(to + icmpGuard)
	defer guard.Stop()
	select {
	case r := <-ch:
		return echoOutcome{echoResult: r}
	case <-ctx.Done():
		select { // prefer a result that is already available
		case r := <-ch:
			return echoOutcome{echoResult: r}
		default:
		}
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			// The caller's deadline is a time limit like the probe's own timeout.
			return echoOutcome{local: StatusTimeout, localErr: "no ICMP result before the caller's deadline"}
		}
		return echoOutcome{local: StatusCanceled, localErr: ctx.Err().Error()}
	case <-guard.C:
		return echoOutcome{local: StatusTimeout,
			localErr: fmt.Sprintf("IcmpSendEcho did not return within %v", to+icmpGuard)}
	}
}

// localErrStatus classifies a local IcmpSendEcho failure. With no route to the destination
// (for example while this PC's link is down) Windows fails the call with a Win32 "network
// unreachable" error instead of an IP_STATUS code; that is reported as StatusUnreachable,
// as the TCP probe reports the same condition. Anything else is StatusError.
func localErrStatus(err error) string {
	if isUnreachable(err) {
		return StatusUnreachable
	}
	return StatusError
}

// Ping sends one ICMP echo request (32-byte payload) to target, an IPv4 address or a host
// name resolved to IPv4 (resolution is bounded by the timeout; the echo then gets its own
// timeout). Status is the IP_STATUS name; ReplyFrom/TTL/RTTus are set whenever a reply
// structure with a sender came back, including ICMP errors from routers (e.g. a gateway
// reporting IP_DEST_NET_UNREACHABLE). OK requires IP_SUCCESS from the target.
func (p *Prober) Ping(ctx context.Context, target string, timeout time.Duration) model.ProbeResult {
	res := model.ProbeResult{Kind: model.KindICMP, Target: target}
	dst, err := p.resolveIPv4(ctx, target, effectiveTimeout(ctx, timeout))
	if err != nil {
		res.Status, res.Err = StatusError, err.Error()
		if ctx.Err() != nil {
			res.Status = StatusCanceled
		}
		return res
	}
	o := p.echoCtx(ctx, dst, 0, timeout)
	switch {
	case o.local != "":
		res.Status, res.Err = o.local, o.localErr
	case o.err != nil:
		res.Status, res.Err = localErrStatus(o.err), o.err.Error()
	default:
		res.Status = ICMPStatusName(o.code)
		if o.answered() {
			res.ReplyFrom = o.from.String()
			res.TTL = int(o.ttl)
			res.RTTus = micros(o.elapsed)
		}
		res.OK = o.code == ipSuccess && o.answered() && o.from == dst
		if o.code == ipSuccess && o.answered() && o.from != dst {
			res.Err = fmt.Sprintf("echo reply came from %s, not from the target %s", o.from, dst)
		}
	}
	return res
}

// Traceroute probes target with one ICMP echo per TTL (1..maxHops, perHop timeout each),
// like tracert -h maxHops -w perHop with a single attempt per hop. Routers answer with
// IP_TTL_EXPIRED_TRANSIT (their address is the hop); the trace stops at IP_SUCCESS
// (Reached when it came from the target), at a "destination unreachable" report, when this
// PC has no route (the hop's status is "unreachable: <system error>", as the fast-cycle
// probes report it), at a local error, or when ctx ends (the interrupted hop is recorded as
// StatusCanceled).
//
// Hops lists only the TTLs that were probed (it is empty, not nil, when none was). A target
// that cannot be resolved or used, and a local failure of the ICMP API (which produced no
// network outcome for its TTL), are recorded in Err - "local error at TTL n: ..." for the
// latter - and never as a hop. Err starts with "canceled: " when the caller's context ended
// while resolving the target.
func (p *Prober) Traceroute(ctx context.Context, target string, maxHops int, perHop time.Duration) (tr model.Traceroute) {
	sw := startStopwatch()
	tr = model.Traceroute{Target: target, Hops: []model.Hop{}}
	// Named result: the deferred assignment applies to whatever value is returned.
	defer func() { tr.DurMs = sw.elapsed().Milliseconds() }()

	if maxHops <= 0 {
		maxHops = defaultMaxHops
	}
	if maxHops > maxTTL {
		maxHops = maxTTL
	}
	if perHop <= 0 {
		perHop = defaultPerHop
	}
	dst, err := p.resolveIPv4(ctx, target, effectiveTimeout(ctx, traceResolveTimeout))
	if err != nil {
		tr.Err = err.Error()
		if ctx.Err() != nil {
			tr.Err = StatusCanceled + ": " + tr.Err
		}
		return tr // nothing was sent
	}
	for ttl := 1; ttl <= maxHops; ttl++ {
		o := p.echoCtx(ctx, dst, uint8(ttl), perHop)
		hop := model.Hop{TTL: ttl}
		switch {
		case o.local == StatusCanceled:
			hop.Status = StatusCanceled
			tr.Hops = append(tr.Hops, hop)
			return tr
		case o.local != "":
			hop.Status = o.local
		case o.err != nil && localErrStatus(o.err) == StatusUnreachable:
			// No route from this PC (e.g. its link is down): a network condition of this
			// hop, and the next TTL would meet the same.
			hop.Status = StatusUnreachable + ": " + o.err.Error()
			tr.Hops = append(tr.Hops, hop)
			return tr
		case o.err != nil:
			// The ICMP API failed locally: no network outcome for this TTL, so it is not a
			// hop, and the failure will not fix itself on the next one.
			tr.Err = fmt.Sprintf("local error at TTL %d: %v", ttl, o.err)
			return tr
		default:
			hop.Status = ICMPStatusName(o.code)
			if o.answered() {
				hop.Addr = o.from.String()
				hop.RTTus = micros(o.elapsed)
			}
		}
		tr.Hops = append(tr.Hops, hop)
		if o.local == "" && o.answered() {
			if o.code == ipSuccess {
				tr.Reached = o.from == dst
				return tr
			}
			if isDestUnreachable(o.code) {
				return tr
			}
		}
	}
	return tr
}
