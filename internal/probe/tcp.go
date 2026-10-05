package probe

import (
	"context"
	"errors"
	"net"
	"sync"
	"syscall"
	"time"

	"attmonitor/internal/model"
)

// TCP connects to target ("host:port") and closes the connection immediately. Status is
// StatusConnected (OK; RTTus = connect time; ReplyFrom = the peer address), StatusRefused
// (the host answered with RST), StatusTimeout, StatusUnreachable (no route / ICMP
// unreachable), StatusCanceled, or StatusError with the error text in Err.
//
// RTTus is the time from the start of the successful connect attempt to its completion:
// resolving a host name and earlier failed attempts (e.g. an IPv6 address tried first) are
// not counted. RTTus is set only for StatusConnected.
//
// Some Windows versions retry a SYN that was answered with RST before reporting "refused"
// (historically about 1-2 s; immediate on Windows 11 loopback), so with short timeouts a
// closed port can be reported as StatusTimeout.
func (p *Prober) TCP(ctx context.Context, target string, timeout time.Duration) model.ProbeResult {
	res := model.ProbeResult{Kind: model.KindTCP, Target: target}
	if _, _, err := net.SplitHostPort(target); err != nil {
		res.Status, res.Err = StatusError, err.Error()
		return res
	}
	to := effectiveTimeout(ctx, timeout)
	if ctx.Err() != nil || to <= 0 {
		res.Status, res.Err = StatusCanceled, ctxErr(ctx).Error()
		return res
	}
	dctx, cancel := context.WithTimeout(ctx, to)
	defer cancel()
	starts := new(connectStarts)
	dctx = context.WithValue(dctx, connectStartsKey{}, starts)

	sw := startStopwatch()
	conn, err := p.dial(dctx, "tcp", target)
	end := hrNow()
	if err == nil {
		res.OK = true
		res.Status = StatusConnected
		start := sw.start // fallback: the whole dial (a dial function that bypasses markConnectStart)
		ra := conn.RemoteAddr()
		if ra != nil {
			res.ReplyFrom = ra.String()
		}
		if s, ok := starts.forPeer(ra); ok {
			start = s
		}
		res.RTTus = micros(max(end-start, 0))
		_ = conn.Close()
		return res
	}
	res.Status = classifyDialError(ctx, err)
	res.Err = err.Error()
	return res
}

// connectStarts records when the dialer began each connect attempt of one TCP probe, keyed
// by remote address (net.Dialer.ControlContext runs after the socket is created and right
// before connect is called).
type connectStarts struct {
	mu sync.Mutex
	at map[string]time.Duration
}

type connectStartsKey struct{}

// markConnectStart is the probe dialer's ControlContext hook. It records the start of a
// connect attempt for a TCP probe that asked for it via the context; for other dials (HTTP
// checks) it does nothing.
func markConnectStart(ctx context.Context, _, address string, _ syscall.RawConn) error {
	if cs, ok := ctx.Value(connectStartsKey{}).(*connectStarts); ok {
		now := hrNow()
		cs.mu.Lock()
		if cs.at == nil {
			cs.at = make(map[string]time.Duration)
		}
		cs.at[address] = now
		cs.mu.Unlock()
	}
	return nil
}

// forPeer returns when the attempt to peer started: by address, or the only attempt made.
func (cs *connectStarts) forPeer(peer net.Addr) (time.Duration, bool) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	if peer != nil {
		if s, ok := cs.at[peer.String()]; ok {
			return s, true
		}
	}
	if len(cs.at) == 1 {
		for _, s := range cs.at {
			return s, true
		}
	}
	return 0, false
}

// classifyDialError maps a dial error to a TCP probe status. parent is the caller's
// context: its cancellation is reported as StatusCanceled, while the probe's own deadline
// (or the caller's deadline) is a timeout.
func classifyDialError(parent context.Context, err error) string {
	switch {
	case errors.Is(parent.Err(), context.Canceled):
		return StatusCanceled
	case isRefused(err):
		return StatusRefused
	case isUnreachable(err):
		return StatusUnreachable
	case errors.Is(err, context.DeadlineExceeded), isTimeoutErrno(err):
		return StatusTimeout
	case errors.Is(err, context.Canceled):
		return StatusCanceled
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return StatusTimeout
	}
	return StatusError
}
