package syslogrx

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net"
	"net/netip"
	"runtime/debug"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"attmonitor/internal/contracts"
	"attmonitor/internal/model"
)

// Defaults (docs/syslog-snmp-traffic.md §3.2, config.SyslogConfig).
const (
	DefaultListen       = ":514"
	DefaultMaxPerMinute = 2000
	DefaultMaxMessage   = 8 << 10
	// DefaultMaxBytesPerMinute: the stored lines of a minute's messages (Options.MaxBytesPerMinute)
	// fill at most one chunk of the syslog store (1 MiB), so the store seals - and the ledger
	// records - at most about one chunk a minute by size, whatever the datagrams hold. 2,000 of
	// the gateway's usual messages (a few hundred bytes each as stored) fit.
	DefaultMaxBytesPerMinute = 1 << 20
)

const (
	// maxDatagram is the largest UDP payload (65,535 bytes less the 8-byte UDP header; IPv4
	// allows 65,507). The read buffer is larger, so no datagram is cut short and every size is
	// known.
	maxDatagram = 65535 - 8
	readBuffer  = 64 << 10
	// socketBuffer is the receive buffer asked of the system, so that a burst (a gateway that
	// boots logs a lot at once) is not lost while the receiver is busy.
	socketBuffer = 1 << 20
	// logEvery is the shortest time between two log entries of the same kind; the entries held
	// back meanwhile are counted in the next one.
	logEvery = time.Minute
)

// While the socket keeps failing with errors that are not transient, the receiver pauses
// between attempts: errPauseMin after the second failure in a row, doubled per further failure
// up to errPauseMax (variables for tests).
var (
	errPauseMin = 10 * time.Millisecond
	errPauseMax = time.Second
)

// parseDatagram parses an accepted datagram (Parse; a test replaces it to check the guard
// against a parser that panics).
var parseDatagram = Parse

var _ contracts.SyslogReceiver = (*Receiver)(nil)

// Options configures a Receiver. Zero values select the defaults.
type Options struct {
	// Listen is the UDP address to bind: ":514" (the default) is port 514 on every interface,
	// "127.0.0.1:0" a free port on the loopback interface. The host must be an IP address.
	Listen string
	// Allowed are the senders whose datagrams are accepted (see SetAllowed).
	Allowed []netip.Addr
	// MaxPerMinute caps the messages kept per minute of receive time (default 2000).
	MaxPerMinute int
	// MaxBytesPerMinute caps the size of the messages kept per minute of receive time as the
	// syslog store writes them - each one's json.Marshal line and its line feed - (default
	// DefaultMaxBytesPerMinute). Escaped control characters make a datagram's line up to about
	// twelve times its size, so MaxPerMinute alone does not bound what is stored.
	MaxBytesPerMinute int
	// MaxMessage is the largest datagram kept, in bytes (default 8192, at most 65527).
	MaxMessage int
	// MaxPending caps the messages kept between two Drain calls (default 4 × MaxPerMinute).
	MaxPending int
	Now        func() time.Time // receive times (default time.Now)
	Logger     *slog.Logger
}

// Receiver receives syslog datagrams over UDP and keeps the ones from allowed senders until
// they are drained (contracts.SyslogReceiver). All methods are safe for concurrent use. One Run
// is active at a time; messages not drained yet survive the end of Run.
type Receiver struct {
	o       Options
	log     *slog.Logger
	allowed atomic.Pointer[allowList]
	running atomic.Bool
	// listen binds the socket: net.ListenPacket (tests replace it before Run).
	listen func(network, address string) (net.PacketConn, error)

	mu        sync.Mutex
	addr      string // the bound address while Run listens
	listenErr error  // why the last Run could not listen, or stopped listening
	pending   []model.SyslogMessage
	dropped   int       // since the last Drain
	rejected  int       // since the last Drain
	minute    time.Time // the minute of receive time that inMinute and bytesInMinute count …
	inMinute  int       // … the messages kept in, and …
	// bytesInMinute … their size as stored (storedSize).
	bytesInMinute int
	gates         logGates
}

// logGates rate-limit the log entries that a flood or a failing socket would repeat.
type logGates struct {
	rejected, tooLarge, overCap, overBytes, full, transient, failing, panicked gate
}

// New validates o and returns a Receiver. It does not bind the socket (Run does).
func New(o Options) (*Receiver, error) {
	if o.Listen == "" {
		o.Listen = DefaultListen
	}
	if err := checkListen(o.Listen); err != nil {
		return nil, err
	}
	switch {
	case o.MaxPerMinute < 0:
		return nil, errors.New("syslogrx: MaxPerMinute must not be negative")
	case o.MaxBytesPerMinute < 0:
		return nil, errors.New("syslogrx: MaxBytesPerMinute must not be negative")
	case o.MaxMessage < 0 || o.MaxMessage > maxDatagram:
		return nil, fmt.Errorf("syslogrx: MaxMessage must be 0 (the default) to %d bytes", maxDatagram)
	case o.MaxPending < 0:
		return nil, errors.New("syslogrx: MaxPending must not be negative")
	}
	if o.MaxPerMinute == 0 {
		o.MaxPerMinute = DefaultMaxPerMinute
	}
	if o.MaxBytesPerMinute == 0 {
		o.MaxBytesPerMinute = DefaultMaxBytesPerMinute
	}
	if o.MaxMessage == 0 {
		o.MaxMessage = DefaultMaxMessage
	}
	if o.MaxPending == 0 {
		o.MaxPending = min(o.MaxPerMinute, math.MaxInt/4) * 4
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
	r := &Receiver{o: o, log: o.Logger, listen: net.ListenPacket}
	r.SetAllowed(o.Allowed)
	r.o.Allowed = nil // SetAllowed replaces the list; r.allowed holds it
	return r, nil
}

// checkListen accepts "host:port" and ":port" with an IP address as host and a port from 0 (a
// free port) to 65535.
func checkListen(s string) error {
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return fmt.Errorf("syslogrx: Listen %q: %w", s, err)
	}
	if host != "" {
		if _, err := netip.ParseAddr(host); err != nil {
			return fmt.Errorf("syslogrx: Listen %q: the host must be an IP address", s)
		}
	}
	if _, err := strconv.ParseUint(port, 10, 16); err != nil {
		return fmt.Errorf("syslogrx: Listen %q: the port must be a number from 0 to 65535", s)
	}
	return nil
}

// Run binds Options.Listen and receives datagrams until ctx is done; then it closes the socket
// and returns nil (at once when ctx is done already). When the socket cannot be bound, Run
// returns the error, and Listening reports it until the next Run.
//
// Receive errors do not end Run. Transient ones are skipped: an ICMP error about an earlier
// datagram (Windows reports port unreachable on a UDP socket as WSAECONNRESET unless the socket
// opts out, as Go's sockets do; the code is handled anyway) or a datagram cut short. After other
// errors Run tries again, pausing while they persist (at most a second). Both are logged at most
// once a minute. A second Run while one is active returns an error.
func (r *Receiver) Run(ctx context.Context) error {
	if !r.running.CompareAndSwap(false, true) {
		return errors.New("syslogrx: the receiver is already running")
	}
	defer r.running.Store(false)
	if ctx.Err() != nil {
		return nil
	}
	pc, err := r.listen("udp", r.o.Listen)
	if err != nil {
		err = fmt.Errorf("syslogrx: %w", err)
		r.setListening("", err)
		r.log.Warn("syslog receiver: cannot listen", "listen", r.o.Listen, "err", err)
		return err
	}
	if uc, ok := pc.(*net.UDPConn); ok {
		if err := uc.SetReadBuffer(socketBuffer); err != nil {
			r.log.Debug("syslog receiver: could not enlarge the socket's receive buffer", "err", err)
		}
	}
	addr := pc.LocalAddr().String()
	r.setListening(addr, nil)
	r.log.Info("syslog receiver: listening", "addr", addr)

	stop := context.AfterFunc(ctx, func() { pc.Close() }) // unblocks the read
	err = r.serve(ctx, pc)
	stop()
	pc.Close()
	r.setListening("", err)
	if err != nil {
		r.log.Error("syslog receiver: stopped listening", "addr", addr, "err", err)
		return err
	}
	r.log.Info("syslog receiver: stopped", "addr", addr)
	return nil
}

// serve receives datagrams on pc until ctx is done (nil) or pc is closed by something else.
func (r *Receiver) serve(ctx context.Context, pc net.PacketConn) error {
	buf := make([]byte, readBuffer)
	var pause time.Duration
	for {
		n, from, err := readFrom(pc, buf)
		if err == nil {
			pause = 0
			r.accept(buf[:n], from)
			continue
		}
		switch {
		case ctx.Err() != nil:
			return nil
		case errors.Is(err, net.ErrClosed):
			return fmt.Errorf("syslogrx: the socket was closed: %w", err)
		case isTransient(err):
			if ok, held := r.pass(&r.gates.transient); ok {
				r.log.Info("syslog receiver: skipped a receive error about a single datagram",
					"err", err, "suppressed", held)
			}
		default:
			if ok, held := r.pass(&r.gates.failing); ok {
				r.log.Warn("syslog receiver: receiving failed; trying again", "err", err, "suppressed", held)
			}
			if pause > 0 && !sleep(ctx, pause) {
				return nil
			}
			pause = min(max(2*pause, errPauseMin), errPauseMax)
		}
	}
}

// readFrom receives one datagram into buf and returns its size and sender.
func readFrom(pc net.PacketConn, buf []byte) (int, netip.AddrPort, error) {
	if uc, ok := pc.(*net.UDPConn); ok {
		return uc.ReadFromUDPAddrPort(buf)
	}
	n, addr, err := pc.ReadFrom(buf)
	if err != nil || addr == nil {
		return n, netip.AddrPort{}, err
	}
	if ua, ok := addr.(*net.UDPAddr); ok {
		return n, ua.AddrPort(), nil
	}
	ap, _ := netip.ParseAddrPort(addr.String())
	return n, ap, nil
}

// isTransient reports a receive error after which the socket keeps working (transientErrors).
func isTransient(err error) bool {
	for _, e := range transientErrors {
		if errors.Is(err, e) {
			return true
		}
	}
	return false
}

// Outcomes of a datagram.
type outcome int

const (
	kept        outcome = iota
	rejected            // the sender is not allowed
	tooLarge            // larger than MaxMessage
	overCap             // beyond MaxPerMinute in its minute
	overBytes           // beyond MaxBytesPerMinute in its minute
	pendingFull         // MaxPending messages wait to be drained
)

// accept handles the datagram b that just arrived from the sender from.
func (r *Receiver) accept(b []byte, from netip.AddrPort) {
	now := r.o.Now()
	allowed := r.allowed.Load().has(from.Addr())
	oc, logIt, held := r.admit(len(b), allowed, now)
	if oc != kept {
		if logIt {
			r.logDiscard(oc, from, len(b), held)
		}
		return
	}
	m, panicked := parseSafe(b)
	m.RX = now.UTC().Format(time.RFC3339Nano)
	m.Src = formatSrc(from)
	size := storedSize(&m)
	r.mu.Lock()
	if oc, logIt, held = r.admitBytes(size, now); oc != kept {
		r.mu.Unlock()
		if logIt {
			r.logDiscard(oc, from, len(b), held)
		}
		return
	}
	r.pending = append(r.pending, m)
	if panicked != "" {
		logIt, held = r.gates.panicked.allow(now)
	}
	r.mu.Unlock()
	if panicked != "" && logIt {
		r.log.Error("syslog receiver: parsing a datagram failed; it is kept with its exact bytes only",
			"from", m.Src, "panic", panicked, "suppressed", held)
	}
}

// storedSize is the size of m as the syslog store writes it: its json.Marshal line and a line
// feed.
func storedSize(m *model.SyslogMessage) int {
	b, err := json.Marshal(m)
	if err != nil { // not for a message of strings and numbers
		return 0
	}
	return len(b) + 1
}

// admit decides what becomes of a datagram of n bytes received at now and counts it; a kept
// one counts against the cap of its minute. It also says whether to log a discarded one.
func (r *Receiver) admit(n int, allowed bool, now time.Time) (oc outcome, logIt bool, held int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var g *gate
	switch {
	case !allowed:
		r.rejected++
		oc, g = rejected, &r.gates.rejected
	case n > r.o.MaxMessage:
		r.dropped++
		oc, g = tooLarge, &r.gates.tooLarge
	default:
		if minute := now.Truncate(time.Minute); !minute.Equal(r.minute) {
			r.minute, r.inMinute, r.bytesInMinute = minute, 0, 0
		}
		switch {
		case r.inMinute >= r.o.MaxPerMinute:
			r.dropped++
			oc, g = overCap, &r.gates.overCap
		case len(r.pending) >= r.o.MaxPending:
			r.dropped++
			oc, g = pendingFull, &r.gates.full
		default:
			r.inMinute++
			return kept, false, 0
		}
	}
	logIt, held = g.allow(now)
	return oc, logIt, held
}

// admitBytes decides whether a message that admit kept at now, and that takes size bytes as
// stored, fits the minute admit counted it in (one goroutine receives: the minute is still the
// same), and counts it: one beyond MaxBytesPerMinute is dropped and no longer counts against
// MaxPerMinute. Caller holds mu.
func (r *Receiver) admitBytes(size int, now time.Time) (oc outcome, logIt bool, held int) {
	if size > r.o.MaxBytesPerMinute-r.bytesInMinute {
		r.dropped++
		r.inMinute--
		logIt, held = r.gates.overBytes.allow(now)
		return overBytes, logIt, held
	}
	r.bytesInMinute += size
	return kept, false, 0
}

// formatSrc formats a datagram's sender as "ip:port" ("[ip]:port" for IPv6), an IPv4 address
// without its IPv4-in-IPv6 mapping.
func formatSrc(from netip.AddrPort) string {
	return netip.AddrPortFrom(from.Addr().Unmap(), from.Port()).String()
}

// logDiscard logs a datagram that was not kept (never its content).
func (r *Receiver) logDiscard(oc outcome, from netip.AddrPort, n, held int) {
	switch oc {
	case rejected:
		r.log.Info("syslog receiver: datagram from a sender that is not allowed; counted as rejected, not kept",
			"from", formatSrc(from), "bytes", n, "suppressed", held)
	case tooLarge:
		r.log.Warn("syslog receiver: datagram larger than the limit; counted as dropped, not kept",
			"from", formatSrc(from), "bytes", n, "limit", r.o.MaxMessage, "suppressed", held)
	case overCap:
		r.log.Warn("syslog receiver: more messages in this minute than the limit; counted as dropped, not kept",
			"limit", r.o.MaxPerMinute, "suppressed", held)
	case overBytes:
		r.log.Warn("syslog receiver: the messages of this minute would take more space than the limit; counted as dropped, not kept",
			"from", formatSrc(from), "bytes", n, "limit_bytes", r.o.MaxBytesPerMinute, "suppressed", held)
	case pendingFull:
		r.log.Warn("syslog receiver: too many messages wait to be recorded; counted as dropped, not kept",
			"limit", r.o.MaxPending, "suppressed", held)
	}
}

// parseSafe parses an accepted datagram. Should the parser ever panic, the datagram is kept
// with its exact bytes only, and panicked describes the panic for the log.
func parseSafe(b []byte) (m model.SyslogMessage, panicked string) {
	defer func() {
		if p := recover(); p != nil {
			m, _ = rawMessage(b)
			panicked = fmt.Sprintf("%v\n%s", p, debug.Stack())
		}
	}()
	return parseDatagram(b), ""
}

// Drain returns the messages kept since the previous call, oldest first, and how many
// datagrams were dropped (from allowed senders: too large, beyond the per-minute cap, or with
// MaxPending messages waiting) and rejected (from other senders) since then.
func (r *Receiver) Drain() (msgs []model.SyslogMessage, dropped, rejected int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	msgs, dropped, rejected = r.pending, r.dropped, r.rejected
	r.pending, r.dropped, r.rejected = nil, 0, 0
	return msgs, dropped, rejected
}

// SetAllowed replaces the senders whose datagrams are accepted; it takes effect with the next
// datagram. Addresses are compared without IPv4-in-IPv6 mapping and without zone, so
// 192.168.1.254 also matches ::ffff:192.168.1.254 (how a dual-stack socket reports an IPv4
// sender). Invalid addresses are ignored; with no allowed sender every datagram is rejected.
func (r *Receiver) SetAllowed(addrs []netip.Addr) {
	r.allowed.Store(newAllowList(addrs))
}

// Listening reports the address Run is bound to ("" while it does not listen) and why the last
// Run could not listen (nil while it listens, and before the first Run).
func (r *Receiver) Listening() (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.addr, r.listenErr
}

func (r *Receiver) setListening(addr string, err error) {
	r.mu.Lock()
	r.addr, r.listenErr = addr, err
	r.mu.Unlock()
}

// pass reports whether the gate g lets a log entry through now, and how many it held back.
func (r *Receiver) pass(g *gate) (bool, int) {
	now := r.o.Now()
	r.mu.Lock()
	defer r.mu.Unlock()
	return g.allow(now)
}

// allowList is a set of sender addresses, compared without IPv4-in-IPv6 mapping and zone.
type allowList struct{ set map[netip.Addr]struct{} }

func newAllowList(addrs []netip.Addr) *allowList {
	l := &allowList{set: make(map[netip.Addr]struct{}, len(addrs))}
	for _, a := range addrs {
		if a.IsValid() {
			l.set[senderKey(a)] = struct{}{}
		}
	}
	return l
}

func (l *allowList) has(a netip.Addr) bool {
	if l == nil || !a.IsValid() {
		return false
	}
	_, ok := l.set[senderKey(a)]
	return ok
}

func senderKey(a netip.Addr) netip.Addr { return a.Unmap().WithZone("") }

// gate lets one log entry of a kind through per logEvery and counts the ones it holds back.
type gate struct {
	at   time.Time
	held int
}

// allow reports whether an entry may be logged at now, and how many were held back since the
// previous one. A clock set back opens the gate.
func (g *gate) allow(now time.Time) (bool, int) {
	if !g.at.IsZero() && !now.Before(g.at) && now.Sub(g.at) < logEvery {
		g.held++
		return false, 0
	}
	held := g.held
	g.at, g.held = now, 0
	return true, held
}

// sleep waits for d or until ctx is done; it reports whether the whole time passed.
func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	}
}
