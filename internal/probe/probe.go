// Package probe performs att-monitor's network measurements on Windows (docs/DESIGN.md §8):
// ICMP echo and traceroute through the Windows ICMP helper API (iphlpapi IcmpSendEcho: no
// administrator rights, no raw sockets, no cgo), TCP connects, DNS A queries with hijack
// detection, HTTP(S) checks that never follow redirects, SNTP clock offsets, and a
// description of the local link (adapter, Wi-Fi details, traffic counters) used to reach the
// gateway.
//
// Every measurement returns a populated result value rather than an error: a failed
// measurement is evidence too. Results follow these conventions:
//
//   - Status (ProbeResult, traceroute Hop) is the Windows IP_STATUS name for ICMP
//     ("IP_SUCCESS", "IP_REQ_TIMED_OUT", ..., see ICMPStatusName) and StatusConnected /
//     StatusRefused / StatusTimeout / StatusUnreachable for TCP. When no network outcome was
//     obtained it is StatusTimeout (no result within the timeout or the caller's deadline),
//     StatusUnreachable (this PC has no route: the same condition for ICMP and TCP),
//     StatusCanceled (the caller canceled, or its context had already ended so nothing was
//     sent) or StatusError (local failure such as a bad target; the text is in Err).
//     DNS and SNTP results have no status field: their Err starts with "timeout: " or
//     "canceled: " in those cases.
//   - A traceroute's hops are only the TTLs actually probed. A target that cannot be
//     resolved or used, and a local failure of the ICMP API, are recorded in Traceroute.Err
//     (starting with "canceled: " when the caller's context ended), never as a hop; a hop
//     that found no route from this PC has the status "unreachable: <system error>".
//   - A DNS response with the TC bit set is reported in DNSResult.Truncated (Err is left for
//     real errors), and an HTTPS check records the SHA-256 of the certificate the server
//     presented (HTTPResult.TLSCertSHA256) whether or not it verified.
//   - RTT values are measured around the network operation on a high-resolution monotonic
//     clock (QueryPerformanceCounter on Windows, see clock.go: Go's own monotonic clock
//     there only advances at the 0.5-15.6 ms timer tick). They are set only when the
//     network actually answered (an ICMP reply with a sender, an established TCP
//     connection, a DNS response, HTTP response headers, an SNTP reply), never for
//     timeouts or local errors, so they can be aggregated without mistaking a timeout for
//     a slow answer.
//   - OK follows the documented success criterion of each probe (for ICMP: IP_SUCCESS from
//     the target itself).
//   - Name/Role (and DNSResult.ServerRole, Traceroute.Trigger/Incident) are left for the
//     caller, as specified by contracts.Prober.
//
// A Prober is safe for concurrent use.
package probe

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"attmonitor/internal/contracts"
)

// Status values used in addition to the Windows IP_STATUS names (see the package comment).
const (
	StatusConnected   = "connected"   // TCP handshake completed
	StatusRefused     = "refused"     // TCP connection actively refused (RST): the host is up
	StatusTimeout     = "timeout"     // no answer within the timeout
	StatusUnreachable = "unreachable" // the local stack or a router reported no route
	StatusCanceled    = "canceled"    // the caller's context ended before an outcome
	StatusError       = "error"       // local failure; details in Err
)

// DefaultGatewayIP is the BGW320's factory LAN address, used for hijack detection when
// Options.GatewayIP is empty.
const DefaultGatewayIP = "192.168.1.254"

const (
	defaultTimeout   = 2 * time.Second // DESIGN §8 fast-cycle probe timeout
	defaultPerHop    = time.Second
	defaultMaxHops   = 30
	maxTTL           = 255
	defaultUserAgent = "att-monitor"
)

// Options configures a Prober.
type Options struct {
	Logger    *slog.Logger // nil → discard
	UserAgent string       // HTTP User-Agent; "" → "att-monitor"
	// GatewayIP is the AT&T gateway's LAN address. DNS answers, HTTP peers and redirects
	// that point at it are reported as hijacks naming "the gateway's own address" (private
	// addresses are flagged regardless). "" → DefaultGatewayIP. Additive to docs/PACKAGES.md.
	GatewayIP string
}

// Prober implements contracts.Prober.
type Prober struct {
	log       *slog.Logger
	userAgent string
	gatewayIP string

	// transport is the template every HTTP check copies its transport from (see
	// checkTransport); keep-alives disabled. Checks never modify it.
	transport *http.Transport

	// Seams for tests. New installs the real implementations; tests replace them before
	// the first call and never while calls are in flight.
	//
	// rootCAs replaces the system roots for HTTPS verification. Only tests set it (to trust
	// their own test servers); in production it is nil, i.e. the Windows root store.
	rootCAs  *x509.CertPool
	dial     func(ctx context.Context, network, address string) (net.Conn, error)
	lookupIP func(ctx context.Context, host string) ([]netip.Addr, error)
	echo     func(dst netip.Addr, ttl uint8, timeout time.Duration) echoResult
	adapters func() ([]adapterInfo, error)
	bestIf   func(dst netip.Addr) (uint32, error)
	runNetsh func(ctx context.Context) ([]byte, error)
	// ifCounters reads an interface's octet counters (received, sent) by NET_LUID, or by
	// interface index when the LUID is 0.
	ifCounters func(luid uint64, index uint32) (rx, tx uint64, err error)

	icmpInFlight atomic.Int64 // IcmpSendEcho calls not yet returned (see maxICMPInFlight)

	mu sync.Mutex
	// lastAdapter is the AdapterName (GUID) of the adapter last seen on the gateway's
	// subnet; it lets LocalLink report that adapter as disconnected after it lost its
	// address (the classifier's LOCAL_LINK_DOWN rule depends on that).
	lastAdapter string
}

var _ contracts.Prober = (*Prober)(nil)

// New returns a Prober.
func New(opts Options) *Prober {
	p := &Prober{
		log:        opts.Logger,
		userAgent:  strings.TrimSpace(opts.UserAgent),
		gatewayIP:  strings.TrimSpace(opts.GatewayIP),
		echo:       sendEcho,
		adapters:   listAdapters,
		bestIf:     bestInterface,
		runNetsh:   runNetshWLAN,
		ifCounters: interfaceCounters,
	}
	if p.log == nil {
		p.log = slog.New(slog.DiscardHandler)
	}
	if p.userAgent == "" {
		p.userAgent = defaultUserAgent
	}
	if p.gatewayIP == "" {
		p.gatewayIP = DefaultGatewayIP
	}
	// markConnectStart lets TCP time the connect itself, excluding name resolution and
	// earlier failed attempts (see TCP); it does nothing for other dials.
	d := net.Dialer{ControlContext: markConnectStart}
	p.dial = d.DialContext
	p.lookupIP = func(ctx context.Context, host string) ([]netip.Addr, error) {
		return net.DefaultResolver.LookupNetIP(ctx, "ip4", host)
	}
	p.transport = newHTTPTransport(func(ctx context.Context, network, address string) (net.Conn, error) {
		return p.dial(ctx, network, address) // indirect so tests can swap p.dial after New
	})
	return p
}

// effectiveTimeout returns timeout (default when ≤ 0) clipped to the context deadline.
// A result ≤ 0 means the deadline has already passed.
func effectiveTimeout(ctx context.Context, timeout time.Duration) time.Duration {
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	if dl, ok := ctx.Deadline(); ok {
		if rem := time.Until(dl); rem < timeout {
			timeout = rem
		}
	}
	return timeout
}

// errDeadline is reported when the caller's deadline left no time to run a probe.
var errDeadline = errors.New("context deadline leaves no time for the probe")

// ctxErr explains why a probe could not run or finish because of its context: the
// context's own error, or errDeadline when the deadline passed but Err is not yet set.
func ctxErr(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return errDeadline
}

// hostPort splits "host", "host:port", "[v6]:port", "[v6]" or a bare IPv6 literal into
// host and port, using defPort when no port is given.
func hostPort(s, defPort string) (host, port string, err error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", "", errors.New("empty address")
	}
	if _, err := netip.ParseAddr(s); err == nil { // bare IPv4 or IPv6 literal
		return s, defPort, nil
	}
	if h, p, err := net.SplitHostPort(s); err == nil {
		if h == "" {
			return "", "", errors.New("address " + s + " has no host")
		}
		if p == "" {
			p = defPort
		}
		return h, p, nil
	}
	if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") {
		if _, err := netip.ParseAddr(s[1 : len(s)-1]); err == nil {
			return s[1 : len(s)-1], defPort, nil
		}
	}
	if strings.ContainsAny(s, ":[]/ ") {
		return "", "", errors.New("invalid address " + s)
	}
	return s, defPort, nil
}

// resolveIPv4 returns target as an IPv4 address, resolving host names (IPv4 only, because
// the Windows ICMP API used here is IPv4-only) within limit, so that a hung resolver cannot
// hold a probe beyond its time budget.
func (p *Prober) resolveIPv4(ctx context.Context, target string, limit time.Duration) (netip.Addr, error) {
	host := strings.TrimSpace(target)
	if host == "" {
		return netip.Addr{}, errors.New("empty target")
	}
	if a, err := netip.ParseAddr(host); err == nil {
		a = a.Unmap()
		if !a.Is4() {
			return netip.Addr{}, errors.New(target + ": only IPv4 targets are supported")
		}
		return a, nil
	}
	lctx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	addrs, err := p.lookupIP(lctx, host)
	if err != nil {
		if !strings.Contains(err.Error(), host) {
			err = fmt.Errorf("resolving %s: %w", host, err)
		}
		return netip.Addr{}, err
	}
	for _, a := range addrs {
		if a = a.Unmap(); a.Is4() {
			return a, nil
		}
	}
	return netip.Addr{}, errors.New(target + ": no IPv4 address")
}
