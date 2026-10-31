package lanscan

import (
	"cmp"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"attmonitor/internal/contracts"
	"attmonitor/internal/model"
)

// The bounds of a sweep (see the package documentation).
const (
	// MaxAddresses is the size of the largest network swept: a /22 (1,022 hosts). A home network
	// is a /24 as a rule (254 hosts).
	MaxAddresses = 1024
	// InFlight is how many ARP questions are asked at a time at most.
	InFlight = 32
	// Timeout bounds a sweep: what answered by then is kept, and the scan's Problem says so.
	Timeout = 2 * time.Minute
)

// minBits is MaxAddresses as the length of a network's prefix.
const minBits = 22

// errNoAnswer: nobody answered an ARP question - the normal outcome for an address nobody holds.
var errNoAnswer = errors.New("no answer")

// arpFunc asks dst by ARP, from this PC's address src on the interface the question goes out on,
// and returns the MAC address that answered (errNoAnswer when none did). ctx is the sweep's: an
// implementation that cannot be called back (SendARP) ends by itself within seconds.
type arpFunc func(ctx context.Context, dst, src netip.Addr) (net.HardwareAddr, error)

// netIface is what a sweep needs of one of this PC's network interfaces.
type netIface struct {
	Index    int
	Name     string
	MAC      net.HardwareAddr
	Up       bool
	Loopback bool
	// Addrs are its IPv4 addresses, each with the length of its network's prefix (192.168.1.71/24).
	Addrs []netip.Prefix
}

// Options configures New.
type Options struct {
	// Gateway is the gateway's address on the home network (gateway.host, such as
	// "192.168.1.254"): the network swept is that of this PC's IPv4 interface that holds it.
	Gateway string
	Logger  *slog.Logger
	// Now is the clock of the scans' At, when a sweep began (default time.Now).
	Now func() time.Time
}

// Scanner sweeps the home network by ARP (contracts.LANScanner). It is safe for concurrent use:
// each Scan is a sweep of its own.
type Scanner struct {
	gateway string
	log     *slog.Logger
	now     func() time.Time

	// The platform - the ARP question, whether it can be asked at all, this PC's interfaces - and
	// the bounds (InFlight, Timeout); the tests replace them.
	arp        arpFunc
	ready      func() error
	interfaces func() ([]netIface, error)
	inFlight   int
	timeout    time.Duration
}

var _ contracts.LANScanner = (*Scanner)(nil)

// New returns a scanner of the network that holds o.Gateway. It sends nothing: Scan does.
func New(o Options) *Scanner {
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	return &Scanner{
		gateway:    o.Gateway,
		log:        o.Logger,
		now:        o.Now,
		arp:        systemARP,
		ready:      arpReady,
		interfaces: systemInterfaces,
		inFlight:   InFlight,
		timeout:    Timeout,
	}
}

// Scan sweeps the home network once: it finds this PC's IPv4 interface whose network holds the
// gateway's address, refuses a network that is not private (RFC 1918) or larger than MaxAddresses,
// and asks every other address of it by ARP - at most InFlight at a time, for Timeout at most -
// who has it. The scan lists the addresses that answered, in address order, with the MAC address
// that answered (this PC's own addresses with their interfaces' MAC addresses, never asked). A
// sweep that ran out of time keeps what answered, and its Problem says so; so do questions that
// failed otherwise than without an answer (every question failing is an error). When ctx ends
// during the sweep, Scan returns what answered so far with an error wrapping ctx's.
func (s *Scanner) Scan(ctx context.Context) (model.LANScan, error) {
	if err := ctx.Err(); err != nil {
		return model.LANScan{}, err
	}
	if err := s.ready(); err != nil {
		return model.LANScan{}, err
	}
	gw, err := gatewayAddr(s.gateway)
	if err != nil {
		return model.LANScan{}, err
	}
	ifs, err := s.interfaces()
	if err != nil {
		return model.LANScan{}, fmt.Errorf("lanscan: this PC's network interfaces cannot be listed: %w", err)
	}
	h, err := homeNetwork(ifs, gw)
	if err != nil {
		return model.LANScan{}, err
	}
	return s.sweep(ctx, h)
}

// gatewayAddr parses the gateway's address (gateway.host): an IPv4 address.
func gatewayAddr(s string) (netip.Addr, error) {
	a, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil || !a.Unmap().Is4() {
		return netip.Addr{}, fmt.Errorf("lanscan: the gateway's address (gateway.host) %q is not an IPv4 address", s)
	}
	return a.Unmap(), nil
}

// home is the network a sweep asks.
type home struct {
	prefix netip.Prefix // the network (masked), such as 192.168.1.0/24
	self   netip.Addr   // this PC's address in it on iface, which the questions go out from
	iface  netIface
	// own are this PC's addresses in the network - on any of its interfaces that are up - with
	// their interfaces' MAC addresses (nil for an interface that has none): never asked.
	own map[netip.Addr]net.HardwareAddr
}

// homeNetwork finds the network to sweep among this PC's interfaces: that of an IPv4 address of an
// interface that is up (not the loopback) whose network holds the gateway's address gw - of
// several, the most specific network, then the interface with the lowest index, then the lowest
// address. It refuses an interface without a MAC address (ARP does not apply to it), a network
// that is not private (RFC 1918) and one of more than MaxAddresses addresses.
func homeNetwork(ifs []netIface, gw netip.Addr) (home, error) {
	var best *home
	for _, ifc := range ifs {
		if !ifc.Up || ifc.Loopback {
			continue
		}
		for _, p := range ifc.Addrs {
			if !p.IsValid() || !p.Addr().Is4() || !p.Masked().Contains(gw) {
				continue
			}
			c := home{prefix: p.Masked(), self: p.Addr(), iface: ifc}
			if best == nil || moreSpecific(c, *best) {
				best = &c
			}
		}
	}
	if best == nil {
		return home{}, fmt.Errorf("lanscan: no network interface of this PC that is up is on the gateway's network (%s): this PC is not connected to the home network", gw)
	}
	h := *best
	switch {
	case !usableMAC(h.iface.MAC):
		return home{}, fmt.Errorf("lanscan: this PC's interface %q on the gateway's network has no Ethernet (MAC) address: ARP does not apply to it", h.iface.Name)
	case !h.prefix.Addr().IsPrivate():
		return home{}, fmt.Errorf("lanscan: the gateway's network %s is not a private (RFC 1918) network: only a private home network is swept", h.prefix)
	case h.prefix.Bits() < minBits:
		return home{}, fmt.Errorf("lanscan: the gateway's network %s holds %d addresses: at most %d (a /%d) are swept",
			h.prefix, uint64(1)<<(32-h.prefix.Bits()), MaxAddresses, minBits)
	}
	h.own = map[netip.Addr]net.HardwareAddr{}
	for _, ifc := range ifs {
		if !ifc.Up || ifc.Loopback {
			continue
		}
		for _, p := range ifc.Addrs {
			if a := p.Addr(); p.IsValid() && a.Is4() && h.prefix.Contains(a) {
				var mac net.HardwareAddr
				if usableMAC(ifc.MAC) {
					mac = ifc.MAC
				}
				if _, seen := h.own[a]; !seen || mac != nil {
					h.own[a] = mac
				}
			}
		}
	}
	return h, nil
}

// moreSpecific reports whether a is the better network to sweep than b: the longer prefix, then
// the interface with the lower index, then the lower address.
func moreSpecific(a, b home) bool {
	if c := cmp.Compare(a.prefix.Bits(), b.prefix.Bits()); c != 0 {
		return c > 0
	}
	if a.iface.Index != b.iface.Index {
		return a.iface.Index < b.iface.Index
	}
	return a.self.Less(b.self)
}

// usableMAC reports whether mac is an Ethernet station's address: six bytes, neither all zero nor
// a group (multicast or broadcast) address.
func usableMAC(mac net.HardwareAddr) bool {
	return len(mac) == 6 && mac[0]&1 == 0 && !slices.Equal(mac, net.HardwareAddr{0, 0, 0, 0, 0, 0})
}

// hostsOf returns the host addresses of p (masked, at least a /minBits), ascending: every address
// but the network's own and its broadcast address - both of a /31, the one of a /32.
func hostsOf(p netip.Prefix) []netip.Addr {
	p = p.Masked()
	a4 := p.Addr().As4()
	first := binary.BigEndian.Uint32(a4[:])
	last := first + uint32(1)<<(32-p.Bits()) - 1
	if p.Bits() <= 30 {
		first, last = first+1, last-1
	}
	out := make([]netip.Addr, 0, last-first+1)
	for v := first; ; v++ {
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], v)
		out = append(out, netip.AddrFrom4(b))
		if v == last {
			return out
		}
	}
}

// sweep asks every host address of h that is not this PC's own, at most s.inFlight at a time and
// for s.timeout at most (see Scan).
func (s *Scanner) sweep(ctx context.Context, h home) (model.LANScan, error) {
	began, start := s.now(), time.Now()
	var questions []netip.Addr
	own := 0
	for _, a := range hostsOf(h.prefix) {
		if _, mine := h.own[a]; mine {
			own++
			continue
		}
		questions = append(questions, a)
	}
	sctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	// The questions' outcomes (guarded by mu): asked counts those begun; finished those that ended
	// with an answer, without one, or failing - before the sweep ended (closed): a question called
	// back with the sweep, or still in flight at its end, has not finished.
	type host struct {
		addr netip.Addr
		mac  net.HardwareAddr
	}
	var (
		mu                        sync.Mutex
		closed                    bool
		answers                   []host
		asked, finished, failures int
		firstErr                  error
	)
	jobs := make(chan netip.Addr)
	var wg sync.WaitGroup
	for range max(min(s.inFlight, len(questions)), 1) {
		wg.Go(func() {
			for a := range jobs {
				mu.Lock()
				end := closed || sctx.Err() != nil
				if !end {
					asked++
				}
				mu.Unlock()
				if end {
					continue // the sweep has ended: no more questions
				}
				mac, err := s.arp(sctx, a, h.self)
				mu.Lock()
				switch {
				case closed:
				case err == nil:
					finished++
					if usableMAC(mac) {
						answers = append(answers, host{a, slices.Clone(mac)})
					}
				case errors.Is(err, errNoAnswer):
					finished++
				case sctx.Err() != nil && (errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)):
					// Called back with the sweep: it did not finish.
				default:
					finished++
					failures++
					if firstErr == nil {
						firstErr = err
					}
				}
				mu.Unlock()
			}
		})
	}
feed:
	for _, a := range questions {
		if sctx.Err() != nil {
			break
		}
		select {
		case jobs <- a:
		case <-sctx.Done():
			break feed
		}
	}
	close(jobs)
	// Wait for the questions in flight, but not beyond the sweep's end: a question that cannot be
	// called back (SendARP) may take seconds more, and what it finds then is not kept.
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-sctx.Done():
	}
	mu.Lock()
	closed = true
	found := slices.Clone(answers)
	nAsked, nFinished, nFailed, errFirst := asked, finished, failures, firstErr
	mu.Unlock()
	answered := len(found)
	for a, mac := range h.own {
		if mac != nil {
			found = append(found, host{a, mac})
		}
	}
	slices.SortFunc(found, func(x, y host) int { return x.addr.Compare(y.addr) })
	hosts := make([]model.LANHost, len(found))
	for i, f := range found {
		hosts[i] = model.LANHost{IP: f.addr.String(), MAC: f.mac.String()}
	}
	scan := model.LANScan{
		At:     began.UTC().Format(time.RFC3339Nano),
		TookMs: time.Since(start).Milliseconds(),
		Subnet: h.prefix.String(),
		Self:   h.self.String(),
		Asked:  own + nAsked,
		Hosts:  hosts,
	}
	var problems []string
	complete := nFinished == len(questions)
	switch {
	case complete:
	case ctx.Err() != nil:
		problems = append(problems, fmt.Sprintf("the sweep was stopped before it ended, with %d of %d addresses asked", scan.Asked, own+len(questions)))
	default:
		problems = append(problems, fmt.Sprintf("the sweep was stopped after %s with %d of %d addresses asked: what answered by then is kept",
			s.timeout, scan.Asked, own+len(questions)))
	}
	if nFailed > 0 {
		if answered == 0 && nFailed == nFinished {
			return scan, fmt.Errorf("lanscan: every ARP question failed (%d): %w", nFailed, errFirst)
		}
		problems = append(problems, fmt.Sprintf("%d of %d ARP questions failed (%v)", nFailed, nAsked, errFirst))
	}
	scan.Problem = strings.Join(problems, "; ")
	if err := ctx.Err(); err != nil {
		return scan, fmt.Errorf("lanscan: the sweep was stopped before it ended: %w", err)
	}
	s.log.Debug("home network swept", "subnet", scan.Subnet, "interface", h.iface.Name, "asked", scan.Asked,
		"answered", len(scan.Hosts), "failed", nFailed, "took_ms", scan.TookMs, "complete", complete)
	return scan, nil
}

// systemInterfaces lists this PC's network interfaces with their IPv4 addresses (net.Interfaces:
// on Windows the adapters' unicast addresses with their on-link prefix lengths).
func systemInterfaces() ([]netIface, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	out := make([]netIface, 0, len(ifs))
	for _, i := range ifs {
		ni := netIface{Index: i.Index, Name: i.Name, MAC: i.HardwareAddr, Up: i.Flags&net.FlagUp != 0,
			Loopback: i.Flags&net.FlagLoopback != 0}
		addrs, err := i.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip, ok := netip.AddrFromSlice(ipn.IP)
			if !ok || !ip.Unmap().Is4() {
				continue
			}
			ones, bits := ipn.Mask.Size()
			if bits == 8*net.IPv6len {
				ones -= 8 * (net.IPv6len - net.IPv4len) // an IPv4 address with an IPv6-sized mask
			}
			if bits == 0 || ones < 0 || ones > 32 {
				continue // not a canonical mask
			}
			ni.Addrs = append(ni.Addrs, netip.PrefixFrom(ip.Unmap(), ones))
		}
		out = append(out, ni)
	}
	return out, nil
}
