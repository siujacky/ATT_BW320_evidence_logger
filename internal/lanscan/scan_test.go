package lanscan

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"attmonitor/internal/contracts"
	"attmonitor/internal/model"
)

// The tests use documentation values only: the home network 192.168.1.0/24 (this PC 192.168.1.71,
// the gateway 192.168.1.254), other networks of RFC 1918 and RFC 5737, MAC addresses
// 00:00:5e:00:53:xx (RFC 7042).

// mac returns the MAC address 00:00:5e:00:53:<n>.
func mac(n int) net.HardwareAddr { return net.HardwareAddr{0x00, 0x00, 0x5e, 0x00, 0x53, byte(n)} }

// lan returns the address 192.168.1.n.
func lan(n int) netip.Addr { return netip.AddrFrom4([4]byte{192, 168, 1, byte(n)}) }

// pfx parses an address with its network's prefix length ("192.168.1.71/24").
func pfx(s string) netip.Prefix { return netip.MustParsePrefix(s) }

// wifi is this PC's Wi-Fi adapter on the home network: 192.168.1.71/24, MAC 00:00:5e:00:53:71.
func wifi() netIface {
	return netIface{Index: 12, Name: "Wi-Fi", MAC: mac(0x71), Up: true, Addrs: []netip.Prefix{pfx("192.168.1.71/24")}}
}

// fakeLAN is a home network as a sweep sees it: this PC's interfaces, the devices that answer
// (answers), the questions that fail (fail), how long a question takes (delay; 0: no time) and
// whether questions wait for their context (wait: they end with it; otherwise until release is
// closed, ignoring it, as SendARP does). It records every question.
type fakeLAN struct {
	ifs     []netIface
	answers map[netip.Addr]net.HardwareAddr
	fail    map[netip.Addr]error
	delay   func(netip.Addr) time.Duration
	wait    func(netip.Addr) bool
	release chan struct{}

	mu       sync.Mutex
	asked    []netip.Addr
	sources  map[netip.Addr]int
	inFlight int
	most     int
}

func newFakeLAN(ifs ...netIface) *fakeLAN {
	return &fakeLAN{ifs: ifs, answers: map[netip.Addr]net.HardwareAddr{}, fail: map[netip.Addr]error{}, sources: map[netip.Addr]int{},
		release: make(chan struct{})}
}

func (f *fakeLAN) arp(ctx context.Context, dst, src netip.Addr) (net.HardwareAddr, error) {
	f.mu.Lock()
	f.asked = append(f.asked, dst)
	f.sources[src]++
	f.inFlight++
	f.most = max(f.most, f.inFlight)
	f.mu.Unlock()
	defer func() {
		f.mu.Lock()
		f.inFlight--
		f.mu.Unlock()
	}()
	if f.delay != nil {
		time.Sleep(f.delay(dst))
	}
	if f.wait != nil && f.wait(dst) {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-f.release:
		}
	}
	if err := f.fail[dst]; err != nil {
		return nil, err
	}
	if m, ok := f.answers[dst]; ok {
		return m, nil
	}
	return nil, errNoAnswer
}

// questions returns the addresses asked, in address order, and the most asked at a time.
func (f *fakeLAN) questions() ([]netip.Addr, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	q := slices.Clone(f.asked)
	slices.SortFunc(q, netip.Addr.Compare)
	return q, f.most
}

// testNow is the scans' clock.
var testNow = time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)

// scanner returns a scanner of the network holding gateway on f.
func (f *fakeLAN) scanner(gateway string) *Scanner {
	s := New(Options{Gateway: gateway, Now: func() time.Time { return testNow }})
	s.arp = f.arp
	s.ready = func() error { return nil }
	s.interfaces = func() ([]netIface, error) { return slices.Clone(f.ifs), nil }
	return s
}

// hostList writes a scan's hosts as "ip mac" lines.
func hostList(hosts []model.LANHost) []string {
	var out []string
	for _, h := range hosts {
		out = append(out, h.IP+" "+h.MAC)
	}
	return out
}

// TestScanSweepsTheGatewaysNetwork: the network swept is that of this PC's interface that holds the
// gateway's address - not the loopback, an interface that is down, a VPN adapter or another
// network. Every other host address is asked once, from this PC's address there - never the
// network's own address, its broadcast address or this PC's own address, which is listed with its
// interface's MAC address. The hosts come in address order (not in the order they answered), with
// lower-case MAC addresses.
func TestScanSweepsTheGatewaysNetwork(t *testing.T) {
	f := newFakeLAN(
		netIface{Index: 1, Name: "Loopback", Up: true, Loopback: true, Addrs: []netip.Prefix{pfx("127.0.0.1/8")}},
		netIface{Index: 5, Name: "Ethernet", MAC: mac(0x80), Up: false, Addrs: []netip.Prefix{pfx("192.168.1.80/24")}},
		netIface{Index: 7, Name: "VPN", Up: true, Addrs: []netip.Prefix{pfx("10.5.0.2/16")}},
		netIface{Index: 9, Name: "Lab", MAC: mac(0x90), Up: true, Addrs: []netip.Prefix{pfx("172.16.5.10/24")}},
		wifi(),
	)
	f.answers[lan(254)] = mac(0xfe)
	f.answers[lan(64)] = net.HardwareAddr{0x00, 0x00, 0x5E, 0x00, 0x53, 0xAB}
	f.answers[lan(9)] = mac(0x09)
	f.answers[lan(100)] = mac(0x10)
	f.delay = func(a netip.Addr) time.Duration { return time.Duration(255-int(a.As4()[3])%7) * 10 * time.Microsecond }
	sc, err := f.scanner("192.168.1.254").Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"192.168.1.9 00:00:5e:00:53:09", "192.168.1.64 00:00:5e:00:53:ab", "192.168.1.71 00:00:5e:00:53:71",
		"192.168.1.100 00:00:5e:00:53:10", "192.168.1.254 00:00:5e:00:53:fe",
	}
	if got := hostList(sc.Hosts); !slices.Equal(got, want) {
		t.Errorf("hosts %q\nwant %q", got, want)
	}
	if sc.At != "2026-10-30T12:00:00Z" || sc.Subnet != "192.168.1.0/24" || sc.Self != "192.168.1.71" || sc.Asked != 254 ||
		sc.Problem != "" || sc.TookMs < 0 || sc.TookMs > 10_000 {
		t.Errorf("scan %+v", sc)
	}
	asked, _ := f.questions()
	var want253 []netip.Addr
	for n := 1; n <= 254; n++ {
		if n != 71 {
			want253 = append(want253, lan(n))
		}
	}
	if !slices.Equal(asked, want253) {
		t.Errorf("asked %d addresses (%v ... %v), want 192.168.1.1-254 but this PC's .71, each once", len(asked), asked[0], asked[len(asked)-1])
	}
	if len(f.sources) != 1 || f.sources[lan(71)] != 253 {
		t.Errorf("the questions came from %v, want 192.168.1.71 only", f.sources)
	}
}

// TestScanBoundsTheQuestionsInFlight: at most InFlight questions at a time - the sweep asks no 33rd
// while 32 wait - and every address is asked once all the same.
func TestScanBoundsTheQuestionsInFlight(t *testing.T) {
	f := newFakeLAN(wifi())
	f.wait = func(netip.Addr) bool { return true }
	s := f.scanner("192.168.1.254")
	type result struct {
		sc  model.LANScan
		err error
	}
	res := make(chan result, 1)
	go func() {
		sc, err := s.Scan(context.Background())
		res <- result{sc, err}
	}()
	deadline := time.Now().Add(10 * time.Second)
	for {
		f.mu.Lock()
		n := f.inFlight
		f.mu.Unlock()
		if n == InFlight {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d questions in flight, want %d", n, InFlight)
		}
		time.Sleep(time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond) // a 33rd would have begun by now
	if _, most := f.questions(); most != InFlight {
		t.Fatalf("%d questions in flight at most, want %d", most, InFlight)
	}
	close(f.release)
	r := <-res
	if r.err != nil || r.sc.Asked != 254 || r.sc.Problem != "" {
		t.Fatalf("scan %+v, %v", r.sc, r.err)
	}
	if asked, most := f.questions(); len(asked) != 253 || most != InFlight {
		t.Errorf("%d questions, %d at a time at most", len(asked), most)
	}
}

// TestScanStopsAtItsTimeout: a sweep that runs out of time returns at once - not after the
// questions in flight, which may not be called back (SendARP) - with what answered by then, and its
// Problem says so; an answer that comes later is not kept.
func TestScanStopsAtItsTimeout(t *testing.T) {
	for _, callBack := range []bool{true, false} {
		t.Run(fmt.Sprintf("questions called back %v", callBack), func(t *testing.T) {
			f := newFakeLAN(wifi())
			f.answers[lan(2)], f.answers[lan(3)], f.answers[lan(200)] = mac(2), mac(3), mac(200)
			f.wait = func(a netip.Addr) bool { return a.As4()[3] > 40 } // .1 to .40 at once, the others wait
			s := f.scanner("192.168.1.254")
			s.timeout = 100 * time.Millisecond
			if !callBack {
				s.arp = func(_ context.Context, dst, src netip.Addr) (net.HardwareAddr, error) {
					return f.arp(context.Background(), dst, src) // the sweep's end does not call it back, as with SendARP
				}
			}
			t.Cleanup(func() { close(f.release) })
			began := time.Now()
			sc, err := s.Scan(context.Background())
			if took := time.Since(began); took > 5*time.Second {
				t.Fatalf("the sweep took %v", took)
			}
			if err != nil {
				t.Fatal(err)
			}
			if got := hostList(sc.Hosts); !slices.Equal(got, []string{"192.168.1.2 00:00:5e:00:53:02", "192.168.1.3 00:00:5e:00:53:03", "192.168.1.71 00:00:5e:00:53:71"}) {
				t.Errorf("hosts %q", got)
			}
			if sc.Asked <= 40 || sc.Asked >= 254 || !strings.HasPrefix(sc.Problem, "the sweep was stopped after 100ms with ") ||
				!strings.HasSuffix(sc.Problem, " of 254 addresses asked: what answered by then is kept") {
				t.Errorf("scan %+v", sc)
			}
		})
	}
}

// TestScanEndsWithItsContext: a context that has ended asks nothing; one that ends during the sweep
// ends it at once with what answered so far and the context's error.
func TestScanEndsWithItsContext(t *testing.T) {
	f := newFakeLAN(wifi())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := f.scanner("192.168.1.254").Scan(ctx); !errors.Is(err, context.Canceled) {
		t.Errorf("an ended context: %v", err)
	}
	if asked, _ := f.questions(); len(asked) != 0 {
		t.Errorf("%d questions with an ended context", len(asked))
	}

	f = newFakeLAN(wifi())
	f.answers[lan(1)] = mac(1)
	f.wait = func(a netip.Addr) bool { return a != lan(1) }
	ctx, cancel = context.WithCancel(context.Background())
	go func() {
		for {
			if asked, _ := f.questions(); len(asked) >= InFlight {
				cancel()
				return
			}
			time.Sleep(time.Millisecond)
		}
	}()
	t.Cleanup(func() { close(f.release) })
	sc, err := f.scanner("192.168.1.254").Scan(ctx)
	if !errors.Is(err, context.Canceled) || !strings.Contains(err.Error(), "the sweep was stopped before it ended") {
		t.Fatalf("a context that ends during the sweep: %v", err)
	}
	if got := hostList(sc.Hosts); !slices.Equal(got, []string{"192.168.1.1 00:00:5e:00:53:01", "192.168.1.71 00:00:5e:00:53:71"}) {
		t.Errorf("what answered: %q", got)
	}
	if !strings.HasPrefix(sc.Problem, "the sweep was stopped before it ended, with ") || !strings.HasSuffix(sc.Problem, " of 254 addresses asked") {
		t.Errorf("problem %q", sc.Problem)
	}
}

// TestScanRefusals: no sweep of a network that is not private or holds more than MaxAddresses
// addresses, without an interface on the gateway's network or a MAC address on it, with a gateway
// address that is not IPv4, or where ARP questions cannot be asked - each said in plain words,
// before any question.
func TestScanRefusals(t *testing.T) {
	for _, c := range []struct {
		name, gateway string
		ifs           []netIface
		ready         error
		want          string
	}{
		{"a public network", "203.0.113.1", []netIface{{Index: 3, Name: "Ethernet", MAC: mac(1), Up: true, Addrs: []netip.Prefix{pfx("203.0.113.10/24")}}},
			nil, "the gateway's network 203.0.113.0/24 is not a private (RFC 1918) network"},
		{"shared address space", "100.64.0.1", []netIface{{Index: 3, Name: "Ethernet", MAC: mac(1), Up: true, Addrs: []netip.Prefix{pfx("100.64.0.10/24")}}},
			nil, "is not a private (RFC 1918) network"},
		{"a /16", "10.0.0.1", []netIface{{Index: 3, Name: "Ethernet", MAC: mac(1), Up: true, Addrs: []netip.Prefix{pfx("10.0.5.10/16")}}},
			nil, "the gateway's network 10.0.0.0/16 holds 65536 addresses: at most 1024 (a /22) are swept"},
		{"a /21", "192.168.0.1", []netIface{{Index: 3, Name: "Ethernet", MAC: mac(1), Up: true, Addrs: []netip.Prefix{pfx("192.168.3.10/21")}}},
			nil, "holds 2048 addresses"},
		{"not on the gateway's network", "192.168.1.254", []netIface{{Index: 3, Name: "Ethernet", MAC: mac(1), Up: true, Addrs: []netip.Prefix{pfx("192.168.2.10/24")}}},
			nil, "no network interface of this PC that is up is on the gateway's network (192.168.1.254)"},
		{"its interface down", "192.168.1.254", []netIface{{Index: 3, Name: "Ethernet", MAC: mac(1), Addrs: []netip.Prefix{pfx("192.168.1.10/24")}}},
			nil, "no network interface of this PC that is up"},
		{"no MAC address", "192.168.1.254", []netIface{{Index: 3, Name: "Tunnel", Up: true, Addrs: []netip.Prefix{pfx("192.168.1.10/24")}}},
			nil, `this PC's interface "Tunnel" on the gateway's network has no Ethernet (MAC) address`},
		{"no gateway address", "", []netIface{wifi()}, nil, `the gateway's address (gateway.host) "" is not an IPv4 address`},
		{"a host name", "gateway.local", []netIface{wifi()}, nil, "is not an IPv4 address"},
		{"an IPv6 gateway", "fd00::1", []netIface{wifi()}, nil, "is not an IPv4 address"},
		{"no SendARP", "192.168.1.254", []netIface{wifi()}, fmt.Errorf("lanscan: %w: SendARP", contracts.ErrUnavailable), "unavailable"},
	} {
		f := newFakeLAN(c.ifs...)
		s := f.scanner(c.gateway)
		if c.ready != nil {
			s.ready = func() error { return c.ready }
		}
		_, err := s.Scan(context.Background())
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", c.name, err, c.want)
		}
		if c.ready != nil && !errors.Is(err, contracts.ErrUnavailable) {
			t.Errorf("%s: %v does not wrap ErrUnavailable", c.name, err)
		}
		if asked, _ := f.questions(); len(asked) != 0 {
			t.Errorf("%s: %d questions asked", c.name, len(asked))
		}
	}
	// A /22 is swept: 1,022 hosts.
	f := newFakeLAN(netIface{Index: 3, Name: "Ethernet", MAC: mac(1), Up: true, Addrs: []netip.Prefix{pfx("10.1.4.20/22")}})
	sc, err := f.scanner("10.1.7.254").Scan(context.Background())
	if err != nil || sc.Subnet != "10.1.4.0/22" || sc.Asked != 1022 {
		t.Fatalf("a /22: %+v, %v", sc, err)
	}
	if asked, _ := f.questions(); len(asked) != 1021 || asked[0] != netip.MustParseAddr("10.1.4.1") || asked[1020] != netip.MustParseAddr("10.1.7.254") {
		t.Errorf("a /22: %d questions from %v", len(asked), asked[0])
	}
}

// TestScanChoosesTheNetwork: of several of this PC's networks that hold the gateway's address, the
// most specific; of two interfaces on the same network, the one with the lower index sends the
// questions - and both of this PC's addresses are listed with their own MAC addresses, never asked.
func TestScanChoosesTheNetwork(t *testing.T) {
	f := newFakeLAN(
		netIface{Index: 4, Name: "Wide", MAC: mac(0x44), Up: true, Addrs: []netip.Prefix{pfx("192.168.0.10/16")}},
		wifi(),
		netIface{Index: 6, Name: "Ethernet", MAC: mac(0x66), Up: true, Addrs: []netip.Prefix{pfx("192.168.1.66/24"), pfx("192.0.2.5/24")}},
	)
	sc, err := f.scanner("192.168.1.254").Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if sc.Subnet != "192.168.1.0/24" || sc.Self != "192.168.1.66" || sc.Asked != 254 {
		t.Errorf("scan %+v", sc)
	}
	if got := hostList(sc.Hosts); !slices.Equal(got, []string{"192.168.1.66 00:00:5e:00:53:66", "192.168.1.71 00:00:5e:00:53:71"}) {
		t.Errorf("hosts %q", got)
	}
	asked, _ := f.questions()
	if len(asked) != 252 || slices.Contains(asked, lan(66)) || slices.Contains(asked, lan(71)) || f.sources[lan(66)] != 252 {
		t.Errorf("%d questions, from %v", len(asked), f.sources)
	}
}

// TestScanQuestionsThatFail: an answer that is not a station's MAC address is no answer; questions
// that fail otherwise are counted in the Problem - and when every question fails, the sweep fails.
func TestScanQuestionsThatFail(t *testing.T) {
	f := newFakeLAN(wifi())
	f.answers[lan(1)] = mac(1)
	f.answers[lan(2)] = net.HardwareAddr{0, 0, 0, 0, 0, 0}
	f.answers[lan(3)] = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	f.answers[lan(4)] = net.HardwareAddr{0x01, 0x00, 0x5e, 0x00, 0x00, 0x01}
	f.answers[lan(5)] = net.HardwareAddr{0x00, 0x00, 0x5e, 0x00}
	f.fail[lan(6)] = errors.New("SendARP: The parameter is incorrect.")
	f.fail[lan(7)] = errors.New("SendARP: Element not found.")
	sc, err := f.scanner("192.168.1.254").Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got := hostList(sc.Hosts); !slices.Equal(got, []string{"192.168.1.1 00:00:5e:00:53:01", "192.168.1.71 00:00:5e:00:53:71"}) {
		t.Errorf("hosts %q", got)
	}
	if !strings.HasPrefix(sc.Problem, "2 of 253 ARP questions failed (SendARP: ") || sc.Asked != 254 {
		t.Errorf("scan %+v", sc)
	}

	f = newFakeLAN(wifi())
	for n := 1; n <= 254; n++ {
		f.fail[lan(n)] = syscall.Errno(50)
	}
	if _, err := f.scanner("192.168.1.254").Scan(context.Background()); err == nil || !strings.Contains(err.Error(), "every ARP question failed (253)") ||
		!errors.Is(err, syscall.Errno(50)) {
		t.Errorf("every question failing: %v", err)
	}
}

func TestHostsOf(t *testing.T) {
	for _, c := range []struct {
		prefix      string
		n           int
		first, last string
	}{
		{"192.168.1.0/24", 254, "192.168.1.1", "192.168.1.254"},
		{"192.168.1.77/24", 254, "192.168.1.1", "192.168.1.254"},
		{"10.1.4.0/22", 1022, "10.1.4.1", "10.1.7.254"},
		{"172.16.0.8/30", 2, "172.16.0.9", "172.16.0.10"},
		{"172.16.0.8/31", 2, "172.16.0.8", "172.16.0.9"},
		{"172.16.0.8/32", 1, "172.16.0.8", "172.16.0.8"},
	} {
		got := hostsOf(pfx(c.prefix))
		if len(got) != c.n || got[0].String() != c.first || got[len(got)-1].String() != c.last {
			t.Errorf("hostsOf(%s): %d from %v to %v", c.prefix, len(got), got[0], got[len(got)-1])
		}
		if !slices.IsSortedFunc(got, netip.Addr.Compare) {
			t.Errorf("hostsOf(%s) is not in address order", c.prefix)
		}
	}
}

// TestSystemInterfaces: this PC's interfaces are listed with their IPv4 addresses and prefix lengths
// (the content is this PC's: only the form is checked).
func TestSystemInterfaces(t *testing.T) {
	ifs, err := systemInterfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, i := range ifs {
		for _, p := range i.Addrs {
			if !p.IsValid() || !p.Addr().Is4() || p.Bits() < 0 || p.Bits() > 32 {
				t.Errorf("interface %d: address of the wrong form", i.Index)
			}
		}
	}
}
