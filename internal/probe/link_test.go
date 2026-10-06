package probe

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"

	"attmonitor/internal/model"
)

var gw254 = netip.MustParseAddr("192.168.1.254")

func pfx(s string) netip.Prefix { return netip.MustParsePrefix(s) }
func ip(s string) netip.Addr    { return netip.MustParseAddr(s) }

// Adapters modelled on the target PC (GUIDs and addresses partly made up).
var (
	adWiFi = adapterInfo{Name: "{WIFI-GUID}", Friendly: "Wi-Fi", Description: "Intel(R) Wi-Fi 6 AX201 160MHz",
		IfIndex: 15, IfType: ifTypeIEEE80211, OperStatus: operUp, TxSpeed: 576_000_000,
		IPv4: []netip.Prefix{pfx("192.168.1.71/24")}, Gateways: []netip.Addr{gw254}}
	adWiFiDown = adapterInfo{Name: "{WIFI-GUID}", Friendly: "Wi-Fi", IfIndex: 15, IfType: ifTypeIEEE80211,
		OperStatus: operDown}
	adEthUSB = adapterInfo{Name: "{ETH-GUID}", Friendly: "Ethernet 5", IfIndex: 13, IfType: ifTypeEthernet,
		OperStatus: operDown, IPv4: []netip.Prefix{pfx("169.254.91.98/16")}}
	adEthOnLAN = adapterInfo{Name: "{ETH2-GUID}", Friendly: "Ethernet", IfIndex: 7, IfType: ifTypeEthernet,
		OperStatus: operUp, TxSpeed: 1_000_000_000, IPv4: []netip.Prefix{pfx("192.168.1.80/24")},
		Gateways: []netip.Addr{gw254}}
	adHyperV = adapterInfo{Name: "{HYPERV-GUID}", Friendly: "vEthernet (Default Switch)", IfIndex: 32,
		IfType: ifTypeEthernet, OperStatus: operUp, TxSpeed: 10_000_000_000, IPv4: []netip.Prefix{pfx("172.29.32.1/20")}}
	adLoop = adapterInfo{Name: "{LOOP}", Friendly: "Loopback Pseudo-Interface 1", IfIndex: 1, IfType: ifTypeLoopback,
		OperStatus: operUp, IPv4: []netip.Prefix{pfx("127.0.0.1/8")}}
	adGatewayOnly = adapterInfo{Name: "{PPP}", Friendly: "Odd", IfIndex: 40, IfType: 23, OperStatus: operUp,
		IPv4: []netip.Prefix{pfx("10.9.9.9/32")}, Gateways: []netip.Addr{gw254}}
)

func TestSelectAdapter(t *testing.T) {
	tests := []struct {
		name     string
		list     []adapterInfo
		best     uint32
		last     string
		wantName string
		wantHow  string
		wantOK   bool
	}{
		{"wifi on the gateway subnet", []adapterInfo{adLoop, adHyperV, adEthUSB, adWiFi}, 15, "", "Wi-Fi", selOnLink, true},
		{"on-link wins over a wrong route", []adapterInfo{adHyperV, adWiFi}, 32, "", "Wi-Fi", selOnLink, true},
		{"two on-link: best route decides", []adapterInfo{adWiFi, adEthOnLAN}, 7, "", "Ethernet", selOnLink, true},
		{"two on-link: no route, first up", []adapterInfo{func() adapterInfo { a := adWiFi; a.OperStatus = operDown; return a }(), adEthOnLAN}, 0, "", "Ethernet", selOnLink, true},
		{"gateway list only", []adapterInfo{adHyperV, adGatewayOnly}, 0, "", "Odd", selGateway, true},
		{"previous adapter after it lost its address", []adapterInfo{adLoop, adHyperV, adWiFiDown}, 0, "{WIFI-GUID}", "Wi-Fi", selPrevious, true},
		{"previous beats route", []adapterInfo{adHyperV, adWiFiDown}, 32, "{WIFI-GUID}", "Wi-Fi", selPrevious, true},
		{"route as last resort", []adapterInfo{adLoop, adHyperV}, 32, "", "vEthernet (Default Switch)", selRoute, true},
		{"nothing", []adapterInfo{adLoop, adHyperV, adWiFiDown}, 0, "", "", "", false},
		{"previous adapter gone", []adapterInfo{adHyperV}, 0, "{WIFI-GUID}", "", "", false},
		{"empty list", nil, 15, "x", "", "", false},
		{"zero-length prefix is ignored", []adapterInfo{{Name: "z", IPv4: []netip.Prefix{pfx("0.0.0.0/0")}}}, 0, "", "", "", false},
	}
	for _, tt := range tests {
		a, how, ok := selectAdapter(tt.list, gw254, tt.best, tt.last)
		if ok != tt.wantOK || a.Friendly != tt.wantName || how != tt.wantHow {
			t.Errorf("%s: got %q/%q/%v, want %q/%q/%v", tt.name, a.Friendly, how, ok, tt.wantName, tt.wantHow, tt.wantOK)
		}
	}
}

func TestLinkTypeAndState(t *testing.T) {
	for typ, want := range map[uint32]string{71: "wifi", 6: "ethernet", 24: "unknown", 131: "unknown", 0: "unknown"} {
		if got := linkType(typ); got != want {
			t.Errorf("linkType(%d) = %q, want %q", typ, got, want)
		}
	}
	for st, want := range map[uint32]string{1: "connected", 2: "disconnected", 3: "testing", 4: "unknown",
		5: "dormant", 6: "not_present", 7: "disconnected", 99: "oper_status_99"} {
		if got := operState(st); got != want {
			t.Errorf("operState(%d) = %q, want %q", st, got, want)
		}
	}
}

func TestLinkFromAdapter(t *testing.T) {
	got := linkFromAdapter(adWiFi, gw254)
	want := model.LocalLink{Interface: "Wi-Fi", Type: "wifi", State: "connected", LocalIP: "192.168.1.71",
		GatewayIP: "192.168.1.254", LinkMbps: 576}
	if got != want {
		t.Errorf("wifi: got %+v want %+v", got, want)
	}

	multi := adapterInfo{Friendly: "Ethernet", IfType: ifTypeEthernet, OperStatus: operUp, TxSpeed: 999_500_000,
		IPv4:     []netip.Prefix{pfx("169.254.3.3/16"), pfx("10.0.0.5/8"), pfx("192.168.1.80/24")},
		Gateways: []netip.Addr{ip("192.168.1.1")}}
	got = linkFromAdapter(multi, gw254)
	if got.LocalIP != "192.168.1.80" || got.GatewayIP != "192.168.1.1" || got.LinkMbps != 1000 {
		t.Errorf("prefers on-link address, own gateway, rounded speed: %+v", got)
	}
	got = linkFromAdapter(multi, ip("172.16.0.1"))
	if got.LocalIP != "10.0.0.5" {
		t.Errorf("prefers non-link-local when nothing is on-link: %+v", got)
	}
	got = linkFromAdapter(adEthUSB, gw254)
	if got.LocalIP != "169.254.91.98" || got.State != "disconnected" || got.LinkMbps != 0 {
		t.Errorf("APIPA-only adapter: %+v", got)
	}
	got = linkFromAdapter(adapterInfo{Name: "{GUID}", TxSpeed: math.MaxUint64}, gw254)
	if got.Interface != "{GUID}" || got.LinkMbps != 0 || got.LocalIP != "" {
		t.Errorf("unknown speed / name fallback: %+v", got)
	}
	if got := linkFromAdapter(adapterInfo{Description: "Desc"}, gw254); got.Interface != "Desc" {
		t.Errorf("description fallback: %+v", got)
	}
}

// fakeLink installs adapter, route, netsh and interface-counter seams on a Prober.
type fakeLink struct {
	adapters   []adapterInfo
	adaptErr   error
	best       uint32
	netshOut   []byte
	netshErr   error
	netshCalls atomic.Int32
	// counters answers the interface-counter reads (nil: every read fails, so the link carries
	// no counters); ctrCalls counts the reads.
	counters func(luid uint64, index uint32) (rx, tx uint64, err error)
	ctrCalls atomic.Int32
}

func (f *fakeLink) install(p *Prober) {
	p.adapters = func() ([]adapterInfo, error) { return f.adapters, f.adaptErr }
	p.bestIf = func(netip.Addr) (uint32, error) {
		if f.best == 0 {
			return 0, errors.New("no route")
		}
		return f.best, nil
	}
	p.runNetsh = func(context.Context) ([]byte, error) {
		f.netshCalls.Add(1)
		return f.netshOut, f.netshErr
	}
	p.ifCounters = func(luid uint64, index uint32) (uint64, uint64, error) {
		f.ctrCalls.Add(1)
		if f.counters == nil {
			return 0, 0, errors.New("GetIfEntry2Ex: The system cannot find the file specified.")
		}
		return f.counters(luid, index)
	}
}

func TestLocalLinkWiFi(t *testing.T) {
	out := readFixture(t, "netsh_two_interfaces.txt")
	f := &fakeLink{adapters: []adapterInfo{adLoop, adHyperV, adEthUSB, adWiFi}, best: 15, netshOut: out}
	p := New(Options{})
	f.install(p)

	link, raw, err := p.LocalLink(context.Background(), "192.168.1.254")
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(out)
	want := connectedSample
	want.LocalIP, want.GatewayIP, want.LinkMbps = "192.168.1.71", "192.168.1.254", 576
	want.RawSHA256 = hex.EncodeToString(sum[:])
	if link != want {
		t.Fatalf("got  %+v\nwant %+v", link, want)
	}
	if string(raw) != string(out) {
		t.Fatal("raw output is not netsh's exact bytes")
	}

	// The Wi-Fi link drops: the adapter loses its address and netsh says disconnected.
	disc := strings.Replace(string(out), "State                  : connected", "State                  : disconnected", 1)
	f.adapters = []adapterInfo{adLoop, adHyperV, adEthUSB, adWiFiDown}
	f.best = 0
	f.netshOut = []byte(disc)
	link, raw, err = p.LocalLink(context.Background(), "192.168.1.254")
	if err != nil {
		t.Fatal(err)
	}
	if link.Interface != "Wi-Fi" || link.Type != "wifi" || link.State != "disconnected" || link.LocalIP != "" {
		t.Fatalf("after drop: %+v", link)
	}
	if len(raw) == 0 || link.RawSHA256 == "" {
		t.Fatal("raw evidence missing after drop")
	}
}

func TestLocalLinkEthernet(t *testing.T) {
	f := &fakeLink{adapters: []adapterInfo{adWiFi, adEthOnLAN}, best: 7}
	p := New(Options{})
	f.install(p)
	link, raw, err := p.LocalLink(context.Background(), "192.168.1.254")
	if err != nil || raw != nil || f.netshCalls.Load() != 0 {
		t.Fatalf("err %v raw %d netsh calls %d", err, len(raw), f.netshCalls.Load())
	}
	want := model.LocalLink{Interface: "Ethernet", Type: "ethernet", State: "connected", LocalIP: "192.168.1.80",
		GatewayIP: "192.168.1.254", LinkMbps: 1000}
	if link != want {
		t.Fatalf("got %+v want %+v", link, want)
	}
}

func TestLocalLinkNetshProblems(t *testing.T) {
	tests := []struct {
		name      string
		out       []byte
		netshErr  error
		errIn     []string
		wantSSID  string
		wantState string
		wantRaw   bool
	}{
		{"exit error with usable output", readFixture(t, "netsh_two_interfaces.txt"), errors.New("exit status 1"),
			[]string{"netsh wlan show interfaces: exit status 1"}, "ATTexample", "connected", true},
		{"timeout without output", nil, context.DeadlineExceeded,
			[]string{"netsh wlan show interfaces: context deadline exceeded"}, "", "connected", false},
		{"service stopped", readFixture(t, "netsh_wlansvc_stopped.txt"), errors.New("exit status 1"),
			[]string{"exit status 1", "wlansvc"}, "", "connected", true},
		{"adapter missing from netsh", []byte("    Name : Wi-Fi 9\n    State : connected\n"), nil,
			[]string{`no wireless interface named "Wi-Fi"`}, "", "connected", true},
		{"location notice", readFixture(t, "netsh_location_notice.txt"), nil,
			[]string{locationNote}, "", "connected", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &fakeLink{adapters: []adapterInfo{adWiFi}, best: 15, netshOut: tt.out, netshErr: tt.netshErr}
			p := New(Options{})
			f.install(p)
			link, raw, err := p.LocalLink(context.Background(), "192.168.1.254")
			if err != nil {
				t.Fatalf("netsh problems must not fail LocalLink: %v", err)
			}
			for _, s := range tt.errIn {
				if !strings.Contains(link.Err, s) {
					t.Errorf("Err %q does not contain %q", link.Err, s)
				}
			}
			if link.SSID != tt.wantSSID || link.State != tt.wantState || link.LocalIP != "192.168.1.71" {
				t.Errorf("link %+v", link)
			}
			if (len(raw) > 0) != tt.wantRaw || (link.RawSHA256 != "") != tt.wantRaw {
				t.Errorf("raw %d bytes, RawSHA256 %q", len(raw), link.RawSHA256)
			}
		})
	}
}

func TestLocalLinkFailures(t *testing.T) {
	p := New(Options{})
	(&fakeLink{adapters: []adapterInfo{adLoop, adHyperV}}).install(p)
	for _, gw := range []string{"", "bogus", "2001:db8::1"} {
		link, raw, err := p.LocalLink(context.Background(), gw)
		if err == nil || link.Err != err.Error() || raw != nil || link.Type != "unknown" {
			t.Errorf("LocalLink(%q) = %+v, %v", gw, link, err)
		}
	}
	link, _, err := p.LocalLink(context.Background(), "192.168.1.254")
	if err == nil || !strings.Contains(link.Err, "no network adapter") || link.State != "unknown" {
		t.Errorf("no adapter: %+v, %v", link, err)
	}

	(&fakeLink{adaptErr: errors.New("GetAdaptersAddresses: boom")}).install(p)
	if link, _, err := p.LocalLink(context.Background(), "192.168.1.254"); err == nil || !strings.Contains(link.Err, "boom") {
		t.Errorf("adapter error: %+v, %v", link, err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := p.LocalLink(ctx, "192.168.1.254"); !errors.Is(err, context.Canceled) {
		t.Errorf("canceled: %v", err)
	}
}

func TestLocalLinkRemembersOnlyOnLinkAdapters(t *testing.T) {
	p := New(Options{})
	f := &fakeLink{adapters: []adapterInfo{adHyperV}, best: 32}
	f.install(p)
	if l, _, err := p.LocalLink(context.Background(), "192.168.1.254"); err != nil || l.Interface != "vEthernet (Default Switch)" {
		t.Fatalf("route fallback: %+v %v", l, err)
	}
	if p.lastAdapter != "" {
		t.Fatalf("a route-only match must not be remembered, got %q", p.lastAdapter)
	}
	f.adapters, f.best = []adapterInfo{adEthOnLAN, adHyperV}, 7
	if _, _, err := p.LocalLink(context.Background(), "192.168.1.254"); err != nil || p.lastAdapter != "{ETH2-GUID}" {
		t.Fatalf("on-link match not remembered: %q %v", p.lastAdapter, err)
	}
}

// TestLocalLinkCounters: every reading carries the octet counters of the adapter it describes
// (by NET_LUID, else by interface index), read before netsh; counters that cannot be read stay
// nil and change nothing else in the reading.
func TestLocalLinkCounters(t *testing.T) {
	eth := adEthOnLAN
	eth.Luid = 0x6008001000000
	wifi := adWiFi
	wifi.Luid = 0x47008000000000
	var order []string
	byLuid := func(luid uint64, index uint32) (uint64, uint64, error) {
		order = append(order, "counters")
		switch luid {
		case eth.Luid:
			return 9_000_000_000_000, 1_234, nil
		case wifi.Luid:
			return 32_529_277_092, 32_435_574_470, nil
		}
		return 0, 0, errors.New("GetIfEntry2Ex: The system cannot find the file specified.")
	}

	f := &fakeLink{adapters: []adapterInfo{adHyperV, wifi, eth}, best: 7, counters: byLuid}
	p := New(Options{})
	f.install(p)
	link, _, err := p.LocalLink(context.Background(), "192.168.1.254")
	if err != nil || link.Interface != "Ethernet" || link.RxBytes == nil || link.TxBytes == nil ||
		*link.RxBytes != 9_000_000_000_000 || *link.TxBytes != 1_234 || link.Err != "" {
		t.Fatalf("ethernet: %+v %v", link, err)
	}
	want := model.LocalLink{Interface: "Ethernet", Type: "ethernet", State: "connected", LocalIP: "192.168.1.80",
		GatewayIP: "192.168.1.254", LinkMbps: 1000}
	got := link
	got.RxBytes, got.TxBytes = nil, nil
	if got != want {
		t.Fatalf("the counters change nothing else: %+v", got)
	}

	// Wi-Fi: the counters are read before netsh runs (the reading's time is when it starts).
	f = &fakeLink{adapters: []adapterInfo{wifi}, best: 15, netshOut: readFixture(t, "netsh_two_interfaces.txt"), counters: byLuid}
	p = New(Options{})
	f.install(p)
	p.runNetsh = func(context.Context) ([]byte, error) {
		order = append(order, "netsh")
		return f.netshOut, nil
	}
	order = nil
	link, _, err = p.LocalLink(context.Background(), "192.168.1.254")
	if err != nil || link.SSID != "ATTexample" || link.RxBytes == nil || *link.RxBytes != 32_529_277_092 || *link.TxBytes != 32_435_574_470 {
		t.Fatalf("wifi: %+v %v", link, err)
	}
	if strings.Join(order, ",") != "counters,netsh" {
		t.Fatalf("order %v", order)
	}

	// No LUID known: the interface index identifies the adapter.
	f = &fakeLink{adapters: []adapterInfo{adEthOnLAN}, best: 7, counters: func(luid uint64, index uint32) (uint64, uint64, error) {
		if luid != 0 || index != 7 {
			return 0, 0, errors.New("wrong interface")
		}
		return 5, 6, nil
	}}
	p = New(Options{})
	f.install(p)
	if link, _, _ = p.LocalLink(context.Background(), "192.168.1.254"); link.RxBytes == nil || *link.RxBytes != 5 || *link.TxBytes != 6 {
		t.Fatalf("by index: %+v", link)
	}

	// The adapter lost its address (selected as the previous one): its counters still count.
	f = &fakeLink{adapters: []adapterInfo{eth}, best: 7, counters: byLuid}
	p = New(Options{})
	f.install(p)
	if _, _, err := p.LocalLink(context.Background(), "192.168.1.254"); err != nil {
		t.Fatal(err)
	}
	down := eth
	down.OperStatus, down.IPv4, down.Gateways = operDown, nil, nil
	f.adapters, f.best = []adapterInfo{down}, 0
	if link, _, _ = p.LocalLink(context.Background(), "192.168.1.254"); link.State != "disconnected" || link.RxBytes == nil {
		t.Fatalf("previous adapter: %+v", link)
	}

	// Unreadable counters: nil, and no error in the reading.
	f = &fakeLink{adapters: []adapterInfo{adEthOnLAN}, best: 7}
	p = New(Options{})
	f.install(p)
	link, _, err = p.LocalLink(context.Background(), "192.168.1.254")
	if err != nil || link.RxBytes != nil || link.TxBytes != nil || link.Err != "" || f.ctrCalls.Load() != 1 {
		t.Fatalf("unreadable: %+v %v (%d reads)", link, err, f.ctrCalls.Load())
	}

	// No adapter identified: nothing to read.
	f = &fakeLink{adapters: []adapterInfo{adLoop}, counters: byLuid}
	p = New(Options{})
	f.install(p)
	if link, _, err = p.LocalLink(context.Background(), "192.168.1.254"); err == nil || link.RxBytes != nil || f.ctrCalls.Load() != 0 {
		t.Fatalf("no adapter: %+v %v (%d reads)", link, err, f.ctrCalls.Load())
	}
}
