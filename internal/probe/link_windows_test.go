//go:build windows

package probe

import (
	"context"
	"net/netip"
	"testing"
	"time"
)

func TestListAdaptersReal(t *testing.T) {
	list, err := listAdapters()
	if err != nil {
		t.Fatal(err)
	}
	var loop *adapterInfo
	for i := range list {
		a := &list[i]
		if a.Name == "" {
			t.Errorf("adapter without AdapterName: %+v", a)
		}
		for _, p := range a.IPv4 {
			if !p.Addr().Is4() || p.Bits() < 0 || p.Bits() > 32 {
				t.Errorf("bad prefix %v on %q", p, a.Friendly)
			}
		}
		if a.IfType == ifTypeLoopback {
			loop = a
		}
	}
	if loop == nil {
		t.Fatalf("no loopback adapter among %d adapters", len(list))
	}
	if loop.Luid == 0 {
		t.Errorf("loopback adapter without NET_LUID: %+v", loop)
	}
	idx, err := bestInterface(netip.MustParseAddr("127.0.0.1"))
	if err != nil {
		t.Fatal(err)
	}
	if idx != loop.IfIndex {
		t.Errorf("best interface for 127.0.0.1 = %d, loopback IfIndex = %d", idx, loop.IfIndex)
	}
}

func TestLocalLinkLoopbackReal(t *testing.T) {
	p := New(Options{})
	netshCalled := false
	p.runNetsh = func(context.Context) ([]byte, error) { netshCalled = true; return nil, nil }
	link, raw, err := p.LocalLink(context.Background(), "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if link.Interface == "" || link.Type != "unknown" || link.State != "connected" || link.LocalIP != "127.0.0.1" {
		t.Fatalf("loopback link: %+v", link)
	}
	if raw != nil || netshCalled || link.Err != "" {
		t.Fatalf("raw %d netsh %v err %q", len(raw), netshCalled, link.Err)
	}
}

// TestInterfaceCountersReal reads real octet counters (read-only, nothing is sent): the loopback
// pseudo-interface's and those of the interface this computer's default route uses, by NET_LUID
// and by interface index (the same interface, so the second reading is not lower). Skipped when
// the counters or the route are unavailable.
func TestInterfaceCountersReal(t *testing.T) {
	list, err := listAdapters()
	if err != nil {
		t.Skipf("no adapter list: %v", err)
	}
	best, berr := bestInterface(netip.MustParseAddr("1.1.1.1")) // a route lookup, no packet
	tested := 0
	for _, a := range list {
		if a.IfType != ifTypeLoopback && (berr != nil || a.IfIndex != best) {
			continue
		}
		rx1, tx1, err := interfaceCounters(a.Luid, 0)
		if err != nil {
			t.Skipf("GetIfEntry2Ex unavailable for %q: %v", a.Friendly, err)
		}
		rx2, tx2, err := interfaceCounters(0, a.IfIndex)
		if err != nil {
			t.Fatalf("%q by index %d: %v", a.Friendly, a.IfIndex, err)
		}
		if rx2 < rx1 || tx2 < tx1 {
			t.Fatalf("%q: counters went back from %d/%d to %d/%d", a.Friendly, rx1, tx1, rx2, tx2)
		}
		t.Logf("%q (index %d, type %d): received %d, sent %d bytes", a.Friendly, a.IfIndex, a.IfType, rx2, tx2)
		tested++
	}
	if tested == 0 {
		t.Skip("no loopback or default-route interface")
	}
	if _, _, err := interfaceCounters(0, 0); err == nil {
		t.Error("no interface given must fail")
	}
	if _, _, err := interfaceCounters(0xdead0000beef, 0); err == nil {
		t.Error("an unknown NET_LUID must fail")
	}

	// LocalLink reads them for the adapter it describes (loopback: its own counters).
	p := New(Options{})
	p.runNetsh = func(context.Context) ([]byte, error) { return nil, nil }
	link, _, err := p.LocalLink(context.Background(), "127.0.0.1")
	if err != nil || link.RxBytes == nil || link.TxBytes == nil || link.Err != "" {
		t.Fatalf("loopback link: %+v %v", link, err)
	}
}

func TestRunNetshWLANReal(t *testing.T) {
	// Read-only local command. Only its mechanics are checked; output is not logged because
	// it contains the real SSID/BSSID.
	start := time.Now()
	out, err := runNetshWLAN(context.Background())
	if el := time.Since(start); el > netshTimeout+2*time.Second {
		t.Fatalf("took %v", el)
	}
	if len(out) == 0 && err == nil {
		t.Fatal("no output and no error")
	}
	if len(out) > 0 {
		if _, perr := ParseNetshWLAN(out, ""); perr != nil {
			t.Logf("netsh output not parseable here (%v); acceptable on PCs without Wi-Fi", perr)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := runNetshWLAN(ctx); err == nil {
		t.Error("canceled context must fail")
	}
}
