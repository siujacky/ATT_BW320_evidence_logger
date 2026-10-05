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
