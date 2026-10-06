package gateway

import (
	"net/netip"
	"testing"

	"attmonitor/internal/model"
)

// TestParseNATTableRealCapture parses the sanitized capture of the real NAT table page
// (testdata/gateway/nattable_real.html, BGW320-505 firmware 6.34.7). The real page has fourteen
// columns: besides the six the parser needs it shows "IP Family", "Protocol Number", "Lifetime",
// the translated "NAT Source/Destination Address/Port" and "Bidirectional", and it lists IPv6
// connections too. The session must be the connection as the device opened it: a parser that took
// the NAT columns would show this network's devices behind the gateway's public address (50 LAN
// sources instead of 68).
func TestParseNATTableRealCapture(t *testing.T) {
	got, err := ParseNATTable(fixture(t, "nattable_real.html"))
	if err != nil {
		t.Fatalf("ParseNATTable: %v", err)
	}
	if len(got.Sessions) != 120 || got.Skipped != 0 {
		t.Fatalf("%d sessions, %d skipped; want 120 and 0", len(got.Sessions), got.Skipped)
	}
	if got.InUse != 120 || got.Available != 32767 || got.Display != "All" {
		t.Errorf("totals %d in use / %d available, display %q; want 120 / 32767 / \"All\"", got.InUse, got.Available, got.Display)
	}

	lan := netip.MustParsePrefix("192.168.0.0/16")
	wan := netip.MustParseAddr("203.0.113.1") // the stand-in of the gateway's public address
	protos := map[string]int{}
	states := map[string]int{}
	var lanSrc, wanSrc, v6, dns, https int
	for _, s := range got.Sessions {
		protos[s.Proto]++
		states[s.State]++
		src := netip.MustParseAddr(s.Src)
		switch {
		case src.Is6():
			v6++
		case lan.Contains(src):
			lanSrc++
		case src == wan:
			wanSrc++
		default:
			t.Errorf("unexpected source %s (%+v)", s.Src, s)
		}
		switch s.DstPort {
		case 53:
			dns++
		case 443:
			https++
		}
	}
	if protos["icmp"] != 5 || protos["tcp"] != 79 || protos["udp"] != 36 {
		t.Errorf("protocols %v; want icmp 5, tcp 79, udp 36", protos)
	}
	if lanSrc != 68 || wanSrc != 19 || v6 != 33 {
		t.Errorf("sources: %d LAN, %d the gateway's own public address, %d IPv6; want 68, 19 and 33", lanSrc, wanSrc, v6)
	}
	if states[""] != 41 || states["CLOSE"] != 39 || states["ESTABLISHED"] != 32 || states["TIME_WAIT"] != 8 {
		t.Errorf("TCP states %v; want \"\" 41, CLOSE 39, ESTABLISHED 32, TIME_WAIT 8", states)
	}
	if dns != 33 || https != 76 {
		t.Errorf("destination port 53: %d, 443: %d; want 33 and 76", dns, https)
	}

	// One outbound connection, with the addresses and ports of the connection as opened (its NAT
	// columns hold the gateway's public address as the source).
	want := model.NATSession{Proto: "tcp", State: "ESTABLISHED", Src: "192.168.1.102", SrcPort: 59002, Dst: "203.0.113.3", DstPort: 443}
	found := false
	for _, s := range got.Sessions {
		if s == want {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("session %+v not found", want)
	}
}
