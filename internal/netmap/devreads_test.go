package netmap

import (
	"net/netip"
	"reflect"
	"slices"
	"testing"
	"time"

	"attmonitor/internal/model"
)

// TestDeviceReadsTenures: an address's history - which device held it from which read to which. A
// tenure goes on over reads that list the device without the address (off, or not listed), and
// ends when another device holds the address; of several entries that give one address those
// that are on hold it, and two that are on hold it together (shared); an entry listed twice holds
// it once.
func TestDeviceReadsTenures(t *testing.T) {
	dev := func(n, name, ip, status string) model.LANDevice {
		return model.LANDevice{MAC: "00:00:5e:00:53:" + n, Name: name, IPv4: ip, Status: status}
	}
	h := newDevReads(mins(0), mins(100))
	for _, r := range []struct {
		at      float64
		devices []model.LANDevice
	}{
		{-5, []model.LANDevice{dev("01", "a", "192.168.1.70", "on")}},
		{10, []model.LANDevice{dev("01", "a", "", "off")}},                                                   // a, without an address
		{20, []model.LANDevice{dev("01", "a", "192.168.1.70", "on"), dev("01", "a", "192.168.1.70", "on")}},  // listed twice
		{30, []model.LANDevice{dev("01", "a", "192.168.1.70", "off"), dev("02", "b", "192.168.1.70", "on")}}, // b holds it: a is off
		{40, []model.LANDevice{dev("02", "b", "192.168.1.70", "on"), dev("03", "c", "192.168.1.70", "on")}},  // b and c: a conflict
		{50, []model.LANDevice{dev("01", "a2", "192.168.1.70", "on"),
			dev("04", "d", "192.168.1.75", "off"), dev("05", "e", "192.168.1.75", "off")}}, // a again, renamed; d and e left: no conflict
		{100, []model.LANDevice{dev("09", "late", "192.168.1.99", "on")}}, // at the period's end: names only
	} {
		h.add(mins(r.at), r.devices)
	}
	ts := func(m float64) string { return rfc3339(mins(m)) }
	use := func(n, name string, first, last float64, reads, shared int) model.NetAddrUse {
		return model.NetAddrUse{Addr: "192.168.1.70", Device: "mac:00:00:5e:00:53:" + n, Name: name, MAC: "00:00:5e:00:53:" + n,
			First: ts(first), Last: ts(last), Reads: reads, Shared: shared}
	}
	at75 := func(u model.NetAddrUse) model.NetAddrUse { u.Addr = "192.168.1.75"; return u }
	want := []model.NetAddrUse{
		use("01", "a", -5, 20, 2, 0),
		use("02", "b", 30, 40, 2, 1),
		use("03", "c", 40, 40, 1, 1),
		use("01", "a2", 50, 50, 1, 0),
		at75(use("04", "d", 50, 50, 1, 0)),
		at75(use("05", "e", 50, 50, 1, 0)),
	}
	if got := h.history(); !reflect.DeepEqual(got, want) {
		t.Errorf("history:\n got %+v\nwant %+v", got, want)
	}
	if h.reads != 5 {
		t.Errorf("%d reads in the period, want 5 (the one before it and the one at its end do not count)", h.reads)
	}
	a := h.stats["mac:00:00:5e:00:53:01"]
	if a.reads != 4 || a.onReads != 2 || a.seen != nanos(mins(50)) {
		t.Errorf("a: %+v", a)
	}
	if got := h.addresses("mac:00:00:5e:00:53:01"); !slices.Equal(got, []string{"192.168.1.70"}) {
		t.Errorf("a's addresses %q", got)
	}
	if _, named := h.named[netip.MustParseAddr("192.168.1.99")]; !named || h.stats["mac:00:00:5e:00:53:09"] != nil {
		t.Error("the read at the period's end does not only name its addresses")
	}
}

// TestDeviceReadsBoundTheHistory: two devices that swap their addresses at every read make two
// tenures a read; the history keeps the maxAddrUses that ended last, in order, with the tenure
// that never ended.
func TestDeviceReadsBoundTheHistory(t *testing.T) {
	h := newDevReads(t0, t0.Add(31*24*time.Hour))
	n := 2*maxAddrUses + 10
	for i := range n {
		x, y := "192.168.1.10", "192.168.1.11"
		if i%2 == 1 {
			x, y = y, x
		}
		h.add(t0.Add(time.Duration(i)*time.Minute), []model.LANDevice{{MAC: "00:00:5e:00:53:01", IPv4: x, Status: "on"},
			{MAC: "00:00:5e:00:53:02", IPv4: y, Status: "on"}, {MAC: "00:00:5e:00:53:03", IPv4: "192.168.1.12", Status: "on"}})
	}
	got := h.history()
	if len(got) != maxAddrUses {
		t.Fatalf("%d tenures, want %d", len(got), maxAddrUses)
	}
	// Two tenures a read: those kept ended within the last maxAddrUses/2 reads.
	oldest := t0.Add(time.Duration(n-maxAddrUses/2-2) * time.Minute)
	for i, u := range got {
		if i > 0 {
			p := got[i-1]
			pa, ua := netip.MustParseAddr(p.Addr), netip.MustParseAddr(u.Addr)
			if pa.Compare(ua) > 0 || pa == ua && p.First > u.First {
				t.Fatalf("out of order: %+v before %+v", p, u)
			}
		}
		if last, _ := time.Parse(time.RFC3339Nano, u.Last); last.Before(oldest) {
			t.Fatalf("an old tenure was kept: %+v", u)
		}
	}
	if !slices.ContainsFunc(got, func(u model.NetAddrUse) bool { return u.Addr == "192.168.1.12" && u.Reads == n }) {
		t.Error("the tenure that never ended is not kept whole")
	}
	if len(h.ended) > 2*maxAddrUses {
		t.Errorf("%d ended tenures kept while reading", len(h.ended))
	}
}

func TestDeviceKeys(t *testing.T) {
	for _, tc := range []struct {
		d    model.LANDevice
		want string
	}{
		{model.LANDevice{MAC: "00:00:5E:00:53:0A", IPv4: "192.168.1.5"}, "mac:00:00:5e:00:53:0a"},
		{model.LANDevice{MAC: "00-00-5e-00-53-0b"}, "mac:00:00:5e:00:53:0b"},
		{model.LANDevice{MAC: "00:00:00:00:00:00", IPv4: "192.168.1.6"}, "ip:192.168.1.6"},
		{model.LANDevice{MAC: "unknown", IPv4: "::ffff:192.168.1.7"}, "ip:192.168.1.7"},
		{model.LANDevice{IPv4: "bogus", IPv6: []string{"fe80::1%br0", "2001:db8::1"}, Name: "x"}, "ip:fe80::1"},
		{model.LANDevice{IPv6: []string{"2001:db8::1/64"}}, "ip:2001:db8::1"},
		{model.LANDevice{Name: " printer "}, "name:printer"},
		{model.LANDevice{Status: "on"}, ""},
	} {
		if got := lanDeviceKey(tc.d); got != tc.want {
			t.Errorf("lanDeviceKey(%+v) = %q, want %q", tc.d, got, tc.want)
		}
	}
	for addr, want := range map[string]bool{"192.168.1.5": true, "10.1.2.3": true, "172.16.0.1": true, "169.254.7.7": true,
		"::ffff:192.168.1.5": true, "100.64.0.1": false, "192.0.2.1": false, "fd00::1": false, "fe80::1": false, "2001:db8::1": false} {
		if got := lanCandidate(netip.MustParseAddr(addr)); got != want {
			t.Errorf("lanCandidate(%s) = %v, want %v", addr, got, want)
		}
	}
}

// TestDeviceOrNext: an address the Device List read in effect names counts for that device; one
// it does not name, for the device the next read names there when it comes within 20 minutes.
func TestDeviceOrNext(t *testing.T) {
	n := newDevNamer()
	n.add(nanos(mins(0)), []model.LANDevice{{MAC: "00:00:5e:00:53:01", IPv4: "192.168.1.10", Status: "on"}})
	n.add(nanos(mins(15)), []model.LANDevice{{MAC: "00:00:5e:00:53:01", IPv4: "192.168.1.10", Status: "on"}}) // the same: not kept apart
	n.add(nanos(mins(30)), []model.LANDevice{{MAC: "00:00:5e:00:53:01", IPv4: "192.168.1.10", Status: "on"},
		{MAC: "00:00:5e:00:53:02", IPv4: "192.168.1.11", Status: "on"}})
	a10, a11 := netip.MustParseAddr("192.168.1.10").As16(), netip.MustParseAddr("192.168.1.11").As16()
	key := func(num int32, a [16]byte) string { k, _ := n.describe(num, netip.AddrFrom16(a).Unmap()); return k }
	for _, tc := range []struct {
		lan  [16]byte
		at   float64
		want string
	}{
		{a10, -5, "mac:00:00:5e:00:53:01"}, // before the first read: the first one
		{a10, 20, "mac:00:00:5e:00:53:01"},
		{a11, 5, "ip:192.168.1.11"},        // the next different read is 25 minutes later
		{a11, 12, "mac:00:00:5e:00:53:02"}, // 18 minutes later
		{a11, 30, "mac:00:00:5e:00:53:02"},
		{a11, -5, "ip:192.168.1.11"}, // the first read is in effect, and does not name it
	} {
		if got := key(n.deviceOrNext(tc.lan, nanos(mins(tc.at))), tc.lan); got != tc.want {
			t.Errorf("%s at %v min: %s, want %s", netip.AddrFrom16(tc.lan).Unmap(), tc.at, got, tc.want)
		}
	}
	var none *devNamer
	if got := none.deviceOrNext(a10, 0); got != 0 {
		t.Errorf("without reads: %d", got)
	}
}
