package ipintel

import (
	"net/netip"
	"testing"

	"attmonitor/internal/model"
)

func TestClassify(t *testing.T) {
	const (
		public    = model.IPKindPublic
		private   = model.IPKindPrivate
		shared    = model.IPKindShared
		loopback  = model.IPKindLoopback
		linkLocal = model.IPKindLinkLocal
		multicast = model.IPKindMulticast
		reserved  = model.IPKindReserved
	)
	cases := []struct {
		addr, kind string
		lookup     string // the address looked up ("" = addr itself)
	}{
		// IPv4
		{"0.0.0.0", reserved, ""},
		{"0.255.255.255", reserved, ""},
		{"1.0.0.0", public, ""},
		{"8.8.8.8", public, ""},
		{"9.255.255.255", public, ""},
		{"10.0.0.0", private, ""},
		{"10.255.255.255", private, ""},
		{"11.0.0.0", public, ""},
		{"100.63.255.255", public, ""},
		{"100.64.0.0", shared, ""},
		{"100.127.255.255", shared, ""},
		{"100.128.0.0", public, ""},
		{"126.255.255.255", public, ""},
		{"127.0.0.1", loopback, ""},
		{"127.255.255.255", loopback, ""},
		{"169.253.255.255", public, ""},
		{"169.254.0.1", linkLocal, ""},
		{"169.255.0.0", public, ""},
		{"172.15.255.255", public, ""},
		{"172.16.0.0", private, ""},
		{"172.31.255.255", private, ""},
		{"172.32.0.0", public, ""},
		{"192.0.0.1", reserved, ""},
		{"192.0.0.9", public, ""},  // PCP anycast: globally reachable
		{"192.0.0.10", public, ""}, // TURN anycast
		{"192.0.0.255", reserved, ""},
		{"192.0.1.0", public, ""},
		{"192.0.2.1", reserved, ""},
		{"192.0.3.0", public, ""},
		{"192.88.99.1", reserved, ""}, // deprecated 6to4 relay anycast, like 2002::/16
		{"192.167.255.255", public, ""},
		{"192.168.0.0", private, ""},
		{"192.168.1.254", private, ""},
		{"192.168.255.255", private, ""},
		{"192.169.0.0", public, ""},
		{"198.17.255.255", public, ""},
		{"198.18.0.0", reserved, ""},
		{"198.19.255.255", reserved, ""},
		{"198.20.0.0", public, ""},
		{"198.51.100.7", reserved, ""},
		{"203.0.113.200", reserved, ""},
		{"203.0.114.0", public, ""},
		{"223.255.255.255", public, ""},
		{"224.0.0.251", multicast, ""},
		{"239.255.255.250", multicast, ""},
		{"240.0.0.1", reserved, ""},
		{"255.255.255.255", reserved, ""},
		// IPv6
		{"::", reserved, ""},
		{"::1", loopback, ""},
		{"::2", reserved, ""},
		{"::1.2.3.4", reserved, ""}, // deprecated IPv4-compatible
		{"::ffff:8.8.8.8", public, "8.8.8.8"},
		{"::ffff:192.168.1.10", private, "192.168.1.10"},
		{"::ffff:127.0.0.1", loopback, "127.0.0.1"},
		{"::ffff:203.0.113.1", reserved, "203.0.113.1"},
		{"64:ff9b::808:808", public, "8.8.8.8"}, // NAT64
		{"64:ff9b::a00:1", private, "10.0.0.1"},
		{"64:ff9b:1::1", reserved, ""},
		{"100::1", reserved, ""},
		{"2001::1", reserved, ""},     // Teredo
		{"2001:2::1", reserved, ""},   // benchmarking
		{"2001:1::1", public, ""},     // PCP anycast
		{"2001:3::1", public, ""},     // AMT
		{"2001:4:112::1", public, ""}, // AS112-v6
		{"2001:1ff:ffff::1", reserved, ""},
		{"2001:200::1", public, ""},
		{"2001:db8::1", reserved, ""},
		{"2001:db8:ffff:ffff:ffff:ffff:ffff:ffff", reserved, ""},
		{"2001:db9::1", public, ""},
		{"2001:4860:4860::8888", public, ""},
		{"2002:c000:204::1", reserved, ""}, // 6to4
		{"2606:4700:4700::1111", public, ""},
		{"3ffe::1", public, ""},
		{"3fff::1", reserved, ""},
		{"3fff:fff::1", reserved, ""},
		{"4000::1", reserved, ""},
		{"5f00::1", reserved, ""},
		{"fc00::1", private, ""},
		{"fd12:3456:789a::1", private, ""},
		{"fe80::1", linkLocal, ""},
		{"fe80::1%eth0", linkLocal, "fe80::1"},
		{"febf::1", linkLocal, ""},
		{"fec0::1", reserved, ""},
		{"ff02::1", multicast, ""},
		{"ff0e::1", multicast, ""},
	}
	for _, c := range cases {
		a := mustAddr(t, c.addr)
		kind, la := classify(a)
		want := c.lookup
		if want == "" {
			want = a.WithZone("").String()
		}
		if kind != c.kind || la.String() != want {
			t.Errorf("classify(%s) = %s, %s; want %s, %s", c.addr, kind, la, c.kind, want)
		}
	}
	if kind, la := classify(netip.Addr{}); kind != model.IPKindInvalid || la.IsValid() {
		t.Errorf("classify(invalid) = %s, %v", kind, la)
	}
}

// TestSpecialTables checks the tables' order: a globally reachable block listed after the
// special block that holds it would never be found.
func TestSpecialTables(t *testing.T) {
	for _, table := range [][]specialRange{special4, special6} {
		for i, s := range table {
			if !s.prefix.IsValid() || s.prefix != s.prefix.Masked() {
				t.Errorf("%v is not a canonical prefix", s.prefix)
			}
			for _, earlier := range table[:i] {
				if earlier.prefix.Bits() <= s.prefix.Bits() && earlier.prefix.Contains(s.prefix.Addr()) {
					t.Errorf("%v (%s) is hidden by %v (%s) before it", s.prefix, s.kind, earlier.prefix, earlier.kind)
				}
			}
		}
	}
}
