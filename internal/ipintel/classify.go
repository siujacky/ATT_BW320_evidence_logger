package ipintel

import (
	"net/netip"

	"attmonitor/internal/model"
)

// specialRange is a special-purpose address block and the kind of its addresses.
type specialRange struct {
	prefix netip.Prefix
	kind   string
}

// special4 are the IPv4 special-purpose blocks (IANA IPv4 Special-Purpose Address Registry, RFC
// 6890), checked in order: the first block that holds an address names its kind; an address in
// none is public. Blocks the registry marks globally reachable inside a special one come first.
var special4 = []specialRange{
	{netip.MustParsePrefix("0.0.0.0/8"), model.IPKindReserved},       // "this network" (RFC 791)
	{netip.MustParsePrefix("10.0.0.0/8"), model.IPKindPrivate},       // RFC 1918
	{netip.MustParsePrefix("100.64.0.0/10"), model.IPKindShared},     // carrier-grade NAT (RFC 6598)
	{netip.MustParsePrefix("127.0.0.0/8"), model.IPKindLoopback},     // RFC 1122
	{netip.MustParsePrefix("169.254.0.0/16"), model.IPKindLinkLocal}, // RFC 3927
	{netip.MustParsePrefix("172.16.0.0/12"), model.IPKindPrivate},    // RFC 1918
	{netip.MustParsePrefix("192.0.0.9/32"), model.IPKindPublic},      // PCP anycast (RFC 7723)
	{netip.MustParsePrefix("192.0.0.10/32"), model.IPKindPublic},     // TURN anycast (RFC 8155)
	{netip.MustParsePrefix("192.0.0.0/24"), model.IPKindReserved},    // IETF protocol assignments
	{netip.MustParsePrefix("192.0.2.0/24"), model.IPKindReserved},    // TEST-NET-1 (RFC 5737)
	{netip.MustParsePrefix("192.88.99.0/24"), model.IPKindReserved},  // deprecated 6to4 relays (RFC 7526)
	{netip.MustParsePrefix("192.168.0.0/16"), model.IPKindPrivate},   // RFC 1918
	{netip.MustParsePrefix("198.18.0.0/15"), model.IPKindReserved},   // benchmarking (RFC 2544)
	{netip.MustParsePrefix("198.51.100.0/24"), model.IPKindReserved}, // TEST-NET-2 (RFC 5737)
	{netip.MustParsePrefix("203.0.113.0/24"), model.IPKindReserved},  // TEST-NET-3 (RFC 5737)
	{netip.MustParsePrefix("224.0.0.0/4"), model.IPKindMulticast},    // RFC 5771
	{netip.MustParsePrefix("240.0.0.0/4"), model.IPKindReserved},     // RFC 1112, with 255.255.255.255
}

// special6 are the IPv6 special-purpose blocks (IANA IPv6 Special-Purpose Address Registry and
// IPv6 Address Space), checked in order like special4. Global unicast (2000::/3) is public;
// an address in none of the blocks is in space the IETF keeps reserved. IPv4-mapped and NAT64
// addresses are classified by the IPv4 address they carry before this table is used.
var special6 = []specialRange{
	{netip.MustParsePrefix("::/128"), model.IPKindReserved},        // unspecified
	{netip.MustParsePrefix("::1/128"), model.IPKindLoopback},       // RFC 4291
	{netip.MustParsePrefix("2001:1::1/128"), model.IPKindPublic},   // PCP anycast (RFC 7723)
	{netip.MustParsePrefix("2001:1::2/128"), model.IPKindPublic},   // TURN anycast (RFC 8155)
	{netip.MustParsePrefix("2001:1::3/128"), model.IPKindPublic},   // DNS-SD SRP anycast (RFC 9665)
	{netip.MustParsePrefix("2001:3::/32"), model.IPKindPublic},     // AMT (RFC 7450)
	{netip.MustParsePrefix("2001:4:112::/48"), model.IPKindPublic}, // AS112-v6 (RFC 7535)
	{netip.MustParsePrefix("2001:20::/28"), model.IPKindPublic},    // ORCHIDv2 (RFC 7343)
	{netip.MustParsePrefix("2001:30::/28"), model.IPKindPublic},    // drone remote ID (RFC 9374)
	{netip.MustParsePrefix("2001::/23"), model.IPKindReserved},     // IETF protocol assignments, with Teredo and benchmarking
	{netip.MustParsePrefix("2001:db8::/32"), model.IPKindReserved}, // documentation (RFC 3849)
	{netip.MustParsePrefix("2002::/16"), model.IPKindReserved},     // 6to4 (RFC 3056)
	{netip.MustParsePrefix("3fff::/20"), model.IPKindReserved},     // documentation (RFC 9637)
	{netip.MustParsePrefix("2000::/3"), model.IPKindPublic},        // global unicast
	{netip.MustParsePrefix("fc00::/7"), model.IPKindPrivate},       // unique local (RFC 4193)
	{netip.MustParsePrefix("fe80::/10"), model.IPKindLinkLocal},    // RFC 4291
	{netip.MustParsePrefix("ff00::/8"), model.IPKindMulticast},     // RFC 4291
}

// nat64 is the well-known NAT64 prefix (RFC 6052): its addresses stand for the IPv4 address in
// their last 32 bits, which is the one really reached.
var nat64 = netip.MustParsePrefix("64:ff9b::/96")

// classify returns the kind of addr (a model.IPKind* constant) and the address that stands for
// it in lookups: addr without its zone, or the IPv4 address that an IPv4-mapped (::ffff:0:0/96)
// or NAT64 address carries - so that ::ffff:8.8.8.8 is named like 8.8.8.8.
func classify(addr netip.Addr) (string, netip.Addr) {
	if !addr.IsValid() {
		return model.IPKindInvalid, netip.Addr{}
	}
	a := addr.WithZone("")
	switch {
	case a.Is4In6():
		a = a.Unmap()
	case a.Is6() && nat64.Contains(a):
		b := a.As16()
		a = netip.AddrFrom4([4]byte(b[12:16]))
	}
	table, other := special6, model.IPKindReserved
	if a.Is4() {
		table, other = special4, model.IPKindPublic
	}
	for _, s := range table {
		if s.prefix.Contains(a) {
			return s.kind, a
		}
	}
	return other, a
}
