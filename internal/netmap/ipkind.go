package netmap

import (
	"net/netip"

	"attmonitor/internal/contracts"
	"attmonitor/internal/model"
)

// Special-purpose ranges (RFC 6890 and its successors) that classify does not find with the
// netip methods. Addresses in them never belong to an Internet site.
var (
	sharedV4   = netip.MustParsePrefix("100.64.0.0/10") // carrier-grade NAT (RFC 6598)
	reservedV4 = []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/8"),
		netip.MustParsePrefix("192.0.0.0/24"),
		netip.MustParsePrefix("192.0.2.0/24"), // documentation
		netip.MustParsePrefix("192.88.99.0/24"),
		netip.MustParsePrefix("198.18.0.0/15"),   // benchmarking
		netip.MustParsePrefix("198.51.100.0/24"), // documentation
		netip.MustParsePrefix("203.0.113.0/24"),  // documentation
		netip.MustParsePrefix("240.0.0.0/4"),     // reserved, and the broadcast address
	}
	globalV6   = netip.MustParsePrefix("2000::/3")
	reservedV6 = []netip.Prefix{
		netip.MustParsePrefix("2001::/23"),     // IETF protocol assignments
		netip.MustParsePrefix("2001:db8::/32"), // documentation
		netip.MustParsePrefix("3fff::/20"),     // documentation (RFC 9637)
	}
)

// classify returns the kind of an address (model.IPKind*) without the IP database: what the
// view knows when no contracts.IPIntel is attached. IPv4-mapped IPv6 addresses count as IPv4.
func classify(a netip.Addr) string {
	if !a.IsValid() {
		return model.IPKindInvalid
	}
	a = a.Unmap()
	switch {
	case a.IsLoopback():
		return model.IPKindLoopback
	case a.IsMulticast():
		return model.IPKindMulticast
	case a.IsLinkLocalUnicast():
		return model.IPKindLinkLocal
	case a.IsPrivate():
		return model.IPKindPrivate
	case a.IsUnspecified():
		return model.IPKindReserved
	case a.Is4() && sharedV4.Contains(a):
		return model.IPKindShared
	case a.Is4():
		for _, p := range reservedV4 {
			if p.Contains(a) {
				return model.IPKindReserved
			}
		}
		return model.IPKindPublic
	case !globalV6.Contains(a):
		return model.IPKindReserved
	}
	for _, p := range reservedV6 {
		if p.Contains(a) {
			return model.IPKindReserved
		}
	}
	return model.IPKindPublic
}

// lookup describes addresses for one request: through the IP database when there is one
// (whose kinds it trusts unless it leaves the kind out), else by their kind alone.
type lookup struct {
	intel contracts.IPIntel
}

// info returns what is known about a.
func (l lookup) info(a netip.Addr) model.IPInfo {
	a = a.Unmap()
	if l.intel == nil || !a.IsValid() {
		return model.IPInfo{Kind: classify(a)}
	}
	info := l.intel.Lookup(a)
	if info.Kind == "" {
		info.Kind = classify(a)
	}
	return info
}

// service names a port with the port table ("" when it does not know the port, or without the
// IP database).
func (l lookup) service(proto string, port int) string {
	if l.intel == nil || proto == "" {
		return ""
	}
	return l.intel.Service(proto, port)
}
