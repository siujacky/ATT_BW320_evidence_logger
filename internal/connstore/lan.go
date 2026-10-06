package connstore

import (
	"net/netip"
	"strings"
)

// gatewayKey is the device key of the sessions that have no local address on either side:
// those the gateway itself opened from its public address.
const gatewayKey = "gateway"

// shared is the shared address space of carrier-grade NAT (RFC 6598, 100.64.0.0/10): like the
// private ranges, the addresses of a network behind a NAT.
var shared = netip.MustParsePrefix("100.64.0.0/10")

// isLocal reports whether a (unmapped, without zone) is an address of a local network: private
// (RFC 1918; IPv6 unique local, fc00::/7), link-local (169.254.0.0/16, fe80::/10) or shared
// (100.64.0.0/10). The side of a NAT session with such an address is the device on the home
// network; the other side is the remote one.
func isLocal(a netip.Addr) bool {
	return a.IsPrivate() || a.IsLinkLocalUnicast() || shared.Contains(a)
}

// parseAddr parses an address of a NAT session. An IPv4-mapped IPv6 address counts as the IPv4
// address and a zone is dropped, so that each address has one form in the views.
func parseAddr(s string) (netip.Addr, bool) {
	a, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil {
		return netip.Addr{}, false
	}
	return a.Unmap().WithZone(""), true
}

// parseDeviceAddr parses an address of the Device List, which may come with a prefix length
// ("2001:db8::10/64").
func parseDeviceAddr(s string) (netip.Addr, bool) {
	s = strings.TrimSpace(s)
	if a, ok := parseAddr(s); ok {
		return a, true
	}
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return netip.Addr{}, false
	}
	return p.Addr().Unmap().WithZone(""), true
}

// orientation says which side of a NAT session is the device on the home network.
type orientation uint8

const (
	// outbound: the source is local - the device opened the session; the destination is the
	// remote side and the port the remote one.
	outbound orientation = iota
	// inbound: only the destination is local - the remote side opened the session (a port
	// forward, a pinhole); the port is the device's.
	inbound
	// fromGateway: neither side is local - the gateway's own session from its public address
	// (the source); the destination is the remote side.
	fromGateway
)

// orient returns the orientation of a session between src and dst (both parsed by parseAddr).
// In every case the flow's port is the destination port: the service the opening side asked
// for.
func orient(src, dst netip.Addr) orientation { return orientLocal(isLocal(src), isLocal(dst)) }

// orientLocal is orient for addresses already classified by isLocal.
func orientLocal(srcLocal, dstLocal bool) orientation {
	switch {
	case srcLocal:
		return outbound
	case dstLocal:
		return inbound
	}
	return fromGateway
}

// normPort returns p when it is a port number, else 0 (the gateway client already writes 0 for
// a port it does not understand).
func normPort(p int) int32 {
	if p < 0 || p > 65535 {
		return 0
	}
	return int32(p)
}

// normProto returns a protocol as the views name it: lower case, without spaces.
func normProto(p string) string {
	return strings.ToLower(strings.TrimSpace(p))
}
