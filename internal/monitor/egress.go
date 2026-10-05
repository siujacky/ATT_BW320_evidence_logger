package monitor

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"attmonitor/internal/model"
)

// Egress (rules 2026.10-4, DESIGN §9): rules 2 and 3 blame the provider for internet probes that
// fail or degrade while the AT&T gateway answers on the LAN. That only holds for probes that
// leave this computer through that gateway. With a VPN tunnel (even one that keeps LAN access),
// a second network adapter or a hotspot holding the default route, or a mis-set route, they do
// not: a stalled tunnel or a distant VPN endpoint would read as an AT&T outage or slowdown. So
// every local-link check also records the route this computer uses to reach the gateway and each
// internet destination (model.LocalLink.Egress, the "egress" member of the local_link record),
// and the classifier attributes nothing to the provider while that route bypasses the gateway.

// routeInfo is the route this computer's IP stack uses for one destination.
type routeInfo struct {
	IfIndex uint32
	IfName  string
	NextHop netip.Addr // invalid or unspecified: on-link
}

// routeLookup returns the route to dst (GetBestRoute2 on Windows).
type routeLookup func(dst netip.Addr) (routeInfo, error)

// checkEgress resolves the routes to the gateway and to the destinations (IPv4 only: an IPv6
// destination is not compared with the gateway's IPv4 route). A destination is reached through
// the gateway when the first hop of its route is the gateway - or, when the gateway is itself
// behind a router of this network, that same router on the same interface. A VPN tunnel (its
// own adapter, on-link or with a tunnel address as next hop), a hotspot or another network
// holding the default route have another first hop. Bypass: the route to at least one
// destination does not leave through the gateway (its interface or first hop differs).
func checkEgress(lookup routeLookup, gateway string, dests []string) *model.EgressCheck {
	e := &model.EgressCheck{Gateway: gateway}
	gw, err := netip.ParseAddr(strings.TrimSpace(gateway))
	if err != nil || !gw.Unmap().Is4() {
		e.Err = fmt.Sprintf("the gateway address %q is not an IPv4 address", gateway)
		return e
	}
	gw = gw.Unmap()
	gr, err := lookup(gw)
	if err != nil {
		e.Err = "route to the gateway: " + errText(err)
		return e
	}
	e.GatewayIf, e.GatewayIfName = gr.IfIndex, gr.IfName
	first := gw
	if gr.NextHop.IsValid() && !gr.NextHop.IsUnspecified() {
		first = gr.NextHop.Unmap()
		e.GatewayNextHop = first.String()
	}
	for _, d := range dests {
		a, err := netip.ParseAddr(d)
		if err != nil || !a.Unmap().Is4() {
			continue
		}
		a = a.Unmap()
		r := model.EgressRoute{Target: a.String()}
		ri, err := lookup(a)
		if err != nil {
			r.Err = errText(err)
			e.Routes = append(e.Routes, r)
			continue
		}
		r.If, r.IfName = ri.IfIndex, ri.IfName
		hop := netip.Addr{}
		if ri.NextHop.IsValid() && !ri.NextHop.IsUnspecified() {
			hop = ri.NextHop.Unmap()
			r.NextHop = hop.String()
		}
		// The gateway itself as first hop is the gateway whatever adapter of its LAN reaches it
		// (Ethernet and Wi-Fi both connected); a router in between must be the one the gateway
		// is reached through, on the same adapter.
		r.ViaGateway = hop == first && (hop == gw || ri.IfIndex == gr.IfIndex)
		e.Bypass = e.Bypass || !r.ViaGateway
		e.Routes = append(e.Routes, r)
	}
	return e
}

// egressDests lists the destinations whose route is checked: the internet probe targets, the
// AT&T next hop and resolver when known, and the public resolvers (distinct, in order).
func (m *Monitor) egressDests(ispHop, ispDNS string) []string {
	var out []string
	add := func(s string) {
		if a, err := netip.ParseAddr(hostOnly(strings.TrimSpace(s))); err == nil && !slices.Contains(out, a.Unmap().String()) {
			out = append(out, a.Unmap().String())
		}
	}
	for _, sp := range m.set.targets {
		if sp.Role == model.RoleInet {
			add(sp.Target)
		}
	}
	add(ispHop)
	add(ispDNS)
	for _, p := range m.set.publicResolvers {
		add(p)
	}
	return out
}

// linkEgress returns the route check recorded with a local link (nil when there is no link or
// it carries no check).
func linkEgress(l *model.LocalLink) *model.EgressCheck {
	if l == nil {
		return nil
	}
	return l.Egress
}

// bypassRoute returns the first destination whose route bypasses the gateway (nil if none, or
// when the check is unknown or failed).
func bypassRoute(e *model.EgressCheck) *model.EgressRoute {
	if e == nil || e.Err != "" || !e.Bypass {
		return nil
	}
	for i := range e.Routes {
		if r := &e.Routes[i]; r.Err == "" && !r.ViaGateway {
			return r
		}
	}
	return nil
}

// egressChanged: the check started or stopped bypassing the gateway, or failing, or a route
// moved to another interface or first hop.
func egressChanged(a, b *model.EgressCheck) bool {
	if (a == nil) != (b == nil) {
		return true
	}
	if a == nil {
		return false
	}
	if a.Bypass != b.Bypass || (a.Err == "") != (b.Err == "") || a.GatewayIf != b.GatewayIf || a.GatewayNextHop != b.GatewayNextHop || len(a.Routes) != len(b.Routes) {
		return true
	}
	for i := range a.Routes {
		x, y := a.Routes[i], b.Routes[i]
		if x.Target != y.Target || x.If != y.If || x.NextHop != y.NextHop || x.ViaGateway != y.ViaGateway || (x.Err == "") != (y.Err == "") {
			return true
		}
	}
	return false
}

// ifLabel names an interface for a sentence.
func ifLabel(name string, index uint32) string {
	if name != "" {
		return fmt.Sprintf("%q (interface %d)", name, index)
	}
	return fmt.Sprintf("interface %d", index)
}

// bypassText states which route bypasses the gateway, e.g. "this computer's route to 1.1.1.1
// leaves through "NordLynx" (interface 23) via 10.5.0.1, not through the AT&T gateway
// 192.168.1.254 ("Wi-Fi" (interface 12))" ("" when none does).
func bypassText(e *model.EgressCheck) string {
	r := bypassRoute(e)
	if r == nil {
		return ""
	}
	via := "directly (on-link)"
	if r.NextHop != "" {
		via = "via " + r.NextHop
	}
	gwVia := ""
	if e.GatewayNextHop != "" {
		gwVia = " via " + e.GatewayNextHop
	}
	return fmt.Sprintf("this computer's route to %s leaves through %s %s, not through the AT&T gateway %s (reached through %s%s)",
		r.Target, ifLabel(r.IfName, r.If), via, e.Gateway, ifLabel(e.GatewayIfName, e.GatewayIf), gwVia)
}
