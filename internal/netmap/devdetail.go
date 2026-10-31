package netmap

import (
	"cmp"
	"context"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"attmonitor/internal/contracts"
	"attmonitor/internal/model"
)

// A device's details (docs/dhcp-table.md §7): one device of the Devices view, or one unknown
// address, with its addresses and who else held them, the LAN scans as it answered them, and what
// its syslog messages are found by.

// maxMatchIPv4 bounds the IPv4 terms of a device's details (NetDeviceDetail.Match): its holds of
// an address, widened and joined where they meet. A device whose address changes back and forth
// at every read holds each address in one term; the newest are kept.
const maxMatchIPv4 = 128

// Kinds of a syslog term (model.NetSyslogTerm.Kind).
const (
	termIPv4 = "ipv4"
	termIPv6 = "ipv6"
	termMAC  = "mac"
)

// devBuild is a Devices view as built and kept for reuse, with what a device's details need
// beyond it (Device). Nothing of it changes once it is built: callers get copies.
type devBuild struct {
	view model.NetDevicesView
	// unknown is every unknown address, as the view lists them (view.Unknown: the first limit).
	unknown []model.NetUnknownAddr
	// baseKey maps a listed device's key to the key the period's reads and the address history know
	// it by (without "#2", ...).
	baseKey map[string]string
	// v6 are the IPv6 addresses the period's reads gave each device (by key), those given last
	// first (at most maxDeviceV6).
	v6 map[string][]netip.Addr
	// every is how often the Device List was read: an IPv4 hold is widened by it on each side.
	every time.Duration
	scans *scanDetail // nil without scans
}

// Device returns one device's details (contracts.NetworkView; docs/dhcp-table.md §7): the device
// of the Devices view of [q.From, q.To) whose key is key - as that view lists it, with the same
// issues - or the unknown LAN address addr (an IPv4 address); one of key and addr is given. With
// it: the address history entries of its IPv4 addresses (its own holds and any other device's),
// the period's LAN scans as it answered them (the newest maxDetailScans, newest first) and Match,
// what its syslog messages are found by: for a device each IPv4 address it held, while it held it
// - from one Device List interval before the first read that showed it with the address to one
// interval after the last (a hold is only seen at the reads), within the period - and each of its
// IPv6 addresses and its MAC address for the whole period; for an unknown address that address for
// the whole period. The web layer reads the syslog messages (Syslog is left empty). The details
// reuse the Devices view built for the period (the one built for MaxLimit rows, as the dashboard
// asks); they fail with ErrUnavailable without a connection store, ErrRange for a period that is
// not valid and contracts.ErrNotFound when the period knows neither the device nor the address.
func (v *View) Device(ctx context.Context, q contracts.NetQuery, key, addr string) (model.NetDeviceDetail, error) {
	notFound := fmt.Errorf("netmap: device details: not a device or an unknown address of the period: %w", contracts.ErrNotFound)
	if (key == "") == (addr == "") {
		if v.conns == nil {
			return model.NetDeviceDetail{}, fmt.Errorf("netmap: device details: no connection store: %w", contracts.ErrUnavailable)
		}
		if _, _, err := v.period(q); err != nil {
			return model.NetDeviceDetail{}, err
		}
		return model.NetDeviceDetail{}, fmt.Errorf("netmap: device details: a device key or an unknown address, one of them: %w", contracts.ErrNotFound)
	}
	b, err := v.devicesBuild(ctx, q, MaxLimit, "device details")
	if err != nil {
		return model.NetDeviceDetail{}, err
	}
	if key != "" {
		dd, ok := b.deviceDetail(key)
		if !ok {
			return model.NetDeviceDetail{}, notFound
		}
		return dd, nil
	}
	a, err := netip.ParseAddr(strings.TrimSpace(addr))
	if err != nil || !a.Is4() {
		return model.NetDeviceDetail{}, notFound
	}
	dd, ok := b.unknownDetail(a)
	if !ok {
		return model.NetDeviceDetail{}, notFound
	}
	return dd, nil
}

// deviceDetail returns the details of the listed device key (false when the view lists none).
func (b *devBuild) deviceDetail(key string) (model.NetDeviceDetail, bool) {
	i := slices.IndexFunc(b.view.Devices, func(d model.NetLANDevice) bool { return d.Key == key })
	if i < 0 {
		return model.NetDeviceDetail{}, false
	}
	d := cloneLANDevice(b.view.Devices[i])
	base := b.baseKey[d.Key]
	// Its addresses: those it held in the period, the one it is listed with, those of its holds.
	held := map[string]bool{}
	for _, s := range d.Addresses {
		held[s] = true
	}
	if d.IPv4 != "" {
		held[d.IPv4] = true
	}
	for _, u := range b.view.Addresses {
		if u.Device == base {
			held[u.Addr] = true
		}
	}
	return model.NetDeviceDetail{
		From:      b.view.From,
		To:        b.view.To,
		Device:    &d,
		Addresses: b.addressUses(func(u model.NetAddrUse) bool { return held[u.Addr] }),
		Scans:     b.scans.device(key),
		Match:     b.deviceMatch(d, base),
		Syslog:    []model.SyslogEntry{},
	}, true
}

// unknownDetail returns the details of the unknown address a (false when it is none of the
// period's).
func (b *devBuild) unknownDetail(a netip.Addr) (model.NetDeviceDetail, bool) {
	s := a.String()
	i := slices.IndexFunc(b.unknown, func(u model.NetUnknownAddr) bool { return u.Addr == s })
	if i < 0 {
		return model.NetDeviceDetail{}, false
	}
	u := b.unknown[i]
	u.Issues = slices.Clone(u.Issues)
	return model.NetDeviceDetail{
		From:      b.view.From,
		To:        b.view.To,
		Unknown:   &u,
		Addresses: b.addressUses(func(use model.NetAddrUse) bool { return use.Addr == s }),
		Scans:     b.scans.unknownAddr(a),
		Match:     []model.NetSyslogTerm{{Kind: termIPv4, Text: s}},
		Syslog:    []model.SyslogEntry{},
	}, true
}

// addressUses returns the entries of the address history that keep says to, in its order.
func (b *devBuild) addressUses(keep func(model.NetAddrUse) bool) []model.NetAddrUse {
	out := []model.NetAddrUse{}
	for _, u := range b.view.Addresses {
		if keep(u) {
			out = append(out, u)
		}
	}
	return out
}

// hold is a time a device held an IPv4 address: [from, to), Unix nanoseconds.
type hold struct {
	addr     netip.Addr
	from, to int64
}

// deviceMatch returns what the device d's syslog messages are found by: its IPv4 holds (the
// address history's tenures of base, each widened by b.every on each side and clipped to the
// period, joined where they meet; at most maxMatchIPv4, the newest), oldest first, then its IPv6
// addresses (the newest read's, then those the period's reads gave it) and its MAC address for the
// whole period.
func (b *devBuild) deviceMatch(d model.NetLANDevice, base string) []model.NetSyslogTerm {
	pFrom, pTo := parseRFC3339(b.view.From).UnixNano(), parseRFC3339(b.view.To).UnixNano()
	every := int64(b.every)
	var holds []hold
	for _, u := range b.view.Addresses {
		a, ok := deviceIPv4(u.Addr)
		first, last := parseRFC3339(u.First), parseRFC3339(u.Last)
		if u.Device != base || !ok || first.IsZero() || last.IsZero() {
			continue
		}
		h := hold{addr: a, from: max(first.UnixNano()-every, pFrom), to: min(last.UnixNano()+every, pTo)}
		if h.from < h.to {
			holds = append(holds, h)
		}
	}
	holds = joinHolds(holds)
	if len(holds) > maxMatchIPv4 {
		slices.SortStableFunc(holds, func(x, y hold) int { return cmp.Compare(y.to, x.to) })
		holds = holds[:maxMatchIPv4]
	}
	slices.SortFunc(holds, func(x, y hold) int { return cmp.Or(cmp.Compare(x.from, y.from), x.addr.Compare(y.addr)) })
	terms := []model.NetSyslogTerm{}
	for _, h := range holds {
		t := model.NetSyslogTerm{Kind: termIPv4, Text: h.addr.String()}
		if h.from > pFrom {
			t.From = rfc3339(time.Unix(0, h.from))
		}
		if h.to < pTo {
			t.To = rfc3339(time.Unix(0, h.to))
		}
		terms = append(terms, t)
	}
	seen := map[netip.Addr]bool{}
	v6 := func(a netip.Addr) {
		if a = a.WithZone(""); a.Is6() && !a.Is4In6() && !seen[a] && len(seen) < maxDeviceV6 {
			seen[a] = true
			terms = append(terms, model.NetSyslogTerm{Kind: termIPv6, Text: a.String()})
		}
	}
	for _, s := range d.IPv6 {
		if a, ok := lanAddr(s); ok {
			v6(a)
		}
	}
	for _, a := range b.v6[d.Key] {
		v6(a)
	}
	if mac := normMAC(d.MAC); mac != "" {
		terms = append(terms, model.NetSyslogTerm{Kind: termMAC, Text: mac})
	}
	return terms
}

// joinHolds joins the holds of one address that overlap or meet.
func joinHolds(holds []hold) []hold {
	slices.SortFunc(holds, func(x, y hold) int { return cmp.Or(x.addr.Compare(y.addr), cmp.Compare(x.from, y.from)) })
	out := holds[:0]
	for _, h := range holds {
		if n := len(out); n > 0 && out[n-1].addr == h.addr && h.from <= out[n-1].to {
			out[n-1].to = max(out[n-1].to, h.to)
			continue
		}
		out = append(out, h)
	}
	return out
}
