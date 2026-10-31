package netmap

import (
	"bytes"
	"cmp"
	"context"
	"net"
	"net/netip"
	"slices"
	"strings"
	"time"

	"attmonitor/internal/model"
)

// maxAddrUses bounds the address history of a Devices view (NetDevicesView.Addresses): a
// household's month holds a few dozen tenures, a device whose address comes and goes at every
// Device List read some hundreds. Beyond the bound the tenures that ended first are left out.
const maxAddrUses = 5000

// maxDeviceV6 bounds the IPv6 addresses kept of each device for its details (the syslog terms):
// the gateway lists a device's global and link-local addresses, which change with its temporary
// addresses - a few a day. The newest are kept.
const maxDeviceV6 = 32

// Bounds of the Device List interval a device's details widen its IPv4 holds by (devReads.every):
// the default of connections.devices_interval stands in for a period whose reads are too few to
// tell it, and the interval is kept within the setting's limits.
const (
	defaultDevicesInterval = 15 * time.Minute
	minDevicesInterval     = 5 * time.Minute
	maxDevicesInterval     = 24 * time.Hour
)

// devReads is what the Device List reads of a Devices view's period say: about each device, by
// its key (stats); which device held each IPv4 address from which read to which (the tenures);
// which IPv4 addresses some read lists, of any device (named); and the namer of the LAN addresses
// of the period's dropped packets. The reads are those the connection store gives for the period
// (deviceHistory): the one in effect at its start - as a rule made before it - and every later one
// made before its end. All of them name addresses, and those made before its end make the address
// history and the devices' addresses, so that an address can be tied to the device that held it
// at the period's start; only those made in the period count as its reads.
type devReads struct {
	from, to int64 // the period, Unix nanoseconds
	reads    int   // the reads made in the period
	stats    map[string]*devStats
	named    map[netip.Addr]struct{}
	open     map[netip.Addr]map[string]*tenure // the tenures going on, by address and device key
	ended    []*tenure
	namer    *devNamer
	// macs are the MAC addresses the reads name (lower case, colon separated), each with its name
	// in the newest read that names it: a LAN scan's answer from another one is an unknown device's.
	macs map[string]string
	// at are the times of the reads (Unix nanoseconds, as they come): their interval (every).
	at []int64
	// v6 are the IPv6 addresses the reads give each device (by key), each with the newest read
	// that gave it: what its syslog messages may name it by.
	v6 map[string]map[netip.Addr]int64

	// A month holds thousands of reads of the same few dozen entries: what a read needs is kept
	// from one to the next - the identity of each entry as listed (ids), and the read's claims and
	// keys (claims, holding, listed), emptied at each read.
	ids     map[entryID]entryKeys
	claims  []claim
	holding []claim
	listed  map[string]bool
}

// entryID is what an entry's key and MAC address (entryKeys: lanDeviceKey, normMAC) depend on -
// but for an entry keyed by its IPv6 address, which is not cached.
type entryID struct{ mac, ipv4, name string }

type entryKeys struct{ key, mac string }

// devStats is what the reads say about one device.
type devStats struct {
	reads, onReads int   // the period's reads that listed it, and those that showed it on
	seen           int64 // the newest of them that showed it on (Unix nanoseconds; 0: none)
	// addrs are the IPv4 addresses it held, each with the newest read that showed it holding it.
	addrs map[netip.Addr]int64
}

// tenure is a device's hold on an IPv4 address: the reads from first to last that showed it with
// the address, without a read in between that showed another device with it alone.
type tenure struct {
	addr        netip.Addr
	key         string
	name, mac   string // as the newest of its reads gives them
	first, last int64
	reads       int
	shared      int // its reads in which another device claimed the address too, both of them on
}

func newDevReads(from, to time.Time) *devReads {
	return &devReads{from: nanos(from), to: nanos(to), stats: map[string]*devStats{}, named: map[netip.Addr]struct{}{},
		open: map[netip.Addr]map[string]*tenure{}, namer: newDevNamer(), ids: map[entryID]entryKeys{}, listed: map[string]bool{},
		macs: map[string]string{}, v6: map[string]map[netip.Addr]int64{}}
}

// keysOf returns the key and the MAC address of an entry, cached by what they depend on (at most
// maxAddrUses entries: a list of ever new entries is computed anew).
func (h *devReads) keysOf(d model.LANDevice) entryKeys {
	id := entryID{mac: d.MAC, ipv4: d.IPv4, name: d.Name}
	if k, ok := h.ids[id]; ok {
		return k
	}
	k := entryKeys{key: lanDeviceKey(d), mac: normMAC(d.MAC)}
	if _, v4 := deviceIPv4(d.IPv4); (k.mac != "" || v4 || len(d.IPv6) == 0) && len(h.ids) < maxAddrUses {
		h.ids[id] = k
	}
	return k
}

// stat returns the stats of the device key, adding them.
func (h *devReads) stat(key string) *devStats {
	st := h.stats[key]
	if st == nil {
		st = &devStats{addrs: map[netip.Addr]int64{}}
		h.stats[key] = st
	}
	return st
}

// claim is a Device List entry's claim on an IPv4 address in one read.
type claim struct {
	addr           netip.Addr
	key, name, mac string
	on             bool
}

// add takes a read made at at (they come oldest first). Where several entries of the read give
// the same IPv4 address, those that are on hold it - as in the connection store and the firewall
// view: the gateway keeps showing the last address of a device that left, which DHCP may have
// given to another one since - and when none is, every one of them does; two that are on claim it
// together (an address conflict: each tenure counts the read as shared). A read made at or after
// the period's end - the one in effect at its start when none was made before it - only names
// addresses.
func (h *devReads) add(at time.Time, devices []model.LANDevice) {
	t := nanos(at)
	h.namer.add(t, devices)
	h.at = append(h.at, t)
	inPeriod, after := t >= h.from && t < h.to, t >= h.to
	if inPeriod {
		h.reads++
	}
	h.claims = h.claims[:0]
	clear(h.listed) // the keys this read lists: true once shown on
	for _, d := range devices {
		k := h.keysOf(d)
		if k.mac != "" {
			if name := strings.TrimSpace(d.Name); name != "" || h.macs[k.mac] == "" {
				h.macs[k.mac] = name
			}
		}
		if k.key == "" {
			continue
		}
		if !after && len(d.IPv6) > 0 {
			h.addV6(k.key, d.IPv6, t)
		}
		on := isOn(d.Status)
		if inPeriod {
			st := h.stat(k.key)
			wasOn, was := h.listed[k.key]
			if !was {
				st.reads++
			}
			if on && !wasOn {
				st.onReads++
				st.seen = max(st.seen, t)
			}
			h.listed[k.key] = wasOn || on
		}
		if a, ok := deviceIPv4(d.IPv4); ok {
			h.named[a] = struct{}{}
			if !after {
				h.claims = append(h.claims, claim{addr: a, key: k.key, name: strings.TrimSpace(d.Name), mac: k.mac, on: on})
			}
		}
	}
	// By address, each address's claims in the order of the list.
	slices.SortStableFunc(h.claims, func(x, y claim) int { return x.addr.Compare(y.addr) })
	for i := 0; i < len(h.claims); {
		j := i + 1
		for j < len(h.claims) && h.claims[j].addr == h.claims[i].addr {
			j++
		}
		var on bool
		h.holding, on = holders(h.holding[:0], h.claims[i:j])
		h.hold(h.claims[i].addr, h.holding, t, on && len(h.holding) > 1)
		for _, c := range h.holding {
			st := h.stat(c.key)
			st.addrs[c.addr] = max(st.addrs[c.addr], t)
		}
		i = j
	}
}

// holders appends to out the claims that hold an address - those that are on (on), else all of
// them - each device once (an entry listed twice claims it once).
func holders(out, cs []claim) (_ []claim, on bool) {
	on = slices.ContainsFunc(cs, func(c claim) bool { return c.on })
	for _, c := range cs {
		if on && !c.on || slices.ContainsFunc(out, func(o claim) bool { return o.key == c.key }) {
			continue
		}
		out = append(out, c)
	}
	return out, on
}

// hold notes that the devices cs hold the address a in the read made at t: their tenures go on
// (or begin), and those of the other devices that held it end. conflict: several of them are on
// (two entries that are off and show the same address are the gateway's memory of devices that
// left, not a conflict).
func (h *devReads) hold(a netip.Addr, cs []claim, t int64, conflict bool) {
	cur := h.open[a]
	if cur == nil {
		cur = map[string]*tenure{}
		h.open[a] = cur
	}
	for key, tn := range cur {
		if !slices.ContainsFunc(cs, func(c claim) bool { return c.key == key }) {
			h.end(tn)
			delete(cur, key)
		}
	}
	for _, c := range cs {
		tn := cur[c.key]
		if tn == nil {
			tn = &tenure{addr: a, key: c.key, first: t}
			cur[c.key] = tn
		}
		tn.last = t
		tn.reads++
		if conflict {
			tn.shared++
		}
		if c.name != "" {
			tn.name = c.name
		}
		if c.mac != "" {
			tn.mac = c.mac
		}
	}
}

// end keeps a tenure that ended, within maxAddrUses (the newest ones) once it holds twice that.
func (h *devReads) end(tn *tenure) {
	h.ended = append(h.ended, tn)
	if len(h.ended) > 2*maxAddrUses {
		h.ended = newestTenures(h.ended, maxAddrUses)
	}
}

// newestTenures returns the n tenures that ended last (all of them when there are no more).
func newestTenures(ts []*tenure, n int) []*tenure {
	if len(ts) <= n {
		return ts
	}
	slices.SortFunc(ts, func(x, y *tenure) int {
		return cmp.Or(cmp.Compare(y.last, x.last), compareTenures(x, y))
	})
	return slices.Clip(ts[:n])
}

// compareTenures orders tenures by address, then their first read, then device.
func compareTenures(x, y *tenure) int {
	return cmp.Or(x.addr.Compare(y.addr), cmp.Compare(x.first, y.first), strings.Compare(x.key, y.key))
}

// history returns the address history: every tenure (the newest maxAddrUses), by address, then
// first read, then device.
func (h *devReads) history() []model.NetAddrUse {
	all := slices.Clone(h.ended)
	for _, cur := range h.open {
		for _, tn := range cur {
			all = append(all, tn)
		}
	}
	all = newestTenures(all, maxAddrUses)
	slices.SortFunc(all, compareTenures)
	out := make([]model.NetAddrUse, 0, len(all))
	for _, tn := range all {
		out = append(out, model.NetAddrUse{Addr: tn.addr.String(), Device: tn.key, Name: tn.name, MAC: tn.mac,
			First: rfc3339(time.Unix(0, tn.first)), Last: rfc3339(time.Unix(0, tn.last)), Reads: tn.reads, Shared: tn.shared})
	}
	return out
}

// addV6 notes the IPv6 addresses a read made at t gives the device key: at most maxDeviceV6 of
// them are kept, those given last (trimmed once it holds twice that).
func (h *devReads) addV6(key string, addrs []string, t int64) {
	m := h.v6[key]
	if m == nil {
		m = map[netip.Addr]int64{}
		h.v6[key] = m
	}
	for _, s := range addrs {
		if a, ok := lanAddr(s); ok && a.Is6() {
			a = a.WithZone("")
			m[a] = max(m[a], t)
		}
	}
	if len(m) > 2*maxDeviceV6 {
		for _, a := range sortedV6(m)[maxDeviceV6:] {
			delete(m, a)
		}
	}
}

// ipv6 returns the IPv6 addresses the reads gave the device key, those given last first (at most
// maxDeviceV6).
func (h *devReads) ipv6(key string) []netip.Addr {
	as := sortedV6(h.v6[key])
	return slices.Clip(as[:min(len(as), maxDeviceV6)])
}

// sortedV6 returns the addresses of m, those given last first (then by address).
func sortedV6(m map[netip.Addr]int64) []netip.Addr {
	as := make([]netip.Addr, 0, len(m))
	for a := range m {
		as = append(as, a)
	}
	slices.SortFunc(as, func(x, y netip.Addr) int { return cmp.Or(cmp.Compare(m[y], m[x]), x.Compare(y)) })
	return as
}

// every is how often the Device List was read: the median time between the reads (as they came),
// within the setting's limits; defaultDevicesInterval when there are fewer than two.
func (h *devReads) every() time.Duration {
	var gaps []int64
	for i := 1; i < len(h.at); i++ {
		if d := h.at[i] - h.at[i-1]; d > 0 {
			gaps = append(gaps, d)
		}
	}
	if len(gaps) == 0 {
		return defaultDevicesInterval
	}
	slices.Sort(gaps)
	return min(max(time.Duration(gaps[len(gaps)/2]), minDevicesInterval), maxDevicesInterval)
}

// macNamed reports whether a read names the MAC address mac (as normMAC writes it).
func (h *devReads) macNamed(mac string) bool {
	_, ok := h.macs[mac]
	return ok
}

// addresses returns the IPv4 addresses the device key held, the newest first.
func (h *devReads) addresses(key string) []string {
	st := h.stats[key]
	if st == nil || len(st.addrs) == 0 {
		return nil
	}
	as := make([]netip.Addr, 0, len(st.addrs))
	for a := range st.addrs {
		as = append(as, a)
	}
	slices.SortFunc(as, func(x, y netip.Addr) int { return cmp.Or(cmp.Compare(st.addrs[y], st.addrs[x]), x.Compare(y)) })
	out := make([]string, len(as))
	for i, a := range as {
		out[i] = a.String()
	}
	return out
}

// deviceReads reads the Device List reads of [from, to): through the connection store's
// EachDevices when it has it (deviceHistory), else - or when they cannot be read - its newest read
// alone (list, made at listAt). It fails only when ctx ends.
func (v *View) deviceReads(ctx context.Context, from, to time.Time, list []model.LANDevice, listAt time.Time) (*devReads, error) {
	if hist, ok := v.conns.(deviceHistory); ok {
		h := newDevReads(from, to)
		err := hist.EachDevices(ctx, from, to, func(at time.Time, devices []model.LANDevice) error {
			h.add(at, devices)
			return nil
		})
		if err == nil {
			h.namer.sort()
			v.devWarned.history = false
			return h, nil
		}
		if cerr := ctx.Err(); cerr != nil {
			return nil, cerr
		}
		if !v.devWarned.history {
			v.devWarned.history = true
			v.log.Warn("network view: the Device List reads of the period cannot be read; the Devices tab shows the newest read alone",
				"err", err)
		}
	}
	h := newDevReads(from, to)
	if list != nil {
		h.add(listAt, list)
	}
	return h, nil
}

// lanDeviceKey is the key of a Device List entry (model.NetLANDevice.Key): "mac:<mac>"; for an
// entry without a MAC address "ip:" and its IPv4 address, else its first IPv6 address - as the
// connection store and the firewall view key such an entry - else "name:" and its name; "" for an
// entry that gives none of these.
func lanDeviceKey(d model.LANDevice) string {
	if mac := normMAC(d.MAC); mac != "" {
		return "mac:" + mac
	}
	if a, ok := deviceIPv4(d.IPv4); ok {
		return "ip:" + a.String()
	}
	for _, s := range d.IPv6 {
		if a, ok := lanAddr(s); ok {
			return "ip:" + a.WithZone("").String()
		}
	}
	if name := strings.TrimSpace(d.Name); name != "" {
		return "name:" + name
	}
	return ""
}

// normMAC returns a MAC address in the form of its device key (lower case, colon separated), ""
// when s is not one.
func normMAC(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	hw, err := net.ParseMAC(s)
	if err != nil || bytes.Equal(hw, make([]byte, len(hw))) {
		return ""
	}
	return hw.String()
}

// deviceIPv4 parses a Device List entry's IPv4 address.
func deviceIPv4(s string) (netip.Addr, bool) {
	a, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil {
		return netip.Addr{}, false
	}
	a = a.Unmap()
	return a, a.Is4()
}

// isOn and isOff report whether a Device List status is "on" or "off".
func isOn(status string) bool  { return strings.EqualFold(strings.TrimSpace(status), "on") }
func isOff(status string) bool { return strings.EqualFold(strings.TrimSpace(status), "off") }

// lanCandidate reports whether a LAN address of the NAT samples or of the firewall's drops that
// no Device List read names is an unknown device's (model.NetUnknownAddr): an IPv4 address of a
// home network - private (RFC 1918), or link-local (169.254.0.0/16: the address a device gives
// itself when it gets none by DHCP). An IPv6 address is not: a device's temporary addresses are
// never listed, and a scan of the home network's prefix tries addresses no device has.
func lanCandidate(a netip.Addr) bool {
	a = a.Unmap()
	return a.Is4() && (a.IsPrivate() || a.IsLinkLocalUnicast())
}
