package netmap

import (
	"bytes"
	"cmp"
	"context"
	"maps"
	"net/netip"
	"slices"
	"strings"
	"time"

	"attmonitor/internal/model"
)

// deviceHistory is a connection store that can give the Device List reads of a period. The
// firewall view then names the LAN address of each dropped outbound packet after the read in
// effect when the packet was received - the newest read at or before it, else the first after
// it - as the connection store names the LAN addresses of each NAT read (connstore.Store gives
// them: EachDevices). A store without it (contracts.ConnStore has only Devices, the newest read)
// has every packet named after its newest read, which names an address after the device that
// holds it now: a device that held it before DHCP gave it to another one would be blamed for the
// other's packets.
type deviceHistory interface {
	// EachDevices calls fn, oldest first, with the Device List read in effect at from - the
	// newest made at or before it, else the first made after it - and with every read made in
	// [from, to), each with the time it was made. fn's error ends it and is returned.
	EachDevices(ctx context.Context, from, to time.Time, fn func(at time.Time, devices []model.LANDevice) error) error
}

// devNamer names the LAN addresses of the outbound drops of a request after the Device List
// reads of its period: a drop after the read in effect when it was received. Each device has a
// number - the same in every read, by its key - and number 0 stands for an address that no read
// in effect names: it is named after itself ("ip:<address>").
type devNamer struct {
	reads []namedRead // oldest first
	devs  []namedDev  // by number; devs[0] is unused
	byKey map[string]int32
}

// namedRead is one Device List read: when it was made, and the device number of each address.
type namedRead struct {
	at    int64 // Unix nanoseconds
	addrs map[[16]byte]int32
}

// namedDev is a device of the Device List reads: its key ("mac:<mac>", or "ip:<address>" for one
// without a MAC address) and its name in the newest read that names it ("" when it has none: a
// row then names it after its address).
type namedDev struct {
	key, name string
}

func newDevNamer() *devNamer {
	return &devNamer{devs: []namedDev{{}}, byKey: map[string]int32{}}
}

// add adds a read made at (Unix nanoseconds). Where two devices claim an address, the first that
// is on wins, as in the connection store. A read that names every address as the read before it
// does is not kept apart.
func (n *devNamer) add(at int64, devices []model.LANDevice) {
	addrs := map[[16]byte]int32{}
	claimed := map[[16]byte]model.LANDevice{}
	claim := func(s string, d model.LANDevice) {
		a, ok := lanAddr(s)
		if !ok {
			return
		}
		k := a.As16()
		if had, taken := claimed[k]; !taken || !strings.EqualFold(had.Status, "on") && strings.EqualFold(d.Status, "on") {
			claimed[k] = d
		}
	}
	for _, d := range devices {
		if d.IPv4 != "" {
			claim(d.IPv4, d)
		}
	}
	for _, d := range devices {
		for _, s := range d.IPv6 {
			claim(s, d)
		}
	}
	// By address, so that the numbers do not depend on the order of a map.
	for _, k := range slices.SortedFunc(maps.Keys(claimed), func(x, y [16]byte) int { return bytes.Compare(x[:], y[:]) }) {
		d := claimed[k]
		key := "ip:" + netip.AddrFrom16(k).Unmap().String()
		if d.MAC != "" {
			key = "mac:" + strings.ToLower(d.MAC)
		}
		num, ok := n.byKey[key]
		if !ok {
			num = int32(len(n.devs))
			n.byKey[key] = num
			n.devs = append(n.devs, namedDev{key: key})
		}
		addrs[k] = num
		n.devs[num].name = d.Name // the newest read's name (reads come oldest first)
	}
	if last := len(n.reads) - 1; last >= 0 && n.reads[last].at <= at && maps.Equal(n.reads[last].addrs, addrs) {
		return
	}
	n.reads = append(n.reads, namedRead{at: at, addrs: addrs})
}

// lanAddr parses a Device List address ("192.168.1.64", "2001:db8::1", or one with a prefix
// length), IPv4-mapped addresses as IPv4.
func lanAddr(s string) (netip.Addr, bool) {
	s = strings.TrimSpace(s)
	a, err := netip.ParseAddr(s)
	if err != nil {
		p, perr := netip.ParsePrefix(s)
		if perr != nil {
			return netip.Addr{}, false
		}
		a = p.Addr()
	}
	return a.Unmap(), true
}

// sort orders the reads by time, should a store give them in another order.
func (n *devNamer) sort() {
	slices.SortStableFunc(n.reads, func(x, y namedRead) int { return cmp.Compare(x.at, y.at) })
}

// device returns the number of the device whose address lan was at rx (Unix nanoseconds) in the
// read in effect then (0 when that read does not name it, or without reads).
func (n *devNamer) device(lan [16]byte, rx int64) int32 {
	if n == nil || len(n.reads) == 0 {
		return 0
	}
	i, _ := slices.BinarySearchFunc(n.reads, rx, func(r namedRead, t int64) int {
		if r.at <= t {
			return -1
		}
		return 1
	})
	// reads[i-1] is the newest read at or before rx; before the first read, the first one.
	return n.reads[max(i-1, 0)].addrs[lan]
}

// describe returns the key and the name of the device numbered num at the address lan: the
// Device List's key ("mac:<mac>", else "ip:<address>") and name (else the address).
func (n *devNamer) describe(num int32, lan netip.Addr) (key, name string) {
	addr := lan.String()
	if n == nil || num <= 0 || int(num) >= len(n.devs) {
		return "ip:" + addr, addr
	}
	d := n.devs[num]
	name = d.name
	if name == "" {
		name = addr
	}
	return d.key, name
}

// sameKeys counts the devices among named whose key is that of an address among self: a device
// without a MAC address ("ip:<address>") that the reads in effect at some times name, and not at
// others. Its rows name it alike either way, so it counts as one device.
func (n *devNamer) sameKeys(named map[int32]struct{}, self map[[16]byte]struct{}) int {
	if n == nil || len(self) == 0 {
		return 0
	}
	same := 0
	for num := range named {
		if num <= 0 || int(num) >= len(n.devs) {
			continue
		}
		if s, ok := strings.CutPrefix(n.devs[num].key, "ip:"); ok {
			if a, err := netip.ParseAddr(s); err == nil {
				if _, in := self[a.As16()]; in {
					same++
				}
			}
		}
	}
	return same
}

// devNames returns the namer of the LAN devices of [from, to): after the connection store's
// Device List reads of the period when it can give them (deviceHistory), else after its newest
// read; nil without a connection store. It runs in the firewall slot (View.namesWarned).
func (v *View) devNames(ctx context.Context, from, to time.Time) *devNamer {
	if v.conns == nil {
		return nil
	}
	if h, ok := v.conns.(deviceHistory); ok {
		n := newDevNamer()
		err := h.EachDevices(ctx, from, to, func(at time.Time, devices []model.LANDevice) error {
			n.add(nanos(at), devices)
			return nil
		})
		if err == nil {
			n.sort()
			return n
		}
		if ctx.Err() == nil && !v.namesWarned {
			v.namesWarned = true
			v.log.Warn("network view: the Device List reads of the period cannot be read; the firewall view names the LAN devices after the newest read",
				"err", err)
		}
	}
	n := newDevNamer()
	devs, at := v.conns.Devices()
	n.add(nanos(at), devs)
	return n
}
