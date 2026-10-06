package connstore

import (
	"cmp"
	"encoding/binary"
	"hash/fnv"
	"net"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"time"

	"attmonitor/internal/model"
)

// identity is what a Device List read says about the device behind a LAN address.
type identity struct {
	// key identifies the device across address changes: "mac:<mac>", or "ip:<address>" when the
	// entry gives no MAC address.
	key  string
	name string
	mac  string
	conn string
}

// devRead is one Device List read as the aggregation uses it.
type devRead struct {
	t    int64  // its time, Unix nanoseconds
	hash uint64 // FNV-1a of its line: with t, its identity in a summary's fingerprint
	// addrs are the LAN addresses it lists, sorted, each with the device it belonged to.
	addrs []addrEntry
	// nets are the /64 networks of the global IPv6 addresses it lists: the home network's IPv6
	// prefix, in which a device's other addresses (its temporary ones) are too.
	nets []netip.Prefix
}

// addrEntry is one address of a Device List read.
type addrEntry struct {
	addr netip.Addr
	id   *identity
}

// newDevRead indexes a Device List read by address: each device's IPv4 address and its IPv6
// addresses. When two entries give the same address, an entry whose status is "on" wins over
// one that is not (the gateway keeps showing the last address of a device that left, which DHCP
// may have given to another device since), then the one listed first. intern shares identical
// identities between the reads of a day.
func newDevRead(t time.Time, hash uint64, devices []model.LANDevice, intern map[identity]*identity) *devRead {
	type candidate struct {
		id *identity
		on bool
	}
	best := map[netip.Addr]candidate{}
	for _, d := range devices {
		mac := normMAC(d.MAC)
		on := strings.EqualFold(strings.TrimSpace(d.Status), "on")
		for _, s := range append([]string{d.IPv4}, d.IPv6...) {
			a, ok := parseDeviceAddr(s)
			if !ok {
				continue
			}
			id := identity{key: "mac:" + mac, name: strings.TrimSpace(d.Name), mac: mac, conn: strings.TrimSpace(d.Connection)}
			if mac == "" {
				id.key = "ip:" + a.String()
			}
			p := intern[id]
			if p == nil {
				p = &id
				intern[id] = p
			}
			if c, seen := best[a]; !seen || on && !c.on {
				best[a] = candidate{id: p, on: on}
			}
		}
	}
	r := &devRead{t: t.UnixNano(), hash: hash, addrs: make([]addrEntry, 0, len(best))}
	for a, c := range best {
		r.addrs = append(r.addrs, addrEntry{addr: a, id: c.id})
		if a.Is6() && a.IsGlobalUnicast() && !isLocal(a) {
			if p, err := a.Prefix(64); err == nil && !slices.Contains(r.nets, p) {
				r.nets = append(r.nets, p)
			}
		}
	}
	slices.SortFunc(r.addrs, func(x, y addrEntry) int { return x.addr.Compare(y.addr) })
	return r
}

// lookup returns the device a read lists at address a (nil when it lists none).
func (r *devRead) lookup(a netip.Addr) *identity {
	i, ok := slices.BinarySearchFunc(r.addrs, a, func(e addrEntry, a netip.Addr) int { return e.addr.Compare(a) })
	if !ok {
		return nil
	}
	return r.addrs[i].id
}

// lan reports whether the read (nil: none) tells that a, an address that is not local by itself
// (isLocal), is one of the home network's: it lists a, or a is an IPv6 address in the /64 of a
// global address it lists. A device's global IPv6 addresses are public addresses - a session from
// one would otherwise be taken for the gateway's own, and one to it would make the household's
// own address a remote site.
func (r *devRead) lan(a netip.Addr) bool {
	if r == nil {
		return false
	}
	if r.lookup(a) != nil {
		return true
	}
	if a.Is6() {
		for _, p := range r.nets {
			if p.Contains(a) {
				return true
			}
		}
	}
	return false
}

// normMAC returns a MAC address in the form of its device key (lower case, colon separated), or
// "" when s is not one.
func normMAC(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	hw, err := net.ParseMAC(s)
	if err != nil {
		return ""
	}
	return hw.String()
}

// hashLine returns the FNV-1a hash of a stored line.
func hashLine(line []byte) uint64 {
	h := fnv.New64a()
	h.Write(line)
	return h.Sum64()
}

// devKey is the cache key of the Device List reads of a day: the stamps of its files.
type devKey struct {
	day       day
	gz, plain fileStamp
}

func (k devKey) keyDay() day { return k.day }

// devDay returns the Device List reads of day d, oldest first (reads of the same time in the
// order of the files), from the cache when the day's files did not change. Lines that cannot be
// read are skipped and logged; nil when the store no longer has the day.
func (s *Store) devDay(d day) ([]*devRead, error) {
	if gz, plain, ok := s.dayStamps(kindDevices, d); ok {
		if v, hit := s.devs.get(devKey{day: d, gz: gz, plain: plain}); hit {
			return v, nil
		}
	}
	r, err := s.openDay(kindDevices, d)
	if err != nil || r == nil {
		return nil, err
	}
	defer r.close()
	intern := map[identity]*identity{}
	var reads []*devRead
	bad, foreign := 0, 0
	damage, _ := r.each(func(line []byte) error {
		t, devices, err := decodeDevices(line)
		switch {
		case line == nil || err != nil:
			bad++
		case dayOf(t) != d:
			foreign++
		default:
			reads = append(reads, newDevRead(t, hashLine(line), devices, intern))
		}
		return nil
	})
	s.noteReadProblems(kindDevices, d, damage, bad, 0, foreign)
	slices.SortStableFunc(reads, func(a, b *devRead) int { return cmp.Compare(a.t, b.t) })
	// Only the newest version of a day's files is read again: today's file changes with every
	// append, and its older versions would crowd the other days out.
	s.devs.removeIf(func(k devKey) bool { return k.day == d })
	s.devs.put(devKey{day: d, gz: r.gzStamp, plain: r.plainStamp}, reads, 1)
	return reads, nil
}

// segment is the Device List reads that name the LAN addresses of the NAT reads of one day: the
// newest read before the day, or - when the store has none - the first read after the day's
// start; and the reads of the day. fp is their fingerprint: a summary of the day computed with
// other reads (one added later, or the read before the day pruned) is not used.
type segment struct {
	reads []*devRead // oldest first
	fp    uint64
}

// devNextWithin is how much later than a NAT read the next Device List read may come and still
// name the read's addresses that the read in effect does not list (segment.after): the Device
// List is read every connections.devices_interval (15 minutes by default), and a device that has
// just joined is most likely the one that read lists at its address.
const devNextWithin = 20 * time.Minute

// after returns the first Device List read after t, when it comes within devNextWithin (nil
// otherwise).
func (sg *segment) after(t int64) *devRead {
	i := sort.Search(len(sg.reads), func(i int) bool { return sg.reads[i].t > t })
	if i < len(sg.reads) && sg.reads[i].t-t <= int64(devNextWithin) {
		return sg.reads[i]
	}
	return nil
}

// at returns the Device List read in effect at t: the newest at or before t, else the first
// after it (nil without any).
func (sg *segment) at(t int64) *devRead {
	i := sort.Search(len(sg.reads), func(i int) bool { return sg.reads[i].t > t })
	if i > 0 {
		return sg.reads[i-1]
	}
	if len(sg.reads) > 0 {
		return sg.reads[0]
	}
	return nil
}

// devView gives one query the Device List reads it needs, day by day, loading each day once.
type devView struct {
	s    *Store
	days []day // the days with Device List files, oldest first
	memo map[day][]*devRead
}

// newDevView returns the view of the Device List days of a snapshot.
func newDevView(s *Store, sn *snapshot) *devView {
	v := &devView{s: s, memo: map[day][]*devRead{}}
	for _, e := range sn.days[kindDevices] {
		v.days = append(v.days, e.day)
	}
	return v
}

// reads returns the reads of day d; a day that cannot be read is logged and has none.
func (v *devView) reads(d day) []*devRead {
	if rs, ok := v.memo[d]; ok {
		return rs
	}
	rs, err := v.s.devDay(d)
	if err != nil {
		v.s.warnOnce(fileName(kindDevices, d, false), "connection store: a day of Device List reads cannot be read; its devices are not named", "err", err)
	}
	v.memo[d] = rs
	return rs
}

// segment returns the segment of the NAT day d.
func (v *devView) segment(d day) *segment {
	i, _ := slices.BinarySearch(v.days, d)
	var carry *devRead
	for j := i - 1; j >= 0 && carry == nil; j-- {
		if rs := v.reads(v.days[j]); len(rs) > 0 {
			carry = rs[len(rs)-1]
		}
	}
	sg := &segment{}
	if carry != nil {
		sg.reads = append(sg.reads, carry)
	}
	if i < len(v.days) && v.days[i] == d {
		sg.reads = append(sg.reads, v.reads(d)...)
	}
	if len(sg.reads) == 0 {
		// No read before or during the day: the NAT reads are named after the first one later.
		for j := i; j < len(v.days); j++ {
			if rs := v.reads(v.days[j]); len(rs) > 0 {
				sg.reads = append(sg.reads, rs[0])
				break
			}
		}
	}
	h := fnv.New64a()
	var b [16]byte
	for _, r := range sg.reads {
		binary.LittleEndian.PutUint64(b[:8], uint64(r.t))
		binary.LittleEndian.PutUint64(b[8:], r.hash)
		h.Write(b[:])
	}
	sg.fp = h.Sum64()
	return sg
}
