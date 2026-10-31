package netmap

import (
	"cmp"
	"context"
	"net/netip"
	"slices"
	"strings"
	"time"

	"attmonitor/internal/model"
)

// The LAN scans in the Devices view (docs/dhcp-table.md §6): the period's scans, which device
// answered them at which address, and the addresses that answered with a MAC address no Device List
// read of the period names.

const (
	// maxDetailScans bounds the scans a device's details list (NetDeviceDetail.Scans): the newest. A
	// month of hourly scans is 744.
	maxDetailScans = 800
	// maxScanHosts bounds the answers of one scan that are read: a scan asks at most 1,024
	// addresses (a /22), so a scan that holds more is not the scanner's.
	maxScanHosts = 4096
	// scanFresh is how far apart the newest scan and the newest Device List read may be for the
	// issues that compare them (no_answer, scan_mac, scan_addr): a scan farther from the read would
	// compare the network with a list of another time.
	scanFresh = time.Hour
	// maxMACCache bounds the MAC addresses whose normal form a request remembers.
	maxMACCache = 4096
)

// scanAnswer is an address that answered a scan and the MAC address that answered for it (as
// normMAC writes it; "" when it is not a valid one).
type scanAnswer struct {
	addr netip.Addr
	mac  string
}

// scanHit is a device's answer to one scan: the scan (its index) and the address it answered at.
type scanHit struct {
	scan int32
	addr [4]byte
}

// devScan adds up a listed device's answers to the period's scans.
type devScan struct {
	hits  int       // the scans it answered
	seen  int64     // when the newest of them began (Unix nanoseconds; set when hits > 0)
	last  int32     // the index of the scan it answered last (-1: none)
	trail []scanHit // its answers, as they came (at most 2*maxDetailScans: the last)
}

// unkScan adds up an unknown address's answers to the period's scans.
type unkScan struct {
	hits        int
	first, last int64   // when the first and the last of them began (Unix nanoseconds)
	at          int64   // when the newest of them began
	mac         string  // the MAC address that answered it then
	trail       []int32 // the scans' indices, as they came (at most 2*maxDetailScans: the last)
}

// lanScans is what the period's LAN scans say (devAssembly.addScans).
type lanScans struct {
	at     []int64           // by scan index (the order they came in): when each began, Unix nanoseconds
	newest int               // the index of the newest scan (-1: none)
	info   model.NetScanInfo // the newest scan, summed up
	hosts  []scanAnswer      // the newest scan's answers, in address order
	dev    []devScan         // by index in devAssembly.devices
	unk    map[netip.Addr]*unkScan
	macs   map[string]string // MAC addresses as the scans give them → normMAC (a cache)
}

// newLANScans returns the sums of the scans for n listed devices.
func newLANScans(n int) *lanScans {
	s := &lanScans{newest: -1, dev: make([]devScan, n), unk: map[netip.Addr]*unkScan{}, macs: map[string]string{}}
	for i := range s.dev {
		s.dev[i].last = -1
	}
	return s
}

// addScans reads the period's LAN scans (a.eachScan; nil: there are none) and gives each answer to
// the device it came from - by its MAC address, or for an entry without one by its address in the
// Device List read in effect at the scan (else the next read within devNextWithin) - else, when no
// Device List read of the period names its MAC address, to the unknown address; an answer from the
// gateway's own address, or from a device of the period's reads that the newest read no longer
// lists, is neither's. A failure other than ctx's leaves no scan figures at all (it is kept in
// a.scanErr) and the view goes on without them; ctx's ends the build.
func (a *devAssembly) addScans(ctx context.Context) error {
	if a.eachScan == nil {
		return nil
	}
	s := newLANScans(len(a.devices))
	listed := make([]netip.Addr, len(a.devices)) // the IPv4 address each device is listed with
	for i, d := range a.devices {
		listed[i], _ = deviceIPv4(d.IPv4)
	}
	from, to := nanos(a.from), nanos(a.to)
	err := a.eachScan(ctx, func(sc model.LANScan) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		a.addScan(s, sc, listed, from, to)
		return nil
	})
	if err != nil {
		if cerr := ctx.Err(); cerr != nil {
			return cerr
		}
		a.scanErr = err
		return nil
	}
	a.scan = s
	for i := range a.devices {
		d, nd := &s.dev[i], &a.devices[i]
		if d.hits == 0 {
			continue
		}
		nd.ScanHits = d.hits
		nd.ScanSeen = rfc3339(time.Unix(0, d.seen))
		if h, ok := d.answer(int32(s.newest)); ok {
			nd.ScanAddr = netip.AddrFrom4(h.addr).String()
		}
	}
	for addr, us := range s.unk {
		u := a.unknownScanAt(addr)
		_, u.named = a.reads.named[addr]
		u.scanHits = us.hits
		u.scanTrail = us.trail
		u.u.MAC = us.mac
		u.u.ScanSeen = rfc3339(time.Unix(0, us.at))
		u.seen(time.Unix(0, us.first))
		u.seen(time.Unix(0, us.last))
	}
	return nil
}

// addScan adds one scan: one that began outside [from, to) (Unix nanoseconds), or at a time that
// does not parse, is not the period's.
func (a *devAssembly) addScan(s *lanScans, sc model.LANScan, listed []netip.Addr, from, to int64) {
	t, ok := parseRX(sc.At)
	if !ok || t < from || t >= to {
		return
	}
	idx := int32(len(s.at))
	s.at = append(s.at, t)
	answers := s.answers(sc.Hosts)
	if s.newest < 0 || t >= s.at[s.newest] {
		s.newest = int(idx)
		s.hosts = answers
		s.info = model.NetScanInfo{At: rfc3339(time.Unix(0, t)), Subnet: sc.Subnet, Asked: sc.Asked, Answered: len(answers),
			TookMs: sc.TookMs, Problem: sc.Problem}
	}
	for _, an := range answers {
		if a.gateway.IsValid() && an.addr == a.gateway {
			continue // the gateway itself
		}
		if an.mac != "" {
			if i, ok := a.byMAC[an.mac]; ok {
				s.dev[i].hit(idx, t, an.addr, listed[i])
				continue
			}
			if a.reads.macNamed(an.mac) {
				continue // a device of the period that the newest read no longer lists
			}
		}
		if i, ok := a.macLessAt(an.addr, t); ok {
			if i >= 0 {
				s.dev[i].hit(idx, t, an.addr, listed[i])
			}
			continue // an entry without a MAC address (when i < 0, one the newest read no longer lists)
		}
		if lanCandidate(an.addr) {
			s.unknown(an.addr, idx, t, an.mac, a.lans)
		}
	}
}

// answers returns the answers of a scan that can be read - an IPv4 address, each once (its first
// answer) - in address order, with their MAC addresses as normMAC writes them; at most
// maxScanHosts.
func (s *lanScans) answers(hosts []model.LANHost) []scanAnswer {
	out := make([]scanAnswer, 0, min(len(hosts), maxScanHosts))
	for _, h := range hosts[:min(len(hosts), maxScanHosts)] {
		a, err := netip.ParseAddr(strings.TrimSpace(h.IP))
		if err != nil || !a.Unmap().Is4() {
			continue
		}
		out = append(out, scanAnswer{addr: a.Unmap(), mac: s.normMAC(h.MAC)})
	}
	slices.SortStableFunc(out, func(x, y scanAnswer) int { return x.addr.Compare(y.addr) })
	return slices.CompactFunc(out, func(x, y scanAnswer) bool { return x.addr == y.addr })
}

// normMAC is normMAC, remembered for the MAC addresses seen (at most maxMACCache).
func (s *lanScans) normMAC(raw string) string {
	if m, ok := s.macs[raw]; ok {
		return m
	}
	m := normMAC(raw)
	if len(s.macs) < maxMACCache {
		s.macs[raw] = m
	}
	return m
}

// hit notes that the device answered the scan idx (begun at t) at addr; of several addresses it
// answered one scan at, the one it is listed with is kept, else the first (the lowest).
func (d *devScan) hit(idx int32, t int64, addr, listed netip.Addr) {
	a4 := addr.As4()
	if d.last == idx {
		if addr == listed {
			d.trail[len(d.trail)-1].addr = a4
		}
		return
	}
	d.last = idx
	if d.hits == 0 || t > d.seen {
		d.seen = t
	}
	d.hits++
	d.trail = append(d.trail, scanHit{scan: idx, addr: a4})
	if len(d.trail) > 2*maxDetailScans {
		d.trail = slices.Clone(d.trail[len(d.trail)-maxDetailScans:])
	}
}

// answer returns the device's answer to the scan idx (false when it did not answer it).
func (d *devScan) answer(idx int32) (scanHit, bool) {
	for i := len(d.trail) - 1; i >= 0; i-- {
		if d.trail[i].scan == idx {
			return d.trail[i], true
		}
	}
	return scanHit{}, false
}

// unknown notes that addr answered the scan idx (begun at t) from mac, for an address that is no
// listed device's: at most bound such addresses are counted (0: no bound), the first seen.
func (s *lanScans) unknown(addr netip.Addr, idx int32, t int64, mac string, bound int) {
	u := s.unk[addr]
	if u == nil {
		if bound > 0 && len(s.unk) >= bound {
			return
		}
		u = &unkScan{first: t, last: t, at: t, mac: mac}
		s.unk[addr] = u
	} else if len(u.trail) > 0 && u.trail[len(u.trail)-1] == idx {
		return
	}
	u.hits++
	u.first, u.last = min(u.first, t), max(u.last, t)
	if t >= u.at {
		u.at, u.mac = t, mac
	}
	u.trail = append(u.trail, idx)
	if len(u.trail) > 2*maxDetailScans {
		u.trail = slices.Clone(u.trail[len(u.trail)-maxDetailScans:])
	}
}

// macLessAt reports whether an answer at addr at t (Unix nanoseconds) is that of an entry without a
// MAC address: the Device List read in effect then (else the next read within devNextWithin) gives
// addr to such an entry. i is the index of that entry among the listed devices, -1 when the newest
// read no longer lists it.
func (a *devAssembly) macLessAt(addr netip.Addr, t int64) (i int, ok bool) {
	num := a.reads.namer.deviceOrNext(addr.As16(), t)
	if num <= 0 {
		return 0, false
	}
	key, _ := a.reads.namer.describe(num, addr)
	if !strings.HasPrefix(key, "ip:") {
		return 0, false
	}
	if j, listed := a.owner[key]; listed && a.devices[j].MAC == "" {
		return j, true
	}
	return -1, true
}

// unknownScanAt returns the unknown address addr - adding it - for an answer to a scan: the
// address may be one a Device List read names (the MAC address that answered is what no read
// names).
func (a *devAssembly) unknownScanAt(addr netip.Addr) *unknownAcc {
	u := a.unknown[addr]
	if u == nil {
		u = &unknownAcc{u: model.NetUnknownAddr{Addr: addr.String()}, sites: distinct{exact: a.exact}}
		a.unknown[addr] = u
	}
	return u
}

// answerAt returns the newest scan's answer at addr (false when none).
func (s *lanScans) answerAt(addr netip.Addr) (scanAnswer, bool) {
	i, ok := slices.BinarySearchFunc(s.hosts, addr, func(an scanAnswer, a netip.Addr) int { return an.addr.Compare(a) })
	if !ok {
		return scanAnswer{}, false
	}
	return s.hosts[i], true
}

// scanIssues returns the issues of the device i that compare the newest Device List read with the
// newest LAN scan, when the scan began within scanFresh of the read: no_answer (it is shown on, its
// IPv4 address lies in the network swept and the sweep asked every address, yet it did not answer),
// scan_addr (it answered at another IPv4 address than it is listed with) and scan_mac (it is shown
// on, and another MAC address answered for its IPv4 address).
func (a *devAssembly) scanIssues(i int) []model.NetIssue {
	s := a.scan
	if s == nil || s.newest < 0 || a.list == nil || a.listAt.IsZero() {
		return nil
	}
	at := time.Unix(0, s.at[s.newest])
	if d := at.Sub(a.listAt); d > scanFresh || d < -scanFresh {
		return nil
	}
	d := a.devices[i]
	ip, hasIP := deviceIPv4(d.IPv4)
	var out []model.NetIssue
	switch {
	case d.ScanAddr == "":
		if isOn(d.Status) && hasIP && s.info.Problem == "" && inSubnet(ip, s.info.Subnet) {
			out = append(out, noAnswerIssue(at, a.listAt))
		}
	case d.MAC != "" && d.ScanAddr != d.IPv4:
		out = append(out, scanAddrIssue(d.ScanAddr, d.IPv4))
	}
	if d.MAC != "" && hasIP && isOn(d.Status) {
		if an, ok := s.answerAt(ip); ok && an.mac != "" && an.mac != d.MAC && !(a.gateway.IsValid() && ip == a.gateway) {
			out = append(out, a.scanMACIssue(d.IPv4, an.mac))
		}
	}
	return out
}

// scanMACIssue is the issue scan_mac of a device listed at addr, which the newest scan found
// answered by mac: named after the device of the newest read with that MAC address, else after
// the one an earlier read of the period named.
func (a *devAssembly) scanMACIssue(addr, mac string) model.NetIssue {
	if j, ok := a.byMAC[mac]; ok {
		o := a.devices[j]
		return scanMACIssue(addr, mac, &o, "", true)
	}
	name, named := a.reads.macs[mac]
	return scanMACIssue(addr, mac, nil, name, named)
}

// inSubnet reports whether the network subnet ("192.168.1.0/24", as a scan states it) holds a
// (false when subnet is not a network).
func inSubnet(a netip.Addr, subnet string) bool {
	p, err := netip.ParsePrefix(strings.TrimSpace(subnet))
	return err == nil && p.Contains(a)
}

// scanDetail is what a device's details need of the period's scans (devBuild.scans): the newest
// maxDetailScans scans, and each listed device's and each unknown address's answers to them.
type scanDetail struct {
	at  []int64                 // when each began (Unix nanoseconds), the newest first
	dev map[string][]scanHit    // by device key: its answers (scan: the position in at), the newest first
	unk map[netip.Addr][]uint64 // by unknown address: the scans it answered, a bit per position in at
}

// scanDetail returns the scans as the details list them (nil without scans). It is called before
// the devices are sorted: s.dev follows a.devices.
func (a *devAssembly) scanDetail() *scanDetail {
	s := a.scan
	if s == nil || len(s.at) == 0 {
		return nil
	}
	order := make([]int32, len(s.at))
	for i := range order {
		order[i] = int32(i)
	}
	slices.SortStableFunc(order, func(x, y int32) int { return cmp.Or(cmp.Compare(s.at[y], s.at[x]), cmp.Compare(y, x)) })
	order = order[:min(len(order), maxDetailScans)]
	pos := make([]int32, len(s.at)) // scan index → position in sd.at (-1: not listed)
	for i := range pos {
		pos[i] = -1
	}
	sd := &scanDetail{at: make([]int64, len(order)), dev: map[string][]scanHit{}, unk: map[netip.Addr][]uint64{}}
	for p, idx := range order {
		sd.at[p] = s.at[idx]
		pos[idx] = int32(p)
	}
	for i := range a.devices {
		var hits []scanHit
		for _, h := range s.dev[i].trail {
			if p := pos[h.scan]; p >= 0 {
				hits = append(hits, scanHit{scan: p, addr: h.addr})
			}
		}
		if len(hits) > 0 {
			slices.SortFunc(hits, func(x, y scanHit) int { return cmp.Compare(x.scan, y.scan) })
			sd.dev[a.devices[i].Key] = hits
		}
	}
	for addr, u := range a.unknown {
		if len(u.scanTrail) == 0 {
			continue
		}
		bits := make([]uint64, (len(order)+63)/64)
		for _, idx := range u.scanTrail {
			if p := pos[idx]; p >= 0 {
				bits[p/64] |= 1 << (p % 64)
			}
		}
		sd.unk[addr] = bits
	}
	return sd
}

// device lists the scans as the device key answered them, the newest first.
func (sd *scanDetail) device(key string) []model.NetScanSeen {
	if sd == nil {
		return []model.NetScanSeen{}
	}
	out := sd.list()
	for _, h := range sd.dev[key] {
		out[h.scan].Addr = netip.AddrFrom4(h.addr).String()
	}
	return out
}

// unknownAddr lists the scans as the unknown address addr answered them, the newest first.
func (sd *scanDetail) unknownAddr(addr netip.Addr) []model.NetScanSeen {
	if sd == nil {
		return []model.NetScanSeen{}
	}
	out := sd.list()
	bits := sd.unk[addr]
	for p := range out {
		if p/64 < len(bits) && bits[p/64]&(1<<(p%64)) != 0 {
			out[p].Addr = addr.String()
		}
	}
	return out
}

// list returns the scans, the newest first, none of them answered yet.
func (sd *scanDetail) list() []model.NetScanSeen {
	out := make([]model.NetScanSeen, len(sd.at))
	for p, t := range sd.at {
		out[p].At = rfc3339(time.Unix(0, t))
	}
	return out
}
