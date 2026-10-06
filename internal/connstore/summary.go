package connstore

import (
	"cmp"
	"context"
	"net/netip"
	"slices"
	"strings"

	"attmonitor/internal/model"
)

// summary is what the NAT reads of a day, or of the part of a day a query covers, add up to:
// the unit of the cache and of the merge into an aggregate. Times are Unix nanoseconds. Once
// complete it is never changed: concurrent queries share the cached ones.
type summary struct {
	reads       int
	first, last int64 // the first and the last read (when reads > 0)
	newest      newestRead
	devs        []devSum
	flows       []flowSum
}

// weight is the summary's size for the cache's bound.
func (s *summary) weight() int64 { return int64(len(s.devs) + len(s.flows)) }

// newestRead is the newest read of a summary: its time and totals, and its sessions by device key
// (for a device filter's own count: ConnAggregate.OpenDevice).
type newestRead struct {
	t                      int64
	inUse, available, open int
	devs                   map[string]int
}

// devSum is a device of a summary. Its name, MAC address and connection are the newest
// non-empty ones the Device List gave (each with the time of the NAT read it named), its LAN
// address the newest one of its sessions.
type devSum struct {
	key                string
	name, mac, conn    string
	nameT, macT, connT int64
	lan                netip.Addr
	lanT               int64
	samples, weight    int
	// leftFlows counts its flows left out beyond the bound (scanner.prune, merger.prune), leftOut
	// their weight (counted in weight too).
	leftFlows, leftOut int
}

// flowSum is a flow of a summary: one (device, remote address, port, protocol, direction).
type flowSum struct {
	remote, lan     netip.Addr // lan: the device's address in the newest read that showed it
	first, last     int64
	proto           string
	dev             int32 // index into summary.devs
	port            int32
	samples, weight int32
	inbound         bool
}

// flowKey identifies a flow while a summary is built.
type flowKey struct {
	remote  netip.Addr
	proto   string
	dev     int32
	port    int32
	inbound bool
}

// addrState is what a string of a NAT line's table is, as an address.
type addrState uint8

const (
	addrUnknown addrState = iota // not looked at yet
	addrLocal
	addrRemote
	addrInvalid
)

// lineStr is what the scanner made of a string of the current line's table so far.
type lineStr struct {
	addr      netip.Addr
	proto     string
	dev       int32 // the device of the current read at this address (-1: not resolved yet)
	state     addrState
	protoDone bool // proto is set
}

// scanner builds a summary from NAT reads (decoded lines), one read at a time.
type scanner struct {
	max      int // the most flows it counts one by one (maxFlows)
	sum      summary
	devIdx   map[string]int32
	flowIdx  map[flowKey]int32
	devSeen  []int32 // per device: the read it was last counted in
	flowSeen []int32 // per flow: the same
	read     int32   // the number of the current read (from 1)
	protos   map[string]string
	ipKeys   map[netip.Addr]string // "ip:<address>" keys made so far
	line     natLine               // the decoded line, reused
	strs     []lineStr             // per string of the current line's table
	// dr is the Device List read in effect for the current line, next the first read after it
	// within devNextWithin (nil: none); readDevs counts the current line's sessions by device.
	dr, next *devRead
	readDevs map[int32]int
}

// newScanner returns an empty scanner that counts at most max flows one by one.
func newScanner(max int) *scanner {
	return &scanner{max: max, devIdx: map[string]int32{}, flowIdx: map[flowKey]int32{}, protos: map[string]string{},
		ipKeys: map[netip.Addr]string{}, readDevs: map[int32]int{}}
}

// add counts one NAT read made at t (sc.line), naming its LAN addresses after the Device List
// read dr (nil: none) - or, for an address dr does not list, after next, the first read after the
// NAT read within devNextWithin (nil: none): a device that joined, or got another address, since
// the read in effect is named after the next read that lists it, and keeps one key throughout. It
// returns the number of sessions that could not be read (an index outside the string table, an
// address that does not parse): they are left out.
func (sc *scanner) add(t int64, dr, next *devRead) (bad int) {
	l := &sc.line
	sc.read++
	sc.dr, sc.next = dr, next
	clear(sc.readDevs)
	s := &sc.sum
	if s.reads == 0 || t < s.first {
		s.first = t
	}
	if s.reads == 0 || t > s.last {
		s.last = t
	}
	s.reads++
	newest := s.newest.t == 0 || t >= s.newest.t
	if newest {
		s.newest = newestRead{t: t, inUse: l.InUse, available: l.Available, open: l.sessions()}
	}
	n := len(l.Strs)
	sc.strs = slices.Grow(sc.strs[:0], n)[:n]
	for i := range sc.strs {
		sc.strs[i] = lineStr{dev: -1}
	}
	for i := 0; i+sessionInts <= len(l.S); i += sessionInts {
		p, st, src, dst := l.S[i], l.S[i+1], l.S[i+2], l.S[i+4]
		if uint(p) >= uint(n) || uint(st) >= uint(n) || uint(src) >= uint(n) || uint(dst) >= uint(n) {
			bad++
			continue
		}
		sa, da := sc.addr(src), sc.addr(dst)
		if sa.state == addrInvalid || da.state == addrInvalid {
			bad++
			continue
		}
		lanIdx, lan, remote := src, sa.addr, da.addr
		o := orientLocal(sa.state == addrLocal, da.state == addrLocal)
		if o == inbound {
			lanIdx, lan, remote = dst, da.addr, sa.addr
		}
		dev := sc.device(lanIdx, lan, o == fromGateway, t)
		sc.count(dev, flowKey{remote: remote, proto: sc.proto(p), dev: dev, port: normPort(l.S[i+5]), inbound: o == inbound}, lan, t)
		sc.readDevs[dev]++
	}
	if newest {
		s.newest.devs = make(map[string]int, len(sc.readDevs))
		for d, n := range sc.readDevs {
			s.newest.devs[s.devs[d].key] = n
		}
	}
	return bad
}

// addr returns the string i of the current line's table as an address: local when it is an
// address of a local network (isLocal) or one the Device List read in effect - or the next one -
// tells is the home network's (devRead.lan: a device's global IPv6 address, or one in its /64).
func (sc *scanner) addr(i int) lineStr {
	ls := &sc.strs[i]
	if ls.state == addrUnknown {
		a, ok := parseAddr(sc.line.Strs[i])
		switch {
		case !ok:
			ls.state = addrInvalid
		case isLocal(a), sc.dr.lan(a), sc.next.lan(a):
			ls.addr, ls.state = a, addrLocal
		default:
			ls.addr, ls.state = a, addrRemote
		}
	}
	return *ls
}

// proto returns the string i of the current line's table as a protocol, normalized and shared
// with the earlier reads.
func (sc *scanner) proto(i int) string {
	ls := &sc.strs[i]
	if !ls.protoDone {
		raw := sc.line.Strs[i]
		p, ok := sc.protos[raw]
		if !ok {
			p = normProto(raw)
			sc.protos[strings.Clone(raw)] = p
		}
		ls.proto, ls.protoDone = p, true
	}
	return ls.proto
}

// device returns the device of the current read at the address string lanIdx (lan): the
// gateway when the session has no local side, else the device the Device List read in effect
// (sc.dr) lists at that address - else the next read (sc.next) - else the address itself. The
// device's attributes are updated from the read that named it.
func (sc *scanner) device(lanIdx int, lan netip.Addr, gateway bool, t int64) int32 {
	if d := sc.strs[lanIdx].dev; d >= 0 {
		return d
	}
	var id *identity
	key := gatewayKey
	if !gateway {
		if sc.dr != nil {
			id = sc.dr.lookup(lan)
		}
		if id == nil && sc.next != nil {
			id = sc.next.lookup(lan)
		}
		if id != nil {
			key = id.key
		} else {
			key = sc.ipKey(lan)
		}
	}
	d, ok := sc.devIdx[key]
	if !ok {
		d = int32(len(sc.sum.devs))
		sc.sum.devs = append(sc.sum.devs, devSum{key: key})
		sc.devSeen = append(sc.devSeen, 0)
		sc.devIdx[key] = d
	}
	ds := &sc.sum.devs[d]
	if t >= ds.lanT {
		ds.lan, ds.lanT = lan, t
	}
	if id != nil {
		setNewest(&ds.name, &ds.nameT, id.name, t)
		setNewest(&ds.mac, &ds.macT, id.mac, t)
		setNewest(&ds.conn, &ds.connT, id.conn, t)
	}
	sc.strs[lanIdx].dev = d
	return d
}

// ipKey returns the device key "ip:<address>" of a LAN address the Device List does not name.
func (sc *scanner) ipKey(a netip.Addr) string {
	k, ok := sc.ipKeys[a]
	if !ok {
		k = "ip:" + a.String()
		sc.ipKeys[a] = k
	}
	return k
}

// setNewest sets *v to s when s is not empty and t is not older than *vt.
func setNewest(v *string, vt *int64, s string, t int64) {
	if s != "" && t >= *vt {
		*v, *vt = s, t
	}
}

// count counts one session of flow k, from the device's address lan, in the current read.
func (sc *scanner) count(dev int32, k flowKey, lan netip.Addr, t int64) {
	ds := &sc.sum.devs[dev]
	if sc.devSeen[dev] != sc.read {
		sc.devSeen[dev] = sc.read
		ds.samples++
	}
	ds.weight++
	fi, ok := sc.flowIdx[k]
	if !ok {
		if len(sc.sum.flows) >= sc.max {
			sc.prune()
		}
		fi = int32(len(sc.sum.flows))
		sc.sum.flows = append(sc.sum.flows, flowSum{remote: k.remote, lan: lan, first: t, last: t, proto: k.proto,
			dev: dev, port: k.port, inbound: k.inbound})
		sc.flowSeen = append(sc.flowSeen, 0)
		sc.flowIdx[k] = fi
	}
	f := &sc.sum.flows[fi]
	if sc.flowSeen[fi] != sc.read {
		sc.flowSeen[fi] = sc.read
		f.samples++
	}
	f.weight++
	if t < f.first {
		f.first = t
	}
	if t >= f.last {
		f.last, f.lan = t, lan
	}
}

// prune leaves out the lightest flows of the summary being built, down to three quarters of the
// bound (pruneFlows: the heaviest stay, chosen the same way every time): their sessions stay in
// their device's weight and are added to its leftOut, and its leftFlows counts them. A flow left
// out that comes again later starts anew.
func (sc *scanner) prune() {
	s := &sc.sum
	keep := pruneFlows(len(s.flows), sc.max, func(a, b int) int {
		fa, fb := &s.flows[a], &s.flows[b]
		return cmp.Or(cmp.Compare(fb.weight, fa.weight), cmp.Compare(fb.samples, fa.samples), cmp.Compare(fb.last, fa.last),
			strings.Compare(s.devs[fa.dev].key, s.devs[fb.dev].key), fa.remote.Compare(fb.remote), cmp.Compare(fa.port, fb.port),
			strings.Compare(fa.proto, fb.proto), compareBool(fa.inbound, fb.inbound))
	})
	flows, seen := make([]flowSum, 0, len(keep)), make([]int32, 0, len(keep))
	sc.flowIdx = make(map[flowKey]int32, len(keep))
	kept := make([]bool, len(s.flows))
	for _, i := range keep {
		kept[i] = true
	}
	for i := range s.flows {
		f := &s.flows[i]
		if !kept[i] {
			d := &s.devs[f.dev]
			d.leftFlows++
			d.leftOut += int(f.weight)
			continue
		}
		sc.flowIdx[flowKey{remote: f.remote, proto: f.proto, dev: f.dev, port: f.port, inbound: f.inbound}] = int32(len(flows))
		flows = append(flows, *f)
		seen = append(seen, sc.flowSeen[i])
	}
	s.flows, sc.flowSeen = flows, seen
}

// pruneFlows returns which of n flows to keep when they exceed the bound max: the heaviest three
// quarters of max by compare (heaviest first), in their order of n.
func pruneFlows(n, max int, compare func(a, b int) int) []int {
	order := make([]int, n)
	for i := range order {
		order[i] = i
	}
	slices.SortFunc(order, compare)
	keep := order[:max*3/4]
	slices.Sort(keep)
	return keep
}

// compareBool orders false before true.
func compareBool(a, b bool) int {
	switch {
	case a == b:
		return 0
	case a:
		return 1
	}
	return -1
}

// finish returns the completed summary, its slices clipped (a cached summary holds no spare
// capacity); the scanner must not be used afterwards.
func (sc *scanner) finish() *summary {
	s := sc.sum
	s.devs = slices.Clip(s.devs)
	s.flows = slices.Clip(s.flows)
	return &s
}

// merger adds the summaries of a query's days up to its aggregate.
type merger struct {
	filter      string // the device filter ("" = every device)
	max         int    // the most flows it counts one by one (maxFlows)
	reads       int
	first, last int64
	newest      newestRead
	devs        map[string]*devSum
	flows       map[outKey]*outFlow
}

// outKey identifies a flow of an aggregate.
type outKey struct {
	remote  netip.Addr
	dev     string
	proto   string
	port    int32
	inbound bool
}

// outFlow is a flow of an aggregate.
type outFlow struct {
	outKey
	lan             netip.Addr
	first, last     int64
	samples, weight int
}

// newMerger returns a merger for the device filter (a ConnDevice.Key, "" for every device) that
// counts at most max flows one by one.
func newMerger(filter string, max int) *merger {
	return &merger{filter: filter, max: max, devs: map[string]*devSum{}, flows: map[outKey]*outFlow{}}
}

// mergeEvery is how many flows the merge adds, or writes out, between two checks of its context.
const mergeEvery = 1 << 14

// add adds a summary. Summaries are added oldest first and cover disjoint reads. Beyond the bound
// the lightest flows are left out (prune). It fails only when ctx ends.
func (m *merger) add(ctx context.Context, s *summary) error {
	if s == nil || s.reads == 0 {
		return nil
	}
	if m.reads == 0 || s.first < m.first {
		m.first = s.first
	}
	if m.reads == 0 || s.last > m.last {
		m.last = s.last
	}
	m.reads += s.reads
	if m.newest.t == 0 || s.newest.t >= m.newest.t {
		m.newest = s.newest
	}
	for i := range s.devs {
		d := &s.devs[i]
		if m.filter != "" && d.key != m.filter {
			continue
		}
		o := m.devs[d.key]
		if o == nil {
			c := *d
			m.devs[d.key] = &c
			continue
		}
		o.samples += d.samples
		o.weight += d.weight
		o.leftFlows += d.leftFlows
		o.leftOut += d.leftOut
		setNewest(&o.name, &o.nameT, d.name, d.nameT)
		setNewest(&o.mac, &o.macT, d.mac, d.macT)
		setNewest(&o.conn, &o.connT, d.conn, d.connT)
		if d.lanT >= o.lanT {
			o.lan, o.lanT = d.lan, d.lanT
		}
	}
	for i := range s.flows {
		if i%mergeEvery == mergeEvery-1 {
			if err := ctx.Err(); err != nil {
				return err
			}
		}
		f := &s.flows[i]
		key := s.devs[f.dev].key
		if m.filter != "" && key != m.filter {
			continue
		}
		k := outKey{remote: f.remote, dev: key, proto: f.proto, port: f.port, inbound: f.inbound}
		o := m.flows[k]
		if o == nil {
			if len(m.flows) >= m.max {
				m.prune()
			}
			m.flows[k] = &outFlow{outKey: k, lan: f.lan, first: f.first, last: f.last, samples: int(f.samples),
				weight: int(f.weight)}
			continue
		}
		o.samples += int(f.samples)
		o.weight += int(f.weight)
		o.first = min(o.first, f.first)
		if f.last >= o.last {
			o.last, o.lan = f.last, f.lan
		}
	}
	return nil
}

// prune leaves out the lightest flows merged so far, down to three quarters of the bound
// (pruneFlows, by compareFlows): their weight is added to their device's leftOut, and its leftFlows
// counts them. A flow left out that a later day brings again starts anew.
func (m *merger) prune() {
	flows := make([]*outFlow, 0, len(m.flows))
	for _, f := range m.flows {
		flows = append(flows, f)
	}
	keep := pruneFlows(len(flows), m.max, func(a, b int) int { return compareFlows(flows[a], flows[b]) })
	kept := make([]bool, len(flows))
	for _, i := range keep {
		kept[i] = true
	}
	for i, f := range flows {
		if kept[i] {
			continue
		}
		delete(m.flows, f.outKey)
		if d := m.devs[f.dev]; d != nil {
			d.leftFlows++
			d.leftOut += f.weight
		}
	}
}

// result completes out (whose From, To and empty lists the caller set) with what was merged:
// devices and flows by weight, largest first; ties by samples, then (flows) the newest, then by
// key, so that the order is always the same. It fails only when ctx ends.
func (m *merger) result(ctx context.Context, out model.ConnAggregate) (model.ConnAggregate, error) {
	out.Samples = m.reads
	if m.filter != "" {
		out.OpenDevice = m.newest.devs[m.filter]
	}
	for _, d := range m.devs {
		out.FlowsLeftOut += d.leftFlows
	}
	if m.reads > 0 {
		out.First, out.Last = formatTime(fromUnixNano(m.first)), formatTime(fromUnixNano(m.last))
		out.InUse, out.Available, out.Open = m.newest.inUse, m.newest.available, m.newest.open
	}
	devs := make([]*devSum, 0, len(m.devs))
	for _, d := range m.devs {
		devs = append(devs, d)
	}
	slices.SortFunc(devs, func(a, b *devSum) int {
		if c := cmp.Compare(b.weight, a.weight); c != 0 {
			return c
		}
		if c := cmp.Compare(b.samples, a.samples); c != 0 {
			return c
		}
		return strings.Compare(a.key, b.key)
	})
	out.Devices = make([]model.ConnDevice, 0, len(devs))
	for _, d := range devs {
		cd := model.ConnDevice{Key: d.key, Name: d.name, MAC: d.mac, Connection: d.conn, Samples: d.samples, Weight: d.weight,
			LeftOut: d.leftOut}
		if d.lan.Is4() {
			cd.IPv4 = d.lan.String()
		}
		out.Devices = append(out.Devices, cd)
	}
	flows := make([]*outFlow, 0, len(m.flows))
	for _, f := range m.flows {
		flows = append(flows, f)
	}
	if err := ctx.Err(); err != nil {
		return model.ConnAggregate{}, err
	}
	slices.SortFunc(flows, compareFlows)
	out.Flows = make([]model.ConnFlow, 0, len(flows))
	for i, f := range flows {
		if i%mergeEvery == mergeEvery-1 {
			if err := ctx.Err(); err != nil {
				return model.ConnAggregate{}, err
			}
		}
		out.Flows = append(out.Flows, model.ConnFlow{Device: f.dev, LAN: f.lan.String(), Remote: f.remote.String(),
			Port: int(f.port), Proto: f.proto, Inbound: f.inbound, First: formatTime(fromUnixNano(f.first)),
			Last: formatTime(fromUnixNano(f.last)), Samples: f.samples, Weight: f.weight})
	}
	return out, nil
}

// compareFlows orders flows by weight, largest first, then by samples, the newest first, and
// their key.
func compareFlows(a, b *outFlow) int {
	if c := cmp.Compare(b.weight, a.weight); c != 0 {
		return c
	}
	if c := cmp.Compare(b.samples, a.samples); c != 0 {
		return c
	}
	if c := cmp.Compare(b.last, a.last); c != 0 {
		return c
	}
	if c := strings.Compare(a.dev, b.dev); c != 0 {
		return c
	}
	if c := a.remote.Compare(b.remote); c != 0 {
		return c
	}
	if c := cmp.Compare(a.port, b.port); c != 0 {
		return c
	}
	if c := strings.Compare(a.proto, b.proto); c != 0 {
		return c
	}
	switch {
	case a.inbound == b.inbound:
		return 0
	case !a.inbound:
		return -1
	}
	return 1
}
