package netmap

import (
	"bytes"
	"cmp"
	"math"
	"net/netip"
	"slices"
	"time"

	"attmonitor/internal/model"
)

// maxPorts bounds the distinct destination ports kept per source (FwSource.Ports counts at most
// that many).
const maxPorts = 1024

// builder adds up dropped packets: those of a chunk, of the part of a chunk received in a
// period, or of a whole request. The sums are kept in slices, indexed by maps: a source or a
// destination costs no allocation of its own.
//
// A chunk's builder counts everything one by one: a chunk whose summary would hold more than a
// chunk the store seals can (scan.over) is read into the request's builder instead. The
// request's builder (lim) counts one by one only up to its bounds: the inbound sources and the
// outbound rows beyond them are counted by country and in sketches (srcOver, outOver), and the
// services beyond them as "Other", so that its memory does not grow with what a hostile sender
// can multiply - the sources of spoofed packets above all.
type builder struct {
	counts   [nDirs]int
	hours    map[int64]*[nDirs]int // by hour (Unix hours)
	srcIdx   map[[16]byte]int32    // the inbound packets' sources: index in srcs
	srcs     []srcSum
	services map[svcKey]int // the inbound packets' destinations
	reasons  map[uint8]int
	outIdx   map[outKey]int32 // index in outs
	outs     []outSum
	// The earliest and latest receive time of the messages seen (see).
	hasRX        bool
	rxMin, rxMax int64
	// lim holds the request builder's bounds and what it counted beyond them (nil in a chunk's
	// builder).
	lim *limits
}

// srcSum is a source of inbound packets.
type srcSum struct {
	addr  [16]byte
	count int
	last  int64    // receive time of its newest packet (Unix nanoseconds)
	ports []uint16 // the distinct destination ports it tried, sorted (at most maxPorts)
}

// svcKey is a destination of inbound packets: a protocol and port (0 without ports).
type svcKey struct {
	proto uint8
	port  uint16
}

// outKey is a LAN device's dropped packets toward one destination. dev is the device's number in
// the request's devNamer: 0 when its address names it (always 0 in a chunk's builder, whose rows
// the request names when it adds them up).
type outKey struct {
	lan, remote   [16]byte
	dev           int32
	port          uint16
	proto, reason uint8
}

// outSum counts the packets of an outKey.
type outSum struct {
	key   outKey
	count int
	last  int64
}

// repeat is a repeat line that repeats a message of an earlier chunk - or several such lines of
// the same kind received in the same hour, one after the other: their repeats added up, at the
// receive time of the newest (a chunk of millions of them then takes no more room than its
// hours).
type repeat struct {
	rx int64
	n  uint32
	// cond: a BSD repeat line that only other such lines precede in its chunk: it repeats the
	// message before the chunk, and counts only when that was a drop.
	cond bool
}

// What the message before the next one was, for a BSD repeat line (scan.tail, chunkAgg.tail).
const (
	tailNone  = iota // no message yet, or only BSD repeat lines (they repeat the message before)
	tailDrop         // a drop, or a repeat line counting drops
	tailOther        // another message: a BSD repeat line after it repeats it, and counts nothing
)

func newBuilder() *builder {
	return &builder{
		hours:    map[int64]*[nDirs]int{},
		srcIdx:   map[[16]byte]int32{},
		services: map[svcKey]int{},
		reasons:  map[uint8]int{},
		outIdx:   map[outKey]int32{},
	}
}

// newRequestBuilder returns the builder of a request's sums, bounded by bd: lk finds the countries
// of the sources counted beyond the bound, names the LAN devices (nil: every address names
// itself).
func newRequestBuilder(bd bounds, lk lookup, names *devNamer) *builder {
	b := newBuilder()
	b.lim = &limits{bounds: bd, lk: lk, names: names}
	return b
}

// limits are the request builder's bounds and what it counted beyond them.
type limits struct {
	bounds
	lk    lookup
	names *devNamer
	src   *srcOver // nil until a source was beyond the bound
	out   *outOver // nil until an outbound row was beyond the bound
	// otherServices counts the inbound packets to services beyond the bound.
	otherServices int
}

// srcOver is what a request counted of the inbound sources beyond its bound: their packets by
// country, sketches of how many distinct sources sent them - in all, and in each country - and
// the heaviest of them. None of these sources is one the builder counts one by one: the builder
// stops adding sources once its bound is reached, so a source either was added before (and is
// counted there) or comes here every time.
type srcOver struct {
	drops     int
	distinct  *hll
	countries map[string]*countryOver // by the country of a public source ("" when not placed)
	heavy     *heavy[[16]byte]
}

// countryOver is what a request counted of a country's sources beyond its bound.
type countryOver struct {
	weight int
	sites  *hll
}

// outOver is what a request counted of the outbound rows beyond its bound: a sketch of how many
// distinct rows there were, their devices - the named ones (by number) and a sketch of the
// addresses that name themselves - and the heaviest rows. None of these rows is one the builder
// counts one by one (as srcOver).
type outOver struct {
	drops    int
	distinct *hll
	devs     map[int32]struct{}
	lans     *hll
	heavy    *heavy[outKey]
}

// hourOf returns the hour (Unix hours) of a receive time.
func hourOf(rx int64) int64 {
	h := rx / int64(time.Hour)
	if rx < 0 && rx%int64(time.Hour) != 0 {
		h--
	}
	return h
}

// see notes the receive time of a message.
func (b *builder) see(rx int64) {
	switch {
	case !b.hasRX:
		b.hasRX, b.rxMin, b.rxMax = true, rx, rx
	case rx < b.rxMin:
		b.rxMin = rx
	case rx > b.rxMax:
		b.rxMax = rx
	}
}

// add counts n drops like d received at rx.
func (b *builder) add(d drop, rx int64, n int) {
	b.counts[d.dir] += n
	b.hour(hourOf(rx))[d.dir] += n
	b.reasons[d.reason] += n
	switch d.dir {
	case dirIn:
		if d.srcOK {
			var one [1]uint16
			ports := one[:0]
			if d.dpt != 0 {
				one[0] = d.dpt
				ports = one[:]
			}
			b.addSource(d.src, n, rx, ports)
		}
		b.addService(svcKey{proto: d.proto, port: d.dpt}, n)
	case dirOut:
		if d.srcOK && d.dstOK {
			b.addOut(outKey{lan: d.src, remote: d.dst, port: d.dpt, proto: d.proto, reason: d.reason}, n, rx)
		}
	}
}

func (b *builder) hour(h int64) *[nDirs]int {
	c := b.hours[h]
	if c == nil {
		c = new([nDirs]int)
		b.hours[h] = c
	}
	return c
}

// addSource counts n inbound packets from the source a, the newest received at rx, to the
// destination ports (sorted; not kept).
func (b *builder) addSource(a [16]byte, n int, rx int64, ports []uint16) {
	if i, ok := b.srcIdx[a]; ok {
		s := &b.srcs[i]
		s.count += n
		if rx > s.last {
			s.last = rx
		}
		s.ports = mergePorts(s.ports, ports)
		return
	}
	if b.lim != nil && len(b.srcs) >= b.lim.sources {
		b.lim.overSource(a, n, rx, ports)
		return
	}
	b.srcIdx[a] = int32(len(b.srcs))
	b.srcs = append(b.srcs, srcSum{addr: a, count: n, last: rx, ports: mergePorts(nil, ports)})
}

// addService counts n inbound packets to the service k.
func (b *builder) addService(k svcKey, n int) {
	if b.lim != nil && len(b.services) >= b.lim.services {
		if _, ok := b.services[k]; !ok {
			b.lim.otherServices += n
			return
		}
	}
	b.services[k] += n
}

// addOut counts n packets of the outbound row k, the newest received at rx. The request's
// builder names the row's device after the Device List read in effect at rx.
func (b *builder) addOut(k outKey, n int, rx int64) {
	if b.lim != nil {
		k.dev = b.lim.names.device(k.lan, rx)
	}
	if i, ok := b.outIdx[k]; ok {
		o := &b.outs[i]
		o.count += n
		if rx > o.last {
			o.last = rx
		}
		return
	}
	if b.lim != nil && len(b.outs) >= b.lim.outbound {
		b.lim.overOut(k, n, rx)
		return
	}
	b.outIdx[k] = int32(len(b.outs))
	b.outs = append(b.outs, outSum{key: k, count: n, last: rx})
}

// overSource counts the packets of a source beyond the bound.
func (l *limits) overSource(a [16]byte, n int, rx int64, ports []uint16) {
	o := l.src
	if o == nil {
		o = &srcOver{distinct: newHLL(hllPrecision), countries: map[string]*countryOver{}, heavy: newHeavy[[16]byte](l.heavy)}
		l.src = o
	}
	o.drops += n
	h := hash16(a)
	o.distinct.add(h)
	if info := l.lk.info(netip.AddrFrom16(a).Unmap()); info.Kind == model.IPKindPublic {
		c := o.countries[info.Country]
		if c == nil {
			c = &countryOver{sites: newHLL(hllPartPrecision)}
			o.countries[info.Country] = c
		}
		c.weight += n
		c.sites.add(h)
	}
	o.heavy.add(a, n, rx, ports)
}

// overOut counts the packets of an outbound row beyond the bound.
func (l *limits) overOut(k outKey, n int, rx int64) {
	o := l.out
	if o == nil {
		o = &outOver{distinct: newHLL(hllPrecision), devs: map[int32]struct{}{}, lans: newHLL(hllPrecision),
			heavy: newHeavy[outKey](l.heavy)}
		l.out = o
	}
	o.drops += n
	o.distinct.add(hashOut(k))
	if k.dev > 0 {
		o.devs[k.dev] = struct{}{}
	} else {
		o.lans.add(hash16(k.lan))
	}
	o.heavy.add(k, n, rx, nil)
}

// hashOut hashes an outbound row.
func hashOut(k outKey) uint64 {
	h := mix64(hash16(k.lan) + 0x9e3779b97f4a7c15)
	h = mix64(h ^ hash16(k.remote))
	return mix64(h ^ (uint64(uint32(k.dev))<<32 | uint64(k.port)<<16 | uint64(k.proto)<<8 | uint64(k.reason)))
}

// tooBig reports whether a chunk's builder holds more than a chunk the store seals can: more
// than rows distinct sources, services or outbound rows, or more than hours hours.
func (b *builder) tooBig(rows, hours int) bool {
	return len(b.srcs) > rows || len(b.outs) > rows || len(b.services) > rows || len(b.hours) > hours
}

// addPort adds p to the sorted ports (unless maxPorts are kept already).
func addPort(ports []uint16, p uint16) []uint16 {
	i, found := slices.BinarySearch(ports, p)
	if found || len(ports) >= maxPorts {
		return ports
	}
	return slices.Insert(ports, i, p)
}

// mergePorts adds the sorted ports add to the sorted ports, keeping at most maxPorts. It never
// changes add, and allocates only when a port is new (a source seen in many chunks mostly tries
// the same ports again).
func mergePorts(ports, add []uint16) []uint16 {
	switch {
	case len(add) == 0 || len(ports) >= maxPorts:
		return ports
	case len(ports) == 0:
		return slices.Clone(add[:min(len(add), maxPorts)])
	case len(add) <= 4 || len(add)*8 < len(ports):
		// A few ports: a binary search each, and an insertion for a new one.
		for _, p := range add {
			ports = addPort(ports, p)
		}
		return ports
	}
	missing := 0
	for i, j := 0, 0; j < len(add); {
		switch {
		case i < len(ports) && ports[i] < add[j]:
			i++
		case i < len(ports) && ports[i] == add[j]:
			i, j = i+1, j+1
		default:
			missing++
			j++
		}
	}
	switch {
	case missing == 0:
		return ports
	case len(ports)+missing > maxPorts:
		// Up to the cap: the smallest of the new ports are added.
		for _, p := range add {
			ports = addPort(ports, p)
		}
		return ports
	}
	// Merged from the back, in place, into ports grown as append grows a slice.
	n := len(ports) + missing
	i, j := len(ports)-1, len(add)-1
	ports = slices.Grow(ports, missing)[:n]
	for k := n - 1; j >= 0; k-- {
		switch {
		case i >= 0 && ports[i] > add[j]:
			ports[k] = ports[i]
			i--
		case i >= 0 && ports[i] == add[j]:
			ports[k] = ports[i]
			i, j = i-1, j-1
		default:
			ports[k] = add[j]
			j--
		}
	}
	return ports
}

// chunkAgg is the summary of a chunk's dropped packets - or of those of its part received in a
// period - in a compact form without pointers (rows sorted, so that summaries compare). The
// chunk cache keeps the summaries of whole sealed chunks.
type chunkAgg struct {
	// hasRX: a message has a receive time; rxMin and rxMax are the earliest and the latest
	// (summaries of whole chunks only).
	hasRX        bool
	rxMin, rxMax int64
	counts       [nDirs]int
	hours        []hourRow
	sources      []srcRow
	ports        []uint16 // the sources' ports, one source after the other
	services     []svcRow
	reasons      []reasonRow
	outbound     []outRow
	leading      []repeat
	// last is the chunk's last drop and tail what its last message was (whatever the period):
	// a repeat line at the start of the next chunk repeats them.
	last    drop
	hasLast bool
	tail    uint8
}

type hourRow struct {
	hour int64
	n    [nDirs]uint32
}

type srcRow struct {
	addr   [16]byte
	last   int64
	count  uint32
	nports uint16 // its ports in chunkAgg.ports
}

type svcRow struct {
	count uint32
	port  uint16
	proto uint8
}

type reasonRow struct {
	count  uint32
	reason uint8
}

type outRow struct {
	lan, remote   [16]byte
	last          int64
	count         uint32
	port          uint16
	proto, reason uint8
}

// Sizes of the rows (asserted by a test), for chunkAgg.size.
const (
	sizeHourRow   = 24
	sizeSrcRow    = 32
	sizeSvcRow    = 8
	sizeReasonRow = 8
	sizeOutRow    = 48
	sizeRepeat    = 16
	sizeChunkAgg  = 320 // the struct and its slice headers, rounded up
)

// size estimates the memory a summary takes.
func (a *chunkAgg) size() int64 {
	return sizeChunkAgg + sizeHourRow*int64(cap(a.hours)) + sizeSrcRow*int64(cap(a.sources)) +
		2*int64(cap(a.ports)) + sizeSvcRow*int64(cap(a.services)) + sizeReasonRow*int64(cap(a.reasons)) +
		sizeOutRow*int64(cap(a.outbound)) + sizeRepeat*int64(cap(a.leading))
}

// inside reports whether every message of the summarized chunk was received in [from, to).
func (a *chunkAgg) inside(from, to int64) bool {
	return a.hasRX && a.rxMin >= from && a.rxMax < to
}

// ends returns what the request needs of the chunk's ends: the repeat lines at its start, its
// last drop and what its last message was.
func (a *chunkAgg) ends() chunkEnds {
	return chunkEnds{leading: a.leading, last: a.last, hasLast: a.hasLast, tail: a.tail}
}

// sat32 returns n as a uint32, at most math.MaxUint32.
func sat32(n int) uint32 {
	if n > math.MaxUint32 {
		return math.MaxUint32
	}
	return uint32(max(n, 0))
}

// compact returns the summary of what b added up (without the chunk's ends, which the scan
// fills in). It reorders b's sums: b is not used afterwards.
func (b *builder) compact() *chunkAgg {
	a := &chunkAgg{hasRX: b.hasRX, rxMin: b.rxMin, rxMax: b.rxMax, counts: b.counts}
	if len(b.hours) > 0 {
		a.hours = make([]hourRow, 0, len(b.hours))
		for h, c := range b.hours {
			a.hours = append(a.hours, hourRow{hour: h, n: [nDirs]uint32{sat32(c[0]), sat32(c[1]), sat32(c[2])}})
		}
		slices.SortFunc(a.hours, func(x, y hourRow) int { return cmp.Compare(x.hour, y.hour) })
	}
	if len(b.srcs) > 0 {
		srcs := b.srcs
		b.srcIdx = nil // no longer matches
		slices.SortFunc(srcs, func(x, y srcSum) int { return bytes.Compare(x.addr[:], y.addr[:]) })
		a.sources = make([]srcRow, len(srcs))
		nports := 0
		for i, s := range srcs {
			a.sources[i] = srcRow{addr: s.addr, last: s.last, count: sat32(s.count), nports: uint16(len(s.ports))}
			nports += len(s.ports)
		}
		if nports > 0 {
			a.ports = make([]uint16, 0, nports)
			for _, s := range srcs {
				a.ports = append(a.ports, s.ports...)
			}
		}
	}
	if len(b.services) > 0 {
		a.services = make([]svcRow, 0, len(b.services))
		for k, n := range b.services {
			a.services = append(a.services, svcRow{count: sat32(n), port: k.port, proto: k.proto})
		}
		slices.SortFunc(a.services, func(x, y svcRow) int {
			return cmp.Or(cmp.Compare(x.proto, y.proto), cmp.Compare(x.port, y.port))
		})
	}
	if len(b.reasons) > 0 {
		a.reasons = make([]reasonRow, 0, len(b.reasons))
		for r, n := range b.reasons {
			a.reasons = append(a.reasons, reasonRow{count: sat32(n), reason: r})
		}
		slices.SortFunc(a.reasons, func(x, y reasonRow) int { return cmp.Compare(x.reason, y.reason) })
	}
	if len(b.outs) > 0 {
		a.outbound = make([]outRow, len(b.outs))
		for i, o := range b.outs {
			k := o.key
			a.outbound[i] = outRow{lan: k.lan, remote: k.remote, last: o.last, count: sat32(o.count),
				port: k.port, proto: k.proto, reason: k.reason}
		}
		slices.SortFunc(a.outbound, compareOutRows)
	}
	return a
}

// compareOutRows orders outbound rows by their key (so that summaries compare).
func compareOutRows(x, y outRow) int {
	return cmp.Or(bytes.Compare(x.lan[:], y.lan[:]), bytes.Compare(x.remote[:], y.remote[:]),
		cmp.Compare(x.port, y.port), cmp.Compare(x.proto, y.proto), cmp.Compare(x.reason, y.reason))
}

// merge adds a summary to b (its leading repeat lines are resolved by the caller).
func (b *builder) merge(a *chunkAgg) {
	for d := range nDirs {
		b.counts[d] += a.counts[d]
	}
	for _, h := range a.hours {
		c := b.hour(h.hour)
		for d := range nDirs {
			c[d] += int(h.n[d])
		}
	}
	off := 0
	for _, s := range a.sources {
		end := min(off+int(s.nports), len(a.ports))
		b.addSource(s.addr, int(s.count), s.last, a.ports[off:end])
		off = end
	}
	for _, s := range a.services {
		b.addService(svcKey{proto: s.proto, port: s.port}, int(s.count))
	}
	for _, r := range a.reasons {
		b.reasons[r.reason] += int(r.count)
	}
	for _, o := range a.outbound {
		b.addOut(outKey{lan: o.lan, remote: o.remote, port: o.port, proto: o.proto, reason: o.reason}, int(o.count), o.last)
	}
}

// scan passes the messages of one chunk, in the order they were stored, to the builder of the
// chunk's whole summary (full) and/or of its part received in [from, to) (part), and remembers
// the previous drop and what the previous message was, for the repeat lines.
//
// A repeat line counts more drops like the previous drop: syslog-ng's, which quotes a firewall
// line, always; BSD syslogd's, which repeats the message before it whatever that was, only when
// that message was a drop (or a repeat line counting drops). A repeat line before the chunk's
// first drop repeats a drop of an earlier chunk: it is kept with the chunk (leading) for the
// request to resolve.
type scan struct {
	codes    *codes
	full     *builder // nil: not wanted
	part     *builder // nil: not wanted; the request's own builder when the chunk is read into it
	from, to int64
	// rows and hours bound the chunk builders full and part (0: not bounded); over is set once
	// one of them holds more (builder.tooBig): the chunk is then read into the request's builder.
	rows, hours int
	over        bool
	prev        drop
	hasPrev     bool
	tail        uint8
	// fullLeading and partLeading are the repeat lines that repeat a message of an earlier chunk:
	// all of them, and those received in the period.
	fullLeading, partLeading []repeat
	bad                      int // lines that could not be read
}

// message takes one message received at rx.
func (s *scan) message(rx int64, text []byte) {
	if s.full != nil {
		s.full.see(rx)
	}
	kind, d, n := s.codes.parse(text)
	in := s.part != nil && rx >= s.from && rx < s.to
	switch kind {
	case lineDrop:
		if s.full != nil {
			s.full.add(d, rx, 1)
		}
		if in {
			s.part.add(d, rx, 1)
		}
		s.prev, s.hasPrev, s.tail = d, true, tailDrop
	case lineRepeat:
		s.repeat(rx, n, in, false)
		s.tail = tailDrop
	case lineRepeatPrev:
		switch s.tail {
		case tailDrop:
			s.repeat(rx, n, in, false)
		case tailNone: // only BSD repeat lines before it in the chunk: it repeats the chunk before
			s.repeat(rx, n, in, true)
		}
		// After another message it repeats that message: no drop. It changes no tail.
	default:
		s.tail = tailOther
	}
	if s.rows > 0 && (s.full != nil && s.full.tooBig(s.rows, s.hours) ||
		s.part != nil && s.part.lim == nil && s.part.tooBig(s.rows, s.hours)) {
		s.over = true
	}
}

// repeat counts n more drops like the chunk's previous drop at rx or, before the chunk's first
// drop, keeps the line for the request (cond: it counts only when the message before the chunk
// was a drop).
func (s *scan) repeat(rx int64, n int, in, cond bool) {
	if s.hasPrev {
		if s.full != nil {
			s.full.add(s.prev, rx, n)
		}
		if in {
			s.part.add(s.prev, rx, n)
		}
		return
	}
	r := repeat{rx: rx, n: uint32(n), cond: cond}
	if s.full != nil {
		s.fullLeading = addLeading(s.fullLeading, r)
	}
	if in {
		s.partLeading = addLeading(s.partLeading, r)
	}
}

// addLeading appends a leading repeat line, added to the previous one when they are of the same
// hour and kind.
func addLeading(lead []repeat, r repeat) []repeat {
	if k := len(lead) - 1; k >= 0 && lead[k].cond == r.cond && hourOf(lead[k].rx) == hourOf(r.rx) {
		lead[k].n = sat32(int(lead[k].n) + int(r.n))
		lead[k].rx = max(lead[k].rx, r.rx)
		return lead
	}
	return append(lead, r)
}

// fullAgg returns the summary of the whole chunk the scan built (nil when not wanted).
func (s *scan) fullAgg() *chunkAgg {
	if s.full == nil {
		return nil
	}
	return s.agg(s.full, s.fullLeading)
}

// partAgg returns the summary of the chunk's part in the period (nil when not wanted).
func (s *scan) partAgg() *chunkAgg {
	if s.part == nil || s.part.lim != nil {
		return nil
	}
	return s.agg(s.part, s.partLeading)
}

func (s *scan) agg(b *builder, leading []repeat) *chunkAgg {
	a := b.compact()
	if len(leading) > 0 {
		a.leading = slices.Clone(leading)
	}
	a.last, a.hasLast, a.tail = s.prev, s.hasPrev, s.tail
	return a
}

// partEnds returns the ends of the chunk read, with the repeat lines at its start received in
// the period.
func (s *scan) partEnds() chunkEnds {
	return chunkEnds{leading: s.partLeading, last: s.prev, hasLast: s.hasPrev, tail: s.tail}
}
