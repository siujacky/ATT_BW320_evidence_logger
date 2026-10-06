package netmap

import (
	"fmt"
	"math/rand/v2"
	"net/netip"
	"reflect"
	"slices"
	"testing"
	"time"
	"unsafe"
)

// event is a syslog message for the scan tests.
type event struct {
	rx   time.Time
	text string
}

// scanAll scans events as one chunk, with the part [from, to) when from is before to.
func scanAll(c *codes, events []event, from, to time.Time) *scan {
	sc := &scan{codes: c, full: newBuilder()}
	if from.Before(to) {
		sc.part, sc.from, sc.to = newBuilder(), from.UnixNano(), to.UnixNano()
	}
	for _, e := range events {
		sc.message(e.rx.UnixNano(), []byte(e.text))
	}
	return sc
}

func srcKey(s string) [16]byte { return netip.MustParseAddr(s).As16() }

func TestScanCountsRepeatsOfThePreviousDrop(t *testing.T) {
	c := newCodes()
	sc := scanAll(c, []event{
		{at(1), lineInbound},
		{at(2), lineRepeat3},                     // 3 more like the inbound one
		{at(3), lineDHCP},                        // another program's line changes nothing
		{at(4), "last message repeated 2 times"}, // BSD style: it repeats the DHCP line, no drop
		{at(5), lineOutbound},
		{at(6), repeatLine(4)}, // 4 more like the outbound one
		{at(7), "Last message 'dnsmasq[1]: query[A]' repeated 9 times"},       // not a drop
		{at(8), fwLine("203.0.113.66", "TCP", 22)},                            // the same source, another port
		{at(3600 + 1), "Last message 'FIREWALL[8512]: nflo' repeated 1 time"}, // the next hour
	}, time.Time{}, time.Time{})
	b := sc.full
	if b.counts != [nDirs]int{1 + 3 + 1 + 1, 1 + 4, 0} {
		t.Fatalf("counts %v", b.counts)
	}
	h := b.hours[hourOf(at(0).UnixNano())]
	h2 := b.hours[hourOf(at(3601).UnixNano())]
	if h == nil || *h != [nDirs]int{5, 5, 0} || h2 == nil || *h2 != [nDirs]int{1, 0, 0} || len(b.hours) != 2 {
		t.Fatalf("hours %v %v (%d)", h, h2, len(b.hours))
	}
	s := srcOf(b, "203.0.113.66")
	if s == nil || s.count != 6 || s.last != at(3601).UnixNano() || !slices.Equal(s.ports, []uint16{22, 8071}) || len(b.srcs) != 1 {
		t.Fatalf("sources %+v", b.srcs)
	}
	tcp := c.protos.id([]byte("tcp"))
	if b.services[svcKey{tcp, 8071}] != 4 || b.services[svcKey{tcp, 22}] != 2 || len(b.services) != 2 {
		t.Fatalf("services %v", b.services)
	}
	if len(b.outs) != 1 {
		t.Fatalf("outbound %v", b.outs)
	}
	for _, o := range b.outs {
		k := o.key
		if k.lan != srcKey("192.168.1.64") || k.remote != srcKey("192.0.2.44") || k.port != 443 || o.count != 5 || o.last != at(6).UnixNano() {
			t.Fatalf("outbound %+v %+v", k, o)
		}
	}
	if len(sc.fullLeading) != 0 || !sc.hasPrev || sc.tail != tailDrop || !b.hasRX || b.rxMin != at(1).UnixNano() || b.rxMax != at(3601).UnixNano() {
		t.Fatalf("leading %v, prev %v, tail %d, rx %v %d %d", sc.fullLeading, sc.hasPrev, sc.tail, b.hasRX, b.rxMin, b.rxMax)
	}
}

// TestScanCountsBSDRepeatsOnlyAfterADrop: BSD syslogd's "last message repeated N times" repeats
// the message right before it, whatever it was - only after a drop (or a repeat line counting
// drops) does it count drops; at the start of a chunk it is kept for the request, to count only
// when the chunk before ended with a drop.
func TestScanCountsBSDRepeatsOnlyAfterADrop(t *testing.T) {
	const bsd = "last message repeated %d times"
	for _, c := range []struct {
		name     string
		events   []string
		in       int
		leading  []repeat // of the whole chunk (their receive times: the second of the line)
		lastKind uint8    // tail
	}{
		{"after a drop", []string{lineInbound, fmt.Sprintf(bsd, 4)}, 1 + 4, nil, tailDrop},
		{"after a repeat line", []string{lineInbound, lineRepeat3, fmt.Sprintf(bsd, 2)}, 1 + 3 + 2, nil, tailDrop},
		{"twice", []string{lineInbound, fmt.Sprintf(bsd, 2), fmt.Sprintf(bsd, 5)}, 1 + 2 + 5, nil, tailDrop},
		{"after another program's line", []string{lineInbound, lineDHCP, fmt.Sprintf(bsd, 50)}, 1, nil, tailOther},
		{"after another program's repeat", []string{lineInbound, "Last message 'dnsmasq[1]: query' repeated 2 times",
			fmt.Sprintf(bsd, 50)}, 1, nil, tailOther},
		{"first of the chunk", []string{fmt.Sprintf(bsd, 7), lineInbound}, 1, []repeat{{rx: at(0).UnixNano(), n: 7, cond: true}}, tailDrop},
		{"after a quoted repeat at the start", []string{lineRepeat3, fmt.Sprintf(bsd, 2), lineDHCP}, 0,
			[]repeat{{rx: at(1).UnixNano(), n: 3 + 2}}, tailOther},
		{"after another line at the start", []string{lineDHCP, fmt.Sprintf(bsd, 9)}, 0, nil, tailOther},
		{"only BSD lines", []string{fmt.Sprintf(bsd, 1), fmt.Sprintf(bsd, 2)}, 0, []repeat{{rx: at(1).UnixNano(), n: 3, cond: true}}, tailNone},
	} {
		var events []event
		for i, text := range c.events {
			events = append(events, event{at(float64(i)), text})
		}
		sc := scanAll(newCodes(), events, at(0), at(100))
		a := sc.fullAgg()
		if a.counts[dirIn] != c.in || sc.part.counts[dirIn] != c.in || !slices.Equal(a.leading, c.leading) ||
			!slices.Equal(sc.partLeading, c.leading) || a.tail != c.lastKind {
			t.Errorf("%s: inbound %d (part %d), leading %+v (part %+v), tail %d; want %d, %+v, %d", c.name, a.counts[dirIn],
				sc.part.counts[dirIn], a.leading, sc.partLeading, a.tail, c.in, c.leading, c.lastKind)
		}
	}
}

func TestScanKeepsTheRepeatsBeforeTheFirstDrop(t *testing.T) {
	c := newCodes()
	sc := scanAll(c, []event{
		{at(1), lineRepeat3}, // repeats a drop of an earlier chunk
		{at(2), lineDHCP},
		{at(3), repeatLine(2)},
		{at(4), lineGateway},
		{at(5), repeatLine(5)}, // repeats the local drop
	}, at(2), at(10))
	full, part := sc.fullAgg(), sc.partAgg()
	// Repeat lines of the same hour are kept together.
	if !slices.Equal(full.leading, []repeat{{at(3).UnixNano(), 3 + 2, false}}) {
		t.Fatalf("leading %v", full.leading)
	}
	if !slices.Equal(part.leading, []repeat{{at(3).UnixNano(), 2, false}}) { // the first is before the period
		t.Fatalf("leading of the part %v", part.leading)
	}
	if full.counts != [nDirs]int{0, 0, 6} || part.counts != [nDirs]int{0, 0, 6} {
		t.Fatalf("counts %v %v", full.counts, part.counts)
	}
	if !full.hasLast || full.last != part.last || full.last.dir != dirLocal || full.tail != tailDrop {
		t.Fatalf("last %+v %v, tail %d", full.last, full.hasLast, full.tail)
	}
	// Those of another hour, or of another kind, are kept apart.
	sc = scanAll(c, []event{
		{at(1), repeatLine(1)},
		{at(2), "last message repeated 2 times"},
		{at(3600), repeatLine(4)},
		{at(3601), repeatLine(8)},
	}, time.Time{}, time.Time{})
	if want := []repeat{{at(2).UnixNano(), 1 + 2, false}, {at(3601).UnixNano(), 4 + 8, false}}; !slices.Equal(sc.fullLeading, want) {
		t.Fatalf("leading %v, want %v", sc.fullLeading, want)
	}
	sc = scanAll(c, []event{
		{at(1), "last message repeated 2 times"},
		{at(2), repeatLine(1)},
		{at(3), "last message repeated 2 times"},
	}, time.Time{}, time.Time{})
	if want := []repeat{{at(1).UnixNano(), 2, true}, {at(3).UnixNano(), 1 + 2, false}}; !slices.Equal(sc.fullLeading, want) {
		t.Fatalf("leading %v, want %v", sc.fullLeading, want)
	}
	// A chunk of a hundred thousand repeat lines keeps one per hour.
	var many []event
	for i := range 100_000 {
		many = append(many, event{t0.Add(time.Duration(i) * 100 * time.Millisecond), lineRepeat3})
	}
	if sc := scanAll(c, many, time.Time{}, time.Time{}); len(sc.fullLeading) != 3 || sc.fullLeading[0].n != 36_000*3 {
		t.Fatalf("%d leading entries, the first %+v", len(sc.fullLeading), sc.fullLeading[0])
	}
}

func TestScanPartCountsByReceiveTime(t *testing.T) {
	c := newCodes()
	sc := scanAll(c, []event{
		{at(1), lineInbound},   // before the period: not counted, but repeated in it
		{at(2), repeatLine(2)}, // before the period
		{at(10), repeatLine(3)},
		{at(11), lineOutbound},
		{at(20), repeatLine(7)}, // after the period
		{at(15), linePing},      // the clock was set back: in the period
	}, at(10), at(20))
	p := sc.part
	if p.counts != [nDirs]int{3 + 1, 1, 0} {
		t.Fatalf("part counts %v", p.counts)
	}
	if s := srcOf(p, "203.0.113.66"); s == nil || s.count != 3 || s.last != at(10).UnixNano() {
		t.Fatalf("source %+v", s)
	}
	if f := sc.full; f.counts != [nDirs]int{1 + 2 + 3 + 1, 1 + 7, 0} || f.rxMax != at(20).UnixNano() || f.rxMin != at(1).UnixNano() {
		t.Fatalf("full counts %v, rx %d %d", f.counts, f.rxMin, f.rxMax)
	}
	if a := sc.fullAgg(); a.inside(at(1).UnixNano(), at(20).UnixNano()) || !a.inside(at(1).UnixNano(), at(20).UnixNano()+1) {
		t.Fatalf("inside %d %d", a.rxMin, a.rxMax)
	}
}

func TestPortsAreCapped(t *testing.T) {
	var ports []uint16
	for p := 2 * maxPorts; p > 0; p-- {
		ports = addPort(ports, uint16(p))
	}
	if len(ports) != maxPorts || !slices.IsSorted(ports) {
		t.Fatalf("%d ports kept", len(ports))
	}
	a := []uint16{1, 3, 5, 7}
	b := []uint16{2, 3, 6, 7, 9}
	if got := mergePorts(slices.Clone(a), b); !slices.Equal(got, []uint16{1, 2, 3, 5, 6, 7, 9}) {
		t.Fatalf("merged %v", got)
	}
	if got := mergePorts(nil, b); !slices.Equal(got, b) || &got[0] == &b[0] {
		t.Fatalf("merged into nothing %v (shares b: %v)", got, &got[0] == &b[0])
	}
	big := make([]uint16, maxPorts)
	for i := range big {
		big[i] = uint16(2 * i)
	}
	// Once maxPorts are kept, no port is added (the count is what is shown).
	if got := mergePorts(slices.Clone(big), []uint16{1, 3, 5}); len(got) != maxPorts || got[1] != 2 {
		t.Fatalf("merged beyond the cap: %d %v", len(got), got[:4])
	}
	almost := big[:maxPorts-1]
	if got := mergePorts(slices.Clone(almost), []uint16{1, 3, 5}); len(got) != maxPorts || got[1] != 1 || got[2] != 2 {
		t.Fatalf("merged up to the cap: %d %v", len(got), got[:4])
	}
	// Nothing new: nothing is allocated.
	if n := testing.AllocsPerRun(10, func() { mergePorts(a, []uint16{1, 5, 7}) }); n != 0 {
		t.Fatalf("%v allocations merging known ports", n)
	}
}

func TestRowSizes(t *testing.T) {
	for name, c := range map[string][2]uintptr{
		"hourRow":   {unsafe.Sizeof(hourRow{}), sizeHourRow},
		"srcRow":    {unsafe.Sizeof(srcRow{}), sizeSrcRow},
		"svcRow":    {unsafe.Sizeof(svcRow{}), sizeSvcRow},
		"reasonRow": {unsafe.Sizeof(reasonRow{}), sizeReasonRow},
		"outRow":    {unsafe.Sizeof(outRow{}), sizeOutRow},
		"repeat":    {unsafe.Sizeof(repeat{}), sizeRepeat},
	} {
		if c[0] != c[1] {
			t.Errorf("%s takes %d bytes, the estimate says %d", name, c[0], c[1])
		}
	}
	if s := unsafe.Sizeof(chunkAgg{}); s > sizeChunkAgg {
		t.Errorf("chunkAgg takes %d bytes, the estimate says %d", s, sizeChunkAgg)
	}
}

// randomEvents returns n random messages a second apart from start: drops of every kind from a
// few sources and ports, repeat lines of both kinds (some at the start), other programs' lines.
func randomEvents(r *rand.Rand, start time.Time, n int) []event {
	srcs := []string{"203.0.113.1", "203.0.113.2", "192.0.2.9", "2001:db8::7", "198.51.100.20"}
	var out []event
	for i := range n {
		rx := start.Add(time.Duration(i) * time.Second)
		var text string
		switch k := r.IntN(10); {
		case k < 4:
			text = fwLine(srcs[r.IntN(len(srcs))], []string{"TCP", "UDP"}[r.IntN(2)], 1+r.IntN(30))
		case k < 5:
			text = outLine(fmt.Sprintf("192.168.1.%d", 60+r.IntN(3)), srcs[r.IntN(3)], 443, []string{"POLICY", "IP-INVALID"}[r.IntN(2)])
		case k < 6:
			text = []string{linePing, lineGateway, lineToLAN, lineV6}[r.IntN(4)]
		case k < 8:
			text = repeatLine(1 + r.IntN(5))
		case k < 9:
			text = fmt.Sprintf("last message repeated %d times", 1+r.IntN(5)) // BSD style
		default:
			text = lineDHCP
		}
		out = append(out, event{rx, text})
	}
	return out
}

// TestChunkSummariesMergeLikeOnePass splits random messages into chunks and checks that their
// summaries, merged with the repeat lines at their starts given to the previous chunk's last
// drop (a BSD one only when the last message before it was a drop), add up to what one pass over
// all of them counts.
func TestChunkSummariesMergeLikeOnePass(t *testing.T) {
	for seed := range uint64(40) {
		r := rand.New(rand.NewPCG(seed, 7))
		c := newCodes()
		events := randomEvents(r, t0, 50+r.IntN(200))
		want := scanAll(c, events, time.Time{}, time.Time{}).full

		got := newBuilder()
		var prev drop
		hasPrev := false
		tail := uint8(tailNone)
		for rest := events; len(rest) > 0; {
			n := min(len(rest), 1+r.IntN(30))
			a := scanAll(c, rest[:n], time.Time{}, time.Time{}).fullAgg()
			rest = rest[n:]
			got.merge(a)
			for _, rp := range a.leading {
				if hasPrev && (!rp.cond || tail == tailDrop) {
					got.add(prev, rp.rx, int(rp.n))
				}
			}
			if a.hasLast {
				prev, hasPrev = a.last, true
			}
			if a.tail != tailNone {
				tail = a.tail
			}
		}
		// Repeat lines before the very first drop repeat nothing.
		ga, wa := got.compact(), want.compact()
		ga.hasRX, ga.rxMin, ga.rxMax = wa.hasRX, wa.rxMin, wa.rxMax
		if !reflect.DeepEqual(ga, wa) {
			t.Fatalf("seed %d: merged\n%+v\none pass\n%+v", seed, ga, wa)
		}
	}
}

// srcOf returns a builder's sum of a source (nil when it has none).
func srcOf(b *builder, addr string) *srcSum {
	i, ok := b.srcIdx[srcKey(addr)]
	if !ok {
		return nil
	}
	return &b.srcs[i]
}
