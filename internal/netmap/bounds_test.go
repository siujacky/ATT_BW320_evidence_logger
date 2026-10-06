package netmap

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"math"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"attmonitor/internal/contracts"
	"attmonitor/internal/model"
)

// memSourceOf keeps texts as sealed chunks in memory, as the syslog store keeps them (gzip of
// the receiver's JSON lines): chunk i holds texts[i], a message every step from start on.
func memSourceOf(texts [][]string, start time.Time, step time.Duration) *memSource {
	m := &memSource{gz: map[string][]byte{}}
	rx := start
	var raw, gz bytes.Buffer
	for c, lines := range texts {
		raw.Reset()
		gz.Reset()
		var first, last time.Time
		for i, text := range lines {
			if i == 0 {
				first = rx
			}
			last = rx
			raw.WriteString(`{"rx":"` + rx.Format(time.RFC3339Nano) + `","src":"192.168.1.254:514","raw":"<12>` +
				text + `","format":"unknown","pri":12,"facility":1,"severity":4,"msg":"` + text + "\"}\n")
			rx = rx.Add(step)
		}
		zw, _ := gzip.NewWriterLevel(&gz, gzip.BestSpeed)
		zw.Write(raw.Bytes())
		zw.Close()
		name := fmt.Sprintf("syslog-%04d.jsonl.gz", c)
		m.gz[name] = bytes.Clone(gz.Bytes())
		m.refs = append(m.refs, model.SyslogChunkRef{Name: name, SHA256: "sha-" + name, From: first.Format(time.RFC3339Nano),
			To: last.Format(time.RFC3339Nano), Messages: len(lines), GzBytes: int64(gz.Len())})
	}
	return m
}

// within reports whether got is within frac of want.
func within(got, want int, frac float64) bool {
	return math.Abs(float64(got-want)) <= frac*float64(want)
}

// TestFirewallBoundsItsSums: a flood of packets from distinct sources (spoofed SYNs) and of
// outbound packets to distinct addresses no longer grows a request's sums beyond their bounds.
// The totals stay exact, the distinct sources and rows become estimates, and the heaviest
// sources and rows - here first seen in the oldest chunk, so after the bounds were reached -
// still lead the lists.
func TestFirewallBoundsItsSums(t *testing.T) {
	const (
		chunks   = 12
		inbound  = 7500 // per chunk, each from a source of its own
		outbound = 2500 // per chunk, each to an address of its own
	)
	texts := make([][]string, chunks)
	src, dst := 0, 0
	for c := range texts {
		if c == 0 { // the heavy ones
			for h := 1; h <= 3; h++ {
				texts[c] = append(texts[c], fwLine("203.0.113."+strconv.Itoa(h), "TCP", 22), repeatLine(5000))
			}
			texts[c] = append(texts[c], outLine("192.168.1.64", "192.0.2.44", 443, "POLICY"), repeatLine(3000))
		}
		for range inbound {
			texts[c] = append(texts[c], fwLine(fmt.Sprintf("2001:db8:%x:%x::1", src>>16, src&0xffff), "TCP", 1+src%3000))
			src++
		}
		for i := range outbound {
			texts[c] = append(texts[c], outLine("192.168.1."+strconv.Itoa(64+i%2), fmt.Sprintf("2001:db8:f%03x:%x::9", dst>>16, dst&0xffff),
				443, "POLICY"))
			dst++
		}
	}
	start := t0.Add(-48 * time.Hour)
	mem := memSourceOf(texts, start, time.Second)
	in := newFakeIntel()
	for h := 1; h <= 3; h++ {
		in.know("203.0.113."+strconv.Itoa(h), 64496, "Example Scanner", "NL")
	}
	v := New(Options{Syslog: mem, Intel: in, Conns: &fakeConns{devices: sampleDevices}, ResultTTL: -1})
	v.bounds.sources, v.bounds.outbound, v.bounds.services, v.bounds.heavy = 4000, 2000, 500, 64
	ctx := context.Background()
	q := contracts.NetQuery{From: start.Add(-time.Hour), To: t0}
	fw, err := v.Firewall(ctx, q) // reads and keeps every chunk
	if err != nil {
		t.Fatal(err)
	}
	checkSums(t, fw)
	wantIn, wantOut := chunks*inbound+3*5001, chunks*outbound+3001
	if fw.Inbound != wantIn || fw.Outbound != wantOut || fw.Local != 0 {
		t.Fatalf("inbound %d, outbound %d, local %d; want %d, %d, 0", fw.Inbound, fw.Outbound, fw.Local, wantIn, wantOut)
	}
	if !within(fw.Sources, chunks*inbound+3, 0.03) || !within(fw.OutboundTotal, chunks*outbound+1, 0.03) ||
		fw.OutboundDevices != 2 {
		t.Fatalf("sources %d, outbound rows %d, devices %d", fw.Sources, fw.OutboundTotal, fw.OutboundDevices)
	}
	for i, s := range fw.TopSources[:3] { // equal counts: the newest first
		if s.Addr != "203.0.113."+strconv.Itoa(3-i) || s.Count != 5001 || s.Country != "NL" || s.Ports != 1 {
			t.Fatalf("top source %d: %+v", i, s)
		}
	}
	if r := fw.OutboundRows[0]; r.Remote != "192.0.2.44" || r.Count != 3001 || r.Device != "mac:00:00:5e:00:53:10" || r.Name != "Study PC" {
		t.Fatalf("first outbound row %+v", r)
	}
	countries := map[string]model.NetCountry{}
	for _, c := range fw.Countries {
		countries[c.Code] = c
	}
	if nl, other := countries["NL"], countries[""]; len(countries) != 2 || nl.Sites != 3 || nl.Weight != 3*5001 ||
		other.Weight != chunks*inbound || !within(other.Sites, chunks*inbound, 0.07) {
		t.Fatalf("countries %+v", fw.Countries)
	}
	if s := fw.Services[0]; s.Name != "SSH" || s.Count != 3*5001+chunks*inbound/3000 {
		t.Fatalf("services %+v", fw.Services)
	}

	// The request's sums stay within their bounds.
	if err := v.acquireFW(ctx); err != nil {
		t.Fatal(err)
	}
	from, to, _ := v.period(q)
	r, _, err := v.runFirewall(ctx, from, to, newRequestBuilder(v.bounds, lookup{intel: in}, v.devNames(ctx, from, to)))
	v.releaseFW()
	if err != nil {
		t.Fatal(err)
	}
	if b := r.b; len(b.srcs) != 4000 || len(b.outs) != 2000 || len(b.services) > 500 || b.lim.src == nil ||
		len(b.lim.src.heavy.items) != 64 || len(b.lim.out.heavy.items) != 64 || len(b.lim.src.countries) != 2 {
		t.Fatalf("%d sources, %d rows, %d services kept", len(b.srcs), len(b.outs), len(b.services))
	}

	// Building it again from the cached summaries allocates what the bounds allow, not what the
	// flood holds (about 30 MiB without them).
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	again, err := v.Firewall(ctx, q)
	runtime.ReadMemStats(&after)
	if err != nil || !reflect.DeepEqual(again, fw) {
		t.Fatalf("built again: %v\n%s", err, diffFields(t, again, fw))
	}
	if alloc := after.TotalAlloc - before.TotalAlloc; alloc > 10<<20 {
		t.Fatalf("a warm build allocated %.1f MiB", float64(alloc)/(1<<20))
	}
}

// TestFirewallReadsAHugeChunkDirectly: a chunk that holds more than a summary keeps (none the
// store seals does) is read straight into the request's bounded sums and not kept; the view
// still counts exactly, also the repeat lines that follow it.
func TestFirewallReadsAHugeChunkDirectly(t *testing.T) {
	s := testStore(t)
	var msgs []model.SyslogMessage
	appendMsgs(t, s, true, syslogMsg(at(1), lineInbound), syslogMsg(at(2), repeatLine(2)))
	msgs = append(msgs, syslogMsg(at(1), lineInbound), syslogMsg(at(2), repeatLine(2)))
	var huge []model.SyslogMessage
	for i := range 300 {
		huge = append(huge, syslogMsg(at(10+float64(i)), fwLine(fmt.Sprintf("2001:db8:1::%x", i+1), "UDP", 1+i)))
	}
	huge = append(huge, syslogMsg(at(400), lineOutbound), syslogMsg(at(401), lineDHCP))
	appendMsgs(t, s, true, huge...)
	msgs = append(msgs, huge...)
	// A BSD repeat line repeats the DHCP line before it; the quoted one the outbound drop.
	tail := []model.SyslogMessage{syslogMsg(at(500), "last message repeated 50 times"), syslogMsg(at(501), repeatLine(4)),
		syslogMsg(at(502), linePing)}
	appendMsgs(t, s, true, tail...)
	msgs = append(msgs, tail...)
	conns := &fakeConns{devices: sampleDevices}
	v := New(Options{Syslog: s, Intel: sampleIntel(), Conns: conns, ResultTTL: -1})
	v.bounds.chunkRows = 100
	oracle := New(Options{Syslog: s, Intel: sampleIntel(), Conns: conns, ResultTTL: -1})
	for _, c := range []struct{ from, to float64 }{{0, 1000}, {450, 1000}, {5, 405}, {100, 200}} {
		for range 2 {
			fw, err := v.Firewall(context.Background(), contracts.NetQuery{From: at(c.from), To: at(c.to)})
			if err != nil {
				t.Fatal(err)
			}
			want := onePass(oracle, s, msgs, at(c.from), at(c.to), DefaultLimit)
			if !reflect.DeepEqual(fw, want) {
				t.Fatalf("[%v, %v):\n%s", c.from, c.to, diffFields(t, fw, want))
			}
		}
	}
	if fw, _ := v.Firewall(context.Background(), contracts.NetQuery{From: at(450), To: at(1000)}); fw.Outbound != 4 || fw.Inbound != 1 {
		t.Fatalf("after the huge chunk: outbound %d, inbound %d", fw.Outbound, fw.Inbound)
	}
	// The huge chunk's summary is not kept; the others are.
	if e, _ := v.chunks.stats(); e != 2 {
		t.Fatalf("%d summaries kept", e)
	}
}

// TestConnectionsBoundsItsWork: a period of many flows is drawn from its heaviest ones; the
// others still count in the diagram's weights (as Other), in the totals and in the rows.
func TestConnectionsBoundsItsWork(t *testing.T) {
	const n = 100_000
	in := newFakeIntel()
	in.know("203.0.113.7", 64500, "Big Org", "DE")
	devs := []string{devPC, devIP, "ip:192.168.1.71", "ip:192.168.1.72"}
	var flows []model.ConnFlow
	total := 0
	for i := range n {
		f := model.ConnFlow{Device: devs[i%4], LAN: "192.168.1.70", Remote: fmt.Sprintf("2001:db8:%x:%x::1", i>>16, i&0xffff),
			Proto: "udp", Port: 50000 + i%1000, Samples: 1, Weight: 100 + i%50}
		if i < 10 { // heavy flows to an organisation the database knows
			f.Remote, f.Port, f.Proto, f.Weight = "203.0.113.7", 443+i, "tcp", 100_000-i
		}
		flows = append(flows, f)
		total += f.Weight
	}
	// The most seen flow is light: it is not drawn, but leads the rows.
	flows = append(flows, model.ConnFlow{Device: devPC, LAN: "192.168.1.64", Remote: "203.0.113.7", Proto: "tcp", Port: 993,
		Samples: 60, Weight: 60})
	total += 60
	conns := &fakeConns{agg: model.ConnAggregate{Samples: 360, Flows: flows}}
	v := New(Options{Conns: conns, Intel: in, ResultTTL: -1})
	v.bounds.flows = 2000
	ctx := context.Background()
	q := contracts.NetQuery{From: t0, To: t0.Add(24 * time.Hour), Limit: 50}
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	nc, err := v.Connections(ctx, q)
	runtime.ReadMemStats(&after)
	if err != nil {
		t.Fatal(err)
	}
	// About 60 MiB without the bound.
	if alloc := after.TotalAlloc - before.TotalAlloc; alloc > 20<<20 {
		t.Fatalf("a build of %d flows allocated %.1f MiB", n, float64(alloc)/(1<<20))
	}
	if nc.RowsTotal != n+1 || len(nc.Rows) != 50 || nc.Rows[0].Samples != 60 || nc.Rows[0].Port != 993 || nc.Rows[0].Org != "Big Org" {
		t.Fatalf("%d rows of %d, the first %+v", len(nc.Rows), nc.RowsTotal, nc.Rows[0])
	}
	if !within(nc.Totals.Sites, n-10+1, 0.03) || nc.Totals.Devices != 4 || nc.Totals.Orgs != 1 || nc.Totals.Countries != 1 {
		t.Fatalf("totals %+v", nc.Totals)
	}
	orgs, other := 0, model.NetOrg{}
	for _, o := range nc.Orgs {
		orgs += o.Weight
		if o.Key == orgOther {
			other = o
		}
	}
	svcs := 0
	for _, s := range nc.Services {
		svcs += s.Weight
	}
	devOrg, orgSvc := 0, 0
	for _, l := range nc.Links {
		if l.From == orgOther || l.From == orgLocal || l.From == orgUnknown || strings.HasPrefix(l.From, "org:") || strings.HasPrefix(l.From, "as") {
			orgSvc += l.Weight
		} else {
			devOrg += l.Weight
		}
	}
	if orgs != total || svcs != total || devOrg != total || orgSvc != total || other.Weight == 0 {
		t.Fatalf("weights: orgs %d, services %d, bands %d and %d, other %+v; want %d", orgs, svcs, devOrg, orgSvc, other, total)
	}
	if nc.Orgs[0].Key != "org:big org" || nc.Orgs[0].ASN != 64500 || nc.Orgs[0].Weight != 10*100_000-45 {
		t.Fatalf("first organisation %+v", nc.Orgs[0])
	}
	for _, d := range nc.Devices {
		if !within(d.Sites, (n-10)/4, 0.1) {
			t.Fatalf("device %+v", d)
		}
	}
}

func TestHLLEstimates(t *testing.T) {
	for _, n := range []int{0, 1, 2, 10, 1000, 20_000, 300_000} {
		for _, p := range []uint8{hllPrecision, hllPartPrecision} {
			h := newHLL(p)
			for i := range n {
				h.add(hash16(srcKey(fmt.Sprintf("2001:db8::%x:%x", i>>16, i&0xffff))))
				h.add(hash16(srcKey(fmt.Sprintf("2001:db8::%x:%x", i>>16, i&0xffff)))) // again: no difference
			}
			tol := 4 * 1.04 / math.Sqrt(float64(int(1)<<p)) // 4 standard errors
			if got := h.count(); n <= 2 && got != n || n == 10 && (got < 9 || got > 11) || n > 10 && !within(got, n, tol) {
				t.Errorf("p=%d: %d distinct estimated as %d", p, n, got)
			}
		}
	}
}

// TestHeavyKeepsTheHeaviest: among many light keys, the heavy ones are kept with what was
// added for them since, the light ones replacing each other.
func TestHeavyKeepsTheHeaviest(t *testing.T) {
	h := newHeavy[int](50)
	for i := range 200_000 {
		h.add(1_000_000+i, 1, int64(i), nil)
		if i%10 == 0 {
			h.add(i/10%5, 100, int64(i), []uint16{uint16(i % 7)}) // five keys, 400,000 each
		}
	}
	if len(h.items) != 50 || len(h.pos) != 50 {
		t.Fatalf("%d items, %d positions", len(h.items), len(h.pos))
	}
	for k := range 5 {
		i, ok := h.pos[k]
		if !ok {
			t.Fatalf("heavy key %d not kept", k)
		}
		// Kept from its first time on, before the table was full: counted exactly.
		if it := h.items[i]; it.count != 400_000 || it.err != 0 || it.last < 199_950 || len(it.ports) != 7 {
			t.Fatalf("heavy key %d: %+v", k, it)
		}
	}
	for i := range h.items {
		if h.pos[h.items[i].key] != i || i > 0 && h.less(i, (i-1)/2) {
			t.Fatalf("heap broken at %d", i)
		}
	}
	// No room: nothing kept.
	none := newHeavy[int](0)
	none.add(1, 5, 0, nil)
	if len(none.items) != 0 {
		t.Fatal("kept without room")
	}
}

func TestTopKeepsTheFirst(t *testing.T) {
	items := make([]int, 10_000)
	for i := range items {
		items[i] = (i * 7919) % len(items)
	}
	for _, k := range []int{0, 1, 5, 10_000, 20_000} {
		got := topK(items, k, func(a, b int) int { return b - a }) // largest first
		if len(got) != min(k, len(items)) {
			t.Fatalf("k=%d: %d items", k, len(got))
		}
		for i, x := range got {
			if x != len(items)-1-i {
				t.Fatalf("k=%d: item %d is %d", k, i, x)
			}
		}
	}
}
