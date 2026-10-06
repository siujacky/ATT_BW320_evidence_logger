package netmap

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"math/rand/v2"
	"strconv"
	"sync"
	"testing"
	"time"

	"attmonitor/internal/contracts"
	"attmonitor/internal/model"
)

// The benchmarks' syslog: 100 sealed chunks of 20,000 lines, a line every 1.3 seconds - a month
// of a busy gateway's firewall log (two million lines).
const (
	benchChunks = 100
	benchLines  = 20000
	benchStep   = 1300 * time.Millisecond
)

// memSource serves sealed chunks from memory as the syslog store keeps them (gzip of JSON lines).
type memSource struct {
	refs []model.SyslogChunkRef
	gz   map[string][]byte
}

func (m *memSource) Chunks() []model.SyslogChunkRef { return m.refs }

func (m *memSource) OpenChunk(name string) (io.ReadCloser, error) {
	b, ok := m.gz[name]
	if !ok {
		return nil, fmt.Errorf("chunk %q: %w", name, contracts.ErrNotFound)
	}
	return io.NopCloser(bytes.NewReader(b)), nil
}

func (m *memSource) EachOpen(context.Context, time.Time, time.Time, func(*model.SyslogMessage) error) error {
	return nil
}

func (m *memSource) Usage() model.SyslogUsage {
	return model.SyslogUsage{Chunks: len(m.refs), Oldest: m.refs[0].From, Newest: m.refs[len(m.refs)-1].To}
}

// benchStart is when the benchmarks' syslog starts.
var benchStart = t0.Add(-benchChunks * benchLines * benchStep)

// benchSource builds the benchmarks' syslog once: inbound drops from 20,000 sources (the 768
// IPv4 documentation addresses, then IPv6 ones) to 1,000 ports, repeat lines, outbound drops of
// a few LAN devices, pings and the gateway's own packets.
var benchSource = sync.OnceValue(func() *memSource {
	r := rand.New(rand.NewPCG(1, 2))
	src := func(i int) string {
		switch {
		case i < 256:
			return "192.0.2." + strconv.Itoa(i)
		case i < 512:
			return "198.51.100." + strconv.Itoa(i-256)
		case i < 768:
			return "203.0.113." + strconv.Itoa(i-512)
		}
		return fmt.Sprintf("2001:db8:%x::%x", i/65536, i%65536+1)
	}
	m := &memSource{gz: map[string][]byte{}}
	var raw bytes.Buffer
	for c := range benchChunks {
		raw.Reset()
		var first, last time.Time
		for i := range benchLines {
			rx := benchStart.Add(time.Duration(c*benchLines+i) * benchStep)
			if i == 0 {
				first = rx
			}
			last = rx
			var text string
			switch k := r.IntN(100); {
			case k < 70:
				text = fwLine(src(int(r.ExpFloat64()*3000)%20000), []string{"TCP", "UDP"}[r.IntN(2)], 1+r.IntN(1000))
			case k < 85:
				text = repeatLine(1 + r.IntN(4))
			case k < 95:
				text = outLine("192.168.1."+strconv.Itoa(60+r.IntN(8)), src(r.IntN(768)), []int{443, 853, 3478}[r.IntN(3)], "POLICY")
			case k < 98:
				text = linePing
			default:
				text = lineGateway
			}
			// As json.Marshal writes a model.SyslogMessage of the receiver.
			raw.WriteString(`{"rx":"` + rx.Format(time.RFC3339Nano) + `","src":"192.168.1.254:514","raw":"<12>` +
				text + `","format":"unknown","pri":12,"facility":1,"severity":4,"msg":"` + text + "\"}\n")
		}
		var gz bytes.Buffer
		zw, _ := gzip.NewWriterLevel(&gz, gzip.BestSpeed)
		zw.Write(raw.Bytes())
		zw.Close()
		name := fmt.Sprintf("syslog-%03d.jsonl.gz", c)
		m.gz[name] = gz.Bytes()
		m.refs = append(m.refs, model.SyslogChunkRef{Name: name, SHA256: "sha-" + name, From: first.Format(time.RFC3339Nano),
			To: last.Format(time.RFC3339Nano), Messages: benchLines, GzBytes: int64(gz.Len())})
	}
	return m
})

// monthQuery asks for the whole month (every chunk wholly inside it).
var monthQuery = contracts.NetQuery{From: benchStart.Add(-time.Hour), To: t0.Add(time.Hour)}

// BenchmarkFirewallCold builds the month's firewall view without anything cached: every line
// of every chunk is read.
func BenchmarkFirewallCold(b *testing.B) {
	src := benchSource()
	ctx := context.Background()
	for b.Loop() {
		v := New(Options{Syslog: src, ResultTTL: -1})
		if fw, err := v.Firewall(ctx, monthQuery); err != nil || fw.Drops == 0 {
			b.Fatal(fw.Drops, err)
		}
	}
	b.ReportMetric(float64(benchChunks*benchLines)*float64(b.N)/b.Elapsed().Seconds(), "lines/s")
}

// BenchmarkFirewallWarm builds the month's firewall view again with every chunk's summary
// cached (the result cache off).
func BenchmarkFirewallWarm(b *testing.B) {
	src := benchSource()
	ctx := context.Background()
	v := New(Options{Syslog: src, ResultTTL: -1})
	if _, err := v.Firewall(ctx, monthQuery); err != nil {
		b.Fatal(err)
	}
	entries, size := v.chunks.stats()
	if entries != benchChunks {
		b.Fatalf("%d summaries cached (%d bytes)", entries, size)
	}
	for b.Loop() {
		if _, err := v.Firewall(ctx, monthQuery); err != nil {
			b.Fatal(err)
		}
	}
	b.ReportMetric(float64(size)/(1<<20), "cache-MiB")
}

// BenchmarkFirewallDay builds the view of 24 hours that end at a different time each time (the
// two chunks at its ends are read again, the ones inside come from the cache).
func BenchmarkFirewallDay(b *testing.B) {
	src := benchSource()
	ctx := context.Background()
	v := New(Options{Syslog: src, ResultTTL: -1})
	if _, err := v.Firewall(ctx, monthQuery); err != nil {
		b.Fatal(err)
	}
	i := 0
	for b.Loop() {
		to := benchStart.Add(29*24*time.Hour + time.Duration(i)*time.Minute)
		if _, err := v.Firewall(ctx, contracts.NetQuery{From: to.Add(-24 * time.Hour), To: to}); err != nil {
			b.Fatal(err)
		}
		i++
	}
}

func BenchmarkParseLine(b *testing.B) {
	c := newCodes()
	text := []byte(lineInbound)
	b.SetBytes(int64(len(text)))
	for b.Loop() {
		if kind, _, _ := c.parse(text); kind != lineDrop {
			b.Fatal(kind)
		}
	}
}

func BenchmarkLineText(b *testing.B) {
	line := marshal(b, syslogMsg(t0, lineInbound))
	b.SetBytes(int64(len(line)))
	for b.Loop() {
		if _, _, ok := lineText(line); !ok {
			b.Fatal("not read")
		}
	}
}

// BenchmarkConnections builds the connections view of 5,000 flows (the result cache off).
func BenchmarkConnections(b *testing.B) {
	in := newFakeIntel()
	var flows []model.ConnFlow
	for i := range 5000 {
		remote := fmt.Sprintf("2001:db8:%x::1", i)
		if i%3 == 0 {
			remote = "203.0.113." + strconv.Itoa(i%256)
			in.know(remote, 64496+i%16, "Org "+strconv.Itoa(i%16), []string{"US", "DE", "JP"}[i%3])
		}
		flows = append(flows, model.ConnFlow{Device: "ip:192.168.1." + strconv.Itoa(60+i%8), Remote: remote, Proto: "tcp",
			Port: []int{443, 80, 22, 8443}[i%4], Samples: 1 + i%50, Weight: 1 + i%70})
	}
	conns := &fakeConns{agg: model.ConnAggregate{Samples: 360, Flows: flows}}
	v := New(Options{Conns: conns, Intel: in, ResultTTL: -1})
	ctx := context.Background()
	for b.Loop() {
		if _, err := v.Connections(ctx, contracts.NetQuery{From: t0, To: t0.Add(24 * time.Hour)}); err != nil {
			b.Fatal(err)
		}
		conns.calls()
		in.askedPTR()
	}
}
