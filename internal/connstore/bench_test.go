package connstore

import (
	"bytes"
	"context"
	"io"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"attmonitor/internal/contracts"
	"attmonitor/internal/model"
)

// The benchmarks' realistic volume (docs/syslog-map-graphic.md): a NAT table read every 4
// minutes - 360 a day - of about 400 sessions, and a Device List read of 10 devices every 15
// minutes, for 30 days, plus today until noon.
const (
	benchDays     = 30
	benchReads    = 360
	benchSessions = 400
	benchDevices  = 10
)

// benchNow is the benchmarks' clock: noon of the day after the 30 whole days.
var benchNow = at(benchDays, 12, 0)

var (
	benchOnce sync.Once
	benchPath string
	benchErr  error
)

// TestMain removes the benchmarks' shared directory once every test and benchmark has run.
func TestMain(m *testing.M) {
	code := m.Run()
	if benchPath != "" {
		os.RemoveAll(benchPath)
	}
	os.Exit(code)
}

// benchDir returns a directory with the benchmarks' days, written once - directly, not through
// 10,800 fsynced appends - and shared by the benchmarks, which must not change it.
func benchDir(b *testing.B) string {
	b.Helper()
	benchOnce.Do(func() {
		benchPath, benchErr = os.MkdirTemp("", "connstore-bench-")
		if benchErr == nil {
			benchErr = writeBenchDays(benchPath)
		}
	})
	if benchErr != nil {
		b.Fatal(benchErr)
	}
	return benchPath
}

// benchGen makes the reads of a household: devices that keep connections open for a while and
// open new ones, mostly HTTPS, to remote addresses some of which are far more popular than
// others (all from the documentation ranges).
type benchGen struct {
	rng     *rand.Rand
	remotes []string
	flows   []benchFlow
}

type benchFlow struct {
	host, port, sport, sessions int
	remote, proto               string
}

func newBenchGen(seed uint64) *benchGen {
	g := &benchGen{rng: rand.New(rand.NewPCG(seed, seed))}
	for _, n := range []string{"192.0.2.", "198.51.100.", "203.0.113."} {
		for i := range 256 {
			g.remotes = append(g.remotes, n+strconv.Itoa(i))
		}
	}
	return g
}

// newFlow returns a connection a device opens now.
func (g *benchGen) newFlow() benchFlow {
	u := g.rng.Float64()
	f := benchFlow{host: 64 + g.rng.IntN(benchDevices+1), remote: g.remotes[int(u*u*u*float64(len(g.remotes)))],
		port: 443, proto: "tcp", sport: 32768 + g.rng.IntN(28000), sessions: 1 + g.rng.IntN(3)}
	switch r := g.rng.IntN(20); {
	case r < 3:
		f.port, f.proto = 443, "udp"
	case r < 5:
		f.port, f.proto = 53, "udp"
	case r < 6:
		f.port = 80
	case r < 7:
		f.port = []int{5228, 8883, 993, 3478}[g.rng.IntN(4)]
	}
	return f
}

// read returns the next NAT table read: nine in ten connections are still open, new ones fill
// it up to about 400 sessions.
func (g *benchGen) read() model.NATTable {
	kept := g.flows[:0]
	n := 0
	for _, f := range g.flows {
		if g.rng.IntN(10) > 0 {
			kept = append(kept, f)
			n += f.sessions
		}
	}
	g.flows = kept
	for n < benchSessions {
		f := g.newFlow()
		g.flows = append(g.flows, f)
		n += f.sessions
	}
	nt := model.NATTable{InUse: n, Available: 16384 - n, Sessions: make([]model.NATSession, 0, n)}
	for _, f := range g.flows {
		for i := range f.sessions {
			src := "192.168.1." + strconv.Itoa(f.host)
			nt.Sessions = append(nt.Sessions, model.NATSession{Proto: f.proto, State: "ESTABLISHED", Src: src,
				SrcPort: f.sport + i, Dst: f.remote, DstPort: f.port})
		}
	}
	return nt
}

// devices returns a Device List read: the 10 devices (the 11th address is not listed).
func (g *benchGen) devices() []model.LANDevice {
	out := make([]model.LANDevice, benchDevices)
	for i := range out {
		out[i] = model.LANDevice{MAC: macOf(0x40 + i), Name: "bench-device-" + strconv.Itoa(i), IPv4: "192.168.1." + strconv.Itoa(64+i),
			Status: "on", Allocation: "dhcp", Connection: []string{"Wi-Fi 5 GHz", "Ethernet"}[i%2]}
	}
	return out
}

// writeBenchDays writes the benchmarks' days into dir: the 30 whole days compressed, today's
// first half plain.
func writeBenchDays(dir string) error {
	g := newBenchGen(7)
	for d := 0; d <= benchDays; d++ {
		var nat, dev bytes.Buffer
		reads := benchReads
		if d == benchDays {
			reads /= 2
		}
		for i := range reads {
			t := at(d, 0, 0).Add(time.Duration(i) * 4 * time.Minute)
			if i%15 == 0 || i%15 == 4 || i%15 == 8 || i%15 == 11 { // every 15 minutes, near enough
				line, err := encodeDevices(t, g.devices())
				if err != nil {
					return err
				}
				dev.Write(line)
			}
			line, err := encodeNAT(t, g.read())
			if err != nil {
				return err
			}
			nat.Write(line)
		}
		for k, content := range map[kind][]byte{kindNAT: nat.Bytes(), kindDevices: dev.Bytes()} {
			path := filepath.Join(dir, fileName(k, dayOf(at(d, 0, 0)), d < benchDays))
			var err error
			if d < benchDays {
				_, _, err = writeGzip(path, func(w io.Writer) error { _, err := w.Write(content); return err })
			} else {
				err = os.WriteFile(path, content, 0o644)
			}
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// benchStore opens the benchmarks' days with the clock at benchNow.
func benchStore(b *testing.B) *Store {
	b.Helper()
	s, err := Open(benchDir(b), Options{KeepDays: 60, Now: func() time.Time { return benchNow }})
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { s.Close() })
	return s
}

// benchAggregate runs q b.N times and reports the reads, flows and lines decoded per query.
func benchAggregate(b *testing.B, s *Store, q contracts.ConnQuery, cold bool) {
	b.Helper()
	ctx := context.Background()
	if !cold {
		if _, err := s.Aggregate(ctx, q); err != nil { // warm the cache
			b.Fatal(err)
		}
	}
	lines := s.stats.lines.Load()
	var a model.ConnAggregate
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if cold {
			b.StopTimer()
			s.sums = newDayCache[sumKey, *sumEntry](summaryDays, summaryWeight)
			s.devs = newDayCache[devKey, []*devRead](deviceDays, deviceDays)
			b.StartTimer()
		}
		var err error
		if a, err = s.Aggregate(ctx, q); err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
	b.ReportMetric(float64(a.Samples), "reads")
	b.ReportMetric(float64(len(a.Flows)), "flows")
	b.ReportMetric(float64(s.stats.lines.Load()-lines)/float64(b.N), "lines-decoded/op")
	n, w := s.sums.size()
	b.ReportMetric(float64(n), "cached-days")
	b.ReportMetric(float64(w), "cached-weight")
}

// BenchmarkAggregate24h is the Network page's default view: the last 24 hours, half of
// yesterday and half of today, both read raw.
func BenchmarkAggregate24h(b *testing.B) {
	benchAggregate(b, benchStore(b), contracts.ConnQuery{From: benchNow.Add(-24 * time.Hour), To: benchNow}, false)
}

// BenchmarkAggregate7dWarm is a week, its 6 whole days from the cache.
func BenchmarkAggregate7dWarm(b *testing.B) {
	benchAggregate(b, benchStore(b), contracts.ConnQuery{From: benchNow.Add(-7 * 24 * time.Hour), To: benchNow}, false)
}

// BenchmarkAggregate30dWarm is the longest view, its 29 whole days from the cache.
func BenchmarkAggregate30dWarm(b *testing.B) {
	benchAggregate(b, benchStore(b), contracts.ConnQuery{From: benchNow.Add(-30 * 24 * time.Hour), To: benchNow}, false)
}

// BenchmarkAggregate30dWarmDevice is the longest view filtered to one device.
func BenchmarkAggregate30dWarmDevice(b *testing.B) {
	benchAggregate(b, benchStore(b), contracts.ConnQuery{From: benchNow.Add(-30 * 24 * time.Hour), To: benchNow,
		Device: macKey(0x40)}, false)
}

// BenchmarkAggregate30dCold is the longest view with an empty cache: every day is read.
func BenchmarkAggregate30dCold(b *testing.B) {
	benchAggregate(b, benchStore(b), contracts.ConnQuery{From: benchNow.Add(-30 * 24 * time.Hour), To: benchNow}, true)
}

// BenchmarkOpen opens the 30 days (the monitor's start).
func BenchmarkOpen(b *testing.B) {
	dir := benchDir(b)
	b.ResetTimer()
	for range b.N {
		s, err := Open(dir, Options{KeepDays: 60, Now: func() time.Time { return benchNow }})
		if err != nil {
			b.Fatal(err)
		}
		s.Close()
	}
}

// BenchmarkAppendNAT appends reads of about 400 sessions (each written and fsynced).
func BenchmarkAppendNAT(b *testing.B) {
	g := newBenchGen(9)
	reads := make([]model.NATTable, 64)
	for i := range reads {
		reads[i] = g.read()
	}
	t0 := at(0, 0, 0)
	s, err := Open(b.TempDir(), Options{Now: func() time.Time { return t0 }})
	if err != nil {
		b.Fatal(err)
	}
	defer s.Close()
	b.ResetTimer()
	for i := range b.N {
		if err := s.AppendNAT(t0.Add(time.Duration(i)*time.Second), reads[i%len(reads)]); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkCompressDay compresses a day of NAT table reads (once a day, at the first read of
// the next day).
func BenchmarkCompressDay(b *testing.B) {
	g := newBenchGen(11)
	var content bytes.Buffer
	for i := range benchReads {
		line, err := encodeNAT(at(0, 0, 0).Add(time.Duration(i)*4*time.Minute), g.read())
		if err != nil {
			b.Fatal(err)
		}
		content.Write(line)
	}
	path := filepath.Join(b.TempDir(), "day.jsonl.gz")
	var gzSize int64
	b.SetBytes(int64(content.Len()))
	b.ResetTimer()
	for range b.N {
		var err error
		if _, gzSize, err = writeGzip(path, func(w io.Writer) error { _, err := w.Write(content.Bytes()); return err }); err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
	b.ReportMetric(float64(content.Len())/(1<<20), "MiB-plain")
	b.ReportMetric(float64(gzSize)/(1<<20), "MiB-gz")
}
