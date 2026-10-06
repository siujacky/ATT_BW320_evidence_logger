package ipintel

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"math/rand/v2"
	"net/netip"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// benchRows is the size of a real IPv4 table.
const benchRows = 500_000

var (
	benchOnce sync.Once
	benchGz   []byte // a benchRows-line IPv4 table, gzip-compressed
)

// benchTable returns a synthetic IPv4 table of benchRows lines like the real one: /22 ranges
// from 1.0.0.0, every fourth one not routed, of 60,000 ASes (documentation-style names).
func benchTable(b *testing.B) []byte {
	benchOnce.Do(func() {
		var raw bytes.Buffer
		for i := range benchRows {
			start := uint32(0x01000000) + uint32(i)<<10
			if i%4 == 3 {
				fmt.Fprintf(&raw, "%s\t%s\t0\tNone\tNot routed\n", string32(start), string32(start+1023))
				continue
			}
			asn := 100000 + i%60000
			fmt.Fprintf(&raw, "%s\t%s\t%d\tUS\tEXAMPLE-AS-%d Example Networks %d Ltd\n", string32(start), string32(start+1023), asn, asn, asn)
		}
		var z bytes.Buffer
		zw := gzip.NewWriter(&z)
		zw.Write(raw.Bytes())
		zw.Close()
		benchGz = z.Bytes()
	})
	return benchGz
}

// BenchmarkLoad measures the load of a table of the real IPv4 table's size (decompress, parse,
// check, build).
func BenchmarkLoad(b *testing.B) {
	gz := benchTable(b)
	b.SetBytes(int64(len(gz)))
	b.ReportAllocs()
	for b.Loop() {
		l, err := parseGzip(context.Background(), bytes.NewReader(gz), fam4)
		if err != nil || l.stats.rows != benchRows {
			b.Fatal(err)
		}
	}
}

// BenchmarkLoadHostile loads tables made to push the parser's limits, and reports the most heap
// in use while each is read, above what was in use before (peak-heap-MiB: sampled every
// millisecond, so a little low if anything) and the size of its file (gzip-MiB). The limits of
// parse.go keep each within a few times what a table of the real one's size takes ("real-size",
// BenchmarkLoad's table) - their doc comment quotes these figures. Run it with
//
//	go test -run=^$ -bench=LoadHostile -benchtime=3x ./internal/ipintel/
func BenchmarkLoadHostile(b *testing.B) {
	// line is a data line of the IPv4 range of index i (16 addresses: no two adjacent).
	line := func(i, asn int, desc string) string {
		a := uint32(0x01000000) + uint32(i)<<4
		return fmt.Sprintf("%s\t%s\t%d\tUS\t%s\n", string32(a), string32(a+7), asn, desc)
	}
	// most makes the table of the lines row returns for 0, 1, 2 ..., as many as the limits let
	// through: maxRows, or as many whole lines as fit in maxContentBytes.
	most := func(row func(i int) string) func(io.Writer) {
		return func(w io.Writer) {
			total := 0
			for i := range maxRows {
				s := row(i)
				if total += len(s); total > maxContentBytes-1<<10 {
					return
				}
				io.WriteString(w, s)
			}
		}
	}
	cases := []struct {
		name    string
		fam     family
		refused bool
		table   func(w io.Writer)
	}{
		{"real-size", fam4, false, nil},
		// A review's experiment: 110,000 lines, each with a description of its own of 2.2 KB.
		{"long-descriptions", fam4, true, func(w io.Writer) {
			pad := strings.Repeat("x", 2200)
			for i := range 110_000 {
				io.WriteString(w, line(i, 64496+i%1000, fmt.Sprintf("D%09d %s", i, pad)))
			}
		}},
		// As many networks as allowed, then lines of the first one.
		{"most-networks", fam4, false, most(func(i int) string {
			if i < maxNetworks {
				return line(i, 100000+i, fmt.Sprintf("N%07d", i))
			}
			return line(i, 100000, "N0000000")
		})},
		// Networks of the longest names, up to maxNamesBytes, then lines of one more network.
		{"most-names", fam4, false, most(func(i int) string {
			if i < maxNamesBytes/maxNameBytes {
				return line(i, 100000+i, fmt.Sprintf("N%07d %s", i, strings.Repeat("z", maxNameBytes-9)))
			}
			return line(i, 1, "")
		})},
		// IPv6 ranges, no two adjacent, of one network: the ranges take the most memory a table
		// can (32 bytes of addresses each, against 8 in IPv4).
		{"most-ipv6-ranges", fam6, false, most(func(i int) string {
			return fmt.Sprintf("::%x:%x\t::%x:%x\t1\t\t\n", i>>15, (i&0x7fff)*2, i>>15, (i&0x7fff)*2)
		})},
	}
	for _, c := range cases {
		b.Run(c.name, func(b *testing.B) {
			gz := benchTable(b)
			if c.table != nil {
				var z bytes.Buffer
				zw, _ := gzip.NewWriterLevel(&z, gzip.BestSpeed)
				c.table(zw)
				zw.Close()
				gz = z.Bytes()
			}
			var peak uint64
			for b.Loop() {
				var err error
				peak = max(peak, peakHeap(func() { _, err = parseGzip(context.Background(), bytes.NewReader(gz), c.fam) }))
				if (err != nil) != c.refused {
					b.Fatalf("refused: %v, want %v", err, c.refused)
				}
			}
			b.ReportMetric(float64(peak)/(1<<20), "peak-heap-MiB")
			b.ReportMetric(float64(len(gz))/(1<<20), "gzip-MiB")
		})
	}
}

// peakHeap runs f and returns the most heap in use (runtime.MemStats.HeapInuse) seen while it
// ran, above what was in use before.
func peakHeap(f func()) uint64 {
	runtime.GC()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	base, peak := ms.HeapInuse, ms.HeapInuse
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Go(func() {
		var ms runtime.MemStats
		tick := time.NewTicker(time.Millisecond)
		defer tick.Stop()
		for {
			runtime.ReadMemStats(&ms)
			peak = max(peak, ms.HeapInuse)
			select {
			case <-done:
				return
			case <-tick.C:
			}
		}
	})
	f()
	close(done)
	wg.Wait()
	return peak - base
}

// BenchmarkLookup measures Lookup of public IPv4 addresses in a table of the real size.
func BenchmarkLookup(b *testing.B) {
	l, err := parseGzip(context.Background(), bytes.NewReader(benchTable(b)), fam4)
	if err != nil {
		b.Fatal(err)
	}
	d, err := Open(b.TempDir(), Options{Enabled: true})
	if err != nil {
		b.Fatal(err)
	}
	d.install(l)
	addrs := make([]netip.Addr, 4096)
	rng := rand.New(rand.NewPCG(1, 2))
	for i := range addrs {
		v := uint32(0x01000000) + rng.Uint32N(benchRows<<10)
		addrs[i] = netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
	}
	b.ReportAllocs()
	i := 0
	for b.Loop() {
		d.Lookup(addrs[i&4095])
		i++
	}
}

// BenchmarkLookupIPv6 measures Lookup of public IPv6 addresses (a small table: the search is
// logarithmic).
func BenchmarkLookupIPv6(b *testing.B) {
	d, err := Open(b.TempDir(), Options{Enabled: true})
	if err != nil {
		b.Fatal(err)
	}
	l, err := parseGzip(context.Background(), bytes.NewReader(gzRows(rows6)), fam6)
	if err != nil {
		b.Fatal(err)
	}
	d.install(l)
	a := netip.MustParseAddr("2a00:1450:4001:80b::200e")
	b.ReportAllocs()
	for b.Loop() {
		d.Lookup(a)
	}
}
