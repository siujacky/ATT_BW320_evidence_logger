package ipintel

import (
	"context"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"attmonitor/internal/model"
)

// TestLookupDuringSwap looks addresses up while the tables are swapped back and forth, and
// checks that each lookup sees one table whole: never the ASN of one with the name of the other.
// Run it with -race.
func TestLookupDuringSwap(t *testing.T) {
	other4 := slices.Clone(rows4)
	other4[6] = row{"8.8.8.0", "8.8.8.255", 64510, "AU", "EXAMPLE-SWAPPED"}
	other6 := slices.Clone(rows6)
	other6[1] = row{"2001:4860::", "2001:4860:ffff:ffff:ffff:ffff:ffff:ffff", 64511, "NZ", "EXAMPLE-SWAPPED6"}
	ctx := context.Background()
	load := func(b []byte, f family) *loaded {
		l, err := parseGzip(ctx, bytesReader(b), f)
		if err != nil {
			t.Fatal(err)
		}
		return l
	}
	a4, b4 := load(gzRows(rows4), fam4), load(gzRows(other4), fam4)
	a6, b6 := load(gzRows(rows6), fam6), load(gzRows(other6), fam6)
	want := map[string][2]model.IPInfo{
		"8.8.8.8": {
			{Kind: model.IPKindPublic, ASN: 15169, Org: "Google", ASName: "GOOGLE", Country: "US"},
			{Kind: model.IPKindPublic, ASN: 64510, Org: "Example Swapped", ASName: "EXAMPLE-SWAPPED", Country: "AU"},
		},
		"2001:4860::8888": {
			{Kind: model.IPKindPublic, ASN: 15169, Org: "Google", ASName: "GOOGLE", Country: "US"},
			{Kind: model.IPKindPublic, ASN: 64511, Org: "Example Swapped6", ASName: "EXAMPLE-SWAPPED6", Country: "NZ"},
		},
	}

	d := openTest(t, t.TempDir(), Options{})
	d.install(a4)
	d.install(a6)
	var stop atomic.Bool
	var wg sync.WaitGroup
	var lookups atomic.Int64
	for range 8 {
		wg.Go(func() {
			for !stop.Load() {
				for s, w := range want {
					got := d.Lookup(mustAddr(t, s))
					if got != w[0] && got != w[1] {
						t.Errorf("Lookup(%s) = %+v: a mix of two tables", s, got)
						return
					}
					lookups.Add(1)
				}
				d.Status()
				d.Updated()
				d.PTR(mustAddr(t, "8.8.8.8"), false)
			}
		})
	}
	// Swap until the readers have done plenty of lookups (they may start late).
	deadline := time.Now().Add(10 * time.Second)
	swaps := 0
	for ; swaps < 2000 || lookups.Load() < 20000; swaps++ {
		if swaps%2 == 0 {
			d.install(b4)
			d.install(b6)
		} else {
			d.install(a4)
			d.install(a6)
		}
		if time.Now().After(deadline) {
			break
		}
	}
	stop.Store(true)
	wg.Wait()
	if n := lookups.Load(); n < 20000 {
		t.Fatalf("only %d lookups during %d swaps", n, swaps)
	}
}

// TestRunAndLookupsConcurrently runs Run (loading, reloading and resolving) while other
// goroutines look up, ask for names and for the status. Run it with -race.
func TestRunAndLookupsConcurrently(t *testing.T) {
	dir := t.TempDir()
	writeTables(t, dir, gzRows(rows4), gzRows(rows6))
	r := newFakeResolver()
	r.set("8.8.8.8", "dns.google")
	d := openTest(t, dir, Options{ReverseDNS: true, Resolver: r})
	stop := startRun(t, d)
	var wg sync.WaitGroup
	for i := range 4 {
		wg.Go(func() {
			for j := range 2000 {
				d.Lookup(mustAddr(t, "8.8.8.8"))
				d.Lookup(mustAddr(t, "2606:4700::1"))
				d.PTR(mustAddr(t, "8.8.8.8"), true)
				d.PTR(mustAddr(t, "11.0.0.1"), j%7 == i)
				d.Service("udp", 443)
				d.Status()
			}
		})
	}
	wg.Wait()
	waitFor(t, "the tables", func() bool { return d.Status().V4Ranges == 10 && d.Status().V6Ranges == 4 })
	waitFor(t, "the name", func() bool { return d.PTR(mustAddr(t, "8.8.8.8"), false) == "dns.google" })
	stop()
}
