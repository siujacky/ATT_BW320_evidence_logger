package monitor

import (
	"context"
	"errors"
	"math"
	"reflect"
	"testing"
	"time"

	"attmonitor/internal/model"
)

// ---------------------------------------------------------------------------- helpers

// addCycles adds an ONLINE cycle every 10 s from from to to (inclusive), as the fast cycle
// records them.
func addCycles(ps *pointStore, from, to time.Time) {
	for at := from; !at.After(to); at = at.Add(10 * time.Second) {
		ps.addSample(at, sampleAt(model.StateOnline, false))
	}
}

// ctrSnap is a reachable snapshot taken at at whose broadbandstatistics page shows the given WAN
// counters (bytes and packets received, sent) and whose sysinfo shows the given uptime.
func ctrSnap(seq uint64, at time.Time, rxB, rxP, txB, txP, up int64) *snapObs {
	s := okSnapshot(allPages, at)
	s.System.UptimeSec = up
	s.Broadband.Counters = map[string]int64{ctrRxBytes: rxB, ctrRxPkts: rxP, ctrTxBytes: txB, ctrTxPkts: txP}
	return &snapObs{Seq: seq, At: at, Snap: &s, live: true}
}

// wanFeed produces the snapshots of a gateway whose WAN carries what the test says: 32-bit byte
// counters (they wrap every 4 GiB) and an uptime that advances with time.
type wanFeed struct {
	seq                uint64
	at                 time.Time
	rxB, rxP, txB, txP int64 // since the gateway booted (bytes not wrapped)
	up                 int64
}

func newWANFeed(at time.Time) *wanFeed { return &wanFeed{at: at, up: 100_000} }

// add advances the feed by d, in which the WAN carried the given bytes and packets.
func (f *wanFeed) add(d time.Duration, rxB, rxP, txB, txP int64) *snapObs {
	f.seq++
	f.at = f.at.Add(d)
	f.up += int64(d / time.Second)
	f.rxB, f.rxP, f.txB, f.txP = f.rxB+rxB, f.rxP+rxP, f.txB+txB, f.txP+txP
	return ctrSnap(f.seq, f.at, f.rxB%(1<<32), f.rxP, f.txB%(1<<32), f.txP, f.up)
}

// next advances the feed by d at the given rates (Mb/s, 1500-byte packets).
func (f *wanFeed) next(d time.Duration, rxMbps, txMbps float64) *snapObs {
	rx, tx := int64(math.Round(rxMbps*1e6/8*d.Seconds())), int64(math.Round(txMbps*1e6/8*d.Seconds()))
	return f.add(d, rx, rx/1500, tx, tx/1500)
}

// reboot restarts the gateway: its uptime and counters start again.
func (f *wanFeed) reboot() { f.up, f.rxB, f.rxP, f.txB, f.txP = 0, 0, 0, 0, 0 }

func pcLink(iface string, rx, tx uint64) *model.LocalLink {
	return &model.LocalLink{Interface: iface, Type: "wifi", State: "connected", RxBytes: &rx, TxBytes: &tx}
}

// checkRate fails unless a chart rate is shown and equals want (charts round to 1 kb/s).
func checkRate(t *testing.T, what string, got *float64, want float64) {
	t.Helper()
	if got == nil || math.Abs(*got-want) > 5e-4+1e-9 {
		v := "none"
		if got != nil {
			v = fmtNum(*got)
		}
		t.Errorf("%s: %s, want %s", what, v, fmtNum(want))
	}
}

// noTraffic fails if a bucket shows any rate.
func noTraffic(t *testing.T, what string, p model.TrafficPoint) {
	t.Helper()
	if p.WANRx != nil || p.WANTx != nil || p.WANRxPeak != nil || p.WANTxPeak != nil || p.AtLeast || p.PCRx != nil || p.PCTx != nil {
		t.Errorf("%s: no traffic is known there: %+v", what, p)
	}
}

// ---------------------------------------------------------------------------- intervals

// The WAN intervals of the traffic history come from wanTrafficOf between consecutive snapshots
// with counters: exact rates, a wrap of the 32-bit byte counter, "at least" rates, and unknown
// intervals after a restart (counters reset), with a counter missing and between readings
// further apart than maxTrafficSpan. The times are the broadbandstatistics fetch times.
func TestTrafficHistoryWAN(t *testing.T) {
	ps := newPointStore()
	addCycles(ps, t0, t0.Add(30*time.Minute))
	gap := gapLimit(10 * time.Second)
	at := func(s int) time.Time { return t0.Add(time.Duration(s) * time.Second) }
	ps.addWAN(ctrSnap(1, at(0), 4_200_000_000, 1_000, 2_000, 20, 100), gap)
	if len(ps.wan) != 0 {
		t.Fatalf("one reading makes no interval: %+v", ps.wan)
	}
	// 75 MB received and 7.5 MB sent in 60 s: 10 and 1 Mb/s. The snapshot began 3 s before it
	// fetched the counters.
	s2 := ctrSnap(2, at(60), 4_275_000_000, 61_000, 7_502_000, 10_020, 160)
	s2.At = at(57)
	ps.addWAN(s2, gap)
	// 75 MB more: the 32-bit byte counter wrapped once, which 60 000 packets tell for certain.
	ps.addWAN(ctrSnap(3, at(120), 4_350_000_000-1<<32, 121_000, 15_002_000, 20_020, 220), gap)
	// 1 GB in five million packets: the counter may have wrapped again, so "at least".
	ps.addWAN(ctrSnap(4, at(180), 4_350_000_000-1<<32+1_000_000_000, 5_121_000, 22_502_000, 30_020, 280), gap)
	// The gateway restarted: its uptime and counters start again.
	ps.addWAN(ctrSnap(5, at(240), 5_000, 50, 4_000, 40, 30), gap)
	// A snapshot that lacks a counter (an unparsed row): no rate to it, nor from it.
	s6 := ctrSnap(6, at(300), 755_000, 550, 79_000, 540, 90)
	delete(s6.Snap.Broadband.Counters, ctrTxPkts)
	ps.addWAN(s6, gap)
	ps.addWAN(ctrSnap(7, at(360), 1_505_000, 1_050, 154_000, 1_040, 150), gap)
	ps.addWAN(ctrSnap(8, at(420), 2_255_000, 1_550, 229_000, 1_540, 210), gap)
	// Six minutes without a reading (more than maxTrafficSpan).
	ps.addWAN(ctrSnap(9, at(780), 9_755_000, 6_550, 979_000, 6_540, 570), gap)

	wants := []struct {
		from, to       int
		known, atLeast bool
		rx, tx         float64
		rxB, txB       int64
	}{
		{0, 60, true, false, 10, 1, 75_000_000, 7_500_000},
		{60, 120, true, false, 10, 1, 75_000_000, 7_500_000},
		{120, 180, true, true, 1e9 * 8 / 60 / 1e6, 1, 1_000_000_000, 7_500_000},
		{180, 240, false, false, 0, 0, 0, 0},
		{240, 300, false, false, 0, 0, 0, 0},
		{300, 360, false, false, 0, 0, 0, 0},
		{360, 420, true, false, 0.1, 0.01, 750_000, 75_000},
		{420, 780, false, false, 0, 0, 0, 0},
	}
	if len(ps.wan) != len(wants) {
		t.Fatalf("%d intervals: %+v", len(ps.wan), ps.wan)
	}
	for i, w := range wants {
		iv := ps.wan[i]
		if iv.from != at(w.from).UnixNano() || iv.to != at(w.to).UnixNano() || iv.known != w.known || iv.atLeast != w.atLeast ||
			math.Abs(iv.rxMbps-w.rx) > 1e-9 || math.Abs(iv.txMbps-w.tx) > 1e-9 || iv.rxBytes != w.rxB || iv.txBytes != w.txB {
			t.Errorf("interval %d: %+v, want %+v", i, iv, w)
		}
	}
	// The classifier's computation gives the same deltas.
	if w := wanTrafficOf(ctrSnap(1, at(0), 4_200_000_000, 1_000, 2_000, 20, 100), s2); w.Err != "" || w.RxBytes != 75_000_000 || w.TxBytes != 7_500_000 || w.heavy() {
		t.Fatalf("wanTrafficOf: %+v", w)
	}
}

// An interval within which the monitor had a gap (no cycle for longer than gapLimit: the
// computer slept, the monitor was stopped) is unknown although the counters span it; the next
// interval, without a gap, has its rate again. The same holds for this computer's counters.
func TestTrafficHistoryGap(t *testing.T) {
	ps := newPointStore()
	gap := gapLimit(10 * time.Second)
	at := func(s int) time.Time { return t0.Add(time.Duration(s) * time.Second) }
	addCycles(ps, at(0), at(60))
	addCycles(ps, at(180), at(900)) // no cycle from 60 s to 180 s
	for _, tc := range []struct {
		a, b int
		want bool
	}{
		{0, 60, false}, {30, 90, false}, {30, 91, true}, {100, 170, true}, {175, 900, false}, {900, 931, true}, {-5, 25, false},
	} {
		if got := ps.gapIn(at(tc.a).UnixNano(), at(tc.b).UnixNano(), gap); got != tc.want {
			t.Errorf("gapIn(%d s, %d s) = %v", tc.a, tc.b, got)
		}
	}

	ps.addWAN(ctrSnap(1, at(30), 0, 0, 0, 0, 100), gap)
	ps.addWAN(ctrSnap(2, at(160), 1_625_000, 1_100, 0, 0, 230), gap) // across the gap
	ps.addWAN(ctrSnap(3, at(280), 3_125_000, 2_100, 0, 0, 350), gap)
	if len(ps.wan) != 2 || ps.wan[0].known || !ps.wan[1].known || math.Abs(ps.wan[1].rxMbps-0.1) > 1e-9 {
		t.Fatalf("WAN %+v", ps.wan)
	}
	span := pcSpanLimit(time.Minute, 10*time.Minute)
	ps.addPC(at(30), pcLink("Wi-Fi", 0, 0), span, gap)
	ps.addPC(at(160), pcLink("Wi-Fi", 1_000, 1_000), span, gap)
	ps.addPC(at(280), pcLink("Wi-Fi", 1_501_000, 1_000), span, gap)
	if len(ps.pc) != 2 || ps.pc[0].known || !ps.pc[1].known || math.Abs(ps.pc[1].rxMbps-0.1) > 1e-9 || ps.pc[1].txMbps != 0 {
		t.Fatalf("PC %+v", ps.pc)
	}
}

// This computer's traffic: rates between consecutive readings with counters (a reading without
// them is spanned), unknown when a counter decreased (the adapter was reset), the readings are
// of another interface, the counters jumped beyond any adapter, or the readings are further
// apart than pcSpanLimit.
func TestTrafficHistoryPC(t *testing.T) {
	ps := newPointStore()
	addCycles(ps, t0, t0.Add(time.Hour))
	gap, span := gapLimit(10*time.Second), pcSpanLimit(time.Minute, 10*time.Minute)
	if span != 12*time.Minute {
		t.Fatalf("span %v", span)
	}
	at := func(s int) time.Time { return t0.Add(time.Duration(s) * time.Second) }
	ps.addPC(at(0), pcLink("Wi-Fi", 1_000_000, 2_000_000), span, gap)
	ps.addPC(at(60), pcLink("Wi-Fi", 8_500_000, 2_750_000), span, gap)
	ps.addPC(at(120), &model.LocalLink{Interface: "Wi-Fi", Type: "wifi", State: "connected"}, span, gap) // no counters
	ps.addPC(at(120), nil, span, gap)
	ps.addPC(at(180), pcLink("Wi-Fi", 23_500_000, 4_250_000), span, gap)
	ps.addPC(at(240), pcLink("Wi-Fi", 500, 600), span, gap)             // the adapter was reset
	ps.addPC(at(300), pcLink("Ethernet", 50_000_000, 7_000), span, gap) // another interface (its counters are higher)
	ps.addPC(at(360), pcLink("Ethernet", 125_000_000, 7_507_000), span, gap)
	ps.addPC(at(1140), pcLink("Ethernet", 150_000_000, 7_607_000), span, gap) // 13 minutes later
	ps.addPC(at(1200), pcLink("Ethernet", 1<<60, 7_707_000), span, gap)       // beyond any adapter
	ps.addPC(at(1260), pcLink("Ethernet", 1<<60+750_000, 7_782_000), span, gap)
	wants := []struct {
		from, to int
		known    bool
		rx, tx   float64
	}{
		{0, 60, true, 1, 0.1},
		{60, 180, true, 1, 0.1},
		{180, 240, false, 0, 0},
		{240, 300, false, 0, 0},
		{300, 360, true, 10, 1},
		{360, 1140, false, 0, 0},
		{1140, 1200, false, 0, 0},
		{1200, 1260, true, 0.1, 0.01},
	}
	if len(ps.pc) != len(wants) {
		t.Fatalf("%d intervals: %+v", len(ps.pc), ps.pc)
	}
	for i, w := range wants {
		iv := ps.pc[i]
		if iv.from != at(w.from).UnixNano() || iv.to != at(w.to).UnixNano() || iv.known != w.known || iv.atLeast ||
			math.Abs(iv.rxMbps-w.rx) > 1e-9 || math.Abs(iv.txMbps-w.tx) > 1e-9 {
			t.Errorf("interval %d: %+v, want %+v", i, iv, w)
		}
	}
}

// The traffic history is kept as long as the other series data: intervals that ended before the
// cutoff are dropped with the cycles (one that ends at it stays).
func TestTrafficPrune(t *testing.T) {
	ps := newPointStore()
	h := func(i int) int64 { return t0.Add(time.Duration(i) * time.Hour).UnixNano() }
	for i := 0; i < 10; i++ {
		ps.wan = append(ps.wan, trafficIv{from: h(i), to: h(i + 1), known: true})
		ps.pc = append(ps.pc, trafficIv{from: h(i + 1), to: h(i)}) // reversed by a clock step
	}
	ps.prune(t0.Add(5 * time.Hour))
	if len(ps.wan) != 6 || ps.wan[0].from != h(4) || len(ps.pc) != 6 || ps.pc[0].to != h(4) {
		t.Fatalf("after prune: wan %+v pc %+v", ps.wan, ps.pc)
	}
}

// ---------------------------------------------------------------------------- series

// Series.Traffic has the buckets of Series.Points: per bucket the time-weighted mean of the known
// interval rates over the time they cover, the highest interval rate, "at least" when one of
// them is, and no rates where no interval is known.
func TestTrafficSeriesBuckets(t *testing.T) {
	ps := newPointStore()
	now := t0.Add(time.Hour) // 04:20:00 UTC
	addCycles(ps, t0, now)
	gap := gapLimit(10 * time.Second)
	f := newWANFeed(t0.Add(20*time.Minute + 20*time.Second)) // 03:40:20
	ps.addWAN(f.add(0, 0, 0, 0, 0), gap)
	ps.addWAN(f.next(time.Minute, 30, 3), gap)                                 // A 03:40:20-03:41:20
	ps.addWAN(f.next(time.Minute, 60, 6), gap)                                 // B 03:41:20-03:42:20
	ps.addWAN(f.next(time.Minute, 20, 2), gap)                                 // C 03:42:20-03:43:20
	ps.addWAN(f.add(time.Minute, 1_000_000_000, 5_000_000, 150_000, 100), gap) // D 03:43:20-03:44:20, at least
	f.reboot()
	ps.addWAN(f.next(time.Minute, 50, 5), gap) // E 03:44:20-03:45:20: unknown (restart)
	ps.addWAN(f.next(time.Minute, 10, 1), gap) // F 03:45:20-03:46:20
	span := pcSpanLimit(time.Minute, 10*time.Minute)
	ps.addPC(t0.Add(30*time.Minute), pcLink("Wi-Fi", 0, 0), span, gap)
	ps.addPC(t0.Add(31*time.Minute), pcLink("Wi-Fi", 15_000_000, 3_750_000), span, gap)  // 03:50-03:51: 2 / 0.5
	ps.addPC(t0.Add(32*time.Minute), pcLink("Wi-Fi", 45_000_000, 15_000_000), span, gap) // 03:51-03:52: 4 / 1.5

	dPeak := 1e9 * 8 / 60 / 1e6 // D: 133.3 Mb/s at least

	series := map[string]model.Series{}
	for _, rng := range []string{"1h", "6h", "24h", "7d"} {
		s, err := ps.buildSeries(rng, now, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if len(s.Traffic) != len(s.Points) || s.HeavyTrafficMbps != heavyTrafficMbps || len(s.TrafficDays) == 0 {
			t.Fatalf("%s: %d traffic points for %d points, heavy %v, %d days", rng, len(s.Traffic), len(s.Points), s.HeavyTrafficMbps, len(s.TrafficDays))
		}
		for i := range s.Points {
			if s.Traffic[i].T != s.Points[i].T {
				t.Fatalf("%s: bucket %d at %s, the point at %s", rng, i, s.Traffic[i].T, s.Points[i].T)
			}
		}
		series[rng] = s
	}
	bucket := func(rng string, hh, mm, ss int) model.TrafficPoint {
		s := series[rng]
		from, _ := parseTS(s.From)
		return s.Traffic[int(time.Date(2026, 10, 5, hh, mm, ss, 0, time.UTC).Sub(from)/(time.Duration(s.StepSec)*time.Second))]
	}

	// 1 h, 10 s buckets: each inside one interval.
	p := bucket("1h", 3, 40, 30)
	checkRate(t, "1h A rx", p.WANRx, 30)
	checkRate(t, "1h A tx", p.WANTx, 3)
	checkRate(t, "1h A rx peak", p.WANRxPeak, 30)
	checkRate(t, "1h A tx peak", p.WANTxPeak, 3)
	if p.AtLeast || p.PCRx != nil {
		t.Errorf("1h A: %+v", p)
	}
	checkRate(t, "1h B rx", bucket("1h", 3, 41, 20).WANRx, 60)
	noTraffic(t, "1h before the first reading", bucket("1h", 3, 40, 10))
	if p = bucket("1h", 3, 43, 40); !p.AtLeast {
		t.Errorf("1h D: %+v", p)
	}
	checkRate(t, "1h D rx", p.WANRx, dPeak)
	checkRate(t, "1h D tx", p.WANTx, 0.02)
	noTraffic(t, "1h E (restart)", bucket("1h", 3, 44, 40))
	checkRate(t, "1h F rx", bucket("1h", 3, 45, 40).WANRx, 10)
	p = bucket("1h", 3, 50, 30)
	checkRate(t, "1h PC rx", p.PCRx, 2)
	checkRate(t, "1h PC tx", p.PCTx, 0.5)
	if p.WANRx != nil {
		t.Errorf("1h 03:50:30: no WAN reading covers it: %+v", p)
	}
	checkRate(t, "1h PC rx 03:51:30", bucket("1h", 3, 51, 30).PCRx, 4)

	// 6 h, 60 s buckets: 03:41 holds 20 s of A and 40 s of B.
	p = bucket("6h", 3, 41, 0)
	checkRate(t, "6h 03:41 rx", p.WANRx, (20*30+40*60)/60.0)
	checkRate(t, "6h 03:41 tx", p.WANTx, (20*3+40*6)/60.0)
	checkRate(t, "6h 03:41 rx peak", p.WANRxPeak, 60)
	checkRate(t, "6h 03:41 tx peak", p.WANTxPeak, 6)
	if p.AtLeast {
		t.Errorf("6h 03:41: %+v", p)
	}
	p = bucket("6h", 3, 44, 0) // 20 s of D, 40 s unknown
	checkRate(t, "6h 03:44 rx", p.WANRx, dPeak)
	if !p.AtLeast {
		t.Errorf("6h 03:44: %+v", p)
	}
	p = bucket("6h", 3, 45, 0) // 20 s unknown, 40 s of F
	checkRate(t, "6h 03:45 rx", p.WANRx, 10)
	checkRate(t, "6h 03:45 tx", p.WANTx, 1)
	if p.AtLeast {
		t.Errorf("6h 03:45: %+v", p)
	}
	noTraffic(t, "6h 03:47", bucket("6h", 3, 47, 0))

	// 24 h, 5 min buckets: 03:40 holds A to D and 40 s unknown.
	p = bucket("24h", 3, 40, 0)
	checkRate(t, "24h 03:40 rx", p.WANRx, (30+60+20+dPeak)/4)
	checkRate(t, "24h 03:40 tx", p.WANTx, (3+6+2+0.02)/4)
	checkRate(t, "24h 03:40 rx peak", p.WANRxPeak, dPeak)
	checkRate(t, "24h 03:40 tx peak", p.WANTxPeak, 6)
	if !p.AtLeast {
		t.Errorf("24h 03:40: %+v", p)
	}
	if p = bucket("24h", 3, 45, 0); p.AtLeast {
		t.Errorf("24h 03:45: %+v", p)
	}
	checkRate(t, "24h 03:45 rx", p.WANRx, 10)
	p = bucket("24h", 3, 50, 0)
	checkRate(t, "24h 03:50 PC rx", p.PCRx, 3)
	checkRate(t, "24h 03:50 PC tx", p.PCTx, 1)

	// 7 d, 30 min buckets.
	p = bucket("7d", 3, 30, 0)
	checkRate(t, "7d rx", p.WANRx, (30+60+20+dPeak+10)/5)
	checkRate(t, "7d rx peak", p.WANRxPeak, dPeak)
	checkRate(t, "7d PC rx", p.PCRx, 3)
	if !p.AtLeast {
		t.Errorf("7d: %+v", p)
	}
	noTraffic(t, "7d 04:00", bucket("7d", 4, 0, 0))
}

// TrafficDays: the WAN volume per local calendar day (a fixed zone, UTC-5, here) from known
// deltas - an interval across midnight is shared by time - with the time covered, complete only
// when the whole day (the current day: until a recent latest reading) has known deltas.
func TestTrafficDays(t *testing.T) {
	zone := time.FixedZone("UTC-5", -5*60*60)
	local := func(d, hh, mm, ss int) time.Time { return time.Date(2026, 10, d, hh, mm, ss, 0, zone) }
	gap := gapLimit(10 * time.Second)
	// One reading a minute, at :30, from 23:58:30 on the 3rd to 00:10:30 on the 5th: 1 MB/s down
	// and 0.1 MB/s up (8 and 0.8 Mb/s); the interval that ends at atLeast is "at least".
	build := func(atLeast time.Time) (*pointStore, *wanFeed) {
		ps := newPointStore()
		addCycles(ps, local(3, 23, 58, 0), local(5, 0, 12, 0))
		f := newWANFeed(local(3, 23, 58, 30))
		ps.addWAN(f.add(0, 0, 0, 0, 0), gap)
		for f.at.Before(local(5, 0, 10, 30)) {
			if f.at.Add(time.Minute).Equal(atLeast) {
				ps.addWAN(f.add(time.Minute, 1_000_000_000, 5_000_000, 6_000_000, 4_000), gap)
				continue
			}
			ps.addWAN(f.add(time.Minute, 60_000_000, 40_000, 6_000_000, 4_000), gap)
		}
		return ps, f
	}
	type day struct {
		day      string
		rx, tx   int64
		covered  int64
		complete bool
	}
	check := func(what string, got []model.TrafficDay, want []day) {
		t.Helper()
		if len(got) != len(want) {
			t.Fatalf("%s: %+v", what, got)
		}
		for i, w := range want {
			g := got[i]
			if g.Day != w.day || g.RxBytes != w.rx || g.TxBytes != w.tx || g.CoveredS != w.covered || g.Complete != w.complete {
				t.Errorf("%s: day %d %+v, want %+v", what, i, g, w)
			}
		}
	}

	ps, f := build(time.Time{})
	// The 3rd is covered from 23:58:30 only; the 4th fully, with half of the intervals across
	// each midnight; the 5th until its latest reading, 10 s ago.
	check("ten seconds after the latest reading", ps.trafficDays(local(3, 23, 0, 0), local(5, 0, 10, 40), zone), []day{
		{"2026-10-03", 90_000_000, 9_000_000, 90, false},
		{"2026-10-04", 86_400_000_000, 8_640_000_000, 86_400, true},
		{"2026-10-05", 630_000_000, 63_000_000, 630, true},
	})
	// Days from the range's first day: one day before midnight UTC-5 and the 5th.
	check("the range's days", ps.trafficDays(local(4, 0, 10, 40), local(5, 0, 10, 40), zone), []day{
		{"2026-10-04", 86_400_000_000, 8_640_000_000, 86_400, true},
		{"2026-10-05", 630_000_000, 63_000_000, 630, true},
	})
	// No reading for 9.5 minutes (more than maxTrafficSpan): the 5th is not complete.
	check("no recent reading", ps.trafficDays(local(4, 0, 20, 0), local(5, 0, 20, 0), zone), []day{
		{"2026-10-04", 86_400_000_000, 8_640_000_000, 86_400, true},
		{"2026-10-05", 630_000_000, 63_000_000, 630, false},
	})
	// The gateway restarts: the interval to its next reading is unknown.
	f.reboot()
	ps.addWAN(f.add(time.Minute, 60_000_000, 40_000, 6_000_000, 4_000), gap)
	check("after a restart", ps.trafficDays(local(4, 0, 11, 40), local(5, 0, 11, 40), zone), []day{
		{"2026-10-04", 86_400_000_000, 8_640_000_000, 86_400, true},
		{"2026-10-05", 630_000_000, 63_000_000, 630, false},
	})

	// An "at least" interval at noon on the 4th: its delta is not known, so the day is not
	// complete and the interval counts neither in the totals nor in the time covered.
	ps, _ = build(local(4, 12, 0, 30))
	check("at least", ps.trafficDays(local(4, 0, 10, 40), local(5, 0, 10, 40), zone), []day{
		{"2026-10-04", 86_340_000_000, 8_634_000_000, 86_340, false},
		{"2026-10-05", 630_000_000, 63_000_000, 630, true},
	})

	// No reading at all: every day of the range is shown, empty and not complete.
	check("empty", newPointStore().trafficDays(local(4, 0, 10, 40), local(5, 0, 10, 40), zone), []day{
		{"2026-10-04", 0, 0, 0, false},
		{"2026-10-05", 0, 0, 0, false},
	})
}

// ---------------------------------------------------------------------------- through the monitor

// The monitor feeds the traffic history live: every recorded snapshot with WAN counters (an
// unreachable snapshot in between is spanned by the next interval) and every local-link reading,
// whose counters the local_link record and the status carry; Series shows both.
func TestTrafficThroughTheMonitor(t *testing.T) {
	base := time.Date(2026, 10, 5, 3, 0, 0, 0, time.UTC)
	r, clk := clockRig(t, base)
	m, ctx := r.m, context.Background()
	r.gw.snap = func(call int, pages []string, trigger string) (model.GatewaySnapshot, map[string][]byte, error) {
		if call == 3 {
			return model.GatewaySnapshot{}, nil, errors.New("dial tcp 192.168.1.254:443: i/o timeout")
		}
		s := okSnapshot(pages, clk.Now())
		k := int64(call)
		s.Broadband.Counters = map[string]int64{ctrRxBytes: k * 75_000_000, ctrRxPkts: k * 50_000, ctrTxBytes: k * 7_500_000, ctrTxPkts: k * 5_000}
		return s, pageBodies(pages, "ok"), nil
	}
	reads := 0
	r.pr.link = func() (model.LocalLink, []byte, error) {
		reads++
		rx, tx := uint64(reads)*3_750_000, uint64(reads)*375_000 // 0.5 and 0.05 Mb/s
		return model.LocalLink{Interface: "Wi-Fi", Type: "wifi", State: "connected", SSID: "home", SignalPct: 90, RxBytes: &rx, TxBytes: &tx}, nil, nil
	}
	for i := 0; i <= 36; i++ { // six minutes: a cycle every 10 s, a snapshot and a link reading every minute
		cycleAt(r, clk, base, i, healthy())
		if i%6 == 0 {
			clk.Set(base.Add(time.Duration(i)*10*time.Second + time.Second))
			m.takeSnapshot(ctx, trigPeriodic, nil)
			m.checkLocalLink(ctx, false)
		}
	}
	clk.Set(base.Add(6*time.Minute + 5*time.Second))
	s, err := m.Series("1h")
	if err != nil {
		t.Fatal(err)
	}
	from, _ := parseTS(s.From)
	at := func(sec int) model.TrafficPoint {
		return s.Traffic[int(base.Add(time.Duration(sec)*time.Second).Sub(from)/(10*time.Second))]
	}
	for _, sec := range []int{30, 150, 330} { // 150 s: from the 2nd to the 4th snapshot (the 3rd failed)
		p := at(sec)
		checkRate(t, "WAN rx", p.WANRx, 10)
		checkRate(t, "WAN tx", p.WANTx, 1)
		checkRate(t, "PC rx", p.PCRx, 0.5)
		checkRate(t, "PC tx", p.PCTx, 0.05)
	}
	noTraffic(t, "before the first readings", at(-10))
	if n := len(m.st.points.wan); n != 5 {
		t.Fatalf("%d WAN intervals (six snapshots with counters)", n)
	}
	rec := decode[model.LocalLink](t, lastOfType(t, r, model.TypeLocalLink))
	if rec.RxBytes == nil || *rec.RxBytes != 3_750_000 || rec.TxBytes == nil || *rec.TxBytes != 375_000 {
		t.Fatalf("the local_link record carries the counters: %+v", rec)
	}
	if st := m.Status(); st.LocalLink == nil || st.LocalLink.RxBytes == nil || *st.LocalLink.RxBytes != 7*3_750_000 {
		t.Fatalf("status: %+v", st.LocalLink)
	}
}

// After a restart the traffic history is rebuilt from the ledger: the WAN intervals from the
// gateway_snapshot records (they carry the counters), this computer's from the local_link
// records (one every 10 minutes: coarser than live). The state cache's shorter scan rebuilds
// the same, and the live snapshots continue it.
func TestTrafficRebuild(t *testing.T) {
	base := time.Date(2026, 10, 5, 3, 0, 0, 0, time.UTC)
	r, clk := clockRig(t, base.Add(-10*time.Minute))
	prev := "run-old"
	r.led.appendAs(prev, base, model.TypeMonitorStart, model.MonitorStart{})
	counters := func(k int64) map[string]int64 {
		return map[string]int64{ctrRxBytes: k * 75_000_000, ctrRxPkts: k * 50_000, ctrTxBytes: k * 7_500_000, ctrTxPkts: k * 5_000}
	}
	for i := 0; i <= 150; i++ { // 25 minutes
		at := base.Add(time.Duration(i) * 10 * time.Second)
		r.led.appendAs(prev, at.Add(time.Second), model.TypeSample, model.Sample{Started: fmtTS(at), Verdict: model.Verdict{State: model.StateOnline}})
		if i%6 == 3 {
			s := okSnapshot(allPages, at)
			s.Broadband.Counters = counters(int64(i / 6))
			r.led.appendAs(prev, at.Add(2*time.Second), model.TypeGatewaySnapshot, s)
		}
		if i%60 == 5 {
			k := uint64(i / 60)
			rx, tx := k*75_000_000, k*7_500_000 // 1 and 0.1 Mb/s over 10 minutes
			r.led.appendAs(prev, at.Add(3*time.Second), model.TypeLocalLink, model.LocalLink{Interface: "Wi-Fi", Type: "wifi", State: "connected", RxBytes: &rx, TxBytes: &tx})
		}
	}
	r.led.appendAs(prev, base.Add(25*time.Minute+time.Second), model.TypeMonitorStop, model.MonitorStop{Reason: "service stop"})
	now := base.Add(25*time.Minute + 20*time.Second)
	clk.Set(now)
	r.m.rebuild(now)

	ps := r.m.st.points
	if len(ps.wan) != 24 || len(ps.pc) != 2 {
		t.Fatalf("rebuilt %d WAN and %d PC intervals", len(ps.wan), len(ps.pc))
	}
	for i, iv := range ps.wan {
		if !iv.known || math.Abs(iv.rxMbps-10) > 1e-9 || math.Abs(iv.txMbps-1) > 1e-9 || iv.from != base.Add(time.Duration(30+60*i)*time.Second).UnixNano() {
			t.Fatalf("WAN interval %d: %+v", i, iv)
		}
	}
	for i, iv := range ps.pc { // dated by the records
		if !iv.known || math.Abs(iv.rxMbps-1) > 1e-9 || math.Abs(iv.txMbps-0.1) > 1e-9 || iv.from != base.Add(time.Duration(53+600*i)*time.Second).UnixNano() {
			t.Fatalf("PC interval %d: %+v", i, iv)
		}
	}
	s, err := r.m.Series("1h")
	if err != nil {
		t.Fatal(err)
	}
	from, _ := parseTS(s.From)
	p := s.Traffic[int(base.Add(5*time.Minute).Sub(from)/(10*time.Second))]
	checkRate(t, "rebuilt WAN rx", p.WANRx, 10)
	checkRate(t, "rebuilt PC rx", p.PCRx, 1)

	// The state cache: its rebuild scans only the recent records, with the same outcome.
	r.m.writeCache()
	r2 := newRig(t, r.cfg, r.led)
	r2.m.opts.StateDir = r.m.opts.StateDir
	if _, ok := r2.m.loadCache(); !ok {
		t.Fatal("no state cache")
	}
	r2.m.rebuild(now)
	if !reflect.DeepEqual(r2.m.st.points.wan, ps.wan) || !reflect.DeepEqual(r2.m.st.points.pc, ps.pc) {
		t.Fatalf("cached rebuild differs: %+v %+v", r2.m.st.points.wan, r2.m.st.points.pc)
	}

	// The restart took 20 s (shorter than the gap limit): the first live snapshot continues the
	// history from the last recorded one.
	r.gw.snap = func(call int, pages []string, trigger string) (model.GatewaySnapshot, map[string][]byte, error) {
		s := okSnapshot(pages, clk.Now())
		s.Broadband.Counters = counters(25)
		return s, pageBodies(pages, "ok"), nil
	}
	cycleAt(r, clk, base, 152, healthy()) // 25:20
	clk.Set(base.Add(25*time.Minute + 30*time.Second))
	r.m.takeSnapshot(context.Background(), trigStartup, nil)
	if n := len(ps.wan); n != 25 || !ps.wan[24].known || math.Abs(ps.wan[24].rxMbps-10) > 1e-9 ||
		ps.wan[24].from != base.Add(24*time.Minute+30*time.Second).UnixNano() {
		t.Fatalf("live continuation: %d intervals, last %+v", n, ps.wan[n-1])
	}
}
