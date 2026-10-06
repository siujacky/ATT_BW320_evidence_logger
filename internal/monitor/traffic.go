package monitor

import (
	"fmt"
	"math"
	"sort"
	"time"

	"attmonitor/internal/model"
)

// Household traffic (rules 2026.10-4, DESIGN §9 rule 3). High latency or packet loss on the
// Internet while the gateway answers this computer quickly and without loss is also exactly what
// the household's own traffic produces when it fills the connection (the gateway's WAN queue
// grows, "bufferbloat"). The gateway's own IPv4 Statistics counters, read with every snapshot,
// tell how much it carried: a DEGRADED cycle is attributed to the provider only when they do not
// show heavy traffic, and its reasons state the measured rates either way.

// heavyTrafficMbps: WAN traffic at or above this rate in either direction (averaged between two
// gateway snapshots) may be the cause of the degradation itself. It is about 80 % of the slowest
// AT&T Fiber tier (100 Mb/s), so no tier can be filled below it; on faster tiers it errs towards
// "undetermined", never towards blaming the provider.
const heavyTrafficMbps = 80.0

// maxTrafficSpan bounds the time between the two snapshots a rate is computed from.
const maxTrafficSpan = 5 * time.Minute

// maxFrameBytes bounds the bytes one packet adds to the byte counters (an Ethernet frame with
// headers); with the packet counter it tells whether the 32-bit byte counter may have wrapped
// more than once between two readings.
const maxFrameBytes = 1600

// maxPacketRate is more packets per second than a 10 Gb/s line can carry: a counter delta that
// implies more was a reset, not a wrap.
const maxPacketRate = 2e7

// The gateway's IPv4 Statistics counters (broadbandstatistics, section/label keys).
const (
	ctrRxBytes = "IPv4 Statistics/Receive Bytes"
	ctrTxBytes = "IPv4 Statistics/Transmit Bytes"
	ctrRxPkts  = "IPv4 Statistics/Receive Packets"
	ctrTxPkts  = "IPv4 Statistics/Transmit Packets"
)

// WANTraffic is the traffic the gateway's WAN carried between two recorded snapshots.
type WANTraffic struct {
	FromSeq, ToSeq uint64
	Dur            time.Duration
	// Rx/Tx: received from / sent to the Internet. Mbps is from the byte counters; AtLeast means
	// the byte counter (32 bits on this gateway: it wraps every 4 GiB) may have wrapped more
	// often than can be told, so the true rate may be higher. PPS is from the packet counters.
	RxMbps, TxMbps       float64
	RxAtLeast, TxAtLeast bool
	RxPPS, TxPPS         float64
	// RxBytes/TxBytes are the byte counter deltas the rates come from (with AtLeast: the least
	// the gateway can have carried).
	RxBytes, TxBytes int64
	Err              string // why no rate could be computed ("" when it could)
}

// heavy: the traffic may fill the connection (DESIGN §9 rule 3).
func (w *WANTraffic) heavy() bool {
	return w.Err == "" && (w.RxAtLeast || w.TxAtLeast || w.RxMbps >= heavyTrafficMbps || w.TxMbps >= heavyTrafficMbps)
}

// counterDelta returns cur - prev for a counter that may wrap once at 2^32 between readings.
func counterDelta(prev, cur int64) (int64, bool) {
	switch {
	case prev < 0 || cur < 0:
		return 0, false
	case cur >= prev:
		return cur - prev, true
	case prev < 1<<32 && cur < 1<<32:
		return cur + 1<<32 - prev, true
	}
	return 0, false
}

// ctrAt is when a snapshot read the gateway's counters: the broadbandstatistics fetch time,
// else the snapshot's own time.
func ctrAt(o *snapObs) time.Time {
	if t, ok := pageFetchedAt(o.Snap, "broadbandstatistics"); ok {
		return t
	}
	return o.At
}

// wanTrafficOf computes the WAN traffic between two recorded snapshots that carry the gateway's
// counters (a: the earlier one). The time between them is taken from the broadbandstatistics
// fetch times.
func wanTrafficOf(a, b *snapObs) *WANTraffic {
	w := &WANTraffic{FromSeq: a.Seq, ToSeq: b.Seq}
	if a.Snap == nil || b.Snap == nil || a.Snap.Broadband == nil || b.Snap.Broadband == nil {
		w.Err = "no WAN counters in the gateway snapshots"
		return w
	}
	w.Dur = ctrAt(b).Sub(ctrAt(a))
	if w.Dur <= 0 || w.Dur > maxTrafficSpan {
		w.Err = fmt.Sprintf("the two latest gateway snapshots with WAN counters are %s apart", w.Dur.Round(time.Second))
		return w
	}
	if ua, ub := a.Snap.System, b.Snap.System; ua != nil && ub != nil && ua.UptimeSec >= 0 && ub.UptimeSec >= 0 && ub.UptimeSec < ua.UptimeSec {
		w.Err = "the gateway restarted between the two snapshots (its counters were reset)"
		return w
	}
	ca, cb := a.Snap.Broadband.Counters, b.Snap.Broadband.Counters
	secs := w.Dur.Seconds()
	dir := func(bytesKey, pktsKey string) (delta int64, mbps, pps float64, atLeast, ok bool) {
		ba, okA := ca[bytesKey]
		bb, okB := cb[bytesKey]
		pa, okC := ca[pktsKey]
		pb, okD := cb[pktsKey]
		if !okA || !okB || !okC || !okD {
			return 0, 0, 0, false, false
		}
		db, ok1 := counterDelta(ba, bb)
		dp, ok2 := counterDelta(pa, pb)
		if !ok1 || !ok2 || float64(dp)/secs > maxPacketRate {
			return 0, 0, 0, false, false // a decrease that was a reset, not a wrap
		}
		// The bytes are known exactly only if one more wrap (2^32 bytes) would be more than the
		// packets counted could carry.
		atLeast = float64(db)+math.Exp2(32) <= float64(dp)*maxFrameBytes
		return db, float64(db) * 8 / secs / 1e6, float64(dp) / secs, atLeast, true
	}
	var okRx, okTx bool
	w.RxBytes, w.RxMbps, w.RxPPS, w.RxAtLeast, okRx = dir(ctrRxBytes, ctrRxPkts)
	w.TxBytes, w.TxMbps, w.TxPPS, w.TxAtLeast, okTx = dir(ctrTxBytes, ctrTxPkts)
	if !okRx || !okTx {
		w.Err = "the gateway's WAN counters are missing or decreased (reset) between the two snapshots"
	}
	return w
}

// rateText renders one direction, e.g. "312.4 Mb/s" or "at least 427.0 Mb/s (52,000 packets/s)".
func rateText(mbps, pps float64, atLeast bool) string {
	if atLeast {
		return fmt.Sprintf("at least %.1f Mb/s (%.0f packets/s; the gateway's byte counter wraps every 4 GiB)", mbps, pps)
	}
	return fmt.Sprintf("%.1f Mb/s", mbps)
}

// trafficText states the measurement, e.g. "the gateway's own WAN counters (snapshots #10 and
// #19, 60 s apart) show this home network receiving 312.4 Mb/s and sending 4.1 Mb/s".
func (w *WANTraffic) trafficText() string {
	return fmt.Sprintf("the gateway's own WAN counters (snapshots #%d and #%d, %s apart) show this home network receiving %s and sending %s",
		w.FromSeq, w.ToSeq, w.Dur.Round(time.Second), rateText(w.RxMbps, w.RxPPS, w.RxAtLeast), rateText(w.TxMbps, w.TxPPS, w.TxAtLeast))
}

// ---------------------------------------------------------------------------- traffic history

// The traffic history feeds the dashboard's traffic chart and daily totals (Series.Traffic and
// TrafficDays, docs/syslog-snmp-traffic.md §3.3). It holds the traffic between consecutive
// readings of two kinds of counters, as long as the other series data (seriesKeep):
//
//   - the gateway's WAN counters, from every recorded reachable snapshot that carries them
//     (every 60 s, 15 s during incidents), with wanTrafficOf's rates: the computation of the
//     classifier's household-traffic rule. After a restart they are rebuilt from the
//     gateway_snapshot records, which hold the counters: the same resolution.
//   - this computer's own interface counters (model.LocalLink.RxBytes/TxBytes), from every
//     local-link reading (every 60 s). Only the readings recorded as local_link records survive
//     a restart - one every LocalLinkRecordEvery (10 min) and one at each change - so after a
//     restart the hours before it show this computer's traffic as means over about 10 minutes,
//     dated by their records (a few seconds after the counters were read, while netsh ran).
//
// The rate between two readings is the mean over the time between them, and it is known only
// when the counters can be trusted for that whole time. Otherwise the interval is unknown: it
// has no rate, and nothing is interpolated across it. That is the case when the counters are
// missing or were reset (the gateway restarted, a counter decreased, the two readings are of
// different interfaces), when the readings are further apart than the computation allows (WAN:
// maxTrafficSpan; this computer: pcSpanLimit), and when the monitor had a gap within it (no
// cycle for longer than gapLimit, DESIGN §6: the computer slept, the monitor was stopped).

// trafficIv is the traffic between two consecutive counter readings, taken at from and to (unix
// ns).
type trafficIv struct {
	from, to         int64
	known            bool    // the rates are known (see above)
	atLeast          bool    // WAN: a byte counter may have wrapped more often than can be told
	rxMbps, txMbps   float64 // mean rates over the interval: received, sent
	rxBytes, txBytes int64   // the counter deltas they come from
}

// pcReading is a reading of this computer's interface counters.
type pcReading struct {
	t      int64 // unix ns
	iface  string
	rx, tx uint64
}

// maxPCMbps bounds this computer's rate: a counter delta that implies more than any adapter can
// carry means the counters were replaced (another adapter took the alias), not traffic.
const maxPCMbps = 100_000

// pcSpanLimit is the longest time between two readings of this computer's counters that still
// makes an interval: local_link records - all that a restart keeps - are written at least every
// recordEvery, at the first reading after it (readings come every interval).
func pcSpanLimit(interval, recordEvery time.Duration) time.Duration {
	return recordEvery + 2*interval
}

// trafficSnapshotLocked adds a recorded reachable snapshot with the gateway's WAN counters to the
// traffic history. Caller holds mu.
func (m *Monitor) trafficSnapshotLocked(cur *snapObs) {
	m.st.points.addWAN(cur, gapLimit(m.set.fast))
}

// trafficLinkLocked adds a local-link reading taken at at (recorded or not) to the history of
// this computer's traffic. Caller holds mu.
func (m *Monitor) trafficLinkLocked(at time.Time, l *model.LocalLink) {
	m.st.points.addPC(at, l, pcSpanLimit(m.set.linkInterval, m.set.linkRecordEvery), gapLimit(m.set.fast))
}

// addWAN adds a recorded reachable snapshot that carries the gateway's WAN counters: the interval
// since the previous one has wanTrafficOf's rates, unless that gives none or the monitor had a
// gap within it.
func (ps *pointStore) addWAN(o *snapObs, gap time.Duration) {
	prev := ps.lastWAN
	ps.lastWAN = o
	if prev == nil {
		return
	}
	iv := trafficIv{from: ctrAt(prev).UnixNano(), to: ctrAt(o).UnixNano()}
	if w := wanTrafficOf(prev, o); w.Err == "" && !ps.gapIn(iv.from, iv.to, gap) {
		iv.known, iv.atLeast = true, w.RxAtLeast || w.TxAtLeast
		iv.rxMbps, iv.txMbps, iv.rxBytes, iv.txBytes = w.RxMbps, w.TxMbps, w.RxBytes, w.TxBytes
	}
	ps.wan = append(ps.wan, iv)
}

// addPC adds a local-link reading taken at at to the history of this computer's traffic; one
// without counters is skipped (the next interval spans it). The interval since the previous
// reading is unknown when the interface changed, a counter decreased (the adapter was reset) or
// jumped beyond maxPCMbps, the readings are more than maxSpan apart, or the monitor had a gap
// within it.
func (ps *pointStore) addPC(at time.Time, l *model.LocalLink, maxSpan, gap time.Duration) {
	if l == nil || l.RxBytes == nil || l.TxBytes == nil {
		return
	}
	cur := &pcReading{t: at.UnixNano(), iface: l.Interface, rx: *l.RxBytes, tx: *l.TxBytes}
	prev := ps.lastPC
	ps.lastPC = cur
	if prev == nil {
		return
	}
	iv := trafficIv{from: prev.t, to: cur.t}
	d := cur.t - prev.t
	if d > 0 && d <= int64(maxSpan) && cur.iface == prev.iface && cur.rx >= prev.rx && cur.tx >= prev.tx && !ps.gapIn(prev.t, cur.t, gap) {
		secs := float64(d) / float64(time.Second)
		rx, tx := float64(cur.rx-prev.rx)*8/secs/1e6, float64(cur.tx-prev.tx)*8/secs/1e6
		if rx <= maxPCMbps && tx <= maxPCMbps {
			iv.known, iv.rxMbps, iv.txMbps = true, rx, tx
			iv.rxBytes, iv.txBytes = int64(cur.rx-prev.rx), int64(cur.tx-prev.tx)
		}
	}
	ps.pc = append(ps.pc, iv)
}

// gapIn reports whether the monitor had a gap within [a, b] (unix ns): a stretch longer than gap
// in which no recorded cycle started.
func (ps *pointStore) gapIn(a, b int64, gap time.Duration) bool {
	i := sort.Search(len(ps.pts), func(i int) bool { return ps.pts[i].t >= a })
	last := a
	for ; i < len(ps.pts) && ps.pts[i].t <= b; i++ {
		if ps.pts[i].t-last > int64(gap) {
			return true
		}
		last = ps.pts[i].t
	}
	return b-last > int64(gap)
}

// pruneTraffic drops the intervals that ended before c (unix ns).
func pruneTraffic(ivs []trafficIv, c int64) []trafficIv {
	i := 0
	for i < len(ivs) && max(ivs[i].from, ivs[i].to) < c {
		i++
	}
	return dropFront(ivs, i)
}

// trafficPoints aggregates the traffic history into the n chart buckets of step from first (the
// buckets of Series.Points): per bucket, the time-weighted mean of the known rates over the part
// of the bucket they cover, the highest WAN interval rate among them, and whether any of those
// WAN rates is "at least". A bucket that no known interval overlaps has no rates.
func (ps *pointStore) trafficPoints(first time.Time, step time.Duration, n int) []model.TrafficPoint {
	type acc struct {
		w, rx, tx      float64 // the time covered (ns) and the rates weighted by it
		rxPeak, txPeak float64
		atLeast        bool
	}
	f, st := first.UnixNano(), int64(step)
	spread := func(ivs []trafficIv) []acc {
		out := make([]acc, n)
		for _, iv := range ivs {
			if !iv.known || iv.to <= f {
				continue
			}
			for b := max(0, int((iv.from-f)/st)); b < n; b++ {
				bs := f + int64(b)*st
				if bs >= iv.to {
					break
				}
				w := float64(min(iv.to, bs+st) - max(iv.from, bs))
				if w <= 0 {
					continue
				}
				a := &out[b]
				a.w += w
				a.rx += iv.rxMbps * w
				a.tx += iv.txMbps * w
				a.rxPeak, a.txPeak = max(a.rxPeak, iv.rxMbps), max(a.txPeak, iv.txMbps)
				a.atLeast = a.atLeast || iv.atLeast
			}
		}
		return out
	}
	wan, pc := spread(ps.wan), spread(ps.pc)
	out := make([]model.TrafficPoint, n)
	for i := range out {
		p := model.TrafficPoint{T: fmtTS(first.Add(time.Duration(i) * step))}
		if a := wan[i]; a.w > 0 {
			p.WANRx, p.WANTx = chartRate(a.rx/a.w), chartRate(a.tx/a.w)
			p.WANRxPeak, p.WANTxPeak = chartRate(a.rxPeak), chartRate(a.txPeak)
			p.AtLeast = a.atLeast
		}
		if a := pc[i]; a.w > 0 {
			p.PCRx, p.PCTx = chartRate(a.rx/a.w), chartRate(a.tx/a.w)
		}
		out[i] = p
	}
	return out
}

// chartRate returns a rate for the chart (Mb/s), rounded to 1 kb/s.
func chartRate(v float64) *float64 {
	v = round3(v)
	return &v
}

// trafficDays sums the WAN counter deltas per local calendar day (in loc), from the day of first
// to the day of now. Each day's totals cover the whole day as far as the history reaches, not
// only the part in the chart's range. Only exactly known deltas count - an "at least" interval
// is unknown here - and an interval across midnight is shared in proportion to its time on each
// side. Complete means the totals are the day's whole traffic: every moment of the day lies in an
// interval with a known delta (of the current day: every moment until the latest reading, which
// must not be older than maxTrafficSpan; a longer silence is a gap already).
func (ps *pointStore) trafficDays(first, now time.Time, loc *time.Location) []model.TrafficDay {
	y, mo, d := first.In(loc).Date()
	bounds := []int64{time.Date(y, mo, d, 0, 0, 0, 0, loc).UnixNano()} // day starts, and the last day's end
	var days []model.TrafficDay
	for i := 0; ; i++ {
		end := time.Date(y, mo, d+i+1, 0, 0, 0, 0, loc)
		days = append(days, model.TrafficDay{Day: time.Date(y, mo, d+i, 0, 0, 0, 0, loc).Format(time.DateOnly)})
		bounds = append(bounds, end.UnixNano())
		if end.After(now) {
			break
		}
	}
	type acc struct {
		rx, tx  float64
		covered int64 // ns
		unknown bool
	}
	accs := make([]acc, len(days))
	for _, iv := range ps.wan {
		lo, hi := min(iv.from, iv.to), max(iv.from, iv.to) // a clock step back reverses them
		exact := iv.known && !iv.atLeast
		for k := sort.Search(len(days), func(k int) bool { return bounds[k+1] > lo }); k < len(days) && bounds[k] < hi; k++ {
			ov := min(hi, bounds[k+1]) - max(lo, bounds[k])
			a := &accs[k]
			switch {
			case ov <= 0:
			case !exact:
				a.unknown = true
			default:
				share := float64(ov) / float64(hi-lo)
				a.rx += float64(iv.rxBytes) * share
				a.tx += float64(iv.txBytes) * share
				a.covered += ov
			}
		}
	}
	nowNs := now.UnixNano()
	for k := range days {
		start, until := bounds[k], bounds[k+1]
		if until > nowNs { // the current day
			until = nowNs
			if l := ps.lastWAN; l != nil {
				if t := ctrAt(l).UnixNano(); nowNs-t <= int64(maxTrafficSpan) {
					until = min(t, nowNs)
				}
			}
		}
		a := accs[k]
		days[k].RxBytes, days[k].TxBytes = int64(math.Round(a.rx)), int64(math.Round(a.tx))
		days[k].CoveredS = a.covered / int64(time.Second)
		days[k].Complete = !a.unknown && until > start && a.covered >= until-start
	}
	return days
}
