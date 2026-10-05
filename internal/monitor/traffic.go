package monitor

import (
	"fmt"
	"math"
	"time"
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
	Err                  string // why no rate could be computed ("" when it could)
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

// wanTrafficOf computes the WAN traffic between two recorded snapshots that carry the gateway's
// counters (a: the earlier one). The time between them is taken from the broadbandstatistics
// fetch times.
func wanTrafficOf(a, b *snapObs) *WANTraffic {
	w := &WANTraffic{FromSeq: a.Seq, ToSeq: b.Seq}
	if a.Snap == nil || b.Snap == nil || a.Snap.Broadband == nil || b.Snap.Broadband == nil {
		w.Err = "no WAN counters in the gateway snapshots"
		return w
	}
	at := func(o *snapObs) time.Time {
		if t, ok := pageFetchedAt(o.Snap, "broadbandstatistics"); ok {
			return t
		}
		return o.At
	}
	w.Dur = at(b).Sub(at(a))
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
	dir := func(bytesKey, pktsKey string) (mbps, pps float64, atLeast, ok bool) {
		ba, okA := ca[bytesKey]
		bb, okB := cb[bytesKey]
		pa, okC := ca[pktsKey]
		pb, okD := cb[pktsKey]
		if !okA || !okB || !okC || !okD {
			return 0, 0, false, false
		}
		db, ok1 := counterDelta(ba, bb)
		dp, ok2 := counterDelta(pa, pb)
		if !ok1 || !ok2 || float64(dp)/secs > maxPacketRate {
			return 0, 0, false, false // a decrease that was a reset, not a wrap
		}
		// The bytes are known exactly only if one more wrap (2^32 bytes) would be more than the
		// packets counted could carry.
		atLeast = float64(db)+math.Exp2(32) <= float64(dp)*maxFrameBytes
		return float64(db) * 8 / secs / 1e6, float64(dp) / secs, atLeast, true
	}
	var okRx, okTx bool
	w.RxMbps, w.RxPPS, w.RxAtLeast, okRx = dir(ctrRxBytes, ctrRxPkts)
	w.TxMbps, w.TxPPS, w.TxAtLeast, okTx = dir(ctrTxBytes, ctrTxPkts)
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
