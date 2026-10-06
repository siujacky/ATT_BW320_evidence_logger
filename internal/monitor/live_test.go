package monitor

import (
	"context"
	"errors"
	"math"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"attmonitor/internal/model"
)

// liveCounters makes the fake gateway's Broadband Status page show the WAN counters ctr holds
// (bytes and packets received, sent), fetched at the fake clock's time.
func liveCounters(r *rig, clk *fakeClock, ctr *atomic.Pointer[[4]int64]) {
	r.gw.snap = func(call int, pages []string, trigger string) (model.GatewaySnapshot, map[string][]byte, error) {
		s := okSnapshot(pages, clk.Now())
		c := ctr.Load()
		s.Broadband.Counters = map[string]int64{ctrRxBytes: c[0], ctrRxPkts: c[1], ctrTxBytes: c[2], ctrTxPkts: c[3]}
		return s, pageBodies(pages, "live"), nil
	}
}

func setCtr(ctr *atomic.Pointer[[4]int64], rxB, rxP, txB, txP int64) {
	ctr.Store(&[4]int64{rxB, rxP, txB, txP})
}

func liveRead(t *testing.T, r *rig) model.LiveTraffic {
	t.Helper()
	v, err := r.m.LiveTraffic(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// The flow meter reads only the Broadband Status page (trigger "live"), computes the rates against
// the previous read, and feeds nothing into the evidence: no record, no blob, no snapshot state,
// no traffic history.
func TestLiveTrafficRatesWithoutEvidence(t *testing.T) {
	base := time.Date(2026, 10, 5, 3, 0, 0, 0, time.UTC)
	r, clk := clockRig(t, base)
	var ctr atomic.Pointer[[4]int64]
	setCtr(&ctr, 1_000_000, 1000, 100_000, 100)
	liveCounters(r, clk, &ctr)
	r.m.liveEvery = 0
	nRecs := len(r.led.records(""))

	v := liveRead(t, r)
	if v.At != fmtTS(base) || v.WANRx != nil || v.WANTx != nil || v.IntervalS != 0 || v.Err != "" || len(v.History) != 0 {
		t.Fatalf("first read: %+v", v)
	}
	clk.Set(base.Add(5 * time.Second))
	setCtr(&ctr, 1_000_000+6_250_000, 1000+5000, 100_000+625_000, 100+500) // 10 and 1 Mb/s
	v = liveRead(t, r)
	checkRate(t, "WAN rx", v.WANRx, 10)
	checkRate(t, "WAN tx", v.WANTx, 1)
	if v.IntervalS != 5 || v.AtLeast || v.Err != "" || v.At != fmtTS(base.Add(5*time.Second)) {
		t.Fatalf("second read: %+v", v)
	}
	if len(v.History) != 1 || v.History[0].T != v.At || v.History[0].WANRx != v.WANRx {
		t.Fatalf("history %+v", v.History)
	}

	calls, triggers := r.gw.snapshotCalls()
	r.gw.mu.Lock()
	pageSets := slices.Clone(r.gw.pageSets)
	r.gw.mu.Unlock()
	if calls != 2 || !reflect.DeepEqual(triggers, []string{"live", "live"}) || !reflect.DeepEqual(pageSets[0], []string{"broadbandstatistics"}) {
		t.Fatalf("gateway reads %d %v %v", calls, triggers, pageSets)
	}
	if n := len(r.led.records("")); n != nRecs {
		t.Fatalf("the flow meter wrote %d records", n-nRecs)
	}
	r.led.mu.Lock()
	blobs := len(r.led.blobs)
	r.led.mu.Unlock()
	if blobs != 0 {
		t.Fatalf("the flow meter stored %d blobs", blobs)
	}
	r.m.mu.Lock()
	defer r.m.mu.Unlock()
	if r.m.st.lastSnap != nil || r.m.st.lastGood != nil || r.m.st.lastCtr != nil || len(r.m.st.points.wan) != 0 || r.m.st.points.lastWAN != nil {
		t.Fatal("the flow meter fed the monitor's snapshot state")
	}
}

// At most one gateway read every liveEvery, shared by every caller: callers that arrive during a
// read wait for it and get the same readings; a caller whose context ends first gets the latest
// readings with its error.
func TestLiveTrafficSharedAndRateLimited(t *testing.T) {
	r := newRig(t, nil, nil)
	release := make(chan struct{})
	r.gw.snap = func(call int, pages []string, trigger string) (model.GatewaySnapshot, map[string][]byte, error) {
		<-release
		s := okSnapshot(pages, time.Now())
		s.Broadband.Counters = map[string]int64{ctrRxBytes: 1, ctrRxPkts: 1, ctrTxBytes: 1, ctrTxPkts: 1}
		return s, nil, nil
	}
	r.m.liveEvery = time.Hour
	results := make([]model.LiveTraffic, 8)
	errs := make([]error, 8)
	var wg sync.WaitGroup
	for i := range results {
		wg.Go(func() { results[i], errs[i] = r.m.LiveTraffic(context.Background()) })
	}
	waitFor(t, "the read", 10*time.Second, func() bool { n, _ := r.gw.snapshotCalls(); return n == 1 })
	cctx, cancel := context.WithCancel(context.Background())
	cancel()
	if v, err := r.m.LiveTraffic(cctx); !errors.Is(err, context.Canceled) || v.At != "" {
		t.Fatalf("a caller whose context ended: %+v %v", v, err)
	}
	time.Sleep(20 * time.Millisecond)
	close(release)
	wg.Wait()
	for i := range results {
		if errs[i] != nil || results[i].At == "" || !reflect.DeepEqual(results[i], results[0]) {
			t.Fatalf("caller %d: %+v %v (first %+v)", i, results[i], errs[i], results[0])
		}
	}
	if again := liveRead(t, r); !reflect.DeepEqual(again, results[0]) {
		t.Fatalf("within liveEvery the latest readings are returned: %+v", again)
	}
	if n, _ := r.gw.snapshotCalls(); n != 1 {
		t.Fatalf("%d gateway reads", n)
	}
}

// A failed read keeps the previous readings (At says when they were taken) and says why; the
// next good read clears it. A page without counters is a failed read.
func TestLiveTrafficFailedRead(t *testing.T) {
	base := time.Date(2026, 10, 5, 3, 0, 0, 0, time.UTC)
	r, clk := clockRig(t, base)
	var ctr atomic.Pointer[[4]int64]
	setCtr(&ctr, 0, 0, 0, 0)
	liveCounters(r, clk, &ctr)
	r.m.liveEvery = 0
	liveRead(t, r)
	clk.Set(base.Add(5 * time.Second))
	setCtr(&ctr, 6_250_000, 5000, 625_000, 500)
	good := liveRead(t, r)

	ok := r.gw.snap
	clk.Set(base.Add(10 * time.Second))
	r.gw.snap = func(int, []string, string) (model.GatewaySnapshot, map[string][]byte, error) {
		return model.GatewaySnapshot{}, nil, errors.New("gateway 192.168.1.254: no page could be fetched (broadbandstatistics: i/o timeout)")
	}
	bad := liveRead(t, r)
	if !strings.Contains(bad.Err, "i/o timeout") || bad.At != good.At || bad.WANRx != good.WANRx || len(bad.History) != len(good.History) {
		t.Fatalf("failed read: %+v (before %+v)", bad, good)
	}
	r.gw.snap = func(call int, pages []string, trigger string) (model.GatewaySnapshot, map[string][]byte, error) {
		s := okSnapshot(pages, clk.Now())
		s.Broadband = nil
		s.Pages[0].Status, s.Pages[0].Err = 500, "HTTP 500"
		return s, nil, nil
	}
	if v := liveRead(t, r); !strings.Contains(v.Err, "no WAN counters") || v.At != good.At {
		t.Fatalf("page without counters: %+v", v)
	}
	r.gw.snap = ok
	clk.Set(base.Add(15 * time.Second))
	setCtr(&ctr, 3*6_250_000, 15000, 3*625_000, 1500)
	v := liveRead(t, r)
	if v.Err != "" || v.IntervalS != 10 || v.At != fmtTS(base.Add(15*time.Second)) {
		t.Fatalf("read after the failure: %+v", v)
	}
	checkRate(t, "WAN rx since the previous good read", v.WANRx, 10)
}

// The history keeps about liveKeep of readings, at most maxLivePoints.
func TestLiveTrafficHistoryIsBounded(t *testing.T) {
	base := time.Date(2026, 10, 5, 3, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name string
		step time.Duration
		keep time.Duration
		want int
	}{
		{"by time", 5 * time.Second, liveHistory, int(liveHistory/(5*time.Second)) + 1},
		{"by count", time.Second, time.Hour, maxLivePoints},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, clk := clockRig(t, base)
			var ctr atomic.Pointer[[4]int64]
			setCtr(&ctr, 0, 0, 0, 0)
			liveCounters(r, clk, &ctr)
			r.m.liveEvery, r.m.liveKeep = 0, tc.keep
			var v model.LiveTraffic
			for i := range 400 {
				clk.Set(base.Add(time.Duration(i) * tc.step))
				k := int64(i)
				setCtr(&ctr, k*1_250_000, k*1000, k*125_000, k*100)
				v = liveRead(t, r)
			}
			if len(v.History) != tc.want {
				t.Fatalf("%d points, want %d", len(v.History), tc.want)
			}
			first, _ := parseTS(v.History[0].T)
			last, _ := parseTS(v.History[len(v.History)-1].T)
			if last.Sub(first) > tc.keep || v.History[len(v.History)-1].T != v.At {
				t.Fatalf("history from %v to %v", first, last)
			}
			for i := 1; i < len(v.History); i++ {
				if v.History[i].T <= v.History[i-1].T {
					t.Fatal("history must be oldest first")
				}
			}
		})
	}
}

// The rates use the traffic math of the household-traffic rule: a 32-bit byte counter that
// wrapped, counters reset by a gateway restart (no rate), "at least" when another wrap would fit;
// with no previous read the newest recorded snapshot is the baseline.
func TestLiveTrafficCounterMath(t *testing.T) {
	base := time.Date(2026, 10, 5, 3, 0, 0, 0, time.UTC)
	r, clk := clockRig(t, base)
	var ctr atomic.Pointer[[4]int64]
	setCtr(&ctr, 1<<32-1000, 1_000_000, 50_000, 500)
	liveCounters(r, clk, &ctr)
	r.m.liveEvery = 0

	// The monitor's own poll records counters; the first live read 30 s later rates against it.
	r.m.takeSnapshot(context.Background(), trigPeriodic, nil)
	clk.Set(base.Add(30 * time.Second))
	setCtr(&ctr, 5000, 1_000_010, 50_000+3_750_000, 500+2500) // wrapped: 6,000 bytes; 1 Mb/s up
	v := liveRead(t, r)
	if v.IntervalS != 30 || v.AtLeast {
		t.Fatalf("against the recorded snapshot: %+v", v)
	}
	checkRate(t, "wrapped rx", v.WANRx, 6000*8/30.0/1e6)
	checkRate(t, "tx", v.WANTx, 1)

	// Restarted gateway: counters small again (packets too): no rate, and no error.
	clk.Set(base.Add(35 * time.Second))
	setCtr(&ctr, 10_000, 20, 10_000, 20)
	if v := liveRead(t, r); v.WANRx != nil || v.WANTx != nil || v.Err != "" {
		t.Fatalf("after a reset: %+v", v)
	}

	// Enough packets for another 4 GiB to fit: at least.
	clk.Set(base.Add(40 * time.Second))
	setCtr(&ctr, 10_000+1_000_000, 20+3_000_000, 20_000, 40)
	v = liveRead(t, r)
	if !v.AtLeast || v.WANRx == nil || math.Abs(*v.WANRx-1.6) > 1e-3 {
		t.Fatalf("ambiguous wrap: %+v", v)
	}
}

// A live read has no uptime: a previous read from before a gateway restart (minutes ago, the
// dashboard was closed meanwhile) is no baseline, since over that long a reset of the counters
// passes for a wrap of them (the counters are those of the owner's gateway).
func TestLiveTrafficNoBaselineAcrossARestart(t *testing.T) {
	base := time.Date(2026, 10, 5, 3, 0, 0, 0, time.UTC)
	r, clk := clockRig(t, base)
	var ctr atomic.Pointer[[4]int64]
	setCtr(&ctr, 3_318_039_056, 51_550_629, 2_922_828_452, 36_710_191)
	liveCounters(r, clk, &ctr)
	r.m.liveEvery = 0
	liveRead(t, r)
	clk.Set(base.Add(4 * time.Minute)) // the gateway restarted meanwhile
	setCtr(&ctr, 10_000_000, 20_000, 2_000_000, 9_000)
	if w := wanTrafficOf(r.m.live.prev, &snapObs{At: clk.Now(), Snap: &model.GatewaySnapshot{
		Pages:     []model.PageCapture{{Page: "broadbandstatistics", FetchedAt: fmtTS(clk.Now())}},
		Broadband: &model.BroadbandStatus{Counters: map[string]int64{ctrRxBytes: 10_000_000, ctrRxPkts: 20_000, ctrTxBytes: 2_000_000, ctrTxPkts: 9_000}},
	}}); w.Err != "" {
		t.Fatalf("the premise: over 4 minutes the reset passes for a wrap (%s)", w.Err)
	}
	if v := liveRead(t, r); v.WANRx != nil || v.WANTx != nil || v.Err != "" {
		t.Fatalf("rated across a restart: %+v", v)
	}
	clk.Set(base.Add(4*time.Minute + 5*time.Second))
	setCtr(&ctr, 10_000_000+625_000, 20_000+500, 2_000_000, 9_000)
	v := liveRead(t, r)
	checkRate(t, "WAN rx after the restart", v.WANRx, 1)
}

// This computer's rates come from its newest local-link readings while they are recent.
func TestLiveTrafficThisComputer(t *testing.T) {
	base := time.Date(2026, 10, 5, 3, 0, 0, 0, time.UTC)
	r, clk := clockRig(t, base)
	var ctr atomic.Pointer[[4]int64]
	setCtr(&ctr, 0, 0, 0, 0)
	liveCounters(r, clk, &ctr)
	r.m.liveEvery = 0
	var rx atomic.Uint64
	r.pr.link = func() (model.LocalLink, []byte, error) {
		v, t := rx.Load(), rx.Load()/10
		return model.LocalLink{Interface: "Wi-Fi", Type: "wifi", State: "connected", RxBytes: &v, TxBytes: &t}, nil, nil
	}
	for i := 0; i <= 6; i++ { // a cycle every 10 s (no monitoring gap), a reading at 1 s and 61 s
		cycleAt(r, clk, base, i, healthy())
		if i == 0 || i == 6 {
			clk.Set(base.Add(time.Duration(i)*10*time.Second + time.Second))
			r.m.checkLocalLink(context.Background(), false)
			rx.Store(7_500_000) // 1 Mb/s in, 0.1 out over the minute
		}
	}
	clk.Set(base.Add(65 * time.Second))
	v := liveRead(t, r)
	checkRate(t, "PC rx", v.PCRx, 1)
	checkRate(t, "PC tx", v.PCTx, 0.1)
	if len(v.History) != 1 || v.History[0].PCRx == nil {
		t.Fatalf("history %+v", v.History)
	}
	clk.Set(base.Add(61*time.Second + 2*r.m.set.linkInterval + time.Second))
	if v := liveRead(t, r); v.PCRx != nil || v.PCTx != nil {
		t.Fatalf("stale local-link readings: %+v", v)
	}
}

// Without callers the flow meter reads nothing; once Run has ended it reads nothing either.
func TestLiveTrafficOnlyOnDemand(t *testing.T) {
	r := newRig(t, nil, nil)
	stop := r.start(t)
	waitFor(t, "gateway polls", 10*time.Second, func() bool { n, _ := r.gw.snapshotCalls(); return n >= 3 })
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	n, triggers := r.gw.snapshotCalls()
	if slices.Contains(triggers, trigLive) {
		t.Fatalf("live reads without a caller: %v", triggers)
	}
	v := liveRead(t, r)
	if after, _ := r.gw.snapshotCalls(); after != n || !strings.Contains(v.Err, "stopped") {
		t.Fatalf("read after Run ended: %d calls, %+v", after-n, v)
	}
}

// The evidence comes first: a flow-meter read never queues for the gateway lock. While a poll
// holds it the read is skipped - the previous readings come back at once with the reason - and
// once the poll is done the flow meter reads again.
func TestLiveTrafficNeverQueuesBehindAPoll(t *testing.T) {
	r := newRig(t, nil, nil)
	release := make(chan struct{})
	r.gw.snap = func(call int, pages []string, trigger string) (model.GatewaySnapshot, map[string][]byte, error) {
		if trigger != trigLive {
			<-release
		}
		s := okSnapshot(pages, time.Now())
		s.Broadband.Counters = map[string]int64{ctrRxBytes: 1, ctrRxPkts: 1, ctrTxBytes: 1, ctrTxPkts: 1}
		return s, pageBodies(pages, "x"), nil
	}
	r.m.liveEvery = 0
	polled := make(chan struct{})
	go func() {
		defer close(polled)
		r.m.takeSnapshot(context.Background(), trigIncident, nil)
	}()
	waitFor(t, "the poll", 10*time.Second, func() bool { n, _ := r.gw.snapshotCalls(); return n == 1 })
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	v, err := r.m.LiveTraffic(ctx)
	if err != nil || !strings.Contains(v.Err, "evidence") {
		t.Fatalf("a read while a poll holds the gateway: %+v %v", v, err)
	}
	if _, triggers := r.gw.snapshotCalls(); slices.Contains(triggers, trigLive) {
		t.Fatalf("the flow meter read the gateway while a poll held it: %v", triggers)
	}
	close(release)
	<-polled
	if v := liveRead(t, r); v.Err != "" || v.At == "" {
		t.Fatalf("after the poll: %+v", v)
	}
	if _, triggers := r.gw.snapshotCalls(); !reflect.DeepEqual(triggers, []string{trigIncident, trigLive}) {
		t.Fatalf("gateway reads %v", triggers)
	}
}

// A flow-meter read skipped because the gateway lock is held says what holds it, and speaks of the
// evidence only for what is evidence: the Network page's samplers hold the lock too - a NAT read
// for up to natTimeout, a login included, a Device List read for up to devTimeout - and neither is
// evidence, nor does the next reading follow "within seconds" of one. The reason begins with
// "skipped" (the dashboard shows it as a wait, not as a failed read); while what holds the lock
// does not say what it does, the reason names none. Once it is done, the flow meter reads again.
func TestLiveTrafficSaysWhatHoldsTheGateway(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name string
		// hold holds the gateway lock as the case's holder does: its request to the gateway calls
		// wait before it answers. It runs in a goroutine of its own.
		hold func(r *rig, wait func())
		want string // the reason says "the monitor was <want>"
		// notEvidence: what holds the lock is not evidence, and the reason must not say it is.
		notEvidence bool
	}{
		{"a poll's snapshot", func(r *rig, wait func()) {
			r.gw.mu.Lock()
			r.gw.snap = func(call int, pages []string, trigger string) (model.GatewaySnapshot, map[string][]byte, error) {
				wait()
				return okSnapshot(pages, time.Now()), pageBodies(pages, "ok"), nil
			}
			r.gw.mu.Unlock()
			r.m.takeSnapshot(ctx, trigPeriodic, nil)
		}, "taking a snapshot of the gateway for its evidence", false},
		{"the settings check's read of the outage-redirect setting", func(r *rig, wait func()) {
			r.gw.mu.Lock()
			r.gw.notifHold = wait
			r.gw.mu.Unlock()
			_ = r.m.checkNotification(ctx)
		}, "checking the gateway's outage-redirect setting", false},
		{"the operator's change of the outage-redirect setting", func(r *rig, wait func()) {
			r.gw.mu.Lock()
			r.gw.notifHold = wait
			r.gw.mu.Unlock()
			_, _ = r.m.SetGatewayNotification(ctx, false, "web")
		}, "changing the gateway's outage-redirect setting", false},
		{"the settings check's read of the Syslog page", func(r *rig, wait func()) {
			r.gw.mu.Lock()
			read := r.gw.syslog
			r.gw.syslog = func() (model.SyslogSetting, []byte, error) {
				wait()
				return read()
			}
			r.gw.mu.Unlock()
			_ = r.m.checkNotification(ctx)
		}, "checking the gateway's Syslog setting", false},
		{"the operator's change of the Syslog page", func(r *rig, wait func()) {
			r.gw.mu.Lock()
			set := r.gw.setSyslog
			r.gw.setSyslog = func(want model.SyslogTarget) ([]byte, []byte, error) {
				wait()
				return set(want)
			}
			r.gw.mu.Unlock()
			_, _ = r.m.SetGatewaySyslog(ctx, true, "web")
		}, "changing the gateway's Syslog setting", false},
		{"a NAT read for the Network page", func(r *rig, wait func()) {
			r.gw.mu.Lock()
			r.gw.nat = func() (model.NATTable, []byte, error) {
				wait()
				return testNATTable(), testNATPage, nil
			}
			r.gw.mu.Unlock()
			r.m.sampleNAT(ctx)
		}, "reading the gateway's NAT table for the Network page", true},
		{"a Device List read for the Network page", func(r *rig, wait func()) {
			r.gw.mu.Lock()
			r.gw.devices = func() ([]model.LANDevice, []byte, error) {
				wait()
				return testDevices(), testDevicesPage, nil
			}
			r.gw.mu.Unlock()
			r.m.sampleDevices(ctx)
		}, "reading the gateway's Device List for the Network page", true},
		{"a holder that does not say what it does", func(r *rig, wait func()) {
			r.m.gwMu.Lock()
			defer r.m.gwMu.Unlock()
			wait()
		}, "using the gateway", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, _, _ := networkRig(t)
			r.m.liveEvery = 0
			r.m.conns.natTimeout, r.m.conns.devTimeout = time.Hour, time.Hour
			entered, enter := gate()
			released, release := gate()
			defer release() // also when the test fails: nothing is left waiting
			held := make(chan struct{})
			go func() {
				defer close(held)
				tc.hold(r, func() {
					enter()
					<-released
				})
			}()
			await(t, "the holder's request to the gateway", entered)
			v, err := r.m.LiveTraffic(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.HasPrefix(v.Err, "skipped: ") || !strings.Contains(v.Err, "the monitor was "+tc.want) || strings.Contains(v.Err, "within seconds") {
				t.Fatalf("the skip reason %q; want one that begins with \"skipped: \" and says the monitor was %s", v.Err, tc.want)
			}
			if tc.notEvidence && strings.Contains(v.Err, "evidence") {
				t.Fatalf("the skip reason %q speaks of the evidence for a read that is not evidence", v.Err)
			}
			if _, triggers := r.gw.snapshotCalls(); slices.Contains(triggers, trigLive) {
				t.Fatalf("the flow meter read the gateway while it was held: %v", triggers)
			}
			release()
			await(t, "the end of the holder", held)
			if v := liveRead(t, r); v.Err != "" || v.At == "" {
				t.Fatalf("once the holder is done: %+v", v)
			}
		})
	}
}

// A flow-meter read holds the gateway lock for liveTimeout at most: an evidence snapshot that
// needs the lock meanwhile - the gateway answers nothing, an incident polls every 15 s - waits no
// longer than that, not for the gateway's timeout.
func TestLiveReadDelaysTheEvidenceAtMostLiveTimeout(t *testing.T) {
	r := newRig(t, nil, nil)
	r.m.set.gwTimeout = 3 * time.Second
	r.m.liveTimeout = 200 * time.Millisecond
	r.m.liveEvery = 0
	liveStarted := make(chan struct{}, 1)
	var polledAt atomic.Pointer[time.Time]
	r.gw.snapCtx = func(ctx context.Context, call int, pages []string, trigger string) (model.GatewaySnapshot, map[string][]byte, error) {
		if trigger == trigLive {
			liveStarted <- struct{}{}
			<-ctx.Done() // a gateway that does not answer
			return model.GatewaySnapshot{}, nil, ctx.Err()
		}
		now := time.Now()
		polledAt.Store(&now)
		return okSnapshot(pages, now), pageBodies(pages, "ok"), nil
	}
	read := make(chan model.LiveTraffic, 1)
	go func() {
		v, _ := r.m.LiveTraffic(context.Background())
		read <- v
	}()
	select {
	case <-liveStarted:
	case <-time.After(10 * time.Second):
		t.Fatal("the flow meter did not read the gateway")
	}
	asked := time.Now()
	r.m.takeSnapshot(context.Background(), trigIncident, nil)
	at := polledAt.Load()
	if at == nil {
		t.Fatal("the poll did not read the gateway")
	}
	if waited := at.Sub(asked); waited > time.Second {
		t.Fatalf("the poll waited %v behind the flow meter (liveTimeout %v, gateway timeout %v)", waited, r.m.liveTimeout, r.m.set.gwTimeout)
	}
	if v := <-read; !strings.Contains(v.Err, "deadline") {
		t.Fatalf("the flow meter's read: %+v", v)
	}
}

// While the newest recorded snapshot found the gateway unreachable the flow meter does not read
// it (a read would only wait for its timeout); once a poll reaches it again, it does.
func TestLiveTrafficNotReadWhileTheGatewayDoesNotAnswer(t *testing.T) {
	r := newRig(t, nil, nil)
	r.m.liveEvery = 0
	r.gw.snap = func(call int, pages []string, trigger string) (model.GatewaySnapshot, map[string][]byte, error) {
		if trigger == trigLive {
			t.Errorf("a flow-meter read while the gateway does not answer (call %d)", call)
		}
		return model.GatewaySnapshot{}, nil, errors.New("gateway 192.168.1.254: no page could be fetched (broadbandstatistics: i/o timeout)")
	}
	r.m.takeSnapshot(context.Background(), trigIncident, nil)
	if v := liveRead(t, r); !strings.Contains(v.Err, "did not answer the monitor's latest poll") || v.At != "" {
		t.Fatalf("while unreachable: %+v", v)
	}
	r.gw.mu.Lock()
	r.gw.snap = nil
	r.gw.mu.Unlock()
	r.m.takeSnapshot(context.Background(), trigIncident, nil)
	if v := liveRead(t, r); v.Err != "" || v.At == "" {
		t.Fatalf("once the gateway answers: %+v", v)
	}
	if _, triggers := r.gw.snapshotCalls(); !reflect.DeepEqual(triggers, []string{trigIncident, trigIncident, trigLive}) {
		t.Fatalf("gateway reads %v", triggers)
	}
}

// The floor between two flow-meter reads counts from the end of the previous read, so a slow
// gateway is not read back to back.
func TestLiveTrafficFloorCountsFromTheEndOfARead(t *testing.T) {
	r := newRig(t, nil, nil)
	r.m.liveEvery = 400 * time.Millisecond
	r.gw.snap = func(call int, pages []string, trigger string) (model.GatewaySnapshot, map[string][]byte, error) {
		time.Sleep(600 * time.Millisecond) // a slow answer
		s := okSnapshot(pages, time.Now())
		s.Broadband.Counters = map[string]int64{ctrRxBytes: 1, ctrRxPkts: 1, ctrTxBytes: 1, ctrTxPkts: 1}
		return s, nil, nil
	}
	liveRead(t, r)
	liveRead(t, r) // the read began more than liveEvery ago, but ended just now
	if n, _ := r.gw.snapshotCalls(); n != 1 {
		t.Fatalf("%d gateway reads right after a slow one", n)
	}
	time.Sleep(r.m.liveEvery + 50*time.Millisecond)
	liveRead(t, r)
	if n, _ := r.gw.snapshotCalls(); n != 2 {
		t.Fatalf("%d gateway reads once liveEvery passed after the read", n)
	}
}
