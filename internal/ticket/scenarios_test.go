package ticket

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"attmonitor/internal/model"
)

// Scenarios for layout tests: a bad day, long unbreakable values, an evening start.

// cliVerification is a verification line in the form cmd/att-monitor's ticket-report states it
// (the longest form the report prints on page 1).
const cliVerification = "verified OK — 9,412 records, hash chain and Ed25519 signatures intact, report re-computed from the records, " +
	"49 trusted RFC 3161 time-stamp(s), key ae21 6c2e f524 7a37 82c1 35ef a279 a3e4 cdc6 1094 270f 5d2b e58c 6204 b7a6 12c9"

// stressScenario is the real situation on a bad day: monitoring from 15:00 UTC the day before,
// a 70-second provider outage every 80 minutes during which the fiber link goes down (the gateway
// shows Rx 0 and reports PON INIT, and the Last Change value moves), a service stop of 17 minutes
// every 5 hours, two gateway restarts reported by events, and the Wi-Fi signal varying.
func stressScenario(t testing.TB) *scenario {
	f := newFake(t)
	s := &scenario{f: f, now: ts("2026-10-05T14:00:00Z")}
	s.to, s.from = s.now, s.now.Add(-24*time.Hour)
	g := ts("2026-10-04T15:00:00Z")
	f.add(g, model.TypeGenesis, genesisData())
	s.addBootstrap(g.Add(68 * time.Millisecond))
	s.start = g.Add(81 * time.Millisecond)
	f.add(s.start, model.TypeMonitorStart, model.MonitorStart{Mode: "service", Config: testConfig, ConfigSHA256: sha256Hex(testConfig)})
	cycle := uint64(0)
	rx := []int64{-309, -311, -313, -315, -312, -310}
	nsnap := 0
	lc := lastChange
	var prevSnap uint64
	run := 0
	at := s.start
	for at.Before(s.to) {
		// A service stop of 17 minutes every 5 hours.
		if h := at.Sub(s.start); h > 0 && int(h/time.Minute)%300 == 0 && h%time.Minute < 10*time.Second {
			f.add(at, model.TypeMonitorStop, model.MonitorStop{Reason: "service stop"})
			at = at.Add(17 * time.Minute)
			run++
			f.run = fmt.Sprintf("%032x", run+100)
			f.add(at, model.TypeMonitorStart, model.MonitorStart{Mode: "service", Config: testConfig, ConfigSHA256: sha256Hex(testConfig)})
		}
		cycle++
		// A 70-second outage every 80 minutes.
		mins := int(at.Sub(s.start) / time.Minute)
		inOut := mins%80 == 40 && at.Sub(s.start)%time.Minute < 70*time.Second
		state, attr, inet := model.StateOnline, model.AttrNone, true
		if inOut {
			state, attr, inet = model.StateISPOutage, model.AttrProvider, false
		}
		f.add(at.Add(15*time.Millisecond), model.TypeSample, sample(cycle, at, state, attr, true, int64(2000+(cycle%7)*150), inet, ""))
		if inOut && at.Sub(s.start)%time.Minute < 10*time.Second {
			opened, closed := at, at.Add(70*time.Second)
			id := "INC-" + opened.UTC().Format("20060102-150405") + "Z"
			inc := model.Incident{ID: id, Opened: opened.Format(time.RFC3339Nano), Closed: closed.Format(time.RFC3339Nano), DurationSec: 70,
				State: model.StateISPOutage, Cause: model.CauseFiberLinkDown, Attribution: model.AttrProvider, Rules: "2026.10-4",
				Causes: []string{model.CauseISPEdgeUnreachable, model.CauseFiberLinkDown},
				Summary: fmt.Sprintf("ISP outage from %s to %s (1m10s), cause FIBER_LINK_DOWN: the AT&T gateway reported its fiber/PON link down. Attributed to the provider (AT&T). Measured time: 1m10s without Internet (ISP_OUTAGE cycles).",
					opened.UTC().Format(time.RFC3339), closed.UTC().Format(time.RFC3339)),
				Stats: model.IncidentStats{DowntimeSec: 70}}
			f.add(at.Add(20*time.Millisecond), model.TypeIncidentClose, inc)
			// The fiber link goes down inside the outage, between two snapshots.
			newLC := at.Add(5 * time.Second).Unix()
			snap := snapshot(at.Add(8*time.Second), 0, true, true, 300000+int64(at.Sub(s.start)/time.Second), newLC)
			snap.Broadband.PONLinkStatus, snap.Derived.PONOperational = "INIT (O1)", bptr(false)
			snap.Fiber.OpticalStatus, snap.Derived.OpticalUp = "Down", bptr(false)
			sq := f.add(at.Add(8*time.Second), model.TypeGatewaySnapshot, snap)
			f.add(at.Add(8*time.Second+time.Millisecond), model.TypeGatewayEvent, model.GatewayEvent{Kind: model.GwEvOpticalLinkChange,
				Before: fmt.Sprint(lc), After: fmt.Sprint(newLC), Evidence: []uint64{prevSnap, sq}})
			f.add(at.Add(8*time.Second+2*time.Millisecond), model.TypeGatewayEvent, model.GatewayEvent{Kind: model.GwEvPONState,
				Before: "OPERATION (O5)", After: "INIT (O1)", Evidence: []uint64{prevSnap, sq}})
			f.add(at.Add(8*time.Second+3*time.Millisecond), model.TypeGatewayEvent, model.GatewayEvent{Kind: model.GwEvBroadbandState,
				Before: "Up", After: "Down", Evidence: []uint64{prevSnap, sq}})
			lc = newLC
			prevSnap = sq
		}
		if cycle%6 == 2 && !inOut {
			snapAt := at.Add(2 * time.Second)
			up := int64(300000) + int64(snapAt.Sub(s.start)/time.Second)
			seq := f.add(snapAt, model.TypeGatewaySnapshot, snapshot(snapAt, rx[nsnap%len(rx)], true, true, up, lc))
			s.snaps = append(s.snaps, seq)
			prevSnap = seq
			nsnap++
		}
		if cycle%60 == 1 {
			s.links = append(s.links, f.add(at.Add(20*time.Millisecond), model.TypeLocalLink, wifi(70+int(cycle/60)%15, false)))
		}
		at = at.Add(10 * time.Second)
	}
	// Two restarts reported by events.
	f.add(s.to.Add(-time.Minute), model.TypeGatewayEvent, model.GatewayEvent{Kind: model.GwEvReboot, Before: "2026-10-01T22:52:37Z", After: "2026-10-05T02:00:00Z"})
	f.add(s.to.Add(-50*time.Second), model.TypeGatewayEvent, model.GatewayEvent{Kind: model.GwEvReboot, Before: "2026-10-05T02:00:00Z", After: "2026-10-05T09:00:00Z"})
	return s
}

// clearedScenario is the real day on which the alarm cleared: the real situation until 13:30 UTC,
// then a 5-minute provider outage in which the fiber link goes down (the gateway shows no receive
// level and PON INIT), after which the level is 9.5 dB higher, -21.4 dBm, and the gateway clears
// its low-Rx flags (gateway_event optical_alarm).
func clearedScenario(t testing.TB) *scenario {
	f := newFake(t)
	s := &scenario{f: f, now: ts("2026-10-05T14:00:00Z")}
	s.to, s.from = s.now, s.now.Add(-24*time.Hour)
	g := ts("2026-10-05T12:45:47.5635624Z")
	f.add(g, model.TypeGenesis, genesisData())
	s.addBootstrap(g.Add(68 * time.Millisecond))
	s.start = g.Add(81 * time.Millisecond)
	f.add(s.start, model.TypeMonitorStart, model.MonitorStart{Mode: "service", Config: testConfig, ConfigSHA256: sha256Hex(testConfig)})
	outFrom, outTo := ts("2026-10-05T13:30:00Z"), ts("2026-10-05T13:35:00Z")
	id := "INC-20261005-133000Z"
	rx := []int64{-311, -313, -315, -312, -310}
	lc := lastChange
	var prevSnap uint64
	cycle, nsnap, phase := uint64(0), 0, 0 // phase: 0 before the outage, 1 in it, 2 after it
	for at := s.start; at.Before(s.to); at = at.Add(10 * time.Second) {
		cycle++
		inOut := !at.Before(outFrom) && at.Before(outTo)
		state, attr, inet, inc := model.StateOnline, model.AttrNone, true, ""
		if inOut {
			state, attr, inet, inc = model.StateISPOutage, model.AttrProvider, false, id
		}
		s.samples = append(s.samples, f.add(at.Add(15*time.Millisecond), model.TypeSample, sample(cycle, at, state, attr, true, 2400, inet, inc)))
		if !at.Before(outTo) && phase == 1 {
			f.add(at.Add(20*time.Millisecond), model.TypeIncidentClose, model.Incident{ID: id, Opened: outFrom.Format(time.RFC3339Nano),
				Closed: outTo.Format(time.RFC3339Nano), DurationSec: 300, State: model.StateISPOutage, Cause: model.CauseFiberLinkDown,
				Attribution: model.AttrProvider, Rules: "2026.10-4", Causes: []string{model.CauseFiberLinkDown},
				Summary: "ISP outage, cause FIBER_LINK_DOWN: the AT&T gateway reported its fiber/PON link down. Attributed to the provider (AT&T).",
				Stats:   model.IncidentStats{DowntimeSec: 300}})
		}
		if cycle%6 != 2 {
			continue
		}
		snapAt := at.Add(2 * time.Second)
		up := int64(309201) + int64(snapAt.Sub(s.start)/time.Second)
		var snap model.GatewaySnapshot
		var events []model.GatewayEvent
		switch {
		case inOut:
			if phase == 0 {
				phase, lc = 1, outFrom.Add(4*time.Second).Unix()
				events = append(events, model.GatewayEvent{Kind: model.GwEvPONState, Before: "OPERATION (O5)", After: "INIT (O1)"},
					model.GatewayEvent{Kind: model.GwEvOpticalLinkChange, Before: fmt.Sprint(lastChange), After: fmt.Sprint(lc)})
			}
			snap = snapshot(snapAt, 0, true, true, up, lc)
			snap.Broadband.PONLinkStatus, snap.Derived.PONOperational = "INIT (O1)", bptr(false)
			snap.Fiber.OpticalStatus, snap.Derived.OpticalUp = "Down", bptr(false)
		case phase == 0:
			r := rx[nsnap%len(rx)]
			if !snapAt.Add(time.Minute).Before(outFrom) {
				r = -309 // the last reading before the loss of light
			}
			snap = snapshot(snapAt, r, true, true, up, lc)
		default:
			if phase == 1 {
				prev := lc
				phase, lc = 2, outTo.Add(-8*time.Second).Unix()
				events = append(events, model.GatewayEvent{Kind: model.GwEvPONState, Before: "INIT (O1)", After: "OPERATION (O5)"},
					model.GatewayEvent{Kind: model.GwEvOpticalLinkChange, Before: fmt.Sprint(prev), After: fmt.Sprint(lc)},
					model.GatewayEvent{Kind: model.GwEvOpticalAlarm, Before: "OPTICAL_RX_LOW_ALARM,OPTICAL_RX_LOW_WARNING",
						Detail: "cleared: OPTICAL_RX_LOW_ALARM, OPTICAL_RX_LOW_WARNING; Rx -21.4 dBm, Tx 4.8 dBm"})
			}
			snap = snapshot(snapAt, -214+int64(nsnap%2), false, false, up, lc)
		}
		seq := f.add(snapAt, model.TypeGatewaySnapshot, snap)
		if nsnap == 0 {
			events = append(events, model.GatewayEvent{Kind: model.GwEvOpticalAlarm, After: "OPTICAL_RX_LOW_ALARM,OPTICAL_RX_LOW_WARNING",
				Detail: "alarm flags already raised at the first gateway observation by this monitor; Rx -31.1 dBm, Tx 4.8 dBm"})
		}
		for i, e := range events {
			e.Evidence = []uint64{seq}
			if prevSnap != 0 {
				e.Evidence = []uint64{prevSnap, seq}
			}
			f.add(snapAt.Add(time.Duration(i+1)*time.Millisecond), model.TypeGatewayEvent, e)
		}
		s.snaps = append(s.snaps, seq)
		prevSnap = seq
		nsnap++
		if cycle%60 == 2 {
			s.links = append(s.links, f.add(snapAt.Add(20*time.Millisecond), model.TypeLocalLink, wifi(82+int(cycle/60)%3, false)))
		}
	}
	return s
}

// stressCustomer fills every customer field with long, realistic text.
func stressCustomer() Customer {
	return Customer{Name: "Jordan Alexander Example-Montgomery III", Account: "123456789012",
		Address:  "12345 North Example Boulevard, Apartment 1234, Springfield Heights, IL 62704-1234",
		Phone:    "+1 (217) 555-0123 ext. 4567",
		BestTime: "Weekdays 8:00 AM - 5:00 PM Central, or text anytime",
		Notes:    "Ticket#000000000000000000000000000000000000 jordan.alexander.example-montgomery@example-very-long-domain-name.com"}
}

// longTokenNotes is a customer note without any break opportunity.
var longTokenNotes = strings.Repeat("TICKET", 20)

// longTokenOptions puts long unbreakable values into the customer fields and the bundle name.
func longTokenOptions(s *scenario) Options {
	o := s.options()
	o.Customer = Customer{Name: "Jordan Example",
		Account: "ACCT-" + strings.Repeat("1234567890", 6),
		Address: "https://maps.example.com/place/" + strings.Repeat("abcdefghij", 8),
		Notes:   longTokenNotes}
	o.BundleName = "att-evidence_20261004T140000Z_20261005T140000Z_6961b23f_" + strings.Repeat("x", 80) + ".zip"
	return o
}

// eveningScenario is the real situation with monitoring from 00:30 UTC (19:30 CDT the day before,
// so local and UTC dates differ) and an optical alarm event naming four of the gateway's flags.
func eveningScenario(t testing.TB) *scenario {
	f := newFake(t)
	s := &scenario{f: f, now: ts("2026-10-05T14:00:00Z")}
	s.to, s.from = s.now, s.now.Add(-24*time.Hour)
	g := ts("2026-10-05T00:30:00Z")
	f.add(g, model.TypeGenesis, genesisData())
	s.addBootstrap(g.Add(68 * time.Millisecond))
	s.start = g.Add(81 * time.Millisecond)
	f.add(s.start, model.TypeMonitorStart, model.MonitorStart{Mode: "service", Config: testConfig, ConfigSHA256: sha256Hex(testConfig)})
	cycle := uint64(0)
	for at := s.start; at.Before(s.to); at = at.Add(10 * time.Second) {
		cycle++
		s.samples = append(s.samples, f.add(at.Add(15*time.Millisecond), model.TypeSample, sample(cycle, at, model.StateOnline, model.AttrNone, true, 2400, true, "")))
		if cycle%6 == 2 {
			snapAt := at.Add(2 * time.Second)
			seq := f.add(snapAt, model.TypeGatewaySnapshot, snapshot(snapAt, -312, true, true, 300000+int64(snapAt.Sub(s.start)/time.Second), lastChange))
			s.snaps = append(s.snaps, seq)
			if cycle == 2 {
				f.add(snapAt.Add(time.Millisecond), model.TypeGatewayEvent, model.GatewayEvent{Kind: model.GwEvOpticalAlarm,
					After:  "OPTICAL_RX_LOW_ALARM,OPTICAL_RX_LOW_WARNING,OPTICAL_TX_LOW_WARNING,TEMPERATURE_HIGH_WARNING",
					Detail: "alarm flags already raised at the first gateway observation by this monitor; Rx -31.2 dBm, Tx 4.8 dBm", Evidence: []uint64{seq}})
			}
		}
	}
	return s
}
