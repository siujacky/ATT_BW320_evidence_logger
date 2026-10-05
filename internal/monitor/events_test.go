package monitor

import (
	"slices"
	"strings"
	"testing"
	"time"

	"attmonitor/internal/model"
)

// obsOf is a snapshot taken by this process at at (its clock measures the time between two).
func obsOf(seq uint64, at time.Time, mut func(*model.GatewaySnapshot)) *snapObs {
	s := okSnapshot([]string{"broadbandstatistics", "fiberstat", "sysinfo"}, at)
	if mut != nil {
		mut(&s)
	}
	return &snapObs{Seq: seq, At: at, Snap: &s, live: true}
}

// ledgerObs is a snapshot read back from the ledger (taken by an earlier run of the monitor):
// at is the time this computer's clock then showed; gwOffMs (optional) the gateway's own clock
// minus that.
func ledgerObs(seq uint64, at time.Time, gwOffMs *int64, mut func(*model.GatewaySnapshot)) *snapObs {
	o := obsOf(seq, at, mut)
	o.live = false
	o.Snap.Derived.GatewayClockOffsetMs = gwOffMs
	return o
}

func unreachableObs(seq uint64, at time.Time) *snapObs {
	return &snapObs{Seq: seq, At: at, live: true, Snap: &model.GatewaySnapshot{
		Pages: []model.PageCapture{{Page: "sysinfo", FetchedAt: fmtTS(at), Err: "dial tcp 192.168.1.254:443: i/o timeout"}},
	}}
}

func eventKinds(evs []model.GatewayEvent) []string {
	var k []string
	for _, e := range evs {
		k = append(k, e.Kind)
	}
	return k
}

func findEvent(evs []model.GatewayEvent, kind string) *model.GatewayEvent {
	for i := range evs {
		if evs[i].Kind == kind {
			return &evs[i]
		}
	}
	return nil
}

func TestGatewayEvents(t *testing.T) {
	at1 := t0
	at2 := t0.Add(time.Minute)
	prev := obsOf(10, at1, nil)

	tests := []struct {
		name        string
		prevAttempt *snapObs
		prevGood    *snapObs
		cur         *snapObs
		want        []string // event kinds, in order
		check       func(t *testing.T, evs []model.GatewayEvent)
	}{
		{name: "no change", prevAttempt: prev, prevGood: prev, cur: obsOf(11, at2, func(s *model.GatewaySnapshot) {
			s.System.UptimeSec, s.Derived.UptimeSec = 274746, 274746
			s.Derived.BootTimeEstimate = prev.Snap.Derived.BootTimeEstimate
		})},
		{name: "reboot: uptime decreased", prevAttempt: prev, prevGood: prev, cur: obsOf(11, at2, func(s *model.GatewaySnapshot) {
			s.System.UptimeSec, s.Derived.UptimeSec = 35, 35
			s.Derived.BootTimeEstimate = fmtTS(at2.Add(-35 * time.Second))
		}), want: []string{model.GwEvReboot}, check: func(t *testing.T, evs []model.GatewayEvent) {
			e := evs[0]
			if !strings.Contains(e.Detail, "uptime went from 274686 s to 35 s") || e.After != fmtTS(at2.Add(-35*time.Second)) {
				t.Fatalf("detail %q after %q", e.Detail, e.After)
			}
			if !slices.Equal(e.Evidence, []uint64{10, 11}) {
				t.Fatalf("evidence %v", e.Evidence)
			}
		}},
		{name: "reboot: boot estimate moved > 120 s while uptime grew (monitor was down)", prevAttempt: prev, prevGood: obsOf(10, at1, func(s *model.GatewaySnapshot) {
			s.System.UptimeSec, s.Derived.UptimeSec = 100, 100
			s.Derived.BootTimeEstimate = fmtTS(at1.Add(-100 * time.Second))
		}), cur: obsOf(11, at1.Add(2*time.Hour), func(s *model.GatewaySnapshot) {
			s.System.UptimeSec, s.Derived.UptimeSec = 600, 600
			s.Derived.BootTimeEstimate = fmtTS(at1.Add(2*time.Hour - 600*time.Second))
		}), want: []string{model.GwEvReboot}},
		{name: "boot estimate jitter ≤ 120 s is not a reboot", prevAttempt: prev, prevGood: prev, cur: obsOf(11, at2, func(s *model.GatewaySnapshot) {
			s.System.UptimeSec, s.Derived.UptimeSec = 274700, 274700
			s.Derived.BootTimeEstimate = fmtTS(at1.Add(-274686*time.Second + 90*time.Second))
		})},
		{name: "boot estimate computed from sysinfo fetch time when absent", prevAttempt: prev, prevGood: obsOf(10, at1, func(s *model.GatewaySnapshot) {
			s.Derived.BootTimeEstimate = ""
		}), cur: obsOf(11, at2, func(s *model.GatewaySnapshot) {
			s.Derived.BootTimeEstimate = ""
			s.System.UptimeSec = 274686 + 60 + 500 // 500 s more than elapsed: boot moved back 500 s
		}), want: []string{model.GwEvReboot}},
		{name: "firmware change", prevAttempt: prev, prevGood: prev, cur: obsOf(11, at2, func(s *model.GatewaySnapshot) {
			s.Derived.Firmware, s.System.SoftwareVersion = "6.35.1", "6.35.1"
			s.Derived.BootTimeEstimate = prev.Snap.Derived.BootTimeEstimate
		}), want: []string{model.GwEvFirmwareChange}, check: func(t *testing.T, evs []model.GatewayEvent) {
			if evs[0].Before != "6.34.7" || evs[0].After != "6.35.1" {
				t.Fatalf("%+v", evs[0])
			}
		}},
		{name: "WAN down: broadband state, IP removed, clock blank", prevAttempt: prev, prevGood: prev, cur: func() *snapObs {
			o := obsOf(11, at2, nil)
			d := downSnapshot([]string{"sysinfo"}, at2)
			d.Derived.BootTimeEstimate = prev.Snap.Derived.BootTimeEstimate
			o.Snap = &d
			return o
		}(), want: []string{model.GwEvWANIPChange, model.GwEvBroadbandState, model.GwEvGatewayClock}, check: func(t *testing.T, evs []model.GatewayEvent) {
			if e := findEvent(evs, model.GwEvBroadbandState); e.Before != "Up" || e.After != "Down" {
				t.Fatalf("%+v", e)
			}
			if e := findEvent(evs, model.GwEvWANIPChange); e.Before != "203.0.113.5" || e.After != "" || !strings.Contains(e.Detail, "removed") {
				t.Fatalf("%+v", e)
			}
			if e := findEvent(evs, model.GwEvGatewayClock); e.After != "blank" {
				t.Fatalf("%+v", e)
			}
		}},
		{name: "WAN IP changed", prevAttempt: prev, prevGood: prev, cur: obsOf(11, at2, func(s *model.GatewaySnapshot) {
			s.Broadband.IPv4, s.Derived.WANIPv4 = "203.0.113.77", "203.0.113.77"
			s.Derived.BootTimeEstimate = prev.Snap.Derived.BootTimeEstimate
		}), want: []string{model.GwEvWANIPChange}, check: func(t *testing.T, evs []model.GatewayEvent) {
			if !strings.Contains(evs[0].Detail, "changed from 203.0.113.5 to 203.0.113.77") {
				t.Fatalf("%q", evs[0].Detail)
			}
		}},
		{name: "PON state", prevAttempt: prev, prevGood: prev, cur: obsOf(11, at2, func(s *model.GatewaySnapshot) {
			s.Broadband.PONLinkStatus = "POPUP (O6)"
			s.Derived.PONOperational = boolp(false)
			s.Derived.BootTimeEstimate = prev.Snap.Derived.BootTimeEstimate
		}), want: []string{model.GwEvPONState}, check: func(t *testing.T, evs []model.GatewayEvent) {
			if evs[0].Before != "OPERATION (O5)" || evs[0].After != "POPUP (O6)" || !strings.Contains(evs[0].Detail, "operational: yes → no") {
				t.Fatalf("%+v", evs[0])
			}
		}},
		{name: "optical alarm raised and cleared", prevAttempt: prev, prevGood: prev, cur: obsOf(11, at2, func(s *model.GatewaySnapshot) {
			s.Derived.Alarms = []string{"OPTICAL_RX_LOW_ALARM", "TEMPERATURE_HIGH_WARNING"}
			s.Derived.BootTimeEstimate = prev.Snap.Derived.BootTimeEstimate
		}), want: []string{model.GwEvOpticalAlarm}, check: func(t *testing.T, evs []model.GatewayEvent) {
			e := evs[0]
			for _, s := range []string{"raised: TEMPERATURE_HIGH_WARNING", "cleared: OPTICAL_RX_LOW_WARNING", "Rx -31.5 dBm, Tx 3.7 dBm"} {
				if !strings.Contains(e.Detail, s) {
					t.Fatalf("detail %q lacks %q", e.Detail, s)
				}
			}
			if e.Before != "OPTICAL_RX_LOW_ALARM,OPTICAL_RX_LOW_WARNING" || e.After != "OPTICAL_RX_LOW_ALARM,TEMPERATURE_HIGH_WARNING" {
				t.Fatalf("before %q after %q", e.Before, e.After)
			}
		}},
		{name: "alarm order change is not an event", prevAttempt: prev, prevGood: prev, cur: obsOf(11, at2, func(s *model.GatewaySnapshot) {
			s.Derived.Alarms = []string{"OPTICAL_RX_LOW_WARNING", "OPTICAL_RX_LOW_ALARM"}
			s.Derived.BootTimeEstimate = prev.Snap.Derived.BootTimeEstimate
		})},
		{name: "optical link change (flap shorter than the poll interval)", prevAttempt: prev, prevGood: prev, cur: obsOf(11, at2, func(s *model.GatewaySnapshot) {
			s.Derived.FiberLastChange = 1791151300
			s.Derived.BootTimeEstimate = prev.Snap.Derived.BootTimeEstimate
		}), want: []string{model.GwEvOpticalLinkChange}, check: func(t *testing.T, evs []model.GatewayEvent) {
			if evs[0].Before != "1791151188" || evs[0].After != "1791151300" || !strings.Contains(evs[0].Detail, "shorter than the poll interval") {
				t.Fatalf("%+v", evs[0])
			}
		}},
		{name: "counters reset without reboot", prevAttempt: prev, prevGood: prev, cur: obsOf(11, at2, func(s *model.GatewaySnapshot) {
			s.Broadband.Counters = map[string]int64{"IPv4 Statistics/Receive Packets": 12, "IPv4 Statistics/Transmit Packets": 9}
			s.Derived.BootTimeEstimate = prev.Snap.Derived.BootTimeEstimate
		}), want: []string{model.GwEvCountersReset}, check: func(t *testing.T, evs []model.GatewayEvent) {
			if !strings.Contains(evs[0].Detail, "IPv4 Statistics/Receive Packets 1000→12") {
				t.Fatalf("%q", evs[0].Detail)
			}
		}},
		{name: "one decreasing counter (wrap) is not a reset", prevAttempt: prev, prevGood: prev, cur: obsOf(11, at2, func(s *model.GatewaySnapshot) {
			s.Broadband.Counters = map[string]int64{"IPv4 Statistics/Receive Packets": 12, "IPv4 Statistics/Transmit Packets": 950}
			s.Derived.BootTimeEstimate = prev.Snap.Derived.BootTimeEstimate
		})},
		{name: "counters reset by a reboot is only a reboot", prevAttempt: prev, prevGood: prev, cur: obsOf(11, at2, func(s *model.GatewaySnapshot) {
			s.Broadband.Counters = map[string]int64{"IPv4 Statistics/Receive Packets": 12, "IPv4 Statistics/Transmit Packets": 9}
			s.System.UptimeSec, s.Derived.UptimeSec = 30, 30
			s.Derived.BootTimeEstimate = fmtTS(at2.Add(-30 * time.Second))
		}), want: []string{model.GwEvReboot}},
		{name: "gateway clock set again", prevAttempt: prev, prevGood: obsOf(10, at1, func(s *model.GatewaySnapshot) {
			s.Derived.GatewayClockBlank = true
			s.System.GatewayTimeRaw = ""
		}), cur: obsOf(11, at2, func(s *model.GatewaySnapshot) {
			s.Derived.BootTimeEstimate = prev.Snap.Derived.BootTimeEstimate
		}), want: []string{model.GwEvGatewayClock}, check: func(t *testing.T, evs []model.GatewayEvent) {
			if evs[0].Before != "blank" || evs[0].After != "set" || !strings.Contains(evs[0].Detail, "2026-10-04T22:10:44") {
				t.Fatalf("%+v", evs[0])
			}
		}},
		{name: "gateway became unreachable", prevAttempt: prev, prevGood: prev, cur: unreachableObs(11, at2),
			want: []string{model.GwEvUnreachable}, check: func(t *testing.T, evs []model.GatewayEvent) {
				e := evs[0]
				if e.Before != "reachable" || e.After != "unreachable" || !strings.Contains(e.Detail, "i/o timeout") || !slices.Equal(e.Evidence, []uint64{10, 11}) {
					t.Fatalf("%+v", e)
				}
			}},
		{name: "gateway reachable again (compared with the last good snapshot too)", prevAttempt: unreachableObs(11, at2), prevGood: prev, cur: obsOf(12, at2.Add(time.Minute), func(s *model.GatewaySnapshot) {
			s.System.UptimeSec, s.Derived.UptimeSec = 20, 20
			s.Derived.BootTimeEstimate = fmtTS(at2.Add(time.Minute - 20*time.Second))
		}), want: []string{model.GwEvUnreachable, model.GwEvReboot}, check: func(t *testing.T, evs []model.GatewayEvent) {
			if evs[0].After != "reachable" || !slices.Equal(evs[0].Evidence, []uint64{11, 12}) || !slices.Equal(evs[1].Evidence, []uint64{10, 12}) {
				t.Fatalf("%+v", evs)
			}
		}},
		{name: "first observation with alarms raised", cur: obsOf(1, at1, nil), want: []string{model.GwEvOpticalAlarm},
			check: func(t *testing.T, evs []model.GatewayEvent) {
				if evs[0].Before != "" || evs[0].After != "OPTICAL_RX_LOW_ALARM,OPTICAL_RX_LOW_WARNING" || !strings.Contains(evs[0].Detail, "first gateway observation") {
					t.Fatalf("%+v", evs[0])
				}
			}},
		{name: "first observation without alarms", cur: obsOf(1, at1, func(s *model.GatewaySnapshot) { s.Derived.Alarms = nil })},
		{name: "parse gaps do not produce events", prevAttempt: prev, prevGood: prev, cur: obsOf(11, at2, func(s *model.GatewaySnapshot) {
			s.Fiber, s.System, s.Broadband = nil, nil, nil
			s.Derived = model.GatewayDerived{Reachable: true}
		})},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			evs := gatewayEvents(tc.prevAttempt, tc.prevGood, tc.prevGood, tc.cur)
			if got := eventKinds(evs); !slices.Equal(got, tc.want) {
				t.Fatalf("kinds %v want %v\n%+v", got, tc.want, evs)
			}
			if tc.check != nil {
				tc.check(t, evs)
			}
		})
	}
}

func TestMaterialChangeAndStoragePolicy(t *testing.T) {
	at := t0
	base := okSnapshot(nil, at)
	same := okSnapshot(nil, at.Add(time.Minute))
	same.System.UptimeSec += 60
	same.Derived.BootTimeEstimate = base.Derived.BootTimeEstimate
	mut := func(f func(*model.GatewaySnapshot)) *model.GatewaySnapshot {
		s := okSnapshot(nil, at.Add(time.Minute))
		s.System.UptimeSec += 60
		s.Derived.BootTimeEstimate = base.Derived.BootTimeEstimate
		f(&s)
		return &s
	}
	tests := []struct {
		name string
		prev *model.GatewaySnapshot
		cur  *model.GatewaySnapshot
		want bool
	}{
		{"no previous snapshot", nil, &same, true},
		{"unchanged", &base, &same, false},
		{"broadband down", &base, mut(func(s *model.GatewaySnapshot) { s.Derived.BroadbandUp = boolp(false) }), true},
		{"pon raw text", &base, mut(func(s *model.GatewaySnapshot) { s.Broadband.PONLinkStatus = "OPERATION (O5) " }), true},
		{"optical flags", &base, mut(func(s *model.GatewaySnapshot) { s.Fiber.RxLOSState = "1" }), true},
		{"alarm set", &base, mut(func(s *model.GatewaySnapshot) { s.Derived.Alarms = nil }), true},
		{"wan ip", &base, mut(func(s *model.GatewaySnapshot) { s.Derived.WANIPv4 = "203.0.113.9" }), true},
		{"uptime reset", &base, mut(func(s *model.GatewaySnapshot) { s.System.UptimeSec = 5 }), true},
		{"firmware", &base, mut(func(s *model.GatewaySnapshot) { s.Derived.Firmware = "6.35.1" }), true},
		{"fiber last change", &base, mut(func(s *model.GatewaySnapshot) { s.Derived.FiberLastChange++ }), true},
		{"reachability", &base, &model.GatewaySnapshot{}, true},
		{"counters only", &base, mut(func(s *model.GatewaySnapshot) { s.Broadband.Counters["IPv4 Statistics/Receive Packets"] += 500 }), false},
	}
	for _, tc := range tests {
		if got := materialChange(tc.prev, tc.cur, time.Minute, true); got != tc.want {
			t.Errorf("%s: material %v want %v", tc.name, got, tc.want)
		}
	}

	interval := 5 * time.Minute
	policy := []struct {
		name               string
		incident, material bool
		last               time.Time
		want               bool
	}{
		{"never stored", false, false, time.Time{}, true},
		{"recently stored, nothing new", false, false, at.Add(-time.Minute), false},
		{"interval elapsed", false, false, at.Add(-interval), true},
		{"incident open", true, false, at.Add(-time.Second), true},
		{"material change", false, true, at.Add(-time.Second), true},
	}
	for _, p := range policy {
		if got := shouldStoreRaw(p.incident, p.material, p.last, at, interval); got != p.want {
			t.Errorf("%s: store %v want %v", p.name, got, p.want)
		}
	}
}
