package ticket

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"attmonitor/internal/model"
)

// flapScenario mirrors what the live ledger recorded on 2026-10-05: during monitoring the fiber
// link went down and came back while the gateway kept running (PON O5 -> O1 -> O3 -> O5, three
// Last Change moves, Rx shown as 0 while the link was down) and the monitor recorded a provider
// outage with cause FIBER_LINK_DOWN.
type flapScenario struct {
	*scenario
	events  []uint64 // the optical_link_change events
	dark    []uint64 // snapshots with Rx 0 while the link was down
	inc     model.Incident
	closeAt uint64
}

func newFlapScenario(t *testing.T) *flapScenario {
	f := newFake(t)
	fs := &flapScenario{scenario: &scenario{f: f, now: ts("2026-10-05T14:00:00Z")}}
	fs.to, fs.from = fs.now, fs.now.Add(-2*time.Hour)
	fs.start = ts("2026-10-05T12:00:07Z") // cycles on :07, :17 ... like the outage times below
	f.add(fs.start, model.TypeMonitorStart, model.MonitorStart{Mode: "service", Config: testConfig})

	down := ts("2026-10-05T13:04:57Z") // first failing cycle
	up := ts("2026-10-05T13:06:07Z")   // first good cycle again
	lc := lastChange
	type flap struct {
		at    time.Time
		rx    int64
		pon   string
		ponOK bool
		optUp bool
		lc    int64
	}
	flaps := map[string]flap{
		"13:05:02": {ts("2026-10-05T13:05:02Z"), 0, "INIT (O1)", false, false, ts("2026-10-05T13:04:51Z").Unix()},
		"13:05:21": {ts("2026-10-05T13:05:21Z"), 0, "INIT (O1)", false, true, ts("2026-10-05T13:05:07Z").Unix()},
		"13:05:36": {ts("2026-10-05T13:05:36Z"), -309, "SERIAL NUMBER (O3)", false, true, ts("2026-10-05T13:05:27Z").Unix()},
	}
	incID := "INC-20261005-130457Z"
	fs.inc = model.Incident{ID: incID, Opened: down.Format(time.RFC3339Nano), Closed: up.Format(time.RFC3339Nano), DurationSec: 69,
		State: model.StateISPOutage, Cause: model.CauseFiberLinkDown, Attribution: model.AttrProvider, Rules: "2026.10-4",
		Causes: []string{model.CauseISPEdgeUnreachable, model.CauseFiberLinkDown}, Stats: model.IncidentStats{DowntimeSec: 69}}

	var prevSnap uint64
	cycle := uint64(0)
	nextSnap := fs.start.Add(30 * time.Second)
	flapKeys := []string{"13:05:02", "13:05:21", "13:05:36"}
	fi := 0
	for at := fs.start; at.Before(fs.to); at = at.Add(10 * time.Second) {
		cycle++
		state, attr, incField, inet := model.StateOnline, model.AttrNone, "", true
		if !at.Before(down) && at.Before(up) {
			state, attr, inet = model.StateISPOutage, model.AttrProvider, false
			if at.After(down.Add(15 * time.Second)) {
				incField = incID
			}
		}
		f.add(at.Add(10*time.Millisecond), model.TypeSample, sample(cycle, at, state, attr, true, 2400, inet, incField))
		if at.Equal(down.Add(20 * time.Second)) {
			f.add(at.Add(20*time.Millisecond), model.TypeIncidentOpen, fs.inc)
		}
		if at.Equal(up.Add(20 * time.Second)) {
			fs.closeAt = f.add(at.Add(20*time.Millisecond), model.TypeIncidentClose, fs.inc)
		}
		// Snapshots: every minute, plus the three taken during the flap.
		var snapAt time.Time
		var fl *flap
		if fi < len(flapKeys) {
			k := flaps[flapKeys[fi]]
			if !k.at.After(at.Add(10*time.Second)) && k.at.After(at) {
				snapAt, fl = k.at, &k
				fi++
			}
		}
		if fl == nil && !at.Before(nextSnap) && (at.Before(down.Add(-10*time.Second)) || at.After(up)) {
			snapAt = at.Add(2 * time.Second)
			nextSnap = nextSnap.Add(time.Minute)
		}
		if snapAt.IsZero() {
			continue
		}
		uptime := int64(400000) + int64(snapAt.Sub(fs.start)/time.Second)
		var snap model.GatewaySnapshot
		if fl != nil {
			snap = snapshot(snapAt, fl.rx, true, true, uptime, fl.lc)
			snap.Broadband.PONLinkStatus, snap.Derived.PONOperational = fl.pon, bptr(fl.ponOK)
			snap.Broadband.Connection, snap.Derived.BroadbandUp = "Down", bptr(false)
			if !fl.optUp {
				snap.Fiber.OpticalStatus, snap.Derived.OpticalUp = "Down", bptr(false)
			}
			lcBefore := lc
			lc = fl.lc
			seq := f.add(snapAt, model.TypeGatewaySnapshot, snap)
			if fl.rx == 0 {
				fs.dark = append(fs.dark, seq)
			}
			ev := f.add(snapAt.Add(time.Millisecond), model.TypeGatewayEvent, model.GatewayEvent{Kind: model.GwEvOpticalLinkChange,
				Before: fmt.Sprint(lcBefore), After: fmt.Sprint(fl.lc), Evidence: []uint64{prevSnap, seq}})
			fs.events = append(fs.events, ev)
			prevSnap = seq
			continue
		}
		snap = snapshot(snapAt, []int64{-309, -312, -315}[cycle%3], true, true, uptime, lc)
		prevSnap = f.add(snapAt, model.TypeGatewaySnapshot, snap)
		fs.snaps = append(fs.snaps, prevSnap)
	}
	return fs
}

func TestFiberFlapDuringOutage(t *testing.T) {
	fs := newFlapScenario(t)
	if len(fs.events) != 3 || len(fs.dark) != 2 {
		t.Fatalf("scenario: events %v dark %v", fs.events, fs.dark)
	}
	rep, err := Build(context.Background(), fs.f, Options{From: fs.from, To: fs.to, Now: func() time.Time { return fs.now }, Location: cdt})
	if err != nil {
		t.Fatal(err)
	}
	// (a) Rx 0 while the link was down is no receive level, not 0.0 dBm.
	op := rep.Optical
	if op.NoLightN != 2 || op.Levels != len(op.Readings)-2 {
		t.Errorf("no-light %d levels %d of %d", op.NoLightN, op.Levels, len(op.Readings))
	}
	a := rep.Bullet("optical").String()
	wantContains(t, "optical", a, "between -31.5 and -30.9 dBm",
		fmt.Sprintf("In 2 further readings, taken while the gateway reported its own fiber link down (snapshots #%d, #%d), it showed no receive level (Rx 0).", fs.dark[0], fs.dark[1]),
		"Every measured level was below both thresholds.")
	wantNotContains(t, "optical", a, "0.0 dBm", "and 0.0")
	for _, row := range op.Rows {
		if row.NoLight && !strings.Contains(row.Why, "fiber link down") {
			t.Errorf("dark reading row %+v", row)
		}
	}
	if ch := op.Chart; ch == nil || ch.YTicks[len(ch.YTicks)-1].Label != "-28.5" {
		t.Errorf("the chart's axis must not stretch to the placeholder 0: %+v", ch.YTicks)
	}

	// (b) the three changes, grouped with the outage they fall in, UTC confirmed by bracketing.
	b := rep.Bullet("link").String()
	wantContains(t, "link", b,
		"3 fiber link state changes without a gateway restart, including during an outage.",
		"During the outage INC-20261005-130457Z the optical link changed state 3 times",
		"= 13:04:51, 13:05:07 and 13:05:27 UTC on 2026-10-05, the only reading that falls between the gateway readings around each",
		fmt.Sprintf("(gateway_event optical_link_change #%d, #%d, #%d)", fs.events[0], fs.events[1], fs.events[2]),
		"That supports the UTC reading of all these Last Change values.",
		"The gateway did not restart", "so the link changed state while the gateway kept running")
	if rep.Link.Confirmed != "UTC" || len(rep.Link.Changes) != 3 {
		t.Errorf("link = %+v", rep.Link)
	}
	for _, ch := range rep.Link.Changes {
		if !ch.UTCPossible || ch.LocalPossible || ch.PrevObserved.IsZero() {
			t.Errorf("change %d: utc %v local %v prev %v", ch.Value, ch.UTCPossible, ch.LocalPossible, ch.PrevObserved)
		}
	}

	// (c) the outage with its recorded cause.
	c := rep.Bullet("outages").String()
	wantContains(t, "outages", c, "recorded the incident INC-20261005-130457Z attributed to AT&T: 1 min 09 s without Internet",
		fmt.Sprintf("(incident_close #%d, downtime_s)", fs.closeAt),
		"Recorded cause: FIBER_LINK_DOWN: the gateway itself reported its fiber (PON) link down.")

	// The requested action ties the flap to the outage.
	wantContains(t, "action", rep.Action.String(), "Please dispatch a technician",
		"including during the outage INC-20261005-130457Z attributed to AT&T")
	wantNotContains(t, "action", rep.Action.String(), "also measured")

	// The details list the changes with their records.
	page, err := rep.HTML()
	if err != nil {
		t.Fatal(err)
	}
	text := pageText(t, page)
	wantContains(t, "html", text, "Fiber link change", "1791151188 → 1791205491", "fiber link down",
		fmt.Sprintf("gateway_event optical_link_change #%d, #%d, #%d", fs.events[0], fs.events[1], fs.events[2]))
}

// TestSeveralProviderIncidents: totals, the longest and the other incidents.
func TestSeveralProviderIncidents(t *testing.T) {
	f := newFake(t)
	base := ts("2026-10-05T10:00:00Z")
	f.add(base, model.TypeMonitorStart, model.MonitorStart{Mode: "service", Config: testConfig})
	for i := 0; i < 60; i++ {
		at := base.Add(time.Duration(i) * 10 * time.Second)
		f.add(at, model.TypeSample, sample(uint64(i+1), at, model.StateOnline, model.AttrNone, true, 2000, true, ""))
	}
	mk := func(id, opened string, down int64, cause string) model.Incident {
		o := ts(opened)
		return model.Incident{ID: id, Opened: o.Format(time.RFC3339Nano), Closed: o.Add(time.Duration(down+20) * time.Second).Format(time.RFC3339Nano),
			DurationSec: down + 20, State: model.StateISPOutage, Cause: cause, Attribution: model.AttrProvider, Rules: "2026.10-4",
			Stats: model.IncidentStats{DowntimeSec: down}}
	}
	f.add(base.Add(time.Minute), model.TypeIncidentClose, mk("INC-A", "2026-10-05T09:00:00Z", 90, model.CauseWANDown))
	long := f.add(base.Add(2*time.Minute), model.TypeIncidentClose, mk("INC-B", "2026-10-05T10:01:00Z", 400, model.CauseFiberLinkDown))
	rep, err := Build(context.Background(), f, Options{From: base.Add(-30 * time.Minute), To: base.Add(30 * time.Minute),
		Now: func() time.Time { return base.Add(30 * time.Minute) }, Location: time.UTC})
	if err != nil {
		t.Fatal(err)
	}
	c := rep.Bullet("outages").String()
	wantContains(t, "outages", c, "2 incidents attributed to AT&T (INC-A and INC-B): 8 min 10 s without Internet in total",
		fmt.Sprintf("the longest 6 min 40 s (INC-B, incident_close #%d)", long),
		"INC-A began before this window; its figures include that time.",
		"Recorded causes: WAN_DOWN: the gateway itself reported its broadband connection down; FIBER_LINK_DOWN")
	wantContains(t, "action", rep.Action.String(), "Please investigate the fiber service.", "2 outage incidents attributed to AT&T")
}
