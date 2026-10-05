package ticket

import (
	"strings"
	"testing"

	"attmonitor/internal/model"
)

// TestClearedAlarm: the real day on which the gateway's low-Rx alarm cleared after a step change of
// the level across a loss of light. The report said "The gateway's own low-Rx optical ALARM is
// active" and asked AT&T to clean the fiber "until the gateway's low-Rx alarm clears" although the
// alarm had cleared an hour before; it did not mention the 9.5 dB step at all.
func TestClearedAlarm(t *testing.T) {
	cs := clearedScenario(t)
	rep := mustBuild(t, cs, cs.options())
	op := &rep.Optical

	if op.AlarmRuns != 1 || op.Clear == nil {
		t.Fatalf("alarm runs %d, clear %+v", op.AlarmRuns, op.Clear)
	}
	cl := op.Clear
	if !cl.SetFrom.Setup || cl.LastSet.RxX10 != -309 || cl.Cleared.RxX10 != -214 || cl.Cleared.Alarm {
		t.Errorf("clear: from %+v, last set %+v, cleared %+v", cl.SetFrom, cl.LastSet, cl.Cleared)
	}
	if cl.EventSeq == 0 || cs.f.recs[cl.EventSeq].body.Type != model.TypeGatewayEvent {
		t.Errorf("the clearing's gateway_event optical_alarm is not named: %d", cl.EventSeq)
	}
	if len(op.Steps) != 1 {
		t.Fatalf("%d steps", len(op.Steps))
	}
	st := op.Steps[0]
	if st.DeltaX10() != 95 || len(st.NoLight) == 0 || st.To.Seq != cl.Cleared.Seq {
		t.Errorf("step %+v", st)
	}

	optical := rep.Bullet("optical")
	wantContains(t, "optical", optical.String(),
		"The gateway's own low-Rx optical ALARM was set from the first reading until it cleared at 2026-10-05 08:35 CDT (13:35 UTC).",
		"Its own low-Rx ALARM threshold is -29.5 dBm and its WARNING threshold is -29.2 dBm. Both low-Rx flags were set in every reading from 2026-10-04 22:10 CDT (2026-10-05 03:10 UTC) to 2026-10-05 08:29 CDT (13:29 UTC); the gateway cleared them in snapshot #",
		", recorded as gateway_event optical_alarm #",
		"and did not set them again in the 24 readings since.",
		"Across a loss of light (no receive level in snapshots #",
		"the level rose by 9.5 dB: from -30.9 dBm in snapshot #",
		"to -21.4 dBm in snapshot #",
		"A step change like this across a loss of light usually means the fiber connection changed at that moment (for example a connector reseated or cleaned, or work on the line); these records cannot show who made the change.")
	wantNotContains(t, "optical", optical.String(), "is active", "Every reading was below both thresholds", "the ALARM flag was set in")

	action := rep.Action.String()
	wantContains(t, "action", action,
		"Please check the fiber line and send a technician unless the cause has been repaired.",
		"The gateway's low-Rx alarm, set since the first reading, cleared at 2026-10-05 08:35 CDT (13:35 UTC), when the fiber link came back from a loss of light with the receive level 9.5 dB higher.",
		"The fiber link went down in the outage INC-20261005-133000Z attributed to AT&T.",
		"Please confirm whether any work was done on this line or at the fiber terminal between 2026-10-05 08:29 CDT (13:29 UTC) and 2026-10-05 08:35 CDT (13:35 UTC).",
		"Unless that work repaired the cause, please dispatch a technician",
		"Gateway: NOKIA BGW320-505")
	wantNotContains(t, "action", action, "until the gateway's low-Rx alarm clears", "The gateway reports a received optical level below")

	// The key facts name the clearing and the step; the readings table keeps both readings of the
	// step and says so.
	var facts []string
	for _, f := range rep.Evidence.Facts {
		facts = append(facts, f.What+" = "+f.Ref)
	}
	wantContains(t, "facts", strings.Join(facts, "\n"), "The gateway's low-Rx ALARM flag cleared at 2026-10-05 13:35:",
		"Receive level step of +9.5 dB across a loss of light at 2026-10-05 13:35:")
	var steps int
	for _, row := range op.Rows {
		if strings.Contains(row.Why, "step change") {
			steps++
		}
	}
	if steps != 2 {
		t.Errorf("%d rows of the readings table are marked as a step change's readings", steps)
	}
	wantContains(t, "rows note", op.RowsNote, "both readings of every step change of 3.0 dB or more (1)")
}

// TestAlarmStillSet: a cleared and re-raised alarm is active, not cleared; an old latest reading
// is not stated in the present tense.
func TestAlarmStillSet(t *testing.T) {
	s := realScenario(t)
	rep := mustBuild(t, s, s.options())
	if rep.Optical.Clear != nil || rep.Optical.AlarmRuns != 1 {
		t.Errorf("clear %+v, runs %d", rep.Optical.Clear, rep.Optical.AlarmRuns)
	}
	wantContains(t, "lead", rep.Bullet("optical").Lead, "The gateway's own low-Rx optical ALARM is active.")
	wantContains(t, "action", rep.Action.Lead, "Please dispatch a technician to check the fiber connection.")

	// The same records in a window ending two hours after the latest reading.
	o := s.options()
	o.To = o.To.Add(2 * 60 * 60 * 1e9)
	o.From = o.To.Add(-24 * 60 * 60 * 1e9)
	rep = mustBuild(t, s, o)
	wantContains(t, "old lead", rep.Bullet("optical").Lead, "The gateway's own low-Rx optical ALARM was set at the latest reading, 2026-10-05 08:59 CDT (13:59 UTC).")
}

// TestStepPairs: steps are found between consecutive readings with a level, across no-light
// readings, and only from 3.0 dB.
func TestStepPairs(t *testing.T) {
	rs := []Reading{{RxX10: -310}, {RxX10: -281}, {RxX10: -250}, {NoLight: true}, {NoLight: true}, {RxX10: -280}, {RxX10: -279}}
	got := stepPairs(rs)
	if len(got) != 2 || got[0] != [2]int{1, 2} || got[1] != [2]int{2, 5} {
		t.Errorf("steps %v", got)
	}
}
