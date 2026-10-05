package monitor

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"attmonitor/internal/model"
)

// secretBlob stands for the DPAPI-protected access code: it must never reach the ledger.
const secretBlob = "c2VjcmV0LWRwYXBpLWJsb2I="

// segmentRig is a clockRig whose fake ledger starts a new daily segment (segment_open) before
// the first record of every later UTC date, like the real ledger.
func segmentRig(t *testing.T, start time.Time) (*rig, *fakeClock) {
	t.Helper()
	r, clk := clockRig(t, start)
	r.led.mu.Lock()
	r.led.segments = true
	r.led.mu.Unlock()
	r.cfg.Gateway.AccessCodeProtected = secretBlob
	return r, clk
}

// typesAfter lists the types of the records after seq.
func typesAfter(r *rig, seq uint64) []string {
	var out []string
	for _, b := range r.led.records("") {
		if b.Seq > seq {
			out = append(out, b.Type)
		}
	}
	return out
}

// countType counts the records of a type.
func countType(r *rig, typ string) int { return len(ofType(r.led.records(""), typ)) }

// segmentOpens returns the segment_open records.
func segmentOpens(r *rig) []model.Body { return ofType(r.led.records(""), model.TypeSegmentOpen) }

// checkConfigState checks a config_state record: the configuration (secrets removed) and hash
// that monitor_start records, the rules version, reason "new_segment".
func checkConfigState(t *testing.T, r *rig, b model.Body) {
	t.Helper()
	if b.Type != model.TypeConfigState {
		t.Fatalf("seq %d is a %s, not config_state", b.Seq, b.Type)
	}
	cs := decode[model.ConfigState](t, b)
	if cs.Rules != RulesVersion || cs.Reason != "new_segment" || cs.ConfigSHA256 != r.cfg.RedactedSHA256() || sha256Hex(cs.Config) != cs.ConfigSHA256 {
		t.Fatalf("config_state %+v (sha256(config) %s)", cs, sha256Hex(cs.Config))
	}
	if strings.Contains(string(b.Data), secretBlob) {
		t.Fatal("config_state contains the protected access code")
	}
	starts := ofType(r.led.records(""), model.TypeMonitorStart)
	if len(starts) == 0 {
		return
	}
	ms := decode[model.MonitorStart](t, starts[len(starts)-1])
	if cs.ConfigSHA256 != ms.ConfigSHA256 || !bytes.Equal(cs.Config, ms.Config) {
		t.Fatalf("config_state differs from monitor_start: %s vs %s", cs.ConfigSHA256, ms.ConfigSHA256)
	}
}

// Every new daily segment states the configuration in force: config_state right after the
// record that opened the segment (also without an open incident), exactly once per segment,
// with the configuration and hash monitor_start recorded.
func TestConfigStateOncePerNewSegment(t *testing.T) {
	ctx := context.Background()
	base := time.Date(2026, 10, 5, 23, 59, 20, 0, time.UTC)
	r, clk := segmentRig(t, base)
	if err := r.m.recordStart(clk.Now()); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 4; i++ {
		cycleAt(r, clk, base, i, healthy()) // 23:59:20 .. 23:59:50
	}
	if n := countType(r, model.TypeConfigState); n != 0 || len(segmentOpens(r)) != 0 {
		t.Fatalf("no new segment yet, but %d config_state", n)
	}
	cycleAt(r, clk, base, 4, healthy()) // 00:00:00: the first record of the new day
	so := segmentOpens(r)
	if len(so) != 1 {
		t.Fatalf("segment_open records %d", len(so))
	}
	if got := typesAfter(r, so[0].Seq-1); !slices.Equal(got, []string{model.TypeSegmentOpen, model.TypeSample, model.TypeConfigState}) {
		t.Fatalf("records from the segment_open: %v", got)
	}
	checkConfigState(t, r, r.led.records("")[so[0].Seq+2])

	// The rest of the day adds none.
	for i := 5; i < 12; i++ {
		cycleAt(r, clk, base, i, healthy())
	}
	if _, err := r.m.Note(ctx, "AT&T ticket 123", "owner", "test"); err != nil {
		t.Fatal(err)
	}
	if n := countType(r, model.TypeConfigState); n != 1 {
		t.Fatalf("config_state records %d, want 1 per segment", n)
	}

	// The next day's first record is an operator note: config_state follows it.
	clk.Set(base.Add(25 * time.Hour))
	ref, err := r.m.Note(ctx, "AT&T ticket 124", "owner", "test")
	if err != nil {
		t.Fatal(err)
	}
	recs := r.led.records("")
	if recs[ref.Seq-1].Type != model.TypeSegmentOpen || len(recs) != int(ref.Seq)+2 {
		t.Fatalf("records from the segment_open: %v", typesAfter(r, ref.Seq-2))
	}
	checkConfigState(t, r, recs[ref.Seq+1])
	if n := countType(r, model.TypeConfigState); n != 2 || len(segmentOpens(r)) != 2 {
		t.Fatalf("%d config_state for %d new segments", n, len(segmentOpens(r)))
	}
}

// With an incident open, the record that opens a segment is followed by config_state and then
// the incident_update (one each).
func TestConfigStateBeforeTheSegmentsIncidentUpdate(t *testing.T) {
	base := time.Date(2026, 10, 5, 23, 59, 20, 0, time.UTC)
	r, clk := segmentRig(t, base)
	for i := 0; i < 4; i++ {
		cycleAt(r, clk, base, i, outageCycle()) // opens at 23:59:40
	}
	id := r.m.openIncidentID()
	if id == "" {
		t.Fatal("incident should be open")
	}
	for i := 4; i < 9; i++ {
		cycleAt(r, clk, base, i, outageCycle()) // 00:00:00 starts the new segment
	}
	so := segmentOpens(r)
	if len(so) != 1 {
		t.Fatalf("segment_open records %d", len(so))
	}
	got := typesAfter(r, so[0].Seq)
	if len(got) < 3 || got[0] != model.TypeSample || got[1] != model.TypeConfigState || got[2] != model.TypeIncidentUpdate {
		t.Fatalf("records after the segment_open: %v", got)
	}
	recs := r.led.records("")
	checkConfigState(t, r, recs[so[0].Seq+2])
	if upd := decode[model.Incident](t, recs[so[0].Seq+3]); upd.ID != id || !upd.Open {
		t.Fatalf("update %+v", upd)
	}
	if n := countType(r, model.TypeConfigState); n != 1 {
		t.Fatalf("config_state records %d", n)
	}
}

// monitor_start carries the configuration, so a startup writes no config_state - unless
// monitor_start is the first record of a new daily segment.
func TestConfigStateAtStartup(t *testing.T) {
	// The previous record is from the same day: nothing.
	r, clk := segmentRig(t, time.Date(2026, 10, 6, 8, 0, 0, 0, time.UTC))
	if err := r.m.recordStart(clk.Now()); err != nil {
		t.Fatal(err)
	}
	if got := r.led.types(""); !slices.Equal(got, []string{model.TypeGenesis, model.TypeMonitorStart}) {
		t.Fatalf("records %v", got)
	}

	// The previous record is from yesterday: monitor_start opens the segment.
	r2, clk2 := segmentRig(t, time.Date(2026, 10, 6, 0, 0, 30, 0, time.UTC))
	if err := r2.m.recordStart(clk2.Now()); err != nil {
		t.Fatal(err)
	}
	want := []string{model.TypeGenesis, model.TypeSegmentOpen, model.TypeMonitorStart, model.TypeConfigState}
	if got := r2.led.types(""); !slices.Equal(got, want) {
		t.Fatalf("records %v, want %v", got, want)
	}
	checkConfigState(t, r2, r2.led.records("")[3])
}

// The same through Run: a run that starts on a new day writes config_state right after
// monitor_start and no other; a run that starts in the current segment writes none.
func TestRunConfigStateAtStartup(t *testing.T) {
	for _, tc := range []struct {
		name        string
		start       time.Time
		configState bool
	}{
		{"new segment", time.Date(2026, 10, 6, 0, 0, 30, 0, time.UTC), true},
		{"same segment", time.Date(2026, 10, 6, 9, 0, 0, 0, time.UTC), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clk := &fakeClock{t: tc.start}
			led := newFakeLedgerAt("run-current", tc.start.Add(-time.Minute))
			led.now, led.segments = clk.Now, true
			r := newRig(t, nil, led)
			r.cfg.Gateway.AccessCodeProtected = secretBlob
			r.m.now = clk.Now
			stop := r.start(t)
			waitFor(t, "samples", 10*time.Second, func() bool { return countType(r, model.TypeSample) >= 3 })
			if err := stop(); err != nil {
				t.Fatal(err)
			}
			types := r.led.types("")
			i := slices.Index(types, model.TypeMonitorStart)
			switch {
			case !tc.configState && countType(r, model.TypeConfigState) != 0:
				t.Fatalf("records %v", types)
			case tc.configState && (countType(r, model.TypeConfigState) != 1 || types[i-1] != model.TypeSegmentOpen || types[i+1] != model.TypeConfigState):
				t.Fatalf("records %v", types)
			}
			if tc.configState {
				checkConfigState(t, r, r.led.records("")[i+1])
			}
		})
	}
}

// Only a segment the ledger really started counts: when the wall clock is behind the active
// segment's date (it was stepped back across midnight), a record with a later UTC date than the
// previous record does not open a segment, and nothing is added for it.
func TestNoSegmentRecordsWithoutSegmentOpen(t *testing.T) {
	base := time.Date(2026, 10, 5, 23, 59, 20, 0, time.UTC)
	r, clk := segmentRig(t, base)
	r.led.mu.Lock()
	r.led.segDay = "2026-10-06" // the active segment is already the 6th's
	r.led.mu.Unlock()
	for i := 0; i < 9; i++ {
		cycleAt(r, clk, base, i, outageCycle()) // opens an incident; midnight at cycle 4
	}
	if r.m.openIncidentID() == "" {
		t.Fatal("incident should be open")
	}
	types := r.led.types("")
	if slices.Contains(types, model.TypeSegmentOpen) || slices.Contains(types, model.TypeConfigState) || slices.Contains(types, model.TypeIncidentUpdate) {
		t.Fatalf("records %v", types)
	}
}

// A config_state the ledger refused is written after the next record of the same segment (once).
func TestConfigStateRetriedAfterFailedAppend(t *testing.T) {
	base := time.Date(2026, 10, 5, 23, 59, 50, 0, time.UTC)
	r, clk := segmentRig(t, base)
	cycleAt(r, clk, base, 0, healthy())
	diskFull := errors.New("disk full")
	r.led.setRejectRecord(func(typ string) error {
		if typ == model.TypeConfigState {
			return diskFull
		}
		return nil
	})
	cycleAt(r, clk, base, 1, healthy()) // 00:00:00 opens the segment; its config_state fails
	if n := countType(r, model.TypeConfigState); n != 0 || len(segmentOpens(r)) != 1 {
		t.Fatalf("config_state %d", n)
	}
	r.led.setRejectRecord(nil)
	cycleAt(r, clk, base, 2, healthy())
	cycleAt(r, clk, base, 3, healthy())
	so := segmentOpens(r)[0]
	want := []string{model.TypeSample, model.TypeSample, model.TypeConfigState, model.TypeSample}
	if got := typesAfter(r, so.Seq); !slices.Equal(got, want) {
		t.Fatalf("records after the segment_open: %v, want %v", got, want)
	}
	checkConfigState(t, r, r.led.records("")[so.Seq+3])
}

// The record that would have been the first of the new segment fails after the ledger wrote
// segment_open (a write failure of the record itself): the next record written is the
// segment's first for the monitor, and config_state follows it.
func TestConfigStateAfterTheSegmentsFirstRecordFailed(t *testing.T) {
	base := time.Date(2026, 10, 5, 23, 59, 50, 0, time.UTC)
	r, clk := segmentRig(t, base)
	cycleAt(r, clk, base, 0, healthy())
	r.led.setRejectRecord(func(typ string) error {
		if typ == model.TypeSample {
			return errors.New("write failed")
		}
		return nil
	})
	cycleAt(r, clk, base, 1, healthy()) // 00:00:00: segment_open written, the sample fails
	r.led.setRejectRecord(nil)
	so := segmentOpens(r)
	if len(so) != 1 || countType(r, model.TypeConfigState) != 0 {
		t.Fatalf("records %v", r.led.types(""))
	}
	cycleAt(r, clk, base, 2, healthy())
	cycleAt(r, clk, base, 3, healthy())
	want := []string{model.TypeSample, model.TypeConfigState, model.TypeSample}
	if got := typesAfter(r, so[0].Seq); !slices.Equal(got, want) {
		t.Fatalf("records after the segment_open: %v, want %v", got, want)
	}
	checkConfigState(t, r, r.led.records("")[so[0].Seq+2])
}
