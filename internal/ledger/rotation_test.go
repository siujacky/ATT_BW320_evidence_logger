package ledger

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"attmonitor/internal/model"
)

func TestRotationAcrossUTCMidnight(t *testing.T) {
	dir := t.TempDir()
	start := time.Date(2026, 10, 5, 23, 59, 30, 0, time.UTC)
	clk := newClock(start)
	s := openStore(t, testOptions(dir, clk))
	refs := appendSamples(t, s, clk, 6, 10*time.Second) // 23:59:40 … 00:00:30
	day1, day2 := segName(start), segName(start.Add(time.Hour))

	day1Bytes, err := os.ReadFile(segPath(dir, day1))
	if err != nil {
		t.Fatal(err)
	}
	day1Lines := readLines(t, segPath(dir, day1))
	day2Lines := readLines(t, segPath(dir, day2))
	// genesis + samples at :40 and :50 on day 1; midnight sample rotates.
	if len(day1Lines) != 3 || len(day2Lines) != 5 {
		t.Fatalf("day1 %d lines, day2 %d lines", len(day1Lines), len(day2Lines))
	}
	_, so := parseLine(t, day2Lines[0])
	if so.Type != model.TypeSegmentOpen || so.Seq != 3 || so.TS != refs[2].TS {
		t.Fatalf("first record of day 2: %+v", so)
	}
	env2, _ := parseLine(t, day1Lines[2])
	if so.Prev != sha256Hex([]byte(env2.B)) {
		t.Fatal("segment_open does not chain to the last record of the previous segment")
	}
	d := decodeData[model.SegmentOpen](t, so)
	sum := sha256.Sum256(day1Bytes)
	if d.Segment != day2 || d.PrevSegment != day1 || d.PrevSegmentSHA256 != hex.EncodeToString(sum[:]) ||
		d.PrevSegmentRecords != 3 || d.PrevSegmentLastSeq != 2 {
		t.Fatalf("segment_open data %+v", d)
	}
	// The record that triggered rotation follows segment_open with the same ts.
	_, first := parseLine(t, day2Lines[1])
	if first.Seq != 4 || first.Type != model.TypeSample || first.TS != so.TS || refs[2].Seq != 4 {
		t.Fatalf("triggering record %+v (ref %+v)", first, refs[2])
	}
	// The sealed segment is never touched again.
	after, _ := os.ReadFile(segPath(dir, day1))
	if string(after) != string(day1Bytes) {
		t.Fatal("sealed segment changed")
	}
	rep, err := s.Verify(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	requireOK(t, rep)
	if len(rep.Segments) != 2 || rep.TypeCounts[model.TypeSegmentOpen] != 1 {
		t.Fatalf("report %+v", rep)
	}

	// Reopen: Open validates the active segment including its link to the sealed one.
	s.Close()
	s2 := openStore(t, testOptions(dir, clk))
	if typesOf(scanAll(t, s2))[len(scanAll(t, s2))-1] != model.TypeSample {
		t.Fatal("reopen appended unexpected records (no recovery or alert expected)")
	}
}

func TestClockStepsBackAndForth(t *testing.T) {
	dir := t.TempDir()
	start := time.Date(2026, 10, 5, 23, 59, 50, 0, time.UTC)
	clk := newClock(start)
	s := openStore(t, testOptions(dir, clk))
	appendSamples(t, s, clk, 2, 10*time.Second) // 00:00:00 rotates to day 2
	day1, day2, day3 := segName(start), segName(start.Add(time.Hour)), segName(start.Add(25*time.Hour))
	if s.active.name != day2 {
		t.Fatalf("active %s", s.active.name)
	}
	day1Before, _ := os.ReadFile(segPath(dir, day1))

	// The wall clock steps back into day 1: keep writing to day 2, never reopen day 1.
	clk.Step(start.Add(-2 * time.Hour))
	back := mustAppend(t, s, model.TypeClockJump, model.ClockJump{WallDeltaMs: -7200000, MonoDeltaMs: 0, JumpMs: -7200000})
	appendSamples(t, s, clk, 3, 10*time.Second)
	if s.active.name != day2 {
		t.Fatalf("active %s after clock step back", s.active.name)
	}
	day1After, _ := os.ReadFile(segPath(dir, day1))
	if string(day1Before) != string(day1After) {
		t.Fatal("day 1 segment was modified after the clock stepped back")
	}
	_, b, err := s.Record(back.Seq)
	if err != nil || b.TS != back.TS {
		t.Fatalf("record %+v %v", b, err)
	}
	if ts, _ := time.Parse(time.RFC3339Nano, b.TS); !utcDate(ts).Equal(utcDate(start)) {
		t.Fatalf("ts %s should be on day 1 (it is stored in day 2)", b.TS)
	}
	// ScanTime still finds a record stored in a later-dated segment after a small step back.
	found := false
	from := start.Add(-3 * time.Hour)
	if err := s.ScanTime(from, from.Add(2*time.Hour), func(_ model.Envelope, b model.Body) error {
		found = found || b.Seq == back.Seq
		return nil
	}); err != nil || !found {
		t.Fatalf("ScanTime missed the back-dated record: %v", err)
	}

	// The clock steps forward again into day 3: rotate.
	clk.Step(start.Add(25 * time.Hour))
	appendSamples(t, s, clk, 1, time.Second)
	if s.active.name != day3 {
		t.Fatalf("active %s", s.active.name)
	}
	if _, err := os.Stat(segPath(dir, day3)); err != nil {
		t.Fatal(err)
	}
	rep, err := s.Verify(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	requireOK(t, rep)
	if rep.ClockJumps != 1 || len(rep.Segments) != 3 {
		t.Fatalf("report %+v", rep)
	}
	files, _ := filepath.Glob(filepath.Join(dir, "ledger", "*.jsonl"))
	if len(files) != 3 {
		t.Fatalf("segment files %v", files)
	}
}

func TestRotationMovesForeignFileToQuarantine(t *testing.T) {
	dir := t.TempDir()
	clk := newClock(t0)
	s := openStore(t, testOptions(dir, clk))
	appendSamples(t, s, clk, 1, time.Second)
	next := segName(t0.Add(24 * time.Hour))
	if err := os.WriteFile(segPath(dir, next), []byte("not a ledger\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	clk.Advance(24 * time.Hour)
	ref := mustAppend(t, s, model.TypeSample, samplePayload(9))
	bodies := scanAll(t, s)
	got := typesOf(bodies[len(bodies)-3:])
	if got[0] != model.TypeSegmentOpen || got[1] != model.TypeIntegrityAlert || got[2] != model.TypeSample || bodies[len(bodies)-1].Seq != ref.Seq {
		t.Fatalf("types %v", got)
	}
	q, err := os.ReadFile(filepath.Join(dir, "quarantine", next+".jsonl.foreign"))
	if err != nil || string(q) != "not a ledger\n" {
		t.Fatalf("quarantined foreign file: %q %v", q, err)
	}
	rep, _ := s.Verify(context.Background())
	requireOK(t, rep)
}

// If a rotation renamed its new segment into place but could not open it afterwards, the
// next rotation finds that file. It must be described as left by this writer's failed
// rotation, not as a file that "existed before this ledger created it".
func TestRotationAfterUnopenableNewSegmentIsDescribedHonestly(t *testing.T) {
	dir := t.TempDir()
	clk := newClock(t0)
	s := openStore(t, testOptions(dir, clk))
	appendSamples(t, s, clk, 1, time.Second)
	next := segPath(dir, segName(t0.Add(24*time.Hour)))
	openAfterCreate = func(path string) (*os.File, error) { return nil, errors.New("simulated sharing violation") }
	t.Cleanup(func() { openAfterCreate = openExclusiveRW })
	clk.Advance(24 * time.Hour)
	if _, err := s.Append(model.TypeSample, samplePayload(1)); err == nil {
		t.Fatal("expected the rotation to fail")
	}
	openAfterCreate = openExclusiveRW
	if _, err := os.Stat(next); err != nil {
		t.Fatalf("the renamed segment should exist: %v", err)
	}
	mustAppend(t, s, model.TypeSample, samplePayload(2))
	bodies := scanAll(t, s)
	alert := decodeData[model.IntegrityAlert](t, bodies[len(bodies)-2])
	d := strings.Join(alert.Details, "\n")
	if strings.Contains(d, "existed before this ledger created it") || !strings.Contains(d, "could not be opened") {
		t.Fatalf("alert %+v", alert)
	}
	rep, _ := s.Verify(context.Background())
	requireOK(t, rep)
}
