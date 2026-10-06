package connstore

import (
	"strconv"
	"testing"
	"time"

	"attmonitor/internal/config"
)

// Messages of the clock checks.
const (
	msgAhead   = "the clock is ahead of the time the monotonic clock has measured"
	msgAgrees  = "the clock agrees with the monotonic clock again"
	msgTrusted = "the clock has stayed ahead of the monotonic clock for a day"
	msgMoved   = "the file of a day after today was being written"
	msgLater   = "there are reads of a day after today"
	msgDeleted = "deleted a day beyond the retention limits"
)

// TestAForwardClockStepDeletesNothing sets the system clock 60 days ahead for one round of reads
// (Windows' Secure Time Seeding has set clocks months ahead), then corrects it: no day may be
// deleted for the step, the writer must go back to today's file at once, and the day after today
// that the step wrote must be kept as it is.
func TestAForwardClockStepDeletesNothing(t *testing.T) {
	h := newHarness(t, at(0, 12, 0), Options{}) // keep_days 30
	fillDays(h, 0, 19, 3)
	before := h.agg(day0, at(20, 0, 0)).Samples
	if before != 20 {
		t.Fatalf("%d reads before the step, want 20", before)
	}

	// One round of reads with the clock 60 days ahead: 4 minutes later by the monotonic clock.
	h.clk.Step(at(79, 12, 4), 4*time.Minute)
	h.nat(at(79, 12, 4), tcp(10, 40000, "203.0.113.5", 443))
	if n := h.log.count(msgDeleted); n != 0 {
		t.Fatalf("the step deleted %d days:\n%s", n, h.log.all())
	}
	if h.log.count(msgAhead) != 1 || h.log.attr(msgAhead, "applied_as_of") != rfc(at(19, 12, 4)) {
		t.Errorf("the step was not logged as expected:\n%s", h.log.all())
	}
	// The clock is corrected; the reads go on.
	for i := range 3 {
		h.clk.Step(at(19, 12, 8+4*i), 4*time.Minute)
		h.nat(at(19, 12, 8+4*i), tcp(10, 40000, "203.0.113.5", 443))
	}
	if n := h.log.count(msgDeleted); n != 0 {
		t.Errorf("%d days deleted after the correction:\n%s", n, h.log.all())
	}
	// The writer left the file of day 79 once, with a warning, and stays on today's.
	if h.log.count(msgMoved) != 1 || h.log.count("a read of an earlier day") != 0 || h.log.count(msgAgrees) != 1 {
		t.Errorf("the correction was not logged as expected:\n%s", h.log.all())
	}
	if w := h.s.w[kindNAT]; w == nil || w.day != dayOf(at(19, 0, 0)) {
		t.Errorf("the NAT writer is on %v, want today's file", w)
	}
	if after := h.agg(day0, at(20, 0, 0)).Samples; after != before+3 {
		t.Errorf("%d reads of days 0 to 19 after the correction, want %d", after, before+3)
	}
	// The read of day 79 is kept, the newest; its day stays plain until it is over.
	if u := h.s.Usage(); u.Oldest != rfc(at(0, 12, 0)) || u.Newest != rfc(at(79, 12, 4)) {
		t.Errorf("Usage = %+v", u)
	}
	later := fileName(kindNAT, dayOf(at(79, 0, 0)), false)
	if lines := h.lines(later); len(lines) != 1 {
		t.Errorf("%s holds %d reads, want 1", later, len(lines))
	}
	// The next day compresses today's file as usual (it was compressed by the step's read: the
	// reads since are merged into it); the day after today stays as it is.
	h.clk.Set(at(20, 0, 4))
	h.nat(at(20, 0, 4), tcp(10, 40000, "203.0.113.5", 443))
	day19 := fileName(kindNAT, dayOf(at(19, 0, 0)), false)
	if h.exists(day19) || len(h.lines(day19+gzExt)) != 4 {
		t.Errorf("day 19 was not compressed with its 4 reads:\n%s", h.log.all())
	}
	if !h.exists(later) {
		t.Errorf("%s was compressed or deleted before its day", later)
	}
	// A restart reports the day after today.
	h.reopen()
	if h.log.count(msgLater) != 1 || h.log.attr(msgLater, "day") != dayOf(at(79, 0, 0)).String() {
		t.Errorf("the day after today was not reported:\n%s", h.log.all())
	}
	if a := h.agg(day0, at(21, 0, 0)); a.Samples != before+4 {
		t.Errorf("%d reads after the restart, want %d", a.Samples, before+4)
	}
}

// keptDays returns the days, counted from day0, that have a NAT file.
func keptDays(h *harness) []int {
	h.t.Helper()
	var out []int
	for d := -5; d <= 100; d++ {
		k := dayOf(at(d, 0, 0))
		if _, ok := h.s.entry(kindNAT, k); ok {
			out = append(out, d)
		}
	}
	return out
}

// TestTheAgeLimitTrustsTheClockNoFurtherThanTheMonotonicClock prunes while the system clock is
// 60 days ahead of what the monotonic clock measured: the days that are old by the monotonic
// clock's time go, the others stay; the size limit applies as always; and once the clock is set
// back, the age limit follows it again.
func TestTheAgeLimitTrustsTheClockNoFurtherThanTheMonotonicClock(t *testing.T) {
	h := newHarness(t, at(0, 12, 0), Options{KeepDays: 5})
	fillDays(h, 0, 9, 3) // days 0 to 3 are deleted as the days go by
	if got := keptDays(h); len(got) != 6 || got[0] != 4 {
		t.Fatalf("kept days %v, want 4 to 9", got)
	}
	// The clock is stepped 60 days ahead; 12 hours pass.
	h.clk.Step(at(69, 12, 0), 12*time.Hour)
	if err := h.s.Prune(time.Time{}); err != nil {
		t.Fatal(err)
	}
	// As of the monotonic clock's time (day 10, 00:00), day 4 ended five days ago: it goes, as it
	// would have without the step; the others stay.
	if got := keptDays(h); len(got) != 5 || got[0] != 5 {
		t.Errorf("kept days %v after pruning with the clock ahead, want 5 to 9", got)
	}
	if h.log.count(msgAhead) != 1 || h.log.attr(msgAhead, "ahead") != (60*24*time.Hour-12*time.Hour).String() {
		t.Errorf("not logged as expected:\n%s", h.log.all())
	}
	// The size limit applies as always: the oldest day goes.
	var size int64
	for d := 6; d <= 9; d++ {
		for k := range numKinds {
			f, _ := h.s.entry(k, dayOf(at(d, 0, 0)))
			size += max(f.gz, 0) + max(f.plain, 0)
		}
	}
	h.s.mu.Lock()
	h.s.mib = 1 // KeepMB counts bytes from here on
	h.s.mu.Unlock()
	h.s.SetRetention(5, int(size))
	if err := h.s.Prune(time.Time{}); err != nil {
		t.Fatal(err)
	}
	if got := keptDays(h); len(got) != 4 || got[0] != 6 || h.log.attr(msgDeleted, "limit") != "keep_mb "+strconv.FormatInt(size, 10) {
		t.Errorf("kept days %v after the size limit, want 6 to 9:\n%s", got, h.log.all())
	}
	if h.log.count(msgAhead) != 1 {
		t.Errorf("the step was logged again:\n%s", h.log.all())
	}
	h.s.SetRetention(5, config.MaxConnKeepMB)
	// The clock is set back to the right time (day 9, 12:00 and the 24 hours measured since).
	h.clk.Step(at(10, 12, 0), 12*time.Hour)
	if err := h.s.Prune(time.Time{}); err != nil {
		t.Fatal(err)
	}
	if h.log.count(msgAgrees) != 1 {
		t.Errorf("the correction was not logged:\n%s", h.log.all())
	}
	if got := keptDays(h); len(got) != 4 || got[0] != 6 {
		t.Errorf("kept days %v after the correction, want 6 to 9", got)
	}
	// The age limit follows the clock again: day 6 ended at day 7, 00:00, five days before day
	// 12, 00:00.
	h.clk.Set(at(12, 0, 0))
	if err := h.s.Prune(time.Time{}); err != nil {
		t.Fatal(err)
	}
	if got := keptDays(h); len(got) != 3 || got[0] != 7 {
		t.Errorf("kept days %v at day 12, want 7 to 9", got)
	}
	if h.log.count(msgAhead) != 1 || h.log.count(msgAgrees) != 1 {
		t.Errorf("logged:\n%s", h.log.all())
	}
}

// TestAClockThatStaysAheadIsTrustedAfterADay steps the clock 30 days ahead and leaves it there:
// a day later (by the monotonic clock) the age limit follows it, so that a clock that was behind
// and was corrected does not hold the age limit back until the next restart.
func TestAClockThatStaysAheadIsTrustedAfterADay(t *testing.T) {
	h := newHarness(t, at(0, 12, 0), Options{KeepDays: 10})
	fillDays(h, 0, 4, 3)
	h.clk.Step(at(34, 12, 0), time.Hour)
	if err := h.s.Prune(time.Time{}); err != nil {
		t.Fatal(err)
	}
	if got := keptDays(h); len(got) != 5 {
		t.Fatalf("kept days %v after the step, want 0 to 4", got)
	}
	// Still ahead 23 hours later: still held back.
	h.clk.Step(at(35, 11, 0), 23*time.Hour)
	if err := h.s.Prune(time.Time{}); err != nil {
		t.Fatal(err)
	}
	if got := keptDays(h); len(got) != 5 || h.log.count(msgTrusted) != 0 {
		t.Fatalf("kept days %v 23 hours after the step, want 0 to 4:\n%s", got, h.log.all())
	}
	// A day after the step: the clock is trusted, and the days old by it go.
	h.clk.Step(at(35, 12, 0), time.Hour)
	if err := h.s.Prune(time.Time{}); err != nil {
		t.Fatal(err)
	}
	if got := keptDays(h); len(got) != 0 || h.log.count(msgTrusted) != 1 {
		t.Errorf("kept days %v a day after the step, want none:\n%s", got, h.log.all())
	}
	// The clock trusted again is the reference from here on: no new warning while it agrees.
	h.clk.Set(at(35, 14, 0))
	h.nat(at(35, 14, 0), tcp(10, 40000, "203.0.113.5", 443))
	if err := h.s.Prune(time.Time{}); err != nil {
		t.Fatal(err)
	}
	if h.log.count(msgAhead) != 1 || h.log.count(msgAgrees) != 0 {
		t.Errorf("logged:\n%s", h.log.all())
	}
}

// TestOpenAppliesOnlyTheSizeLimit: the age limit waits until the store has been open for an hour,
// whoever prunes first.
func TestOpenAppliesOnlyTheSizeLimit(t *testing.T) {
	h := newHarness(t, at(0, 12, 0), Options{})
	fillDays(h, 0, 5, 3)
	// A restart with keep_days 2: days 0 to 2 are old (day 2 ended at day 3, 00:00).
	h.o.KeepDays = 2
	h.reopen()
	if got := keptDays(h); len(got) != 6 {
		t.Errorf("kept days %v after Open, want 0 to 5", got)
	}
	if u := h.s.Usage(); u.Oldest != rfc(at(0, 12, 0)) || u.Error != "" {
		t.Errorf("Usage after Open = %+v", u)
	}
	h.clk.Set(at(5, 12, 59))
	if err := h.s.Prune(time.Time{}); err != nil {
		t.Fatal(err)
	}
	if got := keptDays(h); len(got) != 6 {
		t.Errorf("kept days %v 59 minutes after Open, want 0 to 5", got)
	}
	// An hour after that Prune, an append prunes: the age limit applies.
	h.clk.Set(at(5, 13, 59))
	h.nat(at(5, 13, 59), tcp(10, 40000, "203.0.113.5", 443))
	if got := keptDays(h); len(got) != 3 || got[0] != 3 {
		t.Errorf("kept days %v two hours after Open, want 3 to 5", got)
	}
	if h.log.count(msgDeleted) != 3 || h.log.attr(msgDeleted, "limit") != "keep_days 2" {
		t.Errorf("deletions logged:\n%s", h.log.all())
	}
}

// TestOpenSetsATimerForTheAgeLimit: with nothing appending or pruning (connections.enabled off),
// the timer Open sets applies the age limit; Close stops it.
func TestOpenSetsATimerForTheAgeLimit(t *testing.T) {
	h := newHarness(t, at(0, 12, 0), Options{})
	fillDays(h, 0, 5, 3)
	h.o.KeepDays = 2
	h.o.ageDelay = 20 * time.Millisecond
	// Closed before the timer runs: nothing is deleted.
	h.reopen()
	if err := h.s.Close(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	if got := keptDays(h); len(got) != 6 || h.log.count(msgDeleted) != 0 {
		t.Fatalf("kept days %v after the store was closed, want 0 to 5:\n%s", got, h.log.all())
	}
	// Open, and wait: the clock does not move, nothing is appended.
	h.open()
	deadline := time.Now().Add(10 * time.Second)
	for len(keptDays(h)) == 6 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	h.s.wmu.Lock() // the timer's prune holds it until it is done
	h.s.wmu.Unlock()
	if got := keptDays(h); len(got) != 3 || got[0] != 3 {
		t.Errorf("kept days %v once the timer ran, want 3 to 5:\n%s", got, h.log.all())
	}
	if u := h.s.Usage(); u.Oldest != rfc(at(3, 12, 0)) || u.Error != "" {
		t.Errorf("Usage = %+v", u)
	}
	for _, name := range []string{"nat-2026-10-05.jsonl.gz", "devices-2026-10-07.jsonl.gz"} {
		if h.exists(name) {
			t.Errorf("%s was not deleted", name)
		}
	}
}

// TestDevicesAfterAForwardClockStep: a Device List read made while the clock was ahead does not
// stay the newest once the clock is corrected - neither while the store runs nor after a restart.
func TestDevicesAfterAForwardClockStep(t *testing.T) {
	h := newHarness(t, at(0, 12, 0), Options{})
	h.devices(at(0, 12, 0), device(10, 1, "before", ""))
	h.clk.Step(at(60, 12, 0), 15*time.Minute)
	h.devices(at(60, 12, 0), device(10, 1, "during", ""))
	if devices, when := h.s.Devices(); devices[0].Name != "during" || !when.Equal(at(60, 12, 0)) {
		t.Errorf("Devices while the clock is ahead = %+v, %s", devices, when)
	}
	h.clk.Step(at(0, 12, 30), 15*time.Minute)
	h.devices(at(0, 12, 30), device(10, 1, "after", ""))
	if devices, when := h.s.Devices(); devices[0].Name != "after" || !when.Equal(at(0, 12, 30)) {
		t.Errorf("Devices once the clock was corrected = %+v, %s", devices, when)
	}
	// A read made earlier than the one kept, which is not after now, does not replace it.
	h.devices(at(0, 12, 20), device(10, 1, "older", ""))
	if devices, _ := h.s.Devices(); devices[0].Name != "after" {
		t.Errorf("Devices after an older read = %+v", devices)
	}
	h.reopen()
	if devices, when := h.s.Devices(); devices[0].Name != "after" || !when.Equal(at(0, 12, 30)) {
		t.Errorf("Devices after a restart = %+v, %s", devices, when)
	}
	// With the clock behind every day kept, the newest read is the newest day's.
	h.clk.Step(at(-30, 0, 0), time.Minute)
	h.reopen()
	if devices, _ := h.s.Devices(); len(devices) != 1 || devices[0].Name != "during" {
		t.Errorf("Devices with the clock behind every day = %+v", devices)
	}
}

// TestALateReadWithTheClockOnTheNewestDay: a read of an earlier day while the clock is on the
// writer's day (made before midnight, stored after) goes to its day's file without moving the
// writer; the writer only moves off a day after today.
func TestALateReadWithTheClockOnTheNewestDay(t *testing.T) {
	h := newHarness(t, at(1, 0, 5), Options{})
	h.nat(at(1, 0, 1), tcp(10, 1, "203.0.113.5", 443))
	h.nat(at(0, 23, 59), tcp(10, 2, "203.0.113.5", 443))
	if w := h.s.w[kindNAT]; w == nil || w.day != dayOf(at(1, 0, 0)) {
		t.Errorf("the writer is on %v, want day 1", w)
	}
	if h.log.count("a read of an earlier day than the newest was stored") != 1 || h.log.count(msgMoved) != 0 {
		t.Errorf("logged:\n%s", h.log.all())
	}
	if a := h.agg(day0, at(2, 0, 0)); a.Samples != 2 {
		t.Errorf("%d reads, want 2", a.Samples)
	}
}
