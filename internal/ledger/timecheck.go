package ledger

import (
	"fmt"
	"sort"
	"time"

	"attmonitor/internal/model"
)

// Record times against the times the chain itself proves.
//
// A record's ts is the writer's wall clock, which the custodian controls. The chain holds
// independent times: every anchor record holds an RFC 3161 token whose genTime comes from a
// Time-Stamp Authority. Two facts follow, and VerifyReader checks every record against both:
//
//   - Lower bound. The anchor record contains the SHA-256 of its token, which did not exist
//     before its genTime, and every later record chains to the anchor record. So every record from
//     an anchor record on (the anchor record included) was written after that genTime.
//   - Upper bound. The token time-stamps the hash of record head_seq, which commits to every
//     record up to it. So every record up to head_seq existed by that genTime.
//
// Only anchors that are accepted as proof of time are used (their token verifies for the head
// hash and chains to a trusted root — without a token verifier, the record's issue-time flags —
// and their head check passed in the main pass). A record dated more than tsTolerance before the
// lower bound or after the upper bound carries a false time, and that is a verification failure
// (probTime). A clock that is off makes the records written close to each time-stamp provably
// mis-dated, so contradictions found around consecutive anchoring events are reported together:
// one failure per contiguous period, naming the worst record and the time-stamp it contradicts.
//
// Without such anchors nothing proves which ts is false, but the chain still proves the order in
// which records were written: a run of records dated more than tsTolerance before an earlier
// record (the clock was set back, or records were back-dated) is described in a note, with the
// clock_jump record or the writer's integrity_alert that documents it, if any. So are clock_check
// records whose SNTP servers found the clock far off, and records dated after the verification.
// Monitoring gaps whose end points carry such ts are marked as unreliable.

const (
	// probTime: a record's ts contradicts a trusted time-stamp in the chain.
	probTime = "ts_contradiction"

	// tsTolerance is how far a record's ts may lie on the wrong side of a trusted time-stamp (and
	// how far record ts may go backwards) before verification reports it. It absorbs the error of
	// the writer's clock (Windows Time keeps a PC within seconds; one that synchronises weekly
	// drifts by up to about a minute) and of the TSAs' clocks — a failure cannot be undone in an
	// append-only ledger, so it must not depend on a third party's clock being exact to the
	// minute. Every back- or forward-dating that could move an outage to another time of day is
	// far larger. Agreement within it is reported with the largest discrepancy found.
	tsTolerance = 5 * time.Minute

	// maxPendingTS bounds the records kept, exactly, until a trusted anchor covers them (about ten
	// days of records without one). Older ones are folded into a summary that keeps the latest ts.
	maxPendingTS = 1 << 17
	// maxBackNotes bounds the notes listing backward steps of the record ts (all are counted).
	maxBackNotes = 5
	// maxFlaggedRanges bounds the runs of inconsistent ts remembered to mark monitoring gaps.
	maxFlaggedRanges = 1 << 16

	// clockBehindPrefix begins the detail of the integrity_alert the writer appends when the wall
	// clock is behind the newest record on open; the verifier recognises it as documentation.
	clockBehindPrefix = "the computer's clock is behind the newest ledger record"
)

// tsRec locates one record and its ts.
type tsRec struct {
	seq  uint64
	ts   time.Time
	seg  int32
	line int32
}

// tsBound is a trusted time-stamp: the anchor record that holds it, the record it covers, the TSA
// and its genTime.
type tsBound struct {
	anchor uint64
	head   uint64
	tsa    string
	gen    time.Time
}

// tsRun collects the records whose ts contradict trusted time-stamps over a contiguous period. It
// ends when a whole anchoring window (the records a time-stamp bounds first) passes without one.
type tsRun struct {
	n           int   // contradicting records
	first, last tsRec // first and last contradicting record
	worst       tsRec
	by          time.Duration // how far the worst record's ts lies beyond its bound
	bound       tsBound       // the time-stamp the worst record contradicts

	hit, seen bool     // the current window had a contradicting / any record
	sub       seqRange // consecutive contradicting records (marks gaps)
	subOn     bool
}

// tsFold summarises pending records folded out of the exact list.
type tsFold struct {
	n           int
	first, last tsRec
	max         tsRec
}

// backRun is a run of consecutive records dated more than tsTolerance before an earlier record.
type backRun struct {
	n             int
	first, last   tsRec
	ref           tsRec // the earlier record with the latest ts
	worst         tsRec
	by            time.Duration
	jump          uint64 // a clock_jump record in the run
	haveJump      bool
	writerAlert   bool // the run begins with the writer's integrity_alert about the clock
	beforeGenesis bool
}

type seqRange struct{ from, to uint64 }

// gapEnd identifies the samples around a listed monitoring gap.
type gapEnd struct {
	from, to uint64
	byTS     bool // length measured with ts (across a restart), not the monotonic clock
	unknown  bool // ts go back across it: its length is unknown (already explained)
}

// timeChecker performs the checks above, in chain order, for the full verifier.
type timeChecker struct {
	now   func() time.Time // the verifier's clock
	note  func(string)
	names []string // segment names by index

	used       int // trusted anchors applied as bounds
	windowHead uint64
	haveWindow bool

	floor     tsBound // the latest genTime of the trusted anchor records seen
	haveFloor bool
	low       tsRun
	lowMax    time.Duration // largest (floor - ts) seen, for the agreement note
	haveLow   bool

	pend     []tsRec // records no trusted anchor has covered yet, in chain order
	pendHead int
	fold     tsFold
	high     tsRun
	highMax  time.Duration // largest (ts - genTime) of a covered record
	haveHigh bool

	max         tsRec // the record with the latest ts so far
	haveMax     bool
	genesis     time.Time
	haveGenesis bool
	back        backRun
	backRuns    int

	lowFails, highFails []model.VerifyFailure // each in ledger order, capped
	failTotal           int

	flagged     []seqRange
	flaggedFull bool

	sntpN     int
	sntpWorst int64 // ms, server - local
	sntpRec   tsRec
}

func newTimeChecker(names []string, now func() time.Time, note func(string)) *timeChecker {
	return &timeChecker{names: names, now: now, note: note}
}

// anchor applies a trusted anchor whose checks passed. It is called for the anchor record before
// record() checks that record's own ts.
func (t *timeChecker) anchor(b tsBound) {
	t.used++
	t.cover(b)
	// Each anchoring event (the TSAs stamp the same head one after the other) starts a new window
	// of records that its genTimes bound from below.
	if !t.haveWindow || b.head != t.windowHead {
		t.endWindow(&t.low, true)
		t.windowHead, t.haveWindow = b.head, true
	}
	if !t.haveFloor || b.gen.After(t.floor.gen) {
		t.floor, t.haveFloor = b, true
	}
}

// cover checks the records up to b.head that no trusted anchor had covered against b.gen.
func (t *timeChecker) cover(b tsBound) {
	limit := b.gen.Add(tsTolerance)
	if t.fold.n > 0 {
		if b.head < t.fold.last.seq {
			return // covers only part of the folded records: a later anchor covers them all
		}
		t.endRun(&t.high, false)
		f := t.fold
		t.fold = tsFold{}
		if by := f.max.ts.Sub(b.gen); !t.haveHigh || by > t.highMax {
			t.highMax, t.haveHigh = by, true
		}
		if f.max.ts.After(limit) {
			t.flag(f.max.seq, f.max.seq)
			t.addFail(&t.highFails, f.max, fmt.Sprintf(
				"of the %d records seq %d–%d (more than %d records awaited a trusted time-stamp, so they were not examined one by one), "+
					"seq %d is dated %s, %s after the genTime %s of the trusted time-stamp held by anchor record %d (%s), which covers the chain up to seq %d: "+
					"it existed by that time, so its ts is false — forward-dated, or the clock was ahead (tolerance %s)",
				f.n, f.first.seq, f.last.seq, maxPendingTS, f.max.seq, fmtTS(f.max.ts), fmtDur(f.max.ts.Sub(b.gen)), fmtTS(b.gen),
				b.anchor, oneLine(clip(b.tsa)), b.head, tsTolerance))
		}
	}
	for t.pendHead < len(t.pend) && t.pend[t.pendHead].seq <= b.head {
		rec := t.pend[t.pendHead]
		t.pendHead++
		by := rec.ts.Sub(b.gen)
		if !t.haveHigh || by > t.highMax {
			t.highMax, t.haveHigh = by, true
		}
		if rec.ts.After(limit) {
			t.offend(&t.high, rec, by, b)
		} else {
			t.pass(&t.high)
		}
	}
	t.compact()
	t.endWindow(&t.high, false)
}

// offend adds a contradicting record to run.
func (t *timeChecker) offend(run *tsRun, rec tsRec, by time.Duration, b tsBound) {
	if run.n == 0 {
		run.first = rec
	}
	run.n++
	run.last = rec
	if run.n == 1 || by > run.by {
		run.worst, run.by, run.bound = rec, by, b
	}
	run.hit, run.seen = true, true
	if run.subOn {
		run.sub.to = rec.seq
	} else {
		run.sub, run.subOn = seqRange{rec.seq, rec.seq}, true
	}
}

// pass notes a record that agrees with its bound.
func (t *timeChecker) pass(run *tsRun) {
	run.seen = true
	if run.subOn {
		t.flag(run.sub.from, run.sub.to)
		run.subOn = false
	}
}

// endWindow closes an anchoring window: the run ends if the window held records and none of them
// contradicted its time-stamp.
func (t *timeChecker) endWindow(run *tsRun, low bool) {
	if run.n > 0 && run.seen && !run.hit {
		t.endRun(run, low)
	}
	run.hit, run.seen = false, false
}

// endRun reports the run, if any, as one failure located at its first contradicting record.
func (t *timeChecker) endRun(run *tsRun, low bool) {
	if run.subOn {
		t.flag(run.sub.from, run.sub.to)
	}
	r := *run
	*run = tsRun{}
	if r.n == 0 {
		return
	}
	who, them, these := fmt.Sprintf("seq %d is", r.first.seq), "it", "its ts is"
	if r.n > 1 {
		who, them, these = fmt.Sprintf("%d records from seq %d to seq %d are", r.n, r.first.seq, r.last.seq), "them", "these ts are"
	}
	b := r.bound
	if low {
		t.addFail(&t.lowFails, r.first, fmt.Sprintf(
			"%s dated up to %s earlier than trusted time-stamps that precede %s in the chain: seq %d is dated %s, %s before the genTime %s "+
				"of the time-stamp held by anchor record %d (%s). Records from an anchor record on were written after its genTime, so %s false — "+
				"back-dated, or the clock was behind (tolerance %s)",
			who, fmtDur(r.by), them, r.worst.seq, fmtTS(r.worst.ts), fmtDur(r.by), fmtTS(b.gen), b.anchor, oneLine(clip(b.tsa)), these, tsTolerance))
		return
	}
	t.addFail(&t.highFails, r.first, fmt.Sprintf(
		"%s dated up to %s later than trusted time-stamps that cover %s: seq %d is dated %s, %s after the genTime %s "+
			"of the time-stamp held by anchor record %d (%s), which covers the chain up to seq %d. Covered records existed by that genTime, so %s false — "+
			"forward-dated, or the clock was ahead (tolerance %s)",
		who, fmtDur(r.by), them, r.worst.seq, fmtTS(r.worst.ts), fmtDur(r.by), fmtTS(b.gen), b.anchor, oneLine(clip(b.tsa)), b.head, these, tsTolerance))
}

// compact drops the evaluated head of the pending list.
func (t *timeChecker) compact() {
	switch {
	case t.pendHead == len(t.pend):
		t.pend, t.pendHead = t.pend[:0], 0
	case t.pendHead >= 4096 && 2*t.pendHead >= len(t.pend):
		n := copy(t.pend, t.pend[t.pendHead:])
		t.pend, t.pendHead = t.pend[:n], 0
	}
}

// push adds a record to the pending list, folding the older half when it is full.
func (t *timeChecker) push(rec tsRec) {
	if n := len(t.pend) - t.pendHead; n >= maxPendingTS {
		half := n / 2
		for _, e := range t.pend[t.pendHead : t.pendHead+half] {
			if t.fold.n == 0 {
				t.fold.first, t.fold.max = e, e
			}
			t.fold.n++
			t.fold.last = e
			if e.ts.After(t.fold.max.ts) {
				t.fold.max = e
			}
		}
		t.pendHead += half
		t.compact()
	}
	t.pend = append(t.pend, rec)
}

// record checks one record, in chain order.
func (t *timeChecker) record(r *lineResult) {
	if !r.tsOK {
		t.endBack()
		return
	}
	b := &r.body
	rec := tsRec{seq: b.Seq, ts: r.ts, seg: int32(r.seg), line: int32(r.lineNo)}
	if b.Type == model.TypeGenesis && !t.haveGenesis {
		t.genesis, t.haveGenesis = r.ts, true
	}

	// Lower bound: written after the latest trusted genTime that precedes it.
	if t.haveFloor {
		by := t.floor.gen.Sub(r.ts)
		if !t.haveLow || by > t.lowMax {
			t.lowMax, t.haveLow = by, true
		}
		if by > tsTolerance {
			t.offend(&t.low, rec, by, t.floor)
		} else {
			t.pass(&t.low)
		}
	}

	// Order: dated well before a record that precedes it.
	if t.haveMax && r.ts.Before(t.max.ts.Add(-tsTolerance)) {
		run := &t.back
		if run.n == 0 {
			*run = backRun{first: rec, ref: t.max, writerAlert: r.clockAlert}
		}
		run.n++
		run.last = rec
		if by := run.ref.ts.Sub(r.ts); run.n == 1 || by > run.by {
			run.by, run.worst = by, rec
		}
		if b.Type == model.TypeClockJump && !run.haveJump {
			run.jump, run.haveJump = b.Seq, true
		}
		if t.haveGenesis && r.ts.Before(t.genesis.Add(-tsTolerance)) {
			run.beforeGenesis = true
		}
	} else {
		t.endBack()
	}
	if !t.haveMax || r.ts.After(t.max.ts) {
		t.max, t.haveMax = rec, true
	}

	if b.Type == model.TypeClockCheck && r.sntpOK && absMs(r.sntpOffMs) > uint64(tsTolerance.Milliseconds()) {
		t.sntpN++
		if t.sntpN == 1 || absMs(r.sntpOffMs) > absMs(t.sntpWorst) {
			t.sntpWorst, t.sntpRec = r.sntpOffMs, rec
		}
	}
	t.push(rec)
}

func (t *timeChecker) endBack() {
	run := t.back
	if run.n == 0 {
		return
	}
	t.back = backRun{}
	t.backRuns++
	t.flag(run.first.seq, run.last.seq)
	if t.backRuns > maxBackNotes {
		return
	}
	var how string
	switch {
	case run.haveJump:
		how = fmt.Sprintf("the clock_jump record seq %d documents a step of the wall clock", run.jump)
	case run.writerAlert:
		how = fmt.Sprintf("the writer's integrity_alert seq %d records that the clock was behind the newest record when the ledger was opened", run.first.seq)
	default:
		how = "no clock_jump record documents a step of the wall clock here"
	}
	genesis := ""
	if run.beforeGenesis {
		genesis = ", some of them before the genesis record"
	}
	who, them := fmt.Sprintf("seq %d is", run.first.seq), "it"
	if run.n > 1 {
		who, them = fmt.Sprintf("seq %d–%d (%d records) are", run.first.seq, run.last.seq, run.n), "them"
	}
	t.note(fmt.Sprintf("record ts go backwards: %s dated up to %s before seq %d (ts %s), which precedes %s in the chain%s; %s (tolerance %s)",
		who, fmtDur(run.by), run.ref.seq, fmtTS(run.ref.ts), them, genesis, how, tsTolerance))
}

// addFail records a failure located at the first record of its run. Each list is filled in
// ledger order and keeps the first maxReportedFailures; all failures are counted.
func (t *timeChecker) addFail(list *[]model.VerifyFailure, at tsRec, detail string) {
	t.failTotal++
	if len(*list) >= maxReportedFailures {
		return
	}
	seg := ""
	if int(at.seg) >= 0 && int(at.seg) < len(t.names) {
		seg = t.names[at.seg]
	}
	*list = append(*list, model.VerifyFailure{Seq: at.seq, Segment: seg, Line: int(at.line), Problem: probTime,
		Detail: clipTo(detail, maxDetailBytes)})
}

func (t *timeChecker) flag(from, to uint64) {
	if len(t.flagged) >= maxFlaggedRanges {
		t.flaggedFull = true
		return
	}
	t.flagged = append(t.flagged, seqRange{from, to})
}

// finish closes the open runs and adds the summary notes. Records that no trusted anchor covers
// (the unanchored tail) are not judged against an upper bound: nothing bounds them yet.
func (t *timeChecker) finish() {
	t.endRun(&t.low, true)
	t.endRun(&t.high, false)
	t.endBack()
	if n := t.backRuns - maxBackNotes; n > 0 {
		t.note(fmt.Sprintf("%d further backward step(s) of the record ts are not listed", n))
	}
	if t.used > 0 && t.failTotal == 0 {
		t.note(fmt.Sprintf("record ts agree with the %d trusted time-stamp(s) in the chain within the %s tolerance: no record is dated more than %s before a time-stamp "+
			"that precedes it, nor more than %s after one that covers it", t.used, tsTolerance, fmtDur(max(t.lowMax, 0)), fmtDur(max(t.highMax, 0))))
	}
	if t.sntpN > 0 {
		dir := "behind"
		if t.sntpWorst < 0 {
			dir = "ahead of"
		}
		t.note(fmt.Sprintf("%d clock_check record(s) found this computer's clock more than %s off the SNTP time servers (median of the answers; largest: %s %s them at seq %d, %s): records written around them are dated off by about as much",
			t.sntpN, tsTolerance, fmtMs(t.sntpWorst), dir, t.sntpRec.seq, fmtTS(t.sntpRec.ts)))
	}
	// Compared with the end of the verification: a live ledger gains records while it runs.
	if end := t.now().UTC(); t.haveMax && t.max.ts.Sub(end) > tsTolerance {
		t.note(fmt.Sprintf("records are dated after the time of this verification (%s): the newest, seq %d, is dated %s, %s later — their ts are false, or the verifying computer's clock is behind",
			fmtTS(end), t.max.seq, fmtTS(t.max.ts), fmtDur(t.max.ts.Sub(end))))
	}
	if t.flaggedFull {
		t.note(fmt.Sprintf("more than %d runs of inconsistent record ts: monitoring gaps beyond them are not marked as unreliable", maxFlaggedRanges))
	}
}

// annotateGaps marks the gaps whose end points carry an inconsistent ts. ends is parallel to gaps.
func (t *timeChecker) annotateGaps(gaps []model.Gap, ends []gapEnd) {
	if len(t.flagged) == 0 || len(ends) != len(gaps) {
		return
	}
	r := append([]seqRange(nil), t.flagged...)
	sort.Slice(r, func(i, j int) bool { return r[i].from < r[j].from })
	merged := r[:1]
	for _, x := range r[1:] {
		last := &merged[len(merged)-1]
		if x.from <= last.to {
			if x.to > last.to {
				last.to = x.to
			}
			continue
		}
		merged = append(merged, x)
	}
	in := func(seq uint64) bool {
		i := sort.Search(len(merged), func(i int) bool { return merged[i].to >= seq })
		return i < len(merged) && merged[i].from <= seq
	}
	for i := range gaps {
		e := ends[i]
		if e.unknown {
			continue
		}
		var at uint64
		switch {
		case in(e.from):
			at = e.from
		case in(e.to):
			at = e.to
		default:
			continue
		}
		what := "its times are"
		if e.byTS {
			what = "its length and times are"
		}
		gaps[i].Explanation += fmt.Sprintf("; %s unreliable: the ts of sample seq %d contradicts a trusted time-stamp or the order of earlier records (see failures and notes)", what, at)
	}
}

func fmtTS(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

// fmtDur rounds a duration for a message: to the second, or to the millisecond below a second.
func fmtDur(d time.Duration) string {
	if d >= time.Second || d <= -time.Second {
		return d.Round(time.Second).String()
	}
	return d.Round(time.Millisecond).String()
}

// fmtMs formats a millisecond count from a record (any int64) as a duration.
func fmtMs(ms int64) string {
	if absMs(ms) > uint64(time.Duration(1<<62)/time.Millisecond) {
		return fmt.Sprintf("%d ms", ms)
	}
	return fmtDur(time.Duration(ms) * time.Millisecond)
}

func absMs(v int64) uint64 {
	if v < 0 {
		return uint64(-(v + 1)) + 1
	}
	return uint64(v)
}

// medianOffset is the median clock offset of the SNTP answers of a clock_check record; with an
// even number of answers, the middle one closer to zero. A single server that is far off never
// decides.
func medianOffset(results []model.ClockResult) (int64, bool) {
	var offs []int64
	for _, r := range results {
		if r.OK {
			offs = append(offs, r.OffsetMs)
		}
	}
	if len(offs) == 0 {
		return 0, false
	}
	sort.Slice(offs, func(i, j int) bool { return offs[i] < offs[j] })
	m := offs[len(offs)/2]
	if len(offs)%2 == 0 {
		if a := offs[len(offs)/2-1]; absMs(a) < absMs(m) {
			m = a
		}
	}
	return m, true
}
