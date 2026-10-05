package ledger

// Integration round: an evidence bundle holds the genesis segment plus one contiguous run of
// segments (docs/DESIGN.md §13). With AllowOmittedSegments an omitted run is allowed only between
// the genesis segment and the first other included segment; any other seq/segment discontinuity
// is a removed segment and must fail.

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"attmonitor/internal/contracts"
	"attmonitor/internal/model"
)

// bundleView is a subsetReader whose Record, like a real bundle's, finds only records of the
// included segments.
type bundleView struct{ subsetReader }

func (r *bundleView) Record(seq uint64) (model.Envelope, model.Body, error) {
	segs, err := r.Segments()
	if err != nil {
		return model.Envelope{}, model.Body{}, err
	}
	for _, si := range segs {
		if seq >= si.FirstSeq && seq <= si.LastSeq {
			return r.s.Record(seq)
		}
	}
	return model.Envelope{}, model.Body{}, fmt.Errorf("record %d: %w", seq, contracts.ErrNotFound)
}

var _ contracts.LedgerReader = (*bundleView)(nil)

func newBundleView(ro *Store, names []string, keep ...int) *bundleView {
	m := map[string]bool{}
	for _, i := range keep {
		m[names[i]] = true
	}
	return &bundleView{subsetReader{s: ro, keep: m}}
}

// sixDayLedger is a closed ledger of six daily segments (2026-10-05 … 2026-10-10), each holding
// three samples (plus its segment_open), opened read-only.
func sixDayLedger(t *testing.T) (*Store, []string) {
	t.Helper()
	dir := t.TempDir()
	clk := newClock(t0)
	s := openStore(t, testOptions(dir, clk))
	var names []string
	for d := 0; d < 6; d++ {
		if d > 0 {
			clk.Advance(24 * time.Hour)
		}
		appendSamples(t, s, clk, 3, 10*time.Second)
		names = append(names, segName(clk.Now()))
	}
	s.Close()
	opts := testOptions(dir, clk)
	opts.ReadOnly = true
	return openStore(t, opts), names
}

func TestBundleOmissionAllowedOnlyAfterGenesis(t *testing.T) {
	ro, names := sixDayLedger(t)
	cases := []struct {
		keep    []int
		ok      bool
		omitted bool // the "segments omitted" note is expected
	}{
		{[]int{0, 1, 2, 3, 4, 5}, true, false},
		{[]int{0, 2, 3, 4, 5}, true, true},
		{[]int{0, 3, 4}, true, true},
		{[]int{0, 5}, true, true},
		{[]int{0, 1, 2}, true, false}, // later segments are simply not part of the bundle
		{[]int{0}, true, false},
		{[]int{0, 1, 3, 4}, false, false},    // segment 2 removed from the run
		{[]int{0, 1, 2, 3, 5}, false, false}, // the last segment of the run removed
		{[]int{0, 2, 4, 5}, false, true},     // first omission allowed, the second is a removed segment
		{[]int{0, 3, 5}, false, true},
	}
	for _, tc := range cases {
		t.Run(fmt.Sprint(tc.keep), func(t *testing.T) {
			rep, err := VerifyReader(context.Background(), newBundleView(ro, names, tc.keep...),
				VerifyOptions{AllowOmittedSegments: true, CheckBlobs: true, ExpectFingerprint: ro.Fingerprint()})
			if err != nil {
				t.Fatal(err)
			}
			notes := strings.Join(rep.Notes, "\n")
			if got := strings.Contains(notes, "segments omitted between "+names[0]+" and "); got != tc.omitted {
				t.Errorf("omitted note = %v, want %v: %q", got, tc.omitted, rep.Notes)
			}
			if tc.ok {
				requireOK(t, rep)
				return
			}
			p := problems(rep)
			if rep.OK || p[probSeqGap] != 1 || p[probSegmentHash] == 0 {
				t.Fatalf("a segment removed from the middle of the run was accepted:\n%s", dumpReport(rep))
			}
			for _, f := range rep.Failures {
				if f.Problem == probSeqGap && !strings.Contains(f.Detail, "missing") {
					t.Errorf("seq_gap detail does not explain the removed segment: %q", f.Detail)
				}
			}
			if strings.Count(notes, "segments omitted") > 1 {
				t.Errorf("a second omission was accepted as a note: %q", rep.Notes)
			}
		})
	}
}

// The segment_open that ends an omitted run must name a predecessor dated strictly between the
// genesis segment and itself.
func TestBundleOmissionNeedsAPlausiblePredecessor(t *testing.T) {
	genesisSeg, runSeg := "ledger-2026-10-05", "ledger-2026-10-08"
	c := &chainChecker{opts: VerifyOptions{AllowOmittedSegments: true}, firstLedgerSeg: 0,
		names: []string{genesisSeg, runSeg}, expectSeq: 4, haveExpect: true}
	for _, n := range c.names {
		_, d, _ := parseSegmentName(n)
		c.dates = append(c.dates, d)
	}
	r := &lineResult{seg: 1, body: model.Body{Seq: 9, Type: model.TypeSegmentOpen}}
	for prev, want := range map[string]bool{
		"ledger-2026-10-06": true,  // days between the genesis segment and the run: omitted
		"ledger-2026-10-07": true,  //
		genesisSeg:          false, // contiguous: the seq jump is a run of removed records
		runSeg:              false, // the segment's own date
		"ledger-2026-10-04": false, // before the genesis segment
		"ledger-2026-10-09": false, // after the segment
		"not a segment":     false,
		"":                  false,
	} {
		r.segOpen = &model.SegmentOpen{Segment: runSeg, PrevSegment: prev}
		if got := c.omissionAllowed(r, true, genesisSeg); got != want {
			t.Errorf("PrevSegment %q: omission allowed = %v, want %v", prev, got, want)
		}
	}
	// Only the first line of the first segment after the genesis segment, only forward, only a
	// segment_open, only in bundle mode.
	r.segOpen = &model.SegmentOpen{Segment: runSeg, PrevSegment: "ledger-2026-10-06"}
	if c.omissionAllowed(r, false, genesisSeg) {
		t.Error("allowed for a line that is not the first of its segment")
	}
	if r.seg = 2; c.omissionAllowed(r, true, genesisSeg) {
		t.Error("allowed after the first segment of the run")
	}
	r.seg = 1
	if r.body.Seq = 3; c.omissionAllowed(r, true, genesisSeg) {
		t.Error("allowed for a backward seq")
	}
	r.body.Seq = 9
	if r.body.Type = model.TypeSample; c.omissionAllowed(r, true, genesisSeg) {
		t.Error("allowed for a record that is not segment_open")
	}
	r.body.Type = model.TypeSegmentOpen
	if c.omissionAllowed(r, true, "ledger-2026-10-04") {
		t.Error("allowed although the preceding included segment is not the genesis segment")
	}
	c.opts.AllowOmittedSegments = false
	if c.omissionAllowed(r, true, genesisSeg) {
		t.Error("allowed outside bundle mode")
	}
}

// An anchor whose covered record lies in the omitted run cannot be checked (a note); one whose
// covered record lies in a segment removed from the run is a failure.
func TestBundleAnchorCoveringOmittedOrRemovedRecord(t *testing.T) {
	dir := t.TempDir()
	clk := newClock(t0)
	var gen time.Time // when the TSA stamped the covered record: at the anchor, on day 3
	opts := testOptions(dir, clk)
	s := openStore(t, opts)
	var names []string
	var anchor, covered model.Ref
	for d := 0; d < 5; d++ {
		if d > 0 {
			clk.Advance(24 * time.Hour)
		}
		if d == 3 {
			appendSamples(t, s, clk, 1, 10*time.Second) // rotates into day 3
			gen = clk.Now()
			anchor = appendAnchor(t, s, covered, "TOKEN:"+covered.Hash, gen, true, true)
		}
		appendSamples(t, s, clk, 3, 10*time.Second)
		names = append(names, segName(clk.Now()))
		if d == 2 {
			covered = s.Head() // the last record of day 2
		}
	}
	s.Close()
	opts.ReadOnly = true
	ro := openStore(t, opts)
	verify := func(keep ...int) model.VerifyReport {
		t.Helper()
		rep, err := VerifyReader(context.Background(), newBundleView(ro, names, keep...),
			VerifyOptions{AllowOmittedSegments: true, CheckBlobs: true, TokenVerifier: trustTSA{gen: gen}})
		if err != nil {
			t.Fatal(err)
		}
		return rep
	}

	rep := verify(0, 1, 2, 3, 4)
	requireOK(t, rep)
	if rep.LastAnchoredSeq != covered.Seq {
		t.Fatalf("complete bundle: last anchored %d, want %d", rep.LastAnchoredSeq, covered.Seq)
	}

	rep = verify(0, 3, 4) // days 1 and 2 omitted: the covered record is not included
	requireOK(t, rep)
	a := anchorBySeq(t, rep, anchor.Seq)
	if a.OK || !strings.Contains(a.Detail, "not included") || rep.LastAnchoredSeq != 0 || rep.UnanchoredTail != rep.Records {
		t.Fatalf("anchor %+v, last anchored %d, unanchored %d of %d", a, rep.LastAnchoredSeq, rep.UnanchoredTail, rep.Records)
	}
	if notes := strings.Join(rep.Notes, "\n"); !strings.Contains(notes, fmt.Sprintf("covers record %d, which is not included", covered.Seq)) {
		t.Fatalf("notes %q", rep.Notes)
	}

	rep = verify(0, 1, 3, 4) // day 2 removed from the run: the anchor cannot be checked either
	p := problems(rep)
	if rep.OK || p[probSeqGap] != 1 || p[probAnchor] != 1 {
		t.Fatalf("removed segment with a covered record:\n%s", dumpReport(rep))
	}
	if a := anchorBySeq(t, rep, anchor.Seq); a.OK || rep.LastAnchoredSeq != 0 {
		t.Fatalf("anchor %+v, last anchored %d", a, rep.LastAnchoredSeq)
	}
}
