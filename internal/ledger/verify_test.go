package ledger

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"attmonitor/internal/contracts"
	"attmonitor/internal/model"
)

func TestGapExplanations(t *testing.T) {
	dir := t.TempDir()
	clk := newClock(t0)
	opts := testOptions(dir, clk)
	s := openStore(t, opts)
	sample := func() { clk.Advance(10 * time.Second); mustAppend(t, s, model.TypeSample, samplePayload(0)) }
	reopen := func() {
		s.Close()
		s = openStore(t, opts)
		mustAppend(t, s, model.TypeMonitorStart, model.MonitorStart{Mode: "service"})
	}

	sample()
	sample()
	// 1. Clean stop, restart 5 minutes later.
	mustAppend(t, s, model.TypeMonitorStop, model.MonitorStop{Reason: "service stop", UptimeSec: 20})
	clk.Advance(5 * time.Minute)
	reopen()
	sample()
	sample()
	// 2. Suspend/resume within one process (the monotonic clock counts the suspension).
	mustAppend(t, s, model.TypePowerEvent, model.PowerEvent{Kind: "suspend"})
	clk.Advance(2 * time.Minute)
	mustAppend(t, s, model.TypePowerEvent, model.PowerEvent{Kind: "resume_automatic"})
	sample()
	// 3. Crash: no monitor_stop before the next start.
	clk.Advance(3 * time.Minute)
	reopen()
	sample()
	// 4. Nothing recorded at all.
	clk.Advance(time.Minute)
	sample()
	// 5. 25 s spacing is below 3 × 10 s: not a gap.
	clk.Advance(15 * time.Second)
	sample()
	// 6. A wall-clock step within one run is not a gap (monotonic spacing is 10 s).
	clk.Step(clk.Now().Add(time.Hour))
	mustAppend(t, s, model.TypeClockJump, model.ClockJump{WallDeltaMs: 3600000})
	sample()
	// 7. System shutdown without a monitor_stop.
	mustAppend(t, s, model.TypePowerEvent, model.PowerEvent{Kind: "shutdown"})
	clk.Advance(10 * time.Minute)
	reopen()
	sample()
	// 8. Recovery without monitor_start (torn write found on restart).
	mustAppend(t, s, model.TypeRecovery, model.Recovery{Segment: "x", Reason: "test"})
	clk.Advance(40 * time.Second)
	sample()

	rep, err := s.Verify(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	requireOK(t, rep)
	want := []struct {
		expl string
		secs int64
	}{
		{"monitor stopped (service stop)", 310},
		{"system suspended", 130},
		{"monitor crashed or killed (no clean stop)", 190},
		{"unexplained", 70},
		{"system shutdown", 610},
		{"monitor crashed or killed (no clean stop)", 50},
	}
	if len(rep.Gaps) != len(want) {
		t.Fatalf("gaps %+v", rep.Gaps)
	}
	for i, w := range want {
		g := rep.Gaps[i]
		if g.Explanation != w.expl || g.Seconds != w.secs || g.From == "" || g.To <= g.From {
			t.Errorf("gap %d = %+v, want %q %ds", i, g, w.expl, w.secs)
		}
	}
	if rep.ClockJumps != 1 {
		t.Fatalf("clock jumps %d", rep.ClockJumps)
	}

	// The FastInterval option scales the threshold.
	opts.ReadOnly = true
	opts.FastInterval = time.Hour
	ro := openStore(t, opts)
	rep, _ = ro.Verify(context.Background())
	if len(rep.Gaps) != 0 {
		t.Fatalf("gaps with a 1h interval: %+v", rep.Gaps)
	}
}

// subsetReader exposes some segments of a store, like an evidence bundle does.
type subsetReader struct {
	s        *Store
	keep     map[string]bool
	dropLine map[string]int // segment → 1-based line to drop
}

func (r *subsetReader) Scan(from uint64, fn func(model.Envelope, model.Body) error) error {
	return r.s.Scan(from, fn)
}
func (r *subsetReader) ScanTime(from, to time.Time, fn func(model.Envelope, model.Body) error) error {
	return r.s.ScanTime(from, to, fn)
}
func (r *subsetReader) Record(seq uint64) (model.Envelope, model.Body, error) { return r.s.Record(seq) }
func (r *subsetReader) GetBlob(id string) ([]byte, error)                     { return r.s.GetBlob(id) }
func (r *subsetReader) Segments() ([]contracts.SegmentInfo, error) {
	all, err := r.s.Segments()
	var out []contracts.SegmentInfo
	for _, si := range all {
		if r.keep[si.Name] {
			out = append(out, si)
		}
	}
	return out, err
}
func (r *subsetReader) OpenSegment(name string) (io.ReadCloser, error) {
	if !r.keep[name] {
		return nil, contracts.ErrNotFound
	}
	rc, err := r.s.OpenSegment(name)
	if err != nil || r.dropLine[name] == 0 {
		return rc, err
	}
	b, _ := io.ReadAll(rc)
	rc.Close()
	lines := bytes.SplitAfter(b, []byte("\n"))
	n := r.dropLine[name] - 1
	return io.NopCloser(bytes.NewReader(bytes.Join(append(lines[:n:n], lines[n+1:]...), nil))), nil
}

var _ contracts.LedgerReader = (*subsetReader)(nil)

func TestBundleModeOmittedSegments(t *testing.T) {
	dir := t.TempDir()
	clk := newClock(t0)
	s := openStore(t, testOptions(dir, clk))
	var names []string
	for d := 0; d < 4; d++ {
		if d > 0 {
			clk.Advance(24 * time.Hour)
		}
		appendSamples(t, s, clk, 4, 10*time.Second)
		names = append(names, segName(clk.Now()))
	}
	s.Close()
	opts := testOptions(dir, clk)
	opts.ReadOnly = true
	ro := openStore(t, opts)
	ctx := context.Background()

	bundle := &subsetReader{s: ro, keep: map[string]bool{names[0]: true, names[2]: true, names[3]: true}}
	rep, err := VerifyReader(ctx, bundle, VerifyOptions{AllowOmittedSegments: true, CheckBlobs: true, ExpectFingerprint: ro.Fingerprint()})
	if err != nil {
		t.Fatal(err)
	}
	requireOK(t, rep)
	if fmt.Sprint(rep.Segments) != fmt.Sprint([]string{names[0], names[2], names[3]}) {
		t.Fatalf("segments %v", rep.Segments)
	}
	notes := strings.Join(rep.Notes, "\n")
	if !strings.Contains(notes, "segments omitted between "+names[0]+" and "+names[2]) {
		t.Fatalf("notes %v", rep.Notes)
	}
	// Days 3→4 are contiguous (a real day without samples); the omission of day 2 is not a gap.
	if len(rep.Gaps) != 1 || !strings.HasPrefix(rep.Gaps[0].From, strings.TrimPrefix(names[2], "ledger-")) {
		t.Fatalf("gaps %+v", rep.Gaps)
	}
	if rep.Records != 15 { // genesis+4, (open+4)×2
		t.Fatalf("records %d", rep.Records)
	}

	// Without bundle mode the omission is a failure.
	rep, _ = VerifyReader(ctx, bundle, VerifyOptions{})
	p := problems(rep)
	if rep.OK || p[probSeqGap] == 0 || p[probPrev] == 0 || p[probSegmentHash] == 0 {
		t.Fatalf("expected failures:\n%s", dumpReport(rep))
	}

	// A record missing inside an included segment is never acceptable.
	bundle.dropLine = map[string]int{names[2]: 3}
	rep, _ = VerifyReader(ctx, bundle, VerifyOptions{AllowOmittedSegments: true})
	if rep.OK || problems(rep)[probSeqGap] == 0 {
		t.Fatalf("expected seq_gap:\n%s", dumpReport(rep))
	}

	// The genesis segment is required (it carries the public key).
	bundle = &subsetReader{s: ro, keep: map[string]bool{names[2]: true, names[3]: true}}
	rep, _ = VerifyReader(ctx, bundle, VerifyOptions{AllowOmittedSegments: true})
	if rep.OK || problems(rep)[probSignature] == 0 {
		t.Fatalf("expected bad_signature without genesis:\n%s", dumpReport(rep))
	}
}

// fakeTSA accepts tokens of the form "TOKEN:<hex digest>".
type fakeTSA struct{ gen time.Time }

func (f fakeTSA) VerifyToken(token, digest []byte) (contracts.TokenInfo, error) {
	if !bytes.Equal(token, []byte("TOKEN:"+hex.EncodeToString(digest))) {
		return contracts.TokenInfo{}, errors.New("message imprint does not match")
	}
	return contracts.TokenInfo{GenTime: f.gen, Serial: "01", Policy: "1.2.3.4", TSAName: "CN=Fake TSA", ChainOK: true}, nil
}

func TestAnchorVerification(t *testing.T) {
	dir := t.TempDir()
	clk := newClock(t0)
	// The TSA stamps the head shortly after it was written: a genTime that contradicts the records'
	// ts would itself be a verification failure (ts_contradiction).
	gen := t0.Add(time.Minute)
	opts := testOptions(dir, clk)
	opts.TokenVerifier = fakeTSA{gen: gen}
	s := openStore(t, opts)
	anchor := func(head model.Ref, token string, genTime time.Time) model.Ref {
		t.Helper()
		id, err := s.PutBlob([]byte(token))
		if err != nil {
			t.Fatal(err)
		}
		return mustAppend(t, s, model.TypeAnchor, model.Anchor{
			TSAURL: "http://tsa.example/", HeadSeq: head.Seq, HeadHash: head.Hash, TokenSHA256: id,
			GenTime: genTime.Format(time.RFC3339), Verified: true, ChainOK: true, Reason: "periodic",
		}, id)
	}
	refs := appendSamples(t, s, clk, 5, 10*time.Second)
	head := s.Head()
	a1 := anchor(head, "TOKEN:"+head.Hash, gen)
	a2 := anchor(head, "TOKEN:"+head.Hash, gen) // second TSA, same head
	appendSamples(t, s, clk, 3, 10*time.Second)
	bad := model.Ref{Seq: refs[1].Seq, Hash: refs[2].Hash} // head_hash of the wrong record
	a3 := anchor(bad, "TOKEN:"+bad.Hash, gen)
	h2 := s.Head()
	a4 := anchor(h2, "TOKEN:"+strings.Repeat("0", 64), gen) // token for another digest
	a5 := anchor(h2, "TOKEN:"+h2.Hash, gen.Add(time.Hour))  // recorded gen_time ≠ token
	tail := appendSamples(t, s, clk, 4, 10*time.Second)

	for _, ring := range []int{0, 2} { // 2 forces the deferred Record() lookup
		t.Run(fmt.Sprintf("ring=%d", ring), func(t *testing.T) {
			rep, err := VerifyReader(context.Background(), s, VerifyOptions{TokenVerifier: fakeTSA{gen: gen}, CheckBlobs: true, ringSize: ring})
			if err != nil {
				t.Fatal(err)
			}
			if len(rep.Anchors) != 5 {
				t.Fatalf("anchors %+v", rep.Anchors)
			}
			wantOK := map[uint64]bool{a1.Seq: true, a2.Seq: true, a3.Seq: false, a4.Seq: false, a5.Seq: false}
			for _, a := range rep.Anchors {
				if a.OK != wantOK[a.Seq] {
					t.Errorf("anchor %d OK=%v (%s)", a.Seq, a.OK, a.Detail)
				}
				if a.OK && (a.TSA != "CN=Fake TSA" || !a.ChainOK || a.GenTime != gen.Format(time.RFC3339Nano) || a.HeadSeq != head.Seq) {
					t.Errorf("anchor check %+v", a)
				}
			}
			var anchorFails []uint64
			for _, f := range rep.Failures {
				if f.Problem != probAnchor {
					t.Errorf("unexpected failure %+v", f)
				}
				anchorFails = append(anchorFails, f.Seq)
			}
			if fmt.Sprint(anchorFails) != fmt.Sprint([]uint64{a3.Seq, a4.Seq, a5.Seq}) {
				t.Fatalf("anchor failures at %v:\n%s", anchorFails, dumpReport(rep))
			}
			last := tail[len(tail)-1].Seq
			if rep.LastAnchoredSeq != head.Seq || rep.UnanchoredTail != last-head.Seq {
				t.Fatalf("last anchored %d, unanchored %d", rep.LastAnchoredSeq, rep.UnanchoredTail)
			}
		})
	}

	// Store.Verify uses Options.TokenVerifier.
	rep, err := s.Verify(context.Background())
	if err != nil || problems(rep)[probAnchor] != 3 {
		t.Fatalf("Store.Verify anchors:\n%s", dumpReport(rep))
	}

	// Without a verifier only linkage and token presence are checked, and a note says so.
	rep, _ = VerifyReader(context.Background(), s, VerifyOptions{CheckBlobs: true})
	if problems(rep)[probAnchor] != 1 || !strings.Contains(strings.Join(rep.Notes, "\n"), "not cryptographically checked") {
		t.Fatalf("without verifier:\n%s", dumpReport(rep))
	}

	// A missing token blob is reported as such.
	tok := mustBlobOf(t, s, a1.Seq)
	os.Remove(s.blobPath(tok))
	rep, _ = VerifyReader(context.Background(), s, VerifyOptions{TokenVerifier: fakeTSA{gen: gen}, CheckBlobs: true})
	p := problems(rep)
	if p[probBlobMissing] != 1 || p[probAnchor] != 5 { // a1 and a2 share the token content
		t.Fatalf("missing token:\n%s", dumpReport(rep))
	}
}

func mustBlobOf(t *testing.T, s *Store, seq uint64) string {
	t.Helper()
	_, b, err := s.Record(seq)
	if err != nil || len(b.Blobs) != 1 {
		t.Fatalf("record %d: %+v %v", seq, b, err)
	}
	return b.Blobs[0]
}

func TestFailuresAreCapped(t *testing.T) {
	dir := t.TempDir()
	clk := newClock(t0)
	s := openStore(t, testOptions(dir, clk))
	appendSamples(t, s, clk, 250, time.Second)
	s.Close()
	path := segPath(dir, segName(t0))
	lines := readLines(t, path)
	zero := strings.Repeat("0", 64)
	for i, l := range lines {
		env, _ := parseLine(t, l)
		lines[i] = bytes.Replace(l, []byte(env.H), []byte(zero), 1)
	}
	writeLines(t, path, lines)
	rep := verifyRO(t, dir, clk)
	if len(rep.Failures) != maxReportedFailures || rep.FailuresTotal != 251 || rep.OK {
		t.Fatalf("failures %d total %d", len(rep.Failures), rep.FailuresTotal)
	}
	for _, f := range rep.Failures {
		if f.Problem != probHash {
			t.Fatalf("unexpected %+v", f)
		}
	}
	if rep.Failures[0].Seq != 0 || rep.Failures[199].Seq != 199 {
		t.Fatal("the first failures in ledger order must be kept")
	}
}

func TestExpectFingerprint(t *testing.T) {
	s, _, clk := newLedger(t)
	appendSamples(t, s, clk, 2, time.Second)
	ctx := context.Background()
	for _, fp := range []string{s.Fingerprint(), FormatFingerprint(s.Fingerprint()), strings.ToUpper(s.Fingerprint())} {
		rep, err := VerifyReader(ctx, s, VerifyOptions{ExpectFingerprint: fp})
		if err != nil {
			t.Fatal(err)
		}
		requireOK(t, rep)
	}
	rep, _ := VerifyReader(ctx, s, VerifyOptions{ExpectFingerprint: strings.Repeat("ab", 32)})
	if rep.OK || problems(rep)[probSignature] != 1 || rep.Failures[0].Seq != 0 {
		t.Fatalf("wrong fingerprint accepted:\n%s", dumpReport(rep))
	}
}

func TestVerifyCancelled(t *testing.T) {
	s, _, clk := newLedger(t)
	appendSamples(t, s, clk, 300, time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := VerifyReader(ctx, s, VerifyOptions{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
}

// emptyReader has no segments.
type emptyReader struct{}

func (emptyReader) Scan(uint64, func(model.Envelope, model.Body) error) error { return nil }
func (emptyReader) ScanTime(time.Time, time.Time, func(model.Envelope, model.Body) error) error {
	return nil
}
func (emptyReader) Record(uint64) (model.Envelope, model.Body, error) {
	return model.Envelope{}, model.Body{}, contracts.ErrNotFound
}
func (emptyReader) Segments() ([]contracts.SegmentInfo, error) { return nil, nil }
func (emptyReader) OpenSegment(string) (io.ReadCloser, error)  { return nil, contracts.ErrNotFound }
func (emptyReader) GetBlob(string) ([]byte, error)             { return nil, contracts.ErrNotFound }

type failingReader struct{ emptyReader }

func (failingReader) Segments() ([]contracts.SegmentInfo, error) {
	return nil, errors.New("disk on fire")
}

func TestVerifyReaderEdgeCases(t *testing.T) {
	// Nothing to verify is not "verified": OK must be false (review fix).
	rep, err := VerifyReader(context.Background(), emptyReader{}, VerifyOptions{})
	if err != nil || rep.OK || rep.Records != 0 || rep.FailuresTotal != 1 || problems(rep)[probParse] != 1 {
		t.Fatalf("empty: %+v %v", rep, err)
	}
	if _, err := VerifyReader(context.Background(), failingReader{}, VerifyOptions{}); err == nil || !strings.Contains(err.Error(), "disk on fire") {
		t.Fatalf("listing error: %v", err)
	}
}
