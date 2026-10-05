package ledger

// Record times against the independent times the chain itself contains. An anchor record holds a
// TSA token that did not exist before its genTime, so every record from that anchor record on was
// written after it; the token covers the chain up to its head, so every record up to the head
// existed by then. A record whose ts contradicts either bound by more than the tolerance carries a
// false time (back-dated, forward-dated, or a clock that was far off), and verification must not
// pass it — nor list made-up monitoring gaps computed from it.

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"attmonitor/internal/contracts"
	"attmonitor/internal/model"
)

// tsProblem is the failure class of a ts that contradicts a trusted time-stamp (a literal, so that
// these tests also compile against a verifier that does not know it).
const tsProblem = "ts_contradiction"

// timeTSA verifies tokens "TS|<genTime>|<hex digest>" (TSA certificate chains to a trusted root)
// and "UTS|<genTime>|<hex digest>" (genuine for the digest, but not chained), reporting the
// genTime the token names: a TSA whose clock is right, whatever the PC's clock says.
type timeTSA struct{}

func (timeTSA) VerifyToken(token, digest []byte) (contracts.TokenInfo, error) {
	parts := strings.Split(string(token), "|")
	if len(parts) != 3 || parts[2] != hex.EncodeToString(digest) {
		return contracts.TokenInfo{}, errors.New("message imprint does not match")
	}
	gen, err := time.Parse(time.RFC3339Nano, parts[1])
	if err != nil {
		return contracts.TokenInfo{}, err
	}
	info := contracts.TokenInfo{GenTime: gen, Serial: "01", Policy: "1.2.3.4", TSAName: "CN=Clock TSA"}
	switch parts[0] {
	case "TS":
		info.ChainOK = true
	case "UTS":
		info.ChainNote = untrustedChainNote
	default:
		return contracts.TokenInfo{}, errors.New("unknown token")
	}
	return info, nil
}

// stampAt appends an anchor record over head with a token the TSA issued at gen (the record's
// issue-time flags say verified and chained).
func stampAt(t *testing.T, s *Store, head model.Ref, gen time.Time, trusted bool) model.Ref {
	t.Helper()
	kind := "TS"
	if !trusted {
		kind = "UTS"
	}
	return appendAnchor(t, s, head, kind+"|"+gen.UTC().Format(time.RFC3339Nano)+"|"+head.Hash, gen.UTC(), true, true)
}

func timeFailures(rep model.VerifyReport) []model.VerifyFailure {
	var out []model.VerifyFailure
	for _, f := range rep.Failures {
		if f.Problem == tsProblem {
			out = append(out, f)
		}
	}
	return out
}

func notesWith(rep model.VerifyReport, sub string) []string {
	var out []string
	for _, n := range rep.Notes {
		if strings.Contains(n, sub) {
			out = append(out, n)
		}
	}
	return out
}

func verifyWith(t *testing.T, r contracts.LedgerReader, opts VerifyOptions) model.VerifyReport {
	t.Helper()
	rep, err := VerifyReader(context.Background(), r, opts)
	if err != nil {
		t.Fatalf("VerifyReader: %v", err)
	}
	return rep
}

// The finding's scenario: the custodian stops the monitor, sets the clock back two days, runs it
// (anchors from a TSA with a correct clock cover the run), restores the clock and restarts.
// Every verifier used to PASS, list a made-up 50-hour "monitor stopped" gap and hide the restart.
func TestBackdatedRunContradictsTrustedTimeStamps(t *testing.T) {
	dir := t.TempDir()
	clk := newClock(t0)
	opts := testOptions(dir, clk)
	opts.TokenVerifier = timeTSA{}
	s := openStore(t, opts)

	appendSamples(t, s, clk, 3, 10*time.Second)
	a1 := stampAt(t, s, s.Head(), clk.Now(), true)
	appendSamples(t, s, clk, 3, 10*time.Second)
	stop1 := mustAppend(t, s, model.TypeMonitorStop, model.MonitorStop{Reason: "service stop"})
	s.Close()

	// Back-dated run: the clock reads two days earlier; the TSA's genTime is the real time.
	const back = 50 * time.Hour
	clk.Advance(5 * time.Second)
	clk.Step(clk.Now().Add(-back))
	s = openStore(t, opts)
	firstBack := stop1.Seq + 1
	mustAppend(t, s, model.TypeMonitorStart, model.MonitorStart{Mode: "service"})
	backSamples := appendSamples(t, s, clk, 3, 10*time.Second)
	a2 := stampAt(t, s, s.Head(), clk.Now().Add(back), true)
	appendSamples(t, s, clk, 2, 10*time.Second)
	stop2 := mustAppend(t, s, model.TypeMonitorStop, model.MonitorStop{Reason: "service stop"})
	s.Close()

	// The clock is restored and the monitor restarted 5 s later.
	clk.Advance(5 * time.Second)
	clk.Step(clk.Now().Add(back))
	s = openStore(t, opts)
	mustAppend(t, s, model.TypeMonitorStart, model.MonitorStart{Mode: "service"})
	appendSamples(t, s, clk, 3, 10*time.Second)
	stampAt(t, s, s.Head(), clk.Now(), true)
	appendSamples(t, s, clk, 2, 10*time.Second)

	// The writer documents a clock that is behind the newest record when it opens the ledger.
	_, alert, err := s.Record(firstBack)
	if err != nil {
		t.Fatal(err)
	}
	if alert.Type != model.TypeIntegrityAlert || !strings.Contains(string(alert.Data), "clock is behind the newest") {
		t.Fatalf("record %d after the clock was set back is %s %s, want the writer's integrity_alert", firstBack, alert.Type, alert.Data)
	}

	check := func(t *testing.T, rep model.VerifyReport, tsa string) {
		t.Helper()
		if rep.OK {
			t.Fatalf("back-dated records verified OK:\n%s", dumpReport(rep))
		}
		tf := timeFailures(rep)
		if len(tf) != 1 || rep.FailuresTotal != 1 {
			t.Fatalf("want exactly one %s failure for the back-dated run:\n%s", tsProblem, dumpReport(rep))
		}
		f := tf[0]
		if f.Seq != firstBack || f.Line != int(firstBack)+1 || f.Segment != segName(t0) {
			t.Errorf("failure located at seq %d %s line %d, want the first back-dated record %d", f.Seq, f.Segment, f.Line, firstBack)
		}
		for _, want := range []string{
			fmt.Sprintf("%d records from seq %d to seq %d are", stop2.Seq-firstBack+1, firstBack, stop2.Seq),
			fmt.Sprintf("anchor record %d (%s", a2.Seq, tsa), "50h0m0s",
		} {
			if !strings.Contains(f.Detail, want) {
				t.Errorf("detail %q lacks %q", f.Detail, want)
			}
		}
		// The order check names the step and its documentation.
		if n := notesWith(rep, "record ts go backwards"); len(n) != 1 ||
			!strings.Contains(n[0], fmt.Sprintf("seq %d", firstBack)) || !strings.Contains(n[0], "integrity_alert") {
			t.Errorf("backward-step notes %q", n)
		}
		// Gaps: the restart into the back-dated run cannot be measured (ts go back) and is listed;
		// the gap measured from a back-dated sample is marked as unreliable, not presented as fact.
		if len(rep.Gaps) != 2 {
			t.Fatalf("gaps %+v", rep.Gaps)
		}
		g := rep.Gaps[0]
		if g.To != backSamples[0].TS || g.Seconds != 0 || !strings.Contains(g.Explanation, "length unknown") ||
			!strings.HasPrefix(g.Explanation, "monitor stopped (service stop)") {
			t.Errorf("gap into the back-dated run %+v", g)
		}
		g = rep.Gaps[1]
		if !strings.HasPrefix(g.Explanation, "monitor stopped (service stop)") || !strings.Contains(g.Explanation, "unreliable") {
			t.Errorf("gap out of the back-dated run %+v", g)
		}
		if rep.LastAnchoredSeq <= a1.Seq {
			t.Errorf("last anchored %d", rep.LastAnchoredSeq)
		}
	}
	t.Run("Store.Verify", func(t *testing.T) {
		rep, err := s.Verify(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		check(t, rep, "CN=Clock TSA")
	})
	t.Run("VerifyReader", func(t *testing.T) {
		check(t, verifyWith(t, s, VerifyOptions{TokenVerifier: timeTSA{}, CheckBlobs: true}), "CN=Clock TSA")
	})
	t.Run("without verifier", func(t *testing.T) {
		// The records' issue-time flags make the anchors proof of time; their recorded gen_time is used.
		check(t, verifyWith(t, s, VerifyOptions{CheckBlobs: true}), "http://tsa.example/")
	})
}

// A clock running ahead: the anchor covering genesis..head proves those records existed hours
// before the times they claim.
func TestForwardDatedRecordsContradictCoveringTimeStamp(t *testing.T) {
	dir := t.TempDir()
	const ahead = 3 * time.Hour
	clk := newClock(t0.Add(ahead))
	opts := testOptions(dir, clk)
	opts.TokenVerifier = timeTSA{}
	s := openStore(t, opts)
	mustAppend(t, s, model.TypeMonitorStart, model.MonitorStart{Mode: "service"})
	appendSamples(t, s, clk, 3, 10*time.Second)
	head := s.Head()
	a := stampAt(t, s, head, clk.Now().Add(-ahead), true)
	// Windows Time corrects the clock within the run; the monitor records the step.
	appendSamples(t, s, clk, 1, 10*time.Second)
	clk.Step(clk.Now().Add(-ahead))
	jump := mustAppend(t, s, model.TypeClockJump, model.ClockJump{WallDeltaMs: -ahead.Milliseconds(), JumpMs: -ahead.Milliseconds()})
	appendSamples(t, s, clk, 3, 10*time.Second)
	stampAt(t, s, s.Head(), clk.Now(), true)
	appendSamples(t, s, clk, 1, 10*time.Second)

	rep, err := s.Verify(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	tf := timeFailures(rep)
	if rep.OK || len(tf) != 1 {
		t.Fatalf("want one %s failure:\n%s", tsProblem, dumpReport(rep))
	}
	// One failure for the whole forward-dated period: genesis..head (covered by the first anchor)
	// and, covered by the second, the first anchor record and the sample written before the
	// correction.
	f := tf[0]
	if f.Seq != 0 || f.Line != 1 {
		t.Errorf("failure at seq %d line %d, want the genesis record", f.Seq, f.Line)
	}
	for _, want := range []string{
		fmt.Sprintf("%d records from seq 0 to seq %d are", jump.Seq, jump.Seq-1),
		fmt.Sprintf("anchor record %d", a.Seq), "later than", "3h0m0s",
	} {
		if !strings.Contains(f.Detail, want) {
			t.Errorf("detail %q lacks %q", f.Detail, want)
		}
	}
	if n := notesWith(rep, "record ts go backwards"); len(n) != 1 || !strings.Contains(n[0], fmt.Sprintf("clock_jump record seq %d", jump.Seq)) {
		t.Errorf("backward-step notes %q", n)
	}
}

// An anchor record dated before the genTime of the token it holds cannot be: it was written after
// the token existed.
func TestAnchorRecordDatedBeforeItsOwnTimeStamp(t *testing.T) {
	s, _, clk := newLedger(t)
	appendSamples(t, s, clk, 3, 10*time.Second)
	a := stampAt(t, s, s.Head(), clk.Now().Add(time.Hour), true) // the PC's clock is an hour behind
	rep := verifyWith(t, s, VerifyOptions{TokenVerifier: timeTSA{}, CheckBlobs: true})
	tf := timeFailures(rep)
	if rep.OK || len(tf) != 1 || tf[0].Seq != a.Seq || !strings.Contains(tf[0].Detail, "seq "+fmt.Sprint(a.Seq)+" is dated") {
		t.Fatalf("want one %s failure at the anchor record %d:\n%s", tsProblem, a.Seq, dumpReport(rep))
	}
	// Records before it are not covered by anything that bounds them from below.
	if !strings.Contains(tf[0].Detail, "earlier than") {
		t.Errorf("detail %q", tf[0].Detail)
	}
}

// Ordinary clock error is tolerated; only a trusted time-stamp counts.
func TestTimeStampToleranceAndTrust(t *testing.T) {
	for _, tc := range []struct {
		name    string
		off     time.Duration // PC clock minus real time
		trusted bool
		fails   bool
		agree   string // the agreement note states the largest discrepancy found
	}{
		{"accurate", 0, true, false, "no record is dated more than 0s before a time-stamp that precedes it, nor more than 0s after one that covers it"},
		{"4m behind", -4 * time.Minute, true, false, "more than 4m0s before a time-stamp"},
		{"4m ahead", 4 * time.Minute, true, false, "more than 4m0s after one that covers it"},
		{"6m behind", -6 * time.Minute, true, true, ""},
		{"6m ahead", 6 * time.Minute, true, true, ""},
		{"untrusted tokens prove nothing", -50 * time.Hour, false, false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			clk := newClock(t0.Add(tc.off))
			s := openStore(t, testOptions(dir, clk))
			for i := 0; i < 3; i++ {
				appendSamples(t, s, clk, 3, 10*time.Second)
				stampAt(t, s, s.Head(), clk.Now().Add(-tc.off), tc.trusted)
			}
			appendSamples(t, s, clk, 2, 10*time.Second)
			rep := verifyWith(t, s, VerifyOptions{TokenVerifier: timeTSA{}, CheckBlobs: true})
			if got := len(timeFailures(rep)) > 0; got != tc.fails || rep.OK == tc.fails {
				t.Fatalf("ts failures %v, want %v:\n%s", got, tc.fails, dumpReport(rep))
			}
			agree := notesWith(rep, "agree with the 3 trusted time-stamp(s)")
			if want := tc.trusted && !tc.fails; (len(agree) == 1) != want || (want && !strings.Contains(agree[0], tc.agree)) {
				t.Errorf("agreement note %q (want one: %v, saying %q)", agree, want, tc.agree)
			}
		})
	}
}

// Without trusted anchors the order of the ts is all a verifier has: a step back is reported with
// what documents it, and ts before the genesis record are named.
func TestBackwardStepsWithoutTimeStamps(t *testing.T) {
	dir := t.TempDir()
	clk := newClock(t0)
	opts := testOptions(dir, clk)
	s := openStore(t, opts)
	clk.Advance(3 * time.Hour)
	appendSamples(t, s, clk, 3, 10*time.Second)
	// Within a run (still after the genesis record): the monitor documents the step with clock_jump.
	clk.Step(clk.Now().Add(-time.Hour))
	appendSamples(t, s, clk, 1, 10*time.Second)
	jump := mustAppend(t, s, model.TypeClockJump, model.ClockJump{WallDeltaMs: -3600000, JumpMs: -3600000})
	appendSamples(t, s, clk, 2, 10*time.Second)
	clk.Step(clk.Now().Add(time.Hour))
	appendSamples(t, s, clk, 2, 10*time.Second)
	mustAppend(t, s, model.TypeMonitorStop, model.MonitorStop{Reason: "service stop"})
	s.Close()
	// Across a restart, to before the genesis record: the writer documents it on open.
	clk.Step(t0.Add(-24 * time.Hour))
	s = openStore(t, opts)
	appendSamples(t, s, clk, 2, 10*time.Second)

	rep := verifyWith(t, s, VerifyOptions{CheckBlobs: true})
	requireOK(t, rep) // without a trusted time-stamp nothing proves which ts is false
	n := notesWith(rep, "record ts go backwards")
	if len(n) != 2 {
		t.Fatalf("backward-step notes %q", rep.Notes)
	}
	if !strings.Contains(n[0], fmt.Sprintf("clock_jump record seq %d", jump.Seq)) || strings.Contains(n[0], "genesis") {
		t.Errorf("in-run step note %q", n[0])
	}
	if !strings.Contains(n[1], "before the genesis record") || !strings.Contains(n[1], "integrity_alert") {
		t.Errorf("restart step note %q", n[1])
	}
}

// The writer records a clock that is behind the newest record when the ledger is opened.
func TestOpenWithClockBehindNewestRecord(t *testing.T) {
	dir := t.TempDir()
	clk := newClock(t0)
	opts := testOptions(dir, clk)
	s := openStore(t, opts)
	appendSamples(t, s, clk, 2, 10*time.Second)
	alerts := func(s *Store) []model.IntegrityAlert {
		var out []model.IntegrityAlert
		for _, b := range scanAll(t, s) {
			if b.Type == model.TypeIntegrityAlert {
				out = append(out, decodeData[model.IntegrityAlert](t, b))
			}
		}
		return out
	}

	s.Close()
	clk.Step(clk.Now().Add(-90 * time.Second)) // a small correction: tolerated
	s = openStore(t, opts)
	if a := alerts(s); len(a) != 0 {
		t.Fatalf("alerts after a 90 s step back: %+v", a)
	}
	head := s.Head()
	s.Close()
	clk.Step(clk.Now().Add(-10 * time.Minute))
	s = openStore(t, opts)
	a := alerts(s)
	if len(a) != 1 || len(a[0].Details) != 1 {
		t.Fatalf("alerts %+v", a)
	}
	d := a[0].Details[0]
	for _, want := range []string{"clock is behind the newest", fmt.Sprintf("seq %d", head.Seq), head.TS} {
		if !strings.Contains(d, want) {
			t.Errorf("alert detail %q lacks %q", d, want)
		}
	}
	// A read-only open never writes.
	ro := opts
	ro.ReadOnly = true
	clk.Step(clk.Now().Add(-time.Hour))
	openStore(t, ro)
}

// Large SNTP offsets measured by the monitor and records dated after the verification are noted.
func TestClockEvidenceNotes(t *testing.T) {
	s, _, clk := newLedger(t)
	appendSamples(t, s, clk, 2, 10*time.Second)
	cc := func(offs ...int64) model.ClockCheck {
		var c model.ClockCheck
		for i, o := range offs {
			c.Results = append(c.Results, model.ClockResult{Server: fmt.Sprint("ntp", i), OK: true, OffsetMs: o})
		}
		c.Results = append(c.Results, model.ClockResult{Server: "down", Err: "timeout"})
		return c
	}
	mustAppend(t, s, model.TypeClockCheck, cc(400, -200, 350))
	rep, err := verifyReader(context.Background(), s, VerifyOptions{}, clk.Now)
	if err != nil {
		t.Fatal(err)
	}
	if n := notesWith(rep, "clock_check"); len(n) != 0 {
		t.Fatalf("notes for small offsets %q", n)
	}
	// One server far off does not count; the median of the answers does.
	mustAppend(t, s, model.TypeClockCheck, cc(150, 3_600_000, -120))
	big := mustAppend(t, s, model.TypeClockCheck, cc(10_800_000, 10_800_500, 10_799_000))
	rep, _ = verifyReader(context.Background(), s, VerifyOptions{}, clk.Now)
	n := notesWith(rep, "clock_check")
	if len(n) != 1 || !strings.Contains(n[0], "1 clock_check record") || !strings.Contains(n[0], fmt.Sprintf("seq %d", big.Seq)) ||
		!strings.Contains(n[0], "3h0m0s behind") {
		t.Fatalf("SNTP notes %q", n)
	}
	// Verified an hour before the newest records were (supposedly) written.
	rep, _ = verifyReader(context.Background(), s, VerifyOptions{}, func() time.Time { return t0.Add(-time.Hour) })
	if n := notesWith(rep, "dated after the time of this verification"); len(n) != 1 || !strings.Contains(n[0], "1h0m20s later") {
		t.Fatalf("future notes %q", rep.Notes)
	}
	requireOK(t, rep)
}

// Time failures are counted and listed in ledger order with the others, whichever check found them.
func TestTimeFailuresListedInLedgerOrder(t *testing.T) {
	dir := t.TempDir()
	const ahead = time.Hour
	clk := newClock(t0.Add(ahead))
	opts := testOptions(dir, clk)
	s := openStore(t, opts)
	refs := appendSamples(t, s, clk, 4, 10*time.Second)
	stampAt(t, s, s.Head(), clk.Now().Add(-ahead), true)
	appendSamples(t, s, clk, 3, 10*time.Second)
	s.Close()
	// Damage a record after the forward-dated run: its failure is found first, but lies later.
	path := segPath(dir, segName(clk.Now()))
	lines := readLines(t, path)
	last := len(lines) - 1
	env, _ := parseLine(t, lines[last])
	lines[last] = []byte(strings.Replace(string(lines[last]), env.H, strings.Repeat("0", 64), 1))
	writeLines(t, path, lines)

	ro := opts
	ro.ReadOnly = true
	r := openStore(t, ro)
	rep := verifyWith(t, r, VerifyOptions{TokenVerifier: timeTSA{}, CheckBlobs: true})
	if rep.FailuresTotal != 2 || len(rep.Failures) != 2 {
		t.Fatalf("failures:\n%s", dumpReport(rep))
	}
	if rep.Failures[0].Problem != tsProblem || rep.Failures[0].Seq != 0 || rep.Failures[1].Problem != probHash {
		t.Fatalf("failures not in ledger order:\n%s", dumpReport(rep))
	}
	if !strings.Contains(rep.Failures[0].Detail, fmt.Sprintf("from seq 0 to seq %d", refs[3].Seq)) {
		t.Errorf("detail %q", rep.Failures[0].Detail)
	}
	// The report stays JSON-encodable with the new class.
	if _, err := json.Marshal(rep); err != nil {
		t.Fatal(err)
	}
}

// A clock that stays off makes only the records written close to each time-stamp provably
// mis-dated. The contradictions of consecutive anchoring events (two TSAs each) are one failure,
// not one per time-stamp; once the clock is right again for a whole window, the failure ends.
func TestSustainedClockOffsetIsOneFailurePerPeriod(t *testing.T) {
	dir := t.TempDir()
	const ahead = 8 * time.Minute
	clk := newClock(t0.Add(ahead))
	s := openStore(t, testOptions(dir, clk))
	stampBoth := func(off time.Duration) {
		h := s.Head()
		stampAt(t, s, h, clk.Now().Add(-off), true) // DigiCert
		stampAt(t, s, h, clk.Now().Add(-off), true) // FreeTSA, same head
	}
	var first uint64
	for i := 0; i < 6; i++ { // 6 windows of 30 minutes with the clock 8 minutes ahead
		refs := appendSamples(t, s, clk, 180, 10*time.Second)
		if i == 0 {
			first = refs[len(refs)-1].Seq // at most the last 3 minutes before a time-stamp are provably ahead
		}
		stampBoth(ahead)
	}
	clk.Step(clk.Now().Add(-ahead))
	mustAppend(t, s, model.TypeClockJump, model.ClockJump{WallDeltaMs: -ahead.Milliseconds(), JumpMs: -ahead.Milliseconds()})
	for i := 0; i < 3; i++ { // the clock is right again
		appendSamples(t, s, clk, 180, 10*time.Second)
		stampBoth(0)
	}
	rep := verifyWith(t, s, VerifyOptions{TokenVerifier: timeTSA{}, CheckBlobs: true})
	tf := timeFailures(rep)
	if len(tf) != 1 || rep.FailuresTotal != 1 {
		t.Fatalf("want one failure for the whole period:\n%s", dumpReport(rep))
	}
	if f := tf[0]; f.Seq > first || !strings.Contains(f.Detail, "8m0s later than") {
		t.Errorf("failure %+v", f)
	}
}

// More records than maxPendingTS awaiting a trusted anchor are folded into a summary that keeps
// the latest ts: memory stays bounded and a forward-dated record among them is still found.
func TestPendingRecordsFoldWhenNoAnchorCoversThem(t *testing.T) {
	feed := func(tc *timeChecker, n int, odd uint64, oddTS time.Time) {
		for i := 0; i < n; i++ {
			seq := uint64(i)
			r := &lineResult{seg: 0, lineNo: i + 1, tsOK: true, ts: t0.Add(time.Duration(i) * time.Second)}
			if seq == odd {
				r.ts = oddTS
			}
			r.body = model.Body{Seq: seq, Type: model.TypeSample}
			tc.record(r)
		}
	}
	const n = maxPendingTS + maxPendingTS/2
	end := t0.Add(n * time.Second)
	for _, tc := range []struct {
		name  string
		odd   uint64
		fails bool
	}{
		{"folded and forward-dated", 7, true},
		{"exact and forward-dated", n - 3, true},
		{"none", n + 1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var notes []string
			c := newTimeChecker([]string{"ledger-2026-10-05"}, func() time.Time { return end }, func(s string) { notes = append(notes, s) })
			feed(c, n, tc.odd, end.Add(time.Hour))
			if l := len(c.pend) - c.pendHead; l > maxPendingTS || c.fold.n == 0 {
				t.Fatalf("pending %d (cap %d), folded %d", l, maxPendingTS, c.fold.n)
			}
			c.anchor(tsBound{anchor: n, head: n - 1, tsa: "CN=TSA", gen: end})
			c.finish()
			fails := append(c.lowFails, c.highFails...)
			if (len(fails) > 0) != tc.fails || c.failTotal != len(fails) {
				t.Fatalf("failures %+v, notes %q", fails, notes)
			}
			if tc.fails && (fails[0].Problem != probTime || !strings.Contains(fails[0].Detail, fmt.Sprintf("seq %d is dated", tc.odd))) {
				t.Fatalf("failure %+v", fails[0])
			}
			if len(c.pend)-c.pendHead != 0 || c.fold.n != 0 {
				t.Fatalf("covered records still pending: %d, folded %d", len(c.pend)-c.pendHead, c.fold.n)
			}
		})
	}
}
