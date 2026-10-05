package ledger

// Integration round: an anchor proves time only when its time-stamp token verifies for the
// anchored head hash AND the TSA certificate chains to a trusted root. A token signed by a
// certificate that does not chain proves nothing (anyone can make one; the DigiCert channel is
// plain HTTP), so it must not move last_anchored_seq / unanchored_tail.

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"attmonitor/internal/contracts"
	"attmonitor/internal/model"
)

const untrustedChainNote = "system roots: x509: certificate signed by unknown authority"

// trustTSA accepts "TOKEN:<hex digest>" (chains to a trusted root) and "UNTRUSTED:<hex digest>"
// (genuine for the digest, but its TSA certificate does not chain to a trusted root).
type trustTSA struct {
	gen   time.Time
	calls *int
}

func (f trustTSA) VerifyToken(token, digest []byte) (contracts.TokenInfo, error) {
	if f.calls != nil {
		*f.calls++
	}
	h := hex.EncodeToString(digest)
	info := contracts.TokenInfo{GenTime: f.gen, Serial: "01", Policy: "1.2.3.4", TSAName: "CN=Fake TSA"}
	switch {
	case bytes.Equal(token, []byte("TOKEN:"+h)):
		info.ChainOK = true
	case bytes.Equal(token, []byte("UNTRUSTED:"+h)):
		info.ChainNote = untrustedChainNote
	default:
		return contracts.TokenInfo{}, errors.New("message imprint does not match")
	}
	return info, nil
}

// appendAnchor stores token as a blob and appends an anchor record for head with the given
// issue-time flags.
func appendAnchor(t *testing.T, s *Store, head model.Ref, token string, gen time.Time, verified, chainOK bool) model.Ref {
	t.Helper()
	id, err := s.PutBlob([]byte(token))
	if err != nil {
		t.Fatal(err)
	}
	return mustAppend(t, s, model.TypeAnchor, model.Anchor{
		TSAURL: "http://tsa.example/", HeadSeq: head.Seq, HeadHash: head.Hash, TokenSHA256: id,
		GenTime: gen.Format(time.RFC3339), Verified: verified, ChainOK: chainOK, Reason: "periodic",
	}, id)
}

func anchorBySeq(t *testing.T, rep model.VerifyReport, seq uint64) model.AnchorCheck {
	t.Helper()
	for _, a := range rep.Anchors {
		if a.Seq == seq {
			return a
		}
	}
	t.Fatalf("no anchor check for seq %d in %+v", seq, rep.Anchors)
	return model.AnchorCheck{}
}

func TestUntrustedChainAnchorIsNotProofOfTime(t *testing.T) {
	dir := t.TempDir()
	clk := newClock(t0)
	// The TSA stamps the head shortly after it was written: a genTime that contradicts the records'
	// ts would itself be a verification failure (ts_contradiction).
	gen := t0.Add(time.Minute)
	opts := testOptions(dir, clk)
	opts.TokenVerifier = trustTSA{gen: gen}
	s := openStore(t, opts)

	appendSamples(t, s, clk, 5, 10*time.Second)
	h1 := s.Head()
	a1 := appendAnchor(t, s, h1, "TOKEN:"+h1.Hash, gen, true, true)
	appendSamples(t, s, clk, 3, 10*time.Second)
	h2 := s.Head()
	// Issue-time flags claim a trusted chain: the token itself is what counts.
	a2 := appendAnchor(t, s, h2, "UNTRUSTED:"+h2.Hash, gen, true, true)
	tail := appendSamples(t, s, clk, 4, 10*time.Second)
	last := tail[len(tail)-1].Seq

	check := func(t *testing.T, rep model.VerifyReport) {
		t.Helper()
		requireOK(t, rep) // an untrusted chain is not tampering: no failure
		if !rep.TokensChecked {
			t.Error("TokensChecked = false although a token verifier checked the tokens")
		}
		if len(rep.Anchors) != 2 {
			t.Fatalf("anchors %+v", rep.Anchors)
		}
		if c := anchorBySeq(t, rep, a1.Seq); !c.OK || !c.ChainOK || c.Detail != "" {
			t.Errorf("trusted anchor %+v", c)
		}
		c := anchorBySeq(t, rep, a2.Seq)
		if !c.OK || c.ChainOK || !strings.Contains(c.Detail, untrustedChainNote) || !strings.Contains(c.Detail, "proof of time") {
			t.Errorf("untrusted anchor %+v", c)
		}
		if c.HeadSeq != h2.Seq || c.TSA != "CN=Fake TSA" || c.GenTime != gen.Format(time.RFC3339Nano) {
			t.Errorf("untrusted anchor facts %+v", c)
		}
		if rep.LastAnchoredSeq != h1.Seq || rep.UnanchoredTail != last-h1.Seq {
			t.Errorf("last anchored %d (want %d), unanchored tail %d (want %d)", rep.LastAnchoredSeq, h1.Seq, rep.UnanchoredTail, last-h1.Seq)
		}
		notes := strings.Join(rep.Notes, "\n")
		if strings.Count(notes, "not accepted as proof of time") != 1 ||
			!strings.Contains(notes, "1 of 2 anchor record(s) are not accepted as proof of time") ||
			!strings.Contains(notes, "does not chain to a trusted root") {
			t.Errorf("notes %q", rep.Notes)
		}
	}
	for _, ring := range []int{0, 2} { // 2 forces the deferred Record() lookup of the covered head
		t.Run(fmt.Sprintf("ring=%d", ring), func(t *testing.T) {
			rep, err := VerifyReader(context.Background(), s, VerifyOptions{TokenVerifier: trustTSA{gen: gen}, CheckBlobs: true, ringSize: ring})
			if err != nil {
				t.Fatal(err)
			}
			check(t, rep)
		})
	}
	t.Run("Store.Verify", func(t *testing.T) {
		rep, err := s.Verify(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		check(t, rep)
	})
}

func TestNoTrustedAnchorLeavesWholeLedgerUnanchored(t *testing.T) {
	s, _, clk := newLedger(t)
	gen := t0.Add(time.Hour)
	appendSamples(t, s, clk, 3, 10*time.Second)
	h := s.Head()
	appendAnchor(t, s, h, "UNTRUSTED:"+h.Hash, gen, true, true)
	appendAnchor(t, s, h, "UNTRUSTED:"+h.Hash, gen, true, true) // second TSA, same head
	appendSamples(t, s, clk, 2, 10*time.Second)
	rep, err := VerifyReader(context.Background(), s, VerifyOptions{TokenVerifier: trustTSA{gen: gen}, CheckBlobs: true})
	if err != nil {
		t.Fatal(err)
	}
	requireOK(t, rep)
	if rep.LastAnchoredSeq != 0 || rep.UnanchoredTail != rep.Records {
		t.Fatalf("last anchored %d, unanchored %d of %d records", rep.LastAnchoredSeq, rep.UnanchoredTail, rep.Records)
	}
	notes := strings.Join(rep.Notes, "\n")
	if !strings.Contains(notes, "2 of 2 anchor record(s) are not accepted as proof of time") ||
		!strings.Contains(notes, "no anchor is accepted as proof of time") {
		t.Fatalf("notes %q", rep.Notes)
	}
}

// Without a token verifier the anchor record's own issue-time flags decide (verified && chain_ok),
// and the report says so.
func TestAnchorProofWithoutVerifierUsesIssueTimeFlags(t *testing.T) {
	s, _, clk := newLedger(t)
	// The TSA stamps the head shortly after it was written: a genTime that contradicts the records'
	// ts would itself be a verification failure (ts_contradiction).
	gen := t0.Add(time.Minute)
	appendSamples(t, s, clk, 3, 10*time.Second)
	h1 := s.Head()
	a1 := appendAnchor(t, s, h1, "TOKEN:"+h1.Hash, gen, true, true)
	appendSamples(t, s, clk, 2, 10*time.Second)
	h2 := s.Head()
	a2 := appendAnchor(t, s, h2, "TOKEN:"+h2.Hash, gen, true, false)
	appendSamples(t, s, clk, 2, 10*time.Second)
	h3 := s.Head()
	a3 := appendAnchor(t, s, h3, "TOKEN:"+h3.Hash, gen, false, true)
	tail := appendSamples(t, s, clk, 2, 10*time.Second)
	last := tail[len(tail)-1].Seq

	for _, checkBlobs := range []bool{true, false} {
		t.Run(fmt.Sprintf("blobs=%v", checkBlobs), func(t *testing.T) {
			rep, err := VerifyReader(context.Background(), s, VerifyOptions{CheckBlobs: checkBlobs})
			if err != nil {
				t.Fatal(err)
			}
			requireOK(t, rep)
			if rep.TokensChecked {
				t.Error("TokensChecked = true without a token verifier")
			}
			if rep.LastAnchoredSeq != h1.Seq || rep.UnanchoredTail != last-h1.Seq {
				t.Errorf("last anchored %d (want %d), unanchored %d", rep.LastAnchoredSeq, h1.Seq, rep.UnanchoredTail)
			}
			if c := anchorBySeq(t, rep, a1.Seq); !c.OK || !c.ChainOK {
				t.Errorf("anchor recorded as verified+chained: %+v", c)
			}
			for _, seq := range []uint64{a2.Seq, a3.Seq} {
				if c := anchorBySeq(t, rep, seq); !c.OK || c.ChainOK || !strings.Contains(c.Detail, "proof of time") {
					t.Errorf("anchor %d recorded as untrusted: %+v", seq, c)
				}
			}
			notes := strings.Join(rep.Notes, "\n")
			if !strings.Contains(notes, "issue-time flags") || !strings.Contains(notes, "2 of 3 anchor record(s) are not accepted as proof of time") {
				t.Errorf("notes %q", rep.Notes)
			}
		})
	}
}

// TokensChecked is true only when a TokenVerifier actually checked tokens.
func TestTokensCheckedOnlyWhenAVerifierChecked(t *testing.T) {
	s, _, clk := newLedger(t)
	appendSamples(t, s, clk, 2, time.Second)
	calls := 0
	ctx := context.Background()
	rep, err := VerifyReader(ctx, s, VerifyOptions{TokenVerifier: trustTSA{gen: t0, calls: &calls}, CheckBlobs: true})
	if err != nil {
		t.Fatal(err)
	}
	if rep.TokensChecked || calls != 0 {
		t.Fatalf("no anchor, yet TokensChecked=%v (verifier called %d times)", rep.TokensChecked, calls)
	}
	h := s.Head()
	appendAnchor(t, s, h, "TOKEN:"+h.Hash, t0, true, true)
	rep, _ = VerifyReader(ctx, s, VerifyOptions{TokenVerifier: trustTSA{gen: t0, calls: &calls}})
	if !rep.TokensChecked || calls != 1 {
		t.Fatalf("TokensChecked=%v after %d verifier call(s)", rep.TokensChecked, calls)
	}
	rep, _ = VerifyReader(ctx, s, VerifyOptions{CheckBlobs: true})
	if rep.TokensChecked {
		t.Fatal("TokensChecked without a verifier")
	}
}

// noteTSA verifies every token but never chains, explaining why with note.
type noteTSA struct{ note string }

func (n noteTSA) VerifyToken(token, digest []byte) (contracts.TokenInfo, error) {
	return contracts.TokenInfo{GenTime: t0.Add(time.Hour), TSAName: "CN=Self-signed", ChainNote: n.note}, nil
}

// The chain note quotes what the verifier saw in the token: it is kept on one line and bounded.
func TestChainNoteInDetailIsOneLineAndBounded(t *testing.T) {
	s, _, clk := newLedger(t)
	appendSamples(t, s, clk, 2, time.Second)
	h := s.Head()
	a := appendAnchor(t, s, h, "self-signed token", t0.Add(time.Hour), true, true)
	for _, note := range []string{"certificate \"CN=evil\nINJECTED\" signed by unknown authority\r", strings.Repeat("x", 4096)} {
		rep, err := VerifyReader(context.Background(), s, VerifyOptions{TokenVerifier: noteTSA{note: note}, CheckBlobs: true})
		if err != nil {
			t.Fatal(err)
		}
		requireOK(t, rep)
		c := anchorBySeq(t, rep, a.Seq)
		if !c.OK || c.ChainOK || strings.ContainsAny(c.Detail, "\r\n") || len(c.Detail) > maxDetailBytes+3 ||
			!strings.Contains(c.Detail, "proof of time") {
			t.Fatalf("detail %q", c.Detail)
		}
		if rep.LastAnchoredSeq != 0 || rep.UnanchoredTail != rep.Records {
			t.Fatalf("a self-signed token was accepted as proof of time: %+v", rep)
		}
	}
}

// A failed anchor never proves time, and the note's breakdown counts it.
func TestFailedAnchorIsCountedAsNotProof(t *testing.T) {
	s, _, clk := newLedger(t)
	// The TSA stamps the head shortly after it was written: a genTime that contradicts the records'
	// ts would itself be a verification failure (ts_contradiction).
	gen := t0.Add(time.Minute)
	refs := appendSamples(t, s, clk, 4, 10*time.Second)
	h := s.Head()
	appendAnchor(t, s, h, "TOKEN:"+h.Hash, gen, true, true)
	bad := model.Ref{Seq: refs[3].Seq, Hash: refs[1].Hash}
	appendAnchor(t, s, bad, "TOKEN:"+bad.Hash, gen, true, true) // head_hash of another record
	appendSamples(t, s, clk, 1, 10*time.Second)
	rep, err := VerifyReader(context.Background(), s, VerifyOptions{TokenVerifier: trustTSA{gen: gen}, CheckBlobs: true})
	if err != nil {
		t.Fatal(err)
	}
	if rep.OK || problems(rep)[probAnchor] != 1 || rep.LastAnchoredSeq != h.Seq {
		t.Fatalf("report:\n%s", dumpReport(rep))
	}
	if notes := strings.Join(rep.Notes, "\n"); !strings.Contains(notes, "1 of 2 anchor record(s) are not accepted as proof of time") ||
		!strings.Contains(notes, "1 failed") {
		t.Fatalf("notes %q", rep.Notes)
	}
}
