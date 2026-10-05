package monitor

import (
	"context"
	"strings"
	"testing"

	"attmonitor/internal/contracts"
	"attmonitor/internal/model"
)

const untrustedNote = "system roots: x509: certificate signed by unknown authority"

// noteOnTrusted is an anchorer that (inconsistently) attaches a chain note to tokens whose
// chain is trusted.
type noteOnTrusted struct{ *fakeAnchorer }

func (n noteOnTrusted) VerifyToken(token, digest []byte) (contracts.TokenInfo, error) {
	info, err := n.fakeAnchorer.VerifyToken(token, digest)
	info.ChainNote = "should not be recorded"
	return info, err
}

// An anchor record keeps the anchorer's explanation of a TSA certificate that did not chain to
// a trusted root (model.Anchor.ChainNote = TokenInfo.ChainNote), never a note on a trusted one;
// for a token that did not verify at all the note says why. The dashboard warning quotes it.
func TestAnchorRecordsChainNote(t *testing.T) {
	ctx := context.Background()
	r := newRig(t, nil, nil)
	r.m.anchorer = chainlessAnchorer{r.anc, func(u string) bool { return u == "http://tsa.test/a" }}
	anchors, err := r.m.AnchorNow(ctx, "manual")
	if err != nil || len(anchors) != 2 {
		t.Fatalf("anchors %+v err %v", anchors, err)
	}
	recs := ofType(r.led.records(""), model.TypeAnchor)
	a, b := decode[model.Anchor](t, recs[0]), decode[model.Anchor](t, recs[1])
	if a.TSAURL != "http://tsa.test/a" || !a.Verified || a.ChainOK || a.ChainNote != untrustedNote || anchors[0].ChainNote != untrustedNote {
		t.Fatalf("untrusted anchor %+v", a)
	}
	if !b.ChainOK || b.ChainNote != "" || strings.Contains(string(recs[1].Data), "chain_note") {
		t.Fatalf("trusted anchor %+v (%s)", b, recs[1].Data)
	}

	// Every TSA untrusted: the warning names the reason.
	r.m.anchorer = chainlessAnchorer{r.anc, func(string) bool { return true }}
	if _, err := r.m.AnchorNow(ctx, "manual"); err != nil {
		t.Fatal(err)
	}
	var cond *model.Condition
	for _, c := range r.m.Status().Conditions {
		if c.Code == condAnchorUntrusted {
			cond = &c
		}
	}
	if cond == nil || !strings.Contains(cond.Message, untrustedNote) {
		t.Fatalf("condition %+v", cond)
	}

	// A token whose signature does not verify.
	r2 := newRig(t, nil, nil)
	r2.m.anchorer = badTokenAnchorer{r2.anc}
	if _, err := r2.m.AnchorNow(ctx, "manual"); err != nil {
		t.Fatal(err)
	}
	for _, rec := range ofType(r2.led.records(""), model.TypeAnchor) {
		if x := decode[model.Anchor](t, rec); x.Verified || x.ChainOK || !strings.Contains(x.ChainNote, "signature invalid") {
			t.Fatalf("unverified anchor %+v", x)
		}
	}

	// Trusted: no note, whatever the anchorer says.
	r3 := newRig(t, nil, nil)
	r3.m.anchorer = noteOnTrusted{r3.anc}
	anchors, err = r3.m.AnchorNow(ctx, "manual")
	if err != nil || len(anchors) != 2 {
		t.Fatalf("anchors %+v err %v", anchors, err)
	}
	for _, x := range anchors {
		if !x.ChainOK || x.ChainNote != "" {
			t.Fatalf("trusted anchor %+v", x)
		}
	}
}
