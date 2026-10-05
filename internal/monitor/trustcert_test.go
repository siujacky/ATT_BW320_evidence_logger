package monitor

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"attmonitor/internal/contracts"
	"attmonitor/internal/model"
)

// Gateway certificate fingerprints (lowercase hex SHA-256, as the gateway client reports them).
var (
	fpA = sha256Hex([]byte("gateway certificate A"))
	fpB = sha256Hex([]byte("gateway certificate B"))
	fpC = sha256Hex([]byte("gateway certificate C"))
)

// certRig returns a rig whose gateway certificate fpA is pinned while fpB is pending, as the
// certificate observer leaves it after a status page met a changed certificate.
func certRig(t *testing.T) *rig {
	t.Helper()
	r := newRig(t, nil, nil)
	r.cfg.Gateway.PinnedCertSHA256 = fpA
	if !r.gw.observer(fpA, fpB) {
		t.Fatal("a status page must keep being read")
	}
	if pin, pending := pins(r); pin != fpA || pending != fpB {
		t.Fatalf("pin %q pending %q", pin, pending)
	}
	return r
}

// pins reads the pinned and the pending certificate under the monitor's configuration lock.
func pins(r *rig) (pinned, pending string) {
	r.m.cfgMu.Lock()
	defer r.m.cfgMu.Unlock()
	return r.cfg.Gateway.PinnedCertSHA256, r.cfg.Gateway.PendingCertSHA256
}

// colonPairs renders a hex fingerprint the way certificate viewers show it ("AB:CD:...").
func colonPairs(hexFP string) string {
	var parts []string
	for i := 0; i+2 <= len(hexFP); i += 2 {
		parts = append(parts, hexFP[i:i+2])
	}
	return strings.ToUpper(strings.Join(parts, ":"))
}

func certCondition(st model.Status) *model.Condition {
	for i := range st.Conditions {
		if st.Conditions[i].Code == condGatewayCertChanged {
			return &st.Conditions[i]
		}
	}
	return nil
}

// TrustCert confirms only the certificate the operator reviewed (contracts.Actions.TrustCert):
// the expected fingerprint is normalized (case, ':' separators, spaces); a different pending
// certificate is refused with an ErrBusy-wrapped error naming both fingerprints and nothing
// changes; "" trusts whatever is pending; nothing pending is ErrNotFound.
func TestTrustCertExpectedFingerprint(t *testing.T) {
	ctx := context.Background()

	t.Run("match", func(t *testing.T) {
		r := certRig(t)
		saved := r.saved.Load()
		cc, err := r.m.TrustCert(ctx, "operator via web", " "+colonPairs(fpB)+"\t")
		if err != nil || cc.Before != fpA || cc.After != fpB || cc.Target != "monitor" || cc.Actor != "operator via web" || cc.Result != "applied" {
			t.Fatalf("trust: %+v %v", cc, err)
		}
		if pin, pending := pins(r); pin != fpB || pending != "" || r.saved.Load() != saved+1 {
			t.Fatalf("pin %q pending %q saved %d", pin, pending, r.saved.Load()-saved)
		}
		recs := ofType(r.led.records(""), model.TypeConfigChange)
		if len(recs) != 1 || decode[model.ConfigChange](t, recs[0]) != cc {
			t.Fatalf("config_change records %d", len(recs))
		}
		if certCondition(r.m.Status()) != nil {
			t.Fatal("GATEWAY_CERT_CHANGED must clear")
		}
	})

	t.Run("mismatch", func(t *testing.T) {
		r := certRig(t)
		saved, records := r.saved.Load(), len(r.led.records(""))
		cc, err := r.m.TrustCert(ctx, "operator via web", fpC)
		if !errors.Is(err, contracts.ErrBusy) || errors.Is(err, contracts.ErrNotFound) || cc != (model.ConfigChange{}) {
			t.Fatalf("trust: %+v %v", cc, err)
		}
		if msg := err.Error(); !strings.Contains(msg, fpB) || !strings.Contains(msg, fpC) {
			t.Fatalf("the error must name the pending and the reviewed fingerprint: %q", msg)
		}
		if strings.Contains(err.Error(), contracts.ErrBusy.Error()) {
			t.Fatalf("the refusal is not about a concurrent operation: %q", err)
		}
		if pin, pending := pins(r); pin != fpA || pending != fpB || r.saved.Load() != saved || len(r.led.records("")) != records {
			t.Fatalf("a refused confirmation changed something: pin %q pending %q saved %d records %d→%d",
				pin, pending, r.saved.Load()-saved, records, len(r.led.records("")))
		}
		if c := certCondition(r.m.Status()); c == nil || !strings.Contains(c.Message, fpB) {
			t.Fatalf("GATEWAY_CERT_CHANGED must stay: %+v", c)
		}
		// The certificate actually pending can still be confirmed.
		if cc, err := r.m.TrustCert(ctx, "operator via web", strings.ToUpper(fpB)); err != nil || cc.After != fpB {
			t.Fatalf("trust the pending one: %+v %v", cc, err)
		}
	})

	t.Run("empty trusts whatever is pending", func(t *testing.T) {
		r := certRig(t)
		cc, err := r.m.TrustCert(ctx, "cli DOMAIN\\owner", "  ")
		if err != nil || cc.Before != fpA || cc.After != fpB || cc.Actor != "cli DOMAIN\\owner" {
			t.Fatalf("trust: %+v %v", cc, err)
		}
		if pin, pending := pins(r); pin != fpB || pending != "" {
			t.Fatalf("pin %q pending %q", pin, pending)
		}
	})

	t.Run("nothing pending", func(t *testing.T) {
		r := newRig(t, nil, nil)
		r.cfg.Gateway.PinnedCertSHA256 = fpA
		for _, expected := range []string{"", fpA, fpB} {
			if _, err := r.m.TrustCert(ctx, "operator", expected); !errors.Is(err, contracts.ErrNotFound) || errors.Is(err, contracts.ErrBusy) {
				t.Fatalf("expected %q: %v", expected, err)
			}
		}
		if pin, pending := pins(r); pin != fpA || pending != "" || len(ofType(r.led.records(""), model.TypeConfigChange)) != 0 {
			t.Fatalf("pin %q pending %q", pin, pending)
		}
	})
}

// The expected fingerprint is compared with the pending certificate in the same critical
// section that moves the pin: a certificate that becomes pending while the operator confirms is
// never trusted in place of the reviewed one, whichever comes first.
func TestTrustCertComparesUnderTheConfigLock(t *testing.T) {
	ctx := context.Background()
	for i := 0; i < 25; i++ {
		r := certRig(t)
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.gw.observer(fpA, fpC) // a status page meets yet another certificate
		}()
		cc, err := r.m.TrustCert(ctx, "operator via web", fpB)
		wg.Wait()
		pin, pending := pins(r)
		switch {
		case err == nil: // confirmed first; C then differs from the new pin
			if cc.After != fpB || pin != fpB || pending != fpC {
				t.Fatalf("run %d: confirmed %+v, pin %q pending %q", i, cc, pin, pending)
			}
		case errors.Is(err, contracts.ErrBusy): // C replaced B before the comparison
			if pin != fpA || pending != fpC {
				t.Fatalf("run %d: refused, pin %q pending %q", i, pin, pending)
			}
		default:
			t.Fatalf("run %d: %v", i, err)
		}
		if g := r.m.Status().GatewayCert; g == nil || g.Pinned != pin || g.Pending != pending {
			t.Fatalf("run %d: status %+v, pin %q pending %q", i, g, pin, pending)
		}
	}
}

// Status.GatewayCert reports the pin whenever one exists, and while a changed certificate
// waits for confirmation: which one, since when (its first sighting) and the cert_changed
// record that reported it - the same record the GATEWAY_CERT_CHANGED condition names, also
// after a restart.
func TestStatusGatewayCert(t *testing.T) {
	ctx := context.Background()
	r := newRig(t, nil, nil)
	gc := func() *model.GatewayCertState { return r.m.Status().GatewayCert }
	expect := func(what string, got *model.GatewayCertState, want model.GatewayCertState) {
		t.Helper()
		if got == nil || *got != want {
			t.Fatalf("%s: gateway_cert %+v, want %+v", what, got, want)
		}
	}
	if g := gc(); g != nil {
		t.Fatalf("no certificate seen yet: %+v", g)
	}

	r.gw.observer("", fpA) // trust on first use
	expect("pinned", gc(), model.GatewayCertState{Pinned: fpA})

	r.gw.observer(fpA, fpB) // a status page meets a changed certificate
	ev := lastOfType(t, r, model.TypeGatewayEvent)
	if e := decode[model.GatewayEvent](t, ev); e.Kind != model.GwEvCertChanged || e.After != fpB {
		t.Fatalf("event %+v", e)
	}
	pendingB := model.GatewayCertState{Pinned: fpA, Pending: fpB, Since: ev.TS, Seq: ev.Seq}
	st := r.m.Status()
	expect("pending", st.GatewayCert, pendingB)
	if c := certCondition(st); c == nil || c.Severity != "critical" || c.Seq != ev.Seq || c.Since != ev.TS || !strings.Contains(c.Message, fpB) {
		t.Fatalf("condition %+v", c)
	}

	r.gw.observer(fpA, fpB) // seen again: still the first sighting
	r.m.gwAuth.Store(true)
	r.gw.observer(fpA, fpB) // refused inside an authenticated request: no new record either
	r.m.gwAuth.Store(false)
	expect("pending, seen again", gc(), pendingB)

	// A restart rebuilds the same view from the configuration and the ledger.
	m2, err := New(Options{Config: r.cfg, Ledger: r.led, Gateway: &fakeGateway{}, Prober: newFakeProber()})
	if err != nil {
		t.Fatal(err)
	}
	m2.rebuild(time.Now())
	st2 := m2.Status()
	expect("rebuilt", st2.GatewayCert, pendingB)
	if c := certCondition(st2); c == nil || c.Seq != ev.Seq || c.Since != ev.TS {
		t.Fatalf("rebuilt condition %+v", c)
	}

	r.gw.observer(fpB, fpA) // the pinned certificate is presented again
	if st := r.m.Status(); certCondition(st) != nil {
		t.Fatalf("nothing pending any more: %+v", st.Conditions)
	}
	expect("pinned again", gc(), model.GatewayCertState{Pinned: fpA})

	r.gw.observer(fpA, fpC) // another change: pending since its own record
	ev2 := lastOfType(t, r, model.TypeGatewayEvent)
	expect("pending C", gc(), model.GatewayCertState{Pinned: fpA, Pending: fpC, Since: ev2.TS, Seq: ev2.Seq})

	if _, err := r.m.TrustCert(ctx, "operator via web", fpC); err != nil {
		t.Fatal(err)
	}
	expect("confirmed", gc(), model.GatewayCertState{Pinned: fpC})

	// A pending certificate whose record cannot be named (here: a configuration edited by
	// hand, no pin) is still reported; no record is guessed.
	r3 := newRig(t, nil, nil)
	r3.cfg.Gateway.PendingCertSHA256 = fpB
	expect("pending without pin or record", r3.m.Status().GatewayCert, model.GatewayCertState{Pending: fpB})
}

// Status never pairs the pending certificate with the record of another one: while a newer
// certificate's record is still being written, Since/Seq stay empty rather than wrong.
func TestStatusGatewayCertNeverNamesAnotherCertificatesRecord(t *testing.T) {
	r := certRig(t)
	setAppendErr(r.led, errors.New("disk full"))
	r.gw.observer(fpA, fpC) // C becomes pending, but its cert_changed record cannot be written
	setAppendErr(r.led, nil)
	st := r.m.Status()
	if g := st.GatewayCert; g == nil || *g != (model.GatewayCertState{Pinned: fpA, Pending: fpC}) {
		t.Fatalf("gateway_cert %+v", g)
	}
	if c := certCondition(st); c == nil || c.Seq != 0 || c.Since != "" || !strings.Contains(c.Message, fpC) {
		t.Fatalf("condition %+v", c)
	}
}

// Authenticated operations refused because a certificate awaits confirmation match
// contracts.ErrGatewayCertRejected (the web answers 409 "confirm the gateway certificate
// first") as well as contracts.ErrUnavailable, name the certificate and never reach the gateway.
func TestPendingCertificateRefusalIsCertRejected(t *testing.T) {
	ctx := context.Background()
	r := certRig(t)
	r.cfg.Gateway.AccessCodeProtected = "protected-blob"
	r.gw.notif = true
	checkErr := r.m.checkNotification(ctx)
	_, setErr := r.m.SetGatewayNotification(ctx, false, "operator via web")
	for name, err := range map[string]error{"notification check": checkErr, "notification change": setErr} {
		if !errors.Is(err, contracts.ErrGatewayCertRejected) || !errors.Is(err, contracts.ErrUnavailable) {
			t.Fatalf("%s: %v", name, err)
		}
		if msg := err.Error(); !strings.Contains(msg, fpB) || !strings.Contains(msg, "trust-cert") {
			t.Fatalf("%s: %q", name, msg)
		}
	}
	if r.gw.notifCalls != 0 || len(r.gw.setCalls) != 0 {
		t.Fatalf("the gateway was contacted: %d reads, %v changes", r.gw.notifCalls, r.gw.setCalls)
	}
	if st := r.m.Status(); st.Notification == nil || !strings.Contains(st.Notification.Err, "trust-cert") {
		t.Fatalf("notification state %+v", st.Notification)
	}
}
