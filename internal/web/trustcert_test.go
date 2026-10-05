package web

// POST /api/gateway/trust-cert and the mapping of the contracts' error sentinels to HTTP
// statuses (docs/DESIGN.md §2 certificate policy, §12).

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"attmonitor/internal/contracts"
	"attmonitor/internal/model"
)

const trustURL = "/api/gateway/trust-cert"

// condGatewayCertChanged is the condition the monitor shows while a changed gateway
// certificate waits for the operator's confirmation (docs/DESIGN.md §9).
const condGatewayCertChanged = "GATEWAY_CERT_CHANGED"

// testCertSince is when the harness gateway first presented its changed certificate.
const testCertSince = "2026-10-05T03:19:00Z"

// certMessage is the monitor's GATEWAY_CERT_CHANGED wording for the pending certificate fp.
func certMessage(fp string) string {
	return "AT&T gateway presented a TLS certificate (SHA-256 " + fp + ") different from the pinned one: status pages are still read, " +
		"but authenticated requests (the notification setting) are paused until the certificate is confirmed (trust-cert)"
}

// withPendingCert makes the harness monitor report pending as the changed gateway certificate
// waiting for confirmation, as the monitor does: a cert_changed gateway_event in the ledger,
// the GATEWAY_CERT_CHANGED condition citing it, Status.GatewayCert, and the same certificate
// held as pending by the fake monitor's TrustCert. It returns the event's seq.
func withPendingCert(hs *harness, pending string) uint64 {
	r := hs.reader
	r.mu.Lock()
	seq := uint64(len(r.bodies))
	data, _ := json.Marshal(model.GatewayEvent{Kind: model.GwEvCertChanged, Before: testPinnedCert, After: pending,
		Detail: "gateway 192.168.1.254 presented a TLS certificate different from the pinned one"})
	body := model.Body{V: model.FormatVersion, Seq: seq, Prev: r.envs[len(r.envs)-1].H, TS: testCertSince,
		Run: strings.Repeat("0f", 16), Type: model.TypeGatewayEvent, Data: data}
	r.envs = append(r.envs, sealRecord(testKey, body))
	r.bodies = append(r.bodies, body)
	r.mu.Unlock()
	hs.status.mu.Lock()
	hs.status.status.Conditions = append(hs.status.status.Conditions, model.Condition{
		Code: condGatewayCertChanged, Severity: "critical", Message: certMessage(pending), Since: testCertSince, Seq: seq})
	hs.status.status.GatewayCert = &model.GatewayCertState{Pinned: testPinnedCert, Pending: pending, Since: testCertSince, Seq: seq}
	hs.status.mu.Unlock()
	hs.actions.mu.Lock()
	hs.actions.trustPending = pending
	hs.actions.mu.Unlock()
	return seq
}

// setGatewayCert replaces Status.GatewayCert of the harness monitor (nil: not reported).
func setGatewayCert(hs *harness, gc *model.GatewayCertState) {
	hs.status.mu.Lock()
	defer hs.status.mu.Unlock()
	hs.status.status.GatewayCert = gc
}

func (f *fakeActions) trustCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.trustCalls)
}

// wantContains fails for every want that msg does not contain.
func wantContains(t *testing.T, msg string, wants ...string) {
	t.Helper()
	for _, want := range wants {
		if !strings.Contains(msg, want) {
			t.Errorf("message %q does not mention %q", msg, want)
		}
	}
}

func TestTrustCertEndpoint(t *testing.T) {
	hs := newHarness(t)

	// The CLI may post no body at all; without Origin the actor is the CLI.
	rec := hs.serve(hs.request(http.MethodPost, trustURL, nil, nil))
	wantStatus(t, rec, http.StatusOK)
	cc := decode[model.ConfigChange](t, rec)
	if cc.Before != testPinnedCert || cc.After != testNewCert || cc.Actor != "operator via cli" || cc.Result != "applied" {
		t.Errorf("change = %+v", cc)
	}
	// From the dashboard (Origin) the actor is the web client; "client" overrides.
	wantStatus(t, hs.serve(hs.request(http.MethodPost, trustURL, strings.NewReader(`{}`), map[string]string{"Origin": testOrigin})), http.StatusOK)
	wantStatus(t, hs.post(trustURL, `{"client":"web"}`), http.StatusOK)
	wantStatus(t, hs.post(trustURL, " \n "), http.StatusOK) // white space only: no body
	actors, expected := hs.actions.trustState()
	if got := strings.Join(actors, ";"); got != "operator via cli;operator via web;operator via web;operator via cli" {
		t.Errorf("actors = %s", got)
	}
	// Without a fingerprint the monitor is asked for whatever is pending.
	if !slices.Equal(expected, []string{"", "", "", ""}) {
		t.Errorf("expected fingerprints = %q, want none", expected)
	}

	// Nothing waits for confirmation: 404 with the documented message.
	hs.actions.trustErr = fmt.Errorf("no changed gateway certificate is waiting for confirmation: %w", contracts.ErrNotFound)
	if msg := wantJSONError(t, hs.post(trustURL, `{}`), http.StatusNotFound); msg != msgNoPendingCert {
		t.Errorf("message = %q, want %q", msg, msgNoPendingCert)
	}
	hs.actions.trustErr = nil

	calls := hs.actions.trustCount()
	for _, tc := range []struct {
		name, body, ctype string
		code              int
	}{
		{"short fingerprint", `{"sha256":"` + strings.Repeat("a", 63) + `"}`, "", 400},
		{"not hex", `{"sha256":"` + strings.Repeat("g", 64) + `"}`, "", 400},
		// Separators alone are not "no fingerprint": that would confirm whatever is pending.
		{"separators only", `{"sha256":":::"}`, "", 400},
		{"spaced colon", `{"sha256":" : "}`, "", 400},
		{"not a string", `{"sha256":42}`, "", 400},
		{"bad client", `{"client":"monitor"}`, "", 400},
		{"unknown field", `{"pin":"x"}`, "", 400},
		{"not an object", `["` + testNewCert + `"]`, "", 400},
		{"trailing data", `{}{}`, "", 400},
		{"broken JSON", `{"sha256":`, "", 400},
		{"unpaired surrogate", `{"client":"` + esc("d800") + `"}`, "", 400},
		{"form content type", `sha256=` + testNewCert, "application/x-www-form-urlencoded", 415},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hdr := map[string]string{}
			if tc.ctype != "" {
				hdr["Content-Type"] = tc.ctype
			}
			wantJSONError(t, hs.serve(hs.request(http.MethodPost, trustURL, strings.NewReader(tc.body), hdr)), tc.code)
		})
	}
	// CSRF protection applies.
	wantJSONError(t, hs.serve(hs.request(http.MethodPost, trustURL, strings.NewReader(`{}`), map[string]string{CSRFHeader: ""})), http.StatusForbidden)
	wantJSONError(t, hs.serve(hs.request(http.MethodPost, trustURL, strings.NewReader(`{}`), map[string]string{"Origin": "http://evil.example"})), http.StatusForbidden)
	if n := hs.actions.trustCount(); n != calls {
		t.Fatalf("rejected requests reached Actions.TrustCert (%d calls)", n-calls)
	}
	wantJSONError(t, hs.get(trustURL), http.StatusMethodNotAllowed)

	hs.srv.actions = nil
	wantJSONError(t, hs.post(trustURL, `{}`), http.StatusServiceUnavailable)
}

// The fingerprint the operator reviewed reaches the monitor normalized, so that the monitor can
// compare it with the pending certificate under its own lock; without one the monitor is asked
// for whatever is pending ("").
func TestTrustCertPassesTheReviewedFingerprint(t *testing.T) {
	var pairs []string
	for i := 0; i < len(testNewCert); i += 2 {
		pairs = append(pairs, strings.ToUpper(testNewCert[i:i+2]))
	}
	for _, tc := range []struct{ name, body, want string }{
		{"as shown", `{"sha256":"` + testNewCert + `"}`, testNewCert},
		// As people copy it: grouped in fours, or as upper-case byte pairs with colons.
		{"grouped in fours", `{"sha256":"` + groupFP(testNewCert) + `"}`, testNewCert},
		{"upper-case pairs with colons", `{"sha256":"` + strings.Join(pairs, ":") + `"}`, testNewCert},
		{"padded", `{"sha256":"  ` + testNewCert + `\t","client":"cli"}`, testNewCert},
		{"no fingerprint", `{}`, ""},
		{"blank fingerprint", `{"sha256":"  "}`, ""},
		{"no body", ``, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, reported := range []bool{true, false} { // with and without Status.GatewayCert
				hs := newHarness(t)
				if reported {
					withPendingCert(hs, testNewCert)
				}
				rec := hs.post(trustURL, tc.body)
				wantStatus(t, rec, http.StatusOK)
				if _, got := hs.actions.trustState(); !slices.Equal(got, []string{tc.want}) {
					t.Errorf("GatewayCert reported %v: TrustCert got expected %q, want %q", reported, got, tc.want)
				}
				if cc := decode[model.ConfigChange](t, rec); cc.After != testNewCert {
					t.Errorf("change = %+v", cc)
				}
			}
		})
	}
}

// What waits for confirmation is the monitor's certificate state (Status.GatewayCert): nothing
// pending is a 404 and another certificate than the reviewed one a 409, both without asking
// the monitor to change anything.
func TestTrustCertAnswersFromTheMonitorsCertificateState(t *testing.T) {
	t.Run("nothing is pending", func(t *testing.T) {
		hs := newHarness(t)
		setGatewayCert(hs, &model.GatewayCertState{Pinned: testPinnedCert})
		for _, body := range []string{`{"sha256":"` + testNewCert + `"}`, `{}`, ``} {
			if msg := wantJSONError(t, hs.post(trustURL, body), http.StatusNotFound); msg != msgNoPendingCert {
				t.Errorf("%s: message = %q, want %q", body, msg, msgNoPendingCert)
			}
		}
		if n := hs.actions.trustCount(); n != 0 {
			t.Errorf("the monitor was asked to trust a certificate although none is pending (%d calls)", n)
		}
	})
	t.Run("another certificate is pending", func(t *testing.T) {
		hs := newHarness(t)
		withPendingCert(hs, testNewCert)
		msg := wantJSONError(t, hs.post(trustURL, `{"sha256":"`+testPinnedCert+`"}`), http.StatusConflict)
		wantContains(t, msg, "not confirmed", "now SHA-256 "+testNewCert, "not the one you reviewed ("+testPinnedCert+")")
		if n := hs.actions.trustCount(); n != 0 {
			t.Errorf("the monitor was asked to trust a certificate the operator did not review (%d calls)", n)
		}
	})
	t.Run("the reviewed certificate is pending", func(t *testing.T) {
		hs := newHarness(t)
		withPendingCert(hs, testNewCert)
		wantStatus(t, hs.post(trustURL, `{"sha256":"`+groupFP(testNewCert)+`"}`), http.StatusOK)
		if _, got := hs.actions.trustState(); !slices.Equal(got, []string{testNewCert}) {
			t.Errorf("TrustCert got expected %q", got)
		}
	})
	t.Run("pending as the monitor spells it", func(t *testing.T) {
		hs := newHarness(t)
		withPendingCert(hs, testNewCert)
		setGatewayCert(hs, &model.GatewayCertState{Pinned: testPinnedCert, Pending: " " + strings.ToUpper(testNewCert), Seq: 9})
		wantStatus(t, hs.post(trustURL, `{"sha256":"`+testNewCert+`"}`), http.StatusOK)
	})
}

// Without Status.GatewayCert (an older status source, or none at all) the web layer cannot tell
// what is pending, and the condition's wording is not parsed for it: the monitor compares the
// reviewed fingerprint under its own lock and refuses a mismatch (ErrBusy), answered 409.
func TestTrustCertWithoutCertificateStateTheMonitorDecides(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(hs *harness)
	}{
		{"no certificate state", func(hs *harness) {}},
		{"condition and record only", func(hs *harness) {
			withPendingCert(hs, testNewCert)
			setGatewayCert(hs, nil)
		}},
		{"no status source", func(hs *harness) { hs.srv.status = nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hs := newHarness(t)
			tc.setup(hs)
			msg := wantJSONError(t, hs.post(trustURL, `{"sha256":"`+testPinnedCert+`"}`), http.StatusConflict)
			wantContains(t, msg, "not confirmed", "not the one you reviewed", testPinnedCert)
			wantStatus(t, hs.post(trustURL, `{"sha256":"`+testNewCert+`"}`), http.StatusOK)
			if _, got := hs.actions.trustState(); !slices.Equal(got, []string{testPinnedCert, testNewCert}) {
				t.Errorf("TrustCert got expected %q", got)
			}
		})
	}
}

// The certificate can change after the page was loaded and after the web layer looked at the
// status. The monitor compares the reviewed fingerprint under its own lock and refuses; the
// answer names the certificate waiting now and says nothing about being "busy".
func TestTrustCertMonitorRefusesACertificateThatChangedMeanwhile(t *testing.T) {
	other := strings.Repeat("ef", 32)
	hs := newHarness(t)
	withPendingCert(hs, testNewCert)
	hs.actions.trustFn = func(expected string) (model.ConfigChange, error) {
		// Meanwhile the gateway presented yet another certificate.
		setGatewayCert(hs, &model.GatewayCertState{Pinned: testPinnedCert, Pending: other, Since: "2026-10-05T03:21:00Z", Seq: 99})
		return model.ConfigChange{}, fmt.Errorf("the gateway certificate waiting for confirmation is SHA-256 %s, not %s: %w", other, expected, contracts.ErrBusy)
	}
	rec := hs.post(trustURL, `{"sha256":"`+testNewCert+`"}`)
	msg := wantJSONError(t, rec, http.StatusConflict)
	wantContains(t, msg, "certificate was not confirmed", "now SHA-256 "+other, "not the one you reviewed ("+testNewCert+")",
		"confirm it only if you recognise it")
	if strings.Contains(msg, "busy") {
		t.Errorf("a refused certificate is reported as a busy monitor: %q", msg)
	}
	if strings.Contains(rec.Body.String(), `"change"`) {
		t.Errorf("nothing changed, but the answer carries a change: %s", rec.Body.String())
	}
	if _, got := hs.actions.trustState(); !slices.Equal(got, []string{testNewCert}) {
		t.Errorf("TrustCert got expected %q", got)
	}

	// Nothing waits any more by the time the refusal is answered: still refused, still clear.
	hs = newHarness(t)
	withPendingCert(hs, testNewCert)
	hs.actions.trustFn = func(expected string) (model.ConfigChange, error) {
		setGatewayCert(hs, &model.GatewayCertState{Pinned: testPinnedCert})
		return model.ConfigChange{}, fmt.Errorf("certificate mismatch: %w", contracts.ErrBusy)
	}
	msg = wantJSONError(t, hs.post(trustURL, `{"sha256":"`+testNewCert+`"}`), http.StatusConflict)
	wantContains(t, msg, "not confirmed", "not the one you reviewed", testNewCert, "Reload the page", "certificate mismatch")
}

// What the monitor did is reported as it happened. That includes, as a defence, a confirmation
// the monitor reports as done for another certificate than the reviewed one (it compares under
// its lock, so this would be a defect of the monitor).
func TestTrustCertReportsWhatHappened(t *testing.T) {
	other := strings.Repeat("ef", 32)
	for _, tc := range []struct {
		name     string
		change   model.ConfigChange
		err      error
		code     int
		contains []string
		change2  bool // the response carries the change
	}{
		{"a different certificate was trusted", model.ConfigChange{Target: "monitor", Before: testPinnedCert, After: other, Result: "applied"}, nil,
			409, []string{"a different certificate was trusted", other, testNewCert, "stop att-monitor"}, true},
		{"a different certificate was trusted, configuration not saved", model.ConfigChange{Target: "monitor", Before: testPinnedCert, After: other,
			Result: "applied until the monitor restarts: the configuration could not be saved: disk full"}, errors.New("save config: disk full"),
			409, []string{"a different certificate was trusted", other, testNewCert, "save config: disk full"}, true},
		{"trusted without saying which", model.ConfigChange{Target: "monitor", Before: testPinnedCert, Result: "applied"}, nil,
			409, []string{"not which one", testNewCert, "Gateway page"}, true},
		{"trusted, configuration not saved", model.ConfigChange{Target: "monitor", Before: testPinnedCert, After: testNewCert,
			Result: "applied until the monitor restarts: the configuration could not be saved: disk full"}, errors.New("save config: disk full"),
			500, []string{"is trusted", "applied until the monitor restarts", "disk full"}, true},
		{"failed with a change", model.ConfigChange{Target: "monitor", Before: testPinnedCert, After: other, Result: "failed: config locked"},
			errors.New("config locked"), 500, []string{"config locked"}, true},
		{"applied but not recorded", model.ConfigChange{}, fmt.Errorf("append config_change: disk full: %w", contracts.ErrNotRecorded),
			500, []string{"applied but could not be recorded", "disk full"}, false},
		{"not recorded wins over not found", model.ConfigChange{}, errors.Join(contracts.ErrNotFound, contracts.ErrNotRecorded),
			500, []string{"applied but could not be recorded"}, false},
		{"nothing pending at the monitor", model.ConfigChange{}, fmt.Errorf("no changed gateway certificate is waiting: %w", contracts.ErrNotFound),
			404, []string{msgNoPendingCert}, false},
		{"unavailable", model.ConfigChange{}, fmt.Errorf("monitor stopping: %w", contracts.ErrUnavailable), 503, []string{"monitor stopping"}, false},
		// Busy although the reviewed certificate is still the pending one: not a refusal of the
		// certificate, so the monitor's own words are passed on.
		{"busy", model.ConfigChange{}, fmt.Errorf("another confirmation: %w", contracts.ErrBusy), 409, []string{"another confirmation"}, false},
		{"unknown failure", model.ConfigChange{}, errors.New("ledger: segment unreadable"), 500, []string{"segment unreadable"}, false},
		{"timeout", model.ConfigChange{}, context.DeadlineExceeded, 504, []string{"timed out"}, false},
		{"cancelled", model.ConfigChange{}, context.Canceled, 503, []string{"cancelled"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hs := newHarness(t)
			withPendingCert(hs, testNewCert)
			hs.actions.trustChange, hs.actions.trustErr = tc.change, tc.err
			rec := hs.post(trustURL, `{"sha256":"`+testNewCert+`"}`)
			wantStatus(t, rec, tc.code)
			ce := decode[ConfigChangeError](t, rec)
			wantContains(t, ce.Error, tc.contains...)
			if (ce.Change != nil) != tc.change2 || (ce.Change != nil && *ce.Change != tc.change) {
				t.Errorf("change in the response = %+v", ce.Change)
			}
		})
	}

	// Without a reviewed fingerprint there is nothing to compare: what the monitor trusted is
	// reported as done.
	hs := newHarness(t)
	hs.actions.trustChange = model.ConfigChange{Target: "monitor", Before: testPinnedCert, After: other, Result: "applied"}
	if cc := decode[model.ConfigChange](t, hs.post(trustURL, `{}`)); cc.After != other {
		t.Errorf("change = %+v", cc)
	}
}

// Only one authenticated gateway operation at a time: a confirmation and a setting change
// exclude each other.
func TestTrustCertIsSingleFlightWithGatewayChanges(t *testing.T) {
	hs := newHarness(t)
	hs.actions.trustIn = make(chan struct{}, 1)
	hs.actions.trustGate = make(chan struct{})
	done := make(chan int, 1)
	go func() { done <- hs.post(trustURL, `{}`).Code }()
	<-hs.actions.trustIn
	wantJSONError(t, hs.post(trustURL, `{}`), http.StatusConflict)
	wantJSONError(t, hs.post("/api/gateway/notification", `{"enabled":false}`), http.StatusConflict)
	close(hs.actions.trustGate)
	if code := <-done; code != http.StatusOK {
		t.Fatalf("first confirmation = %d", code)
	}
	if n := len(hs.actions.notifCalls); n != 0 {
		t.Errorf("a setting change ran during the confirmation")
	}
	wantStatus(t, hs.post("/api/gateway/notification", `{"enabled":false}`), http.StatusOK)
}

// Closing the browser tab must not interrupt a confirmation half-way.
func TestTrustCertSurvivesClientDisconnect(t *testing.T) {
	hs := newHarness(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	wantStatus(t, hs.serve(hs.request(http.MethodPost, trustURL, strings.NewReader(`{}`), nil).WithContext(ctx)), http.StatusOK)
	if hs.actions.trustCtxErr != nil {
		t.Fatalf("TrustCert saw a cancelled context: %v", hs.actions.trustCtxErr)
	}
}

// ----------------------------------------------------------------------------- error mapping

// Every endpoint that passes on a dependency's error maps the contracts' sentinels the same
// way (errors.Is, so wrapped errors count): docs/DESIGN.md §12.
func TestErrorSentinelMapping(t *testing.T) {
	cases := []struct {
		name       string
		err        error
		code       int
		contains   string
		retryAfter string
	}{
		{"busy", fmt.Errorf("an anchoring round is already running: %w", contracts.ErrBusy), 409, "already running", ""},
		{"rate limited", fmt.Errorf("too many requests: %w", contracts.ErrRateLimited), 429, "too many requests", ""},
		{"unavailable", fmt.Errorf("anchoring is disabled: %w", contracts.ErrUnavailable), 503, "anchoring is disabled", ""},
		{"sessions full", fmt.Errorf("login: %w", contracts.ErrGatewaySessionsFull), 503, "all of its web sessions are in use", "300"},
		{"login rejected", fmt.Errorf("login: %w", contracts.ErrGatewayAuth), 502, "rejected the stored device access code", ""},
		{"logins paused", fmt.Errorf("login: %w", contracts.ErrGatewayAuthLocked), 503, "logins are paused after repeated rejected access codes", ""},
		{"login throttled", fmt.Errorf("login: %w", contracts.ErrGatewayLoginThrottled), 503, "at most one per minute", "60"},
		{"no access code", fmt.Errorf("check: %w", contracts.ErrGatewayNoAccessCode), 503, "att-monitor set-access-code", ""},
		{"certificate rejected", fmt.Errorf("login: %w", contracts.ErrGatewayCertRejected), 409, "confirm the gateway certificate first", ""},
		{"not recorded", fmt.Errorf("append: disk full: %w", contracts.ErrNotRecorded), 500, "applied but could not be recorded", ""},
		{"not recorded wins", errors.Join(contracts.ErrGatewaySessionsFull, contracts.ErrNotRecorded), 500, "applied but could not be recorded", ""},
		// The ledger refuses every write after a failed one until the service restarts and
		// reopens it: the operator must learn that nothing can be recorded now, and why.
		{"ledger broken", fmt.Errorf("append operator_note: %w", contracts.ErrLedgerBroken), 503, "nothing can be recorded until att-monitor restarts", ""},
		{"ledger broken keeps the cause", fmt.Errorf("append operator_note: %w", contracts.ErrLedgerBroken), 503, "Details: append operator_note", ""},
		{"not recorded wins over a broken ledger", errors.Join(contracts.ErrLedgerBroken, contracts.ErrNotRecorded), 500, "applied but could not be recorded", ""},
		{"locked wins over rejected", errors.Join(contracts.ErrGatewayAuth, contracts.ErrGatewayAuthLocked), 503, "logins are paused", ""},
		{"message keeps the cause", fmt.Errorf("gateway 192.168.1.254: %w", contracts.ErrGatewayAuth), 502, "Details: gateway 192.168.1.254", ""},
	}
	endpoints := []struct {
		name string
		set  func(hs *harness, err error)
		call func(hs *harness) *httptest.ResponseRecorder
	}{
		{"note", func(hs *harness, err error) { hs.actions.noteErr = err },
			func(hs *harness) *httptest.ResponseRecorder { return hs.post("/api/notes", `{"text":"x"}`) }},
		{"gateway notification", func(hs *harness, err error) { hs.srv.actions = emptyChangeActions{&fakeActions{notifErr: err}} },
			func(hs *harness) *httptest.ResponseRecorder {
				return hs.post("/api/gateway/notification", `{"enabled":false}`)
			}},
		{"trust-cert", func(hs *harness, err error) { hs.actions.trustErr = err },
			func(hs *harness) *httptest.ResponseRecorder { return hs.post(trustURL, `{}`) }},
		{"anchor", func(hs *harness, err error) { hs.actions.anchorErr = err },
			func(hs *harness) *httptest.ResponseRecorder { return hs.post("/api/anchor", "") }},
		{"export", func(hs *harness, err error) { hs.exporter.buildErr = err },
			func(hs *harness) *httptest.ResponseRecorder {
				return hs.post("/api/exports", `{"incident_id":"INC-1"}`)
			}},
		{"verify", func(hs *harness, err error) { hs.verifier.err = err },
			func(hs *harness) *httptest.ResponseRecorder { return hs.post("/api/verify", "") }},
		{"series", func(hs *harness, err error) { hs.status.seriesErr = err },
			func(hs *harness) *httptest.ResponseRecorder { return hs.get("/api/series?range=1h") }},
	}
	for _, ep := range endpoints {
		for _, tc := range cases {
			t.Run(ep.name+"/"+tc.name, func(t *testing.T) {
				hs := newHarness(t)
				ep.set(hs, tc.err)
				rec := ep.call(hs)
				msg := wantJSONError(t, rec, tc.code)
				if !strings.Contains(msg, tc.contains) {
					t.Errorf("message %q does not contain %q", msg, tc.contains)
				}
				if got := rec.Header().Get("Retry-After"); got != tc.retryAfter {
					t.Errorf("Retry-After = %q, want %q", got, tc.retryAfter)
				}
				assertSecurityHeaders(t, rec.Header(), false)
			})
		}
	}
}

// Errors outside the contracts keep their previous answers.
func TestUnclassifiedErrorsKeepTheirStatus(t *testing.T) {
	hs := newHarness(t)
	hs.srv.actions = emptyChangeActions{&fakeActions{notifErr: errors.New("gateway: all web server sessions are in use")}}
	if msg := wantJSONError(t, hs.post("/api/gateway/notification", `{"enabled":false}`), http.StatusBadGateway); msg != "gateway: all web server sessions are in use" {
		t.Errorf("notification message = %q", msg)
	}
	hs = newHarness(t)
	hs.actions.anchorErr = errors.New("freetsa.org: timeout")
	if msg := wantJSONError(t, hs.post("/api/anchor", ""), http.StatusBadGateway); msg != "anchor: freetsa.org: timeout" {
		t.Errorf("anchor message = %q", msg)
	}
	hs = newHarness(t)
	hs.actions.noteErr = errors.New("ledger closed")
	if msg := wantJSONError(t, hs.post("/api/notes", `{"text":"x"}`), http.StatusInternalServerError); msg != "note: ledger closed" {
		t.Errorf("note message = %q", msg)
	}
	// A gateway change the gateway reported as made stays a 500 whatever the error.
	hs = newHarness(t)
	hs.srv.actions = fixedChangeActions{fakeActions: &fakeActions{}, change: model.ConfigChange{Result: "verified"},
		err: fmt.Errorf("record: %w", contracts.ErrUnavailable)}
	if msg := wantJSONError2(t, hs.post("/api/gateway/notification", `{"enabled":false}`), http.StatusInternalServerError); !strings.Contains(msg, "reports the setting as changed") {
		t.Errorf("message = %q", msg)
	}
}

// wantJSONError2 is wantJSONError for bodies that may carry a "change" next to "error".
func wantJSONError2(t *testing.T, rec *httptest.ResponseRecorder, code int) string {
	t.Helper()
	wantStatus(t, rec, code)
	return decode[ConfigChangeError](t, rec).Error
}
