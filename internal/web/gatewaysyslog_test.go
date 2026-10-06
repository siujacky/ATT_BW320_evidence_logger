package web

// The operator's control of the gateway's Syslog page (docs/syslog-snmp-traffic.md §3.1, phase
// 2): POST /api/gateway/syslog, guarded and answered like POST /api/gateway/notification, and
// the dashboard's "Send the gateway’s log to this PC" / "Stop sending" on the Syslog page and the
// Overview's syslog card, rendered by the real script from the demo world.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"attmonitor/internal/contracts"
	"attmonitor/internal/model"
)

const gwSyslogURL = "/api/gateway/syslog"

func TestGatewaySyslogEndpoint(t *testing.T) {
	hs := newHarness(t)
	// From the dashboard (a browser sends Origin): the change the monitor recorded.
	rec := hs.serve(hs.request(http.MethodPost, gwSyslogURL, strings.NewReader(`{"enabled":true}`), map[string]string{"Origin": testOrigin}))
	wantStatus(t, rec, http.StatusOK)
	cc := decode[model.ConfigChange](t, rec)
	if cc.Target != "gateway" || cc.After != "on -> 192.168.1.71:514, level Notice" || cc.Actor != "operator via web" || cc.Result != "verified" {
		t.Errorf("change = %+v", cc)
	}
	// From the CLI; and switching it off.
	wantStatus(t, hs.post(gwSyslogURL, `{"enabled":false,"client":"cli"}`), http.StatusOK)
	wantStatus(t, hs.post(gwSyslogURL, `{"enabled":true}`), http.StatusOK)
	calls := hs.syslogCtl.gwCallList()
	var got []string
	for i, c := range calls {
		got = append(got, fmt.Sprintf("%v|%s", c.enabled, c.actor))
		// Detached from the request, with the notification setting's time limit.
		if c.ctxErr != nil || c.deadline <= notificationTimeout-time.Minute || c.deadline > notificationTimeout {
			t.Errorf("call %d: context error %v, %v left", i, c.ctxErr, c.deadline)
		}
	}
	if want := []string{"true|operator via web", "false|operator via cli", "true|operator via cli"}; !slices.Equal(got, want) {
		t.Errorf("calls = %q, want %q", got, want)
	}
	if gatewaySyslogTimeout != notificationTimeout {
		t.Errorf("the change has %v, the notification setting %v", gatewaySyslogTimeout, notificationTimeout)
	}
	// Nothing else of the syslog control was asked.
	if n := len(hs.syslogCtl.callList()); n != 0 {
		t.Errorf("%d retention changes", n)
	}

	bad := []struct {
		name, body, ctype string
		code              int
		contains          string
	}{
		{"empty object", `{}`, "", 400, "enabled (true or false) is required"},
		{"null", `{"enabled":null}`, "", 400, "enabled"},
		{"string", `{"enabled":"true"}`, "", 400, "invalid JSON body"},
		{"number", `{"enabled":1}`, "", 400, "invalid JSON body"},
		{"unknown field", `{"enabled":true,"server":"192.168.1.20"}`, "", 400, "unknown field"},
		{"bad client", `{"enabled":true,"client":"monitor"}`, "", 400, "client"},
		{"not an object", `[true]`, "", 400, "invalid JSON body"},
		{"trailing data", `{"enabled":true}{"enabled":false}`, "", 400, "exactly one JSON object"},
		{"empty body", ``, "", 400, "must be a JSON object"},
		{"invalid UTF-8", "{\"enabled\":true,\"client\":\"\xff\"}", "", 400, "valid UTF-8"},
		{"form content type", `enabled=true`, "application/x-www-form-urlencoded", 415, "application/json"},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			before := len(hs.syslogCtl.gwCallList())
			hdr := map[string]string{}
			if tc.ctype != "" {
				hdr["Content-Type"] = tc.ctype
			}
			msg := wantJSONError(t, hs.serve(hs.request(http.MethodPost, gwSyslogURL, strings.NewReader(tc.body), hdr)), tc.code)
			if !strings.Contains(msg, tc.contains) {
				t.Errorf("message %q does not say %q", msg, tc.contains)
			}
			if len(hs.syslogCtl.gwCallList()) != before {
				t.Error("an invalid request reached SetGatewaySyslog")
			}
		})
	}
	// A missing Content-Type is accepted (CLI clients).
	wantStatus(t, hs.serve(hs.request(http.MethodPost, gwSyslogURL, strings.NewReader(`{"enabled":true}`), map[string]string{"Content-Type": ""})), http.StatusOK)
}

// A failure is answered like one of the notification setting (gatewayChangeError): 502 when
// the gateway failed, 500 when the gateway took the change and what came after failed, the
// sentinels as everywhere; the answer carries the change the monitor reported, if any.
func TestGatewaySyslogErrors(t *testing.T) {
	verified := model.ConfigChange{Target: "gateway", What: "syslog.ha", Before: "off", After: "on -> 192.168.1.71:514, level Notice", Actor: "operator via cli", Result: "verified"}
	failed := verified
	failed.Result = "failed: gateway: POST syslog.ha (Update): HTTP 500; Save not posted"
	tests := []struct {
		name       string
		change     model.ConfigChange
		err        error
		code       int
		contains   string
		retryAfter string
	}{
		{"gateway failed", failed, errors.New("gateway: POST syslog.ha (Update): HTTP 500; Save not posted"), 502, "gateway: POST syslog.ha (Update): HTTP 500; Save not posted", ""},
		{"not applied", failed, errors.New("gateway: setting not applied: Syslog reads off (wanted on) after saving"), 502, "Syslog reads off (wanted on)", ""},
		{"page not understood", model.ConfigChange{}, errors.New("gateway: Syslog page not understood: no control labelled \"Log Level\"; nothing posted"), 502, "nothing posted", ""},
		{"taken, not recorded", verified, fmt.Errorf("append config_change: disk full: %w", contracts.ErrNotRecorded), 500,
			"the gateway reports the setting as changed (verified), but the change could not be completed: append config_change: disk full", ""},
		{"taken, config not saved", verified, errors.New("save config: access denied"), 500, "the gateway reports the setting as changed (verified)", ""},
		{"already so, config not saved", model.ConfigChange{Target: "gateway", What: "syslog.ha", Before: "off", After: "off", Actor: "operator via cli",
			Result: "unchanged: the gateway's Syslog is already off"}, errors.New("gateway.enforce_syslog was set to false but could not be saved"), 500,
			"the gateway's setting is already as asked (unchanged: the gateway's Syslog is already off), but the change could not be completed: gateway.enforce_syslog was set to false", ""},
		{"not recorded, no change", model.ConfigChange{}, fmt.Errorf("append: %w", contracts.ErrNotRecorded), 500, "applied but could not be recorded (gateway Syslog setting change)", ""},
		{"sessions full", failed, fmt.Errorf("login: %w", contracts.ErrGatewaySessionsFull), 503, "all of its web sessions are in use", "300"},
		{"throttled", model.ConfigChange{}, fmt.Errorf("login: %w", contracts.ErrGatewayLoginThrottled), 503, "at most one per minute", "60"},
		{"rejected code", failed, fmt.Errorf("login: %w", contracts.ErrGatewayAuth), 502, "rejected the stored device access code", ""},
		{"no access code", model.ConfigChange{}, fmt.Errorf("syslog: %w", contracts.ErrGatewayNoAccessCode), 503, "att-monitor set-access-code", ""},
		{"certificate", model.ConfigChange{}, fmt.Errorf("login: %w", contracts.ErrGatewayCertRejected), 409, "confirm the gateway certificate first", ""},
		{"busy", model.ConfigChange{}, fmt.Errorf("a gateway settings check is running: %w", contracts.ErrBusy), 409, "gateway Syslog setting change: a gateway settings check is running", ""},
		{"unavailable", model.ConfigChange{}, fmt.Errorf("this computer's address toward the gateway is not known yet: %w", contracts.ErrUnavailable), 503, "address toward the gateway is not known yet", ""},
		{"ledger broken", model.ConfigChange{}, fmt.Errorf("append: %w", contracts.ErrLedgerBroken), 503, "nothing can be recorded until att-monitor restarts", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			hs := newHarness(t)
			hs.syslogCtl.gwChange, hs.syslogCtl.gwErr = tc.change, tc.err
			rec := hs.post(gwSyslogURL, `{"enabled":true}`)
			wantStatus(t, rec, tc.code)
			e := decode[ConfigChangeError](t, rec)
			if !strings.Contains(e.Error, tc.contains) {
				t.Errorf("error %q does not say %q", e.Error, tc.contains)
			}
			if wantCC := tc.change != (model.ConfigChange{}); (e.Change != nil) != wantCC || (wantCC && *e.Change != tc.change) {
				t.Errorf("change = %+v, want %+v", e.Change, tc.change)
			}
			if got := rec.Header().Get("Retry-After"); got != tc.retryAfter {
				t.Errorf("Retry-After = %q, want %q", got, tc.retryAfter)
			}
			assertSecurityHeaders(t, rec.Header(), false)
		})
	}

	// The same failures through the notification setting get the same answers (one mapping).
	for _, tc := range tests {
		hs := newHarness(t)
		hs.syslogCtl.gwChange, hs.syslogCtl.gwErr = tc.change, tc.err
		hs.srv.actions = fixedChangeActions{fakeActions: &fakeActions{}, change: tc.change, err: tc.err}
		a, b := hs.post(gwSyslogURL, `{"enabled":true}`), hs.post("/api/gateway/notification", `{"enabled":false}`)
		ea, eb := decode[ConfigChangeError](t, a), decode[ConfigChangeError](t, b)
		norm := strings.NewReplacer("gateway Syslog setting change", "OP", "gateway setting change", "OP")
		if a.Code != b.Code || norm.Replace(ea.Error) != norm.Replace(eb.Error) || a.Header().Get("Retry-After") != b.Header().Get("Retry-After") {
			t.Errorf("%s: syslog %d %q, notification %d %q", tc.name, a.Code, ea.Error, b.Code, eb.Error)
		}
	}

	// Without a syslog control: 404, as JSON, for any body.
	hs := newHarness(t)
	hs.srv.syslogCtl = nil
	for _, body := range []string{`{"enabled":true}`, `{`, ``} {
		if msg := wantJSONError(t, hs.post(gwSyslogURL, body), http.StatusNotFound); !strings.Contains(msg, "the gateway's Syslog setting cannot be changed here") {
			t.Errorf("message = %q", msg)
		}
	}
}

// POST /api/gateway/syslog logs in to the gateway and changes it: the protections of every
// state-changing endpoint apply, and none of the rejected requests reaches the monitor.
func TestGatewaySyslogProtections(t *testing.T) {
	big := `{"enabled":true,"client":"` + strings.Repeat("a", MaxBodyBytes) + `"}`
	tests := []struct {
		name string
		req  func(hs *harness) *http.Request
		code int
	}{
		{"missing header", func(hs *harness) *http.Request {
			return hs.request(http.MethodPost, gwSyslogURL, strings.NewReader(`{"enabled":true}`), map[string]string{CSRFHeader: ""})
		}, http.StatusForbidden},
		{"cross origin", func(hs *harness) *http.Request {
			return hs.request(http.MethodPost, gwSyslogURL, strings.NewReader(`{"enabled":true}`), map[string]string{"Origin": "http://evil.example"})
		}, http.StatusForbidden},
		{"null origin (sandboxed page)", func(hs *harness) *http.Request {
			return hs.request(http.MethodPost, gwSyslogURL, strings.NewReader(`{"enabled":true}`), map[string]string{"Origin": "null"})
		}, http.StatusForbidden},
		{"cross-site fetch metadata", func(hs *harness) *http.Request {
			return hs.request(http.MethodPost, gwSyslogURL, strings.NewReader(`{"enabled":true}`), map[string]string{"Sec-Fetch-Site": "cross-site"})
		}, http.StatusForbidden},
		{"foreign Host", func(hs *harness) *http.Request {
			r := hs.request(http.MethodPost, gwSyslogURL, strings.NewReader(`{"enabled":true}`), nil)
			r.Host = "evil.example:8320"
			return r
		}, http.StatusMisdirectedRequest},
		{"body over the limit", func(hs *harness) *http.Request {
			r := hs.request(http.MethodPost, gwSyslogURL, io.MultiReader(strings.NewReader(big)), nil)
			r.ContentLength = -1
			return r
		}, http.StatusRequestEntityTooLarge},
		{"GET", func(hs *harness) *http.Request { return hs.request(http.MethodGet, gwSyslogURL, nil, nil) }, http.StatusMethodNotAllowed},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			hs := newHarness(t)
			rec := hs.serve(tc.req(hs))
			wantJSONError(t, rec, tc.code)
			assertSecurityHeaders(t, rec.Header(), false)
			if tc.code == http.StatusMethodNotAllowed && rec.Header().Get("Allow") != "POST" {
				t.Errorf("Allow = %q", rec.Header().Get("Allow"))
			}
			if n := len(hs.syslogCtl.gwCallList()); n != 0 {
				t.Errorf("a rejected request reached SetGatewaySyslog (%d calls)", n)
			}
		})
	}
}

// One authenticated gateway operation at a time: a change of the Syslog setting, of the
// notification setting and a certificate confirmation exclude each other. Closing the browser
// tab does not interrupt a change half-way.
func TestGatewaySyslogIsSingleFlightAndDetached(t *testing.T) {
	hs := newHarness(t)
	hs.syslogCtl.gwIn = make(chan struct{}, 1)
	hs.syslogCtl.gwGate = make(chan struct{})
	done := make(chan int, 1)
	go func() { done <- hs.post(gwSyslogURL, `{"enabled":true}`).Code }()
	<-hs.syslogCtl.gwIn
	for _, r := range []struct{ path, body string }{{gwSyslogURL, `{"enabled":false}`}, {"/api/gateway/notification", `{"enabled":false}`}, {trustURL, `{}`}} {
		if msg := wantJSONError(t, hs.post(r.path, r.body), http.StatusConflict); msg != msgGatewayBusy {
			t.Errorf("%s while a Syslog change runs: %q", r.path, msg)
		}
	}
	close(hs.syslogCtl.gwGate)
	if code := <-done; code != http.StatusOK {
		t.Fatalf("first change = %d", code)
	}
	if calls := hs.syslogCtl.gwCallList(); len(calls) != 1 || !calls[0].enabled || len(hs.actions.notifCalls) != 0 {
		t.Errorf("calls = %+v, notification calls %v", calls, hs.actions.notifCalls)
	}
	// And the other way round: while the notification setting changes.
	hs.actions.notifIn = make(chan struct{}, 1)
	hs.actions.notifGate = make(chan struct{})
	go func() { done <- hs.post("/api/gateway/notification", `{"enabled":false}`).Code }()
	<-hs.actions.notifIn
	wantJSONError(t, hs.post(gwSyslogURL, `{"enabled":false}`), http.StatusConflict)
	close(hs.actions.notifGate)
	if code := <-done; code != http.StatusOK {
		t.Fatalf("notification change = %d", code)
	}
	wantStatus(t, hs.post(gwSyslogURL, `{"enabled":false}`), http.StatusOK)

	hs = newHarness(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	wantStatus(t, hs.serve(hs.request(http.MethodPost, gwSyslogURL, strings.NewReader(`{"enabled":true}`), nil).WithContext(ctx)), http.StatusOK)
	if calls := hs.syslogCtl.gwCallList(); len(calls) != 1 || calls[0].ctxErr != nil {
		t.Errorf("calls = %+v", calls)
	}
}

// ----------------------------------------------------------------------------- dashboard

const (
	sendButton = "Send the gateway’s log to this PC"
	stopButton = "Stop sending"
)

// buttonState returns how a view shows a button: "shown", "disabled" (shown, disabled),
// "aria-disabled" (shown, announced as unavailable, but it keeps the keyboard focus), "hidden"
// or "" (none).
func buttonState(v dashboardView, text string) string {
	for _, b := range v.Buttons {
		if b.Text != text {
			continue
		}
		switch {
		case !b.Shown:
			return "hidden"
		case b.Disabled:
			return "disabled"
		case b.AriaDisabled:
			return "aria-disabled"
		}
		return "shown"
	}
	return ""
}

// wantFocus fails the test unless the keyboard focus in the view is on the element want
// describes: "<tag>:<the start of its text>" (dashboardView.Focus).
func wantFocus(t *testing.T, rep dashboardReport, view, want string) {
	t.Helper()
	if v, ok := rep.Views[view]; !ok {
		t.Errorf("view %q was not rendered (views: %v)", view, keys(rep.Views))
	} else if !strings.HasPrefix(v.Focus, want) {
		t.Errorf("%s: the keyboard focus is on %q, want %q", view, v.Focus, want)
	}
}

// The outcome of a change of the gateway's Syslog setting, as the focus describes it.
const doneFocus = "div:Done. Recorded in the evidence ledger as a configuration change: "

// gwSyslogPosts lists the statuses of the dashboard's POST /api/gateway/syslog requests.
func gwSyslogPosts(rep dashboardReport) []int {
	var out []int
	for _, r := range rep.Requests {
		if r.Method == http.MethodPost && r.Path == gwSyslogURL {
			out = append(out, r.Status)
		}
	}
	return out
}

// demoChanges returns the config_change records of what (the gateway's Syslog page, or
// gateway.enforce_syslog) in the demo ledger that an operator made, as "before → after".
func demoChanges(t *testing.T, w *demoWorld, what string) []string {
	t.Helper()
	w.mu.Lock()
	defer w.mu.Unlock()
	var out []string
	for _, b := range w.bodies {
		var cc model.ConfigChange
		if b.Type == model.TypeConfigChange && json.Unmarshal(b.Data, &cc) == nil && cc.What == what && strings.HasPrefix(cc.Actor, "operator") {
			out = append(out, cc.Before+" → "+cc.After+" by "+cc.Actor)
		}
	}
	return out
}

// The control of the gateway's Syslog setting on the Syslog page and the Overview: each change
// is confirmed in a dialog that says what happens on the gateway, shows its progress while it
// runs and its outcome after; a cancelled dialog sends nothing; the Overview's control stays put
// (with its outcome) when the status refresh rebuilds the cards. Used from the keyboard, it
// never sends the focus back to the start of the page: the button pressed keeps it while the
// change runs (the dialog gives it back), and once that button is no longer offered the outcome
// has it.
func TestDashboardGatewaySyslogControl(t *testing.T) {
	requireNode(t)
	w := newDemoWorld(time.Now())
	rep := runDashboard(t, w, "gwsyslog")
	contains := viewChecker(t, rep)
	v := func(name string) dashboardView {
		t.Helper()
		view, ok := rep.Views[name]
		if !ok {
			t.Fatalf("view %q was not rendered (views: %v)", name, keys(rep.Views))
		}
		return view
	}

	// Kept by att-monitor and sent here: only "Stop sending" is offered.
	contains("syslog", "Receiver and gateway setting", "Kept by att-monitoryes on, sending to 192.168.1.71:514 · level Notice")
	if s, o := buttonState(v("syslog"), sendButton), buttonState(v("syslog"), stopButton); s != "hidden" || o != "shown" {
		t.Errorf("buttons while kept and sent here: send %q, stop %q", s, o)
	}
	// Stopping: the dialog says what happens on the gateway; progress while it runs.
	if len(rep.Dialogs) != 4 {
		t.Fatalf("%d dialogs, want 4: %q", len(rep.Dialogs), rep.Dialogs)
	}
	for _, want := range []string{"Stop the gateway sending its log?",
		"att-monitor will log in to the AT&T gateway with the stored access code and set Syslog to Off on its Diagnostics › Syslog page: " +
			"the gateway then sends its log to no syslog server (it sends it to 192.168.1.71:514 now).",
		"The pages before and after the change are stored as evidence, and the change is recorded in the evidence ledger.",
		"att-monitor no longer sets this setting (gateway.enforce_syslog off) until you choose “Send the gateway’s log to this PC” again"} {
		if !strings.Contains(rep.Dialogs[0], want) {
			t.Errorf("the stop dialog does not say %q:\n%s", want, rep.Dialogs[0])
		}
	}
	contains("syslog stopping", "Talking to the gateway… Logging in, changing its Syslog page and reading it back can take a minute or two.")
	// While it runs, the button says that it does nothing (aria-disabled; pressed again, it
	// opens no dialog and sends nothing) but stays enabled: a disabled button would lose the
	// focus the dialog gave back to it.
	if s := buttonState(v("syslog stopping"), stopButton); s != "aria-disabled" {
		t.Errorf("stop button while the change runs: %q", s)
	}
	wantFocus(t, rep, "syslog stopping", "button:"+stopButton)
	contains("syslog stopped", "Done. Recorded in the evidence ledger as a configuration change: "+demoSyslogWhat+
		", on -> 192.168.1.71:514, level Notice → off (verified). "+
		"The gateway sends its log to no syslog server now, and att-monitor no longer sets it.",
		"Gateway settingoff the gateway sends no syslog messages", "Kept by att-monitorno att-monitor only reads this setting",
		"att-monitor does not keep this setting (gateway.enforce_syslog is off)")
	if s, o := buttonState(v("syslog stopped"), sendButton), buttonState(v("syslog stopped"), stopButton); s != "shown" || o != "hidden" {
		t.Errorf("buttons once stopped: send %q, stop %q", s, o)
	}
	// "Stop sending" is no longer offered: the outcome has the focus.
	wantFocus(t, rep, "syslog stopped", doneFocus+demoSyslogWhat+", on -> 192.168.1.71:514, level Notice → off (verified).")
	// Cancelled: nothing sent, the outcome before stays, the button keeps the focus.
	if v("syslog cancelled").Requests != v("syslog stopped").Requests {
		t.Error("a cancelled change sent a request")
	}
	contains("syslog cancelled", "Done. Recorded in the evidence ledger")
	wantFocus(t, rep, "syslog cancelled", "button:"+sendButton)
	// Sending: what the page will be set to (the target the monitor reports: this PC's address,
	// port 514, the level chosen), and how.
	for _, d := range rep.Dialogs[1:3] {
		for _, want := range []string{"Send the gateway’s log to this PC?",
			"set its Diagnostics › Syslog page: Syslog On, Server IP Address 192.168.1.71, Server Port 514, Log Level Notice.",
			"The page enables those fields only once Syslog is On, so att-monitor first switches it on (the page’s Update), then fills them in and saves.",
			"From then on att-monitor keeps the setting"} {
			if !strings.Contains(d, want) {
				t.Errorf("the send dialog does not say %q:\n%s", want, d)
			}
		}
	}
	contains("syslog sending", "Done. Recorded in the evidence ledger as a configuration change: "+demoSyslogWhat+
		", off → on -> 192.168.1.71:514, level Notice (verified). "+
		"att-monitor keeps the gateway sending its log to this PC; new messages show on the Syslog page as they arrive.",
		"Gateway settingon sends to 192.168.1.71:514 (this PC) · level Notice", "Kept by att-monitoryes on, sending to 192.168.1.71:514 · level Notice")
	wantFocus(t, rep, "syslog sending", doneFocus+demoSyslogWhat+", off → on -> 192.168.1.71:514, level Notice (verified).")
	// The Overview's card shows the outcome too, and changes the setting the same way; its
	// control is not rebuilt by the status refresh (the harness reports that as an error).
	contains("overview sending", "Gateway syslog", "Kept by att-monitoryes", "Done. Recorded in the evidence ledger")
	if o := buttonState(v("overview sending"), stopButton); o != "shown" {
		t.Errorf("the Overview's stop button: %q", o)
	}
	contains("overview stopped", "on -> 192.168.1.71:514, level Notice → off (verified).", "Kept by att-monitorno")
	if !strings.Contains(rep.Dialogs[3], "Stop the gateway sending its log?") {
		t.Errorf("the Overview's dialog: %q", rep.Dialogs[3])
	}
	wantFocus(t, rep, "overview stopped", doneFocus+demoSyslogWhat+", on -> 192.168.1.71:514, level Notice → off (verified).")

	if posts := gwSyslogPosts(rep); !slices.Equal(posts, []int{200, 200, 200}) {
		t.Errorf("POST %s: %v", gwSyslogURL, posts)
	}
	// Each change of the page, and each change of the choice, is recorded.
	if got, want := demoChanges(t, w, demoSyslogWhat), []string{"on -> 192.168.1.71:514, level Notice → off by operator via web",
		"off → on -> 192.168.1.71:514, level Notice by operator via web", "on -> 192.168.1.71:514, level Notice → off by operator via web"}; !slices.Equal(got, want) {
		t.Errorf("recorded changes of the page %q, want %q", got, want)
	}
	if got, want := demoChanges(t, w, demoEnforceWhat), []string{"true → false by operator via web", "false → true by operator via web",
		"true → false by operator via web"}; !slices.Equal(got, want) {
		t.Errorf("recorded changes of gateway.enforce_syslog %q, want %q", got, want)
	}
	w.mu.Lock()
	enforce, gw := w.syslogEnforce, w.syslogGw
	w.mu.Unlock()
	if enforce || gw.Enabled {
		t.Errorf("after the changes: enforce %v, gateway %+v", enforce, gw)
	}
}

// A change that fails is never reported as made, and one the gateway took is never reported as
// failed; a page that already shows the choice is not reported as changed; a monitor that offers
// no such change says so and offers none.
func TestDashboardGatewaySyslogFailures(t *testing.T) {
	requireNode(t)
	t.Run("gateway", func(t *testing.T) {
		w := newDemoWorld(time.Now())
		w.mu.Lock()
		// Not kept, off, and nothing received since the service started.
		w.syslogState, w.syslogSetErr = "offquiet", demoSyslogSetErr
		w.syslogLast, w.syslogReceived = nil, 0
		w.mu.Unlock()
		rep := runDashboard(t, w, "gwsyslogon")
		viewChecker(t, rep)("syslog changed",
			"The change could not be completed or confirmed: "+demoSyslogSetErr+". (Recorded result: failed: "+demoSyslogSetErr+".)",
			// The choice is kept (the monitor tries again at its next check); the page as read,
			// and why it could not be set; the condition, with the record of the attempt.
			"Kept by att-monitoryes on, sending to 192.168.1.71:514 · level Notice",
			"Gateway settingoff the gateway sends no syslog messages", "(its Syslog setting is off); the monitor could not set it: "+demoSyslogSetErr,
			"The gateway’s Syslog page could not be set", "The monitor could not set the gateway's Syslog page to send its log to this computer",
			// Setting it failed: how to set it by hand.
			"To set it on the gateway itself: open its Diagnostics › Syslog page, set Syslog to On (the page then enables its other fields), "+
				"enter Server IP Address 192.168.1.71 and Server Port 514, and save: its messages then show here within a minute.")
		if text := rep.Views["syslog changed"].Text; strings.Contains(text, "Done.") {
			t.Error("a failed change is reported as done")
		}
		if posts := gwSyslogPosts(rep); !slices.Equal(posts, []int{http.StatusBadGateway}) {
			t.Errorf("POST %s: %v", gwSyslogURL, posts)
		}
		// It is still offered: the button keeps the focus.
		wantFocus(t, rep, "syslog changed", "button:"+sendButton)
	})
	t.Run("record", func(t *testing.T) {
		w := newDemoWorld(time.Now())
		w.mu.Lock()
		w.syslogRecordErr = "ledger: append config_change: The disk is full."
		w.mu.Unlock()
		rep := runDashboard(t, w, "gwsyslogoff")
		viewChecker(t, rep)("syslog changed", "The gateway reports the setting as changed (verified), but the change could not be completed: "+
			"the gateway's Syslog page was set (off), but the change could not be recorded: applied but not recorded in the evidence ledger: ledger: append config_change: The disk is full.")
		if text := rep.Views["syslog changed"].Text; strings.Contains(text, "could not be completed or confirmed") || strings.Contains(text, "Done.") {
			t.Error("a change the gateway took is reported as failed, or as recorded")
		}
		if posts := gwSyslogPosts(rep); !slices.Equal(posts, []int{http.StatusInternalServerError}) {
			t.Errorf("POST %s: %v", gwSyslogURL, posts)
		}
		// "Stop sending" is no longer offered (the gateway took it): the outcome has the focus.
		wantFocus(t, rep, "syslog changed", "div:The gateway reports the setting as changed (verified)")
	})
	t.Run("already so", func(t *testing.T) {
		w := newDemoWorld(time.Now())
		w.mu.Lock()
		w.syslogState = "manual" // sends here, but not kept
		w.mu.Unlock()
		rep := runDashboard(t, w, "gwsyslogon")
		viewChecker(t, rep)("syslog changed", "Already so. The gateway’s Syslog page already showed this, so it was not changed "+
			"(unchanged: the gateway already sends its log to this computer). att-monitor keeps the gateway sending its log to this PC;",
			"Kept by att-monitoryes")
		if text := rep.Views["syslog changed"].Text; strings.Contains(text, "Done.") || strings.Contains(text, "Recorded in the evidence ledger as a configuration change") {
			t.Error("a page that already showed the choice is reported as changed")
		}
		if got := demoChanges(t, w, demoSyslogWhat); len(got) != 0 {
			t.Errorf("changes of the page recorded: %q", got)
		}
		if got := demoChanges(t, w, demoEnforceWhat); !slices.Equal(got, []string{"false → true by operator via web"}) {
			t.Errorf("changes of gateway.enforce_syslog: %q", got)
		}
		wantFocus(t, rep, "syslog changed", "div:Already so. ")
	})
	t.Run("not offered", func(t *testing.T) {
		w := newDemoWorld(time.Now())
		srv := newDemoServer(t, w, nil)
		srv.syslogCtl = nil
		rep := runDashboardOn(t, srv, "gwsyslogoff")
		viewChecker(t, rep)("syslog changed", "The gateway's Syslog setting cannot be changed here: this att-monitor offers no control of it.")
		for _, b := range []string{sendButton, stopButton} {
			if s := buttonState(rep.Views["syslog changed"], b); s != "hidden" {
				t.Errorf("%s offered by a monitor without the control: %q", b, s)
			}
		}
		// Neither button is left: the focus is on what the control says instead.
		wantFocus(t, rep, "syslog changed", "div:The gateway's Syslog setting cannot be changed here")
	})
}

// While authenticated gateway actions cannot run (no access code, a changed certificate), the
// buttons are disabled and the card says why; it says how to set the page by hand.
func TestDashboardGatewaySyslogBlocked(t *testing.T) {
	requireNode(t)
	for name, set := range map[string]func(w *demoWorld){
		"no access code": func(w *demoWorld) {
			w.mu.Lock()
			w.noAccessCode = true
			w.mu.Unlock()
		},
		"certificate": func(w *demoWorld) { w.setPendingCert(demoNewCertSHA) },
	} {
		t.Run(name, func(t *testing.T) {
			w := newDemoWorld(time.Now())
			set(w)
			w.mu.Lock()
			w.syslogState = "pending" // kept, but read as off: att-monitor cannot set it now
			w.mu.Unlock()
			rep := runDashboard(t, w, "overview")
			for _, view := range []string{"overview", "syslog"} {
				v := rep.Views[view]
				for _, b := range []string{sendButton, stopButton} {
					if s := buttonState(v, b); s != "disabled" {
						t.Errorf("%s: %s is %q, want disabled", view, b, s)
					}
				}
				why := "No usable gateway access code is stored, so att-monitor can neither set nor read this setting (att-monitor set-access-code)."
				if name == "certificate" {
					why = "The gateway presented an unconfirmed TLS certificate, so att-monitor will not log in to it until the certificate is confirmed"
				}
				viewChecker(t, rep)(view, why, "To set it on the gateway itself: open its Diagnostics › Syslog page")
			}
		})
	}
}

// TestAppJSGatewaySyslogWords runs the decisions of the syslog card under Node.js: which change
// the control offers, and when the card says how to set the gateway by hand - only while the
// gateway does not send its log here and att-monitor cannot set it (setting it failed or cannot
// be done); while it merely does not keep the setting, the control is the way.
func TestAppJSGatewaySyslogWords(t *testing.T) {
	prog := jsProgram(t, nil, []string{"syslogStatus", "gwSyslogOffers", "syslogHandHint", "gatewayAuthBlock", "certPending", "certState", "findCondition", "syslogPort"})
	prog += `const on = { enabled: true, server: '192.168.1.71', port: 514 };
const cases = {
  keptOK: { enforce: true, state: 'ok', gateway: on, gateway_seq: 9 },
  keptOff: { enforce: true, state: 'off', gateway: { enabled: false }, gateway_seq: 9 },
  keptElsewhere: { enforce: true, state: 'elsewhere', gateway: on, gateway_seq: 9 },
  keptError: { enforce: true, state: 'error', problem: 'x', gateway: on, gateway_seq: 9 },
  keptNotRead: { enforce: true, state: 'unknown' },
  keptNotUnderstood: { enforce: true, state: 'unknown', gateway_seq: 9 },
  freeOK: { enforce: false, state: 'ok', gateway: on, gateway_seq: 9 },
  freeOff: { enforce: false, state: 'off', gateway: { enabled: false }, gateway_seq: 9 },
  freeElsewhere: { enforce: false, state: 'elsewhere', gateway: on, gateway_seq: 9 },
  freeNotRead: { enforce: false, state: 'unknown' },
};
const out = {};
for (const [name, sl] of Object.entries(cases)) {
  const o = gwSyslogOffers(sl);
  out[name] = [o.on, o.off, syslogHandHint({ syslog: sl }), syslogHandHint({ syslog: sl, conditions: [{ code: 'NO_ACCESS_CODE' }] }),
    syslogHandHint({ syslog: sl, gateway_cert: { pinned: 'a', pending: 'b' } })];
}
out.none = syslogHandHint({});
// The latest attempt to set the page failed (the state stays as read).
const failed = [{ code: 'SYSLOG_SETTING_FAILED' }];
out.failed = [syslogHandHint({ syslog: cases.keptOff, conditions: failed }), syslogHandHint({ syslog: cases.keptOK, conditions: failed })];
out.ports = [syslogPort({ target: { port: 1514 }, listen: ':514' }), syslogPort({ listen: '0.0.0.0:5514' }), syslogPort({})];
console.log(JSON.stringify(out));
`
	var got map[string]json.RawMessage
	if err := json.Unmarshal(runNode(t, prog), &got); err != nil {
		t.Fatal(err)
	}
	// [offers on, offers off, hand hint, … without an access code, … with a changed certificate]
	want := map[string]string{
		"keptOK":            `[false,true,false,false,false]`,
		"keptOff":           `[true,true,false,true,true]`,
		"keptElsewhere":     `[true,true,false,true,true]`,
		"keptError":         `[true,true,true,true,true]`,
		"keptNotRead":       `[true,true,false,true,true]`,
		"keptNotUnderstood": `[true,true,true,true,true]`,
		"freeOK":            `[true,true,false,false,false]`,
		"freeOff":           `[true,false,false,true,true]`,
		"freeElsewhere":     `[true,true,false,true,true]`,
		"freeNotRead":       `[true,true,false,true,true]`,
		"none":              `false`,
		"failed":            `[true,false]`,
		"ports":             `[1514,5514,514]`,
	}
	for name, w := range want {
		if g := string(got[name]); g != w {
			t.Errorf("%s = %s, want %s", name, g, w)
		}
	}
}

// TestAppJSGatewaySyslogDialog runs gwSyslogDialog under Node.js: the confirmation says what
// will happen on the gateway - the values the page gets (the target the monitor reports, else
// this PC's address and the receiver's port, and how the level is chosen), the Update round only
// when Syslog is switched on, the server the gateway sends to now when that changes, a receiver
// that is off - and what att-monitor does from then on.
func TestAppJSGatewaySyslogDialog(t *testing.T) {
	prog := jsProgram(t, nil, []string{"syslogStatus", "syslogTarget", "syslogPort", "gwSyslogDialog"})
	prog += `function h(tag, props, ...kids) { return { kids: kids.flat(Infinity).filter((k) => k != null && k !== '') }; }
const text = (n) => n == null ? '' : typeof n === 'string' ? n : n.kids.map(text).join('');
const words = (d) => ({ title: d.title, confirm: d.confirm, body: d.body.map(text).filter(Boolean) });
const target = { enabled: true, server: '192.168.1.71', port: 514, level: 'Notice' };
const other = { enabled: true, server: '192.168.1.20', port: 1514, level: 'Warning' };
console.log(JSON.stringify({
  target: words(gwSyslogDialog(true, { syslog: { state: 'off', enabled: true, target, gateway: { enabled: false } } })),
  noTarget: words(gwSyslogDialog(true, { syslog: { state: 'unknown', enabled: true, listen: '0.0.0.0:5514' }, local_link: { local_ip: '192.168.1.80' } })),
  noAddress: words(gwSyslogDialog(true, { syslog: { state: 'unknown', enabled: false } })),
  elsewhere: words(gwSyslogDialog(true, { syslog: { state: 'elsewhere', enabled: true, target, gateway: other } })),
  stop: words(gwSyslogDialog(false, { syslog: { state: 'elsewhere', gateway: other } })),
  stopOff: words(gwSyslogDialog(false, { syslog: { state: 'off', gateway: { enabled: false } } })),
}));
`
	type dialogWords struct {
		Title, Confirm string
		Body           []string
	}
	var got map[string]dialogWords
	if err := json.Unmarshal(runNode(t, prog), &got); err != nil {
		t.Fatal(err)
	}
	const (
		update   = "The page enables those fields only once Syslog is On, so att-monitor first switches it on (the page’s Update), then fills them in and saves. "
		evidence = "att-monitor then reads the page back: the change counts only if the gateway shows it. The pages before and after the change are stored as evidence, and the change is recorded in the evidence ledger."
		keeps    = "From then on att-monitor keeps the setting: it reads it in its daily settings check (also after this PC’s address changes) and sets it again whenever it differs."
		rxOff    = "This PC’s syslog receiver is off (syslog.enabled is false in config.json): the gateway’s messages are not received until it is turned on."
		set      = "att-monitor will log in to the AT&T gateway with the stored access code and set its Diagnostics › Syslog page: Syslog On, "
		level    = "Log Level as gateway.syslog_level says, else as already set while Syslog is on, else the most detailed level the page offers (not Debug)."
		stop     = "att-monitor will log in to the AT&T gateway with the stored access code and set Syslog to Off on its Diagnostics › Syslog page: the gateway then sends its log to no syslog server"
		stopKept = "att-monitor no longer sets this setting (gateway.enforce_syslog off) until you choose “Send the gateway’s log to this PC” again; it still reads it in its daily settings check. The messages received so far stay in the syslog store, within its limits."
	)
	for name, want := range map[string]dialogWords{
		"target":    {"Send the gateway’s log to this PC?", "Send the log to this PC", []string{set + "Server IP Address 192.168.1.71, Server Port 514, Log Level Notice.", update + evidence, keeps}},
		"noTarget":  {"Send the gateway’s log to this PC?", "Send the log to this PC", []string{set + "Server IP Address 192.168.1.80, Server Port 5514, " + level, update + evidence, keeps}},
		"noAddress": {"Send the gateway’s log to this PC?", "Send the log to this PC", []string{set + "Server IP Address this PC’s address toward the gateway, Server Port 514, " + level, update + evidence, keeps, rxOff}},
		// Syslog is on already (elsewhere): no Update round; where it sends now is said.
		"elsewhere": {"Send the gateway’s log to this PC?", "Send the log to this PC", []string{set + "Server IP Address 192.168.1.71, Server Port 514, Log Level Notice.",
			"The gateway sends its log to 192.168.1.20:1514 now: it will send it to this PC instead.", evidence, keeps}},
		"stop":    {"Stop the gateway sending its log?", "Stop sending", []string{stop + " (it sends it to 192.168.1.20:1514 now). " + evidence, stopKept}},
		"stopOff": {"Stop the gateway sending its log?", "Stop sending", []string{stop + ". " + evidence, stopKept}},
	} {
		if g := got[name]; g.Title != want.Title || g.Confirm != want.Confirm || !slices.Equal(g.Body, want.Body) {
			t.Errorf("%s:\n got %q\nwant %q", name, g, want)
		}
	}
}

// The words of the syslog card changed with phase 2: nothing says that att-monitor does not
// change the setting.
func TestAppJSSaysTheSettingIsKept(t *testing.T) {
	src := appJS(t)
	for _, old := range []string{"it does not change it yet", "does not change it yet", "later version"} {
		if strings.Contains(src, old) {
			t.Errorf("app.js still says %q", old)
		}
	}
	if !regexp.MustCompile(`'/api/gateway/syslog'`).MatchString(src) {
		t.Error("app.js does not post to /api/gateway/syslog")
	}
}
