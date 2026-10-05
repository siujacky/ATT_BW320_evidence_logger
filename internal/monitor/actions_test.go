package monitor

import (
	"context"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"attmonitor/internal/config"
	"attmonitor/internal/contracts"
	"attmonitor/internal/model"
)

func TestNote(t *testing.T) {
	r := newRig(t, nil, nil)
	ctx := context.Background()
	if _, err := r.m.Note(ctx, "   ", "me", "web"); err == nil {
		t.Fatal("empty note must fail")
	}
	if _, err := r.m.Note(ctx, strings.Repeat("x", maxNoteBytes+1), "me", "web"); err == nil {
		t.Fatal("oversized note must fail")
	}
	// Operator text is recorded exactly as sent or not at all (DESIGN \u00A712): invalid UTF-8 is
	// refused rather than silently replaced.
	if _, err := r.m.Note(ctx, "AT&T ticket 12345 opened \xff", "Alex", "web"); err == nil {
		t.Fatal("invalid UTF-8 must be refused")
	}
	if _, err := r.m.Note(ctx, "ticket", "Alex \xff", "web"); err == nil {
		t.Fatal("invalid UTF-8 in the author must be refused")
	}
	ref, err := r.m.Note(ctx, "  AT&T ticket 12345 opened \u2014 \u5DF2\u5831\u544A ", " \u738B Alex ", "")
	if err != nil {
		t.Fatal(err)
	}
	_, body, _ := r.led.Record(ref.Seq)
	n := decode[model.OperatorNote](t, body)
	if n.Text != "AT&T ticket 12345 opened \u2014 \u5DF2\u5831\u544A" || n.Author != "王 Alex" || n.Source != "unknown" {
		t.Fatalf("note %+v", n)
	}
}

func TestNoteDuringIncidentIsEvidence(t *testing.T) {
	r := newRig(t, nil, nil)
	ctx := context.Background()
	bad := cyc(gwICMP(true, 1900), inet(false, false, 0))
	for i := 0; i < 3; i++ {
		r.m.processCycle(ctx, t0.Add(time.Duration(i)*40*time.Millisecond), time.Millisecond, bad)
	}
	ref, err := r.m.Note(ctx, "called AT&T, ticket 999", "owner", "cli")
	if err != nil {
		t.Fatal(err)
	}
	st := r.m.Status()
	if st.ActiveIncident == nil {
		t.Fatal("no active incident")
	}
	found := false
	for _, e := range st.ActiveIncident.Evidence {
		found = found || (e.Seq == ref.Seq && e.Type == model.TypeOperatorNote)
	}
	if !found {
		t.Fatalf("note not attached: %+v", st.ActiveIncident.Evidence)
	}
}

func TestSetGatewayNotification(t *testing.T) {
	ctx := context.Background()
	t.Run("enable clears enforce_notification_off", func(t *testing.T) {
		r := newRig(t, nil, nil)
		r.cfg.Gateway.EnforceNotificationOff = true
		cc, err := r.m.SetGatewayNotification(ctx, true, "operator via web")
		if err != nil {
			t.Fatal(err)
		}
		if cc.Target != "gateway" || cc.What != bbeventWhat || cc.Before != "off" || cc.After != "on" || cc.Actor != "operator via web" {
			t.Fatalf("change %+v", cc)
		}
		if !strings.HasPrefix(cc.Result, "verified; monitor setting enforce_notification_off changed from true to false") {
			t.Fatalf("result %q", cc.Result)
		}
		if r.cfg.Gateway.EnforceNotificationOff || r.saved.Load() != 1 {
			t.Fatalf("enforce %v saved %d", r.cfg.Gateway.EnforceNotificationOff, r.saved.Load())
		}
		recs := ofType(r.led.records(""), model.TypeConfigChange)
		if len(recs) != 1 || len(recs[0].Blobs) != 2 {
			t.Fatalf("config_change records %+v", recs)
		}
		for _, b := range recs[0].Blobs {
			if !r.led.HasBlob(b) {
				t.Fatal("before/after page not stored")
			}
		}
		st := r.m.Status()
		if st.Notification == nil || !st.Notification.Enabled || st.Notification.Seq != recs[0].Seq {
			t.Fatalf("notification state %+v", st.Notification)
		}
		var redirect bool
		for _, c := range st.Conditions {
			redirect = redirect || (c.Code == condNotificationRedirectOn && c.Severity == "warning")
		}
		if !redirect {
			t.Fatalf("conditions %+v", st.Conditions)
		}
	})
	t.Run("disable keeps enforcement", func(t *testing.T) {
		r := newRig(t, nil, nil)
		r.gw.notif = true
		cc, err := r.m.SetGatewayNotification(ctx, false, "")
		if err != nil {
			t.Fatal(err)
		}
		if cc.Before != "on" || cc.After != "off" || cc.Result != "verified" || cc.Actor != "operator" {
			t.Fatalf("change %+v", cc)
		}
		if !r.cfg.Gateway.EnforceNotificationOff || r.saved.Load() != 0 {
			t.Fatal("disabling must not touch the monitor configuration")
		}
	})
	t.Run("disable after an operator enable re-enables enforcement", func(t *testing.T) {
		r := newRig(t, nil, nil)
		r.gw.notif = true
		r.cfg.Gateway.EnforceNotificationOff = false // an earlier "on" cleared it
		cc, err := r.m.SetGatewayNotification(ctx, false, "cli")
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(cc.Result, "verified; monitor setting enforce_notification_off changed from false to true") {
			t.Fatalf("result %q", cc.Result)
		}
		if !r.cfg.Gateway.EnforceNotificationOff || r.saved.Load() != 1 {
			t.Fatalf("enforce %v saved %d", r.cfg.Gateway.EnforceNotificationOff, r.saved.Load())
		}
	})
	t.Run("gateway failure is recorded and returned", func(t *testing.T) {
		r := newRig(t, nil, nil)
		r.gw.setErr = errors.New("all web server sessions are in use")
		cc, err := r.m.SetGatewayNotification(ctx, true, "cli")
		if err == nil || !strings.HasPrefix(cc.Result, "failed: all web server sessions are in use") {
			t.Fatalf("err %v result %q", err, cc.Result)
		}
		if !r.cfg.Gateway.EnforceNotificationOff || r.saved.Load() != 0 {
			t.Fatal("a failed change must not alter the monitor configuration")
		}
		recs := ofType(r.led.records(""), model.TypeConfigChange)
		if len(recs) != 1 {
			t.Fatal("the failed attempt is a custody fact and must be recorded")
		}
		if st := r.m.Status(); st.Notification != nil {
			t.Fatalf("state must not change on failure: %+v", st.Notification)
		}
	})
}

func TestNotificationCheckEnforcesOff(t *testing.T) {
	ctx := context.Background()
	r := newRig(t, nil, nil)
	r.cfg.Gateway.AccessCodeProtected = "protected-blob"
	r.gw.notif = true
	if err := r.m.checkNotification(ctx); err != nil {
		t.Fatal(err)
	}
	recs := r.led.records("")
	evs := ofType(recs, model.TypeGatewayEvent)
	if len(evs) != 1 {
		t.Fatalf("events %d", len(evs))
	}
	ev := decode[model.GatewayEvent](t, evs[0])
	if ev.Kind != model.GwEvNotificationSetting || ev.Before != "" || ev.After != "on" || len(evs[0].Blobs) != 1 {
		t.Fatalf("event %+v blobs %v", ev, evs[0].Blobs)
	}
	ccs := ofType(recs, model.TypeConfigChange)
	if len(ccs) != 1 {
		t.Fatalf("config changes %d", len(ccs))
	}
	cc := decode[model.ConfigChange](t, ccs[0])
	if cc.Actor != "monitor (enforce_notification_off)" || cc.Before != "on" || cc.After != "off" || cc.Result != "verified" || len(ccs[0].Blobs) != 2 {
		t.Fatalf("change %+v blobs %v", cc, ccs[0].Blobs)
	}
	if len(r.gw.setCalls) != 1 || r.gw.setCalls[0] {
		t.Fatalf("set calls %v", r.gw.setCalls)
	}
	// Second check: off, already known → nothing new.
	if err := r.m.checkNotification(ctx); err != nil {
		t.Fatal(err)
	}
	if n := len(r.led.records("")); n != len(recs) {
		t.Fatalf("unchanged setting must not be re-recorded (%d → %d records)", len(recs), n)
	}
	if st := r.m.Status(); st.Notification == nil || st.Notification.Enabled || st.Notification.Seq != ccs[0].Seq {
		t.Fatalf("state %+v", st.Notification)
	}
}

func TestNotificationCheckWithoutEnforcement(t *testing.T) {
	ctx := context.Background()
	r := newRig(t, nil, nil)
	r.cfg.Gateway.EnforceNotificationOff = false
	r.gw.notif = true
	if err := r.m.checkNotification(ctx); err != nil {
		t.Fatal(err)
	}
	if len(r.gw.setCalls) != 0 {
		t.Fatal("must not change the setting without enforcement")
	}
	st := r.m.Status()
	if st.Notification == nil || !st.Notification.Enabled {
		t.Fatalf("state %+v", st.Notification)
	}
	found := false
	for _, c := range st.Conditions {
		found = found || c.Code == condNotificationRedirectOn
	}
	if !found {
		t.Fatal("NOTIFICATION_REDIRECT_ON condition missing")
	}
	// A later change off → on is recorded with Before.
	r.gw.notif = false
	if err := r.m.checkNotification(ctx); err != nil {
		t.Fatal(err)
	}
	evs := ofType(r.led.records(""), model.TypeGatewayEvent)
	if len(evs) != 2 {
		t.Fatalf("events %d", len(evs))
	}
	if e := decode[model.GatewayEvent](t, evs[1]); e.Before != "on" || e.After != "off" {
		t.Fatalf("event %+v", e)
	}
}

func TestNotificationCheckError(t *testing.T) {
	ctx := context.Background()
	r := newRig(t, nil, nil)
	r.gw.notifErr = errors.New("all web server sessions are in use")
	if err := r.m.checkNotification(ctx); err == nil {
		t.Fatal("error expected")
	}
	if n := len(r.led.records("")); n != 1 { // genesis only
		t.Fatalf("records %d", n)
	}
	st := r.m.Status()
	if st.Notification == nil || !strings.Contains(st.Notification.Err, "sessions are in use") {
		t.Fatalf("state %+v", st.Notification)
	}
}

func TestNotificationLoopRetriesNotTooOften(t *testing.T) {
	r := newRig(t, nil, nil)
	r.cfg.Gateway.AccessCodeProtected = "protected-blob"
	r.gw.notifErr = errors.New("all web server sessions are in use")
	r.m.notifMinInterval = 300 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { r.m.notificationLoop(ctx); close(done) }()
	times := func() []time.Time {
		r.gw.mu.Lock()
		defer r.gw.mu.Unlock()
		return slices.Clone(r.gw.notifTimes)
	}
	waitFor(t, "three attempts", 10*time.Second, func() bool { return len(times()) >= 3 })
	cancel()
	<-done
	ts := times()
	for i := 1; i < len(ts); i++ {
		// The floor is measured from the end of the previous attempt, so the spacing between
		// starts can only be larger.
		if gap := ts[i].Sub(ts[i-1]); gap < 300*time.Millisecond {
			t.Fatalf("attempts %d and %d only %v apart (floor 300 ms)", i-1, i, gap)
		}
	}
}

func TestNotificationLoopSkipsWithoutAccessCode(t *testing.T) {
	r := newRig(t, nil, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	r.m.notificationLoop(ctx)
	if r.gw.notifCalls != 0 {
		t.Fatal("no authenticated request without an access code")
	}
}

func TestCertObserver(t *testing.T) {
	r := newRig(t, nil, nil)
	r.cfg.Gateway.PinnedCertSHA256 = ""
	obs := r.gw.observer
	if obs == nil {
		t.Fatal("New must install the certificate observer")
	}
	if !obs("", "aaaa") {
		t.Fatal("first certificate must be accepted")
	}
	if r.cfg.Gateway.PinnedCertSHA256 != "aaaa" || r.saved.Load() != 1 {
		t.Fatalf("pin %q saved %d", r.cfg.Gateway.PinnedCertSHA256, r.saved.Load())
	}
	if !obs("aaaa", "bbbb") {
		t.Fatal("changed certificate must be accepted")
	}
	if !obs("aaaa", "BBBB") { // same pin, different case: nothing to record
		t.Fatal("accept")
	}
	evs := ofType(r.led.records(""), model.TypeGatewayEvent)
	if len(evs) != 2 {
		t.Fatalf("events %d", len(evs))
	}
	e1, e2 := decode[model.GatewayEvent](t, evs[0]), decode[model.GatewayEvent](t, evs[1])
	if e1.Kind != model.GwEvCertPinned || e1.After != "aaaa" || !strings.Contains(e1.Detail, "trust on first use") {
		t.Fatalf("%+v", e1)
	}
	if e2.Kind != model.GwEvCertChanged || e2.Before != "aaaa" || e2.After != "bbbb" {
		t.Fatalf("%+v", e2)
	}
	if r.saved.Load() != 2 {
		t.Fatalf("saved %d", r.saved.Load())
	}
}

func TestCertObserverSaveFailure(t *testing.T) {
	cfg := testConfig()
	cfg.Gateway.PinnedCertSHA256 = "old"
	gw := &fakeGateway{}
	m, err := New(Options{Config: cfg, Ledger: newFakeLedger("r"), Gateway: gw, Prober: newFakeProber(),
		SaveConfig: func(*config.Config) error { return errors.New("access denied") }})
	if err != nil {
		t.Fatal(err)
	}
	if !gw.observer("old", "new") {
		t.Fatal("accept")
	}
	evs := ofType(m.led.(*fakeLedger).records(""), model.TypeGatewayEvent)
	if e := decode[model.GatewayEvent](t, evs[0]); !strings.Contains(e.Detail, "could not be saved: access denied") {
		t.Fatalf("%+v", e)
	}
}

func TestAnchorNowAndStatus(t *testing.T) {
	ctx := context.Background()
	r := newRig(t, nil, nil)
	anchors, err := r.m.AnchorNow(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(anchors) != 2 {
		t.Fatalf("anchors %d", len(anchors))
	}
	recs := ofType(r.led.records(""), model.TypeAnchor)
	if len(recs) != 2 {
		t.Fatalf("anchor records %d", len(recs))
	}
	for _, b := range recs {
		a := decode[model.Anchor](t, b)
		if a.Reason != "manual" || !a.Verified || !a.ChainOK || a.HeadSeq != 0 || a.Nonce != "c0ffee" || a.GenTime == "" || !r.led.HasBlob(a.TokenSHA256) || b.Blobs[0] != a.TokenSHA256 {
			t.Fatalf("anchor %+v blobs %v", a, b.Blobs)
		}
	}
	st := r.m.Status()
	// last_anchor_seq names the covered record (the head when the time-stamp was requested).
	if st.Ledger.LastAnchorTSA != "CN=http://tsa.test/b" || st.Ledger.LastAnchorSeq != decode[model.Anchor](t, recs[1]).HeadSeq || st.Ledger.HeadSeq != recs[1].Seq || st.Ledger.UnanchoredCount != 2 {
		t.Fatalf("ledger status %+v", st.Ledger)
	}
	if st.Ledger.Fingerprint != "fp-test" || st.Ledger.GenesisTS == "" || st.Ledger.DataDir == "" {
		t.Fatalf("ledger status %+v", st.Ledger)
	}

	// Export: custody record, then an anchor that covers it.
	ref, err := r.m.RecordExport(ctx, model.CustodyExport{FileName: "att-evidence_x.zip", BundleSHA256: "abc", Requester: "web 127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	all := r.led.records("")
	last := decode[model.Anchor](t, all[len(all)-1])
	if last.Reason != "export" || last.HeadSeq != ref.Seq {
		t.Fatalf("anchor after export %+v (custody seq %d)", last, ref.Seq)
	}
	if _, err := r.m.RecordExport(ctx, model.CustodyExport{}); err == nil {
		t.Fatal("export without a file name must fail")
	}
}

func TestAnchorFailuresAndUnverifiedTokens(t *testing.T) {
	ctx := context.Background()
	r := newRig(t, nil, nil)
	r.anc.fail = true
	if _, err := r.m.AnchorNow(ctx, "manual"); err == nil || !strings.Contains(err.Error(), "tsa unreachable") {
		t.Fatalf("err %v", err)
	}
	if n := len(ofType(r.led.records(""), model.TypeAnchor)); n != 0 {
		t.Fatalf("no anchor may be recorded on failure, got %d", n)
	}

	// A token that does not verify is recorded honestly as unverified and is not "last anchor".
	r2 := newRig(t, nil, nil)
	r2.m.anchorer = badTokenAnchorer{r2.anc}
	anchors, err := r2.m.AnchorNow(ctx, "manual")
	if err != nil || len(anchors) != 2 || anchors[0].Verified || anchors[0].ChainOK {
		t.Fatalf("anchors %+v err %v", anchors, err)
	}
	if st := r2.m.Status(); st.Ledger.LastAnchorTime != "" {
		t.Fatalf("unverified anchors must not count: %+v", st.Ledger)
	}

	// Disabled anchoring.
	cfg := testConfig()
	cfg.Anchoring.Enabled = false
	r3 := newRig(t, cfg, nil)
	if _, err := r3.m.AnchorNow(ctx, "manual"); err == nil {
		t.Fatal("anchoring disabled must fail")
	}
	if _, err := r3.m.RecordExport(ctx, model.CustodyExport{FileName: "x.zip"}); err != nil {
		t.Fatal("export must still be recorded without anchoring")
	}
}

type badTokenAnchorer struct{ *fakeAnchorer }

func (b badTokenAnchorer) VerifyToken(token, digest []byte) (contracts.TokenInfo, error) {
	return contracts.TokenInfo{}, errors.New("signature invalid")
}

func TestVerifyUpdatesStatus(t *testing.T) {
	cfg := testConfig()
	v := &fakeVerifier{rep: model.VerifyReport{OK: false, At: "2026-10-05T04:00:00Z", Records: 1234, FailuresTotal: 3}}
	m, err := New(Options{Config: cfg, Ledger: newFakeLedger("r"), Gateway: &fakeGateway{}, Prober: newFakeProber(), Verifier: v})
	if err != nil {
		t.Fatal(err)
	}
	rep, err := m.Verify(context.Background())
	if err != nil || rep.Records != 1234 {
		t.Fatalf("rep %+v err %v", rep, err)
	}
	lv := m.Status().Ledger.LastVerify
	if lv == nil || lv.OK || lv.Records != 1234 || lv.Failures != 3 || lv.At != "2026-10-05T04:00:00Z" {
		t.Fatalf("last verify %+v", lv)
	}
	m2, _ := New(Options{Config: cfg, Ledger: newFakeLedger("r"), Gateway: &fakeGateway{}, Prober: newFakeProber()})
	if _, err := m2.Verify(context.Background()); err == nil {
		t.Fatal("no verifier configured must fail")
	}
}

func TestNewValidation(t *testing.T) {
	cfg := testConfig()
	led := newFakeLedger("r")
	cases := []Options{
		{Ledger: led, Gateway: &fakeGateway{}, Prober: newFakeProber()},
		{Config: cfg, Gateway: &fakeGateway{}, Prober: newFakeProber()},
		{Config: cfg, Ledger: led, Prober: newFakeProber()},
		{Config: cfg, Ledger: led, Gateway: &fakeGateway{}},
	}
	for i, o := range cases {
		if _, err := New(o); err == nil {
			t.Errorf("case %d: missing dependency accepted", i)
		}
	}
	m, err := New(Options{Config: cfg, Ledger: led, Gateway: &fakeGateway{}, Prober: newFakeProber()})
	if err != nil {
		t.Fatal(err)
	}
	if m.reader == nil {
		t.Fatal("a ledger that is also a reader is used for the rebuild")
	}
	if m.anchorer != nil {
		t.Fatal("no anchorer given: anchoring disabled")
	}
	st := m.Status()
	if st.Verdict.State != model.StateUnknown || st.Conditions == nil || len(st.Stats) != 2 || st.Monitor.Mode != "console" {
		t.Fatalf("status before Run %+v", st)
	}
}

func TestStateCache(t *testing.T) {
	r := newRig(t, nil, nil)
	stop := r.start(t)
	waitFor(t, "a sample and a snapshot", 10*time.Second, func() bool {
		recs := r.led.records("")
		return len(ofType(recs, model.TypeSample)) > 0 && len(ofType(recs, model.TypeGatewaySnapshot)) > 0
	})
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	stateDir := r.m.opts.StateDir
	// A second monitor on the same ledger and state directory uses the cache.
	m2, err := New(Options{Config: testConfig(), Ledger: r.led, Gateway: &fakeGateway{}, Prober: newFakeProber(), StateDir: stateDir})
	if err != nil {
		t.Fatal(err)
	}
	c, ok := m2.loadCache()
	if !ok {
		t.Fatal("cache should be valid")
	}
	recs := r.led.records("")
	if c.Seq != recs[len(recs)-1].Seq || c.LastStopRun != "run-current" || c.LastStartRun != "run-current" || c.LastSampleTS == "" || c.LastSnapSeq == nil {
		t.Fatalf("cache %+v", c)
	}
	// The rebuilt state matches a rebuild without cache.
	m2.rebuild(time.Now())
	m3, _ := New(Options{Config: testConfig(), Ledger: r.led, Gateway: &fakeGateway{}, Prober: newFakeProber()})
	m3.rebuild(time.Now())
	if m2.st.lastStopRun != m3.st.lastStopRun || m2.st.lastSampleSeq != m3.st.lastSampleSeq || len(m2.st.points.pts) != len(m3.st.points.pts) ||
		m2.st.lastGood.Seq != m3.st.lastGood.Seq || m2.st.ispHop != "203.0.113.1" || m2.st.ispDNS != "68.94.156.9" {
		t.Fatalf("cached rebuild differs: %+v vs %+v", m2.st.lastGood, m3.st.lastGood)
	}

	// A cache that does not match the ledger is ignored.
	path := m2.cachePath()
	b, _ := os.ReadFile(path)
	tampered := strings.Replace(string(b), c.Hash, strings.Repeat("0", 64), 1)
	if err := os.WriteFile(path, []byte(tampered), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, ok := m2.loadCache(); ok {
		t.Fatal("cache with a wrong head hash must be ignored")
	}
	if err := os.WriteFile(path, []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, ok := m2.loadCache(); ok {
		t.Fatal("corrupt cache must be ignored")
	}
}

func TestRebuildRestoresState(t *testing.T) {
	led := newFakeLedger("run-current")
	prev := "run-old"
	base := time.Now().Add(-time.Hour)
	led.appendAs(prev, base, model.TypeMonitorStart, model.MonitorStart{})
	snap := okSnapshot([]string{"sysinfo"}, base)
	snapRef := led.appendAs(prev, base.Add(time.Second), model.TypeGatewaySnapshot, snap)
	led.appendAs(prev, base.Add(2*time.Second), model.TypeGatewaySnapshot, model.GatewaySnapshot{Pages: []model.PageCapture{{Page: "sysinfo", Err: "timeout"}}})
	blob, _ := led.PutBlob([]byte("token"))
	anchorRef := led.appendAs(prev, base.Add(3*time.Second), model.TypeAnchor, model.Anchor{TSAURL: "http://tsa", TSAName: "CN=TSA", HeadSeq: 2, GenTime: "2026-10-05T03:00:00Z", Verified: true, ChainOK: true, TokenSHA256: blob}, blob)
	led.appendAs(prev, base.Add(4*time.Second), model.TypeAnchor, model.Anchor{TSAURL: "http://bad", HeadSeq: 3, Verified: false})
	led.appendAs(prev, base.Add(5*time.Second), model.TypeGatewayEvent, model.GatewayEvent{Kind: model.GwEvNotificationSetting, After: "on"})
	ccRef := led.appendAs(prev, base.Add(6*time.Second), model.TypeConfigChange, model.ConfigChange{Target: "gateway", What: bbeventWhat, Before: "on", After: "off", Result: "verified"})
	led.appendAs(prev, base.Add(7*time.Second), model.TypeConfigChange, model.ConfigChange{Target: "gateway", What: bbeventWhat, Before: "off", After: "on", Result: "failed: timeout"})
	closedInc := model.Incident{ID: "INC-1", Opened: fmtTS(base.Add(-time.Hour)), Closed: fmtTS(base.Add(-50 * time.Minute)), State: model.StateISPOutage, Attribution: model.AttrProvider}
	led.appendAs(prev, base.Add(8*time.Second), model.TypeIncidentClose, closedInc)
	led.appendAs(prev, base.Add(9*time.Second), model.TypeSample, model.Sample{Started: fmtTS(base.Add(9 * time.Second)), Verdict: model.Verdict{State: model.StateOnline}, Probes: []model.ProbeResult{{Name: "gw", OK: true, RTTus: 1000}}})
	led.appendAs(prev, base.Add(10*time.Second), model.TypeMonitorStop, model.MonitorStop{Reason: "service stop"})

	r := newRig(t, nil, led)
	r.m.rebuild(time.Now())
	m := r.m
	if m.st.lastStartRun != prev || m.st.lastStopRun != prev {
		t.Fatalf("runs %q %q", m.st.lastStartRun, m.st.lastStopRun)
	}
	if m.st.lastGood == nil || m.st.lastGood.Seq != snapRef.Seq || m.st.lastSnap.Seq != snapRef.Seq+1 {
		t.Fatalf("snapshots good %+v last %+v", m.st.lastGood, m.st.lastSnap)
	}
	if m.st.ispHop != "203.0.113.1" || m.st.ispDNS != "68.94.156.9" {
		t.Fatalf("hop %q dns %q", m.st.ispHop, m.st.ispDNS)
	}
	if m.st.lastAnchor == nil || m.st.lastAnchor.Seq != anchorRef.Seq {
		t.Fatalf("anchor %+v", m.st.lastAnchor)
	}
	if m.st.notif == nil || m.st.notif.Enabled || m.st.notif.Seq != ccRef.Seq {
		t.Fatalf("notification %+v (failed changes must not count)", m.st.notif)
	}
	if _, ok := m.st.incidents["INC-1"]; !ok || len(m.st.points.pts) != 1 || len(m.st.points.opt) != 1 {
		t.Fatalf("incidents %v points %d optical %d", m.st.incidents, len(m.st.points.pts), len(m.st.points.opt))
	}
	st := m.Status()
	// The newest anchoring round (head 3) produced only an unverified anchor: it does not count
	// (the last anchor stays the trusted one) and the rebuilt status warns about it.
	if st.Gateway == nil || st.Ledger.LastAnchorTSA != "CN=TSA" || st.Ledger.LastAnchorSeq != 2 ||
		len(withoutCond(withoutCond(st.Conditions, condNoAccessCode), condAnchorUntrusted)) != 2 ||
		len(st.Conditions) != 4 {
		t.Fatalf("status %+v", st)
	}
	// The rebuilt snapshot is the baseline for event derivation and probes.
	specs := m.probeSpecs()
	var hop string
	for _, s := range specs {
		if s.Role == model.RoleISPHop {
			hop = s.Target
		}
	}
	if hop != "203.0.113.1" {
		t.Fatalf("isp hop target %q", hop)
	}
}

func TestStatusConditions(t *testing.T) {
	r := newRig(t, nil, nil)
	at := time.Now()
	s := okSnapshot([]string{"fiberstat"}, at)
	r.m.mu.Lock()
	r.m.applySnapshotLocked(&snapObs{Seq: 7, At: at, Snap: &s}, nil, nil)
	r.m.mu.Unlock()
	st := r.m.Status()
	st.Conditions = withoutCond(st.Conditions, condNoAccessCode)
	if len(st.Conditions) != 2 {
		t.Fatalf("conditions %+v", st.Conditions)
	}
	c := st.Conditions[0]
	if c.Code != "OPTICAL_RX_LOW_ALARM" || c.Severity != "critical" || c.Seq != 7 || c.Since != fmtTS(at) ||
		c.Message != "AT&T gateway reports optical receive power -31.5 dBm, below its alarm threshold -29.5 dBm" {
		t.Fatalf("%+v", c)
	}
	if w := st.Conditions[1]; w.Severity != "warning" || w.Message != "AT&T gateway reports optical receive power -31.5 dBm, below its warning threshold -29.2 dBm" {
		t.Fatalf("%+v", w)
	}
	if st.Gateway == nil || st.GatewayAt != fmtTS(at) {
		t.Fatal("latest snapshot in status")
	}
}

func TestConditionMessages(t *testing.T) {
	snap := &model.GatewaySnapshot{Fiber: &model.FiberStatus{Measures: []model.DMIMeasure{
		{Name: "Temperature", Current: i64p(85), Unit: "C", HighAlarm: model.Threshold{Active: true, Threshold: i64p(80)}},
		{Name: "Tx Power", Current: i64p(-12), Unit: "0.1dBm", LowWarn: model.Threshold{Active: true, Threshold: i64p(0)}},
		{Name: "Vcc", Current: i64p(3), Unit: "V"},
		{Name: "Tx Bias", Current: i64p(600), Unit: "mA", HighAlarm: model.Threshold{Active: true, Threshold: i64p(500)}},
	}}}
	tests := map[string]string{
		"TEMPERATURE_HIGH_ALARM":     "AT&T gateway reports optical module temperature 85 °C, above its alarm threshold 80 °C",
		"OPTICAL_TX_LOW_WARNING":     "AT&T gateway reports optical transmit power -1.2 dBm, below its warning threshold 0.0 dBm",
		"VCC_LOW_ALARM":              "AT&T gateway reports optical module supply voltage 3 V and flags it below its alarm threshold",
		"TX_BIAS_HIGH_ALARM":         "AT&T gateway reports laser bias current 600 mA, above its alarm threshold 500 mA",
		"OPTICAL_RX_HIGH_ALARM":      "AT&T gateway flags optical receive power above its alarm threshold (OPTICAL_RX_HIGH_ALARM)",
		"SOMETHING_ELSE":             "AT&T gateway flags SOMETHING_ELSE",
		"OPTICAL_RX_LOW_ALARM":       "AT&T gateway flags optical receive power below its alarm threshold (OPTICAL_RX_LOW_ALARM)",
		"TEMPERATURE_HIGH_WARN":      "AT&T gateway reports optical module temperature 85 °C and flags it above its warning threshold",
		"OPTICAL_TEMP_LOW_ALARM":     "AT&T gateway reports optical module temperature 85 °C and flags it below its alarm threshold",
		"OPTICAL_TX_BIAS_HIGH_ALARM": "AT&T gateway reports laser bias current 600 mA, above its alarm threshold 500 mA",
	}
	for code, want := range tests {
		if got := conditionMessage(code, snap); got != want {
			t.Errorf("%s:\n got  %q\n want %q", code, got, want)
		}
	}
	sev := map[string]string{"X_LOW_ALARM": "critical", "X_HIGH_WARNING": "warning", "X_LOW_WARN": "warning", "X": "info"}
	for code, want := range sev {
		if got := conditionSeverity(code); got != want {
			t.Errorf("severity %s = %s want %s", code, got, want)
		}
	}
}

func TestHijackDetectors(t *testing.T) {
	dns := []struct {
		name    string
		answers []string
		want    bool
	}{
		{"www.google.com", []string{"142.250.72.36"}, false},
		{"www.google.com", []string{gwIP}, true},
		{"www.google.com", []string{"10.0.0.1"}, true},
		{"www.google.com", []string{"127.0.0.1"}, true},
		{"www.google.com", []string{"169.254.1.1"}, true},
		{"www.google.com", []string{"::ffff:192.168.1.254"}, true},
		{"www.google.com", []string{"www.l.google.com."}, false},
		{"0123456789abcdef.invalid", nil, false},
		{"0123456789abcdef.invalid.", []string{"203.0.113.10"}, true},
	}
	for _, d := range dns {
		got, why := detectDNSHijack(d.name, d.answers, gwIP)
		if got != d.want || (got && why == "") {
			t.Errorf("dns %s %v: %v %q", d.name, d.answers, got, why)
		}
	}
	http := []struct {
		r    model.HTTPResult
		want bool
	}{
		{model.HTTPResult{RemoteAddr: "23.200.0.1:80", Status: 200}, false},
		{model.HTTPResult{RemoteAddr: gwIP + ":80", Status: 200}, true},
		{model.HTTPResult{RemoteAddr: "23.200.0.1:80", Status: 302, Location: "http://192.168.1.254/cgi-bin/redirect.ha"}, true},
		{model.HTTPResult{RemoteAddr: "23.200.0.1:80", Status: 302, Location: "http://10.1.1.1/portal"}, true},
		{model.HTTPResult{RemoteAddr: "23.200.0.1:80", Status: 302, Location: "https://www.msn.com/"}, false},
		{model.HTTPResult{Location: "::bad url"}, false},
	}
	for i, h := range http {
		if got, _ := detectHTTPHijack(h.r, gwIP); got != h.want {
			t.Errorf("http %d: %v", i, got)
		}
	}
}

func TestBBEventChecked(t *testing.T) {
	read := func(name string) []byte {
		b, err := os.ReadFile("../../testdata/gateway/" + name)
		if err != nil {
			t.Skipf("fixture %s: %v", name, err)
		}
		return b
	}
	if c, ok := bbeventChecked(read("events_checked.html")); !ok || !c {
		t.Fatalf("checked fixture: %v %v", c, ok)
	}
	if c, ok := bbeventChecked(read("events_unchecked.html")); !ok || c {
		t.Fatalf("unchecked fixture: %v %v", c, ok)
	}
	if _, ok := bbeventChecked(read("sysinfo.html")); ok {
		t.Fatal("no checkbox on sysinfo")
	}
	if _, ok := bbeventChecked(nil); ok {
		t.Fatal("empty page")
	}
	if c, ok := bbeventChecked([]byte(`<INPUT TYPE=checkbox NAME=bbevent CHECKED>`)); !ok || !c {
		t.Fatal("bare attributes")
	}
}
