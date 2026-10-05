package monitor

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"attmonitor/internal/model"
)

func setAppendErr(l *fakeLedger, err error) {
	l.mu.Lock()
	l.appendErr = err
	l.mu.Unlock()
}

func setPutErr(l *fakeLedger, err error) {
	l.mu.Lock()
	l.putErr = err
	l.mu.Unlock()
}

// TestLedgerAppendFailures: when the ledger cannot write, nothing is built on unrecorded
// facts, actions report the error, and monitoring resumes when the ledger recovers.
func TestLedgerAppendFailures(t *testing.T) {
	r := newRig(t, nil, nil)
	m := r.m
	ctx := context.Background()
	setAppendErr(r.led, errors.New("disk full"))
	bad := cyc(gwICMP(true, 1900), inet(false, false, 0))
	start := time.Now()
	for i := 0; i < 5; i++ {
		m.processCycle(ctx, start.Add(time.Duration(i)*time.Second), time.Millisecond, bad)
	}
	if m.incidentOpen() {
		t.Fatal("no incident may be opened from cycles that are not in the ledger")
	}
	if st := m.Status(); st.LastSample != nil || st.Verdict.State != model.StateUnknown {
		t.Fatalf("unrecorded cycles must not become the status: %+v", st.Verdict)
	}
	if _, err := m.Note(ctx, "x", "", "web"); err == nil {
		t.Fatal("note must fail")
	}
	if _, err := m.RecordExport(ctx, model.CustodyExport{FileName: "x.zip"}); err == nil {
		t.Fatal("export record must fail")
	}
	if _, err := m.AnchorNow(ctx, "manual"); err == nil || !strings.Contains(err.Error(), "recording anchor") {
		t.Fatalf("anchor err %v", err)
	}
	if m.takeSnapshot(ctx, trigPeriodic, nil) != nil {
		t.Fatal("an unrecorded snapshot must not be used")
	}
	if st := m.Status(); st.Gateway != nil {
		t.Fatal("unrecorded snapshot became the status")
	}
	// Recovery.
	setAppendErr(r.led, nil)
	for i := 5; i < 8; i++ {
		m.processCycle(ctx, start.Add(time.Duration(i)*time.Second), time.Millisecond, bad)
	}
	if !m.incidentOpen() {
		t.Fatal("monitoring must resume once the ledger accepts records")
	}
}

func TestBlobStoreFailure(t *testing.T) {
	r := newRig(t, nil, nil)
	m := r.m
	ctx := context.Background()
	setPutErr(r.led, errors.New("disk full"))
	if m.takeSnapshot(ctx, trigStartup, nil) == nil {
		t.Fatal("the snapshot itself must still be recorded")
	}
	recs := ofType(r.led.records(""), model.TypeGatewaySnapshot)
	s := decode[model.GatewaySnapshot](t, recs[0])
	for _, p := range s.Pages {
		if p.Stored || p.SHA256 == "" {
			t.Fatalf("page %s: stored=%v sha=%q (hash kept, not marked stored)", p.Page, p.Stored, p.SHA256)
		}
	}
	if len(recs[0].Blobs) != 0 {
		t.Fatal("no blob may be referenced")
	}
	m.checkLocalLink(ctx, true)
	l := decode[model.LocalLink](t, ofType(r.led.records(""), model.TypeLocalLink)[0])
	if l.RawSHA256 != "" {
		t.Fatal("raw output not stored → not referenced")
	}
	if _, err := m.AnchorNow(ctx, "manual"); err == nil || !strings.Contains(err.Error(), "storing token") {
		t.Fatalf("anchor err %v", err)
	}
	// Notification pages that cannot be stored do not block recording the setting.
	r.gw.notif = true
	r.cfg.Gateway.EnforceNotificationOff = false
	if err := m.checkNotification(ctx); err != nil {
		t.Fatal(err)
	}
	if evs := ofType(r.led.records(""), model.TypeGatewayEvent); len(evs) == 0 || len(evs[len(evs)-1].Blobs) != 0 {
		t.Fatal("notification event without blob")
	}
}

// TestPanicsDoNotWedgeTheMonitor: a panicking gateway client or prober is contained by the
// worker and leaves no lock held.
func TestPanicsDoNotWedgeTheMonitor(t *testing.T) {
	r := newRig(t, nil, nil)
	m := r.m
	ctx := context.Background()
	r.gw.snap = func(int, []string, string) (model.GatewaySnapshot, map[string][]byte, error) { panic("parser bug") }
	m.safely("gateway", func() { m.takeSnapshot(ctx, trigPeriodic, nil) })
	r.gw.mu.Lock()
	r.gw.snap = nil
	r.gw.mu.Unlock()
	done := make(chan *snapObs, 1)
	go func() { done <- m.takeSnapshot(ctx, trigPeriodic, nil) }()
	select {
	case s := <-done:
		if s == nil {
			t.Fatal("snapshot after a recovered panic not recorded")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("gateway lock still held after a panic")
	}

	r.pr.link = func() (model.LocalLink, []byte, error) { panic("netsh parser bug") }
	m.safely("locallink", func() { m.checkLocalLink(ctx, false) })
	r.pr.dns = func(string, string) model.DNSResult { panic("dns bug") }
	m.runServiceCheck(ctx) // per-check panics are contained inside parallel()
	sc := decode[model.ServiceCheck](t, ofType(r.led.records(""), model.TypeServiceCheck)[0])
	for _, d := range sc.DNS {
		if d.Err != "check did not complete" {
			t.Fatalf("a panicking DNS check must be recorded as incomplete: %+v", d)
		}
	}
	// State lock is free.
	got := make(chan model.Status, 1)
	go func() { got <- m.Status() }()
	select {
	case <-got:
	case <-time.After(5 * time.Second):
		t.Fatal("state lock still held")
	}
}
