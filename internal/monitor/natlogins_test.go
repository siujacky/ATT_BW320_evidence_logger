package monitor

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"attmonitor/internal/config"
	"attmonitor/internal/contracts"
	"attmonitor/internal/model"
)

// The NAT sampler's logins (docs/DESIGN.md §2: logins must stay rare): the reads that keep failing
// back off, the logins the reads cause are counted and have a budget, two reads in a row that each
// needed one make the next wait an hour, and what a run knows of them outlives it.

// loginEachRead makes the fake gateway answer every NAT read with testNATTable after a login (its
// login count raised), or - for the reads for which skip says so - in a reused session.
func loginEachRead(r *rig, skip func(n int) bool) {
	var n atomic.Int64
	r.gw.mu.Lock()
	defer r.gw.mu.Unlock()
	r.gw.natCtx = func(context.Context) (model.NATTable, []byte, error) {
		if i := int(n.Add(1)); skip == nil || !skip(i) {
			r.gw.logins.Add(1)
		}
		return testNATTable(), testNATPage, nil
	}
}

// TestNATSamplerBacksOffFailures: a read that keeps failing - other than a refusal of the login
// policy - is tried again after an interval, then two, four, ... up to two hours, and the status
// says when; a read that works ends the back-off.
func TestNATSamplerBacksOffFailures(t *testing.T) {
	ctx := context.Background()
	const interval = 10 * time.Minute
	r, _ := connRig(t, func(c *config.Config) { c.Connections.Interval = config.D(interval) })
	failing := fmt.Errorf("gateway: GET nattable.ha: unexpected HTTP status 500 Internal Server Error")
	answerNAT(r.gw, model.NATTable{}, []byte("<html>500</html>"), failing)
	for i, wait := range []time.Duration{interval, 2 * interval, 4 * interval, 8 * interval, connFailBackoffMax, connFailBackoffMax} {
		began := time.Now()
		next := r.m.sampleNAT(ctx)
		wantNext(t, fmt.Sprintf("failure %d", i+1), began, next, wait)
		if p := natProblem(r); i > 0 {
			if at := problemTime(t, p, "failed, so the next is at "); at.Sub(next).Abs() > 2*time.Second {
				t.Fatalf("failure %d: the problem says the next read is at %v, it is due at %v", i+1, at, next)
			}
		}
	}
	answerNAT(r.gw, testNATTable(), testNATPage, nil)
	r.m.sampleNAT(ctx)
	answerNAT(r.gw, model.NATTable{}, nil, failing)
	began := time.Now()
	wantNext(t, "a failure after a read that worked", began, r.m.sampleNAT(ctx), interval)
}

// TestNATSamplerLoginBudget: once the NAT reads needed 6 gateway logins within a day, the rounds
// make no read - they say why, and the status says when the reads resume and how many logins they
// needed - until the oldest of those logins is a day old.
func TestNATSamplerLoginBudget(t *testing.T) {
	ctx := context.Background()
	r, store := connRig(t, func(c *config.Config) { c.Connections.Interval = config.D(4 * time.Minute) })
	// A login every other read: no two in a row, so only the budget stops them.
	loginEachRead(r, func(n int) bool { return n%2 == 0 })
	for range 2*connLoginBudget - 1 {
		r.m.sampleNAT(ctx)
	}
	if n := natCalls(r); n != 2*connLoginBudget-1 {
		t.Fatalf("%d reads", n)
	}
	st := connStatus(t, r)
	if st.NATLogins != connLoginBudget || st.NATProblem != "" {
		t.Fatalf("status %+v after %d logins", st, connLoginBudget)
	}
	began := time.Now()
	next := r.m.sampleNAT(ctx)
	if n := natCalls(r); n != 2*connLoginBudget-1 {
		t.Fatalf("read with the login budget used up (%d reads)", n)
	}
	wantNext(t, "a round with the budget used up", began, next, 4*time.Minute)
	st = connStatus(t, r)
	mustContain(t, "the problem", st.NATProblem, "NAT reads paused: they needed 6 gateway logins within the last 24 hours (at most 6",
		"they resume at ")
	if at, ok := parseTS(st.NATNext); !ok || at.Sub(began.Add(connLoginWindow)).Abs() > time.Minute {
		t.Fatalf("the next read %q, want a day after the first login", st.NATNext)
	}
	// A day after the first login the reads resume.
	r.m.conns.locked(func() { r.m.conns.nat.logins[0] = time.Now().Add(-connLoginWindow) })
	r.m.sampleNAT(ctx)
	if nat, _ := store.reads(); natCalls(r) != 2*connLoginBudget || len(nat) != 2*connLoginBudget {
		t.Fatalf("%d reads, %d appended, once the oldest login is a day old", natCalls(r), len(nat))
	}
}

// TestNATSamplerLoginStreak: two reads in a row that each needed a login - the gateway may end its
// sessions sooner than the client assumes - make the next round wait an hour; a read in a reused
// session ends the streak.
func TestNATSamplerLoginStreak(t *testing.T) {
	ctx := context.Background()
	const interval = 4 * time.Minute
	r, _ := connRig(t, func(c *config.Config) { c.Connections.Interval = config.D(interval) })
	loginEachRead(r, func(n int) bool { return n == 4 })
	began := time.Now()
	wantNext(t, "the first read with a login", began, r.m.sampleNAT(ctx), interval)
	began = time.Now()
	wantNext(t, "the second in a row", began, r.m.sampleNAT(ctx), connLoginStreakWait)
	began = time.Now()
	wantNext(t, "the third in a row", began, r.m.sampleNAT(ctx), connLoginStreakWait)
	began = time.Now()
	wantNext(t, "a read in a reused session", began, r.m.sampleNAT(ctx), interval)
	began = time.Now()
	wantNext(t, "a read with a login after it", began, r.m.sampleNAT(ctx), interval)
}

// TestNATHeldReadAfterALogin: a read stopped for the evidence after it had logged in is not tried
// again half a minute later - which, should the login's session be lost, would log in again - but
// an interval later; one stopped before it logged in is tried again shortly.
func TestNATHeldReadAfterALogin(t *testing.T) {
	ctx := context.Background()
	const interval = time.Hour
	for _, login := range []bool{true, false} {
		r, _ := connRig(t, func(c *config.Config) { c.Connections.Interval = config.D(interval) })
		r.m.conns.natTimeout, r.m.conns.busyRetry = time.Hour, time.Minute
		entered := make(chan struct{})
		r.gw.mu.Lock()
		r.gw.natCtx = func(ctx context.Context) (model.NATTable, []byte, error) {
			if login {
				r.gw.logins.Add(1)
			}
			close(entered)
			<-ctx.Done()
			return model.NATTable{}, nil, fmt.Errorf("gateway login: verifying GET nattable: %w", ctx.Err())
		}
		r.gw.mu.Unlock()
		done := make(chan time.Time, 1)
		began := time.Now()
		go func() { done <- r.m.sampleNAT(ctx) }()
		<-entered
		r.m.processCycle(ctx, time.Now(), time.Millisecond, outageCycle())
		next := await(t, "the stopped round", done)
		want := time.Minute
		if login {
			want = interval
		}
		wantNext(t, fmt.Sprintf("a held read (login %v)", login), began, next, want)
		if p := natProblem(r); p != connSkipFailing {
			t.Fatalf("problem %q", p)
		}
	}
}

// natRigIn is a connRig whose monitor keeps its state in dir.
func natRigIn(t *testing.T, dir string) *rig {
	t.Helper()
	c := testConfig()
	c.Connections.Interval = config.D(4 * time.Minute)
	store := &fakeConnStore{usage: model.ConnStoreUsage{KeepDays: 30, KeepMB: 200}}
	r := newRigWith(t, c, nil, func(o *Options) { o.Conns, o.StateDir = store, dir })
	r.cfg.Gateway.AccessCodeProtected = "protected-blob"
	answerNAT(r.gw, testNATTable(), testNATPage, nil)
	return r
}

// TestNATSamplerStateOutlivesTheRun: the logins the NAT reads caused and a stop after a rejected
// access code are kept in the state folder; the next run starts with them - the budget is not new,
// and the rejected code is not tried again - but not with logins older than a day, and a login
// dated after the clock counts as made now.
func TestNATSamplerStateOutlivesTheRun(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	r := natRigIn(t, dir)
	loginEachRead(r, func(n int) bool { return n%2 == 0 })
	for range 3 {
		r.m.sampleNAT(ctx)
	}
	answerNAT(r.gw, model.NATTable{}, nil, fmt.Errorf("gateway: login rejected: %w", contracts.ErrGatewayAuth))
	r.m.sampleNAT(ctx)
	if n := natCalls(r); n != 4 {
		t.Fatalf("%d reads", n)
	}

	r2 := natRigIn(t, dir)
	r2.m.restoreNATState(time.Now())
	r2.m.sampleNAT(ctx)
	if n := natCalls(r2); n != 0 {
		t.Fatalf("the next run tried the rejected access code again (%d reads)", n)
	}
	st := connStatus(t, r2)
	mustContain(t, "the problem", st.NATProblem, "the gateway rejected the access code")
	if st.NATLogins != 2 {
		t.Fatalf("the next run knows of %d logins, want 2", st.NATLogins)
	}

	// Saved logins older than a day are forgotten; one dated after the clock counts as made now.
	now := time.Now()
	saved := natSaved{Version: natSavedVersion, Logins: []time.Time{now.Add(-25 * time.Hour), now.Add(-time.Hour), now.Add(48 * time.Hour)}}
	b, err := json.Marshal(saved)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, natStateFile), b, 0o600); err != nil {
		t.Fatal(err)
	}
	r3 := natRigIn(t, dir)
	r3.m.restoreNATState(now)
	var logins []time.Time
	r3.m.conns.locked(func() { logins = r3.m.conns.nat.logins })
	if len(logins) != 2 || !logins[1].Equal(now) {
		t.Fatalf("restored logins %v", logins)
	}
	// A file that is not usable is ignored.
	if err := os.WriteFile(filepath.Join(dir, natStateFile), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	r4 := natRigIn(t, dir)
	r4.m.restoreNATState(now)
	r4.m.sampleNAT(ctx)
	if n := natCalls(r4); n != 1 {
		t.Fatalf("%d reads with an unusable state file", n)
	}
}

// TestNATFirstReadWaitsForTheStartupCheck: the first NAT read of a run comes after the startup
// settings check - whose login session it reuses - also when that check waits for its floor (a
// check was made just before the restart); the status says when the read is expected meanwhile.
// Without an access code there is no check to wait for.
func TestNATFirstReadWaitsForTheStartupCheck(t *testing.T) {
	led := newFakeLedger("run-current")
	if _, err := led.Append(model.TypeGatewayEvent, model.GatewayEvent{Kind: model.GwEvNotificationSetting, After: "off"}); err != nil {
		t.Fatal(err)
	}
	c := testConfig()
	c.Connections.Interval = config.D(time.Hour)
	r := newRigWith(t, c, led, func(o *Options) { o.Conns = &fakeConnStore{} })
	r.cfg.Gateway.AccessCodeProtected = "protected-blob"
	answerNAT(r.gw, testNATTable(), testNATPage, nil)
	r.m.notifMinInterval = 500 * time.Millisecond // the startup check waits for it
	r.m.conns.natFirst = 10 * time.Millisecond
	started := time.Now()
	stop := r.start(t)
	time.Sleep(200 * time.Millisecond)
	if n := natCalls(r); n != 0 {
		t.Fatalf("%d NAT reads before the startup settings check", n)
	}
	if next, ok := parseTS(connStatus(t, r).NATNext); !ok || next.Sub(started) < 400*time.Millisecond {
		t.Fatalf("while waiting the next read is announced at %q, %v after the start", connStatus(t, r).NATNext, next.Sub(started))
	}
	waitFor(t, "the first NAT read", 10*time.Second, func() bool { return natCalls(r) > 0 })
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	nat, _ := r.gw.networkReads()
	r.gw.mu.Lock()
	checked := r.gw.notifTimes
	r.gw.mu.Unlock()
	if len(checked) == 0 || nat[0].Before(checked[0]) {
		t.Fatalf("the NAT table was read at %v, the settings checked at %v", nat[0], checked)
	}

	// Without an access code there is nothing to check: the round comes and says so.
	r2, _ := connRig(t, nil)
	r2.cfg.Gateway.AccessCodeProtected = ""
	stop2 := r2.start(t)
	waitFor(t, "a NAT round", 10*time.Second, func() bool { return natProblem(r2) == natSkipNoCode })
	if err := stop2(); err != nil {
		t.Fatal(err)
	}
}

// TestSettingsCheckRejectionStopsNATReads: when the gateway rejects the settings check's login, the
// NAT reads stop as after a rejection of their own - an attempt with the same code would only use
// up the login attempts left.
func TestSettingsCheckRejectionStopsNATReads(t *testing.T) {
	r, _ := connRig(t, nil)
	r.gw.mu.Lock()
	r.gw.notifErr = fmt.Errorf("gateway: login rejected: login page returned again (1 of 3 allowed failures within an hour): %w", contracts.ErrGatewayAuth)
	r.gw.mu.Unlock()
	stop := r.start(t)
	waitFor(t, "the NAT round", 10*time.Second, func() bool {
		return strings.Contains(natProblem(r), "the gateway rejected the access code")
	})
	time.Sleep(100 * time.Millisecond) // rounds come every 60 ms
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	if n := natCalls(r); n != 0 {
		t.Fatalf("%d NAT reads with the rejected access code", n)
	}
	if next, ok := parseTS(connStatus(t, r).NATNext); !ok || time.Until(next) < 50*time.Minute {
		t.Fatalf("the next read %q, want the end of the hour's stop", connStatus(t, r).NATNext)
	}
}
