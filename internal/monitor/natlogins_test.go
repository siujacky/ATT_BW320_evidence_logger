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
// login count raised), or - for the reads for which skip says so - in a reused session. A read
// that needs a login in a context that forbids one (contracts.WithoutGatewayLogin) fails with
// contracts.ErrGatewayLoginNeeded instead, as the real client does.
func loginEachRead(r *rig, skip func(n int) bool) {
	var n atomic.Int64
	r.gw.mu.Lock()
	defer r.gw.mu.Unlock()
	r.gw.natCtx = func(ctx context.Context) (model.NATTable, []byte, error) {
		if i := int(n.Add(1)); skip == nil || !skip(i) {
			if contracts.GatewayLoginForbidden(ctx) {
				return model.NATTable{}, nil, fmt.Errorf("gateway: GET nattable.ha: the session is gone: %w", contracts.ErrGatewayLoginNeeded)
			}
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

// TestNATSamplerLoginBudget: once the NAT reads needed 6 gateway logins within a day they make no
// login until the oldest of those logins is a day old: a read in the session that the gateway
// keeps goes on (the status counts the logins and notes that none is made), and a read that would
// need one makes none, says why and puts the next round off until a login may be made.
func TestNATSamplerLoginBudget(t *testing.T) {
	ctx := context.Background()
	const interval = 4 * time.Minute
	r, store := connRig(t, func(c *config.Config) { c.Connections.Interval = config.D(interval) })
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
	// Read 12 is made in read 11's session: it goes on.
	began := time.Now()
	wantNext(t, "a read in the session with the budget used up", began, r.m.sampleNAT(ctx), interval)
	if nat, _ := store.reads(); natCalls(r) != 2*connLoginBudget || len(nat) != 2*connLoginBudget {
		t.Fatalf("%d reads, %d appended: the read in the session did not go on", natCalls(r), len(nat))
	}
	st = connStatus(t, r)
	if st.NATLogins != connLoginBudget || st.NATProblem != "" {
		t.Fatalf("status %+v after the read in the session", st)
	}
	mustContain(t, "the note", st.NATNote, "the NAT reads needed 6 gateway logins within the last 24 hours (at most 6): until ",
		"they make no login")
	// Read 13 would need a login: it makes none, and the next round waits until one may be made.
	began = time.Now()
	next := r.m.sampleNAT(ctx)
	if nat, _ := store.reads(); len(nat) != 2*connLoginBudget || r.gw.logins.Load() != connLoginBudget {
		t.Fatalf("%d appended, %d logins after a read that would have needed a login", len(nat), r.gw.logins.Load())
	}
	var oldest time.Time
	r.m.conns.locked(func() { oldest = r.m.conns.nat.logins[0] })
	if want := oldest.Add(connLoginWindow); next.Sub(want).Abs() > time.Second {
		t.Fatalf("the next round at %v, want %v: a day after the first login", next, want)
	}
	mustContain(t, "the problem", natProblem(r), "NAT reads paused: they needed 6 gateway logins within the last 24 hours (at most 6",
		"they resume at ")
	// A day after the first login the reads may log in again: read 14 in the session, read 15 with
	// a login.
	r.m.conns.locked(func() { r.m.conns.nat.logins[0] = time.Now().Add(-connLoginWindow) })
	r.m.sampleNAT(ctx)
	r.m.sampleNAT(ctx)
	if nat, _ := store.reads(); len(nat) != 2*connLoginBudget+2 || r.gw.logins.Load() != connLoginBudget+1 {
		t.Fatalf("%d appended, %d logins once the oldest login is a day old", len(nat), r.gw.logins.Load())
	}
	if p := natProblem(r); p != "" {
		t.Fatalf("problem %q after the reads resumed", p)
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

// TestNATSamplerStreakDoesNotFeedItself: the read after the hour's wait must log in - the client
// keeps a session 5 minutes after its last use - and that login, due after the pause, neither
// extends the streak nor makes the next read wait another hour: the reads go back to their interval
// when the gateway keeps its sessions again, instead of one login an hour until the day's budget
// is used up (as on the owner's gateway from 2026-10-28). Every login still counts for the budget,
// and a gateway that still ends its sessions is still found out by the read after that one.
func TestNATSamplerStreakDoesNotFeedItself(t *testing.T) {
	ctx := context.Background()
	const interval = 4 * time.Minute
	r, _ := connRig(t, func(c *config.Config) { c.Connections.Interval = config.D(interval) })
	// Reads 1-3 log in (the gateway ended the sessions); read 4 reuses read 3's session.
	loginEachRead(r, func(n int) bool { return n >= 4 })
	began := time.Now()
	wantNext(t, "the first read with a login", began, r.m.sampleNAT(ctx), interval)
	began = time.Now()
	wantNext(t, "the second in a row", began, r.m.sampleNAT(ctx), connLoginStreakWait)
	// The hour's wait: the previous read began an hour ago.
	pause := func(d time.Duration) {
		r.m.conns.locked(func() { r.m.conns.nat.lastRead = r.m.conns.nat.lastRead.Add(-d) })
	}
	pause(connLoginStreakWait)
	began = time.Now()
	wantNext(t, "the read after the hour's wait, which had to log in", began, r.m.sampleNAT(ctx), interval)
	began = time.Now()
	wantNext(t, "the next read, in that read's session", began, r.m.sampleNAT(ctx), interval)
	var streak, logins int
	r.m.conns.locked(func() { streak, logins = r.m.conns.nat.streak, len(r.m.conns.nat.logins) })
	if streak != 0 || logins != 3 {
		t.Fatalf("streak %d, logins counted %d; want 0 and 3 (every login counts for the budget)", streak, logins)
	}
	if st := connStatus(t, r); st.NATLogins != 3 {
		t.Fatalf("status nat_logins %d, want 3", st.NATLogins)
	}

	// The gateway ends its sessions again: two logins in a row, the hour's wait, the due login -
	// and the read after it, which should have reused that login's session, logs in too: it waits
	// another hour (not one more interval: the due login did not end the streak). The first three
	// logins are taken as a day old, out of the budget's way.
	r.m.conns.locked(func() { r.m.conns.nat.logins = nil })
	loginEachRead(r, nil)
	began = time.Now()
	wantNext(t, "a login again", began, r.m.sampleNAT(ctx), interval)
	began = time.Now()
	wantNext(t, "and again", began, r.m.sampleNAT(ctx), connLoginStreakWait)
	pause(connLoginStreakWait)
	began = time.Now()
	wantNext(t, "the due login after the second wait", began, r.m.sampleNAT(ctx), interval)
	began = time.Now()
	wantNext(t, "a login the session should have spared", began, r.m.sampleNAT(ctx), connLoginStreakWait)
	r.m.conns.locked(func() { logins = len(r.m.conns.nat.logins) })
	if logins != 4 {
		t.Fatalf("logins counted %d, want 4", logins)
	}
}

// TestNATSamplerStreakAfterAShortPause: a read that logs in less than the session reuse after the
// previous one still extends the streak - the gateway ended a session the client still held.
func TestNATSamplerStreakAfterAShortPause(t *testing.T) {
	ctx := context.Background()
	const interval = 4 * time.Minute
	r, _ := connRig(t, func(c *config.Config) { c.Connections.Interval = config.D(interval) })
	loginEachRead(r, nil)
	began := time.Now()
	wantNext(t, "the first read with a login", began, r.m.sampleNAT(ctx), interval)
	r.m.conns.locked(func() { r.m.conns.nat.lastRead = r.m.conns.nat.lastRead.Add(-(connSessionReuse - 30*time.Second)) })
	began = time.Now()
	wantNext(t, "a login 4 min 30 s after the previous read", began, r.m.sampleNAT(ctx), connLoginStreakWait)
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
