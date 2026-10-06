package monitor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"attmonitor/internal/config"
	"attmonitor/internal/contracts"
	"attmonitor/internal/model"
)

// The Network page's samplers (docs/syslog-map-graphic.md §2.1): which device on the home network
// talks to which remote address, from the gateway's NAT table (Diagnostics > NAT Table, behind the
// login) read every connections.interval, and the devices' names, from its Device List (Device >
// Device List, no login) read every connections.devices_interval. What they read goes to
// the connection store (Options.Conns). None of it is evidence: it describes the household's own
// traffic, not AT&T's faults, so nothing of it is written to the ledger - nor, through it, to
// MongoDB or into an evidence bundle.
//
// The evidence comes first, and authenticated requests stay rare:
//
//   - The NAT read is an authenticated request, made under the guard of every other one: only with
//     an access code stored; never while a changed gateway certificate waits for the operator's
//     confirmation (withGatewayAuth checks that again holding the gateway lock, and raises gwAuth
//     so that the certificate observer refuses a changed certificate met by the read's own TLS
//     handshake); never half-way through the operator's confirmation of one (TrustCert), which
//     moves the pin before its change is recorded and undoes the move when the record fails: the
//     read holds certMu shared, which TrustCert holds exclusively for all of that, so no NAT read
//     uses a pin whose change is not in the ledger - but the read never waits for certMu: a round
//     that finds a confirmation in progress is tried again busyRetry later. It then waits for the
//     gateway lock like every request to the gateway (one at a time). It does not hold notifMu,
//     which the settings check and the operator's changes of a gateway setting hold across their
//     requests: those that start while a read is in progress wait for it at the gateway lock
//     (natTimeout at most) instead of being refused as busy, and a read that starts while one of
//     them runs waits for its request in progress the same way.
//   - It follows the gateway client's login policy: a refusal of it - a login throttled (one a
//     minute), the gateway's web sessions all in use, logins paused after rejected ones - waits
//     until its cooldown ends, and at least an interval. A rejected (or unusable) access code -
//     met by a NAT read or by the settings check - stops the reads until the stored access code
//     changes (att-monitor set-access-code), or for an hour at most: every attempt with it would
//     use up the login budget that the settings check needs too.
//   - Normally the reads need no login at all: the gateway client reuses its session for 5 minutes
//     after its last use, longer than the interval (at most 4 minutes), and the first read of a
//     run waits for the startup settings check, whose session it reuses. The logins the reads do
//     cause - after a pause in the reads longer than the session reuse (an incident, skipped
//     rounds), or when the gateway ends sessions sooner than the client assumes - are counted
//     (the gateway client's LoginAttempts, compared around each read): after two reads in a row
//     that each needed one, the next waits an hour, and once the reads needed connLoginBudget
//     logins within a day they pause until the oldest of them is a day old. Those logins and a stop
//     after a rejected access code are kept in the state folder (natStateFile), so that a restart
//     - even in a loop - starts with what the previous run knew. A read that keeps failing
//     otherwise is tried again after an interval, then two, four, ... up to connFailBackoffMax.
//   - Neither sampler reads while an incident is open or being closed, while the latest cycle was
//     bad (an incident may be opening) or while the newest snapshot found the gateway unreachable:
//     the gateway is polled for evidence then (samplerHold). A read in progress is stopped as soon
//     as that happens; it holds the gateway lock for at most natTimeout (devTimeout for the Device
//     List) in any case, the longest an evidence snapshot can be delayed by it.
//
// For checking the page parsers against the gateway's firmware, the page of the first read that
// worked since the start, of a read whose page was not understood and of a read that left out rows
// it did not understand is copied to last-nattable.html (last-devices.html for the Device List) in
// the data directory's connections folder, each at most once an hour. Not evidence either.

const (
	// connNATFirst and connDevicesFirst delay the first reads after the start: the startup
	// snapshot and the startup settings check come first (and the NAT read then normally reuses
	// the settings check's login session).
	connNATFirst     = time.Minute
	connDevicesFirst = 30 * time.Second
	// connBusyRetry: a NAT round skipped because the operator was confirming a changed gateway
	// certificate, or because the latest cycle was bad, is tried again this much later (within the
	// interval): half a minute, so that a single skipped round still reads within the gateway
	// client's 5-minute session reuse after the read before it (an interval of 4 minutes at most,
	// this, and a wait for the gateway lock), with no new login.
	connBusyRetry = 30 * time.Second
	// connAuthRetry: after a rejected access code the NAT reads stop until the stored code
	// changes, or for this long.
	connAuthRetry = time.Hour
	// connFailBackoffMax bounds the wait after NAT reads that keep failing (natFailure): it doubles
	// with each failure in a row - an interval, two, four, ... - up to this.
	connFailBackoffMax = 2 * time.Hour
	// connLoginBudget is how many gateway logins the NAT reads may cause within connLoginWindow
	// (docs/DESIGN.md §2: logins must stay rare): once they have, the reads pause until the oldest
	// of those logins is connLoginWindow old. After connLoginStreak reads in a row that each needed
	// a login - the gateway may end its sessions sooner than the client assumes - the next read
	// waits connLoginStreakWait.
	connLoginBudget     = 6
	connLoginWindow     = 24 * time.Hour
	connLoginStreak     = 2
	connLoginStreakWait = time.Hour
	// connRawEvery: each raw page copy is written at most this often.
	connRawEvery = time.Hour
	// connPruneEvery: how often the connection store's retention limits are applied, and the raw
	// page copies older than connections.keep_days deleted, whether or not the samplers run.
	connPruneEvery = time.Hour
	// connHoldPoll: how often a read in progress looks whether the gateway is needed for evidence.
	connHoldPoll = 250 * time.Millisecond
	// connFailReport: how often failing reads are reported again in the operational log.
	connFailReport = 6 * time.Hour
	// The gateway client's login policy (docs/DESIGN.md §2), for a refusal that does not say when
	// its cooldown ends: one login attempt a minute, none for 5 minutes after "all web server
	// sessions are in use", none for an hour at most after 3 rejected logins.
	policyThrottled    = time.Minute
	policySessionsFull = 5 * time.Minute
	policyLocked       = time.Hour
	// The raw page copies, in the data directory's connections folder.
	natRawFile     = "last-nattable.html"
	devicesRawFile = "last-devices.html"
	// natStateFile, in the state folder, keeps what the NAT sampler must not forget at a restart
	// (natSaved). Not evidence.
	natStateFile = "nat-sampler.json"
)

// Why a sampler round did not read (Status.Connections: NATProblem, DevicesProblem).
const (
	connSkipIncident = "skipped during an incident: the gateway is left to the evidence collection then"
	connSkipFailing  = "skipped: the latest connection check failed (an incident may be opening), so the gateway is left to the evidence collection; tried again shortly"
	natSkipNoCode    = "not read: the NAT table is behind the gateway's login, and no gateway access code is stored (att-monitor set-access-code)"
	natSkipCert      = "not read: a changed gateway certificate awaits your confirmation (trust-cert); authenticated requests are paused until then"
	natSkipConfirm   = "skipped: a gateway certificate confirmation (trust-cert) was in progress; tried again shortly"
)

// errCertConfirming: the NAT read was not made because the operator's confirmation of a changed
// gateway certificate (TrustCert) held certMu, which the samplers never wait for.
var errCertConfirming = errors.New(natSkipConfirm)

// samplerHeld: a sampler's read was not made, or was stopped, because the gateway is needed for
// evidence collection (why: samplerHold's words).
type samplerHeld struct{ why string }

func (e samplerHeld) Error() string { return e.why }

// loginCooldown is implemented by the gateway client's refusals of its login policy that say when
// the next login attempt is allowed (the monitor does not import the gateway client: an error with
// this method, anywhere in the chain, is enough).
type loginCooldown interface{ CooldownUntil() time.Time }

// connSamplers is the samplers' configuration and state (Monitor.conns; nil without a connection
// store, Options.Conns).
type connSamplers struct {
	store   contracts.ConnStore
	enabled bool // connections.enabled: the samplers run
	// interval and devInterval are connections.interval and connections.devices_interval;
	// natTimeout and devTimeout bound a read, and with it its hold of the gateway lock.
	interval, devInterval  time.Duration
	natTimeout, devTimeout time.Duration
	// Tunables (connNATFirst, connDevicesFirst, ...); tests shorten them.
	natFirst, devFirst, busyRetry, authRetry, rawEvery, holdPoll time.Duration
	// pruneEvery is how often connRetentionLoop applies the retention limits (connPruneEvery).
	pruneEvery time.Duration

	natLog, devLog, pruneLog logGate

	mu  sync.Mutex // guards nat and dev; never held while another lock is taken
	nat natState
	dev devState
	// saveMu serializes the writes of natStateFile (saveNATState).
	saveMu sync.Mutex
}

// natState is what the NAT sampler knows (guarded by connSamplers.mu).
type natState struct {
	// The newest read that worked (at zero: none yet): when, by the monitor's clock, how many
	// sessions it listed and the page's totals (-1 unknown).
	at                         time.Time
	sessions, inUse, available int
	// problem says why the newest round did not read the table, or why its read failed ("" when it
	// read the table); note what the newest read that worked could not keep - rows not understood,
	// or the read itself when the connection store refused it ("" when nothing).
	problem, note string
	next          time.Time // when the next round is due (real time; zero while the sampler does not run)
	// After a rejected or unusable access code (stopUntil not zero; real time): no read before
	// stopUntil unless the stored code no longer is stopStamp (accessCodeStamp). stopWhy says so.
	stopUntil          time.Time
	stopStamp, stopWhy string
	// fails counts the reads in a row that failed (natFailure; not the refusals of the login policy,
	// nor the rounds that did not read), for their back-off.
	fails int
	// logins are when the gateway logins that NAT reads caused were made (real time, oldest first,
	// within connLoginWindow); streak counts the reads in a row that each needed one.
	logins []time.Time
	streak int
	raw    rawCopy
}

// devState is what the Device List sampler knows (guarded by connSamplers.mu).
type devState struct {
	at      time.Time // the newest read that worked (monitor clock; zero: none yet)
	devices int       // how many devices it listed
	problem string
	raw     rawCopy
}

// rawCopy is the bookkeeping of a raw page copy (copyRawPage): whether a read has worked since the
// start (the first one's page is copied), and the copy this run wrote last: when (real time, for
// the hourly limit, and by the monitor's clock, for the status) and where.
type rawCopy struct {
	worked  bool
	written time.Time
	at      time.Time
	path    string
}

// newConnSamplers returns the samplers for a connection store (nil without one) with the
// configuration's intervals - its defaults for a zero value (a hand-built configuration). A read
// may take a login and the page (natTimeout: three gateway request timeouts) or one page
// (devTimeout: one, and some slack, like a one-page snapshot).
func newConnSamplers(store contracts.ConnStore, c config.ConnectionsConfig, gwTimeout time.Duration) *connSamplers {
	if store == nil {
		return nil
	}
	d := config.Default().Connections
	return &connSamplers{
		store:       store,
		enabled:     c.Enabled,
		interval:    durOr(c.Interval, d.Interval.Duration),
		devInterval: durOr(c.DevicesInterval, d.DevicesInterval.Duration),
		natTimeout:  3 * gwTimeout,
		devTimeout:  gwTimeout + 5*time.Second,
		natFirst:    connNATFirst,
		devFirst:    connDevicesFirst,
		busyRetry:   connBusyRetry,
		authRetry:   connAuthRetry,
		rawEvery:    connRawEvery,
		holdPoll:    connHoldPoll,
		pruneEvery:  connPruneEvery,
		nat:         natState{inUse: -1, available: -1},
	}
}

// locked runs f holding the samplers' lock (released even if f panics).
func (c *connSamplers) locked(f func()) {
	c.mu.Lock()
	defer c.mu.Unlock()
	f()
}

// samplersOn reports whether the samplers run: a connection store and connections.enabled.
func (m *Monitor) samplersOn() bool { return m.conns != nil && m.conns.enabled }

// ---------------------------------------------------------------------------- the NAT table

// natLoop runs the NAT sampler (sampleNAT): after this run's startup settings check (whose login
// session the first read reuses: startupChecked) and natFirst after the start, then about every
// connections.interval - later while the login policy refuses logins, while reads keep failing and
// while the reads' own login budget is used up, sooner after a round that had to leave the gateway
// to another operation. What the previous run knew of the reads' logins and of a rejected access
// code is restored first (restoreNATState).
func (m *Monitor) natLoop(ctx context.Context) {
	c := m.conns
	start := time.Now()
	m.restoreNATState(start)
	// Until the startup check has been made, the status says when it is expected at the earliest.
	c.locked(func() { c.nat.next = start.Add(m.notificationStartDelay() + c.natFirst) })
	select {
	case <-m.startupChecked:
	case <-ctx.Done():
		return
	}
	next := later(start.Add(c.natFirst), time.Now())
	for {
		c.locked(func() { c.nat.next = next })
		if !sleepUntil(ctx, next, nil) {
			return
		}
		next = time.Now().Add(c.interval) // should the round panic
		m.safely("connections", func() { next = m.sampleNAT(ctx) })
	}
}

// sampleNAT makes one round of the NAT sampler: unless natPaused says no, it reads the NAT table
// under the guard of the authenticated requests (readNAT) and appends what it read to the
// connection store. A read that needed a gateway login is counted (natLogin). It returns when the
// next round is due (real time).
func (m *Monitor) sampleNAT(ctx context.Context) time.Time {
	c := m.conns
	began := time.Now()
	next := began.Add(c.interval)
	if why, retry := m.natPaused(began); why != "" {
		m.noteNATSkip(why)
		if !retry.IsZero() {
			next = earlier(next, retry)
		}
		return next
	}
	table, raw, loggedIn, err := m.readNAT(ctx)
	next = m.natLogin(began, next, loggedIn, err)
	if ctx.Err() != nil {
		return next // stopping: an aborted read says nothing
	}
	var (
		held    samplerHeld
		pending *certPendingError
	)
	switch {
	case errors.Is(err, errCertConfirming):
		m.noteNATSkip(natSkipConfirm)
		return earlier(next, began.Add(c.busyRetry))
	case errors.As(err, &held):
		m.noteNATSkip(held.why)
		// Tried again shortly - unless the read had sent a login already: then the session it got
		// is reused at the next round, an interval later, rather than another login be risked.
		if held.why == connSkipFailing && !loggedIn {
			next = earlier(next, began.Add(c.busyRetry))
		}
		return next
	case errors.As(err, &pending), errors.Is(err, contracts.ErrGatewayCertRejected):
		// A changed certificate waits for confirmation (became pending while this round waited
		// for the gateway lock), or this read's TLS handshake met one and the observer refused it
		// before anything was sent: GATEWAY_CERT_CHANGED says so, nothing failed.
		m.noteNATSkip(natSkipCert)
		return next
	case err != nil:
		problem, due := m.natFailure(err, raw, began, next)
		c.locked(func() { c.nat.problem, c.nat.note = problem, "" })
		m.connFailed(&c.natLog, "cannot read the gateway's NAT table for the Network page", problem)
		return due
	}
	m.natRead(table, raw)
	return next
}

// natPaused says why no NAT read is made now ("" when one may be) and, for a round that left the
// gateway to a failing cycle or stays stopped after a rejected access code, when to look again
// (zero: at the next round): the gateway is needed for evidence (samplerHold), no access code is
// stored, a changed certificate waits for confirmation, the reads have used up their login budget
// (natBudgetEnd), or the access code was rejected and has not been stored anew since (for at most
// authRetry).
func (m *Monitor) natPaused(now time.Time) (why string, retry time.Time) {
	c := m.conns
	if why := m.samplerHold(); why != "" {
		if why == connSkipFailing {
			retry = now.Add(c.busyRetry)
		}
		return why, retry
	}
	if !m.hasAccessCode() {
		return natSkipNoCode, time.Time{}
	}
	if m.pendingCert() != "" {
		return natSkipCert, time.Time{}
	}
	if end, n := m.natBudgetEnd(now); !end.IsZero() {
		return fmt.Sprintf("NAT reads paused: they needed %d gateway logins within the last %s (at most %d: logins must stay rare); they resume at %s",
			n, fmtWindow(connLoginWindow), connLoginBudget, fmtHuman(m.monitorTime(end))), time.Time{}
	}
	var until time.Time
	var stamp, stopWhy string
	c.locked(func() { until, stamp, stopWhy = c.nat.stopUntil, c.nat.stopStamp, c.nat.stopWhy })
	if until.IsZero() {
		return "", time.Time{}
	}
	if now.Before(until) && m.accessCodeStamp() == stamp {
		return stopWhy, until
	}
	c.locked(func() { c.nat.stopUntil, c.nat.stopStamp, c.nat.stopWhy = time.Time{}, "", "" })
	m.saveNATState()
	m.log.Info("NAT table reads for the Network page resume after the rejected access code", "code_changed", now.Before(until))
	return "", time.Time{}
}

// fmtWindow writes the login budget's window ("24 hours").
func fmtWindow(d time.Duration) string {
	if h := d / time.Hour; d == h*time.Hour {
		return plural(int(h), "hour", "hours")
	}
	return d.String()
}

// natBudgetEnd returns, when the NAT reads have used up their login budget at now (connLoginBudget
// logins within connLoginWindow), when the oldest of those logins leaves the window - the reads
// resume then - and how many there were; the zero time while the budget is not used up.
func (m *Monitor) natBudgetEnd(now time.Time) (end time.Time, n int) {
	c := m.conns
	c.locked(func() {
		c.nat.logins = recentLogins(c.nat.logins, now)
		if n = len(c.nat.logins); n >= connLoginBudget {
			end = c.nat.logins[n-connLoginBudget].Add(connLoginWindow)
		}
	})
	return end, n
}

// recentLogins returns the logins of ts (oldest first) within connLoginWindow before now.
func recentLogins(ts []time.Time, now time.Time) []time.Time {
	i := 0
	for i < len(ts) && now.Sub(ts[i]) >= connLoginWindow {
		i++
	}
	return ts[i:]
}

// natLogin notes whether a NAT read needed a gateway login (loggedIn; err is the read's error) and
// returns when the next round is due given the regular one (next). A login is counted for the
// budget and kept in the state folder. After connLoginStreak reads that each needed one, with no
// read between them that worked without one, the next round waits connLoginStreakWait after this
// one began: the gateway may end its sessions sooner than the client assumes, and every read would
// then log in. Only a read that worked without a login - the session was reused - ends the streak.
func (m *Monitor) natLogin(began, next time.Time, loggedIn bool, err error) time.Time {
	c := m.conns
	streak := 0
	c.locked(func() {
		switch {
		case loggedIn:
			c.nat.logins = append(recentLogins(c.nat.logins, began), began)
			c.nat.streak++
		case err == nil:
			c.nat.streak = 0
		}
		streak = c.nat.streak
	})
	if !loggedIn {
		return next
	}
	m.saveNATState()
	if streak >= connLoginStreak {
		m.log.Warn("NAT table reads for the Network page needed a gateway login each: the next read waits an hour",
			"reads", streak)
		return later(next, began.Add(connLoginStreakWait))
	}
	return next
}

// loginCounter is implemented by the gateway client: the login forms it has posted (gateway.Client
// LoginAttempts). The monitor does not import the gateway client: the read's logins are told by
// comparing the count before and after it, holding the gateway lock, which every authenticated
// request holds.
type loginCounter interface{ LoginAttempts() uint64 }

// loginAttempts returns the gateway client's login count, and false when it keeps none.
func (m *Monitor) loginAttempts() (uint64, bool) {
	lc, ok := m.gw.(loginCounter)
	if !ok {
		return 0, false
	}
	return lc.LoginAttempts(), true
}

// readNAT reads the NAT table under the guard of every authenticated gateway request: holding
// certMu shared, which it never waits for (errCertConfirming while TrustCert holds it, or waits
// for it: the pin may have moved without its change being recorded yet), and inside
// withGatewayAuth (the gateway lock and gwAuth; refused with errCertPending while a changed
// certificate waits for confirmation). It holds certMu until the read has ended, so a
// confirmation that starts meanwhile waits for the read rather than move the pin under it. It
// does not take notifMu: a settings check or an operator's change of a gateway setting is never
// refused as busy because of a NAT read, and waits for one in progress at the gateway lock. The
// read itself is bounded by natTimeout and stopped when the gateway is needed for evidence
// (samplerRead: samplerHeld). loggedIn reports whether the gateway client posted a login form
// during the read.
func (m *Monitor) readNAT(ctx context.Context) (table model.NATTable, raw []byte, loggedIn bool, err error) {
	if !m.certMu.TryRLock() {
		return model.NATTable{}, nil, false, errCertConfirming
	}
	defer m.certMu.RUnlock()
	if aerr := m.withGatewayAuth(gwUseNAT, func() {
		before, counted := m.loginAttempts()
		err = m.samplerRead(ctx, m.conns.natTimeout, func(rctx context.Context) error {
			var rerr error
			table, raw, rerr = m.gw.NATTable(rctx)
			return rerr
		})
		after, _ := m.loginAttempts()
		loggedIn = counted && after != before
	}); aerr != nil {
		return model.NATTable{}, nil, false, aerr
	}
	return table, raw, loggedIn, err
}

// natFailure words a NAT read that failed (err; raw: the page, when one was read) for the status,
// and returns when the next round is due given the round's start (began) and the regular next
// round (next): a refusal of the login policy waits until its cooldown ends (cooldownEnd); a
// rejected or unusable access code stops the reads for authRetry (the rounds meanwhile only look
// whether the stored code changed; natStop); any other failure waits an interval after the first,
// two after the second in a row, then four, ... up to connFailBackoffMax, and a page that came with
// it - not understood, or as much of it as arrived - is copied (copyRawPage).
func (m *Monitor) natFailure(err error, raw []byte, began, next time.Time) (problem string, due time.Time) {
	c := m.conns
	switch {
	case errors.Is(err, contracts.ErrGatewayAuth), errors.Is(err, contracts.ErrGatewayNoAccessCode):
		problem, until := m.natStop(err)
		return problem, earlier(next, until)
	case errors.Is(err, contracts.ErrGatewayAuthLocked):
		due = later(next, cooldownEnd(err, policyLocked))
		return "logins are paused after 3 rejected attempts within an hour; the next NAT read is at " + fmtHuman(m.monitorTime(due)), due
	case errors.Is(err, contracts.ErrGatewaySessionsFull):
		due = later(next, cooldownEnd(err, policySessionsFull))
		return "the gateway's web sessions are all in use, so no login is made for a while; the next NAT read is at " + fmtHuman(m.monitorTime(due)), due
	case errors.Is(err, contracts.ErrGatewayLoginThrottled):
		due = later(next, cooldownEnd(err, policyThrottled))
		return "a login was attempted less than a minute before (one a minute at most); the next NAT read is at " + fmtHuman(m.monitorTime(due)), due
	}
	// The gateway client's error says what went wrong ("... page not understood: ..."); a page
	// that came with it is copied.
	problem = "the NAT table could not be read: " + errText(err)
	if len(raw) > 0 {
		problem += m.copyRawPage(&c.nat.raw, natRawFile, raw, false, true)
	}
	fails := 0
	c.locked(func() {
		c.nat.fails++
		fails = c.nat.fails
	})
	if fails > 1 {
		wait := c.interval
		for range fails - 1 {
			if wait = 2 * wait; wait >= connFailBackoffMax {
				wait = connFailBackoffMax
				break
			}
		}
		next = later(next, began.Add(wait))
		problem += fmt.Sprintf("; %d reads in a row failed, so the next is at %s", fails, fmtHuman(m.monitorTime(next)))
	}
	return problem, next
}

// natStop stops the NAT reads after the gateway rejected the stored access code, or after it could
// not be used (err): until the code is stored anew, or for authRetry (natPaused). It returns the
// problem the status shows and when the reads resume at the latest; the stop is kept in the state
// folder.
func (m *Monitor) natStop(err error) (problem string, until time.Time) {
	c := m.conns
	until = time.Now().Add(c.authRetry)
	what := "the gateway rejected the access code"
	if !errors.Is(err, contracts.ErrGatewayAuth) {
		what = "the stored gateway access code could not be used (" + errText(err) + ")"
	}
	problem = fmt.Sprintf("%s at %s; NAT reads stop until it is stored anew (att-monitor set-access-code), and are tried again at %s at the latest",
		what, fmtHuman(m.now()), fmtHuman(m.monitorTime(until)))
	stamp := m.accessCodeStamp()
	c.locked(func() { c.nat.stopUntil, c.nat.stopStamp, c.nat.stopWhy = until, stamp, problem })
	m.saveNATState()
	return problem, until
}

// natStopAfterRejection stops the NAT reads after the settings check's login was rejected (err), as
// a rejection met by a NAT read would: each attempt with the same code would only use up the login
// attempts the settings check needs. Without the samplers it does nothing.
func (m *Monitor) natStopAfterRejection(err error) {
	if !m.samplersOn() {
		return
	}
	problem, _ := m.natStop(err)
	m.conns.locked(func() { m.conns.nat.problem = problem })
}

// cooldownEnd returns when a refusal of the gateway client's login policy (err) ends: when it
// says so (loginCooldown), else policy - the policy's longest cooldown of that kind - from now;
// never more than policyLocked ahead (the longest any refusal lasts), whatever a clock says.
func cooldownEnd(err error, policy time.Duration) time.Time {
	now := time.Now()
	until := now.Add(policy)
	var cd loginCooldown
	if errors.As(err, &cd) {
		if u := cd.CooldownUntil(); !u.IsZero() {
			until = u
		}
	}
	return earlier(later(until, now), now.Add(policyLocked))
}

// natRead keeps a NAT table read that worked: it is appended to the connection store, its page is
// copied when it is the first since the start or rows of it were not understood (copyRawPage),
// and the status follows it - a read with nothing wrong clears the problem, and what the read
// could not keep (rows not understood, or the read itself when the store refused it) is its note:
// the table was read all the same.
func (m *Monitor) natRead(table model.NATTable, raw []byte) {
	c := m.conns
	now := m.now()
	serr := c.store.AppendNAT(now, table)
	// A page whose totals count sessions of which no row was understood was not understood either.
	suspect := table.Skipped > 0 || (len(table.Sessions) == 0 && table.InUse > 0)
	copied := m.copyRawPage(&c.nat.raw, natRawFile, raw, true, suspect)
	note := ""
	switch {
	case serr != nil:
		note = "the connection store could not keep the newest read: " + errText(serr)
	case table.Skipped > 0:
		note = plural(table.Skipped, "row", "rows") + " of the NAT table page left out (not understood)" + copied
	case suspect:
		note = fmt.Sprintf("the NAT table page counts %d sessions in use, but none of its rows was understood%s", table.InUse, copied)
	}
	first := false
	c.locked(func() {
		first = c.nat.at.IsZero()
		c.nat.at, c.nat.sessions, c.nat.inUse, c.nat.available = now, len(table.Sessions), table.InUse, table.Available
		c.nat.problem, c.nat.note, c.nat.fails = "", note, 0
	})
	if serr != nil {
		m.connFailed(&c.natLog, "cannot keep the gateway's NAT table reads for the Network page", note)
		return
	}
	m.connWorked(&c.natLog, "NAT table reads for the Network page work again")
	if first {
		m.log.Info("the gateway's NAT table is read for the Network page", "sessions", len(table.Sessions), "in_use", table.InUse,
			"available", table.Available, "skipped", table.Skipped, "every", c.interval)
	} else {
		m.log.Debug("NAT table read", "sessions", len(table.Sessions), "in_use", table.InUse, "skipped", table.Skipped)
	}
}

// noteNATSkip notes a NAT round that did not read (why) for the status.
func (m *Monitor) noteNATSkip(why string) {
	c := m.conns
	c.locked(func() { c.nat.problem, c.nat.note = why, "" })
	m.log.Debug("NAT table not read", "why", why)
}

// ---------------------------------------------------------------------------- what outlives a run

// natSaved is natStateFile: the gateway logins the NAT reads caused within connLoginWindow (real
// time, oldest first) and a stop after a rejected access code - what a restart must not forget, or
// a service restarting in a loop would get a new login budget and a new attempt with a rejected
// code at every start. Not evidence: a cache of the sampler's own pauses, in the state folder.
type natSaved struct {
	Version   int         `json:"version"`
	Logins    []time.Time `json:"logins,omitempty"`
	StopUntil time.Time   `json:"stop_until,omitzero"`
	StopStamp string      `json:"stop_stamp,omitempty"`
	StopWhy   string      `json:"stop_why,omitempty"`
}

// natSavedVersion is natStateFile's format.
const natSavedVersion = 1

// natStatePath is natStateFile in the state folder ("" without one).
func (m *Monitor) natStatePath() string {
	if m.opts.StateDir == "" {
		return ""
	}
	return filepath.Join(m.opts.StateDir, natStateFile)
}

// saveNATState writes natStateFile (a failure is logged; the sampler goes on).
func (m *Monitor) saveNATState() {
	path := m.natStatePath()
	if path == "" {
		return
	}
	c := m.conns
	c.saveMu.Lock()
	defer c.saveMu.Unlock()
	var s natSaved
	c.locked(func() {
		s = natSaved{Version: natSavedVersion, Logins: slices.Clone(c.nat.logins), StopUntil: c.nat.stopUntil,
			StopStamp: c.nat.stopStamp, StopWhy: c.nat.stopWhy}
	})
	b, err := json.Marshal(s)
	if err == nil {
		err = writeFileAtomic(path, b)
	}
	if err != nil {
		m.log.Warn("cannot save the NAT table reads' logins and pauses; a restart would forget them", "file", path, "err", err)
	}
}

// restoreNATState takes over what the previous run saved (natStateFile) at now: the logins within
// connLoginWindow - a login dated after now (the clock was set back) counts as made now - and a
// stop after a rejected access code that has not ended, for authRetry at most from now. A file that
// cannot be read is logged and ignored.
func (m *Monitor) restoreNATState(now time.Time) {
	path := m.natStatePath()
	if path == "" {
		return
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			m.log.Warn("cannot read what the previous run knew of the NAT table reads' logins", "file", path, "err", err)
		}
		return
	}
	var s natSaved
	if err := json.Unmarshal(b, &s); err != nil || s.Version != natSavedVersion {
		m.log.Warn("what the previous run knew of the NAT table reads' logins is not usable; it is ignored", "file", path, "err", err)
		return
	}
	var logins []time.Time
	for _, t := range s.Logins {
		if t.After(now) {
			t = now
		}
		if now.Sub(t) < connLoginWindow {
			logins = append(logins, t)
		}
	}
	slices.SortFunc(logins, func(a, b time.Time) int { return a.Compare(b) })
	c := m.conns
	c.locked(func() {
		c.nat.logins = logins
		if s.StopUntil.After(now) {
			c.nat.stopUntil, c.nat.stopStamp, c.nat.stopWhy = earlier(s.StopUntil, now.Add(c.authRetry)), s.StopStamp, s.StopWhy
		}
	})
	if len(logins) > 0 || s.StopUntil.After(now) {
		m.log.Info("the NAT table reads continue from what the previous run knew", "logins_last_day", len(logins),
			"stopped_until", s.StopUntil.UTC().Format(time.RFC3339))
	}
}

// ---------------------------------------------------------------------------- the Device List

// devicesLoop runs the Device List sampler (sampleDevices): devFirst after the start, then every
// connections.devices_interval.
func (m *Monitor) devicesLoop(ctx context.Context) {
	c := m.conns
	next := time.Now().Add(c.devFirst)
	for {
		if !sleepUntil(ctx, next, nil) {
			return
		}
		next = time.Now().Add(c.devInterval)
		m.safely("connections", func() { m.sampleDevices(ctx) })
	}
}

// sampleDevices makes one round of the Device List sampler: unless the gateway is needed for
// evidence (samplerHold) it reads the Device List - unauthenticated, holding the gateway lock like
// a status read - and appends it to the connection store.
func (m *Monitor) sampleDevices(ctx context.Context) {
	c := m.conns
	if why := m.samplerHold(); why != "" {
		m.noteDevicesSkip(why)
		return
	}
	devices, raw, err := m.readDevices(ctx)
	if ctx.Err() != nil {
		return
	}
	var held samplerHeld
	if errors.As(err, &held) {
		m.noteDevicesSkip(held.why)
		return
	}
	if err != nil {
		// The page that came with the error - not understood, a login page in its place, an error
		// page - is copied; the gateway client's error says which.
		problem := "the Device List could not be read: " + errText(err)
		if len(raw) > 0 {
			problem += m.copyRawPage(&c.dev.raw, devicesRawFile, raw, false, true)
		}
		c.locked(func() { c.dev.problem = problem })
		m.connFailed(&c.devLog, "cannot read the gateway's Device List for the Network page", problem)
		return
	}
	now := m.now()
	serr := c.store.AppendDevices(now, devices)
	// Every home network has a device (this computer): a page that lists none was not understood.
	copied := m.copyRawPage(&c.dev.raw, devicesRawFile, raw, true, len(devices) == 0)
	problem := ""
	switch {
	case serr != nil:
		problem = "the Device List was read, but the connection store could not keep it: " + errText(serr)
	case len(devices) == 0:
		problem = "the Device List page listed no device that was understood" + copied
	}
	first := false
	c.locked(func() {
		first = c.dev.at.IsZero()
		c.dev.at, c.dev.devices, c.dev.problem = now, len(devices), problem
	})
	if serr != nil {
		m.connFailed(&c.devLog, "cannot keep the gateway's Device List reads for the Network page", problem)
		return
	}
	m.connWorked(&c.devLog, "Device List reads for the Network page work again")
	if first {
		m.log.Info("the gateway's Device List is read for the Network page", "devices", len(devices), "every", c.devInterval)
	} else {
		m.log.Debug("Device List read", "devices", len(devices))
	}
}

// readDevices reads the Device List holding the gateway lock (one request to the gateway at a
// time), bounded by devTimeout and stopped when the gateway is needed for evidence (samplerRead).
func (m *Monitor) readDevices(ctx context.Context) (devices []model.LANDevice, raw []byte, err error) {
	m.lockGateway(gwUseDevices)
	defer m.unlockGateway()
	err = m.samplerRead(ctx, m.conns.devTimeout, func(rctx context.Context) error {
		var rerr error
		devices, raw, rerr = m.gw.Devices(rctx)
		return rerr
	})
	return devices, raw, err
}

// noteDevicesSkip notes a Device List round that did not read (why) for the status.
func (m *Monitor) noteDevicesSkip(why string) {
	c := m.conns
	c.locked(func() { c.dev.problem = why })
	m.log.Debug("Device List not read", "why", why)
}

// ---------------------------------------------------------------------------- shared

// samplerHold says why the samplers must leave the gateway to evidence collection now ("" when
// they need not): an incident is open or being closed (the gateway is polled more often then, and
// the close procedure snapshots it), the latest cycle was bad (an incident may be opening, and
// the first bad cycle asks for a snapshot), or the newest snapshot found the gateway unreachable
// (a read would only hold the gateway lock until its timeout; the next poll tells when it answers).
func (m *Monitor) samplerHold() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	switch {
	case m.st.tracker.open != nil || len(m.st.closing) > 0:
		return connSkipIncident
	case isBad(m.st.lastVerdict.State):
		return connSkipFailing
	case m.st.lastSnap != nil && !m.st.lastSnap.reachable():
		return fmt.Sprintf("skipped: the gateway did not answer the monitor's latest poll (%s); read again once a poll reaches it",
			fmtHuman(m.st.lastSnap.At))
	}
	return ""
}

// samplerRead runs read, a sampler's request to the gateway, unless the gateway is needed for
// evidence already (samplerHeld). Its context ends with ctx, after timeout, and as soon as the
// gateway is needed for evidence (holdWatch): the read's error is then samplerHeld. The caller
// holds the gateway lock.
func (m *Monitor) samplerRead(ctx context.Context, timeout time.Duration, read func(context.Context) error) error {
	if why := m.samplerHold(); why != "" {
		return samplerHeld{why: why}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	tctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	rctx, stop := m.holdWatch(tctx)
	err := read(rctx)
	stop()
	var held samplerHeld
	if err != nil && errors.As(context.Cause(rctx), &held) {
		return held
	}
	return err
}

// holdWatch returns a context that is cancelled, with a samplerHeld cause, as soon as samplerHold
// says the gateway is needed for evidence: a goroutine looks every holdPoll until stop is called,
// which ends it and waits for it.
func (m *Monitor) holdWatch(ctx context.Context) (rctx context.Context, stop func()) {
	hctx, cancel := context.WithCancelCause(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		t := time.NewTicker(m.conns.holdPoll)
		defer t.Stop()
		for {
			select {
			case <-hctx.Done():
				return
			case <-t.C:
				if why := m.samplerHold(); why != "" {
					cancel(samplerHeld{why: why})
					return
				}
			}
		}
	}()
	return hctx, func() {
		cancel(nil)
		<-done
	}
}

// copyRawPage copies page to the data directory's connections\<name> (atomically) when a copy is
// wanted - its read is the first that worked since the start (worked), or its page was not
// understood, not the page expected, or rows of it were left out (suspect) - and this run wrote
// none in the last rawEvery;
// rc is that page's bookkeeping (guarded by the samplers' lock). It returns a note about the newest
// copy of this run for the status ("" when there is none). Without a data directory (a
// configuration not loaded from one, as in tests) nothing is written. The Device List's copy is
// written without the Wi-Fi network's name (redactWiFiName). The copies are deleted once they are
// older than connections.keep_days, and at the start while the samplers are off
// (connRetentionLoop).
func (m *Monitor) copyRawPage(rc *rawCopy, name string, page []byte, worked, suspect bool) string {
	c := m.conns
	dir := m.connDir()
	now, at := time.Now(), m.now()
	due := false
	c.locked(func() {
		first := worked && !rc.worked
		rc.worked = rc.worked || worked
		if dir != "" && len(page) > 0 && (first || suspect) && (rc.written.IsZero() || now.Sub(rc.written) >= c.rawEvery) {
			rc.written, due = now, true
		}
	})
	if due {
		path := filepath.Join(dir, name)
		if name == devicesRawFile {
			page = redactWiFiName(page)
		}
		if err := writeFileAtomic(path, page); err != nil {
			m.log.Warn("cannot copy a gateway page read for the Network page", "file", path, "err", err)
		} else {
			c.locked(func() { rc.at, rc.path = at, path })
		}
	}
	var note string
	c.locked(func() {
		if rc.path != "" {
			note = fmt.Sprintf("; a copy of the page read at %s is in %s", fmtHuman(rc.at), rc.path)
		}
	})
	return note
}

// wifiName matches the Wi-Fi network's name where the Device List page shows it: the last line of
// a Wi-Fi device's Connection Type cell ("5 GHz Radio-1<br />Type: Home<br />Name: ATT-EXAMPLE").
var wifiName = regexp.MustCompile(`(?i)(<br\s*/?>\s*Name:[ \t]*)[^<\r\n]*`)

// redactWiFiName returns the Device List page with the Wi-Fi network's name replaced by
// "(removed)": the parser never keeps it (model.LANDevice.Connection), nor does the copy of the
// page kept for checking the parser, which needs only the page's structure.
func redactWiFiName(page []byte) []byte { return wifiName.ReplaceAll(page, []byte("${1}(removed)")) }

// connRetentionLoop applies the connection store's retention limits every pruneEvery, whatever the
// samplers do: also with connections.enabled off, and while the samplers are held for an incident
// or an unreachable gateway - the appends, which prune too, are made only by reads that worked
// (contracts.ConnStore.Prune; the store applies keep_days only once it has been open for an hour).
// It deletes the raw page copies older than the store's keep_days, and at the start the copies'
// temporary files a crash left and - with the samplers off - the copies themselves
// (cleanRawCopies).
func (m *Monitor) connRetentionLoop(ctx context.Context) {
	c := m.conns
	m.safely("connections", func() { m.cleanRawCopies(time.Now(), true) })
	next := time.Now().Add(c.pruneEvery)
	for {
		if !sleepUntil(ctx, next, nil) {
			return
		}
		next = time.Now().Add(c.pruneEvery)
		m.safely("connections", func() {
			if err := c.store.Prune(time.Time{}); err != nil {
				m.connFailed(&c.pruneLog, "the connection store's retention limits could not be applied in full", errText(err))
			} else {
				m.connWorked(&c.pruneLog, "the connection store's retention limits are applied again")
			}
			m.cleanRawCopies(time.Now(), false)
		})
	}
}

// cleanRawCopies deletes the raw page copies (copyRawPage) that must not be kept at now: while the
// samplers are off (connections.enabled false: nothing replaces them) or once they are older than
// the connection store's keep_days. At the start (start) it also deletes the temporary files a
// crash between their writing and their renaming left.
func (m *Monitor) cleanRawCopies(now time.Time, start bool) {
	c := m.conns
	dir := m.connDir()
	if dir == "" {
		return
	}
	keep := time.Duration(max(c.store.Usage().KeepDays, 1)) * 24 * time.Hour
	for _, rc := range []struct {
		name string
		copy *rawCopy
	}{{natRawFile, &c.nat.raw}, {devicesRawFile, &c.dev.raw}} {
		path := filepath.Join(dir, rc.name)
		if start {
			if tmps, _ := filepath.Glob(filepath.Join(dir, rc.name+".*.tmp")); len(tmps) > 0 {
				for _, tmp := range tmps {
					if err := os.Remove(tmp); err != nil && !errors.Is(err, os.ErrNotExist) {
						m.log.Warn("cannot delete a temporary copy of a gateway page", "file", tmp, "err", err)
					}
				}
			}
		}
		fi, err := os.Stat(path)
		if err != nil {
			continue
		}
		why := ""
		switch {
		case !c.enabled:
			why = "the NAT table and Device List are not read (connections.enabled is false)"
		case now.Sub(fi.ModTime()) >= keep:
			why = "it is older than connections.keep_days"
		}
		if why == "" {
			continue
		}
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			m.log.Warn("cannot delete a copy of a gateway page read for the Network page", "file", path, "err", err)
			continue
		}
		c.locked(func() {
			if rc.copy.path == path {
				rc.copy.path, rc.copy.at = "", time.Time{}
			}
		})
		m.log.Info("deleted a copy of a gateway page read for the Network page", "file", path, "why", why)
	}
}

// connDir returns the data directory's connections folder ("" when the configuration was not
// loaded from a data directory).
func (m *Monitor) connDir() string {
	m.cfgMu.Lock()
	dir := m.cfg.DataDir()
	m.cfgMu.Unlock()
	if dir == "" {
		return ""
	}
	return config.PathsFor(dir).Connections
}

// accessCodeStamp identifies the stored gateway access code without decrypting it: the size and
// modification time of keys\gateway-access-code.dpapi and a hash of the in-config blob (a
// configuration without a data directory). A code stored anew (att-monitor set-access-code)
// changes it, which ends the NAT reads' pause after a rejected access code.
func (m *Monitor) accessCodeStamp() string {
	m.cfgMu.Lock()
	dir, blob := m.cfg.DataDir(), m.cfg.Gateway.AccessCodeProtected
	m.cfgMu.Unlock()
	var b strings.Builder
	if dir != "" {
		if fi, err := os.Stat(config.AccessCodeFile(dir)); err == nil {
			fmt.Fprintf(&b, "file %d %d; ", fi.Size(), fi.ModTime().UnixNano())
		}
	}
	if blob != "" {
		b.WriteString("config " + sha256Hex([]byte(blob)))
	}
	return b.String()
}

// connFailed logs a sampler round that failed (problem) through its gate: when the failures
// start, every connFailReport while they go on.
func (m *Monitor) connFailed(g *logGate, msg, problem string) {
	if loud, n, since := g.fail(m.now(), connFailReport); loud {
		m.log.Warn(msg, "problem", problem, "failures", n, "since", since)
	} else {
		m.log.Debug(msg, "problem", problem, "failures", n)
	}
}

// connWorked notes a sampler round that worked; the end of a streak of failures is logged (msg).
func (m *Monitor) connWorked(g *logGate, msg string) {
	if rec, n, since := g.ok(); rec {
		m.log.Info(msg, "failures", n, "since", since)
	}
}

// monitorTime converts a real time of the samplers' schedule to the monitor's clock, which the
// status and the problems show.
func (m *Monitor) monitorTime(t time.Time) time.Time { return m.now().Add(time.Until(t)) }

// earlier returns the earlier of a and b; later the later.
func earlier(a, b time.Time) time.Time {
	if b.Before(a) {
		return b
	}
	return a
}

func later(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}

// ---------------------------------------------------------------------------- status

// connStatus returns Status.Connections: the samplers' newest reads and problems, when the next
// NAT read is due, and the connection store's volume; nil without a connection store. It takes
// the samplers' lock and the store's own, never mu.
func (m *Monitor) connStatus() *model.ConnSamplerStatus {
	c := m.conns
	if c == nil {
		return nil
	}
	usage := c.store.Usage()
	now := m.now()
	budgetEnd, logins := m.natBudgetEnd(time.Now())
	c.mu.Lock()
	defer c.mu.Unlock()
	s := &model.ConnSamplerStatus{
		Enabled:         c.enabled,
		Interval:        c.interval.String(),
		DevicesInterval: c.devInterval.String(),
		Sessions:        c.nat.sessions,
		InUse:           c.nat.inUse,
		Available:       c.nat.available,
		NATProblem:      c.nat.problem,
		NATNote:         c.nat.note,
		NATLogins:       logins,
		Devices:         c.dev.devices,
		DevicesProblem:  c.dev.problem,
		Store:           &usage,
	}
	if !c.nat.at.IsZero() {
		s.NATAt = fmtTS(c.nat.at)
	}
	if !c.dev.at.IsZero() {
		s.DevicesAt = fmtTS(c.dev.at)
	}
	// The next read: the next round, or - while the reads stop after a rejected access code, or
	// pause after using up their login budget - the end of that pause.
	if next := later(later(c.nat.next, c.nat.stopUntil), budgetEnd); !next.IsZero() {
		s.NATNext = fmtTS(now.Add(time.Until(next)))
	}
	return s
}
