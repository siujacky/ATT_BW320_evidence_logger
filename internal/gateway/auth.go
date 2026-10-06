package gateway

import (
	"context"
	"crypto/md5" //nolint:gosec // MD5 is the gateway's login protocol, not our choice
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
	"unicode/utf16"

	"attmonitor/internal/contracts"
)

// SessionReuse is how long the client reuses its authenticated session after the session's last
// use. Logins stay rare only while the authenticated requests come closer together than this, so
// the NAT table's reads for the Network page (config.MaxConnInterval) are kept within it.
const SessionReuse = 5 * time.Minute

// Login policy (docs/DESIGN.md §2: authenticated requests must be rare). A wrong access code
// must never turn into a stream of attempts that could trip the gateway's own lockout.
const (
	loginSpacing         = 60 * time.Second // minimum time between two login attempts
	maxFailures          = 3                // rejected logins tolerated within failureWindow...
	failureWindow        = time.Hour        // ...after which no attempt is made until the oldest ages out
	sessionsFullCooldown = 5 * time.Minute  // no login while the gateway's session pool is full
	sessionReuse         = SessionReuse     // an authenticated session is reused this long after its last use
	handshakeRetries     = 5                // extra GETs while the login page has no nonce yet
	notificationPage     = "events"         // Diagnostics > Event Notifications (bbevent)
)

// Authentication errors. All errors returned by the authenticated operations are free of
// the access code and of anything derived from it.
//
// Each error that has a counterpart in internal/contracts also matches it with errors.Is (as
// does every error that wraps it), so other packages can react without importing this one:
// ErrSessionsFull matches contracts.ErrGatewaySessionsFull, ErrAuth contracts.ErrGatewayAuth,
// ErrAuthLocked contracts.ErrGatewayAuthLocked, ErrLoginThrottled
// contracts.ErrGatewayLoginThrottled and ErrNoAccessCode contracts.ErrGatewayNoAccessCode
// (ErrCertRejected, in client.go, matches contracts.ErrGatewayCertRejected).
var (
	// ErrSessionsFull: the gateway said "all web server sessions are in use". Logins are
	// paused for 5 minutes (returned wrapped in a *CooldownError).
	ErrSessionsFull = contractError("gateway: all web server sessions are in use", contracts.ErrGatewaySessionsFull)
	// ErrAuth: the gateway rejected the login (wrong access code or protocol change).
	ErrAuth = contractError("gateway: login rejected", contracts.ErrGatewayAuth)
	// ErrAuthLocked: 3 logins were rejected within the last hour; no further attempt is made
	// until the oldest failure is an hour old (returned wrapped in a *CooldownError).
	ErrAuthLocked = contractError("gateway: logins paused after 3 rejected attempts within an hour", contracts.ErrGatewayAuthLocked)
	// ErrLoginThrottled: a login was attempted less than 60 s ago (wrapped in a *CooldownError).
	ErrLoginThrottled = contractError("gateway: at most one login attempt per minute", contracts.ErrGatewayLoginThrottled)
	// ErrNoAccessCode: no access code is configured (or it could not be decrypted).
	ErrNoAccessCode = contractError("gateway: no access code available", contracts.ErrGatewayNoAccessCode)
	// ErrNotApplied: the setting read back after saving differs from the requested value.
	ErrNotApplied = errors.New("gateway: setting not applied")
)

// contractErr is a gateway sentinel error that is also an instance of a contracts sentinel:
// it keeps the gateway's own (more specific) message, and unwraps to the contracts sentinel,
// so errors.Is matches both - and whatever the contracts sentinel itself may wrap.
type contractErr struct {
	msg      string
	contract error
}

// contractError returns a sentinel with message msg that errors.Is-matches contract.
func contractError(msg string, contract error) error {
	return &contractErr{msg: msg, contract: contract}
}

func (e *contractErr) Error() string { return e.msg }

// Unwrap returns the contracts sentinel this error stands for.
func (e *contractErr) Unwrap() error { return e.contract }

// CooldownError is returned while logins are paused; Err is ErrSessionsFull, ErrAuthLocked
// or ErrLoginThrottled (errors.Is works through it, for the contracts sentinels too).
type CooldownError struct {
	Err   error
	Until time.Time
}

func (e *CooldownError) Error() string {
	return fmt.Sprintf("%v (no login attempt before %s)", e.Err, e.Until.UTC().Format(time.RFC3339))
}

func (e *CooldownError) Unwrap() error { return e.Err }

// CooldownUntil returns when the next login attempt is allowed. The monitor, which cannot import
// this package, finds it through an interface and waits until then instead of guessing.
func (e *CooldownError) CooldownUntil() time.Time { return e.Until }

// authState is the login policy state and the current session (guarded by Client.mu).
type authState struct {
	lastAttempt time.Time
	failures    []time.Time // rejected logins within failureWindow
	fullUntil   time.Time   // sessions-full cooldown end
	sess        *authSession
}

// LoginPolicy is the state of the login policy that outlives the process (docs/DESIGN.md §2): when
// the latest login attempt began, the rejected logins of the last hour and the end of a pause after
// "all web server sessions are in use". A service that ends and is started again - by the service
// manager after a failure, in a loop if need be - must not get a new allowance of login attempts
// with every start: Options.LoginPolicy restores what Options.OnLoginPolicy was given last.
type LoginPolicy struct {
	LastAttempt time.Time   `json:"last_attempt,omitzero"`
	Failures    []time.Time `json:"failures,omitempty"`
	FullUntil   time.Time   `json:"full_until,omitzero"`
}

// restorePolicy takes over a saved login policy at now. A time after now - saved while the clock
// was ahead, or read now that it is behind - counts as now, so that a clock set back can hold back
// the logins by no more than the policy's own pauses (an hour after rejected logins, a minute after
// an attempt, 5 minutes after a full session pool); rejections older than an hour are forgotten, and
// only the newest maxFailures are kept.
func (c *Client) restorePolicy(p LoginPolicy, now time.Time) {
	notAfterNow := func(t time.Time) time.Time {
		if t.After(now) {
			return now
		}
		return t
	}
	if !p.LastAttempt.IsZero() {
		c.auth.lastAttempt = notAfterNow(p.LastAttempt)
	}
	var failures []time.Time
	for _, f := range p.Failures {
		if f = notAfterNow(f); !f.IsZero() && now.Sub(f) < failureWindow {
			failures = append(failures, f)
		}
	}
	slices.SortFunc(failures, func(a, b time.Time) int { return a.Compare(b) })
	if n := len(failures); n > maxFailures {
		failures = failures[n-maxFailures:]
	}
	c.auth.failures = failures
	if p.FullUntil.After(now) {
		c.auth.fullUntil = p.FullUntil
		if limit := now.Add(sessionsFullCooldown); c.auth.fullUntil.After(limit) {
			c.auth.fullUntil = limit
		}
	}
}

// policyChanged hands the login policy's state to Options.OnLoginPolicy, when set, after it changed
// (a login attempt began, was rejected or succeeded, or the session pool was found full). The calls
// are serialized, each with the state as it is then, so that the last call always has the newest
// state; c.mu must not be held.
func (c *Client) policyChanged() {
	if c.onPolicy == nil {
		return
	}
	c.policyMu.Lock()
	defer c.policyMu.Unlock()
	c.mu.Lock()
	p := LoginPolicy{LastAttempt: c.auth.lastAttempt, Failures: slices.Clone(c.auth.failures), FullUntil: c.auth.fullUntil}
	c.mu.Unlock()
	c.onPolicy(p)
}

// LoginAttempts returns how many login forms this client has posted since it was made: each one a
// login attempt the gateway may have seen (rejected ones too). The monitor compares it before and
// after a request to tell whether that request needed a login: its NAT table reads have a login
// budget of their own (docs/DESIGN.md §19).
func (c *Client) LoginAttempts() uint64 { return c.loginPosts.Load() }

// sessionUnpaged bounds how long a session that serves no page is reused. An answer that is
// neither the page asked for nor the login page (an error status, a redirect elsewhere) keeps the
// session for the next request (authPage); but should such an answer be the way some firmware says
// that the session is gone, the session would never be given up: after this long without a page
// served in it, the next request logs in anew instead.
const sessionUnpaged = time.Hour

// authSession is an authenticated cookie session. lastUsed is when the gateway last answered a
// request in it without asking for the login; paged when it last served the page asked for (or
// when the session logged in). It is reused while both are recent (reusableSession).
type authSession struct {
	hc       *http.Client
	lastUsed time.Time
	paged    time.Time
}

// acquire serializes authenticated operations (one gateway session at a time).
func (c *Client) acquire(ctx context.Context) error {
	select {
	case c.authSem <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c *Client) release() { <-c.authSem }

// noteSessionsFull starts (or extends) the sessions-full cooldown.
func (c *Client) noteSessionsFull() *CooldownError {
	c.mu.Lock()
	until := c.now().Add(sessionsFullCooldown)
	if until.After(c.auth.fullUntil) {
		c.auth.fullUntil = until
	}
	until = c.auth.fullUntil
	c.mu.Unlock()
	c.policyChanged()
	c.log.Warn("gateway web session pool is full; logins paused", "host", c.host, "until", until.UTC().Format(time.RFC3339))
	return &CooldownError{Err: ErrSessionsFull, Until: until}
}

// loginAllowed applies the policy before a login attempt.
func (c *Client) loginAllowed(now time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if now.Before(c.auth.fullUntil) {
		return &CooldownError{Err: ErrSessionsFull, Until: c.auth.fullUntil}
	}
	kept := c.auth.failures[:0]
	for _, f := range c.auth.failures {
		if now.Sub(f) < failureWindow {
			kept = append(kept, f)
		}
	}
	c.auth.failures = kept
	if len(kept) >= maxFailures {
		return &CooldownError{Err: ErrAuthLocked, Until: kept[0].Add(failureWindow)}
	}
	if !c.auth.lastAttempt.IsZero() && now.Sub(c.auth.lastAttempt) < loginSpacing {
		return &CooldownError{Err: ErrLoginThrottled, Until: c.auth.lastAttempt.Add(loginSpacing)}
	}
	return nil
}

// loginFailed records a rejected login and returns the error for the caller.
func (c *Client) loginFailed(why string) error {
	c.mu.Lock()
	c.auth.failures = append(c.auth.failures, c.now())
	n := len(c.auth.failures)
	c.auth.sess = nil
	c.mu.Unlock()
	c.policyChanged()
	c.log.Warn("gateway login rejected", "host", c.host, "detail", why, "failures_last_hour", n)
	return fmt.Errorf("%w: %s (%d of %d allowed failures within an hour)", ErrAuth, why, n, maxFailures)
}

// loginVerified records a login whose protected page was served: the rejections counted before it
// are forgotten (the access code works).
func (c *Client) loginVerified() {
	c.mu.Lock()
	had := len(c.auth.failures) > 0
	c.auth.failures = nil
	c.mu.Unlock()
	if had {
		c.policyChanged()
	}
}

// reusableSession returns the current session if it was used recently (sessionReuse) and served a
// page not too long ago (sessionUnpaged).
func (c *Client) reusableSession() *authSession {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := c.auth.sess
	now := c.now()
	if s == nil || now.Sub(s.lastUsed) >= sessionReuse || now.Sub(s.paged) >= sessionUnpaged {
		c.auth.sess = nil
		return nil
	}
	return s
}

func (c *Client) dropSession() {
	c.mu.Lock()
	c.auth.sess = nil
	c.mu.Unlock()
}

// touch keeps s as the session after it served a page, or after its login form was (or may have
// been) accepted: the next request reuses it.
func (c *Client) touch(s *authSession) {
	c.mu.Lock()
	s.lastUsed = c.now()
	s.paged = s.lastUsed
	c.auth.sess = s
	c.mu.Unlock()
}

// keep keeps s as the session after the gateway answered in it without the page asked for and
// without asking for the login (an error status, a redirect elsewhere): it is reused by the next
// request, but only within sessionUnpaged of its last page.
func (c *Client) keep(s *authSession) {
	c.mu.Lock()
	s.lastUsed = c.now()
	c.auth.sess = s
	c.mu.Unlock()
}

// sleepCtx waits for d or until ctx is done.
func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// authPage returns an authenticated page (e.g. "events", "syslog"), reusing a recent session
// when the gateway still honours it, otherwise logging in with that page as the protected
// page (so a login costs no extra request for the page itself).
//
// A reused session is given up - and a login made - only when the gateway says that it is gone:
// it answers with its login page, or a redirect to it. Any other answer is the request's error,
// and the session is kept for the next request: an error status or a redirect elsewhere (nothing
// says that the session is gone, and a new login would most likely meet the same answer - while
// leaving one more session in the gateway's small pool, as would the next: a login on every read;
// keep, within sessionUnpaged), and the page served but not read whole (too large, too slow, or
// the caller gave up: the session works; touch). A request that got no answer at all changes
// nothing: the session ages out sessionReuse after its last use. The answer that came with such
// an error is returned with it (body), for the caller to look at.
func (c *Client) authPage(ctx context.Context, page string) (s *authSession, body []byte, err error) {
	limit := c.bodyCap(page)
	if s := c.reusableSession(); s != nil {
		ex := c.doLimit(ctx, s.hc, http.MethodGet, c.pageURL(page), "", "", limit)
		if !ex.responded {
			return nil, nil, fmt.Errorf("gateway: GET %s.ha: %w", page, ex.err)
		}
		p := scan(ex.body)
		switch {
		case p.sessionsFull():
			return nil, nil, c.noteSessionsFull()
		case p.isLogin(), isLoginRedirect(ex):
			c.log.Debug("gateway session no longer valid; logging in again", "page", page, "status", ex.status, "login_page", p.isLogin())
			c.dropSession()
			return c.login(ctx, page)
		case ex.status != http.StatusOK:
			c.keep(s)
			c.log.Debug("gateway answered an authenticated page with an unexpected status; the session is kept", "page", page,
				"status", ex.status, "location", ex.location)
			return nil, ex.body, fmt.Errorf("gateway: GET %s.ha: unexpected HTTP status %s", page, statusText(ex.status))
		case ex.err != nil:
			c.touch(s)
			return nil, ex.body, fmt.Errorf("gateway: GET %s.ha: %w", page, ex.err)
		}
		c.touch(s)
		return s, ex.body, nil
	}
	return c.login(ctx, page)
}

// bodyCap is the most of page's body that is read: maxBody, or natMaxBody for the NAT table, whose
// size grows with the connections the gateway translates.
func (c *Client) bodyCap(page string) int64 {
	if page == natPage && c.natMaxBody > 0 {
		return c.natMaxBody
	}
	return c.maxBody
}

// login performs the BGW320 login (docs/DESIGN.md §2) in a fresh cookie session and returns
// the session plus the protected page (e.g. "events") fetched to verify it.
//
//  1. GET the protected page (e.g. /cgi-bin/events.ha): the first answer is a login page
//     without nonce (cookie handshake); GET again (up to 5 retries, small backoff) until the
//     login page carries <input name="nonce">.
//  2. POST /cgi-bin/login.ha with nonce, password = "*" x len(code), hashpassword =
//     lowercase hex MD5(code + nonce), Continue=Continue, and a Referer header.
//  3. Success = a 302 that does not point back to login.ha (or a non-login 200) AND the next
//     GET of the protected page is not a login page.
//
// A caller that has given up already (ctx done) gets its error before anything is counted or
// dropped: no attempt is recorded and the current session stays. Once the gateway accepted the
// login form, the new session is kept even when the verifying GET does not bring the page - no
// answer, an error status, a page not read whole: the next request reuses it instead of logging in
// again (and leaving yet another session in the gateway's pool). Only the page served verifies the
// login; until then the rejected logins counted before stay counted. LoginAttempts counts every
// login form posted.
func (c *Client) login(ctx context.Context, protectedPage string) (*authSession, []byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, fmt.Errorf("gateway login: %w", err)
	}
	now := c.now()
	if err := c.loginAllowed(now); err != nil {
		return nil, nil, err
	}
	if c.accessCode == nil {
		return nil, nil, ErrNoAccessCode
	}
	code, err := c.accessCode()
	if err != nil {
		// The error comes from the caller's secret store; never echo the code even if a
		// faulty provider put it into the message.
		msg := err.Error()
		if code != "" {
			msg = strings.ReplaceAll(msg, code, "[redacted]")
		}
		return nil, nil, fmt.Errorf("%w: %s", ErrNoAccessCode, msg)
	}
	if code == "" {
		return nil, nil, ErrNoAccessCode
	}

	c.mu.Lock()
	c.auth.lastAttempt = now
	c.auth.sess = nil
	c.mu.Unlock()
	c.policyChanged()

	s := &authSession{hc: c.sessionClient()}
	pageURL := c.pageURL(protectedPage)
	limit := c.bodyCap(protectedPage)

	// 1. Cookie handshake until the login form offers a nonce. Firmware 6.34.7 renders the
	// login page in place of the protected page; should a firmware redirect to login.ha
	// instead, the handshake continues there (redirects are never followed automatically).
	var nonce string
	formURL := pageURL // page whose login form supplied the nonce (Referer of the POST)
	for i := 0; ; i++ {
		ex := c.doLimit(ctx, s.hc, http.MethodGet, formURL, "", "", limit)
		if !ex.responded || ex.err != nil {
			return nil, nil, fmt.Errorf("gateway login: GET %s: %w", formURL, ex.err)
		}
		p := scan(ex.body)
		if p.sessionsFull() {
			return nil, nil, c.noteSessionsFull()
		}
		switch {
		case ex.status == http.StatusOK && !p.isLogin():
			if formURL == pageURL {
				// The gateway served the protected page without asking for the access code.
				c.log.Info("gateway served a protected page without login", "host", c.host)
				c.touch(s)
				return s, ex.body, nil
			}
		case ex.status == http.StatusOK:
			nonce = p.nonce("/login.ha")
		case isLoginRedirect(ex):
			formURL = c.pageURL("login")
		}
		if nonce != "" {
			break
		}
		if i >= handshakeRetries {
			return nil, nil, fmt.Errorf("gateway login: no login nonce after %d requests (last HTTP status %s)", i+1, statusText(ex.status))
		}
		if err := sleepCtx(ctx, c.handshakeBackoff*time.Duration(i+1)); err != nil {
			return nil, nil, fmt.Errorf("gateway login: %w", err)
		}
	}

	// 2. Submit the login form exactly as the gateway's JavaScript (hashpwd) would.
	sum := md5.Sum([]byte(code + nonce)) //nolint:gosec // protocol-mandated
	form := encodeForm(
		"nonce", nonce,
		"password", strings.Repeat("*", len(utf16.Encode([]rune(code)))), // JS String.length
		"hashpassword", hex.EncodeToString(sum[:]),
		"Continue", "Continue",
	)
	c.loginPosts.Add(1)
	ex := c.do(ctx, s.hc, http.MethodPost, c.pageURL("login"), form, formURL)
	if !ex.responded {
		if ex.connected {
			// The form may have reached the gateway and logged the session in: it is kept, so that
			// the next request finds out with one GET rather than with another login.
			c.touch(s)
		}
		return nil, nil, fmt.Errorf("gateway login: POST login.ha: %w", ex.err)
	}
	p := scan(ex.body)
	switch {
	case p.sessionsFull():
		return nil, nil, c.noteSessionsFull()
	case ex.status >= 300 && ex.status < 400:
		if isLoginAction(locationPath(ex.location)) {
			return nil, nil, c.loginFailed("redirected back to login.ha")
		}
	case ex.status == http.StatusOK:
		if p.isLogin() {
			return nil, nil, c.loginFailed("login page returned again")
		}
	default:
		return nil, nil, fmt.Errorf("gateway login: POST login.ha: unexpected HTTP status %s", statusText(ex.status))
	}

	// 3. Verify: the protected page must now be served. On firmware that redirects protected
	// pages to login.ha, a rejected code can be answered with the same 302 as a success; the
	// redirect of this GET is then the only sign of the rejection, and it must count as one.
	// The gateway accepted the form: from here on the session is kept unless the gateway says
	// that the login did not work (see above).
	ex = c.doLimit(ctx, s.hc, http.MethodGet, pageURL, "", "", limit)
	if !ex.responded {
		c.touch(s)
		return nil, nil, fmt.Errorf("gateway login: verifying GET %s: %w", protectedPage, ex.err)
	}
	p = scan(ex.body)
	switch {
	case p.sessionsFull():
		return nil, nil, c.noteSessionsFull()
	case p.isLogin(), isLoginRedirect(ex):
		return nil, nil, c.loginFailed("protected page still requires login")
	case ex.status != http.StatusOK:
		c.touch(s)
		return nil, ex.body, fmt.Errorf("gateway login: verifying GET %s: unexpected HTTP status %s", protectedPage, statusText(ex.status))
	}
	c.loginVerified()
	c.touch(s)
	c.log.Info("gateway login succeeded", "host", c.host)
	if ex.err != nil {
		// The page was served (the login works) but not read whole.
		return nil, ex.body, fmt.Errorf("gateway login: verifying GET %s: %w", protectedPage, ex.err)
	}
	return s, ex.body, nil
}

// isLoginRedirect reports whether a response redirects to the login page.
func isLoginRedirect(ex exchange) bool {
	return ex.status >= 300 && ex.status < 400 && isLoginAction(locationPath(ex.location))
}

// locationPath returns the path of a redirect target (absolute or relative).
func locationPath(loc string) string {
	if u, err := url.Parse(strings.TrimSpace(loc)); err == nil {
		return u.Path
	}
	return loc
}

// encodeForm serializes name/value pairs in the given order the way browsers encode
// application/x-www-form-urlencoded bodies (WHATWG URL standard): ASCII alphanumerics and
// "*-._" stay literal, space becomes "+", everything else is percent-encoded.
func encodeForm(kv ...string) string {
	var b strings.Builder
	for i := 0; i+1 < len(kv); i += 2 {
		if b.Len() > 0 {
			b.WriteByte('&')
		}
		b.WriteString(formEscape(kv[i]))
		b.WriteByte('=')
		b.WriteString(formEscape(kv[i+1]))
	}
	return b.String()
}

func formEscape(s string) string {
	e := url.QueryEscape(s) // keeps A-Za-z0-9 - _ . ~ ; space -> '+'
	e = strings.ReplaceAll(e, "%2A", "*")
	return strings.ReplaceAll(e, "~", "%7E")
}

// ---------------------------------------------------------------- posting a settings form

// postForm posts a settings form (body, application/x-www-form-urlencoded) to page in session
// s, with the page itself as Referer, and classifies the answer. err is set when the POST
// cannot have changed anything worth reading back (no connection was made), when the session
// pool is full and when the session has expired (ErrLoginRequired). Otherwise problem is ""
// when the gateway answered with a page (200) or a redirect, and says why the outcome is
// unknown when there was no answer or an error status: the gateway may still have applied
// the form, so the caller reads the setting back either way - the result and the "after"
// evidence must say what the gateway now reports, not merely that the POST went wrong.
func (c *Client) postForm(ctx context.Context, s *authSession, page, body string) (ex exchange, problem string, err error) {
	pageURL := c.pageURL(page)
	ex = c.do(ctx, s.hc, http.MethodPost, pageURL, body, pageURL)
	switch {
	case !ex.responded && !ex.connected:
		// No connection was made, so the gateway cannot have received the form.
		return ex, "", fmt.Errorf("gateway: POST %s.ha: %w", page, ex.err)
	case !ex.responded:
		return ex, "no answer to the POST: " + ex.err.Error(), nil
	}
	p := scan(ex.body)
	switch {
	case p.sessionsFull():
		return ex, "", c.noteSessionsFull()
	case ex.status == http.StatusOK && p.isLogin(), isLoginRedirect(ex):
		c.dropSession()
		return ex, "", fmt.Errorf("gateway: POST %s.ha: %w (session expired)", page, ErrLoginRequired)
	case ex.status != http.StatusOK && (ex.status < 300 || ex.status >= 400):
		return ex, "the POST was answered with HTTP " + statusText(ex.status), nil
	}
	return ex, "", nil
}

// readBack reads page again in session s after postForm; problem is the POST's unknown
// outcome, which errors repeat. after is the body read, returned with the error too when
// there is one (nil when no answer arrived). Parsing the page is up to the caller.
func (c *Client) readBack(ctx context.Context, s *authSession, page, problem string) (after []byte, err error) {
	ex := c.do(ctx, s.hc, http.MethodGet, c.pageURL(page), "", "")
	prefix := "gateway: "
	if problem != "" {
		prefix = fmt.Sprintf("gateway: POST %s.ha: %s; ", page, problem)
	}
	switch {
	case !ex.responded:
		return nil, fmt.Errorf("%sverifying GET %s.ha: %w", prefix, page, ex.err)
	case ex.err != nil:
		return ex.body, fmt.Errorf("%sverifying GET %s.ha: %w", prefix, page, ex.err)
	case isLoginRedirect(ex):
		c.dropSession()
		return ex.body, fmt.Errorf("gateway: verifying GET %s.ha: %w (session expired)", page, ErrLoginRequired)
	}
	return ex.body, nil
}

// getPage GETs page in session s (when a POST was answered with a redirect to it).
func (c *Client) getPage(ctx context.Context, s *authSession, page string) ([]byte, error) {
	ex := c.do(ctx, s.hc, http.MethodGet, c.pageURL(page), "", "")
	if !ex.responded {
		return nil, fmt.Errorf("gateway: GET %s.ha: %w", page, ex.err)
	}
	p := scan(ex.body)
	switch {
	case p.sessionsFull():
		return nil, c.noteSessionsFull()
	case p.isLogin(), isLoginRedirect(ex):
		c.dropSession()
		return nil, fmt.Errorf("gateway: GET %s.ha: %w (session expired)", page, ErrLoginRequired)
	case ex.status != http.StatusOK:
		return nil, fmt.Errorf("gateway: GET %s.ha: unexpected HTTP status %s", page, statusText(ex.status))
	case ex.err != nil:
		return nil, fmt.Errorf("gateway: GET %s.ha: %w", page, ex.err)
	}
	return ex.body, nil
}

// ---------------------------------------------------------------- notification setting

// Notification reads the "Broadband Status Notification" (bbevent) setting from events.ha.
// It needs authentication, so it is rate limited (see the error variables); raw is the exact
// events.ha body that was read.
func (c *Client) Notification(ctx context.Context) (enabled bool, raw []byte, err error) {
	if err := c.acquire(ctx); err != nil {
		return false, nil, err
	}
	defer c.release()
	_, body, err := c.authPage(ctx, notificationPage)
	if err != nil {
		return false, nil, err
	}
	enabled, err = parseNotification(scan(body))
	if err != nil {
		return false, body, err
	}
	return enabled, body, nil
}

// SetNotification sets the "Broadband Status Notification" (bbevent) setting: it reads
// events.ha (authenticated), posts the page's form with its nonce, Save=Save and bbevent=on
// only when enabling, then reads the page again and verifies that the checkbox matches.
// before and after are the exact bodies of the two reads (returned also on failure when
// available). The read-back decides the outcome: it is also made when the POST got no answer
// or an error status (the gateway may still have applied it), and the error is nil only when
// the page read afterwards shows the requested value (ErrNotApplied otherwise). It is skipped
// only when the POST never reached the gateway, the session turned out to be expired
// (ErrLoginRequired) or the session pool is full. When the setting already has the requested
// value no form is posted and after is the same body as before.
func (c *Client) SetNotification(ctx context.Context, enabled bool) (before, after []byte, err error) {
	if err := c.acquire(ctx); err != nil {
		return nil, nil, err
	}
	defer c.release()
	s, before, err := c.authPage(ctx, notificationPage)
	if err != nil {
		return nil, nil, err
	}
	p := scan(before)
	current, err := parseNotification(p)
	if err != nil {
		return before, nil, err
	}
	if current == enabled {
		c.log.Info("gateway notification setting already as requested; nothing posted", "enabled", enabled)
		return before, before, nil
	}
	nonce := p.nonce("/events.ha")
	if nonce == "" {
		return before, nil, fmt.Errorf("events: %w (form has no nonce)", ErrUnexpectedPage)
	}
	fields := []string{"nonce", nonce}
	if enabled {
		fields = append(fields, "bbevent", "on") // an unchecked checkbox is simply omitted
	}
	fields = append(fields, "Save", "Save")
	ex, postProblem, err := c.postForm(ctx, s, notificationPage, encodeForm(fields...))
	if err != nil {
		return before, nil, err
	}
	if postProblem == "" {
		c.log.Info("gateway notification setting posted", "enabled", enabled, "status", ex.status, "location", ex.location)
	} else {
		c.log.Warn("gateway notification POST outcome unknown; reading the setting back", "enabled", enabled, "detail", postProblem)
	}
	after, err = c.readBack(ctx, s, notificationPage, postProblem)
	if err != nil {
		return before, after, err
	}
	got, err := parseNotification(scan(after))
	if err != nil {
		if errors.Is(err, ErrLoginRequired) {
			c.dropSession()
		}
		return before, after, err
	}
	c.touch(s)
	if got != enabled {
		detail := ""
		if postProblem != "" {
			detail = " (" + postProblem + ")"
		}
		return before, after, fmt.Errorf("%w: Broadband Status Notification reads %s after saving%s", ErrNotApplied, onOff(got), detail)
	}
	if postProblem != "" {
		c.log.Warn("gateway notification setting verified by reading it back", "enabled", enabled, "detail", postProblem)
	}
	return before, after, nil
}

func onOff(b bool) string {
	if b {
		return "on"
	}
	return "off"
}
