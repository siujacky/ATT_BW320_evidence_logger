package gateway

import (
	"context"
	"crypto/md5" //nolint:gosec // MD5 is the gateway's login protocol, not our choice
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf16"

	"attmonitor/internal/contracts"
)

// Login policy (docs/DESIGN.md §2: authenticated requests must be rare). A wrong access code
// must never turn into a stream of attempts that could trip the gateway's own lockout.
const (
	loginSpacing         = 60 * time.Second // minimum time between two login attempts
	maxFailures          = 3                // rejected logins tolerated within failureWindow...
	failureWindow        = time.Hour        // ...after which no attempt is made until the oldest ages out
	sessionsFullCooldown = 5 * time.Minute  // no login while the gateway's session pool is full
	sessionReuse         = 5 * time.Minute  // an authenticated session is reused this long after its last use
	handshakeRetries     = 5                // extra GETs while the login page has no nonce yet
	protectedPage        = "events"         // page used to start (and verify) a login
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

// authState is the login policy state and the current session (guarded by Client.mu).
type authState struct {
	lastAttempt time.Time
	failures    []time.Time // rejected logins within failureWindow
	fullUntil   time.Time   // sessions-full cooldown end
	sess        *authSession
}

// authSession is an authenticated cookie session.
type authSession struct {
	hc       *http.Client
	lastUsed time.Time
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
	c.log.Warn("gateway login rejected", "host", c.host, "detail", why, "failures_last_hour", n)
	return fmt.Errorf("%w: %s (%d of %d allowed failures within an hour)", ErrAuth, why, n, maxFailures)
}

// reusableSession returns the current session if it was used recently.
func (c *Client) reusableSession() *authSession {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := c.auth.sess
	if s == nil || c.now().Sub(s.lastUsed) >= sessionReuse {
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

func (c *Client) touch(s *authSession) {
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

// eventsPage returns the authenticated events.ha page, reusing a recent session when the
// gateway still honours it, otherwise logging in.
func (c *Client) eventsPage(ctx context.Context) (*authSession, []byte, error) {
	if s := c.reusableSession(); s != nil {
		ex := c.do(ctx, s.hc, http.MethodGet, c.pageURL(protectedPage), "", "")
		if !ex.responded {
			return nil, nil, fmt.Errorf("gateway: GET %s: %w", protectedPage, ex.err)
		}
		p := scan(ex.body)
		if p.sessionsFull() {
			return nil, nil, c.noteSessionsFull()
		}
		if ex.err == nil && ex.status == http.StatusOK && !p.isLogin() {
			c.touch(s)
			return s, ex.body, nil
		}
		c.log.Debug("gateway session no longer valid; logging in again", "status", ex.status, "login_page", p.isLogin())
		c.dropSession()
	}
	return c.login(ctx)
}

// login performs the BGW320 login (docs/DESIGN.md §2) in a fresh cookie session and returns
// the session plus the protected page fetched to verify it.
//
//  1. GET /cgi-bin/events.ha: the first answer is a login page without nonce (cookie
//     handshake); GET again (up to 5 retries, small backoff) until the login page carries
//     <input name="nonce">.
//  2. POST /cgi-bin/login.ha with nonce, password = "*" x len(code), hashpassword =
//     lowercase hex MD5(code + nonce), Continue=Continue, and a Referer header.
//  3. Success = a 302 that does not point back to login.ha (or a non-login 200) AND the next
//     GET of the protected page is not a login page.
func (c *Client) login(ctx context.Context) (*authSession, []byte, error) {
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

	s := &authSession{hc: c.sessionClient()}
	pageURL := c.pageURL(protectedPage)

	// 1. Cookie handshake until the login form offers a nonce. Firmware 6.34.7 renders the
	// login page in place of the protected page; should a firmware redirect to login.ha
	// instead, the handshake continues there (redirects are never followed automatically).
	var nonce string
	formURL := pageURL // page whose login form supplied the nonce (Referer of the POST)
	for i := 0; ; i++ {
		ex := c.do(ctx, s.hc, http.MethodGet, formURL, "", "")
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
	ex := c.do(ctx, s.hc, http.MethodPost, c.pageURL("login"), form, formURL)
	if !ex.responded {
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
	ex = c.do(ctx, s.hc, http.MethodGet, pageURL, "", "")
	if !ex.responded || ex.err != nil {
		return nil, nil, fmt.Errorf("gateway login: verifying GET %s: %w", protectedPage, ex.err)
	}
	p = scan(ex.body)
	switch {
	case p.sessionsFull():
		return nil, nil, c.noteSessionsFull()
	case p.isLogin(), isLoginRedirect(ex):
		return nil, nil, c.loginFailed("protected page still requires login")
	case ex.status != http.StatusOK:
		return nil, nil, fmt.Errorf("gateway login: verifying GET %s: unexpected HTTP status %s", protectedPage, statusText(ex.status))
	}
	c.mu.Lock()
	c.auth.failures = nil
	c.mu.Unlock()
	c.touch(s)
	c.log.Info("gateway login succeeded", "host", c.host)
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

// ---------------------------------------------------------------- notification setting

// Notification reads the "Broadband Status Notification" (bbevent) setting from events.ha.
// It needs authentication, so it is rate limited (see the error variables); raw is the exact
// events.ha body that was read.
func (c *Client) Notification(ctx context.Context) (enabled bool, raw []byte, err error) {
	if err := c.acquire(ctx); err != nil {
		return false, nil, err
	}
	defer c.release()
	_, body, err := c.eventsPage(ctx)
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
	s, before, err := c.eventsPage(ctx)
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
	pageURL := c.pageURL(protectedPage)
	ex := c.do(ctx, s.hc, http.MethodPost, pageURL, encodeForm(fields...), pageURL)

	// When the POST may have reached the gateway but its outcome is unknown (no answer, or an
	// error status), the setting is read back anyway: the result and the "after" evidence must
	// say what the gateway now reports, not merely that the POST went wrong.
	var postProblem string
	switch {
	case !ex.responded && !ex.connected:
		// No connection was made, so the gateway cannot have received the form.
		return before, nil, fmt.Errorf("gateway: POST events.ha: %w", ex.err)
	case !ex.responded:
		postProblem = "no answer to the POST: " + ex.err.Error()
	default:
		pp := scan(ex.body)
		switch {
		case pp.sessionsFull():
			return before, nil, c.noteSessionsFull()
		case ex.status == http.StatusOK && pp.isLogin(), isLoginRedirect(ex):
			c.dropSession()
			return before, nil, fmt.Errorf("gateway: POST events.ha: %w (session expired)", ErrLoginRequired)
		case ex.status != http.StatusOK && (ex.status < 300 || ex.status >= 400):
			postProblem = "the POST was answered with HTTP " + statusText(ex.status)
		}
	}
	if postProblem == "" {
		c.log.Info("gateway notification setting posted", "enabled", enabled, "status", ex.status, "location", ex.location)
	} else {
		c.log.Warn("gateway notification POST outcome unknown; reading the setting back", "enabled", enabled, "detail", postProblem)
	}

	ex = c.do(ctx, s.hc, http.MethodGet, pageURL, "", "")
	if !ex.responded {
		if postProblem != "" {
			return before, nil, fmt.Errorf("gateway: POST events.ha: %s; verifying GET events.ha: %w", postProblem, ex.err)
		}
		return before, nil, fmt.Errorf("gateway: verifying GET events.ha: %w", ex.err)
	}
	after = ex.body
	if ex.err != nil {
		if postProblem != "" {
			return before, after, fmt.Errorf("gateway: POST events.ha: %s; verifying GET events.ha: %w", postProblem, ex.err)
		}
		return before, after, fmt.Errorf("gateway: verifying GET events.ha: %w", ex.err)
	}
	if isLoginRedirect(ex) {
		c.dropSession()
		return before, after, fmt.Errorf("gateway: verifying GET events.ha: %w (session expired)", ErrLoginRequired)
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
