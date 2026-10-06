package gateway

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptrace"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"

	"attmonitor/internal/contracts"
	"attmonitor/internal/model"
)

// Defaults and limits.
const (
	DefaultHost      = "192.168.1.254"
	DefaultTimeout   = 20 * time.Second // lanstatistics takes ~9 s on firmware 6.34.7
	DefaultUserAgent = "att-monitor/dev"
	// MaxBodyBytes caps every response body (bytes beyond it are not read) but the NAT table's.
	MaxBodyBytes = 4 << 20
	// NATMaxBodyBytes caps the NAT table page, whose size grows with the connections the gateway
	// translates (a few hundred bytes of markup each, up to the gateway's limit of about 8,000).
	NATMaxBodyBytes = 16 << 20
)

var _ contracts.Gateway = (*Client)(nil)

// Options configures a Client (docs/PACKAGES.md "internal/gateway").
type Options struct {
	Host             string        // "192.168.1.254" (an "ip:port" is accepted, e.g. for tests)
	Scheme           string        // "https" (default; certificate pinned) | "http"
	PinnedCertSHA256 string        // hex SHA-256 of the gateway's DER leaf certificate; "" = trust on first use
	Timeout          time.Duration // per request (default 20 s)
	AccessCode       func() (string, error)
	UserAgent        string // "att-monitor/<version>"
	Now              func() time.Time
	Location         *time.Location // gateway clock zone (default time.Local)
	Logger           *slog.Logger
	HTTPClient       *http.Client // tests only; nil -> built-in client with pinning
	// LoginPolicy restores the login policy's state that an earlier process saved through
	// OnLoginPolicy (docs/DESIGN.md §2: a service restarting in a loop gets no new allowance of
	// login attempts with every start). OnLoginPolicy, when set, is called with that state after
	// every change of it - a login attempt begins, is rejected or works, the session pool is found
	// full - so that it can be saved; the calls are serialized, without the client's locks held.
	LoginPolicy   LoginPolicy
	OnLoginPolicy func(LoginPolicy)
}

// Client implements contracts.Gateway for the AT&T BGW320. It is safe for concurrent use;
// authenticated operations are serialized.
type Client struct {
	host       string
	scheme     string
	timeout    time.Duration
	userAgent  string
	accessCode func() (string, error)
	now        func() time.Time
	loc        *time.Location
	log        *slog.Logger
	maxBody    int64
	natMaxBody int64 // the NAT table page's cap (bodyCap)

	base       *http.Client // template: transport (pinning) + no redirects
	snapClient *http.Client // unauthenticated status pages (persistent cookie jar)

	pinDecision sync.Mutex // serializes pin decisions (one observer call per change)

	mu       sync.Mutex
	pin      string
	observer contracts.CertObserver
	auth     authState // login policy and session (see auth.go)

	// onPolicy is Options.OnLoginPolicy; policyMu serializes its calls (policyChanged).
	// loginPosts counts the login forms posted (LoginAttempts).
	onPolicy   func(LoginPolicy)
	policyMu   sync.Mutex
	loginPosts atomic.Uint64

	authSem          chan struct{} // serializes authenticated operations
	handshakeBackoff time.Duration // base delay between login handshake GETs
}

// New returns a Client. It never performs I/O.
func New(opts Options) *Client {
	c := &Client{
		host:             strings.TrimSpace(opts.Host),
		scheme:           strings.ToLower(strings.TrimSpace(opts.Scheme)),
		timeout:          opts.Timeout,
		userAgent:        opts.UserAgent,
		accessCode:       opts.AccessCode,
		now:              opts.Now,
		loc:              opts.Location,
		log:              opts.Logger,
		maxBody:          MaxBodyBytes,
		natMaxBody:       NATMaxBodyBytes,
		pin:              normalizePin(opts.PinnedCertSHA256),
		onPolicy:         opts.OnLoginPolicy,
		authSem:          make(chan struct{}, 1),
		handshakeBackoff: 250 * time.Millisecond,
	}
	if c.host == "" {
		c.host = DefaultHost
	}
	if c.scheme != "http" {
		c.scheme = "https"
	}
	if c.timeout <= 0 {
		c.timeout = DefaultTimeout
	}
	if c.userAgent == "" {
		c.userAgent = DefaultUserAgent
	}
	if c.now == nil {
		c.now = time.Now
	}
	if c.loc == nil {
		c.loc = time.Local
	}
	if c.log == nil {
		c.log = slog.New(slog.DiscardHandler)
	}
	c.restorePolicy(opts.LoginPolicy, c.now())
	if c.pin != "" && !isHexDigest(c.pin) {
		c.log.Warn("configured gateway certificate pin is not a SHA-256 fingerprint; it cannot match, so every certificate goes to the pin policy",
			"pin", c.pin)
	}
	if opts.HTTPClient != nil {
		cp := *opts.HTTPClient
		c.base = &cp
	} else {
		c.base = &http.Client{Transport: c.newTransport()}
	}
	c.base.CheckRedirect = noRedirects
	c.base.Jar = nil
	c.snapClient = c.sessionClient()
	return c
}

// noRedirects makes the http.Client return 3xx responses as they are: redirects are
// recorded (PageCapture.Location), never followed.
func noRedirects(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

// sessionClient returns an http.Client sharing the pinned transport with a fresh cookie jar.
func (c *Client) sessionClient() *http.Client {
	cp := *c.base
	jar, _ := cookiejar.New(nil) // cookiejar.New never fails without options
	cp.Jar = jar
	return &cp
}

// newTransport builds the HTTP transport: no proxy (the gateway is on the LAN), no
// keep-alives, no transparent decompression (bodies are hashed exactly as received), HTTP/1.1,
// and TLS through dialTLS (certificate pinning).
func (c *Client) newTransport() *http.Transport {
	d := &net.Dialer{Timeout: c.timeout, KeepAlive: -1}
	return &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dctx, cancel := c.dialContext(ctx)
			defer cancel() // an established connection is not affected
			return d.DialContext(dctx, network, addr)
		},
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return c.dialTLS(ctx, d, network, addr)
		},
		DisableKeepAlives:      true,
		DisableCompression:     true,
		ResponseHeaderTimeout:  c.timeout,
		MaxResponseHeaderBytes: 256 << 10,
		ForceAttemptHTTP2:      false,
	}
}

// Host returns the gateway host as configured.
func (c *Client) Host() string { return c.host }

// PinnedCert returns the currently pinned certificate SHA-256 ("" if none yet).
func (c *Client) PinnedCert() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.pin
}

// SetCertObserver installs the TLS pin policy callback (see contracts.CertObserver). It is
// called from the TLS handshake, so it must not call back into Snapshot or the
// authenticated operations synchronously.
func (c *Client) SetCertObserver(o contracts.CertObserver) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.observer = o
}

// pinPrefixes are labels that tools print in front of a SHA-256 fingerprint, in the compact
// form normalizePin compares them in (lower case, separators removed): openssl's
// "SHA256 Fingerprint=", certificate viewers' "SHA-256:", HPKP-style "sha256/".
var pinPrefixes = []string{"sha256fingerprint=", "sha256fingerprint", "sha256=", "sha256/", "sha256"}

// normalizePin returns a configured certificate fingerprint as 64 lower-case hex digits. It
// accepts the usual ways of writing one: any case, ':', '-' or white-space separators and a
// "SHA256:", "SHA-256", "sha256/" or "sha256 Fingerprint=" label. A value that is not a
// SHA-256 fingerprint is returned trimmed but otherwise as configured: it can never match a
// certificate, so the CertObserver policy decides (and is shown exactly what was configured).
func normalizePin(s string) string {
	s = strings.TrimSpace(s)
	compact := strings.Map(func(r rune) rune {
		switch r {
		case ':', '-', ' ', '\t', '\r', '\n':
			return -1
		}
		return unicode.ToLower(r)
	}, s)
	if isHexDigest(compact) {
		return compact
	}
	for _, p := range pinPrefixes {
		if rest, ok := strings.CutPrefix(compact, p); ok && isHexDigest(rest) {
			return rest
		}
	}
	return s
}

// isHexDigest reports whether s is a SHA-256 digest in lower-case hex.
func isHexDigest(s string) bool {
	if len(s) != sha256.Size*2 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------- TLS pinning

// CertError reports a TLS certificate that the pin policy rejected.
type CertError struct {
	Pinned   string // pin in force ("" = none yet)
	Observed string // SHA-256 of the certificate the gateway presented
	Reason   string // why no decision could be made ("" = the policy declined)
}

// ErrCertRejected matches every *CertError via errors.Is. It matches
// contracts.ErrGatewayCertRejected in turn, so every certificate rejection does too.
var ErrCertRejected = contractError("gateway: TLS certificate rejected by pin policy", contracts.ErrGatewayCertRejected)

func (e *CertError) Error() string {
	if e.Reason != "" {
		return fmt.Sprintf("gateway TLS certificate sha256 %s rejected: %s (pinned %q)", e.Observed, e.Reason, e.Pinned)
	}
	if e.Pinned == "" {
		return fmt.Sprintf("gateway TLS certificate sha256 %s not accepted (no pin yet; observer declined)", e.Observed)
	}
	return fmt.Sprintf("gateway TLS certificate sha256 %s does not match pinned %s (rejected)", e.Observed, e.Pinned)
}

// Is makes errors.Is(err, ErrCertRejected) true for certificate pin rejections, and true for
// every error ErrCertRejected matches (contracts.ErrGatewayCertRejected).
func (e *CertError) Is(target error) bool { return errors.Is(ErrCertRejected, target) }

// certRecorder travels with one request (as a context value, which net/http hands to the
// dial) and captures the certificate observed during that request's TLS handshake, so
// PageCapture.TLSCertSHA256 is recorded even when the handshake is rejected. It also carries
// the request's own context: net/http detaches dials from request cancellation (a dial may
// serve a later request), but without keep-alives a connection only ever serves the request
// that dialed it, so the handshake - and above all the pin decision - is abandoned with it.
type certRecorder struct {
	req context.Context // the request's context; set before the request starts, then read-only

	mu       sync.Mutex
	observed string
}

// requestDone returns the request context's error, if the request is over.
func (r *certRecorder) requestDone() error {
	if r == nil || r.req == nil {
		return nil
	}
	return r.req.Err()
}

func (r *certRecorder) set(s string) {
	if r == nil {
		return
	}
	r.mu.Lock()
	r.observed = s
	r.mu.Unlock()
}

func (r *certRecorder) get() string {
	if r == nil {
		return ""
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.observed
}

type certRecorderKey struct{}

func certHash(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

// dialContext returns the context for one request's dial (and TLS handshake). net/http keeps
// the request context's values for dials but not its cancellation; the request's
// certRecorder ties the dial back to the request, so that it is abandoned when the request is
// canceled (caller gave up, service stopping): no orphaned dial, and no pin decision for a
// request nobody waits for. The per-request timeout applies as well.
func (c *Client) dialContext(ctx context.Context) (context.Context, context.CancelFunc) {
	dctx, cancel := context.WithTimeout(ctx, c.timeout)
	rec, _ := ctx.Value(certRecorderKey{}).(*certRecorder)
	if rec == nil || rec.req == nil {
		return dctx, cancel
	}
	stop := context.AfterFunc(rec.req, cancel)
	return dctx, func() { stop(); cancel() }
}

// dialTLS performs the TLS handshake for one request (see dialContext for its lifetime).
func (c *Client) dialTLS(ctx context.Context, d *net.Dialer, network, addr string) (net.Conn, error) {
	rec, _ := ctx.Value(certRecorderKey{}).(*certRecorder)
	hctx, cancel := c.dialContext(ctx)
	defer cancel()
	raw, err := d.DialContext(hctx, network, addr)
	if err != nil {
		return nil, err
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	cfg := &tls.Config{
		// The BGW320 serves a self-signed certificate that no public CA vouches for (and that
		// names no stable host), so chain and hostname verification cannot work.
		// InsecureSkipVerify only disables that PKIX check: the gateway's identity is
		// enforced by pinning the SHA-256 of its leaf certificate in VerifyConnection, which
		// runs on every handshake (trust on first use and changes go through the
		// CertObserver policy). Without a valid pin decision the handshake fails before any
		// HTTP request - in particular before any login form - is sent.
		InsecureSkipVerify: true, //nolint:gosec // identity enforced by the certificate pin below
		ServerName:         host,
		MinVersion:         tls.VersionTLS12,
		VerifyConnection: func(cs tls.ConnectionState) error {
			return c.verifyPin(cs, rec)
		},
	}
	tc := tls.Client(raw, cfg)
	if err := tc.HandshakeContext(hctx); err != nil {
		_ = raw.Close()
		return nil, err
	}
	return tc, nil
}

// verifyPin enforces the certificate pin: a matching certificate is accepted; on first use
// (no pin) or a mismatch the CertObserver decides (no observer: accept on first use, reject a
// mismatch); an accepted certificate becomes the new pin. A request that is already over
// gets no decision (and the observer is not consulted), and an observer that panics counts as
// a rejection: it runs on a net/http goroutine, where a panic would end the whole process.
func (c *Client) verifyPin(cs tls.ConnectionState, rec *certRecorder) error {
	if len(cs.PeerCertificates) == 0 {
		return errors.New("gateway presented no TLS certificate")
	}
	observed := certHash(cs.PeerCertificates[0].Raw)
	rec.set(observed)

	c.pinDecision.Lock()
	defer c.pinDecision.Unlock()
	c.mu.Lock()
	pinned, obs := c.pin, c.observer
	c.mu.Unlock()
	if observed == pinned {
		return nil
	}
	if err := rec.requestDone(); err != nil {
		return fmt.Errorf("gateway TLS certificate sha256 %s not evaluated: request ended (%w)", observed, err)
	}
	accept := pinned == "" // trust on first use when nobody is asked
	if obs != nil {
		var panicked any
		accept, panicked = consultObserver(obs, pinned, observed)
		if panicked != nil {
			c.log.Error("gateway certificate observer panicked; certificate rejected", "host", c.host,
				"pinned", pinned, "observed", observed, "panic", fmt.Sprint(panicked))
			return &CertError{Pinned: pinned, Observed: observed, Reason: "the certificate observer failed"}
		}
	}
	if !accept {
		c.log.Warn("gateway TLS certificate rejected", "host", c.host, "pinned", pinned, "observed", observed)
		return &CertError{Pinned: pinned, Observed: observed}
	}
	c.mu.Lock()
	c.pin = observed
	c.mu.Unlock()
	c.log.Info("gateway TLS certificate pinned", "host", c.host, "previous", pinned, "pinned", observed)
	return nil
}

// consultObserver calls the pin policy, converting a panic into a rejection.
func consultObserver(obs contracts.CertObserver, pinned, observed string) (accept bool, panicked any) {
	defer func() {
		if r := recover(); r != nil {
			accept, panicked = false, r
		}
	}()
	return obs(pinned, observed), nil
}

// ---------------------------------------------------------------- HTTP exchange

// exchange is the outcome of one HTTP request.
type exchange struct {
	started   time.Time // Options.Now at request start
	dur       time.Duration
	status    int
	location  string
	body      []byte // exact bytes as received (at most maxBody)
	cert      string // SHA-256 of the presented TLS leaf certificate ("" for http)
	connected bool   // a TCP (and TLS) connection was established
	responded bool   // an HTTP response was received
	truncated bool
	err       error // transport error, body read error or truncation
}

// hostForURL brackets a bare IPv6 address.
func hostForURL(h string) string {
	if a, err := netip.ParseAddr(h); err == nil && a.Is6() {
		return "[" + h + "]"
	}
	return h
}

func (c *Client) pageURL(page string) string {
	return c.scheme + "://" + hostForURL(c.host) + "/cgi-bin/" + page + ".ha"
}

// validPage accepts gateway page names such as "broadbandstatistics" (no paths or queries).
func validPage(p string) bool {
	if p == "" || len(p) > 64 {
		return false
	}
	for _, r := range p {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-') {
			return false
		}
	}
	return true
}

// do performs one request with the per-request timeout and body cap (maxBody). form, when not
// empty, is sent as an application/x-www-form-urlencoded POST body. Nothing about the request
// body is ever logged or put into errors.
func (c *Client) do(ctx context.Context, hc *http.Client, method, rawURL, form, referer string) exchange {
	return c.doLimit(ctx, hc, method, rawURL, form, referer, c.maxBody)
}

// doLimit is do with its own body cap: at most maxBody bytes of the body are read.
func (c *Client) doLimit(ctx context.Context, hc *http.Client, method, rawURL, form, referer string, maxBody int64) exchange {
	var ex exchange
	rec := &certRecorder{}
	var connected atomic.Bool
	ctx = context.WithValue(ctx, certRecorderKey{}, rec)
	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		GotConn: func(httptrace.GotConnInfo) { connected.Store(true) },
	})
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	rec.req = ctx // before the request starts: the dial goroutine only reads it

	var body io.Reader
	if method == http.MethodPost {
		body = strings.NewReader(form)
	}
	req, err := http.NewRequestWithContext(ctx, method, rawURL, body)
	ex.started = c.now()
	if err != nil {
		ex.err = err
		return ex
	}
	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	if referer != "" {
		req.Header.Set("Referer", referer)
	}
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	t0 := time.Now()
	resp, err := hc.Do(req)
	ex.connected = connected.Load()
	if err != nil {
		ex.dur = time.Since(t0)
		ex.cert = rec.get()
		var ue *url.Error
		if errors.As(err, &ue) && ue.Err != nil {
			err = ue.Err // the URL is recorded separately
		}
		ex.err = err
		return ex
	}
	defer resp.Body.Close()
	ex.responded = true
	ex.status = resp.StatusCode
	ex.location = resp.Header.Get("Location")
	ex.cert = rec.get()
	if ex.cert == "" && resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		ex.cert = certHash(resp.TLS.PeerCertificates[0].Raw) // custom Options.HTTPClient
	}
	b, rerr := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	switch {
	case int64(len(b)) > maxBody:
		b = b[:maxBody]
		ex.truncated = true
		ex.err = fmt.Errorf("response body exceeds %d bytes (truncated)", maxBody)
	case rerr != nil:
		ex.err = fmt.Errorf("reading response body: %w", rerr)
	}
	ex.body = b
	ex.dur = time.Since(t0)
	return ex
}

// ---------------------------------------------------------------- Snapshot

// Snapshot fetches pages sequentially without authentication, records a PageCapture for
// each (exact SHA-256, status, redirect target, timing, TLS certificate), parses sysinfo,
// broadbandstatistics, fiberstat and lanstatistics, and derives the summary facts. Bodies
// are returned exactly as received, keyed by page name (pages that produced no HTTP response
// are absent). A page that fails is reported in its PageCapture.Err; the error is non-nil
// only when no page produced an HTTP response at all (the partial snapshot is still
// returned so the failure itself can be recorded). That error names the first failure and
// wraps the failures of every page, so errors.Is/As see their causes - e.g. ErrCertRejected
// (contracts.ErrGatewayCertRejected) when the pin policy rejected the gateway's certificate.
//
// When no connection to the gateway can be established at all (connection refused, dial
// timeout, TLS certificate rejected), the remaining pages are not attempted and are recorded
// as such (PageCapture.NotAttempted, with the reason in Err): a powered-off or rebooting
// gateway costs one timeout per snapshot, not one per page.
func (c *Client) Snapshot(ctx context.Context, pages []string, trigger string) (model.GatewaySnapshot, map[string][]byte, error) {
	snap := model.GatewaySnapshot{Pages: []model.PageCapture{}, Trigger: trigger}
	bodies := make(map[string][]byte, len(pages))
	var responded bool
	var firstErr, skip string
	var causes []error // why pages produced no HTTP response
	seen := make(map[string]bool, len(pages))
	for _, name := range pages {
		if seen[name] {
			continue // each page once per snapshot (bodies are keyed by page name)
		}
		seen[name] = true
		var r captured
		if skip != "" && validPage(name) {
			r.pc = model.PageCapture{Page: name, URL: c.pageURL(name), FetchedAt: formatTS(c.now()), NotAttempted: true, Err: skip}
		} else {
			r = c.capture(ctx, name)
		}
		if r.responded {
			responded = true
			bodies[name] = r.body
		} else {
			if firstErr == "" {
				firstErr = name + ": " + r.pc.Err
			}
			if r.err != nil {
				causes = append(causes, r.err)
			}
		}
		if r.noConn && skip == "" {
			skip = "not attempted: no connection to the gateway (" + name + " failed)"
		}
		if r.page != nil {
			c.parseInto(&snap, &r.pc, r.page)
		}
		snap.Pages = append(snap.Pages, r.pc)
	}
	snap.Derived = Derive(&snap, c.deriveTime(&snap), c.loc)
	switch {
	case len(pages) == 0:
		return snap, bodies, errors.New("gateway: no pages requested")
	case !responded:
		return snap, bodies, &snapshotError{
			msg:    fmt.Sprintf("gateway %s: no page could be fetched (%s)", c.host, firstErr),
			causes: causes,
		}
	}
	return snap, bodies, nil
}

// snapshotError is Snapshot's error when no page produced an HTTP response: the message names
// the first failure, Unwrap exposes the failures of all pages.
type snapshotError struct {
	msg    string
	causes []error
}

func (e *snapshotError) Error() string   { return e.msg }
func (e *snapshotError) Unwrap() []error { return e.causes }

// captured is the outcome of fetching one status page.
type captured struct {
	pc        model.PageCapture
	body      []byte // exact bytes as received
	page      *page  // scanned page when eligible for parsing (HTTP 200, complete, not login/sessions-full)
	responded bool   // an HTTP response was received
	noConn    bool   // no connection could be established (the gateway is unreachable)
	err       error  // why no HTTP response was received (nil when one was, or for an invalid name)
}

// capture fetches one page.
func (c *Client) capture(ctx context.Context, name string) captured {
	r := captured{pc: model.PageCapture{Page: name}}
	pc := &r.pc
	if !validPage(name) {
		pc.FetchedAt = formatTS(c.now())
		pc.Err = "invalid page name"
		return r
	}
	pc.URL = c.pageURL(name)
	if err := ctx.Err(); err != nil {
		pc.FetchedAt = formatTS(c.now())
		pc.Err = "not fetched: " + err.Error()
		r.err = err
		return r
	}
	ex := c.do(ctx, c.snapClient, http.MethodGet, pc.URL, "", "")
	pc.FetchedAt = formatTS(ex.started)
	pc.DurMs = ex.dur.Milliseconds()
	pc.TLSCertSHA256 = ex.cert
	if !ex.responded {
		if ex.err != nil {
			pc.Err = ex.err.Error()
			r.err = ex.err
		}
		r.noConn = !ex.connected && ctx.Err() == nil
		c.log.Debug("gateway page fetch failed", "page", name, "connected", ex.connected, "err", pc.Err)
		return r
	}
	r.responded = true
	r.body = ex.body
	pc.Status = ex.status
	pc.Location = ex.location
	pc.Bytes = len(ex.body)
	sum := sha256.Sum256(ex.body)
	pc.SHA256 = hex.EncodeToString(sum[:])

	p := scan(ex.body)
	pc.LoginPage = p.isLogin()
	switch {
	case ex.err != nil:
		pc.Err = ex.err.Error()
	case p.sessionsFull():
		pc.Err = "gateway reports all web server sessions are in use"
		c.noteSessionsFull()
	case ex.status != http.StatusOK:
		pc.Err = "unexpected HTTP status " + statusText(ex.status)
	case pc.LoginPage:
		pc.Err = "login page returned instead of the status page"
	default:
		r.page = p
	}
	c.log.Debug("gateway page fetched", "page", name, "status", pc.Status, "bytes", pc.Bytes,
		"dur_ms", pc.DurMs, "login_page", pc.LoginPage, "err", pc.Err)
	return r
}

// parseInto parses a successfully fetched page into the snapshot; a parse failure is
// recorded in the page's capture.
func (c *Client) parseInto(snap *model.GatewaySnapshot, pc *model.PageCapture, p *page) {
	var err error
	switch pc.Page {
	case "sysinfo":
		snap.System, err = parseSysInfo(p)
	case "broadbandstatistics":
		snap.Broadband, err = parseBroadband(p)
	case "fiberstat":
		snap.Fiber, err = parseFiber(p)
	case "lanstatistics":
		snap.LAN, err = parseLAN(p)
	}
	if err != nil {
		pc.Err = "parse: " + err.Error()
	}
}

// deriveTime is the reference time for Derive: the recorded start of the sysinfo request
// (the page whose clock and uptime are compared), else of the first page. It is parsed back
// from the recorded string so that anyone can reproduce Derive from the ledger record.
func (c *Client) deriveTime(snap *model.GatewaySnapshot) time.Time {
	pick := ""
	for _, pc := range snap.Pages {
		if pc.Page == "sysinfo" && pc.FetchedAt != "" {
			pick = pc.FetchedAt
			break
		}
		if pick == "" {
			pick = pc.FetchedAt
		}
	}
	if t, err := time.Parse(time.RFC3339Nano, pick); err == nil {
		return t
	}
	return c.now()
}

func formatTS(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

func statusText(code int) string {
	if t := http.StatusText(code); t != "" {
		return fmt.Sprintf("%d %s", code, t)
	}
	return fmt.Sprint(code)
}
