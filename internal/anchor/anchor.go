// Package anchor implements RFC 3161 time-stamping of the evidence ledger head by independent
// public Time-Stamp Authorities (docs/DESIGN.md §11) and the verification of the tokens.
//
// Privacy: a request carries only the 32-byte SHA-256 digest (plus a random nonce and
// certReq=true); no evidence data leaves the machine.
//
// Honesty of the result: Client.Timestamp reports success for a TSA only when the reply is a
// granted RFC 3161 TimeStampResp whose token passes VerifyToken for the digest and echoes the
// request's nonce. VerifyToken separates two questions:
//
//   - Is the token genuine for this digest? Any doubt is an error: input that is not DER, a
//     TimeStampResp/CMS envelope with components RFC 3161 and RFC 5652 do not define, PKIStatus
//     other than granted/grantedWithMods, no embedded certificate, bad CMS signature or message
//     digest, content type other than id-ct-TSTInfo, ESS signing-certificate mismatch, more than
//     one signer, a TSTInfo version other than 1, a tsa name that does not name the signer, an
//     imprint algorithm other than SHA-256, or an imprint other than the digest.
//   - Is the signer a trusted TSA? Reported as TokenInfo.ChainOK, never as an error: the signer
//     certificate must meet the RFC 3161 TSA profile (critical extended key usage timeStamping
//     only, the `openssl ts -verify` rules) and chain at genTime, through the certificates
//     carried in the token, to the embedded FreeTSA root (pinned by SHA-256), caller-supplied
//     roots, or the Windows root store. When it does not, TokenInfo.ChainNote says why: one
//     printable line of at most 200 bytes naming each root source tried and what it reported.
//
// A genuine token only proves that whoever holds the key of the embedded certificate signed
// the time: anyone can make one with a self-signed certificate. Only ChainOK says that this key
// belongs to a trusted TSA, so a token with ChainOK == false is not evidence of time.
//
// Third-party agreement: evidence bundles are checked independently with `openssl ts -verify`.
// The checks above are those OpenSSL makes, and the envelope check closes the gaps between Go's
// lenient decoders and OpenSSL's strict ones (e.g. elements appended to a SEQUENCE), so that a
// token accepted here with ChainOK == true is also accepted by OpenSSL given the root.
package anchor

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"attmonitor/internal/contracts"
)

const (
	defaultTimeout   = 20 * time.Second
	defaultUserAgent = "att-monitor (RFC 3161 time-stamp client)"
	// maxResponseBytes bounds a TSA reply (real replies are 3-8 KiB).
	maxResponseBytes = 1 << 20
	// clockSkewWarn is the TSA-vs-local clock difference worth an operational warning.
	clockSkewWarn = 5 * time.Minute
)

// Options configures a Client.
type Options struct {
	URLs    []string      // TSA endpoints, e.g. "http://timestamp.digicert.com"
	Timeout time.Duration // per request (default 20s)
	// HTTPClient is optional (tests). It is copied, and the copy never follows redirects and
	// never sends cookies, whatever the original's settings.
	HTTPClient *http.Client
	Roots      *x509.CertPool // optional extra roots (system and embedded roots are always tried)
	UserAgent  string         // default "att-monitor (RFC 3161 time-stamp client)"
	Logger     *slog.Logger   // nil → discard
}

// Client requests and verifies RFC 3161 time-stamps. It is safe for concurrent use.
type Client struct {
	urls      []string
	timeout   time.Duration
	hc        *http.Client
	roots     *x509.CertPool
	userAgent string
	log       *slog.Logger
}

var (
	_ contracts.Anchorer      = (*Client)(nil)
	_ contracts.TokenVerifier = (*Client)(nil)
)

// New returns a Client for opts.
func New(opts Options) *Client {
	c := &Client{
		urls:      slices.Clone(opts.URLs),
		timeout:   opts.Timeout,
		roots:     opts.Roots,
		userAgent: opts.UserAgent,
		log:       opts.Logger,
	}
	if c.timeout <= 0 {
		c.timeout = defaultTimeout
	}
	if c.userAgent == "" {
		c.userAgent = defaultUserAgent
	}
	if c.log == nil {
		c.log = slog.New(slog.DiscardHandler)
	}
	var hc http.Client
	if opts.HTTPClient != nil {
		hc = *opts.HTTPClient // shares the transport; the policies below apply to the copy only
	} else {
		hc.Transport = newTransport()
	}
	// A redirect would turn the POST into something else or send it somewhere else (e.g. a
	// gateway's outage page); report it instead. Cookies are never part of a TSA request.
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	hc.Jar = nil
	c.hc = &hc
	return c
}

// newTransport returns the dedicated transport used when Options.HTTPClient is nil.
func newTransport() *http.Transport {
	return &http.Transport{
		Proxy:                  http.ProxyFromEnvironment,
		DialContext:            (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout:    10 * time.Second,
		ExpectContinueTimeout:  time.Second,
		MaxResponseHeaderBytes: 64 << 10,
		ForceAttemptHTTP2:      true,
		// Requests are minutes apart: a fresh connection per request avoids failures on stale
		// pooled connections (a POST is not retried automatically), e.g. right after an outage.
		DisableKeepAlives: true,
		// Keep the reply bytes exactly as sent; replies are small anyway.
		DisableCompression: true,
	}
}

// Timestamp asks every configured TSA, concurrently, to time-stamp digest (a 32-byte SHA-256
// value) and returns one result per configured URL, in configuration order. Each request
// carries its own random 64-bit nonce and certReq=true.
//
// A result has Err == nil only if the reply is a granted RFC 3161 response whose token passes
// VerifyToken for digest and echoes the request nonce; Token then holds the DER TimeStampResp
// exactly as received and Info its verified content (including ChainOK and ChainNote). When
// Err != nil, Token is nil and Info is zero. Failures of one TSA never affect another.
func (c *Client) Timestamp(ctx context.Context, digest []byte) []contracts.TimestampResult {
	results := make([]contracts.TimestampResult, len(c.urls))
	d := bytes.Clone(digest) // private copy for the request goroutines
	var wg sync.WaitGroup
	for i, u := range c.urls {
		wg.Go(func() { results[i] = c.timestampOne(ctx, u, d) })
	}
	wg.Wait()
	return results
}

// VerifyToken verifies a stored token against digest with the system roots, the embedded roots
// and Options.Roots (see the package-level VerifyToken).
func (c *Client) VerifyToken(token, digest []byte) (contracts.TokenInfo, error) {
	return VerifyToken(token, digest, c.roots)
}

// timestampOne performs and logs one TSA exchange.
func (c *Client) timestampOne(ctx context.Context, rawURL string, digest []byte) (res contracts.TimestampResult) {
	start := time.Now()
	res.URL = displayURL(rawURL)
	defer func() {
		if r := recover(); r != nil {
			res = contracts.TimestampResult{URL: res.URL, Err: fmt.Errorf("anchor: internal error: %v", r)}
		}
		if res.Err != nil {
			c.log.Warn("time-stamp request failed", "tsa", res.URL, "err", res.Err, "elapsed", time.Since(start))
			return
		}
		c.log.Info("time-stamp obtained", "tsa", res.URL, "gen_time", res.Info.GenTime.Format(time.RFC3339Nano),
			"serial", res.Info.Serial, "tsa_name", res.Info.TSAName, "chain_ok", res.Info.ChainOK,
			"bytes", len(res.Token), "elapsed", time.Since(start))
	}()
	token, info, err := c.exchange(ctx, rawURL, digest)
	if err != nil {
		res.Err = err
		return res
	}
	res.Token, res.Info = token, info
	return res
}

// exchange sends one TimeStampReq to rawURL and verifies the reply.
func (c *Client) exchange(ctx context.Context, rawURL string, digest []byte) ([]byte, contracts.TokenInfo, error) {
	var zero contracts.TokenInfo
	if err := checkTSAURL(rawURL); err != nil {
		return nil, zero, err
	}
	nonce, err := newNonce()
	if err != nil {
		return nil, zero, err
	}
	reqDER, err := BuildRequest(digest, nonce)
	if err != nil {
		return nil, zero, err
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rawURL, bytes.NewReader(reqDER))
	if err != nil {
		return nil, zero, fmt.Errorf("anchor: build HTTP request: %w", err)
	}
	req.Header.Set("Content-Type", "application/timestamp-query")
	req.Header.Set("Accept", "application/timestamp-reply")
	req.Header.Set("User-Agent", c.userAgent)
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, zero, fmt.Errorf("anchor: TSA request failed: %w", err)
	}
	defer resp.Body.Close()
	body, err := readReply(resp)
	if err != nil {
		return nil, zero, err
	}

	v, err := verifyCore(body, digest)
	if err != nil {
		return nil, zero, err
	}
	// The stored token must be what the contract and the bundle verifier (`openssl ts -verify
	// -in`) expect: a TimeStampResp. VerifyToken itself also accepts bare tokens.
	if v.status == statusBareToken {
		return nil, zero, errors.New("anchor: TSA replied with a bare time-stamp token instead of a TimeStampResp (RFC 3161 §2.4.2)")
	}
	if v.nonce == nil || v.nonce.Cmp(nonce) != 0 {
		got := bigHex(v.nonce)
		if got == "" {
			got = "none"
		}
		return nil, zero, fmt.Errorf("%w: sent %s, token has %s", errNonceMismatch, bigHex(nonce), got)
	}
	if v.status == statusGrantedWithMods {
		c.log.Warn("TSA granted the time-stamp with modifications", "tsa", rawURL)
	}
	if chainErr := v.checkChain(c.roots); !v.info.ChainOK {
		c.log.Warn("TSA certificate not verified to a trusted root (token kept; chain_ok=false)",
			"tsa", rawURL, "tsa_name", v.info.TSAName, "reason", chainErr)
	}
	if skew := time.Since(v.info.GenTime); skew > clockSkewWarn || skew < -clockSkewWarn {
		c.log.Warn("TSA time differs from the local clock", "tsa", rawURL,
			"gen_time", v.info.GenTime.Format(time.RFC3339), "local_minus_tsa", skew.Round(time.Second))
	}
	return body, v.info, nil
}

// readReply checks the HTTP envelope of a TSA reply and returns the body (at most
// maxResponseBytes).
func readReply(resp *http.Response) ([]byte, error) {
	if resp.StatusCode != http.StatusOK {
		// The reason phrase is server-controlled and may hold any byte but CR/LF.
		msg := "anchor: TSA answered HTTP " + clip(oneLine(resp.Status), 100)
		if loc := resp.Header.Get("Location"); loc != "" && resp.StatusCode >= 300 && resp.StatusCode < 400 {
			msg += fmt.Sprintf(" redirecting to %q (redirects are not followed)", clip(loc, 200))
		}
		return nil, errors.New(msg + bodySnippet(resp.Body))
	}
	ct := resp.Header.Get("Content-Type")
	if mt, _, err := mime.ParseMediaType(ct); err != nil ||
		(mt != "application/timestamp-reply" && mt != "application/timestamp-response") {
		return nil, fmt.Errorf("anchor: TSA reply has Content-Type %q, expected application/timestamp-reply%s",
			clip(ct, 100), bodySnippet(resp.Body))
	}
	if resp.ContentLength > maxResponseBytes {
		return nil, fmt.Errorf("anchor: TSA reply of %d bytes exceeds the %d-byte limit", resp.ContentLength, maxResponseBytes)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("anchor: reading TSA reply: %w", err)
	}
	if len(body) > maxResponseBytes {
		return nil, fmt.Errorf("anchor: TSA reply exceeds the %d-byte limit", maxResponseBytes)
	}
	return body, nil
}

// bodySnippet reads the start of an unexpected reply for the error message (an intercepting
// gateway or captive portal is easy to recognise from it).
func bodySnippet(r io.Reader) string {
	b, _ := io.ReadAll(io.LimitReader(r, 80))
	if len(b) == 0 {
		return ""
	}
	return fmt.Sprintf("; body starts %q", b)
}

// checkTSAURL accepts absolute http(s) URLs without credentials: a TSA request must not carry
// anything but the time-stamp query, and URLs end up in logs and ledger records.
func checkTSAURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return errors.New("anchor: invalid TSA URL")
	}
	switch {
	case u.Scheme != "http" && u.Scheme != "https":
		return fmt.Errorf("anchor: TSA URL scheme %q is not http or https", u.Scheme)
	case u.Host == "":
		return errors.New("anchor: TSA URL has no host")
	case u.User != nil:
		return errors.New("anchor: TSA URL must not contain credentials")
	}
	return nil
}

// displayURL returns rawURL with any user information (user name and password) redacted, also
// when the URL does not parse.
func displayURL(raw string) string {
	u, err := url.Parse(raw)
	if err == nil {
		switch {
		case u.User != nil:
			u.User = url.User("REDACTED")
			return u.String()
		case strings.Contains(u.Opaque, "@"): // "user:pw@host" parses as scheme "user"
			return u.Scheme + ":REDACTED@" + u.Opaque[strings.LastIndex(u.Opaque, "@")+1:]
		}
		return raw
	}
	if i := strings.Index(raw, "://"); i >= 0 {
		rest := raw[i+3:]
		authority := rest
		if j := strings.IndexAny(rest, "/?#"); j >= 0 {
			authority = rest[:j]
		}
		k := strings.LastIndex(authority, "@")
		if k < 0 {
			// A password with an unescaped '/', '?' or '#' ends the authority early; for a URL
			// that does not parse anyway, redact up to the last '@'.
			k = strings.LastIndex(rest, "@")
		}
		if k >= 0 {
			return raw[:i+3] + "REDACTED@" + rest[k+1:]
		}
	}
	return raw
}
