package probe

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"attmonitor/internal/model"
)

const (
	httpBodyLimit = 64 << 10 // bytes of body read and hashed
	bodyPrefixLen = 512      // bytes of body kept as text in the result
)

// newHTTPTransport builds the template of the HTTP checks' transports: direct connections
// only (a system or environment proxy would measure the proxy, not the line), no keep-alive
// (every check makes a fresh connection whose peer is recorded), and no transparent gzip so
// the body hash covers the bytes as sent. TLS certificates are verified the standard way
// (system roots, the URL's host name); this configuration never relaxes that.
func newHTTPTransport(dial func(ctx context.Context, network, address string) (net.Conn, error)) *http.Transport {
	return &http.Transport{
		Proxy:                  nil,
		DialContext:            dial,
		DisableKeepAlives:      true,
		DisableCompression:     true,
		ForceAttemptHTTP2:      false,
		MaxResponseHeaderBytes: 64 << 10,
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12},
	}
}

// checkTransport returns the transport for one check: a copy of the template whose TLS
// configuration reports the server's certificate to leaf.
//
// Verification is not touched (InsecureSkipVerify stays false): crypto/tls verifies the
// chain against the system roots (rootCAs in tests), with the intermediates the server sent,
// for the URL's host name, exactly as before. VerifyConnection only runs after that
// verification succeeded and merely observes; a failed verification is reported by
// crypto/tls as a *tls.CertificateVerificationError, which carries the certificates (see
// tlsLeaf.setFromError).
//
// A transport per check costs nothing here (connections are never reused) and keeps
// concurrent checks from seeing each other's certificates. Closing it when the check ends
// (CloseIdleConnections) also cancels a dial or TLS handshake that net/http keeps running
// after the request gave up, which would otherwise hold a connection open for as long as an
// unresponsive server allows.
func (p *Prober) checkTransport(leaf *tlsLeaf) *http.Transport {
	t := p.transport.Clone() // deep-copies TLSClientConfig: the template is never modified
	if t.TLSClientConfig == nil {
		t.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	t.TLSClientConfig.RootCAs = p.rootCAs // nil: system roots
	t.TLSClientConfig.VerifyConnection = func(cs tls.ConnectionState) error {
		leaf.set(cs.PeerCertificates)
		return nil
	}
	return t
}

// tlsLeaf holds the SHA-256 of the leaf certificate presented to one HTTPS check. It is
// written from TLS callbacks, which run on net/http's dial goroutine.
type tlsLeaf struct {
	mu  sync.Mutex
	sum string // lowercase hex of the DER certificate; "" = none seen
}

// set records certs[0], the server's leaf certificate (Raw is its DER as received).
func (l *tlsLeaf) set(certs []*x509.Certificate) {
	if len(certs) == 0 || certs[0] == nil || len(certs[0].Raw) == 0 {
		return
	}
	sum := sha256.Sum256(certs[0].Raw)
	l.mu.Lock()
	l.sum = hex.EncodeToString(sum[:])
	l.mu.Unlock()
}

// setFromError records the leaf certificate of a failed certificate verification: crypto/tls
// returns the presented chain with the error. Other errors carry no certificate.
func (l *tlsLeaf) setFromError(err error) {
	var cve *tls.CertificateVerificationError
	if errors.As(err, &cve) {
		l.set(cve.UnverifiedCertificates)
	}
}

func (l *tlsLeaf) get() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.sum
}

// HTTP performs one GET of rawURL without following redirects and with a fresh connection.
// The peer address is captured from httptrace (GotConn, or the TCP connect when TLS fails),
// at most 64 KiB of the body are read and hashed (BodySHA256 covers exactly the bytes read),
// BodyPrefix keeps the first 512 bytes as text (invalid UTF-8 replaced by U+FFFD), and
// RTTus is the time until the response headers arrived.
//
// OK requires the status to match (expectStatus 0 = any 2xx), the body to contain
// expectBody (when set) and the body to be read without error. Hijacked is set when a
// check addressed to a public host was answered by the gateway or a non-public address,
// or redirected to one (see httpHijack); checks aimed at local hosts are never flagged.
//
// For https:// URLs, TLSCertSHA256 is the lowercase hex SHA-256 of the DER leaf certificate
// the server presented, whatever became of it: recorded when it verified (also if the
// handshake or the request failed afterwards) and when its verification failed, since a
// certificate that does not verify for a public name is the evidence of interception. The
// verification itself is the standard one (see checkTransport): an HTTPS check can only be
// OK with a certificate valid for the URL's host, and Err says why a certificate was
// rejected. Plain http:// checks leave TLSCertSHA256 empty.
func (p *Prober) HTTP(ctx context.Context, name, rawURL string, expectStatus int, expectBody string, timeout time.Duration) model.HTTPResult {
	res := model.HTTPResult{Name: name, URL: rawURL}
	u, err := url.Parse(rawURL)
	if err != nil {
		res.Err = err.Error()
		return res
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		res.Err = "unsupported URL " + rawURL + " (want http:// or https:// with a host)"
		return res
	}
	to := effectiveTimeout(ctx, timeout)
	if ctx.Err() != nil || to <= 0 {
		res.Err = StatusCanceled + ": " + ctxErr(ctx).Error()
		return res
	}
	rctx, cancel := context.WithTimeout(ctx, to)
	defer cancel()

	var mu sync.Mutex // trace hooks may run on dialer goroutines
	var connAddr, dialAddr string
	var leaf tlsLeaf
	trace := &httptrace.ClientTrace{
		ConnectDone: func(network, addr string, err error) {
			if err == nil {
				mu.Lock()
				dialAddr = addr
				mu.Unlock()
			}
		},
		GotConn: func(info httptrace.GotConnInfo) {
			if info.Conn == nil {
				return
			}
			if ra := info.Conn.RemoteAddr(); ra != nil {
				mu.Lock()
				connAddr = ra.String()
				mu.Unlock()
			}
		},
		TLSHandshakeDone: func(cs tls.ConnectionState, err error) {
			if err != nil {
				// Captured here too: client.Do reports the request's own error (e.g. its
				// deadline) instead of the handshake's when both happened.
				leaf.setFromError(err)
				return
			}
			leaf.set(cs.PeerCertificates)
		},
	}
	remote := func() string {
		mu.Lock()
		defer mu.Unlock()
		if connAddr != "" {
			return connAddr
		}
		return dialAddr
	}

	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(rctx, trace), http.MethodGet, rawURL, nil)
	if err != nil {
		res.Err = err.Error()
		return res
	}
	req.Header.Set("User-Agent", p.userAgent)
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Cache-Control", "no-cache")
	transport := p.checkTransport(&leaf)
	defer transport.CloseIdleConnections() // runs after the body is closed (defers are LIFO)
	client := &http.Client{
		Transport:     transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}

	sw := startStopwatch()
	resp, err := client.Do(req)
	if err != nil {
		leaf.setFromError(err)
		res.TLSCertSHA256 = leaf.get()
		res.RemoteAddr = remote()
		res.Err = err.Error()
		res.Hijacked, res.HijackWhy = httpHijack(u, res.RemoteAddr, "", p.gatewayIP)
		return res
	}
	defer resp.Body.Close()
	res.RTTus = micros(sw.elapsed())
	if resp.TLS != nil {
		leaf.set(resp.TLS.PeerCertificates) // the connection that answered
	}
	res.TLSCertSHA256 = leaf.get()
	res.Status = resp.StatusCode
	res.Location = resp.Header.Get("Location")
	res.RemoteAddr = remote()

	body, readErr := io.ReadAll(io.LimitReader(resp.Body, httpBodyLimit))
	sum := sha256.Sum256(body)
	res.BodySHA256 = hex.EncodeToString(sum[:])
	res.BodyPrefix = prefixUTF8(body, bodyPrefixLen)
	if readErr != nil {
		res.Err = "reading body: " + readErr.Error()
	}

	statusOK := resp.StatusCode == expectStatus ||
		expectStatus == 0 && resp.StatusCode >= 200 && resp.StatusCode <= 299
	bodyOK := expectBody == "" || bytes.Contains(body, []byte(expectBody))
	res.OK = statusOK && bodyOK && readErr == nil
	res.Hijacked, res.HijackWhy = httpHijack(u, res.RemoteAddr, res.Location, p.gatewayIP)
	return res
}

// httpHijack decides whether a check addressed to reqURL was answered by something other
// than the public server it named: the peer is the gateway or a non-public address, or the
// Location header points at one (or at a local host name such as *.attlocal.net). Checks
// whose own host is local are never flagged. The reason lists every finding.
func httpHijack(reqURL *url.URL, remoteAddr, location, gatewayIP string) (bool, string) {
	host := reqURL.Hostname()
	if host == "" || isLocalHost(host) {
		return false, ""
	}
	var reasons []string
	if remoteAddr != "" {
		if ap, err := netip.ParseAddrPort(remoteAddr); err == nil {
			if why := suspiciousAddr(ap.Addr(), gatewayIP); why != "" {
				reasons = append(reasons, boundedReason(fmt.Sprintf("connected to %s, %s, for public host %s",
					remoteAddr, why, clipText(host, maxReasonItem)), ""))
			}
		}
	}
	if location != "" {
		// The full header is in HTTPResult.Location; the reason quotes a bounded prefix.
		quoted := clipText(location, maxReasonItem)
		if lu, err := reqURL.Parse(location); err == nil {
			lh := lu.Hostname()
			if a, err := netip.ParseAddr(lh); err == nil {
				if why := suspiciousAddr(a, gatewayIP); why != "" {
					reasons = append(reasons, boundedReason(fmt.Sprintf("redirected to %s, %s", quoted, why), ""))
				}
			} else if isLocalName(lh) {
				reasons = append(reasons, boundedReason(fmt.Sprintf("redirected to %s, a local host name", quoted), ""))
			}
		}
	}
	return len(reasons) > 0, strings.Join(reasons, "; ")
}

// prefixUTF8 returns at most n bytes of b as valid UTF-8: invalid sequences become U+FFFD,
// and a multi-byte character cut by the limit is dropped rather than replaced.
func prefixUTF8(b []byte, n int) string {
	if len(b) > n {
		b = b[:n]
		// Look back over at most 3 continuation bytes for the start of the last character.
		for i := 1; i <= utf8.UTFMax-1 && i <= len(b); i++ {
			c := b[len(b)-i]
			if c < utf8.RuneSelf { // ASCII: no character was cut
				break
			}
			if utf8.RuneStart(c) {
				if !utf8.FullRune(b[len(b)-i:]) {
					b = b[:len(b)-i]
				}
				break
			}
		}
	}
	return strings.ToValidUTF8(string(b), string(utf8.RuneError))
}
