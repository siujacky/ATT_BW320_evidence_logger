package anchor

import (
	"bytes"
	"context"
	"crypto"
	"errors"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/digitorus/timestamp"

	"attmonitor/internal/contracts"
)

// syncBuffer is a goroutine-safe log sink.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func TestClientTimestampSuccess(t *testing.T) {
	tsa := newCert(t, tsaSpec(t, "Fake TSA"), nil)
	f := &fakeTSA{signer: tsa}
	srv := serve(t, f)
	digest := randomDigest(t)
	var logs syncBuffer
	c := New(Options{
		URLs:      []string{srv.URL},
		Timeout:   10 * time.Second,
		Roots:     poolOf(tsa.cert),
		UserAgent: "att-monitor-test/1.0",
		Logger:    slog.New(slog.NewTextHandler(&logs, nil)),
	})
	before := time.Now().Truncate(time.Second)
	results := c.Timestamp(context.Background(), digest)
	after := time.Now()

	if len(results) != 1 {
		t.Fatalf("%d results, want 1", len(results))
	}
	r := results[0]
	if r.Err != nil {
		t.Fatalf("Err = %v", r.Err)
	}
	if r.URL != srv.URL {
		t.Errorf("URL = %q, want %q", r.URL, srv.URL)
	}
	// Token is the reply exactly as the TSA sent it.
	sent := f.replies()
	if len(sent) != 1 || !bytes.Equal(r.Token, sent[0]) {
		t.Fatal("Token differs from the bytes the TSA sent")
	}

	// The request: a POST of exactly BuildRequest(digest, nonce) with the RFC 3161 media types
	// and nothing else identifying.
	reqs := f.requests()
	if len(reqs) != 1 {
		t.Fatalf("%d requests, want 1", len(reqs))
	}
	got := reqs[0]
	if got.method != http.MethodPost {
		t.Errorf("method = %s", got.method)
	}
	for k, want := range map[string]string{
		"Content-Type": "application/timestamp-query",
		"Accept":       "application/timestamp-reply",
		"User-Agent":   "att-monitor-test/1.0",
	} {
		if v := got.header.Get(k); v != want {
			t.Errorf("header %s = %q, want %q", k, v, want)
		}
	}
	for _, k := range []string{"Cookie", "Authorization", "Accept-Encoding"} {
		if v := got.header.Get(k); v != "" {
			t.Errorf("unexpected header %s: %q", k, v)
		}
	}
	tsq, err := timestamp.ParseRequest(got.body)
	if err != nil {
		t.Fatalf("request does not parse: %v", err)
	}
	if tsq.HashAlgorithm != crypto.SHA256 || !bytes.Equal(tsq.HashedMessage, digest) || !tsq.Certificates {
		t.Errorf("request = %+v", tsq)
	}
	if tsq.Nonce == nil || tsq.Nonce.Sign() <= 0 || tsq.Nonce.BitLen() > 64 {
		t.Errorf("nonce = %v", tsq.Nonce)
	}
	if want, _ := BuildRequest(digest, tsq.Nonce); !bytes.Equal(got.body, want) {
		t.Errorf("request body is not exactly BuildRequest(digest, nonce):\n%x\n%x", got.body, want)
	}

	// Info is the verified token content.
	if r.Info.Nonce != bigHex(tsq.Nonce) {
		t.Errorf("Info.Nonce = %q, want %q", r.Info.Nonce, bigHex(tsq.Nonce))
	}
	if r.Info.GenTime.Before(before) || r.Info.GenTime.After(after) {
		t.Errorf("GenTime %v outside [%v, %v]", r.Info.GenTime, before, after)
	}
	if r.Info.TSAName != tsa.cert.Subject.String() || r.Info.Policy != testPolicy.String() || r.Info.Serial == "" {
		t.Errorf("Info = %+v", r.Info)
	}
	if !r.Info.ChainOK || r.Info.ChainNote != "" {
		t.Errorf("ChainOK = %v, ChainNote = %q with the TSA certificate in Options.Roots", r.Info.ChainOK, r.Info.ChainNote)
	}

	// Re-verifying the stored token gives the same answer; without the extra root the token is
	// still genuine but not chained, and ChainNote says why.
	if info, err := c.VerifyToken(r.Token, digest); err != nil || info != r.Info {
		t.Errorf("Client.VerifyToken = %+v, %v; want %+v", info, err, r.Info)
	}
	if info, err := VerifyToken(r.Token, digest, nil); err != nil || info.ChainOK || info.ChainNote != note3(unknownCA, "none", unknownCA) {
		t.Errorf("VerifyToken without roots = %+v, %v; want genuine, ChainOK=false, ChainNote %q", info, err, note3(unknownCA, "none", unknownCA))
	}
	if !strings.Contains(logs.String(), "time-stamp obtained") {
		t.Errorf("no success log line: %s", logs.String())
	}
}

// TestClientTimestampChainNote: a genuine time-stamp from a TSA that chains to no trusted root is
// kept (Err == nil, ChainOK == false), and Info.ChainNote says why for every root source tried —
// the same note re-verification gives — while the log carries the full diagnostic.
func TestClientTimestampChainNote(t *testing.T) {
	tsa := newCert(t, tsaSpec(t, "Untrusted TSA"), nil)
	f := &fakeTSA{signer: tsa}
	var logs syncBuffer
	c := New(Options{URLs: []string{serve(t, f).URL}, Logger: slog.New(slog.NewTextHandler(&logs, nil))})
	digest := randomDigest(t)
	r := c.Timestamp(context.Background(), digest)[0]
	if r.Err != nil {
		t.Fatalf("Err = %v", r.Err)
	}
	want := note3(unknownCA, "none", unknownCA)
	if r.Info.ChainOK || r.Info.ChainNote != want {
		t.Errorf("ChainOK = %v, ChainNote = %q; want false, %q", r.Info.ChainOK, r.Info.ChainNote, want)
	}
	if info, err := c.VerifyToken(r.Token, digest); err != nil || info != r.Info {
		t.Errorf("Client.VerifyToken = %+v, %v; want %+v", info, err, r.Info)
	}
	log := logs.String()
	if !strings.Contains(log, "chain_ok=false") || !strings.Contains(log, "extra roots: none") {
		t.Errorf("log lacks the chain diagnostic: %s", log)
	}
}

// TestClientTimestampPerURL runs one Timestamp call against many TSAs that fail in different
// ways: each failure stays confined to its own result and the good TSAs still succeed.
func TestClientTimestampPerURL(t *testing.T) {
	tsa := newCert(t, tsaSpec(t, "Fake TSA"), nil)
	digest := randomDigest(t)
	reply := func(der []byte, ct string) func(http.ResponseWriter, *http.Request, []byte) {
		return func(w http.ResponseWriter, _ *http.Request, _ []byte) {
			w.Header().Set("Content-Type", ct)
			w.Write(der)
		}
	}
	rejection, err := timestamp.CreateErrorResponse(timestamp.Rejection, timestamp.BadAlgorithm)
	if err != nil {
		t.Fatal(err)
	}

	redirectTarget := &fakeTSA{signer: tsa}
	redirectURL := serve(t, redirectTarget).URL

	type tc struct {
		name      string
		f         *fakeTSA // nil: rawURL is used as is
		rawURL    string
		wantURL   string   // "" → the URL as given
		wantErr   []string // nil → success
		wantIs    error
		wantCalls int // requests the server must have received (-1: don't check)
	}
	tests := []tc{
		{name: "good", f: &fakeTSA{signer: tsa}, wantCalls: 1},
		{name: "HTTP 500", f: &fakeTSA{handler: func(w http.ResponseWriter, _ *http.Request, _ []byte) {
			http.Error(w, "boom", http.StatusInternalServerError)
		}}, wantErr: []string{"HTTP 500 Internal Server Error", `body starts "boom`}, wantCalls: 1},
		{name: "wrong Content-Type", f: &fakeTSA{signer: tsa, contentType: "text/html; charset=utf-8"},
			wantErr: []string{`Content-Type "text/html; charset=utf-8"`}, wantCalls: 1},
		{name: "octet-stream", f: &fakeTSA{signer: tsa, contentType: "application/octet-stream"},
			wantErr: []string{"Content-Type"}, wantCalls: 1},
		{name: "legacy timestamp-response type", f: &fakeTSA{signer: tsa, contentType: "Application/TimeStamp-Response"}, wantCalls: 1},
		{name: "HTML body (captive portal)", f: &fakeTSA{handler: reply([]byte("<html>AT&T: no internet</html>"), "application/timestamp-reply")},
			wantErr: []string{"anchor:"}, wantCalls: 1},
		{name: "oversize with Content-Length", f: &fakeTSA{handler: func(w http.ResponseWriter, _ *http.Request, _ []byte) {
			w.Header().Set("Content-Type", "application/timestamp-reply")
			w.Header().Set("Content-Length", "1048577")
			w.Write(make([]byte, maxResponseBytes+1))
		}}, wantErr: []string{"1048577 bytes exceeds"}, wantCalls: 1},
		{name: "oversize chunked", f: &fakeTSA{handler: func(w http.ResponseWriter, _ *http.Request, _ []byte) {
			w.Header().Set("Content-Type", "application/timestamp-reply")
			chunk := make([]byte, 64<<10)
			for range 17 { // 1088 KiB
				if _, err := w.Write(chunk); err != nil {
					return
				}
				w.(http.Flusher).Flush()
			}
		}}, wantErr: []string{"exceeds the 1048576-byte limit"}, wantCalls: 1},
		{name: "exactly at the size limit", f: &fakeTSA{handler: reply(make([]byte, maxResponseBytes), "application/timestamp-reply")},
			wantErr: []string{"anchor:"}, wantCalls: 1},
		{name: "redirect not followed", f: &fakeTSA{handler: func(w http.ResponseWriter, r *http.Request, _ []byte) {
			http.Redirect(w, r, redirectURL, http.StatusTemporaryRedirect)
		}}, wantErr: []string{"HTTP 307", "redirects are not followed", redirectURL}, wantCalls: 1},
		{name: "PKIStatus rejection", f: &fakeTSA{handler: reply(rejection, "application/timestamp-reply")},
			wantErr: []string{"rejection (2)", "badAlg"}, wantCalls: 1},
		{name: "different nonce", f: &fakeTSA{signer: tsa, nonce: func(n *big.Int) *big.Int { return new(big.Int).Add(n, big.NewInt(1)) }},
			wantIs: errNonceMismatch, wantCalls: 1},
		{name: "nonce omitted", f: &fakeTSA{signer: tsa, nonce: func(*big.Int) *big.Int { return nil }},
			wantIs: errNonceMismatch, wantErr: []string{"token has none"}, wantCalls: 1},
		{name: "bad signature", f: &fakeTSA{signer: tsa, tamper: func(b []byte) []byte { return flip(b, len(b)-1, 0x01) }},
			wantErr: []string{"invalid time-stamp token"}, wantCalls: 1},
		{name: "other imprint", f: &fakeTSA{signer: tsa, imprint: func(b []byte) []byte { b[0] ^= 1; return b }},
			wantIs: errImprintMismatch, wantCalls: 1},
		{name: "no certificates", f: &fakeTSA{signer: tsa, noCerts: true}, wantIs: errNoCertificates, wantCalls: 1},
		{name: "timeout", f: &fakeTSA{handler: func(w http.ResponseWriter, r *http.Request, _ []byte) {
			select {
			case <-r.Context().Done():
			case <-time.After(30 * time.Second):
			}
		}}, wantErr: []string{"deadline exceeded"}, wantCalls: -1},
		{name: "connection refused", rawURL: "http://127.0.0.1:1/tsr", wantErr: []string{"TSA request failed"}},
		{name: "ftp scheme", rawURL: "ftp://timestamp.example/tsr", wantErr: []string{`scheme "ftp"`}},
		{name: "relative URL", rawURL: "/tsr", wantErr: []string{`scheme ""`}},
		{name: "no host", rawURL: "http:///tsr", wantErr: []string{"no host"}},
		{name: "good, second", f: &fakeTSA{signer: tsa}, wantCalls: 1},
	}
	credTarget := &fakeTSA{signer: tsa}
	credHost := strings.TrimPrefix(serve(t, credTarget).URL, "http://")
	tests = append(tests, tc{name: "credentials in URL", rawURL: "http://alice:s3cret@" + credHost + "/tsr",
		wantURL: "http://REDACTED@" + credHost + "/tsr", wantErr: []string{"must not contain credentials"}})

	urls := make([]string, len(tests))
	for i := range tests {
		if tests[i].f != nil {
			tests[i].rawURL = serve(t, tests[i].f).URL
		}
		urls[i] = tests[i].rawURL
	}
	var logs syncBuffer
	c := New(Options{URLs: urls, Timeout: 2 * time.Second, Roots: poolOf(tsa.cert),
		Logger: slog.New(slog.NewTextHandler(&logs, nil))})
	results := c.Timestamp(context.Background(), digest)
	if len(results) != len(tests) {
		t.Fatalf("%d results for %d URLs", len(results), len(tests))
	}
	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := results[i]
			wantURL := tt.wantURL
			if wantURL == "" {
				wantURL = tt.rawURL
			}
			if r.URL != wantURL {
				t.Errorf("URL = %q, want %q", r.URL, wantURL)
			}
			if tt.wantErr == nil && tt.wantIs == nil {
				if r.Err != nil {
					t.Fatalf("Err = %v", r.Err)
				}
				if sent := tt.f.replies(); len(sent) != 1 || !bytes.Equal(r.Token, sent[0]) {
					t.Error("Token differs from the reply as sent")
				}
				if !r.Info.ChainOK || r.Info.TSAName != tsa.cert.Subject.String() {
					t.Errorf("Info = %+v", r.Info)
				}
			} else {
				if r.Err == nil {
					t.Fatalf("succeeded, want error %v %v", tt.wantIs, tt.wantErr)
				}
				if tt.wantIs != nil && !errors.Is(r.Err, tt.wantIs) {
					t.Errorf("Err = %v, want %v", r.Err, tt.wantIs)
				}
				for _, s := range tt.wantErr {
					if !strings.Contains(r.Err.Error(), s) {
						t.Errorf("Err = %q, want containing %q", r.Err, s)
					}
				}
				if r.Token != nil || r.Info != (contracts.TokenInfo{}) {
					t.Errorf("failed result carries Token (%d bytes) / Info %+v", len(r.Token), r.Info)
				}
			}
			if tt.f != nil && tt.wantCalls >= 0 {
				if n := len(tt.f.requests()); n != tt.wantCalls {
					t.Errorf("server received %d requests, want %d", n, tt.wantCalls)
				}
			}
		})
	}
	if n := len(redirectTarget.requests()); n != 0 {
		t.Errorf("redirect target received %d requests", n)
	}
	if n := len(credTarget.requests()); n != 0 {
		t.Errorf("a URL with credentials was contacted (%d requests)", n)
	}
	if strings.Contains(logs.String(), "s3cret") || strings.Contains(logs.String(), "alice") {
		t.Error("credentials leaked into the log")
	}
}

// TestClientTimestampConcurrent proves the TSAs are asked in parallel: each fake TSA answers
// only once both requests have arrived.
func TestClientTimestampConcurrent(t *testing.T) {
	tsa := newCert(t, tsaSpec(t, "Fake TSA"), nil)
	var arrived sync.WaitGroup
	arrived.Add(2)
	both := make(chan struct{})
	go func() { arrived.Wait(); close(both) }()
	barrier := func(f *fakeTSA) func(http.ResponseWriter, *http.Request, []byte) {
		return func(w http.ResponseWriter, _ *http.Request, body []byte) {
			arrived.Done()
			select {
			case <-both:
				f.respond(w, body)
			case <-time.After(10 * time.Second):
				http.Error(w, "requests were not concurrent", http.StatusServiceUnavailable)
			}
		}
	}
	a, b := &fakeTSA{signer: tsa}, &fakeTSA{signer: tsa}
	a.handler, b.handler = barrier(a), barrier(b)
	c := New(Options{URLs: []string{serve(t, a).URL, serve(t, b).URL}, Timeout: 20 * time.Second})
	for i, r := range c.Timestamp(context.Background(), randomDigest(t)) {
		if r.Err != nil {
			t.Errorf("result %d: %v", i, r.Err)
		}
	}
}

func TestClientTimestampNonceFreshness(t *testing.T) {
	tsa := newCert(t, tsaSpec(t, "Fake TSA"), nil)
	f := &fakeTSA{signer: tsa}
	u := serve(t, f).URL
	c := New(Options{URLs: []string{u, u, u}})
	for _, r := range c.Timestamp(context.Background(), randomDigest(t)) {
		if r.Err != nil {
			t.Fatal(r.Err)
		}
	}
	seen := map[string]bool{}
	for _, req := range f.requests() {
		tsq, err := timestamp.ParseRequest(req.body)
		if err != nil {
			t.Fatal(err)
		}
		if seen[tsq.Nonce.String()] {
			t.Errorf("nonce %v reused", tsq.Nonce)
		}
		seen[tsq.Nonce.String()] = true
	}
}

func TestClientTimestampInvalidInput(t *testing.T) {
	tsa := newCert(t, tsaSpec(t, "Fake TSA"), nil)
	f := &fakeTSA{signer: tsa}
	u := serve(t, f).URL
	c := New(Options{URLs: []string{u, u}})

	t.Run("digest length", func(t *testing.T) {
		for _, d := range [][]byte{nil, make([]byte, 31), make([]byte, 64)} {
			res := c.Timestamp(context.Background(), d)
			if len(res) != 2 {
				t.Fatalf("%d results", len(res))
			}
			for _, r := range res {
				if !errors.Is(r.Err, errDigestLength) {
					t.Errorf("len %d: Err = %v", len(d), r.Err)
				}
			}
		}
		if n := len(f.requests()); n != 0 {
			t.Errorf("%d requests sent for an invalid digest", n)
		}
	})
	t.Run("canceled context", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		for _, r := range c.Timestamp(ctx, randomDigest(t)) {
			if !errors.Is(r.Err, context.Canceled) {
				t.Errorf("Err = %v, want context.Canceled", r.Err)
			}
		}
	})
	t.Run("no URLs", func(t *testing.T) {
		if res := New(Options{}).Timestamp(context.Background(), randomDigest(t)); len(res) != 0 {
			t.Errorf("%d results without URLs", len(res))
		}
	})
}

func TestNewDefaults(t *testing.T) {
	urls := []string{"http://a.example/tsr"}
	c := New(Options{URLs: urls})
	urls[0] = "http://changed.example/"
	if c.urls[0] != "http://a.example/tsr" {
		t.Error("Options.URLs not copied")
	}
	if c.timeout != defaultTimeout || c.userAgent != defaultUserAgent || c.log == nil {
		t.Errorf("defaults: timeout %v, UA %q, log %v", c.timeout, c.userAgent, c.log)
	}
	tr, ok := c.hc.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport %T", c.hc.Transport)
	}
	if !tr.DisableKeepAlives || !tr.DisableCompression || tr.MaxResponseHeaderBytes != 64<<10 || tr.Proxy == nil {
		t.Errorf("transport settings: %+v", tr)
	}
	if err := c.hc.CheckRedirect(nil, nil); !errors.Is(err, http.ErrUseLastResponse) {
		t.Errorf("CheckRedirect = %v", err)
	}
	if c2 := New(Options{Timeout: -time.Second}); c2.timeout != defaultTimeout {
		t.Errorf("negative timeout → %v", c2.timeout)
	}
}

// TestClientCustomHTTPClient checks that a caller-supplied client is used for transport but
// never sends cookies or follows redirects, and is itself left unmodified.
func TestClientCustomHTTPClient(t *testing.T) {
	tsa := newCert(t, tsaSpec(t, "Fake TSA"), nil)
	f := &fakeTSA{signer: tsa}
	mux := http.NewServeMux()
	mux.Handle("/tsr", f)
	mux.HandleFunc("/moved", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/tsr", http.StatusFound)
	})
	srv := serve(t, mux)
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	base, _ := url.Parse(srv.URL)
	jar.SetCookies(base, []*http.Cookie{{Name: "session", Value: "abc", Path: "/"}})
	custom := &http.Client{Jar: jar}

	c := New(Options{URLs: []string{srv.URL + "/tsr", srv.URL + "/moved"}, HTTPClient: custom})
	res := c.Timestamp(context.Background(), randomDigest(t))
	if res[0].Err != nil {
		t.Errorf("/tsr: %v", res[0].Err)
	}
	if res[1].Err == nil || !strings.Contains(res[1].Err.Error(), "HTTP 302") {
		t.Errorf("/moved: Err = %v, want an unfollowed 302", res[1].Err)
	}
	reqs := f.requests()
	if len(reqs) != 1 {
		t.Errorf("/tsr received %d requests, want 1 (redirect must not be followed)", len(reqs))
	}
	for _, r := range reqs {
		if r.header.Get("Cookie") != "" {
			t.Errorf("cookie sent: %q", r.header.Get("Cookie"))
		}
	}
	if custom.Jar != jar || custom.CheckRedirect != nil {
		t.Error("the caller's http.Client was modified")
	}
}

func TestCheckTSAURL(t *testing.T) {
	tests := []struct {
		raw, wantErr, display string
	}{
		{"http://timestamp.digicert.com", "", "http://timestamp.digicert.com"},
		{"https://freetsa.org/tsr", "", "https://freetsa.org/tsr"},
		{"HTTPS://FreeTSA.org/tsr", "", "HTTPS://FreeTSA.org/tsr"},
		{"ftp://freetsa.org/tsr", "scheme", "ftp://freetsa.org/tsr"},
		{"", "scheme", ""},
		{"freetsa.org/tsr", "scheme", "freetsa.org/tsr"},
		{"https:///tsr", "no host", "https:///tsr"},
		{"http://%zz", "invalid", "http://%zz"},
		{"https://user@freetsa.org/tsr", "credentials", "https://REDACTED@freetsa.org/tsr"},
		{"https://user:pw@freetsa.org/tsr", "credentials", "https://REDACTED@freetsa.org/tsr"},
		{"https://user:p%zzw@freetsa.org/a@b", "invalid", "https://REDACTED@freetsa.org/a@b"},
		{"https://freetsa.org/%zz@x", "invalid", "https://REDACTED@x"}, // unparseable: over-redacted
		// Unescaped '/' in a password ends the authority early (url.Parse then fails on the port).
		{"http://user:pa/ss@host/tsr", "invalid", "http://REDACTED@host/tsr"},
		{"https://user:p#w@host/tsr", "invalid", "https://REDACTED@host/tsr"},
		// Without "//" the credentials end up in the opaque part of a scheme named "user".
		{"user:pw@freetsa.org/tsr", "scheme", "user:REDACTED@freetsa.org/tsr"},
	}
	for _, tt := range tests {
		err := checkTSAURL(tt.raw)
		if tt.wantErr == "" && err != nil || tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)) {
			t.Errorf("checkTSAURL(%q) = %v, want %q", tt.raw, err, tt.wantErr)
		}
		if err != nil && strings.Contains(err.Error(), "pw") {
			t.Errorf("error leaks the password: %v", err)
		}
		if got := displayURL(tt.raw); got != tt.display {
			t.Errorf("displayURL(%q) = %q, want %q", tt.raw, got, tt.display)
		}
	}
}
