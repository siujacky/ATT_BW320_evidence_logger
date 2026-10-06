// Package web serves att-monitor's localhost dashboard and JSON API (docs/DESIGN.md §12).
//
// The server listens on a loopback address only, and every request is treated as possibly
// coming from a hostile web page open in the owner's browser. The middleware therefore
// enforces, for every route:
//
//   - DNS-rebinding defense: the Host header must be 127.0.0.1:<port>, localhost:<port>,
//     [::1]:<port> (or the configured loopback listen IP with that port); anything else is
//     answered 421 Misdirected Request.
//   - CSRF defense: state-changing requests (every method except GET, HEAD and OPTIONS)
//     must carry "X-ATT-Monitor: 1". A custom header cannot be attached to a cross-origin
//     request without a CORS preflight, which this server never grants. When the browser
//     sends Origin it must equal this server's origin, and a Sec-Fetch-Site header, when
//     present, must say "same-origin" (or "none"). Violations are answered 403.
//   - Response hardening: Cache-Control no-store, X-Content-Type-Options nosniff,
//     Referrer-Policy no-referrer and a strict Content-Security-Policy on every response.
//     Raw gateway pages are only ever rendered under a sandbox CSP (opaque origin, no
//     scripts), see handleBlobView.
//   - Request bodies are limited to 1 MiB.
//
// Every error response is a JSON object {"error": "..."}. Errors of the dependencies are
// mapped with errors.Is (see classifyErr): contracts.ErrBusy 409, ErrRateLimited 429,
// ErrUnavailable 503, ErrNotRecorded 500 ("applied but could not be recorded"),
// ErrLedgerBroken 503 (nothing can be recorded until the service restarts), and the gateway
// sentinels to 409/502/503 with an explanation the operator can act on. A feature the monitor
// does not offer at all (the syslog store, its retention control, the flow meter) answers 404.
package web

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"runtime/debug"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"attmonitor/internal/config"
	"attmonitor/internal/contracts"
)

// CSRF header that every state-changing request must carry (docs/DESIGN.md §12).
const (
	CSRFHeader      = "X-ATT-Monitor"
	CSRFHeaderValue = "1"
)

// MaxBodyBytes limits request bodies.
const MaxBodyBytes = 1 << 20

// Security header values.
const (
	// contentSecurityPolicy is sent with every response (docs/DESIGN.md §12).
	contentSecurityPolicy = "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; frame-ancestors 'none'"
	// sandboxCSP replaces it for raw gateway pages: they are hostile by default, so they get
	// an opaque origin, no scripts, no network access except data: images and inline styles.
	sandboxCSP = "sandbox; default-src 'none'; img-src data:; style-src 'unsafe-inline'"
)

// securityHeaders are set on every response: the headers of docs/DESIGN.md §12 plus, as
// defense in depth, legacy framing protection and no cross-origin embedding of any response
// (e.g. <script src> / <img src> from another site).
var securityHeaders = [...][2]string{
	{"Cache-Control", "no-store"},
	{"X-Content-Type-Options", "nosniff"},
	{"Content-Security-Policy", contentSecurityPolicy},
	{"Referrer-Policy", "no-referrer"},
	{"X-Frame-Options", "DENY"},
	{"Cross-Origin-Resource-Policy", "same-origin"},
}

// Server timeouts. There is deliberately no WriteTimeout: verification of a large ledger and
// bundle downloads may legitimately take minutes.
const (
	readHeaderTimeout = 10 * time.Second
	readTimeout       = time.Minute
	idleTimeout       = 2 * time.Minute
	maxHeaderBytes    = 64 << 10
)

// shutdownTimeout is the grace period for in-flight requests when Run's context ends (a
// variable only so that tests can shorten it).
var shutdownTimeout = 5 * time.Second

// Options configures the web server. Every dependency may be nil; the endpoints that need
// a missing dependency answer 503 (e.g. the CLI may serve a read-only view). The syslog
// store, its retention control and the flow meter are features a monitor may not offer: their
// endpoints then answer 404 and the dashboard leaves them out or says why.
type Options struct {
	Listen   string // loopback ip:port; "" = config default (127.0.0.1:8320); port 0 = ephemeral
	Status   contracts.StatusSource
	Actions  contracts.Actions
	Reader   contracts.LedgerReader
	Verifier contracts.Verifier
	Exporter contracts.Exporter
	// SyslogReader reads the syslog store (GET /api/syslog); its messages are linked to their
	// syslog_chunk records through Reader. SyslogControl changes how much of it is kept (POST
	// /api/syslog/retention). LiveTraffic is the flow meter (GET /api/traffic/live).
	SyslogReader  contracts.SyslogReader
	SyslogControl contracts.SyslogControl
	LiveTraffic   contracts.LiveTrafficSource
	Version       string // shown in the dashboard footer ("" = "dev")
	Logger        *slog.Logger
}

// Server is the localhost dashboard and JSON API.
type Server struct {
	status    contracts.StatusSource
	actions   contracts.Actions
	reader    contracts.LedgerReader
	verifier  contracts.Verifier
	exporter  contracts.Exporter
	syslog    contracts.SyslogReader
	syslogCtl contracts.SyslogControl
	live      contracts.LiveTrafficSource
	version   string
	log       *slog.Logger

	listen   string // configured listen address
	listenIP string // its IP, lower-case, without brackets (allowed as Host too)
	port     atomic.Uint32

	handler http.Handler
	static  map[string]staticFile // embedded assets by path below static/
	index   staticFile            // index.html with the version filled in

	// Long-running operations are single-flight: a second request gets 409. gatewayMu covers
	// every operator action on the gateway's authenticated side (the notification setting and
	// confirming a changed certificate): one at a time. syslogMu covers changes of the syslog
	// retention (they delete what no longer fits).
	verifyMu  sync.Mutex
	exportMu  sync.Mutex
	anchorMu  sync.Mutex
	gatewayMu sync.Mutex
	syslogMu  sync.Mutex

	// chunkSeqs remembers the syslog_chunk record of each sealed chunk found (GET /api/syslog).
	chunkSeqs chunkSeqCache

	running atomic.Bool
	runCtx  atomic.Pointer[context.Context] // context passed to Run (cancels detached operations)

	now func() time.Time // tests may replace it
}

// New validates opts and builds the server. It does not listen yet; see Run and Handler.
func New(opts Options) (*Server, error) {
	listen := strings.TrimSpace(opts.Listen)
	if listen == "" {
		listen = config.Default().Web.Listen
	}
	ap, err := netip.ParseAddrPort(listen)
	if err != nil {
		return nil, fmt.Errorf("web: listen address %q must be a loopback ip:port (e.g. 127.0.0.1:8320): %v", listen, err)
	}
	if !ap.Addr().IsLoopback() || ap.Addr().Zone() != "" {
		return nil, fmt.Errorf("web: listen address %q is not a loopback address; the dashboard must only be reachable from this PC", listen)
	}
	log := opts.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	version := strings.TrimSpace(opts.Version)
	if version == "" {
		version = "dev"
	}
	static, index, err := loadStatic(version)
	if err != nil {
		return nil, err
	}
	s := &Server{
		status:    opts.Status,
		actions:   opts.Actions,
		reader:    opts.Reader,
		verifier:  opts.Verifier,
		exporter:  opts.Exporter,
		syslog:    opts.SyslogReader,
		syslogCtl: opts.SyslogControl,
		live:      opts.LiveTraffic,
		version:   version,
		log:       log,
		listen:    ap.String(),
		listenIP:  strings.ToLower(ap.Addr().Unmap().String()),
		static:    static,
		index:     index,
		now:       time.Now,
	}
	s.port.Store(uint32(ap.Port()))
	s.handler = s.middleware(s.routes())
	return s, nil
}

// Handler returns the complete HTTP handler (security middleware + routes). It is safe for
// concurrent use and can be mounted on any server, e.g. httptest in tests.
func (s *Server) Handler() http.Handler { return s.handler }

// Run listens on the configured loopback address and serves until ctx is done, then shuts
// down gracefully (in-flight requests get a few seconds to finish). It returns nil after a
// graceful shutdown.
func (s *Server) Run(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.listen)
	if err != nil {
		return fmt.Errorf("web: listen on %s: %w", s.listen, err)
	}
	return s.serve(ctx, ln)
}

// serve runs the HTTP server on ln until ctx is done. The Host allow-list follows the port
// actually bound (relevant when the configured port is 0).
func (s *Server) serve(ctx context.Context, ln net.Listener) error {
	if !s.running.CompareAndSwap(false, true) {
		ln.Close()
		return errors.New("web: server is already running")
	}
	defer s.running.Store(false)
	if tcp, ok := ln.Addr().(*net.TCPAddr); ok {
		s.port.Store(uint32(tcp.Port))
	}
	s.runCtx.Store(&ctx)
	defer s.runCtx.Store(nil)

	srv := &http.Server{
		Handler:           s.handler,
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		IdleTimeout:       idleTimeout,
		MaxHeaderBytes:    maxHeaderBytes,
		BaseContext:       func(net.Listener) context.Context { return ctx },
		ErrorLog:          slog.NewLogLogger(s.log.Handler(), slog.LevelWarn),
	}
	s.log.Info("web: dashboard listening", "url", "http://"+ln.Addr().String()+"/")

	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	select {
	case err := <-errc:
		return fmt.Errorf("web: serve: %w", err)
	case <-ctx.Done():
	}
	shCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(shCtx); err != nil {
		// Requests still running after the grace period (or connections that never sent a
		// request, e.g. a browser's speculative preconnect) are cut off. That is the normal
		// end of a stop, not a failure of the server.
		s.log.Info("web: closing connections still open after the shutdown grace period", "err", err)
		srv.Close()
	}
	if serr := <-errc; serr != nil && !errors.Is(serr, http.ErrServerClosed) {
		return fmt.Errorf("web: serve: %w", serr)
	}
	s.log.Info("web: dashboard stopped")
	return nil
}

// ----------------------------------------------------------------------------- middleware

// middleware applies the security policy of docs/DESIGN.md §12 to every request.
func (s *Server) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w}
		hdr := sw.Header()
		for _, kv := range securityHeaders {
			hdr.Set(kv[0], kv[1])
		}

		defer func() {
			if v := recover(); v != nil {
				if v == http.ErrAbortHandler {
					panic(v)
				}
				s.log.Error("web: handler panic", "method", r.Method, "path", r.URL.Path,
					"panic", fmt.Sprint(v), "stack", string(debug.Stack()))
				if !sw.wroteHeader {
					writeError(sw, http.StatusInternalServerError, "internal error")
				}
			}
			s.logRequest(r, sw.code(), time.Since(start))
		}()

		if !s.hostAllowed(r.Host) {
			s.log.Warn("web: rejected request with unexpected Host header (DNS-rebinding defense)",
				"host", r.Host, "remote", r.RemoteAddr, "method", r.Method, "path", r.URL.Path)
			writeError(sw, http.StatusMisdirectedRequest,
				"host not allowed: open the dashboard as http://127.0.0.1:"+strconv.Itoa(int(s.port.Load()))+"/")
			return
		}
		if !isSafeMethod(r.Method) {
			if why := csrfProblem(r); why != "" {
				s.log.Warn("web: rejected state-changing request (CSRF defense)", "reason", why,
					"origin", r.Header.Get("Origin"), "remote", r.RemoteAddr, "method", r.Method, "path", r.URL.Path)
				writeError(sw, http.StatusForbidden, why)
				return
			}
		}
		if r.ContentLength > MaxBodyBytes {
			writeError(sw, http.StatusRequestEntityTooLarge, "request body too large (limit 1 MiB)")
			return
		}
		// MaxBytesReader gets the original writer so that net/http can close the
		// connection after an oversized body.
		r.Body = http.MaxBytesReader(w, r.Body, MaxBodyBytes)
		next.ServeHTTP(sw, r)
	})
}

func (s *Server) logRequest(r *http.Request, code int, d time.Duration) {
	level := slog.LevelDebug
	if code >= 500 {
		level = slog.LevelWarn
	}
	s.log.Log(context.Background(), level, "web: request", "method", r.Method, "path", r.URL.Path,
		"status", code, "dur_ms", d.Milliseconds(), "remote", r.RemoteAddr)
}

// isSafeMethod reports whether m cannot change state (RFC 9110 §9.2.1).
func isSafeMethod(m string) bool {
	return m == http.MethodGet || m == http.MethodHead || m == http.MethodOptions
}

// hostAllowed implements the Host allow-list (DNS-rebinding defense).
func (s *Server) hostAllowed(hostport string) bool {
	port := strconv.Itoa(int(s.port.Load()))
	host, p, err := net.SplitHostPort(hostport)
	if err != nil {
		// No port in Host: only equivalent when the server uses the default HTTP port.
		if port != "80" {
			return false
		}
		host, p = strings.TrimSuffix(strings.TrimPrefix(hostport, "["), "]"), port
	}
	if p != port {
		return false
	}
	switch host = strings.ToLower(host); host {
	case "127.0.0.1", "localhost", "::1":
		return true
	}
	return host == s.listenIP
}

// csrfProblem returns why a state-changing request must be rejected, or "".
func csrfProblem(r *http.Request) string {
	if r.Header.Get(CSRFHeader) != CSRFHeaderValue {
		return "missing or invalid " + CSRFHeader + " header"
	}
	if origins, present := r.Header["Origin"]; present {
		if len(origins) != 1 || !strings.EqualFold(origins[0], "http://"+r.Host) {
			return "cross-origin request rejected"
		}
	}
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" && site != "none" {
		return "cross-site request rejected"
	}
	return ""
}

// statusWriter records the status code for logging and panic recovery.
type statusWriter struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (w *statusWriter) WriteHeader(code int) {
	if !w.wroteHeader {
		w.status, w.wroteHeader = code, true
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(b)
}

// Unwrap lets http.ResponseController reach the underlying writer.
func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *statusWriter) code() int {
	if !w.wroteHeader {
		return http.StatusOK
	}
	return w.status
}

// serveContent serves content with http.ServeContent (HEAD, Range and conditional requests)
// while keeping this server's rules for the error answers ServeContent writes by itself — 416
// for an unsatisfiable Range, 412 for a failed precondition. net/http answers those in plain
// text and, since Go 1.23, deletes Cache-Control from them; here they become the usual JSON
// error, keep every security header (including a sandbox CSP set by the handler) and drop the
// headers that describe the content (attachment name, SHA-256, Last-Modified).
func serveContent(w http.ResponseWriter, r *http.Request, modtime time.Time, content io.ReadSeeker) {
	cw := &contentWriter{ResponseWriter: w, keep: http.Header{}}
	for _, kv := range securityHeaders {
		if v := w.Header().Values(kv[0]); len(v) > 0 {
			cw.keep[http.CanonicalHeaderKey(kv[0])] = slices.Clone(v)
		}
	}
	http.ServeContent(cw, r, "", modtime, content)
}

// contentWriter turns the error answers of http.ServeContent into JSON errors.
type contentWriter struct {
	http.ResponseWriter
	keep   http.Header // security headers as they were before ServeContent ran
	failed bool
}

func (w *contentWriter) WriteHeader(code int) {
	if w.failed {
		return
	}
	if code < http.StatusBadRequest {
		w.ResponseWriter.WriteHeader(code)
		return
	}
	w.failed = true
	h := w.ResponseWriter.Header()
	for _, k := range []string{"Content-Disposition", "X-Content-SHA256", "Last-Modified", "Etag", "Content-Length"} {
		h.Del(k)
	}
	for k, v := range w.keep {
		h[k] = v
	}
	msg := strings.ToLower(http.StatusText(code))
	if code == http.StatusRequestedRangeNotSatisfiable {
		if n, ok := strings.CutPrefix(h.Get("Content-Range"), "bytes */"); ok {
			msg += " (the content has " + n + " bytes)"
		}
	}
	writeError(w.ResponseWriter, code, msg)
}

func (w *contentWriter) Write(b []byte) (int, error) {
	if w.failed {
		return len(b), nil // net/http's plain-text message; the JSON error is already written
	}
	return w.ResponseWriter.Write(b)
}

// Unwrap lets http.ResponseController reach the underlying writer.
func (w *contentWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// ----------------------------------------------------------------------------- routing

// router registers method-specific ServeMux patterns (Go 1.22+) and, once per path, a
// method-less fallback so that a wrong method gets a JSON 405 with an Allow header instead of
// ServeMux's plain-text one.
type router struct {
	mux     *http.ServeMux
	allowed map[string][]string // path pattern -> registered methods (read-only after setup)
}

func newRouter() *router {
	return &router{mux: http.NewServeMux(), allowed: map[string][]string{}}
}

func (rt *router) handle(method, path string, h http.HandlerFunc) {
	if _, seen := rt.allowed[path]; !seen {
		rt.mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Allow", rt.allow(path))
			writeError(w, http.StatusMethodNotAllowed, "method "+r.Method+" not allowed")
		})
	}
	rt.allowed[path] = append(rt.allowed[path], method)
	rt.mux.HandleFunc(method+" "+path, h)
}

func (rt *router) allow(path string) string {
	ms := slices.Clone(rt.allowed[path])
	if slices.Contains(ms, http.MethodGet) && !slices.Contains(ms, http.MethodHead) {
		ms = append(ms, http.MethodHead) // GET patterns also match HEAD
	}
	slices.Sort(ms)
	return strings.Join(ms, ", ")
}

// routes builds the endpoint table of docs/DESIGN.md §12.
func (s *Server) routes() http.Handler {
	rt := newRouter()
	rt.handle(http.MethodGet, "/{$}", s.handleIndex)
	rt.handle(http.MethodGet, "/static/{file...}", s.handleStatic)

	rt.handle(http.MethodGet, "/api/status", s.handleStatus)
	rt.handle(http.MethodGet, "/api/series", s.handleSeries)
	rt.handle(http.MethodGet, "/api/incidents", s.handleIncidents)
	rt.handle(http.MethodGet, "/api/incidents/{id}", s.handleIncident)
	rt.handle(http.MethodGet, "/api/records", s.handleRecords)
	rt.handle(http.MethodGet, "/api/syslog", s.handleSyslog)
	rt.handle(http.MethodPost, "/api/syslog/retention", s.handleSyslogRetention)
	rt.handle(http.MethodGet, "/api/traffic/live", s.handleLiveTraffic)
	rt.handle(http.MethodGet, "/api/blobs/{id}", s.handleBlob)
	rt.handle(http.MethodGet, "/api/blobs/{id}/view", s.handleBlobView)
	rt.handle(http.MethodPost, "/api/verify", s.handleVerify)
	rt.handle(http.MethodGet, "/api/exports", s.handleExportList)
	rt.handle(http.MethodPost, "/api/exports", s.handleExportCreate)
	rt.handle(http.MethodGet, "/api/exports/{name}", s.handleExportDownload)
	rt.handle(http.MethodPost, "/api/notes", s.handleNote)
	rt.handle(http.MethodPost, "/api/gateway/notification", s.handleNotification)
	rt.handle(http.MethodPost, "/api/gateway/trust-cert", s.handleTrustCert)
	rt.handle(http.MethodPost, "/api/anchor", s.handleAnchor)

	rt.mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		writeError(w, http.StatusNotFound, "not found")
	})
	return rt.mux
}
