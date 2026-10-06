// Package contracts defines the interfaces between att-monitor packages
// (docs/DESIGN.md §4 dependency rule). Implementations assert conformance at compile time:
//
//	var _ contracts.Ledger = (*Store)(nil)
//
// Consumers depend only on these interfaces, so every package builds and tests in isolation;
// cmd/att-monitor wires the concrete implementations together.
package contracts

import (
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"net/netip"
	"time"

	"attmonitor/internal/model"
)

// ErrStop may be returned from a scan callback to end the scan early without error.
var ErrStop = errors.New("stop scan")

// ErrNotFound is returned when a record, blob, incident or export does not exist.
var ErrNotFound = errors.New("not found")

// Generic operation errors (wrap them; consumers use errors.Is). The web layer maps them to
// 409 / 429 / 503.
var (
	ErrBusy        = errors.New("busy: an operation of this kind is already running")
	ErrRateLimited = errors.New("rate limited")
	ErrUnavailable = errors.New("unavailable")
	// ErrNotRecorded: the operation took effect (e.g. the gateway applied a setting) but the
	// ledger record could not be written. Callers must not report the change as "not applied".
	ErrNotRecorded = errors.New("applied but not recorded in the evidence ledger")
	// ErrLedgerBroken: the ledger refuses all further writes after a failed write (sticky). The
	// monitor stops so the Windows service restarts and the ledger is reopened (crash recovery).
	ErrLedgerBroken = errors.New("evidence ledger unusable after a failed write")
)

// Gateway errors. internal/gateway wraps these so other packages can react with errors.Is
// without importing it.
var (
	ErrGatewaySessionsFull   = errors.New("gateway: all web server sessions are in use")
	ErrGatewayAuth           = errors.New("gateway: login failed")
	ErrGatewayAuthLocked     = errors.New("gateway: login paused after repeated failures")
	ErrGatewayLoginThrottled = errors.New("gateway: login throttled")
	ErrGatewayCertRejected   = errors.New("gateway: TLS certificate rejected")
	ErrGatewayNoAccessCode   = errors.New("gateway: no access code configured")
)

// ------------------------------------------------------------------ ledger

// Ledger is the append side of the evidence store (implemented by ledger.Store).
// All methods are safe for concurrent use.
type Ledger interface {
	// Append JSON-encodes data, chains, signs, writes and fsyncs one record.
	// blobs lists blob ids referenced by data (they must already exist).
	Append(recordType string, data any, blobs ...string) (model.Ref, error)
	// PutBlob stores exact bytes and returns their lowercase hex SHA-256 (deduplicated).
	PutBlob(content []byte) (string, error)
	GetBlob(id string) ([]byte, error) // ErrNotFound if absent
	HasBlob(id string) bool
	Head() model.Ref
	GenesisTS() string
	PublicKey() ed25519.PublicKey
	Fingerprint() string
	RunID() string
	// MonoNow returns nanoseconds since the store's process-start reference (the "mono" value
	// the next record would get).
	MonoNow() int64
	Close() error
}

// SegmentInfo describes one ledger segment file.
type SegmentInfo struct {
	Name       string // "ledger-2026-10-05"
	Path       string // disk path (.jsonl/.jsonl.gz) or, for bundles, an archive-internal path: read via OpenSegment
	Date       time.Time
	Compressed bool
	FirstSeq   uint64
	LastSeq    uint64 // best effort for the active segment
	Records    int
	Active     bool
}

// LedgerReader reads records, segments and blobs (implemented by ledger.Store and by the
// bundle reader used to verify exported evidence).
type LedgerReader interface {
	// Scan calls fn for each record with seq >= fromSeq in ascending order.
	// Returning ErrStop ends the scan with a nil error.
	Scan(fromSeq uint64, fn func(env model.Envelope, body model.Body) error) error
	// ScanTime calls fn for records whose ts lies in [from, to), in ascending seq order.
	ScanTime(from, to time.Time, fn func(env model.Envelope, body model.Body) error) error
	// Record returns a single record by seq (ErrNotFound if absent).
	Record(seq uint64) (model.Envelope, model.Body, error)
	Segments() ([]SegmentInfo, error)
	// OpenSegment returns the UNCOMPRESSED bytes of a segment by name.
	OpenSegment(name string) (io.ReadCloser, error)
	GetBlob(id string) ([]byte, error)
}

// Verifier performs full integrity verification (docs/DESIGN.md §6).
type Verifier interface {
	Verify(ctx context.Context) (model.VerifyReport, error)
}

// ------------------------------------------------------------------ anchoring

// TokenInfo is the verified content of an RFC 3161 time-stamp token.
type TokenInfo struct {
	GenTime time.Time
	Serial  string // hex
	Policy  string // OID dotted
	Nonce   string // hex, "" if absent
	TSAName string // signer certificate subject
	ChainOK bool   // signer certificate chains to a trusted root
	// ChainNote explains a false ChainOK (e.g. "system roots: x509: certificate signed by unknown authority").
	ChainNote string
}

// TokenVerifier checks a DER TimeStampResp (or bare token) against the digest it should cover.
type TokenVerifier interface {
	VerifyToken(token []byte, digest []byte) (TokenInfo, error)
}

// TimestampResult is the outcome of one TSA request.
type TimestampResult struct {
	URL   string
	Token []byte // DER TimeStampResp as received
	Info  TokenInfo
	Err   error
}

// Anchorer requests RFC 3161 time-stamps from the configured TSAs.
type Anchorer interface {
	// Timestamp asks every configured TSA to time-stamp digest (32-byte SHA-256).
	Timestamp(ctx context.Context, digest []byte) []TimestampResult
	TokenVerifier
}

// ------------------------------------------------------------------ gateway

// CertObserver is consulted when the gateway presents a TLS certificate whose SHA-256 differs
// from the pinned one (previous == "" on first use). Return true to accept (and re-pin).
type CertObserver func(previous, observed string) (accept bool)

// Gateway talks to the AT&T BGW320 web UI (implemented by gateway.Client).
type Gateway interface {
	// Snapshot fetches the given pages (unauthenticated, sequentially), parses and derives.
	// It returns the snapshot (PageCapture.Stored left false) and the exact bodies by page name.
	// A page that fails is reported in its PageCapture.Err; error is non-nil only if no page
	// could be fetched at all.
	Snapshot(ctx context.Context, pages []string, trigger string) (model.GatewaySnapshot, map[string][]byte, error)
	// Notification reads the "Broadband Status Notification" (bbevent) setting. Authenticated.
	Notification(ctx context.Context) (enabled bool, raw []byte, err error)
	// SetNotification changes the setting and returns the page before and after. Authenticated.
	SetNotification(ctx context.Context, enabled bool) (before, after []byte, err error)
	// Syslog reads the Syslog page (Diagnostics → Syslog): whether the gateway sends its log
	// to a syslog server, which one and at which level. Authenticated, read-only; raw is the
	// exact page that was read.
	Syslog(ctx context.Context) (setting model.SyslogSetting, raw []byte, err error)
	// SetSyslog sets the Syslog page to want (only the syslog controls change), reads it back
	// and returns the pages before and after. It never posts a form it does not fully
	// understand, and it fails unless the page read afterwards shows want. Authenticated.
	SetSyslog(ctx context.Context, want model.SyslogTarget) (before, after []byte, err error)
	// SetCertObserver installs the TLS pin policy callback.
	SetCertObserver(CertObserver)
	// PinnedCert returns the currently pinned certificate SHA-256 ("" if none yet).
	PinnedCert() string
	Host() string
}

// ------------------------------------------------------------------ probes

// Prober performs network measurements (implemented by probe.Prober).
// Name/Role fields of results are filled in by the caller.
type Prober interface {
	Ping(ctx context.Context, target string, timeout time.Duration) model.ProbeResult
	TCP(ctx context.Context, target string, timeout time.Duration) model.ProbeResult
	// DNS sends one A query for name to server ("ip" or "ip:port") over UDP.
	DNS(ctx context.Context, server, name string, timeout time.Duration) model.DNSResult
	// HTTP performs one GET without following redirects. expectStatus 0 = any 2xx;
	// expectBody "" = not checked.
	HTTP(ctx context.Context, name, url string, expectStatus int, expectBody string, timeout time.Duration) model.HTTPResult
	Traceroute(ctx context.Context, target string, maxHops int, perHop time.Duration) model.Traceroute
	SNTP(ctx context.Context, server string, timeout time.Duration) model.ClockResult
	// LocalLink describes the adapter used to reach gatewayIP; raw is the tool output to keep.
	LocalLink(ctx context.Context, gatewayIP string) (model.LocalLink, []byte, error)
}

// ------------------------------------------------------------------ monitor (consumed by web/cli)

// StatusSource exposes the monitor's live view (implemented by monitor.Monitor).
type StatusSource interface {
	Status() model.Status
	// Series returns chart data for "1h", "6h", "24h" or "7d".
	Series(rangeName string) (model.Series, error)
	// Incidents returns incidents overlapping [from, to), newest first.
	Incidents(from, to time.Time) []model.Incident
	Incident(id string) (model.Incident, bool)
}

// Actions are operator-initiated operations that write to the ledger (implemented by monitor.Monitor).
type Actions interface {
	Note(ctx context.Context, text, author, source string) (model.Ref, error)
	SetGatewayNotification(ctx context.Context, enabled bool, actor string) (model.ConfigChange, error)
	// AnchorNow time-stamps the head now. Partial success returns the anchors obtained AND a non-nil
	// error describing the TSAs that failed; no anchor at all returns (nil, error).
	AnchorNow(ctx context.Context, reason string) ([]model.Anchor, error)
	// TrustCert confirms a changed gateway TLS certificate that is pending (config
	// gateway.pending_cert_sha256): it becomes the pin, a config_change is recorded and
	// authenticated gateway operations resume. ErrNotFound when nothing is pending.
	// expectedSHA256 is the pending fingerprint the operator reviewed ("" = whatever is pending);
	// the monitor compares it under its own lock and refuses (ErrBusy-wrapped mismatch error) if a
	// different certificate is pending.
	TrustCert(ctx context.Context, actor, expectedSHA256 string) (model.ConfigChange, error)
	// RecordExport appends a custody_export record and then anchors the new head.
	RecordExport(ctx context.Context, e model.CustodyExport) (model.Ref, error)
}

// ------------------------------------------------------------------ syslog

// SyslogReceiver receives the gateway's syslog datagrams (implemented by syslogrx.Receiver; the
// monitor owns its lifecycle and writes what it drains to the ledger).
type SyslogReceiver interface {
	// Run listens until ctx is done. It returns nil then, or an error when it cannot listen at
	// all (Listening reports the same error meanwhile).
	Run(ctx context.Context) error
	// Drain returns the messages accepted since the previous call, oldest first, and how many
	// accepted messages were dropped by the per-minute cap and how many datagrams came from
	// senders that are not allowed, since the previous call.
	Drain() (msgs []model.SyslogMessage, dropped, rejected int)
	// SetAllowed replaces the accepted senders (the gateway's address, plus configured extras).
	SetAllowed(addrs []netip.Addr)
	// Listening reports the bound address ("" while not listening) and why it is not listening.
	Listening() (addr string, err error)
}

// ------------------------------------------------------------------ export

// ExportRequest asks for an evidence bundle.
type ExportRequest struct {
	From       time.Time
	To         time.Time
	IncidentID string // optional: narrows From/To to the incident (± 15 min)
	PreparedBy string
	Notes      string
	Requester  string
}

// ExportInfo describes a produced bundle.
type ExportInfo struct {
	FileName       string    `json:"file_name"`
	Path           string    `json:"-"`
	Size           int64     `json:"size"`
	Created        time.Time `json:"created"`
	SHA256         string    `json:"sha256"`
	ManifestSHA256 string    `json:"manifest_sha256,omitempty"`
	Records        int       `json:"records,omitempty"`
	Blobs          int       `json:"blobs,omitempty"`
	CustodySeq     uint64    `json:"custody_seq,omitempty"`
}

// Exporter builds and lists evidence bundles (implemented by export.Exporter).
type Exporter interface {
	Build(ctx context.Context, req ExportRequest) (ExportInfo, error)
	List() ([]ExportInfo, error)
	// Open returns a reader for a bundle by file name (ErrNotFound if absent).
	Open(name string) (io.ReadCloser, ExportInfo, error)
}
