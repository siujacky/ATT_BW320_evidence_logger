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
	// NATTable reads the NAT table page (Diagnostics → NAT Table): every connection the gateway
	// is translating. Authenticated and read only: the page's display selector is never posted.
	// raw is the exact page that was read (also with a parse error).
	NATTable(ctx context.Context) (table model.NATTable, raw []byte, err error)
	// Devices reads the Device List page (Device → Device List). Unauthenticated and read only:
	// its "Clear and Rescan for Devices" form is never posted. raw is the exact page read, also
	// with an error once the gateway answered.
	Devices(ctx context.Context) (devices []model.LANDevice, raw []byte, err error)
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

// SyslogReader reads the syslog store (the dashboard, exports and the MongoDB copy).
type SyslogReader interface {
	// Query returns the messages received in [from, to) for which match returns true (nil:
	// all), newest first, at most limit, and whether more matched. Entry.Chunk names the chunk;
	// Entry.Seq is left 0 (callers that need it map chunk names to syslog_chunk records).
	Query(ctx context.Context, from, to time.Time, match func(*model.SyslogMessage) bool, limit int) (entries []model.SyslogEntry, truncated bool, err error)
	// Usage reports the stored volume and the retention limits.
	Usage() model.SyslogUsage
	// OpenChunk opens the exact stored bytes (gzip) of a sealed chunk; ErrNotFound when the
	// chunk does not exist (pruned, or never sealed).
	OpenChunk(name string) (io.ReadCloser, error)
}

// SyslogStore keeps the gateway's syslog messages in chunk files within a size limit, and
// optionally an age limit (implemented by syslogstore.Store). It never writes the ledger: the
// monitor records a syslog_chunk record for every chunk it returns as sealed and a syslog_prune
// record for every deletion it returns.
type SyslogStore interface {
	SyslogReader
	// Recover seals the chunk a previous run left open (reason "recovered"); call it once,
	// before the first Append.
	Recover(now time.Time) ([]model.SyslogChunk, error)
	// Append adds messages (oldest first) and the dropped/rejected counts to the open chunk,
	// sealing it whenever it reaches the chunk size limit; it returns the chunks it sealed.
	Append(msgs []model.SyslogMessage, dropped, rejected int, now time.Time) ([]model.SyslogChunk, error)
	// Seal seals the open chunk when it is older than the chunk age limit, or - with force -
	// whenever it holds anything (reason "stop" at shutdown). nil when nothing was sealed.
	Seal(now time.Time, reason string, force bool) (*model.SyslogChunk, error)
	// Prune deletes the oldest sealed chunks beyond the retention limits and returns them.
	Prune(now time.Time) ([]model.SyslogChunkRef, error)
	// SetRetention changes the limits (keepMB >= 1; keepDays 0 = no age limit).
	SetRetention(keepMB, keepDays int)
}

// SyslogControl changes how much syslog is kept (implemented by monitor.Monitor): it saves
// syslog.keep_mb/keep_days, records a config_change, applies them at once (pruning what no longer
// fits, recorded as syslog_prune) and returns the change.
type SyslogControl interface {
	SetSyslogRetention(ctx context.Context, keepMB, keepDays int, actor string) (model.ConfigChange, error)
	// SetGatewaySyslog is the operator's choice for the gateway's Syslog page: enabled sets it
	// to send to this computer (and keeps it so: gateway.enforce_syslog true), disabled switches
	// it off on the gateway and stops enforcing. Both are read back from the gateway and recorded
	// (gateway_event syslog_setting with the pages before and after, config_change).
	SetGatewaySyslog(ctx context.Context, enabled bool, actor string) (model.ConfigChange, error)
}

// SyslogChunkSource gives the firewall view of the Network page (internal/netmap) the syslog
// store's messages chunk by chunk, so that what a sealed chunk holds - which never changes - is
// read once and cached by its name (implemented by syslogstore.Store).
type SyslogChunkSource interface {
	// Chunks lists the sealed chunks kept, oldest first (From/To are the earliest and the latest
	// receive time of a chunk's messages).
	Chunks() []model.SyslogChunkRef
	// OpenChunk opens the exact stored bytes (gzip) of a sealed chunk; ErrNotFound when it is gone.
	OpenChunk(name string) (io.ReadCloser, error)
	// EachOpen calls fn, oldest first, for each message of the open chunk (not sealed yet) that
	// was received in [from, to). Returning ErrStop ends it early with a nil error.
	EachOpen(ctx context.Context, from, to time.Time, fn func(*model.SyslogMessage) error) error
	// Usage reports the stored volume, the oldest and newest message and the retention limits.
	Usage() model.SyslogUsage
}

// ------------------------------------------------------------------ network (the Network page)

// ConnQuery selects the NAT samples of a period.
type ConnQuery struct {
	From, To time.Time // [From, To)
	Device   string    // a ConnDevice.Key ("" = every device)
}

// ConnStore keeps the samples of the gateway's NAT table and Device List (implemented by
// connstore.Store) in daily files under connections\, within connections.keep_days and
// connections.keep_mb. None of it is evidence: it is never written to the ledger.
// All methods are safe for concurrent use.
type ConnStore interface {
	// AppendNAT adds one NAT table read; AppendDevices one Device List read.
	AppendNAT(t time.Time, nat model.NATTable) error
	AppendDevices(t time.Time, devices []model.LANDevice) error
	// Aggregate summarizes the NAT reads of [q.From, q.To) by device and flow, naming each LAN
	// address after the Device List read nearest before (else after) that NAT read. Its work is
	// bounded: whole past days come from a cache.
	Aggregate(ctx context.Context, q ConnQuery) (model.ConnAggregate, error)
	// Devices returns the newest Device List read (nil before the first) and when it was read.
	Devices() ([]model.LANDevice, time.Time)
	// Prune deletes the oldest files beyond the retention limits. The monitor calls it every hour
	// whether or not its samplers run; appends also do it, at most once an hour.
	Prune(now time.Time) error
	// SetRetention changes the limits (keepDays >= 1, keepMB >= 1).
	SetRetention(keepDays, keepMB int)
	Usage() model.ConnStoreUsage
}

// IPIntel names addresses and ports without asking anyone (implemented by ipintel.DB): the
// offline IPtoASN database (the address ranges of every network with its AS number, name and
// country), a table of well-known ports and a cache of reverse DNS names. Safe for concurrent use.
type IPIntel interface {
	// Lookup classifies addr and, when it is public, looks it up in the IP database. It never
	// blocks on the network.
	Lookup(addr netip.Addr) model.IPInfo
	// Service names a port ("tcp", 443 → "HTTPS"; "udp", 443 → "QUIC"); "" when unknown.
	Service(proto string, port int) string
	// PTR returns the cached reverse DNS name of a public addr ("" when not known). With resolve,
	// an address not cached yet is queued for a lookup in the background (bounded: a few at a time,
	// each with a short timeout), so a later call may know it. Never blocks on the network.
	PTR(addr netip.Addr, resolve bool) string
	// Updated is when the loaded IP database was written (zero when none is loaded).
	Updated() time.Time
	Status() model.IPIntelStatus
}

// NetQuery asks for the Network page's views of [From, To).
type NetQuery struct {
	From, To time.Time
	// Range is the name the period was asked by when it ends now ("24h": From and To are then that
	// period as of the request), "" for a period given by its boundaries. The views key the views
	// they keep for reuse by it: a request for the same range a few seconds later - a second tab,
	// the CLI - gets the view built for the first.
	Range  string
	Device string // a device key ("" = every device); connections only
	Limit  int    // table rows (0 = the default; capped)
}

// NetworkView builds the dashboard's Network page (implemented by netmap.View) from the
// connection store, the IP database and the syslog store. Every call's work is bounded.
type NetworkView interface {
	// Connections: which device talked to which remote address (the NAT table samples).
	Connections(ctx context.Context, q NetQuery) (model.NetConnections, error)
	// Firewall: what the gateway's firewall dropped (the syslog).
	Firewall(ctx context.Context, q NetQuery) (model.NetFirewall, error)
	// NetworkStatus: the connection store, the IP database and the syslog kept (Samplers is left
	// nil: the web layer takes it from the monitor's Status; ConfigWarnings is added by the
	// wiring in cmd/att-monitor, from config.Warnings).
	NetworkStatus() model.NetworkStatus
}

// LiveTrafficSource gives the dashboard's flow meter (implemented by monitor.Monitor): each call
// may read the gateway's WAN counters (unauthenticated, at most every few seconds, shared by all
// callers) and returns the newest rates and the recent history. Nothing of it is recorded.
type LiveTrafficSource interface {
	LiveTraffic(ctx context.Context) (model.LiveTraffic, error)
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
