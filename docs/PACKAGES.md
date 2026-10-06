# Package APIs (contract for parallel implementation)

Read together with `docs/DESIGN.md`, `internal/model/*.go`, `internal/contracts/contracts.go`
and `internal/config/config.go` (all already written — **do not edit them**; if you need a
change, define a local type/adaptor and report the requested change in your summary).

Rules for every package:
* Only create/modify files inside your own package directory (plus `testdata/<pkg>/` if needed).
* **Never** edit `go.mod`/`go.sum`, never run `go get` or `go mod tidy`. Approved modules are
  already pinned: `golang.org/x/sys/...`, `golang.org/x/net/dns/dnsmessage`,
  `github.com/digitorus/timestamp`, `github.com/digitorus/pkcs7`. Everything else: stdlib.
* Import only: stdlib, approved modules, `attmonitor/internal/model`,
  `attmonitor/internal/contracts`, `attmonitor/internal/config` (and `internal/secret` where stated).
* Use `log/slog` (`*slog.Logger`, nil → `slog.New(slog.DiscardHandler)`) for operational logs.
* Assert interface conformance at compile time.
* `gofmt`, `go vet ./internal/<pkg>/...` and `go test ./internal/<pkg>/...` must pass offline.
  Live tests only behind `ATTMON_LIVE=1` (`t.Skip` otherwise).
* Windows-only code may use `//go:build windows`; the whole product targets windows/amd64.
* Never send authenticated or mutating requests to the real gateway (192.168.1.254) from tests.

---------------------------------------------------------------------------------------------
## internal/ledger
```go
type Options struct {
    Paths         config.Paths          // uses Paths.Ledger, Blobs, Keys, Quarantine
    Host          model.HostInfo        // genesis
    Software      model.SoftwareInfo    // genesis
    Statement     string                // genesis statement ("" → sensible default)
    TokenVerifier contracts.TokenVerifier // optional; used by Verify for anchor records
    FastInterval  time.Duration         // for gap detection in Verify (default 10s)
    Now           func() time.Time      // default time.Now
    Logger        *slog.Logger
    ReadOnly      bool                  // no lock, no key, no writes (verification/reading)
    // KeyProtect/KeyUnprotect default to DPAPI machine scope (internal/secret); tests may
    // inject identity functions.
    KeyProtect    func([]byte) ([]byte, error)
    KeyUnprotect  func([]byte) ([]byte, error)
}
func Open(opts Options) (*Store, error)        // creates keys + genesis on first use (unless ReadOnly)
func (s *Store) Created() bool                  // genesis written by this Open
func (s *Store) ImportBootstrap(dir string) (model.Ref, error) // files → blobs + bootstrap_import record
func (s *Store) Verify(ctx context.Context) (model.VerifyReport, error)
func (s *Store) CompressSealed(olderThan time.Duration) (int, error) // gzip sealed segments
// *Store implements contracts.Ledger, contracts.LedgerReader, contracts.Verifier.

type VerifyOptions struct {
    TokenVerifier        contracts.TokenVerifier
    FastInterval         time.Duration
    CheckBlobs           bool
    AllowOmittedSegments bool   // bundle mode: an omitted run is allowed only between the genesis segment and the included run
    ExpectFingerprint    string // optional
}
// VerifyReader verifies any LedgerReader (full ledger or an exported bundle).
func VerifyReader(ctx context.Context, r contracts.LedgerReader, opts VerifyOptions) (model.VerifyReport, error)
func Fingerprint(pub ed25519.PublicKey) string
```

## internal/anchor
```go
type Options struct {
    URLs       []string
    Timeout    time.Duration
    HTTPClient *http.Client      // optional
    Roots      *x509.CertPool    // optional extra roots (system roots are always tried)
    UserAgent  string
    Logger     *slog.Logger
}
func New(opts Options) *Client   // implements contracts.Anchorer (and TokenVerifier)
func VerifyToken(token, digest []byte, roots *x509.CertPool) (contracts.TokenInfo, error)
func BuildRequest(digest []byte, nonce *big.Int) ([]byte, error) // DER TimeStampReq, certReq=true
```
Test vectors: `testdata/tsa/manifest.txt` (digest = SHA-256 of the file =
`0bb4c71bfeddf27eb9647853d1e5aa8f981f222fe4ffac0c7d1d8db73f1d443b`), `testdata/tsa/digicert.tsr`
and `testdata/tsa/freetsa.tsr` — real TimeStampResp DER from 2026-10-05T03:19:57Z.

## internal/gateway
```go
type Options struct {
    Host             string        // "192.168.1.254"
    Scheme           string        // "https" | "http"
    PinnedCertSHA256 string
    Timeout          time.Duration // per request
    AccessCode       func() (string, error)
    UserAgent        string
    Now              func() time.Time
    Location         *time.Location // gateway clock zone (default time.Local)
    Logger           *slog.Logger
    HTTPClient       *http.Client   // tests only; nil → built-in client with pinning
    // The login policy outlives the process (docs/DESIGN.md §2): restored from LoginPolicy, handed to
    // OnLoginPolicy after every change (cmd/att-monitor keeps it in state\gateway-login.json).
    LoginPolicy   LoginPolicy      // {LastAttempt, Failures, FullUntil}
    OnLoginPolicy func(LoginPolicy)
}
func New(opts Options) *Client   // implements contracts.Gateway
const SessionReuse = 5 * time.Minute // an authenticated session is reused this long after its last use
func (c *Client) LoginAttempts() uint64 // the login forms posted (the monitor counts the NAT reads' logins)
func ParseSysInfo(body []byte) (*model.SystemInfo, error)
func ParseBroadband(body []byte) (*model.BroadbandStatus, error)
func ParseFiber(body []byte) (*model.FiberStatus, error)
func ParseLAN(body []byte) (*model.LANStatus, error)
func ParseNotification(body []byte) (enabled bool, err error)
func ParseSyslog(body []byte) (model.SyslogSetting, error) // Diagnostics > Syslog, controls found by their labels
var ErrSyslogPage error // the Syslog page is not understood (Syslog returns the page with it; SetSyslog posts nothing)
func IsLoginPage(body []byte) bool
func SessionsFull(body []byte) bool
func Derive(s *model.GatewaySnapshot, fetchedAt time.Time, loc *time.Location) model.GatewayDerived
// Client.Syslog reads the Syslog page (authenticated, read-only); Client.SetSyslog changes only its
// syslog controls - with the page's Update round first when the switch changes (firmware 6.34.7
// disables the fields while Syslog is off), then the Save - reads the page back and fails unless it
// shows the target. The monitor calls it to keep the page set (docs/syslog-snmp-traffic.md §3.1).
// The Network page (docs/DESIGN.md §19), both read only - their forms are never posted:
func ParseNATTable(body []byte) (model.NATTable, error)   // Diagnostics > NAT Table, by its column labels
func ParseDevices(body []byte) ([]model.LANDevice, error) // Device > Device List
var ErrNATPage, ErrDevicesPage error                       // the page is not understood (returned with the page)
// Client.NATTable: authenticated, through the login policy, in the shared session (within 5 min of the
// previous authenticated request it costs one GET; a page up to NATMaxBodyBytes, 16 MiB). A read that
// fails otherwise than with the login page keeps the session. Client.Devices: unauthenticated, in the
// status pages' session (no login, not subject to the login policy). Both return the exact page read
// (also with an error, as much as arrived).
func (e *CooldownError) CooldownUntil() time.Time // when the next login attempt is allowed
```
Fixtures: `testdata/gateway/*.html` (sanitized real pages, see README there: `syslog_real_off.html`
is the real Syslog page; the pages derived from it, and the other `syslog_*.html`, are synthetic;
`devices_real.html` is a sanitized capture of the Device List, `nattable_synthetic.html` is made up:
the NAT table is behind the login).

## internal/probe
```go
type Options struct { Logger *slog.Logger; UserAgent string }
func New(opts Options) *Prober   // implements contracts.Prober
// Pure helpers exported for tests:
func ParseNetshWLAN(out []byte, iface string) (model.LocalLink, error)
func DetectDNSHijack(name string, answers []string, gatewayIP string) (bool, string)
func ICMPStatusName(code uint32) string
// LocalLink also fills RxBytes/TxBytes: the 64-bit octet counters (GetIfEntry2Ex) of the adapter
// that reaches the gateway, for this computer's traffic rates (docs/DESIGN.md §18).
```

## internal/monitor
```go
const RulesVersion = "2026.10-4"
type Options struct {
    Config     *config.Config
    SaveConfig func(*config.Config) error // persist pin / notification state changes
    Ledger     contracts.Ledger
    Reader     contracts.LedgerReader     // rebuild state at startup
    Verifier   contracts.Verifier         // optional (status "last verify")
    Gateway    contracts.Gateway
    Prober     contracts.Prober
    Anchorer   contracts.Anchorer         // nil when anchoring disabled
    Software   model.SoftwareInfo
    Host       model.HostInfo
    Mode       string                     // "service" | "console"
    Listen     string
    DataDir    string
    StateDir   string                     // caches (non-evidence)
    Now        func() time.Time
    Logger     *slog.Logger
    MongoStatus func() model.MongoStatus  // optional: Status().Mongo (called without the lock)
    // The gateway's syslog (docs/DESIGN.md §18): the receiver the monitor runs, and the store it
    // writes, recording syslog_chunk / syslog_prune. The pipeline runs only with both and
    // Config.Syslog.Enabled; nil: none. A store with syslogstore.Store's bookkeeping methods
    // (MarkRecorded, Unrecorded, PlanPrune, CommitPrune, CancelPrune) keeps the records complete
    // across restarts; another gets that bookkeeping in memory only.
    Syslog      contracts.SyslogReceiver
    SyslogStore contracts.SyslogStore
    // The Network page's samples (docs/DESIGN.md §19; nil: no samplers, Status.Connections nil).
    // With Config.Connections.Enabled the monitor reads the NAT table every connections.interval
    // (authenticated, under the guard of every other authenticated request, after the startup
    // settings check, with a login budget kept in StateDir\nat-sampler.json) and the Device List
    // every connections.devices_interval, and appends what it reads; never to the ledger. Whether
    // or not the samplers run, it applies the store's retention limits hourly and deletes the raw
    // page copies older than connections.keep_days.
    Conns       contracts.ConnStore
}
func New(opts Options) (*Monitor, error)
func (m *Monitor) Run(ctx context.Context) error // writes monitor_start … monitor_stop
func (m *Monitor) PowerEvent(kind string)        // from the service control handler
func (m *Monitor) SetSyslogRetention(ctx context.Context, keepMB, keepDays int, actor string) (model.ConfigChange, error)
// SetGatewaySyslog: the operator's choice for the gateway's Syslog page - saves and records
// gateway.enforce_syslog, then reads, records and sets the page (to this computer, or off); the
// daily settings check keeps it so while gateway.enforce_syslog (docs/DESIGN.md §18).
func (m *Monitor) SetGatewaySyslog(ctx context.Context, enabled bool, actor string) (model.ConfigChange, error)
func (m *Monitor) LiveTraffic(ctx context.Context) (model.LiveTraffic, error) // the flow meter, unrecorded
// *Monitor implements contracts.StatusSource, contracts.Actions, contracts.SyslogControl and
// contracts.LiveTrafficSource.

type ClassifyInput struct {
    Cycle      []model.ProbeResult     // this cycle
    Window     [][]model.ProbeResult   // last N cycles incl. this one, oldest first
    Snapshot   *model.GatewaySnapshot  // latest, may be nil
    SnapshotAge time.Duration
    Service    *model.ServiceCheck     // latest, may be nil
    ServiceAge time.Duration
    Link       *model.LocalLink        // latest, may be nil
    LinkAge    time.Duration
    SnapshotSeq, ServiceSeq, LinkSeq uint64 // ledger seqs of the inputs (reported in Verdict.Inputs when fresh)
    PrevService    *model.ServiceCheck // previous service check (two-consecutive-checks DNS rule)
    PrevServiceGap time.Duration
    PrevServiceSeq uint64
    Egress         *model.EgressCheck  // route check from the latest local_link
    Traffic        *WANTraffic         // WAN rates from the gateway's counters
    TrafficAge     time.Duration
}
// Run returns only after ctx is done, or with an error when the ledger refuses records for 5 min
// (or at once on contracts.ErrLedgerBroken) so the Windows service restarts.
func Classify(in ClassifyInput, cfg config.IncidentConfig) model.Verdict // pure, deterministic
```

## internal/web
```go
type Options struct {
    Listen   string
    Status   contracts.StatusSource
    Actions  contracts.Actions
    Reader   contracts.LedgerReader
    Verifier contracts.Verifier
    Exporter contracts.Exporter
    // Optional (nil: the endpoint answers 404 with a JSON error; the dashboard hides or explains it):
    SyslogReader  contracts.SyslogReader      // GET /api/syslog (entries linked to syslog_chunk records via Reader)
    SyslogControl contracts.SyslogControl     // POST /api/syslog/retention, POST /api/gateway/syslog
    LiveTraffic   contracts.LiveTrafficSource // GET /api/traffic/live
    Network       contracts.NetworkView       // GET /api/network/connections, /firewall, /status (samplers from Status)
    Version  string
    Logger   *slog.Logger
}
func New(opts Options) (*Server, error)
func (s *Server) Handler() http.Handler
func (s *Server) Run(ctx context.Context) error   // listen until ctx is done (graceful shutdown)
type SyslogRetentionRequest struct { KeepMB *int; KeepDays *int; Client string } // keep_mb required; keep_days absent = 0
type GatewaySyslogRequest struct { Enabled *bool; Client string } // POST /api/gateway/syslog: enabled required
// POST /api/gateway/syslog shares the notification setting's guard (one authenticated gateway
// operation at a time), its time limit (3 min, detached) and its error mapping ({error, change}).
const DefaultSyslogLimit = 200; const MaxSyslogLimit = 5000                    // GET /api/syslog limit
const MaxSyslogAnswerBytes = 16 << 20 // GET /api/syslog also ends its list before the message that would take its JSON beyond this
const DefaultSyslogSpan = 24 * time.Hour; const MaxSyslogSpan = 31 * 24 * time.Hour
const WarningHeader = "X-ATT-Monitor-Warning"
// GET /api/network/connections and /firewall: range= (NetworkRanges, ending now) or from=/to=,
// device= (connections only), limit=; answered within networkTimeout (30 s, tied to the request).
var NetworkRanges = []string{"1h", "24h", "7d", "30d"}; const DefaultNetworkRange = "24h"
const MaxNetworkSpan = 31 * 24 * time.Hour; const MaxNetworkLimit = 1000; const MaxNetworkDeviceChars = 128
const NetworkFutureSlack = time.Hour // to may lie this far after the server's clock
```

## internal/export
```go
type Options struct {
    Dir           string                  // exports directory
    Reader        contracts.LedgerReader
    Verifier      contracts.Verifier       // verification result goes into README/REPORT
    Actions       contracts.Actions        // RecordExport (custody_export + anchor); may be nil (CLI offline)
    TokenVerifier contracts.TokenVerifier  // per-anchor CMS/chain check shown in the report (optional)
    Syslog        contracts.SyslogReader   // optional: the period's kept chunks go into the bundle as syslog/<name>
    ExtraFiles    map[string][]byte        // extra bundle files, e.g. "keys/tsa-roots.pem" (in MANIFEST)
    Software      model.SoftwareInfo
    Now           func() time.Time
    Logger        *slog.Logger
}
func New(opts Options) *Exporter          // implements contracts.Exporter
func OpenBundle(path string) (*Bundle, error) // *Bundle implements contracts.LedgerReader; Close()
func VerifyManifest(path string) error                    // manifest + layout + report check
func VerifyReport(path string) (*ReportCheck, error)     // re-derives report.json/REPORT.html/README.txt from the records
var ErrReportMismatch error; const DefaultFullVerifyTimeout = 4 * time.Minute // Options.FullVerifyTimeout
// VerifySyslogChunks checks every syslog/<name> of a bundle against its syslog_chunk record
// (SHA-256, size and line count of the gunzipped content) and lists the period's chunks that are
// not in it (pruned per a syslog_prune record, or absent): not failures. A mismatch wraps
// ErrSyslogMismatch and still returns the check.
func VerifySyslogChunks(path string) (*SyslogCheck, error)
type SyslogCheck struct { Records, OfPeriod, Files, Verified int; Pruned, Absent, Problems, Notes []string } // OK(), Summary()
var ErrSyslogMismatch error
// assets/verify_bundle.py is embedded and copied into every bundle as tools/verify_bundle.py (item 9:
// the same syslog chunk checks, the same verdicts).
```

## internal/winsvc
```go
const ServiceName = "ATTMonitor"
type InstallOptions struct { ExePath string; Args []string; DisplayName, Description string }
func Install(o InstallOptions) error   // auto start, LocalSystem, recovery actions, event source
func Uninstall() error
func Start() error
func Stop(timeout time.Duration) error
func Status() (string, error)          // "running", "stopped", "not installed", ...
func IsService() (bool, error)
func IsAdmin() bool
func Run(run func(ctx context.Context, power <-chan string) error) error // SCM handler
func NewEventLogHandler(level slog.Level) (slog.Handler, func(), error)    // writes to Application log
func SecureDataDir(dir string) error    // SYSTEM+Administrators full, Users read&execute, no inheritance from parent
func CheckDataDir(dir string) error     // SecureDataDir's refusals, changing nothing (install runs it before anything else)
```

## internal/sysinfo
```go
func Host() model.HostInfo
func Software(version, commit, rules string) model.SoftwareInfo // includes exe SHA-256
```

## internal/mongostore
The MongoDB copy of the ledger (docs/DESIGN.md §17). Uses the official driver
`go.mongodb.org/mongo-driver/v2`. Never required by evidence collection.
```go
const DefaultURI = "mongodb://127.0.0.1:27017"; const DefaultDatabase = "attmonitor"
var ErrIntegrity error // a document disagrees with the ledger (never overwritten)
type Options struct {
    URI, Database  string                 // "" → defaults; the URI must not carry credentials
    Reader         contracts.LedgerReader // the ledger (ledger.Store also gives Head for the lag)
    StoreBlobs     bool                   // copy the exact blob bytes (≤ 15 MB each)
    Interval       time.Duration          // between passes (5 s)
    BatchSize      int                    // records per insert (500)
    ConnectTimeout time.Duration          // connect / server selection (3 s)
    Logger         *slog.Logger
    Now            func() time.Time
    Syslog         contracts.SyslogReader // optional: the "syslog" collection follows syslog_chunk / syslog_prune
}
func New(o Options) (*Replicator, error)                          // validates; MongoDB may be down
func (r *Replicator) Run(ctx context.Context) error                // until ctx is done; nil then
func (r *Replicator) SyncOnce(ctx context.Context) (copied int, err error)
func (r *Replicator) Status() model.MongoStatus                    // never blocks on MongoDB
func (r *Replicator) SyslogDocuments() int64                       // cached count of the syslog collection
func (r *Replicator) Close(ctx context.Context) error
type VerifyResult struct {
    Records, Checked, Missing, Mismatched, BadHash int
    BlobsChecked, BlobsMissing, BlobsCorrupt     int
    SyslogDocs, SyslogChunks, SyslogBad, SyslogPruned, SyslogForged, SyslogMissing int // the syslog collection
    SyslogTrimmed int // chunks the store keeps whose documents the collection's size limit deleted (not a problem)
    LedgerHead uint64; CopiedUpTo int64 /* -1: nothing copied */; NotCopied int // the copy's extent
    Problems []string; OK bool
}
var ErrClosed error // SyncOnce after Close
func Verify(ctx context.Context, uri, database string, r contracts.LedgerReader, pub ed25519.PublicKey) (VerifyResult, error)
type VerifyOptions struct { URI, Database string; Reader contracts.LedgerReader; PublicKey ed25519.PublicKey; Syslog contracts.SyslogReader }
func VerifyWith(ctx context.Context, o VerifyOptions) (VerifyResult, error) // with Syslog: also chunks the copy lacks
func RedactURI(uri string) string
```
Live tests run only with `ATTMON_MONGO=1`, against `mongodb://127.0.0.1:27017`, in a throw-away
database (`attmonitor_test_<random>`) that each test drops.

## internal/syslogrx
The receiver of the gateway's syslog (docs/DESIGN.md §18). Stdlib only.
```go
const DefaultListen = ":514"; const DefaultMaxPerMinute = 2000; const DefaultMaxMessage = 8 << 10
const DefaultMaxBytesPerMinute = 1 << 20
type Options struct {
    Listen            string        // UDP "host:port" (":514"; "127.0.0.1:0" in tests); the host must be an IP
    Allowed           []netip.Addr  // accepted senders (SetAllowed replaces them)
    MaxPerMinute      int           // per UTC minute of receive time (2000)
    MaxBytesPerMinute int           // the stored size (JSON lines) of a minute's messages (1 MiB)
    MaxMessage        int           // bytes (8192, at most 65527)
    MaxPending        int           // kept between two Drain calls (4 × MaxPerMinute)
    Now               func() time.Time
    Logger            *slog.Logger
}
func New(o Options) (*Receiver, error)  // implements contracts.SyslogReceiver; binds nothing (Run does)
func Parse(b []byte) model.SyslogMessage // RFC 5424 / RFC 3164 / unknown; Raw or RawB64 is the exact datagram
```
Tests bind only `127.0.0.1:0`, never port 514.

## internal/syslogstore
The syslog store: chunk files within a size (and optional age) limit (docs/DESIGN.md §18). It never
writes the ledger: the monitor records what it seals and deletes.
```go
const DefaultKeepMB = 100; const DefaultChunkBytes = 1 << 20; const DefaultChunkAge = 5 * time.Minute
var ErrReadOnly, ErrClosed error
type Options struct {
    Dir              string        // config.Paths.Syslog
    KeepMB, KeepDays int           // retention limits (0 MB → 100; clamped to the config's limits)
    ChunkBytes       int64         // seal at this content size (1 MiB)
    ChunkAge         time.Duration // Seal seals at this age (5 min)
    ReadOnly         bool          // index and read only (the CLI; another process may write)
    Now              func() time.Time
    Logger           *slog.Logger
}
func New(o Options) (*Store, error) // implements contracts.SyslogStore (and SyslogReader, SyslogChunkSource)
func (s *Store) Close() error                   // releases the open chunk's file without sealing it
// contracts.SyslogChunkSource, for the Network page's firewall view (internal/netmap):
func (s *Store) Chunks() []model.SyslogChunkRef // the sealed chunks kept, oldest first (From/To: earliest/latest receive time)
func (s *Store) EachOpen(ctx context.Context, from, to time.Time, fn func(*model.SyslogMessage) error) error // the open chunk's messages
// The writer's bookkeeping of its records (the monitor uses them when the store has them):
func (s *Store) MarkRecorded(name string, seq uint64) error // the chunk's syslog_chunk record (kept in its sidecar)
func (s *Store) Unrecorded() []model.SyslogChunk            // sealed chunks without a noted record, oldest first
func (s *Store) PlanPrune(now time.Time) ([]model.SyslogChunkRef, error) // choose, delete nothing yet
func (s *Store) CommitPrune() ([]model.SyslogChunkRef, error)            // delete what PlanPrune chose
func (s *Store) CancelPrune()                                            // keep it (its record was refused)
```
One writer (the monitor; its ledger lock keeps a second one away), any number of readers.

## internal/connstore
The connection store: the Network page's samples of the gateway's NAT table and Device List in daily
files, within a retention limit (docs/DESIGN.md §19). Not evidence: it never writes the ledger.
```go
const DefaultKeepDays = 30; const DefaultKeepMB = 200
var ErrClosed error // the writing methods after Close
type Options struct {
    KeepDays, KeepMB int              // retention limits (0 → the defaults; at least 1 day and 1 MiB)
    Logger           *slog.Logger
    Now              func() time.Time // which UTC day is today (never pruned)
}
func Open(dir string, opts Options) (*Store, error) // config.Paths.Connections; creates it; repairs; compresses past days and prunes in the background
// *Store implements contracts.ConnStore: AppendNAT, AppendDevices, Aggregate, Devices, Prune,
// SetRetention, Usage. Aggregate counts at most 200,000 flows one by one (FlowsLeftOut: the rest).
func (s *Store) Close() error // closes the files being appended to, waits for Open's background work; reading keeps working
// The Device List read in effect at from, then the later reads before to, oldest first: netmap's firewall
// view names each dropped packet's LAN address after the read in effect when it was received.
func (s *Store) EachDevices(ctx context.Context, from, to time.Time, fn func(at time.Time, devices []model.LANDevice) error) error
```
Files `nat-YYYY-MM-DD.jsonl` and `devices-YYYY-MM-DD.jsonl` per UTC day, gzipped (`.jsonl.gz`) once
the day is over; files with other names in the folder are never touched. One writer (the monitor:
its ledger lock keeps a second one away, so the CLI never opens the store), any number of readers.

## internal/ipintel
Names addresses and ports without asking anyone (docs/DESIGN.md §19): the offline IPtoASN database
(public domain, PDDL 1.0), a table of well-known ports, and a cache of reverse DNS names.
```go
const DefaultURLv4 = "https://iptoasn.com/data/ip2asn-v4.tsv.gz"; const DefaultURLv6 = "https://iptoasn.com/data/ip2asn-v6.tsv.gz"
const DefaultRefresh = 7 * 24 * time.Hour; const MinRefresh = time.Hour
type Resolver interface { LookupAddr(ctx context.Context, addr string) ([]string, error) } // *net.Resolver is one
type Options struct {
    Enabled      bool          // geo.enabled; without it Lookup only classifies, PTR returns "", Run does nothing
    Download     bool          // geo.download: fetch missing tables, look for newer ones every Refresh
    URLv4, URLv6 string        // https, no credentials, query or fragment (with Download, Open fails otherwise); default DefaultURLv4/v6
    Refresh      time.Duration // geo.refresh (default DefaultRefresh, at least MinRefresh)
    ReverseDNS   bool          // connections.reverse_dns: PTR lookups in the background (off: ptr-cache.json deleted)
    KeepDays     int           // connections.keep_days: the longest a PTR answer is kept (below its time to live)
    UserAgent    string
    HTTPClient   *http.Client  // tests; copied, https redirects only, no cookies
    Resolver     Resolver      // default net.DefaultResolver (this computer's)
    Logger       *slog.Logger
    Now          func() time.Time
}
func Open(dir string, opts Options) (*DB, error) // config.Paths.Geo; reads and downloads nothing
func (d *DB) Run(ctx context.Context)             // loads, downloads, resolves until ctx ends; saves the PTR cache
// *DB implements contracts.IPIntel: Lookup, Service, PTR, Updated, Status (never wait for the network).
```
Files in its folder: `ip2asn-v4.tsv.gz`, `ip2asn-v6.tsv.gz` (as downloaded, or placed by hand),
`ip2asn.json` (what was downloaded, when looked for), `ptr-cache.json` (the reverse DNS answers still
current only: never one that has outlived its time to live).

## internal/netmap
Builds the Network page (docs/DESIGN.md §19) from the connection store, the IP database and the syslog
store. Reads only; keeps nothing but in-memory caches.
```go
const MaxRange = 31 * 24 * time.Hour; const DefaultPeriod = 24 * time.Hour
const DefaultLimit = 200; const MaxLimit = 1000                  // table rows (NetQuery.Limit)
const DefaultCacheBytes = 64 << 20; const DefaultCacheChunks = 16384 // sealed chunks' firewall summaries
const DefaultResultTTL = 30 * time.Second                        // a view is reused this long for the same request (a range ending now: by its name)
var ErrRange error                                               // the period is not valid
type Options struct {
    Conns  contracts.ConnStore         // nil: Connections fails (ErrUnavailable)
    Intel  contracts.IPIntel           // nil: addresses classified only, no organisations, countries, services
    Syslog contracts.SyslogChunkSource // nil: Firewall fails (ErrUnavailable)
    Logger *slog.Logger
    Now    func() time.Time
    CacheBytes int64; CacheChunks int; ResultTTL time.Duration // 0 → defaults; negative: no cache / no reuse
}
func New(o Options) *View // implements contracts.NetworkView: Connections, Firewall, NetworkStatus
// One connections view and one firewall view are built at a time; organisations are keyed by the
// name the IP database gives them ("org:google"), else by AS ("as64500").
```

## Syslog and traffic contracts
Defined in `internal/model/syslog.go`, `internal/contracts` and `internal/config` (docs/DESIGN.md §18):
```go
contracts.SyslogReceiver    // Run, Drain, SetAllowed, Listening (syslogrx.Receiver)
contracts.SyslogReader      // Query(ctx, from, to, match, limit), Usage, OpenChunk (syslogstore.Store)
contracts.SyslogStore       // SyslogReader + Recover, Append, Seal, Prune, SetRetention (syslogstore.Store)
contracts.SyslogControl     // SetSyslogRetention, SetGatewaySyslog (monitor.Monitor)
contracts.LiveTrafficSource // LiveTraffic (monitor.Monitor)
contracts.Gateway           // + Syslog, SetSyslog (gateway.Client)
model.TypeSyslogChunk / TypeSyslogPrune, model.SyslogChunk / SyslogPrune / SyslogChunkRef,
model.SyslogMessage / SyslogEntry / SyslogList / SyslogUsage / SyslogStatus / SyslogSetting / SyslogTarget,
model.TrafficPoint / TrafficDay / LiveTraffic / LivePoint, model.GwEvSyslogSetting
config.SyslogConfig {Enabled, Listen, Port, Allow, FlushInterval, MaxPerMinute, KeepMB, KeepDays}
config.GatewayConfig.EnforceSyslog (default true), SyslogLevel (default "")
config.MinSyslogKeepMB, MaxSyslogKeepMB, MaxSyslogKeepDays; config.Paths.Syslog
```

## Network page contracts
Defined in `internal/model/network.go`, `internal/contracts` and `internal/config` (docs/DESIGN.md §19).
None of these types is ever written to the ledger.
```go
contracts.ConnStore          // AppendNAT, AppendDevices, Aggregate(ctx, ConnQuery), Devices, Prune, SetRetention, Usage (connstore.Store)
contracts.IPIntel            // Lookup, Service, PTR, Updated, Status (ipintel.DB)
contracts.SyslogChunkSource  // Chunks, OpenChunk, EachOpen, Usage (syslogstore.Store)
contracts.NetworkView        // Connections(ctx, NetQuery), Firewall(ctx, NetQuery), NetworkStatus (netmap.View)
contracts.ConnQuery{From, To, Device}; contracts.NetQuery{From, To, Range, Device, Limit}
contracts.Gateway            // + NATTable, Devices (gateway.Client)
model.NATSession / NATTable / LANDevice; model.ConnStoreUsage / ConnDevice / ConnFlow / ConnAggregate
model.IPInfo (Kind: model.IPKind*) / IPIntelStatus; model.ConnSamplerStatus (Status.Connections)
model.NetConnections / NetDevice / NetOrg / NetService / NetLink / NetCountry / NetConnRow / NetTotals
model.NetFirewall (+ OutboundDevices) / FwHour / FwSource / FwService / FwReason / FwOutRow; model.NetworkStatus (+ ConfigWarnings)
config.ConnectionsConfig {Enabled, Interval, DevicesInterval, KeepDays, KeepMB, ReverseDNS}
config.GeoConfig {Enabled, Download, URLv4, URLv6, Refresh}; config.Paths.Connections, Paths.Geo
config.MinConnInterval … MaxGeoRefresh (the settings' limits: Load brings these sections into them)
(*config.Config).Warnings() []string // what Load replaced in these sections, and by what (never saved)
```

## cmd/att-monitor
CLI and wiring (docs/DESIGN.md §14). Written last, during integration. `openStack` opens the ledger,
then the syslog store: in the service and console modes with `syslog.enabled` a writable
`syslogstore.Store` and a `syslogrx.Receiver` (allowed: the gateway and `syslog.allow`) for
`monitor.Options.Syslog` / `SyslogStore`; otherwise (the CLI, or syslog off) the store read-only.
The same store is `web.Options.SyslogReader`, `export.Options.Syslog` and
`mongostore.Options.Syslog`; the monitor is `web.Options.SyslogControl` and `LiveTraffic`. A store
that cannot be opened is logged and left out (never a typed nil in an interface). `install` sets up
the Windows Firewall rule of the receiver (`netsh`, through a replaceable runner so tests never run
it) and `uninstall` removes it. `gateway syslog on|off` goes through `POST /api/gateway/syslog`, or
with the service stopped through `Monitor.SetGatewaySyslog` after `strictGatewayTLS` (a replaceable
function, so tests never reach a gateway).

The Network page (service and console modes only): `openStack` opens the connection store in
`Paths.Connections` (`monitor.Options.Conns`; also with `connections.enabled` off, so that old
samples are still shown and pruned) and the IP database in `Paths.Geo` (`ipintel.Open` with
`Enabled` = `geo.enabled`), and builds `netmap.New` over them and the syslog store
(`web.Options.Network`); a part that cannot be opened is logged and passed as an untyped nil.
`openStack` sets up the operational log before it loads the configuration (a config.json it cannot
use is explained there), logs `config.Warnings`, and the view passed to the dashboard adds them to
its status (`NetworkStatus.ConfigWarnings`).
`runMonitor` runs `(*ipintel.DB).Run` beside the MongoDB copy, and `stack.close` closes the
connection store after the monitor stopped. The CLI never opens the connection store (it has one
writer): `att-monitor network` reads `GET /api/network/*` of the running service.
