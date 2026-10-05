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
}
func New(opts Options) *Client   // implements contracts.Gateway
func ParseSysInfo(body []byte) (*model.SystemInfo, error)
func ParseBroadband(body []byte) (*model.BroadbandStatus, error)
func ParseFiber(body []byte) (*model.FiberStatus, error)
func ParseLAN(body []byte) (*model.LANStatus, error)
func ParseNotification(body []byte) (enabled bool, err error)
func IsLoginPage(body []byte) bool
func SessionsFull(body []byte) bool
func Derive(s *model.GatewaySnapshot, fetchedAt time.Time, loc *time.Location) model.GatewayDerived
```
Fixtures: `testdata/gateway/*.html` (sanitized real pages, see README there).

## internal/probe
```go
type Options struct { Logger *slog.Logger; UserAgent string }
func New(opts Options) *Prober   // implements contracts.Prober
// Pure helpers exported for tests:
func ParseNetshWLAN(out []byte, iface string) (model.LocalLink, error)
func DetectDNSHijack(name string, answers []string, gatewayIP string) (bool, string)
func ICMPStatusName(code uint32) string
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
}
func New(opts Options) (*Monitor, error)
func (m *Monitor) Run(ctx context.Context) error // writes monitor_start … monitor_stop
func (m *Monitor) PowerEvent(kind string)        // from the service control handler
// *Monitor implements contracts.StatusSource and contracts.Actions.

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
    Version  string
    Logger   *slog.Logger
}
func New(opts Options) (*Server, error)
func (s *Server) Handler() http.Handler
func (s *Server) Run(ctx context.Context) error   // listen until ctx is done (graceful shutdown)
```

## internal/export
```go
type Options struct {
    Dir           string                  // exports directory
    Reader        contracts.LedgerReader
    Verifier      contracts.Verifier       // verification result goes into README/REPORT
    Actions       contracts.Actions        // RecordExport (custody_export + anchor); may be nil (CLI offline)
    TokenVerifier contracts.TokenVerifier  // per-anchor CMS/chain check shown in the report (optional)
    ExtraFiles    map[string][]byte        // extra bundle files, e.g. "keys/tsa-roots.pem" (in MANIFEST)
    Software      model.SoftwareInfo
    Now           func() time.Time
    Logger        *slog.Logger
}
func New(opts Options) *Exporter          // implements contracts.Exporter
func OpenBundle(path string) (*Bundle, error) // *Bundle implements contracts.LedgerReader; Close()
func VerifyManifest(path string) error                    // manifest + layout + report check
func VerifyReport(path string) (ReportCheck, error)      // re-derives report.json/REPORT.html/README.txt from the records
var ErrReportMismatch error; const DefaultFullVerifyTimeout = 4 * time.Minute // Options.FullVerifyTimeout
// assets/verify_bundle.py is embedded and copied into every bundle as tools/verify_bundle.py.
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
}
func New(o Options) (*Replicator, error)                          // validates; MongoDB may be down
func (r *Replicator) Run(ctx context.Context) error                // until ctx is done; nil then
func (r *Replicator) SyncOnce(ctx context.Context) (copied int, err error)
func (r *Replicator) Status() model.MongoStatus                    // never blocks on MongoDB
func (r *Replicator) Close(ctx context.Context) error
type VerifyResult struct {
    Records, Checked, Missing, Mismatched, BadHash int
    BlobsChecked, BlobsMissing, BlobsCorrupt     int
    LedgerHead uint64; CopiedUpTo int64 /* -1: nothing copied */; NotCopied int // the copy's extent
    Problems []string; OK bool
}
var ErrClosed error // SyncOnce after Close
func Verify(ctx context.Context, uri, database string, r contracts.LedgerReader, pub ed25519.PublicKey) (VerifyResult, error)
func RedactURI(uri string) string
```
Live tests run only with `ATTMON_MONGO=1`, against `mongodb://127.0.0.1:27017`, in a throw-away
database (`attmonitor_test_<random>`) that each test drops.

## cmd/att-monitor
CLI and wiring (docs/DESIGN.md §14). Written last, during integration.
