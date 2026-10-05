// Package config defines att-monitor's configuration file (docs/DESIGN.md §15), defaults,
// data-directory layout and the DPAPI-protected gateway access code.
package config

import (
	"bufio"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"attmonitor/internal/model"
	"attmonitor/internal/secret"
)

// FileName is the configuration file name inside the data directory.
const FileName = "config.json"

// accessCodeEntropy binds DPAPI blobs to this purpose.
var accessCodeEntropy = []byte("att-monitor gateway access code v1")

// Duration is a time.Duration that marshals as a Go duration string ("10s").
type Duration struct{ time.Duration }

// D is a convenience constructor.
func D(d time.Duration) Duration { return Duration{d} }

func (d Duration) MarshalJSON() ([]byte, error) { return json.Marshal(d.String()) }

func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		var n int64 // also accept nanoseconds
		if err2 := json.Unmarshal(b, &n); err2 != nil {
			return fmt.Errorf("duration: %w", err)
		}
		d.Duration = time.Duration(n)
		return nil
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	d.Duration = v
	return nil
}

// HTTPCheck is one HTTP(S) service check.
type HTTPCheck struct {
	Name         string `json:"name"`
	URL          string `json:"url"`
	ExpectStatus int    `json:"expect_status"`
	ExpectBody   string `json:"expect_body,omitempty"`
}

// GatewayConfig configures access to the AT&T gateway.
type GatewayConfig struct {
	Host             string `json:"host"`
	Scheme           string `json:"scheme"` // "https" (default, certificate pinned) or "http"
	PinnedCertSHA256 string `json:"pinned_cert_sha256"`
	// PendingCertSHA256 is a changed gateway certificate seen but not yet confirmed by the operator.
	// While set, status pages are still read (evidence continuity) but no authenticated request is
	// sent (an impostor could otherwise collect MD5(access code + nonce)).
	PendingCertSHA256         string   `json:"pending_cert_sha256,omitempty"`
	AccessCodeProtected       string   `json:"access_code_protected,omitempty"` // base64 DPAPI blob
	EnforceNotificationOff    bool     `json:"enforce_notification_off"`
	NotificationCheckInterval Duration `json:"notification_check_interval"`
	PollInterval              Duration `json:"poll_interval"`
	IncidentPollInterval      Duration `json:"incident_poll_interval"`
	LANStatsInterval          Duration `json:"lan_stats_interval"`
	RawStoreInterval          Duration `json:"raw_store_interval"`
	Timeout                   Duration `json:"timeout"`
	Pages                     []string `json:"pages"`
}

// ProbesConfig configures the fast cycle and service checks.
type ProbesConfig struct {
	FastInterval            Duration          `json:"fast_interval"`
	Timeout                 Duration          `json:"timeout"`
	Targets                 []model.ProbeSpec `json:"targets"`
	ServiceInterval         Duration          `json:"service_interval"`
	ServiceIncidentInterval Duration          `json:"service_incident_interval"`
	DNSName                 string            `json:"dns_name"`
	PublicResolvers         []string          `json:"public_resolvers"`
	HTTPChecks              []HTTPCheck       `json:"http_checks"`
	LocalLinkInterval       Duration          `json:"local_link_interval"`
	LocalLinkRecordEvery    Duration          `json:"local_link_record_every"`
	TracerouteTargets       []string          `json:"traceroute_targets"`
	TracerouteMaxHops       int               `json:"traceroute_max_hops"`
	TracerouteInterval      Duration          `json:"traceroute_interval"`
}

// IncidentConfig holds classifier and incident thresholds (docs/DESIGN.md §9-§10).
type IncidentConfig struct {
	OpenAfterCycles    int      `json:"open_after_cycles"`
	CloseAfterCycles   int      `json:"close_after_cycles"`
	WindowCycles       int      `json:"window_cycles"`
	LossDegradedPct    float64  `json:"loss_degraded_pct"`
	LatencyDegradedMs  float64  `json:"latency_degraded_ms"`
	GatewayLatencyOkMs float64  `json:"gateway_latency_ok_ms"`
	SnapshotFreshness  Duration `json:"snapshot_freshness"`
}

// AnchorConfig configures RFC 3161 anchoring.
type AnchorConfig struct {
	Enabled  bool     `json:"enabled"`
	Interval Duration `json:"interval"`
	TSAURLs  []string `json:"tsa_urls"`
	Timeout  Duration `json:"timeout"`
}

// ClockConfig configures SNTP clock checks.
type ClockConfig struct {
	NTPServers []string `json:"ntp_servers"`
	Interval   Duration `json:"interval"`
}

// WebConfig configures the localhost dashboard.
type WebConfig struct {
	Listen string `json:"listen"`
}

// MongoConfig configures the copy of the evidence in a local MongoDB (docs/DESIGN.md §17): every
// ledger record with its exact signed bytes, the raw blobs and the incidents, kept in step with
// the ledger. The signed JSONL ledger stays the source of truth; the monitor never waits for
// MongoDB. The URI must not contain credentials: the configuration is recorded in the ledger.
type MongoConfig struct {
	Enabled    bool     `json:"enabled"`
	URI        string   `json:"uri"`
	Database   string   `json:"database"`
	StoreBlobs bool     `json:"store_blobs"`
	Interval   Duration `json:"interval"`
}

// Config is the complete configuration.
type Config struct {
	Version           int            `json:"version"`
	Gateway           GatewayConfig  `json:"gateway"`
	Probes            ProbesConfig   `json:"probes"`
	Incident          IncidentConfig `json:"incident"`
	Anchoring         AnchorConfig   `json:"anchoring"`
	Clock             ClockConfig    `json:"clock"`
	Web               WebConfig      `json:"web"`
	Mongo             MongoConfig    `json:"mongo"`
	HeartbeatInterval Duration       `json:"heartbeat_interval"`
	BootstrapDir      string         `json:"bootstrap_dir,omitempty"`

	// dataDir is the directory holding config.json (set by Load/LoadOrCreate/Save/SetDataDir).
	// Secrets live in <dataDir>\keys, which install protects with a SYSTEM+Administrators-only ACL.
	dataDir string
}

// SetDataDir tells the config where its data directory is (secrets are stored under keys\).
func (c *Config) SetDataDir(dir string) { c.dataDir = dir }

// DataDir returns the data directory set by Load/LoadOrCreate/Save/SetDataDir ("" if unknown).
func (c *Config) DataDir() string { return c.dataDir }

// AccessCodeFile is where the DPAPI-protected gateway access code is stored.
// It lives in keys\ (private ACL) rather than in config.json (readable by local users).
func AccessCodeFile(dataDir string) string {
	return filepath.Join(dataDir, "keys", "gateway-access-code.dpapi")
}

// Default returns the default configuration (docs/DESIGN.md §8-§12).
func Default() *Config {
	return &Config{
		Version: 1,
		Gateway: GatewayConfig{
			Host:                      "192.168.1.254",
			Scheme:                    "https",
			EnforceNotificationOff:    true,
			NotificationCheckInterval: D(24 * time.Hour),
			PollInterval:              D(60 * time.Second),
			IncidentPollInterval:      D(15 * time.Second),
			LANStatsInterval:          D(15 * time.Minute),
			RawStoreInterval:          D(5 * time.Minute),
			Timeout:                   D(20 * time.Second),
			Pages:                     []string{"broadbandstatistics", "fiberstat", "sysinfo"},
		},
		Probes: ProbesConfig{
			FastInterval: D(10 * time.Second),
			Timeout:      D(2 * time.Second),
			Targets: []model.ProbeSpec{
				{Name: "gateway_icmp", Label: "AT&T gateway (ICMP)", Kind: model.KindICMP, Role: model.RoleGateway, Target: ""},
				{Name: "gateway_tcp", Label: "AT&T gateway (TCP 443)", Kind: model.KindTCP, Role: model.RoleGateway, Target: ""},
				{Name: "isp_hop_icmp", Label: "AT&T next hop (ICMP)", Kind: model.KindICMP, Role: model.RoleISPHop, Target: ""},
				{Name: "inet_icmp_cloudflare", Label: "Cloudflare 1.1.1.1", Kind: model.KindICMP, Role: model.RoleInet, Target: "1.1.1.1"},
				{Name: "inet_icmp_google", Label: "Google 8.8.8.8", Kind: model.KindICMP, Role: model.RoleInet, Target: "8.8.8.8"},
				{Name: "inet_icmp_quad9", Label: "Quad9 9.9.9.9", Kind: model.KindICMP, Role: model.RoleInet, Target: "9.9.9.9"},
				{Name: "inet_tcp_cloudflare", Label: "Cloudflare 1.1.1.1:443", Kind: model.KindTCP, Role: model.RoleInet, Target: "1.1.1.1:443"},
				{Name: "inet_tcp_google", Label: "Google 8.8.8.8:443", Kind: model.KindTCP, Role: model.RoleInet, Target: "8.8.8.8:443"},
			},
			ServiceInterval:         D(60 * time.Second),
			ServiceIncidentInterval: D(15 * time.Second),
			DNSName:                 "www.google.com",
			PublicResolvers:         []string{"1.1.1.1"},
			HTTPChecks: []HTTPCheck{
				{Name: "msft_connecttest", URL: "http://www.msftconnecttest.com/connecttest.txt", ExpectStatus: 200, ExpectBody: "Microsoft Connect Test"},
				{Name: "google_204", URL: "https://www.google.com/generate_204", ExpectStatus: 204},
			},
			LocalLinkInterval:    D(60 * time.Second),
			LocalLinkRecordEvery: D(10 * time.Minute),
			TracerouteTargets:    []string{"8.8.8.8", "1.1.1.1"},
			TracerouteMaxHops:    15,
			TracerouteInterval:   D(5 * time.Minute),
		},
		Incident: IncidentConfig{
			OpenAfterCycles:    3,
			CloseAfterCycles:   3,
			WindowCycles:       6,
			LossDegradedPct:    20,
			LatencyDegradedMs:  150,
			GatewayLatencyOkMs: 20,
			SnapshotFreshness:  D(150 * time.Second),
		},
		Anchoring: AnchorConfig{
			Enabled:  true,
			Interval: D(30 * time.Minute),
			TSAURLs:  []string{"http://timestamp.digicert.com", "https://freetsa.org/tsr"},
			Timeout:  D(20 * time.Second),
		},
		Clock: ClockConfig{
			NTPServers: []string{"time.windows.com", "time.google.com", "pool.ntp.org"},
			Interval:   D(time.Hour),
		},
		Web: WebConfig{Listen: "127.0.0.1:8320"},
		Mongo: MongoConfig{
			Enabled:    true,
			URI:        "mongodb://127.0.0.1:27017",
			Database:   "attmonitor",
			StoreBlobs: true,
			Interval:   D(5 * time.Second),
		},
		HeartbeatInterval: D(15 * time.Minute),
	}
}

// Load reads path, applying defaults for fields that are absent from the file.
func Load(path string) (*Config, error) {
	c := Default()
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, c); err != nil {
		return nil, fmt.Errorf("config %s: %w", path, err)
	}
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("config %s: %w", path, err)
	}
	c.dataDir = filepath.Dir(path)
	return c, nil
}

// LoadOrCreate loads path, or writes and returns the defaults if it does not exist.
func LoadOrCreate(path string) (*Config, error) {
	c, err := Load(path)
	if errors.Is(err, os.ErrNotExist) {
		c = Default()
		if err := Save(path, c); err != nil {
			return nil, err
		}
		return c, nil
	}
	return c, err
}

// Save writes c atomically (temp file + rename).
func Save(path string, c *Config) error {
	if err := c.Validate(); err != nil {
		return err
	}
	if c.dataDir == "" {
		c.dataDir = filepath.Dir(path)
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(b, '\n')); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Validate checks the configuration for values the monitor cannot work with.
func (c *Config) Validate() error {
	var errs []string
	if _, err := netip.ParseAddr(c.Gateway.Host); err != nil {
		errs = append(errs, "gateway.host must be an IP address")
	}
	if c.Gateway.Scheme != "https" && c.Gateway.Scheme != "http" {
		errs = append(errs, `gateway.scheme must be "https" or "http"`)
	}
	if c.Probes.FastInterval.Duration < 2*time.Second {
		errs = append(errs, "probes.fast_interval must be >= 2s")
	}
	if c.Probes.Timeout.Duration <= 0 || c.Probes.Timeout.Duration >= c.Probes.FastInterval.Duration {
		errs = append(errs, "probes.timeout must be > 0 and < fast_interval")
	}
	if c.Gateway.PollInterval.Duration < 10*time.Second {
		errs = append(errs, "gateway.poll_interval must be >= 10s")
	}
	if c.Incident.OpenAfterCycles < 1 || c.Incident.CloseAfterCycles < 1 || c.Incident.WindowCycles < 1 {
		errs = append(errs, "incident cycle counts must be >= 1")
	}
	ap, err := netip.ParseAddrPort(c.Web.Listen)
	if err != nil || !ap.Addr().IsLoopback() {
		errs = append(errs, "web.listen must be a loopback ip:port (e.g. 127.0.0.1:8320)")
	}
	if c.Mongo.Enabled {
		errs = append(errs, validateMongo(c.Mongo)...)
	}
	seen := map[string]bool{}
	for _, t := range c.Probes.Targets {
		if t.Name == "" || seen[t.Name] {
			errs = append(errs, "probe target names must be unique and non-empty")
			break
		}
		seen[t.Name] = true
		if t.Kind != model.KindICMP && t.Kind != model.KindTCP {
			errs = append(errs, "probe "+t.Name+": kind must be icmp or tcp")
		}
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

// validateMongo checks an enabled mongo section. Credentials are refused: the configuration is
// recorded in the ledger and in evidence bundles, so a password in the URI would be published
// with the evidence.
func validateMongo(m MongoConfig) []string {
	var errs []string
	rest, ok := strings.CutPrefix(m.URI, "mongodb://")
	if !ok {
		rest, ok = strings.CutPrefix(m.URI, "mongodb+srv://")
	}
	hosts := rest
	if i := strings.IndexAny(hosts, "/?"); i >= 0 {
		hosts = hosts[:i]
	}
	switch {
	case !ok || hosts == "":
		errs = append(errs, `mongo.uri must be a MongoDB URI such as "mongodb://127.0.0.1:27017"`)
	case strings.Contains(m.URI, "@") || mongoSecretOption(m.URI):
		errs = append(errs, "mongo.uri must not contain credentials (the configuration is recorded in the evidence ledger)")
	}
	if !validMongoDatabase(m.Database) {
		errs = append(errs, "mongo.database must be 1-63 characters without spaces or any of /\\.\"$*<>:|?")
	}
	if m.Interval.Duration < time.Second {
		errs = append(errs, "mongo.interval must be >= 1s")
	}
	return errs
}

// mongoSecretOption reports whether a URI option carries a secret, by the rules of
// internal/mongostore (which config cannot import): options are separated by "&" or ";", keys
// are unescaped as the driver does (one that cannot be counts as secret), and a key naming a
// password, secret or token, or authMechanismProperties, carries one.
func mongoSecretOption(uri string) bool {
	_, query, ok := strings.Cut(uri, "?")
	if !ok {
		return false
	}
	for _, kv := range strings.FieldsFunc(query, func(c rune) bool { return c == '&' || c == ';' }) {
		k, _, _ := strings.Cut(kv, "=")
		key, err := url.QueryUnescape(k)
		if err != nil {
			return true
		}
		key = strings.ToLower(key)
		if strings.Contains(key, "password") || strings.Contains(key, "secret") || strings.Contains(key, "token") || key == "authmechanismproperties" {
			return true
		}
	}
	return false
}

// validMongoDatabase applies MongoDB's database name rules on Windows.
func validMongoDatabase(name string) bool {
	if name == "" || len(name) > 63 {
		return false
	}
	return !strings.ContainsAny(name, "/\\.\"$*<>:|? \x00")
}

// HasAccessCode reports whether an access code is stored.
func (c *Config) HasAccessCode() bool {
	if c.dataDir != "" {
		if _, err := os.Stat(AccessCodeFile(c.dataDir)); err == nil {
			return true
		}
	}
	return c.Gateway.AccessCodeProtected != ""
}

// AccessCode decrypts the stored gateway access code (keys\gateway-access-code.dpapi; the
// legacy in-config field is used only when no file exists, e.g. in-memory test configs).
func (c *Config) AccessCode() (string, error) {
	var blob []byte
	if c.dataDir != "" {
		b, err := os.ReadFile(AccessCodeFile(c.dataDir))
		switch {
		case err == nil:
			blob = b
		case !errors.Is(err, os.ErrNotExist):
			return "", fmt.Errorf("read access code: %w", err)
		}
	}
	if blob == nil && c.Gateway.AccessCodeProtected != "" {
		b, err := base64.StdEncoding.DecodeString(c.Gateway.AccessCodeProtected)
		if err != nil {
			return "", fmt.Errorf("access code blob: %w", err)
		}
		blob = b
	}
	if blob == nil {
		return "", errors.New("no gateway access code configured (run: att-monitor set-access-code --file password.txt)")
	}
	plain, err := secret.Unprotect(blob, accessCodeEntropy)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

// SetAccessCode encrypts code with machine-scope DPAPI. With a known data directory the blob
// is written to keys\gateway-access-code.dpapi (atomically) and never to config.json.
func (c *Config) SetAccessCode(code string) error {
	code = strings.TrimSpace(code)
	if code == "" {
		return errors.New("empty access code")
	}
	blob, err := secret.Protect([]byte(code), accessCodeEntropy, true)
	if err != nil {
		return err
	}
	if c.dataDir == "" {
		c.Gateway.AccessCodeProtected = base64.StdEncoding.EncodeToString(blob)
		return nil
	}
	path := AccessCodeFile(c.dataDir)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, blob, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	c.Gateway.AccessCodeProtected = ""
	return nil
}

// RedactedSHA256 hashes the configuration with secrets removed (recorded in monitor_start).
func (c *Config) RedactedSHA256() string {
	cp := *c
	cp.Gateway.AccessCodeProtected = ""
	b, _ := json.Marshal(&cp)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Redacted returns a copy safe to display or export.
func (c *Config) Redacted() *Config {
	cp := *c
	if cp.Gateway.AccessCodeProtected != "" {
		cp.Gateway.AccessCodeProtected = "(protected)"
	}
	return &cp
}

// ParsePasswordFile reads a file with lines "ip:<host>" and "password:<access code>".
// Either line may be absent (host "" / code ""), but not both.
func ParsePasswordFile(path string) (host, code string, err error) {
	f, err := os.Open(path)
	if err != nil {
		return "", "", err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r\n")
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "ip", "host", "gateway":
			host = strings.TrimSpace(v)
		case "password", "access code", "accesscode", "code":
			code = strings.TrimSpace(v)
		}
	}
	if err := sc.Err(); err != nil {
		return "", "", err
	}
	if host == "" && code == "" {
		return "", "", fmt.Errorf("%s: no ip: or password: line found", path)
	}
	return host, code, nil
}

// Paths is the data-directory layout (docs/DESIGN.md §5).
type Paths struct {
	Root, Config, Keys, Ledger, Blobs, Exports, Quarantine, State, Logs string
}

// PathsFor returns the layout rooted at dataDir.
func PathsFor(dataDir string) Paths {
	return Paths{
		Root:       dataDir,
		Config:     filepath.Join(dataDir, FileName),
		Keys:       filepath.Join(dataDir, "keys"),
		Ledger:     filepath.Join(dataDir, "ledger"),
		Blobs:      filepath.Join(dataDir, "blobs"),
		Exports:    filepath.Join(dataDir, "exports"),
		Quarantine: filepath.Join(dataDir, "quarantine"),
		State:      filepath.Join(dataDir, "state"),
		Logs:       filepath.Join(dataDir, "logs"),
	}
}

// MkdirAll creates every directory of the layout.
func (p Paths) MkdirAll() error {
	for _, d := range []string{p.Root, p.Keys, p.Ledger, p.Blobs, p.Exports, p.Quarantine, p.State, p.Logs} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return err
		}
	}
	return nil
}

// DefaultDataDir returns %ProgramData%\ATTMonitor.
func DefaultDataDir() string {
	pd := os.Getenv("ProgramData")
	if pd == "" {
		pd = `C:\ProgramData`
	}
	return filepath.Join(pd, "ATTMonitor")
}
