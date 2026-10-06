// Package config defines att-monitor's configuration file (docs/DESIGN.md §15), defaults,
// data-directory layout and the DPAPI-protected gateway access code.
package config

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
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
	PendingCertSHA256      string `json:"pending_cert_sha256,omitempty"`
	AccessCodeProtected    string `json:"access_code_protected,omitempty"` // base64 DPAPI blob
	EnforceNotificationOff bool   `json:"enforce_notification_off"`
	// EnforceSyslog keeps the gateway's Syslog page set to send its log to this computer
	// (docs/syslog-snmp-traffic.md phase 2): on, this computer's address, syslog.port, and
	// SyslogLevel - when empty, the level already set while syslog is on, else an option named
	// like "Informational", else the most detailed option that is not "Debug".
	EnforceSyslog             bool     `json:"enforce_syslog"`
	SyslogLevel               string   `json:"syslog_level,omitempty"`
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

// SyslogConfig configures the receiver of the gateway's syslog messages
// (docs/syslog-snmp-traffic.md). Messages are accepted only from the gateway (and Allow).
type SyslogConfig struct {
	Enabled bool `json:"enabled"`
	// Listen is the UDP address the receiver binds (":514" = every interface, port 514).
	Listen string `json:"listen"`
	// Port is the port the gateway is told to send to (the Listen port, unless something such as
	// a port forward sits in between).
	Port int `json:"port"`
	// Allow lists further senders (IP addresses) accepted besides the gateway.
	Allow []string `json:"allow,omitempty"`
	// FlushInterval is how often received messages are written to the syslog store (at most
	// MaxSyslogFlushInterval, so a chunk is sealed, and its syslog_chunk record written, within
	// minutes of its newest message); MaxPerMinute caps the messages kept per minute (the rest
	// are counted as dropped).
	FlushInterval Duration `json:"flush_interval"`
	MaxPerMinute  int      `json:"max_per_minute"`
	// KeepMB limits the syslog store: the oldest chunks are deleted once the stored messages
	// take more than this many MiB (default 100). KeepDays, when above 0, also deletes chunks
	// older than that many days. Each deletion is recorded in the ledger (syslog_prune), and the
	// SHA-256 of every chunk stays in its syslog_chunk record.
	KeepMB   int `json:"keep_mb"`
	KeepDays int `json:"keep_days"`
}

// ConnectionsConfig configures the samples behind the dashboard's Network page
// (docs/syslog-map-graphic.md): the gateway's NAT table (authenticated, read only) and its Device
// List (unauthenticated). They are not evidence: they are kept in connections\ for KeepDays
// within KeepMB and never written to the ledger.
type ConnectionsConfig struct {
	Enabled bool `json:"enabled"`
	// Interval is the time between two NAT table reads (2-4 min, default 4 min). The NAT table is
	// behind the gateway's login, and the gateway client reuses its login session for 5 minutes
	// after its last use: reads closer together than that keep one session and need no new login,
	// while any longer interval would need a login for every read (logins must stay rare: a few a
	// day). The reads follow the gateway client's login policy, have a login budget of their own and
	// pause whenever authenticated requests must not be sent.
	Interval Duration `json:"interval"`
	// DevicesInterval is the time between two Device List reads (5 min to 24 h, default 15 min).
	DevicesInterval Duration `json:"devices_interval"`
	KeepDays        int      `json:"keep_days"`
	KeepMB          int      `json:"keep_mb"`
	// ReverseDNS looks up the reverse DNS (PTR) names of the public addresses the dashboard shows,
	// through this computer's resolver, a few at a time; the names are cached.
	ReverseDNS bool `json:"reverse_dns"`
}

// GeoConfig configures the offline IP database of the Network page: the public-domain IPtoASN
// tables (the address ranges of every network with its AS number, name and country). Download
// fetches them into geo\ (only the public files are downloaded: no address is ever sent) and
// looks for newer ones every Refresh; without it, files placed in geo\ by hand are used.
type GeoConfig struct {
	Enabled  bool     `json:"enabled"`
	Download bool     `json:"download"`
	URLv4    string   `json:"url_v4"`
	URLv6    string   `json:"url_v6"`
	Refresh  Duration `json:"refresh"`
}

// Limits of the connections and geo settings. Load brings a value outside them into them
// (normalizeNetwork) rather than refuse the configuration.
//
// MaxConnInterval keeps the NAT table's reads within the gateway client's 5-minute session reuse
// (gateway.SessionReuse) with a margin for a read that waits for the gateway lock and for a round
// skipped for the evidence, which is tried again half a minute later: a longer interval would need
// a gateway login for every read - "reading less" would mean logging in more.
const (
	MinConnInterval        = 2 * time.Minute
	MaxConnInterval        = 4 * time.Minute
	MinConnDevicesInterval = 5 * time.Minute
	MaxConnDevicesInterval = 24 * time.Hour
	MaxConnKeepDays        = 3650
	MinConnKeepMB          = 10
	MaxConnKeepMB          = 1 << 20 // 1 TiB
	MinGeoRefresh          = 24 * time.Hour
	MaxGeoRefresh          = 90 * 24 * time.Hour
)

// connIntervalWhy says why connections.interval is no longer than MaxConnInterval.
const connIntervalWhy = "a longer interval would need a gateway login for every read: the login session is reused for 5 minutes only"

// Config is the complete configuration.
type Config struct {
	Version           int               `json:"version"`
	Gateway           GatewayConfig     `json:"gateway"`
	Probes            ProbesConfig      `json:"probes"`
	Incident          IncidentConfig    `json:"incident"`
	Anchoring         AnchorConfig      `json:"anchoring"`
	Clock             ClockConfig       `json:"clock"`
	Web               WebConfig         `json:"web"`
	Mongo             MongoConfig       `json:"mongo"`
	Syslog            SyslogConfig      `json:"syslog"`
	Connections       ConnectionsConfig `json:"connections"`
	Geo               GeoConfig         `json:"geo"`
	HeartbeatInterval Duration          `json:"heartbeat_interval"`
	BootstrapDir      string            `json:"bootstrap_dir,omitempty"`

	// dataDir is the directory holding config.json (set by Load/LoadOrCreate/Save/SetDataDir).
	// Secrets live in <dataDir>\keys, which install protects with a SYSTEM+Administrators-only ACL.
	dataDir string
	// warnings are the settings of the Network page that Load did not use as written, and what it
	// used instead (Warnings). They are not part of the file and never saved.
	warnings []string
}

// SetDataDir tells the config where its data directory is (secrets are stored under keys\).
func (c *Config) SetDataDir(dir string) { c.dataDir = dir }

// DataDir returns the data directory set by Load/LoadOrCreate/Save/SetDataDir ("" if unknown).
func (c *Config) DataDir() string { return c.dataDir }

// Warnings says, one sentence each, which settings of the Network page (the connections and geo
// sections) Load could not use as written and what it used instead (nil when none). Those settings
// never keep the monitor from starting: the service logs these warnings when it starts, and the
// Network page's status (GET /api/network/status) and `att-monitor network` show them.
func (c *Config) Warnings() []string { return slices.Clone(c.warnings) }

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
			EnforceSyslog:             true,
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
		Syslog: SyslogConfig{
			Enabled:       true,
			Listen:        ":514",
			Port:          514,
			FlushInterval: D(30 * time.Second),
			MaxPerMinute:  2000,
			KeepMB:        100,
		},
		Connections: ConnectionsConfig{
			Enabled:         true,
			Interval:        D(4 * time.Minute),
			DevicesInterval: D(15 * time.Minute),
			KeepDays:        30,
			KeepMB:          200,
			ReverseDNS:      true,
		},
		Geo: GeoConfig{
			Enabled:  true,
			Download: true,
			URLv4:    "https://iptoasn.com/data/ip2asn-v4.tsv.gz",
			URLv6:    "https://iptoasn.com/data/ip2asn-v6.tsv.gz",
			Refresh:  D(7 * 24 * time.Hour),
		},
		HeartbeatInterval: D(15 * time.Minute),
	}
}

// utf8BOM is the byte order mark that Windows PowerShell 5.1 (Set-Content -Encoding UTF8) and some
// editors write at the start of a UTF-8 file. It is not JSON: Load skips it.
var utf8BOM = []byte{0xef, 0xbb, 0xbf}

// Load reads path, applying defaults for fields that are absent from the file. A value the monitor
// cannot work with makes it fail (Validate) - except in the Network page's sections (connections,
// geo), which are not evidence and must never keep evidence collection from starting: there a
// member that cannot be read is left out (readSection), a value out of its range is replaced
// (normalizeNetwork), and Warnings says what is used instead.
func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	c := Default()
	// Every section but the Network page's goes into c. Those two are kept as written: f's own
	// fields hide the Config's fields of the same JSON names (encoding/json prefers the shallower
	// field), and readSection reads them member by member.
	f := struct {
		*Config
		Connections json.RawMessage `json:"connections"`
		Geo         json.RawMessage `json:"geo"`
	}{Config: c}
	if err := json.Unmarshal(bytes.TrimPrefix(b, utf8BOM), &f); err != nil {
		return nil, fmt.Errorf("config %s: %w", path, err)
	}
	d := Default()
	c.warnings = slices.Concat(
		readSection("connections", f.Connections, &c.Connections, d.Connections),
		readSection("geo", f.Geo, &c.Geo, d.Geo),
		c.normalizeNetwork())
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("config %s: %w", path, err)
	}
	c.dataDir = filepath.Dir(path)
	return c, nil
}

// readSection reads raw, a section of config.json as written (absent or null: nothing to read), into
// *dst, whose fields hold the section's defaults (def). It decodes the members one at a time, in the
// order written, as json.Unmarshal decodes an object - a member goes to the field of its JSON name,
// case ignored, an unknown member is ignored, the last of two for one field wins - except that a
// member that cannot be decoded (a value of the wrong JSON type, a duration that is not one) is left
// out with a warning: the setting keeps its default, but a switch (a setting whose default is true or
// false) is turned off, so that nothing the owner may have meant to stop is read from the gateway or
// the Internet. A section that is not a JSON object has all its switches turned off.
func readSection[T any](name string, raw json.RawMessage, dst *T, def T) []string {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return nil
	}
	defs := sectionMembers(def)
	dec := json.NewDecoder(bytes.NewReader(raw))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		var off []string
		for _, m := range defs {
			if m.isSwitch() {
				_ = setMember(dst, m.name, json.RawMessage("false"))
				off = append(off, m.name)
			}
		}
		return []string{fmt.Sprintf(`%s is not a JSON object such as {"enabled": false}: %s taken as false (off), the other settings are the defaults`,
			name, strings.Join(off, " and "))}
	}
	var warns []string
	for dec.More() {
		tok, err := dec.Token()
		key, ok := tok.(string)
		var v json.RawMessage
		if err != nil || !ok || dec.Decode(&v) != nil {
			break // cannot happen: the whole file was decoded once already
		}
		saved := *dst
		if setMember(dst, key, v) == nil {
			continue
		}
		*dst = saved
		i := slices.IndexFunc(defs, func(m member) bool { return strings.EqualFold(m.name, key) })
		if i < 0 {
			continue // cannot happen: an unknown member is ignored without an error
		}
		m := defs[i]
		if m.isSwitch() {
			_ = setMember(dst, m.name, json.RawMessage("false"))
			warns = append(warns, fmt.Sprintf("%s.%s is not true or false: it is taken as false (off)", name, m.name))
			continue
		}
		warns = append(warns, fmt.Sprintf("%s.%s is not %s: the default, %s, is used", name, m.name, m.want(), m.text()))
	}
	return warns
}

// member is a member of a section of config.json with its default value as JSON.
type member struct {
	name  string
	value json.RawMessage
}

// sectionMembers returns the members of def, a section, as JSON (in the order of its fields).
func sectionMembers(def any) []member {
	b, err := json.Marshal(def)
	if err != nil {
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	if _, err := dec.Token(); err != nil {
		return nil
	}
	var out []member
	for dec.More() {
		tok, err := dec.Token()
		var v json.RawMessage
		if err != nil || dec.Decode(&v) != nil {
			break
		}
		if name, ok := tok.(string); ok {
			out = append(out, member{name, v})
		}
	}
	return out
}

// isSwitch reports whether the member is a switch: its default is true or false.
func (m member) isSwitch() bool {
	return bytes.Equal(m.value, []byte("true")) || bytes.Equal(m.value, []byte("false"))
}

// text is the default as the warnings show it: a string without its quotes.
func (m member) text() string {
	var s string
	if json.Unmarshal(m.value, &s) == nil {
		return s
	}
	return string(m.value)
}

// want says what the member's value must be, from its default: a whole number, a duration (such
// as the default) or a string.
func (m member) want() string {
	var s string
	switch {
	case json.Unmarshal(m.value, &s) != nil:
		return "a whole number"
	case validDuration(s):
		return fmt.Sprintf("a duration such as %q", s)
	}
	return "a string"
}

// validDuration reports whether s is a Go duration string ("4m0s").
func validDuration(s string) bool {
	_, err := time.ParseDuration(s)
	return err == nil
}

// setMember decodes the member {"<name>": v} into dst, as json.Unmarshal would.
func setMember[T any](dst *T, name string, v json.RawMessage) error {
	k, err := json.Marshal(name)
	if err != nil {
		return err
	}
	return json.Unmarshal(slices.Concat([]byte("{"), k, []byte(":"), v, []byte("}")), dst)
}

// normalizeNetwork brings the settings of the Network page into the ranges the monitor works with
// (the limits above), whether or not their section is enabled - the retention limits apply also with
// the samplers off, and every value is recorded with the configuration: a value of 0 or less (or
// "") becomes the default, one below the minimum the minimum, one above the maximum the maximum,
// and a download URL that is not an https:// URL without credentials, query or fragment the default
// URL. It returns a warning for each change.
func (c *Config) normalizeNetwork() []string {
	d := Default()
	cc, g := &c.Connections, &c.Geo
	tooLong := cc.Interval.Duration > MaxConnInterval
	interval := clampSetting("connections.interval", &cc.Interval.Duration, d.Connections.Interval.Duration, MinConnInterval, MaxConnInterval)
	if tooLong {
		interval += " (" + connIntervalWhy + ")"
	}
	return slices.DeleteFunc([]string{
		interval,
		clampSetting("connections.devices_interval", &cc.DevicesInterval.Duration, d.Connections.DevicesInterval.Duration,
			MinConnDevicesInterval, MaxConnDevicesInterval),
		clampSetting("connections.keep_days", &cc.KeepDays, d.Connections.KeepDays, 1, MaxConnKeepDays),
		clampSetting("connections.keep_mb", &cc.KeepMB, d.Connections.KeepMB, MinConnKeepMB, MaxConnKeepMB),
		geoURLSetting("geo.url_v4", &g.URLv4, d.Geo.URLv4),
		geoURLSetting("geo.url_v6", &g.URLv6, d.Geo.URLv6),
		clampSetting("geo.refresh", &g.Refresh.Duration, d.Geo.Refresh.Duration, MinGeoRefresh, MaxGeoRefresh),
	}, func(w string) bool { return w == "" })
}

// clampSetting brings *v into [lo, hi] as normalizeNetwork says (def: the default) and returns the
// warning, "" when *v was in range.
func clampSetting[T int | time.Duration](name string, v *T, def, lo, hi T) string {
	was := *v
	switch {
	case was <= 0:
		*v = def
		return fmt.Sprintf("%s is %v, not %v to %v: the default, %v, is used", name, was, lo, hi, def)
	case was < lo:
		*v = lo
		return fmt.Sprintf("%s is %v, below the minimum: %v is used", name, was, lo)
	case was > hi:
		*v = hi
		return fmt.Sprintf("%s is %v, above the maximum: %v is used", name, was, hi)
	}
	return ""
}

// geoURLSetting replaces a download URL that is empty or not one geoURLOK accepts by the default def,
// and returns the warning, "" when the URL was fine. The warning never repeats the URL: it may hold
// a password.
func geoURLSetting(name string, v *string, def string) string {
	switch {
	case geoURLOK(*v):
		return ""
	case *v == "":
		*v = def
		return fmt.Sprintf("%s is empty: the default, %s, is used", name, def)
	}
	*v = def
	return fmt.Sprintf("%s is not an https:// URL without credentials, query or fragment: the default, %s, is used", name, def)
}

// geoURLOK reports whether s can be a download URL of the IP database: https, with a host, without
// credentials, query or fragment. The configuration is recorded in the ledger (monitor_start and
// every segment's config_state) - and through it in the MongoDB copy and every evidence bundle - so
// a URL must carry no secret: neither a password nor a query (a mirror's "?token=" or
// "?license_key="), which the IPtoASN files do not need. ipintel checks the same.
func geoURLOK(s string) bool {
	u, err := url.Parse(s)
	return err == nil && u.Scheme == "https" && u.Host != "" && u.User == nil && u.Fragment == "" &&
		u.RawQuery == "" && !u.ForceQuery
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
	if c.Syslog.Enabled {
		errs = append(errs, validateSyslog(c.Syslog)...)
	}
	// The Network page's sections, enabled or not: Load brings them into range before (it never
	// fails on them), so these checks only refuse values set out of range in code, before a Save.
	errs = append(errs, validateConnections(c.Connections)...)
	errs = append(errs, validateGeo(c.Geo)...)
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

// validateSyslog checks an enabled syslog section.
func validateSyslog(s SyslogConfig) []string {
	var errs []string
	host, port, err := net.SplitHostPort(s.Listen)
	if err != nil {
		errs = append(errs, `syslog.listen must be "host:port" or ":port", e.g. ":514"`)
	} else {
		if host != "" {
			if _, err := netip.ParseAddr(host); err != nil {
				errs = append(errs, "syslog.listen: the host must be an IP address")
			}
		}
		if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
			errs = append(errs, "syslog.listen: the port must be 1-65535")
		}
	}
	if s.Port < 1 || s.Port > 65535 {
		errs = append(errs, "syslog.port must be 1-65535")
	}
	for _, a := range s.Allow {
		if _, err := netip.ParseAddr(a); err != nil {
			errs = append(errs, "syslog.allow entries must be IP addresses")
			break
		}
	}
	if s.FlushInterval.Duration < time.Second || s.FlushInterval.Duration > MaxSyslogFlushInterval {
		errs = append(errs, "syslog.flush_interval must be 1s to "+MaxSyslogFlushInterval.String())
	}
	if s.MaxPerMinute < 1 {
		errs = append(errs, "syslog.max_per_minute must be >= 1")
	}
	if s.KeepMB < MinSyslogKeepMB || s.KeepMB > MaxSyslogKeepMB {
		errs = append(errs, fmt.Sprintf("syslog.keep_mb must be %d-%d", MinSyslogKeepMB, MaxSyslogKeepMB))
	}
	if s.KeepDays < 0 || s.KeepDays > MaxSyslogKeepDays {
		errs = append(errs, fmt.Sprintf("syslog.keep_days must be 0 (no age limit) to %d", MaxSyslogKeepDays))
	}
	return errs
}

// validateConnections checks the connections section (normalizeNetwork's ranges).
func validateConnections(s ConnectionsConfig) []string {
	var errs []string
	if s.Interval.Duration < MinConnInterval || s.Interval.Duration > MaxConnInterval {
		errs = append(errs, "connections.interval must be "+MinConnInterval.String()+" to "+MaxConnInterval.String()+" ("+connIntervalWhy+")")
	}
	if s.DevicesInterval.Duration < MinConnDevicesInterval || s.DevicesInterval.Duration > MaxConnDevicesInterval {
		errs = append(errs, "connections.devices_interval must be "+MinConnDevicesInterval.String()+" to "+MaxConnDevicesInterval.String())
	}
	if s.KeepDays < 1 || s.KeepDays > MaxConnKeepDays {
		errs = append(errs, fmt.Sprintf("connections.keep_days must be 1-%d", MaxConnKeepDays))
	}
	if s.KeepMB < MinConnKeepMB || s.KeepMB > MaxConnKeepMB {
		errs = append(errs, fmt.Sprintf("connections.keep_mb must be %d-%d", MinConnKeepMB, MaxConnKeepMB))
	}
	return errs
}

// validateGeo checks the geo section, enabled or not: the database is fetched over HTTPS only, from
// a URL without credentials or query (the configuration is recorded in the ledger: geoURLOK), and
// refreshed within normalizeNetwork's range.
func validateGeo(g GeoConfig) []string {
	var errs []string
	for _, f := range []struct{ name, v string }{{"geo.url_v4", g.URLv4}, {"geo.url_v6", g.URLv6}} {
		if !geoURLOK(f.v) {
			errs = append(errs, f.name+" must be an https:// URL without credentials, query or fragment")
		}
	}
	if g.Refresh.Duration < MinGeoRefresh || g.Refresh.Duration > MaxGeoRefresh {
		errs = append(errs, "geo.refresh must be "+MinGeoRefresh.String()+" to "+MaxGeoRefresh.String())
	}
	return errs
}

// Limits of the syslog retention settings.
const (
	MinSyslogKeepMB   = 1
	MaxSyslogKeepMB   = 1 << 20 // 1 TiB
	MaxSyslogKeepDays = 3650
	// MaxSyslogFlushInterval bounds syslog.flush_interval.
	MaxSyslogFlushInterval = 5 * time.Minute
)

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
	// Syslog holds the syslog store's chunk files (kept within syslog.keep_mb, unlike the
	// ledger and the blobs, which are never deleted).
	Syslog string
	// Connections holds the connection store's daily sample files (connections.keep_days within
	// connections.keep_mb); Geo the IP database and the reverse DNS cache. Neither is evidence.
	Connections, Geo string
}

// PathsFor returns the layout rooted at dataDir.
func PathsFor(dataDir string) Paths {
	return Paths{
		Root:        dataDir,
		Config:      filepath.Join(dataDir, FileName),
		Keys:        filepath.Join(dataDir, "keys"),
		Ledger:      filepath.Join(dataDir, "ledger"),
		Blobs:       filepath.Join(dataDir, "blobs"),
		Exports:     filepath.Join(dataDir, "exports"),
		Quarantine:  filepath.Join(dataDir, "quarantine"),
		State:       filepath.Join(dataDir, "state"),
		Logs:        filepath.Join(dataDir, "logs"),
		Syslog:      filepath.Join(dataDir, "syslog"),
		Connections: filepath.Join(dataDir, "connections"),
		Geo:         filepath.Join(dataDir, "geo"),
	}
}

// MkdirAll creates every directory of the layout.
func (p Paths) MkdirAll() error {
	for _, d := range []string{p.Root, p.Keys, p.Ledger, p.Blobs, p.Exports, p.Quarantine, p.State, p.Logs, p.Syslog, p.Connections, p.Geo} {
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
