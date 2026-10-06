package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDefaultValidates(t *testing.T) {
	if err := Default().Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestSaveLoadRoundTripAndDefaultsMerge(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, FileName)
	// A partial file: unspecified fields must come from Default().
	if err := os.WriteFile(p, []byte(`{"probes":{"fast_interval":"15s"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.Probes.FastInterval.Duration != 15*time.Second {
		t.Fatalf("fast interval %v", c.Probes.FastInterval)
	}
	if c.Gateway.Host != "192.168.1.254" || len(c.Probes.Targets) == 0 {
		t.Fatal("defaults not merged")
	}
	if err := Save(p, c); err != nil {
		t.Fatal(err)
	}
	c2, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if c2.RedactedSHA256() != c.RedactedSHA256() {
		t.Fatal("round trip changed config")
	}
}

// TestMongoConfig: the MongoDB copy is on by default against the local server; a URI with
// credentials is refused, because the configuration is recorded in the ledger and in bundles.
func TestMongoConfig(t *testing.T) {
	d := Default().Mongo
	if !d.Enabled || d.URI != "mongodb://127.0.0.1:27017" || d.Database != "attmonitor" || !d.StoreBlobs || d.Interval.Duration != 5*time.Second {
		t.Fatalf("defaults %+v", d)
	}
	// A config.json written before the mongo section existed gets the defaults.
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(`{"version":1,"web":{"listen":"127.0.0.1:8320"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil || c.Mongo != d {
		t.Fatalf("old config: %+v, %v", c.Mongo, err)
	}
	for uri, want := range map[string]string{
		"mongodb://admin:secret@127.0.0.1:27017":                           "credentials",
		"mongodb://admin@127.0.0.1:27017":                                  "credentials",
		"mongodb://127.0.0.1:27017/?authSource=x&password=hunt":            "credentials",
		"mongodb://127.0.0.1/?a=1;tlsCertificateKeyFilePassword=x":         "credentials",
		"mongodb://127.0.0.1/?authMechanismProperties=AWS_SESSION_TOKEN:x": "credentials",
		"mongodb://127.0.0.1/?%70assword=x":                                "credentials",
		"mongodb://127.0.0.1/?%zz=x":                                       "credentials",
		"http://127.0.0.1:27017":                                           "MongoDB URI",
		"mongodb://":                                                       "MongoDB URI",
		"mongodb://127.0.0.1:27017/?directConnection=true":                 "",
		"mongodb+srv://cluster.example.net":                                "",
	} {
		c := Default()
		c.Mongo.URI = uri
		err := c.Validate()
		if want == "" && err != nil || want != "" && (err == nil || !strings.Contains(err.Error(), want)) {
			t.Errorf("%s: %v (want %q)", uri, err, want)
		}
	}
	for name, ok := range map[string]bool{"attmonitor": true, "att-monitor_2": true, "": false, "a.b": false, "a b": false, `a\b`: false, strings.Repeat("x", 64): false} {
		c := Default()
		c.Mongo.Database = name
		if err := c.Validate(); (err == nil) != ok {
			t.Errorf("database %q: %v", name, err)
		}
	}
	// Disabled, the section is not checked.
	c = Default()
	c.Mongo = MongoConfig{}
	if err := c.Validate(); err != nil {
		t.Errorf("disabled: %v", err)
	}
}

// TestSyslogConfig: the receiver is on by default on UDP 514; an old config.json gets the
// defaults; bad values are refused only while the receiver is enabled.
func TestSyslogConfig(t *testing.T) {
	d := Default().Syslog
	if !d.Enabled || d.Listen != ":514" || d.Port != 514 || d.FlushInterval.Duration != 30*time.Second || d.MaxPerMinute != 2000 || len(d.Allow) != 0 ||
		d.KeepMB != 100 || d.KeepDays != 0 {
		t.Fatalf("defaults %+v", d)
	}
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"version":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if c, err := Load(path); err != nil || c.Syslog.Listen != ":514" || !c.Syslog.Enabled {
		t.Fatalf("old config: %+v %v", c.Syslog, err)
	}
	for name, mut := range map[string]func(*SyslogConfig){
		"listen":       func(s *SyslogConfig) { s.Listen = "514" },
		"listenip":     func(s *SyslogConfig) { s.Listen = "gateway:514" },
		"port0":        func(s *SyslogConfig) { s.Listen = ":0" },
		"target":       func(s *SyslogConfig) { s.Port = 70000 },
		"allow":        func(s *SyslogConfig) { s.Allow = []string{"not-an-ip"} },
		"flush":        func(s *SyslogConfig) { s.FlushInterval = D(0) },
		"flushlong":    func(s *SyslogConfig) { s.FlushInterval = D(6 * time.Minute) },
		"maxperminute": func(s *SyslogConfig) { s.MaxPerMinute = 0 },
		"keepmb0":      func(s *SyslogConfig) { s.KeepMB = 0 },
		"keepmbhuge":   func(s *SyslogConfig) { s.KeepMB = MaxSyslogKeepMB + 1 },
		"keepdays":     func(s *SyslogConfig) { s.KeepDays = -1 },
	} {
		c := Default()
		mut(&c.Syslog)
		if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "syslog.") {
			t.Errorf("%s: %v", name, err)
		}
		c.Syslog.Enabled = false
		if err := c.Validate(); err != nil {
			t.Errorf("%s disabled: %v", name, err)
		}
	}
	c := Default()
	c.Syslog.Listen, c.Syslog.Allow = "192.168.1.71:5514", []string{"192.168.1.254", "::1"}
	if err := c.Validate(); err != nil {
		t.Errorf("valid: %v", err)
	}
}

func TestValidateRejectsNonLoopbackListen(t *testing.T) {
	c := Default()
	c.Web.Listen = "0.0.0.0:8320"
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "loopback") {
		t.Fatalf("expected loopback error, got %v", err)
	}
}

func TestAccessCodeProtectedAndRedacted(t *testing.T) {
	c := Default()
	const code = `4#9*1=7%2/`
	if err := c.SetAccessCode(code); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(c.Gateway.AccessCodeProtected, code) {
		t.Fatal("access code stored in clear")
	}
	got, err := c.AccessCode()
	if err != nil || got != code {
		t.Fatalf("got %q, %v", got, err)
	}
	h1 := c.RedactedSHA256()
	if err := c.SetAccessCode("other"); err != nil {
		t.Fatal(err)
	}
	if c.RedactedSHA256() != h1 {
		t.Fatal("redacted hash must not depend on the secret")
	}
	if c.Redacted().Gateway.AccessCodeProtected != "(protected)" {
		t.Fatal("Redacted() leaked the blob")
	}
}

func TestAccessCodeStoredInKeysDirNotConfig(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, FileName)
	c, err := LoadOrCreate(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if c.DataDir() != dir {
		t.Fatalf("data dir %q", c.DataDir())
	}
	if c.HasAccessCode() {
		t.Fatal("fresh config claims an access code")
	}
	const code = `4#9*1=7%2/`
	if err := c.SetAccessCode(code); err != nil {
		t.Fatal(err)
	}
	if err := Save(cfgPath, c); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "access_code") {
		t.Fatalf("config.json must not hold the access code blob:\n%s", raw)
	}
	blob, err := os.ReadFile(AccessCodeFile(dir))
	if err != nil {
		t.Fatalf("access code file: %v", err)
	}
	if strings.Contains(string(blob), code) {
		t.Fatal("access code file holds plaintext")
	}
	c2, err := Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if !c2.HasAccessCode() {
		t.Fatal("reloaded config does not see the access code")
	}
	got, err := c2.AccessCode()
	if err != nil || got != code {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestParsePasswordFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "password.txt")
	if err := os.WriteFile(p, []byte("ip:192.168.1.254\r\npassword:4#9*1=7%2/\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	host, code, err := ParsePasswordFile(p)
	if err != nil || host != "192.168.1.254" || code != "4#9*1=7%2/" {
		t.Fatalf("got %q %q %v", host, code, err)
	}
}

// writeConfig writes body as config.json into a new directory and returns its path.
func writeConfig(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), FileName)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestLoadSkipsByteOrderMark: Windows PowerShell 5.1 (Set-Content -Encoding UTF8) and some editors
// begin a UTF-8 file with a byte order mark, which is not JSON: Load skips it.
func TestLoadSkipsByteOrderMark(t *testing.T) {
	c, err := Load(writeConfig(t, "\xef\xbb\xbf"+`{"version":1,"probes":{"fast_interval":"15s"}}`))
	if err != nil {
		t.Fatalf("Load of a file with a byte order mark: %v", err)
	}
	if c.Probes.FastInterval.Duration != 15*time.Second {
		t.Errorf("fast interval %v", c.Probes.FastInterval)
	}
	// Only the mark is skipped: anything else before the JSON is still an error.
	if _, err := Load(writeConfig(t, "\xef\xbb\xbf\xef\xbb\xbf{}")); err == nil {
		t.Error("two byte order marks were accepted")
	}
}

// TestNetworkSettingsNeverStopTheLoad: the Network page's sections (connections, geo) are not
// evidence, so a value there that cannot be used never makes Load fail, enabled or not: a value of
// 0 or less becomes the default, one out of range its limit, a download URL that is not https or
// carries credentials the default URL, a member of the wrong JSON type its default (a switch is
// then off), and a section that is not an object has its switches off. Each is a warning, which
// never repeats a URL (it may hold a password); the next Save writes the values used.
func TestNetworkSettingsNeverStopTheLoad(t *testing.T) {
	d := Default()
	conns := func(mut func(*ConnectionsConfig)) ConnectionsConfig { c := d.Connections; mut(&c); return c }
	geo := func(mut func(*GeoConfig)) GeoConfig { g := d.Geo; mut(&g); return g }
	for _, tc := range []struct {
		body  string
		conns ConnectionsConfig
		geo   GeoConfig
		warns []string // the warnings, in order (each a substring)
	}{
		// Out of range.
		{`"connections":{"interval":"1m"}`, conns(func(c *ConnectionsConfig) { c.Interval = D(2 * time.Minute) }), d.Geo,
			[]string{"connections.interval is 1m0s, below the minimum: 2m0s is used"}},
		{`"connections":{"interval":"2h"}`, conns(func(c *ConnectionsConfig) { c.Interval = D(4 * time.Minute) }), d.Geo,
			[]string{"connections.interval is 2h0m0s, above the maximum: 4m0s is used (a longer interval would need a gateway login for every read"}},
		{`"connections":{"interval":"5m"}`, conns(func(c *ConnectionsConfig) { c.Interval = D(4 * time.Minute) }), d.Geo,
			[]string{"connections.interval is 5m0s, above the maximum: 4m0s is used (a longer interval would need a gateway login for every read"}},
		{`"connections":{"interval":"0s"}`, d.Connections, d.Geo,
			[]string{"connections.interval is 0s, not 2m0s to 4m0s: the default, 4m0s, is used"}},
		{`"connections":{"interval":240}`, conns(func(c *ConnectionsConfig) { c.Interval = D(2 * time.Minute) }), d.Geo,
			[]string{"connections.interval is 240ns, below the minimum: 2m0s is used"}},
		{`"connections":{"devices_interval":"1m"}`, conns(func(c *ConnectionsConfig) { c.DevicesInterval = D(5 * time.Minute) }), d.Geo,
			[]string{"connections.devices_interval is 1m0s, below the minimum: 5m0s is used"}},
		{`"connections":{"devices_interval":"48h"}`, conns(func(c *ConnectionsConfig) { c.DevicesInterval = D(24 * time.Hour) }), d.Geo,
			[]string{"connections.devices_interval is 48h0m0s, above the maximum: 24h0m0s is used"}},
		{`"connections":{"keep_days":0}`, d.Connections, d.Geo,
			[]string{"connections.keep_days is 0, not 1 to 3650: the default, 30, is used"}},
		{`"connections":{"keep_days":-5}`, d.Connections, d.Geo,
			[]string{"connections.keep_days is -5, not 1 to 3650: the default, 30, is used"}},
		{`"connections":{"keep_days":5000}`, conns(func(c *ConnectionsConfig) { c.KeepDays = MaxConnKeepDays }), d.Geo,
			[]string{"connections.keep_days is 5000, above the maximum: 3650 is used"}},
		{`"connections":{"keep_mb":5}`, conns(func(c *ConnectionsConfig) { c.KeepMB = MinConnKeepMB }), d.Geo,
			[]string{"connections.keep_mb is 5, below the minimum: 10 is used"}},
		{`"connections":{"keep_mb":0}`, d.Connections, d.Geo,
			[]string{"connections.keep_mb is 0, not 10 to 1048576: the default, 200, is used"}},
		{`"connections":{"keep_mb":2000000}`, conns(func(c *ConnectionsConfig) { c.KeepMB = MaxConnKeepMB }), d.Geo,
			[]string{"connections.keep_mb is 2000000, above the maximum: 1048576 is used"}},
		// Switched off: the limits still apply (the store's retention limits are used either way).
		{`"connections":{"enabled":false,"keep_days":0,"keep_mb":3}`,
			conns(func(c *ConnectionsConfig) { c.Enabled, c.KeepMB = false, MinConnKeepMB }), d.Geo,
			[]string{"connections.keep_days is 0", "connections.keep_mb is 3, below the minimum: 10 is used"}},
		{`"geo":{"refresh":"12h"}`, d.Connections, geo(func(g *GeoConfig) { g.Refresh = D(24 * time.Hour) }),
			[]string{"geo.refresh is 12h0m0s, below the minimum: 24h0m0s is used"}},
		{`"geo":{"refresh":"2400h"}`, d.Connections, geo(func(g *GeoConfig) { g.Refresh = D(MaxGeoRefresh) }),
			[]string{"geo.refresh is 2400h0m0s, above the maximum: 2160h0m0s is used"}},
		{`"geo":{"enabled":false,"refresh":"-1h"}`, d.Connections, geo(func(g *GeoConfig) { g.Enabled = false }),
			[]string{"geo.refresh is -1h0m0s, not 24h0m0s to 2160h0m0s: the default, 168h0m0s, is used"}},
		// Download URLs.
		{`"geo":{"url_v4":""}`, d.Connections, d.Geo, []string{"geo.url_v4 is empty: the default, " + d.Geo.URLv4 + ", is used"}},
		{`"geo":{"url_v6":"http://example.invalid/v6.tsv.gz"}`, d.Connections, d.Geo,
			[]string{"geo.url_v6 is not an https:// URL without credentials, query or fragment: the default, " + d.Geo.URLv6 + ", is used"}},
		// A query is refused like credentials: the configuration is recorded in the ledger.
		{`"geo":{"url_v4":"https://mirror.example.invalid/v4.tsv.gz?token=SECRET-TOKEN-123"}`, d.Connections, d.Geo,
			[]string{"geo.url_v4 is not an https:// URL without credentials, query or fragment"}},
		{`"geo":{"url_v6":"https://mirror.example.invalid/v6.tsv.gz?"}`, d.Connections, d.Geo,
			[]string{"geo.url_v6 is not an https:// URL without credentials, query or fragment"}},
		{`"geo":{"url_v4":"https://example.invalid/v4.tsv.gz#part"}`, d.Connections, d.Geo, []string{"geo.url_v4 is not an https:// URL"}},
		{`"geo":{"url_v4":"https://owner:hunter2@example.invalid/v4.tsv.gz"}`, d.Connections, d.Geo, []string{"geo.url_v4 is not an https:// URL"}},
		{`"geo":{"enabled":false,"download":false,"url_v4":"https://owner:hunter2@example.invalid/v4.tsv.gz"}`, d.Connections,
			geo(func(g *GeoConfig) { g.Enabled, g.Download = false, false }), []string{"geo.url_v4 is not an https:// URL"}},
		{`"geo":{"url_v4":"https://mirror.example.invalid/v4.tsv.gz"}`, d.Connections,
			geo(func(g *GeoConfig) { g.URLv4 = "https://mirror.example.invalid/v4.tsv.gz" }), nil},
		// Members that cannot be read: a switch is off, any other setting keeps its default, and the
		// other members are read as written.
		{`"connections":{"enabled":"false"}`, conns(func(c *ConnectionsConfig) { c.Enabled = false }), d.Geo,
			[]string{"connections.enabled is not true or false: it is taken as false (off)"}},
		{`"connections":{"reverse_dns":1}`, conns(func(c *ConnectionsConfig) { c.ReverseDNS = false }), d.Geo,
			[]string{"connections.reverse_dns is not true or false: it is taken as false (off)"}},
		{`"geo":{"download":"no","refresh":"48h"}`, d.Connections,
			geo(func(g *GeoConfig) { g.Download, g.Refresh = false, D(48*time.Hour) }),
			[]string{"geo.download is not true or false: it is taken as false (off)"}},
		{`"connections":{"keep_days":"7"}`, d.Connections, d.Geo,
			[]string{"connections.keep_days is not a whole number: the default, 30, is used"}},
		{`"connections":{"keep_mb":250.5}`, d.Connections, d.Geo,
			[]string{"connections.keep_mb is not a whole number: the default, 200, is used"}},
		{`"connections":{"interval":"4 minutes"}`, d.Connections, d.Geo,
			[]string{`connections.interval is not a duration such as "4m0s": the default, 4m0s, is used`}},
		{`"connections":{"devices_interval":{"minutes":15}}`, d.Connections, d.Geo,
			[]string{`connections.devices_interval is not a duration such as "15m0s"`}},
		{`"geo":{"url_v4":42}`, d.Connections, d.Geo, []string{"geo.url_v4 is not a string: the default, " + d.Geo.URLv4 + ", is used"}},
		{`"connections":{"enabled":false,"keep_days":"x","interval":"3m","keep_mb":50}`,
			conns(func(c *ConnectionsConfig) { c.Enabled, c.Interval, c.KeepMB = false, D(3*time.Minute), 50 }), d.Geo,
			[]string{"connections.keep_days is not a whole number"}},
		// Names as encoding/json matches them; of two for one setting the last wins, and a bad one
		// leaves the one before; unknown members are ignored, as everywhere in the file.
		{`"connections":{"Keep_Days":7,"ENABLED":false,"bogus":"x"}`,
			conns(func(c *ConnectionsConfig) { c.KeepDays, c.Enabled = 7, false }), d.Geo, nil},
		{`"connections":{"keep_days":7,"keep_days":9}`, conns(func(c *ConnectionsConfig) { c.KeepDays = 9 }), d.Geo, nil},
		{`"connections":{"keep_days":7,"keep_days":"x"}`, conns(func(c *ConnectionsConfig) { c.KeepDays = 7 }), d.Geo,
			[]string{"connections.keep_days is not a whole number"}},
		// Sections that are not objects: their switches are off.
		{`"connections":false`, conns(func(c *ConnectionsConfig) { c.Enabled, c.ReverseDNS = false, false }), d.Geo,
			[]string{`connections is not a JSON object such as {"enabled": false}: enabled and reverse_dns taken as false (off), the other settings are the defaults`}},
		{`"geo":"off"`, d.Connections, geo(func(g *GeoConfig) { g.Enabled, g.Download = false, false }),
			[]string{`geo is not a JSON object such as {"enabled": false}: enabled and download taken as false (off)`}},
		{`"connections":null,"geo":null`, d.Connections, d.Geo, nil},
		{`"connections":{},"geo":{}`, d.Connections, d.Geo, nil},
		// In range: nothing to say.
		{`"connections":{"interval":"2m","devices_interval":"24h","keep_days":1,"keep_mb":10},"geo":{"refresh":"24h"}`,
			conns(func(c *ConnectionsConfig) {
				c.Interval, c.DevicesInterval, c.KeepDays, c.KeepMB = D(2*time.Minute), D(24*time.Hour), 1, 10
			}), geo(func(g *GeoConfig) { g.Refresh = D(24 * time.Hour) }), nil},
	} {
		p := writeConfig(t, `{"version":1,`+tc.body+`}`)
		c, err := Load(p)
		if err != nil {
			t.Errorf("%s: Load failed: %v", tc.body, err)
			continue
		}
		if c.Connections != tc.conns || c.Geo != tc.geo {
			t.Errorf("%s:\n connections %+v\n        want %+v\n geo %+v\nwant %+v", tc.body, c.Connections, tc.conns, c.Geo, tc.geo)
		}
		warns := c.Warnings()
		if len(warns) != len(tc.warns) {
			t.Errorf("%s: warnings %q, want %d", tc.body, warns, len(tc.warns))
		} else {
			for i, w := range tc.warns {
				if !strings.Contains(warns[i], w) {
					t.Errorf("%s: warning %q, want %q", tc.body, warns[i], w)
				}
			}
		}
		for _, w := range warns {
			if strings.Contains(w, "hunter2") || strings.Contains(w, "owner") || strings.Contains(w, "SECRET-TOKEN") {
				t.Errorf("%s: a warning repeats the URL's credentials: %q", tc.body, w)
			}
		}
		// The values used are saved as they are: the next load has nothing to say.
		if err := Save(p, c); err != nil {
			t.Errorf("%s: Save: %v", tc.body, err)
			continue
		}
		if raw, _ := os.ReadFile(p); strings.Contains(string(raw), "hunter2") || strings.Contains(string(raw), "SECRET-TOKEN") ||
			strings.Contains(string(raw), "warning") {
			t.Errorf("%s: saved:\n%s", tc.body, raw)
		}
		c2, err := Load(p)
		if err != nil || len(c2.Warnings()) != 0 || c2.Connections != c.Connections || c2.Geo != c.Geo {
			t.Errorf("%s: after Save: %+v %+v %q %v", tc.body, c2.Connections, c2.Geo, c2.Warnings(), err)
		}
	}
}

// TestNetworkWarningsAreNotConfiguration: the warnings are not part of the configuration - not in
// its JSON, not in the hash recorded in monitor_start - and Warnings returns a copy.
func TestNetworkWarningsAreNotConfiguration(t *testing.T) {
	c, err := Load(writeConfig(t, `{"version":1,"connections":{"keep_days":0}}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Warnings()) != 1 {
		t.Fatalf("warnings %q", c.Warnings())
	}
	if c.RedactedSHA256() != Default().RedactedSHA256() {
		t.Error("the warnings change the configuration's hash")
	}
	c.Warnings()[0] = "changed"
	if c.Warnings()[0] == "changed" {
		t.Error("Warnings returns the configuration's own slice")
	}
	if Default().Warnings() != nil {
		t.Error("the defaults have warnings")
	}
}

// TestOtherSettingsStillStopTheLoad: outside the Network page's sections a value the monitor
// cannot work with still makes Load fail, and so does a file that is not JSON (also inside those
// sections).
func TestOtherSettingsStillStopTheLoad(t *testing.T) {
	for _, body := range []string{
		`{"gateway":{"host":"gateway"}}`,
		`{"probes":{"fast_interval":"10 seconds"}}`,
		`{"syslog":{"keep_mb":0}}`,
		`{"web":{"listen":"0.0.0.0:8320"}}`,
		`{"mongo":{"enabled":"yes"}}`,
		`{"connections":{"interval":}}`,
		`{"geo":{"refresh":"24h"}`,
	} {
		if _, err := Load(writeConfig(t, body)); err == nil {
			t.Errorf("%s: loaded", body)
		}
	}
}

// TestConnIntervalWithinTheSessionReuse: the NAT table may be read every 2 to 4 minutes, never less
// often: the gateway client reuses its login session for 5 minutes, and a longer interval would need
// a login for every read. Validate says why.
func TestConnIntervalWithinTheSessionReuse(t *testing.T) {
	for _, d := range []time.Duration{2 * time.Minute, 3 * time.Minute, 4 * time.Minute} {
		c := Default()
		c.Connections.Interval = D(d)
		if err := c.Validate(); err != nil {
			t.Errorf("%v refused: %v", d, err)
		}
	}
	c := Default()
	c.Connections.Interval = D(10 * time.Minute)
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "2m0s to 4m0s") ||
		!strings.Contains(err.Error(), "a gateway login for every read") {
		t.Errorf("10m: %v", err)
	}
}

// TestValidateChecksNetworkSections: values set out of range in code are refused by Validate, and so
// by Save, whether or not their section is enabled (Load never gets there with them).
func TestValidateChecksNetworkSections(t *testing.T) {
	for name, mut := range map[string]func(*Config){
		"interval":         func(c *Config) { c.Connections.Interval = D(time.Minute) },
		"interval 4m1s":    func(c *Config) { c.Connections.Interval = D(4*time.Minute + time.Second) },
		"interval 5m":      func(c *Config) { c.Connections.Interval = D(5 * time.Minute) },
		"interval 10m":     func(c *Config) { c.Connections.Interval = D(10 * time.Minute) },
		"interval 1h":      func(c *Config) { c.Connections.Interval = D(time.Hour) },
		"url, query":       func(c *Config) { c.Geo.URLv4 = "https://mirror.example.invalid/v4.tsv.gz?token=x" },
		"url, empty query": func(c *Config) { c.Geo.URLv6 = "https://mirror.example.invalid/v6.tsv.gz?" },
		"keep_days, off":   func(c *Config) { c.Connections.Enabled, c.Connections.KeepDays = false, 0 },
		"keep_mb":          func(c *Config) { c.Connections.KeepMB = 5 },
		"refresh":          func(c *Config) { c.Geo.Refresh = D(time.Hour) },
		"url, geo off":     func(c *Config) { c.Geo.Enabled, c.Geo.URLv4 = false, "http://example.invalid/x" },
		"url, with login":  func(c *Config) { c.Geo.URLv6 = "https://a:b@example.invalid/x" },
	} {
		c := Default()
		mut(c)
		if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "connections.") && !strings.Contains(err.Error(), "geo.") {
			t.Errorf("%s: %v", name, err)
		}
		if err := Save(filepath.Join(t.TempDir(), FileName), c); err == nil {
			t.Errorf("%s: saved", name)
		}
	}
}
