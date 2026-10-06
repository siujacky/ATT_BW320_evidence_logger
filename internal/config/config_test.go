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
