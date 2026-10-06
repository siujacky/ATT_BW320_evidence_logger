package main

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"attmonitor/internal/config"
	"attmonitor/internal/connstore"
	"attmonitor/internal/contracts"
	"attmonitor/internal/ledger"
	"attmonitor/internal/model"
	"attmonitor/internal/netmap"
	"attmonitor/internal/syslogstore"
)

// newDataDir returns a data directory with a configuration (the MongoDB copy off, plus the JSON
// members in extra) and a new evidence ledger, as the service leaves them. Nothing is started:
// no socket is bound and no request is sent.
func newDataDir(t *testing.T, extra string) string {
	t.Helper()
	dir := t.TempDir()
	cfg := `{"version":1,"mongo":{"enabled":false}`
	if extra != "" {
		cfg += "," + extra
	}
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(cfg+"}"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := openStack(stackOptions{dataDir: dir, mode: "console"})
	if err != nil {
		t.Fatal(err)
	}
	s.close()
	return dir
}

// openLedgerReadOnly opens the ledger of a data directory for reading.
func openLedgerReadOnly(t *testing.T, dir string) *ledger.Store {
	t.Helper()
	led, err := ledger.Open(ledger.Options{Paths: config.PathsFor(dir), ReadOnly: true, Logger: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { led.Close() })
	return led
}

// TestOpenStackSyslog: with syslog.enabled the service writes the syslog store and has the
// receiver (not listening before the monitor runs it); the CLI and a service with syslog off
// only read the store; a store that cannot be opened leaves the rest of the stack working. No
// nil pointer ever reaches an interface (a typed nil would look like a store).
func TestOpenStackSyslog(t *testing.T) {
	dir := newDataDir(t, `"syslog":{"enabled":true,"keep_mb":64,"keep_days":3}`)
	s, err := openStack(stackOptions{dataDir: dir, mode: "console"})
	if err != nil {
		t.Fatal(err)
	}
	store := s.syslog
	if store == nil || s.syslogRx == nil || s.syslogWriter() == nil || s.syslogReceiver() == nil || s.syslogReader() == nil {
		t.Fatalf("service: store %v, receiver %v", s.syslog, s.syslogRx)
	}
	if addr, _ := s.syslogRx.Listening(); addr != "" {
		t.Errorf("listening before the monitor runs: %s", addr)
	}
	if st := s.mon.Status(); st.Syslog == nil || !st.Syslog.Enabled || st.Syslog.Store == nil || st.Syslog.Store.KeepMB != 64 || st.Syslog.Store.KeepDays != 3 {
		t.Errorf("Status.syslog %+v", st.Syslog)
	}
	if _, err := store.Recover(testNow); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Append([]model.SyslogMessage{{RX: "2026-10-05T21:00:00Z", Src: "192.168.1.254:514", Raw: "x"}}, 0, 0, testNow); err != nil {
		t.Fatal(err)
	}
	s.close()
	if _, err := store.Append(nil, 1, 0, testNow); !errors.Is(err, syslogstore.ErrClosed) {
		t.Errorf("the store was not closed with the stack: %v", err)
	}

	// The CLI reads the store, and reads it only.
	c, err := openStack(stackOptions{dataDir: dir, mode: "cli"})
	if err != nil {
		t.Fatal(err)
	}
	if c.syslog == nil || c.syslogRx != nil || c.syslogWriter() != nil || c.syslogReceiver() != nil || c.syslogReader() == nil {
		t.Fatalf("cli: store %v, receiver %v", c.syslog, c.syslogRx)
	}
	if _, err := c.syslog.Append(nil, 1, 0, testNow); !errors.Is(err, syslogstore.ErrReadOnly) {
		t.Errorf("the CLI's store is writable: %v", err)
	}
	if u := c.syslog.Usage(); u.OpenMessages != 1 || u.KeepMB != 64 {
		t.Errorf("the CLI does not see the open chunk: %+v", u)
	}
	if st := c.mon.Status(); st.Syslog != nil {
		t.Errorf("the CLI's monitor has syslog: %+v", st.Syslog)
	}
	c.close()

	// Syslog off: read, not written, no receiver.
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(`{"version":1,"mongo":{"enabled":false},"syslog":{"enabled":false}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	off, err := openStack(stackOptions{dataDir: dir, mode: "console"})
	if err != nil {
		t.Fatal(err)
	}
	if off.syslog == nil || off.syslogRx != nil || off.syslogWriter() != nil || off.syslogReceiver() != nil {
		t.Errorf("syslog off: store %v, receiver %v", off.syslog, off.syslogRx)
	}
	off.close()
}

// TestOpenStackWithoutSyslogStore: a syslog folder that cannot be used (here a file in its place)
// is logged; the service starts without syslog, and its readers get no store at all.
func TestOpenStackWithoutSyslogStore(t *testing.T) {
	dir := newDataDir(t, "")
	syslogDir := config.PathsFor(dir).Syslog
	if err := os.RemoveAll(syslogDir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(syslogDir, []byte("not a folder"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"console", "cli"} {
		s, err := openStack(stackOptions{dataDir: dir, mode: mode})
		if err != nil {
			t.Fatalf("%s: %v", mode, err)
		}
		if s.syslog != nil || s.syslogRx != nil || s.syslogReader() != nil || s.syslogWriter() != nil || s.syslogReceiver() != nil ||
			s.syslogChunks() != nil {
			t.Errorf("%s: store %v, receiver %v", mode, s.syslog, s.syslogRx)
		}
		if s.network != nil {
			// The firewall view has nothing to read.
			if _, err := s.network.Firewall(context.Background(), contracts.NetQuery{}); !errors.Is(err, contracts.ErrUnavailable) {
				t.Errorf("%s: firewall view without a syslog store: %v", mode, err)
			}
		}
		if st := s.mon.Status(); st.Syslog != nil {
			t.Errorf("%s: Status.syslog %+v", mode, st.Syslog)
		}
		s.close()
	}
}

// TestOpenStackNetwork: the service and console modes open the connection store (in the data
// directory's connections folder) for the monitor's samplers and the network view, the IP
// database (in geo; nothing is read or downloaded until runMonitor runs it) and the view over
// both and the syslog store; the stack's close closes the connection store. The CLI opens none
// of it: the connection store has one writer, and the CLI reads the page through the service.
func TestOpenStackNetwork(t *testing.T) {
	dir := newDataDir(t, `"syslog":{"enabled":true,"keep_mb":64}`)
	paths := config.PathsFor(dir)
	s, err := openStack(stackOptions{dataDir: dir, mode: "console"})
	if err != nil {
		t.Fatal(err)
	}
	if s.conns == nil || s.intel == nil || s.network == nil || s.connStore() == nil || s.ipIntel() == nil || s.networkView() == nil ||
		s.syslogChunks() == nil {
		t.Fatalf("console: store %v, IP database %v, view %v", s.conns, s.intel, s.network)
	}
	st := s.mon.Status().Connections
	if st == nil || !st.Enabled || st.Interval != "4m0s" || st.DevicesInterval != "15m0s" || st.Store == nil || st.Store.KeepDays != 30 ||
		st.Store.KeepMB != 200 {
		t.Fatalf("Status.connections %+v", st)
	}
	ns := s.network.NetworkStatus()
	if ns.Store == nil || ns.IPIntel == nil || !ns.IPIntel.Enabled || !ns.IPIntel.Download || !ns.IPIntel.ReverseDNS || ns.IPIntel.Loaded ||
		ns.Syslog == nil || ns.Syslog.KeepMB != 64 {
		t.Fatalf("network status %+v", ns)
	}
	// What the samplers append is in the connections folder, and the view reads it.
	at := now().UTC().Add(-time.Minute)
	nat := model.NATTable{Sessions: []model.NATSession{{Proto: "tcp", State: "ESTABLISHED", Src: "192.168.1.70", SrcPort: 50000,
		Dst: "203.0.113.5", DstPort: 443}}, InUse: 1, Available: 8191}
	if err := s.conns.AppendNAT(at, nat); err != nil {
		t.Fatal(err)
	}
	if m, _ := filepath.Glob(filepath.Join(paths.Connections, "nat-*.jsonl")); len(m) != 1 {
		t.Fatalf("NAT files in %s: %v", paths.Connections, m)
	}
	nc, err := s.network.Connections(context.Background(), contracts.NetQuery{From: at.Add(-time.Minute), To: at.Add(time.Minute)})
	if err != nil || nc.Samples != 1 || len(nc.Rows) != 1 || nc.Rows[0].Remote != "203.0.113.5" || nc.Rows[0].Service != "HTTPS" {
		t.Fatalf("connections view %+v, %v", nc, err)
	}
	if _, err := s.network.Firewall(context.Background(), contracts.NetQuery{}); err != nil {
		t.Fatalf("firewall view: %v", err)
	}
	store := s.conns
	s.close()
	if err := store.AppendNAT(at, nat); !errors.Is(err, connstore.ErrClosed) {
		t.Errorf("the connection store was not closed with the stack: %v", err)
	}

	c, err := openStack(stackOptions{dataDir: dir, mode: "cli"})
	if err != nil {
		t.Fatal(err)
	}
	defer c.close()
	if c.conns != nil || c.intel != nil || c.network != nil || c.connStore() != nil || c.ipIntel() != nil || c.networkView() != nil {
		t.Fatalf("cli: store %v, IP database %v, view %v", c.conns, c.intel, c.network)
	}
	if st := c.mon.Status(); st.Connections != nil {
		t.Errorf("the CLI's monitor has samplers: %+v", st.Connections)
	}
}

// TestOpenStackNetworkSwitchedOff: with connections.enabled off the connection store is still
// opened - the samplers do not run, the status says so, the page shows what was recorded before
// and the retention limits keep deleting old samples; with geo.enabled off the IP database only
// classifies addresses and names ports, and its status says it is off.
func TestOpenStackNetworkSwitchedOff(t *testing.T) {
	dir := newDataDir(t, `"connections":{"enabled":false,"keep_days":7},"geo":{"enabled":false}`)
	s, err := openStack(stackOptions{dataDir: dir, mode: "console"})
	if err != nil {
		t.Fatal(err)
	}
	defer s.close()
	if s.conns == nil || s.intel == nil || s.network == nil {
		t.Fatalf("store %v, IP database %v, view %v", s.conns, s.intel, s.network)
	}
	if st := s.mon.Status().Connections; st == nil || st.Enabled || st.Store == nil || st.Store.KeepDays != 7 {
		t.Fatalf("Status.connections %+v", st)
	}
	if ns := s.network.NetworkStatus(); ns.IPIntel == nil || ns.IPIntel.Enabled || ns.IPIntel.Download {
		t.Fatalf("IP database status %+v", ns.IPIntel)
	}
}

// TestOpenStackWithoutNetworkParts: a connections folder that cannot be used (here a file in its
// place) and an IP database that cannot be opened are logged; the stack starts, and the monitor
// and the view get no part at all (never a typed nil in an interface): no samplers, a
// connections view that is unavailable, a firewall view that still works.
func TestOpenStackWithoutNetworkParts(t *testing.T) {
	dir := newDataDir(t, "")
	paths := config.PathsFor(dir)
	if err := os.RemoveAll(paths.Connections); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths.Connections, []byte("not a folder"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := openStack(stackOptions{dataDir: dir, mode: "console"})
	if err != nil {
		t.Fatal(err)
	}
	defer s.close()
	if s.conns != nil || s.connStore() != nil || s.network == nil {
		t.Fatalf("store %v, view %v", s.conns, s.network)
	}
	if st := s.mon.Status(); st.Connections != nil {
		t.Errorf("samplers without a store: %+v", st.Connections)
	}
	if _, err := s.network.Connections(context.Background(), contracts.NetQuery{}); !errors.Is(err, contracts.ErrUnavailable) {
		t.Errorf("connections view without a store: %v", err)
	}
	if _, err := s.network.Firewall(context.Background(), contracts.NetQuery{}); err != nil {
		t.Errorf("firewall view: %v", err)
	}
	if ns := s.network.NetworkStatus(); ns.Store != nil || ns.IPIntel == nil || ns.Syslog == nil {
		t.Errorf("network status %+v", ns)
	}

	// An IP database whose download URL is not https (config.Load replaces such a URL by the
	// default; here it is set behind its back) cannot be opened: the view gets none.
	s.cfg.Geo = config.GeoConfig{Enabled: true, Download: true, URLv4: "http://example.invalid/v4.tsv.gz", URLv6: "http://example.invalid/v6.tsv.gz"}
	s.intel, s.network = nil, nil
	s.openNetwork()
	if s.intel != nil || s.ipIntel() != nil || s.network == nil {
		t.Fatalf("IP database %v, view %v", s.intel, s.network)
	}
	if ns := s.network.NetworkStatus(); ns.IPIntel != nil {
		t.Errorf("IP database status without one: %+v", ns.IPIntel)
	}
}

// TestOpenStackNetworkSettingsOutOfRange: a setting of the Network page that config.json gives out
// of range, or in a form that cannot be read, never keeps the evidence logger from starting: the
// stack opens with the value config.Load used instead, logs a warning naming the setting, and the
// page's status shows the warnings. Without warnings the view is the network view itself.
func TestOpenStackNetworkSettingsOutOfRange(t *testing.T) {
	for _, tc := range []struct {
		extra string
		check func(*stack) bool
		warn  string
	}{
		{`"connections":{"interval":"1m"}`, func(s *stack) bool { return s.mon.Status().Connections.Interval == "2m0s" },
			"connections.interval is 1m0s, below the minimum: 2m0s is used"},
		{`"connections":{"keep_days":0}`, func(s *stack) bool { return s.conns.Usage().KeepDays == 30 },
			"connections.keep_days is 0, not 1 to 3650: the default, 30, is used"},
		{`"connections":{"keep_mb":5}`, func(s *stack) bool { return s.conns.Usage().KeepMB == 10 },
			"connections.keep_mb is 5, below the minimum: 10 is used"},
		{`"connections":{"enabled":"false"}`, func(s *stack) bool { return !s.mon.Status().Connections.Enabled },
			"connections.enabled is not true or false: it is taken as false (off)"},
		{`"geo":{"refresh":"12h"}`, func(s *stack) bool { return s.cfg.Geo.Refresh.Duration == 24*time.Hour && s.intel != nil },
			"geo.refresh is 12h0m0s, below the minimum: 24h0m0s is used"},
		{`"geo":{"url_v4":""}`, func(s *stack) bool { return s.intel != nil && s.intel.Status().Source == "IPtoASN (iptoasn.com)" },
			"geo.url_v4 is empty: the default, https://iptoasn.com/data/ip2asn-v4.tsv.gz, is used"},
	} {
		dir := newDataDir(t, tc.extra) // opens the stack once: it fails the test if the start fails
		s, err := openStack(stackOptions{dataDir: dir, mode: "console"})
		if err != nil {
			t.Fatalf("%s: %v", tc.extra, err)
		}
		if s.conns == nil || s.network == nil || !tc.check(s) {
			t.Errorf("%s: the stack does not use the value config.Load chose: %+v %+v", tc.extra, s.cfg.Connections, s.cfg.Geo)
		}
		if ns := s.networkView().NetworkStatus(); !slices.Equal(ns.ConfigWarnings, []string{tc.warn}) || ns.Store == nil {
			t.Errorf("%s: the page's status says %q", tc.extra, ns.ConfigWarnings)
		}
		s.close()
		lg, err := os.ReadFile(filepath.Join(config.PathsFor(dir).Logs, "console.log"))
		if err != nil || !strings.Contains(string(lg), "config.json: a setting of the Network page is not used as written") ||
			!strings.Contains(string(lg), tc.warn) {
			t.Errorf("%s: the log does not say it (%v):\n%s", tc.extra, err, lg)
		}
	}

	// Nothing to say: the view is passed as it is, and its status has no warnings.
	s, err := openStack(stackOptions{dataDir: newDataDir(t, ""), mode: "console"})
	if err != nil {
		t.Fatal(err)
	}
	defer s.close()
	if v, ok := s.networkView().(*netmap.View); !ok || v != s.network || s.networkView().NetworkStatus().ConfigWarnings != nil {
		t.Errorf("view %T", s.networkView())
	}
}

// TestOpenStackLogsConfigError: a config.json the monitor cannot work with stops the start, and the
// operational log (logs\service.log for the service, here console.log) says why: the logger is set
// up before the configuration is read. The log is closed again (else the folder could not be
// deleted).
func TestOpenStackLogsConfigError(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(`{"version":1,"gateway":{"host":"gateway"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := openStack(stackOptions{dataDir: dir, mode: "console"}); err == nil || !strings.Contains(err.Error(), "gateway.host must be an IP address") {
		t.Fatalf("openStack: %v", err)
	}
	lg, err := os.ReadFile(filepath.Join(config.PathsFor(dir).Logs, "console.log"))
	if err != nil || !strings.Contains(string(lg), "config.json cannot be used") || !strings.Contains(string(lg), "gateway.host must be an IP address") {
		t.Fatalf("log (%v):\n%s", err, lg)
	}
	if err := os.Remove(filepath.Join(config.PathsFor(dir).Logs, "console.log")); err != nil {
		t.Errorf("the log is still open: %v", err)
	}
}

// TestInstallLayoutHasTheNetworkFolders: install (and setup, which runs it) secures the data
// directory and then lays it out with config.Paths.MkdirAll, so that every folder inherits the
// secured ACL: the Network page's folders are part of that layout. The service's own start does
// not create them (the connection store and the IP database do), so that a broken folder never
// keeps evidence collection from starting.
func TestInstallLayoutHasTheNetworkFolders(t *testing.T) {
	p := config.PathsFor(filepath.Join(t.TempDir(), "ATTMonitor"))
	if err := p.MkdirAll(); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{p.Connections, p.Geo} {
		if st, err := os.Stat(d); err != nil || !st.IsDir() {
			t.Errorf("the installer's layout has no %s: %v", d, err)
		}
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(`{"version":1,"mongo":{"enabled":false},"geo":{"download":false}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := openStack(stackOptions{dataDir: dir, mode: "console"})
	if err != nil {
		t.Fatal(err)
	}
	defer s.close()
	if _, err := os.Stat(config.PathsFor(dir).Geo); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the start created the IP database's folder before it had anything to keep: %v", err)
	}
}

func TestSyslogSenders(t *testing.T) {
	cfg := config.Default()
	cfg.Syslog.Allow = []string{"192.168.1.254", " 10.0.0.2 ", "not an address", "fe80::1"}
	want := []netip.Addr{netip.MustParseAddr("192.168.1.254"), netip.MustParseAddr("10.0.0.2"), netip.MustParseAddr("fe80::1")}
	if got := syslogSenders(cfg); !reflect.DeepEqual(got, want) {
		t.Errorf("syslogSenders = %v, want %v", got, want)
	}
}
