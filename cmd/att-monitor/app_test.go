package main

import (
	"errors"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"attmonitor/internal/config"
	"attmonitor/internal/ledger"
	"attmonitor/internal/model"
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
		if s.syslog != nil || s.syslogRx != nil || s.syslogReader() != nil || s.syslogWriter() != nil || s.syslogReceiver() != nil {
			t.Errorf("%s: store %v, receiver %v", mode, s.syslog, s.syslogRx)
		}
		if st := s.mon.Status(); st.Syslog != nil {
			t.Errorf("%s: Status.syslog %+v", mode, st.Syslog)
		}
		s.close()
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
