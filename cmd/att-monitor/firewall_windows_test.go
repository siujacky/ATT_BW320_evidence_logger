package main

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"attmonitor/internal/config"
)

// fakeNetsh replaces netsh for a test: it records every command and answers from fail (a
// command whose words start with a key fails, printing the value). The firewall is never
// changed or even read.
type fakeNetsh struct {
	calls [][]string
	fail  map[string]string
}

func useFakeNetsh(t *testing.T) *fakeNetsh {
	t.Helper()
	f := &fakeNetsh{fail: map[string]string{}}
	restore := runNetsh
	runNetsh = func(args ...string) ([]byte, error) {
		f.calls = append(f.calls, args)
		cmd := strings.Join(args, " ")
		for prefix, out := range f.fail {
			if strings.HasPrefix(cmd, prefix) {
				return []byte(out), errors.New("exit status 1")
			}
		}
		return []byte("Ok.\r\n\r\n"), nil
	}
	t.Cleanup(func() { runNetsh = restore })
	return f
}

const testExe = `C:\Program Files\ATT Monitor\att-monitor.exe`

func addArgs(port, remote string) []string {
	return []string{"advfirewall", "firewall", "add", "rule", "name=AT&T Internet Monitor syslog", "dir=in", "action=allow", "protocol=UDP",
		"localport=" + port, "remoteip=" + remote, "program=" + testExe, "profile=any", "enable=yes",
		"description=Lets the AT&T gateway's syslog messages reach the AT&T Internet Monitor. Added by att-monitor install, removed by uninstall."}
}

var (
	deleteArgs = []string{"advfirewall", "firewall", "delete", "rule", "name=AT&T Internet Monitor syslog"}
	showArgs   = []string{"advfirewall", "firewall", "show", "rule", "name=AT&T Internet Monitor syslog"}
)

// TestEnsureSyslogFirewallRule: the rule is replaced (delete, whatever its outcome, then add)
// with every argument on its own, limited to the gateway, the port and the program.
func TestEnsureSyslogFirewallRule(t *testing.T) {
	f := useFakeNetsh(t)
	f.fail["advfirewall firewall delete"] = "No rules match the specified criteria."
	if err := ensureSyslogFirewallRule(testExe, netip.MustParseAddr("192.168.1.254"), 514); err != nil {
		t.Fatal(err)
	}
	if want := [][]string{deleteArgs, addArgs("514", "192.168.1.254")}; !reflect.DeepEqual(f.calls, want) {
		t.Errorf("netsh calls\n%q\nwant\n%q", f.calls, want)
	}

	f.calls = nil
	if err := ensureSyslogFirewallRule(testExe, netip.MustParseAddr("::ffff:10.0.0.1"), 5514); err != nil {
		t.Fatal(err)
	}
	if got := f.calls[1]; !reflect.DeepEqual(got, addArgs("5514", "10.0.0.1")) {
		t.Errorf("add %q", got)
	}

	// A failed add is an error that says what netsh said.
	f.fail["advfirewall firewall add"] = "The requested operation requires elevation (Run as administrator).\r\n\r\n"
	err := ensureSyslogFirewallRule(testExe, netip.MustParseAddr("192.168.1.254"), 514)
	if err == nil || !strings.Contains(err.Error(), `netsh could not add the rule "AT&T Internet Monitor syslog": exit status 1 (The requested operation requires elevation (Run as administrator).)`) {
		t.Errorf("failed add: %v", err)
	}

	// Nothing is run for arguments that cannot make a rule.
	f.calls = nil
	for _, c := range []struct {
		exe  string
		gw   netip.Addr
		port int
	}{{testExe, netip.Addr{}, 514}, {testExe, netip.MustParseAddr("192.168.1.254"), 0}, {testExe, netip.MustParseAddr("192.168.1.254"), 65536},
		{"att-monitor.exe", netip.MustParseAddr("192.168.1.254"), 514}} {
		if err := ensureSyslogFirewallRule(c.exe, c.gw, c.port); err == nil {
			t.Errorf("%+v accepted", c)
		}
	}
	if len(f.calls) != 0 {
		t.Errorf("netsh ran: %q", f.calls)
	}
}

// TestRemoveSyslogFirewallRule: deleted; absent (netsh fails, and cannot show the rule either) is
// no error; a rule that exists but cannot be deleted is.
func TestRemoveSyslogFirewallRule(t *testing.T) {
	f := useFakeNetsh(t)
	if removed, err := removeSyslogFirewallRule(); !removed || err != nil {
		t.Errorf("present: %v %v", removed, err)
	}
	if !reflect.DeepEqual(f.calls, [][]string{deleteArgs}) {
		t.Errorf("calls %q", f.calls)
	}

	f.calls = nil
	f.fail["advfirewall firewall delete"] = "No rules match the specified criteria."
	f.fail["advfirewall firewall show"] = "No rules match the specified criteria."
	if removed, err := removeSyslogFirewallRule(); removed || err != nil {
		t.Errorf("absent: %v %v", removed, err)
	}
	if !reflect.DeepEqual(f.calls, [][]string{deleteArgs, showArgs}) {
		t.Errorf("calls %q", f.calls)
	}

	delete(f.fail, "advfirewall firewall show")
	f.fail["advfirewall firewall delete"] = "The requested operation requires elevation (Run as administrator)."
	if removed, err := removeSyslogFirewallRule(); removed || err == nil || !strings.Contains(err.Error(), "requires elevation") {
		t.Errorf("not deleted: %v %v", removed, err)
	}
}

// TestSyncSyslogFirewallRule: the rule follows the configuration: syslog.listen's port and the
// gateway with syslog on, removed with it off.
func TestSyncSyslogFirewallRule(t *testing.T) {
	f := useFakeNetsh(t)
	cfg := config.Default()
	cfg.Syslog.Listen = "0.0.0.0:5514"
	msg, err := syncSyslogFirewallRule(testExe, cfg)
	if err != nil || msg != `Windows Firewall: rule "AT&T Internet Monitor syslog" lets UDP datagrams from the gateway 192.168.1.254 in to port 5514, for att-monitor.exe only.` {
		t.Errorf("enabled: %q %v", msg, err)
	}
	if len(f.calls) != 2 || !reflect.DeepEqual(f.calls[1], addArgs("5514", "192.168.1.254")) {
		t.Errorf("calls %q", f.calls)
	}

	f.calls = nil
	cfg.Syslog.Enabled = false
	if msg, err := syncSyslogFirewallRule(testExe, cfg); err != nil || !strings.Contains(msg, "removed (syslog.enabled is false)") {
		t.Errorf("disabled: %q %v", msg, err)
	}
	if !reflect.DeepEqual(f.calls, [][]string{deleteArgs}) {
		t.Errorf("calls %q", f.calls)
	}
	f.fail["advfirewall firewall"] = "No rules match the specified criteria."
	if msg, err := syncSyslogFirewallRule(testExe, cfg); err != nil || msg != "" {
		t.Errorf("disabled, no rule: %q %v", msg, err)
	}

	f.calls = nil
	cfg.Syslog.Enabled = true
	for _, mut := range []func(*config.Config){
		func(c *config.Config) { c.Gateway.Host = "gateway.local" },
		func(c *config.Config) { c.Syslog.Listen = "514" },
		func(c *config.Config) { c.Syslog.Listen = ":0" },
	} {
		c := *cfg
		mut(&c)
		if _, err := syncSyslogFirewallRule(testExe, &c); err == nil {
			t.Errorf("accepted %+v %+v", c.Gateway.Host, c.Syslog.Listen)
		}
	}
	if len(f.calls) != 0 {
		t.Errorf("netsh ran: %q", f.calls)
	}
}

func TestNetshPath(t *testing.T) {
	if got, want := netshPath(), filepath.Join(os.Getenv("SystemRoot"), "System32", "netsh.exe"); got != want {
		t.Errorf("netshPath = %q, want %q", got, want)
	}
}
