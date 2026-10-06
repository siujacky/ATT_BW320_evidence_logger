package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"attmonitor/internal/config"
)

// The Windows Firewall rule of the syslog receiver (docs/DESIGN.md §18): the gateway sends its
// syslog messages to this computer as UDP datagrams, which Windows Firewall drops unless a rule
// lets them in. install adds one inbound rule, limited to the gateway's address, the receiver's
// UDP port and the installed program, and uninstall removes it. Both run netsh with every
// argument passed on its own (no shell).

// syslogFirewallRule is the name of the rule in Windows Firewall.
const syslogFirewallRule = "AT&T Internet Monitor syslog"

// netshTimeout bounds one netsh command.
const netshTimeout = 30 * time.Second

// runNetsh runs netsh with args and returns what it printed. Tests replace it and record the
// arguments: they never change the firewall.
var runNetsh = func(args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), netshTimeout)
	defer cancel()
	return exec.CommandContext(ctx, netshPath(), args...).CombinedOutput()
}

// netshPath is netsh.exe in the system folder rather than whatever a search of PATH finds first
// (install runs as administrator).
func netshPath() string {
	if root := os.Getenv("SystemRoot"); root != "" {
		return filepath.Join(root, "System32", "netsh.exe")
	}
	return "netsh"
}

// ensureSyslogFirewallRule makes the rule let UDP datagrams from gateway to port in, for the
// program exe only. A rule of the same name is replaced, so running install again brings the
// address, port and program up to date.
func ensureSyslogFirewallRule(exe string, gateway netip.Addr, port int) error {
	switch {
	case !gateway.IsValid():
		return errors.New("no gateway address")
	case port < 1 || port > 65535:
		return fmt.Errorf("%d is not a UDP port", port)
	case !filepath.IsAbs(exe):
		return fmt.Errorf("the program %q is not given by its full path", exe)
	}
	// An earlier install may have added the rule, or not: either way it is replaced.
	_, _ = runNetsh("advfirewall", "firewall", "delete", "rule", "name="+syslogFirewallRule)
	out, err := runNetsh("advfirewall", "firewall", "add", "rule",
		"name="+syslogFirewallRule,
		"dir=in", "action=allow", "protocol=UDP",
		"localport="+strconv.Itoa(port),
		"remoteip="+gateway.Unmap().String(),
		"program="+exe,
		"profile=any", "enable=yes",
		"description=Lets the AT&T gateway's syslog messages reach the AT&T Internet Monitor. Added by att-monitor install, removed by uninstall.")
	if err != nil {
		return netshError("add", out, err)
	}
	return nil
}

// removeSyslogFirewallRule deletes the rule and reports whether there was one; no rule is no
// error.
func removeSyslogFirewallRule() (bool, error) {
	out, err := runNetsh("advfirewall", "firewall", "delete", "rule", "name="+syslogFirewallRule)
	if err == nil {
		return true, nil
	}
	// netsh fails alike when no rule has the name and when it cannot delete one, and says why
	// in the system's language: the rule is taken as absent when it cannot be shown either.
	if _, serr := runNetsh("advfirewall", "firewall", "show", "rule", "name="+syslogFirewallRule); serr != nil {
		return false, nil
	}
	return false, netshError("delete", out, err)
}

// netshError words a failed netsh command with what netsh printed.
func netshError(op string, out []byte, err error) error {
	if text := strings.Join(strings.Fields(string(out)), " "); text != "" {
		return fmt.Errorf("netsh could not %s the rule %q: %w (%s)", op, syslogFirewallRule, err, text)
	}
	return fmt.Errorf("netsh could not %s the rule %q: %w", op, syslogFirewallRule, err)
}

// syncSyslogFirewallRule makes Windows Firewall match the syslog configuration: with
// syslog.enabled the rule lets the gateway's datagrams in to the receiver's port (syslog.listen)
// for exe; otherwise a rule an earlier install added is removed. It returns what it did, in
// words ("" when there was nothing to do).
func syncSyslogFirewallRule(exe string, cfg *config.Config) (string, error) {
	if !cfg.Syslog.Enabled {
		removed, err := removeSyslogFirewallRule()
		if err != nil || !removed {
			return "", err
		}
		return fmt.Sprintf("Windows Firewall: rule %q removed (syslog.enabled is false).", syslogFirewallRule), nil
	}
	gw, err := netip.ParseAddr(cfg.Gateway.Host)
	if err != nil {
		return "", fmt.Errorf("gateway.host %q is not an IP address", cfg.Gateway.Host)
	}
	port, err := listenPort(cfg.Syslog.Listen)
	if err != nil {
		return "", err
	}
	if err := ensureSyslogFirewallRule(exe, gw, port); err != nil {
		return "", err
	}
	return fmt.Sprintf("Windows Firewall: rule %q lets UDP datagrams from the gateway %s in to port %d, for %s only.",
		syslogFirewallRule, gw.Unmap(), port, filepath.Base(exe)), nil
}

// listenPort returns the port of a syslog.listen address (":514" gives 514).
func listenPort(listen string) (int, error) {
	_, p, err := net.SplitHostPort(listen)
	if err != nil {
		return 0, fmt.Errorf("syslog.listen %q: %w", listen, err)
	}
	n, err := strconv.Atoi(p)
	if err != nil || n < 1 || n > 65535 {
		return 0, fmt.Errorf("syslog.listen %q: the port must be 1-65535", listen)
	}
	return n, nil
}
