package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"attmonitor/internal/config"
	"attmonitor/internal/winsvc"
)

// repoURL is where the program comes from (shown in Settings > Apps).
const repoURL = "https://github.com/siujacky/ATT_BW320_evidence_logger"

// installOptions are the inputs of installService.
type installOptions struct {
	DataDir   string
	Listen    string // dashboard address; "" keeps the configured one
	Bootstrap string // folder of setup-time evidence to import at genesis; "" none
	Host      string // gateway address; "" keeps the configured one
	Code      string // gateway Device Access Code; "" keeps the stored one (if any)
	NoStart   bool
	Out       io.Writer
}

// cmdInstall installs or upgrades the service (elevated). `att-monitor setup` is the guided
// version that asks for the Device Access Code.
func cmdInstall(args []string) error {
	fs, data := newFlags("install")
	listen := fs.String("listen", "", "dashboard listen address (loopback only), e.g. 127.0.0.1:8320")
	codeFile := fs.String("access-code-file", "", "file with lines ip:<host> and password:<device access code>")
	bootstrap := fs.String("bootstrap", "", "folder of evidence collected before installation (imported at genesis)")
	noStart := fs.Bool("no-start", false, "do not start the service after installing")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := requireAdmin("install"); err != nil {
		return err
	}
	o := installOptions{DataDir: defaultDataDir(*data), Listen: *listen, NoStart: *noStart, Out: os.Stdout}
	if *bootstrap != "" {
		abs, err := filepath.Abs(*bootstrap)
		if err != nil {
			return err
		}
		o.Bootstrap = abs
	}
	if *codeFile != "" {
		host, code, err := config.ParsePasswordFile(*codeFile)
		if err != nil {
			return err
		}
		o.Host, o.Code = host, code
	}
	return installService(o)
}

// The service control and the program copy of installService, replaceable so that a test of what
// it refuses can never reach the real service or Program Files.
var (
	installStatus = winsvc.Status
	installStop   = winsvc.Stop
	installStart  = winsvc.Start
	installCopy   = copyFile
	installTarget = installDir
)

// installService copies the program to Program Files, prepares and secures the data
// directory, stores the access code, sets up the Windows Firewall rule of the syslog receiver,
// creates (or upgrades) the service, starts it and waits for the dashboard. An upgrade that fails
// after stopping the service restarts the previous one.
func installService(o installOptions) error {
	out := o.Out
	if out == nil {
		out = io.Discard
	}
	// Before anything changes: a data directory that SecureDataDir would refuse below - a mistyped
	// --data, or one laid out by a newer version whose folders this one does not know - leaves the
	// running service and the installed program as they are, instead of a refusal after the
	// program was replaced (and the service restarted with it).
	if err := winsvc.CheckDataDir(o.DataDir); err != nil {
		return fmt.Errorf("data directory: %w (nothing was changed)", err)
	}
	paths := config.PathsFor(o.DataDir)
	src, err := os.Executable()
	if err != nil {
		return err
	}
	dstDir := installTarget()
	if err := os.MkdirAll(dstDir, 0o755); err != nil {
		return err
	}
	dst := filepath.Join(dstDir, "att-monitor.exe")

	state, _ := installStatus()
	upgrade := state != "" && state != winsvc.StatusNotInstalled
	stoppedForUpgrade := false
	if upgrade {
		fmt.Fprintln(out, "Service already installed — upgrading the executable in place.")
		if state == "running" || state == "start pending" {
			if err := installStop(60 * time.Second); err != nil {
				return fmt.Errorf("stop service for upgrade: %w", err)
			}
			stoppedForUpgrade = true
		}
	}
	// An upgrade that fails after stopping the service must not leave the evidence logger down.
	succeeded := false
	defer func() {
		if stoppedForUpgrade && !succeeded {
			if err := installStart(); err != nil {
				fmt.Fprintln(out, "WARNING: the upgrade failed and the service could not be restarted:", err)
			} else {
				fmt.Fprintln(out, "The upgrade failed; the previous service was restarted.")
			}
		}
	}()
	if !strings.EqualFold(filepath.Clean(src), filepath.Clean(dst)) {
		if err := installCopy(src, dst); err != nil {
			return fmt.Errorf("copy executable to %s: %w", dst, err)
		}
	}
	fmt.Fprintln(out, "Executable:", dst)

	// Secure (and validate) the data directory before creating the layout inside it, so a
	// mistyped --data that points at a system or profile folder is refused untouched.
	if err := winsvc.SecureDataDir(o.DataDir); err != nil {
		return fmt.Errorf("secure data directory: %w", err)
	}
	if err := paths.MkdirAll(); err != nil {
		return err
	}
	// keys\ holds the ledger signing key and the gateway access code: SYSTEM + Administrators only.
	if err := winsvc.SecurePrivateDir(paths.Keys); err != nil {
		return fmt.Errorf("secure keys directory: %w", err)
	}
	cfg, err := config.LoadOrCreate(paths.Config)
	if err != nil {
		return err
	}
	if o.Listen != "" {
		cfg.Web.Listen = o.Listen
	}
	if o.Bootstrap != "" {
		cfg.BootstrapDir = o.Bootstrap
	}
	if o.Host != "" {
		cfg.Gateway.Host = o.Host
	}
	if o.Code != "" {
		if err := cfg.SetAccessCode(o.Code); err != nil {
			return err
		}
		fmt.Fprintln(out, "Gateway access code stored (DPAPI-encrypted).")
	}
	if err := config.Save(paths.Config, cfg); err != nil {
		return err
	}
	fmt.Fprintln(out, "Data directory:", o.DataDir)
	// Windows Firewall lets the gateway's syslog datagrams in only with a rule (best effort: the
	// monitor works without them).
	if msg, err := syncSyslogFirewallRule(dst, cfg); err != nil {
		fmt.Fprintln(out, "Note: could not set up the Windows Firewall rule for the gateway's syslog messages:", err)
	} else if msg != "" {
		fmt.Fprintln(out, msg)
	}

	if !upgrade {
		if err := winsvc.Install(winsvc.InstallOptions{
			ExePath:     dst,
			Args:        []string{"service", "--data", o.DataDir},
			DisplayName: displayName,
			Description: description,
		}); err != nil {
			return err
		}
		fmt.Fprintln(out, "Service installed:", winsvc.ServiceName)
	}
	// Settings > Apps and the Start menu: conveniences, so a failure is only reported.
	dashboard := "http://" + cfg.Web.Listen + "/"
	if err := registerApp(dst, dashboard); err != nil {
		fmt.Fprintln(out, "Note: could not add the program to Settings > Apps:", err)
	}
	if err := writeStartMenuShortcut(dashboard); err != nil {
		fmt.Fprintln(out, "Note: could not add the Start menu shortcut:", err)
	}
	if o.NoStart {
		succeeded = true
		return nil
	}
	if err := installStart(); err != nil {
		return fmt.Errorf("start service: %w", err)
	}
	succeeded = true // the (new) service is running; dashboard readiness below is informational
	fmt.Fprint(out, "Starting")
	for i := 0; i < 60; i++ {
		if _, ok := serviceAPI(o.DataDir); ok {
			fmt.Fprintln(out, " — running.")
			printFingerprint(out, paths)
			fmt.Fprintf(out, "Dashboard: %s\n", dashboard)
			return nil
		}
		fmt.Fprint(out, ".")
		time.Sleep(time.Second)
	}
	fmt.Fprintln(out)
	return fmt.Errorf("service started but the dashboard did not answer within 60 s; see %s", filepath.Join(paths.Logs, "service.log"))
}

func printFingerprint(out io.Writer, paths config.Paths) {
	b, err := os.ReadFile(filepath.Join(paths.Keys, "ledger-signing.pub.txt"))
	if err == nil {
		fmt.Fprintln(out, "Ledger signing key (write this down / share it with whoever verifies your evidence):")
		fmt.Fprintln(out, strings.TrimSpace(string(b)))
	}
}

// cmdUninstall removes the service, the program, its Start menu shortcut, its Settings > Apps
// entry and the Windows Firewall rule of the syslog receiver. The evidence in the data directory
// is never touched. With --interactive (the command Settings > Apps runs) it asks for
// confirmation and for administrator rights itself.
func cmdUninstall(args []string) error {
	fs := flag.NewFlagSet("uninstall", flag.ContinueOnError)
	interactive := fs.Bool("interactive", false, "ask for confirmation and administrator rights (Settings > Apps)")
	elevated := fs.Bool("elevated", false, "internal: started by --interactive with administrator rights")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *interactive && !*elevated && !winsvc.IsAdmin() {
		// Settings > Apps starts uninstallers without administrator rights.
		code, err := runElevated([]string{"uninstall", "--interactive", "--elevated"})
		switch {
		case errors.Is(err, errElevationCancelled):
			fmt.Println("Uninstalling needs administrator permission; nothing was changed.")
			pauseIfOwnWindow()
			return exitCode(1)
		case err != nil:
			return err
		case code != 0:
			return exitCode(code)
		}
		return nil
	}
	if err := requireAdmin("uninstall"); err != nil {
		return err
	}
	if *interactive {
		fmt.Println("AT&T Internet Monitor — uninstall")
		fmt.Println()
		fmt.Printf("This removes the monitoring service and the program. Your evidence in %s is kept.\n", config.DefaultDataDir())
		if !askYesNo(stdinReader(), os.Stdout, "Remove the AT&T Internet Monitor?", false) {
			fmt.Println("Nothing was changed.")
			pauseFor(3 * time.Second)
			return nil
		}
	}
	err := winsvc.Uninstall()
	switch {
	case err == nil:
		fmt.Println("Service removed.")
	case errors.Is(err, winsvc.ErrNotInstalled):
		fmt.Println("The service was not installed.")
	default:
		if *interactive {
			fmt.Println("Could not remove the service:", err)
			pauseIfOwnWindow()
		}
		return err
	}
	switch removed, err := removeSyslogFirewallRule(); {
	case err != nil:
		fmt.Println("Note: could not remove the Windows Firewall rule for the gateway's syslog messages:", err)
	case removed:
		fmt.Printf("Windows Firewall rule %q removed.\n", syslogFirewallRule)
	}
	if err := unregisterApp(); err != nil {
		fmt.Println("Note: could not remove the Settings > Apps entry:", err)
	}
	if err := removeStartMenuShortcut(); err != nil {
		fmt.Println("Note: could not remove the Start menu shortcut:", err)
	}
	removeProgramFiles(os.Stdout)
	fmt.Println("Evidence data was NOT deleted:", config.DefaultDataDir())
	if *interactive {
		pauseFor(5 * time.Second)
	}
	return nil
}
