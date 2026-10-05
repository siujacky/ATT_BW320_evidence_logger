package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/http"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"attmonitor/internal/anchor"
	"attmonitor/internal/config"
	"attmonitor/internal/contracts"
	"attmonitor/internal/export"
	"attmonitor/internal/ledger"
	"attmonitor/internal/model"
	"attmonitor/internal/sysinfo"
	"attmonitor/internal/winsvc"
)

const (
	displayName = "AT&T Internet Monitor (evidence logger)"
	description = "Monitors the AT&T BGW320 gateway and Internet reachability and records tamper-evident, " +
		"time-stamped evidence (hash-chained, signed ledger). Dashboard: http://127.0.0.1:8320"
)

func isService() bool {
	ok, err := winsvc.IsService()
	return err == nil && ok
}

func newFlags(name string) (*flag.FlagSet, *string) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	data := fs.String("data", "", "data directory (default %ProgramData%\\ATTMonitor)")
	return fs, data
}

// ------------------------------------------------------------------ service / console

func cmdService(args []string) error {
	fs, data := newFlags("service")
	if err := fs.Parse(args); err != nil {
		return err
	}
	dataDir := defaultDataDir(*data)
	var extra slog.Handler
	h, closeEv, err := winsvc.NewEventLogHandler(slog.LevelWarn)
	if err == nil {
		extra = h
		defer closeEv()
	}
	return winsvc.Run(func(ctx context.Context, power <-chan string) error {
		return runMonitor(ctx, stackOptions{dataDir: dataDir, mode: "service", extraLog: extra}, power)
	})
}

func cmdRun(args []string) error {
	fs, data := newFlags("run")
	duration := fs.Duration("duration", 0, "stop gracefully after this long (testing), e.g. 3m")
	if err := fs.Parse(args); err != nil {
		return err
	}
	dataDir := defaultDataDir(*data)
	ctx, cancel := context.WithCancelCause(context.Background())
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sig
		cancel(errors.New("console interrupt"))
	}()
	if *duration > 0 {
		t := time.AfterFunc(*duration, func() { cancel(errors.New("console run duration elapsed")) })
		defer t.Stop()
	}
	fmt.Fprintf(os.Stderr, "att-monitor %s running in console mode (data: %s). Press Ctrl+C to stop.\n", version, dataDir)
	return runMonitor(ctx, stackOptions{dataDir: dataDir, mode: "console", console: true}, nil)
}

// ------------------------------------------------------------------ install / lifecycle

func requireAdmin(what string) error {
	if !winsvc.IsAdmin() {
		return fmt.Errorf("%s requires an elevated (Run as administrator) terminal", what)
	}
	return nil
}

func installDir() string {
	pf := os.Getenv("ProgramFiles")
	if pf == "" {
		pf = `C:\Program Files`
	}
	return filepath.Join(pf, "ATT Monitor")
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp := dst + ".new"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(tmp)
		return err
	}
	if err := out.Sync(); err != nil {
		out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, dst)
}

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
	dataDir := defaultDataDir(*data)
	paths := config.PathsFor(dataDir)

	src, err := os.Executable()
	if err != nil {
		return err
	}
	dstDir := installDir()
	if err := os.MkdirAll(dstDir, 0o755); err != nil {
		return err
	}
	dst := filepath.Join(dstDir, "att-monitor.exe")

	state, _ := winsvc.Status()
	upgrade := state != "" && state != "not installed"
	stoppedForUpgrade := false
	if upgrade {
		fmt.Println("Service already installed — upgrading the executable in place.")
		if state == "running" || state == "start pending" {
			if err := winsvc.Stop(60 * time.Second); err != nil {
				return fmt.Errorf("stop service for upgrade: %w", err)
			}
			stoppedForUpgrade = true
		}
	}
	// An upgrade that fails after stopping the service must not leave the evidence logger down.
	succeeded := false
	defer func() {
		if stoppedForUpgrade && !succeeded {
			if err := winsvc.Start(); err != nil {
				fmt.Fprintln(os.Stderr, "WARNING: the upgrade failed and the service could not be restarted:", err)
			} else {
				fmt.Fprintln(os.Stderr, "The upgrade failed; the previous service was restarted.")
			}
		}
	}()
	if !strings.EqualFold(filepath.Clean(src), filepath.Clean(dst)) {
		if err := copyFile(src, dst); err != nil {
			return fmt.Errorf("copy executable to %s: %w", dst, err)
		}
	}
	fmt.Println("Executable:", dst)

	// Secure (and validate) the data directory before creating the layout inside it, so a
	// mistyped --data that points at a system or profile folder is refused untouched.
	if err := winsvc.SecureDataDir(dataDir); err != nil {
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
	if *listen != "" {
		cfg.Web.Listen = *listen
	}
	if *bootstrap != "" {
		abs, err := filepath.Abs(*bootstrap)
		if err != nil {
			return err
		}
		cfg.BootstrapDir = abs
	}
	if *codeFile != "" {
		host, code, err := config.ParsePasswordFile(*codeFile)
		if err != nil {
			return err
		}
		if host != "" {
			cfg.Gateway.Host = host
		}
		if code != "" {
			if err := cfg.SetAccessCode(code); err != nil {
				return err
			}
			fmt.Println("Gateway access code stored (DPAPI-encrypted).")
		}
	}
	if err := config.Save(paths.Config, cfg); err != nil {
		return err
	}
	fmt.Println("Data directory:", dataDir)

	if !upgrade {
		if err := winsvc.Install(winsvc.InstallOptions{
			ExePath:     dst,
			Args:        []string{"service", "--data", dataDir},
			DisplayName: displayName,
			Description: description,
		}); err != nil {
			return err
		}
		fmt.Println("Service installed:", winsvc.ServiceName)
	}
	if *noStart {
		succeeded = true
		return nil
	}
	if err := winsvc.Start(); err != nil {
		return fmt.Errorf("start service: %w", err)
	}
	succeeded = true // the (new) service is running; dashboard readiness below is informational
	fmt.Print("Starting")
	for i := 0; i < 60; i++ {
		if _, ok := serviceAPI(dataDir); ok {
			fmt.Println(" — running.")
			printFingerprint(paths)
			fmt.Printf("Dashboard: http://%s\n", cfg.Web.Listen)
			return nil
		}
		fmt.Print(".")
		time.Sleep(time.Second)
	}
	fmt.Println()
	return fmt.Errorf("service started but the dashboard did not answer within 60 s; see %s", filepath.Join(paths.Logs, "service.log"))
}

func printFingerprint(paths config.Paths) {
	b, err := os.ReadFile(filepath.Join(paths.Keys, "ledger-signing.pub.txt"))
	if err == nil {
		fmt.Println("Ledger signing key (write this down / share it with whoever verifies your evidence):")
		fmt.Println(strings.TrimSpace(string(b)))
	}
}

func cmdUninstall(args []string) error {
	if err := requireAdmin("uninstall"); err != nil {
		return err
	}
	if err := winsvc.Uninstall(); err != nil {
		return err
	}
	fmt.Println("Service removed. Evidence data was NOT deleted:", config.DefaultDataDir())
	return nil
}

func cmdStart(args []string) error {
	if err := requireAdmin("start"); err != nil {
		return err
	}
	return winsvc.Start()
}

func cmdStop(args []string) error {
	if err := requireAdmin("stop"); err != nil {
		return err
	}
	return winsvc.Stop(60 * time.Second)
}

func cmdStatus(args []string) error {
	fs, data := newFlags("status")
	asJSON := fs.Bool("json", false, "print the full status JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	st, err := winsvc.Status()
	if err != nil {
		st = "unknown (" + err.Error() + ")"
	}
	fmt.Println("Service:", st)
	api, ok := serviceAPI(defaultDataDir(*data))
	if !ok {
		fmt.Println("Dashboard: not reachable")
		return nil
	}
	var s model.Status
	if err := api.do(background(), http.MethodGet, "/api/status", nil, &s); err != nil {
		return err
	}
	if *asJSON {
		return printJSON(s)
	}
	fmt.Printf("Dashboard: %s\n", api.base)
	fmt.Printf("State:     %s %s (attribution: %s) since %s\n", s.Verdict.State, s.Verdict.Cause, s.Verdict.Attribution, s.Since)
	for _, r := range s.Verdict.Reasons {
		fmt.Println("  -", r)
	}
	if s.ActiveIncident != nil {
		fmt.Printf("Incident:  %s opened %s (%s %s)\n", s.ActiveIncident.ID, s.ActiveIncident.Opened, s.ActiveIncident.State, s.ActiveIncident.Cause)
	}
	for _, c := range s.Conditions {
		fmt.Printf("Condition: [%s] %s\n", c.Severity, c.Message)
	}
	for _, w := range s.Stats {
		fmt.Printf("Last %-4s  availability %s  incidents %d  AT&T-attributed time without Internet %s  degraded %s  coverage %s\n",
			w.Window, pctFloor(w.AvailabilityPct), w.Incidents, (time.Duration(w.ProviderOutageSec) * time.Second).String(),
			(time.Duration(w.DegradedSec) * time.Second).String(), pctFloor(w.CoveragePct))
	}
	fmt.Printf("Ledger:    head #%d %s…  last anchor %s  key %s\n", s.Ledger.HeadSeq, short(s.Ledger.HeadHash, 12), s.Ledger.LastAnchorTime, short(s.Ledger.Fingerprint, 16))
	return nil
}

func short(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func printJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// ------------------------------------------------------------------ access code / gateway

func cmdSetAccessCode(args []string) error {
	fs, data := newFlags("set-access-code")
	file := fs.String("file", "", "file with a password:<access code> line (and optionally ip:<host>)")
	stdin := fs.Bool("stdin", false, "read the access code from standard input")
	if err := fs.Parse(args); err != nil {
		return err
	}
	dataDir := defaultDataDir(*data)
	paths := config.PathsFor(dataDir)
	var host, code string
	switch {
	case *file != "":
		var err error
		host, code, err = config.ParsePasswordFile(*file)
		if err != nil {
			return err
		}
	case *stdin:
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return err
		}
		code = strings.TrimSpace(line)
	default:
		return errors.New("use --file PATH or --stdin")
	}
	if code == "" {
		return errors.New("no access code found")
	}
	cfg, err := config.LoadOrCreate(paths.Config)
	if err != nil {
		return err
	}
	if host != "" {
		cfg.Gateway.Host = host
	}
	if err := cfg.SetAccessCode(code); err != nil {
		return err
	}
	if err := config.Save(paths.Config, cfg); err != nil {
		return fmt.Errorf("%w (an elevated terminal is required for %s)", err, paths.Config)
	}
	fmt.Println("Access code stored (DPAPI machine scope) in", paths.Config)
	if st, _ := winsvc.Status(); st == "running" {
		fmt.Println("Restarting the service so it picks up the new access code…")
		if err := winsvc.Stop(60 * time.Second); err != nil {
			return err
		}
		return winsvc.Start()
	}
	return nil
}

func actor() string {
	if u, err := user.Current(); err == nil {
		return "cli user " + u.Username
	}
	return "cli"
}

func cmdGateway(args []string) error {
	if len(args) > 0 && args[0] == "trust-cert" {
		return cmdTrustCert(args[1:])
	}
	if len(args) == 0 || args[0] != "notification" {
		return errors.New("usage: att-monitor gateway notification [status|on|off]\n       att-monitor gateway trust-cert")
	}
	args = args[1:]
	action := "status"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		action, args = strings.ToLower(args[0]), args[1:]
	}
	fs, data := newFlags("gateway notification")
	if err := fs.Parse(args); err != nil {
		return err
	}
	dataDir := defaultDataDir(*data)
	ctx := background()
	if api, ok := serviceAPI(dataDir); ok {
		switch action {
		case "status":
			var s model.Status
			if err := api.do(ctx, http.MethodGet, "/api/status", nil, &s); err != nil {
				return err
			}
			if s.Notification == nil {
				fmt.Println("Broadband Status Notification: not checked yet (needs the access code; checked at startup and daily)")
				return nil
			}
			printNotification(s.Notification.Enabled, s.Notification.CheckedAt, s.Notification.Err)
			return nil
		case "on", "off":
			var cc model.ConfigChange
			if err := api.do(ctx, http.MethodPost, "/api/gateway/notification", map[string]any{"enabled": action == "on"}, &cc); err != nil {
				return err
			}
			fmt.Printf("Gateway setting %s: %s → %s (%s)\n", cc.What, cc.Before, cc.After, cc.Result)
			return nil
		}
		return fmt.Errorf("unknown action %q", action)
	}
	s, err := openStack(stackOptions{dataDir: dataDir, mode: "cli"})
	if err != nil {
		return err
	}
	defer s.close()
	if err := strictGatewayTLS(s); err != nil {
		return err
	}
	switch action {
	case "status":
		enabled, _, err := s.gw.Notification(ctx)
		if err != nil {
			return err
		}
		printNotification(enabled, now().UTC().Format(time.RFC3339), "")
		return nil
	case "on", "off":
		cc, err := s.mon.SetGatewayNotification(ctx, action == "on", actor())
		if err != nil {
			return err
		}
		fmt.Printf("Gateway setting %s: %s → %s (%s)\n", cc.What, cc.Before, cc.After, cc.Result)
		return nil
	}
	return fmt.Errorf("unknown action %q", action)
}

// strictGatewayTLS prepares a CLI-only stack for authenticated gateway requests (the service
// is not running). The login sends MD5(access code + nonce), so it must only ever go to the
// certificate the operator trusts: refuse while a changed certificate is pending or before any
// pin exists, and replace the monitor's status-read observer (which accepts a changed
// certificate for evidence continuity) with one that rejects every certificate but the pin.
func strictGatewayTLS(s *stack) error {
	if p := s.cfg.Gateway.PendingCertSHA256; p != "" {
		return fmt.Errorf("the gateway presented a changed TLS certificate (%s) that has not been confirmed; "+
			"run `att-monitor gateway trust-cert` first if AT&T updated the gateway", p)
	}
	pinned := strings.ToLower(strings.TrimSpace(s.cfg.Gateway.PinnedCertSHA256))
	if pinned == "" {
		return errors.New("the gateway certificate is not pinned yet: start the service once (it pins the certificate " +
			"on first contact and records it in the ledger) before using authenticated gateway commands")
	}
	s.gw.SetCertObserver(func(previous, observed string) bool {
		return strings.EqualFold(strings.TrimSpace(observed), pinned)
	})
	return nil
}

// cmdTrustCert confirms a changed gateway TLS certificate (DESIGN §2 certificate policy).
func cmdTrustCert(args []string) error {
	fs, data := newFlags("gateway trust-cert")
	if err := fs.Parse(args); err != nil {
		return err
	}
	dataDir := defaultDataDir(*data)
	pending := ""
	cfg, err := config.Load(config.PathsFor(dataDir).Config)
	if err == nil {
		if cfg.Gateway.PendingCertSHA256 == "" {
			fmt.Println("No changed gateway certificate is pending; nothing to confirm.")
			return nil
		}
		pending = cfg.Gateway.PendingCertSHA256
		fmt.Printf("Trusted certificate: %s\nPending certificate: %s\n", cfg.Gateway.PinnedCertSHA256, pending)
	}
	fmt.Println("Only confirm if AT&T updated your gateway (e.g. a firmware update) or you replaced it;")
	fmt.Println("otherwise another device may be impersonating your gateway.")
	fmt.Print("Type YES to trust the new certificate: ")
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	if strings.TrimSpace(line) != "YES" {
		return errors.New("not confirmed")
	}
	ctx := background()
	var cc model.ConfigChange
	if api, ok := serviceAPI(dataDir); ok {
		// Send the fingerprint the user just reviewed: the service refuses if a different
		// certificate is pending by the time the request arrives.
		body := map[string]any{"client": "cli"}
		if pending != "" {
			body["sha256"] = pending
		}
		if err := api.do(ctx, http.MethodPost, "/api/gateway/trust-cert", body, &cc); err != nil {
			return err
		}
	} else {
		s, err := openStack(stackOptions{dataDir: dataDir, mode: "cli"})
		if err != nil {
			return err
		}
		defer s.close()
		if cc, err = s.mon.TrustCert(ctx, actor(), pending); err != nil {
			return err
		}
	}
	fmt.Printf("Gateway certificate trusted: %s → %s (%s)\n", cc.Before, cc.After, cc.Result)
	return nil
}

func printNotification(enabled bool, at, errText string) {
	state := "OFF (the gateway will NOT redirect browsers when the WAN is down)"
	if enabled {
		state = "ON (the gateway redirects browsers to its own page when the WAN is down)"
	}
	fmt.Printf("Broadband Status Notification: %s — checked %s\n", state, at)
	if errText != "" {
		fmt.Println("Last check error:", errText)
	}
}

// ------------------------------------------------------------------ verification

func tokenVerifier() contracts.TokenVerifier {
	return anchor.New(anchor.Options{URLs: config.Default().Anchoring.TSAURLs, UserAgent: userAgent()})
}

func cmdVerify(args []string) error {
	fs, data := newFlags("verify")
	asJSON := fs.Bool("json", false, "print the full report as JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	dataDir := defaultDataDir(*data)
	fast := config.Default().Probes.FastInterval.Duration
	if c, err := config.Load(config.PathsFor(dataDir).Config); err == nil {
		fast = c.Probes.FastInterval.Duration
	}
	st, err := ledger.Open(ledger.Options{
		Paths:         config.PathsFor(dataDir),
		ReadOnly:      true,
		TokenVerifier: tokenVerifier(),
		FastInterval:  fast,
		Logger:        slog.New(slog.DiscardHandler),
	})
	if err != nil {
		return err
	}
	defer st.Close()
	rep, err := st.Verify(background())
	if err != nil {
		return err
	}
	return reportVerify(rep, *asJSON)
}

func cmdVerifyBundle(args []string) error {
	fs := flag.NewFlagSet("verify-bundle", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "print the full report as JSON")
	expect := fs.String("expect-fingerprint", "", "ledger key fingerprint received independently from the evidence owner")
	if err := fs.Parse(reorderArgs(args, "json")); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: att-monitor verify-bundle FILE.zip")
	}
	path := fs.Arg(0)
	// VerifyManifest also re-derives the report; a report mismatch is reported on its own REPORT
	// line below and does not stop the ledger verification.
	if err := export.VerifyManifest(path); err != nil && !errors.Is(err, export.ErrReportMismatch) {
		fmt.Println("MANIFEST: FAILED —", err)
		return exitCode(2)
	}
	fmt.Println("MANIFEST: OK (every file matches MANIFEST.sha256)")
	reportFailed := false
	rc, rerr := export.VerifyReport(path)
	if rerr == nil && rc != nil && rc.Verified {
		fmt.Println("REPORT:   OK (REPORT.html, report.json and README.txt are exactly what the bundle's own records give)")
	} else {
		reportFailed = true
		fmt.Println("REPORT:   FAILED —", rerr)
		if rc != nil {
			for _, d := range rc.Differences {
				fmt.Println("          differs:", d)
			}
		}
	}
	if rc != nil && len(rc.Stated) > 0 {
		fmt.Println("          taken as stated by report.json (cannot come from records):", strings.Join(rc.Stated, "; "))
	}
	b, err := export.OpenBundle(path)
	if err != nil {
		return err
	}
	defer b.Close()
	rep, err := ledger.VerifyReader(background(), b, ledger.VerifyOptions{
		TokenVerifier:        tokenVerifier(),
		FastInterval:         config.Default().Probes.FastInterval.Duration,
		CheckBlobs:           true,
		AllowOmittedSegments: true,
		ExpectFingerprint:    strings.ToLower(strings.ReplaceAll(strings.TrimSpace(*expect), " ", "")),
	})
	if err != nil {
		return err
	}
	if sum, err := fileSHA256(path); err == nil {
		fmt.Println("Bundle SHA-256:", sum)
	}
	err = reportVerify(rep, *asJSON)
	if err == nil && reportFailed {
		return exitCode(2)
	}
	return err
}

// pctFloor formats a percentage truncated (never rounded up) to 3 decimals, so an availability
// below 100 % can never print as 100.000 %.
func pctFloor(v float64) string {
	if v >= 100 {
		return "100%"
	}
	if v > 0 && v < 0.001 {
		return "< 0.001%"
	}
	return fmt.Sprintf("%.3f%%", math.Floor(v*1000)/1000)
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func reportVerify(rep model.VerifyReport, asJSON bool) error {
	if asJSON {
		if err := printJSON(rep); err != nil {
			return err
		}
	} else {
		verdict := "PASSED"
		if !rep.OK {
			verdict = "FAILED"
		}
		fmt.Printf("Verification %s — %d records, %s … %s\n", verdict, rep.Records, rep.FirstTS, rep.LastTS)
		fmt.Printf("Head hash: %s\nKey fingerprint: %s\n", rep.HeadHash, rep.Fingerprint)
		fmt.Printf("Blobs checked: %d   Anchors: %d   Unanchored tail: %d records   Clock jumps: %d\n",
			rep.BlobsChecked, len(rep.Anchors), rep.UnanchoredTail, rep.ClockJumps)
		for _, a := range rep.Anchors {
			ok := "ok"
			if !a.OK {
				ok = "INVALID " + a.Detail
			}
			chain := ""
			if a.OK && !a.ChainOK {
				chain = " (TSA certificate not chained to a local root)"
			}
			fmt.Printf("  anchor #%d %s covers ≤#%d at %s — %s%s\n", a.Seq, a.TSA, a.HeadSeq, a.GenTime, ok, chain)
		}
		for _, g := range rep.Gaps {
			fmt.Printf("  gap %s → %s (%ds): %s\n", g.From, g.To, g.Seconds, g.Explanation)
		}
		for _, n := range rep.Notes {
			fmt.Println("  note:", n)
		}
		for _, f := range rep.Failures {
			fmt.Printf("  FAIL seq %d (%s line %d): %s — %s\n", f.Seq, f.Segment, f.Line, f.Problem, f.Detail)
		}
		if rep.FailuresTotal > len(rep.Failures) {
			fmt.Printf("  … %d more failures\n", rep.FailuresTotal-len(rep.Failures))
		}
	}
	if !rep.OK {
		return exitCode(2)
	}
	return nil
}

// ------------------------------------------------------------------ export / notes / anchor

// parseWhen accepts YYYY-MM-DD, YYYY-MM-DDTHH:MM (local) or RFC 3339.
func parseWhen(s string) (time.Time, error) {
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, nil
		}
	}
	for _, layout := range []string{"2006-01-02T15:04:05", "2006-01-02T15:04", "2006-01-02 15:04", "2006-01-02"} {
		if t, err := time.ParseInLocation(layout, s, time.Local); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("cannot parse time %q (use YYYY-MM-DD, YYYY-MM-DDTHH:MM or RFC 3339)", s)
}

// isDateOnly reports whether s is a plain YYYY-MM-DD date.
func isDateOnly(s string) bool {
	_, err := time.Parse("2006-01-02", strings.TrimSpace(s))
	return err == nil
}

func cmdExport(args []string) error {
	fs, data := newFlags("export")
	from := fs.String("from", "", "start time")
	to := fs.String("to", "", "end time (default now)")
	incident := fs.String("incident", "", "incident id (overrides --from/--to)")
	preparedBy := fs.String("prepared-by", "", "name recorded in the custody log")
	notes := fs.String("notes", "", "notes recorded in the custody log")
	out := fs.String("out", "", "also copy the bundle to this folder")
	if err := fs.Parse(args); err != nil {
		return err
	}
	var req contracts.ExportRequest
	req.IncidentID, req.PreparedBy, req.Notes, req.Requester = *incident, *preparedBy, *notes, actor()
	if req.IncidentID == "" {
		if *from == "" {
			return errors.New("--from is required (or --incident)")
		}
		var err error
		if req.From, err = parseWhen(*from); err != nil {
			return err
		}
		req.To = now()
		if *to != "" {
			if req.To, err = parseWhen(*to); err != nil {
				return err
			}
			// A date-only --to means "through that day": include the whole day.
			if isDateOnly(*to) {
				req.To = req.To.AddDate(0, 0, 1)
			}
		}
	}
	dataDir := defaultDataDir(*data)
	ctx := background()
	var info contracts.ExportInfo
	var path string
	if api, ok := serviceAPI(dataDir); ok {
		body := map[string]any{"incident_id": req.IncidentID, "prepared_by": req.PreparedBy, "notes": req.Notes}
		if !req.From.IsZero() {
			body["from"] = req.From.UTC().Format(time.RFC3339)
			body["to"] = req.To.UTC().Format(time.RFC3339)
		}
		if err := api.do(ctx, http.MethodPost, "/api/exports", body, &info); err != nil {
			return err
		}
		path = filepath.Join(config.PathsFor(dataDir).Exports, info.FileName)
		if *out != "" {
			p, err := api.download(ctx, "/api/exports/"+info.FileName, *out, info.FileName)
			if err != nil {
				return err
			}
			path = p
		}
	} else {
		s, err := openStack(stackOptions{dataDir: dataDir, mode: "cli"})
		if err != nil {
			return err
		}
		defer s.close()
		info, err = s.exp.Build(ctx, req)
		if err != nil {
			return err
		}
		path = info.Path
		if *out != "" {
			if err := os.MkdirAll(*out, 0o755); err != nil {
				return err
			}
			dst := filepath.Join(*out, info.FileName)
			if err := copyFile(info.Path, dst); err != nil {
				return err
			}
			path = dst
		}
	}
	fmt.Println("Evidence bundle:", path)
	fmt.Println("SHA-256:        ", info.SHA256)
	if info.CustodySeq != 0 {
		fmt.Printf("Custody record:  ledger #%d\n", info.CustodySeq)
	}
	return nil
}

func cmdNote(args []string) error {
	fs, data := newFlags("note")
	author := fs.String("author", "", "author name")
	if err := fs.Parse(reorderArgs(args)); err != nil {
		return err
	}
	text := strings.TrimSpace(strings.Join(fs.Args(), " "))
	if text == "" {
		return errors.New(`usage: att-monitor note "text" [--author NAME]`)
	}
	dataDir := defaultDataDir(*data)
	ctx := background()
	var ref model.Ref
	if api, ok := serviceAPI(dataDir); ok {
		if err := api.do(ctx, http.MethodPost, "/api/notes", map[string]string{"text": text, "author": *author}, &ref); err != nil {
			return err
		}
	} else {
		s, err := openStack(stackOptions{dataDir: dataDir, mode: "cli"})
		if err != nil {
			return err
		}
		defer s.close()
		if ref, err = s.mon.Note(ctx, text, *author, "cli"); err != nil {
			return err
		}
	}
	fmt.Printf("Note recorded as ledger #%d (%s)\n", ref.Seq, ref.TS)
	return nil
}

// reorderArgs moves flags that follow positional words to the front, so `note "text" --author X`
// and `verify-bundle FILE --json` work with the standard flag package. Flags listed in
// boolFlags take no value.
func reorderArgs(args []string, boolFlags ...string) []string {
	isBool := func(a string) bool {
		name := strings.TrimLeft(a, "-")
		for _, b := range boolFlags {
			if name == b {
				return true
			}
		}
		return false
	}
	var flags, words []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			words = append(words, args[i+1:]...)
			break
		}
		if strings.HasPrefix(a, "-") && len(a) > 1 {
			flags = append(flags, a)
			if !strings.Contains(a, "=") && !isBool(a) && i+1 < len(args) {
				flags = append(flags, args[i+1])
				i++
			}
			continue
		}
		words = append(words, a)
	}
	return append(flags, words...)
}

func cmdAnchor(args []string) error {
	fs, data := newFlags("anchor")
	if err := fs.Parse(args); err != nil {
		return err
	}
	dataDir := defaultDataDir(*data)
	ctx := background()
	var anchors []model.Anchor
	if api, ok := serviceAPI(dataDir); ok {
		if err := api.do(ctx, http.MethodPost, "/api/anchor", map[string]string{}, &anchors); err != nil {
			return err
		}
	} else {
		s, err := openStack(stackOptions{dataDir: dataDir, mode: "cli"})
		if err != nil {
			return err
		}
		defer s.close()
		if anchors, err = s.mon.AnchorNow(ctx, "manual"); err != nil {
			return err
		}
	}
	if len(anchors) == 0 {
		return errors.New("no time-stamp authority answered (offline?)")
	}
	for _, a := range anchors {
		fmt.Printf("Anchored ledger #%d (%s…) at %s by %s\n", a.HeadSeq, short(a.HeadHash, 12), a.GenTime, a.TSAURL)
	}
	return nil
}

func cmdVersion(args []string) error {
	sw := sysinfo.Software(version, commit, "")
	fmt.Printf("att-monitor %s", version)
	if commit != "" {
		fmt.Printf(" (%s)", commit)
	}
	fmt.Printf("\n%s %s/%s\nexe: %s\nsha256: %s\n", runtime.Version(), runtime.GOOS, runtime.GOARCH, sw.ExePath, sw.ExeSHA256)
	return nil
}
