package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"attmonitor/internal/config"
	"attmonitor/internal/contracts"
	"attmonitor/internal/gateway"
	"attmonitor/internal/ledger"
	"attmonitor/internal/model"
	"attmonitor/internal/winsvc"
)

// cmdSetup is the guided installer: what a double-click on att-monitor.exe runs, and
// `att-monitor setup`. It asks for one thing - the Device Access Code printed on the gateway's
// label - checks it with the gateway and installs (or updates) the service:
//
//  1. Without administrator rights it starts itself again with them (Windows' UAC prompt), in a
//     window of its own, and waits.
//  2. With them it looks for the gateway, asks for the code (typing hidden), checks it with a
//     read-only login - the gateway client allows one attempt per minute and none after three
//     rejections within an hour, so a wrong code can never lock the gateway - and installs or
//     updates the service. An update keeps the evidence, the settings and the stored code
//     unless a new one is typed.
//  3. Back without administrator rights it shows the evidence key and opens the dashboard in
//     the user's browser (never in a browser running as administrator).
func cmdSetup(args []string) error {
	fs, data := newFlags("setup")
	elevated := fs.Bool("elevated", false, "internal: the administrator part of setup, started by setup itself")
	if err := fs.Parse(args); err != nil {
		return err
	}
	w := newWizard()
	err := w.run(background(), setupOptions{dataDir: defaultDataDir(*data), dataFlag: *data, elevatedChild: *elevated})
	if err != nil {
		var ec exitCode
		if !errors.As(err, &ec) {
			fmt.Fprintln(w.out, "\nSetup did not finish:", err)
			ec = 1
		}
		pauseIfOwnWindow()
		return ec
	}
	if *elevated {
		// The window that asked for administrator rights shows the result.
		pauseFor(3 * time.Second)
		return nil
	}
	pauseIfOwnWindow()
	return nil
}

type setupOptions struct {
	dataDir       string
	dataFlag      string // --data as given ("" = the default), passed on to the elevated part
	elevatedChild bool   // started by setup itself with administrator rights
}

// codeChecker checks a Device Access Code with the gateway (gatewayChecker; fakes in tests).
type codeChecker interface {
	// Identify reads the gateway's model and firmware (no login).
	Identify(ctx context.Context) (string, error)
	// Check logs in with code and reads the outage-redirect setting: a read-only request.
	Check(ctx context.Context, code string) (redirectOn bool, err error)
}

// wizard is the setup dialogue and everything it touches, replaceable in tests.
type wizard struct {
	in       *bufio.Reader
	out      io.Writer
	readCode func() (string, error) // one line, typing hidden
	now      func() time.Time
	sleep    func(time.Duration)
	checker  func(host, pin string) codeChecker
	install  func(installOptions) error
	state    func() string                       // the service's state (winsvc.Status)
	loadCfg  func(dataDir string) *config.Config // nil when there is no configuration yet
	admin    func() bool
	elevate  func(args []string) (int, error)
	status   func(dataDir string) (*model.Status, error)
	openURL  func(string) error
}

func newWizard() *wizard {
	return &wizard{
		in: stdin, out: os.Stdout, readCode: readHiddenLine, now: time.Now, sleep: time.Sleep,
		checker: func(host, pin string) codeChecker { return newGatewayChecker(host, pin) },
		install: installService,
		state:   func() string { s, _ := winsvc.Status(); return s },
		loadCfg: func(dataDir string) *config.Config {
			c, err := config.Load(config.PathsFor(dataDir).Config)
			if err != nil {
				return nil
			}
			return c
		},
		admin: winsvc.IsAdmin, elevate: runElevated, status: serviceStatus, openURL: openURL,
	}
}

func (w *wizard) say(format string, a ...any) { fmt.Fprintf(w.out, format, a...) }

func (w *wizard) run(ctx context.Context, o setupOptions) error {
	if !o.elevatedChild {
		w.say("AT&T Internet Monitor - setup\n" +
			"=============================\n" +
			"This installs a Windows service that records tamper-evident evidence about your AT&T Fiber\n" +
			"connection and shows it on a dashboard in your browser. All you need is the Device Access Code\n" +
			"printed on the label of your AT&T gateway.\n\n")
	}
	if !w.admin() {
		w.say("Windows will now ask for permission to make changes (installing a service needs administrator\n" +
			"rights). Setup continues in a new window.\n")
		args := []string{"setup", "--elevated"}
		if o.dataFlag != "" {
			args = append(args, "--data", o.dataDir)
		}
		code, err := w.elevate(args)
		switch {
		case errors.Is(err, errElevationCancelled):
			w.say("\nSetup needs administrator permission to install the service. Run it again and choose Yes.\n")
			return exitCode(1)
		case err != nil:
			return err
		case code != 0:
			w.say("\nSetup did not finish (the administrator window showed why). Run it again to retry.\n")
			return exitCode(code)
		}
		return w.finish(o, true)
	}
	if o.elevatedChild {
		w.say("AT&T Internet Monitor - setup (administrator)\n\n")
	}
	if err := w.adminPart(ctx, o); err != nil {
		return err
	}
	if o.elevatedChild {
		w.say("\nSetup is complete.\n")
		return nil
	}
	return w.finish(o, false) // run as administrator: no browser is started from here
}

// adminPart finds the gateway, asks for and checks the code, and installs.
func (w *wizard) adminPart(ctx context.Context, o setupOptions) error {
	cfg := w.loadCfg(o.dataDir)
	state := w.state()
	installed := state != "" && state != winsvc.StatusNotInstalled
	host, pin, stored := config.Default().Gateway.Host, "", false
	if cfg != nil {
		host, pin, stored = cfg.Gateway.Host, cfg.Gateway.PinnedCertSHA256, cfg.HasAccessCode()
	}
	if installed {
		w.say("The monitor is already installed (%s). Setup updates it to version %s; the evidence, the\n"+
			"settings and the evidence key are kept.\n\n", state, version)
	}
	w.say("Looking for your AT&T gateway at %s ... ", host)
	chk := w.checker(host, pin)
	ictx, cancel := context.WithTimeout(ctx, 30*time.Second)
	name, err := chk.Identify(ictx)
	cancel()
	reachable := err == nil
	if reachable {
		w.say("found %s.\n\n", name)
	} else {
		w.say("no answer (%v).\n", err)
		w.say("Check that this computer is connected to the AT&T gateway, by Wi-Fi or Ethernet.\n")
		if !askYesNo(w.in, w.out, "Install anyway? The code cannot be checked now.", true) {
			return errors.New("cancelled")
		}
		w.say("\n")
	}
	code, err := w.askCode(ctx, chk, reachable, stored)
	if err != nil {
		return err
	}
	w.say("\nInstalling ...\n")
	return w.install(installOptions{DataDir: o.dataDir, Code: code, Out: w.out})
}

// maxCodeTries matches the gateway client's limit of three rejected logins within an hour.
const maxCodeTries = 3

// askCode asks for the Device Access Code until the gateway accepts it. It returns the code to
// store; "" keeps the stored code (if any) or installs without one, as the user chose.
func (w *wizard) askCode(ctx context.Context, chk codeChecker, reachable, stored bool) (string, error) {
	w.say("Type the Device Access Code printed on the label of your AT&T gateway (it is not the Wi-Fi\n" +
		"password). What you type is not shown.\n")
	if stored {
		w.say("A code is already stored: press Enter without typing to keep it.\n")
	}
	rejected := 0
	for {
		w.say("Device Access Code: ")
		code, err := w.readCode()
		if err != nil {
			return "", fmt.Errorf("reading the code: %w", err)
		}
		code = strings.TrimSpace(code)
		if code == "" {
			if stored {
				w.say("Keeping the stored code.\n")
				return "", nil
			}
			if askYesNo(w.in, w.out, "Install without the code? The monitor works, but it cannot keep the gateway's outage\n"+
				"redirect switched off until you add the code (att-monitor set-access-code).", false) {
				return "", nil
			}
			continue
		}
		if !reachable {
			w.say("The code is stored without a check; the monitor uses it once the gateway answers.\n")
			return code, nil
		}
		w.say("Checking the code with the gateway ... ")
		on, err := w.check(ctx, chk, code)
		switch {
		case err == nil:
			w.say("accepted.\n")
			if on {
				w.say("The gateway's outage redirect (Broadband Status Notification) is ON: the monitor switches it off\n" +
					"and keeps it off.\n")
			} else {
				w.say("The gateway's outage redirect (Broadband Status Notification) is already off: the monitor keeps\n" +
					"it off.\n")
			}
			return code, nil
		case errors.Is(err, contracts.ErrGatewayAuth), errors.Is(err, contracts.ErrGatewayAuthLocked):
			rejected++
			w.say("not accepted.\n")
			if rejected >= maxCodeTries || errors.Is(err, contracts.ErrGatewayAuthLocked) {
				w.say("The gateway did not accept the code %s. To keep its login from locking, it is not tried\n"+
					"again for an hour.\n", timesText(rejected))
				if askYesNo(w.in, w.out, "Install without the code for now? Add it later with att-monitor set-access-code.", true) {
					return "", nil
				}
				return "", errors.New("cancelled: no accepted Device Access Code")
			}
			w.say("Check the label on the gateway: the code is next to \"Device Access Code\" and may contain\n" +
				"symbols such as # * = %%. Upper and lower case matter.\n")
		default:
			w.say("not checked (%s).\n", checkProblem(err))
			w.say("The code is stored; the monitor checks it when it next logs in to the gateway.\n")
			return code, nil
		}
	}
}

// check checks code with the gateway, waiting out the gateway client's spacing of one login
// attempt per minute when needed.
func (w *wizard) check(ctx context.Context, chk codeChecker, code string) (bool, error) {
	for i := 0; ; i++ {
		cctx, cancel := context.WithTimeout(ctx, 90*time.Second)
		on, err := chk.Check(cctx, code)
		cancel()
		var cd *gateway.CooldownError
		if i < 2 && errors.As(err, &cd) && errors.Is(err, contracts.ErrGatewayLoginThrottled) {
			if wait := cd.Until.Sub(w.now()) + time.Second; wait > 0 {
				w.say("\nWaiting %d s (the gateway allows one login attempt per minute) ... ", int((wait+time.Second-1)/time.Second))
				w.sleep(wait)
			}
			continue
		}
		return on, err
	}
}

// checkProblem says in plain words why a code could not be checked.
func checkProblem(err error) string {
	switch {
	case errors.Is(err, contracts.ErrGatewaySessionsFull):
		return "all of the gateway's web sessions are in use"
	case errors.Is(err, contracts.ErrGatewayCertRejected):
		return "the gateway presented a different certificate than the monitor trusts; confirm it on the dashboard"
	case errors.Is(err, context.DeadlineExceeded):
		return "the gateway did not answer in time"
	}
	return err.Error()
}

func timesText(n int) string {
	switch n {
	case 1:
		return "once"
	case 2:
		return "twice"
	}
	return fmt.Sprintf("%d times", n)
}

// finish shows what was installed, from the running service; open starts the dashboard in the
// user's browser.
func (w *wizard) finish(o setupOptions, open bool) error {
	st, err := w.status(o.dataDir)
	if err != nil {
		w.say("\nThe service is installed, but its dashboard does not answer yet (%v).\n", err)
		return nil
	}
	url := "http://" + st.Monitor.Listen + "/"
	w.say("\nDone: the AT&T Internet Monitor %s is installed and running.\n\n", st.Monitor.Version)
	w.say("  Dashboard      %s\n", url)
	w.say("  Evidence key   %s\n", ledger.FormatFingerprint(st.Ledger.Fingerprint))
	w.say("                 Write it down or email it to yourself: it identifies your evidence.\n")
	w.say("  Start menu     \"AT&T Internet Monitor\" opens the dashboard.\n")
	w.say("  Uninstall      Settings > Apps > Installed apps (the evidence is kept).\n")
	for _, c := range st.Conditions {
		if c.Code == "NO_ACCESS_CODE" {
			w.say("  Gateway code   not stored or not usable: run setup again to add it.\n")
			break
		}
	}
	if open {
		if err := w.openURL(url); err == nil {
			w.say("\nOpening the dashboard in your browser.\n")
		}
	}
	return nil
}

// serviceStatus reads /api/status from the running service.
func serviceStatus(dataDir string) (*model.Status, error) {
	api, ok := serviceAPI(dataDir)
	if !ok {
		return nil, errors.New("the service's dashboard does not answer")
	}
	var st model.Status
	if err := api.do(background(), http.MethodGet, "/api/status", nil, &st); err != nil {
		return nil, err
	}
	return &st, nil
}

// readLine reads one line without its line ending.
func readLine(r *bufio.Reader) (string, error) {
	s, err := r.ReadString('\n')
	if err != nil && !(errors.Is(err, io.EOF) && s != "") {
		return "", err
	}
	return strings.TrimRight(s, "\r\n"), nil
}

// askYesNo asks a yes/no question; Enter takes the default, and so does the end of the input.
func askYesNo(r *bufio.Reader, out io.Writer, question string, def bool) bool {
	hint := "[y/N]"
	if def {
		hint = "[Y/n]"
	}
	for {
		fmt.Fprintf(out, "%s %s ", question, hint)
		line, err := readLine(r)
		if err != nil {
			fmt.Fprintln(out)
			return def
		}
		switch strings.ToLower(strings.TrimSpace(line)) {
		case "":
			return def
		case "y", "yes":
			return true
		case "n", "no":
			return false
		}
	}
}

// gatewayChecker is the codeChecker of the real gateway: one client for every attempt, so its
// login policy (one attempt per minute, none after three rejections within an hour) spans them.
type gatewayChecker struct {
	c    *gateway.Client
	code string // the code being checked, read by the client's AccessCode callback
}

func newGatewayChecker(host, pin string) *gatewayChecker {
	g := &gatewayChecker{}
	g.c = gateway.New(gateway.Options{
		Host:             host,
		PinnedCertSHA256: pin, // "" = trust on first use, for this check only (nothing is saved)
		Timeout:          20 * time.Second,
		UserAgent:        userAgent(),
		AccessCode:       func() (string, error) { return g.code, nil },
		Logger:           slog.New(slog.DiscardHandler),
	})
	return g
}

func (g *gatewayChecker) Identify(ctx context.Context) (string, error) {
	snap, _, err := g.c.Snapshot(ctx, []string{"sysinfo"}, "setup")
	if err != nil {
		return "", err
	}
	s := snap.System
	if s == nil || (s.Model == "" && s.Manufacturer == "") {
		return "", errors.New("it answered, but its system page does not look like an AT&T gateway's")
	}
	name := strings.TrimSpace(s.Manufacturer + " " + s.Model)
	if s.SoftwareVersion != "" {
		name += ", firmware " + s.SoftwareVersion
	}
	return name, nil
}

func (g *gatewayChecker) Check(ctx context.Context, code string) (bool, error) {
	g.code = code
	on, _, err := g.c.Notification(ctx)
	return on, err
}

// setupWanted reports whether a start without arguments should run the guided setup: the
// program was started from Explorer (a double-click), not from a terminal.
func setupWanted() bool { return ownConsole() }
