// Command att-monitor is the AT&T Internet Monitor: a Windows service that records
// tamper-evident, chain-of-custody evidence about the AT&T BGW320 gateway and the Internet
// path, with a localhost dashboard. See docs/DESIGN.md.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
)

// Set at build time: go build -ldflags "-X main.version=1.0.0 -X main.commit=abc123"
var (
	version = "dev"
	commit  = ""
)

const usageText = `att-monitor — AT&T Internet Monitor (evidence logger)

Usage:
  att-monitor setup                            guided install: asks for the gateway's Device Access Code
                                               (also what a double-click on att-monitor.exe runs)
  att-monitor install [--data DIR] [--listen 127.0.0.1:8320] [--access-code-file PATH] [--bootstrap DIR]
  att-monitor uninstall [--interactive]
  att-monitor start | stop | status
  att-monitor run [--data DIR]                 run in the foreground (console mode)
  att-monitor set-access-code (--file PATH | --stdin) [--data DIR]
  att-monitor gateway notification [status|on|off] [--data DIR]
  att-monitor gateway syslog [status|on|off] [--json] [--data DIR]
                                               the gateway's Syslog setting, the receiver and the store; on: send
                                               the gateway's log to this PC and keep it so, off: stop it
  att-monitor gateway trust-cert [--data DIR]  confirm a changed gateway certificate (after AT&T updates)
  att-monitor syslog [--since 24h] [--grep TEXT] [--severity LEVEL] [--limit N] [--json] [--data DIR]
                                               the gateway's syslog messages kept on this PC, oldest first
  att-monitor syslog retention [--keep-mb N] [--keep-days D] [--yes] [--data DIR]
                                               how much syslog is kept (100 MiB unless changed)
  att-monitor verify [--data DIR] [--json]     verify the whole evidence ledger
  att-monitor verify-bundle FILE.zip [--json]  verify an exported evidence bundle
  att-monitor export --from TIME --to TIME [--incident ID] [--prepared-by NAME] [--notes TEXT] [--out DIR] [--data DIR]
  att-monitor note "text" [--author NAME] [--data DIR]
  att-monitor ticket-report [--hours 24] [--out DIR] [--name N] [--account A] [--address ADDR] [--phone P]
                            [--best-time T] [--notes TEXT] [--no-pdf]   PDF for an AT&T service ticket (from a verified bundle)
  att-monitor mongo status | verify [--json] [--data DIR]   the MongoDB copy of the ledger
  att-monitor anchor [--data DIR]              request RFC 3161 time-stamps for the ledger head now
  att-monitor version

TIME is YYYY-MM-DD, YYYY-MM-DDTHH:MM (local time) or RFC 3339. A date-only --to includes that whole day.
Dashboard: http://127.0.0.1:8320 (while the service is running)
`

func main() {
	if err := run(os.Args[1:]); err != nil {
		var ec exitCode
		if errors.As(err, &ec) {
			os.Exit(int(ec))
		}
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

// exitCode lets a command finish with a specific status without printing an error.
type exitCode int

func (e exitCode) Error() string { return fmt.Sprintf("exit status %d", int(e)) }

func run(args []string) error {
	if len(args) == 0 {
		if isService() {
			return cmdService(nil)
		}
		if setupWanted() {
			// Started from Explorer (a double-click): the guided setup.
			return cmdSetup(nil)
		}
		fmt.Print(usageText)
		return nil
	}
	cmd, rest := args[0], args[1:]
	switch strings.ToLower(cmd) {
	case "service":
		return cmdService(rest)
	case "run":
		return cmdRun(rest)
	case "setup":
		return cmdSetup(rest)
	case "install":
		return cmdInstall(rest)
	case "uninstall":
		return cmdUninstall(rest)
	case "start":
		return cmdStart(rest)
	case "stop":
		return cmdStop(rest)
	case "status":
		return cmdStatus(rest)
	case "set-access-code":
		return cmdSetAccessCode(rest)
	case "gateway":
		return cmdGateway(rest)
	case "syslog":
		return cmdSyslog(rest)
	case "verify":
		return cmdVerify(rest)
	case "verify-bundle":
		return cmdVerifyBundle(rest)
	case "export":
		return cmdExport(rest)
	case "note":
		return cmdNote(rest)
	case "ticket-report":
		return cmdTicketReport(rest)
	case "mongo":
		return cmdMongo(rest)
	case "anchor":
		return cmdAnchor(rest)
	case "version", "--version", "-v":
		return cmdVersion(rest)
	case "help", "--help", "-h", "/?":
		fmt.Print(usageText)
		return nil
	default:
		fmt.Fprint(os.Stderr, usageText)
		return fmt.Errorf("unknown command %q", cmd)
	}
}

// background is the root context for short CLI commands.
func background() context.Context { return context.Background() }
