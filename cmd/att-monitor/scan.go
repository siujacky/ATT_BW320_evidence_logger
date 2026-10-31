package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"time"

	"attmonitor/internal/config"
	"attmonitor/internal/contracts"
	"attmonitor/internal/lanscan"
	"attmonitor/internal/model"
)

// The LAN scan on the command line (docs/dhcp-table.md §6):
//
//	att-monitor scan [--json] [--data DIR]
//
// sweeps the home network once, now, as the service does every connections.scan_interval: every
// address of this PC's own IPv4 network - the one of its interface that holds gateway.host - is
// asked by ARP who has it (no administrator rights needed; nothing leaves the home network, and
// nothing else is sent to the devices). It prints what answered: address, MAC address and, when
// the service runs, the name the gateway's newest Device List read gives the device (GET
// /api/network/devices), with a note for this PC, the gateway and a device the Device List does
// not name. It stores nothing: the service keeps its own sweeps for the Network page.

// scanUsage is the usage of the scan command.
const scanUsage = "usage: att-monitor scan [--json] [--data DIR]"

// newScanner returns the sweeper of the home network that holds the gateway's address (the tests
// replace it).
var newScanner = func(gateway string) contracts.LANScanner {
	return lanscan.New(lanscan.Options{Gateway: gateway})
}

// scanNamesTimeout bounds the request for the Device List's names.
const scanNamesTimeout = 30 * time.Second

func cmdScan(args []string) error { return scanCommand(os.Stdout, args) }

// scanCommand runs `att-monitor scan …`, writing to out. Wrong arguments are refused before
// anything is sent.
func scanCommand(out io.Writer, args []string) error {
	fs, data := newFlags("scan")
	asJSON := fs.Bool("json", false, "print the sweep as JSON (as the service keeps it: model.LANScan), without the names")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q\n%s", fs.Arg(0), scanUsage)
	}
	dataDir := defaultDataDir(*data)
	cfg := configOrDefault(dataDir)
	sc, err := newScanner(cfg.Gateway.Host).Scan(background())
	if err != nil {
		return err
	}
	if *asJSON {
		return writeJSON(out, sc)
	}
	dv, why := scanNames(dataDir)
	printScan(out, sc, dv, why, cfg)
	return nil
}

// scanNames asks the running service for its Devices view (the newest Device List read's devices);
// nil, with the reason in words, when there is none.
func scanNames(dataDir string) (*model.NetDevicesView, string) {
	api, ok := lookupService(dataDir)
	if !ok {
		return nil, "the service is not running, so the devices are not named (the names come from its reads of the gateway's Device List)"
	}
	ctx, cancel := context.WithTimeout(background(), scanNamesTimeout)
	defer cancel()
	q := url.Values{"range": {"1h"}, "limit": {"1"}}
	var dv model.NetDevicesView
	if err := api.do(ctx, http.MethodGet, "/api/network/devices?"+q.Encode(), nil, &dv); err != nil {
		var se *serviceError
		if errors.As(err, &se) && se.Status == http.StatusNotFound && se.msg == "not found" {
			return nil, "the running service has no Devices view (it is an older version of att-monitor), so the devices are not named"
		}
		return nil, "the devices are not named: the service did not give its Device List (" + terminalSafe(err.Error()) + ")"
	}
	if dv.ListAt == "" {
		return nil, "the devices are not named: the service has not read the gateway's Device List yet"
	}
	return &dv, ""
}

// printScan prints a sweep: what was swept and when, how many answered, then every address that
// answered - in address order - with its MAC address, its name in the Device List (dv; nil: none,
// why says so) and a note: this PC, the gateway, not in the Device List, listed at another address,
// or an address the Device List gives another device. Every text from the gateway is escaped.
func printScan(out io.Writer, sc model.LANScan, dv *model.NetDevicesView, why string, cfg *config.Config) {
	fmt.Fprintf(out, "LAN scan of %s at %s (this PC's local time): %s answered, of %d asked, in %.1f s\n",
		terminalSafe(sc.Subnet), localTime(sc.At, "2006-01-02 15:04:05"), plural(len(sc.Hosts), "address", "addresses"), sc.Asked,
		float64(sc.TookMs)/1000)
	if sc.Problem != "" {
		fmt.Fprintln(out, "Problem:", terminalSafe(sc.Problem))
	}
	byMAC := map[string]model.NetLANDevice{}
	byIPv4 := map[string]model.NetLANDevice{}
	if dv != nil {
		fmt.Fprintf(out, "Names:   from the gateway's Device List as read at %s (through the service)\n", localTime(dv.ListAt, "2006-01-02 15:04"))
		for _, d := range dv.Devices {
			if mac := strings.ToLower(d.MAC); mac != "" {
				if _, seen := byMAC[mac]; !seen {
					byMAC[mac] = d
				}
			}
			if d.IPv4 != "" && !strings.EqualFold(d.Status, "off") {
				if _, seen := byIPv4[d.IPv4]; !seen {
					byIPv4[d.IPv4] = d
				}
			}
		}
	} else if why != "" {
		fmt.Fprintln(out, "Names:  ", why)
	}
	gateway := strings.TrimSpace(cfg.Gateway.Host)
	if a, err := netip.ParseAddr(gateway); err == nil {
		gateway = a.Unmap().String() // as the scan writes addresses
	}
	if len(sc.Hosts) > 0 {
		tw := newTable(out)
		fmt.Fprintln(tw, "  ADDRESS\tMAC\tNAME\tNOTE")
		unlisted := 0
		for _, h := range sc.Hosts {
			name, notes := "-", []string{}
			d, listed := byMAC[strings.ToLower(h.MAC)]
			if listed {
				name = terminalSafe(clip(deviceTitle(d), netNameChars))
			}
			switch {
			case h.IP == sc.Self:
				notes = append(notes, "this PC")
			case h.IP == gateway:
				notes = append(notes, "the gateway")
			case dv != nil && !listed:
				// A device the Device List does not name: a fixed address, or one that joined since.
				if other, ok := byIPv4[h.IP]; ok {
					notes = append(notes, "the Device List gives this address to "+terminalSafe(clip(deviceTitle(other), netNameChars))+
						" ("+dash(other.MAC)+")")
				} else {
					notes = append(notes, "not in the Device List")
				}
				unlisted++
			}
			if listed && d.IPv4 != "" && d.IPv4 != h.IP {
				notes = append(notes, "the Device List lists it at "+terminalSafe(d.IPv4))
			}
			note := "-"
			if len(notes) > 0 {
				note = strings.Join(notes, "; ")
			}
			fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\n", terminalSafe(h.IP), terminalSafe(h.MAC), name, note)
		}
		tw.Flush()
		if unlisted > 0 {
			fmt.Fprintf(out, "%s with a MAC address the gateway's Device List does not name: perhaps a device with a fixed address, or one that joined since the list was read.\n",
				plural(unlisted, "address answered", "addresses answered"))
		}
	}
	c := cfg.Connections
	switch {
	case !c.Enabled:
		fmt.Fprintln(out, "Nothing was stored. The service makes no sweeps: connections.enabled is false in config.json.")
	case c.ScanInterval.Duration <= 0:
		fmt.Fprintln(out, "Nothing was stored. The service makes no sweeps: connections.scan_interval is 0 in config.json.")
	default:
		fmt.Fprintf(out, "Nothing was stored. The service sweeps every %s (connections.scan_interval) and keeps its sweeps for the Network page's Devices tab.\n",
			c.ScanInterval.Duration)
	}
}
