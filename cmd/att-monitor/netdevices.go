package main

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"attmonitor/internal/model"
)

// The Network page's Devices tab on the command line (docs/dhcp-table.md): `att-monitor network
// --devices` prints the gateway's Device List - its DHCP table: which device has which address -
// with what the period says about each device (the LAN scans included), its issues and the LAN
// addresses no Device List read names, from GET /api/network/devices of the running service (one
// device's details: netdevice.go). Every text the service passes on from the gateway (names,
// connections, speeds, the gateway's times) is escaped for the terminal (terminalSafe), as are the
// issues' sentences, which quote them.

// issueLabels are the short names of the issues in the DHCP table's ISSUES column.
var issueLabels = map[string]string{
	model.IssueAddressShared:  "address conflict",
	model.IssueAddressChanged: "address changed",
	model.IssueOffline:        "off",
	model.IssueWeakWiFi:       "weak Wi-Fi",
	model.IssueSlowLink:       "slow link",
	model.IssueBlocked:        "blocked",
	model.IssueUnlisted:       "unlisted",
	model.IssueNoAnswer:       "no scan answer",
	model.IssueScanMAC:        "another MAC",
	model.IssueScanAddr:       "other address",
}

// printDevices prints a GET /api/network/devices answer: the period, the Device List and NAT
// reads in it and how the samplers fare (ns, when known), the totals, the DHCP table, the
// devices' issues in words and the unknown LAN addresses.
func printDevices(out io.Writer, dv model.NetDevicesView, ns *model.NetworkStatus) {
	fmt.Fprintf(out, "Devices %s to %s (this PC's local time): the gateway's Device List - its DHCP table - with what this period says about each device\n",
		localTime(dv.From, "2006-01-02 15:04"), localTime(dv.To, "2006-01-02 15:04"))
	layout := rowLayout(dv.From, dv.To, time.Local)
	t := dv.Totals
	if dv.ListAt == "" {
		fmt.Fprintln(out, "Device List: not read yet")
	} else {
		fmt.Fprintf(out, "Device List: %s listed, %d on (%d on Wi-Fi, %d on Ethernet), as read at %s; %s in this period\n",
			plural(t.Listed, "device", "devices"), t.Online, t.WiFi, t.Wired, localTime(dv.ListAt, "2006-01-02 15:04"),
			plural(dv.Reads, "read", "reads"))
	}
	if dv.NATReads == 0 {
		fmt.Fprintln(out, "NAT reads:   none in this period, so the open connections and sites are not known")
	} else {
		fmt.Fprintf(out, "NAT reads:   %d in this period; OPEN counts the connections of the newest, at %s\n", dv.NATReads,
			localTime(dv.NATAt, layout))
	}
	printSamplers(out, ns)
	printScans(out, dv, ns, layout)
	if ns != nil && ns.Syslog == nil {
		fmt.Fprintln(out, "Firewall:    no syslog is kept, so the blocked packets are not known")
	}
	if t.Issues > 0 {
		fmt.Fprintf(out, "Issues:      %s with a warning or a critical issue\n", plural(t.Issues, "device or address", "devices and addresses"))
	}
	printDHCPTable(out, dv.Devices, dv.Scans, layout)
	printDeviceIssues(out, dv.Devices)
	printUnknown(out, dv, layout)
	fmt.Fprintln(out, "The gateway does not show DHCP lease times: its DHCP Server page needs the login, and the monitor does not read it."+
		" BLOCKED counts the packets the gateway's firewall dropped: sent by the device / sent to it from the Internet."+
		" SCAN says whether the device answered the newest LAN scan of this period (when it last answered one, and where when not at its address).")
	fmt.Fprintln(out, "A device's details and its syslog messages: att-monitor network --devices --key <its MAC address> (an entry without one: "+
		"--key ip:<its address>; an unknown address: --addr <the address>).")
	printConfigWarnings(out, ns)
}

// printScans says how many LAN scans the period has and sums up the newest, and how the scans fare
// as the service's status says (ns, when known).
func printScans(out io.Writer, dv model.NetDevicesView, ns *model.NetworkStatus, layout string) {
	var smp *model.ConnSamplerStatus
	if ns != nil {
		smp = ns.Samplers
	}
	next := ""
	if smp != nil && smp.ScanNext != "" {
		next = "; the next is due at " + localTime(smp.ScanNext, "2006-01-02 15:04")
	}
	switch s := dv.Scan; {
	case s != nil:
		fmt.Fprintf(out, "LAN scans:   %d in this period; the newest, of %s at %s: %d of the %d addresses asked answered%s\n", dv.Scans,
			terminalSafe(s.Subnet), localTime(s.At, layout), s.Answered, s.Asked, next)
		if s.Problem != "" {
			fmt.Fprintln(out, "             but", terminalSafe(s.Problem))
		}
	case smp != nil && smp.Enabled && smp.ScanInterval == "":
		fmt.Fprintln(out, "LAN scans:   none: connections.scan_interval is 0 in config.json, so the service does not sweep the home network")
	default:
		fmt.Fprintf(out, "LAN scans:   none in this period, so SCAN is not known%s\n", next)
	}
	if smp != nil && smp.ScanProblem != "" {
		fmt.Fprintln(out, "LAN scan:   ", terminalSafe(smp.ScanProblem))
	}
}

// printDHCPTable lists the devices as the service orders them: those with a critical issue,
// then with a warning, then the others, those that are off last. scans is how many LAN scans the
// period has.
func printDHCPTable(out io.Writer, devices []model.NetLANDevice, scans int, layout string) {
	if len(devices) == 0 {
		return
	}
	fmt.Fprintln(out, "DHCP table:")
	tw := newTable(out)
	fmt.Fprintln(tw, "  STATUS\tNAME\tIPV4\tMAC\tCONNECTION\tALLOCATION\tLAST SEEN ON\tOPEN\tSITES\tBLOCKED\tSCAN\tISSUES")
	for _, d := range devices {
		seen := "-"
		if d.Seen != "" {
			seen = localTime(d.Seen, layout)
		}
		fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\t%s\t%s\t%s\t%d\t%d\t%d/%d\t%s\t%s\n", dash(d.Status), terminalSafe(clip(deviceTitle(d), netNameChars)),
			dash(d.IPv4), dash(d.MAC), connectionText(d), dash(d.Allocation), seen, d.Open, d.Sites, d.Blocked, d.BlockedIn,
			scanText(d, scans, layout), issueText(d.Issues))
	}
	tw.Flush()
}

// scanText is a device's SCAN cell: "answered 10:05" (the newest scan, "at <address>" when not at
// the one it is listed with), "no answer (last 09:05)", "no answer", or "not scanned" when the
// period has no scan.
func scanText(d model.NetLANDevice, scans int, layout string) string {
	switch {
	case scans == 0:
		return "not scanned"
	case d.ScanAddr != "":
		s := "answered " + localTime(d.ScanSeen, layout)
		if d.ScanAddr != d.IPv4 {
			s += " at " + terminalSafe(d.ScanAddr)
		}
		return s
	case d.ScanSeen != "":
		return "no answer (last " + localTime(d.ScanSeen, layout) + ")"
	}
	return "no answer"
}

// printDeviceIssues says each device's issues in words, the devices in the table's order.
func printDeviceIssues(out io.Writer, devices []model.NetLANDevice) {
	header := false
	for _, d := range devices {
		for _, is := range d.Issues {
			if !header {
				fmt.Fprintln(out, "Issues of the devices:")
				header = true
			}
			who := terminalSafe(deviceTitle(d))
			if d.IPv4 != "" && d.IPv4 != d.Name {
				who += " (" + terminalSafe(d.IPv4) + ")"
			}
			fmt.Fprintf(out, "  %-8s  %s: %s\n", terminalSafe(is.Level), who, terminalSafe(is.Text))
		}
	}
}

// printUnknown lists the LAN addresses that no Device List read of the period names.
func printUnknown(out io.Writer, dv model.NetDevicesView, layout string) {
	total := max(dv.Totals.Unknown, len(dv.Unknown))
	if total == 0 {
		return
	}
	s := fmt.Sprintf("Unknown addresses: %s of the home network that the NAT table, the firewall's drops or the LAN scans show and no Device List "+
		"read of this period names (or whose MAC address none names)", plural(total, "LAN address", "LAN addresses"))
	if len(dv.Unknown) < total {
		s += fmt.Sprintf("; the %d seen last%s", len(dv.Unknown), moreRows(len(dv.Unknown)))
	}
	fmt.Fprintln(out, s+":")
	if len(dv.Unknown) == 0 {
		return
	}
	tw := newTable(out)
	fmt.Fprintln(tw, "  ADDRESS\tFIRST\tLAST\tOPEN\tSITES\tBLOCKED\tMAC (LAN SCAN)\tSCANNED")
	selfAssigned := false
	for _, u := range dv.Unknown {
		addr := terminalSafe(u.Addr)
		if a, err := netip.ParseAddr(u.Addr); err == nil && a.Is4() && a.IsLinkLocalUnicast() {
			addr += " (self-assigned)"
			selfAssigned = true
		}
		first, last := "-", "-"
		if u.First != "" {
			first, last = localTime(u.First, layout), localTime(u.Last, layout)
		}
		scanned := "-"
		if u.ScanSeen != "" {
			scanned = localTime(u.ScanSeen, layout)
		}
		fmt.Fprintf(tw, "  %s\t%s\t%s\t%d\t%d\t%d/%d\t%s\t%s\n", addr, first, last, u.Open, u.Sites, u.Blocked, u.BlockedIn, dash(u.MAC), scanned)
	}
	tw.Flush()
	if selfAssigned {
		fmt.Fprintln(out, "  A device gives itself an address in 169.254.0.0/16 (self-assigned) when it gets none from the gateway's DHCP server.")
	}
}

// deviceTitle names a device in the table: its name, else its MAC address, else its key.
func deviceTitle(d model.NetLANDevice) string {
	switch {
	case d.Name != "":
		return d.Name
	case d.MAC != "":
		return d.MAC
	}
	return d.Key
}

// connectionText is a device's connection as the table shows it: "Wi-Fi 5 GHz, 4 bars",
// "Ethernet LAN-1, 1000Mbps fullduplex", "-".
func connectionText(d model.NetLANDevice) string {
	parts := []string{}
	if d.Connection != "" {
		parts = append(parts, terminalSafe(d.Connection))
	}
	if d.Signal > 0 {
		parts = append(parts, plural(d.Signal, "bar", "bars"))
	}
	if d.Speed != "" {
		parts = append(parts, terminalSafe(clip(d.Speed, netNameChars)))
	}
	if d.Mesh {
		parts = append(parts, "mesh")
	}
	if len(parts) == 0 {
		return "-"
	}
	return strings.Join(parts, ", ")
}

// issueText lists a device's issues by their short names ("-" for none).
func issueText(issues []model.NetIssue) string {
	if len(issues) == 0 {
		return "-"
	}
	names := make([]string, len(issues))
	for i, is := range issues {
		if l, ok := issueLabels[is.Code]; ok {
			names[i] = l
		} else {
			names[i] = terminalSafe(is.Code)
		}
	}
	return strings.Join(names, ", ")
}

// devicesError explains the answer of a service that has no Devices view - an older version,
// whose router answers any unknown path "not found" - and passes any other error on.
func devicesError(err error) error {
	var se *serviceError
	if errors.As(err, &se) && se.Status == http.StatusNotFound && se.msg == "not found" {
		return fmt.Errorf("%w: the running service has no Devices view on its Network page (it is an older version of att-monitor): "+
			"install this version to upgrade it (att-monitor install, or setup)", err)
	}
	return err
}
