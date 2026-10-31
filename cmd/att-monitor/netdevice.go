package main

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"attmonitor/internal/model"
	"attmonitor/internal/web"
)

// One device's details on the command line (docs/dhcp-table.md §7): `att-monitor network --devices
// --key KEY` prints the device as the Devices view lists it, its issues, the addresses it held and
// who else held them, the LAN scans as it answered them, what its syslog messages are found by and
// those messages, newest first, from GET /api/network/device of the running service; `--addr
// ADDRESS` the same of an unknown LAN address. Every text the service passes on from the gateway
// and its syslog is escaped for the terminal (terminalSafe).

// detailScansShown is how many of the LAN scans the details print, the newest.
const detailScansShown = 6

// deviceDetailArgs checks --key and --addr: only with --devices, one of them, a key the service
// can take (web.MaxNetworkDeviceKeyBytes bytes of text at most, no control characters; a MAC address
// alone, as the DHCP table shows it, is the key "mac:" and that address) or an IPv4 address. It
// returns the query parameters that name the device (nil without either).
func deviceDetailArgs(devices bool, key, addr string) (url.Values, error) {
	addr = strings.TrimSpace(addr)
	switch {
	case key == "" && addr == "":
		return nil, nil
	case !devices:
		return nil, errors.New("--key and --addr name a device of the Devices view: give --devices too")
	case key != "" && addr != "":
		return nil, errors.New("--key names a device of the DHCP table, --addr an unknown address: give one of them")
	case key != "":
		if hw, err := net.ParseMAC(strings.TrimSpace(key)); err == nil && len(hw) == 6 {
			key = "mac:" + hw.String()
		}
		if !networkKeyOK(key) {
			return nil, fmt.Errorf("--key: a device's MAC address, or its key as the DHCP table's --json lists it (mac:…, ip:…, name:…): "+
				"at most %d bytes of text, no control characters", web.MaxNetworkDeviceKeyBytes)
		}
		return url.Values{"key": {key}}, nil
	}
	a, err := netip.ParseAddr(addr)
	if err != nil || !a.Is4() {
		return nil, fmt.Errorf("--addr %q: an IPv4 address, as the unknown addresses list it", addr)
	}
	return url.Values{"addr": {a.String()}}, nil
}

// networkKeyOK reports whether k can be a key of the Devices view, by the service's rule: 1 to
// web.MaxNetworkDeviceKeyBytes bytes of UTF-8 without control or format characters.
func networkKeyOK(k string) bool {
	if k == "" || len(k) > web.MaxNetworkDeviceKeyBytes || !utf8.ValidString(k) {
		return false
	}
	for _, r := range k {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return false
		}
	}
	return true
}

// deviceDetailCommand asks the service for one device's details (q: the period, the device and the
// limit of syslog messages) and prints them, or the answer as JSON.
func deviceDetailCommand(out io.Writer, api *apiClient, q url.Values, asJSON bool) error {
	var dd model.NetDeviceDetail
	hdr, err := api.call(background(), http.MethodGet, "/api/network/device?"+q.Encode(), nil, &dd)
	if err != nil {
		return deviceDetailError(err)
	}
	warning := terminalSafe(hdr.Get(web.WarningHeader))
	if asJSON {
		if warning != "" {
			fmt.Fprintln(errOutput, "WARNING:", warning)
		}
		return writeJSON(out, dd)
	}
	printDeviceDetail(out, dd, networkStatus(api), warning)
	return nil
}

// errOutput is where the details' warnings go with --json, so as not to mix with the JSON (the
// tests replace it).
var errOutput io.Writer = os.Stderr

// deviceDetailError explains the answer of a service that has no device details - an older
// version, whose router answers any unknown path "not found" - and passes any other error on (the
// service words its own "not found": no such device or address in the period).
func deviceDetailError(err error) error {
	var se *serviceError
	if errors.As(err, &se) && se.Status == http.StatusNotFound && se.msg == "not found" {
		return fmt.Errorf("%w: the running service has no device details on its Network page (it is an older version of att-monitor): "+
			"install this version to upgrade it (att-monitor install, or setup)", err)
	}
	return err
}

// printDeviceDetail prints a GET /api/network/device answer: the device (or the unknown address)
// and what the period says about it, its issues, its addresses and who else held them, the LAN
// scans, and its syslog messages newest first with what they are found by.
func printDeviceDetail(out io.Writer, dd model.NetDeviceDetail, ns *model.NetworkStatus, warning string) {
	layout := rowLayout(dd.From, dd.To, time.Local)
	period := localTime(dd.From, "2006-01-02 15:04") + " to " + localTime(dd.To, "2006-01-02 15:04")
	var issues []model.NetIssue
	switch {
	case dd.Device != nil:
		d := *dd.Device
		issues = d.Issues
		fmt.Fprintf(out, "Device %s (%s), %s (this PC's local time)\n", terminalSafe(deviceTitle(d)), terminalSafe(d.Key), period)
		status := "as the newest Device List read shows it"
		if d.Seen != "" {
			status += "; last seen on at " + localTime(d.Seen, "2006-01-02 15:04")
		}
		fmt.Fprintf(out, "Status:      %s, %s; on in %d of the %d reads of this period that list it\n", dash(d.Status), status, d.OnReads, d.Reads)
		ids := []string{"IPv4 " + dash(d.IPv4)}
		if d.Allocation != "" {
			ids[0] += " (" + terminalSafe(d.Allocation) + ")"
		}
		ids = append(ids, "MAC "+dash(d.MAC))
		for _, a := range d.IPv6 {
			ids = append(ids, "IPv6 "+terminalSafe(a))
		}
		fmt.Fprintln(out, "Addresses:  ", strings.Join(ids, ", "))
		fmt.Fprintln(out, "Connection: ", connectionText(d))
		if d.LastActivity != "" {
			fmt.Fprintln(out, "Activity:    the gateway gives its last activity as", terminalSafe(d.LastActivity))
		}
		fmt.Fprintf(out, "Traffic:     %s open in the newest NAT read, %s in this period; the firewall dropped %d it sent / %d sent to it\n",
			plural(d.Open, "connection", "connections"), plural(d.Sites, "site", "sites"), d.Blocked, d.BlockedIn)
		if len(dd.Scans) > 0 {
			scans := "LAN scans:   it answered " + plural(d.ScanHits, "LAN scan", "LAN scans") + " of this period"
			switch {
			case d.ScanAddr != "":
				scans += ", the newest at " + terminalSafe(d.ScanAddr)
			case d.ScanSeen != "":
				scans += ", the last at " + localTime(d.ScanSeen, layout) + " - not the newest"
			}
			fmt.Fprintln(out, scans)
		}
	case dd.Unknown != nil:
		u := *dd.Unknown
		issues = u.Issues
		fmt.Fprintf(out, "Unknown address %s, %s (this PC's local time): no Device List read of this period names it\n", terminalSafe(u.Addr), period)
		if u.First != "" {
			fmt.Fprintf(out, "Seen:        from %s to %s\n", localTime(u.First, layout), localTime(u.Last, layout))
		}
		if u.MAC != "" {
			fmt.Fprintf(out, "MAC:         %s answered for it in the LAN scan of %s\n", terminalSafe(u.MAC), localTime(u.ScanSeen, layout))
		}
		fmt.Fprintf(out, "Traffic:     %s open in the newest NAT read, %s in this period; the firewall dropped %d it sent / %d sent to it\n",
			plural(u.Open, "connection", "connections"), plural(u.Sites, "site", "sites"), u.Blocked, u.BlockedIn)
	default:
		fmt.Fprintf(out, "Nothing is known of it in %s (this PC's local time)\n", period)
	}
	if len(issues) > 0 {
		fmt.Fprintln(out, "Issues:")
		for _, is := range issues {
			fmt.Fprintf(out, "  %-8s  %s\n", terminalSafe(is.Level), terminalSafe(is.Text))
		}
	}
	printDetailAddresses(out, dd, layout)
	printDetailScans(out, dd.Scans, layout)
	printDetailSyslog(out, dd, ns, warning, layout)
}

// printDetailAddresses lists who held the addresses in the period: the device itself and the others.
func printDetailAddresses(out io.Writer, dd model.NetDeviceDetail, layout string) {
	if len(dd.Addresses) == 0 {
		return
	}
	self := ""
	if dd.Device != nil {
		self = readsKey(dd.Device.Key)
	}
	fmt.Fprintln(out, "Who held its addresses in this period (as the Device List reads show them):")
	tw := newTable(out)
	fmt.Fprintln(tw, "  ADDRESS\tDEVICE\tFIRST READ\tLAST READ\tREADS")
	for _, u := range dd.Addresses {
		who := u.Name
		if who == "" {
			who = u.MAC
		}
		if who == "" {
			who = u.Device
		}
		who = terminalSafe(clip(who, netNameChars))
		if self != "" && u.Device == self {
			who += " (this device)"
		}
		if u.Shared > 0 {
			who += fmt.Sprintf(" (another claimed it too in %s)", plural(u.Shared, "read", "reads"))
		}
		fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\t%d\n", terminalSafe(u.Addr), who, localTime(u.First, layout), localTime(u.Last, layout), u.Reads)
	}
	tw.Flush()
}

// readsKey is the key the Device List reads know a device of the DHCP table by: its own, without
// the "#2", "#3", ... that tells an entry the newest read gives twice from the first.
func readsKey(key string) string {
	if i := strings.LastIndexByte(key, '#'); i > 0 && i < len(key)-1 && strings.Trim(key[i+1:], "0123456789") == "" {
		return key[:i]
	}
	return key
}

// printDetailScans lists the newest LAN scans of the period as it answered them.
func printDetailScans(out io.Writer, scans []model.NetScanSeen, layout string) {
	if len(scans) == 0 {
		fmt.Fprintln(out, "LAN scans:   none in this period")
		return
	}
	shown := scans[:min(len(scans), detailScansShown)]
	fmt.Fprintln(out, "The newest LAN scans of this period:")
	for _, s := range shown {
		answer := "no answer"
		if s.Addr != "" {
			answer = "answered at " + terminalSafe(s.Addr)
		}
		fmt.Fprintf(out, "  %s  %s\n", localTime(s.At, layout), answer)
	}
}

// printDetailSyslog prints the syslog messages that name it, newest first, and what they are found
// by.
func printDetailSyslog(out io.Writer, dd model.NetDeviceDetail, ns *model.NetworkStatus, warning, layout string) {
	if len(dd.Match) > 0 {
		terms := make([]string, len(dd.Match))
		for i, t := range dd.Match {
			terms[i] = terminalSafe(t.Text)
			switch {
			case t.From != "" && t.To != "":
				terms[i] += " (from " + localTime(t.From, layout) + " to " + localTime(t.To, layout) + ")"
			case t.From != "":
				terms[i] += " (from " + localTime(t.From, layout) + ")"
			case t.To != "":
				terms[i] += " (until " + localTime(t.To, layout) + ")"
			}
		}
		fmt.Fprintln(out, "Syslog:      its messages are found by", strings.Join(terms, ", "))
	}
	if warning != "" {
		fmt.Fprintln(out, "WARNING:", warning)
	}
	switch {
	case dd.SyslogError != "":
		fmt.Fprintln(out, "Syslog:     ", terminalSafe(dd.SyslogError))
		return
	case ns != nil && ns.Syslog == nil:
		fmt.Fprintln(out, "Syslog:      no syslog is kept, so its messages are not known")
		return
	case len(dd.Syslog) == 0:
		fmt.Fprintln(out, "Syslog:      no message of this period names it")
		return
	}
	s := fmt.Sprintf("Syslog:      %s of this period name it, newest first", plural(len(dd.Syslog), "message", "messages"))
	if dd.SyslogTruncated {
		s = fmt.Sprintf("Syslog:      the newest %s that name it; more do (--limit shows more, up to %d, or a shorter period)",
			plural(len(dd.Syslog), "message", "messages"), web.MaxDeviceSyslogLimit)
	}
	fmt.Fprintln(out, s+":")
	for _, m := range dd.Syslog {
		fmt.Fprintf(out, "  %s  %-7s  %s\n", localTime(m.RX, "2006-01-02 15:04:05"), severityName(m.Severity), terminalSafe(syslogLineText(m.SyslogMessage)))
	}
}
