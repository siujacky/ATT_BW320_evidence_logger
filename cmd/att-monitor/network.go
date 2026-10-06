package main

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"
	"unicode/utf8"

	"attmonitor/internal/config"
	"attmonitor/internal/model"
	"attmonitor/internal/web"
)

// The dashboard's Network page on the command line (docs/syslog-map-graphic.md, docs/DESIGN.md
// §19):
//
//	att-monitor network [--range 1h|24h|7d|30d | --from TIME --to TIME] [--device KEY] [--firewall]
//	                    [--limit N] [--json] [--data DIR]
//
// The running service builds the page's views: it alone opens the connection store, which has a
// single writer, and it keeps the IP database and the views' caches. The command therefore asks
// its API - GET /api/network/connections, or /api/network/firewall with --firewall, and
// /api/network/status for the samplers - and prints a short summary in this PC's local time.
// None of it is evidence.

// networkUsage is the usage of the network command.
const networkUsage = "usage: att-monitor network [--range 1h|24h|7d|30d | --from TIME --to TIME] [--device KEY] [--firewall] [--limit N] [--json] [--data DIR]"

// Sizes of the summary.
const (
	// networkDefaultLimit is how many table rows are asked for without --limit: a summary for a
	// terminal (--limit, up to web.MaxNetworkLimit, asks for more).
	networkDefaultLimit = 20
	// netTopDevices and netTopCountries: how many of the period's devices and countries are listed.
	netTopDevices   = 10
	netTopCountries = 10
	// Names are cut to these many characters in the tables: they come from the gateway's Device
	// List, the IP database and reverse DNS, and may be of any length.
	netNameChars = 28
	netPTRChars  = 40
)

func cmdNetwork(args []string) error { return networkCommand(os.Stdout, args) }

// networkCommand runs `att-monitor network …`, writing to out: the connections of the period
// (which device talked to which site, from the samples of the gateway's NAT table) or, with
// --firewall, what the gateway's firewall dropped (from its syslog). Wrong arguments are refused
// before the service is asked.
func networkCommand(out io.Writer, args []string) error {
	fs, data := newFlags("network")
	rng := fs.String("range", "", "the period, ending now: "+strings.Join(web.NetworkRanges, ", ")+" (default "+web.DefaultNetworkRange+")")
	from := fs.String("from", "", "the start of the period: YYYY-MM-DD, YYYY-MM-DDTHH:MM (local time) or RFC 3339 "+
		"(default: 24 hours before --to, or the start of its day when --to is a date alone)")
	to := fs.String("to", "", "the end of the period (default now); a date alone includes that whole day, as far as it has gone")
	device := fs.String("device", "", "only this device's connections: its key, as the list of devices shows it (mac:…, ip:…, gateway)")
	firewall := fs.Bool("firewall", false, "what the gateway's firewall dropped (from its syslog) instead of the connections")
	limit := fs.Int("limit", networkDefaultLimit, fmt.Sprintf("table rows: the most seen connections, or the blocked outbound destinations with the most packets (1 to %d)", web.MaxNetworkLimit))
	asJSON := fs.Bool("json", false, "print the service's answer (GET /api/network/connections, or /firewall) as JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q\n%s", fs.Arg(0), networkUsage)
	}
	q, err := networkPeriod(*rng, *from, *to, now(), time.Local)
	if err != nil {
		return err
	}
	if *device != "" {
		if *firewall {
			return errors.New("--device: the firewall view is not per device (the syslog names addresses, not devices); leave out --device or --firewall")
		}
		if !deviceKeyOK(*device) {
			return fmt.Errorf("--device: a device key, as the list of devices shows it (mac:…, ip:…, gateway): at most %d printable characters, no spaces",
				web.MaxNetworkDeviceChars)
		}
		q.Set("device", *device)
	}
	if *limit < 1 || *limit > web.MaxNetworkLimit {
		return fmt.Errorf("--limit must be 1 to %d", web.MaxNetworkLimit)
	}
	q.Set("limit", strconv.Itoa(*limit))
	dataDir := defaultDataDir(*data)
	api, ok := lookupService(dataDir)
	if !ok {
		paths := config.PathsFor(dataDir)
		return fmt.Errorf("the service is not running (its dashboard does not answer), and the Network page's views are built by it: "+
			"start it with `att-monitor start`. The connection samples are kept in %s, the firewall messages with the syslog in %s",
			paths.Connections, paths.Syslog)
	}
	ctx := background()
	if *firewall {
		var fw model.NetFirewall
		if err := api.do(ctx, http.MethodGet, "/api/network/firewall?"+q.Encode(), nil, &fw); err != nil {
			return networkError(err)
		}
		if *asJSON {
			return writeJSON(out, fw)
		}
		printFirewall(out, fw, networkStatus(api))
		return nil
	}
	var nc model.NetConnections
	if err := api.do(ctx, http.MethodGet, "/api/network/connections?"+q.Encode(), nil, &nc); err != nil {
		return networkError(err)
	}
	if *asJSON {
		return writeJSON(out, nc)
	}
	printConnections(out, nc, networkStatus(api))
	return nil
}

// networkPeriod returns the period parameters of a request: range= (one of web.NetworkRanges;
// the default), or from= and to= in RFC 3339 UTC. Times without a zone, and dates, are in loc (this
// PC's local time). A date alone as --to includes that whole day, as far as it has gone, and
// without --from is that day alone (from its midnight in loc: a day of 23 or 25 hours when the
// clocks change); otherwise --from defaults to 24 hours before --to, and --to to now. The period is
// checked as the service checks it: from before to, at most web.MaxNetworkSpan (31 days of 24
// hours) long, ending at most web.NetworkFutureSlack after now.
func networkPeriod(rng, from, to string, now time.Time, loc *time.Location) (url.Values, error) {
	v := url.Values{}
	switch {
	case rng != "" && (from != "" || to != ""):
		return nil, errors.New("--range cannot be combined with --from or --to: give a period ending now, or the start and the end of one")
	case rng != "":
		if !slices.Contains(web.NetworkRanges, rng) {
			return nil, fmt.Errorf("--range %q: use one of %s", rng, strings.Join(web.NetworkRanges, ", "))
		}
		v.Set("range", rng)
		return v, nil
	case from == "" && to == "":
		v.Set("range", web.DefaultNetworkRange)
		return v, nil
	}
	end := now
	var start time.Time
	dayAlone := false // start is the midnight of a date alone as --to
	if to != "" {
		t, err := parseWhenIn(strings.TrimSpace(to), loc)
		if err != nil {
			return nil, fmt.Errorf("--to: %w", err)
		}
		end = t
		if isDateOnly(to) {
			// Through that day: the whole day, or as far as it has gone. Without --from, that day
			// alone - from its own midnight, not 24 hours before its end, which is another hour of
			// the day on the days the clocks change.
			if end = t.AddDate(0, 0, 1); end.After(now) {
				end = now
			}
			if from == "" {
				if !t.Before(now) {
					return nil, fmt.Errorf("--to %s: that day has not begun yet", strings.TrimSpace(to))
				}
				start, dayAlone = t, true
			}
		}
	}
	if !dayAlone {
		start = end.Add(-24 * time.Hour)
	}
	if from != "" {
		t, err := parseWhenIn(strings.TrimSpace(from), loc)
		if err != nil {
			return nil, fmt.Errorf("--from: %w", err)
		}
		start = t
	}
	switch {
	case !start.Before(end):
		return nil, errors.New("--from must be before --to")
	case end.Sub(start) > web.MaxNetworkSpan:
		return nil, spanError(start, end, loc)
	case end.After(now.Add(web.NetworkFutureSlack)):
		return nil, errors.New("--to may be at most an hour from now")
	}
	v.Set("from", start.UTC().Format(time.RFC3339Nano))
	v.Set("to", end.UTC().Format(time.RFC3339Nano))
	return v, nil
}

// spanError refuses a period [start, end) longer than the service's web.MaxNetworkSpan, which is
// 31 days of 24 hours: 31 whole days in loc that include the change back from summer time are an
// hour longer than that, which the error then says.
func spanError(start, end time.Time, loc *time.Location) error {
	limit := web.MaxNetworkSpan
	msg := fmt.Sprintf("--from and --to may be at most %d days of 24 hours (%d hours) apart", limit/(24*time.Hour), limit/time.Hour)
	_, offStart := start.In(loc).Zone()
	_, offEnd := end.In(loc).Zone()
	if back := time.Duration(offStart-offEnd) * time.Second; back > 0 && end.Sub(start) <= limit+back {
		msg += fmt.Sprintf(": this period is %s hours long, because the clocks go back in it (give a shorter period, or times)",
			strconv.FormatFloat(end.Sub(start).Hours(), 'f', -1, 64))
	}
	return errors.New(msg)
}

// deviceKeyOK reports whether k can be a device key, by the service's rule: 1 to
// web.MaxNetworkDeviceChars printable ASCII characters without spaces.
func deviceKeyOK(k string) bool {
	if k == "" || len(k) > web.MaxNetworkDeviceChars {
		return false
	}
	for i := 0; i < len(k); i++ {
		if c := k[i]; c <= ' ' || c > '~' {
			return false
		}
	}
	return true
}

// networkError explains the answer of a service that has no network endpoints at all - an older
// version, whose router answers any unknown path "not found" - and passes any other error on (a
// service that has the endpoints says why it cannot answer).
func networkError(err error) error {
	var se *serviceError
	if errors.As(err, &se) && se.Status == http.StatusNotFound && se.msg == "not found" {
		return fmt.Errorf("%w: the running service has no Network page (it is an older version of att-monitor): "+
			"install this version to upgrade it (att-monitor install, or setup)", err)
	}
	return err
}

// networkStatus returns the service's GET /api/network/status (nil when it cannot be read: the
// summary then leaves out what it says).
func networkStatus(api *apiClient) *model.NetworkStatus {
	var ns model.NetworkStatus
	if err := api.do(background(), http.MethodGet, "/api/network/status", nil, &ns); err != nil {
		return nil
	}
	return &ns
}

// ------------------------------------------------------------------ connections

// printConnections prints a GET /api/network/connections answer: the period, the NAT reads in
// it and how the samplers fare (ns, when known), the totals, the devices, the organisations and
// the countries, and the connections most seen.
func printConnections(out io.Writer, nc model.NetConnections, ns *model.NetworkStatus) {
	fmt.Fprintf(out, "Connections %s to %s (this PC's local time): which device talked to which site, from reads of the gateway's NAT table\n",
		localTime(nc.From, "2006-01-02 15:04"), localTime(nc.To, "2006-01-02 15:04"))
	layout := rowLayout(nc.From, nc.To, time.Local)
	names := map[string]model.NetDevice{}
	for _, d := range nc.Devices {
		names[d.Key] = d
	}
	if nc.Device != "" {
		label := "not seen in this period"
		if d, ok := names[nc.Device]; ok {
			label = deviceLabel(d)
		}
		fmt.Fprintf(out, "Device:      %s (%s)\n", label, terminalSafe(nc.Device))
	}
	if nc.Samples == 0 {
		fmt.Fprintln(out, "NAT reads:   none in this period")
	} else {
		s := fmt.Sprintf("NAT reads:   %d, from %s to %s; the newest listed %s", nc.Samples, localTime(nc.First, layout),
			localTime(nc.Last, layout), plural(nc.Open, "open connection", "open connections"))
		if nc.Device != "" {
			s += fmt.Sprintf(", %d of them the device's", nc.OpenDevice)
		}
		if nc.InUse >= 0 && nc.Available >= 0 {
			s += fmt.Sprintf(" (the gateway counted %d sessions in use, %d available)", nc.InUse, nc.Available)
		}
		fmt.Fprintln(out, s)
	}
	printSamplers(out, ns)
	if nc.Samples > 0 {
		t := nc.Totals
		fmt.Fprintf(out, "Totals:      %s, %s (remote addresses), %s, %s\n", plural(t.Devices, "device", "devices"),
			plural(t.Sites, "site", "sites"), plural(t.Orgs, "organisation", "organisations"), plural(t.Countries, "country", "countries"))
		if nc.FlowsLeftOut > 0 {
			fmt.Fprintf(out, "             %s too light to count one by one in so busy a period count only in their devices and as Other;"+
				" the sites and organisations are at least the numbers shown\n", plural(nc.FlowsLeftOut, "connection", "connections"))
		}
		printNetDevices(out, nc)
		printNetOrgs(out, nc.Orgs)
		printConnCountries(out, nc.Countries)
		printConnRows(out, nc, names, layout)
		fmt.Fprintln(out, "SEEN counts the connections open at each NAT read, READS the reads that listed a connection. A connection that"+
			" opens and closes between two reads is not seen. IPv6 connections are listed too.")
	}
	printIPDB(out, nc.IPDB, ns)
	printConfigWarnings(out, ns)
}

// printSamplers says how the NAT table and Device List reads fare, as the service's status says
// (nothing when it says nothing).
func printSamplers(out io.Writer, ns *model.NetworkStatus) {
	if ns == nil || ns.Samplers == nil {
		return
	}
	smp := ns.Samplers
	switch {
	case !smp.Enabled:
		fmt.Fprintln(out, "NAT table:   not read: connections.enabled is false in config.json (what is shown was recorded before)")
		return
	case smp.NATProblem != "":
		fmt.Fprintln(out, "NAT table:  ", terminalSafe(smp.NATProblem))
	case smp.NATAt != "":
		s := fmt.Sprintf("NAT table:   read every %s, last at %s", terminalSafe(smp.Interval), localTime(smp.NATAt, "2006-01-02 15:04"))
		if smp.NATNext != "" {
			s += ", next at " + localTime(smp.NATNext, "15:04")
		}
		fmt.Fprintln(out, s)
	case smp.NATNext != "":
		fmt.Fprintf(out, "NAT table:   not read yet; the first read is due at %s\n", localTime(smp.NATNext, "2006-01-02 15:04"))
	}
	if smp.NATProblem == "" && smp.NATNote != "" {
		// The newest read worked, but did not keep everything (said above as read).
		fmt.Fprintln(out, "             but", terminalSafe(smp.NATNote))
	}
	if smp.NATLogins > 0 {
		fmt.Fprintf(out, "             the reads needed %s in the last 24 hours\n", plural(smp.NATLogins, "gateway login", "gateway logins"))
	}
	if smp.DevicesProblem != "" {
		fmt.Fprintln(out, "Device List:", terminalSafe(smp.DevicesProblem))
	}
}

// printNetDevices lists the period's devices, the busiest first (at most netTopDevices), each with
// its key for --device.
func printNetDevices(out io.Writer, nc model.NetConnections) {
	if len(nc.Devices) == 0 {
		return
	}
	fmt.Fprintln(out, "Devices:")
	tw := newTable(out)
	fmt.Fprintln(tw, "  DEVICE\tADDRESS\tCONNECTION\tKEY (FOR --device)\tSEEN\tSITES")
	for i, d := range nc.Devices {
		if i == netTopDevices {
			break
		}
		fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\t%d\t%d\n", terminalSafe(clip(d.Name, netNameChars)), dash(d.IPv4), dash(d.Connection),
			terminalSafe(d.Key), d.Weight, d.Sites)
	}
	tw.Flush()
	if n := len(nc.Devices) - netTopDevices; n > 0 {
		fmt.Fprintf(out, "  and %s more\n", plural(n, "device", "devices"))
	}
}

// printNetOrgs lists the organisations of the flow diagram (the busiest, then the others grouped).
func printNetOrgs(out io.Writer, orgs []model.NetOrg) {
	if len(orgs) == 0 {
		return
	}
	fmt.Fprintln(out, "Organisations:")
	tw := newTable(out)
	fmt.Fprintln(tw, "  ORGANISATION\tCOUNTRY\tSEEN\tSITES")
	for _, o := range orgs {
		name := terminalSafe(clip(o.Name, netNameChars))
		switch {
		case o.Key == "other":
			name = "Other (" + plural(o.Members, "organisation", "organisations") + ")"
		case len(o.ASNs) > 1: // one company's ASes, one organisation
			asns := make([]string, len(o.ASNs))
			for i, a := range o.ASNs {
				asns[i] = "AS" + strconv.Itoa(a)
			}
			name += " (" + strings.Join(asns, ", ") + ")"
		case o.ASN > 0:
			name += " (AS" + strconv.Itoa(o.ASN) + ")"
		}
		fmt.Fprintf(tw, "  %s\t%s\t%d\t%d\n", name, countryText(o.Country), o.Weight, o.Sites)
	}
	tw.Flush()
}

// printConnCountries lists the countries of the remote addresses by their sites.
func printConnCountries(out io.Writer, cs []model.NetCountry) {
	if len(cs) == 0 {
		return
	}
	fmt.Fprintln(out, "Countries:   "+countriesText(cs, func(c model.NetCountry) int { return c.Sites }, "sites"))
}

// printConnRows lists the connections most seen: device -> remote address (its reverse DNS
// name), organisation, country, service, when first and last seen, and in how many NAT reads.
func printConnRows(out io.Writer, nc model.NetConnections, names map[string]model.NetDevice, layout string) {
	if len(nc.Rows) == 0 {
		return
	}
	if nc.RowsTotal > len(nc.Rows) {
		fmt.Fprintf(out, "Connections: the %d most seen of %d%s\n", len(nc.Rows), nc.RowsTotal, moreRows(len(nc.Rows)))
	} else {
		fmt.Fprintf(out, "Connections: %d\n", len(nc.Rows))
	}
	tw := newTable(out)
	fmt.Fprintln(tw, "  DEVICE\t\tREMOTE\tORGANISATION\tCOUNTRY\tSERVICE\tFIRST\tLAST\tREADS")
	for _, r := range nc.Rows {
		dev := r.Device
		if d, ok := names[r.Device]; ok {
			dev = d.Name
		}
		arrow, svc := "->", serviceText(r.Service, r.Proto, r.Port)
		if r.Inbound {
			arrow, svc = "<-", svc+" (inbound)"
		}
		remote := terminalSafe(r.Remote)
		if r.PTR != "" {
			remote += " (" + terminalSafe(clip(r.PTR, netPTRChars)) + ")"
		}
		fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%d\n", terminalSafe(clip(dev, netNameChars)), arrow, remote,
			orgText(r.Org, r.ASN, r.Kind), countryText(r.Country), svc, localTime(r.First, layout), localTime(r.Last, layout), r.Samples)
	}
	tw.Flush()
}

// ------------------------------------------------------------------ firewall

// printFirewall prints a GET /api/network/firewall answer: the period, the drops by direction,
// the sources and their countries, the services probed, the reasons and the LAN devices'
// packets that were blocked on their way out.
func printFirewall(out io.Writer, fw model.NetFirewall, ns *model.NetworkStatus) {
	fmt.Fprintf(out, "Firewall %s to %s (this PC's local time): what the gateway's firewall dropped, from its syslog\n",
		localTime(fw.From, "2006-01-02 15:04"), localTime(fw.To, "2006-01-02 15:04"))
	layout := rowLayout(fw.From, fw.To, time.Local)
	if oldest, err := time.Parse(time.RFC3339Nano, fw.Oldest); err == nil {
		if from, err := time.Parse(time.RFC3339Nano, fw.From); err == nil && oldest.After(from) {
			fmt.Fprintf(out, "Note:        the syslog kept starts at %s: what the gateway logged before was not received here, or is no longer kept\n",
				localTime(fw.Oldest, "2006-01-02 15:04"))
		}
	}
	if fw.Drops == 0 {
		fmt.Fprintln(out, "Dropped:     nothing in this period (the gateway logs only the packets it drops, never the connections it allows)")
		printIPDB(out, fw.IPDB, ns)
		printConfigWarnings(out, ns)
		return
	}
	fmt.Fprintf(out, "Dropped:     %s: %d inbound (from the Internet), %d outbound (from the home network), %d local (the gateway's own, or between the home network and the gateway)\n",
		plural(fw.Drops, "packet", "packets"), fw.Inbound, fw.Outbound, fw.Local)
	if fw.Sources > 0 {
		s := "Sources:     " + plural(fw.Sources, "Internet address", "Internet addresses")
		if len(fw.Countries) > 0 {
			s += "; packets by country: " + countriesText(fw.Countries, func(c model.NetCountry) int { return c.Weight }, "")
		}
		fmt.Fprintln(out, s)
	}
	if len(fw.TopSources) > 0 {
		fmt.Fprintln(out, "Top sources:")
		tw := newTable(out)
		fmt.Fprintln(tw, "  ADDRESS\tORGANISATION\tCOUNTRY\tPACKETS\tPORTS\tLAST")
		for _, s := range fw.TopSources {
			fmt.Fprintf(tw, "  %s\t%s\t%s\t%d\t%d\t%s\n", terminalSafe(s.Addr), orgText(s.Org, s.ASN, ""), countryText(s.Country),
				s.Count, s.Ports, localTime(s.Last, layout))
		}
		tw.Flush()
	}
	if len(fw.Services) > 0 {
		fmt.Fprintln(out, "Probed services (what the inbound packets tried to reach):")
		tw := newTable(out)
		for _, s := range fw.Services {
			name := "Other ports"
			if s.Port > 0 || s.Proto != "" {
				name = serviceText(clip(s.Name, netNameChars), s.Proto, s.Port)
			}
			fmt.Fprintf(tw, "  %s\t%d\n", name, s.Count)
		}
		tw.Flush()
	}
	if len(fw.Reasons) > 0 {
		fmt.Fprintln(out, "Reasons:")
		tw := newTable(out)
		for _, r := range fw.Reasons {
			label := terminalSafe(r.Label)
			if r.Reason != "" && r.Reason != "*" {
				label += " (" + terminalSafe(r.Reason) + ")"
			}
			fmt.Fprintf(tw, "  %s\t%d\n", label, r.Count)
		}
		tw.Flush()
	}
	printOutRows(out, fw, layout)
	printIPDB(out, fw.IPDB, ns)
	printConfigWarnings(out, ns)
}

// printOutRows lists the LAN devices' packets that the firewall blocked on their way out, by
// destination, the most first.
func printOutRows(out io.Writer, fw model.NetFirewall, layout string) {
	if fw.OutboundTotal == 0 && len(fw.OutboundRows) == 0 {
		return
	}
	s := fmt.Sprintf("Blocked on the way out: %s, from %s", plural(fw.OutboundTotal, "destination", "destinations"),
		plural(fw.OutboundDevices, "device", "devices"))
	if len(fw.OutboundRows) < fw.OutboundTotal {
		s += fmt.Sprintf("; the %d with the most packets%s", len(fw.OutboundRows), moreRows(len(fw.OutboundRows)))
	}
	fmt.Fprintln(out, s+":")
	tw := newTable(out)
	fmt.Fprintln(tw, "  DEVICE\t\tDESTINATION\tORGANISATION\tCOUNTRY\tSERVICE\tREASON\tPACKETS\tLAST")
	for _, r := range fw.OutboundRows {
		dev := r.Name
		if dev == "" {
			dev = r.LAN
		}
		reason := r.Label
		if reason == "" {
			reason = r.Reason
		}
		fmt.Fprintf(tw, "  %s\t->\t%s\t%s\t%s\t%s\t%s\t%d\t%s\n", terminalSafe(clip(dev, netNameChars)), terminalSafe(r.Remote),
			orgText(r.Org, r.ASN, ""), countryText(r.Country), serviceText(r.Service, r.Proto, r.Port),
			terminalSafe(clip(reason, netNameChars)), r.Count, localTime(r.Last, layout))
	}
	tw.Flush()
}

// ------------------------------------------------------------------ shared

// printIPDB says which IP database named the addresses (ipdb: when it was written; "" none).
func printIPDB(out io.Writer, ipdb string, ns *model.NetworkStatus) {
	if ipdb != "" {
		fmt.Fprintf(out, "IP database: IPtoASN of %s (countries are where the networks are registered)\n", localTime(ipdb, "2006-01-02"))
		return
	}
	s := "IP database: none loaded, so organisations and countries are not shown"
	if ns != nil && ns.IPIntel != nil {
		switch ip := ns.IPIntel; {
		case !ip.Enabled:
			s += " (geo.enabled is false in config.json)"
		case ip.Error != "":
			s += " (" + terminalSafe(ip.Error) + ")"
		case ip.Download:
			s += " yet (it is being downloaded)"
		}
	}
	fmt.Fprintln(out, s)
}

// printConfigWarnings lists the settings of the Network page that the service could not use as
// written in config.json, each with what it uses instead, as its status says (nothing when it says
// nothing).
func printConfigWarnings(out io.Writer, ns *model.NetworkStatus) {
	if ns == nil {
		return
	}
	for _, w := range ns.ConfigWarnings {
		fmt.Fprintln(out, "config.json:", terminalSafe(w))
	}
}

// rowLayout is how the times within the period [from, to) are shown in the time zone loc: the
// time of day when the period lies within one day there, else the date and the time of day.
func rowLayout(from, to string, loc *time.Location) string {
	f, err1 := time.Parse(time.RFC3339Nano, from)
	t, err2 := time.Parse(time.RFC3339Nano, to)
	if err1 == nil && err2 == nil {
		fl, tl := f.In(loc), t.Add(-time.Nanosecond).In(loc)
		if fl.Year() == tl.Year() && fl.YearDay() == tl.YearDay() {
			return "15:04"
		}
	}
	return "01-02 15:04"
}

// moreRows says how to see more than the n table rows shown ("" when the service gives no more).
func moreRows(n int) string {
	if n >= web.MaxNetworkLimit {
		return ""
	}
	return fmt.Sprintf(" (--limit shows more, up to %d)", web.MaxNetworkLimit)
}

// newTable returns a writer that aligns tab-separated columns.
func newTable(out io.Writer) *tabwriter.Writer { return tabwriter.NewWriter(out, 0, 0, 2, ' ', 0) }

// clip cuts s to at most n characters, the last of them "…" when it was cut.
func clip(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)
	return string(r[:n-1]) + "…"
}

// deviceLabel names a device: its name, and its LAN address when that is not the name.
func deviceLabel(d model.NetDevice) string {
	s := terminalSafe(d.Name)
	if d.IPv4 != "" && d.IPv4 != d.Name {
		s += ", " + terminalSafe(d.IPv4)
	}
	return s
}

// orgText names the network of an address: its organisation and AS number, else what kind of
// address it is (kind, when known), else "unknown".
func orgText(org string, asn int, kind string) string {
	switch {
	case org != "" && asn > 0:
		return terminalSafe(clip(org, netNameChars)) + " (AS" + strconv.Itoa(asn) + ")"
	case org != "":
		return terminalSafe(clip(org, netNameChars))
	case asn > 0:
		return "AS" + strconv.Itoa(asn)
	case kind != "" && kind != model.IPKindPublic:
		return terminalSafe(kind) + " address"
	}
	return "unknown"
}

// countryText is a country code as shown ("-" when not known).
func countryText(code string) string {
	if code == "" {
		return "-"
	}
	return terminalSafe(code)
}

// countriesText lists countries with a number each (value), the first netTopCountries: "US 40,
// NL 5, unknown 2"; unit follows the list ("sites").
func countriesText(cs []model.NetCountry, value func(model.NetCountry) int, unit string) string {
	parts := make([]string, 0, min(len(cs), netTopCountries))
	for i, c := range cs {
		if i == netTopCountries {
			break
		}
		code := "unknown"
		if c.Code != "" {
			code = terminalSafe(c.Code)
		}
		parts = append(parts, code+" "+strconv.Itoa(value(c)))
	}
	s := strings.Join(parts, ", ")
	if unit != "" {
		s += " " + unit
	}
	if n := len(cs) - netTopCountries; n > 0 {
		s += fmt.Sprintf(" (and %s more)", plural(n, "country", "countries"))
	}
	return s
}

// serviceText names a service with its protocol and port: "HTTPS tcp/443", "tcp/8443", "ICMP" (a
// name that only repeats the protocol and the port, such as "tcp 8443", is not shown twice).
func serviceText(name, proto string, port int) string {
	p := portText(proto, port)
	n := strings.ToLower(strings.TrimSpace(name))
	switch {
	case p == "":
		return terminalSafe(name)
	case n == "":
		return p
	case n == p || n == strings.Replace(p, "/", " ", 1):
		if port == 0 {
			return terminalSafe(name) // "ICMP" rather than "icmp"
		}
		return p
	}
	return terminalSafe(name) + " " + p
}

// dash is s as shown, "-" when empty.
func dash(s string) string {
	if s == "" {
		return "-"
	}
	return terminalSafe(s)
}

// portText is a protocol and port as shown: "tcp/443", "icmp" ("" when neither is known).
func portText(proto string, port int) string {
	proto = terminalSafe(strings.ToLower(proto))
	switch {
	case port > 0 && proto != "":
		return proto + "/" + strconv.Itoa(port)
	case port > 0:
		return "port " + strconv.Itoa(port)
	}
	return proto
}
