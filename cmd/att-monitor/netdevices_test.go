package main

import (
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"attmonitor/internal/model"
)

// netDevices is a Devices answer for the 24 hours before testNow: three devices - one whose name
// holds a terminal escape, one with two warnings that did not answer the newest LAN scan, one off
// without a name that answered it at an address the gateway does not list - and two of three
// unknown addresses, one of them self-assigned, the other found by the LAN scan too.
func netDevices() model.NetDevicesView {
	issue := func(code, level, text string) model.NetIssue {
		return model.NetIssue{Code: code, Level: level, Text: text}
	}
	return model.NetDevicesView{
		From: ts(-24 * time.Hour), To: ts(0), ListAt: ts(-10 * time.Minute), Reads: 96, NATReads: 360, NATAt: ts(-2 * time.Minute),
		Totals: model.NetDeviceTotals{Listed: 3, Online: 2, WiFi: 2, Wired: 1, Issues: 5, Unknown: 3, Scanned: 12},
		Scans:  24,
		Scan:   &model.NetScanInfo{At: ts(-5 * time.Minute), Subnet: "192.168.1.0/24", Asked: 254, Answered: 12, TookMs: 4200},
		Devices: []model.NetLANDevice{
			{Key: "mac:00:00:5e:00:53:26", Name: "Cam\x1b[2Jera", MAC: "00:00:5e:00:53:26", IPv4: "192.168.1.71", Status: "on", Allocation: "dhcp",
				Connection: "Wi-Fi 5 GHz", Signal: 4, Seen: ts(-10 * time.Minute), OnReads: 1, Reads: 1,
				ScanAddr: "192.168.1.71", ScanSeen: ts(-5 * time.Minute), ScanHits: 1,
				Issues: []model.NetIssue{issue(model.IssueAddressShared, model.IssueCritical,
					"192.168.1.71 is also claimed by printer (00:00:5e:00:53:25) in the newest Device List read (an address conflict).")}},
			{Key: "mac:00:00:5e:00:53:23", Name: "desk-pc", MAC: "00:00:5e:00:53:23", IPv4: "192.168.1.66", Status: "on", Allocation: "static",
				Connection: "Ethernet LAN-2", Speed: "10Mbps halfduplex", Seen: ts(-10 * time.Minute), OnReads: 96, Reads: 96, Open: 5, Sites: 12,
				Blocked: 150, BlockedIn: 3, ScanSeen: ts(-65 * time.Minute), ScanHits: 22, Issues: []model.NetIssue{
					issue(model.IssueBlocked, model.IssueWarning, "In this period the gateway's firewall dropped 150 packets it sent toward the Internet and 3 packets sent to it from the Internet."),
					issue(model.IssueSlowLink, model.IssueWarning, `Its Ethernet link runs at 10 Mb/s, half duplex (the gateway shows "10Mbps halfduplex"); Ethernet normally runs at 100 or 1000 Mb/s, full duplex.`),
					issue(model.IssueNoAnswer, model.IssueInfo, "The newest Device List read shows it on, but it did not answer the newest LAN scan (made 5 min after that read); a device that sleeps may not answer.")}},
			{Key: "mac:00:00:5e:00:53:24", MAC: "00:00:5e:00:53:24", Status: "off", Connection: "Wi-Fi", LastActivity: "Mon Oct 5 12:01:00 2026",
				Reads: 96, ScanAddr: "192.168.1.90", ScanSeen: ts(-5 * time.Minute), ScanHits: 3, Issues: []model.NetIssue{
					issue(model.IssueScanAddr, model.IssueInfo, "It answered the newest LAN scan at 192.168.1.90; the gateway lists no IPv4 address for it."),
					issue(model.IssueOffline, model.IssueInfo,
						"The newest Device List read shows it off, and no read of this period showed it on. The gateway gives its last activity as Mon Oct 5 12:01:00 2026\u202e.")}},
		},
		Unknown: []model.NetUnknownAddr{
			{Addr: "192.168.1.150", First: ts(-5 * time.Hour), Last: ts(-time.Hour), Open: 2, Sites: 3, Blocked: 1, MAC: "00:00:5e:00:53:99",
				ScanSeen: ts(-5 * time.Minute),
				Issues:   []model.NetIssue{issue(model.IssueUnlisted, model.IssueWarning, "No Device List read of this period names 192.168.1.150.")}},
			{Addr: "169.254.7.7", First: ts(-3 * time.Hour), Last: ts(-3 * time.Hour), BlockedIn: 1,
				Issues: []model.NetIssue{issue(model.IssueUnlisted, model.IssueWarning, "No Device List read of this period names 169.254.7.7.")}},
		},
		Addresses: []model.NetAddrUse{{Addr: "192.168.1.71", Device: "mac:00:00:5e:00:53:26", Name: "camera", First: ts(-10 * time.Minute),
			Last: ts(-10 * time.Minute), Reads: 1, Shared: 1}},
	}
}

// TestNetworkDevices: the Devices view, through GET /api/network/devices and /api/network/status:
// the reads and the LAN scans, the DHCP table in the service's order, the issues in words and the
// unknown addresses, in local time, with every text the gateway gave escaped.
func TestNetworkDevices(t *testing.T) {
	st := netStatus()
	st.Syslog = &model.SyslogUsage{Bytes: 1 << 20, Chunks: 3, Messages: 900, KeepMB: 100}
	st.Samplers.ScanInterval, st.Samplers.ScanAt, st.Samplers.ScanHosts, st.Samplers.ScanNext = "1h0m0s", ts(-5*time.Minute), 12, ts(55*time.Minute)
	f := &fakeNetwork{devs: netDevices(), status: st}
	useNetwork(t, f)
	var out strings.Builder
	if err := networkCommand(&out, []string{"--devices", "--data", t.TempDir()}); err != nil {
		t.Fatal(err)
	}
	if got := f.requests(); !reflect.DeepEqual(got, []string{"/api/network/devices?limit=20&range=24h", "/api/network/status?"}) {
		t.Errorf("requests %q", got)
	}
	dv := f.devs
	lay := rowLayout(dv.From, dv.To, time.Local)
	got := out.String()
	if strings.ContainsRune(got, 0x1b) || strings.ContainsRune(got, 0x202e) {
		t.Errorf("a terminal escape reached the output:\n%s", got)
	}
	seen, scanned := at(ts(-10*time.Minute), lay), at(ts(-5*time.Minute), lay)
	wantText(t, squeeze(got),
		"Devices "+at(dv.From, "2006-01-02 15:04")+" to "+at(dv.To, "2006-01-02 15:04")+
			" (this PC's local time): the gateway's Device List - its DHCP table - with what this period says about each device\n",
		"Device List: 3 devices listed, 2 on (2 on Wi-Fi, 1 on Ethernet), as read at "+at(dv.ListAt, "2006-01-02 15:04")+"; 96 reads in this period\n",
		"NAT reads: 360 in this period; OPEN counts the connections of the newest, at "+at(dv.NATAt, lay)+"\n",
		"NAT table: read every 4m0s, last at ",
		"LAN scans: 24 in this period; the newest, of 192.168.1.0/24 at "+scanned+": 12 of the 254 addresses asked answered; the next is due at "+
			at(ts(55*time.Minute), "2006-01-02 15:04")+"\n",
		"Issues: 5 devices and addresses with a warning or a critical issue\n",
		"DHCP table:\n STATUS NAME IPV4 MAC CONNECTION ALLOCATION LAST SEEN ON OPEN SITES BLOCKED SCAN ISSUES\n",
		bs(" on Cam~x1b[2Jera 192.168.1.71 00:00:5e:00:53:26 Wi-Fi 5 GHz, 4 bars dhcp "+seen+" 0 0 0/0 answered "+scanned+" address conflict\n"),
		" on desk-pc 192.168.1.66 00:00:5e:00:53:23 Ethernet LAN-2, 10Mbps halfduplex static "+seen+" 5 12 150/3 no answer (last "+
			at(ts(-65*time.Minute), lay)+") blocked, slow link, no scan answer\n",
		" off 00:00:5e:00:53:24 - 00:00:5e:00:53:24 Wi-Fi - - 0 0 0/0 answered "+scanned+" at 192.168.1.90 other address, off\n",
		"Issues of the devices:\n",
		bs(" critical Cam~x1b[2Jera (192.168.1.71): 192.168.1.71 is also claimed by printer (00:00:5e:00:53:25) in the newest Device List read (an address conflict).\n"),
		" warning desk-pc (192.168.1.66): In this period the gateway's firewall dropped 150 packets it sent toward the Internet and 3 packets sent to it from the Internet.\n",
		` warning desk-pc (192.168.1.66): Its Ethernet link runs at 10 Mb/s, half duplex (the gateway shows "10Mbps halfduplex"); Ethernet normally runs at 100 or 1000 Mb/s, full duplex.`+"\n",
		" info desk-pc (192.168.1.66): The newest Device List read shows it on, but it did not answer the newest LAN scan (made 5 min after that read); a device that sleeps may not answer.\n",
		" info 00:00:5e:00:53:24: It answered the newest LAN scan at 192.168.1.90; the gateway lists no IPv4 address for it.\n",
		bs(" info 00:00:5e:00:53:24: The newest Device List read shows it off, and no read of this period showed it on. The gateway gives its last activity as Mon Oct 5 12:01:00 2026~u202e.\n"),
		"Unknown addresses: 3 LAN addresses of the home network that the NAT table, the firewall's drops or the LAN scans show and no Device List read of this period"+
			" names (or whose MAC address none names); the 2 seen last (--limit shows more, up to 1000):\n ADDRESS FIRST LAST OPEN SITES BLOCKED MAC (LAN SCAN) SCANNED\n",
		" 192.168.1.150 "+at(ts(-5*time.Hour), lay)+" "+at(ts(-time.Hour), lay)+" 2 3 1/0 00:00:5e:00:53:99 "+scanned+"\n",
		" 169.254.7.7 (self-assigned) "+at(ts(-3*time.Hour), lay)+" "+at(ts(-3*time.Hour), lay)+" 0 0 0/1 - -\n"+
			" A device gives itself an address in 169.254.0.0/16 (self-assigned) when it gets none from the gateway's DHCP server.\n",
		"The gateway does not show DHCP lease times: its DHCP Server page needs the login, and the monitor does not read it.",
		"SCAN says whether the device answered the newest LAN scan of this period",
		"A device's details and its syslog messages: att-monitor network --devices --key <its MAC address> (an entry without one: "+
			"--key ip:<its address>; an unknown address: --addr <the address>).\n")
	if strings.Contains(got, "no syslog is kept") {
		t.Errorf("the syslog is said not to be kept:\n%s", got)
	}

	// Another period and limit, as for the other views.
	if err := networkCommand(io.Discard, []string{"--devices", "--range", "7d", "--limit", "500", "--data", t.TempDir()}); err != nil {
		t.Fatal(err)
	}
	if got := f.requests(); got[len(got)-2] != "/api/network/devices?limit=500&range=7d" {
		t.Errorf("requests %q", got)
	}
}

// TestNetworkDevicesNotRead: before the first Device List read, without NAT reads in the period
// and without a syslog store, the summary says so - and nothing else.
func TestNetworkDevicesNotRead(t *testing.T) {
	st := netStatus()
	st.Samplers.DevicesProblem = "the Device List could not be read: gateway: GET devices.ha: timeout"
	f := &fakeNetwork{devs: model.NetDevicesView{From: ts(-time.Hour), To: ts(0)}, status: st}
	useNetwork(t, f)
	var out strings.Builder
	if err := networkCommand(&out, []string{"--devices", "--range", "1h", "--data", t.TempDir()}); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	wantText(t, got, "Device List: not read yet\n",
		"NAT reads:   none in this period, so the open connections and sites are not known\n",
		"Device List: the Device List could not be read: gateway: GET devices.ha: timeout\n",
		"LAN scans:   none: connections.scan_interval is 0 in config.json, so the service does not sweep the home network\n",
		"Firewall:    no syslog is kept, so the blocked packets are not known\n",
		"The gateway does not show DHCP lease times")
	for _, s := range []string{"DHCP table:", "Issues", "Unknown addresses"} {
		if strings.Contains(got, s) {
			t.Errorf("an empty answer printed %q:\n%s", s, got)
		}
	}

	// Scans that are made, none in the period yet, the newest attempt failed; a sweep that stopped
	// short; no status at all.
	st.Samplers.ScanInterval, st.Samplers.ScanNext = "1h0m0s", ts(20*time.Minute)
	st.Samplers.ScanProblem = "not made: an incident is open (the gateway is polled for evidence)\x1b[2J"
	out.Reset()
	if err := networkCommand(&out, []string{"--devices", "--range", "1h", "--data", t.TempDir()}); err != nil {
		t.Fatal(err)
	}
	wantText(t, out.String(), "LAN scans:   none in this period, so SCAN is not known; the next is due at "+at(ts(20*time.Minute), "2006-01-02 15:04")+"\n"+
		bs("LAN scan:    not made: an incident is open (the gateway is polled for evidence)~x1b[2J\n"))
	f.mu.Lock()
	f.devs = model.NetDevicesView{From: ts(-time.Hour), To: ts(0), Scans: 1, Devices: []model.NetLANDevice{{Key: "mac:00:00:5e:00:53:01", Status: "on"}},
		Scan: &model.NetScanInfo{At: ts(-30 * time.Minute), Subnet: "192.168.1.0/24", Asked: 120, Answered: 4,
			Problem: "the sweep was stopped after 2m0s with 120 of 254 addresses asked: what answered by then is kept"}}
	f.status = nil
	f.mu.Unlock()
	out.Reset()
	if err := networkCommand(&out, []string{"--devices", "--range", "1h", "--data", t.TempDir()}); err != nil {
		t.Fatal(err)
	}
	wantText(t, squeeze(out.String()), "LAN scans: 1 in this period; the newest, of 192.168.1.0/24 at "+at(ts(-30*time.Minute), "15:04")+
		": 4 of the 120 addresses asked answered\n but the sweep was stopped after 2m0s with 120 of 254 addresses asked: what answered by then is kept\n",
		" on mac:00:00:5e:00:53:01 - - - - - 0 0 0/0 no answer -\n")
}

// TestNetworkDevicesJSONAndErrors: --json prints the service's answer as it is; an older service,
// which has no Devices view, is told apart from a service that cannot answer.
func TestNetworkDevicesJSONAndErrors(t *testing.T) {
	f := &fakeNetwork{devs: netDevices(), status: netStatus()}
	useNetwork(t, f)
	var out strings.Builder
	if err := networkCommand(&out, []string{"--devices", "--json", "--data", t.TempDir()}); err != nil {
		t.Fatal(err)
	}
	var dv model.NetDevicesView
	onlyJSON(t, out.String(), &dv)
	if !reflect.DeepEqual(dv, f.devs) {
		t.Errorf("JSON %+v, want %+v", dv, f.devs)
	}
	for _, r := range f.requests() {
		if strings.HasPrefix(r, "/api/network/status") {
			t.Errorf("--json asked for the status: %q", f.requests())
		}
	}
	f.mu.Lock()
	f.fail, f.failMsg = http.StatusNotFound, "not found"
	f.mu.Unlock()
	if err := networkCommand(io.Discard, []string{"--devices", "--data", t.TempDir()}); err == nil ||
		!strings.Contains(err.Error(), "no Devices view on its Network page (it is an older version of att-monitor)") {
		t.Errorf("an older service: %v", err)
	}
	f.mu.Lock()
	f.fail, f.failMsg = http.StatusServiceUnavailable, "unavailable: netmap: devices view: no connection store"
	f.mu.Unlock()
	if err := networkCommand(io.Discard, []string{"--devices", "--data", t.TempDir()}); err == nil || !strings.Contains(err.Error(), "no connection store") ||
		strings.Contains(err.Error(), "older version") {
		t.Errorf("503: %v", err)
	}
}
