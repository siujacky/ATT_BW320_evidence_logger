package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"attmonitor/internal/model"
	"attmonitor/internal/web"
)

// fakeDevice is the running service's GET /api/network/device as the network command sees it: the
// details it sets, with a warning header; the other paths are its fakeNetwork's, and every request
// is recorded there.
type fakeDevice struct {
	*fakeNetwork
	detail  model.NetDeviceDetail
	warning string // the answer's web.WarningHeader
	fail    int    // answer with this status …
	failMsg string // … and error
}

func (f *fakeDevice) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/api/network/device" {
		f.fakeNetwork.ServeHTTP(w, r)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.asked = append(f.asked, r.URL.Path+"?"+r.URL.RawQuery)
	w.Header().Set("Content-Type", "application/json")
	if f.warning != "" {
		w.Header().Set(web.WarningHeader, f.warning)
	}
	if f.fail != 0 {
		w.WriteHeader(f.fail)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": f.failMsg})
		return
	}
	_ = json.NewEncoder(w).Encode(f.detail)
}

// useDevice makes the network command find f as the running service (as useNetwork does).
func useDevice(t *testing.T, f *fakeDevice) {
	t.Helper()
	f.t = t
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	restore := lookupService
	lookupService = func(string) (*apiClient, bool) { return &apiClient{base: srv.URL, hc: srv.Client()}, true }
	t.Cleanup(func() { lookupService = restore })
	fixClock(t)
}

// netDeviceDetail is the details of a laptop for the 24 hours before testNow: its name holds a
// terminal escape, it moved from .70 to .71, the tablet held .70 after it, and two syslog messages
// name it - one of them with hostile text.
func netDeviceDetail() model.NetDeviceDetail {
	sev := 4
	msg := func(at time.Duration, text string) model.SyslogEntry {
		return model.SyslogEntry{Chunk: "syslog-20261005T2200Z", Seq: 42, SyslogMessage: model.SyslogMessage{RX: ts(at), Src: "192.168.1.254:514",
			Raw: "<12>" + text, Format: "rfc3164", Severity: &sev, Host: "dsldevice", App: "FIREWALL[8512]", Msg: text}}
	}
	return model.NetDeviceDetail{
		From: ts(-24 * time.Hour), To: ts(0),
		Device: &model.NetLANDevice{Key: "mac:00:00:5e:00:53:21", Name: "Lap\x1b[2Jtop", MAC: "00:00:5e:00:53:21", IPv4: "192.168.1.71",
			IPv6: []string{"2001:db8::21"}, Status: "on", Allocation: "dhcp", Connection: "Wi-Fi 5 GHz", Signal: 4, Seen: ts(-10 * time.Minute),
			OnReads: 95, Reads: 96, Addresses: []string{"192.168.1.71", "192.168.1.70"}, Open: 7, Sites: 30, Blocked: 2, BlockedIn: 1,
			ScanAddr: "192.168.1.71", ScanSeen: ts(-5 * time.Minute), ScanHits: 23,
			Issues: []model.NetIssue{{Code: model.IssueAddressChanged, Level: model.IssueInfo,
				Text: "It held 2 IPv4 addresses in this period, the newest first: 192.168.1.71, 192.168.1.70."}}},
		Addresses: []model.NetAddrUse{
			{Addr: "192.168.1.70", Device: "mac:00:00:5e:00:53:21", Name: "Lap\x1b[2Jtop", MAC: "00:00:5e:00:53:21", First: ts(-20 * time.Hour), Last: ts(-3 * time.Hour), Reads: 68},
			{Addr: "192.168.1.70", Device: "mac:00:00:5e:00:53:22", Name: "tablet", MAC: "00:00:5e:00:53:22", First: ts(-2 * time.Hour), Last: ts(-10 * time.Minute), Reads: 8, Shared: 1},
			{Addr: "192.168.1.71", Device: "mac:00:00:5e:00:53:21", Name: "Lap\x1b[2Jtop", MAC: "00:00:5e:00:53:21", First: ts(-150 * time.Minute), Last: ts(-10 * time.Minute), Reads: 10},
		},
		Scans: []model.NetScanSeen{{At: ts(-5 * time.Minute), Addr: "192.168.1.71"}, {At: ts(-65 * time.Minute)}, {At: ts(-125 * time.Minute), Addr: "192.168.1.71"},
			{At: ts(-185 * time.Minute), Addr: "192.168.1.70"}, {At: ts(-245 * time.Minute), Addr: "192.168.1.70"}, {At: ts(-305 * time.Minute), Addr: "192.168.1.70"},
			{At: ts(-365 * time.Minute), Addr: "192.168.1.70"}},
		Match: []model.NetSyslogTerm{
			{Kind: "ipv4", Text: "192.168.1.70", To: ts(-165 * time.Minute)},
			{Kind: "ipv4", Text: "192.168.1.71", From: ts(-165 * time.Minute)},
			{Kind: "ipv6", Text: "2001:db8::21"},
			{Kind: "mac", Text: "00:00:5e:00:53:21"},
		},
		Syslog: []model.SyslogEntry{
			msg(-2*time.Minute, "nflog_log_fw(), action=DROP reason=POLICY IN=br0 OUT=veip0.1 SRC=192.168.1.71 DST=192.0.2.44 \x1b]0;evil\x07"),
			msg(-3*time.Hour, "DHCPACK(br1) 192.168.1.70 00:00:5e:00:53:21 laptop\u202e"),
		},
	}
}

// TestNetworkDeviceDetails: --devices --key prints one device's details through GET
// /api/network/device: who it is, what the period says about it, its issues, who held its addresses,
// the newest LAN scans, what its syslog messages are found by and those messages, newest first -
// every text from the gateway and the syslog escaped.
func TestNetworkDeviceDetails(t *testing.T) {
	st := netStatus()
	st.Syslog = &model.SyslogUsage{Bytes: 1 << 20, Chunks: 3, Messages: 900, KeepMB: 100}
	f := &fakeDevice{fakeNetwork: &fakeNetwork{status: st}, detail: netDeviceDetail()}
	useDevice(t, f)
	var out strings.Builder
	if err := networkCommand(&out, []string{"--devices", "--key", "mac:00:00:5e:00:53:21", "--data", t.TempDir()}); err != nil {
		t.Fatal(err)
	}
	if got := f.requests(); !reflect.DeepEqual(got, []string{"/api/network/device?key=mac%3A00%3A00%3A5e%3A00%3A53%3A21&limit=20&range=24h",
		"/api/network/status?"}) {
		t.Errorf("requests %q", got)
	}
	got := out.String()
	if strings.ContainsRune(got, 0x1b) || strings.ContainsRune(got, 0x202e) || strings.ContainsRune(got, 0x07) {
		t.Errorf("a terminal escape reached the output:\n%s", got)
	}
	dd := f.detail
	lay := rowLayout(dd.From, dd.To, time.Local)
	wantText(t, squeeze(got),
		bs("Device Lap~x1b[2Jtop (mac:00:00:5e:00:53:21), "+at(dd.From, "2006-01-02 15:04")+" to "+at(dd.To, "2006-01-02 15:04")+" (this PC's local time)\n"),
		"Status: on, as the newest Device List read shows it; last seen on at "+at(ts(-10*time.Minute), "2006-01-02 15:04")+"; on in 95 of the 96 reads of this period that list it\n",
		"Addresses: IPv4 192.168.1.71 (dhcp), MAC 00:00:5e:00:53:21, IPv6 2001:db8::21\n",
		"Connection: Wi-Fi 5 GHz, 4 bars\n",
		"Traffic: 7 connections open in the newest NAT read, 30 sites in this period; the firewall dropped 2 it sent / 1 sent to it\n",
		"LAN scans: it answered 23 LAN scans of this period, the newest at 192.168.1.71\n",
		"Issues:\n info It held 2 IPv4 addresses in this period, the newest first: 192.168.1.71, 192.168.1.70.\n",
		"Who held its addresses in this period (as the Device List reads show them):\n ADDRESS DEVICE FIRST READ LAST READ READS\n",
		bs(" 192.168.1.70 Lap~x1b[2Jtop (this device) "+at(ts(-20*time.Hour), lay)+" "+at(ts(-3*time.Hour), lay)+" 68\n"),
		" 192.168.1.70 tablet (another claimed it too in 1 read) "+at(ts(-2*time.Hour), lay)+" "+at(ts(-10*time.Minute), lay)+" 8\n",
		"The newest LAN scans of this period:\n "+at(ts(-5*time.Minute), lay)+" answered at 192.168.1.71\n "+at(ts(-65*time.Minute), lay)+" no answer\n",
		"Syslog: its messages are found by 192.168.1.70 (until "+at(ts(-165*time.Minute), lay)+"), 192.168.1.71 (from "+at(ts(-165*time.Minute), lay)+
			"), 2001:db8::21, 00:00:5e:00:53:21\n",
		"Syslog: 2 messages of this period name it, newest first:\n",
		bs(" "+at(ts(-2*time.Minute), "2006-01-02 15:04:05")+" warning dsldevice FIREWALL[8512]: nflog_log_fw(), action=DROP reason=POLICY IN=br0 OUT=veip0.1 "+
			"SRC=192.168.1.71 DST=192.0.2.44 ~x1b]0;evil~x07\n"),
		bs(" "+at(ts(-3*time.Hour), "2006-01-02 15:04:05")+" warning dsldevice FIREWALL[8512]: DHCPACK(br1) 192.168.1.70 00:00:5e:00:53:21 laptop~u202e\n"))
	if n := strings.Count(got, " answered at ") + strings.Count(got, " no answer\n"); n != detailScansShown {
		t.Errorf("%d scans printed, want %d:\n%s", n, detailScansShown, got)
	}

	// Another period and limit; more messages than the limit.
	f.mu.Lock()
	f.detail.SyslogTruncated = true
	f.mu.Unlock()
	out.Reset()
	if err := networkCommand(&out, []string{"--devices", "--key", "name:Büro PC", "--range", "7d", "--limit", "500", "--data", t.TempDir()}); err != nil {
		t.Fatal(err)
	}
	if got := f.requests(); got[len(got)-2] != "/api/network/device?key=name%3AB%C3%BCro+PC&limit=500&range=7d" {
		t.Errorf("requests %q", got)
	}
	wantText(t, out.String(), "Syslog:      the newest 2 messages that name it; more do (--limit shows more, up to 500, or a shorter period):\n")

	// A MAC address alone, as the DHCP table shows it, is the device's key.
	for _, mac := range []string{"00:00:5E:00:53:21", " 00-00-5e-00-53-21 "} {
		if err := networkCommand(io.Discard, []string{"--devices", "--key", mac, "--data", t.TempDir()}); err != nil {
			t.Fatal(err)
		}
		if got := f.requests(); got[len(got)-2] != "/api/network/device?key=mac%3A00%3A00%3A5e%3A00%3A53%3A21&limit=20&range=24h" {
			t.Errorf("%q: requests %q", mac, got)
		}
	}
}

// TestNetworkDeviceDetailsOfAnUnknownAddress: --addr prints an unknown address's details.
func TestNetworkDeviceDetailsOfAnUnknownAddress(t *testing.T) {
	st := netStatus()
	st.Syslog = &model.SyslogUsage{KeepMB: 100}
	f := &fakeDevice{fakeNetwork: &fakeNetwork{status: st}, detail: model.NetDeviceDetail{From: ts(-time.Hour), To: ts(0),
		Unknown: &model.NetUnknownAddr{Addr: "192.168.1.200", First: ts(-50 * time.Minute), Last: ts(-5 * time.Minute), Open: 1, Sites: 2,
			MAC: "00:00:5e:00:53:99", ScanSeen: ts(-5 * time.Minute), Issues: []model.NetIssue{{Code: model.IssueUnlisted, Level: model.IssueWarning,
				Text: "No Device List read of this period names 192.168.1.200, yet it answered 2 LAN scans of this period (from 00:00:5e:00:53:99)."}}},
		Addresses: []model.NetAddrUse{}, Scans: []model.NetScanSeen{{At: ts(-5 * time.Minute), Addr: "192.168.1.200"}},
		Match: []model.NetSyslogTerm{{Kind: "ipv4", Text: "192.168.1.200"}}, Syslog: []model.SyslogEntry{}}}
	useDevice(t, f)
	var out strings.Builder
	if err := networkCommand(&out, []string{"--devices", "--addr", " 192.168.1.200 ", "--range", "1h", "--data", t.TempDir()}); err != nil {
		t.Fatal(err)
	}
	if got := f.requests(); got[0] != "/api/network/device?addr=192.168.1.200&limit=20&range=1h" {
		t.Errorf("requests %q", got)
	}
	wantText(t, out.String(),
		"Unknown address 192.168.1.200, "+at(ts(-time.Hour), "2006-01-02 15:04")+" to "+at(ts(0), "2006-01-02 15:04")+
			" (this PC's local time): no Device List read of this period names it\n",
		"Seen:        from "+at(ts(-50*time.Minute), "15:04")+" to "+at(ts(-5*time.Minute), "15:04")+"\n",
		"MAC:         00:00:5e:00:53:99 answered for it in the LAN scan of "+at(ts(-5*time.Minute), "15:04")+"\n",
		"Issues:\n  warning   No Device List read of this period names 192.168.1.200",
		"The newest LAN scans of this period:\n  "+at(ts(-5*time.Minute), "15:04")+"  answered at 192.168.1.200\n",
		"Syslog:      its messages are found by 192.168.1.200\n",
		"Syslog:      no message of this period names it\n")
	if strings.Contains(out.String(), "Who held") {
		t.Errorf("an empty address history printed:\n%s", out.String())
	}
}

// TestNetworkDeviceDetailsSyslogStates: a syslog that cannot be read, and none kept, are said in
// words; the ledger's warning is printed (with --json, to standard error, the JSON alone on the
// output).
func TestNetworkDeviceDetailsSyslogStates(t *testing.T) {
	st := netStatus()
	f := &fakeDevice{fakeNetwork: &fakeNetwork{status: st}, detail: netDeviceDetail()}
	useDevice(t, f)
	run := func(args ...string) string {
		t.Helper()
		var out strings.Builder
		if err := networkCommand(&out, append(append([]string{"--devices", "--key", "mac:00:00:5e:00:53:21"}, args...), "--data", t.TempDir())); err != nil {
			t.Fatal(err)
		}
		return out.String()
	}
	f.mu.Lock()
	f.detail.Syslog = []model.SyslogEntry{}
	f.mu.Unlock()
	wantText(t, run(), "Syslog:      no syslog is kept, so its messages are not known\n") // the status has no syslog
	f.mu.Lock()
	f.detail.SyslogError = "the syslog messages could not be read: syslogstore: read chunk x: unexpected EOF\x1b[2J"
	f.mu.Unlock()
	wantText(t, run(), bs("Syslog:      the syslog messages could not be read: syslogstore: read chunk x: unexpected EOF~x1b[2J\n"))

	f.mu.Lock()
	f.detail = netDeviceDetail()
	f.warning = "ledger integrity: #42 h does not match b (run Verify for a full check)"
	f.mu.Unlock()
	wantText(t, run(), "WARNING: ledger integrity: #42 h does not match b (run Verify for a full check)\n")
	var errs strings.Builder
	restore := errOutput
	errOutput = &errs
	t.Cleanup(func() { errOutput = restore })
	before := len(f.requests())
	var dd model.NetDeviceDetail
	onlyJSON(t, run("--json"), &dd)
	if !reflect.DeepEqual(dd, netDeviceDetail()) {
		t.Errorf("JSON %+v", dd)
	}
	if errs.String() != "WARNING: ledger integrity: #42 h does not match b (run Verify for a full check)\n" {
		t.Errorf("standard error %q", errs.String())
	}
	if got := f.requests()[before:]; len(got) != 1 || !strings.HasPrefix(got[0], "/api/network/device?") {
		t.Errorf("--json asked for %q", got)
	}
}

// TestNetworkDeviceDetailsArguments: --key and --addr are refused before the service is asked when
// they cannot name a device; an older service, which has no device details, is told apart from the
// service's own "not found".
func TestNetworkDeviceDetailsArguments(t *testing.T) {
	noService(t, false)
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"--key", "mac:00:00:5e:00:53:21"}, "--key and --addr name a device of the Devices view: give --devices too"},
		{[]string{"--addr", "192.168.1.200"}, "give --devices too"},
		{[]string{"--devices", "--key", "mac:00:00:5e:00:53:21", "--addr", "192.168.1.200"}, "give one of them"},
		{[]string{"--devices", "--key", "name:Cam\x1b[2Jera"}, "--key: a device's MAC address, or its key"},
		{[]string{"--devices", "--key", "name:evil\u202e"}, "--key: a device's MAC address, or its key"},
		{[]string{"--devices", "--key", strings.Repeat("k", web.MaxNetworkDeviceKeyBytes+1)}, "--key: a device's MAC address, or its key"},
		{[]string{"--devices", "--addr", "2001:db8::1"}, `--addr "2001:db8::1": an IPv4 address`},
		{[]string{"--devices", "--addr", "192.168.1"}, "an IPv4 address"},
		{[]string{"--devices", "--key", "mac:00:00:5e:00:53:21", "--limit", "501"}, "--limit must be 1 to 500 with --key or --addr"},
		{[]string{"--devices", "--key", "mac:00:00:5e:00:53:21", "--limit", "0"}, "--limit must be 1 to 500"},
		{[]string{"--devices", "--key", "mac:00:00:5e:00:53:21", "--device", "gateway"}, "--device: the Devices view lists every device"},
		{[]string{"--firewall", "--key", "mac:00:00:5e:00:53:21"}, "give --devices too"},
	} {
		err := networkCommand(io.Discard, append(tc.args, "--data", t.TempDir()))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%q: %v, want %q", tc.args, err, tc.want)
		}
	}

	f := &fakeDevice{fakeNetwork: &fakeNetwork{status: netStatus()}, fail: http.StatusNotFound, failMsg: "not found"}
	useDevice(t, f)
	if err := networkCommand(io.Discard, []string{"--devices", "--key", "mac:00:00:5e:00:53:21", "--data", t.TempDir()}); err == nil ||
		!strings.Contains(err.Error(), "no device details on its Network page (it is an older version of att-monitor)") {
		t.Errorf("an older service: %v", err)
	}
	f.mu.Lock()
	f.failMsg = "not found: the Devices view of this period lists no device with this key"
	f.mu.Unlock()
	if err := networkCommand(io.Discard, []string{"--devices", "--key", "mac:00:00:5e:00:53:ff", "--data", t.TempDir()}); err == nil ||
		err.Error() != "service: not found: the Devices view of this period lists no device with this key" {
		t.Errorf("no such device: %v", err)
	}
	f.mu.Lock()
	f.fail, f.failMsg = http.StatusServiceUnavailable, "network device: netmap: device details: no connection store: unavailable"
	f.mu.Unlock()
	if err := networkCommand(io.Discard, []string{"--devices", "--addr", "192.168.1.200", "--data", t.TempDir()}); err == nil ||
		!strings.Contains(err.Error(), "no connection store") || strings.Contains(err.Error(), "older version") {
		t.Errorf("503: %v", err)
	}
}

func TestReadsKey(t *testing.T) {
	for in, want := range map[string]string{
		"mac:00:00:5e:00:53:21": "mac:00:00:5e:00:53:21", "mac:00:00:5e:00:53:21#2": "mac:00:00:5e:00:53:21",
		"mac:00:00:5e:00:53:21#12": "mac:00:00:5e:00:53:21", "name:Printer #": "name:Printer #", "name:#2": "name:", "#2": "#2", "": "",
	} {
		if got := readsKey(in); got != want {
			t.Errorf("readsKey(%q) = %q, want %q", in, got, want)
		}
	}
}
