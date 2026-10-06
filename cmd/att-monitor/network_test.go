package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
	_ "time/tzdata" // America/Chicago, wherever the tests run

	"attmonitor/internal/model"
	"attmonitor/internal/web"
)

// fakeNetwork is a running service's API as the network command sees it: GET
// /api/network/connections, /api/network/firewall and /api/network/status answered from its
// fields, every request recorded.
type fakeNetwork struct {
	t       *testing.T
	mu      sync.Mutex
	conns   model.NetConnections
	fw      model.NetFirewall
	status  *model.NetworkStatus // nil: /api/network/status answers 404
	fail    int                  // answer the views with this status …
	failMsg string               // … and error
	asked   []string             // "<path>?<query>" of every request
}

// useNetwork makes the network command find f (an httptest server on 127.0.0.1:0) as the running
// service, and fixes its clock.
func useNetwork(t *testing.T, f *fakeNetwork) {
	t.Helper()
	f.t = t
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	restore := lookupService
	lookupService = func(string) (*apiClient, bool) { return &apiClient{base: srv.URL, hc: srv.Client()}, true }
	t.Cleanup(func() { lookupService = restore })
	fixClock(t)
}

func (f *fakeNetwork) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	f.asked = append(f.asked, r.URL.Path+"?"+r.URL.RawQuery)
	if r.Method != http.MethodGet {
		f.t.Errorf("%s %s: the network command only reads", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	switch r.URL.Path {
	case "/api/network/connections", "/api/network/firewall":
		if f.fail != 0 {
			w.WriteHeader(f.fail)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": f.failMsg})
			return
		}
		if r.URL.Path == "/api/network/firewall" {
			_ = json.NewEncoder(w).Encode(f.fw)
			return
		}
		_ = json.NewEncoder(w).Encode(f.conns)
	case "/api/network/status":
		if f.status == nil {
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "not found"})
			return
		}
		_ = json.NewEncoder(w).Encode(f.status)
	default:
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "not found: " + r.URL.Path})
	}
}

// requests returns the requests so far.
func (f *fakeNetwork) requests() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.asked...)
}

// squeeze turns every run of spaces into one, so that a test can look for a table row without
// knowing how wide the columns came out.
func squeeze(s string) string { return regexp.MustCompile(` {2,}`).ReplaceAllString(s, " ") }

// ts formats testNow plus d as the service's answers do.
func ts(d time.Duration) string { return testNow.Add(d).Format(time.RFC3339Nano) }

// netConnections is a connections answer for the 24 hours before testNow: four devices (one with
// a name that holds a terminal escape), the flow diagram's organisations, three countries and
// four rows of nine (a reverse DNS name, a connection from outside, a reserved address, an
// unknown device with hostile names).
func netConnections() model.NetConnections {
	return model.NetConnections{
		From: ts(-24 * time.Hour), To: ts(0), Samples: 15, First: ts(-50 * time.Minute), Last: ts(-2 * time.Minute),
		InUse: 412, Available: 7780, Open: 42,
		Totals: model.NetTotals{Devices: 4, Sites: 57, Orgs: 21, Countries: 6},
		Devices: []model.NetDevice{
			{Key: "mac:00:00:5e:00:53:01", Name: "Office PC", IPv4: "192.168.1.71", MAC: "00:00:5e:00:53:01", Connection: "Ethernet", Weight: 120, Sites: 41},
			{Key: "mac:00:00:5e:00:53:02", Name: "Lap\x1b[2Jtop", IPv4: "192.168.1.64", MAC: "00:00:5e:00:53:02", Connection: "Wi-Fi 5 GHz", Weight: 40, Sites: 9},
			{Key: "ip:192.168.1.80", Name: "192.168.1.80", IPv4: "192.168.1.80", Weight: 3, Sites: 1},
			{Key: "gateway", Name: "Gateway", Weight: 2, Sites: 1},
		},
		Orgs: []model.NetOrg{
			{Key: "as64500", Name: "Example Cloud", ASN: 64500, Country: "US", Weight: 90, Sites: 20},
			{Key: "org:example video", Name: "Example Video", ASN: 64501, ASNs: []int{64501, 64502}, Country: "US", Weight: 20, Sites: 4},
			{Key: "local", Name: "Local network", Weight: 5, Sites: 2},
			{Key: "other", Name: "Other", Weight: 30, Sites: 12, Members: 14},
		},
		Countries: []model.NetCountry{{Code: "US", Sites: 20, Weight: 90}, {Code: "NL", Sites: 5, Weight: 10}, {Code: "", Sites: 2, Weight: 5}},
		Rows: []model.NetConnRow{
			{Device: "mac:00:00:5e:00:53:01", LAN: "192.168.1.71", Remote: "203.0.113.5", PTR: "server-5.example.net", Kind: "public",
				Org: "Example Cloud", ASN: 64500, Country: "US", Service: "HTTPS", Proto: "tcp", Port: 443,
				First: ts(-50 * time.Minute), Last: ts(-2 * time.Minute), Samples: 15, Weight: 30},
			{Device: "mac:00:00:5e:00:53:01", LAN: "192.168.1.71", Remote: "198.51.100.7", Kind: "public", Proto: "tcp", Port: 8443, Inbound: true,
				First: ts(-40 * time.Minute), Last: ts(-36 * time.Minute), Samples: 2, Weight: 2},
			{Device: "gateway", LAN: "198.51.100.1", Remote: "192.0.2.53", Kind: "reserved", Service: "DNS", Proto: "udp", Port: 53,
				First: ts(-30 * time.Minute), Last: ts(-30 * time.Minute), Samples: 1, Weight: 1},
			{Device: "mac:00:00:5e:00:53:99", LAN: "192.168.1.90", Remote: "203.0.113.9", PTR: "evil\x1b[31m.example", Kind: "public",
				Org: "Org\u202eevil", ASN: 64501, Country: "NL", Proto: "icmp", First: ts(-20 * time.Minute), Last: ts(-20 * time.Minute), Samples: 1, Weight: 1},
		},
		RowsTotal: 9,
		IPDB:      "2026-10-04T06:00:00Z",
	}
}

// netStatus is a network status whose samplers read the NAT table regularly.
func netStatus() *model.NetworkStatus {
	return &model.NetworkStatus{
		Samplers: &model.ConnSamplerStatus{Enabled: true, Interval: "4m0s", DevicesInterval: "15m0s", NATAt: ts(-2 * time.Minute),
			NATNext: ts(2 * time.Minute), Sessions: 42, InUse: 412, Available: 7780, DevicesAt: ts(-10 * time.Minute), Devices: 4},
		Store:   &model.ConnStoreUsage{Bytes: 4096, Files: 1, KeepDays: 30, KeepMB: 200},
		IPIntel: &model.IPIntelStatus{Enabled: true, Download: true, Loaded: true, V4Ranges: 500000, V6Ranges: 100000, Updated: "2026-10-04T06:00:00Z"},
	}
}

// TestNetworkArguments: wrong arguments are refused before the service is asked.
func TestNetworkArguments(t *testing.T) {
	noService(t, false)
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"--range", "2h"}, `--range "2h": use one of 1h, 24h, 7d, 30d`},
		{[]string{"--range", "1h", "--from", "2026-10-05"}, "--range cannot be combined with --from or --to"},
		{[]string{"--range", "24h", "--to", "2026-10-05"}, "--range cannot be combined"},
		{[]string{"--from", "yesterday"}, "--from: cannot parse time"},
		{[]string{"--to", "2026-13-01"}, "--to: cannot parse time"},
		{[]string{"--from", "2026-10-05T21:00:00Z", "--to", "2026-10-05T20:00:00Z"}, "--from must be before --to"},
		{[]string{"--from", "2026-10-05T21:00:00Z", "--to", "2026-10-05T21:00:00Z"}, "--from must be before --to"},
		{[]string{"--from", "2026-09-01T00:00:00Z", "--to", "2026-10-05T00:00:00Z"}, "at most 31 days of 24 hours (744 hours) apart"},
		{[]string{"--to", "2026-10-07"}, "--to 2026-10-07: that day has not begun yet"},
		{[]string{"--from", "2026-10-05T21:00:00Z", "--to", "2026-10-06T00:00:00Z"}, "--to may be at most an hour from now"},
		{[]string{"--firewall", "--device", "gateway"}, "--device: the firewall view is not per device"},
		{[]string{"--device", "mac 00"}, "--device: a device key"},
		{[]string{"--device", strings.Repeat("k", web.MaxNetworkDeviceChars+1)}, "--device: a device key"},
		{[]string{"--device", "ip:192.168.1.7\x1b"}, "--device: a device key"},
		{[]string{"--limit", "0"}, "--limit must be 1 to 1000"},
		{[]string{"--limit", "1001"}, "--limit must be 1 to 1000"},
		{[]string{"--limit", "x"}, `invalid value "x" for flag -limit`},
		{[]string{"extra"}, `unexpected argument "extra"`},
		{[]string{"--bogus"}, "flag provided but not defined: -bogus"},
	} {
		err := networkCommand(io.Discard, append(tc.args, "--data", t.TempDir()))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%q: %v, want %q", tc.args, err, tc.want)
		}
	}
	// Through the command line too.
	if err := run([]string{"network", "--range", "90d"}); err == nil || !strings.Contains(err.Error(), "--range") {
		t.Errorf("run network --range 90d: %v", err)
	}
	if !strings.Contains(usageText, "att-monitor network [--range 1h|24h|7d|30d | --from TIME --to TIME] [--device KEY] [--firewall]") {
		t.Error("the usage text does not name the network command")
	}
}

// TestNetworkPeriod: the period's parameters - a range ending now (24h by default), or from and to
// in UTC: a date alone as --to includes that whole day (up to now) and without --from is that day
// alone; --from otherwise defaults to 24 hours before --to, --to to now.
func TestNetworkPeriod(t *testing.T) {
	local := func(s string) string {
		v, err := parseWhen(s)
		if err != nil {
			t.Fatal(err)
		}
		return v.UTC().Format(time.RFC3339Nano)
	}
	for _, tc := range []struct {
		rng, from, to string
		want          url.Values
	}{
		{"", "", "", url.Values{"range": {"24h"}}},
		{"7d", "", "", url.Values{"range": {"7d"}}},
		{"", "2026-10-05T20:00:00Z", "2026-10-05T21:30:00Z", url.Values{"from": {"2026-10-05T20:00:00Z"}, "to": {"2026-10-05T21:30:00Z"}}},
		{"", "2026-10-05T20:00:00Z", "", url.Values{"from": {"2026-10-05T20:00:00Z"}, "to": {"2026-10-05T22:00:00Z"}}},
		{"", "", "2026-10-05T12:00:00Z", url.Values{"from": {"2026-10-04T12:00:00Z"}, "to": {"2026-10-05T12:00:00Z"}}},
		{"", "2026-10-01", "2026-10-03", url.Values{"from": {local("2026-10-01")}, "to": {local("2026-10-04")}}},
		{"", "", "2026-10-03", url.Values{"from": {local("2026-10-03")}, "to": {local("2026-10-04")}}},
		{"", "2026-10-01", "2026-12-31", url.Values{"from": {local("2026-10-01")}, "to": {"2026-10-05T22:00:00Z"}}}, // as far as it has gone
		{"", "2026-10-05T23:30:00+02:00", "2026-10-05T23:45:00+02:00", url.Values{"from": {"2026-10-05T21:30:00Z"}, "to": {"2026-10-05T21:45:00Z"}}},
	} {
		got, err := networkPeriod(tc.rng, tc.from, tc.to, testNow, time.Local)
		if err != nil || !reflect.DeepEqual(got, tc.want) {
			t.Errorf("networkPeriod(%q, %q, %q) = %v, %v; want %v", tc.rng, tc.from, tc.to, got, err, tc.want)
		}
	}
	// A date alone as --to that includes now: from that day's midnight to now.
	today := testNow.In(time.Local).Format("2006-01-02")
	got, err := networkPeriod("", "", today, testNow, time.Local)
	if err != nil || got.Get("to") != testNow.UTC().Format(time.RFC3339Nano) || got.Get("from") != local(today) {
		t.Errorf("--to %s: %v, %v", today, got, err)
	}
}

// TestNetworkPeriodClockChanges: in a time zone with summer time, a date alone as --to is that day
// from its own midnight to the next - 25 hours on the day the clocks go back, 23 on the day they go
// forward - and 31 whole days that include the change back are an hour longer than the service
// allows (31 days of 24 hours), which the error explains.
func TestNetworkPeriodClockChanges(t *testing.T) {
	chicago, err := time.LoadLocation("America/Chicago")
	if err != nil {
		t.Fatal(err)
	}
	later := time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		from, to string
		want     url.Values
	}{
		// The clocks go back at 02:00 CDT on 2026-11-01: midnight is 05:00Z, the next 06:00Z.
		{"", "2026-11-01", url.Values{"from": {"2026-11-01T05:00:00Z"}, "to": {"2026-11-02T06:00:00Z"}}},
		// They go forward at 02:00 CST on 2026-03-08: midnight is 06:00Z, the next 05:00Z.
		{"", "2026-03-08", url.Values{"from": {"2026-03-08T06:00:00Z"}, "to": {"2026-03-09T05:00:00Z"}}},
		// 31 days without a change: 744 hours.
		{"2026-09-15", "2026-10-15", url.Values{"from": {"2026-09-15T05:00:00Z"}, "to": {"2026-10-16T05:00:00Z"}}},
		// 31 days across the change forward: 743 hours.
		{"2026-02-20", "2026-03-22", url.Values{"from": {"2026-02-20T06:00:00Z"}, "to": {"2026-03-23T05:00:00Z"}}},
	} {
		got, err := networkPeriod("", tc.from, tc.to, later, chicago)
		if err != nil || !reflect.DeepEqual(got, tc.want) {
			t.Errorf("--from %q --to %q: %v, %v; want %v", tc.from, tc.to, got, err, tc.want)
		}
	}
	_, err = networkPeriod("", "2026-10-15", "2026-11-14", later, chicago)
	if err == nil || err.Error() != "--from and --to may be at most 31 days of 24 hours (744 hours) apart: "+
		"this period is 745 hours long, because the clocks go back in it (give a shorter period, or times)" {
		t.Errorf("31 days across the change back: %v", err)
	}
	if _, err := networkPeriod("", "2026-10-14", "2026-11-14", later, chicago); err == nil || strings.Contains(err.Error(), "clocks") {
		t.Errorf("32 days: %v", err)
	}
}

func TestRowLayout(t *testing.T) {
	utc, east := time.UTC, time.FixedZone("UTC+02:30", 9000)
	for _, tc := range []struct {
		from, to string
		loc      *time.Location
		want     string
	}{
		{"2026-10-05T21:00:00Z", "2026-10-05T22:00:00Z", utc, "15:04"},
		{"2026-10-05T00:00:00Z", "2026-10-06T00:00:00Z", utc, "15:04"}, // to is not in the period
		{"2026-10-04T22:00:00Z", "2026-10-05T22:00:00Z", utc, "01-02 15:04"},
		{"2026-10-05T21:00:00Z", "2026-10-05T22:00:00Z", east, "01-02 15:04"}, // 23:30 to 00:30 there
		{"not a time", "2026-10-05T22:00:00Z", utc, "01-02 15:04"},
	} {
		if got := rowLayout(tc.from, tc.to, tc.loc); got != tc.want {
			t.Errorf("rowLayout(%s, %s, %s) = %q, want %q", tc.from, tc.to, tc.loc, got, tc.want)
		}
	}
}

// TestNetworkConnections: the connections of the default period, through GET
// /api/network/connections and /api/network/status, in words and tables in local time, with what
// a terminal would act on escaped.
func TestNetworkConnections(t *testing.T) {
	f := &fakeNetwork{conns: netConnections(), status: netStatus()}
	useNetwork(t, f)
	var out strings.Builder
	if err := networkCommand(&out, []string{"--data", t.TempDir()}); err != nil {
		t.Fatal(err)
	}
	if got := f.requests(); !reflect.DeepEqual(got, []string{"/api/network/connections?limit=20&range=24h", "/api/network/status?"}) {
		t.Errorf("requests %q", got)
	}
	nc := f.conns
	lay := rowLayout(nc.From, nc.To, time.Local)
	got := out.String()
	if strings.ContainsRune(got, 0x1b) || strings.ContainsRune(got, 0x202e) {
		t.Errorf("a terminal escape reached the output:\n%s", got)
	}
	wantText(t, squeeze(got),
		"Connections "+at(nc.From, "2006-01-02 15:04")+" to "+at(nc.To, "2006-01-02 15:04")+
			" (this PC's local time): which device talked to which site, from reads of the gateway's NAT table\n",
		"NAT reads: 15, from "+at(nc.First, lay)+" to "+at(nc.Last, lay)+"; the newest listed 42 open connections (the gateway counted 412 sessions in use, 7780 available)\n",
		"NAT table: read every 4m0s, last at "+at(nc.Last, "2006-01-02 15:04")+", next at "+at(ts(2*time.Minute), "15:04")+"\n",
		"Totals: 4 devices, 57 sites (remote addresses), 21 organisations, 6 countries\n",
		"Devices:\n DEVICE ADDRESS CONNECTION KEY (FOR --device) SEEN SITES\n",
		" Office PC 192.168.1.71 Ethernet mac:00:00:5e:00:53:01 120 41\n",
		bs(" Lap~x1b[2Jtop 192.168.1.64 Wi-Fi 5 GHz mac:00:00:5e:00:53:02 40 9\n"),
		" 192.168.1.80 192.168.1.80 - ip:192.168.1.80 3 1\n",
		" Gateway - - gateway 2 1\n",
		"Organisations:\n ORGANISATION COUNTRY SEEN SITES\n Example Cloud (AS64500) US 90 20\n Example Video (AS64501, AS64502) US 20 4\n"+
			" Local network - 5 2\n Other (14 organisations) - 30 12\n",
		"Countries: US 20, NL 5, unknown 2 sites\n",
		"Connections: the 4 most seen of 9 (--limit shows more, up to 1000)\n",
		" DEVICE REMOTE ORGANISATION COUNTRY SERVICE FIRST LAST READS\n",
		" Office PC -> 203.0.113.5 (server-5.example.net) Example Cloud (AS64500) US HTTPS tcp/443 "+at(nc.First, lay)+" "+at(nc.Last, lay)+" 15\n",
		" Office PC <- 198.51.100.7 unknown - tcp/8443 (inbound) "+at(ts(-40*time.Minute), lay)+" "+at(ts(-36*time.Minute), lay)+" 2\n",
		" Gateway -> 192.0.2.53 reserved address - DNS udp/53 ",
		bs(" mac:00:00:5e:00:53:99 -> 203.0.113.9 (evil~x1b[31m.example) Org~u202eevil (AS64501) NL icmp "),
		"SEEN counts the connections open at each NAT read, READS the reads that listed a connection.",
		"IP database: IPtoASN of "+at(nc.IPDB, "2006-01-02")+" (countries are where the networks are registered)\n")

	// One device: its name and key head the summary; the request names it.
	f.mu.Lock()
	f.conns.Device, f.conns.OpenDevice, f.conns.FlowsLeftOut = "mac:00:00:5e:00:53:01", 3, 1500
	f.mu.Unlock()
	out.Reset()
	if err := networkCommand(&out, []string{"--device", "mac:00:00:5e:00:53:01", "--range", "7d", "--limit", "50", "--data", t.TempDir()}); err != nil {
		t.Fatal(err)
	}
	if got := f.requests(); got[len(got)-2] != "/api/network/connections?device=mac%3A00%3A00%3A5e%3A00%3A53%3A01&limit=50&range=7d" {
		t.Errorf("requests %q", got)
	}
	wantText(t, out.String(), "Device:      Office PC, 192.168.1.71 (mac:00:00:5e:00:53:01)\n",
		"the newest listed 42 open connections, 3 of them the device's",
		"1500 connections too light to count one by one in so busy a period count only in their devices and as Other")
	// A custom period, as UTC.
	if err := networkCommand(io.Discard, []string{"--from", "2026-10-05T20:00:00Z", "--to", "2026-10-05T21:00:00Z", "--data", t.TempDir()}); err != nil {
		t.Fatal(err)
	}
	if got := f.requests(); got[len(got)-2] != "/api/network/connections?from=2026-10-05T20%3A00%3A00Z&limit=20&to=2026-10-05T21%3A00%3A00Z" {
		t.Errorf("requests %q", got)
	}
}

// TestNetworkConnectionsNotRead: no NAT read in the period - here because no access code is
// stored, which the status says - and no IP database loaded: the summary says why, and nothing
// else.
func TestNetworkConnectionsNotRead(t *testing.T) {
	st := netStatus()
	st.Samplers.NATAt, st.Samplers.NATNext = "", ""
	st.Samplers.NATProblem = "not read: the NAT table is behind the gateway's login, and no gateway access code is stored (att-monitor set-access-code)"
	st.Samplers.DevicesProblem = "the Device List could not be read: gateway: GET devices.ha: timeout"
	st.IPIntel = &model.IPIntelStatus{Enabled: true, Error: `ip2asn-v4.tsv.gz not found in C:\data\geo`}
	f := &fakeNetwork{conns: model.NetConnections{From: ts(-time.Hour), To: ts(0), InUse: -1, Available: -1}, status: st}
	useNetwork(t, f)
	var out strings.Builder
	if err := networkCommand(&out, []string{"--range", "1h", "--data", t.TempDir()}); err != nil {
		t.Fatal(err)
	}
	want := "Connections " + at(ts(-time.Hour), "2006-01-02 15:04") + " to " + at(ts(0), "2006-01-02 15:04") +
		" (this PC's local time): which device talked to which site, from reads of the gateway's NAT table\n" +
		"NAT reads:   none in this period\n" +
		"NAT table:   not read: the NAT table is behind the gateway's login, and no gateway access code is stored (att-monitor set-access-code)\n" +
		"Device List: the Device List could not be read: gateway: GET devices.ha: timeout\n" +
		`IP database: none loaded, so organisations and countries are not shown (ip2asn-v4.tsv.gz not found in C:\data\geo)` + "\n"
	if out.String() != want {
		t.Errorf("output:\n%s\nwant:\n%s", out.String(), want)
	}

	// The samplers switched off, the IP database too, and no status at all.
	st.Samplers = &model.ConnSamplerStatus{Enabled: false}
	st.IPIntel = &model.IPIntelStatus{}
	out.Reset()
	if err := networkCommand(&out, []string{"--data", t.TempDir()}); err != nil {
		t.Fatal(err)
	}
	wantText(t, out.String(), "NAT table:   not read: connections.enabled is false in config.json (what is shown was recorded before)\n",
		"IP database: none loaded, so organisations and countries are not shown (geo.enabled is false in config.json)\n")
	f.mu.Lock()
	f.status = nil
	f.mu.Unlock()
	out.Reset()
	if err := networkCommand(&out, []string{"--data", t.TempDir()}); err != nil {
		t.Fatal(err)
	}
	if got := out.String(); strings.Contains(got, "NAT table:") || !strings.HasSuffix(got, "NAT reads:   none in this period\n"+
		"IP database: none loaded, so organisations and countries are not shown\n") {
		t.Errorf("without a status:\n%s", got)
	}
}

// TestNetworkConnectionsReadNotAllKept: the newest NAT read worked but left rows out (its note):
// the summary says that the table is read - every interval, when last and next - and then what was
// not kept, and how many gateway logins the reads needed in the last day.
func TestNetworkConnectionsReadNotAllKept(t *testing.T) {
	st := netStatus()
	st.Samplers.NATNote = "3 rows of the NAT table page left out (not understood)\x1b[2J"
	st.Samplers.NATLogins = 2
	f := &fakeNetwork{conns: model.NetConnections{From: ts(-time.Hour), To: ts(0), InUse: -1, Available: -1}, status: st}
	useNetwork(t, f)
	var out strings.Builder
	if err := networkCommand(&out, []string{"--range", "1h", "--data", t.TempDir()}); err != nil {
		t.Fatal(err)
	}
	wantText(t, out.String(),
		"NAT table:   read every 4m0s, last at "+at(st.Samplers.NATAt, "2006-01-02 15:04")+", next at "+at(st.Samplers.NATNext, "15:04")+"\n"+
			bs("             but 3 rows of the NAT table page left out (not understood)~x1b[2J\n")+
			"             the reads needed 2 gateway logins in the last 24 hours\n")
	if strings.Contains(out.String(), "not being read") || strings.Contains(out.String(), "not read") {
		t.Errorf("a read that worked is said not to be read:\n%s", out.String())
	}
}

// TestNetworkConfigWarnings: the settings of the page that the service could not use as written
// in config.json (its status's config_warnings) end both summaries, escaped.
func TestNetworkConfigWarnings(t *testing.T) {
	st := netStatus()
	st.ConfigWarnings = []string{"connections.keep_days is 0, not 1 to 3650: the default, 30, is used", "geo.x\x1b[2J"}
	f := &fakeNetwork{conns: model.NetConnections{From: ts(-time.Hour), To: ts(0), InUse: -1, Available: -1},
		fw: model.NetFirewall{From: ts(-time.Hour), To: ts(0)}, status: st}
	useNetwork(t, f)
	for _, args := range [][]string{{"--range", "1h"}, {"--firewall", "--range", "1h"}, {"--firewall"}} {
		if len(args) == 1 {
			f.mu.Lock()
			f.fw = netFirewall()
			f.mu.Unlock()
		}
		var out strings.Builder
		if err := networkCommand(&out, append(args, "--data", t.TempDir())); err != nil {
			t.Fatal(err)
		}
		if !strings.HasSuffix(out.String(), "config.json: connections.keep_days is 0, not 1 to 3650: the default, 30, is used\n"+
			bs("config.json: geo.x~x1b[2J\n")) {
			t.Errorf("%q:\n%s", args, out.String())
		}
	}
}

// netFirewall is a firewall answer for the hour before testNow.
func netFirewall() model.NetFirewall {
	return model.NetFirewall{
		From: ts(-time.Hour), To: ts(0), Oldest: ts(-30 * time.Minute),
		Drops: 30, Inbound: 20, Outbound: 8, Local: 2, Sources: 3,
		Hours:     []model.FwHour{{T: "2026-10-05T21:00:00Z", In: 20, Out: 8, Local: 2}},
		Countries: []model.NetCountry{{Code: "NL", Sites: 2, Weight: 15}, {Code: "", Sites: 1, Weight: 5}},
		TopSources: []model.FwSource{
			{Addr: "203.0.113.66", Org: "Example Scanner", ASN: 64496, Country: "NL", Count: 12, Ports: 3, Last: ts(-5 * time.Minute)},
			{Addr: "2001:db8:1::1", Count: 5, Last: ts(-7 * time.Minute)},
		},
		Services: []model.FwService{{Name: "SSH", Proto: "tcp", Port: 22, Count: 12}, {Name: "tcp 8071", Proto: "tcp", Port: 8071, Count: 3},
			{Name: "ICMP", Proto: "icmp", Count: 2}, {Name: "Other", Count: 3}},
		Reasons: []model.FwReason{{Reason: "POLICY-INPUT-GEN-DISCARD", Label: "Unsolicited, to the gateway", Count: 22},
			{Reason: "POLICY", Label: "Firewall policy", Count: 8}},
		OutboundRows: []model.FwOutRow{
			{Device: "mac:00:00:5e:00:53:01", Name: "Office PC", LAN: "192.168.1.71", Remote: "192.0.2.44", Org: "Example Cloud", ASN: 64500,
				Country: "US", Service: "HTTPS", Proto: "tcp", Port: 443, Reason: "POLICY", Label: "Firewall policy", Count: 6, Last: ts(-3 * time.Minute)},
			{Device: "ip:192.168.1.80", Name: "192.168.1.80", LAN: "192.168.1.80", Remote: "192.0.2.45", Proto: "udp", Port: 3478,
				Reason: "POLICY", Label: "Firewall policy", Count: 1, Last: ts(-9 * time.Minute)},
		},
		OutboundTotal: 3, OutboundDevices: 3,
		IPDB: "2026-10-04T06:00:00Z",
	}
}

// TestNetworkFirewall: what the firewall dropped, through GET /api/network/firewall: the drops by
// direction, the sources, the services, the reasons, the outbound rows with the devices counted
// by the service, and a note when the syslog kept starts after the period does.
func TestNetworkFirewall(t *testing.T) {
	f := &fakeNetwork{fw: netFirewall(), status: netStatus()}
	useNetwork(t, f)
	var out strings.Builder
	if err := networkCommand(&out, []string{"--firewall", "--range", "1h", "--limit", "2", "--data", t.TempDir()}); err != nil {
		t.Fatal(err)
	}
	if got := f.requests(); !reflect.DeepEqual(got, []string{"/api/network/firewall?limit=2&range=1h", "/api/network/status?"}) {
		t.Errorf("requests %q", got)
	}
	fw := f.fw
	lay := rowLayout(fw.From, fw.To, time.Local)
	wantText(t, squeeze(out.String()),
		"Firewall "+at(fw.From, "2006-01-02 15:04")+" to "+at(fw.To, "2006-01-02 15:04")+
			" (this PC's local time): what the gateway's firewall dropped, from its syslog\n",
		"Note: the syslog kept starts at "+at(fw.Oldest, "2006-01-02 15:04")+": what the gateway logged before was not received here, or is no longer kept\n",
		"Dropped: 30 packets: 20 inbound (from the Internet), 8 outbound (from the home network), 2 local (the gateway's own, or between the home network and the gateway)\n",
		"Sources: 3 Internet addresses; packets by country: NL 15, unknown 5\n",
		"Top sources:\n ADDRESS ORGANISATION COUNTRY PACKETS PORTS LAST\n",
		" 203.0.113.66 Example Scanner (AS64496) NL 12 3 "+at(ts(-5*time.Minute), lay)+"\n",
		" 2001:db8:1::1 unknown - 5 0 "+at(ts(-7*time.Minute), lay)+"\n",
		"Probed services (what the inbound packets tried to reach):\n SSH tcp/22 12\n tcp/8071 3\n ICMP 2\n Other ports 3\n",
		"Reasons:\n Unsolicited, to the gateway (POLICY-INPUT-GEN-DISCARD) 22\n Firewall policy (POLICY) 8\n",
		"Blocked on the way out: 3 destinations, from 3 devices; the 2 with the most packets (--limit shows more, up to 1000):\n",
		" DEVICE DESTINATION ORGANISATION COUNTRY SERVICE REASON PACKETS LAST\n",
		" Office PC -> 192.0.2.44 Example Cloud (AS64500) US HTTPS tcp/443 Firewall policy 6 "+at(ts(-3*time.Minute), lay)+"\n",
		" 192.168.1.80 -> 192.0.2.45 unknown - udp/3478 Firewall policy 1 "+at(ts(-9*time.Minute), lay)+"\n",
		"IP database: IPtoASN of "+at(fw.IPDB, "2006-01-02"))

	// Nothing dropped.
	f.mu.Lock()
	f.fw = model.NetFirewall{From: ts(-time.Hour), To: ts(0), Oldest: ts(-48 * time.Hour), IPDB: "2026-10-04T06:00:00Z"}
	f.mu.Unlock()
	out.Reset()
	if err := networkCommand(&out, []string{"--firewall", "--data", t.TempDir()}); err != nil {
		t.Fatal(err)
	}
	if got := out.String(); strings.Contains(got, "Note:") || !strings.Contains(got,
		"\nDropped:     nothing in this period (the gateway logs only the packets it drops, never the connections it allows)\nIP database: ") {
		t.Errorf("nothing dropped:\n%s", got)
	}
}

// TestNetworkJSON: --json prints the service's answer as it is, and nothing else.
func TestNetworkJSON(t *testing.T) {
	f := &fakeNetwork{conns: netConnections(), fw: netFirewall(), status: netStatus()}
	useNetwork(t, f)
	var out strings.Builder
	if err := networkCommand(&out, []string{"--json", "--data", t.TempDir()}); err != nil {
		t.Fatal(err)
	}
	var nc model.NetConnections
	onlyJSON(t, out.String(), &nc)
	if !reflect.DeepEqual(nc, f.conns) {
		t.Errorf("JSON %+v, want %+v", nc, f.conns)
	}
	out.Reset()
	if err := networkCommand(&out, []string{"--firewall", "--json", "--data", t.TempDir()}); err != nil {
		t.Fatal(err)
	}
	var fw model.NetFirewall
	onlyJSON(t, out.String(), &fw)
	if !reflect.DeepEqual(fw, f.fw) {
		t.Errorf("JSON %+v, want %+v", fw, f.fw)
	}
	for _, r := range f.requests() {
		if strings.HasPrefix(r, "/api/network/status") {
			t.Errorf("--json asked for the status: %q", f.requests())
		}
	}
}

// TestNetworkWithoutService: without the running service nothing can be shown, and the error says
// where the samples are kept; an error of the service is passed on.
func TestNetworkWithoutService(t *testing.T) {
	noService(t, true)
	dir := t.TempDir()
	err := networkCommand(io.Discard, []string{"--data", dir})
	if err == nil || !strings.Contains(err.Error(), "the service is not running") || !strings.Contains(err.Error(), "att-monitor start") ||
		!strings.Contains(err.Error(), filepath.Join(dir, "connections")) {
		t.Errorf("no service: %v", err)
	}

	f := &fakeNetwork{fail: http.StatusNotFound, failMsg: "the Network page is not available: this att-monitor offers no view of the connections and the firewall"}
	useNetwork(t, f)
	if err := networkCommand(io.Discard, []string{"--data", dir}); err == nil ||
		err.Error() != "service: the Network page is not available: this att-monitor offers no view of the connections and the firewall" {
		t.Errorf("404: %v", err)
	}
	f.mu.Lock()
	f.fail, f.failMsg = http.StatusServiceUnavailable, "unavailable: netmap: firewall view: no syslog store"
	f.mu.Unlock()
	if err := networkCommand(io.Discard, []string{"--firewall", "--data", dir}); err == nil || !strings.Contains(err.Error(), "no syslog store") {
		t.Errorf("503: %v", err)
	}
	// An older service has no such endpoints: its router answers "not found".
	f.mu.Lock()
	f.fail, f.failMsg = http.StatusNotFound, "not found"
	f.mu.Unlock()
	if err := networkCommand(io.Discard, []string{"--data", dir}); err == nil || !strings.HasPrefix(err.Error(), "service: not found: ") ||
		!strings.Contains(err.Error(), "older version of att-monitor") {
		t.Errorf("an older service: %v", err)
	}
}
