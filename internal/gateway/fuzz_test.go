package gateway

import (
	"errors"
	"net/netip"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"attmonitor/internal/model"
)

// FuzzParsers checks that no input makes a parser or Derive panic (gateway pages are
// untrusted input). The seed corpus runs with every "go test"; fuzz with
// go test -fuzz=FuzzParsers ./internal/gateway/
func FuzzParsers(f *testing.F) {
	for _, name := range []string{"sysinfo.html", "broadbandstatistics.html", "fiberstat.html", "lanstatistics.html",
		"events_checked.html", "login_nonce.html", "hiddenpage.html", "home.html", "broadbandconfig.html",
		"syslog_select.html", "syslog_checkbox_off.html", "syslog_checkbox_on.html", "syslog_radio.html",
		"syslog_real_off.html", "syslog_real_on_update.html", "syslog_real_on.html",
		"nattable_synthetic.html", "devices_real.html"} {
		f.Add(fixture(f, name))
	}
	f.Add([]byte("<form><table><tr><th>Syslog<td><select name=s><option value=1 selected>On<noscript><input type=submit name=Update></noscript></select><label for=s>Server Port</label>"))
	f.Add([]byte("<table><tr><th>Time Since Last Reboot</th><td>99:99:99:99</td></tr></table>"))
	f.Add([]byte("<h1>Rx Power" + nbspLatin1 + "Currently 9999999999999999999999</h1><table><tr><td>Alarm</td><td colspan=999999>1 (Threshold -99999999999999999999)</td></tr></table>"))
	f.Add([]byte("<title>Login<form action=login.ha><input name=nonce value=\x01>"))
	f.Fuzz(func(t *testing.T, body []byte) {
		s := &model.GatewaySnapshot{Pages: []model.PageCapture{{Page: "sysinfo", Status: 200}}}
		s.System, _ = ParseSysInfo(body)
		s.Broadband, _ = ParseBroadband(body)
		s.Fiber, _ = ParseFiber(body)
		s.LAN, _ = ParseLAN(body)
		_, _ = ParseNotification(body)
		_ = IsLoginPage(body)
		_ = SessionsFull(body)
		_ = scan(body).nonce("/login.ha")
		d := Derive(s, time.Date(2026, 10, 5, 3, 10, 43, 0, time.UTC), time.UTC)
		if s.System != nil && d.UptimeSec != s.System.UptimeSec {
			t.Fatalf("uptime %d != %d", d.UptimeSec, s.System.UptimeSec)
		}
		// The WAN-down indicator needs the gateway's own blank "Current Date/Time" row.
		if d.GatewayClockBlank && (s.System == nil || !s.System.GatewayTimePresent || normSpace(s.System.GatewayTimeRaw) != "") {
			t.Fatalf("GatewayClockBlank without a blank Current Date/Time row: %+v", s.System)
		}
		_, _ = ParseSyslog(body)
		nat, err := ParseNATTable(body)
		checkNATResult(t, body, nat, err)
		devices, err := ParseDevices(body)
		checkDevicesResult(t, body, devices, err)
		for _, form := range parseForms(body) {
			_ = form.fields(syslogSwitchLabel)
			for _, c := range form.controls {
				if !c.isSubmit() {
					continue
				}
				// A body that is produced at all is plain ASCII: a browser would encode anything
				// else in the page's character encoding.
				if enc, err := form.encode(c); err == nil {
					for i := 0; i < len(enc); i++ {
						if enc[i] >= 0x80 || enc[i] <= 0x20 {
							t.Fatalf("encoded body %q has byte %#x", enc, enc[i])
						}
					}
				}
			}
		}
	})
}

// FuzzNetworkPages checks that no input makes the Network page's parsers (ParseNATTable,
// ParseDevices) panic, and that what they return stays bounded by the input and well formed:
// canonical IP addresses, ports in range, MAC addresses in one form, connection summaries
// that cannot hold a "Name:" line. The seed corpus runs with every "go test"; fuzz with
// go test -fuzz=FuzzNetworkPages ./internal/gateway/
func FuzzNetworkPages(f *testing.F) {
	for _, name := range []string{"nattable_synthetic.html", "devices_real.html", "login_nonce.html", "home.html",
		"syslog_real_off.html", "sysinfo.html"} {
		f.Add(fixture(f, name))
	}
	f.Add([]byte("<table><tr><th>Protocol<th>TCP State<th>Source Address<th>Source Port<th>Destination Address<th>Destination Port" +
		"<tr><td>tcp<td>ESTABLISHED<td>192.168.1.101<td>51514<td>192.0.2.10<td>443<tr><td>udp<td>192.168.1.102<td>53<td>192.0.2.53<td>53</table>"))
	f.Add([]byte("<table><tr><th colspan=2>Source<th colspan=99999>Destination<tr><td>[2001:db8::1]:443<td>x" +
		"<td>::ffff:1.2.3.4%eth0<td>1.2.3.4:99999<td>1.2.3.4</table><p>Total sessions in use: 99999999999999 Available sessions 7</p>"))
	f.Add([]byte("<table><tr><td>Destination<td>Source<td>Proto<td>State<tr><td>udp<td>192.0.2.1<td>1<td>192.0.2.2<td>2<td>Time Wait" +
		"<tr><td>Total sessions in use<td>1,2,3</table><form><select><option selected label=\"All\">x</select></form>"))
	f.Add([]byte("<title>Device List</title><table><tr><th>MAC Address<td>00-00-5E-00-53-01<tr><th>IPv4 Address / Name<td>192.168.1.1 / a/b" +
		"<tr><th>Connection Type<td><pre>Wi-Fi\r2.4GHz\nName: x</pre><tr><td><hr><tr><th>IPv6 Address<td>fe80::1%br0</table>"))
	f.Add([]byte("<table><tr><th>Name<td>a<tr><th>Name<td>b<tr><th>MAC<td>00:00:00:00:00:00<tr><th>Connection Speed<td>Mbps\tduplex</table>"))
	f.Fuzz(func(t *testing.T, body []byte) {
		nat, err := ParseNATTable(body)
		checkNATResult(t, body, nat, err)
		devices, err := ParseDevices(body)
		checkDevicesResult(t, body, devices, err)
	})
}

// minRowBytes is a lower bound on the bytes each table row that the Network page's parsers count
// (a session, a skipped row, a device) takes: a row of its own ("<tr>") with two non-empty cells
// ("<td>1<td>2", 14 bytes in all), or a label row with a value ("<tr><th>Name<td>x").
const minRowBytes = 10

// maxTextBytes bounds a text taken from body: decoding windows-1252 bytes and entities can make
// text longer than the bytes it comes from, but never four times as long.
func maxTextBytes(body []byte) int { return 4*len(body) + 16 }

// checkNATResult checks what ParseNATTable returned for body: an error is a documented one, with
// an empty table whose totals are unknown; otherwise every session has canonical IP addresses
// (no zone, IPv4-mapped ones unmapped) and ports in range, the protocol is lower case, and there
// are no more sessions and skipped rows than body has room for rows.
func checkNATResult(t testing.TB, body []byte, tbl model.NATTable, err error) {
	t.Helper()
	if err != nil {
		if !errors.Is(err, ErrNATPage) && !errors.Is(err, ErrLoginRequired) {
			t.Fatalf("ParseNATTable: undocumented error %v", err)
		}
		if !reflect.DeepEqual(tbl, noNATTable()) {
			t.Fatalf("ParseNATTable failed but returned %+v", tbl)
		}
		return
	}
	if tbl.Sessions == nil {
		t.Fatal("ParseNATTable: Sessions is nil")
	}
	if rows := len(tbl.Sessions) + tbl.Skipped; tbl.Skipped < 0 || rows*minRowBytes > len(body) {
		t.Fatalf("ParseNATTable: %d sessions and %d skipped rows from %d bytes", len(tbl.Sessions), tbl.Skipped, len(body))
	}
	if tbl.InUse < -1 || tbl.InUse > maxCount || tbl.Available < -1 || tbl.Available > maxCount {
		t.Fatalf("ParseNATTable: totals %d in use, %d available", tbl.InUse, tbl.Available)
	}
	if len(tbl.Display) > maxTextBytes(body) {
		t.Fatalf("ParseNATTable: display %d bytes from %d", len(tbl.Display), len(body))
	}
	for _, s := range tbl.Sessions {
		for _, a := range []string{s.Src, s.Dst} {
			ip, err := netip.ParseAddr(a)
			if err != nil || ip.String() != a || ip.Zone() != "" || ip.Is4In6() {
				t.Fatalf("ParseNATTable: session address %q is not a canonical IP address", a)
			}
		}
		if s.SrcPort < 0 || s.SrcPort > 65535 || s.DstPort < 0 || s.DstPort > 65535 {
			t.Fatalf("ParseNATTable: session ports %d and %d", s.SrcPort, s.DstPort)
		}
		if strings.ContainsAny(s.Proto, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") || len(s.Proto)+len(s.State) > maxTextBytes(body) {
			t.Fatalf("ParseNATTable: session protocol %q, state %q", s.Proto, s.State)
		}
	}
}

// reMACForm is a MAC address as LANDevice.MAC holds it.
var reMACForm = regexp.MustCompile(`^[0-9a-f]{2}(:[0-9a-f]{2}){5}$`)

// checkDevicesResult checks what ParseDevices returned for body: an error is a documented one,
// without devices; otherwise every device names itself somehow, its MAC (lower case, colon
// separated, not all zeros), IPv4 and IPv6 addresses (canonical, each once) are well formed, its
// connection summary holds no "label: value" line, its speed has a number, and there are no more
// devices than body has room for rows.
func checkDevicesResult(t testing.TB, body []byte, devices []model.LANDevice, err error) {
	t.Helper()
	if err != nil {
		if !errors.Is(err, ErrDevicesPage) && !errors.Is(err, ErrLoginRequired) {
			t.Fatalf("ParseDevices: undocumented error %v", err)
		}
		if devices != nil {
			t.Fatalf("ParseDevices failed but returned %+v", devices)
		}
		return
	}
	if devices == nil {
		t.Fatal("ParseDevices: the list is nil")
	}
	if len(devices)*minRowBytes > len(body) {
		t.Fatalf("ParseDevices: %d devices from %d bytes", len(devices), len(body))
	}
	for _, d := range devices {
		if d.MAC == "" && d.IPv4 == "" && d.Name == "" && len(d.IPv6) == 0 {
			t.Fatalf("ParseDevices: a device that names nothing: %+v", d)
		}
		if d.MAC != "" && (!reMACForm.MatchString(d.MAC) || d.MAC == "00:00:00:00:00:00") {
			t.Fatalf("ParseDevices: MAC %q", d.MAC)
		}
		if d.IPv4 != "" {
			if ip, err := netip.ParseAddr(d.IPv4); err != nil || !ip.Is4() || ip.String() != d.IPv4 {
				t.Fatalf("ParseDevices: IPv4 %q", d.IPv4)
			}
		}
		seen := map[string]bool{}
		for _, a := range d.IPv6 {
			if ip, err := netip.ParseAddr(a); err != nil || !ip.Is6() || ip.Zone() != "" || ip.String() != a || seen[a] {
				t.Fatalf("ParseDevices: IPv6 %q in %q", a, d.IPv6)
			}
			seen[a] = true
		}
		if strings.Contains(d.Connection, ":") || len(d.Connection) > 40 {
			t.Fatalf("ParseDevices: connection %q", d.Connection)
		}
		if d.Speed != "" && !strings.ContainsAny(d.Speed, "0123456789") {
			t.Fatalf("ParseDevices: speed %q", d.Speed)
		}
		if n := len(d.Name) + len(d.Status) + len(d.Allocation) + len(d.Speed) + len(d.LastActivity); n > maxTextBytes(body) {
			t.Fatalf("ParseDevices: %d bytes of text from %d", n, len(body))
		}
	}
}
