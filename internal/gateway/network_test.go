package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"attmonitor/internal/contracts"
	"attmonitor/internal/model"
)

// ---------------------------------------------------------------- expected results

// ns builds a NAT session.
func ns(proto, state, src string, sport int, dst string, dport int) model.NATSession {
	return model.NATSession{Proto: proto, State: state, Src: src, SrcPort: sport, Dst: dst, DstPort: dport}
}

// wantNATSynthetic is testdata/gateway/nattable_synthetic.html parsed: every row but the last,
// whose source address (192.168.1.300) is not an IP address.
var wantNATSynthetic = model.NATTable{
	Sessions: []model.NATSession{
		ns("tcp", "ESTABLISHED", "192.168.1.101", 51514, "192.0.2.10", 443),
		ns("tcp", "ESTABLISHED", "192.168.1.101", 51516, "192.0.2.10", 443),
		ns("tcp", "TIME_WAIT", "192.168.1.101", 51490, "198.51.100.20", 80),
		ns("udp", "", "192.168.1.101", 61234, "192.0.2.53", 53),
		ns("udp", "", "192.168.1.101", 50123, "198.51.100.30", 443), // TCP State "&nbsp;"
		ns("tcp", "SYN_SENT", "192.168.1.102", 49822, "203.0.113.80", 8443),
		ns("tcp", "ESTABLISHED", "192.168.1.102", 49801, "198.51.100.25", 5223), // no </td>
		ns("icmp", "", "192.168.1.102", 0, "192.0.2.1", 0),                      // empty ports
		ns("tcp", "ESTABLISHED", "192.168.1.103", 40122, "203.0.113.44", 443),
		ns("tcp", "CLOSE_WAIT", "192.168.1.103", 40110, "203.0.113.45", 443), // a stray </td>
		ns("udp", "", "192.168.1.104", 123, "198.51.100.123", 123),
		ns("tcp", "FIN_WAIT", "192.168.1.104", 52011, "203.0.113.15", 993),
		ns("tcp", "ESTABLISHED", "198.51.100.77", 40001, "192.168.1.105", 8080), // inbound (port forward)
		ns("tcp", "ESTABLISHED", "192.168.1.105", 33445, "192.0.2.140", 8883),
		ns("udp", "", "192.168.1.106", 3478, "203.0.113.200", 3478),
		ns("udp", "", "192.168.1.106", 3074, "198.51.100.150", 3074),
		ns("tcp", "ESTABLISHED", "192.168.1.106", 52344, "198.51.100.60", 443),
		ns("tcp", "LAST_ACK", "192.168.1.150", 50999, "192.0.2.77", 443), // not in the Device List
		ns("udp", "", "192.168.1.150", 51820, "198.51.100.200", 51820),
		ns("udp", "", "203.0.113.10", 32768, "192.0.2.53", 53), // the gateway's own (its public address)
		ns("tcp", "ESTABLISHED", "2001:db8::100", 51600, "2001:db8:ffff::10", 443),
		ns("tcp", "TIME_WAIT", "192.168.1.101", 51600, "192.0.2.10", 80),
		ns("icmp", "", "192.168.1.104", 0, "203.0.113.1", 0),                 // "-" placeholders
		ns("tcp", "ESTABLISHED", "192.168.1.105", 33446, "192.0.2.141", 443), // no </tr>
	},
	InUse:     25,
	Available: 8192,
	Display:   "All sessions",
	Skipped:   1,
}

// wantRealDevices is testdata/gateway/devices_real.html parsed. The IPv6 addresses are in
// canonical form ("2001:db8:0::100" on the page); no Connection keeps the Wi-Fi network's name
// ("ATT-EXAMPLE"), and the first device's Connection Speed - the bare template "Mbps duplex" of
// an Ethernet port that is down - is empty.
var wantRealDevices = []model.LANDevice{
	{MAC: "00:00:5e:00:53:01", Name: "office-pc", LastActivity: "Mon Oct 5 12:01:00 2026", Status: "off",
		Allocation: "dhcp", Connection: "Ethernet LAN-1"},
	{MAC: "00:00:5e:00:53:02", Name: "laptop", IPv4: "192.168.1.101",
		IPv6:         []string{"2001:db8::100", "2001:db8:1::101", "2001:db8:2::102", "fe80::1003"},
		LastActivity: "Mon Oct 5 12:02:00 2026", Status: "on", Allocation: "dhcp", Connection: "Wi-Fi 5 GHz"},
	{MAC: "00:00:5e:00:53:03", Name: "phone", IPv4: "192.168.1.102", LastActivity: "Mon Oct 5 12:03:00 2026",
		Status: "off", Allocation: "dhcp", Connection: "Wi-Fi 5 GHz"},
	{MAC: "00:00:5e:00:53:04", Name: "living-room-tv", IPv4: "192.168.1.103", LastActivity: "Mon Oct 5 12:04:00 2026",
		Status: "off", Allocation: "dhcp", Connection: "Wi-Fi 2.4 GHz"},
	{MAC: "00:00:5e:00:53:05", Name: "tablet", IPv4: "192.168.1.104",
		IPv6:         []string{"2001:db8::104", "2001:db8:1::105", "2001:db8:2::106", "fe80::1007"},
		LastActivity: "Mon Oct 5 12:05:00 2026", Status: "on", Allocation: "dhcp", Connection: "Wi-Fi 5 GHz"},
	{MAC: "00:00:5e:00:53:06", Name: "printer", LastActivity: "Mon Oct 5 12:06:00 2026", Status: "off",
		Allocation: "dhcp", Connection: "Wi-Fi 5 GHz"},
	{MAC: "00:00:5e:00:53:07", Name: "thermostat", IPv4: "192.168.1.105",
		IPv6:         []string{"2001:db8::108", "2001:db8:1::109", "2001:db8:2::10a", "fe80::100b"},
		LastActivity: "Mon Oct 5 12:07:00 2026", Status: "on", Allocation: "dhcp", Connection: "Wi-Fi 5 GHz"},
	{MAC: "00:00:5e:00:53:08", Name: "game-console", IPv4: "192.168.1.106",
		IPv6:         []string{"2001:db8::10c", "2001:db8:1::10d"},
		LastActivity: "Mon Oct 5 12:08:00 2026", Status: "on", Allocation: "dhcp", Connection: "Wi-Fi 5 GHz"},
}

// compareNAT reports every difference between two NAT tables, session by session.
func compareNAT(t *testing.T, got, want model.NATTable) {
	t.Helper()
	if got.InUse != want.InUse || got.Available != want.Available || got.Display != want.Display || got.Skipped != want.Skipped {
		t.Errorf("in use %d, available %d, display %q, skipped %d; want %d, %d, %q, %d",
			got.InUse, got.Available, got.Display, got.Skipped, want.InUse, want.Available, want.Display, want.Skipped)
	}
	if (got.Sessions == nil) != (want.Sessions == nil) {
		t.Errorf("Sessions nil = %v, want %v", got.Sessions == nil, want.Sessions == nil)
	}
	for i := 0; i < max(len(got.Sessions), len(want.Sessions)); i++ {
		switch {
		case i >= len(got.Sessions):
			t.Errorf("session %d missing, want %+v", i+1, want.Sessions[i])
		case i >= len(want.Sessions):
			t.Errorf("session %d = %+v, want none", i+1, got.Sessions[i])
		case got.Sessions[i] != want.Sessions[i]:
			t.Errorf("session %d = %+v, want %+v", i+1, got.Sessions[i], want.Sessions[i])
		}
	}
}

// compareDevices compares two device lists field by field.
func compareDevices(t *testing.T, got, want []model.LANDevice) {
	t.Helper()
	if (got == nil) != (want == nil) {
		t.Errorf("devices nil = %v, want %v", got == nil, want == nil)
	}
	if len(got) != len(want) {
		t.Errorf("%d devices, want %d: %+v", len(got), len(want), got)
		return
	}
	for i := range want {
		g, w := reflect.ValueOf(got[i]), reflect.ValueOf(want[i])
		for f := 0; f < w.NumField(); f++ {
			if gv, wv := g.Field(f).Interface(), w.Field(f).Interface(); !reflect.DeepEqual(gv, wv) {
				t.Errorf("device %d (%s): %s = %#v, want %#v", i+1, want[i].MAC, w.Type().Field(f).Name, gv, wv)
			}
		}
	}
}

// ---------------------------------------------------------------- ParseNATTable

func TestParseNATTableSyntheticFixture(t *testing.T) {
	got, err := ParseNATTable(fixture(t, "nattable_synthetic.html"))
	if err != nil {
		t.Fatal(err)
	}
	compareNAT(t, got, wantNATSynthetic)
}

// natTestPage wraps content in a minimal gateway page.
func natTestPage(content string) []byte {
	return []byte("<html><head><title>NAT Table</title></head><body><div id=\"content-sub\"><h1>NAT Table</h1>\n" +
		content + "\n</div></body></html>")
}

// natTestTable returns a table with a header row of <th> cells and rows of <td> cells.
func natTestTable(header []string, rows ...[]string) string {
	var b strings.Builder
	b.WriteString("<table class=\"table100\">\n<tr>")
	for _, h := range header {
		b.WriteString("<th>" + h + "</th>")
	}
	b.WriteString("</tr>\n")
	for _, r := range rows {
		b.WriteString("<tr>")
		for _, c := range r {
			b.WriteString("<td>" + c + "</td>")
		}
		b.WriteString("</tr>\n")
	}
	return b.String() + "</table>"
}

// stdHeader is the header of the real page.
var stdHeader = []string{"Protocol", "TCP State", "Source Address", "Source Port", "Destination Address", "Destination Port"}

func TestParseNATTableVariants(t *testing.T) {
	totals := `<table><tr><th scope="row">Total sessions available</th><td>8192</td></tr>` +
		`<tr><th scope="row">Total sessions in use</th><td>2</td></tr></table>`
	two := []model.NATSession{
		ns("tcp", "ESTABLISHED", "192.168.1.101", 51514, "192.0.2.10", 443),
		ns("udp", "", "192.168.1.102", 5353, "198.51.100.53", 53),
	}
	tests := []struct {
		name string
		page string
		want model.NATTable
	}{
		{"the real labels", totals + natTestTable(stdHeader,
			[]string{"tcp", "ESTABLISHED", "192.168.1.101", "51514", "192.0.2.10", "443"},
			[]string{"udp", "", "192.168.1.102", "5353", "198.51.100.53", "53"}),
			model.NATTable{Sessions: two, InUse: 2, Available: 8192}},
		{"columns in another order", natTestTable(
			[]string{"Destination Port", "Destination Address", "Protocol", "Source Port", "Source Address", "TCP State"},
			[]string{"443", "192.0.2.10", "tcp", "51514", "192.168.1.101", "ESTABLISHED"},
			[]string{"53", "198.51.100.53", "udp", "5353", "192.168.1.102", ""}),
			model.NATTable{Sessions: two, InUse: -1, Available: -1}},
		{"address and port in one cell", natTestTable(
			[]string{"Protocol", "State", "Source", "Destination"},
			[]string{"tcp", "ESTABLISHED", "192.168.1.101:51514", "192.0.2.10:443"},
			[]string{"udp", "", "192.168.1.102 : 5353", "198.51.100.53:53"},
			[]string{"tcp", "ESTABLISHED", "[2001:db8::100]:51600", "[2001:db8:ffff::10]:443"}),
			model.NATTable{Sessions: append(append([]model.NATSession{}, two...),
				ns("tcp", "ESTABLISHED", "2001:db8::100", 51600, "2001:db8:ffff::10", 443)), InUse: -1, Available: -1}},
		{"the port column wins over a port in the address cell", natTestTable(stdHeader,
			[]string{"tcp", "ESTABLISHED", "192.168.1.101:1", "51514", "192.0.2.10:443", ""},
			[]string{"udp", "", "192.168.1.102:5353", "-", "198.51.100.53:53", "N/A"}),
			model.NATTable{Sessions: two, InUse: -1, Available: -1}},
		{"extra columns are ignored", natTestTable(
			[]string{"#", "Protocol", "TCP State", "Source Address", "Source Port", "Translated Address", "Translated Port",
				"Destination Address", "Destination Port", "Source MAC", "Timeout", "Bytes"},
			[]string{"1", "tcp", "ESTABLISHED", "192.168.1.101", "51514", "203.0.113.10", "61514", "192.0.2.10", "443",
				"00:00:5e:00:53:02", "3600", "123456"},
			[]string{"2", "udp", "", "192.168.1.102", "5353", "203.0.113.10", "65353", "198.51.100.53", "53",
				"00:00:5e:00:53:03", "30", "512"}),
			model.NATTable{Sessions: two, InUse: -1, Available: -1}},
		{"abbreviated labels", natTestTable(
			[]string{"Proto", "State", "Src IP", "Src Port", "Dst IP", "Dst Port"},
			[]string{"tcp", "ESTABLISHED", "192.168.1.101", "51514", "192.0.2.10", "443"},
			[]string{"udp", "", "192.168.1.102", "5353", "198.51.100.53", "53"}),
			model.NATTable{Sessions: two, InUse: -1, Available: -1}},
		{"other spellings", natTestTable(
			[]string{"IP Protocol", "Connection State", "Source IP Address:", "SPort", "Dest. Address", "Dest Port"},
			[]string{"tcp", "ESTABLISHED", "192.168.1.101", "51514", "192.0.2.10", "443"},
			[]string{"udp", "", "192.168.1.102", "5353", "198.51.100.53", "53"}),
			model.NATTable{Sessions: two, InUse: -1, Available: -1}},
		{"upper case", strings.ReplaceAll(totals, "Total sessions", "TOTAL SESSIONS") + natTestTable(
			[]string{"PROTOCOL", "TCP STATE", "SOURCE ADDRESS", "SOURCE PORT", "DESTINATION ADDRESS", "DESTINATION PORT"},
			[]string{"TCP", "ESTABLISHED", "192.168.1.101", "51514", "192.0.2.10", "443"},
			[]string{"UDP", "", "192.168.1.102", "5353", "198.51.100.53", "53"}),
			model.NATTable{Sessions: two, InUse: 2, Available: 8192}},
		{"no totals, no list", natTestTable(stdHeader,
			[]string{"tcp", "ESTABLISHED", "192.168.1.101", "51514", "192.0.2.10", "443"}),
			model.NATTable{Sessions: two[:1], InUse: -1, Available: -1}},
		{"totals in the text", "<p>Total sessions in use: 1,234</p>\n<p>Total Sessions Available:\n8,192</p>" +
			natTestTable(stdHeader, []string{"tcp", "ESTABLISHED", "192.168.1.101", "51514", "192.0.2.10", "443"}),
			model.NATTable{Sessions: two[:1], InUse: 1234, Available: 8192}},
		{"totals in other words", "<p>Available sessions = 4096</p>" + natTestTable(stdHeader,
			[]string{"tcp", "ESTABLISHED", "192.168.1.101", "51514", "192.0.2.10", "443"},
			[]string{"Sessions in use: 1"}),
			model.NATTable{Sessions: two[:1], InUse: 1, Available: 4096}},
		{"totals rows inside the session table", natTestTable(stdHeader,
			[]string{"tcp", "ESTABLISHED", "192.168.1.101", "51514", "192.0.2.10", "443"},
			[]string{"Total sessions in use", "1"},
			[]string{"Total sessions available", "16,384"}),
			model.NATTable{Sessions: two[:1], InUse: 1, Available: 16384}},
		{"a header without rows", totals + natTestTable(stdHeader),
			model.NATTable{Sessions: []model.NATSession{}, InUse: 2, Available: 8192}},
		{"header in thead, cells in tbody", `<table><thead><tr><th scope="col">Protocol</th><th scope="col">TCP State</th>` +
			`<th scope="col">Source Address</th><th scope="col">Source Port</th><th scope="col">Destination Address</th>` +
			`<th scope="col">Destination Port</th></tr></thead><tbody>` +
			`<tr><td>tcp</td><td>ESTABLISHED</td><td>192.168.1.101</td><td>51514</td><td>192.0.2.10</td><td>443</td></tr>` +
			`</tbody></table>`,
			model.NATTable{Sessions: two[:1], InUse: -1, Available: -1}},
		{"header in td cells", `<table><tr><td><b>Protocol</b></td><td><b>TCP State</b></td><td><b>Source Address</b></td>` +
			`<td><b>Source Port</b></td><td><b>Destination Address</b></td><td><b>Destination Port</b></td></tr>` +
			`<tr><td>tcp</td><td>ESTABLISHED</td><td>192.168.1.101</td><td>51514</td><td>192.0.2.10</td><td>443</td></tr></table>`,
			model.NATTable{Sessions: two[:1], InUse: -1, Available: -1}},
		{"sloppy markup", "<table>\r<tr><th>Protocol<th>TCP State<th>Source Address<th>Source Port<th>Destination Address<th>Destination Port\r" +
			"<tr><td>tcp<td>ESTABLISHED</td></td><td>192.168.1.101<td>51514</td><td>192.0.2.10<td>443\r" +
			"<tr><td>udp</td><td></td></td><td>192.168.1.102</td><td>5353</td></th><td>198.51.100.53</td><td>53</td>\r</table>",
			model.NATTable{Sessions: two, InUse: -1, Available: -1}},
		{"a row ended early", natTestTable(stdHeader,
			[]string{"tcp", "ESTABLISHED", "192.168.1.101", "51514", "192.0.2.10", "443"}) +
			"<table><tr><th>Protocol<th>TCP State<th>Source Address<th>Source Port<th>Destination Address<th>Destination Port" +
			"<tr><td>udp</td><td></td><td>192.168.1.102</td><td>5353</td></tr></td><td>198.51.100.53</td><td>53</td></tr></table>",
			// "</tr>" ends the row, as in a browser: neither half holds two addresses.
			model.NATTable{Sessions: two[:1], InUse: -1, Available: -1, Skipped: 2}},
		{"a repeated header row", natTestTable(stdHeader,
			[]string{"tcp", "ESTABLISHED", "192.168.1.101", "51514", "192.0.2.10", "443"},
			stdHeader,
			[]string{"udp", "", "192.168.1.102", "5353", "198.51.100.53", "53"}),
			model.NATTable{Sessions: two, InUse: -1, Available: -1}},
		{"one table per protocol", "<h2>TCP</h2>" + natTestTable(stdHeader,
			[]string{"tcp", "ESTABLISHED", "192.168.1.101", "51514", "192.0.2.10", "443"}) +
			"<h2>UDP</h2>" + natTestTable([]string{"Protocol", "Source Address", "Source Port", "Destination Address", "Destination Port"},
			[]string{"udp", "192.168.1.102", "5353", "198.51.100.53", "53"}),
			model.NATTable{Sessions: two, InUse: -1, Available: -1}},
		{"ports that are not numbers", natTestTable(stdHeader,
			[]string{"tcp", "ESTABLISHED", "192.168.1.101", "http", "192.0.2.10", "65536"},
			[]string{"tcp", "ESTABLISHED", "192.168.1.101", "-1", "192.0.2.10", "4 43"},
			[]string{"tcp", "ESTABLISHED", "192.168.1.101", "51514 (ephemeral)", "192.0.2.10", "443 (https)"}),
			model.NATTable{Sessions: []model.NATSession{
				ns("tcp", "ESTABLISHED", "192.168.1.101", 0, "192.0.2.10", 0),
				ns("tcp", "ESTABLISHED", "192.168.1.101", 0, "192.0.2.10", 4),
				ns("tcp", "ESTABLISHED", "192.168.1.101", 51514, "192.0.2.10", 443),
			}, InUse: -1, Available: -1}},
		{"protocol numbers and placeholders", natTestTable(stdHeader,
			[]string{"6", "N/A", "192.168.1.101", "51514", "192.0.2.10", "443"},
			[]string{"17", "--", "192.168.1.102", "5353", "198.51.100.53", "53"},
			[]string{"1", "*", "192.168.1.103", "", "192.0.2.1", ""},
			[]string{"GRE", "", "192.168.1.104", "", "203.0.113.5", ""},
			[]string{"-", "", "192.168.1.105", "1", "203.0.113.6", "2"}),
			model.NATTable{Sessions: []model.NATSession{
				ns("tcp", "", "192.168.1.101", 51514, "192.0.2.10", 443),
				ns("udp", "", "192.168.1.102", 5353, "198.51.100.53", 53),
				ns("icmp", "", "192.168.1.103", 0, "192.0.2.1", 0),
				ns("gre", "", "192.168.1.104", 0, "203.0.113.5", 0),
				ns("", "", "192.168.1.105", 1, "203.0.113.6", 2),
			}, InUse: -1, Available: -1}},
		{"addresses in other forms", natTestTable(stdHeader,
			[]string{"tcp", "ESTABLISHED", "::ffff:192.168.1.101", "51514", "2001:DB8:0:0::A", "443"},
			[]string{"udp", "", "192.168.001.102", "5353", "[2001:db8::53]", "53"},
			[]string{"udp", "", "fe80::1%br0", "546", "fe80::2", "547"},
			[]string{"tcp", "ESTABLISHED", "192.168.1.101 (laptop)", "51515", "192.0.2.10", "443"}),
			model.NATTable{Sessions: []model.NATSession{
				ns("tcp", "ESTABLISHED", "192.168.1.101", 51514, "2001:db8::a", 443),
				ns("udp", "", "192.168.1.102", 5353, "2001:db8::53", 53),
				ns("udp", "", "fe80::1", 546, "fe80::2", 547),
				ns("tcp", "ESTABLISHED", "192.168.1.101", 51515, "192.0.2.10", 443),
			}, InUse: -1, Available: -1}},
		{"rows that are not understood are skipped", natTestTable(stdHeader,
			[]string{"tcp", "ESTABLISHED", "laptop", "51514", "192.0.2.10", "443"},
			[]string{"tcp", "ESTABLISHED", "192.168.1.101", "51514", "999.0.2.10", "443"},
			[]string{"tcp", "ESTABLISHED", "192.168.1.101", "51514"},
			[]string{"tcp", "ESTABLISHED", "192.168.1.101", "51514", "192.0.2.10", "443"},
			[]string{"No sessions to display"},
			[]string{"Address", "Port", "Address", "Port"},
			[]string{"", "", "", "", "", ""}),
			model.NATTable{Sessions: two[:1], InUse: -1, Available: -1, Skipped: 3}},
		{"a row with a cell left out is read by its content", natTestTable(stdHeader,
			[]string{"udp", "192.168.1.102", "5353", "198.51.100.53", "53"},
			[]string{"tcp", "ESTABLISHED", "192.168.1.101", "192.0.2.10:443"},
			[]string{"tcp", "192.168.1.101", "51514", "203.0.113.10", "192.0.2.10", "443"}),
			model.NATTable{Sessions: []model.NATSession{
				ns("udp", "", "192.168.1.102", 5353, "198.51.100.53", 53),
				ns("tcp", "ESTABLISHED", "192.168.1.101", 0, "192.0.2.10", 443),
			}, InUse: -1, Available: -1, Skipped: 1}},
		{"a row read by its content takes no protocol for the state", natTestTable(
			[]string{"TCP State", "Source Address", "Source Port", "Destination Address", "Destination Port"},
			[]string{"udp", "x", "192.168.1.102", "5353", "198.51.100.53", "53"}),
			model.NATTable{Sessions: []model.NATSession{ns("", "", "192.168.1.102", 5353, "198.51.100.53", 53)},
				InUse: -1, Available: -1}},
		{"a row read by its content keeps the header's order", natTestTable(
			[]string{"Destination Address", "Destination Port", "Source Address", "Source Port", "Protocol", "TCP State"},
			[]string{"192.0.2.10", "443", "192.168.1.101", "51514", "tcp"}),
			model.NATTable{Sessions: []model.NATSession{ns("tcp", "", "192.168.1.101", 51514, "192.0.2.10", 443)},
				InUse: -1, Available: -1}},
		{"a source heading over the address and the port", `<table><tr><th>Protocol</th><th>TCP State</th>` +
			`<th colspan="2">Source</th><th colspan="2">Destination</th></tr>` +
			`<tr><th></th><th></th><th>Address</th><th>Port</th><th>Address</th><th>Port</th></tr>` +
			`<tr><td>tcp</td><td>ESTABLISHED</td><td>192.168.1.101</td><td>51514</td><td>192.0.2.10</td><td>443</td></tr></table>`,
			model.NATTable{Sessions: two[:1], InUse: -1, Available: -1}},
		{"the display list by its label", `<form method="post" action="/cgi-bin/nattable.ha"><table><tr><th>Sort by</th>` +
			`<td><select name="sort"><option>Source</option><option selected>Destination</option></select></td></tr>` +
			`<tr><th><label for="d">Select display option:</label></th><td><select id="d" name="d"><option value="a">All</option>` +
			`<option value="t" selected="selected">TCP only</option></select></td></tr></table></form>` +
			natTestTable(stdHeader, []string{"tcp", "ESTABLISHED", "192.168.1.101", "51514", "192.0.2.10", "443"}),
			model.NATTable{Sessions: two[:1], InUse: -1, Available: -1, Display: "TCP only"}},
		{"the page's only list, nothing selected", `<form method="post" action="/cgi-bin/nattable.ha">Show: ` +
			`<select name="x"><option value="1" disabled>Nothing</option><option value="2">Everything</option><option value="3">Some</option></select>` +
			`<input type="submit" name="Refresh" value="Refresh"></form>` +
			natTestTable(stdHeader, []string{"tcp", "ESTABLISHED", "192.168.1.101", "51514", "192.0.2.10", "443"}),
			model.NATTable{Sessions: two[:1], InUse: -1, Available: -1, Display: "Everything"}},
		{"several unlabelled lists", `<form><select name="a"><option>A</option></select><select name="b"><option>B</option></select></form>` +
			natTestTable(stdHeader, []string{"tcp", "ESTABLISHED", "192.168.1.101", "51514", "192.0.2.10", "443"}),
			model.NATTable{Sessions: two[:1], InUse: -1, Available: -1}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseNATTable(natTestPage(tt.page))
			if err != nil {
				t.Fatal(err)
			}
			compareNAT(t, got, tt.want)
		})
	}
}

// TestParseNATTableEncodingAndLineEndings: the synthetic page with other line endings and with
// raw windows-1252 bytes (or the U+FFFD of a lossy transcription) in place of its entities
// parses the same.
func TestParseNATTableEncodingAndLineEndings(t *testing.T) {
	orig := fixture(t, "nattable_synthetic.html")
	for name, f := range map[string]func([]byte) []byte{
		"CRLF":      func(b []byte) []byte { return bytes.ReplaceAll(b, []byte("\n"), []byte("\r\n")) },
		"CR":        func(b []byte) []byte { return bytes.ReplaceAll(b, []byte("\n"), []byte("\r")) },
		"latin-1":   latin1Variant,
		"U+FFFD":    replacementVariant,
		"utf8 nbsp": func(b []byte) []byte { return bytes.ReplaceAll(b, []byte("&nbsp;"), []byte(nbspUTF8)) },
		"upper-case markup": func(b []byte) []byte {
			for _, tag := range []string{"tr", "td", "th", "table", "select", "option", "label"} {
				b = bytes.ReplaceAll(b, []byte("<"+tag), []byte("<"+strings.ToUpper(tag)))
				b = bytes.ReplaceAll(b, []byte("</"+tag), []byte("</"+strings.ToUpper(tag)))
			}
			return b
		},
	} {
		t.Run(name, func(t *testing.T) {
			b := f(bytes.Clone(orig))
			if bytes.Equal(b, orig) {
				t.Fatal("the variant changes nothing")
			}
			got, err := ParseNATTable(b)
			if err != nil {
				t.Fatal(err)
			}
			compareNAT(t, got, wantNATSynthetic)
		})
	}
}

// TestParseNATTableNotUnderstood: no other page is taken for the NAT table, and a page with no
// session table is an error - with an empty table, its totals unknown.
func TestParseNATTableNotUnderstood(t *testing.T) {
	pages := map[string][]byte{
		"empty":            nil,
		"text":             []byte("garbage"),
		"binary":           {0x00, 0xff, 0xa0, 0x3c, 0x92},
		"addresses only":   []byte("<table><tr><td>tcp</td><td>192.168.1.101</td><td>192.0.2.10</td></tr></table>"),
		"one address only": natTestPage(natTestTable([]string{"Protocol", "Source Address", "Source Port"}, []string{"tcp", "192.168.1.101", "1"})),
		"totals only":      natTestPage(`<table><tr><th>Total sessions in use</th><td>3</td></tr></table>`),
	}
	for _, name := range []string{"sysinfo.html", "broadbandstatistics.html", "fiberstat.html", "lanstatistics.html", "home.html",
		"diag.html", "firewall.html", "sitemap.html", "broadbandconfig.html", "events_checked.html", "hiddenpage.html",
		"syslog_real_off.html", "syslog_select.html", "devices_real.html"} {
		pages[name] = fixture(t, name)
	}
	for name, body := range pages {
		got, err := ParseNATTable(body)
		if !errors.Is(err, ErrNATPage) {
			t.Errorf("%s: err = %v, want ErrNATPage", name, err)
		}
		if !reflect.DeepEqual(got, noNATTable()) {
			t.Errorf("%s: table = %+v, want an empty one with unknown totals", name, got)
		}
	}
	for name, body := range map[string][]byte{
		"login_handshake1.html": fixture(t, "login_handshake1.html"),
		"login_nonce.html":      fixture(t, "login_nonce.html"),
		"sessions full":         sessionsFullPage(t),
	} {
		got, err := ParseNATTable(body)
		if !errors.Is(err, ErrLoginRequired) || errors.Is(err, ErrNATPage) {
			t.Errorf("%s: err = %v, want ErrLoginRequired", name, err)
		}
		if !reflect.DeepEqual(got, noNATTable()) {
			t.Errorf("%s: table = %+v", name, got)
		}
	}
}

// bigNATPage returns a NAT table page with n sessions.
func bigNATPage(n int) []byte {
	var b bytes.Buffer
	b.WriteString(`<html><head><title>NAT Table</title></head><body><table><tr><th scope="row">Total sessions in use</th><td>` +
		strconv.Itoa(n) + "</td></tr></table>\n<table class=\"table100\">\n<tr><th>Protocol</th><th>TCP State</th><th>Source Address</th>" +
		"<th>Source Port</th><th>Destination Address</th><th>Destination Port</th></tr>\n")
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, `<tr><td class="col2">tcp</td><td class="col2">ESTABLISHED</td><td class="col2">192.168.1.%d</td>`+
			`<td class="col2">%d</td><td class="col2">198.51.100.%d</td><td class="col2">443</td></tr>`+"\n",
			100+i%100, 1024+i%60000, i%256)
	}
	b.WriteString("</table></body></html>")
	return b.Bytes()
}

// TestParseNATTableLarge: a table of 10,000 sessions - more than the gateway is likely to show -
// is read whole and quickly.
func TestParseNATTableLarge(t *testing.T) {
	const n = 10000
	body := bigNATPage(n)
	limit := 3 * time.Second
	if raceEnabled {
		limit *= 10
	}
	start := time.Now()
	got, err := ParseNATTable(body)
	took := time.Since(start)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Sessions) != n || got.Skipped != 0 || got.InUse != n || got.Available != -1 {
		t.Fatalf("%d sessions, %d skipped, in use %d, available %d", len(got.Sessions), got.Skipped, got.InUse, got.Available)
	}
	if want := ns("tcp", "ESTABLISHED", "192.168.1.199", 1024+(n-1)%60000, "198.51.100.15", 443); got.Sessions[n-1] != want {
		t.Errorf("last session = %+v, want %+v", got.Sessions[n-1], want)
	}
	if took > limit {
		t.Errorf("parsing %d sessions (%d bytes) took %v", n, len(body), took)
	}
	t.Logf("%d sessions, %d KiB: %v", n, len(body)>>10, took)
}

func BenchmarkParseNATTable10k(b *testing.B) {
	body := bigNATPage(10000)
	b.SetBytes(int64(len(body)))
	for b.Loop() {
		if _, err := ParseNATTable(body); err != nil {
			b.Fatal(err)
		}
	}
}

// TestParseNetworkPathologicalInputs feeds near-cap (4 MiB) hostile pages to both parsers: they
// must finish quickly (linear work) and never fail on them in another way than documented.
func TestParseNetworkPathologicalInputs(t *testing.T) {
	size := MaxBodyBytes
	if raceEnabled {
		size /= 8
	}
	header := "<table><tr><th>Protocol</th><th>TCP State</th><th>Source Address</th><th>Source Port</th>" +
		"<th>Destination Address</th><th>Destination Port</th></tr>"
	cases := map[string][]byte{
		"many headers":        []byte(strings.Repeat(header, size/len(header))),
		"many short sessions": []byte(header + strings.Repeat("<tr><td>::<td>::", size/16)),
		"many skipped rows":   []byte(header + strings.Repeat("<tr><td>1<td>2", size/14)),
		"many salvaged rows":  []byte(header + strings.Repeat("<tr><td>tcp<td>192.0.2.1<td>1<td>192.0.2.2<td>2", size/45)),
		"wide colspans": []byte(strings.Repeat(`<table><tr><th colspan="1000">Source</th><th colspan="1000">Destination</th></tr>`+
			`<tr><td colspan="999">x</td><td>192.0.2.1</td><td>1</td></tr></table>`, size/140)),
		"one wide row":     []byte(header + "<tr>" + strings.Repeat("<td>192.0.2.1:1", size/14)),
		"deep nesting":     []byte(strings.Repeat("<table><tr><td>", size/16)),
		"device labels":    []byte(strings.Repeat("<tr><th>MAC Address</th><td>00:00:5e:00:53:01</td></tr>", size/56)),
		"device rule rows": []byte("<table><tr><th>MAC Address</th><td>00:00:5e:00:53:01</td></tr>" + strings.Repeat("<tr><td><hr>", size/12)),
		"connection lines": []byte("<table><tr><th>MAC Address</th><td>00:00:5e:00:53:01</td></tr><tr><th>Connection Type</th><td><pre>" +
			strings.Repeat("Wi-Fi\n<br>", size/10)),
		"many lists":         []byte(strings.Repeat(`<form><select><option selected>x</option></select></form>`, size/56)),
		"invalid utf-8 soup": bytes.Repeat([]byte{0xA0, '<', 0xA9, '>', 0x92}, size/5),
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			start := time.Now()
			nat, natErr := ParseNATTable(body)
			devs, devErr := ParseDevices(body)
			if d := time.Since(start); d > 30*time.Second {
				t.Errorf("parsing took %v", d)
			}
			checkNATResult(t, body, nat, natErr)
			checkDevicesResult(t, body, devs, devErr)
		})
	}
}

func TestNATColumnOf(t *testing.T) {
	for label, want := range map[string]natColumn{
		"Protocol": natColProto, "Proto": natColProto, "IP Protocol": natColProto, "Protocol Type": natColProto,
		"TCP State": natColState, "State": natColState, "Status": natColState, "Connection State": natColState, "TCP Status": natColState,
		"Source Address": natColSrcAddr, "Source": natColSrcAddr, "Source IP": natColSrcAddr, "Src Addr": natColSrcAddr,
		"SOURCE IPV4 ADDRESS": natColSrcAddr, "Source Address:Port": natColSrcAddr, "Source Host": natColSrcAddr, "SAddr": natColSrcAddr,
		"Source Port": natColSrcPort, "Src Port": natColSrcPort, "SPort": natColSrcPort, "Source Port Number": natColSrcPort,
		"Destination Address": natColDstAddr, "Destination": natColDstAddr, "Dest. IP": natColDstAddr, "Dst Address": natColDstAddr,
		"Destination Port": natColDstPort, "Dest Port": natColDstPort, "dst-port": natColDstPort, "DPort": natColDstPort,
		"Translated Address": natColNone, "Source MAC": natColNone, "Destination Interface": natColNone, "Timeout": natColNone,
		"": natColNone, "#": natColNone, "Bytes": natColNone, "Destinations": natColNone, "Sources": natColNone,
	} {
		if got := natColumnOf(label); got != want {
			t.Errorf("natColumnOf(%q) = %d, want %d", label, got, want)
		}
	}
}

func TestParseEndpoint(t *testing.T) {
	tests := []struct {
		in      string
		addr    string // "" = not an endpoint
		port    int
		hasPort bool
	}{
		{"192.0.2.1", "192.0.2.1", 0, false},
		{"192.0.2.1:443", "192.0.2.1", 443, true},
		{"192.0.2.1 : 443", "192.0.2.1", 443, true},
		{"192.0.2.1 (example)", "192.0.2.1", 0, false},
		{"192.168.001.010", "192.168.1.10", 0, false},
		{"2001:db8::1", "2001:db8::1", 0, false},
		{"[2001:db8::1]", "2001:db8::1", 0, false},
		{"[2001:db8::1]:443", "2001:db8::1", 443, true},
		{"fe80::1%br0", "fe80::1", 0, false},
		{"[fe80::1%br0]:546", "fe80::1", 546, true},
		{"::ffff:192.0.2.1", "::ffff:192.0.2.1", 0, false}, // unmapped by the callers
		{"", "", 0, false},
		{"-", "", 0, false},
		{"192.0.2", "", 0, false},
		{"192.0.2.256", "", 0, false},
		{"192.0.2.1:65536", "", 0, false},
		{"192.0.2.1:", "", 0, false},
		{"192.168.1.300", "", 0, false},
		{"0192.168.1.1", "", 0, false},
		{"+1.2.3.4", "", 0, false},
		{"laptop", "", 0, false},
		{"[192.0.2.1]x", "", 0, false},
	}
	for _, tt := range tests {
		a, port, hasPort, ok := parseEndpoint(tt.in)
		switch {
		case ok != (tt.addr != ""):
			t.Errorf("parseEndpoint(%q) ok = %v", tt.in, ok)
		case ok && (a.String() != tt.addr || port != tt.port || hasPort != tt.hasPort):
			t.Errorf("parseEndpoint(%q) = %s, %d, %v; want %s, %d, %v", tt.in, a, port, hasPort, tt.addr, tt.port, tt.hasPort)
		}
	}
}

func TestNATPortNumberAndLeadingCount(t *testing.T) {
	for in, want := range map[string]int{"443": 443, "0": 0, "65535": 65535, "443 (https)": 443, "53(dns)": 53,
		"65536": -1, "": -1, "-": -1, "N/A": -1, "-1": -1, "4 43": 4, "443/tcp": -1, "123456": -1, "1.5": -1, "1e3": -1} {
		n, ok := natPortNumber(in)
		if (want >= 0) != ok || ok && n != want {
			t.Errorf("natPortNumber(%q) = %d, %v; want %d", in, n, ok, want)
		}
	}
	for in, want := range map[string]int{"25": 25, "8,192": 8192, " 356 of 8192": 356, "16384 (max)": 16384, "0": 0,
		"": -1, "N/A": -1, "1.5": -1, "12abc": -1, ",5": -1, "99999999999": -1, "2147483648": -1} {
		if got := leadingCount(in); got != want {
			t.Errorf("leadingCount(%q) = %d, want %d", in, got, want)
		}
	}
}

// ---------------------------------------------------------------- ParseDevices

func TestParseDevicesRealCapture(t *testing.T) {
	body := fixture(t, "devices_real.html")
	got, err := ParseDevices(body)
	if err != nil {
		t.Fatal(err)
	}
	compareDevices(t, got, wantRealDevices)
	// The Wi-Fi network's name is shown on the page but kept nowhere.
	if !bytes.Contains(body, []byte("Name: ATT-EXAMPLE")) {
		t.Fatal("the fixture no longer shows the Wi-Fi network's name")
	}
	if j, _ := json.Marshal(got); bytes.Contains(j, []byte("ATT-EXAMPLE")) {
		t.Errorf("the Wi-Fi network's name was kept: %s", j)
	}
}

// devicesVariant derives a Device List page from the real capture.
type devicesVariant struct {
	name string
	edit func(t *testing.T, b []byte) []byte
	want []model.LANDevice
}

func TestParseDevicesVariants(t *testing.T) {
	const (
		ruleRow   = `<tr><td colspan="2"><hr class="reshr" noshade="noshade" /></td></tr>` + "\n"
		secondMAC = `<tr><th scope="row">MAC Address</th><td class="col2">` + "\n00:00:5e:00:53:02\n"
	)
	withDevice := func(i int, f func(d *model.LANDevice)) []model.LANDevice {
		out := append([]model.LANDevice(nil), wantRealDevices...)
		d := out[i]
		f(&d)
		out[i] = d
		return out
	}
	tests := []devicesVariant{
		{"CRLF", func(t *testing.T, b []byte) []byte { return bytes.ReplaceAll(b, []byte("\n"), []byte("\r\n")) }, wantRealDevices},
		{"CR", func(t *testing.T, b []byte) []byte { return bytes.ReplaceAll(b, []byte("\n"), []byte("\r")) }, wantRealDevices},
		{"latin-1", func(t *testing.T, b []byte) []byte { return latin1Variant(b) }, wantRealDevices},
		{"U+FFFD", func(t *testing.T, b []byte) []byte { return replacementVariant(b) }, wantRealDevices},
		{"no separator rows", func(t *testing.T, b []byte) []byte { return sub(t, b, ruleRow, "") }, wantRealDevices},
		{"extra separator rows", func(t *testing.T, b []byte) []byte { return sub(t, b, ruleRow, ruleRow+ruleRow) }, wantRealDevices},
		{"a rule in a row with a value separates nothing", func(t *testing.T, b []byte) []byte {
			return sub(t, b, `(Mon Oct 5 12:01:00 2026\n)(</td></tr>)`, "${1}<hr />${2}")
		}, wantRealDevices},
		{"line breaks instead of <br>", func(t *testing.T, b []byte) []byte { return sub(t, b, `<br />`, "\n") }, wantRealDevices},
		{"labels in upper case", func(t *testing.T, b []byte) []byte {
			for _, l := range []string{"MAC Address", "IPv4 Address / Name", "Name", "Last Activity", "Status", "Allocation",
				"Connection Type", "Connection Speed", "Mesh Client", "IPv6 Address"} {
				b = sub(t, b, ">"+l+"<", ">"+strings.ToUpper(l)+":<")
			}
			return b
		}, wantRealDevices},
		{"labels in td cells", func(t *testing.T, b []byte) []byte {
			b = sub(t, b, `<th scope="row">`, `<td>`)
			return sub(t, b, `</th>`, `</td>`)
		}, wantRealDevices},
		{"MAC addresses upper case with dashes", func(t *testing.T, b []byte) []byte {
			return sub(t, b, `00:00:5e:00:53:0([0-9])`, `00-00-5E-00-53-0$1`)
		}, wantRealDevices},
		{"a MAC address that is not one", func(t *testing.T, b []byte) []byte {
			return sub(t, b, `00:00:5e:00:53:01`, `unknown`)
		}, withDevice(0, func(d *model.LANDevice) { d.MAC = "" })},
		{"an all-zero MAC address", func(t *testing.T, b []byte) []byte {
			return sub(t, b, `00:00:5e:00:53:01`, `00:00:00:00:00:00`)
		}, withDevice(0, func(d *model.LANDevice) { d.MAC = "" })},
		{"an IPv4 address without a name", func(t *testing.T, b []byte) []byte {
			return sub(t, b, `192.168.1.101 / laptop`, `192.168.1.101`)
		}, withDevice(1, func(d *model.LANDevice) { d.Name = "" })},
		{"a name with a slash and no address", func(t *testing.T, b []byte) []byte {
			return sub(t, b, `192.168.1.101 / laptop`, `unknown / laptop / 2`)
		}, withDevice(1, func(d *model.LANDevice) { d.IPv4, d.Name = "", "laptop / 2" })},
		{"a separate IPv4 Address row", func(t *testing.T, b []byte) []byte {
			return sub(t, b, `<th scope="row">Name</th><td class="col2">`+"\noffice-pc\n",
				`<th scope="row">Name</th><td class="col2">office-pc</td></tr><tr><th scope="row">IPv4 Address</th><td>192.168.001.100`)
		}, withDevice(0, func(d *model.LANDevice) { d.IPv4 = "192.168.1.100" })},
		{"a speed", func(t *testing.T, b []byte) []byte {
			return sub(t, b, "Mbps\tduplex", "1000Mbps\tfullduplex")
		}, withDevice(0, func(d *model.LANDevice) { d.Speed = "1000Mbps fullduplex" })},
		{"a mesh client", func(t *testing.T, b []byte) []byte {
			return sub(t, b, `(Mesh Client</th><td class="col2">\n)No(\n</td></tr>\n<tr><td colspan="2"><hr class="reshr" noshade="noshade" /></td></tr>\n<tr><th scope="row">MAC Address</th><td class="col2">\n00:00:5e:00:53:04)`,
				"${1}Yes${2}")
		}, withDevice(2, func(d *model.LANDevice) { d.Mesh = true })},
		{"an IPv6 address shown twice and one that is not", func(t *testing.T, b []byte) []byte {
			return sub(t, b, "\n2001:db8:1::101\n", "\n2001:DB8:0:0::100\n</td></tr><tr><th>IPv6 Address</th><td>192.0.2.1</td></tr>"+
				"<tr><th>IPv6 Address</th><td>unknown</td></tr><tr><th>IPv6 Address</th><td>2001:db8:1::101\n")
		}, wantRealDevices},
		{"a network name that reads like a band or a port", func(t *testing.T, b []byte) []byte {
			return sub(t, b, `Name: ATT-EXAMPLE`, `Name: 6 GHz Ethernet LAN-9 Wi-Fi`)
		}, wantRealDevices},
		{"a block that names no device", func(t *testing.T, b []byte) []byte {
			return sub(t, b, ruleRow+secondMAC, ruleRow+`<tr><th scope="row">Status</th><td>on</td></tr>`+
				`<tr><th scope="row">Allocation</th><td>static</td></tr>`+ruleRow+secondMAC)
		}, wantRealDevices},
		{"a device without a separator before it", func(t *testing.T, b []byte) []byte {
			return sub(t, b, `(?s)</table>`, `<tr><th>IPv4 Address / Name</th><td>192.168.1.107 / guest</td></tr>`+
				`<tr><th>MAC Address</th><td>00:00:5e:00:53:09</td></tr><tr><th>Status</th><td>on</td></tr></table>`)
		}, append(append([]model.LANDevice(nil), wantRealDevices...),
			model.LANDevice{MAC: "00:00:5e:00:53:09", Name: "guest", IPv4: "192.168.1.107", Status: "on"})},
		{"no devices", func(t *testing.T, b []byte) []byte {
			return sub(t, b, `(?s)(<table class="table100"[^>]*>).*?(</table>)`, "${1}${2}")
		}, []model.LANDevice{}},
		{"no devices and no table", func(t *testing.T, b []byte) []byte {
			return sub(t, b, `(?s)<table class="table100".*?</table>`, "<p>No devices found.</p>")
		}, []model.LANDevice{}},
	}
	orig := fixture(t, "devices_real.html")
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := tt.edit(t, bytes.Clone(orig))
			if bytes.Equal(b, orig) {
				t.Fatal("the variant changes nothing")
			}
			got, err := ParseDevices(b)
			if err != nil {
				t.Fatal(err)
			}
			compareDevices(t, got, tt.want)
			if j, _ := json.Marshal(got); bytes.Contains(j, []byte("ATT-EXAMPLE")) || bytes.Contains(j, []byte("LAN-9")) {
				t.Errorf("the Wi-Fi network's name was kept: %s", j)
			}
		})
	}
}

// TestParseDevicesNotUnderstood: no other page is taken for the Device List.
func TestParseDevicesNotUnderstood(t *testing.T) {
	pages := map[string][]byte{
		"empty":         nil,
		"text":          []byte("garbage"),
		"binary":        {0x00, 0xff, 0xa0, 0x3c, 0x92},
		"columns":       []byte("<title>Device List</title><table><tr><th>Device</th><th>MAC</th></tr><tr><td>laptop</td><td>00:00:5e:00:53:02</td></tr></table>"),
		"other rows":    []byte("<title>Device List</title><table><tr><th>Device Name</th><td>laptop</td></tr></table>"),
		"a NAT session": natTestPage(natTestTable(stdHeader, []string{"tcp", "ESTABLISHED", "192.168.1.101", "51514", "192.0.2.10", "443"})),
	}
	for _, name := range []string{"sysinfo.html", "broadbandstatistics.html", "fiberstat.html", "lanstatistics.html", "home.html",
		"diag.html", "firewall.html", "sitemap.html", "broadbandconfig.html", "events_checked.html", "hiddenpage.html",
		"syslog_real_off.html", "syslog_select.html", "nattable_synthetic.html"} {
		pages[name] = fixture(t, name)
	}
	for name, body := range pages {
		if got, err := ParseDevices(body); !errors.Is(err, ErrDevicesPage) || got != nil {
			t.Errorf("%s: devices %v, err = %v, want ErrDevicesPage", name, got, err)
		}
	}
	for name, body := range map[string][]byte{
		"login_handshake1.html": fixture(t, "login_handshake1.html"),
		"login_nonce.html":      fixture(t, "login_nonce.html"),
		"sessions full":         sessionsFullPage(t),
	} {
		if got, err := ParseDevices(body); !errors.Is(err, ErrLoginRequired) || errors.Is(err, ErrDevicesPage) || got != nil {
			t.Errorf("%s: devices %v, err = %v, want ErrLoginRequired", name, got, err)
		}
	}
}

func TestConnectionSummary(t *testing.T) {
	tests := []struct {
		lines []string
		want  string
	}{
		{[]string{"Wi-Fi", "5 GHz Radio-1", "Type: Home", "Name: ATT-EXAMPLE"}, "Wi-Fi 5 GHz"},
		{[]string{"Wi-Fi", "2.4 GHz", "Type: Home", "Name: ATT-EXAMPLE"}, "Wi-Fi 2.4 GHz"},
		{[]string{"Wi-Fi 6 GHz Radio-3"}, "Wi-Fi 6 GHz"},
		{[]string{"Wireless", "5GHz"}, "Wi-Fi 5 GHz"},
		{[]string{"Wi-Fi"}, "Wi-Fi"},
		{[]string{"Wi-Fi", "Type: Guest", "Name: 6 GHz Ethernet LAN-3"}, "Wi-Fi"},
		{[]string{"Name: Home 5 GHz", "Wi-Fi", "Radio-2"}, "Wi-Fi"},
		{[]string{"Ethernet LAN-1"}, "Ethernet LAN-1"},
		{[]string{"Ethernet", "LAN 4"}, "Ethernet LAN-4"},
		{[]string{"LAN-2"}, "Ethernet LAN-2"},
		{[]string{"Ethernet"}, "Ethernet"},
		{[]string{"MoCA"}, "MoCA"},
		{[]string{"Name: secret"}, ""},
		{[]string{"Name: secret", "Type: Home"}, ""},
		{[]string{strings.Repeat("x", 41)}, ""},
		{[]string{"emoji \U0001F600"}, ""},
		{nil, ""},
	}
	for _, tt := range tests {
		if got := connectionSummary(tt.lines); got != tt.want {
			t.Errorf("connectionSummary(%q) = %q, want %q", tt.lines, got, tt.want)
		}
	}
}

func TestReadLineRows(t *testing.T) {
	rows := readLineRows([]byte("<p>outside</p><table>\r\n" +
		"<tr><th>A</th><td>one<br>two<BR/>three</td></tr>\n" +
		"<tr><th>B</th><td><pre>x\r\ny\rz\n</pre>after</td></tr>\n" +
		"<tr><th>C</th>\n</td></tr>\n" +
		"<tr><td colspan=2><hr /></td></tr>\n" +
		"<tr><th>D<script>no</script></th><td><div>p1</div><div>p2</div><img alt=\"img\">&nbsp;</td>\n" +
		"<tr><th>E</th><td>inner<table><tr><td>nested</td></tr></table>tail</td></tr>\n" +
		"</table><td>no table</td>"))
	var got []string
	for _, r := range rows {
		var cells []string
		for _, c := range r.cells {
			cells = append(cells, strings.Join(c.lines, "/"))
		}
		s := fmt.Sprintf("%d:%s", r.table, strings.Join(cells, "|"))
		if r.rule {
			s += " (rule)"
		}
		got = append(got, s)
	}
	want := []string{"0:A|one/two/three", "0:B|x/y/z/after", "0:C", "0: (rule)", "0:D|p1/p2", "1:nested", "0:E|inner/tail"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("rows = %q, want %q", got, want)
	}
}

// TestNetworkErrorsHaveNoContractCounterpart: the Network page's errors are the gateway's own.
func TestNetworkErrorsHaveNoContractCounterpart(t *testing.T) {
	for _, err := range []error{ErrNATPage, ErrDevicesPage} {
		for name, c := range contractSentinels {
			if errors.Is(err, c) {
				t.Errorf("%q matches contracts.%s", err, name)
			}
		}
	}
}

// ---------------------------------------------------------------- fake gateway with the Network pages

// networkGateway is the mock gateway (helpers_test.go) with the two pages the Network page reads,
// as on the real gateway: nattable.ha behind the same login as events.ha, devices.ha readable
// without it. It logs every request ("METHOD /path", in order) and answers a POST to either page
// with 405 without acting on it - the client must never send one.
type networkGateway struct {
	*mockGateway

	nat     []byte // nattable.ha once logged in
	devices []byte // devices.ha
	// devicesMode makes devices.ha answer otherwise: "login" (the login page), "redirect" (302
	// to login.ha), "elsewhere" (302 to home.ha), "error" (HTTP 500), "full" (all sessions in use).
	devicesMode string
	devCookie   bool // devices.ha hands out a session cookie of its own
	// natFault makes nattable.ha answer an authenticated session otherwise: "error" (HTTP 500 with
	// an error page), "elsewhere" (302 to hiddenpage.ha, as a page this firmware does not have),
	// "stall" (the headers and the start of the page, then nothing until the client gives up).
	// natStalled receives a value when a stalled answer has begun.
	natFault   string
	natStalled chan struct{}

	// observations
	log        []string // every request, in order
	devCookies []string // the Cookie header of each devices.ha request
	natServed  [][]byte
}

func newNetworkGateway(t testing.TB, code string) *networkGateway {
	return &networkGateway{mockGateway: newMockGateway(t, code, false),
		nat: fixture(t, "nattable_synthetic.html"), devices: fixture(t, "devices_real.html")}
}

func (g *networkGateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	g.mu.Lock()
	g.log = append(g.log, r.Method+" "+r.URL.Path)
	g.mu.Unlock()
	switch r.URL.Path {
	case "/cgi-bin/nattable.ha":
		g.serveNAT(w, r)
	case "/cgi-bin/devices.ha":
		g.serveDevices(w, r)
	default:
		g.mockGateway.ServeHTTP(w, r)
	}
}

func (g *networkGateway) serveNAT(w http.ResponseWriter, r *http.Request) {
	g.mu.Lock()
	locked := true
	defer func() {
		if locked {
			g.mu.Unlock()
		}
	}()
	g.requests++
	g.byPath[r.Method+" "+r.URL.Path]++
	switch {
	case r.Method != http.MethodGet:
		g.write(w, http.StatusMethodNotAllowed, nil)
		return
	case g.sessionsFull:
		g.write(w, http.StatusOK, sessionsFullPage(g.t))
		return
	}
	s, fresh := g.session(w, r)
	switch {
	case s.authed && g.natFault == "error":
		g.write(w, http.StatusInternalServerError, []byte("<html><title>500</title>internal error</html>"))
	case s.authed && g.natFault == "elsewhere":
		w.Header().Set("Location", "/cgi-bin/hiddenpage.ha")
		g.write(w, http.StatusFound, nil)
	case s.authed && g.natFault == "stall":
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(g.nat[:len(g.nat)/2])
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		stalled := g.natStalled
		g.mu.Unlock()
		locked = false
		if stalled != nil {
			stalled <- struct{}{}
		}
		<-r.Context().Done()
	case s.authed:
		g.natServed = append(g.natServed, g.nat)
		g.write(w, http.StatusOK, g.nat)
	case g.redirectToLogin:
		w.Header().Set("Location", "/cgi-bin/login.ha")
		g.write(w, http.StatusFound, nil)
	default:
		g.loginPage(w, s, fresh)
	}
}

func (g *networkGateway) serveDevices(w http.ResponseWriter, r *http.Request) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.requests++
	g.byPath[r.Method+" "+r.URL.Path]++
	g.devCookies = append(g.devCookies, r.Header.Get("Cookie"))
	if r.Method != http.MethodGet {
		g.write(w, http.StatusMethodNotAllowed, nil)
		return
	}
	if _, err := r.Cookie("SessionID"); err != nil && g.devCookie {
		http.SetCookie(w, &http.Cookie{Name: "SessionID", Value: "status-pages", Path: "/"})
	}
	switch {
	case g.sessionsFull, g.devicesMode == "full":
		g.write(w, http.StatusOK, sessionsFullPage(g.t))
	case g.devicesMode == "login":
		g.write(w, http.StatusOK, fixture(g.t, "login_nonce.html"))
	case g.devicesMode == "redirect":
		w.Header().Set("Location", "/cgi-bin/login.ha")
		g.write(w, http.StatusFound, nil)
	case g.devicesMode == "elsewhere":
		w.Header().Set("Location", "/cgi-bin/home.ha")
		g.write(w, http.StatusFound, nil)
	case g.devicesMode == "error":
		g.write(w, http.StatusInternalServerError, []byte("internal error"))
	default:
		g.write(w, http.StatusOK, g.devices)
	}
}

// requestLog returns every request so far ("METHOD /path"), in order.
func (g *networkGateway) requestLog() []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]string(nil), g.log...)
}

// authedSessions returns the ids of the sessions that logged in.
func (g *networkGateway) authedSessions() []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	var ids []string
	for id, s := range g.sessions {
		if s.authed {
			ids = append(ids, id)
		}
	}
	return ids
}

// startNetwork serves g and returns a client (access code testCode) for it.
func startNetwork(t *testing.T, g *networkGateway, clk *fakeClock, logs *syncBuffer) (*Client, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(g)
	t.Cleanup(srv.Close)
	return newTestClient(t, srv, clk, testCode, logs), srv
}

// countAccessCode makes c count how often it asks for the access code.
func countAccessCode(c *Client) *int {
	n := new(int)
	var mu sync.Mutex
	c.accessCode = func() (string, error) {
		mu.Lock()
		*n++
		mu.Unlock()
		return testCode, nil
	}
	return n
}

// onlyReads fails unless every request in log is a GET, apart from exactly logins POSTs of the
// login form: no form of the Network page's pages is ever posted.
func onlyReads(t *testing.T, log []string, logins int) {
	t.Helper()
	posts := 0
	for _, r := range log {
		switch {
		case strings.HasPrefix(r, "GET "):
		case r == "POST /cgi-bin/login.ha":
			posts++
		default:
			t.Errorf("request %q: the Network page's readers only read", r)
		}
	}
	if posts != logins {
		t.Errorf("%d login POSTs, want %d (requests: %q)", posts, logins, log)
	}
}

// ---------------------------------------------------------------- NATTable

// TestNATTableReadsThroughTheLogin: the NAT table is read with one login, whose session the next
// read within 5 minutes reuses (one GET), and nothing but GETs and that login's POST is sent.
func TestNATTableReadsThroughTheLogin(t *testing.T) {
	g := newNetworkGateway(t, testCode)
	clk := newFakeClock()
	c, srv := startNetwork(t, g, clk, nil)
	ctx := context.Background()

	got, raw, err := c.NATTable(ctx)
	if err != nil {
		t.Fatal(err)
	}
	compareNAT(t, got, wantNATSynthetic)
	if !bytes.Equal(raw, g.nat) {
		t.Error("raw is not the exact page served")
	}
	// The login starts on nattable.ha itself: the handshake GET, the GET with the nonce, the
	// login POST and the verifying GET, which is the page read.
	want := []string{"GET /cgi-bin/nattable.ha", "GET /cgi-bin/nattable.ha", "POST /cgi-bin/login.ha", "GET /cgi-bin/nattable.ha"}
	if log := g.requestLog(); !reflect.DeepEqual(log, want) {
		t.Errorf("requests = %q, want %q", log, want)
	}
	g.mu.Lock()
	ref := g.referers[0]
	g.mu.Unlock()
	if ref != srv.URL+"/cgi-bin/nattable.ha" {
		t.Errorf("login Referer = %q", ref)
	}

	// Within the reuse window the session is reused: one GET, no login.
	clk.Advance(4 * time.Minute)
	if got, raw, err = c.NATTable(ctx); err != nil {
		t.Fatal(err)
	}
	compareNAT(t, got, wantNATSynthetic)
	if !bytes.Equal(raw, g.nat) {
		t.Error("raw is not the exact page served")
	}
	clk.Advance(4 * time.Minute) // 4 minutes after the last use: still within the window
	if _, _, err = c.NATTable(ctx); err != nil {
		t.Fatal(err)
	}
	log := g.requestLog()
	if want = append(want, "GET /cgi-bin/nattable.ha", "GET /cgi-bin/nattable.ha"); !reflect.DeepEqual(log, want) {
		t.Errorf("requests = %q, want %q", log, want)
	}
	onlyReads(t, log, 1)
	if _, logins, _ := g.counts(); logins != 1 {
		t.Errorf("logins = %d, want 1", logins)
	}
}

// TestNATTableSessionReuseEnds: after 5 idle minutes, or once the gateway forgets the session, the
// next read logs in again - within the login policy.
func TestNATTableSessionReuseEnds(t *testing.T) {
	g := newNetworkGateway(t, testCode)
	clk := newFakeClock()
	c, _ := startNetwork(t, g, clk, nil)
	ctx := context.Background()
	if _, _, err := c.NATTable(ctx); err != nil {
		t.Fatal(err)
	}
	clk.Advance(sessionReuse)
	if _, _, err := c.NATTable(ctx); err != nil {
		t.Fatal(err)
	}
	if _, logins, _ := g.counts(); logins != 2 {
		t.Errorf("logins = %d, want 2 (no reuse after 5 idle minutes)", logins)
	}
	// The gateway forgets the session: the read finds the login page, and the next login has to
	// wait for the one-a-minute limit.
	g.expireSessions()
	clk.Advance(30 * time.Second)
	if _, _, err := c.NATTable(ctx); !errors.Is(err, ErrLoginThrottled) {
		t.Fatalf("err = %v, want ErrLoginThrottled", err)
	}
	clk.Advance(31 * time.Second)
	got, _, err := c.NATTable(ctx)
	if err != nil {
		t.Fatal(err)
	}
	compareNAT(t, got, wantNATSynthetic)
	if _, logins, _ := g.counts(); logins != 3 {
		t.Errorf("logins = %d, want 3", logins)
	}
	onlyReads(t, g.requestLog(), 3)
}

// TestNATTableReturnsRawPageWithParseError: a page that is not understood is still returned, so
// that what the gateway showed can be looked at.
func TestNATTableReturnsRawPageWithParseError(t *testing.T) {
	g := newNetworkGateway(t, testCode)
	g.nat = fixture(t, "sysinfo.html")
	c, _ := startNetwork(t, g, newFakeClock(), nil)
	got, raw, err := c.NATTable(context.Background())
	if !errors.Is(err, ErrNATPage) {
		t.Fatalf("err = %v, want ErrNATPage", err)
	}
	if !reflect.DeepEqual(got, noNATTable()) {
		t.Errorf("table = %+v, want an empty one with unknown totals", got)
	}
	if !bytes.Equal(raw, g.nat) {
		t.Error("raw is not the page served")
	}
}

// TestNATTableLoginPolicy: the NAT table goes through the same login policy as the settings:
// one attempt a minute, none after three rejections within an hour, none while the gateway's
// session pool is full, none without an access code - and the errors match the contracts'.
func TestNATTableLoginPolicy(t *testing.T) {
	ctx := context.Background()
	t.Run("rejected logins", func(t *testing.T) {
		g := newNetworkGateway(t, "the-real-code")
		clk := newFakeClock()
		c, _ := startNetwork(t, g, clk, nil)
		for i := 1; i <= maxFailures; i++ {
			got, raw, err := c.NATTable(ctx)
			if !errors.Is(err, ErrAuth) || raw != nil || !reflect.DeepEqual(got, noNATTable()) {
				t.Fatalf("attempt %d: err = %v, raw %d bytes, want ErrAuth", i, err, len(raw))
			}
			checkSentinels(t, err, ErrAuth, contracts.ErrGatewayAuth)
			// Immediately afterwards no attempt is made (the lock takes over after the third).
			req := len(g.requestLog())
			wantErr, contract := ErrLoginThrottled, contracts.ErrGatewayLoginThrottled
			if i == maxFailures {
				wantErr, contract = ErrAuthLocked, contracts.ErrGatewayAuthLocked
			}
			_, _, err = c.NATTable(ctx)
			var ce *CooldownError
			if !errors.As(err, &ce) {
				t.Fatalf("attempt %d: err = %v, want a CooldownError", i, err)
			}
			checkSentinels(t, err, wantErr, contract)
			if len(g.requestLog()) != req {
				t.Fatal("a throttled read reached the gateway")
			}
			clk.Advance(loginSpacing + time.Second)
		}
		req := len(g.requestLog())
		if _, _, err := c.NATTable(ctx); !errors.Is(err, ErrAuthLocked) {
			t.Fatalf("err = %v, want ErrAuthLocked", err)
		}
		if len(g.requestLog()) != req {
			t.Error("a locked client contacted the gateway")
		}
		onlyReads(t, g.requestLog(), maxFailures)
	})
	t.Run("sessions full", func(t *testing.T) {
		g := newNetworkGateway(t, testCode)
		g.sessionsFull = true
		clk := newFakeClock()
		c, _ := startNetwork(t, g, clk, nil)
		_, _, err := c.NATTable(ctx)
		var ce *CooldownError
		if !errors.As(err, &ce) || !ce.Until.Equal(clk.Now().Add(sessionsFullCooldown)) {
			t.Fatalf("err = %v, want ErrSessionsFull with a 5 minute cooldown", err)
		}
		checkSentinels(t, err, ErrSessionsFull, contracts.ErrGatewaySessionsFull)
		req := len(g.requestLog())
		clk.Advance(2 * time.Minute)
		if _, _, err := c.NATTable(ctx); !errors.Is(err, ErrSessionsFull) {
			t.Fatalf("during the cooldown: err = %v", err)
		}
		if n := len(g.requestLog()) - req; n != 0 {
			t.Errorf("%d requests during the cooldown", n)
		}
		clk.Advance(3*time.Minute + time.Second)
		g.set(func(m *mockGateway) { m.sessionsFull = false })
		if _, _, err := c.NATTable(ctx); err != nil {
			t.Fatalf("after the cooldown: %v", err)
		}
		onlyReads(t, g.requestLog(), 1)
	})
	t.Run("no access code", func(t *testing.T) {
		g := newNetworkGateway(t, testCode)
		srv := httptest.NewServer(g)
		defer srv.Close()
		c := newTestClient(t, srv, newFakeClock(), "", nil)
		_, _, err := c.NATTable(ctx)
		checkSentinels(t, err, ErrNoAccessCode, contracts.ErrGatewayNoAccessCode)
		if log := g.requestLog(); len(log) != 0 {
			t.Errorf("requests without an access code: %q", log)
		}
	})
	t.Run("protected page redirects to login.ha", func(t *testing.T) {
		g := newNetworkGateway(t, testCode)
		g.redirectToLogin = true
		c, srv := startNetwork(t, g, newFakeClock(), nil)
		got, _, err := c.NATTable(ctx)
		if err != nil {
			t.Fatal(err)
		}
		compareNAT(t, got, wantNATSynthetic)
		g.mu.Lock()
		ref := g.referers[0]
		g.mu.Unlock()
		if ref != srv.URL+"/cgi-bin/login.ha" {
			t.Errorf("login Referer = %q", ref)
		}
		onlyReads(t, g.requestLog(), 1)
	})
}

// TestNATTableSharesTheSession: the settings check and the NAT table share one login, and reads
// that run at the same time are serialized onto one session.
func TestNATTableSharesTheSession(t *testing.T) {
	g := newNetworkGateway(t, testCode)
	c, _ := startNetwork(t, g, newFakeClock(), nil)
	if _, _, err := c.Notification(context.Background()); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 6)
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, _, err := c.NATTable(context.Background())
			if err == nil && len(got.Sessions) != len(wantNATSynthetic.Sessions) {
				err = fmt.Errorf("%d sessions", len(got.Sessions))
			}
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Error(err)
		}
	}
	if _, logins, _ := g.counts(); logins != 1 {
		t.Errorf("logins = %d, want 1", logins)
	}
	g.mu.Lock()
	gets := g.byPath["GET /cgi-bin/nattable.ha"]
	g.mu.Unlock()
	if gets != 6 {
		t.Errorf("GET nattable.ha = %d, want 6 (one per read, in the session of the settings check)", gets)
	}
	onlyReads(t, g.requestLog(), 1)
}

// ---------------------------------------------------------------- Devices

// TestDevicesReadsWithoutLogin: the Device List is one GET - no login, not even the access code
// is asked for - in the status pages' cookie session, never in the authenticated one.
func TestDevicesReadsWithoutLogin(t *testing.T) {
	g := newNetworkGateway(t, testCode)
	g.devCookie = true
	c, _ := startNetwork(t, g, newFakeClock(), nil)
	asked := countAccessCode(c)
	ctx := context.Background()

	got, raw, err := c.Devices(ctx)
	if err != nil {
		t.Fatal(err)
	}
	compareDevices(t, got, wantRealDevices)
	if !bytes.Equal(raw, g.devices) {
		t.Error("raw is not the exact page served")
	}
	if log := g.requestLog(); !reflect.DeepEqual(log, []string{"GET /cgi-bin/devices.ha"}) {
		t.Errorf("requests = %q, want one GET of devices.ha", log)
	}
	if *asked != 0 {
		t.Errorf("the access code was asked for %d times", *asked)
	}

	// After a login for the NAT table, the Device List is still read in the status pages' session.
	if _, _, err := c.NATTable(ctx); err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.Devices(ctx); err != nil {
		t.Fatal(err)
	}
	authed := g.authedSessions()
	if len(authed) != 1 {
		t.Fatalf("authenticated sessions = %q, want one", authed)
	}
	g.mu.Lock()
	cookies := append([]string(nil), g.devCookies...)
	g.mu.Unlock()
	if want := []string{"", "SessionID=status-pages"}; !reflect.DeepEqual(cookies, want) {
		t.Errorf("devices.ha cookies = %q, want %q", cookies, want)
	}
	for _, ck := range cookies {
		if strings.Contains(ck, authed[0]) {
			t.Errorf("devices.ha was read with the authenticated session's cookie %q", ck)
		}
	}
	onlyReads(t, g.requestLog(), 1)
	g.mu.Lock()
	devGets := g.byPath["GET /cgi-bin/devices.ha"]
	g.mu.Unlock()
	if devGets != 2 {
		t.Errorf("GET devices.ha = %d, want 2", devGets)
	}
}

// TestDevicesAnswersThatAreNotTheList: a login page, a redirect, the session pool being full or
// an HTTP error is an error that says so - and never leads to a login or to a POST.
func TestDevicesAnswersThatAreNotTheList(t *testing.T) {
	tests := []struct {
		mode     string
		is       error  // the error must match
		contains string // and say
		raw      bool   // the page is returned
	}{
		{"login", ErrLoginRequired, "devices.ha", true},
		{"redirect", ErrLoginRequired, "devices.ha", true},
		{"elsewhere", nil, "unexpected HTTP status 302", true},
		{"error", nil, "unexpected HTTP status 500", true},
		{"full", ErrSessionsFull, "all web server sessions are in use", true},
	}
	for _, tt := range tests {
		t.Run(tt.mode, func(t *testing.T) {
			g := newNetworkGateway(t, testCode)
			g.devicesMode = tt.mode
			clk := newFakeClock()
			c, _ := startNetwork(t, g, clk, nil)
			asked := countAccessCode(c)
			got, raw, err := c.Devices(context.Background())
			if err == nil || got != nil {
				t.Fatalf("devices %v, err = %v", got, err)
			}
			if tt.is != nil && !errors.Is(err, tt.is) {
				t.Errorf("err = %v, want %v", err, tt.is)
			}
			if !strings.Contains(err.Error(), tt.contains) {
				t.Errorf("err = %q, want it to say %q", err, tt.contains)
			}
			if tt.raw != (raw != nil) {
				t.Errorf("raw = %d bytes", len(raw))
			}
			if log := g.requestLog(); !reflect.DeepEqual(log, []string{"GET /cgi-bin/devices.ha"}) {
				t.Errorf("requests = %q, want one GET of devices.ha", log)
			}
			if *asked != 0 {
				t.Errorf("the access code was asked for %d times", *asked)
			}
			if tt.mode == "full" {
				// Like any page saying so, it pauses the logins: the NAT table is not read.
				checkSentinels(t, err, ErrSessionsFull, contracts.ErrGatewaySessionsFull)
				var ce *CooldownError
				if !errors.As(err, &ce) || !ce.Until.Equal(clk.Now().Add(sessionsFullCooldown)) {
					t.Errorf("err = %v, want a 5 minute cooldown", err)
				}
				if _, _, err := c.NATTable(context.Background()); !errors.Is(err, ErrSessionsFull) {
					t.Errorf("NATTable during the cooldown: err = %v", err)
				}
				if log := g.requestLog(); len(log) != 1 {
					t.Errorf("requests during the cooldown: %q", log[1:])
				}
			} else {
				for name, cs := range contractSentinels {
					if errors.Is(err, cs) {
						t.Errorf("err %q matches contracts.%s", err, name)
					}
				}
			}
		})
	}
}

func TestDevicesParseErrorAndFailures(t *testing.T) {
	t.Run("a page that is not the list", func(t *testing.T) {
		g := newNetworkGateway(t, testCode)
		g.devices = fixture(t, "sysinfo.html")
		c, _ := startNetwork(t, g, newFakeClock(), nil)
		got, raw, err := c.Devices(context.Background())
		if !errors.Is(err, ErrDevicesPage) || got != nil || !bytes.Equal(raw, g.devices) {
			t.Errorf("devices %v, raw %d bytes, err = %v; want ErrDevicesPage with the page", got, len(raw), err)
		}
	})
	t.Run("no devices", func(t *testing.T) {
		g := newNetworkGateway(t, testCode)
		g.devices = sub(t, fixture(t, "devices_real.html"), `(?s)(<table class="table100"[^>]*>).*?(</table>)`, "${1}${2}")
		c, _ := startNetwork(t, g, newFakeClock(), nil)
		got, _, err := c.Devices(context.Background())
		if err != nil || got == nil || len(got) != 0 {
			t.Errorf("devices %v, err = %v; want an empty list", got, err)
		}
	})
	t.Run("unreachable", func(t *testing.T) {
		srv := httptest.NewServer(http.NotFoundHandler())
		srv.Close()
		c := newTestClient(t, srv, newFakeClock(), testCode, nil)
		got, raw, err := c.Devices(context.Background())
		if err == nil || got != nil || raw != nil || !strings.Contains(err.Error(), "devices.ha") {
			t.Errorf("devices %v, raw %v, err = %v", got, raw, err)
		}
	})
	t.Run("canceled", func(t *testing.T) {
		g := newNetworkGateway(t, testCode)
		c, _ := startNetwork(t, g, newFakeClock(), nil)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, _, err := c.Devices(ctx); !errors.Is(err, context.Canceled) {
			t.Errorf("err = %v, want context.Canceled", err)
		}
		if log := g.requestLog(); len(log) != 0 {
			t.Errorf("requests = %q", log)
		}
	})
	t.Run("body over the cap", func(t *testing.T) {
		g := newNetworkGateway(t, testCode)
		c, _ := startNetwork(t, g, newFakeClock(), nil)
		c.maxBody = 1024
		got, raw, err := c.Devices(context.Background())
		if err == nil || got != nil || len(raw) != 1024 || !strings.Contains(err.Error(), "truncated") {
			t.Errorf("devices %v, raw %d bytes, err = %v", got, len(raw), err)
		}
	})
}

// TestNetworkReadsNeedThePinnedCertificate: with a certificate that does not match the pin,
// neither page is read - no HTTP request at all, so no login form - and both errors match the
// contracts' certificate rejection; with the pinned certificate both pages are read.
func TestNetworkReadsNeedThePinnedCertificate(t *testing.T) {
	g := newNetworkGateway(t, testCode)
	srv := httptest.NewUnstartedServer(g)
	srv.Config.ErrorLog = log.New(io.Discard, "", 0) // rejected handshakes are expected
	srv.StartTLS()
	t.Cleanup(srv.Close)
	ctx := context.Background()

	c := tlsClient(srv, strings.Repeat("ab", 32), nil)
	c.accessCode = func() (string, error) { return testCode, nil } // the NAT table's login gets as far as the handshake
	devices, raw, err := c.Devices(ctx)
	checkSentinels(t, err, ErrCertRejected, contracts.ErrGatewayCertRejected)
	if devices != nil || raw != nil {
		t.Errorf("devices %v, raw %d bytes with a rejected certificate", devices, len(raw))
	}
	nat, raw, err := c.NATTable(ctx)
	checkSentinels(t, err, ErrCertRejected, contracts.ErrGatewayCertRejected)
	if !reflect.DeepEqual(nat, noNATTable()) || raw != nil {
		t.Errorf("table %+v, raw %d bytes with a rejected certificate", nat, len(raw))
	}
	if log := g.requestLog(); len(log) != 0 {
		t.Errorf("requests reached the gateway: %q", log)
	}

	c = tlsClient(srv, sha256hex(srv.Certificate().Raw), nil)
	c.handshakeBackoff = time.Millisecond
	asked := countAccessCode(c)
	if devices, _, err = c.Devices(ctx); err != nil {
		t.Fatal(err)
	}
	compareDevices(t, devices, wantRealDevices)
	if nat, _, err = c.NATTable(ctx); err != nil {
		t.Fatal(err)
	}
	compareNAT(t, nat, wantNATSynthetic)
	if *asked != 1 {
		t.Errorf("the access code was asked for %d times, want once (the NAT table's login)", *asked)
	}
	onlyReads(t, g.requestLog(), 1)
}

// TestNetworkSecretsNeverLeak drives the NAT table's paths (success, wrong code, throttling,
// lockout, sessions full, a page not understood) and the Device List's with debug logging:
// neither the access code nor any login hash may appear in an error or in the log.
func TestNetworkSecretsNeverLeak(t *testing.T) {
	var logs syncBuffer
	var errs, hashes []string
	ctx := context.Background()
	for _, sc := range []struct {
		code  string
		setup func(g *networkGateway)
	}{
		{testCode, nil},
		{testCode + "x", nil},
		{testCode, func(g *networkGateway) { g.sessionsFull = true }},
		{testCode, func(g *networkGateway) { g.nat = fixture(t, "home.html") }},
		{testCode, func(g *networkGateway) { g.devicesMode = "login" }},
	} {
		g := newNetworkGateway(t, testCode)
		if sc.setup != nil {
			sc.setup(g)
		}
		clk := newFakeClock()
		srv := httptest.NewServer(g)
		c := newTestClient(t, srv, clk, sc.code, &logs)
		for i := 0; i < 5; i++ {
			if _, _, err := c.NATTable(ctx); err != nil {
				errs = append(errs, err.Error())
			}
			if _, _, err := c.Devices(ctx); err != nil {
				errs = append(errs, err.Error())
			}
			clk.Advance(loginSpacing + time.Second)
		}
		srv.Close()
		hashes = append(hashes, g.hashes()...)
	}
	if len(hashes) == 0 || len(errs) == 0 {
		t.Fatalf("scenarios did not exercise logins (%d hashes, %d errors)", len(hashes), len(errs))
	}
	for _, e := range errs {
		mustNotContainSecret(t, "error", e, testCode, hashes)
	}
	mustNotContainSecret(t, "log", logs.String(), testCode, hashes)
	for _, want := range []string{"gateway login rejected", "gateway login succeeded", "gateway NAT table read"} {
		if !strings.Contains(logs.String(), want) {
			t.Errorf("expected %q in the operational log", want)
		}
	}
}
