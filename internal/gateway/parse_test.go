package gateway

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"attmonitor/internal/model"
)

func i64(v int64) *int64 { return &v }

// ---------------------------------------------------------------- sysinfo

func TestParseSysInfoFixture(t *testing.T) {
	got, err := ParseSysInfo(fixture(t, "sysinfo.html"))
	if err != nil {
		t.Fatal(err)
	}
	want := &model.SystemInfo{
		Manufacturer:       "NOKIA",
		Model:              "BGW320-505",
		Serial:             "N00SERIAL00000",
		SoftwareVersion:    "6.34.7",
		WANMAC:             "00:00:5e:00:53:01",
		FirstUseDate:       "2026-02-17T18:20:24Z",
		HardwareVersion:    "02001E0046004F",
		UptimeRaw:          "274686",
		UptimeSec:          274686,
		GatewayTimeRaw:     "2026-10-04T22:10:44",
		GatewayTimePresent: true,
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ParseSysInfo =\n%+v\nwant\n%+v", got, want)
	}
}

// Fixture edits of the "Current Date/Time" row (sysinfo.html).
const (
	reClockValue = `(Current Date/Time</th>\s*<td class="col2">)\s*2026-10-04T22:10:44\s*`
	reClockRow   = `(?s)<tr>\s*<th scope="row">Current Date/Time</th>.*?</tr>`
)

// TestParseSysInfoClockRowPresence: GatewayTimePresent tells a blank "Current Date/Time"
// (the gateway blanks it while the WAN is down) apart from a page without that row.
func TestParseSysInfoClockRowPresence(t *testing.T) {
	base := fixture(t, "sysinfo.html")
	tests := []struct {
		name        string
		body        []byte
		wantPresent bool
		wantRaw     string
	}{
		{"row with the time", base, true, "2026-10-04T22:10:44"},
		{"blank row (WAN down)", sub(t, base, reClockValue, "${1}"), true, ""},
		{"row of no-break spaces", sub(t, base, reClockValue, "${1}&nbsp;"+nbspLatin1+replChar), true, ""},
		{"row missing", sub(t, base, reClockRow, ""), false, ""},
		{"partial page without the row", []byte(`<h1>System Information</h1><table><tr><th>Model Number</th><td>BGW320-505</td></tr></table>`), false, ""},
		{"partial page with a blank row", []byte(`<table><tr><th>Current Date/Time</th><td> </td></tr></table>`), true, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			si, err := ParseSysInfo(tt.body)
			if err != nil {
				t.Fatal(err)
			}
			if si.GatewayTimePresent != tt.wantPresent || si.GatewayTimeRaw != tt.wantRaw {
				t.Errorf("GatewayTimePresent=%v GatewayTimeRaw=%q, want %v %q", si.GatewayTimePresent, si.GatewayTimeRaw, tt.wantPresent, tt.wantRaw)
			}
		})
	}
}

func TestParseSysInfoVariants(t *testing.T) {
	base := fixture(t, "sysinfo.html")
	tests := []struct {
		name       string
		body       []byte
		wantUptime int64
		wantRaw    string
		wantTime   string
	}{
		{"blank current date/time (WAN down)",
			sub(t, base, `(Current Date/Time</th>\s*<td class="col2">)\s*2026-10-04T22:10:44\s*`, "${1}"),
			274686, "274686", ""},
		{"D:H:M:S uptime",
			sub(t, base, `(Time Since Last Reboot</th>\s*<td class="col2">)274686`, "${1}3:04:18:06"),
			274686, "3:04:18:06", "2026-10-04T22:10:44"},
		{"H:M:S uptime",
			sub(t, base, `(Time Since Last Reboot</th>\s*<td class="col2">)274686`, "${1}76:18:06"),
			274686, "76:18:06", "2026-10-04T22:10:44"},
		{"unparseable uptime",
			sub(t, base, `(Time Since Last Reboot</th>\s*<td class="col2">)274686`, "${1}3 days"),
			-1, "3 days", "2026-10-04T22:10:44"},
		{"uptime row missing",
			sub(t, base, `(?s)<tr>\s*<th scope="row">Time Since Last Reboot</th>.*?</tr>`, ""),
			-1, "", "2026-10-04T22:10:44"},
		{"LF line endings", bytes.ReplaceAll(base, []byte("\r\n"), []byte("\n")),
			274686, "274686", "2026-10-04T22:10:44"},
		{"latin-1 copyright byte", bytes.ReplaceAll(base, []byte("&copy;"), []byte(copyLatin1)),
			274686, "274686", "2026-10-04T22:10:44"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			si, err := ParseSysInfo(tt.body)
			if err != nil {
				t.Fatal(err)
			}
			if si.UptimeSec != tt.wantUptime || si.UptimeRaw != tt.wantRaw || si.GatewayTimeRaw != tt.wantTime {
				t.Errorf("uptime=%d raw=%q time=%q, want %d %q %q", si.UptimeSec, si.UptimeRaw, si.GatewayTimeRaw,
					tt.wantUptime, tt.wantRaw, tt.wantTime)
			}
			if si.Model != "BGW320-505" || si.SoftwareVersion != "6.34.7" {
				t.Errorf("model/firmware = %q/%q", si.Model, si.SoftwareVersion)
			}
		})
	}
}

func TestParseUptime(t *testing.T) {
	tests := []struct {
		in   string
		want int64
	}{
		{"274686", 274686},
		{" 274686 ", 274686},
		{"0", 0},
		{"3:04:18:06", 274686},
		{"03:04:18:06", 274686},
		{"76:18:06", 274686},
		{"0:00:00:00", 0},
		{"400:23:59:59", 400*86400 + 23*3600 + 59*60 + 59},
		{"", -1},
		{"-5", -1},
		{"+5", -1},
		{"12.5", -1},
		{"3 days", -1},
		{"1:2", -1},
		{"1:2:3:4:5", -1},
		{"1:24:00:00", -1}, // hours out of range in D:H:M:S
		{"1:00:60:00", -1},
		{"1:00:00:60", -1},
		{"10:60:00", -1},
		{"1::00:00", -1},
		{"9999999999999", -1},              // more than 100 years
		{"99999999999999999999999999", -1}, // overflow
		{"Unknown", -1},
	}
	for _, tt := range tests {
		if got := parseUptime(tt.in); got != tt.want {
			t.Errorf("parseUptime(%q) = %d, want %d", tt.in, got, tt.want)
		}
	}
}

// ---------------------------------------------------------------- broadbandstatistics

func TestParseBroadbandFixture(t *testing.T) {
	got, err := ParseBroadband(fixture(t, "broadbandstatistics.html"))
	if err != nil {
		t.Fatal(err)
	}
	named := model.BroadbandStatus{
		ConnectionSource: "FIBER",
		Connection:       "Up",
		NetworkType:      "Lightspeed",
		IPv4:             "203.0.113.10",
		GatewayIPv4:      "203.0.113.1",
		PrimaryDNS:       "68.94.156.9",
		SecondaryDNS:     "68.94.157.9",
		MTU:              "1500",
		LineState:        "Up",
		SpeedMbps:        "10000",
		Duplex:           "full",
		IPv6Status:       "Available",
		IPv6Global:       "2001:db8:7118:123f::1",
		IPv6Gateway:      "fe80::e681:84ff:fe4d:680f",
		PONLinkStatus:    "OPERATION (O5)",
		UNIStatus:        "up",
	}
	gotNamed := *got
	gotNamed.Counters, gotNamed.Values = nil, nil
	if !reflect.DeepEqual(gotNamed, named) {
		t.Errorf("named fields =\n%+v\nwant\n%+v", gotNamed, named)
	}
	wantCounters := map[string]int64{
		"IPv4 Statistics/Receive Packets":    38841981,
		"IPv4 Statistics/Transmit Packets":   8600821,
		"IPv4 Statistics/Receive Bytes":      3563015693,
		"IPv4 Statistics/Transmit Bytes":     345288498,
		"IPv4 Statistics/Receive Unicast":    38844974,
		"IPv4 Statistics/Transmit Unicast":   8604205,
		"IPv4 Statistics/Receive Multicast":  0,
		"IPv4 Statistics/Transmit Multicast": 1493,
		"IPv4 Statistics/Receive Drops":      0,
		"IPv4 Statistics/Transmit Drops":     0,
		"IPv4 Statistics/Receive Errors":     0,
		"IPv4 Statistics/Transmit Errors":    0,
		"IPv4 Statistics/Collisions":         0,
	}
	if !reflect.DeepEqual(got.Counters, wantCounters) {
		t.Errorf("Counters =\n%v\nwant\n%v", got.Counters, wantCounters)
	}
	wantValues := map[string]string{
		"Primary Broadband/Primary DNS":          "68.94.156.9",
		"Primary Broadband/Secondary DNS Name":   "", // label carries a trailing &nbsp;
		"Primary Broadband/MTU":                  "1500",
		"Primary Broadband/MAC Address":          "00:00:5e:00:53:02",
		"IPv6/Primary DNS":                       "",
		"IPv6/Secondary DNS":                     "",
		"IPv6/MTU":                               "1500",
		"IPv6/Service Type":                      "native IPv6",
		"IPv6/Link Local Address":                "fe80::be51:5fff:fe04:ac11",
		"Ethernet Status/Current Speed (Mbps)":   "10000",
		"GPON Status/PON Link Status":            "OPERATION (O5)",
		"GPON Status/UNI Status":                 "up",
		"IPv4 Statistics/Receive Bytes":          "3563015693",
		"Primary Broadband/Broadband Connection": "Up",
	}
	for k, v := range wantValues {
		if gv, ok := got.Values[k]; !ok || gv != v {
			t.Errorf("Values[%q] = %q (present %v), want %q", k, gv, ok, v)
		}
	}
	if len(got.Values) != 37 {
		t.Errorf("len(Values) = %d, want 37 (every label/value row)", len(got.Values))
	}
}

// TestParseBroadbandSectionAware reorders sections so that the IPv6 block (with its own
// "Primary DNS" and "MTU") precedes the IPv4 one, and adds an IPv6 Statistics block.
func TestParseBroadbandSectionAware(t *testing.T) {
	page := []byte(`<html><head><title>Broadband Status</title></head><body>
<h2>IPv6</h2><table>
<tr><th>Status</th><td>Unavailable</td></tr>
<tr><th>Primary DNS</th><td>2001:db8::53</td></tr>
<tr><th>MTU</th><td>1492</td></tr>
</table>
<h2>Primary Broadband</h2><table>
<tr><th>Broadband Connection</th><td>Down</td></tr>
<tr><th>Broadband IPv4 Address</th><td>0.0.0.0</td></tr>
<tr><th>Primary DNS</th><td>68.94.156.9</td></tr>
<tr><th>Secondary DNS</th><td></td></tr>
<tr><th>MTU</th><td>1500</td></tr>
</table>
<h2>IPv6 Statistics</h2><table>
<tr><th>Transmit Packets</th><td>42</td></tr>
<tr><th>Transmit Errors</th><td>n/a</td></tr>
</table></body></html>`)
	got, err := ParseBroadband(page)
	if err != nil {
		t.Fatal(err)
	}
	if got.PrimaryDNS != "68.94.156.9" || got.MTU != "1500" || got.SecondaryDNS != "" {
		t.Errorf("IPv4 DNS/MTU = %q/%q/%q, want 68.94.156.9/1500/\"\"", got.PrimaryDNS, got.MTU, got.SecondaryDNS)
	}
	if got.IPv6Status != "Unavailable" || got.Connection != "Down" || got.IPv4 != "0.0.0.0" {
		t.Errorf("IPv6Status=%q Connection=%q IPv4=%q", got.IPv6Status, got.Connection, got.IPv4)
	}
	if got.Values["IPv6/Primary DNS"] != "2001:db8::53" || got.Values["IPv6/MTU"] != "1492" {
		t.Errorf("IPv6 values = %v", got.Values)
	}
	if want := map[string]int64{"IPv6 Statistics/Transmit Packets": 42}; !reflect.DeepEqual(got.Counters, want) {
		t.Errorf("Counters = %v, want %v", got.Counters, want)
	}
	if got.Values["IPv6 Statistics/Transmit Errors"] != "n/a" {
		t.Errorf("non-numeric counter row must stay in Values: %v", got.Values)
	}
}

func TestParseBroadbandDuplicateLabelsKept(t *testing.T) {
	page := []byte(`<h2>GPON Status</h2><table><tr><th>PON Link Status</th><td>OPERATION (O5)</td></tr>
<tr><th>PON Link Status</th><td>OPERATION (O5) second</td></tr></table>`)
	got, err := ParseBroadband(page)
	if err != nil {
		t.Fatal(err)
	}
	if got.PONLinkStatus != "OPERATION (O5)" {
		t.Errorf("first occurrence must win, got %q", got.PONLinkStatus)
	}
	if got.Values["GPON Status/PON Link Status (2)"] != "OPERATION (O5) second" {
		t.Errorf("duplicate row must be kept with a suffix: %v", got.Values)
	}
}

// ---------------------------------------------------------------- fiberstat

func TestParseFiberFixture(t *testing.T) {
	got, err := ParseFiber(fixture(t, "fiberstat.html"))
	if err != nil {
		t.Fatal(err)
	}
	named := *got
	named.Measures, named.Values = nil, nil
	wantNamed := model.FiberStatus{
		OpticalStatus:  "Up",
		FiberModule:    "Unavailable",
		LastChangeRaw:  "1791151188",
		LastChangeUnix: 1791151188,
		LinkState:      "Up",
		WaveLength:     "1270 nm",
		VendorName:     "HUMAX Networks",
		VendorPN:       "HNXGSPP-MAAMC",
		VendorSN:       "DV000000000000",
		RxLOSState:     "1",
		OptLOS:         "0",
		TxFaultState:   "0",
	}
	if !reflect.DeepEqual(named, wantNamed) {
		t.Errorf("named fields =\n%+v\nwant\n%+v", named, wantNamed)
	}
	th := func(active bool, raw string, v int64) model.Threshold {
		return model.Threshold{Active: active, Raw: raw, Threshold: i64(v)}
	}
	wantMeasures := []model.DMIMeasure{
		{Name: "Temperature", CurrentRaw: "35", Current: i64(35), Unit: "C",
			LowAlarm: th(false, "0 (Threshold -10)", -10), HighAlarm: th(false, "0 (Threshold 80)", 80),
			LowWarn: th(false, "0 (Threshold -5)", -5), HighWarn: th(false, "0 (Threshold 75)", 75)},
		{Name: "Vcc", CurrentRaw: "3", Current: i64(3), Unit: "V",
			LowAlarm: th(false, "0 (Threshold 3)", 3), HighAlarm: th(false, "0 (Threshold 3)", 3),
			LowWarn: th(false, "0 (Threshold 3)", 3), HighWarn: th(false, "0 (Threshold 3)", 3)},
		{Name: "Tx Bias", CurrentRaw: "6", Current: i64(6), Unit: "mA",
			LowAlarm: th(false, "0 (Threshold 0)", 0), HighAlarm: th(false, "0 (Threshold 500)", 500),
			LowWarn: th(false, "0 (Threshold 0)", 0), HighWarn: th(false, "0 (Threshold 400)", 400)},
		{Name: "Tx Power", CurrentRaw: "37", Current: i64(37), Unit: "0.1dBm",
			LowAlarm: th(false, "0 (Threshold -10)", -10), HighAlarm: th(false, "0 (Threshold 80)", 80),
			LowWarn: th(false, "0 (Threshold 0)", 0), HighWarn: th(false, "0 (Threshold 70)", 70)},
		{Name: "Rx Power", CurrentRaw: "-315", Current: i64(-315), Unit: "0.1dBm",
			LowAlarm: th(true, "1 (Threshold -295)", -295), HighAlarm: th(false, "0 (Threshold -90)", -90),
			LowWarn: th(true, "1 (Threshold -292)", -292), HighWarn: th(false, "0 (Threshold -100)", -100)},
	}
	if !reflect.DeepEqual(got.Measures, wantMeasures) {
		t.Errorf("Measures =\n%+v\nwant\n%+v", got.Measures, wantMeasures)
	}
	for k, v := range map[string]string{
		"Optical WAN Operational Status": "Up",
		"Last Change":                    "1791151188",
		"Vendor OUI":                     "484D58",
		"OPT Cooled Trans":               "uncooled transceiver",
		"SFF Ver Compliance":             "rev 11.0",
		"Rx Power/Current":               "-315",
		"Rx Power/Low Alarm":             "1 (Threshold -295)",
		"Rx Power/Low Warning":           "1 (Threshold -292)",
		"Rx Power/High Alarm":            "0 (Threshold -90)",
		"Tx Power/Current":               "37",
	} {
		if got.Values[k] != v {
			t.Errorf("Values[%q] = %q, want %q", k, got.Values[k], v)
		}
	}
	// 50 label/value rows + 5 measures x (current + 4 thresholds).
	if len(got.Values) != 50+25 {
		t.Errorf("len(Values) = %d, want 75", len(got.Values))
	}
}

// TestParseFiberHeadingSeparators covers the separators seen (or expected) between the
// measure name and "Currently": &nbsp; entities, U+00A0 as UTF-8, raw windows-1252 0xA0
// bytes, U+FFFD from lossy transcriptions, line breaks/tabs and no separator at all.
func TestParseFiberHeadingSeparators(t *testing.T) {
	base := fixture(t, "fiberstat.html")
	tests := []struct {
		name string
		sep  string
	}{
		{"nbsp entities", "&nbsp;&nbsp;"},
		{"utf-8 nbsp", nbspUTF8 + nbspUTF8},
		{"latin-1 nbsp bytes", nbspLatin1 + nbspLatin1},
		{"replacement characters", replChar + replChar},
		{"mixed odd whitespace", " \r\n\t" + nbspUTF8 + replChar + " "},
		{"no separator", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := bytes.ReplaceAll(base, []byte("&nbsp;&nbsp;Currently"), []byte(tt.sep+"Currently"))
			if n := bytes.Count(body, []byte(tt.sep+"Currently")); n != 5 {
				t.Fatalf("fixture edit produced %d DMI headings, want 5", n)
			}
			fs, err := ParseFiber(body)
			if err != nil {
				t.Fatal(err)
			}
			want := []struct {
				name string
				cur  int64
			}{{"Temperature", 35}, {"Vcc", 3}, {"Tx Bias", 6}, {"Tx Power", 37}, {"Rx Power", -315}}
			if len(fs.Measures) != len(want) {
				t.Fatalf("got %d measures, want %d: %+v", len(fs.Measures), len(want), fs.Measures)
			}
			for i, w := range want {
				m := fs.Measures[i]
				if m.Name != w.name || m.Current == nil || *m.Current != w.cur {
					t.Errorf("measure %d = %q %v, want %q %d", i, m.Name, m.Current, w.name, w.cur)
				}
			}
			rx := fs.Measures[4]
			if !rx.LowAlarm.Active || rx.LowAlarm.Threshold == nil || *rx.LowAlarm.Threshold != -295 {
				t.Errorf("Rx low alarm = %+v", rx.LowAlarm)
			}
		})
	}
}

func TestSplitCurrently(t *testing.T) {
	tests := []struct {
		in        string
		name, cur string
		ok        bool
	}{
		{"Temperature Currently 35", "Temperature", "35", true},
		{"Rx Power Currently -315", "Rx Power", "-315", true},
		{"Rx PowerCurrently -315", "Rx Power", "-315", true},
		{"Rx Power currently: -315", "Rx Power", "-315", true},
		{"Tx Bias Currently", "Tx Bias", "", true},
		{"Vcc Currently N/A", "Vcc", "N/A", true},
		{"Rx Power Currently-315", "Rx Power", "-315", true},
		{"Fiber Status", "", "", false},
		{"Currently 35", "", "", false},
		{"Rx Power Currentlyx", "", "", false},
		{"Help", "", "", false},
	}
	for _, tt := range tests {
		name, cur, ok := splitCurrently(tt.in)
		if name != tt.name || cur != tt.cur || ok != tt.ok {
			t.Errorf("splitCurrently(%q) = %q, %q, %v; want %q, %q, %v", tt.in, name, cur, ok, tt.name, tt.cur, tt.ok)
		}
	}
}

func TestParseThreshold(t *testing.T) {
	tests := []struct {
		raw    string
		active bool
		thr    *int64
		norm   string
	}{
		{"1                 (Threshold -295)", true, i64(-295), "1 (Threshold -295)"},
		{"0 (Threshold 80)", false, i64(80), "0 (Threshold 80)"},
		{"0" + nbspUTF8 + "(Threshold 75)", false, i64(75), "0 (Threshold 75)"},
		{"1(Threshold-292)", true, i64(-292), "1(Threshold-292)"},
		{"1 (threshold: +5)", true, i64(5), "1 (threshold: +5)"},
		{"1", true, nil, "1"},
		{"0", false, nil, "0"},
		{"(Threshold -10)", false, i64(-10), "(Threshold -10)"},
		{"-295", false, nil, "-295"}, // a bare number is not a flag
		{"N/A", false, nil, "N/A"},
		{"", false, nil, ""},
	}
	for _, tt := range tests {
		got := parseThreshold(tt.raw)
		want := model.Threshold{Active: tt.active, Raw: tt.norm, Threshold: tt.thr}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("parseThreshold(%q) = %+v, want %+v", tt.raw, got, want)
		}
	}
}

func TestParseFiberCustomColumnOrder(t *testing.T) {
	// High before Low, and an unknown measure: columns must follow the header row.
	page := []byte(`<table><tr><th>Optical WAN Operational Status</th><td>Down</td></tr></table>
<h1>Rx Power Currently -400</h1><table>
<tr><th>&nbsp;</th><th>High</th><th>Low</th></tr>
<tr><td>Alarm</td><td>0 (Threshold -90)</td><td>1 (Threshold -295)</td></tr>
<tr><td>Warning</td><td>0 (Threshold -100)</td><td>1 (Threshold -292)</td></tr></table>
<h1>Laser Age Currently 12</h1><table><tr><td>Alarm</td><td>1 (Threshold 10)</td><td>0 (Threshold 99)</td></tr></table>`)
	fs, err := ParseFiber(page)
	if err != nil {
		t.Fatal(err)
	}
	if fs.OpticalStatus != "Down" || len(fs.Measures) != 2 {
		t.Fatalf("got %+v", fs)
	}
	rx := fs.Measures[0]
	if !rx.LowAlarm.Active || *rx.LowAlarm.Threshold != -295 || rx.HighAlarm.Active || *rx.HighAlarm.Threshold != -90 {
		t.Errorf("Rx alarms = %+v / %+v", rx.LowAlarm, rx.HighAlarm)
	}
	if rx.Unit != "0.1dBm" || *rx.Current != -400 {
		t.Errorf("Rx = %+v", rx)
	}
	other := fs.Measures[1]
	if other.Name != "Laser Age" || other.Unit != "" || !other.LowAlarm.Active || other.HighAlarm.Active {
		t.Errorf("unknown measure = %+v", other)
	}
}

// ---------------------------------------------------------------- lanstatistics

func TestParseLANFixture(t *testing.T) {
	got, err := ParseLAN(fixture(t, "lanstatistics.html"))
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range map[string]string{
		"Home Network Status/Device IPv4 Address":                              "192.168.1.254",
		"Home Network Status/DHCP Leases Allocated":                            "5",
		"Home Network Status/Public Subnet":                                    "",
		"Home Network Status/IP Passthrough Status":                            "Off (private IP address)",
		"Interfaces/Wi-Fi 5 GHz/Status":                                        "Enabled",
		"Interfaces/Wi-Fi 5 GHz/Active Devices":                                "3",
		"Interfaces/5G Ethernet/Inactive Devices":                              "1",
		"IPv6/Link-local IPv6 Address":                                         "fe80::be51:5fff:fe04:ac12",
		"IPv4 Statistics/Transmit Packets":                                     "43771661",
		"IPv6 Statistics/Transmit Discards":                                    "1",
		"Wi-Fi Status/Mode/5 GHz":                                              "N/AC/AX",
		"Wi-Fi Status/Current Radio Channel/5 GHz":                             "60,149",
		"Wi-Fi Status/Network Name (SSID)/2.4 GHz":                             "ATTexample",
		"Wi-Fi Status/Network Name (SSID)":                                     "ATTexample_Guest",
		"Wi-Fi Status/Guest SSID":                                              "Off",
		"Wi-Fi Network Statistics/Transmit Bytes/5 GHz":                        "5891075834",
		"Wi-Fi Network Statistics/Receive Error Packets/5 GHz":                 "1120",
		"Wi-Fi Client Connection Statistics/00:00:5e:00:53:05/IP Address":      "192.168.1.71",
		"Wi-Fi Client Connection Statistics/00:00:5e:00:53:04/Deauth Count":    "20",
		"Wi-Fi Client Connection Statistics/00:00:5e:00:53:03/Signal Strength": "-75 dBm",
		"LAN Ethernet Statistics/State/Port 1":                                 "down",
		"LAN Ethernet Statistics/Receive Errors/Port 4":                        "0",
	} {
		if gv, ok := got.Values[k]; !ok || gv != v {
			t.Errorf("Values[%q] = %q (present %v), want %q", k, gv, ok, v)
		}
	}
	for k := range got.Values {
		if strings.Contains(k, "Smart Home Manager") || strings.HasPrefix(k, "/") {
			t.Errorf("unexpected key %q", k)
		}
	}
}

// ---------------------------------------------------------------- events / login

func TestParseNotification(t *testing.T) {
	tests := []struct {
		name    string
		body    []byte
		want    bool
		wantErr error
	}{
		{"checked fixture", fixture(t, "events_checked.html"), true, nil},
		{"unchecked fixture", fixture(t, "events_unchecked.html"), false, nil},
		{"bare checked attribute", []byte(`<form action="/cgi-bin/events.ha"><input type="checkbox" name="bbevent" checked></form>`), true, nil},
		{"upper-case attribute", []byte(`<INPUT TYPE="CHECKBOX" NAME="bbevent" CHECKED="CHECKED">`), true, nil},
		{"empty checked value", []byte(`<input type="checkbox" name="bbevent" checked="">`), true, nil},
		{"hidden companion field", []byte(`<input type="hidden" name="bbevent" value="off" checked><input type="checkbox" name="bbevent">`), false, nil},
		{"login handshake", fixture(t, "login_handshake1.html"), false, ErrLoginRequired},
		{"login with nonce", fixture(t, "login_nonce.html"), false, ErrLoginRequired},
		{"other page", fixture(t, "sysinfo.html"), false, ErrUnexpectedPage},
		{"empty body", nil, false, ErrUnexpectedPage},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseNotification(tt.body)
			if !errors.Is(err, tt.wantErr) || (tt.wantErr == nil && err != nil) {
				t.Fatalf("err = %v, want %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("enabled = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsLoginPage(t *testing.T) {
	fixtures := map[string]bool{
		"login_handshake1.html":    true,
		"login_nonce.html":         true,
		"hiddenpage.html":          false,
		"sysinfo.html":             false,
		"broadbandstatistics.html": false, // carries a form nonce, but is not a login page
		"fiberstat.html":           false,
		"lanstatistics.html":       false,
		"home.html":                false,
		"diag.html":                false,
		"firewall.html":            false,
		"sitemap.html":             false,
		"events_checked.html":      false,
		"events_unchecked.html":    false,
		"broadbandconfig.html":     false,
	}
	for name, want := range fixtures {
		if got := IsLoginPage(fixture(t, name)); got != want {
			t.Errorf("IsLoginPage(%s) = %v, want %v", name, got, want)
		}
	}
	synthetic := []struct {
		name string
		body string
		want bool
	}{
		{"title only", `<html><head><title> LOGIN </title></head><body></body></html>`, true},
		{"banner only", `<h1>Access Code   Required</h1>`, true},
		{"form only", `<form method="post" action="/cgi-bin/login.ha?x=1"><input type="password" name="pw"></form>`, true},
		{"password field in login form", `<form action="/cgi-bin/Login.ha"><input id="password" type="password"></form>`, true},
		{"hashpassword field", `<input type="hidden" name="hashpassword">`, true},
		{"banner inside a script is not visible", `<script>var m = "Access Code Required";</script><title>Status</title>`, false},
		{"banner inside a self-closing script", `<script src="x.js"/>var m = "Access Code Required";</script><title>Status</title>`, false},
		{"banner inside noscript", `<noscript>Access Code Required</noscript>`, false},
		{"password input outside a login form", `<form action="/cgi-bin/wconfig.ha"><input id="password" type="password"></form>`, false},
		{"empty", ``, false},
	}
	for _, tt := range synthetic {
		if got := IsLoginPage([]byte(tt.body)); got != tt.want {
			t.Errorf("%s: IsLoginPage = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestSessionsFull(t *testing.T) {
	tests := []struct {
		name string
		body []byte
		want bool
	}{
		{"gateway message", sessionsFullPage(t), true},
		{"mixed case", []byte(`<p>ALL Web Server Sessions Are In Use</p>`), true},
		{"line break inside", []byte("<div>all web server\r\n   sessions are in use, try later</div>"), true},
		{"nbsp inside", []byte("<div>all web&nbsp;server sessions are in use</div>"), true},
		{"in title", []byte("<title>All web server sessions are in use</title>"), true},
		{"script only", []byte(`<script>alert("all web server sessions are in use")</script>`), false},
		{"login page", fixture(t, "login_nonce.html"), false},
		{"status page", fixture(t, "broadbandstatistics.html"), false},
	}
	for _, tt := range tests {
		if got := SessionsFull(tt.body); got != tt.want {
			t.Errorf("%s: SessionsFull = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestPageNonce(t *testing.T) {
	login := scan(fixture(t, "login_nonce.html"))
	if got := login.nonce("/login.ha"); got != "dd0a08f1f4bb9bf6740850db561407c4c1fa799ec65a0a7b6521c20191dad462" {
		t.Errorf("login nonce = %q", got)
	}
	if got := scan(fixture(t, "login_handshake1.html")).nonce("/login.ha"); got != "" {
		t.Errorf("handshake page nonce = %q, want none", got)
	}
	events := scan(fixture(t, "events_checked.html"))
	if got := events.nonce("/events.ha"); got != "632c9628a62414f7310abd046496c505a8de867218bfbebc105914c40b1f8ad3" {
		t.Errorf("events nonce = %q", got)
	}
	// The form-specific nonce wins over an earlier one from another form.
	two := scan([]byte(`<form action="/cgi-bin/other.ha"><input type="hidden" name="nonce" value="aaa"></form>
<form action="/cgi-bin/events.ha"><input type="hidden" name="nonce" value="bbb"></form>`))
	if got := two.nonce("/events.ha"); got != "bbb" {
		t.Errorf("nonce = %q, want bbb", got)
	}
	for _, bad := range []string{"", "has space", strings.Repeat("a", 600), "caf\xc3\xa9"} {
		p := scan([]byte(`<form action="/cgi-bin/login.ha"><input name="nonce" value="` + bad + `"></form>`))
		if got := p.nonce("/login.ha"); got != "" {
			t.Errorf("invalid nonce %q accepted", bad)
		}
	}
}

// ---------------------------------------------------------------- robustness

func TestParsersRejectWrongPages(t *testing.T) {
	login := fixture(t, "login_nonce.html")
	hidden := fixture(t, "hiddenpage.html")
	parsers := map[string]func([]byte) error{
		"sysinfo":   func(b []byte) error { _, err := ParseSysInfo(b); return err },
		"broadband": func(b []byte) error { _, err := ParseBroadband(b); return err },
		"fiber":     func(b []byte) error { _, err := ParseFiber(b); return err },
		"lan":       func(b []byte) error { _, err := ParseLAN(b); return err },
	}
	for name, parse := range parsers {
		if err := parse(login); !errors.Is(err, ErrLoginRequired) {
			t.Errorf("%s(login page) err = %v, want ErrLoginRequired", name, err)
		}
		if err := parse(hidden); !errors.Is(err, ErrUnexpectedPage) {
			t.Errorf("%s(hiddenpage) err = %v, want ErrUnexpectedPage", name, err)
		}
		if err := parse(nil); !errors.Is(err, ErrUnexpectedPage) {
			t.Errorf("%s(nil) err = %v, want ErrUnexpectedPage", name, err)
		}
		if err := parse([]byte("\x00\xff\xfe<<<>>>&&&;</table></tr></td>")); !errors.Is(err, ErrUnexpectedPage) {
			t.Errorf("%s(garbage) err = %v, want ErrUnexpectedPage", name, err)
		}
	}
}

// TestParseEncodingAndLineEndingIndependence parses every fixture after converting line
// endings and after replacing entities by the raw windows-1252 bytes (or the U+FFFD that a
// lossy transcription would contain): the parsed results must not change.
func TestParseEncodingAndLineEndingIndependence(t *testing.T) {
	type parsed struct {
		Sys   *model.SystemInfo
		BB    *model.BroadbandStatus
		Fiber *model.FiberStatus
		LAN   *model.LANStatus
		Notif bool
		Login bool
	}
	parseAll := func(name string, b []byte) parsed {
		var p parsed
		switch name {
		case "sysinfo.html":
			p.Sys, _ = ParseSysInfo(b)
		case "broadbandstatistics.html":
			p.BB, _ = ParseBroadband(b)
		case "fiberstat.html":
			p.Fiber, _ = ParseFiber(b)
		case "lanstatistics.html":
			p.LAN, _ = ParseLAN(b)
		}
		p.Notif, _ = ParseNotification(b)
		p.Login = IsLoginPage(b)
		return p
	}
	variants := map[string]func([]byte) []byte{
		"LF":        func(b []byte) []byte { return bytes.ReplaceAll(b, []byte("\r\n"), []byte("\n")) },
		"CR":        func(b []byte) []byte { return bytes.ReplaceAll(b, []byte("\r\n"), []byte("\r")) },
		"latin-1":   func(b []byte) []byte { return latin1Variant(b) },
		"U+FFFD":    func(b []byte) []byte { return replacementVariant(b) },
		"utf8 nbsp": func(b []byte) []byte { return bytes.ReplaceAll(b, []byte("&nbsp;"), []byte(nbspUTF8)) },
	}
	for _, name := range []string{"sysinfo.html", "broadbandstatistics.html", "fiberstat.html", "lanstatistics.html",
		"events_checked.html", "events_unchecked.html", "login_handshake1.html", "login_nonce.html"} {
		orig := fixture(t, name)
		want := parseAll(name, orig)
		for vname, f := range variants {
			got := parseAll(name, f(orig))
			if !reflect.DeepEqual(got, want) {
				t.Errorf("%s with %s variant parses differently:\n got %+v\nwant %+v", name, vname, got, want)
			}
		}
	}
}

func latin1Variant(b []byte) []byte {
	b = bytes.ReplaceAll(b, []byte("&copy;"), []byte(copyLatin1))
	return bytes.ReplaceAll(b, []byte("&nbsp;"), []byte(nbspLatin1))
}

func replacementVariant(b []byte) []byte {
	b = bytes.ReplaceAll(b, []byte("&copy;"), []byte(replChar))
	return bytes.ReplaceAll(b, []byte("&nbsp;"), []byte(replChar))
}

func TestScanMalformedMarkup(t *testing.T) {
	// Unclosed rows and cells, a cell outside any row, nested tables, nested forms and
	// stray end tags must not lose or merge data.
	p := scan([]byte(`<h2>Sec A</h2><table>
<tr><th>One</th><td>1
<tr><th>Two</th><td>2</td>
<td>outside-row-ok</td></tr>
<tr><th>Nested</th><td><table><tr><th>Inner</th><td>in</td></tr></table>after</td></tr>
</table></tr></td>
<form action="/a.ha"><form action="/b.ha"><input name="x" value="1"></form><input name="y">`))
	var got []string
	for _, r := range p.rows {
		var cells []string
		for _, c := range r.cells {
			cells = append(cells, c.text)
		}
		got = append(got, p.sectionName(r.section)+":"+strings.Join(cells, "|"))
	}
	want := []string{"Sec A:One|1", "Sec A:Two|2|outside-row-ok", "Sec A:Inner|in", "Sec A:Nested|after"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("rows = %q, want %q", got, want)
	}
	if len(p.forms) != 1 || p.forms[0].action != "/a.ha" {
		t.Errorf("forms = %+v (nested form must be ignored)", p.forms)
	}
	if len(p.inputs) != 2 || p.inputs[0].form != 0 || p.inputs[1].form != -1 {
		t.Errorf("inputs = %+v", p.inputs)
	}
}

// TestParsePathologicalInputs feeds near-cap (4 MiB) hostile pages to every parser: they
// must finish quickly (linear work) and keep every row.
func TestParsePathologicalInputs(t *testing.T) {
	size := MaxBodyBytes
	if raceEnabled {
		size /= 8 // still far beyond where quadratic behaviour shows; keeps -race runs short
	}
	dupRows := strings.Repeat("<tr><th>A</th><td>1</td></tr>", (size-160)/29)
	// The WAN row makes the page acceptable to ParseBroadband (see TestParsersRejectOtherStatusPages).
	const wanRow = "<h2>Primary Broadband</h2><table><tr><th>Broadband Connection</th><td>Up</td></tr></table>"
	cases := map[string][]byte{
		"duplicate labels": []byte(wanRow + "<h2>IPv4 Statistics</h2><table>" + dupRows + "</table>"),
		"wide colspan headers": []byte("<h2>S</h2>" + strings.Repeat(
			`<table><tr><th colspan="1000">a</th><th colspan="1000">b</th></tr><tr><td>L</td><td>1</td><td>2</td></tr></table>`,
			size/120)),
		"deep nesting":       []byte(strings.Repeat("<table><tr><td>", size/16)),
		"unclosed headings":  []byte(strings.Repeat("<h1>Rx Power Currently -1", size/26)),
		"many inputs":        []byte(strings.Repeat(`<input name="nonce" value="x y">`, size/33)),
		"invalid utf-8 soup": bytes.Repeat([]byte{0xA0, '<', 0xA9, '>', 0x92}, size/5),
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			start := time.Now()
			_, _ = ParseSysInfo(body)
			bb, _ := ParseBroadband(body)
			_, _ = ParseFiber(body)
			_, _ = ParseLAN(body)
			_, _ = ParseNotification(body)
			_ = IsLoginPage(body)
			if d := time.Since(start); d > 30*time.Second {
				t.Errorf("parsing took %v", d)
			}
			if name == "duplicate labels" {
				n := strings.Count(dupRows, "<tr>")
				if bb == nil {
					t.Fatal("ParseBroadband rejected the page")
				}
				if len(bb.Values) != n+1 || bb.Values[fmt.Sprintf("IPv4 Statistics/A (%d)", n)] != "1" {
					t.Errorf("duplicate rows lost: got %d values, want %d", len(bb.Values), n+1)
				}
			}
		})
	}
}

func TestValueSet(t *testing.T) {
	m := map[string]string{}
	vs := newValueSet(m)
	vs.put("k", "1")
	vs.put("k (2)", "literal") // a label that already looks like a suffixed key
	vs.put("k", "2")
	vs.put("k", "3")
	want := map[string]string{"k": "1", "k (2)": "literal", "k (3)": "2", "k (4)": "3"}
	if !reflect.DeepEqual(m, want) {
		t.Errorf("values = %v, want %v", m, want)
	}
}
