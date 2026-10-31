package web

// The matcher of GET /api/network/device (devicematch.go): a device's syslog terms found as whole
// addresses in the BGW320's lines - the firewall's nflog lines, dnsmasq's DHCP lines, the Wi-Fi
// driver's -, an IPv4 address only while the device held it.

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"time"

	"attmonitor/internal/model"
)

// fwDrop is a line of the gateway's packet filter as the BGW320 writes it: the MAC field holds the
// destination and the source MAC addresses and the frame's type (08:00), then the addresses; sep is
// what follows the MAC field (" " or, as some firmware writes it, ":" run together with SRC=).
func fwDrop(macDst, macSrc, sep, src, dst string) string {
	return "FIREWALL[8512]: nflog_log_fw(), action=DROP reason=POLICY hook=FORWARD mark= IN=br0 OUT=veip0.1 MAC=" + macDst + ":" + macSrc +
		":08:00" + sep + "SRC=" + src + " DST=" + dst + " LEN=40 TOS=0x00 PREC=0x00 TTL=127 ID=0 DF PROTO=TCP SPT=51544 DPT=443 WINDOW=0 RES=0x00 ACK RST URGP=0"
}

// fwIn is an inbound drop toward a LAN address (IPv6 unsolicited, or a port forward).
func fwIn(src, dst string) string {
	return "FIREWALL[8512]: nflog_log_fw(), action=DROP reason=OTHER-DoS hook=FORWARD mark=136314880 IN=veip0.0 OUT=br1 " +
		"MAC=00:00:5e:00:53:fe:00:00:5e:00:53:01:86:dd SRC=" + src + " DST=" + dst + " LEN=1228 TC=0 HOPLIMIT=57 FLOWLBL=0 PROTO=UDP SPT=443 DPT=60512 LEN=1208"
}

// raw is a message received at rx whose datagram is "<12>" and text.
func raw(rx time.Time, text string) *model.SyslogMessage {
	return &model.SyslogMessage{RX: rx.UTC().Format(time.RFC3339Nano), Src: "192.168.1.254:514", Format: "unknown", Raw: "<12>P0000-00-00T07:50:02.114201 L4 " + text}
}

func TestSyslogMatcherIPv4(t *testing.T) {
	const gw, other, mine = "00:00:5e:00:53:fe", "00:00:5e:00:53:01", "00:00:5e:00:53:07"
	m := newSyslogMatcher([]model.NetSyslogTerm{{Kind: "ipv4", Text: "192.168.1.7"}})
	at := syslogNow
	for _, tc := range []struct {
		text string
		want bool
	}{
		{fwDrop(gw, other, " ", "192.168.1.7", "192.0.2.44"), true},
		{fwDrop(gw, other, ":", "192.168.1.7", "192.0.2.44"), true}, // run together with SRC=
		{fwDrop(gw, other, " ", "192.168.1.70", "192.0.2.44"), false},
		{fwDrop(gw, other, " ", "10.192.168.1.7", "192.0.2.44"), false},
		{fwDrop(gw, other, " ", "192.168.1.17", "192.0.2.44"), false},
		{fwDrop(gw, other, " ", "192.0.2.44", "192.168.1.7"), true}, // as the destination
		{fwIn("2001:db8::9", "::ffff:192.168.1.7"), true},           // an IPv4-mapped address is the address
		{"dnsmasq-dhcp[1234]: DHCPACK(br1) 192.168.1.7 " + mine + " phone", true},
		{"dnsmasq-dhcp[1234]: DHCPACK(br1) 192.168.1.70 " + mine + " phone", false},
		{"dnsmasq-dhcp[1234]: DHCPOFFER(br1) 192.168.1.7.", true}, // at a sentence's end
		{"syslog to 192.168.1.7:514 failed", true},
		{"route [192.168.1.7]/32", true},
		{"route 192.168.1.7/24", true},
		{"version 1.192.168.1.7", false},
		{"version 192.168.1.7.5", false},
		{"1192.168.1.7 and 192.168.1.78", false},
		{"192.168.001.007", false},
		{"192.168.1.7", true}, // the whole text
		{"", false},
	} {
		if got := m.match(raw(at, tc.text)); got != tc.want {
			t.Errorf("%q: %v, want %v", tc.text, got, tc.want)
		}
	}
}

// TestSyslogMatcherTimes: an IPv4 term counts only for a message received within its times
// ([From, To); "" leaves a side open), and a time that does not parse finds nothing; the other
// terms count whenever the message was received.
func TestSyslogMatcherTimes(t *testing.T) {
	ts := func(d time.Duration) string { return syslogNow.Add(d).Format(time.RFC3339Nano) }
	m := newSyslogMatcher([]model.NetSyslogTerm{
		{Kind: "ipv4", Text: "192.168.1.70", From: ts(-3 * time.Hour), To: ts(-time.Hour)},
		{Kind: "ipv4", Text: "192.168.1.70", From: ts(-10 * time.Minute)}, // held again
		{Kind: "ipv4", Text: "192.168.1.71", To: ts(-2 * time.Hour)},
		{Kind: "mac", Text: "00:00:5e:00:53:21"},
	})
	line := fwDrop("00:00:5e:00:53:fe", "00:00:5e:00:53:01", " ", "192.168.1.70", "192.0.2.44")
	for _, tc := range []struct {
		text string
		rx   time.Duration
		want bool
	}{
		{line, -3 * time.Hour, true}, // from is in
		{line, -3*time.Hour - time.Nanosecond, false},
		{line, -61 * time.Minute, true},
		{line, -time.Hour, false}, // to is out
		{line, -30 * time.Minute, false},
		{line, -10 * time.Minute, true},
		{line, time.Hour, true}, // open to the end
		{"DHCPACK(br1) 192.168.1.71 laptop", -5 * time.Hour, true},
		{"DHCPACK(br1) 192.168.1.71 laptop", -2 * time.Hour, false},
		{"DHCPACK(br1) 192.168.1.71 00:00:5e:00:53:21 laptop", -time.Minute, true}, // the MAC address, at any time
	} {
		if got := m.match(raw(syslogNow.Add(tc.rx), tc.text)); got != tc.want {
			t.Errorf("%q received at %v: %v, want %v", tc.text, tc.rx, got, tc.want)
		}
	}
	// A receive time that does not parse: the bounded terms find nothing, the others still do.
	bad := raw(syslogNow, line)
	bad.RX = "yesterday"
	if m.match(bad) {
		t.Error("a message of no known time found by an IPv4 term with times")
	}
	if !newSyslogMatcher([]model.NetSyslogTerm{{Kind: "ipv4", Text: "192.168.1.70"}}).match(bad) {
		t.Error("a message of no known time not found by an IPv4 term of the whole period")
	}
}

func TestSyslogMatcherIPv6(t *testing.T) {
	m := newSyslogMatcher([]model.NetSyslogTerm{{Kind: "ipv6", Text: "2001:db8::21"}, {Kind: "ipv6", Text: "fe80::1"}})
	for _, tc := range []struct {
		text string
		want bool
	}{
		{fwIn("2001:db8:9::7", "2001:db8::21"), true},
		{fwIn("2001:db8:9::7", "2001:DB8::21"), true},
		{fwIn("2001:db8:9::7", "2001:0db8:0000:0000:0000:0000:0000:0021"), true}, // written out in full
		{fwIn("2001:db8:9::7", "2001:0DB8:0000:0000:0000:0000:0000:0021"), true},
		{fwIn("2001:db8:9::7", "2001:db8::210"), false},
		{fwIn("2001:db8:9::7", "2001:db8::21:5"), false},
		{fwIn("2001:db8:9::7", "12001:db8::21"), false},
		{fwIn("2001:db8:9::7", "2001:db8:1::21"), false},
		{"connect [2001:db8::21]:443 failed", true},
		{"neighbour fe80::1%br0 reachable", true},
		{"neighbour fe80::10 reachable", false},
		{"route 2001:db8::21/128.", true},
		{"from 2001:db8::21.", true},
		{"2001:db8:0:0::21", false}, // neither the canonical nor the full form
		{"a2001:db8::21", false},
		{fwDrop("00:00:5e:00:53:21", "00:00:5e:00:53:01", " ", "192.168.1.7", "192.0.2.1"), false},
	} {
		if got := m.match(raw(syslogNow, tc.text)); got != tc.want {
			t.Errorf("%q: %v, want %v", tc.text, got, tc.want)
		}
	}
}

// TestSyslogMatcherMAC: a MAC address in either notation and any case, as a whole address - also as
// the destination or the source of the firewall's MAC field, where the gateway runs them together
// with the frame's type - but never as six octets that straddle them.
func TestSyslogMatcherMAC(t *testing.T) {
	const mac = "00:00:5e:00:53:21"
	m := newSyslogMatcher([]model.NetSyslogTerm{{Kind: "mac", Text: "00-00-5E-00-53-21"}})
	for _, tc := range []struct {
		text string
		want bool
	}{
		{fwDrop("00:00:5e:00:53:fe", mac, " ", "192.168.1.70", "192.0.2.44"), true}, // the source
		{fwDrop("00:00:5e:00:53:fe", mac, ":", "192.168.1.70", "192.0.2.44"), true}, // run together with SRC=
		{fwDrop(mac, "00:00:5e:00:53:fe", " ", "192.0.2.44", "192.168.1.70"), true}, // the destination
		{fwDrop("00:00:5E:00:53:FE", "00:00:5E:00:53:21", " ", "192.168.1.70", "192.0.2.44"), true},
		{fwDrop("00:00:5e:00:53:fe", "00:00:5e:00:53:01", " ", "192.168.1.70", "192.0.2.44"), false},
		{"dnsmasq-dhcp[1234]: DHCPACK(br1) 192.168.1.70 00:00:5e:00:53:21 laptop", true},
		{"wl0: 00-00-5E-00-53-21 associated", true},
		{"wl0: STA 00:00:5E:00:53:21 left.", true},
		{"client id 01:00:00:5e:00:53:21", false}, // more octets than one MAC address
		{"00:00:5e:00:53:210", false},
		{"00:00:5e:00:53:2", false},
		{"00-00-5e-00-53-21-ff", false},
		{"", false},
	} {
		if got := m.match(raw(syslogNow, tc.text)); got != tc.want {
			t.Errorf("%q: %v, want %v", tc.text, got, tc.want)
		}
	}
	// Six octets across the destination's end and the source's start are neither address.
	straddle := newSyslogMatcher([]model.NetSyslogTerm{{Kind: "mac", Text: "00:53:fe:00:00:5e"}})
	if straddle.match(raw(syslogNow, fwDrop("00:00:5e:00:53:fe", mac, " ", "192.168.1.70", "192.0.2.44"))) {
		t.Error("a MAC address found across the MAC field's two addresses")
	}
	// A MAC field cut short names the address it holds whole.
	if !m.match(raw(syslogNow, "action=DROP IN=br0 OUT=veip0.1 MAC=00:00:5e:00:53:21:00:00 SRC=192.168.1.70")) ||
		m.match(raw(syslogNow, "action=DROP IN=br0 OUT=veip0.1 MAC=00:00:5e:00:53:01:00:00:5e:00:53 SRC=192.168.1.70")) {
		t.Error("a MAC field cut short")
	}
}

// TestSyslogMatcherText: the text looked in is the exact datagram, else the bytes of one that is
// not UTF-8, else the parsed message.
func TestSyslogMatcherText(t *testing.T) {
	m := newSyslogMatcher([]model.NetSyslogTerm{{Kind: "ipv4", Text: "192.168.1.7"}})
	for _, tc := range []struct {
		msg  model.SyslogMessage
		want bool
	}{
		{model.SyslogMessage{Raw: "<12>x SRC=192.168.1.7", Msg: "nothing"}, true},
		{model.SyslogMessage{Raw: "<12>nothing", Msg: "SRC=192.168.1.7"}, false},
		{model.SyslogMessage{RawB64: base64.StdEncoding.EncodeToString([]byte("<12>\xfe\xff SRC=192.168.1.7")), Msg: "�� SRC=10.0.0.1"}, true},
		{model.SyslogMessage{RawB64: "not base64!", Msg: "SRC=192.168.1.7"}, true},
		{model.SyslogMessage{Msg: "SRC=192.168.1.7"}, true},
	} {
		tc.msg.RX = syslogNow.Format(time.RFC3339Nano)
		if got := m.match(&tc.msg); got != tc.want {
			t.Errorf("%+v: %v, want %v", tc.msg, got, tc.want)
		}
	}
}

// TestNewSyslogMatcher: terms that cannot find anything are left out - another kind, an address
// that does not parse or is of the other family, times that do not parse or are empty -, the kind
// and the text read without case and surrounding space; at most maxDeviceTerms are used; nil when
// none is left.
func TestNewSyslogMatcher(t *testing.T) {
	ts := func(d time.Duration) string { return syslogNow.Add(d).Format(time.RFC3339Nano) }
	if m := newSyslogMatcher(nil); m != nil {
		t.Errorf("no term: %+v", m)
	}
	m := newSyslogMatcher([]model.NetSyslogTerm{
		{Kind: " IPv4 ", Text: " 192.168.1.7 "},
		{Kind: "ipv4", Text: "192.168.1.300"},
		{Kind: "ipv4", Text: "2001:db8::1"},
		{Kind: "ipv4", Text: "192.168.1.8", From: "bogus"},
		{Kind: "ipv4", Text: "192.168.1.9", From: ts(0), To: ts(0)},
		{Kind: "ipv6", Text: "::ffff:192.168.1.10"},
		{Kind: "ipv6", Text: "192.168.1.11"},
		{Kind: "IPV6", Text: "FE80::1%br0"},
		{Kind: "mac", Text: "00:00:5e:00:53:21:00:00"},
		{Kind: "mac", Text: "nothing"},
		{Kind: "MAC", Text: " 00:00:5E:00:53:22 "},
		{Kind: "hostname", Text: "laptop"},
	})
	if m == nil {
		t.Fatal("no matcher")
	}
	var v4 []string
	for a := range m.v4 {
		v4 = append(v4, a)
	}
	if len(v4) != 1 || v4[0] != "192.168.1.7" || len(m.v6) != 2 || !m.v6["fe80::1"] || !m.v6["fe80:0000:0000:0000:0000:0000:0000:0001"] ||
		len(m.mac) != 2 || !m.mac["00:00:5e:00:53:22"] || !m.mac["00-00-5e-00-53-22"] {
		t.Errorf("matcher %+v", m)
	}
	if newSyslogMatcher([]model.NetSyslogTerm{{Kind: "ipv4", Text: "nope"}, {Kind: "mac", Text: "nope"}}) != nil {
		t.Error("a matcher of terms that find nothing")
	}
	var many []model.NetSyslogTerm
	for i := range maxDeviceTerms + 10 {
		many = append(many, model.NetSyslogTerm{Kind: "ipv4", Text: fmt.Sprintf("10.0.%d.%d", i/250, 1+i%250)})
	}
	if m := newSyslogMatcher(many); len(m.v4) != maxDeviceTerms {
		t.Errorf("%d terms used, want %d", len(m.v4), maxDeviceTerms)
	}
}

// BenchmarkSyslogMatcher matches a device's terms - two IPv4 holds, its IPv6 and MAC addresses -
// against a firewall line that names none of them (the common case of a month of syslog).
func BenchmarkSyslogMatcher(b *testing.B) {
	ts := func(d time.Duration) string { return syslogNow.Add(d).Format(time.RFC3339Nano) }
	m := newSyslogMatcher([]model.NetSyslogTerm{
		{Kind: "ipv4", Text: "192.168.1.70", To: ts(-time.Hour)}, {Kind: "ipv4", Text: "192.168.1.71", From: ts(-time.Hour)},
		{Kind: "ipv6", Text: "2001:db8::21"}, {Kind: "mac", Text: "00:00:5e:00:53:21"},
	})
	msg := raw(syslogNow, fwDrop("00:00:5e:00:53:fe", "00:00:5e:00:53:01", " ", "192.168.1.80", "192.0.2.44"))
	b.ReportAllocs()
	for b.Loop() {
		if m.match(msg) {
			b.Fatal("found")
		}
	}
}

// FuzzSyslogMatcher: whatever the text and the term, the matcher does not panic, and what it finds
// is in the text: the IPv4 address as written, an IPv6 or a MAC address in one of its forms (in
// some case; the MAC field writes its addresses in colon notation too).
func FuzzSyslogMatcher(f *testing.F) {
	for _, seed := range []struct{ text, kind, term string }{
		{fwDrop("00:00:5e:00:53:fe", "00:00:5e:00:53:21", " ", "192.168.1.70", "192.0.2.44"), "ipv4", "192.168.1.70"},
		{fwDrop("00:00:5e:00:53:fe", "00:00:5e:00:53:21", ":", "192.168.1.70", "192.0.2.44"), "mac", "00:00:5e:00:53:21"},
		{fwIn("2001:db8:9::7", "2001:db8::21"), "ipv6", "2001:db8::21"},
		{"MAC=", "mac", "00:00:5e:00:53:21"}, {"MAC=::::::::", "mac", "00:00:00:00:00:00"}, {"\xff\xfe", "ipv4", "1.2.3.4"},
	} {
		f.Add(seed.text, seed.kind, seed.term)
	}
	f.Fuzz(func(t *testing.T, text, kind, term string) {
		m := newSyslogMatcher([]model.NetSyslogTerm{{Kind: kind, Text: term}})
		if m == nil || !m.match(&model.SyslogMessage{RX: syslogNow.Format(time.RFC3339Nano), Raw: text}) {
			return
		}
		lowerText := strings.ToLower(text)
		for a := range m.v4 {
			if strings.Contains(text, a) {
				return
			}
		}
		for form := range m.v6 {
			if strings.Contains(lowerText, form) {
				return
			}
		}
		for form := range m.mac {
			if strings.Contains(lowerText, form) {
				return
			}
		}
		t.Fatalf("%s %q found in %q", kind, term, text)
	})
}
