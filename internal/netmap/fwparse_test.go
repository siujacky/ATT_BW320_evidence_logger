package netmap

import (
	"net/netip"
	"strings"
	"testing"

	"attmonitor/internal/model"
)

// parsed is what a test expects of a line.
type parsed struct {
	kind     int
	dir      uint8
	reason   string
	proto    string
	src, dst string // "" when not stated or not an address
	spt, dpt uint16
	n        int // repeats
}

// parseText parses text with fresh code tables and describes the result.
func parseText(text string) parsed {
	c := newCodes()
	kind, d, n := c.parse([]byte(text))
	p := parsed{kind: kind, n: n}
	if kind != lineDrop {
		return p
	}
	p.dir, p.reason, p.proto, p.spt, p.dpt = d.dir, c.reasons.name(d.reason), c.protos.name(d.proto), d.spt, d.dpt
	if d.srcOK {
		p.src = netip.AddrFrom16(d.src).Unmap().String()
	}
	if d.dstOK {
		p.dst = netip.AddrFrom16(d.dst).Unmap().String()
	}
	return p
}

func TestParseTheGatewaysLines(t *testing.T) {
	const head = "P0000-00-00T07:48:34.329154 L4 FIREWALL[8512]: nflog_log_fw(), "
	for _, c := range []struct {
		name, text string
		want       parsed
	}{
		{"inbound to the gateway", lineInbound, parsed{kind: lineDrop, dir: dirIn, reason: "POLICY-INPUT-GEN-DISCARD", proto: "tcp",
			src: "203.0.113.66", dst: "198.51.100.1", spt: 21110, dpt: 8071}},
		{"outbound from the LAN", lineOutbound, parsed{kind: lineDrop, dir: dirOut, reason: "POLICY", proto: "tcp",
			src: "192.168.1.64", dst: "192.0.2.44", spt: 51544, dpt: 443}},
		{"inbound toward the LAN", lineToLAN, parsed{kind: lineDrop, dir: dirIn, reason: "OTHER-DoS", proto: "udp",
			src: "192.0.2.17", dst: "192.168.1.64", spt: 443, dpt: 60512}},
		{"sent by the gateway", lineGateway, parsed{kind: lineDrop, dir: dirLocal, reason: "POLICY", proto: "udp",
			src: "198.51.100.1", dst: "203.0.113.5", spt: 123, dpt: 123}},
		{"ping", linePing, parsed{kind: lineDrop, dir: dirIn, reason: "POLICY-ICMP-ECHO", proto: "icmp",
			src: "203.0.113.140", dst: "198.51.100.1"}},
		{"IPv6", lineV6, parsed{kind: lineDrop, dir: dirIn, reason: "POLICY-INPUT-GEN-DISCARD", proto: "icmpv6",
			src: "2001:db8:1::1", dst: "2001:db8:2::1"}},
		{"syslog-ng repeat", lineRepeat3, parsed{kind: lineRepeat, n: 3}},
		{"another program", lineDHCP, parsed{kind: lineOther}},

		// Repeat lines.
		{"BSD repeat", "last message repeated 5 times", parsed{kind: lineRepeatPrev, n: 5}},
		{"BSD repeat after a header", "P0000-00-00T07:53:47.832643 L4 last message repeated 1 time", parsed{kind: lineRepeatPrev, n: 1}},
		{"BSD repeat capped", "last message repeated 5000000 times", parsed{kind: lineRepeatPrev, n: maxRepeat}},
		{"one repeat", "Last message 'FIREWALL[8512]: nflo' repeated 1 time", parsed{kind: lineRepeat, n: 1}},
		{"repeat of another program", "Last message 'dnsmasq[1234]: quer' repeated 2 times, suppressed by syslog-ng on dsldevice",
			parsed{kind: lineOther}},
		{"repeat quoting the packet filter", "Last message 'kernel: nflog_log_f' repeated 2 times", parsed{kind: lineRepeat, n: 2}},
		{"repeat quoting a quote", "Last message 'FIREWALL[1]: it's o' repeated 4 times", parsed{kind: lineRepeat, n: 4}},
		{"no repeats", "Last message 'FIREWALL[8512]: nflo' repeated 0 times", parsed{kind: lineOther}},
		{"no number", "Last message 'FIREWALL[8512]: nflo' repeated x times", parsed{kind: lineOther}},
		{"no times", "Last message 'FIREWALL[8512]: nflo' repeated 3", parsed{kind: lineOther}},
		{"number too long", "Last message 'FIREWALL[8512]: nflo' repeated 12345678901 times", parsed{kind: lineOther}},
		{"repeats capped", "Last message 'FIREWALL[8512]: nflo' repeated 5000000 times", parsed{kind: lineRepeat, n: maxRepeat}},
		{"quote not ended", "Last message 'FIREWALL[8512]: nflo repeated 3 times", parsed{kind: lineOther}},
		{"not a message", "Fast message 'FIREWALL' repeated 3 times", parsed{kind: lineOther}},
		{"repeat cut short", "P0000-00-00T07:53:47.832643 L4 Last message 'FIREWALL[8512]: nflo' repea", parsed{kind: lineOther}},

		// Not drops.
		{"empty", "", parsed{kind: lineOther}},
		{"garbage", "\x00\xff\xfe=== ==action=DROP", parsed{kind: lineOther}},
		{"action only", "action=DROP", parsed{kind: lineOther}},
		{"accepted", head + "action=ACCEPT reason=X IN=veip0.0 OUT= SRC=203.0.113.9 DST=198.51.100.1 PROTO=TCP SPT=1 DPT=2",
			parsed{kind: lineOther}},
		{"not a field", head + "xaction=DROP IN=veip0.0 OUT=", parsed{kind: lineOther}},
		{"cut before IN", head + "action=DROP reason=POLICY hook=FORWARD mark=", parsed{kind: lineOther}},

		// Drops with fields missing, odd or cut short.
		{"lower case action", head + "action=drop reason=POLICY IN=veip0.0 OUT= SRC=203.0.113.9 DST=198.51.100.1 PROTO=UDP SPT=5 DPT=53",
			parsed{kind: lineDrop, dir: dirIn, reason: "POLICY", proto: "udp", src: "203.0.113.9", dst: "198.51.100.1", spt: 5, dpt: 53}},
		{"rejected", head + "action=REJECT IN=br0 OUT=veip0.0 SRC=192.168.1.5 DST=192.0.2.1 PROTO=TCP DPT=25",
			parsed{kind: lineDrop, dir: dirOut, proto: "tcp", src: "192.168.1.5", dst: "192.0.2.1", dpt: 25}},
		{"cut in the MAC field", head + "action=DROP reason=POLICY-INPUT-GEN-DISCARD hook=INPUT mark=136314880 IN=veip0.0 OUT= MAC=00:00:5e:00:53:01:00:00",
			parsed{kind: lineDrop, dir: dirIn, reason: "POLICY-INPUT-GEN-DISCARD"}},
		{"cut in SRC", head + "action=DROP reason=POLICY IN=veip0.0 OUT= MAC=00:00:5e:00:53:01:00:00:5e:0000:53:02:SRC=203.0.11",
			parsed{kind: lineDrop, dir: dirIn, reason: "POLICY"}},
		{"cut in DPT", head + "action=DROP IN=veip0.0 OUT= SRC=203.0.113.9 DST=198.51.100.1 PROTO=TCP SPT=1 DPT=80",
			parsed{kind: lineDrop, dir: dirIn, proto: "tcp", src: "203.0.113.9", dst: "198.51.100.1", spt: 1, dpt: 80}},
		{"no OUT", head + "action=DROP IN=br0 SRC=192.168.1.5 DST=192.168.1.254 PROTO=UDP DPT=1900",
			parsed{kind: lineDrop, dir: dirLocal, proto: "udp", src: "192.168.1.5", dst: "192.168.1.254", dpt: 1900}},
		{"MAC field apart", head + "action=DROP IN=veip0.0 OUT= MAC=00:00:5e:00:53:01 SRC=203.0.113.9 DST=198.51.100.1",
			parsed{kind: lineDrop, dir: dirIn, src: "203.0.113.9", dst: "198.51.100.1"}},
		{"MAC field glued without a colon", head + "action=DROP IN=veip0.0 OUT= MAC=00:00:5e:00:53:01:00:00:5e:00:53:02SRC=203.0.113.9",
			parsed{kind: lineDrop, dir: dirIn, src: "203.0.113.9"}},
		{"another field ending in SRC", head + "action=DROP IN=veip0.0 OUT= XSRC=203.0.113.1 SRC=203.0.113.9",
			parsed{kind: lineDrop, dir: dirIn, src: "203.0.113.9"}},
		{"spaces", head + "action=DROP  IN=veip0.0   OUT=  SRC=203.0.113.9 ", parsed{kind: lineDrop, dir: dirIn, src: "203.0.113.9"}},
		{"first of a field counts", head + "action=DROP action=ACCEPT IN=veip0.0 IN=br0 OUT= SRC=203.0.113.9 SRC=203.0.113.10",
			parsed{kind: lineDrop, dir: dirIn, src: "203.0.113.9"}},
		{"ICMP error", head + "action=DROP reason=POLICY IN=veip0.0 OUT= SRC=203.0.113.9 DST=198.51.100.1 LEN=56 PROTO=ICMP TYPE=3 CODE=3 [SRC=198.51.100.1 DST=203.0.113.9 LEN=28 PROTO=UDP SPT=5353 DPT=53 ]",
			parsed{kind: lineDrop, dir: dirIn, reason: "POLICY", proto: "icmp", src: "203.0.113.9", dst: "198.51.100.1"}},
		{"IPv4-mapped", head + "action=DROP IN=veip0.0 OUT= SRC=::ffff:203.0.113.7 DST=198.51.100.1",
			parsed{kind: lineDrop, dir: dirIn, src: "203.0.113.7", dst: "198.51.100.1"}},
		{"zone", head + "action=DROP IN=br0 OUT= SRC=fe80::1%br0 DST=ff02::1 PROTO=ICMPv6",
			parsed{kind: lineDrop, dir: dirLocal, proto: "icmpv6", src: "fe80::1", dst: "ff02::1"}},
		{"bad addresses", head + "action=DROP IN=veip0.0 OUT= SRC=01.2.3.4 DST=gateway",
			parsed{kind: lineDrop, dir: dirIn}},
		{"bad ports", head + "action=DROP IN=veip0.0 OUT= PROTO=TCP SPT=-1 DPT=65536", parsed{kind: lineDrop, dir: dirIn, proto: "tcp"}},
		{"numbered protocol", head + "action=DROP IN=veip0.0 OUT= PROTO=47", parsed{kind: lineDrop, dir: dirIn, proto: "47"}},
		{"odd protocol", head + "action=DROP IN=veip0.0 OUT= PROTO=T@P", parsed{kind: lineDrop, dir: dirIn}},
		{"odd reason", head + "action=DROP reason=A\x01B IN=veip0.0", parsed{kind: lineDrop, dir: dirIn, reason: "A?B"}},
		{"long reason", head + "action=DROP reason=" + strings.Repeat("R", 100) + " IN=veip0.0",
			parsed{kind: lineDrop, dir: dirIn, reason: strings.Repeat("R", maxReason)}},
		{"no header", "action=DROP IN=veip0.0 OUT= SRC=203.0.113.9", parsed{kind: lineDrop, dir: dirIn, src: "203.0.113.9"}},
	} {
		if got := parseText(c.text); got != c.want {
			t.Errorf("%s:\n got %+v\nwant %+v", c.name, got, c.want)
		}
	}
}

func TestDirection(t *testing.T) {
	for _, c := range []struct {
		in, out string
		want    uint8
	}{
		{"", "", dirLocal},        // sent by the gateway itself
		{"", "veip0.0", dirLocal}, // ... to the Internet (POSTROUTING)
		{"", "br1", dirLocal},     // ... to the LAN
		{"veip0.0", "", dirIn},    // to the gateway
		{"veip0.0", "br1", dirIn}, // toward the LAN
		{"veip0.0", "veip0.0", dirIn},
		{"ppp0", "", dirIn},        // any other WAN interface
		{"br1", "veip0.0", dirOut}, // from the LAN to the Internet
		{"br0", "ppp0", dirOut},
		{"wl0", "veip0.0", dirOut}, // Wi-Fi
		{"lan1", "veip0.0", dirOut},
		{"br1", "", dirLocal},    // from the LAN to the gateway
		{"br1", "br0", dirLocal}, // LAN to LAN
		{"br1", "wl1", dirLocal},
		{"br1", "lo", dirLocal},
		{"lo", "", dirLocal},
		{"lo", "veip0.0", dirLocal},
	} {
		if got := direction([]byte(c.in), []byte(c.out)); got != c.want {
			t.Errorf("IN=%q OUT=%q: %s, want %s", c.in, c.out, dirNames[got], dirNames[c.want])
		}
	}
}

func TestParseIPv4MatchesNetip(t *testing.T) {
	for _, s := range []string{"1.2.3.4", "0.0.0.0", "255.255.255.255", "192.168.1.64", "01.2.3.4", "1.2.3", "1.2.3.4.5",
		"256.1.1.1", "1..2.3", "", ".1.2.3", "1.2.3.", "1.2.3.4 ", "a.b.c.d", "1.2.3.04", "10.0.0.255", "999.1.1.1"} {
		checkIPv4(t, s)
	}
}

func checkIPv4(t *testing.T, s string) {
	t.Helper()
	got, ok := parseIPv4([]byte(s))
	a, err := netip.ParseAddr(s)
	want := err == nil && a.Is4()
	if ok != want || ok && got != a.As4() {
		t.Errorf("parseIPv4(%q) = %v %v; netip says %v %v", s, got, ok, a, err)
	}
}

func FuzzParseIPv4(f *testing.F) {
	for _, s := range []string{"1.2.3.4", "01.2.3.4", "255.255.255.255", "1.2.3", "::1", "1.2.3.4%x"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) { checkIPv4(t, s) })
}

func TestParsePort(t *testing.T) {
	for s, want := range map[string]uint16{"0": 0, "1": 1, "443": 443, "65535": 65535, "65536": 0, "": 0, "-1": 0,
		"1a": 0, "000080": 0, "00080": 80, " 80": 0} {
		if got := parsePort([]byte(s)); got != want {
			t.Errorf("parsePort(%q) = %d, want %d", s, got, want)
		}
	}
}

func TestCodesStopGrowing(t *testing.T) {
	c := newCodes()
	for i := range 300 {
		c.parse([]byte("action=DROP IN=veip0.0 reason=R" + strings.Repeat("x", i%60) + string(rune('A'+i/60))))
	}
	if len(c.reasons.names) != codeMore {
		t.Fatalf("%d reasons numbered", len(c.reasons.names))
	}
	_, d, _ := c.parse([]byte("action=DROP IN=veip0.0 reason=NEW"))
	if d.reason != codeMore || c.reasons.name(d.reason) != otherReasons {
		t.Fatalf("a reason beyond the table: %d %q", d.reason, c.reasons.name(d.reason))
	}
	// Known values keep their codes.
	_, d2, _ := c.parse([]byte("action=DROP IN=veip0.0 reason=RA"))
	if d2.reason == codeMore || c.reasons.name(d2.reason) != "RA" {
		t.Fatalf("a known reason: %d %q", d2.reason, c.reasons.name(d2.reason))
	}
}

func TestReasonLabel(t *testing.T) {
	for reason, want := range map[string]string{
		"POLICY-INPUT-GEN-DISCARD":  "Unsolicited, to the gateway",
		"POLICY":                    "Firewall policy",
		"OTHER-DoS":                 "Flood (DoS) protection",
		"other-dos":                 "Flood (DoS) protection",
		"POLICY-ICMP-ECHO":          "Ping to the gateway",
		"IP-INVALID":                "Invalid packet",
		"UDP-DST-PORT":              "Blocked UDP port",
		"TCP-SYN-FLOOD":             "TCP SYN flood",
		"POLICY-OUTPUT-GEN-DISCARD": "Policy output gen discard",
		"ICMPV6_NS":                 "ICMPv6 ns",
		"x":                         "X",
		"--":                        "--",
		"":                          "Not stated",
		otherReasons:                "Other reasons",
	} {
		if got := reasonLabel(reason); got != want {
			t.Errorf("reasonLabel(%q) = %q, want %q", reason, got, want)
		}
	}
}

func TestServiceLabel(t *testing.T) {
	for _, c := range []struct {
		proto string
		port  int
		want  string
	}{
		{"tcp", 8071, "tcp 8071"}, {"udp", 60512, "udp 60512"}, {"icmp", 0, "ICMP"}, {"icmpv6", 0, "ICMPv6"},
		{"", 0, "Unknown"}, {"", 80, "port 80"}, {"47", 0, "IP protocol 47"}, {"gre", 0, "GRE"},
	} {
		if got := serviceLabel(c.proto, c.port); got != c.want {
			t.Errorf("serviceLabel(%q, %d) = %q, want %q", c.proto, c.port, got, c.want)
		}
	}
}

// FuzzParse checks that no syslog text makes the parser panic or return what it cannot.
func FuzzParse(f *testing.F) {
	for _, s := range []string{lineInbound, lineOutbound, lineToLAN, lineGateway, linePing, lineV6, lineRepeat3, lineDHCP,
		"last message repeated 2 times", "action=DROP IN=", "action=DROP IN=br0 OUT=veip0.0 MAC=:SRC=", "Last message ''' repeated 9 times",
		"action=DROP IN=veip0.0 [SRC=1.2.3.4", "\x00action=DROP\x00IN=x"} {
		f.Add([]byte(s))
	}
	c := newCodes()
	f.Fuzz(func(t *testing.T, text []byte) {
		kind, d, n := c.parse(text)
		switch kind {
		case lineDrop:
			if d.dir >= nDirs || n != 0 {
				t.Fatalf("drop %+v, n %d", d, n)
			}
			if r := c.reasons.name(d.reason); len(r) > maxReason || strings.ContainsAny(r, " \x00\n") && r != otherReasons {
				t.Fatalf("reason %q", r)
			}
			if p := c.protos.name(d.proto); len(p) > maxProto || strings.ToLower(p) != p {
				t.Fatalf("protocol %q", p)
			}
		case lineRepeat, lineRepeatPrev:
			if n < 1 || n > maxRepeat || d != (drop{}) {
				t.Fatalf("repeat %d %+v", n, d)
			}
		case lineOther:
			if n != 0 || d != (drop{}) {
				t.Fatalf("other line: %+v %d", d, n)
			}
		default:
			t.Fatalf("kind %d", kind)
		}
		if len(c.reasons.names) > codeMore || len(c.protos.names) > codeMore {
			t.Fatalf("code tables grew beyond %d", codeMore)
		}
	})
}

// dirNames names the directions as the model does.
var dirNames = [nDirs]string{model.FwInbound, model.FwOutbound, model.FwLocal}
