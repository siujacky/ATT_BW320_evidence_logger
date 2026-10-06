package connstore

import (
	"testing"
)

func TestOrient(t *testing.T) {
	cases := []struct {
		name     string
		src, dst string
		want     orientation
	}{
		{"LAN to the Internet", lanIP(10), "203.0.113.5", outbound},
		{"the Internet to a port forward", "203.0.113.5", lanIP(10), inbound},
		{"the gateway's own session", gatewayIP, "198.51.100.7", fromGateway},
		{"LAN to LAN", lanIP(10), lanIP(254), outbound},
		{"10/8", "10.0.0.2", "203.0.113.5", outbound},
		{"172.16/12", "172.31.255.2", "203.0.113.5", outbound},
		{"172.32 is not private", "172.32.0.2", "203.0.113.5", fromGateway},
		{"shared 100.64/10", "100.64.0.5", "203.0.113.5", outbound},
		{"shared, last address", "100.127.255.254", "203.0.113.5", outbound},
		{"just outside 100.64/10", "100.128.0.1", "203.0.113.5", fromGateway},
		{"IPv4 link-local", "169.254.10.1", "203.0.113.5", outbound},
		{"IPv6 link-local", "fe80::1", "2001:db8::5", outbound},
		{"IPv6 unique local", "fd00::1", "2001:db8::5", outbound},
		{"IPv6 fc00::/7 low half", "fc00::1", "2001:db8::5", outbound},
		{"to IPv6 unique local", "2001:db8::5", "fd00::1", inbound},
		{"IPv4-mapped", "::ffff:192.168.1.10", "203.0.113.5", outbound},
		{"zone", "fe80::1%eth0", "2001:db8::5", outbound},
		{"loopback is not a LAN device", "127.0.0.1", "203.0.113.5", fromGateway},
		{"multicast destination", lanIP(10), "239.255.255.250", outbound},
		{"documentation to documentation", "192.0.2.1", "198.51.100.1", fromGateway},
	}
	for _, c := range cases {
		src, ok1 := parseAddr(c.src)
		dst, ok2 := parseAddr(c.dst)
		if !ok1 || !ok2 {
			t.Fatalf("%s: addresses do not parse", c.name)
		}
		if got := orient(src, dst); got != c.want {
			t.Errorf("%s: orient(%s, %s) = %d, want %d", c.name, c.src, c.dst, got, c.want)
		}
	}
}

func TestParseAddr(t *testing.T) {
	cases := []struct {
		in, want string
		ok       bool
	}{
		{"192.168.1.10", "192.168.1.10", true},
		{" 192.168.1.10\t", "192.168.1.10", true},
		{"::ffff:192.168.1.10", "192.168.1.10", true},
		{"fe80::1%eth0", "fe80::1", true},
		{"2001:DB8::0:5", "2001:db8::5", true},
		{"", "", false},
		{"192.168.1", "", false},
		{"192.168.1.10/24", "", false},
		{"host.example", "", false},
	}
	for _, c := range cases {
		a, ok := parseAddr(c.in)
		if ok != c.ok || ok && a.String() != c.want {
			t.Errorf("parseAddr(%q) = %v, %v; want %q, %v", c.in, a, ok, c.want, c.ok)
		}
	}
	if a, ok := parseDeviceAddr("2001:db8::10/64"); !ok || a.String() != "2001:db8::10" {
		t.Errorf("parseDeviceAddr with a prefix length = %v, %v", a, ok)
	}
	if _, ok := parseDeviceAddr("2001:db8::10/129"); ok {
		t.Error("parseDeviceAddr accepted a bad prefix length")
	}
}

func TestNormalize(t *testing.T) {
	for in, want := range map[string]string{
		"00:00:5e:00:53:01": "00:00:5e:00:53:01",
		"00-00-5E-00-53-0A": "00:00:5e:00:53:0a",
		" 0000.5e00.5301 ":  "00:00:5e:00:53:01",
		"":                  "",
		"garbage":           "",
		"00:00:5e:00:53":    "",
	} {
		if got := normMAC(in); got != want {
			t.Errorf("normMAC(%q) = %q, want %q", in, got, want)
		}
	}
	for in, want := range map[int]int32{0: 0, 443: 443, 65535: 65535, 65536: 0, -1: 0} {
		if got := normPort(in); got != want {
			t.Errorf("normPort(%d) = %d, want %d", in, got, want)
		}
	}
	for in, want := range map[string]string{"TCP": "tcp", " udp ": "udp", "": ""} {
		if got := normProto(in); got != want {
			t.Errorf("normProto(%q) = %q, want %q", in, got, want)
		}
	}
}
