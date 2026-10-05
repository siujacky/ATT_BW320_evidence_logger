package probe

import (
	"net/netip"
	"net/url"
	"strings"
	"testing"
)

func TestDetectDNSHijack(t *testing.T) {
	const gw = "192.168.1.254"
	tests := []struct {
		name    string
		qname   string
		answers []string
		gw      string
		want    bool
		whyIn   string
	}{
		{"public answer", "www.google.com", []string{"142.250.72.196"}, gw, false, ""},
		{"no answers", "www.google.com", nil, gw, false, ""},
		{"gateway address", "www.google.com", []string{"192.168.1.254"}, gw, true, "192.168.1.254, the gateway's own address"},
		{"gateway even if public", "www.google.com", []string{"203.0.113.254"}, "203.0.113.254", true, "gateway's own address"},
		{"no gateway given", "www.google.com", []string{"192.168.1.254"}, "", true, "private (RFC 1918)"},
		{"rfc1918 10/8", "www.google.com", []string{"10.1.2.3"}, gw, true, "private (RFC 1918)"},
		{"rfc1918 172.16/12", "www.google.com", []string{"172.31.255.1"}, gw, true, "private (RFC 1918)"},
		{"172.32 is public", "www.google.com", []string{"172.32.0.1"}, gw, false, ""},
		{"rfc1918 192.168/16", "www.google.com", []string{"192.168.0.1"}, gw, true, "private (RFC 1918)"},
		{"loopback", "www.google.com", []string{"127.0.0.1"}, gw, true, "loopback"},
		{"link-local", "www.google.com", []string{"169.254.1.1"}, gw, true, "link-local"},
		{"cgnat", "www.google.com", []string{"100.64.0.1"}, gw, true, "carrier-grade NAT"},
		{"cgnat upper bound", "www.google.com", []string{"100.127.255.255"}, gw, true, "carrier-grade NAT"},
		{"just above cgnat", "www.google.com", []string{"100.128.0.1"}, gw, false, ""},
		{"unspecified", "www.google.com", []string{"0.0.0.0"}, gw, true, "unspecified"},
		{"this-network", "www.google.com", []string{"0.1.2.3"}, gw, true, "unspecified"},
		{"one bad among good", "www.google.com", []string{"142.250.72.196", "10.0.0.1"}, gw, true, "10.0.0.1"},
		{"several bad are counted", "www.google.com", []string{"10.0.0.1", "10.0.0.2", "192.168.1.254"}, gw, true, "(+2 more)"},
		{"cname to public is fine", "www.google.com", []string{"CNAME:forcesafesearch.google.com", "216.239.38.120"}, gw, false, ""},
		{"cname into the gateway's domain", "www.google.com", []string{"CNAME:dsldevice.attlocal.net"}, gw, true, "alias (CNAME) of the local name dsldevice.attlocal.net"},
		{"aaaa unique local", "www.google.com", []string{"AAAA:fd00::1"}, gw, true, "unique-local"},
		{"aaaa public", "www.google.com", []string{"AAAA:2607:f8b0::200e"}, gw, false, ""},
		{"aaaa v4-mapped private", "www.google.com", []string{"AAAA:::ffff:192.168.1.254"}, gw, true, "gateway's own address"},
		{"unparseable answers ignored", "www.google.com", []string{"TYPE16", "garbage"}, gw, false, ""},
		{"trailing dot and case", "WWW.Google.COM.", []string{"192.168.1.254"}, gw, true, "www.google.com resolved to"},
		{".invalid any answer", "abc123.invalid", []string{"203.0.113.10"}, gw, true, "must not resolve"},
		{".invalid cname only", "abc123.invalid.", []string{"CNAME:somewhere.example"}, gw, true, "must not resolve"},
		{".invalid uppercase", "ABC.INVALID", []string{"8.8.8.8"}, gw, true, "abc.invalid"},
		{".invalid no answers", "abc123.invalid", nil, gw, false, ""},
		{"local name private is fine", "dsldevice.attlocal.net", []string{"192.168.1.254"}, gw, false, ""},
		{"single label", "router", []string{"192.168.1.254"}, gw, false, ""},
		{".local", "printer.local", []string{"192.168.1.20"}, gw, false, ""},
		{".home.arpa", "nas.home.arpa", []string{"192.168.1.30"}, gw, false, ""},
		{"ip literal name", "192.168.1.254", []string{"192.168.1.254"}, gw, false, ""},
		{"empty name", "", []string{"10.0.0.1"}, gw, false, ""},
	}
	for _, tt := range tests {
		got, why := DetectDNSHijack(tt.qname, tt.answers, tt.gw)
		if got != tt.want || !strings.Contains(why, tt.whyIn) || (!got && why != "") {
			t.Errorf("%s: DetectDNSHijack(%q, %q, %q) = %v, %q; want %v containing %q",
				tt.name, tt.qname, tt.answers, tt.gw, got, why, tt.want, tt.whyIn)
		}
		if got && len(why) > 200 && !strings.HasSuffix(tt.qname, "invalid") {
			t.Errorf("%s: reason too long: %q", tt.name, why)
		}
	}
}

func TestNonPublicReason(t *testing.T) {
	tests := []struct {
		addr  string
		empty bool
	}{
		{"8.8.8.8", true}, {"1.1.1.1", true}, {"203.0.113.5", true}, {"2607:f8b0::1", true},
		{"10.0.0.1", false}, {"172.16.0.1", false}, {"192.168.1.1", false}, {"127.0.0.53", false},
		{"169.254.0.1", false}, {"100.64.1.1", false}, {"0.0.0.0", false}, {"::", false},
		{"::1", false}, {"fe80::1", false}, {"fd12::1", false}, {"::ffff:10.0.0.1", false},
	}
	for _, tt := range tests {
		got := nonPublicReason(netip.MustParseAddr(tt.addr))
		if (got == "") != tt.empty {
			t.Errorf("nonPublicReason(%s) = %q", tt.addr, got)
		}
	}
	if nonPublicReason(netip.Addr{}) == "" {
		t.Error("zero Addr must not be public")
	}
}

func TestIsLocalName(t *testing.T) {
	for name, want := range map[string]bool{
		"localhost": true, "foo.localhost": true, "printer.local": true, "x.lan": true,
		"nas.home.arpa": true, "dsldevice.attlocal.net": true, "ATTLOCAL.NET.": true,
		"router": true, "corp.internal": true, "1.168.192.in-addr.arpa": true,
		"www.google.com": false, "local.example.com": false, "attlocal.net.evil.com": false,
		"": false, "192.168.1.254": false, "::1": false,
	} {
		if got := isLocalName(name); got != want {
			t.Errorf("isLocalName(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestHTTPHijack(t *testing.T) {
	const gw = "192.168.1.254"
	mustURL := func(s string) *url.URL {
		u, err := url.Parse(s)
		if err != nil {
			t.Fatal(err)
		}
		return u
	}
	msft := "http://www.msftconnecttest.com/connecttest.txt"
	tests := []struct {
		name     string
		url      string
		remote   string
		location string
		want     bool
		whyIn    []string
	}{
		{"public peer, no redirect", msft, "23.215.0.136:80", "", false, nil},
		{"gateway peer", msft, "192.168.1.254:80", "", true, []string{"connected to 192.168.1.254:80, the gateway's own address, for public host www.msftconnecttest.com"}},
		{"private peer", msft, "10.0.0.5:80", "", true, []string{"private (RFC 1918)"}},
		{"loopback peer", msft, "127.0.0.1:8080", "", true, []string{"loopback"}},
		{"ipv6 unique local peer", "https://www.google.com/generate_204", "[fd00::1]:443", "", true, []string{"unique-local"}},
		{"public ipv6 peer", "https://www.google.com/generate_204", "[2607:f8b0:4005::2004]:443", "", false, nil},
		{"redirect to the gateway", msft, "23.215.0.136:80", "http://192.168.1.254/cgi-bin/redirect.ha", true,
			[]string{"redirected to http://192.168.1.254/cgi-bin/redirect.ha, the gateway's own address"}},
		{"redirect to gateway https with port", msft, "23.215.0.136:80", "https://192.168.1.254:443/x", true, []string{"gateway's own address"}},
		{"redirect to private ip", msft, "23.215.0.136:80", "http://10.10.10.10/portal", true, []string{"private (RFC 1918)"}},
		{"redirect to local name", msft, "23.215.0.136:80", "http://dsldevice.attlocal.net/redirect", true, []string{"local host name"}},
		{"redirect to public host", msft, "23.215.0.136:80", "https://www.msftconnecttest.com/redirect", false, nil},
		{"relative redirect", msft, "23.215.0.136:80", "/elsewhere", false, nil},
		{"both findings", msft, "192.168.1.254:80", "http://192.168.1.254/", true, []string{"connected to", "; redirected to"}},
		{"unknown peer, gateway redirect", msft, "", "http://192.168.1.254/", true, []string{"redirected to"}},
		{"local target never flagged", "http://192.168.1.254/cgi-bin/sysinfo.ha", "192.168.1.254:80", "http://192.168.1.254/x", false, nil},
		{"loopback target never flagged", "http://127.0.0.1:8080/", "127.0.0.1:8080", "http://192.168.1.254/", false, nil},
		{"local-name target never flagged", "http://dsldevice.attlocal.net/", "192.168.1.254:80", "", false, nil},
		{"unparseable peer ignored", msft, "garbage", "", false, nil},
	}
	for _, tt := range tests {
		got, why := httpHijack(mustURL(tt.url), tt.remote, tt.location, gw)
		if got != tt.want {
			t.Errorf("%s: hijacked = %v (%q), want %v", tt.name, got, why, tt.want)
			continue
		}
		for _, w := range tt.whyIn {
			if !strings.Contains(why, w) {
				t.Errorf("%s: reason %q does not contain %q", tt.name, why, w)
			}
		}
		if !got && why != "" {
			t.Errorf("%s: reason without hijack: %q", tt.name, why)
		}
	}
}
