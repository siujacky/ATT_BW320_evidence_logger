package probe

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"golang.org/x/net/dns/dnsmessage"

	"attmonitor/internal/model"
)

// Fuzz targets for the code that parses bytes from the network or from netsh. `go test`
// runs the seed corpus; `go test -fuzz=FuzzX` searches further.

func FuzzParseNetshWLAN(f *testing.F) {
	files, _ := filepath.Glob(filepath.Join("..", "..", "testdata", "probe", "netsh_*.txt"))
	for _, name := range files {
		if b, err := os.ReadFile(name); err == nil {
			f.Add(b, "Wi-Fi")
			f.Add(b, "")
		}
	}
	f.Add([]byte("    Name : x\n    Signal : NaN%\n    Receive rate (Mbps) : -1e309\n    Channel : -4\n"), "")
	f.Add([]byte("    Name : x\n    Rssi : -4294967296\n    RSSI : 7\n"), "x")
	f.Fuzz(func(t *testing.T, out []byte, iface string) {
		l, err := ParseNetshWLAN(out, iface)
		if l.Type != "wifi" {
			t.Fatalf("Type %q", l.Type)
		}
		if l.SignalPct < 0 || l.Channel < 0 || l.RxMbps < 0 || l.TxMbps < 0 {
			t.Fatalf("negative reading: %+v", l)
		}
		if l.RSSIdBm != 0 && (l.RSSIdBm < minRSSIdBm || l.RSSIdBm > -1) {
			t.Fatalf("RSSI outside -128..-1 dBm: %+v", l)
		}
		if l.State != strings.ToLower(l.State) {
			t.Fatalf("State not lower-cased: %q", l.State)
		}
		for _, s := range []string{l.Interface, l.State, l.SSID, l.BSSID, l.Band, l.RadioType, l.Err} {
			if !utf8.ValidString(s) && err == nil {
				t.Fatalf("invalid UTF-8 in %+v", l)
			}
		}
	})
}

func FuzzParseDNSResponse(f *testing.F) {
	name := dnsmessage.MustNewName("www.google.com.")
	q := dnsmessage.Message{Header: dnsmessage.Header{ID: 4242, Response: true, RCode: dnsmessage.RCodeSuccess},
		Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}},
		Answers: []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: name, Type: dnsmessage.TypeA,
			Class: dnsmessage.ClassINET}, Body: &dnsmessage.AResource{A: [4]byte{192, 168, 1, 254}}}}}
	if b, err := q.Pack(); err == nil {
		f.Add(b)
		f.Add(b[:len(b)-3])
	}
	f.Add([]byte{0x10, 0x92, 0x81, 0x80, 0, 0, 0, 5, 0, 0, 0, 0})
	f.Fuzz(func(t *testing.T, msg []byte) {
		hdr, answers, _, why := parseDNSResponse(msg, 4242, name)
		if why == "" && (hdr.ID != 4242 || !hdr.Response) {
			t.Fatalf("accepted a datagram that is not our response: %+v", hdr)
		}
		hij, reason := DetectDNSHijack("www.google.com", answers, "192.168.1.254")
		if hij != (reason != "") || len(reason) > maxReasonLen {
			t.Fatalf("hijack %v reason %q", hij, reason)
		}
	})
}

func FuzzDetectDNSHijack(f *testing.F) {
	f.Add("www.google.com", "192.168.1.254", "203.0.113.1", "192.168.1.254")
	f.Add("x.invalid", "CNAME:a.b", "AAAA:fd00::1", "")
	f.Add("printer.local", "10.0.0.1", "garbage", "10.0.0.1")
	f.Fuzz(func(t *testing.T, name, a1, a2, gw string) {
		hij, reason := DetectDNSHijack(name, []string{a1, a2}, gw)
		if hij != (reason != "") {
			t.Fatalf("hijack %v with reason %q", hij, reason)
		}
		if len(reason) > maxReasonLen {
			t.Fatalf("reason is %d bytes", len(reason))
		}
	})
}

func FuzzEvalNTPReply(f *testing.F) {
	pkt := make([]byte, ntpPacketLen)
	pkt[0], pkt[1] = 4<<3|4, 2
	f.Add(pkt, int64(10*time.Millisecond))
	f.Fuzz(func(t *testing.T, pkt []byte, rttNs int64) {
		if len(pkt) < ntpPacketLen {
			return // SNTP only evaluates datagrams of at least 48 bytes
		}
		var r model.ClockResult
		t1 := time.Date(2026, 10, 5, 3, 20, 0, 0, time.UTC)
		evalNTPReply(&r, pkt, t1, time.Duration(rttNs))
		if r.OK == (r.Err != "") {
			t.Fatalf("OK %v with Err %q", r.OK, r.Err)
		}
		if !r.OK && (r.OffsetMs != 0 || r.RTTms != 0) {
			t.Fatalf("failed reply carries a measurement: %+v", r)
		}
		if r.OK && r.RTTms < 0 {
			t.Fatalf("negative delay: %+v", r)
		}
	})
}

func FuzzPrefixUTF8(f *testing.F) {
	f.Add([]byte("Copyright \xa9 2026"), 512)
	f.Add([]byte("a\xe2\x82\xacb"), 3)
	f.Fuzz(func(t *testing.T, b []byte, n int) {
		if n < 0 || n > 1<<16 {
			return
		}
		s := prefixUTF8(b, n)
		if !utf8.ValidString(s) {
			t.Fatalf("invalid UTF-8: %q", s)
		}
		if len(s) > 3*n {
			t.Fatalf("%d bytes from a %d-byte prefix", len(s), n)
		}
	})
}

func FuzzClipText(f *testing.F) {
	f.Add("ééééé", 7)
	f.Add("redirected to http://192.168.1.254/", 20)
	f.Fuzz(func(t *testing.T, s string, n int) {
		if n < 0 || n > 1<<16 {
			return
		}
		got := clipText(s, n)
		if len(s) <= n {
			if got != s {
				t.Fatalf("clipText(%q, %d) changed a string that fits: %q", s, n, got)
			}
			return
		}
		if len(got) > max(n, 3) || !strings.HasSuffix(got, "...") {
			t.Fatalf("clipText(%q, %d) = %q", s, n, got)
		}
		if utf8.ValidString(s) && !utf8.ValidString(got) {
			t.Fatalf("clipText split a character: %q", got)
		}
	})
}

func FuzzHostPort(f *testing.F) {
	for _, s := range []string{"1.1.1.1", "[::1]:53", "fe80::1%eth0", "a:b:c", "[", "time.windows.com:123"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		host, port, err := hostPort(s, "53")
		if err == nil && (host == "" || port == "") {
			t.Fatalf("hostPort(%q) = %q, %q with no error", s, host, port)
		}
	})
}
