package probe

import (
	"context"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"
)

// Live tests touch the real network: ICMP/DNS to the gateway and public hosts, SNTP and a
// local adapter query. They never send HTTP (let alone authenticated or mutating requests)
// to the gateway. Run with ATTMON_LIVE=1.
func requireLive(t *testing.T) {
	t.Helper()
	if os.Getenv("ATTMON_LIVE") != "1" {
		t.Skip("set ATTMON_LIVE=1 to run live network tests")
	}
}

const liveGateway = "192.168.1.254"

func TestLivePing(t *testing.T) {
	requireLive(t)
	p := New(Options{})
	for _, target := range []string{liveGateway, "1.1.1.1"} {
		r := p.Ping(context.Background(), target, 2*time.Second)
		t.Logf("ping %s: ok=%v status=%s from=%s ttl=%d rtt=%dµs err=%q", target, r.OK, r.Status, r.ReplyFrom, r.TTL, r.RTTus, r.Err)
		if !r.OK || r.ReplyFrom != target || r.RTTus <= 0 || r.TTL <= 0 {
			t.Errorf("ping %s failed: %+v", target, r)
		}
	}
}

func TestLiveTCP(t *testing.T) {
	requireLive(t)
	p := New(Options{})
	for _, target := range []string{liveGateway + ":443", "1.1.1.1:443"} {
		r := p.TCP(context.Background(), target, 2*time.Second)
		t.Logf("tcp %s: ok=%v status=%s rtt=%dµs err=%q", target, r.OK, r.Status, r.RTTus, r.Err)
		if !r.OK {
			t.Errorf("tcp %s failed: %+v", target, r)
		}
	}
}

func TestLiveTraceroute(t *testing.T) {
	requireLive(t)
	tr := New(Options{}).Traceroute(context.Background(), "8.8.8.8", 6, time.Second)
	for _, h := range tr.Hops {
		t.Logf("hop %2d %-15s %-24s %dµs", h.TTL, h.Addr, h.Status, h.RTTus)
	}
	t.Logf("reached=%v dur=%dms err=%q", tr.Reached, tr.DurMs, tr.Err)
	if len(tr.Hops) == 0 || tr.Err != "" {
		t.Fatalf("no hops or a local error: %+v", tr)
	}
	if h := tr.Hops[0]; h.Addr != liveGateway || (h.Status != "IP_TTL_EXPIRED_TRANSIT" && h.Status != "IP_SUCCESS") {
		t.Errorf("first hop should be the gateway reporting TTL expiry: %+v", h)
	}
}

func TestLiveDNS(t *testing.T) {
	requireLive(t)
	p := New(Options{})
	for _, server := range []string{liveGateway, "1.1.1.1"} {
		r := p.DNS(context.Background(), server, "www.google.com", 2*time.Second)
		t.Logf("dns @%s: ok=%v rcode=%s answers=%v rtt=%dµs hijacked=%v %s truncated=%v err=%q", r.Server, r.OK, r.RCode, r.Answers, r.RTTus, r.Hijacked, r.HijackWhy, r.Truncated, r.Err)
		if !r.OK || r.RCode != "NOERROR" || len(r.Answers) == 0 || r.Hijacked {
			t.Errorf("dns via %s: %+v", server, r)
		}
		inv := p.DNS(context.Background(), server, "att-monitor-probe-check.invalid", 2*time.Second)
		t.Logf("dns @%s .invalid: ok=%v rcode=%s answers=%v hijacked=%v", inv.Server, inv.OK, inv.RCode, inv.Answers, inv.Hijacked)
		if inv.Hijacked {
			t.Errorf("resolver %s answers .invalid names: %+v", server, inv)
		}
	}
}

func TestLiveHTTP(t *testing.T) {
	requireLive(t)
	p := New(Options{})
	r := p.HTTP(context.Background(), "msft_connecttest", "http://www.msftconnecttest.com/connecttest.txt", 200, "Microsoft Connect Test", 5*time.Second)
	t.Logf("msft: ok=%v status=%d remote=%s loc=%q hijacked=%v tls_cert=%q err=%q", r.OK, r.Status, r.RemoteAddr, r.Location, r.Hijacked, r.TLSCertSHA256, r.Err)
	if !r.OK || r.Hijacked || r.TLSCertSHA256 != "" {
		t.Errorf("msft_connecttest: %+v", r)
	}
	r = p.HTTP(context.Background(), "google_204", "https://www.google.com/generate_204", 204, "", 5*time.Second)
	t.Logf("google_204: ok=%v status=%d remote=%s hijacked=%v tls_cert_sha256=%s err=%q", r.OK, r.Status, r.RemoteAddr, r.Hijacked, r.TLSCertSHA256, r.Err)
	if !r.OK || r.Hijacked || len(r.TLSCertSHA256) != 64 || strings.Trim(r.TLSCertSHA256, "0123456789abcdef") != "" {
		t.Errorf("google_204: %+v", r)
	}
}

func TestLiveSNTP(t *testing.T) {
	requireLive(t)
	r := New(Options{}).SNTP(context.Background(), "time.windows.com", 3*time.Second)
	t.Logf("sntp time.windows.com: ok=%v addr=%s offset=%dms rtt=%dms stratum=%d err=%q", r.OK, r.Addr, r.OffsetMs, r.RTTms, r.Stratum, r.Err)
	if !r.OK || r.Stratum < 1 || r.Stratum > 15 || r.Addr == "" {
		t.Errorf("sntp: %+v", r)
	}
}

func TestLiveLocalLink(t *testing.T) {
	requireLive(t)
	link, raw, err := New(Options{}).LocalLink(context.Background(), liveGateway)
	if err != nil {
		t.Fatal(err)
	}
	// SSID/BSSID are deliberately not logged.
	t.Logf("local link: iface=%q type=%s state=%s local=%s gw=%s link=%dMbps band=%q ch=%d radio=%q rx=%d tx=%d signal=%d%% rssi=%ddBm raw=%dB err=%q",
		link.Interface, link.Type, link.State, link.LocalIP, link.GatewayIP, link.LinkMbps, link.Band, link.Channel,
		link.RadioType, link.RxMbps, link.TxMbps, link.SignalPct, link.RSSIdBm, len(raw), link.Err)
	if link.State != "connected" || (link.Type != "wifi" && link.Type != "ethernet") {
		t.Errorf("unexpected link: %+v", link)
	}
	if a, err := netip.ParseAddr(link.LocalIP); err != nil || !netip.MustParsePrefix("192.168.1.0/24").Contains(a) {
		t.Errorf("local IP %q is not on the gateway's LAN", link.LocalIP)
	}
	if link.Type == "wifi" && (len(raw) == 0 || link.SSID == "" || link.SignalPct <= 0) {
		t.Errorf("wifi details missing: %+v (raw %d bytes)", link, len(raw))
	}
	// Windows 11 prints "Rssi : <dBm>"; when it does, the reading must come through.
	if link.Type == "wifi" && strings.Contains(string(raw), "Rssi") && link.RSSIdBm >= 0 {
		t.Errorf("netsh reported an Rssi line but RSSIdBm = %d", link.RSSIdBm)
	}
}
