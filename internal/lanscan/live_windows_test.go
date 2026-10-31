//go:build windows

package lanscan

import (
	"context"
	"net/netip"
	"os"
	"regexp"
	"slices"
	"testing"

	"attmonitor/internal/model"
)

// macForm is how a scan writes a MAC address: lower case, colon separated.
var macForm = regexp.MustCompile(`^[0-9a-f]{2}(:[0-9a-f]{2}){5}$`)

// addrLike matches what could name a host in an error: IPv4 addresses and MAC addresses.
var addrLike = regexp.MustCompile(`\d{1,3}(\.\d{1,3}){3}(/\d+)?|[0-9A-Fa-f]{2}([:-][0-9A-Fa-f]{2}){5}`)

// TestLiveScan sweeps this PC's real home network once, by ARP (SendARP), when ATTMON_LIVE_SCAN=1:
// it shows that the questions work on this machine. It reports counts only - never an address, a
// MAC address or a name (the repository is public, and test logs may be too). The gateway's
// address is ATTMON_LIVE_GATEWAY, else gateway.host's default.
func TestLiveScan(t *testing.T) {
	if os.Getenv("ATTMON_LIVE_SCAN") != "1" {
		t.Skip("sweeps the real home network: set ATTMON_LIVE_SCAN=1 to run it")
	}
	gw := os.Getenv("ATTMON_LIVE_GATEWAY")
	if gw == "" {
		gw = "192.168.1.254"
	}
	sc, err := New(Options{Gateway: gw}).Scan(context.Background())
	if err != nil {
		t.Fatalf("the sweep failed: %s", addrLike.ReplaceAllString(err.Error(), "<address>"))
	}
	prefix, err := netip.ParsePrefix(sc.Subnet)
	if err != nil {
		t.Fatalf("the scan's subnet does not parse")
	}
	selfListed, gwAnswered, malformed := false, false, 0
	var addrs []netip.Addr
	for _, h := range sc.Hosts {
		a, err := netip.ParseAddr(h.IP)
		if err != nil || !prefix.Contains(a) || !macForm.MatchString(h.MAC) {
			malformed++
			continue
		}
		addrs = append(addrs, a)
		selfListed = selfListed || h.IP == sc.Self
		gwAnswered = gwAnswered || h.IP == gw
	}
	t.Logf("swept a /%d network: %d of %d addresses answered in %d ms; this PC listed: %v; the gateway answered: %v; "+
		"hosts malformed: %d; a problem: %v", prefix.Bits(), len(sc.Hosts), sc.Asked, sc.TookMs, selfListed, gwAnswered,
		malformed, sc.Problem != "")
	if !selfListed || !gwAnswered || malformed > 0 || !slices.IsSortedFunc(addrs, netip.Addr.Compare) || hostsUnique(sc.Hosts) != len(sc.Hosts) {
		t.Error("the scan is not as expected (see the counts above)")
	}
}

// hostsUnique counts the distinct addresses of hosts.
func hostsUnique(hosts []model.LANHost) int {
	seen := map[string]bool{}
	for _, h := range hosts {
		seen[h.IP] = true
	}
	return len(seen)
}
