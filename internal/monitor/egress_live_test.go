//go:build windows

package monitor

import (
	"net/netip"
	"os"
	"testing"
)

// TestLiveSystemRoute reads this computer's real routing table (ATTMON_LIVE=1 only): the routes
// to the gateway and to the default internet targets resolve, and the check is consistent.
func TestLiveSystemRoute(t *testing.T) {
	if os.Getenv("ATTMON_LIVE") != "1" {
		t.Skip("live test: set ATTMON_LIVE=1")
	}
	for _, dst := range []string{gwIP, "1.1.1.1", "8.8.8.8"} {
		ri, err := systemRoute(netip.MustParseAddr(dst))
		if err != nil {
			t.Fatalf("%s: %v", dst, err)
		}
		if ri.IfIndex == 0 {
			t.Fatalf("%s: no interface: %+v", dst, ri)
		}
		t.Logf("%s: interface %d %q next hop %v", dst, ri.IfIndex, ri.IfName, ri.NextHop)
	}
	e := checkEgress(systemRoute, gwIP, []string{"1.1.1.1", "8.8.8.8", "9.9.9.9"})
	t.Logf("egress %+v bypass %q", e, bypassText(e))
	if e.Err != "" {
		t.Fatalf("egress check failed: %s", e.Err)
	}
	if _, err := systemRoute(netip.MustParseAddr("2606:4700::1111")); err == nil {
		t.Fatal("IPv6 lookups are not supported")
	}
	free, total, err := systemDiskFree(os.TempDir())
	if err != nil || total == 0 || free > total {
		t.Fatalf("disk free %d of %d: %v", free, total, err)
	}
	t.Logf("disk: %s free of %s", fmtBytes(free), fmtBytes(total))
}
