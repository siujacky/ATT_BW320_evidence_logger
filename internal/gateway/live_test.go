package gateway

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"
)

// documentedCertSHA256 is the gateway certificate observed during setup (docs/DESIGN.md §2).
const documentedCertSHA256 = "49cd292d40af94d686b6ee17cb67ce4ded40e9c0be2b2537c7bc6e37cf9a2ed0"

// TestLiveSnapshot reads the three status pages from the real gateway. It only sends
// unauthenticated GET requests (no login, no form submission) and runs only with
// ATTMON_LIVE=1. ATTMON_GATEWAY overrides the host (default 192.168.1.254).
func TestLiveSnapshot(t *testing.T) {
	if os.Getenv("ATTMON_LIVE") != "1" {
		t.Skip("set ATTMON_LIVE=1 to GET status pages from the real gateway (read-only, unauthenticated)")
	}
	host := os.Getenv("ATTMON_GATEWAY")
	if host == "" {
		host = DefaultHost
	}
	var logs syncBuffer
	var mu sync.Mutex
	var observed [][2]string
	c := New(Options{
		Host:      host,
		Scheme:    "https",
		Timeout:   30 * time.Second,
		UserAgent: "att-monitor/live-test",
		Logger:    debugLogger(&logs),
		// AccessCode deliberately nil: this test can never log in.
	})
	c.SetCertObserver(func(prev, obs string) bool {
		mu.Lock()
		defer mu.Unlock()
		observed = append(observed, [2]string{prev, obs})
		return true // first use in a test client
	})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	snap, bodies, err := c.Snapshot(ctx, statusPages, "live_test")
	t.Logf("operational log:\n%s", logs.String())
	if err != nil {
		t.Fatal(err)
	}
	for _, pc := range snap.Pages {
		b := bodies[pc.Page]
		t.Logf("%-20s status=%d bytes=%d dur=%dms utf8=%v sha256=%s cert=%s err=%q",
			pc.Page, pc.Status, pc.Bytes, pc.DurMs, utf8.Valid(b), pc.SHA256, pc.TLSCertSHA256, pc.Err)
		if pc.Status != 200 || pc.LoginPage || pc.Err != "" || pc.NotAttempted || pc.SHA256 != sha256hex(b) {
			t.Errorf("%s: unexpected capture %+v", pc.Page, pc)
		}
	}
	if si := snap.System; si != nil {
		t.Logf("sysinfo Current Date/Time: row present=%v raw=%q -> gateway_clock_blank=%v gateway_clock_offset_ms=%v",
			si.GatewayTimePresent, si.GatewayTimeRaw, snap.Derived.GatewayClockBlank, deref(snap.Derived.GatewayClockOffsetMs))
		if !si.GatewayTimePresent {
			t.Error("sysinfo has no Current Date/Time row: the gateway's WAN-down indicator cannot be observed (firmware change?)")
		}
		if blank := normSpace(si.GatewayTimeRaw) == ""; snap.Derived.GatewayClockBlank != (si.GatewayTimePresent && blank) {
			t.Errorf("GatewayClockBlank = %v for row present=%v raw=%q", snap.Derived.GatewayClockBlank, si.GatewayTimePresent, si.GatewayTimeRaw)
		}
	}
	mu.Lock()
	t.Logf("certificate observer calls: %v", observed)
	mu.Unlock()
	if pin := c.PinnedCert(); pin != documentedCertSHA256 {
		t.Logf("NOTE: the gateway certificate %s differs from the one documented in DESIGN.md §2 (%s)", pin, documentedCertSHA256)
	}
	if snap.System == nil || !strings.Contains(snap.System.Model, "BGW320") {
		t.Errorf("sysinfo not parsed: %+v", snap.System)
	}
	if snap.Broadband == nil || snap.Broadband.Connection == "" || len(snap.Broadband.Counters) == 0 {
		t.Errorf("broadbandstatistics not parsed: %+v", snap.Broadband)
	}
	if snap.Fiber == nil || len(snap.Fiber.Measures) != 5 || snap.Fiber.OpticalStatus == "" {
		t.Errorf("fiberstat not parsed: %+v", snap.Fiber)
	}
	if !snap.Derived.Reachable {
		t.Error("Derived.Reachable = false")
	}
	d, _ := json.MarshalIndent(snap.Derived, "", "  ")
	t.Logf("derived:\n%s", d)
	if snap.Fiber != nil {
		for _, m := range snap.Fiber.Measures {
			t.Logf("DMI %-12s current=%-6s unit=%-6s lowAlarm=%q lowWarn=%q highAlarm=%q highWarn=%q",
				m.Name, m.CurrentRaw, m.Unit, m.LowAlarm.Raw, m.LowWarn.Raw, m.HighAlarm.Raw, m.HighWarn.Raw)
		}
	}
}
