//go:build windows

package sysinfo

import (
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func TestHost(t *testing.T) {
	h := Host()
	t.Logf("host: %+v", h)

	if strings.TrimSpace(h.Hostname) == "" {
		t.Error("Hostname is empty")
	}
	if !strings.Contains(h.OS, "Windows") {
		t.Errorf("OS = %q, want it to contain \"Windows\"", h.OS)
	}

	m := regexp.MustCompile(`^(\d+)\.(\d+)\.(\d+)$`).FindStringSubmatch(h.OSVersion)
	if m == nil {
		t.Fatalf("OSVersion = %q, want major.minor.build", h.OSVersion)
	}
	major, _ := strconv.Atoi(m[1])
	build, _ := strconv.Atoi(m[3])
	if major < 10 || build == 0 {
		t.Errorf("OSVersion = %q is implausible for a supported Windows", h.OSVersion)
	}
	// The product name must agree with the build number about Windows 10 vs 11.
	if build >= windows11FirstBuild && strings.Contains(h.OS, "Windows 10") {
		t.Errorf("OS = %q on build %d: Windows 10 name not corrected", h.OS, build)
	}
	if !strings.Contains(h.OS, "OS build "+m[3]) {
		t.Errorf("OS = %q does not mention build %s", h.OS, m[3])
	}

	boot, err := time.Parse(time.RFC3339, h.BootTime)
	if err != nil {
		t.Fatalf("BootTime = %q: %v", h.BootTime, err)
	}
	if !strings.HasSuffix(h.BootTime, "Z") {
		t.Errorf("BootTime = %q, want UTC", h.BootTime)
	}
	now := time.Now()
	if boot.After(now.Add(2*time.Second)) || boot.Before(time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("BootTime = %v is implausible (now %v)", boot, now)
	}
	// Cross-check against the tick count directly (±2 s for rounding and elapsed time).
	want := now.Add(-windows.DurationSinceBoot())
	if d := boot.Sub(want); d < -2*time.Second || d > 2*time.Second {
		t.Errorf("BootTime = %v, expected about %v", boot, want.UTC())
	}

	if h.TimeZone == "" || !strings.Contains(h.TimeZone, "UTC") {
		t.Errorf("TimeZone = %q, want a zone with UTC offset", h.TimeZone)
	}
	_, off := now.Zone()
	if !strings.Contains(h.TimeZone, formatTimeZone("", off, "")) {
		t.Errorf("TimeZone = %q does not contain the current offset %s", h.TimeZone, formatTimeZone("", off, ""))
	}

	for _, s := range h.Interfaces {
		if strings.TrimSpace(s) == "" {
			t.Error("empty interface entry")
		}
		if strings.HasPrefix(strings.ToLower(s), "loopback") {
			t.Errorf("loopback interface listed: %q", s)
		}
		if strings.Contains(s, " fe80:") {
			t.Errorf("IPv6 link-local address listed: %q", s)
		}
	}
}

// Host must be stable across calls (it is compared between monitor_start records).
func TestHostStable(t *testing.T) {
	a, b := Host(), Host()
	if a.Hostname != b.Hostname || a.OS != b.OS || a.OSVersion != b.OSVersion || a.TimeZone != b.TimeZone {
		t.Errorf("Host() changed between calls:\n%+v\n%+v", a, b)
	}
	ta, _ := time.Parse(time.RFC3339, a.BootTime)
	tb, _ := time.Parse(time.RFC3339, b.BootTime)
	if d := tb.Sub(ta); d < -time.Second || d > time.Second {
		t.Errorf("BootTime moved by %v between calls (%s, %s)", d, a.BootTime, b.BootTime)
	}
}
