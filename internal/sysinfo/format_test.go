package sysinfo

import (
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestFixProductName(t *testing.T) {
	tests := []struct {
		name  string
		in    string
		build uint32
		want  string
	}{
		{"win11 pro workstations", "Windows 10 Pro for Workstations", 26200, "Windows 11 Pro for Workstations"},
		{"win11 home at first build", "Windows 10 Home", 22000, "Windows 11 Home"},
		{"win11 bare name", "Windows 10", 22631, "Windows 11"},
		{"win11 iot ltsc", "Windows 10 IoT Enterprise LTSC 2024", 26100, "Windows 11 IoT Enterprise LTSC 2024"},
		{"real windows 10 stays", "Windows 10 Pro", 19045, "Windows 10 Pro"},
		{"last windows 10 build stays", "Windows 10 Enterprise", 21999, "Windows 10 Enterprise"},
		{"server 2025 untouched", "Windows Server 2025 Datacenter", 26100, "Windows Server 2025 Datacenter"},
		{"server 2022 untouched", "Windows Server 2022 Standard", 20348, "Windows Server 2022 Standard"},
		{"digit after 10 is not the marketing name", "Windows 100 Lab", 26100, "Windows 100 Lab"},
		{"empty", "", 26100, ""},
		{"build zero (unknown) leaves name alone", "Windows 10 Pro", 0, "Windows 10 Pro"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := fixProductName(tc.in, tc.build); got != tc.want {
				t.Errorf("fixProductName(%q, %d) = %q, want %q", tc.in, tc.build, got, tc.want)
			}
		})
	}
}

func TestComposeOSName(t *testing.T) {
	tests := []struct {
		name                               string
		product, display, release, edition string
		build, ubr                         uint32
		want                               string
	}{
		{
			name: "this machine (win11 reported as win10)", product: "Windows 10 Pro for Workstations",
			display: "25H2", release: "2009", edition: "ProfessionalWorkstation", build: 26200, ubr: 9457,
			want: "Windows 11 Pro for Workstations, version 25H2 (OS build 26200.9457)",
		},
		{
			name: "old windows 10 without DisplayVersion uses ReleaseId", product: "Windows 10 Pro",
			release: "1909", build: 18363, ubr: 1556,
			want: "Windows 10 Pro, version 1909 (OS build 18363.1556)",
		},
		{
			name: "missing product name falls back to edition", edition: "Professional", build: 22631,
			want: "Windows Professional (OS build 22631)",
		},
		{
			name: "registry unreadable", build: 26100,
			want: "Windows (OS build 26100)",
		},
		{
			name: "nothing known at all",
			want: "Windows",
		},
		{
			name: "product without the word Windows gets it", product: "Hyper-V Server", build: 17763,
			want: "Windows Hyper-V Server (OS build 17763)",
		},
		{
			name: "whitespace is trimmed", product: "  Windows 10 Home  ", display: " 24H2 ", build: 26100, ubr: 1,
			want: "Windows 11 Home, version 24H2 (OS build 26100.1)",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := composeOSName(tc.product, tc.display, tc.release, tc.edition, tc.build, tc.ubr)
			if got != tc.want {
				t.Errorf("composeOSName() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestFormatTimeZone(t *testing.T) {
	tests := []struct {
		abbrev string
		offset int
		key    string
		want   string
	}{
		{"CDT", -5 * 3600, "Central Standard Time", "CDT UTC-05:00 [Windows: Central Standard Time]"},
		{"PST", -8 * 3600, "Pacific Standard Time", "PST UTC-08:00 [Windows: Pacific Standard Time]"},
		{"IST", 5*3600 + 30*60, "India Standard Time", "IST UTC+05:30 [Windows: India Standard Time]"},
		{"NPT", 5*3600 + 45*60, "", "NPT UTC+05:45"},
		{"NST", -(3*3600 + 30*60), "Newfoundland Standard Time", "NST UTC-03:30 [Windows: Newfoundland Standard Time]"},
		{"UTC", 0, "UTC", "UTC UTC+00:00 [Windows: UTC]"},
		{"", 9 * 3600, "", "UTC+09:00"},
		{"HKT", 8 * 3600, "  China Standard Time ", "HKT UTC+08:00 [Windows: China Standard Time]"},
	}
	for _, tc := range tests {
		if got := formatTimeZone(tc.abbrev, tc.offset, tc.key); got != tc.want {
			t.Errorf("formatTimeZone(%q, %d, %q) = %q, want %q", tc.abbrev, tc.offset, tc.key, got, tc.want)
		}
	}
}

func TestFormatInterface(t *testing.T) {
	mac := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0x01, 0x02, 0x03}
	p := netip.MustParsePrefix
	tests := []struct {
		name     string
		ifName   string
		prefixes []netip.Prefix
		mac      net.HardwareAddr
		want     string
	}{
		{"wifi ipv4 only", "Wi-Fi", []netip.Prefix{p("192.168.1.71/24")}, mac, "Wi-Fi 192.168.1.71/24 aa:bb:cc:01:02:03"},
		{
			"ipv6 sorted after ipv4, duplicates removed", "Ethernet 2",
			[]netip.Prefix{p("2600:1700:abcd::71/64"), p("192.168.1.80/24"), p("2600:1700:abcd::71/64"), p("10.0.0.2/8")},
			mac, "Ethernet 2 10.0.0.2/8 192.168.1.80/24 2600:1700:abcd::71/64 aa:bb:cc:01:02:03",
		},
		{"tunnel without mac", "VPN", []netip.Prefix{p("10.8.0.6/32")}, nil, "VPN 10.8.0.6/32"},
		{"no address", "vEthernet (Default Switch)", nil, mac, "vEthernet (Default Switch) aa:bb:cc:01:02:03"},
		{"apipa is kept", "Ethernet", []netip.Prefix{p("169.254.10.20/16")}, mac, "Ethernet 169.254.10.20/16 aa:bb:cc:01:02:03"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			in := append([]netip.Prefix(nil), tc.prefixes...)
			if got := formatInterface(tc.ifName, tc.prefixes, tc.mac); got != tc.want {
				t.Errorf("formatInterface() = %q, want %q", got, tc.want)
			}
			for i := range in { // the caller's slice must not be reordered
				if in[i] != tc.prefixes[i] {
					t.Fatalf("formatInterface modified its input: %v", tc.prefixes)
				}
			}
		})
	}
}

func TestFormatBootTime(t *testing.T) {
	// 22:20:00.4 CDT on Oct 4 is 03:20:00.4 UTC on Oct 5: the output must be UTC.
	now := time.Date(2026, 10, 4, 22, 20, 0, 400_000_000, time.FixedZone("CDT", -5*3600))
	tests := []struct {
		since time.Duration
		want  string
	}{
		{0, "2026-10-05T03:20:00Z"},
		{90 * time.Minute, "2026-10-05T01:50:00Z"},
		{3*24*time.Hour + 2*time.Second, "2026-10-02T03:19:58Z"},
		{-600 * time.Millisecond, "2026-10-05T03:20:01Z"}, // 03:20:01.0 exactly
		{100 * time.Millisecond, "2026-10-05T03:20:00Z"},  // 03:20:00.3 rounds down
		{-200 * time.Millisecond, "2026-10-05T03:20:01Z"}, // 03:20:00.6 rounds up
	}
	for _, tc := range tests {
		if got := formatBootTime(now, tc.since); got != tc.want {
			t.Errorf("formatBootTime(now, %v) = %q, want %q", tc.since, got, tc.want)
		}
	}
}

func TestIPNetPrefix(t *testing.T) {
	v4 := func(a, b, c, d byte) net.IP { return net.IPv4(a, b, c, d) } // 16-byte IPv4-mapped form
	tests := []struct {
		name   string
		ipn    *net.IPNet
		want   string
		wantOK bool
	}{
		{"4-byte address and mask", &net.IPNet{IP: net.IP{192, 168, 1, 71}, Mask: net.CIDRMask(24, 32)}, "192.168.1.71/24", true},
		{"16-byte address, 4-byte mask (Go on Windows)", &net.IPNet{IP: v4(192, 168, 1, 71), Mask: net.CIDRMask(24, 32)}, "192.168.1.71/24", true},
		{"16-byte address and IPv4-mapped 16-byte mask", &net.IPNet{IP: v4(10, 0, 0, 2), Mask: net.CIDRMask(96+8, 128)}, "10.0.0.2/8", true},
		{"IPv4 with a too-short 16-byte mask records the host", &net.IPNet{IP: v4(10, 0, 0, 2), Mask: net.CIDRMask(64, 128)}, "10.0.0.2/32", true},
		{"non-canonical mask records the host", &net.IPNet{IP: v4(10, 1, 2, 3), Mask: net.IPv4Mask(255, 0, 255, 0)}, "10.1.2.3/32", true},
		{"APIPA is kept (reveals a DHCP failure)", &net.IPNet{IP: v4(169, 254, 7, 8), Mask: net.CIDRMask(16, 32)}, "169.254.7.8/16", true},
		{"IPv6 global", &net.IPNet{IP: net.ParseIP("2600:1700:abcd::71"), Mask: net.CIDRMask(64, 128)}, "2600:1700:abcd::71/64", true},
		{"IPv6 /128 as Windows reports some addresses", &net.IPNet{IP: net.ParseIP("2600:1700:abcd::46"), Mask: net.CIDRMask(128, 128)}, "2600:1700:abcd::46/128", true},
		{"IPv6 with a 4-byte mask records the host", &net.IPNet{IP: net.ParseIP("2001:db8::1"), Mask: net.CIDRMask(24, 32)}, "2001:db8::1/128", true},
		{"IPv6 link-local skipped", &net.IPNet{IP: net.ParseIP("fe80::1c2b:3a4d"), Mask: net.CIDRMask(64, 128)}, "", false},
		{"nil skipped", nil, "", false},
		{"malformed address skipped", &net.IPNet{IP: net.IP{1, 2, 3}, Mask: net.CIDRMask(24, 32)}, "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p, ok := ipNetPrefix(tc.ipn)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v (prefix %v)", ok, tc.wantOK, p)
			}
			if !ok {
				return
			}
			if !p.IsValid() || p.String() != tc.want {
				t.Errorf("ipNetPrefix = %v (valid %v), want %s", p, p.IsValid(), tc.want)
			}
		})
	}
}
