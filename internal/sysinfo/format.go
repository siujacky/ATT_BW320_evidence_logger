package sysinfo

import (
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"
)

// windows11FirstBuild is the first Windows 11 build number. The registry value ProductName
// still reads "Windows 10 ..." on Windows 11, so the build number decides which it is.
const windows11FirstBuild = 22000

// fixProductName corrects the "Windows 10" product name that the registry reports on
// Windows 11 (build >= 22000). Other names (e.g. "Windows Server 2025 Datacenter") and
// older builds are returned unchanged.
func fixProductName(name string, build uint32) string {
	const old, repl = "Windows 10", "Windows 11"
	if build < windows11FirstBuild {
		return name
	}
	i := strings.Index(name, old)
	if i < 0 {
		return name
	}
	end := i + len(old)
	if end < len(name) && name[end] >= '0' && name[end] <= '9' {
		return name // e.g. "Windows 100": not the marketing version we are fixing
	}
	return name[:i] + repl + name[end:]
}

// composeOSName builds the human-readable OS description from the registry values under
// HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion, in the style winver uses, e.g.
// "Windows 11 Pro for Workstations, version 25H2 (OS build 26200.9457)".
//
// productName falls back to "Windows <editionID>" when empty; displayVersion falls back to
// releaseID (systems before 20H2 have no DisplayVersion); build and ubr (update build
// revision) are omitted when zero. The result always mentions "Windows".
func composeOSName(productName, displayVersion, releaseID, editionID string, build, ubr uint32) string {
	name := strings.TrimSpace(productName)
	if name == "" {
		name = "Windows"
		if e := strings.TrimSpace(editionID); e != "" {
			name += " " + e
		}
	}
	name = fixProductName(name, build)
	if !strings.Contains(strings.ToLower(name), "windows") {
		name = "Windows " + name
	}
	version := strings.TrimSpace(displayVersion)
	if version == "" {
		version = strings.TrimSpace(releaseID)
	}
	if version != "" {
		name += ", version " + version
	}
	if build != 0 {
		b := strconv.FormatUint(uint64(build), 10)
		if ubr != 0 {
			b += "." + strconv.FormatUint(uint64(ubr), 10)
		}
		name += " (OS build " + b + ")"
	}
	return name
}

// formatTimeZone renders the zone abbreviation, its current UTC offset and, when known, the
// Windows time zone id, e.g. "CDT UTC-05:00 [Windows: Central Standard Time]".
func formatTimeZone(abbrev string, offsetSec int, windowsKey string) string {
	sign := '+'
	if offsetSec < 0 {
		sign = '-'
		offsetSec = -offsetSec
	}
	s := fmt.Sprintf("UTC%c%02d:%02d", sign, offsetSec/3600, offsetSec%3600/60)
	if a := strings.TrimSpace(abbrev); a != "" {
		s = a + " " + s
	}
	if k := strings.TrimSpace(windowsKey); k != "" {
		s += " [Windows: " + k + "]"
	}
	return s
}

// formatInterface renders one network adapter as "Name ip/prefix ... mac". Addresses are
// sorted (IPv4 before IPv6) and de-duplicated so the output is stable across calls; the MAC
// part is omitted for adapters without a hardware address (tunnels).
func formatInterface(name string, prefixes []netip.Prefix, mac net.HardwareAddr) string {
	ps := slices.Clone(prefixes)
	slices.SortFunc(ps, func(a, b netip.Prefix) int {
		if c := a.Addr().Compare(b.Addr()); c != 0 {
			return c
		}
		return a.Bits() - b.Bits()
	})
	ps = slices.Compact(ps)
	parts := make([]string, 0, len(ps)+2)
	parts = append(parts, name)
	for _, p := range ps {
		parts = append(parts, p.String())
	}
	if len(mac) > 0 {
		parts = append(parts, mac.String())
	}
	return strings.Join(parts, " ")
}

// ipNetPrefix converts an adapter address to a prefix. IPv4 addresses may arrive as 16-byte
// IPv4-mapped values with a 4- or 16-byte mask (Go on Windows uses a 4-byte mask today);
// either way the result is a plain IPv4 prefix, never an invalid one. A mask that is not a
// canonical prefix, or does not fit the address, records the host address alone. IPv6
// link-local addresses are skipped (ok == false): always present, never routed.
func ipNetPrefix(ipn *net.IPNet) (netip.Prefix, bool) {
	if ipn == nil {
		return netip.Prefix{}, false
	}
	ip, ok := netip.AddrFromSlice(ipn.IP)
	if !ok {
		return netip.Prefix{}, false
	}
	ip = ip.Unmap()
	if ip.Is6() && ip.IsLinkLocalUnicast() {
		return netip.Prefix{}, false
	}
	ones, bits := ipn.Mask.Size()
	if ip.Is4() && bits == 128 { // IPv4-mapped mask: drop the ::ffff:0:0/96 part
		ones, bits = ones-96, 32
	}
	if bits != ip.BitLen() || ones < 0 || ones > bits { // non-canonical or foreign mask
		ones = ip.BitLen()
	}
	return netip.PrefixFrom(ip, ones), true
}

// formatBootTime returns now - sinceBoot as RFC 3339 UTC, rounded to the second (the tick
// count has ~16 ms resolution, so finer digits would only add jitter between calls).
func formatBootTime(now time.Time, sinceBoot time.Duration) string {
	return now.Add(-sinceBoot).UTC().Round(time.Second).Format(time.RFC3339)
}
