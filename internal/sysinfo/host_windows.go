//go:build windows

package sysinfo

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"attmonitor/internal/model"
)

const (
	currentVersionKey = `SOFTWARE\Microsoft\Windows NT\CurrentVersion`
	timeZoneKey       = `SYSTEM\CurrentControlSet\Control\TimeZoneInformation`
)

// Host describes this computer: host name, OS product name and version, boot time, the
// network adapters that are up (loopback excluded) and the time zone.
func Host() model.HostInfo {
	now := time.Now()
	v := windows.RtlGetVersion()
	zone, offset := now.Zone()
	return model.HostInfo{
		Hostname:   hostname(),
		OS:         osName(v.BuildNumber),
		OSVersion:  fmt.Sprintf("%d.%d.%d", v.MajorVersion, v.MinorVersion, v.BuildNumber),
		BootTime:   formatBootTime(now, windows.DurationSinceBoot()),
		Interfaces: interfaces(),
		// The Windows zone id (e.g. "Central Standard Time") disambiguates abbreviations.
		TimeZone: formatTimeZone(zone, offset, registryString(timeZoneKey, "TimeZoneKeyName")),
	}
}

func hostname() string {
	if h, err := os.Hostname(); err == nil && h != "" {
		return h
	}
	if h := os.Getenv("COMPUTERNAME"); h != "" {
		return h
	}
	return "unknown"
}

// osName reads the product name from the registry and fixes the Windows 10/11 confusion.
func osName(build uint32) string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, currentVersionKey, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return composeOSName("", "", "", "", build, 0)
	}
	defer k.Close()
	str := func(name string) string {
		s, _, err := k.GetStringValue(name)
		if err != nil {
			return ""
		}
		return s
	}
	var ubr uint32
	if n, _, err := k.GetIntegerValue("UBR"); err == nil && n <= 0xffffffff {
		ubr = uint32(n)
	}
	return composeOSName(str("ProductName"), str("DisplayVersion"), str("ReleaseId"), str("EditionID"), build, ubr)
}

// registryString returns a REG_SZ value under HKLM, or "" if it cannot be read.
func registryString(path, name string) string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return ""
	}
	defer k.Close()
	s, _, err := k.GetStringValue(name)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(s)
}

// interfaces lists the adapters that are up, excluding loopback, as "Name ip/prefix mac".
// IPv6 link-local addresses are left out (always present, never routed, not informative);
// IPv4 link-local (169.254/16) is kept because it reveals a DHCP failure.
func interfaces() []string {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []string
	for _, ifi := range ifs {
		if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := ifi.Addrs()
		if err != nil {
			addrs = nil
		}
		var prefixes []netip.Prefix
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok {
				if p, ok := ipNetPrefix(ipn); ok {
					prefixes = append(prefixes, p)
				}
			}
		}
		out = append(out, formatInterface(ifi.Name, prefixes, ifi.HardwareAddr))
	}
	slices.Sort(out)
	return out
}
