//go:build windows

package monitor

import (
	"errors"
	"net/netip"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var procGetBestRoute2 = windows.NewLazySystemDLL("iphlpapi.dll").NewProc("GetBestRoute2")

// systemRoute returns the route the IP stack uses for dst (GetBestRoute2, no administrator
// rights needed) and the alias of its interface (GetIfEntry2Ex).
func systemRoute(dst netip.Addr) (routeInfo, error) {
	if !dst.Is4() {
		return routeInfo{}, errors.New("route lookup: IPv4 only")
	}
	if err := procGetBestRoute2.Find(); err != nil {
		return routeInfo{}, err
	}
	var dest, src windows.RawSockaddrInet // SOCKADDR_INET
	d4 := (*windows.RawSockaddrInet4)(unsafe.Pointer(&dest))
	d4.Family = windows.AF_INET
	d4.Addr = dst.As4()
	var row windows.MibIpForwardRow2
	r, _, _ := procGetBestRoute2.Call(0, 0, 0, uintptr(unsafe.Pointer(&dest)), 0,
		uintptr(unsafe.Pointer(&row)), uintptr(unsafe.Pointer(&src)))
	if r != 0 {
		return routeInfo{}, os.NewSyscallError("GetBestRoute2", syscall.Errno(r))
	}
	ri := routeInfo{IfIndex: row.InterfaceIndex}
	if row.NextHop.Family == windows.AF_INET {
		ri.NextHop = netip.AddrFrom4((*windows.RawSockaddrInet4)(unsafe.Pointer(&row.NextHop)).Addr)
	}
	ifRow := windows.MibIfRow2{InterfaceIndex: row.InterfaceIndex}
	if windows.GetIfEntry2Ex(windows.MibIfEntryNormalWithoutStatistics, &ifRow) == nil {
		ri.IfName = windows.UTF16ToString(ifRow.Alias[:])
	}
	return ri, nil
}
