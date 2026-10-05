//go:build windows

package probe

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// netshTimeout bounds "netsh wlan show interfaces".
const netshTimeout = 5 * time.Second

// listAdapters enumerates network adapters with GetAdaptersAddresses (IPv4 unicast
// addresses with prefix lengths, and IPv4 gateways).
func listAdapters() ([]adapterInfo, error) {
	const flags = windows.GAA_FLAG_INCLUDE_GATEWAYS | windows.GAA_FLAG_SKIP_ANYCAST |
		windows.GAA_FLAG_SKIP_MULTICAST | windows.GAA_FLAG_SKIP_DNS_SERVER
	size := uint32(16 << 10)
	for attempt := 0; attempt < 5; attempt++ {
		// A large []byte is at least 8-byte aligned, as IP_ADAPTER_ADDRESSES requires (the
		// standard library's net package uses the same pattern).
		buf := make([]byte, size)
		first := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0]))
		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, flags, 0, first, &size)
		switch {
		case err == nil:
			return convertAdapters(first), nil
		case errors.Is(err, windows.ERROR_NO_DATA):
			return nil, nil
		case errors.Is(err, windows.ERROR_BUFFER_OVERFLOW):
			continue // size now holds the required length
		default:
			return nil, os.NewSyscallError("GetAdaptersAddresses", err)
		}
	}
	return nil, errors.New("GetAdaptersAddresses: buffer kept growing")
}

// convertAdapters copies the linked list into plain values while the buffer is alive.
func convertAdapters(first *windows.IpAdapterAddresses) []adapterInfo {
	var out []adapterInfo
	for aa := first; aa != nil; aa = aa.Next {
		a := adapterInfo{
			Name:        windows.BytePtrToString(aa.AdapterName),
			Friendly:    windows.UTF16PtrToString(aa.FriendlyName),
			Description: windows.UTF16PtrToString(aa.Description),
			IfIndex:     aa.IfIndex,
			IfType:      aa.IfType,
			OperStatus:  aa.OperStatus,
			TxSpeed:     aa.TransmitLinkSpeed,
		}
		for u := aa.FirstUnicastAddress; u != nil; u = u.Next {
			if ip, ok := netip.AddrFromSlice(u.Address.IP()); ok && ip.Unmap().Is4() {
				bits := int(u.OnLinkPrefixLength)
				if bits > 32 {
					bits = 32
				}
				a.IPv4 = append(a.IPv4, netip.PrefixFrom(ip.Unmap(), bits))
			}
		}
		for g := aa.FirstGatewayAddress; g != nil; g = g.Next {
			if ip, ok := netip.AddrFromSlice(g.Address.IP()); ok && ip.Unmap().Is4() {
				a.Gateways = append(a.Gateways, ip.Unmap())
			}
		}
		out = append(out, a)
	}
	return out
}

// bestInterface returns the IPv4 interface index the routing table uses to reach dst.
func bestInterface(dst netip.Addr) (uint32, error) {
	if !dst.Is4() {
		return 0, errors.New("bestInterface: IPv4 only")
	}
	var idx uint32
	if err := windows.GetBestInterfaceEx(&windows.SockaddrInet4{Addr: dst.As4()}, &idx); err != nil {
		return 0, os.NewSyscallError("GetBestInterfaceEx", err)
	}
	return idx, nil
}

// runNetshWLAN runs "%SystemRoot%\System32\netsh.exe wlan show interfaces" (absolute path:
// never resolved through PATH, the service runs as LocalSystem) without a console window and
// returns its combined output. Output is returned even when netsh exits non-zero.
func runNetshWLAN(ctx context.Context) ([]byte, error) {
	sys, err := windows.GetSystemDirectory()
	if err != nil {
		return nil, fmt.Errorf("system directory: %w", err)
	}
	ctx, cancel := context.WithTimeout(ctx, netshTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, filepath.Join(sys, "netsh.exe"), "wlan", "show", "interfaces")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW}
	cmd.WaitDelay = time.Second
	out, err := cmd.CombinedOutput()
	if err != nil && ctx.Err() != nil {
		err = fmt.Errorf("%w (limit %v)", ctx.Err(), netshTimeout)
	}
	return out, err
}
