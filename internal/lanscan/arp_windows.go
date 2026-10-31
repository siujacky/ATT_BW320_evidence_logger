//go:build windows

package lanscan

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os"
	"slices"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"

	"attmonitor/internal/contracts"
)

// procSendARP is iphlpapi.dll's SendARP (golang.org/x/sys/windows has no wrapper of it):
//
//	DWORD SendARP(IPAddr DestIP, IPAddr SrcIP, PVOID pMacAddr, PULONG PhyAddrLen);
//
// It needs no administrator rights and no raw socket. When this PC's ARP cache holds the address
// it answers from there; otherwise it sends ARP requests from SrcIP's interface and waits for the
// answer, a few seconds at most.
var procSendARP = windows.NewLazySystemDLL("iphlpapi.dll").NewProc("SendARP")

// arpReady reports whether SendARP can be called (ErrUnavailable when it cannot be found).
func arpReady() error {
	if err := procSendARP.Find(); err != nil {
		return fmt.Errorf("lanscan: %w: SendARP of iphlpapi.dll: %v", contracts.ErrUnavailable, err)
	}
	return nil
}

// systemARP asks dst by ARP from src (SendARP). ERROR_BAD_NET_NAME (Windows Vista and later) and
// ERROR_GEN_FAILURE (earlier) mean that nobody answered: errNoAnswer, as is an answer that is not
// a six-byte address. The question cannot be called back: ctx is looked at only before it is made.
func systemARP(ctx context.Context, dst, src netip.Addr) (net.HardwareAddr, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// IPAddr is the address in network byte order: its four bytes as they stand, in memory.
	d, s := dst.As4(), src.As4()
	var mac [8]byte // ULONG[2], as in Microsoft's example
	n := uint32(6)  // PhyAddrLen: the room for an Ethernet address; on return the length written
	r, _, _ := procSendARP.Call(uintptr(binary.NativeEndian.Uint32(d[:])), uintptr(binary.NativeEndian.Uint32(s[:])),
		uintptr(unsafe.Pointer(&mac[0])), uintptr(unsafe.Pointer(&n)))
	switch e := syscall.Errno(r); e {
	case 0:
	case windows.ERROR_BAD_NET_NAME, windows.ERROR_GEN_FAILURE:
		return nil, errNoAnswer
	default:
		return nil, os.NewSyscallError("SendARP", e)
	}
	if n != 6 {
		return nil, errNoAnswer
	}
	return net.HardwareAddr(slices.Clone(mac[:6])), nil
}
