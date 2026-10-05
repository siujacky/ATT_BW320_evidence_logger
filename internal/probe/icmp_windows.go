//go:build windows

package probe

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The Windows ICMP helper API. IcmpSendEcho needs neither administrator rights nor raw
// sockets; the kernel sends the request and matches the reply to it.
var (
	modIphlpapi         = windows.NewLazySystemDLL("iphlpapi.dll")
	procIcmpCreateFile  = modIphlpapi.NewProc("IcmpCreateFile")
	procIcmpSendEcho    = modIphlpapi.NewProc("IcmpSendEcho")
	procIcmpCloseHandle = modIphlpapi.NewProc("IcmpCloseHandle")
)

// icmpProcsErr resolves the procedures once; LazyProc.Call would panic on a missing one.
var icmpProcsErr = sync.OnceValue(func() error {
	for _, p := range []*windows.LazyProc{procIcmpCreateFile, procIcmpSendEcho, procIcmpCloseHandle} {
		if err := p.Find(); err != nil {
			return fmt.Errorf("iphlpapi.dll: %w", err)
		}
	}
	return nil
})

// ipOptionInformation mirrors IP_OPTION_INFORMATION (ipexport.h). On amd64: four UCHARs at
// offsets 0-3, four bytes of padding, then the OptionsData pointer at offset 8; size 16.
type ipOptionInformation struct {
	TTL         uint8
	TOS         uint8
	Flags       uint8
	OptionsSize uint8
	OptionsData uintptr // PUCHAR
}

// icmpEchoReply mirrors ICMP_ECHO_REPLY (ipexport.h). On amd64: Address 0, Status 4,
// RoundTripTime 8, DataSize 12, Reserved 14, Data 16 (8-byte pointer), Options 24 (16
// bytes); size 40. Data is declared uintptr: the kernel stores a pointer into the reply
// buffer there, which Go never dereferences and the garbage collector must not trace.
type icmpEchoReply struct {
	Address       uint32 // IPAddr: the address bytes in network order, as stored in memory
	Status        uint32 // IP_STATUS
	RoundTripTime uint32 // milliseconds (coarse; RTT is measured around the call instead)
	DataSize      uint16
	Reserved      uint16
	Data          uintptr // PVOID
	Options       ipOptionInformation
}

// icmpEchoReplySize is sizeof(ICMP_ECHO_REPLY) for the target pointer size: 16 bytes of
// fixed fields, the Data pointer, and IP_OPTION_INFORMATION (4 bytes + padding + pointer).
// It is 40 on amd64 (and 28 on 386).
const icmpEchoReplySize = 16 + 3*unsafe.Sizeof(uintptr(0))

// Compile-time layout check: both array lengths must be non-negative constants, so the
// build fails unless the Go struct has exactly the C size.
var (
	_ [icmpEchoReplySize - unsafe.Sizeof(icmpEchoReply{})]byte
	_ [unsafe.Sizeof(icmpEchoReply{}) - icmpEchoReplySize]byte
)

// icmpPayload is the 32-byte request data, the same pattern Windows ping.exe sends.
var icmpPayload = [32]byte{
	'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p',
	'q', 'r', 's', 't', 'u', 'v', 'w', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i',
}

// icmpReplyExtra is head-room beyond the documented minimum reply buffer
// (sizeof(ICMP_ECHO_REPLY) + request data + 8 bytes for an ICMP error message), for IP
// options and ICMP error payloads quoting the original datagram.
const icmpReplyExtra = 256

// icmpReplyBufSize is the ReplySize passed to IcmpSendEcho.
const icmpReplyBufSize = int(icmpEchoReplySize) + len(icmpPayload) + 8 + icmpReplyExtra

// icmpReplyWords is the reply buffer length in uint64 words: a []uint64 guarantees the
// 8-byte alignment ICMP_ECHO_REPLY needs.
const icmpReplyWords = (icmpReplyBufSize + 7) / 8

// ipv4ToIPAddr converts an address to the IPAddr value IcmpSendEcho expects: the four
// octets in network order in memory, i.e. a little-endian load of the octets on amd64.
func ipv4ToIPAddr(a netip.Addr) uint32 {
	b := a.As4()
	return binary.LittleEndian.Uint32(b[:])
}

// ipAddrToIPv4 is the inverse of ipv4ToIPAddr.
func ipAddrToIPv4(v uint32) netip.Addr {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], v)
	return netip.AddrFrom4(b)
}

// sendEcho performs one blocking IcmpSendEcho call (bounded by timeout) on its own ICMP
// handle. ttl 0 uses the system default TTL (no IP_OPTION_INFORMATION is passed).
func sendEcho(dst netip.Addr, ttl uint8, timeout time.Duration) echoResult {
	if err := icmpProcsErr(); err != nil {
		return echoResult{err: err}
	}
	if !dst.Is4() {
		return echoResult{err: errors.New("IcmpSendEcho: not an IPv4 address: " + dst.String())}
	}
	// Heap-allocated: the kernel writes into it during the call.
	reply := make([]uint64, icmpReplyWords)
	n, elapsed, callErr, err := icmpEcho(dst, ttl, timeout, reply)
	if err != nil {
		return echoResult{err: err}
	}
	return decodeEcho(n, elapsed, callErr, reply)
}

// icmpEcho opens an ICMP handle, sends one echo request to dst and waits up to timeout for
// the reply, which the system writes into reply. elapsed is measured around the
// IcmpSendEcho call on the high-resolution clock; callErr is its GetLastError value; err
// reports a failure to create the handle.
func icmpEcho(dst netip.Addr, ttl uint8, timeout time.Duration, reply []uint64) (n uint32, elapsed time.Duration, callErr, err error) {
	h, _, e := procIcmpCreateFile.Call()
	if windows.Handle(h) == windows.InvalidHandle {
		return 0, 0, nil, fmt.Errorf("IcmpCreateFile: %w", e)
	}
	defer procIcmpCloseHandle.Call(h)

	req := icmpPayload // per-call copy: the buffer passed to the kernel is ours alone
	var opts *ipOptionInformation
	if ttl > 0 {
		opts = &ipOptionInformation{TTL: ttl}
	}
	ms := timeout.Milliseconds()
	if ms < 1 {
		ms = 1
	}
	if ms > math.MaxUint32 {
		ms = math.MaxUint32
	}

	sw := startStopwatch()
	r, _, callErr := procIcmpSendEcho.Call(
		h,
		uintptr(ipv4ToIPAddr(dst)),
		uintptr(unsafe.Pointer(&req[0])),
		uintptr(len(req)),
		uintptr(unsafe.Pointer(opts)), // nil → NULL
		uintptr(unsafe.Pointer(&reply[0])),
		uintptr(len(reply)*8),
		uintptr(ms),
	)
	return uint32(r), sw.elapsed(), callErr, nil
}

// decodeEcho interprets the outcome of an IcmpSendEcho call: n reply structures in reply,
// or (n == 0) the status in callErr.
func decodeEcho(n uint32, elapsed time.Duration, callErr error, reply []uint64) echoResult {
	r := echoResult{elapsed: elapsed, replies: n}
	if n == 0 {
		// No reply structure: GetLastError holds an IP_STATUS (typically IP_REQ_TIMED_OUT
		// or IP_GENERAL_FAILURE) or a Win32 error. The buffer is not consulted, so that a
		// timed-out request is never reported with a ReplyFrom address.
		var code uint32
		var errno syscall.Errno
		if errors.As(callErr, &errno) {
			code = uint32(errno)
		}
		switch {
		case isIPStatus(code):
			r.code = code
		case code == 0:
			r.err = errors.New("IcmpSendEcho returned no reply and no error code")
		default:
			r.err = fmt.Errorf("IcmpSendEcho: %w", callErr)
		}
		return r
	}
	if uintptr(len(reply))*8 < icmpEchoReplySize {
		r.err = fmt.Errorf("IcmpSendEcho: reply buffer of %d bytes cannot hold a reply", len(reply)*8)
		return r
	}
	rep := (*icmpEchoReply)(unsafe.Pointer(&reply[0]))
	r.code = rep.Status
	r.from = ipAddrToIPv4(rep.Address)
	r.ttl = rep.Options.TTL
	return r
}
