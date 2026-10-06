//go:build windows

package syslogrx

import "golang.org/x/sys/windows"

// transientErrors are receive errors after which the socket keeps working. Winsock reports an
// ICMP error for an earlier datagram on a UDP socket as WSAECONNRESET (port unreachable) or
// WSAENETRESET (time exceeded), and a datagram larger than the buffer as WSAEMSGSIZE (the
// datagram is discarded); overlapped completions give the equivalent Win32 codes. Both families
// are recognised.
var transientErrors = []error{
	windows.WSAECONNRESET, windows.ERROR_PORT_UNREACHABLE,
	windows.WSAENETRESET,
	windows.WSAEHOSTUNREACH, windows.ERROR_HOST_UNREACHABLE,
	windows.WSAENETUNREACH, windows.ERROR_NETWORK_UNREACHABLE,
	windows.WSAEMSGSIZE, windows.ERROR_MORE_DATA,
}
