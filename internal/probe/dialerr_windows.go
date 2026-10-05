//go:build windows

package probe

import (
	"errors"

	"golang.org/x/sys/windows"
)

// Connect failures surface either as Winsock codes (WSAE*) or, from overlapped ConnectEx
// completions, as the equivalent Win32 codes; both families are recognised.

func isRefused(err error) bool {
	return errors.Is(err, windows.WSAECONNREFUSED) || errors.Is(err, windows.ERROR_CONNECTION_REFUSED)
}

func isUnreachable(err error) bool {
	return errors.Is(err, windows.WSAENETUNREACH) || errors.Is(err, windows.WSAEHOSTUNREACH) ||
		errors.Is(err, windows.ERROR_NETWORK_UNREACHABLE) || errors.Is(err, windows.ERROR_HOST_UNREACHABLE)
}

func isTimeoutErrno(err error) bool {
	return errors.Is(err, windows.WSAETIMEDOUT) || errors.Is(err, windows.ERROR_SEM_TIMEOUT)
}
