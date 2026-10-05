//go:build windows

package probe

import (
	"net"
	"os"

	"golang.org/x/sys/windows"
)

func refusedErr() error {
	return &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connectex", windows.WSAECONNREFUSED)}
}

func unreachableErr() error {
	return &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connectex", windows.WSAENETUNREACH)}
}
