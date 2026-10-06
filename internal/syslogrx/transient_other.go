//go:build !windows

package syslogrx

import "syscall"

// transientErrors are receive errors after which the socket keeps working: an ICMP error for an
// earlier datagram, or a datagram larger than the buffer.
var transientErrors = []error{syscall.ECONNREFUSED, syscall.EHOSTUNREACH, syscall.ENETUNREACH, syscall.EMSGSIZE}
