//go:build !windows

package monitor

import (
	"errors"
	"net/netip"
)

// systemRoute is implemented for Windows only (the product targets windows/amd64).
func systemRoute(netip.Addr) (routeInfo, error) {
	return routeInfo{}, errors.New("route lookup is not supported on this platform")
}
