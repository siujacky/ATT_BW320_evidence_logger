//go:build !windows

package lanscan

import (
	"context"
	"fmt"
	"net"
	"net/netip"

	"attmonitor/internal/contracts"
)

// arpReady: the questions are asked through Windows' SendARP, which other systems do not have.
func arpReady() error {
	return fmt.Errorf("lanscan: %w: the home network is swept through Windows' SendARP", contracts.ErrUnavailable)
}

// systemARP is never asked on other systems (arpReady refuses first).
func systemARP(context.Context, netip.Addr, netip.Addr) (net.HardwareAddr, error) {
	return nil, contracts.ErrUnavailable
}
