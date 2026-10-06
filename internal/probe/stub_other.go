//go:build !windows

package probe

import (
	"context"
	"errors"
	"net/netip"
	"time"
)

// The product targets windows/amd64. These stubs keep the package (and its pure helpers
// and tests) building elsewhere.

var errUnsupported = errors.New("not supported on this platform (Windows only)")

func sendEcho(netip.Addr, uint8, time.Duration) echoResult { return echoResult{err: errUnsupported} }

func listAdapters() ([]adapterInfo, error) { return nil, errUnsupported }

func bestInterface(netip.Addr) (uint32, error) { return 0, errUnsupported }

func runNetshWLAN(context.Context) ([]byte, error) { return nil, errUnsupported }

func interfaceCounters(uint64, uint32) (uint64, uint64, error) { return 0, 0, errUnsupported }
