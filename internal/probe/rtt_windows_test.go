//go:build windows

package probe

import (
	"context"
	"testing"
	"time"
)

func TestPingRTTIsMeasured(t *testing.T) {
	p := New(Options{})
	checkMeasuredRTT(t, "loopback ping", 20, func() (int64, bool) {
		r := p.Ping(context.Background(), "127.0.0.1", 2*time.Second)
		return r.RTTus, r.OK
	})
}

func TestTracerouteHopRTTIsMeasured(t *testing.T) {
	p := New(Options{})
	checkMeasuredRTT(t, "loopback traceroute hop", 10, func() (int64, bool) {
		tr := p.Traceroute(context.Background(), "127.0.0.1", 3, time.Second)
		if !tr.Reached || len(tr.Hops) != 1 {
			return 0, false
		}
		return tr.Hops[0].RTTus, true
	})
}
