//go:build windows

package syslogrx

import (
	"errors"
	"net"
	"net/netip"
	"testing"

	"golang.org/x/sys/windows"
)

func TestIsTransient(t *testing.T) {
	for _, e := range []error{
		windows.WSAECONNRESET, windows.ERROR_PORT_UNREACHABLE, windows.WSAENETRESET,
		windows.WSAEHOSTUNREACH, windows.ERROR_HOST_UNREACHABLE,
		windows.WSAENETUNREACH, windows.ERROR_NETWORK_UNREACHABLE,
		windows.WSAEMSGSIZE, windows.ERROR_MORE_DATA,
	} {
		if !isTransient(readErr(e)) {
			t.Errorf("%v (%d) is not transient", e, e)
		}
	}
	for _, err := range []error{
		readErr(windows.WSAENOBUFS), readErr(windows.WSAENETDOWN), readErr(windows.WSAENOTSOCK),
		&net.OpError{Op: "read", Net: "udp", Err: net.ErrClosed}, errors.New("boom"),
	} {
		if isTransient(err) {
			t.Errorf("%v is transient", err)
		}
	}
}

// TestRunSkipsConnReset: Windows reports an ICMP port unreachable for an earlier datagram as
// WSAECONNRESET on the next receive. It is skipped at once (no pause) and logged once a minute.
func TestRunSkipsConnReset(t *testing.T) {
	steps := make([]readStep, 0, 52)
	for range 50 {
		steps = append(steps, readStep{err: readErr(windows.WSAECONNRESET)})
	}
	steps = append(steps,
		readStep{err: readErr(windows.ERROR_PORT_UNREACHABLE)},
		readStep{b: []byte("<13>Oct 11 22:14:15 bgw320 kernel: still listening"), from: gatewayAddr})
	conn := newFakeConn(steps...)
	r, _, logs := newReceiver(t, Options{Allowed: []netip.Addr{netip.MustParseAddr("192.168.1.254")}})
	useConn(r, conn)
	run(t, r)
	var d drained
	waitDrained(t, r, &d, "the datagram after the errors", func(d *drained) bool { return len(d.msgs) == 1 })
	if d.msgs[0].Msg != "still listening" || d.msgs[0].Src != "192.168.1.254:514" {
		t.Errorf("%+v", d.msgs[0])
	}
	if logs.count(logTransient) != 1 || logs.count(logFailing) != 0 {
		t.Errorf("log: %q", logs.all())
	}
}
