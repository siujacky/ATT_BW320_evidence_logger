package syslogrx

import (
	"context"
	"encoding/base64"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// These tests send real datagrams over the loopback interface to a receiver bound to a free
// loopback port (never a fixed port, never every interface).

func TestLoopbackReceive(t *testing.T) {
	r, _, _ := newReceiver(t, Options{Allowed: []netip.Addr{netip.MustParseAddr("127.0.0.1")}})
	addr, _ := run(t, r)
	if !strings.HasPrefix(addr, "127.0.0.1:") || strings.HasSuffix(addr, ":0") {
		t.Fatalf("Listening = %q", addr)
	}
	c := sender(t, "udp4", addr)
	src := c.LocalAddr().String()

	var d drained
	// The oversize datagram first, on its own: it must be counted, not kept.
	send(t, c, []byte("<13>Oct 11 22:14:15 host app: "+strings.Repeat("x", 9000)))
	waitDrained(t, r, &d, "the oversize datagram", func(d *drained) bool { return d.dropped == 1 })

	sent := []string{
		"<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8\n",
		"<165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 [exampleSDID@32473 iut=\"3\"] " + bom + "An event",
		"<13>Oct 11 22:14:15 host app: caf\xe9", // not UTF-8: kept as base64
		"",                                      // an empty datagram is a message too
	}
	for _, text := range sent {
		send(t, c, []byte(text))
	}
	waitDrained(t, r, &d, "four messages", func(d *drained) bool { return len(d.msgs) == 4 })
	if d.dropped != 1 || d.rejected != 0 {
		t.Errorf("%d dropped, %d rejected", d.dropped, d.rejected)
	}
	missing := map[string]bool{}
	for _, text := range sent {
		missing[text] = true
	}
	for _, m := range d.msgs {
		raw := m.Raw
		if m.RawB64 != "" {
			b, err := base64.StdEncoding.DecodeString(m.RawB64)
			if err != nil {
				t.Fatal(err)
			}
			raw = string(b)
		}
		if !missing[raw] {
			t.Errorf("unexpected message %+v", m)
			continue
		}
		delete(missing, raw)
		checkRaw(t, []byte(raw), m)
		if m.Src != src || m.RX != "2026-10-05T03:20:00.123456789Z" {
			t.Errorf("Src %q (want %q), RX %q", m.Src, src, m.RX)
		}
		if want := Parse([]byte(raw)); m.Format != want.Format || m.Msg != want.Msg || m.App != want.App {
			t.Errorf("parsed %+v, want %+v", m, want)
		}
	}
	for text := range missing {
		t.Errorf("not received: %q", text)
	}
}

func TestLoopbackRejectedThenAllowedWhileRunning(t *testing.T) {
	// Only ::1 is allowed, so the IPv4 loopback sender is rejected until SetAllowed.
	r, _, logs := newReceiver(t, Options{Allowed: []netip.Addr{netip.IPv6Loopback()}})
	addr, _ := run(t, r)
	c := sender(t, "udp4", addr)

	var d drained
	send(t, c, []byte("<13>Oct 11 22:14:15 host app: confidential before SetAllowed"))
	waitDrained(t, r, &d, "the rejection", func(d *drained) bool { return d.rejected == 1 })
	waitFor(t, "the rejection's log entry", func() bool { return logs.count(logRejected) == 1 })
	if from := logs.attr(logRejected, "from"); from != c.LocalAddr().String() {
		t.Errorf("logged sender %q, want %q", from, c.LocalAddr().String())
	}

	r.SetAllowed([]netip.Addr{netip.MustParseAddr("127.0.0.1")})
	send(t, c, []byte("<13>Oct 11 22:14:15 host app: after SetAllowed"))
	waitDrained(t, r, &d, "the message", func(d *drained) bool { return len(d.msgs) == 1 })
	if d.msgs[0].Msg != "after SetAllowed" || d.rejected != 1 || d.dropped != 0 {
		t.Errorf("%+v, %d rejected, %d dropped", d.msgs, d.rejected, d.dropped)
	}
	for _, line := range logs.all() {
		if strings.Contains(line, "confidential") {
			t.Errorf("rejected content was logged: %s", line)
		}
	}
}

func TestLoopbackIPv6(t *testing.T) {
	r, _, _ := newReceiver(t, Options{Listen: "[::1]:0", Allowed: []netip.Addr{netip.IPv6Loopback()}})
	if pc, err := net.ListenPacket("udp6", "[::1]:0"); err != nil {
		t.Skipf("no IPv6 loopback: %v", err)
	} else {
		pc.Close()
	}
	addr, _ := run(t, r)
	c := sender(t, "udp6", addr)
	send(t, c, []byte("<14>2026-10-05T21:30:01Z bgw320 pon[1]: link up"))
	var d drained
	waitDrained(t, r, &d, "the message", func(d *drained) bool { return len(d.msgs) == 1 })
	if m := d.msgs[0]; m.Src != c.LocalAddr().String() || !strings.HasPrefix(m.Src, "[::1]:") || m.App != "pon" {
		t.Errorf("%+v", m)
	}
}

func TestRunReturnsNilOnCancel(t *testing.T) {
	r, _, _ := newReceiver(t, Options{Allowed: []netip.Addr{netip.MustParseAddr("127.0.0.1")}})
	addr, stop := run(t, r)
	c := sender(t, "udp4", addr)
	send(t, c, []byte("<13>kept after the stop"))
	var d drained
	waitDrained(t, r, &d, "the message", func(d *drained) bool { return len(d.msgs) == 1 })
	send(t, c, []byte("<13>also kept after the stop"))
	waitFor(t, "the second datagram", func() bool {
		r.mu.Lock()
		defer r.mu.Unlock()
		return len(r.pending) == 1
	})

	if err := stop(); err != nil {
		t.Fatalf("Run = %v, want nil", err)
	}
	if a, err := r.Listening(); a != "" || err != nil {
		t.Errorf("Listening after the stop = %q, %v", a, err)
	}
	// The socket is closed (the address can be bound again) and the undrained message is kept.
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		t.Fatalf("the receiver's address is still in use: %v", err)
	}
	pc.Close()
	if msgs, _, _ := r.Drain(); len(msgs) != 1 || msgs[0].Msg != "also kept after the stop" {
		t.Errorf("Drain after the stop = %+v", msgs)
	}

	// Run can start again.
	addr2, stop2 := run(t, r)
	if addr2 == "" {
		t.Fatal("no address")
	}
	if err := stop2(); err != nil {
		t.Fatal(err)
	}
}

func TestListeningReportsPortInUse(t *testing.T) {
	blocker, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Close()
	r, _, logs := newReceiver(t, Options{Listen: blocker.LocalAddr().String()})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err = r.Run(ctx)
	if err == nil || ctx.Err() != nil {
		t.Fatalf("Run on a port in use = %v (context: %v)", err, ctx.Err())
	}
	if !strings.Contains(err.Error(), blocker.LocalAddr().String()) {
		t.Errorf("the error does not name the address: %v", err)
	}
	addr, lerr := r.Listening()
	if addr != "" || lerr != err {
		t.Errorf("Listening = %q, %v; want \"\", %v", addr, lerr, err)
	}
	if logs.count("syslog receiver: cannot listen") != 1 {
		t.Errorf("log: %q", logs.all())
	}

	// Once the port is free, the next Run listens and the error is gone.
	blocker.Close()
	run(t, r)
	if addr, lerr := r.Listening(); addr == "" || lerr != nil {
		t.Errorf("Listening = %q, %v", addr, lerr)
	}
}

func TestLoopbackFloodIsCapped(t *testing.T) {
	r, _, _ := newReceiver(t, Options{MaxPerMinute: 10, Allowed: []netip.Addr{netip.MustParseAddr("127.0.0.1")}})
	addr, _ := run(t, r)
	c := sender(t, "udp4", addr)
	// Send in rounds and wait for each round, so that no datagram is lost in the socket buffer.
	var d drained
	for round := range 5 {
		for range 10 {
			send(t, c, []byte("<13>Oct 11 22:14:15 host app: flood"))
		}
		waitDrained(t, r, &d, "a round", func(d *drained) bool { return len(d.msgs)+d.dropped == 10*(round+1) })
	}
	// The test clock stands still: all 50 arrive in one minute.
	if len(d.msgs) != 10 || d.dropped != 40 {
		t.Errorf("%d kept, %d dropped; want 10 and 40", len(d.msgs), d.dropped)
	}
}

// waitFor polls cond until it holds (10 s at most).
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(2 * time.Millisecond)
	}
}
