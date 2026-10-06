package syslogrx

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"attmonitor/internal/model"
)

func TestNewDefaults(t *testing.T) {
	r, err := New(Options{})
	if err != nil {
		t.Fatal(err)
	}
	if r.o.Listen != ":514" || r.o.MaxPerMinute != 2000 || r.o.MaxMessage != 8192 || r.o.MaxPending != 8000 {
		t.Errorf("defaults: %+v", r.o)
	}
	if r.o.Now == nil || r.log == nil {
		t.Error("no clock or logger")
	}
	if addr, err := r.Listening(); addr != "" || err != nil {
		t.Errorf("Listening before Run = %q, %v", addr, err)
	}
	if msgs, dropped, rejected := r.Drain(); msgs != nil || dropped != 0 || rejected != 0 {
		t.Errorf("Drain of a new receiver = %v, %d, %d", msgs, dropped, rejected)
	}

	r, err = New(Options{MaxPerMinute: 10})
	if err != nil || r.o.MaxPending != 40 {
		t.Errorf("MaxPending for 10 a minute = %d (%v)", r.o.MaxPending, err)
	}
	r, err = New(Options{MaxPerMinute: math.MaxInt})
	if err != nil || r.o.MaxPending <= 0 {
		t.Errorf("MaxPending for MaxInt a minute = %d (%v)", r.o.MaxPending, err)
	}
	r, err = New(Options{MaxPerMinute: 10, MaxPending: 3, MaxMessage: maxDatagram})
	if err != nil || r.o.MaxPending != 3 || r.o.MaxMessage != maxDatagram {
		t.Errorf("explicit limits: %+v (%v)", r.o, err)
	}
}

func TestNewDoesNotBind(t *testing.T) {
	// New succeeds for an address that is in use: only Run binds.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	if _, err := New(Options{Listen: pc.LocalAddr().String()}); err != nil {
		t.Fatal(err)
	}
}

func TestNewValidates(t *testing.T) {
	for _, l := range []string{":514", "127.0.0.1:0", "0.0.0.0:514", "[::]:514", "[::1]:5514", "[fe80::1%eth0]:514", ":0", ":65535"} {
		if _, err := New(Options{Listen: l}); err != nil {
			t.Errorf("Listen %q: %v", l, err)
		}
	}
	bad := []Options{
		{Listen: "514"},
		{Listen: "localhost:514"},
		{Listen: "gateway:514"},
		{Listen: ":syslog"},
		{Listen: ":65536"},
		{Listen: ":-1"},
		{Listen: ":"},
		{Listen: "[::1]"},
		{Listen: "1.2.3.4:5:6"},
		{MaxPerMinute: -1},
		{MaxMessage: -1},
		{MaxMessage: maxDatagram + 1},
		{MaxPending: -1},
	}
	for _, o := range bad {
		if r, err := New(o); err == nil || r != nil {
			t.Errorf("New(%+v) = %v, %v; want an error", o, r, err)
		} else if !strings.HasPrefix(err.Error(), "syslogrx: ") {
			t.Errorf("error without the package prefix: %v", err)
		}
	}
}

func TestAcceptSenders(t *testing.T) {
	r, clk, logs := newReceiver(t, Options{Allowed: []netip.Addr{netip.MustParseAddr("192.168.1.254")}})
	r.accept([]byte("<30>Oct  5 21:30:01 kernel: first"), ap("192.168.1.254:514"))
	// A dual-stack socket reports an IPv4 sender as an IPv4-mapped IPv6 address.
	r.accept([]byte("<30>Oct  5 21:30:01 kernel: second"), ap("[::ffff:192.168.1.254]:40000"))
	r.accept([]byte("secret from another device"), ap("192.168.1.10:514"))
	r.accept([]byte("secret over IPv6"), ap("[::1]:514"))
	r.accept([]byte("no sender"), netip.AddrPort{})

	msgs, dropped, rejected := r.Drain()
	if len(msgs) != 2 || dropped != 0 || rejected != 3 {
		t.Fatalf("Drain = %d messages, %d dropped, %d rejected", len(msgs), dropped, rejected)
	}
	want := []struct{ src, msg string }{{"192.168.1.254:514", "first"}, {"192.168.1.254:40000", "second"}}
	for i, m := range msgs {
		if m.Src != want[i].src || m.Msg != want[i].msg || m.App != "kernel" || m.Format != FormatRFC3164 {
			t.Errorf("message %d: %+v", i, m)
		}
		if m.RX != "2026-10-05T03:20:00.123456789Z" {
			t.Errorf("RX = %q", m.RX)
		}
	}
	for _, m := range msgs {
		if strings.Contains(m.Raw+m.Msg, "secret") {
			t.Errorf("content of a rejected datagram was kept: %+v", m)
		}
	}
	for _, line := range logs.all() {
		if strings.Contains(line, "secret") {
			t.Errorf("content of a rejected datagram was logged: %s", line)
		}
	}
	// Rejections are logged once a minute, with the number held back.
	if n := logs.count(logRejected); n != 1 {
		t.Fatalf("%d rejection log entries, want 1: %q", n, logs.all())
	}
	if from := logs.attr(logRejected, "from"); from != "192.168.1.10:514" {
		t.Errorf("logged sender %q", from)
	}
	clk.Advance(time.Minute)
	r.accept([]byte("x"), ap("[::ffff:192.168.1.11]:514"))
	if n, held := logs.count(logRejected), logs.attr(logRejected, "suppressed"); n != 2 || held != "2" {
		t.Errorf("after a minute: %d entries, suppressed %s; want 2 and 2", n, held)
	}
	if from := logs.attr(logRejected, "from"); from != "192.168.1.11:514" {
		t.Errorf("logged sender %q, want it without the IPv4-in-IPv6 mapping", from)
	}
}

func TestAllowListComparesUnmappedWithoutZone(t *testing.T) {
	r, _, _ := newReceiver(t, Options{})
	kept := func(from string) bool {
		r.accept([]byte("<13>x"), ap(from))
		msgs, _, _ := r.Drain()
		return len(msgs) == 1
	}
	if kept("192.168.1.254:514") {
		t.Error("accepted with no allowed sender")
	}
	r.SetAllowed([]netip.Addr{netip.MustParseAddr("::ffff:192.168.1.254")})
	if !kept("192.168.1.254:514") || !kept("[::ffff:192.168.1.254]:514") {
		t.Error("an allowed IPv4-mapped address does not match its IPv4 sender")
	}
	r.SetAllowed([]netip.Addr{netip.MustParseAddr("fe80::1%eth1")})
	if !kept("[fe80::1%eth0]:514") || !kept("[fe80::1]:514") {
		t.Error("zones are compared")
	}
	if kept("[fe80::2]:514") {
		t.Error("another address accepted")
	}
	allowed := []netip.Addr{netip.MustParseAddr("10.0.0.1"), {}}
	r.SetAllowed(allowed)
	allowed[0] = netip.MustParseAddr("10.0.0.2")
	if !kept("10.0.0.1:514") || kept("10.0.0.2:514") {
		t.Error("SetAllowed keeps the caller's slice")
	}
	r.SetAllowed(nil)
	if kept("10.0.0.1:514") {
		t.Error("accepted after SetAllowed(nil)")
	}
}

func TestSrcKeepsZoneAndPort(t *testing.T) {
	r, _, _ := newReceiver(t, Options{Allowed: []netip.Addr{netip.MustParseAddr("fe80::1"), netip.MustParseAddr("2001:db8::7")}})
	r.accept([]byte("a"), ap("[fe80::1%eth0]:1514"))
	r.accept([]byte("b"), ap("[2001:db8::7]:514"))
	msgs, _, _ := r.Drain()
	if len(msgs) != 2 || msgs[0].Src != "[fe80::1%eth0]:1514" || msgs[1].Src != "[2001:db8::7]:514" {
		t.Errorf("Src: %+v", msgs)
	}
}

func TestTooLargeIsDropped(t *testing.T) {
	r, _, logs := newReceiver(t, Options{MaxMessage: 16, Allowed: []netip.Addr{netip.MustParseAddr("192.168.1.254")}})
	r.accept([]byte(strings.Repeat("a", 16)), ap("192.168.1.254:514"))
	r.accept([]byte(strings.Repeat("b", 17)), ap("192.168.1.254:514"))
	r.accept([]byte(strings.Repeat("c", 17)), ap("192.168.1.9:514")) // the sender is checked first
	msgs, dropped, rejected := r.Drain()
	if len(msgs) != 1 || msgs[0].Raw != strings.Repeat("a", 16) || dropped != 1 || rejected != 1 {
		t.Errorf("Drain = %+v, %d dropped, %d rejected", msgs, dropped, rejected)
	}
	if logs.count(logTooLarge) != 1 || logs.attr(logTooLarge, "bytes") != "17" || logs.attr(logTooLarge, "limit") != "16" {
		t.Errorf("log: %q", logs.all())
	}
}

func TestPerMinuteCap(t *testing.T) {
	r, clk, logs := newReceiver(t, Options{MaxPerMinute: 3, Allowed: []netip.Addr{netip.MustParseAddr("192.168.1.254")}})
	from := ap("192.168.1.254:514")
	feed := func(n int, label string) {
		for i := range n {
			r.accept(fmt.Appendf(nil, "%s %d", label, i), from)
		}
	}
	feed(5, "a") // 03:20:00.123: 3 kept, 2 over the cap
	clk.Set(time.Date(2026, 10, 5, 3, 20, 59, 999999999, time.UTC))
	feed(1, "b") // the same minute: over the cap
	clk.Set(time.Date(2026, 10, 5, 3, 21, 0, 0, time.UTC))
	feed(4, "c") // the next minute: 3 kept, 1 over the cap

	msgs, dropped, rejected := r.Drain()
	var got []string
	for _, m := range msgs {
		got = append(got, m.Raw+" @ "+m.RX)
	}
	want := []string{
		"a 0 @ 2026-10-05T03:20:00.123456789Z", "a 1 @ 2026-10-05T03:20:00.123456789Z", "a 2 @ 2026-10-05T03:20:00.123456789Z",
		"c 0 @ 2026-10-05T03:21:00Z", "c 1 @ 2026-10-05T03:21:00Z", "c 2 @ 2026-10-05T03:21:00Z",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") || dropped != 4 || rejected != 0 {
		t.Errorf("Drain = %d dropped, %d rejected, messages:\n%s", dropped, rejected, strings.Join(got, "\n"))
	}
	// One entry a minute: "a 4", "b 0" and the cap reached again at 03:21:00 ("c 3") are held
	// back, and counted in the next entry.
	if logs.count(logOverCap) != 1 || logs.attr(logOverCap, "limit") != "3" {
		t.Errorf("log: %q", logs.all())
	}
	clk.Set(time.Date(2026, 10, 5, 3, 21, 0, 123456789, time.UTC))
	feed(1, "d")
	if logs.count(logOverCap) != 2 || logs.attr(logOverCap, "suppressed") != "3" {
		t.Errorf("log: %q", logs.all())
	}
}

func TestPendingFull(t *testing.T) {
	r, _, logs := newReceiver(t, Options{MaxPerMinute: 3, MaxPending: 2, Allowed: []netip.Addr{netip.MustParseAddr("192.168.1.254")}})
	from := ap("192.168.1.254:514")
	for _, s := range []string{"1", "2", "3"} {
		r.accept([]byte(s), from)
	}
	msgs, dropped, _ := r.Drain()
	if len(msgs) != 2 || msgs[0].Raw != "1" || msgs[1].Raw != "2" || dropped != 1 {
		t.Fatalf("full buffer: %+v, %d dropped", msgs, dropped)
	}
	if logs.count(logFull) != 1 {
		t.Errorf("log: %q", logs.all())
	}
	// A datagram dropped because the buffer was full does not count against the minute's cap:
	// one more fits in this minute, then the cap applies.
	r.accept([]byte("4"), from)
	r.accept([]byte("5"), from)
	msgs, dropped, _ = r.Drain()
	if len(msgs) != 1 || msgs[0].Raw != "4" || dropped != 1 || logs.count(logOverCap) != 1 {
		t.Errorf("after Drain: %+v, %d dropped; log %q", msgs, dropped, logs.all())
	}
}

func TestDrainOrderAndReset(t *testing.T) {
	r, clk, _ := newReceiver(t, Options{Allowed: []netip.Addr{netip.MustParseAddr("192.168.1.254")}})
	for i := range 5 {
		r.accept(fmt.Appendf(nil, "<14>Oct  5 21:30:0%d bgw320 event %d", i, i), ap("192.168.1.254:514"))
		r.accept([]byte("noise"), ap("192.168.1.66:514"))
		clk.Advance(time.Millisecond)
	}
	msgs, dropped, rejected := r.Drain()
	if len(msgs) != 5 || dropped != 0 || rejected != 5 {
		t.Fatalf("Drain = %d messages, %d dropped, %d rejected", len(msgs), dropped, rejected)
	}
	prev := ""
	for i, m := range msgs {
		if m.Msg != fmt.Sprintf("event %d", i) || m.RX <= prev {
			t.Errorf("message %d: %q at %s after %s", i, m.Msg, m.RX, prev)
		}
		prev = m.RX
	}
	if msgs, dropped, rejected := r.Drain(); msgs != nil || dropped != 0 || rejected != 0 {
		t.Errorf("second Drain = %v, %d, %d", msgs, dropped, rejected)
	}
	// What Drain handed over is the caller's: new messages do not show up in it.
	r.accept([]byte("later"), ap("192.168.1.254:514"))
	if len(msgs) != 5 || msgs[4].Msg != "event 4" {
		t.Errorf("the drained slice changed: %+v", msgs[4])
	}
}

func TestParsePanicKeepsRawBytes(t *testing.T) {
	saved := parseDatagram
	t.Cleanup(func() { parseDatagram = saved })
	parseDatagram = func([]byte) model.SyslogMessage { panic("parser bug") }

	r, _, logs := newReceiver(t, Options{Allowed: []netip.Addr{netip.MustParseAddr("192.168.1.254")}})
	r.accept([]byte("<13>Oct 11 22:14:15 host app: x"), ap("192.168.1.254:514"))
	r.accept([]byte("\xff"), ap("192.168.1.254:514"))
	msgs, _, _ := r.Drain()
	if len(msgs) != 2 {
		t.Fatalf("%d messages kept", len(msgs))
	}
	m := msgs[0]
	if m.Raw != "<13>Oct 11 22:14:15 host app: x" || m.Format != FormatUnknown || m.PRI != nil || m.Msg != "" ||
		m.RX == "" || m.Src != "192.168.1.254:514" {
		t.Errorf("message after a parser panic: %+v", m)
	}
	if msgs[1].RawB64 != "/w==" {
		t.Errorf("invalid UTF-8 after a parser panic: %+v", msgs[1])
	}
	if logs.count(logPanicked) != 1 || !strings.Contains(logs.attr(logPanicked, "panic"), "parser bug") {
		t.Errorf("log: %q", logs.all())
	}
}

func TestGate(t *testing.T) {
	var g gate
	t0 := time.Date(2026, 10, 5, 3, 20, 0, 0, time.UTC)
	check := func(at time.Time, wantOK bool, wantHeld int) {
		t.Helper()
		if ok, held := g.allow(at); ok != wantOK || held != wantHeld {
			t.Errorf("allow(%s) = %v, %d; want %v, %d", at.Format(time.TimeOnly), ok, held, wantOK, wantHeld)
		}
	}
	check(t0, true, 0)
	check(t0.Add(time.Second), false, 0)
	check(t0.Add(59*time.Second), false, 0)
	check(t0.Add(time.Minute), true, 2)
	check(t0.Add(time.Minute+time.Second), false, 0)
	check(t0, true, 1) // a clock set back opens the gate
}

// ---------------------------------------------------------------- Run with a scripted socket

func TestRunSkipsReadErrors(t *testing.T) {
	savedMin, savedMax := errPauseMin, errPauseMax
	t.Cleanup(func() { errPauseMin, errPauseMax = savedMin, savedMax })
	errPauseMin, errPauseMax = 50*time.Millisecond, 50*time.Millisecond

	boom := readErr(errors.New("boom"))
	conn := newFakeConn(
		readStep{err: boom}, readStep{err: boom}, readStep{err: boom},
		readStep{b: []byte("<14>Oct  5 21:30:01 bgw320 kernel: after the errors"), from: gatewayAddr},
	)
	r, _, logs := newReceiver(t, Options{Allowed: []netip.Addr{netip.MustParseAddr("192.168.1.254")}})
	useConn(r, conn)
	start := time.Now()
	addr, _ := run(t, r)
	if addr != "127.0.0.1:5514" {
		t.Errorf("Listening = %q", addr)
	}
	var d drained
	waitDrained(t, r, &d, "the datagram after the errors", func(d *drained) bool { return len(d.msgs) == 1 })
	// No pause after the first failure, then 50 ms before each further attempt.
	if el := time.Since(start); el < 100*time.Millisecond {
		t.Errorf("three failures in a row took %v; want pauses of at least 100 ms in all", el)
	}
	if m := d.msgs[0]; m.Msg != "after the errors" || m.Src != "192.168.1.254:514" {
		t.Errorf("message: %+v", m)
	}
	if logs.count(logFailing) != 1 || !strings.Contains(logs.attr(logFailing, "err"), "boom") {
		t.Errorf("log: %q", logs.all())
	}
}

func TestRunStopsWhileFailing(t *testing.T) {
	savedMin, savedMax := errPauseMin, errPauseMax
	t.Cleanup(func() { errPauseMin, errPauseMax = savedMin, savedMax })
	errPauseMin, errPauseMax = 10*time.Millisecond, time.Second

	conn := newFakeConn()
	conn.forever = readErr(errors.New("socket broken"))
	r, _, _ := newReceiver(t, Options{})
	useConn(r, conn)
	_, stop := run(t, r)
	time.Sleep(300 * time.Millisecond)
	start := time.Now()
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	if el := time.Since(start); el > 500*time.Millisecond {
		t.Errorf("Run took %v to stop during a pause", el)
	}
	// Pauses of 10, 20, 40, 80, 160 ms: a handful of attempts, not a busy loop.
	if n := conn.reads.Load(); n > 20 {
		t.Errorf("%d receive attempts in 300 ms", n)
	}
}

func TestRunReportsSocketClosedUnderneath(t *testing.T) {
	conn := newFakeConn(readStep{err: &net.OpError{Op: "read", Net: "udp", Err: net.ErrClosed}})
	r, _, _ := newReceiver(t, Options{})
	useConn(r, conn)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := r.Run(ctx)
	if err == nil || !errors.Is(err, net.ErrClosed) || ctx.Err() != nil {
		t.Fatalf("Run = %v", err)
	}
	if addr, lerr := r.Listening(); addr != "" || lerr != err {
		t.Errorf("Listening = %q, %v; want \"\", %v", addr, lerr, err)
	}
}

// otherAddr is a net.Addr of a type the net package does not use for UDP.
type otherAddr string

func (a otherAddr) Network() string { return "udp" }
func (a otherAddr) String() string  { return string(a) }

func TestRunReadsSendersOfAnyAddrType(t *testing.T) {
	conn := newFakeConn(
		readStep{b: []byte("a"), from: otherAddr("192.168.1.254:514")},
		readStep{b: []byte("b"), from: nil},
		readStep{b: []byte("c"), from: otherAddr("not an address")},
		readStep{b: []byte("d"), from: (*net.UDPAddr)(nil)},
		readStep{b: []byte("e"), from: &net.UDPAddr{IP: net.ParseIP("192.168.1.254").To4(), Port: 1514}},
	)
	r, _, _ := newReceiver(t, Options{Allowed: []netip.Addr{netip.MustParseAddr("192.168.1.254")}})
	useConn(r, conn)
	run(t, r)
	var d drained
	waitDrained(t, r, &d, "five datagrams", func(d *drained) bool { return len(d.msgs)+d.rejected == 5 })
	if len(d.msgs) != 2 || d.msgs[0].Src != "192.168.1.254:514" || d.msgs[1].Src != "192.168.1.254:1514" || d.rejected != 3 {
		t.Errorf("%+v, %d rejected", d.msgs, d.rejected)
	}
}

func TestRunWithContextDone(t *testing.T) {
	r, _, _ := newReceiver(t, Options{})
	called := false
	r.listen = func(string, string) (net.PacketConn, error) { called = true; return nil, errors.New("unexpected") }
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := r.Run(ctx); err != nil || called {
		t.Errorf("Run with a done context = %v (listen called: %v)", err, called)
	}
}

func TestRunOnceAtATime(t *testing.T) {
	r, _, _ := newReceiver(t, Options{})
	useConn(r, newFakeConn())
	run(t, r)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := r.Run(ctx); err == nil || ctx.Err() != nil {
		t.Errorf("a second Run = %v", err)
	}
	if addr, err := r.Listening(); addr == "" || err != nil {
		t.Errorf("the first Run stopped listening: %q, %v", addr, err)
	}
}
