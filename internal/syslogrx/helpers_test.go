package syslogrx

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"attmonitor/internal/model"
)

// ---------------------------------------------------------------- clock

type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *testClock {
	return &testClock{t: time.Date(2026, 10, 5, 3, 20, 0, 123456789, time.UTC)}
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *testClock) Set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = t
}

func (c *testClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// ---------------------------------------------------------------- logs

// captureHandler records every log record.
type captureHandler struct {
	mu   sync.Mutex
	recs []slog.Record
}

func (h *captureHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h *captureHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	h.recs = append(h.recs, r)
	h.mu.Unlock()
	return nil
}
func (h *captureHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *captureHandler) WithGroup(string) slog.Handler      { return h }

// count returns how many records with this message were logged.
func (h *captureHandler) count(msg string) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	n := 0
	for _, r := range h.recs {
		if r.Message == msg {
			n++
		}
	}
	return n
}

// attr returns the value of key in the last record with this message ("" if absent).
func (h *captureHandler) attr(msg, key string) string {
	h.mu.Lock()
	defer h.mu.Unlock()
	v := ""
	for _, r := range h.recs {
		if r.Message != msg {
			continue
		}
		v = ""
		r.Attrs(func(a slog.Attr) bool {
			if a.Key == key {
				v = a.Value.String()
				return false
			}
			return true
		})
	}
	return v
}

// all returns every logged message with its attributes, for failure output.
func (h *captureHandler) all() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []string
	for _, r := range h.recs {
		s := r.Level.String() + " " + r.Message
		r.Attrs(func(a slog.Attr) bool {
			s += " " + a.String()
			return true
		})
		out = append(out, s)
	}
	return out
}

// Log messages the tests look for.
const (
	logRejected  = "syslog receiver: datagram from a sender that is not allowed; counted as rejected, not kept"
	logTooLarge  = "syslog receiver: datagram larger than the limit; counted as dropped, not kept"
	logOverCap   = "syslog receiver: more messages in this minute than the limit; counted as dropped, not kept"
	logFull      = "syslog receiver: too many messages wait to be recorded; counted as dropped, not kept"
	logTransient = "syslog receiver: skipped a receive error about a single datagram"
	logFailing   = "syslog receiver: receiving failed; trying again"
	logPanicked  = "syslog receiver: parsing a datagram failed; it is kept with its exact bytes only"
)

// ---------------------------------------------------------------- receivers

// newReceiver returns a Receiver on a free loopback port with the test clock and a log capture.
func newReceiver(t *testing.T, o Options) (*Receiver, *testClock, *captureHandler) {
	t.Helper()
	clk := newClock()
	logs := &captureHandler{}
	if o.Listen == "" {
		o.Listen = "127.0.0.1:0"
	}
	if o.Now == nil {
		o.Now = clk.Now
	}
	o.Logger = slog.New(logs)
	r, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	return r, clk, logs
}

// run runs r until the test ends or stop is called, and waits until it listens. stop cancels
// Run and returns its result.
func run(t *testing.T, r *Receiver) (addr string, stop func() error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx) }()
	deadline := time.Now().Add(10 * time.Second)
	for {
		if a, _ := r.Listening(); a != "" {
			addr = a
			break
		}
		select {
		case err := <-done:
			cancel()
			t.Fatalf("Run returned before listening: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			cancel()
			t.Fatal("the receiver did not listen within 10 s")
		}
		time.Sleep(time.Millisecond)
	}
	var once sync.Once
	var result error
	stop = func() error {
		once.Do(func() {
			cancel()
			select {
			case result = <-done:
			case <-time.After(10 * time.Second):
				result = errors.New("Run did not return within 10 s of the cancel")
			}
		})
		return result
	}
	t.Cleanup(func() {
		if err := stop(); err != nil {
			t.Errorf("Run: %v", err)
		}
	})
	return addr, stop
}

// drained accumulates what Drain hands over.
type drained struct {
	msgs              []model.SyslogMessage
	dropped, rejected int
}

func (d *drained) add(r *Receiver) {
	msgs, dropped, rejected := r.Drain()
	d.msgs = append(d.msgs, msgs...)
	d.dropped += dropped
	d.rejected += rejected
}

// waitDrained drains r until cond holds (10 s at most).
func waitDrained(t *testing.T, r *Receiver, d *drained, what string, cond func(*drained) bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		d.add(r)
		if cond(d) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s: %d messages, %d dropped, %d rejected", what, len(d.msgs), d.dropped, d.rejected)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// sender returns a UDP socket on network's loopback address that sends to addr.
func sender(t *testing.T, network, addr string) net.Conn {
	t.Helper()
	c, err := net.Dial(network, addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func send(t *testing.T, c net.Conn, b []byte) {
	t.Helper()
	if _, err := c.Write(b); err != nil {
		t.Fatal(err)
	}
}

// ap parses "ip:port" (test input).
func ap(s string) netip.AddrPort { return netip.MustParseAddrPort(s) }

// ---------------------------------------------------------------- fake socket

// fakeConn is a net.PacketConn whose reads follow a script of datagrams and errors; once the
// script is used up, a read returns forever (when set) or waits until Close.
type fakeConn struct {
	steps   chan readStep
	forever error
	closed  chan struct{}
	once    sync.Once
	reads   atomic.Int64
}

type readStep struct {
	b    []byte
	from net.Addr
	err  error
}

func newFakeConn(steps ...readStep) *fakeConn {
	c := &fakeConn{steps: make(chan readStep, len(steps)), closed: make(chan struct{})}
	for _, s := range steps {
		c.steps <- s
	}
	return c
}

func (c *fakeConn) ReadFrom(p []byte) (int, net.Addr, error) {
	c.reads.Add(1)
	select {
	case <-c.closed:
		return 0, nil, &net.OpError{Op: "read", Net: "udp", Err: net.ErrClosed}
	default:
	}
	if c.forever != nil {
		select {
		case s := <-c.steps:
			return copy(p, s.b), s.from, s.err
		default:
			return 0, nil, c.forever
		}
	}
	select {
	case s := <-c.steps:
		return copy(p, s.b), s.from, s.err
	case <-c.closed:
		return 0, nil, &net.OpError{Op: "read", Net: "udp", Err: net.ErrClosed}
	}
}

func (c *fakeConn) WriteTo([]byte, net.Addr) (int, error) {
	return 0, errors.New("fakeConn: no writes")
}
func (c *fakeConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}
func (c *fakeConn) LocalAddr() net.Addr              { return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5514} }
func (c *fakeConn) SetDeadline(time.Time) error      { return nil }
func (c *fakeConn) SetReadDeadline(time.Time) error  { return nil }
func (c *fakeConn) SetWriteDeadline(time.Time) error { return nil }

// useConn makes r's Run use c instead of binding a socket.
func useConn(r *Receiver, c net.PacketConn) {
	r.listen = func(string, string) (net.PacketConn, error) { return c, nil }
}

// readErr wraps the system error err the way the net package reports a failed receive.
func readErr(err error) error {
	return &net.OpError{Op: "read", Net: "udp", Err: os.NewSyscallError("wsarecvfrom", err)}
}

// gatewayAddr is a datagram's sender as the net package reports it (a 16-byte IPv4 address,
// i.e. ::ffff:192.168.1.254 to netip).
var gatewayAddr = &net.UDPAddr{IP: net.IPv4(192, 168, 1, 254), Port: 514}
