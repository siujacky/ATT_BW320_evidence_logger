package probe

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

func TestTCPConnected(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan struct{}, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			accepted <- struct{}{}
			c.Close()
		}
	}()
	target := ln.Addr().String()
	r := New(Options{}).TCP(context.Background(), target, 2*time.Second)
	if !r.OK || r.Status != StatusConnected || r.Kind != "tcp" || r.Target != target {
		t.Fatalf("got %+v", r)
	}
	if r.RTTus <= 0 || r.ReplyFrom != target || r.Err != "" {
		t.Fatalf("RTT/peer/err: %+v", r)
	}
	select {
	case <-accepted:
	case <-time.After(2 * time.Second):
		t.Fatal("listener never saw the connection")
	}
}

func TestTCPRefused(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	target := ln.Addr().String()
	ln.Close() // the port is now closed
	start := time.Now()
	// Windows retries a SYN answered by RST for ~1-2 s before reporting "refused", so the
	// timeout here is generous.
	r := New(Options{}).TCP(context.Background(), target, 10*time.Second)
	if r.OK || r.Status != StatusRefused {
		t.Fatalf("got %+v", r)
	}
	if r.RTTus != 0 || r.ReplyFrom != "" || r.Err == "" {
		t.Fatalf("refused must carry no RTT/peer but an error text: %+v", r)
	}
	t.Logf("refused after %v: %s", time.Since(start), r.Err)
}

func TestTCPUnansweredTimesOut(t *testing.T) {
	start := time.Now()
	r := New(Options{}).TCP(context.Background(), "192.0.2.1:443", 300*time.Millisecond)
	el := time.Since(start)
	if r.OK {
		t.Fatalf("TEST-NET answered: %+v", r)
	}
	// Online: the SYN goes unanswered (timeout). Offline: no route (unreachable).
	if r.Status != StatusTimeout && r.Status != StatusUnreachable {
		t.Fatalf("status %q err %q", r.Status, r.Err)
	}
	if el > 1500*time.Millisecond {
		t.Fatalf("took %v with a 300ms timeout", el)
	}
	if r.RTTus != 0 {
		t.Fatalf("RTT set on failure: %+v", r)
	}
}

func TestTCPCanceledAndBadTarget(t *testing.T) {
	p := New(Options{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if r := p.TCP(ctx, "127.0.0.1:1", time.Second); r.Status != StatusCanceled || r.OK {
		t.Errorf("pre-canceled: %+v", r)
	}
	for _, target := range []string{"", "127.0.0.1", "no-port.example", "[::1"} {
		r := p.TCP(context.Background(), target, time.Second)
		if r.Status != StatusError || r.OK || r.Err == "" {
			t.Errorf("TCP(%q) = %+v, want error status", target, r)
		}
	}
}

func TestTCPCancelDuringDial(t *testing.T) {
	p := New(Options{})
	p.dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		<-ctx.Done()
		return nil, &net.OpError{Op: "dial", Net: network, Err: ctx.Err()}
	}
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(50*time.Millisecond, cancel)
	r := p.TCP(ctx, "192.0.2.1:443", 5*time.Second)
	if r.Status != StatusCanceled {
		t.Fatalf("got %+v", r)
	}
	// The probe's own timeout (not the caller) is a timeout.
	r = p.TCP(context.Background(), "192.0.2.1:443", 50*time.Millisecond)
	if r.Status != StatusTimeout {
		t.Fatalf("got %+v", r)
	}
}

// timeoutErr is a net.Error reporting a timeout.
type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

func TestClassifyDialError(t *testing.T) {
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	bg := context.Background()
	tests := []struct {
		name   string
		parent context.Context
		err    error
		want   string
	}{
		{"refused", bg, refusedErr(), StatusRefused},
		{"unreachable", bg, unreachableErr(), StatusUnreachable},
		{"deadline", bg, fmt.Errorf("dial: %w", context.DeadlineExceeded), StatusTimeout},
		{"net timeout", bg, &net.OpError{Op: "dial", Err: timeoutErr{}}, StatusTimeout},
		{"os timeout", bg, os.ErrDeadlineExceeded, StatusTimeout},
		{"parent canceled wins", canceled, refusedErr(), StatusCanceled},
		{"canceled error", bg, context.Canceled, StatusCanceled},
		{"dns", bg, &net.DNSError{Err: "no such host", Name: "x.invalid", IsNotFound: true}, StatusError},
		{"other", bg, errors.New("boom"), StatusError},
	}
	for _, tt := range tests {
		if got := classifyDialError(tt.parent, tt.err); got != tt.want {
			t.Errorf("%s: classifyDialError(%v) = %q, want %q", tt.name, tt.err, got, tt.want)
		}
	}
}

func TestClassifyRealRefusedError(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	_, err = net.DialTimeout("tcp", addr, 10*time.Second)
	if err == nil {
		t.Skip("port unexpectedly open")
	}
	if !isRefused(err) {
		t.Fatalf("isRefused(%v) = false (%T)", err, errors.Unwrap(err))
	}
	if strings.TrimSpace(err.Error()) == "" {
		t.Fatal("empty error text")
	}
}
