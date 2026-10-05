package mongostore

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"attmonitor/internal/model"
)

// These tests need no MongoDB: they point the replicator at a localhost port nobody listens on.

func unreachableOptions(t *testing.T, logs *countingHandler) Options {
	return Options{
		URI:            fmt.Sprintf("mongodb://user:hunter2@127.0.0.1:%d/?directConnection=true", unusedPort(t)),
		Database:       "attmonitor_test_unreachable",
		Reader:         &memReader{},
		Interval:       10 * time.Millisecond,
		ConnectTimeout: 100 * time.Millisecond,
		Logger:         slog.New(logs),
	}
}

func TestRunKeepsGoingWhenMongoUnreachable(t *testing.T) {
	logs := &countingHandler{}
	r := newReplicator(t, unreachableOptions(t, logs))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx) }()

	// The dashboard reads the status concurrently.
	var wg sync.WaitGroup
	stop := make(chan struct{})
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				if st := r.Status(); st.Connected || !st.Enabled {
					t.Errorf("status while unreachable: %+v", st)
					return
				}
				time.Sleep(2 * time.Millisecond)
			}
		}()
	}
	time.Sleep(1500 * time.Millisecond)
	close(stop)
	wg.Wait()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned %v, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after its context was canceled")
	}
	st := r.Status()
	if st.Connected || st.HasData || !strings.Contains(st.LastError, "unreachable") || st.LastSync != "" {
		t.Errorf("status %+v", st)
	}
	if strings.Contains(st.LastError, "hunter2") || strings.Contains(st.URI, "hunter2") || strings.Contains(st.URI, "user") {
		t.Errorf("credentials shown: %+v", st)
	}
	msgs := logs.messages()
	if len(msgs) != 1 || !strings.Contains(msgs[0], "unreachable") {
		t.Fatalf("log entries while MongoDB stays unreachable: %q (want exactly one)", msgs)
	}
	for _, m := range msgs {
		if strings.Contains(m, "hunter2") {
			t.Errorf("log leaks the password: %q", m)
		}
	}
}

func TestSyncOnceUnreachable(t *testing.T) {
	logs := &countingHandler{}
	r := newReplicator(t, unreachableOptions(t, logs))
	start := time.Now()
	n, err := r.SyncOnce(context.Background())
	var ue *unreachableError
	if n != 0 || !errors.As(err, &ue) || errors.Is(err, ErrIntegrity) {
		t.Fatalf("SyncOnce = %d, %v", n, err)
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Errorf("SyncOnce took %v with a 100 ms connect timeout", d)
	}
	if st := r.Status(); st.Connected || st.LastError == "" {
		t.Errorf("status %+v", st)
	}
}

func TestCloseStopsRun(t *testing.T) {
	o := unreachableOptions(t, &countingHandler{})
	o.Interval = time.Hour // after the first failure Run would wait an hour
	r, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- r.Run(context.Background()) }()
	time.Sleep(300 * time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := r.Close(ctx); err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after Close")
	}
	if _, err := r.SyncOnce(ctx); !errors.Is(err, ErrClosed) {
		t.Errorf("SyncOnce after Close: %v", err)
	}
	if err := r.Close(ctx); err != nil {
		t.Errorf("second Close: %v", err)
	}
	if err := r.Run(ctx); err != nil {
		t.Errorf("Run after Close: %v", err)
	}
}

func TestRunReturnsAtOnceOnCanceledContext(t *testing.T) {
	r := newReplicator(t, unreachableOptions(t, &countingHandler{}))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	if err := r.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > time.Second {
		t.Errorf("Run took %v on a canceled context", d)
	}
	if _, err := r.SyncOnce(ctx); !errors.Is(err, context.Canceled) {
		t.Errorf("SyncOnce on a canceled context: %v", err)
	}
	if st := r.Status(); st.LastError != "" {
		t.Errorf("a canceled pass changed the state: %+v", st)
	}
}

// headReader is a memReader with a head (like ledger.Store).
type headReader struct {
	*memReader
	mu   sync.Mutex
	head uint64
}

func (h *headReader) Head() model.Ref {
	h.mu.Lock()
	defer h.mu.Unlock()
	return model.Ref{Seq: h.head, Hash: "h"}
}

func (h *headReader) setHead(seq uint64) {
	h.mu.Lock()
	h.head = seq
	h.mu.Unlock()
}

func TestLagWhileUnreachable(t *testing.T) {
	o := unreachableOptions(t, &countingHandler{})
	hr := &headReader{memReader: &memReader{}, head: 40}
	o.Reader = hr
	r := newReplicator(t, o)
	if _, err := r.SyncOnce(context.Background()); err == nil {
		t.Fatal("SyncOnce succeeded")
	}
	// Never connected: what the copy holds is unknown, so no lag is invented.
	if st := r.Status(); st.Lag != 0 || st.HasData {
		t.Fatalf("lag before the copy was ever read: %+v", st)
	}
	// Known resume point (as after a good pass), then MongoDB goes away while the ledger grows.
	r.setResume(31, true)
	for _, head := range []uint64{45, 60} {
		hr.setHead(head)
		if _, err := r.SyncOnce(context.Background()); err == nil {
			t.Fatal("SyncOnce succeeded")
		}
		if st := r.Status(); st.Lag != head-30 || st.LastSeq != 30 || st.Connected {
			t.Fatalf("head %d: status %+v", head, st)
		}
	}
}

func TestUnreachableLogsAtMostHourly(t *testing.T) {
	logs := &countingHandler{}
	o := unreachableOptions(t, logs)
	o.ConnectTimeout = 50 * time.Millisecond
	clk := newClock()
	start := clk.Now()
	o.Now = func() time.Time { clk.Advance(25 * time.Minute); return clk.Now() }
	r := newReplicator(t, o)
	for i := 0; i < 12; i++ {
		if _, err := r.SyncOnce(context.Background()); err == nil {
			t.Fatal("SyncOnce succeeded against an unused port")
		}
	}
	elapsed := clk.Now().Sub(start)
	n := len(logs.messages())
	if limit := 1 + int(elapsed/time.Hour); n < 2 || n > limit {
		t.Fatalf("%d log entries over %v of failures, want between 2 and %d: %q", n, elapsed, limit, logs.messages())
	}
}

func TestVerifyUnreachable(t *testing.T) {
	start := time.Now()
	_, err := Verify(context.Background(), fmt.Sprintf("mongodb://127.0.0.1:%d/?serverSelectionTimeoutMS=200", unusedPort(t)), "attmonitor_test_unreachable", &memReader{}, nil)
	if err == nil || !strings.Contains(err.Error(), "unreachable") {
		t.Fatalf("Verify: %v", err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("Verify took %v", d)
	}
	if _, err := Verify(context.Background(), "", "", nil, nil); err == nil {
		t.Error("Verify without a reader")
	}
	if _, err := Verify(context.Background(), "", "", &memReader{}, make([]byte, 5)); err == nil {
		t.Error("Verify with a bad public key")
	}
	if _, err := Verify(context.Background(), "nope://", "", &memReader{}, nil); err == nil {
		t.Error("Verify with a bad URI")
	}
}
