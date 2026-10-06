package web

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"attmonitor/internal/contracts"
	"attmonitor/internal/model"
	"attmonitor/internal/netmap"
)

// The Network page's views as the service builds them (netmap.View behind the endpoints): a view is
// built once for the requests of the same range that come within the reuse time - a second tab, a
// refresh, the CLI - and one connections view is built at a time, however many requests come.

// countingConns is a connection store whose Aggregate counts its calls and the calls running at
// once (the most so far); while gate is open (not nil) each call waits for it.
type countingConns struct {
	calls, running, most atomic.Int64
	gate                 chan struct{}
}

func (c *countingConns) Aggregate(ctx context.Context, q contracts.ConnQuery) (model.ConnAggregate, error) {
	c.calls.Add(1)
	n := c.running.Add(1)
	defer c.running.Add(-1)
	for {
		most := c.most.Load()
		if n <= most || c.most.CompareAndSwap(most, n) {
			break
		}
	}
	if c.gate != nil {
		select {
		case <-c.gate:
		case <-ctx.Done():
			return model.ConnAggregate{}, ctx.Err()
		}
	}
	return model.ConnAggregate{InUse: -1, Available: -1, Devices: []model.ConnDevice{}, Flows: []model.ConnFlow{}}, nil
}
func (c *countingConns) AppendNAT(time.Time, model.NATTable) error        { return nil }
func (c *countingConns) AppendDevices(time.Time, []model.LANDevice) error { return nil }
func (c *countingConns) Devices() ([]model.LANDevice, time.Time)          { return nil, time.Time{} }
func (c *countingConns) Prune(time.Time) error                            { return nil }
func (c *countingConns) SetRetention(int, int)                            {}
func (c *countingConns) Usage() model.ConnStoreUsage                      { return model.ConnStoreUsage{} }

// countingChunks is a syslog store without messages whose listing counts its calls.
type countingChunks struct{ lists atomic.Int64 }

func (s *countingChunks) Chunks() []model.SyslogChunkRef {
	s.lists.Add(1)
	return nil
}
func (s *countingChunks) OpenChunk(string) (io.ReadCloser, error) { return nil, contracts.ErrNotFound }
func (s *countingChunks) EachOpen(context.Context, time.Time, time.Time, func(*model.SyslogMessage) error) error {
	return nil
}
func (s *countingChunks) Usage() model.SyslogUsage { return model.SyslogUsage{} }

// networkServer serves the views of netmap.New over conns and chunks; the server's and the view's
// clock is clk, which every reading moves on by 50 ms (requests come one after the other).
func networkServer(t *testing.T, conns *countingConns, chunks *countingChunks, clk *atomic.Int64) *harness {
	t.Helper()
	now := func() time.Time { return time.Unix(0, clk.Add(int64(50*time.Millisecond))).UTC() }
	view := netmap.New(netmap.Options{Conns: conns, Syslog: chunks, Now: now})
	srv, err := New(Options{Listen: testListen, Network: view})
	if err != nil {
		t.Fatal(err)
	}
	srv.now = now
	return &harness{t: t, srv: srv}
}

// TestNetworkRangeRequestsShareAView: requests for the same range that come one after the other -
// each a moment later than the one before, so their periods all differ - are answered by one build
// while it is younger than the reuse time; a request after it is built again. The same holds for the
// firewall view (its build lists the syslog chunks twice: before and after reading them).
func TestNetworkRangeRequestsShareAView(t *testing.T) {
	var clk atomic.Int64
	clk.Store(time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC).UnixNano())
	conns, chunks := &countingConns{}, &countingChunks{}
	hs := networkServer(t, conns, chunks, &clk)
	for range 3 {
		wantStatus(t, hs.get("/api/network/connections?range=24h&limit=1000"), http.StatusOK)
		wantStatus(t, hs.get("/api/network/firewall?range=24h&limit=1000"), http.StatusOK)
	}
	if n, lists := conns.calls.Load(), chunks.lists.Load(); n != 1 || lists != 2 {
		t.Fatalf("3 requests of each view built %d connections views and listed the chunks %d times; want 1 build each", n, lists)
	}
	// Another range, another device or another limit is another view.
	wantStatus(t, hs.get("/api/network/connections?range=7d&limit=1000"), http.StatusOK)
	wantStatus(t, hs.get("/api/network/connections?range=24h&limit=1000&device=gateway"), http.StatusOK)
	if n := conns.calls.Load(); n != 1+1+2 { // the device filter adds up every device too
		t.Fatalf("%d Aggregate calls, want 4", n)
	}
	// Once the view is older than the reuse time, it is built again.
	clk.Add(int64(netmap.DefaultResultTTL + time.Second))
	wantStatus(t, hs.get("/api/network/connections?range=24h&limit=1000"), http.StatusOK)
	if n := conns.calls.Load(); n != 5 {
		t.Fatalf("%d Aggregate calls after the reuse time, want 5", n)
	}
}

// TestNetworkConnectionsBuiltOneAtATime: requests for one range that arrive while its view is being
// built wait for that build; requests for other periods wait for their turn - never two builds at
// once inside the evidence logger.
func TestNetworkConnectionsBuiltOneAtATime(t *testing.T) {
	var clk atomic.Int64
	clk.Store(time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC).UnixNano())
	conns := &countingConns{gate: make(chan struct{})}
	hs := networkServer(t, conns, &countingChunks{}, &clk)
	var wg sync.WaitGroup
	codes := make(chan int, 16)
	for i := range 8 {
		wg.Go(func() { codes <- hs.get("/api/network/connections?range=30d").Code })
		time.Sleep(time.Millisecond)
		from := time.Date(2026, 10, 1, i, 0, 0, 0, time.UTC).Format(time.RFC3339)
		wg.Go(func() {
			codes <- hs.get(fmt.Sprintf("/api/network/connections?from=%s&to=2026-10-06T00:00:00Z", from)).Code
		})
	}
	deadline := time.Now().Add(10 * time.Second)
	for conns.calls.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	time.Sleep(100 * time.Millisecond) // the others are waiting by now
	if n := conns.calls.Load(); n != 1 {
		t.Fatalf("%d builds started while the first was running", n)
	}
	close(conns.gate)
	wg.Wait()
	close(codes)
	for c := range codes {
		if c != http.StatusOK {
			t.Fatalf("a request was answered %d", c)
		}
	}
	if n, most := conns.calls.Load(), conns.most.Load(); n != 1+8 || most != 1 {
		t.Fatalf("%d Aggregate calls (want 9: the 8 requests of the range share one), at most %d at once (want 1)", n, most)
	}
}
