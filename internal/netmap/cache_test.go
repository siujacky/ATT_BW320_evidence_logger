package netmap

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"attmonitor/internal/contracts"
	"attmonitor/internal/model"
)

// ---------------------------------------------------------------- result cache

func TestResultCacheReusesAFreshView(t *testing.T) {
	now := t0
	c := newResultCache[int](30*time.Second, func() time.Time { return now })
	ctx := context.Background()
	builds := 0
	build := func() (int, error) { builds++; return builds, nil }
	for _, step := range []struct {
		key     string
		advance time.Duration
		want    int
	}{
		{"a", 0, 1},
		{"a", 29 * time.Second, 1}, // fresh
		{"b", 0, 2},                // another request
		{"a", time.Second, 3},      // 30 s old: built again
		{"b", 0, 2},                // 1 s old
		{"b", 30 * time.Second, 4}, // 31 s old
	} {
		now = now.Add(step.advance)
		if v, err := c.get(ctx, step.key, build); err != nil || v != step.want {
			t.Fatalf("%s: %d %v, want %d", step.key, v, err, step.want)
		}
	}
	// Disabled: built every time.
	d := newResultCache[int](-1, time.Now)
	for want := 5; want < 7; want++ {
		if v, _ := d.get(ctx, "a", build); v != want {
			t.Fatalf("without the cache: %d, want %d", v, want)
		}
	}
}

func TestResultCacheDoesNotKeepFailures(t *testing.T) {
	c := newResultCache[int](time.Minute, time.Now)
	fail := errors.New("store unavailable")
	calls := 0
	build := func() (int, error) {
		calls++
		if calls == 1 {
			return 0, fail
		}
		return 42, nil
	}
	if _, err := c.get(context.Background(), "a", build); !errors.Is(err, fail) {
		t.Fatal(err)
	}
	if v, err := c.get(context.Background(), "a", build); err != nil || v != 42 || calls != 2 {
		t.Fatalf("%d %v after %d calls", v, err, calls)
	}
}

func TestResultCacheBuildsOnceForWaitingRequests(t *testing.T) {
	c := newResultCache[int](time.Minute, time.Now)
	release := make(chan struct{})
	running := make(chan struct{})
	var builds atomic.Int32
	build := func() (int, error) {
		if builds.Add(1) == 1 {
			close(running)
		}
		<-release
		return 7, nil
	}
	var wg sync.WaitGroup
	results := make(chan int, 10)
	wg.Go(func() {
		v, _ := c.get(context.Background(), "a", build)
		results <- v
	})
	<-running
	for range 9 {
		wg.Go(func() {
			v, _ := c.get(context.Background(), "a", build)
			results <- v
		})
	}
	close(release)
	wg.Wait()
	close(results)
	for v := range results {
		if v != 7 {
			t.Fatalf("got %d", v)
		}
	}
	if n := builds.Load(); n != 1 {
		t.Fatalf("built %d times", n)
	}
}

func TestResultCacheWhenTheBuilderGivesUp(t *testing.T) {
	c := newResultCache[int](time.Minute, time.Now)
	running := make(chan struct{})
	release := make(chan struct{})
	leaderCtx, cancelLeader := context.WithCancel(context.Background())
	var leaderErr error
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, leaderErr = c.get(leaderCtx, "a", func() (int, error) {
			close(running)
			<-release
			return 0, leaderCtx.Err()
		})
	}()
	<-running
	// A waiter whose own request goes on builds the view itself once the builder gave up.
	waiter := make(chan int)
	go func() {
		v, err := c.get(context.Background(), "a", func() (int, error) { return 9, nil })
		if err != nil {
			t.Error(err)
		}
		waiter <- v
	}()
	// A waiter whose request ends stops waiting.
	ended, cancelEnded := context.WithCancel(context.Background())
	cancelEnded()
	if _, err := c.get(ended, "a", func() (int, error) { return 1, nil }); !errors.Is(err, context.Canceled) {
		t.Fatalf("a waiter whose request ended: %v", err)
	}
	cancelLeader()
	close(release)
	if v := <-waiter; v != 9 {
		t.Fatalf("waiter got %d", v)
	}
	<-done
	if !errors.Is(leaderErr, context.Canceled) {
		t.Fatalf("builder: %v", leaderErr)
	}
}

// TestResultCacheAfterAPanic: a build that panics does not leave its entry behind: the panic
// reaches the caller that built, the callers waiting for it are let go with an error, and the
// next caller builds the view again instead of waiting for its deadline.
func TestResultCacheAfterAPanic(t *testing.T) {
	c := newResultCache[int](time.Minute, time.Now)
	running, release := make(chan struct{}), make(chan struct{})
	panicked := make(chan any, 1)
	go func() {
		defer func() { panicked <- recover() }()
		c.get(context.Background(), "k", func() (int, error) {
			close(running)
			<-release
			panic("view bug")
		})
	}()
	<-running
	// A caller of the same key meanwhile: it waits for that build, or - should it come after -
	// builds itself; either way it does not wait until its deadline.
	waited := make(chan error, 1)
	waiting := make(chan struct{})
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		close(waiting)
		_, err := c.get(ctx, "k", func() (int, error) { return 3, nil })
		waited <- err
	}()
	<-waiting
	time.Sleep(20 * time.Millisecond)
	close(release)
	if p := <-panicked; p != "view bug" {
		t.Fatalf("the builder's panic: %v", p)
	}
	select {
	case err := <-waited:
		if err != nil && !errors.Is(err, errBuildFailed) {
			t.Fatalf("waiter: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a caller waits for a build that panicked")
	}
	c.mu.Lock()
	left := len(c.m)
	c.mu.Unlock()
	if left > 1 { // at most the waiter's own view, should it have built
		t.Fatalf("%d entries left", left)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	c.mu.Lock()
	delete(c.m, "k") // the waiter's view, if it built one
	c.mu.Unlock()
	if v, err := c.get(ctx, "k", func() (int, error) { return 42, nil }); err != nil || v != 42 {
		t.Fatalf("after the panic: %d %v", v, err)
	}
}

// panickyConns is a connection store whose first Aggregate panics (a bug).
type panickyConns struct {
	*fakeConns
	calls atomic.Int32
}

func (p *panickyConns) Aggregate(ctx context.Context, q contracts.ConnQuery) (model.ConnAggregate, error) {
	if p.calls.Add(1) == 1 {
		panic("aggregate bug")
	}
	return p.fakeConns.Aggregate(ctx, q)
}

func TestConnectionsAfterAPanickingBuild(t *testing.T) {
	conns, in := connScenario()
	p := &panickyConns{fakeConns: conns}
	v := New(Options{Conns: p, Intel: in})
	q := contracts.NetQuery{From: t0, To: t0.Add(time.Hour)} // a custom period: the same key each time
	func() {
		defer func() {
			if r := recover(); r != "aggregate bug" {
				t.Fatalf("recovered %v", r)
			}
		}()
		v.Connections(context.Background(), q)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if nc, err := v.Connections(ctx, q); err != nil || nc.RowsTotal != 18 || p.calls.Load() != 2 {
		t.Fatalf("after the panic: %v, %d rows, %d calls", err, nc.RowsTotal, p.calls.Load())
	}
}

func TestResultCacheIsBounded(t *testing.T) {
	now := t0
	c := newResultCache[int](time.Hour, func() time.Time { return now })
	for i := range 3 * maxResults {
		now = now.Add(time.Second)
		if _, err := c.get(context.Background(), fmt.Sprint(i), func() (int, error) { return i, nil }); err != nil {
			t.Fatal(err)
		}
		if len(c.m) > maxResults {
			t.Fatalf("%d views kept", len(c.m))
		}
	}
	// The newest are kept.
	if _, ok := c.m[fmt.Sprint(3*maxResults-1)]; !ok {
		t.Fatal("the newest view was dropped")
	}
	// Stale ones go at the next build.
	now = now.Add(2 * time.Hour)
	c.get(context.Background(), "new", func() (int, error) { return 0, nil })
	if len(c.m) != 1 {
		t.Fatalf("%d views kept", len(c.m))
	}
}

// ---------------------------------------------------------------- chunk cache

// sized returns a summary of n sources.
func sized(n int) *chunkAgg {
	return &chunkAgg{hasRX: true, sources: make([]srcRow, n)}
}

func refsNamed(names ...string) []model.SyslogChunkRef {
	out := make([]model.SyslogChunkRef, len(names))
	for i, n := range names {
		out[i] = model.SyslogChunkRef{Name: n, SHA256: "sha-" + n}
	}
	return out
}

func TestChunkCacheDropsTheLeastRecentlyUsed(t *testing.T) {
	c := newChunkCache(1<<20, 3)
	all := refsNamed("a", "b", "c", "d", "e")
	put := func(name string) bool { return c.put(name, "sha-"+name, sized(1)) }
	kept := func(name string) bool { return c.peek(name, "sha-"+name) != nil }

	c.begin(all)
	if !put("a") || !put("b") || !put("c") {
		t.Fatal("not kept")
	}
	// Full of what this request uses: d is not kept, nothing is dropped.
	if put("d") || !kept("a") || !kept("b") || !kept("c") {
		t.Fatal("d displaced a summary the request needs")
	}
	// The next request uses b, and needs c: a is dropped for d.
	c.begin(all)
	if c.get("b", "sha-b") == nil {
		t.Fatal("b not kept")
	}
	c.need("c", "sha-c")
	if !put("d") || kept("a") || !kept("b") || !kept("c") || !kept("d") {
		t.Fatal("a was not the one dropped")
	}
	// Another SHA-256 is another chunk.
	if c.get("b", "other") != nil || c.peek("b", "other") != nil {
		t.Fatal("found under another SHA-256")
	}
	// A chunk no longer listed - or listed with another SHA-256 - leaves the cache.
	c.begin([]model.SyslogChunkRef{{Name: "b", SHA256: "sha-b"}, {Name: "c", SHA256: "changed"}})
	if e, _ := c.stats(); e != 1 || !kept("b") {
		t.Fatalf("%d kept", e)
	}
}

func TestChunkCacheBoundsItsMemory(t *testing.T) {
	one := sized(100).size()
	c := newChunkCache(2*one+one/2, 100)
	c.begin(refsNamed("a", "b", "c"))
	if !c.put("a", "sha-a", sized(100)) || !c.put("b", "sha-b", sized(100)) {
		t.Fatal("not kept")
	}
	if c.put("c", "sha-c", sized(100)) { // all needed by this request
		t.Fatal("kept beyond the limit")
	}
	if _, b := c.stats(); b != 2*one {
		t.Fatalf("%d bytes, want %d", b, 2*one)
	}
	c.begin(refsNamed("a", "b", "c"))
	if !c.put("c", "sha-c", sized(100)) {
		t.Fatal("c not kept in the next request")
	}
	if e, b := c.stats(); e != 2 || b != 2*one || c.peek("a", "sha-a") != nil {
		t.Fatalf("%d entries, %d bytes", e, b)
	}
	// A summary larger than the whole cache is not kept; replacing one counts it once.
	if c.put("huge", "sha-huge", sized(1000)) {
		t.Fatal("kept a summary larger than the cache")
	}
	if !c.put("c", "sha-c", sized(100)) {
		t.Fatal("not replaced")
	}
	if e, b := c.stats(); e != 2 || b != 2*one {
		t.Fatalf("after replacing: %d entries, %d bytes", e, b)
	}
}

// ---------------------------------------------------------------- concurrency

// TestViewIsSafeForConcurrentUse builds views from many goroutines while the store's writer
// appends, seals and prunes (run with -race).
func TestViewIsSafeForConcurrentUse(t *testing.T) {
	s := sampleStore(t)
	conns, in := connScenario()
	conns.devices = sampleDevices
	v := New(Options{Syslog: s, Conns: conns, Intel: in, CacheChunks: 2, ResultTTL: time.Millisecond})
	ctx := context.Background()
	stop := make(chan struct{})
	var writer sync.WaitGroup
	writer.Go(func() {
		for i := range 200 { // bounded: each new chunk is more work for every reader
			select {
			case <-stop:
				return
			default:
			}
			rx := at(7200 + float64(i))
			if _, err := s.Append([]model.SyslogMessage{syslogMsg(rx, lineInbound), syslogMsg(rx, repeatLine(2))}, 0, 0, t0); err != nil {
				t.Error(err)
				return
			}
			if i%5 == 0 {
				if _, err := s.Seal(t0, "stop", true); err != nil {
					t.Error(err)
					return
				}
			}
		}
	})
	var readers sync.WaitGroup
	for g := range 8 {
		readers.Go(func() {
			for j := range 25 {
				q := contracts.NetQuery{From: t0.Add(time.Duration(g+j) * time.Second), To: t0.Add(3 * time.Hour), Limit: g}
				if _, err := v.Firewall(ctx, q); err != nil {
					t.Error(err)
				}
				if _, err := v.Connections(ctx, q); err != nil {
					t.Error(err)
				}
				v.NetworkStatus()
			}
		})
	}
	readers.Wait()
	close(stop)
	writer.Wait()
	// Once the writer stopped, a fresh view counts every drop.
	u := s.Usage()
	fw, err := New(Options{Syslog: s}).Firewall(ctx, contracts.NetQuery{From: t0, To: t0.Add(30 * 24 * time.Hour)})
	if err != nil || int64(fw.Drops) != 12+3*(u.Messages-10)/2 {
		t.Fatalf("%d drops of %d messages (%v)", fw.Drops, u.Messages, err)
	}
}
