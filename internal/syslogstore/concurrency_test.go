package syslogstore

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"sync"
	"testing"
	"time"

	"attmonitor/internal/contracts"
	"attmonitor/internal/model"
)

func TestConcurrentWriterReadersAndPrune(t *testing.T) {
	s, _ := testStore(t, Options{KeepMB: 1, ChunkBytes: 64 << 10, ChunkAge: 3 * time.Minute})
	const rounds = 120
	batches := make([][]model.SyslogMessage, rounds)
	for i := range batches {
		batches[i] = randomMsgs(t, t0.Add(time.Duration(i)*time.Minute), 10, 2048)
	}

	var (
		mu       sync.Mutex
		sealed   = map[string]model.SyslogChunk{}
		pruned   = map[string]bool{}
		problems []string
		queries  int // queries that found messages, and chunks read whole, while the writer ran
		reads    int
	)
	problem := func(format string, args ...any) {
		mu.Lock()
		problems = append(problems, fmt.Sprintf(format, args...))
		mu.Unlock()
	}
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup

	// The writer: the monitor's calls, in its order.
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer cancel()
		for i, b := range batches {
			now := t0.Add(time.Duration(i) * time.Minute)
			cs, err := s.Append(b, i%3, i%2, now)
			if err != nil {
				problem("Append: %v", err)
			}
			if c, err := s.Seal(now, "age", false); err != nil {
				problem("Seal: %v", err)
			} else if c != nil {
				cs = append(cs, *c)
			}
			mu.Lock()
			for _, c := range cs {
				sealed[c.Name] = c
			}
			mu.Unlock()
			refs, err := s.Prune(now)
			if err != nil {
				problem("Prune: %v", err)
			}
			mu.Lock()
			for _, r := range refs {
				if pruned[r.Name] {
					problem("%s pruned twice", r.Name)
				}
				pruned[r.Name] = true
			}
			mu.Unlock()
			if i%40 == 39 {
				s.SetRetention(1+(i/40)%2, 0) // 1, 2, 1 MiB
			}
		}
	}()

	// Readers: queries, usage, whole chunks. open returns the store to read for one round.
	reader := func(name string, open func() (*Store, error)) {
		defer wg.Done()
		for n := 0; ctx.Err() == nil || n == 0; n++ {
			st, err := open()
			if err != nil {
				problem("%s New: %v", name, err)
				return
			}
			es, _, err := st.Query(context.Background(), time.Time{}, time.Time{}, nil, 40)
			if err != nil {
				problem("%s Query: %v", name, err)
				return
			}
			if len(es) > 0 && ctx.Err() == nil {
				mu.Lock()
				queries++
				mu.Unlock()
			}
			for i := 1; i < len(es); i++ {
				if es[i].RX > es[i-1].RX {
					problem("%s Query: %s after %s", name, es[i].RX, es[i-1].RX)
				}
			}
			if u := st.Usage(); u.Bytes < 0 || u.Messages < int64(u.OpenMessages) {
				problem("%s Usage: %+v", name, u)
			}
			for _, e := range es {
				if e.Chunk == "" {
					continue
				}
				r, err := st.OpenChunk(e.Chunk)
				if errors.Is(err, contracts.ErrNotFound) {
					continue // pruned meanwhile
				}
				if err != nil {
					problem("%s OpenChunk: %v", name, err)
					continue
				}
				b, err := io.ReadAll(r)
				r.Close()
				if err != nil {
					problem("%s read %s: %v", name, e.Chunk, err)
					continue
				}
				plain, err := gunzipErr(b)
				if err != nil {
					problem("%s %s: %v", name, e.Chunk, err)
					continue
				}
				mu.Lock()
				c, ok := sealed[e.Chunk]
				mu.Unlock()
				if got := sha(plain); ok && got != c.SHA256 {
					problem("%s %s: content %s, sealed %s", name, e.Chunk, got, c.SHA256)
				}
				if ctx.Err() == nil {
					mu.Lock()
					reads++
					mu.Unlock()
				}
				break
			}
			if st != s {
				st.Close() // a read-only store holds no file between calls
			}
		}
	}
	for i := range 3 {
		wg.Add(1)
		go reader(fmt.Sprint("reader", i), func() (*Store, error) { return s, nil })
	}
	// Read-only stores, opened again and again as other processes would, read the same files.
	wg.Add(1)
	go reader("read-only", func() (*Store, error) { return New(Options{Dir: s.dir, ReadOnly: true}) })
	wg.Wait()

	if len(problems) > 0 {
		t.Fatalf("%d problems, the first: %s", len(problems), problems[0])
	}
	t.Logf("while the writer ran: %d queries found messages, %d chunks were read whole", queries, reads)
	if queries == 0 || reads == 0 {
		t.Fatal("the readers did not run alongside the writer")
	}
	// Every chunk sealed and not pruned is kept, and nothing else (a last Prune deletes what
	// readers held, and applies the last retention change).
	refs, err := s.Prune(t0.Add(rounds * time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range refs {
		pruned[r.Name] = true
	}
	var want []string
	for name := range sealed {
		if !pruned[name] {
			want = append(want, name)
		}
	}
	slices.Sort(want)
	if got := sealedFiles(t, s.dir); !slices.Equal(got, want) {
		t.Fatalf("chunks on disk %v\nwant %v", got, want)
	}
	if len(pruned) == 0 || len(want) == 0 {
		t.Fatalf("test setup: %d pruned, %d kept", len(pruned), len(want))
	}
	if u := s.Usage(); u.Chunks != len(want) || u.Bytes > 2<<20 {
		t.Fatalf("Usage: %+v", u)
	}
	for _, name := range want {
		checkChunk(t, s.dir, sealed[name], content(t, s.dir, name))
	}
}

// gunzipErr decompresses b (for goroutines other than the test's).
func gunzipErr(b []byte) ([]byte, error) {
	zr, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	return io.ReadAll(zr)
}
