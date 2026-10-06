package syslogstore

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"attmonitor/internal/contracts"
	"attmonitor/internal/model"
)

// layout stores 3 sealed chunks of 3 messages and an open chunk of 2 (11 seconds apart from
// t0, m-0 … m-10 in order, m-9 and m-10 open) and returns the messages and the chunks.
func layout(t *testing.T) (*Store, *captureHandler, []model.SyslogMessage, []model.SyslogChunk) {
	t.Helper()
	s, h := testStore(t, Options{})
	ms := msgs(t0, 11, "m")
	chunks := fill(t, s, ms[:9], 3)
	if _, err := s.Append(ms[9:], 0, 0, t0); err != nil {
		t.Fatal(err)
	}
	return s, h, ms, chunks
}

func TestQueryNewestFirstAcrossChunks(t *testing.T) {
	s, _, ms, chunks := layout(t)
	es := queryAll(t, s)
	if got := entryTexts(es); !slices.Equal(got, reversed(ms)) {
		t.Fatalf("Query: %v", got)
	}
	for i, e := range es {
		want := ""
		if k := 10 - i; k < 9 {
			want = chunks[k/3].Name
		}
		if e.Chunk != want || e.Seq != 0 {
			t.Fatalf("entry %d (%s): chunk %q seq %d, want %q", i, e.Msg, e.Chunk, e.Seq, want)
		}
		if e.SyslogMessage.Raw != ms[10-i].Raw || *e.Severity != 6 {
			t.Fatalf("entry %d: %+v", i, e)
		}
	}
}

func TestQueryRange(t *testing.T) {
	s, _, ms, _ := layout(t)
	at := func(i int) time.Time { return t0.Add(time.Duration(i) * time.Second) }
	for _, c := range []struct {
		from, to time.Time
		want     []string
	}{
		{at(2), at(5), []string{"m-4", "m-3", "m-2"}}, // from included, to excluded; across two chunks
		{at(4), at(5), []string{"m-4"}},
		{at(9), at(11), []string{"m-10", "m-9"}}, // the open chunk only
		{at(8), at(10), []string{"m-9", "m-8"}},  // open and sealed
		{at(11), at(20), nil},
		{at(-10), at(0), nil},
		{at(3).Add(time.Nanosecond), at(4).Add(time.Nanosecond), []string{"m-4"}},
		{time.Time{}, at(1), []string{"m-0"}},
		{at(10), time.Time{}, []string{"m-10"}}, // a zero to has no end
	} {
		es, truncated, err := s.Query(context.Background(), c.from, c.to, nil, 100)
		if err != nil || truncated || !slices.Equal(entryTexts(es), c.want) && len(es)+len(c.want) > 0 {
			t.Errorf("Query [%v, %v): %v %v %v, want %v", c.from, c.to, entryTexts(es), truncated, err, c.want)
		}
		if es == nil {
			t.Errorf("Query [%v, %v): nil, want an empty list", c.from, c.to)
		}
	}
	// An empty period.
	if es, truncated, err := s.Query(context.Background(), at(5), at(5), nil, 10); err != nil || truncated || es == nil || len(es) != 0 {
		t.Fatalf("empty period: %v %v %v", es, truncated, err)
	}
	_ = ms
}

func TestQueryMatchAndLimit(t *testing.T) {
	s, _, ms, _ := layout(t)
	odd := func(m *model.SyslogMessage) bool {
		return strings.HasSuffix(m.Msg, "1") || strings.HasSuffix(m.Msg, "3") ||
			strings.HasSuffix(m.Msg, "5") || strings.HasSuffix(m.Msg, "7") || strings.HasSuffix(m.Msg, "9")
	}
	ctx := context.Background()
	es, truncated, err := s.Query(ctx, time.Time{}, time.Time{}, odd, 100)
	if err != nil || truncated || !slices.Equal(entryTexts(es), []string{"m-9", "m-7", "m-5", "m-3", "m-1"}) {
		t.Fatalf("match: %v %v %v", entryTexts(es), truncated, err)
	}
	for _, c := range []struct {
		limit     int
		want      int
		truncated bool
	}{{1, 1, true}, {3, 3, true}, {10, 10, true}, {11, 11, false}, {12, 11, false}, {1 << 62, 11, false}} {
		es, truncated, err := s.Query(ctx, time.Time{}, time.Time{}, nil, c.limit)
		if err != nil || len(es) != c.want || truncated != c.truncated || !slices.Equal(entryTexts(es), reversed(ms)[:c.want]) {
			t.Errorf("limit %d: %v %v %v", c.limit, entryTexts(es), truncated, err)
		}
	}
	es, truncated, err = s.Query(ctx, time.Time{}, time.Time{}, odd, 2)
	if err != nil || !truncated || !slices.Equal(entryTexts(es), []string{"m-9", "m-7"}) {
		t.Fatalf("match with limit: %v %v %v", entryTexts(es), truncated, err)
	}
	for _, limit := range []int{0, -1} {
		if _, _, err := s.Query(ctx, time.Time{}, time.Time{}, nil, limit); err == nil {
			t.Errorf("limit %d accepted", limit)
		}
	}
}

func TestQueryStopsReadingOlderChunks(t *testing.T) {
	s, h, _, chunks := layout(t)
	// The oldest chunk's file is damaged after it was indexed.
	writeFile(t, filepath.Join(s.dir, chunks[0].Name), []byte("damaged"))
	es, truncated, err := s.Query(context.Background(), time.Time{}, time.Time{}, nil, 4)
	if err != nil || !truncated || !slices.Equal(entryTexts(es), []string{"m-10", "m-9", "m-8", "m-7"}) {
		t.Fatalf("Query: %v %v %v", entryTexts(es), truncated, err)
	}
	if h.count("cannot be read") != 0 {
		t.Fatalf("an older chunk was read:\n%s", h.all())
	}
	// Reading further finds the damage, says so once, and returns the rest.
	for range 2 {
		es, _, err = s.Query(context.Background(), time.Time{}, time.Time{}, nil, 100)
		if err != nil || len(es) != 8 {
			t.Fatalf("Query: %v %v", entryTexts(es), err)
		}
	}
	if h.count("a chunk cannot be read") != 1 || h.attr("cannot be read", "chunk") != chunks[0].Name {
		t.Fatalf("log:\n%s", h.all())
	}
}

func TestQueryClockSetBack(t *testing.T) {
	// The clock went back an hour while chunk 1 was open, and forward again in chunk 2.
	s, _ := testStore(t, Options{})
	a := []model.SyslogMessage{msg(t0, "a0"), msg(t0.Add(-time.Hour), "a1"), msg(t0.Add(-time.Hour+time.Second), "a2")}
	b := []model.SyslogMessage{msg(t0.Add(-30*time.Minute), "b0"), msg(t0.Add(time.Minute), "b1")}
	fill(t, s, a, 3)
	fill(t, s, b, 2)
	if _, err := s.Append([]model.SyslogMessage{msg(t0.Add(-2*time.Hour), "c0")}, 0, 0, t0); err != nil {
		t.Fatal(err)
	}
	// Newest first by receive time, whatever the chunk.
	if got := entryTexts(queryAll(t, s)); !slices.Equal(got, []string{"b1", "a0", "b0", "a2", "a1", "c0"}) {
		t.Fatalf("Query: %v", got)
	}
	// a1 lies outside its chunk's From-To (a0 to a2) and is found.
	es, _, err := s.Query(context.Background(), t0.Add(-61*time.Minute), t0.Add(-59*time.Minute), nil, 10)
	if err != nil || !slices.Equal(entryTexts(es), []string{"a2", "a1"}) {
		t.Fatalf("Query: %v %v", entryTexts(es), err)
	}
	// The limit is applied by receive time too.
	es, truncated, err := s.Query(context.Background(), time.Time{}, time.Time{}, nil, 2)
	if err != nil || !truncated || !slices.Equal(entryTexts(es), []string{"b1", "a0"}) {
		t.Fatalf("Query: %v %v %v", entryTexts(es), truncated, err)
	}
}

func TestQuerySameReceiveTime(t *testing.T) {
	// A clock that stands still: the latest stored comes first, across chunks.
	ms := make([]model.SyslogMessage, 7)
	for i := range ms {
		ms[i] = msg(t0, "s-"+string(rune('a'+i)))
	}
	lineLen := int64(len(lineOf(t, ms[0])))
	s, _ := testStore(t, Options{ChunkBytes: 3 * lineLen})
	if sealed, err := s.Append(ms, 0, 0, t0); err != nil || len(sealed) != 2 {
		t.Fatalf("Append: %d %v", len(sealed), err)
	}
	if got := entryTexts(queryAll(t, s)); !slices.Equal(got, reversed(ms)) {
		t.Fatalf("Query: %v", got)
	}
	es, truncated, err := s.Query(context.Background(), time.Time{}, time.Time{}, nil, 4)
	if err != nil || !truncated || !slices.Equal(entryTexts(es), reversed(ms)[:4]) {
		t.Fatalf("Query: %v %v %v", entryTexts(es), truncated, err)
	}
}

func TestQueryContext(t *testing.T) {
	s, _, _, _ := layout(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := s.Query(ctx, time.Time{}, time.Time{}, nil, 10); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled: %v", err)
	}
	// Canceled while reading: noticed before the next chunk.
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	seen := 0
	_, _, err := s.Query(ctx, time.Time{}, time.Time{}, func(*model.SyslogMessage) bool {
		seen++
		cancel()
		return true
	}, 100)
	if !errors.Is(err, context.Canceled) || seen > 3 {
		t.Fatalf("canceled while reading: %v after %d messages", err, seen)
	}
}

func TestQueryLongChunkChecksContext(t *testing.T) {
	s, _ := testStore(t, Options{})
	fill(t, s, msgs(t0, ctxEvery+10, "m"), ctxEvery+10)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	seen := 0
	_, _, err := s.Query(ctx, time.Time{}, time.Time{}, func(*model.SyslogMessage) bool {
		if seen++; seen == 10 {
			cancel()
		}
		return true
	}, 1<<20)
	if !errors.Is(err, context.Canceled) || seen >= ctxEvery+10 {
		t.Fatalf("Query: %v after %d messages", err, seen)
	}
}

func TestQueryChangedChunk(t *testing.T) {
	s, h, ms, chunks := layout(t)
	// Someone replaced a chunk's content: Query shows what the file holds, and says so.
	changed := bytes.ReplaceAll(content(t, s.dir, chunks[1].Name), []byte("m-4"), []byte("X-4"))
	writeFile(t, filepath.Join(s.dir, chunks[1].Name), gzipBytes(t, changed))
	got := entryTexts(queryAll(t, s))
	want := reversed(ms)
	want[6] = "X-4"
	if !slices.Equal(got, want) {
		t.Fatalf("Query: %v", got)
	}
	if h.count("does not hold what it was sealed with") != 1 || h.attr("sealed with", "chunk") != chunks[1].Name {
		t.Fatalf("log:\n%s", h.all())
	}
}

func TestQueryMissingChunkFile(t *testing.T) {
	s, h, ms, chunks := layout(t)
	if err := os.Remove(filepath.Join(s.dir, chunks[2].Name)); err != nil {
		t.Fatal(err)
	}
	got := entryTexts(queryAll(t, s))
	if want := append(reversed(ms)[:2], reversed(ms)[5:]...); !slices.Equal(got, want) {
		t.Fatalf("Query: %v, want %v", got, want)
	}
	if h.count("a chunk cannot be read") != 1 {
		t.Fatalf("log:\n%s", h.all())
	}
	if _, err := s.OpenChunk(chunks[2].Name); !errors.Is(err, contracts.ErrNotFound) {
		t.Fatalf("OpenChunk: %v", err)
	}
}

func TestOpenChunk(t *testing.T) {
	s, _, _, chunks := layout(t)
	for _, c := range chunks {
		r, err := s.OpenChunk(c.Name)
		if err != nil {
			t.Fatal(err)
		}
		b, err := io.ReadAll(r)
		if cerr := r.Close(); err != nil || cerr != nil {
			t.Fatalf("read %s: %v %v", c.Name, err, cerr)
		}
		if !bytes.Equal(b, readFile(t, filepath.Join(s.dir, c.Name))) || int64(len(b)) != c.GzBytes || sha(gunzip(t, b)) != c.SHA256 {
			t.Fatalf("OpenChunk(%s) returned other bytes", c.Name)
		}
	}
	open := openFiles(t, s.dir)[0]
	writeFile(t, filepath.Join(s.dir, "x.jsonl.gz"), []byte("x"))
	for _, name := range []string{
		"", ".", "..", open, chunks[0].Name + sidecarExt, "x.jsonl.gz",
		"../" + chunks[0].Name, `..\` + chunks[0].Name, "./" + chunks[0].Name, `sub\` + chunks[0].Name,
		filepath.Join(s.dir, chunks[0].Name), chunks[0].Name + ":stream", strings.ToUpper(chunks[0].Name),
		sealedName(t0.Add(time.Hour), t0.Add(time.Hour), 1), // well formed, but not in the store
		strings.Replace(chunks[0].Name, ".jsonl.gz", "-2.jsonl.gz", 1),
	} {
		if r, err := s.OpenChunk(name); !errors.Is(err, contracts.ErrNotFound) {
			if r != nil {
				r.Close()
			}
			t.Errorf("OpenChunk(%q): %v", name, err)
		}
	}
}
