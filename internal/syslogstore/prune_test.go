package syslogstore

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"attmonitor/internal/contracts"
	"attmonitor/internal/model"
)

const mib = 1 << 20

// bigChunks seals chunks of random messages (2 KiB each, per chunk) into s until they take
// more than total bytes, and returns them oldest first.
func bigChunks(t *testing.T, s *Store, start time.Time, total int64, per int) []model.SyslogChunk {
	t.Helper()
	var out []model.SyslogChunk
	var sum int64
	for i := 0; sum <= total; i++ {
		c := fill(t, s, randomMsgs(t, start.Add(time.Duration(i)*time.Hour), per, 2048), per)
		out = append(out, c...)
		for _, x := range c {
			sum += x.GzBytes
		}
	}
	return out
}

// wantPruned returns the chunks a size limit of limit bytes deletes, oldest first, given the
// open chunk's size.
func wantPruned(chunks []model.SyslogChunk, open, limit int64) []model.SyslogChunk {
	kept := open
	for _, c := range chunks {
		kept += c.GzBytes
	}
	var out []model.SyslogChunk
	for _, c := range chunks {
		if kept <= limit {
			break
		}
		out = append(out, c)
		kept -= c.GzBytes
	}
	return out
}

func refOf(c model.SyslogChunk) model.SyslogChunkRef {
	return model.SyslogChunkRef{Name: c.Name, SHA256: c.SHA256, From: c.From, To: c.To, Messages: c.Messages, GzBytes: c.GzBytes}
}

func refsOf(cs []model.SyslogChunk) []model.SyslogChunkRef {
	out := make([]model.SyslogChunkRef, len(cs))
	for i, c := range cs {
		out[i] = refOf(c)
	}
	return out
}

func TestPruneBySize(t *testing.T) {
	s, _ := testStore(t, Options{KeepMB: 1})
	chunks := bigChunks(t, s, t0, 3*mib/2, 20)
	want := wantPruned(chunks, 0, mib)
	if len(want) == 0 || len(want) == len(chunks) {
		t.Fatalf("test setup: %d of %d chunks to prune", len(want), len(chunks))
	}
	refs, err := s.Prune(t0)
	if err != nil || !slices.Equal(refs, refsOf(want)) {
		t.Fatalf("Prune returned %+v, %v\nwant %+v", refs, err, refsOf(want))
	}
	u := s.Usage()
	if u.Bytes > mib || u.Bytes+want[len(want)-1].GzBytes <= mib || u.Chunks != len(chunks)-len(want) {
		t.Fatalf("Usage after Prune: %+v (deleted %d)", u, len(want))
	}
	for _, c := range want {
		for _, p := range []string{c.Name, c.Name + sidecarExt} {
			if _, err := os.Stat(filepath.Join(s.dir, p)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("%s still exists: %v", p, err)
			}
		}
		if _, err := s.OpenChunk(c.Name); !errors.Is(err, contracts.ErrNotFound) {
			t.Fatalf("OpenChunk of a deleted chunk: %v", err)
		}
	}
	for _, c := range chunks[len(want):] {
		checkChunk(t, s.dir, c, content(t, s.dir, c.Name))
	}
	// The oldest message kept is the first of the oldest chunk kept.
	if es := queryAll(t, s); es[len(es)-1].RX != chunks[len(want)].From || u.Oldest != chunks[len(want)].From {
		t.Fatalf("oldest kept %s (Usage %s), want %s", es[len(es)-1].RX, u.Oldest, chunks[len(want)].From)
	}
	if refs, err := s.Prune(t0); err != nil || len(refs) != 0 {
		t.Fatalf("second Prune: %+v %v", refs, err)
	}
	// A larger limit deletes nothing; a smaller one, applied at once, deletes more.
	s.SetRetention(100, 0)
	if refs, err := s.Prune(t0); err != nil || len(refs) != 0 {
		t.Fatalf("Prune at 100 MiB: %+v %v", refs, err)
	}
}

func TestPruneNeverTheOpenChunk(t *testing.T) {
	s, _ := testStore(t, Options{KeepMB: 1, ChunkBytes: 8 * mib})
	small := fill(t, s, msgs(t0, 4, "m"), 2)
	open := randomMsgs(t, t0.Add(time.Hour), 600, 2048) // more than 1 MiB, still open
	if sealed, err := s.Append(open, 0, 0, t0); err != nil || len(sealed) != 0 {
		t.Fatalf("Append: %v %v", sealed, err)
	}
	refs, err := s.Prune(t0)
	if err != nil || !slices.Equal(refs, refsOf(small)) {
		t.Fatalf("Prune: %+v %v", refs, err)
	}
	if u := s.Usage(); u.Chunks != 0 || u.OpenMessages != 600 || u.Bytes <= mib {
		t.Fatalf("Usage: %+v", u)
	}
	if got := queryAll(t, s); len(got) != 600 {
		t.Fatalf("Query: %d messages", len(got))
	}
}

func TestPruneByDays(t *testing.T) {
	s, _ := testStore(t, Options{KeepDays: 2})
	day := 24 * time.Hour
	var chunks []model.SyslogChunk
	for _, at := range []time.Time{t0.Add(-5 * day), t0.Add(-3 * day), t0.Add(-2 * day), t0.Add(-time.Hour)} {
		chunks = append(chunks, fill(t, s, msgs(at, 2, "m"), 2)...)
	}
	// The third chunk's last message is a second younger than two days.
	refs, err := s.Prune(t0)
	if err != nil || !slices.Equal(refs, refsOf(chunks[:2])) {
		t.Fatalf("Prune: %+v %v", refs, err)
	}
	refs, err = s.Prune(t0.Add(time.Second + time.Nanosecond))
	if err != nil || !slices.Equal(refs, refsOf(chunks[2:3])) {
		t.Fatalf("Prune a little later: %+v %v", refs, err)
	}
	if u := s.Usage(); u.Chunks != 1 || u.KeepDays != 2 {
		t.Fatalf("Usage: %+v", u)
	}
	// Without an age limit, nothing more goes.
	s.SetRetention(100, 0)
	if refs, err := s.Prune(t0.Add(1000 * day)); err != nil || len(refs) != 0 {
		t.Fatalf("Prune without an age limit: %+v %v", refs, err)
	}
}

func TestPruneByDaysUsesLatestReceiveTime(t *testing.T) {
	// The clock was set back while the chunk was open: its To is old, its newest message is not.
	s, _ := testStore(t, Options{KeepDays: 1})
	day := 24 * time.Hour
	ms := []model.SyslogMessage{msg(t0.Add(-time.Hour), "a"), msg(t0.Add(-10*day), "b")}
	chunks := fill(t, s, ms, 2)
	if chunks[0].To != ms[1].RX {
		t.Fatalf("To %s", chunks[0].To)
	}
	if refs, err := s.Prune(t0); err != nil || len(refs) != 0 {
		t.Fatalf("Prune: %+v %v", refs, err)
	}
	if refs, err := s.Prune(t0.Add(2 * day)); err != nil || len(refs) != 1 {
		t.Fatalf("Prune later: %+v %v", refs, err)
	}
}

func TestPruneWaitsForReaders(t *testing.T) {
	s, h := testStore(t, Options{KeepMB: 1})
	chunks := bigChunks(t, s, t0, 3*mib/2, 20)
	want := wantPruned(chunks, 0, mib)
	if len(want) < 2 {
		t.Fatalf("test setup: %d chunks to prune", len(want))
	}
	// A reader has the oldest chunk open (OpenChunk), Query is reading the second.
	r, err := s.OpenChunk(want[0].Name)
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	second := s.byName[want[1].Name]
	s.mu.Unlock()
	if !s.acquire(second) {
		t.Fatal("acquire failed")
	}
	refs, err := s.Prune(t0)
	// The two are not deleted, and no newer chunk is deleted in their place.
	if err != nil || !slices.Equal(refs, refsOf(want[2:])) {
		t.Fatalf("Prune with readers: %+v %v\nwant %+v", refs, err, refsOf(want[2:]))
	}
	if h.count("are being read; they are deleted later") != 1 {
		t.Fatalf("not logged:\n%s", h.all())
	}
	// They are still there and readable.
	b := make([]byte, 10)
	if n, err := r.Read(b); err != nil || n != 10 {
		t.Fatalf("Read: %d %v", n, err)
	}
	if u := s.Usage(); u.Chunks != len(chunks)-len(want)+2 {
		t.Fatalf("Usage: %+v", u)
	}
	s.release(second)
	refs, err = s.Prune(t0)
	if err != nil || !slices.Equal(refs, refsOf(want[1:2])) {
		t.Fatalf("Prune after Query: %+v %v", refs, err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if err := r.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	refs, err = s.Prune(t0)
	if err != nil || !slices.Equal(refs, refsOf(want[:1])) {
		t.Fatalf("Prune after Close: %+v %v", refs, err)
	}
	if u := s.Usage(); u.Bytes > mib {
		t.Fatalf("Usage: %+v", u)
	}
}

func TestPruneCountsTheOpenChunk(t *testing.T) {
	s, _ := testStore(t, Options{KeepMB: 1, ChunkBytes: 8 * mib})
	chunks := bigChunks(t, s, t0, mib/2, 20)
	open := randomMsgs(t, t0.Add(1000*time.Hour), 150, 2048)
	if _, err := s.Append(open, 0, 0, t0); err != nil {
		t.Fatal(err)
	}
	openSize := s.Usage().Bytes
	for _, c := range chunks {
		openSize -= c.GzBytes
	}
	want := wantPruned(chunks, openSize, mib)
	if len(want) == 0 {
		t.Fatalf("test setup: nothing to prune (open chunk %d bytes)", openSize)
	}
	refs, err := s.Prune(t0)
	if err != nil || !slices.Equal(refs, refsOf(want)) {
		t.Fatalf("Prune: %+v %v\nwant %+v", refs, err, refsOf(want))
	}
}
