package mongostore

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"attmonitor/internal/contracts"
	"attmonitor/internal/model"
)

// Tests of the syslog documents, chunks and the follower's queue that need no MongoDB, and the
// syslog store they share with the live tests.

// ---------------------------------------------------------------- an in-memory syslog store

// memSyslog is a contracts.SyslogReader over gzip chunks held in memory; OpenChunk fails on
// demand and counts its calls.
type memSyslog struct {
	mu     sync.Mutex
	chunks map[string][]byte // name -> the exact stored bytes (gzip)
	fail   map[string]error  // name ("" = every chunk) -> the error OpenChunk returns
	opens  map[string]int
	keepMB int // the limit Usage reports (0: none)
}

var _ contracts.SyslogReader = (*memSyslog)(nil)

func newMemSyslog() *memSyslog {
	return &memSyslog{chunks: map[string][]byte{}, fail: map[string]error{}, opens: map[string]int{}}
}

func (m *memSyslog) Query(context.Context, time.Time, time.Time, func(*model.SyslogMessage) bool, int) ([]model.SyslogEntry, bool, error) {
	return nil, false, nil
}

func (m *memSyslog) Usage() model.SyslogUsage {
	m.mu.Lock()
	defer m.mu.Unlock()
	return model.SyslogUsage{KeepMB: m.keepMB}
}

// setKeepMB sets the limit Usage reports (syslog.keep_mb).
func (m *memSyslog) setKeepMB(mb int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.keepMB = mb
}

func (m *memSyslog) OpenChunk(name string) (io.ReadCloser, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.opens[name]++
	if err, ok := m.fail[name]; ok {
		return nil, err
	}
	if err, ok := m.fail[""]; ok {
		return nil, err
	}
	b, ok := m.chunks[name]
	if !ok {
		return nil, fmt.Errorf("syslog store: chunk %s: %w", name, contracts.ErrNotFound)
	}
	return io.NopCloser(bytes.NewReader(b)), nil
}

func (m *memSyslog) put(name string, gz []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.chunks[name] = gz
}

func (m *memSyslog) remove(name string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.chunks, name)
}

// setFail makes OpenChunk(name) fail with err ("" = every chunk; nil: no longer).
func (m *memSyslog) setFail(name string, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err == nil {
		delete(m.fail, name)
		return
	}
	m.fail[name] = err
}

// get returns the stored bytes of a chunk.
func (m *memSyslog) get(name string) []byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.chunks[name]
}

// opensOf returns the OpenChunk calls for a chunk.
func (m *memSyslog) opensOf(name string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.opens[name]
}

func (m *memSyslog) openCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, c := range m.opens {
		n += c
	}
	return n
}

// ---------------------------------------------------------------- chunks built like the store

func gzipBytes(t testing.TB, b []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(b); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// chunkOf builds a chunk as the syslog store seals it: its lines, each ending in a line feed,
// compressed with gzip, and the payload of its syslog_chunk record.
func chunkOf(t testing.TB, name string, lines ...[]byte) (model.SyslogChunk, []byte) {
	t.Helper()
	var content []byte
	for _, l := range lines {
		content = append(append(content, l...), '\n')
	}
	gz := gzipBytes(t, content)
	return model.SyslogChunk{Name: name, From: "2026-10-05T03:20:01Z", To: "2026-10-05T03:24:59Z", Messages: len(lines),
		Bytes: int64(len(content)), SHA256: sha256Hex(content), GzBytes: int64(len(gz)), Reason: "age"}, gz
}

// syslogMsg is a message as the receiver records a firewall drop of the gateway.
func syslogMsg(rx time.Time, text string) model.SyslogMessage {
	pri, facility, severity := 134, 16, 6
	return model.SyslogMessage{
		RX: rx.UTC().Format(time.RFC3339Nano), Src: "192.168.1.254:514",
		Raw: "<134>Oct  5 03:20:01 dsldevice kernel: " + text, Format: "rfc3164",
		PRI: &pri, Facility: &facility, Severity: &severity, TS: "Oct  5 03:20:01", Host: "dsldevice", App: "kernel", Msg: text,
	}
}

// msgLines returns n message lines (JSON, as the store writes them).
func msgLines(t testing.TB, from time.Time, n int, text string) [][]byte {
	t.Helper()
	lines := make([][]byte, n)
	for i := range lines {
		lines[i] = marshalNoEscape(t, syslogMsg(from.Add(time.Duration(i)*time.Second), fmt.Sprintf("%s %d", text, i)))
	}
	return lines
}

var syslogT0 = time.Date(2026, 10, 5, 3, 20, 1, 123456789, time.UTC)

// ---------------------------------------------------------------- documents

func TestSyslogDocDecoded(t *testing.T) {
	m := syslogMsg(syslogT0, `[FW] DROP <b>"x"</b> & é 😀 `+"\x1b[2K‮")
	for _, raw := range [][]byte{marshalNoEscape(t, m), mustJSON(t, m)} { // with and without HTML escaping
		doc, err := syslogDoc("syslog-20261005T032001Z-0001.jsonl.gz", 77, 3, raw)
		if err != nil {
			t.Fatal(err)
		}
		var keys []string
		elems, _ := doc.Elements()
		for _, e := range elems {
			keys = append(keys, e.Key())
		}
		// No msg: raw_line holds the message's text already.
		want := []string{"_id", "chunk", "chunk_seq", "line", "raw_line", "rx", "rx_text", "src", "severity", "facility", "host", "app", "copy_format"}
		if !slices.Equal(keys, want) {
			t.Fatalf("fields %v, want %v", keys, want)
		}
		if id, _ := rawString(doc, "_id"); id != "syslog-20261005T032001Z-0001.jsonl.gz#3" {
			t.Errorf("_id %q", id)
		}
		if n, ok := doc.Lookup("chunk_seq").Int64OK(); !ok || n != 77 {
			t.Errorf("chunk_seq %v", doc.Lookup("chunk_seq"))
		}
		if n, ok := doc.Lookup("line").Int64OK(); !ok || n != 3 {
			t.Errorf("line %v", doc.Lookup("line"))
		}
		if got, _ := rawString(doc, "raw_line"); got != string(raw) {
			t.Errorf("raw_line %q", got)
		}
		if ms, ok := doc.Lookup("rx").DateTimeOK(); !ok || ms != syslogT0.UnixMilli() {
			t.Errorf("rx %v", doc.Lookup("rx"))
		}
		for key, want := range map[string]string{"rx_text": m.RX, "src": m.Src, "host": "dsldevice", "app": "kernel"} {
			if got, _ := rawString(doc, key); got != want {
				t.Errorf("%s = %q, want %q", key, got, want)
			}
		}
		if n, ok := doc.Lookup("severity").Int64OK(); !ok || n != 6 {
			t.Errorf("severity %v", doc.Lookup("severity"))
		}
		if n, ok := doc.Lookup("facility").Int64OK(); !ok || n != 16 {
			t.Errorf("facility %v", doc.Lookup("facility"))
		}
		if n, ok := doc.Lookup("copy_format").Int32OK(); !ok || n != copyFormat {
			t.Errorf("copy_format %v", doc.Lookup("copy_format"))
		}
		again, err := syslogDoc("syslog-20261005T032001Z-0001.jsonl.gz", 77, 3, raw)
		if err != nil || !bytes.Equal(doc, again) {
			t.Error("the document is not deterministic")
		}
	}
}

func mustJSON(t testing.TB, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestSyslogDocOptionalFields(t *testing.T) {
	// A datagram that is not syslog: nothing parsed but the receive time and the sender; and a
	// receive time that is no RFC 3339 time.
	raw := marshalNoEscape(t, model.SyslogMessage{RX: "yesterday", Src: "192.168.1.254:40000", RawB64: "/w==", Format: "unknown"})
	doc, err := syslogDoc("c", 1, 1, raw)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"rx", "severity", "facility", "host", "app", "msg", "undecoded", "note"} {
		if _, err := doc.LookupErr(key); err == nil {
			t.Errorf("field %s present: %v", key, doc.Lookup(key))
		}
	}
	if got, _ := rawString(doc, "rx_text"); got != "yesterday" {
		t.Errorf("rx_text %q", got)
	}
	if got, _ := rawString(doc, "src"); got != "192.168.1.254:40000" {
		t.Errorf("src %q", got)
	}
	// Severity 0 (emergency) is a value, not an absent one.
	zero := 0
	raw = marshalNoEscape(t, model.SyslogMessage{RX: syslogT0.Format(time.RFC3339Nano), Src: "x", Severity: &zero, Facility: &zero})
	doc, err = syslogDoc("c", 1, 1, raw)
	if err != nil {
		t.Fatal(err)
	}
	if n, ok := doc.Lookup("severity").Int64OK(); !ok || n != 0 {
		t.Errorf("severity %v", doc.Lookup("severity"))
	}
}

func TestSyslogDocUndecoded(t *testing.T) {
	for _, raw := range []string{
		"not json",
		"",
		"[1,2]",
		`"a string"`,
		"null",
		`{"rx":5,"src":"x"}`,                  // a field of another type
		`{"rx":"x","src":"y"} extra`,          // more after the object
		`{"rx":"x"`,                           // unterminated
		"{\"rx\":\"\xff\xfe\",\"src\":\"x\"}", // not valid UTF-8
		"\xff\xfe\x00raw bytes",
	} {
		doc, err := syslogDoc("c", 9, 2, []byte(raw))
		if err != nil {
			t.Fatalf("%q: %v", raw, err)
		}
		if b, ok := doc.Lookup("undecoded").BooleanOK(); !ok || !b {
			t.Errorf("%q: undecoded %v", raw, doc.Lookup("undecoded"))
		}
		if note, _ := rawString(doc, "note"); note != noteSyslogUndecoded {
			t.Errorf("%q: note %q", raw, note)
		}
		for _, key := range []string{"rx", "rx_text", "src", "msg"} {
			if _, err := doc.LookupErr(key); err == nil {
				t.Errorf("%q: field %s present", raw, key)
			}
		}
		got, ok := rawLine(doc)
		if !ok || string(got) != raw {
			t.Errorf("%q: raw_line %v", raw, doc.Lookup("raw_line"))
		}
		if _, isString := doc.Lookup("raw_line").StringValueOK(); isString != utf8.ValidString(raw) {
			t.Errorf("%q: raw_line of type %v", raw, doc.Lookup("raw_line").Type)
		}
	}
}

// ---------------------------------------------------------------- chunks

func TestChunkLines(t *testing.T) {
	for in, want := range map[string][]string{
		"":          nil,
		"a\n":       {"a"},
		"a\n\nb\n":  {"a", "", "b"},
		"a\nb":      {"a", "b"},
		"\n":        {""},
		"x\r\ny\n":  {"x\r", "y"},
		"tail only": {"tail only"},
	} {
		var got []string
		for _, l := range chunkLines([]byte(in)) {
			got = append(got, string(l))
		}
		if !slices.Equal(got, want) {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
}

func TestReadChunk(t *testing.T) {
	store := newMemSyslog()
	lines := msgLines(t, syslogT0, 3, "drop")
	c, gz := chunkOf(t, "a", lines...)
	store.put("a", gz)
	got, err := readChunk(store, &c)
	if err != nil || len(got) != 3 || !bytes.Equal(got[2], lines[2]) {
		t.Fatalf("readChunk = %q, %v", got, err)
	}

	// Not in the store: ErrNotFound. Another error: neither ErrNotFound nor a chunkError.
	missing := c
	missing.Name = "gone"
	if _, err := readChunk(store, &missing); !errors.Is(err, contracts.ErrNotFound) {
		t.Errorf("missing chunk: %v", err)
	}
	store.setFail("a", errors.New("sharing violation"))
	var ce *chunkError
	if _, err := readChunk(store, &c); err == nil || errors.Is(err, contracts.ErrNotFound) || errors.As(err, &ce) {
		t.Errorf("transient error: %v", err)
	}
	store.setFail("a", nil)

	content := []byte{}
	for _, l := range lines {
		content = append(append(content, l...), '\n')
	}
	altered := bytes.Replace(content, []byte("drop 1"), []byte("drop X"), 1)
	bad := func(name string, gz []byte, mod func(*model.SyslogChunk), want string) {
		t.Helper()
		cc := c
		cc.Name = name
		if mod != nil {
			mod(&cc)
		}
		store.put(name, gz)
		_, err := readChunk(store, &cc)
		var ce *chunkError
		if !errors.As(err, &ce) || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v, want a chunk error with %q", name, err, want)
		}
	}
	bad("altered", gzipBytes(t, altered), nil, "its SHA-256 is")
	bad("longer", gzipBytes(t, append(append([]byte{}, content...), "x\n"...)), nil, "more than the")
	bad("shorter", gzipBytes(t, content[:len(content)-1]), nil, "bytes, its record gives")
	bad("truncated", gz[:len(gz)-6], nil, "not a complete gzip stream")
	bad("garbage", []byte("this is not gzip"), nil, "not a complete gzip stream")
	bad("empty file", nil, nil, "not a complete gzip stream")
	corrupt := bytes.Clone(gz)
	corrupt[len(corrupt)-5] ^= 0xff // the CRC-32 of the trailer
	bad("checksum", corrupt, nil, "not a complete gzip stream")
	bad("count", gz, func(cc *model.SyslogChunk) { cc.Messages = 4 }, "it holds 3 lines, its record gives 4 messages")
	noLF := content[:len(content)-1]
	bad("no line feed", gzipBytes(t, noLF), func(cc *model.SyslogChunk) { cc.Bytes, cc.SHA256 = int64(len(noLF)), sha256Hex(noLF) }, "does not end with a line feed")
	bad("huge", gz, func(cc *model.SyslogChunk) { cc.Bytes = maxSyslogChunkBytes + 1 }, "its record gives a size of")
	long := append(bytes.Repeat([]byte("x"), maxSyslogLineBytes+1), '\n')
	bad("long line", gzipBytes(t, long), func(cc *model.SyslogChunk) {
		cc.Bytes, cc.SHA256, cc.Messages = int64(len(long)), sha256Hex(long), 1
	}, "at most 4194304 fit a document")
}

// ---------------------------------------------------------------- syslog records

func syslogItem(t testing.TB, seq uint64, typ string, data any) item {
	t.Helper()
	return item{body: model.Body{Seq: seq, Type: typ, Data: dataOf(t, data)}}
}

func TestSyslogOpOf(t *testing.T) {
	c, _ := chunkOf(t, "a", []byte("{}"))
	op, ok := syslogOpOf(syslogItem(t, 5, model.TypeSyslogChunk, c))
	if !ok || op.seq != 5 || op.chunk == nil || *op.chunk != c || op.bad != "" {
		t.Fatalf("chunk record: %+v", op)
	}
	for _, data := range []any{json.RawMessage(`[1]`), json.RawMessage(`null`), model.SyslogChunk{Name: ""}, model.SyslogChunk{Name: strings.Repeat("n", 1025)}} {
		if op, ok := syslogOpOf(syslogItem(t, 6, model.TypeSyslogChunk, data)); !ok || op.bad == "" || op.chunk != nil {
			t.Errorf("chunk record %s: %+v", dataOf(t, data), op)
		}
	}
	p := model.SyslogPrune{Reason: "keep_mb 1", KeepMB: 1, Deleted: []model.SyslogChunkRef{{Name: "a"}, {Name: "b"}, {Name: "a"}}}
	if op, ok := syslogOpOf(syslogItem(t, 7, model.TypeSyslogPrune, p)); !ok || !slices.Equal(op.prune, []string{"a", "b"}) || op.bad != "" {
		t.Errorf("prune record: %+v", op)
	}
	if op, ok := syslogOpOf(syslogItem(t, 8, model.TypeSyslogPrune, json.RawMessage(`"x"`))); !ok || op.bad == "" {
		t.Errorf("bad prune record: %+v", op)
	}
	for _, typ := range []string{model.TypeSample, "syslog", model.TypeGatewayEvent} { // "syslog": the type of the abandoned first design
		if _, ok := syslogOpOf(syslogItem(t, 9, typ, c)); ok {
			t.Errorf("%s taken for a syslog record", typ)
		}
	}
}

// TestSyslogStateFeed: the queue holds every syslog record below upTo that is not applied; a batch
// after a gap is left to the scan of the ledger, and a full queue stops at the first record it
// cannot hold.
func TestSyslogStateFeed(t *testing.T) {
	c, _ := chunkOf(t, "a", []byte("{}"))
	batch := func(from, to uint64, syslogAt ...uint64) []item {
		var out []item
		for seq := from; seq <= to; seq++ {
			typ := model.TypeSample
			if slices.Contains(syslogAt, seq) {
				typ = model.TypeSyslogChunk
			}
			out = append(out, syslogItem(t, seq, typ, c))
		}
		return out
	}
	s := &syslogState{}
	s.restart("uuid")
	s.feed(batch(0, 9, 3, 7))
	if s.upTo != 10 || len(s.ops) != 2 || s.ops[0].seq != 3 || s.applied() != 2 {
		t.Fatalf("after 0-9: upTo %d, %d ops, applied %d", s.upTo, len(s.ops), s.applied())
	}
	s.feed(batch(5, 12, 7, 11)) // a batch copied again: only what is new is queued
	if s.upTo != 13 || len(s.ops) != 3 || s.ops[2].seq != 11 {
		t.Fatalf("after 5-12: upTo %d, ops %d", s.upTo, len(s.ops))
	}
	s.ops = nil
	if s.applied() != 12 {
		t.Fatalf("applied %d with nothing queued", s.applied())
	}
	s.feed(batch(20, 25, 21)) // a gap: 13-19 are read from the ledger later
	if s.upTo != 13 || len(s.ops) != 0 {
		t.Fatalf("after a gap: upTo %d, %d ops", s.upTo, len(s.ops))
	}
	// A full queue: the records it cannot hold wait for the scan.
	all := make([]uint64, 0, syslogMaxQueue+10)
	for seq := uint64(13); seq < 13+syslogMaxQueue+10; seq++ {
		all = append(all, seq)
	}
	s.feed(batch(13, 13+syslogMaxQueue+9, all...))
	if len(s.ops) != syslogMaxQueue || s.upTo != 13+syslogMaxQueue || s.applied() != 12 {
		t.Fatalf("full queue: %d ops, upTo %d, applied %d", len(s.ops), s.upTo, s.applied())
	}
	// The collection the follower writes to.
	s.resume(0, "")
	s.noteCollection("new")
	if s.coll != "new" || s.resetWhy != "" {
		t.Fatalf("a collection that appeared: %+v", s)
	}
	s.noteCollection("other")
	if s.resetWhy == "" {
		t.Fatal("a replaced collection was not noticed")
	}
}

func TestLineGaps(t *testing.T) {
	ls := func(ns ...int64) []syslogLine {
		var out []syslogLine
		for _, n := range ns {
			out = append(out, syslogLine{n: n})
		}
		return out
	}
	m, r, b := lineGaps(ls(1, 2, 3), 3)
	if m.n+r.n+b.n != 0 {
		t.Fatalf("complete: %v %v %v", m, r, b)
	}
	m, r, b = lineGaps(ls(2, 2, 5, 9, 12), 10)
	if m.String() != "1, 3-4, 6-8, 10" || m.n != 7 || r.String() != "2" || b.String() != "12" {
		t.Fatalf("missing %q (%d), repeated %q, beyond %q", m, m.n, r, b)
	}
	m, _, _ = lineGaps(nil, 3)
	if m.String() != "1-3" || m.n != 3 {
		t.Fatalf("no lines: %q", m)
	}
	var many numList
	for i := int64(1); i < 30; i += 2 {
		many.add(i)
	}
	if many.String() != "1, 3, 5, 7, 9, …" || many.n != 15 {
		t.Fatalf("many: %q (%d)", many, many.n)
	}
}

func TestTransientWriteCode(t *testing.T) {
	for _, code := range []int{112, 10107, 11600, 11602, 189, 14031} {
		if !transientWriteCode(code) {
			t.Errorf("code %d: not transient", code)
		}
	}
	for _, code := range []int{121, 2, 10334, 11000, 0} { // validation, bad value, too large, duplicate key
		if transientWriteCode(code) {
			t.Errorf("code %d: transient", code)
		}
	}
}

func TestVerifyWithNeedsAReader(t *testing.T) {
	if _, err := VerifyWith(context.Background(), VerifyOptions{Syslog: newMemSyslog()}); err == nil {
		t.Error("VerifyWith without a ledger reader")
	}
}

// TestSyncOnceUnreachableWithSyslog: the syslog store changes nothing while MongoDB is unreachable.
func TestSyncOnceUnreachableWithSyslog(t *testing.T) {
	o := unreachableOptions(t, &countingHandler{})
	store := newMemSyslog()
	o.Syslog = store
	r := newReplicator(t, o)
	var ue *unreachableError
	if _, err := r.SyncOnce(context.Background()); !errors.As(err, &ue) {
		t.Fatalf("SyncOnce: %v", err)
	}
	if st := r.Status(); strings.Contains(st.LastError, "syslog") || r.SyslogDocuments() != 0 || store.openCount() != 0 {
		t.Fatalf("status %+v", st)
	}
}
