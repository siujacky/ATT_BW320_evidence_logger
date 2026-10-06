package syslogstore

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"attmonitor/internal/model"
)

// t0 is the tests' base time.
var t0 = time.Date(2026, 10, 5, 22, 15, 0, 123456789, time.UTC)

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

// count returns how many records contain sub in their message.
func (h *captureHandler) count(sub string) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	n := 0
	for _, r := range h.recs {
		if strings.Contains(r.Message, sub) {
			n++
		}
	}
	return n
}

// attr returns the value of key in the last record whose message contains sub ("" if absent).
func (h *captureHandler) attr(sub, key string) string {
	h.mu.Lock()
	defer h.mu.Unlock()
	v := ""
	for _, r := range h.recs {
		if !strings.Contains(r.Message, sub) {
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
func (h *captureHandler) all() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	var b strings.Builder
	for _, r := range h.recs {
		b.WriteString(r.Level.String() + " " + r.Message)
		r.Attrs(func(a slog.Attr) bool {
			b.WriteString(" " + a.String())
			return true
		})
		b.WriteString("\n")
	}
	return b.String()
}

// ---------------------------------------------------------------- stores

// testStore opens a writer store in a new directory (or in o.Dir) with a captured log and
// closes it when the test ends.
func testStore(t *testing.T, o Options) (*Store, *captureHandler) {
	t.Helper()
	if o.Dir == "" {
		o.Dir = t.TempDir()
	}
	h := &captureHandler{}
	if o.Logger == nil {
		o.Logger = slog.New(h)
	}
	s, err := New(o)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s, h
}

// reopen closes s and opens a new store on its directory (a restart).
func reopen(t *testing.T, s *Store, o Options) (*Store, *captureHandler) {
	t.Helper()
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	o.Dir = s.dir
	return testStore(t, o)
}

// ---------------------------------------------------------------- messages

// msg returns a message received at rx.
func msg(rx time.Time, text string) model.SyslogMessage {
	sev, fac, pri := 6, 1, 14
	return model.SyslogMessage{
		RX:  rx.UTC().Format(time.RFC3339Nano),
		Src: "192.168.1.254:514",
		Raw: "<14>Oct  5 22:15:00 gw " + text, Format: "rfc3164",
		PRI: &pri, Facility: &fac, Severity: &sev,
		TS: "Oct  5 22:15:00", Host: "gw", Msg: text,
	}
}

// msgs returns n messages received a second apart from start, named prefix-0, prefix-1, ….
func msgs(start time.Time, n int, prefix string) []model.SyslogMessage {
	out := make([]model.SyslogMessage, n)
	for i := range out {
		out[i] = msg(start.Add(time.Duration(i)*time.Second), fmt.Sprintf("%s-%d", prefix, i))
	}
	return out
}

// randomMsgs returns n messages a second apart from start whose text is size random bytes
// (base64), which gzip cannot shrink much.
func randomMsgs(t *testing.T, start time.Time, n, size int) []model.SyslogMessage {
	t.Helper()
	out := make([]model.SyslogMessage, n)
	b := make([]byte, size*3/4)
	for i := range out {
		if _, err := rand.Read(b); err != nil {
			t.Fatal(err)
		}
		out[i] = msg(start.Add(time.Duration(i)*time.Second), base64.StdEncoding.EncodeToString(b))
	}
	return out
}

// lineOf is the stored line of m.
func lineOf(t *testing.T, m model.SyslogMessage) []byte {
	t.Helper()
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return append(b, '\n')
}

// linesOf is the stored content of ms.
func linesOf(t *testing.T, ms []model.SyslogMessage) []byte {
	t.Helper()
	var b []byte
	for _, m := range ms {
		b = append(b, lineOf(t, m)...)
	}
	return b
}

func sha(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// ---------------------------------------------------------------- files

// names returns the names of the files in dir, sorted.
func names(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		out = append(out, e.Name())
	}
	slices.Sort(out)
	return out
}

// withPrefix returns the names in dir that start with prefix and end with suffix.
func withPrefix(t *testing.T, dir, prefix, suffix string) []string {
	t.Helper()
	var out []string
	for _, n := range names(t, dir) {
		if strings.HasPrefix(n, prefix) && strings.HasSuffix(n, suffix) {
			out = append(out, n)
		}
	}
	return out
}

// sealedFiles returns the sealed chunk files in dir, oldest first by name.
func sealedFiles(t *testing.T, dir string) []string {
	return withPrefix(t, dir, sealedPrefix, sealedExt)
}

// openFiles returns the open chunk files in dir.
func openFiles(t *testing.T, dir string) []string { return withPrefix(t, dir, openPrefix, openExt) }

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func mkdir(path string) error     { return os.Mkdir(path, 0o755) }
func removeDir(path string) error { return os.Remove(path) }

func writeFile(t *testing.T, path string, b []byte) {
	t.Helper()
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

// gunzip decompresses b.
func gunzip(t *testing.T, b []byte) []byte {
	t.Helper()
	zr, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	out, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// gzipBytes compresses b as the store does.
func gzipBytes(t *testing.T, b []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw, _ := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if _, err := zw.Write(b); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// readSidecarFile reads the sidecar of the sealed chunk name in dir.
func readSidecarFile(t *testing.T, dir, name string) sidecar {
	t.Helper()
	var sc sidecar
	if err := json.Unmarshal(readFile(t, filepath.Join(dir, name+sidecarExt)), &sc); err != nil {
		t.Fatal(err)
	}
	return sc
}

// content returns the uncompressed content of the sealed chunk name in dir.
func content(t *testing.T, dir, name string) []byte {
	t.Helper()
	return gunzip(t, readFile(t, filepath.Join(dir, name)))
}

// checkChunk checks that the sealed chunk c is stored as described: its file decompresses to
// want, and its sidecar holds c.
func checkChunk(t *testing.T, dir string, c model.SyslogChunk, want []byte) {
	t.Helper()
	gz := readFile(t, filepath.Join(dir, c.Name))
	if got := gunzip(t, gz); !bytes.Equal(got, want) {
		t.Fatalf("chunk %s holds\n%s\nwant\n%s", c.Name, got, want)
	}
	if c.SHA256 != sha(want) || c.Bytes != int64(len(want)) || c.GzBytes != int64(len(gz)) {
		t.Fatalf("chunk %s: sha256 %s bytes %d gz_bytes %d; want %s %d %d", c.Name, c.SHA256, c.Bytes, c.GzBytes,
			sha(want), len(want), len(gz))
	}
	if sc := readSidecarFile(t, dir, c.Name); sc.SyslogChunk != c {
		t.Fatalf("sidecar of %s:\n%+v\nwant\n%+v", c.Name, sc.SyslogChunk, c)
	}
}

// entryTexts returns the Msg of each entry.
func entryTexts(es []model.SyslogEntry) []string {
	out := make([]string, len(es))
	for i, e := range es {
		out[i] = e.Msg
	}
	return out
}

// queryAll returns every message of s, newest first.
func queryAll(t *testing.T, s *Store) []model.SyslogEntry {
	t.Helper()
	es, truncated, err := s.Query(context.Background(), time.Time{}, time.Time{}, nil, 1<<20)
	if err != nil || truncated {
		t.Fatalf("Query: %v (truncated %v)", err, truncated)
	}
	return es
}

// reversed returns the texts of ms, newest (last) first.
func reversed(ms []model.SyslogMessage) []string {
	out := make([]string, len(ms))
	for i, m := range ms {
		out[len(ms)-1-i] = m.Msg
	}
	return out
}

// slogFor returns a logger that writes to h.
func slogFor(h slog.Handler) *slog.Logger { return slog.New(h) }
