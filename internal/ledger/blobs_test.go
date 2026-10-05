package ledger

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"attmonitor/internal/contracts"
	"attmonitor/internal/model"
)

func TestBlobStore(t *testing.T) {
	s, dir, _ := newLedger(t)
	cases := []struct {
		name    string
		content []byte
	}{
		{"html", []byte("<html><title>Broadband Statistics</title>\xa9 2026</html>")}, // Latin-1 byte
		{"empty", []byte{}},
		{"binary", []byte{0, 1, 2, 0xff, 0xfe, '\n', 0}},
		{"large", bytes.Repeat([]byte("fiberstat Rx Power -315 "), 50000)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			id, err := s.PutBlob(tc.content)
			if err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256(tc.content)
			if id != hex.EncodeToString(sum[:]) {
				t.Fatalf("id %s", id)
			}
			path := filepath.Join(dir, "blobs", id[:2], id+".gz")
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			zr, err := gzip.NewReader(bytes.NewReader(raw))
			if err != nil {
				t.Fatal(err)
			}
			plain, _ := io.ReadAll(zr)
			if !bytes.Equal(plain, tc.content) {
				t.Fatal("stored gzip does not hold the exact bytes")
			}
			got, err := s.GetBlob(id)
			if err != nil || !bytes.Equal(got, tc.content) {
				t.Fatalf("GetBlob: %v", err)
			}
			if !s.HasBlob(id) {
				t.Fatal("HasBlob false")
			}
			// Deduplicated: the file is not rewritten.
			st1, _ := os.Stat(path)
			id2, err := s.PutBlob(append([]byte(nil), tc.content...))
			st2, _ := os.Stat(path)
			if err != nil || id2 != id || !st1.ModTime().Equal(st2.ModTime()) {
				t.Fatalf("dedupe: %v %s", err, id2)
			}
		})
	}
	unknown := strings.Repeat("ab", 32)
	for _, id := range []string{unknown, "", "zz", strings.ToUpper(unknown), "../../keys/ledger-signing.key"} {
		if _, err := s.GetBlob(id); !errors.Is(err, contracts.ErrNotFound) {
			t.Fatalf("GetBlob(%q) = %v", id, err)
		}
		if s.HasBlob(id) {
			t.Fatalf("HasBlob(%q) true", id)
		}
	}
	if entries, _ := os.ReadDir(filepath.Join(dir, "blobs", ".tmp")); len(entries) != 0 {
		t.Fatalf("temporary files left: %v", entries)
	}
}

func TestBlobCorruptionDetectedAndRepaired(t *testing.T) {
	s, dir, _ := newLedger(t)
	content := []byte("<html>sysinfo</html>")
	id, err := s.PutBlob(content)
	if err != nil {
		t.Fatal(err)
	}
	path := s.blobPath(id)
	corruptions := map[string][]byte{
		"different content": gz(t, []byte("<html>edited</html>")),
		"not gzip":          []byte("plain text"),
		"truncated gzip":    gz(t, content)[:10],
	}
	for name, bad := range corruptions {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(path, bad, 0o644); err != nil {
				t.Fatal(err)
			}
			_, err := s.GetBlob(id)
			if !errors.Is(err, ErrBlobCorrupt) || !strings.Contains(err.Error(), "corrupt") {
				t.Fatalf("GetBlob on corrupt blob: %v", err)
			}
			if !s.HasBlob(id) {
				t.Fatal("HasBlob does not re-check content")
			}
			// Putting the same bytes again repairs the store and preserves the damaged copy.
			if _, err := s.PutBlob(content); err != nil {
				t.Fatal(err)
			}
			if got, err := s.GetBlob(id); err != nil || !bytes.Equal(got, content) {
				t.Fatalf("after repair: %v", err)
			}
		})
	}
	q, _ := filepath.Glob(filepath.Join(dir, "quarantine", id+".gz.corrupt*"))
	if len(q) != len(corruptions) {
		t.Fatalf("quarantined copies %v", q)
	}
}

func gz(t *testing.T, b []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	zw.Write(b)
	zw.Close()
	return buf.Bytes()
}

func TestConcurrentBlobs(t *testing.T) {
	s, _, _ := newLedger(t)
	var wg sync.WaitGroup
	ids := make([]string, 40)
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			content := []byte(fmt.Sprintf("page %d", i%10)) // 10 distinct, each put 4 times
			id, err := s.PutBlob(content)
			if err != nil {
				t.Error(err)
				return
			}
			if _, err := s.GetBlob(id); err != nil {
				t.Error(err)
			}
			ids[i] = id
		}(i)
	}
	wg.Wait()
	distinct := map[string]bool{}
	for _, id := range ids {
		distinct[id] = true
	}
	if len(distinct) != 10 {
		t.Fatalf("%d distinct ids", len(distinct))
	}
	var list []string
	for id := range distinct {
		list = append(list, id)
	}
	mustAppend(t, s, model.TypeGatewaySnapshot, map[string]any{"pages": list}, list...)
	rep, err := s.Verify(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	requireOK(t, rep)
	if rep.BlobsChecked != 10 {
		t.Fatalf("blobs checked %d", rep.BlobsChecked)
	}
}
