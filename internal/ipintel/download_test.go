package ipintel

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	path4 = "/data/ip2asn-v4.tsv.gz"
	path6 = "/data/ip2asn-v6.tsv.gz"
)

// tableServer serves table files over TLS, as iptoasn.com does, and records the requests.
type tableServer struct {
	*httptest.Server
	mu    sync.Mutex
	files map[string]servedFile
	reqs  []servedReq
}

// servedFile is how the server answers for a path.
type servedFile struct {
	body     []byte
	etag     string
	lastMod  string
	status   int    // not 0: answer with this status instead
	chunked  bool   // send the body in pieces, without Content-Length
	redirect string // not "": redirect there
}

type servedReq struct {
	path, ifNoneMatch, ifModifiedSince, userAgent, acceptEncoding string
}

func newTableServer(t *testing.T) *tableServer {
	s := &tableServer{files: map[string]servedFile{}}
	s.Server = httptest.NewTLSServer(http.HandlerFunc(s.serve))
	t.Cleanup(s.Close)
	return s
}

func (s *tableServer) serve(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.reqs = append(s.reqs, servedReq{r.URL.Path, r.Header.Get("If-None-Match"), r.Header.Get("If-Modified-Since"),
		r.UserAgent(), r.Header.Get("Accept-Encoding")})
	f, ok := s.files[r.URL.Path]
	s.mu.Unlock()
	switch {
	case !ok:
		http.NotFound(w, r)
		return
	case f.redirect != "":
		http.Redirect(w, r, f.redirect, http.StatusFound)
		return
	case f.status != 0:
		http.Error(w, "failure", f.status)
		return
	}
	inm, ims := r.Header.Get("If-None-Match"), r.Header.Get("If-Modified-Since")
	if (inm != "" && inm == f.etag) || (inm == "" && ims != "" && ims == f.lastMod) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	if f.etag != "" {
		w.Header().Set("ETag", f.etag)
	}
	if f.lastMod != "" {
		w.Header().Set("Last-Modified", f.lastMod)
	}
	w.Header().Set("Content-Type", "application/gzip")
	if !f.chunked {
		w.Header().Set("Content-Length", strconv.Itoa(len(f.body)))
		w.Write(f.body)
		return
	}
	for b := f.body; len(b) > 0; {
		n := min(len(b), 512)
		w.Write(b[:n])
		w.(http.Flusher).Flush()
		b = b[n:]
	}
}

func (s *tableServer) set(path string, f servedFile) {
	s.mu.Lock()
	s.files[path] = f
	s.mu.Unlock()
}

// setBoth serves f for both tables.
func (s *tableServer) setBoth(f servedFile) {
	s.set(path4, f)
	s.set(path6, f)
}

func (s *tableServer) requests() []servedReq {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.reqs)
}

// downloadDB opens a downloading DB in dir that fetches from srv (with clk, Run's waits are the
// test's and as long as the schedule says).
func downloadDB(t *testing.T, srv *tableServer, dir string, clk *fakeClock) *DB {
	t.Helper()
	o := Options{
		Download:   true,
		URLv4:      srv.URL + path4,
		URLv6:      srv.URL + path6,
		HTTPClient: srv.Client(),
		Refresh:    24 * time.Hour,
		UserAgent:  "att-monitor test",
	}
	if clk != nil {
		o.Now = clk.Now
	}
	d := openTest(t, dir, o)
	d.minRouted = [2]int{1, 1}
	if clk != nil {
		d.after, d.tick = clk.After, 1000*time.Hour
	}
	return d
}

// tmpFiles lists the temporary files in dir.
func tmpFiles(t *testing.T, dir string) []string {
	t.Helper()
	m, err := filepath.Glob(filepath.Join(dir, "*.tmp"))
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestDownloadAndRefresh(t *testing.T) {
	srv := newTableServer(t)
	v4, v6 := gzRows(rows4), gzRows(rows6)
	srv.set(path4, servedFile{body: v4, etag: `"v4-1"`, lastMod: "Tue, 06 Oct 2026 10:00:00 GMT"})
	srv.set(path6, servedFile{body: v6, lastMod: "Tue, 06 Oct 2026 10:00:00 GMT"})
	dir := t.TempDir()
	clk := newFakeClock(t0)
	d := downloadDB(t, srv, dir, clk)
	stop := startRun(t, d)

	// The files are missing: both are downloaded at once, unconditionally.
	w := clk.next(t)
	reqs := srv.requests()
	if len(reqs) != 2 || reqs[0].path != path4 || reqs[1].path != path6 {
		t.Fatalf("requests %+v", reqs)
	}
	for _, r := range reqs {
		if r.ifNoneMatch != "" || r.ifModifiedSince != "" || r.userAgent != "att-monitor test" || r.acceptEncoding != "identity" {
			t.Fatalf("first request %+v", r)
		}
	}
	if !bytes.Equal(readFile(t, filepath.Join(dir, nameV4)), v4) || !bytes.Equal(readFile(t, filepath.Join(dir, nameV6)), v6) {
		t.Fatal("the files are not stored as downloaded")
	}
	st := d.Status()
	if !st.Loaded || st.V4Ranges != 10 || st.V6Ranges != 4 || st.Error != "" || !st.Download ||
		st.Checked != rfc3339(t0) || st.Next != rfc3339(t0.Add(24*time.Hour)) || st.Source != "IPtoASN (127.0.0.1)" {
		t.Fatalf("status %+v", st)
	}
	if w.d != 24*time.Hour {
		t.Fatalf("wait %v, want 24h", w.d)
	}
	if got := d.Lookup(mustAddr(t, "8.8.8.8")); got.Org != "Google" {
		t.Fatalf("Lookup %+v", got)
	}
	m, err := readMeta(filepath.Join(dir, nameMeta))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(v4)
	if m.V4 == nil || m.V4.ETag != `"v4-1"` || m.V4.SHA256 != hex.EncodeToString(sum[:]) || m.V4.Rows != len(rows4) ||
		m.V4.Ranges != 10 || m.V4.URL != srv.URL+path4 || m.V6 == nil || m.V6.ETag != "" || !m.Checked.Equal(t0) {
		t.Fatalf("metadata %+v %+v %+v", m, m.V4, m.V6)
	}
	if tmp := tmpFiles(t, dir); len(tmp) != 0 {
		t.Fatalf("temporary files left: %v", tmp)
	}
	fi4, _ := os.Stat(filepath.Join(dir, nameV4))

	// A day later: conditional requests, nothing newer.
	clk.fire(w)
	w = clk.next(t)
	reqs = srv.requests()[2:]
	if len(reqs) != 2 || reqs[0].ifNoneMatch != `"v4-1"` || reqs[0].ifModifiedSince == "" ||
		reqs[1].ifNoneMatch != "" || reqs[1].ifModifiedSince != "Tue, 06 Oct 2026 10:00:00 GMT" {
		t.Fatalf("conditional requests %+v", reqs)
	}
	if fi, _ := os.Stat(filepath.Join(dir, nameV4)); !fi.ModTime().Equal(fi4.ModTime()) {
		t.Fatal("the file was rewritten without a newer one")
	}
	if st := d.Status(); st.Checked != rfc3339(t0.Add(24*time.Hour)) || st.Error != "" || w.d != 24*time.Hour {
		t.Fatalf("after 304: status %+v, wait %v", st, w.d)
	}

	// A newer IPv4 table: downloaded and swapped in.
	newer := slices.Clone(rows4)
	newer[6] = row{"8.8.8.0", "8.8.8.255", 64500, "US", "EXAMPLE-NEWER"}
	srv.set(path4, servedFile{body: gzRows(newer), etag: `"v4-2"`})
	clk.fire(w)
	clk.next(t)
	if got := d.Lookup(mustAddr(t, "8.8.8.8")); got.ASN != 64500 {
		t.Fatalf("after the newer table: %+v", got)
	}
	if got := d.Lookup(mustAddr(t, "2001:4860::1")); got.ASN != 15169 {
		t.Fatalf("the IPv6 table changed: %+v", got)
	}
	stop()
	if m, _ := readMeta(filepath.Join(dir, nameMeta)); m.V4 == nil || m.V4.ETag != `"v4-2"` {
		t.Fatalf("metadata after the newer table: %+v", m.V4)
	}
}

// TestDownloadRejected checks that a failed or suspicious download keeps the old data and
// leaves nothing behind.
func TestDownloadRejected(t *testing.T) {
	good := gzRows(rows4)
	reversed := slices.Clone(rows4)
	slices.Reverse(reversed)
	garbage := make([]string, 200)
	for i := range garbage {
		garbage[i] = "<p>Service unavailable</p>"
	}
	big := bytes.Repeat([]byte("x"), 4096)
	cases := []struct {
		name  string
		file  servedFile
		setup func(*DB)
		want  string
	}{
		{"HTTP error", servedFile{status: http.StatusInternalServerError}, nil, "HTTP 500"},
		{"not found", servedFile{status: http.StatusNotFound}, nil, "HTTP 404"},
		{"oversize, announced", servedFile{body: big}, func(d *DB) { d.maxDownload = 1024 }, "more than the 1024"},
		{"oversize, streamed", servedFile{body: big, chunked: true}, func(d *DB) { d.maxDownload = 1024 }, "more than the 1024"},
		{"not gzip", servedFile{body: []byte("<html><body>Maintenance</body></html>")}, nil, "not a gzip file"},
		{"truncated gzip", servedFile{body: good[:len(good)/2]}, nil, "EOF"},
		{"bad checksum", servedFile{body: flipByte(good, len(good)-6)}, nil, "checksum"},
		{"too few rows", servedFile{body: good}, func(d *DB) { d.minRouted = [2]int{100, 100} }, "fewer than the 100"},
		{"unsorted", servedFile{body: gzRows(reversed)}, nil, "not sorted"},
		{"garbage", servedFile{body: gzLines(garbage...)}, nil, "not understood"},
		{"redirect to http", servedFile{redirect: "http://127.0.0.1:1/ip2asn-v4.tsv.gz"}, nil, "not https"},
	}
	old4 := slices.Clone(rows4)
	old4[6] = row{"8.8.8.0", "8.8.8.255", 64501, "US", "EXAMPLE-OLD"}
	old6 := gzRows(rows6)
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := newTableServer(t)
			srv.setBoth(c.file)
			dir := t.TempDir()
			writeTables(t, dir, gzRows(old4), old6)
			d := downloadDB(t, srv, dir, nil)
			if c.setup != nil {
				c.setup(d)
			}
			d.reload(context.Background())
			d.checkTables(context.Background())
			st := d.Status()
			if !strings.Contains(st.Error, c.want) || !strings.Contains(st.Error, nameV4) {
				t.Fatalf("error %q, want %q", st.Error, c.want)
			}
			if d.st.failures != 1 || !st.Loaded || st.Checked != "" {
				t.Fatalf("failures %d, status %+v", d.st.failures, st)
			}
			if got := d.Lookup(mustAddr(t, "8.8.8.8")); got.ASN != 64501 {
				t.Fatalf("the old data is not kept: %+v", got)
			}
			if !bytes.Equal(readFile(t, filepath.Join(dir, nameV4)), gzRows(old4)) ||
				!bytes.Equal(readFile(t, filepath.Join(dir, nameV6)), old6) {
				t.Fatal("the old files were changed")
			}
			if tmp := tmpFiles(t, dir); len(tmp) != 0 {
				t.Fatalf("temporary files left: %v", tmp)
			}
			if m, err := readMeta(filepath.Join(dir, nameMeta)); err != nil || m.Failures != 1 || m.Error == "" {
				t.Fatalf("metadata %+v, %v", m, err)
			}
		})
	}
}

func TestDownloadFollowsHTTPSRedirect(t *testing.T) {
	srv := newTableServer(t)
	srv.set("/moved/v4", servedFile{redirect: srv.URL + path4})
	srv.set(path4, servedFile{body: gzRows(rows4)})
	srv.set(path6, servedFile{body: gzRows(rows6)})
	d := downloadDB(t, srv, t.TempDir(), nil)
	d.urls[fam4] = srv.URL + "/moved/v4"
	d.reload(context.Background())
	d.checkTables(context.Background())
	if st := d.Status(); st.Error != "" || st.V4Ranges != 10 {
		t.Fatalf("status %+v", st)
	}
}

// TestDownloadSchedule follows the checks with a fake clock: a day apart, after a failure an
// hour, then two, four ... at most a day, and a day again once a check works.
func TestDownloadSchedule(t *testing.T) {
	srv := newTableServer(t)
	srv.set(path4, servedFile{body: gzRows(rows4), etag: `"a"`})
	srv.set(path6, servedFile{body: gzRows(rows6), etag: `"b"`})
	dir := t.TempDir()
	clk := newFakeClock(t0)
	d := downloadDB(t, srv, dir, clk)
	startRun(t, d)
	w := clk.next(t)
	if w.d != 24*time.Hour {
		t.Fatalf("first wait %v", w.d)
	}
	srv.setBoth(servedFile{status: http.StatusServiceUnavailable})
	for _, want := range []time.Duration{1, 2, 4, 8, 16, 24, 24} {
		clk.fire(w)
		w = clk.next(t)
		if w.d != want*time.Hour {
			t.Fatalf("after a failure: wait %v, want %vh", w.d, want)
		}
		if st := d.Status(); !strings.Contains(st.Error, "HTTP 503") || st.Next != rfc3339(clk.Now().Add(w.d)) || !st.Loaded {
			t.Fatalf("status %+v", st)
		}
	}
	srv.set(path4, servedFile{body: gzRows(rows4), etag: `"a"`})
	srv.set(path6, servedFile{body: gzRows(rows6), etag: `"b"`})
	clk.fire(w)
	w = clk.next(t)
	if st := d.Status(); w.d != 24*time.Hour || st.Error != "" || st.Checked != rfc3339(clk.Now()) {
		t.Fatalf("after recovering: wait %v, status %+v", w.d, st)
	}
	// 2 downloads, 7 failed checks of 2 requests each, then 2 "not modified".
	if n := len(srv.requests()); n != 2+14+2 {
		t.Fatalf("%d requests", n)
	}
}

// TestDownloadScheduleSurvivesRestart checks that a restart neither downloads again what it has
// nor forgets a failure's backoff.
func TestDownloadScheduleSurvivesRestart(t *testing.T) {
	srv := newTableServer(t)
	srv.set(path4, servedFile{body: gzRows(rows4), etag: `"a"`})
	srv.set(path6, servedFile{body: gzRows(rows6), etag: `"b"`})
	dir := t.TempDir()

	clk := newFakeClock(t0)
	stop := startRun(t, downloadDB(t, srv, dir, clk))
	clk.next(t)
	stop()
	if n := len(srv.requests()); n != 2 {
		t.Fatalf("%d requests", n)
	}

	// An hour later: the files are loaded, no request; the next check is due a day after the last.
	clk = newFakeClock(t0.Add(time.Hour))
	d := downloadDB(t, srv, dir, clk)
	stop = startRun(t, d)
	w := clk.next(t)
	if n := len(srv.requests()); n != 2 || w.d != 23*time.Hour || d.Status().V4Ranges != 10 {
		t.Fatalf("after a restart: %d requests, wait %v, status %+v", n, w.d, d.Status())
	}
	// The check fails; 10 minutes after the restart that follows, the retry is 50 minutes away.
	srv.setBoth(servedFile{status: http.StatusBadGateway})
	clk.fire(w)
	clk.next(t)
	stop()
	clk = newFakeClock(t0.Add(24*time.Hour + 10*time.Minute))
	d = downloadDB(t, srv, dir, clk)
	startRun(t, d)
	w = clk.next(t)
	if n := len(srv.requests()); n != 4 || w.d != 50*time.Minute || !strings.Contains(d.Status().Error, "HTTP 502") {
		t.Fatalf("after a failure and a restart: %d requests, wait %v, status %+v", n, w.d, d.Status())
	}
}

// TestDownloadReplacesUnusableFile checks that a table file that is there but cannot be loaded
// (here cut in half on disk) is downloaded again at once - not at the next scheduled check, up to
// Refresh (a week by default) away, with no organisations or countries for its family until then
// - and that a download that fails then is retried after the backoff, not at once.
func TestDownloadReplacesUnusableFile(t *testing.T) {
	srv := newTableServer(t)
	v4 := gzRows(rows4)
	srv.set(path4, servedFile{body: v4, etag: `"a"`})
	srv.set(path6, servedFile{body: gzRows(rows6), etag: `"b"`})
	dir := t.TempDir()
	clk := newFakeClock(t0)
	stop := startRun(t, downloadDB(t, srv, dir, clk))
	clk.next(t)
	stop()

	// The IPv4 file is damaged, the server fails, and the service starts again an hour later: the
	// check is made at once, fails, and is retried an hour later.
	p := filepath.Join(dir, nameV4)
	if err := os.WriteFile(p, v4[:len(v4)/2], 0o644); err != nil {
		t.Fatal(err)
	}
	srv.setBoth(servedFile{status: http.StatusServiceUnavailable})
	clk.Advance(time.Hour)
	d := downloadDB(t, srv, dir, clk)
	startRun(t, d)
	w := clk.next(t)
	st := d.Status()
	if n := len(srv.requests()); n != 4 || w.d != time.Hour || st.V4Ranges != 0 || st.V6Ranges != 4 ||
		!strings.Contains(st.Error, nameV4+": line ") || !strings.Contains(st.Error, "HTTP 503") {
		t.Fatalf("after the restart: %d requests, wait %v, status %+v", n, w.d, st)
	}

	// The server is back: the file is downloaded again, unconditionally (it is not the one
	// downloaded), and the next check is a Refresh away.
	srv.set(path4, servedFile{body: v4, etag: `"a"`})
	srv.set(path6, servedFile{body: gzRows(rows6), etag: `"b"`})
	clk.fire(w)
	w = clk.next(t)
	reqs := srv.requests()[4:]
	if len(reqs) != 2 || reqs[0].path != path4 || reqs[0].ifNoneMatch != "" || reqs[1].ifNoneMatch != `"b"` {
		t.Fatalf("requests %+v", reqs)
	}
	if st := d.Status(); st.V4Ranges != 10 || st.Error != "" || st.Checked != rfc3339(clk.Now()) || w.d != 24*time.Hour {
		t.Fatalf("after the download: status %+v, wait %v", st, w.d)
	}
	if !bytes.Equal(readFile(t, p), v4) {
		t.Fatal("the damaged file was not replaced")
	}
}

// TestDownloadReplacedFileIsNotConditional checks that a file replaced by hand is not kept on the
// strength of the validators of the one downloaded before.
func TestDownloadReplacedFileIsNotConditional(t *testing.T) {
	srv := newTableServer(t)
	srv.set(path4, servedFile{body: gzRows(rows4), etag: `"a"`})
	srv.set(path6, servedFile{body: gzRows(rows6), etag: `"b"`})
	dir := t.TempDir()
	d := downloadDB(t, srv, dir, nil)
	d.reload(context.Background())
	d.checkTables(context.Background())
	// Replaced by hand with another table.
	other := slices.Clone(rows4)
	other[6] = row{"8.8.8.0", "8.8.8.255", 64502, "US", "EXAMPLE-BY-HAND"}
	writeTables(t, dir, gzRows(other), nil)
	future := time.Now().Add(time.Hour)
	os.Chtimes(filepath.Join(dir, nameV4), future, future)
	d.reload(context.Background())
	if got := d.Lookup(mustAddr(t, "8.8.8.8")); got.ASN != 64502 {
		t.Fatalf("the replaced file was not loaded: %+v", got)
	}
	d.checkTables(context.Background())
	reqs := srv.requests()[2:]
	if len(reqs) != 2 || reqs[0].ifNoneMatch != "" || reqs[1].ifNoneMatch != `"b"` {
		t.Fatalf("requests %+v", reqs)
	}
	if got := d.Lookup(mustAddr(t, "8.8.8.8")); got.ASN != 15169 {
		t.Fatalf("the download did not replace the file: %+v", got)
	}
}

func TestBackoff(t *testing.T) {
	week := 7 * 24 * time.Hour
	for n, want := range map[int]time.Duration{1: time.Hour, 2: 2 * time.Hour, 3: 4 * time.Hour, 8: 128 * time.Hour,
		9: week, 64: week} {
		if got := backoff(n, week); got != want {
			t.Errorf("backoff(%d) = %v, want %v", n, got, want)
		}
	}
	if got := backoff(1, 30*time.Minute); got != 30*time.Minute {
		t.Errorf("backoff below the first pause = %v", got)
	}
}

func TestReadMetaRejects(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, nameMeta)
	sum := strings.Repeat("ab", 32)
	for name, content := range map[string]string{
		"not json":     "{",
		"version":      `{"version": 2}`,
		"too large":    `{"version": 1, "error": "` + strings.Repeat("x", maxMetaBytes) + `"}`,
		"bad entries":  `{"version": 1, "v4": {"url": "https://x/a", "sha256": "zz"}, "v6": {"url": "", "sha256": "` + sum + `"}}`,
		"bad etag":     `{"version": 1, "v4": {"url": "https://x/a", "sha256": "` + sum + `", "etag": "a\u000ab", "last_modified": "ok"}}`,
		"bad failures": `{"version": 1, "failures": -5}`,
	} {
		os.WriteFile(path, []byte(content), 0o644)
		m, err := readMeta(path)
		switch name {
		case "not json", "version", "too large":
			if err == nil {
				t.Errorf("%s: accepted", name)
			}
		case "bad entries":
			if err != nil || m.V4 != nil || m.V6 != nil {
				t.Errorf("%s: %+v, %v", name, m, err)
			}
		case "bad etag":
			if err != nil || m.V4 == nil || m.V4.ETag != "" || m.V4.LastModified != "ok" {
				t.Errorf("%s: %+v, %v", name, m.V4, err)
			}
		case "bad failures":
			if err != nil || m.Failures != 0 {
				t.Errorf("%s: %+v, %v", name, m, err)
			}
		}
	}
}
