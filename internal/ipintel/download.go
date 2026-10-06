package ipintel

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	// downloadTimeout bounds one file's download, from the request to the last byte (a table is a
	// few MB: minutes even on a slow line).
	downloadTimeout = 10 * time.Minute
	// maxRedirects bounds the redirects followed (all of them to https URLs).
	maxRedirects = 5
	// retryFirst is the pause after a failed check; it doubles with every further failure, up to
	// Refresh.
	retryFirst = time.Hour
)

// newHTTPClient returns the client of the downloads: base (copied) or a dedicated one with
// timeouts on every step. It follows redirects to https URLs only and never sends cookies.
func newHTTPClient(base *http.Client) *http.Client {
	var hc http.Client
	if base != nil {
		hc = *base // shares the transport; the policies below apply to the copy only
	} else {
		hc.Transport = &http.Transport{
			Proxy:                  http.ProxyFromEnvironment,
			DialContext:            (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
			TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12},
			TLSHandshakeTimeout:    30 * time.Second,
			ResponseHeaderTimeout:  time.Minute,
			ExpectContinueTimeout:  time.Second,
			IdleConnTimeout:        30 * time.Second,
			MaxResponseHeaderBytes: 64 << 10,
			ForceAttemptHTTP2:      true,
			// The file is stored exactly as the server sends it (it is gzip already).
			DisableCompression: true,
		}
	}
	hc.Jar = nil
	hc.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= maxRedirects {
			return fmt.Errorf("more than %d redirects", maxRedirects)
		}
		if req.URL.Scheme != "https" {
			return fmt.Errorf("redirect to %s refused: not https", req.URL.Redacted())
		}
		return nil
	}
	return &hc
}

// backoff is the pause after the n-th failed check in a row (n >= 1): retryFirst, doubled for
// every further failure, at most limit.
func backoff(n int, limit time.Duration) time.Duration {
	d := retryFirst
	for i := 1; i < n && d < limit; i++ {
		d *= 2
	}
	return min(d, limit)
}

// checkTables looks for newer tables (both families) and installs those it gets, then notes the
// check and saves the schedule. A failure keeps the old data and is retried after backoff.
func (d *DB) checkTables(ctx context.Context) {
	var errs []string
	got := 0
	// A panic (a bug) counts as a failed check, so that it is retried after the backoff, not at once.
	if p := d.safely("download", func() {
		for _, f := range families {
			installed, err := d.fetch(ctx, f)
			if ctx.Err() != nil {
				return
			}
			if err != nil {
				errs = append(errs, err.Error())
			} else if installed {
				got++
			}
		}
	}); p != "" {
		errs = append(errs, p)
	}
	if ctx.Err() != nil {
		return // stopping: not a failed check
	}
	now := d.now()
	problem := strings.Join(errs, "; ")
	var failures int
	d.update(func(s *state) {
		s.attempt = now
		if problem == "" {
			s.checked, s.failures, s.dlErr = now, 0, ""
		} else {
			s.failures = min(s.failures+1, maxFailures)
			s.dlErr = problem
		}
		failures = s.failures
	})
	d.saveMeta()
	switch {
	case problem != "":
		d.log.Warn("ipintel: the IP database could not be updated; the data already loaded is kept",
			"err", problem, "failures", failures, "retry_in", backoff(failures, d.refresh))
	case got > 0:
		d.log.Info("ipintel: IP database updated", "files", got)
	default:
		d.log.Debug("ipintel: IP database is up to date")
	}
}

// fetch asks for family f's table - conditionally when the file on disk is the one downloaded
// before - and when the server sends one, stores it in a temporary file, reads and checks all of
// it, and only then replaces the old file and swaps the new table in. It reports whether it did.
func (d *DB) fetch(ctx context.Context, f family) (bool, error) {
	name := f.fileName()
	ctx, cancel := context.WithTimeout(ctx, downloadTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, d.urls[f], nil)
	if err != nil {
		return false, fmt.Errorf("%s: %w", name, err)
	}
	req.Header.Set("User-Agent", d.userAgent)
	// The file is gzip already: it is stored exactly as sent. Asking for no content coding also
	// keeps any client's transport from decompressing a .gz that a server labels gzip-encoded.
	req.Header.Set("Accept-Encoding", "identity")
	cond := d.conditional(f)
	if cond != nil {
		if cond.ETag != "" {
			req.Header.Set("If-None-Match", cond.ETag)
		}
		if cond.LastModified != "" {
			req.Header.Set("If-Modified-Since", cond.LastModified)
		}
	}
	resp, err := d.hc.Do(req)
	if err != nil {
		return false, fmt.Errorf("%s: %w", name, err)
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusNotModified && cond != nil:
		return false, nil
	case resp.StatusCode != http.StatusOK:
		return false, fmt.Errorf("%s: HTTP %s", name, resp.Status)
	case resp.ContentLength > d.maxDownload:
		return false, fmt.Errorf("%s: %d bytes, more than the %d a table may have", name, resp.ContentLength, d.maxDownload)
	}

	if err := os.MkdirAll(d.dir, 0o755); err != nil {
		return false, fmt.Errorf("%s: %w", name, err)
	}
	tmp, err := os.CreateTemp(d.dir, name+".*.tmp")
	if err != nil {
		return false, fmt.Errorf("%s: %w", name, err)
	}
	keep := false
	defer func() {
		if !keep {
			os.Remove(tmp.Name())
		}
	}()
	n, err := io.Copy(tmp, io.LimitReader(resp.Body, d.maxDownload+1))
	if err == nil && n > d.maxDownload {
		err = fmt.Errorf("more than the %d bytes a table may have", d.maxDownload)
	}
	if err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return false, fmt.Errorf("%s: download: %w", name, err)
	}

	l, err := loadFile(ctx, tmp.Name(), f)
	if err == nil && l.stats.routed < d.minRouted[f] {
		err = fmt.Errorf("only %d announced ranges, fewer than the %d a complete table has", l.stats.routed, d.minRouted[f])
	}
	if err != nil {
		return false, fmt.Errorf("%s: the downloaded file was not used: %w", name, err)
	}
	path := filepath.Join(d.dir, name)
	if err := os.Rename(tmp.Name(), path); err != nil {
		return false, fmt.Errorf("%s: %w", name, err)
	}
	keep = true
	st := fileState{exists: true, size: l.size, mtime: l.at, sum: l.sum}
	if fi, err := os.Stat(path); err == nil {
		st.size, st.mtime = fi.Size(), fi.ModTime()
		l.at = fi.ModTime()
	}
	d.disk[f] = st
	fm := &fileMeta{
		URL:        d.urls[f],
		Downloaded: d.now().UTC(),
		Rows:       l.stats.rows,
		Ranges:     l.ranges(),
		Size:       l.size,
		SHA256:     l.sum,
	}
	if v := resp.Header.Get("ETag"); validatorOK(v) {
		fm.ETag = v
	}
	if v := resp.Header.Get("Last-Modified"); validatorOK(v) {
		fm.LastModified = v
	}
	d.meta.setFile(f, fm)
	d.install(l)
	d.update(func(s *state) { s.loadErr[f] = "" })
	d.log.Info("ipintel: IP database file downloaded", "file", name, "bytes", l.size, "rows", l.stats.rows,
		"ranges", l.ranges(), "skipped_lines", l.stats.bad)
	return true, nil
}

// conditional returns what a conditional request for family f's table may send: the download
// entry of the file on disk, when that file is the one it describes, from the same URL.
func (d *DB) conditional(f family) *fileMeta {
	fm := d.meta.file(f)
	if fm == nil || fm.URL != d.urls[f] || !d.disk[f].exists || d.disk[f].sum != fm.SHA256 {
		return nil
	}
	if fm.ETag == "" && fm.LastModified == "" {
		return nil
	}
	return fm
}
