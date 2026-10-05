package ticket

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// PDF printing with a Chromium-based browser in headless mode: Microsoft Edge (installed on
// every Windows 10/11 computer), else Google Chrome. The browser runs with a fresh, temporary
// profile (so it neither touches nor waits for the user's own browser session) and prints the
// HTML file with its own CSS page size (US Letter) and no header or footer.

// ErrNoBrowser is returned by PrintPDF when neither Edge nor Chrome can be found.
var ErrNoBrowser = errors.New("ticket: no Microsoft Edge or Google Chrome found to print the PDF")

// PrintTimeout bounds one browser run.
const PrintTimeout = 90 * time.Second

// PrintPDF prints the HTML file htmlPath to pdfPath (replacing it) with a headless Microsoft
// Edge, else Google Chrome, and returns the browser executable used. The result is checked to
// be a complete PDF file before it is put in place.
func PrintPDF(ctx context.Context, htmlPath, pdfPath string) (browser string, err error) {
	if ctx == nil {
		ctx = context.Background()
	}
	absHTML, err := filepath.Abs(htmlPath)
	if err != nil {
		return "", fmt.Errorf("ticket: HTML path: %w", err)
	}
	if st, err := os.Stat(absHTML); err != nil {
		return "", fmt.Errorf("ticket: HTML file: %w", err)
	} else if !st.Mode().IsRegular() {
		return "", fmt.Errorf("ticket: HTML file %s is not a regular file", absHTML)
	}
	absPDF, err := filepath.Abs(pdfPath)
	if err != nil {
		return "", fmt.Errorf("ticket: PDF path: %w", err)
	}
	if strings.EqualFold(absPDF, absHTML) {
		return "", errors.New("ticket: the PDF path is the HTML file itself")
	}
	browsers := browserCandidates()
	if len(browsers) == 0 {
		return "", ErrNoBrowser
	}
	var errs []error
	for _, exe := range browsers {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		data, err := printWith(ctx, exe, absHTML)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", exe, err))
			continue
		}
		if err := writeFileAtomic(absPDF, data); err != nil {
			return "", fmt.Errorf("ticket: writing %s: %w", absPDF, err)
		}
		return exe, nil
	}
	return "", fmt.Errorf("ticket: printing the PDF failed: %w", errors.Join(errs...))
}

// printWith runs one browser and returns the PDF bytes it produced.
func printWith(ctx context.Context, exe, absHTML string) ([]byte, error) {
	tmp, err := os.MkdirTemp("", "att-monitor-ticket-")
	if err != nil {
		return nil, err
	}
	defer removeAllRetry(tmp)
	profile := filepath.Join(tmp, "profile")
	out := filepath.Join(tmp, "ticket.pdf")

	ctx, cancel := context.WithTimeout(ctx, PrintTimeout)
	defer cancel()
	args := []string{
		"--headless=new",
		"--disable-gpu",
		"--no-first-run",
		"--no-default-browser-check",
		"--no-pdf-header-footer",
		"--user-data-dir=" + profile,
		"--print-to-pdf=" + out,
		fileURL(absHTML),
	}
	cmd := exec.CommandContext(ctx, exe, args...)
	var log tailBuffer
	cmd.Stdout, cmd.Stderr = &log, &log
	cmd.WaitDelay = 5 * time.Second // helper processes may keep the output pipes open
	hideWindow(cmd)
	runErr := cmd.Run()
	// Some builds hand the job to another browser process and return early: wait for the file.
	wait := 15 * time.Second
	if runErr != nil {
		wait = 2 * time.Second
	}
	data, err := waitForPDF(ctx, out, wait)
	if err != nil {
		if runErr != nil {
			err = fmt.Errorf("%w (browser: %v)", err, runErr)
		}
		if tail := strings.TrimSpace(log.String()); tail != "" {
			err = fmt.Errorf("%w; browser output: %s", err, truncate(oneLine(tail), 400))
		}
		return nil, err
	}
	return data, nil
}

// waitForPDF waits until path holds a complete PDF (it starts with "%PDF-", ends with "%%EOF"
// and its size is stable), for at most wait.
func waitForPDF(ctx context.Context, path string, wait time.Duration) ([]byte, error) {
	deadline := time.Now().Add(wait)
	lastSize := int64(-1)
	for {
		if st, err := os.Stat(path); err == nil && st.Size() > 0 {
			if st.Size() == lastSize {
				data, err := os.ReadFile(path)
				if err == nil && isCompletePDF(data) {
					return data, nil
				}
			}
			lastSize = st.Size()
		}
		if time.Now().After(deadline) {
			break
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("no PDF was produced: %w", ctx.Err())
		case <-time.After(200 * time.Millisecond):
		}
	}
	data, err := os.ReadFile(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return nil, errors.New("the browser produced no PDF file")
	case err != nil:
		return nil, err
	case !bytes.HasPrefix(data, []byte("%PDF-")):
		return nil, errors.New("the browser's output is not a PDF file")
	case !isCompletePDF(data):
		return nil, errors.New("the browser's PDF output is incomplete")
	}
	return data, nil
}

// isCompletePDF checks the PDF header and the end-of-file marker.
func isCompletePDF(b []byte) bool {
	if !bytes.HasPrefix(b, []byte("%PDF-")) {
		return false
	}
	tail := b[max(0, len(b)-1024):]
	return bytes.Contains(tail, []byte("%%EOF"))
}

// fileURL returns the file:/// URL of an absolute path ("file:///C:/dir/a%20b.html").
func fileURL(abs string) string {
	p := filepath.ToSlash(abs)
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return (&url.URL{Scheme: "file", Path: p}).String()
}

// writeFileAtomic writes data next to path and renames it into place.
func writeFileAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	_, err = tmp.Write(data)
	if err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(name, path)
	}
	if err != nil {
		os.Remove(name)
	}
	return err
}

// removeAllRetry removes the temporary profile; browser helper processes can hold files in it
// for a moment after the browser exits.
func removeAllRetry(dir string) {
	for i := 0; i < 40; i++ {
		if err := os.RemoveAll(dir); err == nil {
			return
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// tailBuffer keeps the last 8 KiB written to it.
type tailBuffer struct {
	mu sync.Mutex
	b  []byte
}

func (t *tailBuffer) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.b = append(t.b, p...)
	if over := len(t.b) - 8<<10; over > 0 {
		t.b = append(t.b[:0:0], t.b[over:]...)
	}
	return len(p), nil
}

func (t *tailBuffer) String() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return strings.ToValidUTF8(string(t.b), "?")
}

// isFile reports whether p names an existing regular file.
func isFile(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.Mode().IsRegular()
}

// addCandidate appends a browser path once (case-insensitively, as on Windows).
func addCandidate(list []string, p string) []string {
	p = strings.Trim(strings.TrimSpace(p), `"`)
	if p == "" || !isFile(p) {
		return list
	}
	for _, x := range list {
		if strings.EqualFold(filepath.Clean(x), filepath.Clean(p)) {
			return list
		}
	}
	return append(list, p)
}
