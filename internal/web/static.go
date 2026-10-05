package web

import (
	"bytes"
	"embed"
	"fmt"
	"html"
	"io/fs"
	"net/http"
	"path"
	"strings"
	"time"
)

// staticFS holds the single-page dashboard. It references no external URL so that it keeps
// working while the internet connection is down.
//
//go:embed static
var staticFS embed.FS

// versionPlaceholder in index.html is replaced with the HTML-escaped software version.
const versionPlaceholder = "{{VERSION}}"

// staticTypes maps extensions to Content-Type. The table is explicit on purpose: Go's mime
// package consults the Windows registry, which on some machines maps .js or .css to
// text/plain — with nosniff the browser would then refuse to run or apply them.
var staticTypes = map[string]string{
	".html": "text/html; charset=utf-8",
	".js":   "text/javascript; charset=utf-8",
	".css":  "text/css; charset=utf-8",
	".svg":  "image/svg+xml",
	".json": "application/json; charset=utf-8",
	".txt":  "text/plain; charset=utf-8",
	".png":  "image/png",
	".ico":  "image/x-icon",
}

type staticFile struct {
	data        []byte
	contentType string
}

// loadStatic reads every embedded asset and prepares index.html.
func loadStatic(version string) (map[string]staticFile, staticFile, error) {
	files := map[string]staticFile{}
	err := fs.WalkDir(staticFS, "static", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		ct, ok := staticTypes[strings.ToLower(path.Ext(p))]
		if !ok {
			return fmt.Errorf("web: no content type for embedded file %s", p)
		}
		b, err := staticFS.ReadFile(p)
		if err != nil {
			return err
		}
		files[strings.TrimPrefix(p, "static/")] = staticFile{data: b, contentType: ct}
		return nil
	})
	if err != nil {
		return nil, staticFile{}, err
	}
	idx, ok := files["index.html"]
	if !ok {
		return nil, staticFile{}, fmt.Errorf("web: embedded static/index.html is missing")
	}
	index := staticFile{
		data:        bytes.ReplaceAll(idx.data, []byte(versionPlaceholder), []byte(html.EscapeString(version))),
		contentType: idx.contentType,
	}
	files["index.html"] = index
	return files, index, nil
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	serveStatic(w, r, s.index)
}

func (s *Server) handleStatic(w http.ResponseWriter, r *http.Request) {
	f, ok := s.static[r.PathValue("file")]
	if !ok {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	serveStatic(w, r, f)
}

func serveStatic(w http.ResponseWriter, r *http.Request, f staticFile) {
	w.Header().Set("Content-Type", f.contentType)
	serveContent(w, r, time.Time{}, bytes.NewReader(f.data))
}
