package web

import (
	"bytes"
	"encoding/json"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestStaticFilesServedWithContentTypes(t *testing.T) {
	hs := newHarness(t)
	tests := []struct {
		path, ctype, contains string
	}{
		{"/", "text/html; charset=utf-8", `<script src="/static/app.js" defer></script>`},
		{"/static/index.html", "text/html; charset=utf-8", "<!doctype html>"},
		{"/static/app.js", "text/javascript; charset=utf-8", "'use strict';"},
		{"/static/style.css", "text/css; charset=utf-8", "prefers-color-scheme: dark"},
		{"/static/favicon.svg", "image/svg+xml", "<svg"},
		// The Network page's world map: JSON, never sniffed or run as a script (nosniff).
		{"/static/world.json", "application/json; charset=utf-8", `"countries":[`},
	}
	for _, tc := range tests {
		t.Run(tc.path, func(t *testing.T) {
			rec := hs.get(tc.path)
			wantStatus(t, rec, http.StatusOK)
			if got := rec.Header().Get("Content-Type"); got != tc.ctype {
				t.Errorf("Content-Type = %q, want %q", got, tc.ctype)
			}
			if !strings.Contains(rec.Body.String(), tc.contains) {
				t.Errorf("body does not contain %q", tc.contains)
			}
			assertSecurityHeaders(t, rec.Header(), false)
			head := hs.serve(hs.request(http.MethodHead, tc.path, nil, nil))
			wantStatus(t, head, http.StatusOK)
			if head.Body.Len() != 0 || head.Header().Get("Content-Type") != tc.ctype {
				t.Errorf("HEAD: body %d bytes, type %q", head.Body.Len(), head.Header().Get("Content-Type"))
			}
		})
	}
	for _, p := range []string{"/static/missing.css", "/static/static/app.js", "/static/server.go", "/index.html", "/favicon.ico"} {
		wantJSONError(t, hs.get(p), http.StatusNotFound)
	}
	// Dot segments are cleaned by ServeMux (redirect), never resolved against the file system.
	rec := hs.get("/static/../server.go")
	if rec.Code/100 != 3 || rec.Header().Get("Location") != "/server.go" {
		t.Errorf("dot-segment request: %d Location=%q", rec.Code, rec.Header().Get("Location"))
	}
	assertSecurityHeaders(t, rec.Header(), false)
}

func TestIndexCarriesEscapedVersion(t *testing.T) {
	s, err := New(Options{Version: `1.0 <script>"x"</script>`})
	if err != nil {
		t.Fatal(err)
	}
	body := string(s.index.data)
	if strings.Contains(body, versionPlaceholder) {
		t.Fatal("version placeholder not replaced")
	}
	if strings.Contains(body, "<script>\"x\"") {
		t.Fatal("version inserted without HTML escaping")
	}
	if !strings.Contains(body, `content="1.0 &lt;script&gt;&#34;x&#34;&lt;/script&gt;"`) {
		t.Errorf("escaped version not found in index")
	}
	s2, _ := New(Options{})
	if !strings.Contains(string(s2.index.data), `content="dev"`) {
		t.Error(`empty version should render as "dev"`)
	}
}

// TestWorldMapData checks static/world.json, the Network page's world map (scripts/worldmap):
// the countries of Natural Earth 1:110m as SVG paths keyed by ISO 3166-1 alpha-2 code. The
// dashboard sets each path's d attribute from it, so a path may hold nothing but the commands
// M, L and Z with plain numbers; it must stay small enough to load at once.
func TestWorldMapData(t *testing.T) {
	b, err := staticFS.ReadFile("static/world.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(b) > 200<<10 {
		t.Errorf("world.json is %d bytes, more than 200 KiB", len(b))
	}
	var world struct {
		Source    string `json:"source"`
		License   string `json:"license"`
		W         int    `json:"w"`
		H         int    `json:"h"`
		Countries []struct {
			ID   string `json:"id"`
			Name string `json:"n"`
			D    string `json:"d"`
		} `json:"countries"`
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&world); err != nil {
		t.Fatalf("world.json: %v", err)
	}
	if world.W != 1000 || world.H < 300 || world.H > 600 || !strings.Contains(world.Source, "Natural Earth") {
		t.Errorf("world.json: w %d, h %d, source %q", world.W, world.H, world.Source)
	}
	// world-atlas's ISC licence asks for its copyright and permission notice in every copy: the map
	// carries it, and so does the program that embeds the map.
	if !strings.Contains(world.License, "Copyright") || !strings.Contains(world.License, "Michael Bostock") ||
		!strings.Contains(world.License, "provided that the above copyright notice and this permission notice appear in all copies") {
		t.Errorf("world.json does not carry world-atlas's licence notice: %q", world.License)
	}
	if len(world.Countries) < 150 {
		t.Fatalf("world.json has %d countries", len(world.Countries))
	}
	code := regexp.MustCompile(`^[A-Z]{2}$`)
	path := regexp.MustCompile(`^(M-?[0-9.]+,-?[0-9.]+L(-?[0-9.]+,-?[0-9.]+ ?)+Z)+$`)
	ids := map[string]bool{}
	for _, c := range world.Countries {
		if !code.MatchString(c.ID) || c.Name == "" || !path.MatchString(c.D) {
			t.Errorf("country %q (%q): path %.60q", c.ID, c.Name, c.D)
		}
		ids[c.ID] = true
	}
	for _, want := range []string{"US", "CA", "BR", "GB", "DE", "FR", "NL", "IE", "CN", "JP", "IN", "AU", "RU", "ZA"} {
		if !ids[want] {
			t.Errorf("world.json has no %s", want)
		}
	}
}

// TestStaticHasNoExternalReferences enforces the offline requirement: the dashboard must work
// while the internet connection is down, so it may not load anything from another origin.
func TestStaticHasNoExternalReferences(t *testing.T) {
	// XML namespace identifiers are names, not fetched resources.
	allowed := map[string]bool{"http://www.w3.org/2000/svg": true}
	urlRe := regexp.MustCompile(`(?i)\b(?:https?|ftp|wss?):\/\/[^\s"'<>)]+`)
	protoRelRe := regexp.MustCompile(`(?i)(?:src|href|action|url)\s*[=(]\s*["']?\s*//`)
	importRe := regexp.MustCompile(`(?i)@import|<iframe|<object|<embed|\beval\(|new Function\(|\.innerHTML\s*=|insertAdjacentHTML|document\.write`)
	err := fs.WalkDir(staticFS, "static", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := staticFS.ReadFile(p)
		if err != nil {
			return err
		}
		text := string(b)
		for _, m := range urlRe.FindAllString(text, -1) {
			if !allowed[strings.TrimRight(m, ".,;")] {
				t.Errorf("%s references an external URL: %s", p, m)
			}
		}
		if m := protoRelRe.FindString(text); m != "" {
			t.Errorf("%s has a protocol-relative reference: %s", p, m)
		}
		if m := importRe.FindString(text); m != "" {
			t.Errorf("%s uses a forbidden construct: %s", p, m)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestStaticCompatibleWithCSP checks that nothing in the markup needs 'unsafe-inline':
// no inline <script> bodies, no <style> elements, no style= or on*= attributes.
func TestStaticCompatibleWithCSP(t *testing.T) {
	index, err := staticFS.ReadFile("static/index.html")
	if err != nil {
		t.Fatal(err)
	}
	html := string(index)
	for _, re := range []*regexp.Regexp{
		regexp.MustCompile(`(?is)<script(?:\s[^>]*)?>\s*[^<\s]`), // inline script body
		regexp.MustCompile(`(?i)<style`),
		regexp.MustCompile(`(?i)\sstyle\s*=`),
		regexp.MustCompile(`(?i)\son[a-z]+\s*=`),
		regexp.MustCompile(`(?i)javascript:`),
	} {
		if m := re.FindString(html); m != "" {
			t.Errorf("index.html needs an unsafe CSP: %q", m)
		}
	}
	js, err := staticFS.ReadFile("static/app.js")
	if err != nil {
		t.Fatal(err)
	}
	for _, re := range []*regexp.Regexp{
		regexp.MustCompile(`setAttribute\(\s*['"]style['"]`),
		regexp.MustCompile(`setAttribute\(\s*['"]on[a-z]+['"]`),
		regexp.MustCompile(`\.outerHTML\s*=`),
	} {
		if m := re.FindString(string(js)); m != "" {
			t.Errorf("app.js would be blocked by the CSP: %q", m)
		}
	}
}

// TestAppJSSyntax runs `node --check` on the embedded script when Node.js is installed.
func TestAppJSSyntax(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed; skipping JavaScript syntax check")
	}
	js, err := staticFS.ReadFile("static/app.js")
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "app.js")
	if err := os.WriteFile(p, js, 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(node, "--check", p).CombinedOutput()
	if err != nil {
		t.Fatalf("node --check app.js: %v\n%s", err, out)
	}
}
