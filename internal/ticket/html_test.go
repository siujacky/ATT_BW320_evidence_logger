package ticket

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/html"

	"attmonitor/internal/model"
)

// hostile strings: markup, attribute breakouts, script URLs and external references.
const (
	hostileScript = `<script>alert(1)</script>`
	hostileAttr   = `"><img src=x onerror=alert(1)>`
	hostileURL    = `https://evil.example/x.css`
	hostileStyle  = `</style><style>body{background:url(https://evil.example/a.png)}</style>`
	hostileSVG    = `<svg onload=alert(1)><a href="javascript:alert(2)">x</a></svg>`
)

// hostileScenario puts hostile strings into every text the report takes from records or
// options.
func hostileScenario(t *testing.T) (*scenario, Options) {
	s := realScenario(t)
	f := s.f
	at := s.now.Add(-30 * time.Minute)
	snap := snapshot(at, -313, true, true, 400000, lastChange)
	snap.System.Serial = "N93" + hostileScript
	snap.System.Model = "BGW320" + hostileAttr
	snap.System.Manufacturer = hostileSVG
	snap.Broadband.PONLinkStatus = "O5 " + hostileURL
	snap.Fiber.VendorName = hostileStyle
	f.add(at, model.TypeGatewaySnapshot, snap)
	f.add(at.Add(time.Second), model.TypeGatewayEvent, model.GatewayEvent{Kind: model.GwEvPONState, Before: hostileScript,
		After: hostileAttr, Detail: "javascript:alert(3) " + hostileSVG})
	inc := model.Incident{ID: "INC-" + hostileScript, Opened: at.Add(-10 * time.Minute).Format(time.RFC3339Nano), Closed: at.Format(time.RFC3339Nano),
		DurationSec: 600, State: model.StateISPOutage, Cause: hostileAttr, Attribution: model.AttrProvider, Rules: hostileURL,
		Summary: hostileStyle, Stats: model.IncidentStats{DowntimeSec: 120}}
	f.add(at.Add(2*time.Second), model.TypeIncidentClose, inc)
	l := wifi(80, false)
	l.Band = hostileSVG
	f.add(at.Add(3*time.Second), model.TypeLocalLink, l)
	o := s.options()
	o.Customer = Customer{Name: hostileScript, Account: hostileAttr, Address: hostileStyle, Phone: hostileURL, BestTime: hostileSVG, Notes: "line 1\n" + hostileScript}
	o.Verification = hostileStyle
	o.BundleName = hostileAttr + ".zip"
	o.Generator = hostileSVG
	return s, o
}

// TestHTMLSafety parses the rendered page: no scripts, no external references, no event
// handlers, and the hostile strings appear as text only.
func TestHTMLSafety(t *testing.T) {
	s, o := hostileScenario(t)
	rep, err := Build(context.Background(), s.f, o)
	if err != nil {
		t.Fatal(err)
	}
	page, err := rep.HTML()
	if err != nil {
		t.Fatal(err)
	}
	checkSafeHTML(t, page)
	text := pageText(t, page)
	for _, h := range []string{hostileScript, hostileAttr, hostileURL, hostileSVG} {
		if !strings.Contains(text, h) {
			t.Errorf("hostile string %q should appear as text", h)
		}
	}
	// The serial number goes into the requested action - as text.
	wantContains(t, "action", rep.Action.Text, "serial number N93"+hostileScript)
	// The customer's account goes into the page margins through CSS: escaped there, so the
	// hostile text cannot end the string, the declaration or the style element.
	style := styleText(t, page)
	// (Letters and digits stay as they are - "onerror" is then plain text inside the string.)
	for _, h := range []string{"<img", "</style", "url(", "@import", `"><`, "alert(", "x>"} {
		if strings.Contains(style, h) {
			t.Errorf("the stylesheet contains %q", h)
		}
	}
	if !strings.Contains(style, `@bottom-left { content: "AT\000026T\000020Fiber`) {
		t.Errorf("page identity not in the margin box:\n%s", style)
	}
}

// styleText returns the page's inline stylesheet.
func styleText(t *testing.T, page []byte) string {
	t.Helper()
	doc, err := html.Parse(bytes.NewReader(page))
	if err != nil {
		t.Fatal(err)
	}
	var out string
	var walk func(n *html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "style" && n.FirstChild != nil {
			out += n.FirstChild.Data
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)
	return out
}

// TestHTMLNoExternalReferences checks the ordinary report too.
func TestHTMLNoExternalReferences(t *testing.T) {
	s := realScenario(t)
	rep := mustBuild(t, s, s.options())
	page, err := rep.HTML()
	if err != nil {
		t.Fatal(err)
	}
	checkSafeHTML(t, page)
	for _, bad := range []string{"http://", "https://", "url(", "@import", "<script", "<link", "src=", "href="} {
		if bytes.Contains(bytes.ToLower(page), []byte(bad)) {
			t.Errorf("page contains %q", bad)
		}
	}
	text := pageText(t, page)
	wantContains(t, "page", text,
		"AT&T Fiber service problem evidence: 24 hours to 2026-10-05 09:00 CDT",
		"Summary for AT&T", "Requested action", "Monitoring coverage",
		"Customer name", "AT&T account number", "Best time to reach",
		"Gateway low-Rx ALARM threshold -29.5 dBm", "Gateway low-Rx WARNING threshold -29.2 dBm",
		"setup capture", "ALARM flag", "WARNING flag",
		groupFingerprint(genesisData().Fingerprint),
		"att-monitor verify-bundle", "python tools/verify_bundle.py",
		"openssl ts -verify -attime 1791170397 -digest "+sha256Hex(setupManifest(t)),
		"Window: 2026-10-04 09:00:00 CDT to 2026-10-05 09:00:00 CDT")
	// Blank customer fields render as fill-in lines.
	if n := bytes.Count(page, []byte(`<span class="fill"></span>`)); n != 6 {
		t.Errorf("%d fill-in lines, want 6", n)
	}
	// Print layout: US Letter, a page break before the details, every page numbered and
	// identified in its margin (finding: pages 2 onward carried no identity).
	css := styleText(t, page)
	wantContains(t, "css", css, "size: Letter;", ".sheet + .sheet { break-before: page; }",
		`@bottom-right { content: "Page " counter(page) " of " counter(pages);`,
		`@bottom-left { content: "AT\000026T\000020Fiber\000020service\000020problem\000020evidence\00002c\0000202026\00002d10\00002d04\00002014\00003a00`)
	// Long values never widen the page (the browser would shrink the whole document to fit).
	wantContains(t, "css", css, "td { overflow-wrap: anywhere; }")
	// No text halo: a stroked label is printed twice into the PDF's text.
	wantNotContains(t, "css", css, "paint-order")
	checkBreakAll(t, css)
}

// checkBreakAll: only long values (.ba) and command arguments longer than a line (.code .arg) may
// break between any two characters - hashes, paths and commands broke in the middle.
func checkBreakAll(t *testing.T, css string) {
	t.Helper()
	for _, line := range strings.Split(css, "\n") {
		if strings.Contains(line, "break-all") && !strings.HasPrefix(line, ".ba {") && !strings.HasPrefix(line, ".code .arg {") {
			t.Errorf("break-all in %q", line)
		}
	}
}

// checkSafeHTML walks the parsed document.
func checkSafeHTML(t *testing.T, page []byte) {
	t.Helper()
	doc, err := html.Parse(bytes.NewReader(page))
	if err != nil {
		t.Fatal(err)
	}
	forbidden := map[string]bool{"script": true, "link": true, "img": true, "iframe": true, "object": true, "embed": true,
		"a": true, "image": true, "use": true, "foreignobject": true, "base": true, "form": true, "audio": true, "video": true, "source": true}
	styles := 0
	var walk func(n *html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode {
			if forbidden[strings.ToLower(n.Data)] {
				t.Errorf("forbidden element <%s>", n.Data)
			}
			if n.Data == "style" {
				styles++
				if n.FirstChild != nil && (strings.Contains(n.FirstChild.Data, "url(") || strings.Contains(n.FirstChild.Data, "@import")) {
					t.Error("style element loads a resource")
				}
			}
			for _, a := range n.Attr {
				k := strings.ToLower(a.Key)
				v := strings.ToLower(a.Val)
				if strings.HasPrefix(k, "on") || k == "href" || k == "src" || k == "srcset" || k == "xlink:href" || k == "action" || k == "style" {
					t.Errorf("forbidden attribute %s=%q on <%s>", a.Key, a.Val, n.Data)
				}
				if strings.Contains(v, "://") || strings.Contains(v, "javascript:") || strings.Contains(v, "url(") {
					t.Errorf("attribute %s=%q on <%s> references something", a.Key, a.Val, n.Data)
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)
	if styles != 1 {
		t.Errorf("%d style elements, want the one inline stylesheet", styles)
	}
}

// pageText returns the document's text content (what a reader sees): text nodes in order, with a
// space only where a block element (a cell, a paragraph, a list item...) ends a run of text.
func pageText(t *testing.T, page []byte) string {
	t.Helper()
	doc, err := html.Parse(bytes.NewReader(page))
	if err != nil {
		t.Fatal(err)
	}
	inline := map[string]bool{"span": true, "b": true, "strong": true, "em": true, "i": true, "code": true, "small": true}
	var b strings.Builder
	var walk func(n *html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "style" {
			return
		}
		if n.Type == html.TextNode {
			b.WriteString(n.Data)
		}
		block := n.Type == html.ElementNode && !inline[n.Data]
		if block {
			b.WriteByte(' ')
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
		if block {
			b.WriteByte(' ')
		}
	}
	walk(doc)
	return oneLine(b.String())
}
