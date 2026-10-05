package gateway

import (
	"strconv"
	"strings"

	"golang.org/x/net/html"
)

// The scanner below walks a page with the x/net/html tokenizer (not the tree builder: the
// HTML5 tree-construction rules re-parent misplaced content, while the gateway's pages are
// best read in source order) and extracts the few structures the parsers need: the title,
// headings, table rows with their cells, forms and inputs, and the visible text.

// cell is one <td> or <th>.
type cell struct {
	th   bool
	text string // whitespace-normalized visible text
	span int    // colspan (>= 1)
}

// row is one table row in document order.
type row struct {
	table   int // document-order index of the innermost enclosing <table>
	section int // index into page.headings of the nearest preceding heading, -1 if none
	cells   []cell
}

// form is one <form> element.
type form struct {
	action, method string
}

// input is one <input> element.
type input struct {
	form    int // index into page.forms, -1 when outside any form
	typ     string
	name    string
	id      string
	value   string
	checked bool
}

// page is the scanned representation of one gateway page.
type page struct {
	title    string
	headings []string // h1-h6 texts in document order (empty headings skipped)
	rows     []row
	forms    []form
	inputs   []input
	text     string // all visible text (scripts, styles and other raw-text elements excluded)
}

// sectionName returns the heading text for a row's section index ("" if none).
func (p *page) sectionName(i int) string {
	if i < 0 || i >= len(p.headings) {
		return ""
	}
	return p.headings[i]
}

// skippedRaw lists raw-text elements whose content is not visible page text.
var skippedRaw = map[string]bool{
	"script": true, "style": true, "noscript": true, "noembed": true, "noframes": true,
	"iframe": true, "xmp": true, "textarea": true, "plaintext": true,
}

// inlineTags do not separate words; every other tag boundary counts as white space so that
// "a<br>b" or "<td>a</td><td>b</td>" never fuse into "ab".
var inlineTags = map[string]bool{
	"a": true, "abbr": true, "b": true, "bdi": true, "bdo": true, "big": true, "cite": true,
	"code": true, "data": true, "dfn": true, "em": true, "font": true, "i": true, "img": true,
	"input": true, "kbd": true, "label": true, "mark": true, "nobr": true, "q": true, "s": true,
	"samp": true, "small": true, "span": true, "strike": true, "strong": true, "sub": true,
	"sup": true, "time": true, "tt": true, "u": true, "var": true, "wbr": true,
}

// tableState tracks an open <table>.
type tableState struct {
	index  int
	row    *row
	cell   *strings.Builder
	cellTH bool
	span   int
}

// maxTableDepth bounds table nesting; deeper <table> tags are treated as part of the
// enclosing table (hostile or broken pages cannot make the scanner allocate without bound).
const maxTableDepth = 32

type scanner struct {
	p          *page
	skip       string // raw-text element whose content is being skipped
	inTitle    bool
	titleSeen  bool
	titleBuf   strings.Builder
	inHeading  bool
	headBuf    strings.Builder
	section    int
	tables     []*tableState
	tableCount int
	overflow   int // <table> tags ignored beyond maxTableDepth and not yet closed
	form       int
	textBuf    strings.Builder
}

// scan parses body (any encoding, see decode). It never fails: malformed markup simply
// yields whatever could be recognized.
func scan(body []byte) *page {
	s := &scanner{p: &page{}, section: -1, form: -1}
	z := html.NewTokenizer(strings.NewReader(decode(body)))
	for {
		tt := z.Next()
		switch tt {
		case html.ErrorToken: // io.EOF or a tokenizer error: finish with what we have
			s.finish()
			return s.p
		case html.TextToken:
			s.onText(string(z.Text()))
		case html.StartTagToken, html.SelfClosingTagToken:
			name, hasAttr := z.TagName()
			tag := string(name)
			var attrs map[string]string
			if hasAttr {
				attrs = make(map[string]string)
				for {
					k, v, more := z.TagAttr()
					key := string(k)
					if _, dup := attrs[key]; !dup { // first occurrence wins, as in HTML
						attrs[key] = string(v)
					}
					if !more {
						break
					}
				}
			}
			s.onStart(tag, attrs, tt == html.SelfClosingTagToken)
		case html.EndTagToken:
			name, _ := z.TagName()
			s.onEnd(string(name))
		}
	}
}

func (s *scanner) top() *tableState {
	if len(s.tables) == 0 {
		return nil
	}
	return s.tables[len(s.tables)-1]
}

// sep records a word boundary in every active text buffer.
func (s *scanner) sep() {
	s.textBuf.WriteByte(' ')
	if s.inHeading {
		s.headBuf.WriteByte(' ')
	}
	if t := s.top(); t != nil && t.cell != nil {
		t.cell.WriteByte(' ')
	}
}

func (s *scanner) onText(txt string) {
	if s.skip != "" {
		return
	}
	if s.inTitle {
		s.titleBuf.WriteString(txt)
		return
	}
	s.textBuf.WriteString(txt)
	if s.inHeading {
		s.headBuf.WriteString(txt)
	}
	if t := s.top(); t != nil && t.cell != nil {
		t.cell.WriteString(txt)
	}
}

func (s *scanner) onStart(tag string, attrs map[string]string, selfClosing bool) {
	if s.skip != "" {
		return // cannot happen with the tokenizer's raw-text handling; be defensive
	}
	if !inlineTags[tag] {
		s.sep()
	}
	switch tag {
	case "title":
		// Like the tokenizer, treat "<title/>" as an opening tag: its RCDATA follows.
		s.inTitle = true
		s.titleBuf.Reset()
	case "h1", "h2", "h3", "h4", "h5", "h6":
		s.closeHeading()
		if !selfClosing {
			s.inHeading = true
			s.headBuf.Reset()
		}
	case "table":
		if selfClosing {
			break
		}
		if len(s.tables) >= maxTableDepth {
			s.overflow++
			break
		}
		s.tables = append(s.tables, &tableState{index: s.tableCount})
		s.tableCount++
	case "tr":
		if t := s.top(); t != nil {
			s.closeRow(t)
			t.row = &row{table: t.index, section: s.section}
		}
	case "td", "th":
		if t := s.top(); t != nil {
			s.closeCell(t)
			if t.row == nil { // cell without <tr>: open an implicit row
				t.row = &row{table: t.index, section: s.section}
			}
			t.cell = &strings.Builder{}
			t.cellTH = tag == "th"
			t.span = colspan(attrs["colspan"])
			if selfClosing {
				s.closeCell(t)
			}
		}
	case "thead", "tbody", "tfoot":
		if t := s.top(); t != nil {
			s.closeRow(t)
		}
	case "form":
		// Like HTML parsers, ignore a <form> nested inside an open form.
		if s.form < 0 {
			s.p.forms = append(s.p.forms, form{action: attrs["action"], method: attrs["method"]})
			s.form = len(s.p.forms) - 1
		}
	case "input":
		_, checked := attrs["checked"] // presence is what counts in HTML
		s.p.inputs = append(s.p.inputs, input{
			form:    s.form,
			typ:     strings.ToLower(strings.TrimSpace(attrs["type"])),
			name:    attrs["name"],
			id:      attrs["id"],
			value:   attrs["value"],
			checked: checked,
		})
	}
	if skippedRaw[tag] {
		// The tokenizer reads raw text after these tags even when written self-closing
		// ("<script/>"), up to the matching end tag; skip exactly what it treats as raw.
		s.skip = tag
	}
}

func (s *scanner) onEnd(tag string) {
	if s.skip != "" {
		if tag == s.skip {
			s.skip = ""
		}
		return
	}
	switch tag {
	case "title":
		if s.inTitle {
			s.inTitle = false
			if !s.titleSeen {
				s.titleSeen = true
				s.p.title = normSpace(s.titleBuf.String())
			}
		}
	case "h1", "h2", "h3", "h4", "h5", "h6":
		s.closeHeading()
	case "table":
		if s.overflow > 0 {
			s.overflow--
			break
		}
		if t := s.top(); t != nil {
			s.closeRow(t)
			s.tables = s.tables[:len(s.tables)-1]
		}
	case "tr", "thead", "tbody", "tfoot":
		if t := s.top(); t != nil {
			s.closeRow(t)
		}
	case "td", "th":
		if t := s.top(); t != nil {
			s.closeCell(t)
		}
	case "form":
		s.form = -1
	}
	if !inlineTags[tag] {
		s.sep()
	}
}

func (s *scanner) closeHeading() {
	if !s.inHeading {
		return
	}
	s.inHeading = false
	if h := normSpace(s.headBuf.String()); h != "" {
		s.p.headings = append(s.p.headings, h)
		s.section = len(s.p.headings) - 1
	}
}

func (s *scanner) closeCell(t *tableState) {
	if t.cell == nil {
		return
	}
	if t.row != nil {
		t.row.cells = append(t.row.cells, cell{th: t.cellTH, text: normSpace(t.cell.String()), span: t.span})
	}
	t.cell = nil
}

func (s *scanner) closeRow(t *tableState) {
	s.closeCell(t)
	if t.row != nil && len(t.row.cells) > 0 {
		s.p.rows = append(s.p.rows, *t.row)
	}
	t.row = nil
}

func (s *scanner) finish() {
	s.closeHeading()
	for len(s.tables) > 0 {
		s.closeRow(s.top())
		s.tables = s.tables[:len(s.tables)-1]
	}
	if s.inTitle && !s.titleSeen {
		s.p.title = normSpace(s.titleBuf.String())
	}
	s.p.text = normSpace(s.textBuf.String())
}

// colspan parses a colspan attribute (missing, invalid or out-of-range values mean 1).
func colspan(v string) int {
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil || n < 1 {
		return 1
	}
	if n > 1000 {
		return 1000
	}
	return n
}

// ---------------------------------------------------------------- page-level helpers

const (
	accessCodeRequired = "access code required"
	sessionsInUse      = "all web server sessions are in use"
)

// isLogin reports whether p is the gateway's login page (docs/DESIGN.md §2): title "Login",
// the "Access Code Required" banner, or the login form (action login.ha, or the hidden
// hashpassword field / id="password" input that belong to it).
func (p *page) isLogin() bool {
	if strings.EqualFold(p.title, "login") {
		return true
	}
	if strings.Contains(strings.ToLower(p.text), accessCodeRequired) {
		return true
	}
	for _, f := range p.forms {
		if isLoginAction(f.action) {
			return true
		}
	}
	for _, in := range p.inputs {
		if strings.EqualFold(in.name, "hashpassword") {
			return true
		}
		if strings.EqualFold(in.id, "password") && in.form >= 0 && in.form < len(p.forms) &&
			strings.Contains(strings.ToLower(p.forms[in.form].action), "login") {
			return true
		}
	}
	return false
}

// isLoginAction reports whether a form action or redirect target points at login.ha.
func isLoginAction(u string) bool {
	u = strings.ToLower(strings.TrimSpace(u))
	if i := strings.IndexAny(u, "?#"); i >= 0 {
		u = u[:i]
	}
	return u == "login.ha" || strings.HasSuffix(u, "/login.ha")
}

// sessionsFull reports whether the page carries the gateway's "all web server sessions are
// in use" message (session pool exhausted). Only visible text and the title are considered,
// so a script that merely contains the string cannot trigger it.
func (p *page) sessionsFull() bool {
	return strings.Contains(strings.ToLower(p.text), sessionsInUse) ||
		strings.Contains(strings.ToLower(p.title), sessionsInUse)
}

// nonce returns the value of the hidden "nonce" input of the form whose action ends with
// actionSuffix (e.g. "/login.ha"), falling back to the first nonce on the page when no such
// form exists. Values that are empty, very long or contain characters outside printable
// ASCII are rejected ("" is returned).
func (p *page) nonce(actionSuffix string) string {
	pick := func(match func(in input) bool) string {
		for _, in := range p.inputs {
			if in.name == "nonce" && match(in) && validNonce(in.value) {
				return in.value
			}
		}
		return ""
	}
	suffix := strings.ToLower(actionSuffix)
	if v := pick(func(in input) bool {
		if in.form < 0 || in.form >= len(p.forms) {
			return false
		}
		a := strings.ToLower(strings.TrimSpace(p.forms[in.form].action))
		if i := strings.IndexAny(a, "?#"); i >= 0 {
			a = a[:i]
		}
		return strings.HasSuffix(a, suffix)
	}); v != "" {
		return v
	}
	return pick(func(input) bool { return true })
}

func validNonce(v string) bool {
	if v == "" || len(v) > 512 {
		return false
	}
	for i := 0; i < len(v); i++ {
		if v[i] <= 0x20 || v[i] >= 0x7F {
			return false
		}
	}
	return true
}
