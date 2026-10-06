package gateway

import (
	"bytes"
	"errors"
	"regexp"
	"strings"

	"golang.org/x/net/html"
)

// The form reader reads every <form> of a gateway page the way a browser without JavaScript
// does, so that a settings page can be posted back exactly as the gateway's own page posts it.
// The gateway's settings pages are written for that case: an item with an Update button (in a
// <noscript> element) is changed by posting the form with that button, and the gateway answers
// with the page transformed accordingly. <noscript> content is therefore read as markup here,
// unlike in scan.go, which reads the text a person sees.
//
// For each form it records the method, action and every control in document order with its
// current value as a browser computes it, and each control's label: the text of a <label
// for=id> naming it, else of a <label> around it, else of the <th> of its table row.
// pageForm.encode returns the application/x-www-form-urlencoded body a browser posts for a
// given submit button (HTML "constructing the entry list"). Like scan.go the reader uses the
// x/net/html tokenizer: a control belongs to the form whose start tag precedes it and that is
// still open (the HTML parser's form element pointer), also when the form opens inside a
// table, where the controls would not be the form's descendants in a DOM tree.

// pageForm is one <form> of a page.
type pageForm struct {
	method   string         // "get" (also when absent or invalid), "post" or "dialog"
	action   string         // the action attribute as written ("" = the page's own URL)
	enctype  string         // formURLEncoded (also when absent or invalid), "multipart/form-data" or "text/plain"
	controls []*formControl // in document order
}

// formURLEncoded is the default form encoding, the only one encode produces.
const formURLEncoded = "application/x-www-form-urlencoded"

// formControl is one control of a form: an <input>, <select>, <textarea> or <button>.
type formControl struct {
	tag string // "input", "select", "textarea" or "button"
	// typ is an input's type, lower case ("text" when the attribute is absent or unknown, as
	// in browsers), a button's "submit" (default), "reset" or "button", a select's
	// "select-one" or "select-multiple", or "textarea".
	typ      string
	name, id string
	// value is the current value of an input, textarea or button; a checkbox or radio button
	// submits it when checked ("on" without a value attribute). As in browsers, newlines are
	// removed from the value of a text or password input, and a number input's value that is
	// not a valid number is empty.
	value    string
	hasValue bool // the value attribute is present
	checked  bool // checkbox and radio button
	disabled bool // the control, or a <fieldset disabled> around it, is disabled
	readOnly bool
	maxLen   int               // the maxlength attribute, -1 when absent or invalid
	size     int               // select: the display size (1 for a drop-down list)
	options  []*selectOption   // select: in document order
	text     string            // button: its text
	submit   map[string]string // submit button: its formaction, formmethod and formenctype attributes

	// label is the text of the first <label for=id> naming the control, else of a <label>
	// around it, else - for a control that is neither a button nor a hidden input - row;
	// labelFrom says which.
	label     string
	labelFrom labelSource
	// row is the text of the nearest non-empty <th> before the control (or around it) in its
	// table row, else of the first one after it in that row ("" when there is none).
	row              string
	labelKey, rowKey string // alnumKey of label and row

	owner      int    // index of the form the control belongs to, -1 when none
	formRef    string // the form attribute (formRefSet: present), which overrides the position
	formRefSet bool
}

// selectOption is one <option> of a select.
type selectOption struct {
	value    string // the value attribute, else the text with white space collapsed
	text     string // as displayed: the label attribute when not empty, else the text
	selected bool   // after parsing as in browsers (see resolveSelect)
	disabled bool   // the option or its <optgroup> is disabled
}

// labelSource says where a control's label comes from.
type labelSource int

const (
	labelNone labelSource = iota
	labelFor              // a <label for=id>
	labelWrap             // a <label> around the control
	labelRow              // the <th> of the control's table row
)

// isButton reports whether the control is a button, which is submitted only when it is the
// one clicked (submit, image) or never (reset, button).
func (c *formControl) isButton() bool {
	if c.tag == "button" {
		return true
	}
	switch c.typ {
	case "submit", "image", "reset", "button":
		return c.tag == "input"
	}
	return false
}

// isSubmit reports whether clicking the control submits its form.
func (c *formControl) isSubmit() bool {
	return c.tag == "button" && c.typ == "submit" || c.tag == "input" && (c.typ == "submit" || c.typ == "image")
}

// labelable reports whether a <label> can name the control (every control but a hidden input).
func (c *formControl) labelable() bool { return !(c.tag == "input" && c.typ == "hidden") }

// isField reports whether the control holds a value a person sets: not a hidden input, not a
// button.
func (c *formControl) isField() bool { return c.labelable() && !c.isButton() }

// isRadio reports whether the control is a radio button.
func (c *formControl) isRadio() bool { return c.tag == "input" && c.typ == "radio" }

// ---------------------------------------------------------------- reading

// formRawText are the elements whose content the tokenizer returns as a single text token.
var formRawText = map[string]bool{
	"script": true, "style": true, "title": true, "textarea": true, "xmp": true, "iframe": true,
	"noembed": true, "noframes": true, "noscript": true, "plaintext": true,
}

// maxNoscriptDepth bounds the nesting of <noscript> elements read as markup; deeper content
// is skipped. Each level tokenizes its content again, so the work stays linear in the size of
// the page.
const maxNoscriptDepth = 8

type formReader struct {
	forms    []*pageForm
	controls []*formControl     // every control in document order
	open     int                // the form element pointer: index of the open form, -1 if none
	ids      map[string]idEntry // the first element carrying each id

	raw      string       // raw-text element whose content the tokenizer returns next
	textarea *formControl // textarea whose content is next

	sel           *formControl // open <select>
	opt           *openOption  // its open <option>
	groupDisabled bool         // its open <optgroup> is disabled

	button     *formControl // open <button>
	buttonText strings.Builder

	labels []*labelElem
	label  *labelElem // open <label>

	tables   []*formTable
	overflow int // <table> tags ignored beyond maxTableDepth and not yet closed

	fieldsets []fieldsetState
	fsOff     int // open fieldsets that disable the controls at the current position
}

// idEntry is the first element of a page with a given id.
type idEntry struct {
	form    int          // index of the form when the element is a <form>, else -1
	control *formControl // the control when the element is one
}

// openOption is an <option> whose content is being read.
type openOption struct {
	opt      *selectOption
	hasValue bool
	label    string // the label attribute
	text     strings.Builder
}

// labelElem is one <label>.
type labelElem struct {
	forID   string
	hasFor  bool
	text    strings.Builder
	control *formControl // the first labelable control inside it
}

// formTable is an open <table>: its open row and cell.
type formTable struct {
	row    *formRow
	inCell bool
	inTH   bool // the open cell is a <th>, whose text is collected in thText
	thText strings.Builder
}

// formRow is a table row: the texts of its <th> cells and its controls, in document order.
type formRow struct {
	ths      []string
	controls []rowControl
}

type rowControl struct {
	c     *formControl
	after int // <th> cells opened in the row before the control (including one around it)
}

// fieldsetState is an open <fieldset>.
type fieldsetState struct {
	disabled bool // its disabled attribute
	legends  int  // <legend> tags opened inside it (approximates its legend children)
	inLegend bool // inside its first legend, which a disabled fieldset does not disable
}

// parseForms reads the forms of body (any encoding, see decode). It never fails: malformed
// markup yields whatever could be recognized.
func parseForms(body []byte) []*pageForm {
	r := &formReader{open: -1, ids: map[string]idEntry{}}
	r.read(html.NewTokenizer(strings.NewReader(decode(body))), 0)
	r.finish()
	return r.forms
}

// read processes the tokens of z; depth is the <noscript> nesting of its content.
func (r *formReader) read(z *html.Tokenizer, depth int) {
	for {
		switch z.Next() {
		case html.ErrorToken: // io.EOF or a tokenizer error: finish with what we have
			return
		case html.TextToken:
			r.onText(z.Text(), depth)
		case html.StartTagToken, html.SelfClosingTagToken:
			// As in browsers, "/>" does not close an element that is not void.
			name, hasAttr := z.TagName()
			tag := string(name)
			attrs := tagAttrs(z, hasAttr)
			r.raw = ""
			r.onStart(tag, attrs)
		case html.EndTagToken:
			name, _ := z.TagName()
			r.raw = ""
			r.onEnd(string(name))
		default:
			r.raw = ""
		}
	}
}

// tagAttrs returns the attributes of the current tag (the tokenizer keeps the first of
// duplicates, as HTML does).
func tagAttrs(z *html.Tokenizer, more bool) map[string]string {
	if !more {
		return nil
	}
	attrs := make(map[string]string)
	for more {
		var k, v []byte
		k, v, more = z.TagAttr()
		attrs[string(k)] = string(v)
	}
	return attrs
}

func (r *formReader) onText(t []byte, depth int) {
	switch raw := r.raw; {
	case raw == "textarea":
		r.raw = ""
		if r.textarea != nil {
			// As in browsers, a newline right after <textarea> is not part of the value.
			r.textarea.value = strings.TrimPrefix(string(t), "\n")
		}
		return
	case raw == "noscript":
		r.raw = ""
		if depth < maxNoscriptDepth {
			r.read(html.NewTokenizer(bytes.NewReader(t)), depth+1)
		}
		return
	case raw != "":
		r.raw = "" // script, style and other content that is not shown
		return
	}
	switch {
	case r.opt != nil:
		r.opt.text.Write(t)
	case r.sel != nil:
		// text in a select outside any option is not shown
	case r.button != nil:
		r.buttonText.Write(t)
	default:
		if r.label != nil {
			r.label.text.Write(t)
		}
		if tb := r.top(); tb != nil && tb.inTH {
			tb.thText.Write(t)
		}
	}
}

// sep records a word boundary in the label, <th> and button texts being read (option texts
// are kept exactly: an option without a value attribute submits its text).
func (r *formReader) sep() {
	switch {
	case r.sel != nil:
	case r.button != nil:
		r.buttonText.WriteByte(' ')
	default:
		if r.label != nil {
			r.label.text.WriteByte(' ')
		}
		if tb := r.top(); tb != nil && tb.inTH {
			tb.thText.WriteByte(' ')
		}
	}
}

func (r *formReader) onStart(tag string, attrs map[string]string) {
	if r.sel != nil {
		// Inside a select only options matter; the tags below end it, as the HTML parser's
		// "in select" insertion mode does.
		switch tag {
		case "option":
			r.startOption(attrs)
			return
		case "optgroup":
			r.closeOption()
			_, r.groupDisabled = attrs["disabled"]
			return
		case "hr":
			r.closeOption()
			r.groupDisabled = false
			return
		case "select":
			r.closeSelect() // acts as </select>; the tag itself is dropped
			return
		case "input", "textarea", "keygen", "table", "caption", "colgroup", "col", "tbody", "thead", "tfoot", "tr", "td", "th":
			r.closeSelect() // and the tag is processed below
		default:
			if formRawText[tag] {
				r.raw = tag // its content is not option text
			}
			return
		}
	}
	if !inlineTags[tag] {
		r.sep()
	}
	id, firstID := attrs["id"], false
	if _, dup := r.ids[id]; id != "" && !dup {
		r.ids[id] = idEntry{form: -1}
		firstID = true
	}
	switch tag {
	case "form":
		switch {
		case r.open < 0:
			r.forms = append(r.forms, &pageForm{
				method:  formMethod(attrs["method"]),
				action:  attrs["action"],
				enctype: formEnctype(attrs["enctype"]),
			})
			r.open = len(r.forms) - 1
			if firstID {
				r.ids[id] = idEntry{form: r.open}
			}
		case firstID:
			delete(r.ids, id) // a form inside an open form is dropped, as by HTML parsers
		}
	case "input":
		typ := inputType(attrs["type"])
		c := r.newControl("input", typ, attrs, firstID)
		switch typ {
		case "checkbox", "radio":
			_, c.checked = attrs["checked"]
			if !c.hasValue {
				c.value = "on"
			}
		default:
			c.value = sanitizeValue(typ, c.value)
		}
	case "select":
		_, multiple := attrs["multiple"]
		typ, size := "select-one", parseNonNegInt(attrs["size"])
		if multiple {
			typ = "select-multiple"
		}
		if size < 1 {
			size = 1
			if multiple {
				size = 4
			}
		}
		c := r.newControl("select", typ, attrs, firstID)
		c.size = size
		r.sel = c
	case "textarea":
		r.textarea = r.newControl("textarea", "textarea", attrs, firstID)
	case "button":
		r.closeButton() // a button start tag ends an open button
		typ := strings.ToLower(attrs["type"])
		if typ != "reset" && typ != "button" {
			typ = "submit"
		}
		r.button = r.newControl("button", typ, attrs, firstID)
	case "label":
		l := &labelElem{}
		l.forID, l.hasFor = attrs["for"]
		r.labels = append(r.labels, l)
		r.label = l
	case "fieldset":
		_, off := attrs["disabled"]
		r.fieldsets = append(r.fieldsets, fieldsetState{disabled: off})
		if off {
			r.fsOff++
		}
	case "legend":
		if n := len(r.fieldsets); n > 0 {
			f := &r.fieldsets[n-1]
			if f.legends++; f.legends == 1 {
				f.inLegend = true
				if f.disabled {
					r.fsOff--
				}
			}
		}
	case "table":
		r.closeInline()
		if len(r.tables) >= maxTableDepth {
			r.overflow++
			break
		}
		r.tables = append(r.tables, &formTable{})
	case "tr":
		r.closeInline()
		if t := r.top(); t != nil {
			r.closeRow(t)
			t.row = &formRow{}
		}
	case "td", "th":
		r.closeInline()
		if t := r.top(); t != nil {
			r.closeCell(t)
			if t.row == nil { // cell without <tr>: open an implicit row
				t.row = &formRow{}
			}
			t.inCell = true
			if tag == "th" {
				t.inTH = true
				t.thText.Reset()
				t.row.ths = append(t.row.ths, "")
			}
		}
	case "thead", "tbody", "tfoot":
		r.closeInline()
		if t := r.top(); t != nil {
			r.closeRow(t)
		}
	}
	if formRawText[tag] {
		r.raw = tag
	}
}

// closeInline ends an open <label> and <button> at a table cell, row or table boundary and at
// the end of the form, where a browser's parser closes them too: a label or button left open
// by sloppy markup must not take in the text and controls that follow.
func (r *formReader) closeInline() {
	r.label = nil
	r.closeButton()
}

func (r *formReader) onEnd(tag string) {
	if r.sel != nil {
		switch tag {
		case "option":
			r.closeOption()
			return
		case "optgroup":
			r.closeOption()
			r.groupDisabled = false
			return
		case "select":
			r.closeSelect()
			return
		case "form", "table", "caption", "tbody", "thead", "tfoot", "tr", "td", "th":
			r.closeSelect() // and the tag is processed below
		default:
			return
		}
	}
	if !inlineTags[tag] {
		r.sep()
	}
	switch tag {
	case "form", "table", "caption", "tbody", "thead", "tfoot", "tr", "td", "th":
		r.closeInline()
	}
	switch tag {
	case "form":
		r.open = -1
	case "button":
		r.closeButton()
	case "label":
		r.label = nil
	case "textarea":
		r.textarea = nil
	case "fieldset":
		if n := len(r.fieldsets); n > 0 {
			if f := r.fieldsets[n-1]; f.disabled && !f.inLegend {
				r.fsOff--
			}
			r.fieldsets = r.fieldsets[:n-1]
		}
	case "legend":
		if n := len(r.fieldsets); n > 0 {
			if f := &r.fieldsets[n-1]; f.inLegend {
				f.inLegend = false
				if f.disabled {
					r.fsOff++
				}
			}
		}
	case "table":
		if r.overflow > 0 {
			r.overflow--
			break
		}
		if t := r.top(); t != nil {
			r.closeRow(t)
			r.tables = r.tables[:len(r.tables)-1]
		}
	case "tr", "thead", "tbody", "tfoot":
		if t := r.top(); t != nil {
			r.closeRow(t)
		}
	case "td", "th":
		if t := r.top(); t != nil {
			r.closeCell(t)
		}
	}
}

// newControl records a control at the current position.
func (r *formReader) newControl(tag, typ string, attrs map[string]string, firstID bool) *formControl {
	c := &formControl{tag: tag, typ: typ, name: attrs["name"], id: attrs["id"], owner: r.open, maxLen: -1}
	c.value, c.hasValue = attrs["value"]
	_, off := attrs["disabled"]
	c.disabled = off || r.fsOff > 0
	_, c.readOnly = attrs["readonly"]
	if v, ok := attrs["maxlength"]; ok {
		c.maxLen = parseNonNegInt(v)
	}
	c.formRef, c.formRefSet = attrs["form"]
	if c.isSubmit() {
		for _, k := range []string{"formaction", "formmethod", "formenctype"} {
			if v, ok := attrs[k]; ok {
				if c.submit == nil {
					c.submit = map[string]string{}
				}
				c.submit[k] = v
			}
		}
	}
	if firstID {
		r.ids[c.id] = idEntry{form: -1, control: c}
	}
	r.controls = append(r.controls, c)
	if l := r.label; l != nil && l.control == nil && c.labelable() {
		l.control = c
	}
	if t := r.top(); t != nil && t.row != nil && t.inCell {
		t.row.controls = append(t.row.controls, rowControl{c: c, after: len(t.row.ths)})
	}
	return c
}

func (r *formReader) startOption(attrs map[string]string) {
	r.closeOption()
	o := &openOption{opt: &selectOption{}}
	o.opt.value, o.hasValue = attrs["value"]
	_, o.opt.selected = attrs["selected"]
	_, off := attrs["disabled"]
	o.opt.disabled = off || r.groupDisabled
	o.label = attrs["label"]
	r.sel.options = append(r.sel.options, o.opt)
	r.opt = o
}

func (r *formReader) closeOption() {
	o := r.opt
	if o == nil {
		return
	}
	text := o.text.String()
	if !o.hasValue {
		o.opt.value = collapseASCIISpace(text)
	}
	o.opt.text = normSpace(text)
	if o.label != "" {
		o.opt.text = normSpace(o.label)
	}
	r.opt = nil
}

func (r *formReader) closeSelect() {
	r.closeOption()
	r.sel, r.groupDisabled = nil, false
}

func (r *formReader) closeButton() {
	if r.button != nil {
		r.button.text = normSpace(r.buttonText.String())
		r.button = nil
		r.buttonText.Reset()
	}
}

func (r *formReader) top() *formTable {
	if len(r.tables) == 0 {
		return nil
	}
	return r.tables[len(r.tables)-1]
}

func (r *formReader) closeCell(t *formTable) {
	if t.inTH && t.row != nil {
		t.row.ths[len(t.row.ths)-1] = normLabel(t.thText.String())
	}
	t.inCell, t.inTH = false, false
}

func (r *formReader) closeRow(t *formTable) {
	r.closeCell(t)
	if t.row != nil {
		t.row.resolve()
	}
	t.row = nil
}

// resolve gives each control of the row its row label: the text of the nearest non-empty
// <th> before it (or around it), else of the first non-empty one after it.
func (row *formRow) resolve() {
	if len(row.controls) == 0 {
		return
	}
	n := len(row.ths)
	prev := make([]int, n+1) // prev[i]: the last non-empty th among ths[:i], -1 if none
	prev[0] = -1
	for i, s := range row.ths {
		prev[i+1] = prev[i]
		if s != "" {
			prev[i+1] = i
		}
	}
	next := make([]int, n+1) // next[i]: the first non-empty th among ths[i:], -1 if none
	next[n] = -1
	for i := n - 1; i >= 0; i-- {
		next[i] = next[i+1]
		if row.ths[i] != "" {
			next[i] = i
		}
	}
	keys := make(map[int]string) // alnumKey of each th used, computed once
	for _, rc := range row.controls {
		j := prev[rc.after]
		if j < 0 {
			j = next[rc.after]
		}
		if j < 0 {
			continue
		}
		k, ok := keys[j]
		if !ok {
			k = alnumKey(row.ths[j])
			keys[j] = k
		}
		rc.c.row, rc.c.rowKey = row.ths[j], k
	}
}

// finish closes what is still open and resolves what depends on the whole page: form owners
// of controls with a form attribute, radio groups, select defaults and labels.
func (r *formReader) finish() {
	r.closeSelect()
	r.closeButton()
	for len(r.tables) > 0 {
		r.closeRow(r.top())
		r.tables = r.tables[:len(r.tables)-1]
	}
	for _, c := range r.controls {
		if c.formRefSet {
			c.owner = -1
			if e, ok := r.ids[c.formRef]; ok && e.form >= 0 {
				c.owner = e.form
			}
		}
	}

	// Checking a radio button unchecks the others of its group (same form, same name), so of
	// several written as checked the last one stays checked.
	type group struct {
		form int
		name string
	}
	checked := map[group]*formControl{}
	for _, c := range r.controls {
		if c.isRadio() && c.checked && c.name != "" {
			g := group{c.owner, c.name}
			if prev := checked[g]; prev != nil {
				prev.checked = false
			}
			checked[g] = c
		}
	}

	for _, c := range r.controls {
		if c.tag == "select" {
			resolveSelect(c)
		}
	}

	// Labels: a <label for=id> names the first element with that id, a <label> without for
	// the first labelable control inside it; the first label for the control wins, a for
	// label over a wrapping one, and either over the row.
	for _, l := range r.labels {
		text := normLabel(l.text.String())
		if text == "" {
			continue
		}
		c, from := l.control, labelWrap
		if l.hasFor {
			c, from = r.ids[l.forID].control, labelFor // an id that names nothing labels nothing
		}
		if c == nil || !c.labelable() {
			continue
		}
		if c.labelFrom == labelNone || c.labelFrom == labelWrap && from == labelFor {
			c.label, c.labelFrom, c.labelKey = text, from, alnumKey(text)
		}
	}
	for _, c := range r.controls {
		if c.labelFrom == labelNone && c.isField() && c.row != "" {
			c.label, c.labelFrom, c.labelKey = c.row, labelRow, c.rowKey
		}
		if c.owner >= 0 {
			r.forms[c.owner].controls = append(r.forms[c.owner].controls, c)
		}
	}
}

// resolveSelect applies the browser's selectedness rules to a drop-down list: of several
// options written as selected the last one is selected, and with none the first option that
// is not disabled.
func resolveSelect(c *formControl) {
	if c.typ != "select-one" {
		return
	}
	last := -1
	for i, o := range c.options {
		if o.selected {
			last = i
		}
	}
	for i, o := range c.options {
		o.selected = i == last
	}
	if last < 0 && c.size == 1 {
		for _, o := range c.options {
			if !o.disabled {
				o.selected = true
				break
			}
		}
	}
}

// ---------------------------------------------------------------- attribute values

// inputType returns the type of an input: the type attribute in lower case when it names an
// input type, else "text" (browsers treat a missing or unknown type as text).
func inputType(v string) string {
	t := strings.ToLower(v)
	switch t {
	case "hidden", "text", "search", "tel", "url", "email", "password", "date", "month", "week", "time",
		"datetime-local", "number", "range", "color", "checkbox", "radio", "file", "submit", "image", "reset", "button":
		return t
	}
	return "text"
}

// reFloat matches an HTML valid floating-point number.
var reFloat = regexp.MustCompile(`^-?(?:[0-9]+|[0-9]*\.[0-9]+)(?:[eE][-+]?[0-9]+)?$`)

const asciiSpace = "\t\n\f\r "

// sanitizeValue applies the browser's value sanitization of the input types the gateway uses.
func sanitizeValue(typ, v string) string {
	switch typ {
	case "text", "search", "tel", "password":
		return stripNewlines(v)
	case "url", "email":
		return strings.Trim(stripNewlines(v), asciiSpace)
	case "number":
		if !reFloat.MatchString(v) {
			return ""
		}
	}
	return v
}

func stripNewlines(s string) string {
	if strings.ContainsAny(s, "\r\n") {
		s = strings.NewReplacer("\r", "", "\n", "").Replace(s)
	}
	return s
}

// collapseASCIISpace strips and collapses ASCII white space, as an option's text is turned
// into its value.
func collapseASCIISpace(s string) string {
	return strings.Join(strings.FieldsFunc(s, func(r rune) bool { return strings.ContainsRune(asciiSpace, r) }), " ")
}

// parseNonNegInt implements HTML's rules for parsing non-negative integers (leading white
// space and a "+" allowed, anything after the digits ignored): -1 when s holds none.
func parseNonNegInt(s string) int {
	s = strings.TrimPrefix(strings.TrimLeft(s, asciiSpace), "+")
	n, i := 0, 0
	for ; i < len(s) && s[i] >= '0' && s[i] <= '9'; i++ {
		if n < 1<<30 {
			n = n*10 + int(s[i]-'0')
		}
	}
	if i == 0 {
		return -1
	}
	return n
}

func formMethod(v string) string {
	if m := strings.ToLower(v); m == "post" || m == "dialog" {
		return m
	}
	return "get"
}

func formEnctype(v string) string {
	if e := strings.ToLower(v); e == "multipart/form-data" || e == "text/plain" {
		return e
	}
	return formURLEncoded
}

// ---------------------------------------------------------------- fields and buttons

// formField is what one label names in a form: a single control, or a radio button group
// (the radio buttons of the form that share a name).
type formField struct {
	controls []*formControl
}

// fields returns the fields of f labelled label, compared by alnumKey (case, white space and
// punctuation such as a trailing ":" do not matter): each control other than a hidden input
// or a button whose label matches, and each radio button group with a button whose label or
// row matches (radio buttons usually carry labels of their own, "On" or "Off", while the
// group's label is the row's).
func (f *pageForm) fields(label string) []formField {
	key := alnumKey(label)
	if key == "" {
		return nil
	}
	var out []formField
	groups := map[string]bool{}
	for _, c := range f.controls {
		if !c.isField() {
			continue
		}
		if !c.isRadio() {
			if c.labelKey == key {
				out = append(out, formField{controls: []*formControl{c}})
			}
			continue
		}
		if c.labelKey != key && c.rowKey != key {
			continue
		}
		if c.name == "" { // a radio button without a name is a group of its own
			out = append(out, formField{controls: []*formControl{c}})
			continue
		}
		if groups[c.name] {
			continue
		}
		groups[c.name] = true
		var g formField
		for _, o := range f.controls {
			if o.isRadio() && o.name == c.name {
				g.controls = append(g.controls, o)
			}
		}
		out = append(out, g)
	}
	return out
}

// isRadioGroup reports whether the field is a radio button group.
func (fd formField) isRadioGroup() bool { return fd.controls[0].isRadio() }

// kind describes the field's control for messages ("checkbox", "drop-down list", "radio
// buttons", "text input", ...).
func (fd formField) kind() string {
	c := fd.controls[0]
	switch {
	case fd.isRadioGroup():
		return "radio buttons"
	case c.typ == "select-one":
		return "drop-down list"
	case c.typ == "select-multiple":
		return "multiple-choice list"
	case c.tag == "input" && c.typ == "checkbox":
		return "checkbox"
	case c.tag == "input":
		return c.typ + " input"
	}
	return c.tag
}

// choice is one choice of a field: an option of a drop-down list, or a radio button.
type choice struct {
	text     string // as displayed ("" for a radio button without a label of its own)
	value    string // the value submitted
	explicit bool   // the value is written in the page (a radio button without one submits "on")
	selected bool
	disabled bool
	opt      *selectOption // the option, for a drop-down list
	radio    *formControl  // the radio button, for a radio group
}

// display returns the choice's text, or its value when it has no text.
func (ch choice) display() string {
	if ch.text != "" {
		return ch.text
	}
	return ch.value
}

// choices returns the options of a drop-down list or the buttons of a radio group in document
// order (nil for any other field). A disabled list makes every option disabled.
func (fd formField) choices() []choice {
	c := fd.controls[0]
	var out []choice
	switch {
	case c.typ == "select-one":
		for _, o := range c.options {
			out = append(out, choice{text: o.text, value: o.value, explicit: true, selected: o.selected,
				disabled: o.disabled || c.disabled, opt: o})
		}
	case fd.isRadioGroup():
		for _, rb := range fd.controls {
			ch := choice{value: rb.value, explicit: rb.hasValue, selected: rb.checked, disabled: rb.disabled, radio: rb}
			if rb.labelFrom == labelFor || rb.labelFrom == labelWrap {
				ch.text = rb.label
			}
			out = append(out, ch)
		}
	}
	return out
}

// choose selects ch, one of fd.choices(), and deselects the others.
func (fd formField) choose(ch choice) {
	if ch.opt != nil {
		for _, o := range fd.controls[0].options {
			o.selected = o == ch.opt
		}
		return
	}
	for _, rb := range fd.controls {
		rb.checked = rb == ch.radio
	}
}

// nonce returns the form's nonce: the value of its one enabled control named "nonce" when it
// is valid (validNonce), else "".
func (f *pageForm) nonce() string {
	v, n := "", 0
	for _, c := range f.controls {
		if c.name == "nonce" && !c.disabled {
			v, n = c.value, n+1
		}
	}
	if n != 1 || !validNonce(v) {
		return ""
	}
	return v
}

// submitButton returns the first enabled submit button of f that match accepts and the
// number of different ones (by name and value) it accepts: buttons with the same name and
// value post the same body.
func (f *pageForm) submitButton(match func(c *formControl) bool) (*formControl, int) {
	var first *formControl
	seen := map[[2]string]bool{}
	for _, c := range f.controls {
		if !c.isSubmit() || c.disabled || !match(c) {
			continue
		}
		if first == nil {
			first = c
		}
		seen[[2]string{c.name, c.value}] = true
	}
	return first, len(seen)
}

// submitTarget returns how a click on submitter sends f: the method, action and encoding of
// the form, each overridden by the button's formmethod, formaction or formenctype attribute.
func (f *pageForm) submitTarget(submitter *formControl) (method, action, enctype string) {
	method, action, enctype = f.method, f.action, f.enctype
	if v, ok := submitter.submit["formmethod"]; ok {
		method = formMethod(v)
	}
	if v, ok := submitter.submit["formaction"]; ok {
		action = v
	}
	if v, ok := submitter.submit["formenctype"]; ok {
		enctype = formEnctype(v)
	}
	return method, action, enctype
}

// ---------------------------------------------------------------- encoding

// encode returns the application/x-www-form-urlencoded body a browser posts when submitter,
// a submit button of f, is clicked: the name=value entries of f's controls in document order,
// newlines in names and values written as CRLF. Disabled controls, controls without a name,
// unchecked checkboxes and radio buttons, options not selected and buttons other than the
// submitter are left out. It fails for a submitter that is not an enabled submit button of f,
// and for names and values with bytes outside ASCII, which a browser encodes in the page's
// character encoding (windows-1252 on the gateway): such a form is not posted at all.
func (f *pageForm) encode(submitter *formControl) (string, error) {
	switch {
	case submitter == nil || !submitter.isSubmit():
		return "", errors.New("the form is submitted with a control that is not a submit button")
	case submitter.disabled:
		return "", errors.New("the submit button is disabled")
	case submitter.typ == "image":
		return "", errors.New("image submit buttons are not supported")
	}
	var kv []string
	found := false
	for _, c := range f.controls {
		if c == submitter {
			found = true
		}
		if c.disabled || c.name == "" {
			continue
		}
		switch {
		case c.isButton():
			if c == submitter {
				kv = append(kv, c.name, c.value)
			}
		case c.typ == "checkbox", c.typ == "radio":
			if c.checked {
				kv = append(kv, c.name, c.value)
			}
		case c.tag == "select":
			for _, o := range c.options {
				if o.selected && !o.disabled {
					kv = append(kv, c.name, o.value)
				}
			}
		case c.typ == "file":
			kv = append(kv, c.name, "") // no file chosen
		case c.typ == "hidden" && strings.EqualFold(c.name, "_charset_"):
			// A browser submits its character encoding here, not the value.
			return "", errors.New("the form has a _charset_ field")
		default:
			kv = append(kv, c.name, c.value)
		}
	}
	if !found {
		return "", errors.New("the submit button is not part of the form")
	}
	for i, s := range kv {
		for j := 0; j < len(s); j++ {
			if s[j] >= 0x80 {
				return "", errors.New("the form holds a name or value with characters outside ASCII")
			}
		}
		if strings.ContainsAny(s, "\r\n") {
			s = strings.ReplaceAll(s, "\r\n", "\n")
			s = strings.ReplaceAll(s, "\r", "\n")
			kv[i] = strings.ReplaceAll(s, "\n", "\r\n")
		}
	}
	return encodeForm(kv...), nil
}
