package ticket

import "strings"

// Page 1 is the summary sheet: an AT&T agent reads it alone, and the details start on a new page.
// If the sheet overflows, that forced page break leaves page 2 almost empty, so the sheet must fit
// on one page. Its texts are bounded (summary.go), but the customer's fields and the facts of a bad
// day vary; the sheet therefore keeps its evidence brief - the bundle, the signing key and the
// verification result, all repeated under Evidence and integrity - only when an estimate of its
// height fits the page, and then its monitoring coverage paragraph only when that fits (it opens
// the details otherwise). Should the sheet still not fit, the details follow it on the same page
// instead of after a forced page break.
//
// The estimate lays the texts out the way the browser does: words (and the values segs keeps whole)
// are placed greedily on lines of the box's width, measured with approximate Segoe UI glyph widths;
// the vertical sizes follow the template's CSS. Calibrated against Microsoft Edge's print layout,
// it matches the line count of a summary paragraph exactly or overestimates it by one line, so it
// errs on the safe side: at worst the brief moves to the details when it would just have fitted.

// Geometry of page 1, in points (US Letter, the template's @page margins and font sizes).
const (
	p1Usable    = 712.8 // 11 in less the 0.5 in and 0.6 in margins
	p1Width     = 532.8 // 8.5 in less two 0.55 in margins
	p1Body      = 9.2   // body font size
	p1Line      = 12.33 // a body line: 9.2 pt x 1.34
	p1H1Line    = 18.0  // a title line: 15 pt x 1.2
	p1MetaLine  = 11.39 // a line of the window and generator: 8.5 pt x 1.34
	p1H2        = 29.5  // a heading with its margins and rule
	p1FillRow   = 26.8  // a customer row with a fill-in line
	p1CustLine  = 12.73 // a typed customer value line: 9.5 pt x 1.34
	p1BriefLine = 12.72 // a brief row line: 8 pt x 1.34, plus its padding
	p1NoteLine  = 10.05 // a footnote line: 7.5 pt x 1.34
	p1SpaceEm   = 0.274 // the width of a space, in em
	p1BoldScale = 1.05  // bold text is about this much wider (measured: 1.02 against glyphEm)
)

// glyphEm is the approximate advance width of a character in Segoe UI, in em.
func glyphEm(c rune) float64 {
	switch {
	case c == ' ':
		return p1SpaceEm
	case c >= '0' && c <= '9':
		return 0.559
	case c >= 'a' && c <= 'z':
		switch c {
		case 'i', 'j', 'l':
			return 0.243
		case 'f', 't', 'r':
			return 0.335
		case 'm', 'w':
			return 0.81
		}
		return 0.545
	case c >= 'A' && c <= 'Z':
		switch c {
		case 'I':
			return 0.27
		case 'M', 'W':
			return 0.94
		}
		return 0.66
	}
	switch c {
	case '.', ',', ':', ';', '\'', '|', '!':
		return 0.252
	case '-', '(', ')', '/', '[', ']', '"':
		return 0.35
	case '_':
		return 0.41
	}
	return 0.62
}

// wrapWords splits s into the units a line break cannot split: words, with the values segs keeps
// on one line counted as one unit.
func wrapWords(s string) []string {
	var out []string
	var cur strings.Builder
	for _, sg := range segs(s) {
		if sg.N {
			cur.WriteString(sg.T)
			continue
		}
		for i, part := range strings.Split(sg.T, " ") {
			if i > 0 {
				if cur.Len() > 0 {
					out = append(out, cur.String())
				}
				cur.Reset()
			}
			cur.WriteString(part)
		}
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}

// wrapLines estimates the lines a paragraph - a bold lead, then text - takes in a box widthPt
// wide at sizePt.
func wrapLines(lead, text string, widthPt, sizePt float64) float64 {
	width := widthPt / sizePt
	lines, cur := 0, 0.0
	place := func(s string, scale float64) {
		for _, w := range wrapWords(s) {
			ww := 0.0
			for _, c := range w {
				ww += glyphEm(c)
			}
			ww *= scale
			switch {
			case lines == 0:
				lines, cur = 1, ww
			case cur+p1SpaceEm+ww > width:
				lines, cur = lines+1, ww
			default:
				cur += p1SpaceEm + ww
			}
			// A word wider than the line wraps anywhere (overflow-wrap: anywhere).
			for cur > width {
				lines, cur = lines+1, cur-width
			}
		}
	}
	place(lead, p1BoldScale)
	place(text, 1)
	return float64(lines)
}

// pageOneHeight estimates the height of the summary sheet, with or without its evidence brief.
func (v *htmlView) pageOneHeight(withBrief bool) float64 {
	h := wrapLines(v.Title, "", p1Width, 15)*p1H1Line + 3
	window := "Window: " + v.WindowLocal
	if v.WindowUTC != "" {
		window += " (" + v.WindowUTC + ")"
	}
	h += (wrapLines("", window, p1Width, 8.5)+wrapLines("", "Generated "+v.Generated, p1Width, 8.5))*p1MetaLine + 7
	// The customer box: four columns of 17 % and 33 % of its inner width.
	inner := p1Width - 16
	h += 0.75 + 7 + 0.75 // border and padding
	for _, row := range v.CustRows {
		rh := 0.0
		for _, f := range row {
			fh := p1FillRow
			if f.Value != "" {
				w := 0.33*inner - 10
				if f.Wide {
					w = 0.83*inner - 10
				}
				fh = wrapLines("", f.Value, w, 9.5)*p1CustLine + 5
			}
			rh = max(rh, fh)
		}
		h += rh
	}
	// The headings (Summary for AT&T, Requested action and, when it is on page 1, Monitoring
	// coverage); the bottom margin of the block before each collapses into the heading's top
	// margin, as does the coverage paragraph's into the brief's.
	h += 2 * p1H2
	for i, b := range v.Summary {
		h += wrapLines(b.Lead, b.Text, p1Width-17, p1Body) * p1Line
		if i < len(v.Summary)-1 {
			h += 4
		}
	}
	h += wrapLines(v.Action.Lead, v.Action.Text, p1Width-10.5, p1Body)*p1Line + 11
	if v.CoverageOnPage1 {
		h += p1H2 + wrapLines("", v.Coverage, p1Width, p1Body)*p1Line
	}
	if !withBrief {
		return h
	}
	h += 12.75 // the brief's margin, rule and padding
	for _, k := range v.Brief {
		size, w := 8.0, p1Width-90
		if k.Mono {
			size = 7.6 * 1.08 // Consolas is wider than Segoe UI
		}
		h += max(wrapLines("", k.V, w, size), 1) * p1BriefLine
	}
	return h + 3 + wrapLines("", v.Stated, p1Width, 7.5)*p1NoteLine
}
