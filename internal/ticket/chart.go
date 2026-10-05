package ticket

import (
	"fmt"
	"math"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"attmonitor/internal/model"
)

// Chart is the optical receive-power chart, drawn as inline SVG for print. It follows the
// dataviz basics: one y-axis (dBm); the readings as one 2px line in the first categorical hue,
// broken wherever readings are missing and wherever the gateway reported its fiber link down
// (a reading without a receive level is marked, never drawn as a level or joined across); a
// solid hairline grid; the gateway's own low-Rx alarm and warning thresholds as labelled
// reference lines in the reserved status colors with different dash patterns (so they also
// differ in grayscale); outages the monitor attributed to AT&T as shaded bands; the setup-time
// capture as a labelled marker; the latest level labelled at its end; and three strips under the
// plot - the gateway's ALARM flag, its WARNING flag and fiber link down - in which a full block
// marks a reading with the condition and a thin line a reading without it (the shape carries the
// meaning, not only the color, and every strip is labelled). When the readings cover less than a
// quarter of the window, the plot shows the span they cover and a bar above it shows the whole
// window, so the readings stay legible and the unmeasured time stays visible. Labels sit on
// small white boxes rather than text halos (a halo prints every label twice into the PDF's
// text). Native <title> elements give tooltips without scripts; the readings table is the
// chart's table view.
type Chart struct {
	W, H        int
	Title, Desc string

	X0, X1, Y0, Y1 string // the plot box
	PlotW, PlotH   string
	YUnitX, YUnitY string
	YTicks         []chartTick
	XTicks         []chartTick
	XLabelY        string
	XDateY         string
	TickY2         string
	AxisTitle      string
	AxisTitleX     string
	AxisTitleY     string

	Bands   []chartBand // outages attributed to AT&T, behind the readings
	Refs    []chartRef
	Lines   []string
	Spreads []string // the min-max range of bucketed readings
	Dots    []chartDot
	Setup   *chartMarker
	End     *chartMarker
	Strips  []chartStrip
	Empty   []chartText
	// Context is the bar showing the whole window above a plot of the readings' span (nil: the
	// plot shows the whole window).
	Context *chartContext

	// Facts for the caption.
	Levels      int // readings drawn as receive levels
	NoLight     int // readings without a receive level (the gateway reported its fiber link down)
	Implausible int // values outside +/-100 dBm, not drawn
	Bucketed    bool
	BucketLabel string // "10 min": the readings are drawn as a mean per bucket of this width
	OutageBands int
	// BandsWhat names the shaded incidents: "outage" when every one is an ISP_OUTAGE, else
	// "incident".
	BandsWhat string
	// PlotFrom and PlotTo are the plotted span (the window, or the readings' span with Context).
	PlotFrom, PlotTo time.Time
	// SetupOutside is the setup-time capture when it lies in the window but outside the plot.
	SetupOutside *Reading
}

type chartTick struct {
	X, Y, TY      string
	Label, Label2 string
}

type chartRef struct {
	Y, X0, X1 string
	Class     string
	Label     chartText
}

type chartDot struct {
	X, Y, Title string
}

// chartText is a label on a white box (BX..BH; no box when BW is empty).
type chartText struct {
	X, Y, Anchor, Label string
	BX, BY, BW, BH      string
}

type chartMarker struct {
	X, Y, Path string
	Title      string
	Label      chartText
}

type chartStrip struct {
	Y, H, LX, LY string
	PY, PH       string // the thin "reading without the condition" line
	Label, Class string
	Present      []chartSeg
	Flags        []chartSeg
}

type chartSeg struct {
	X, W, Title string
}

type chartBand struct {
	X, W, Title string
	Label       *chartText
}

type chartContext struct {
	Y, H     string // the bar
	LX, LY   string // its label
	Label    string
	TickY    string
	Ticks    []chartTick
	Present  []chartSeg
	Setup    *chartMarker
	ZoomX    string // the plotted span, outlined on the bar
	ZoomY    string
	ZoomW    string
	ZoomH    string
	Note     chartText
	PresentH string
}

// Geometry, in SVG user units. The figure is drawn at the page's content width (7.4 in for 720
// units), so 10-unit text prints at about 7.4 pt.
const (
	chartW         = 720
	plotX0, plotX1 = 96.0, 614.0
	plotTop        = 24.0 // the plot's top below the panel's top
	plotHeight     = 140.0
	stripTop       = 10.0 // the first strip below the plot
	stripH         = 8.0
	stripStep      = 12.0
	contextH       = 46.0 // the whole-window bar's band above the panel
	ctxBarY        = 16.0
	ctxBarH        = 10.0
	fontPx         = 10.0 // chart text
	charW          = 0.56 // estimated average glyph width, in em
	maxChartPoints = 1200
	bucketPx       = 3.0  // the narrowest bucket when readings are denser than the plot can show
	plausibleX10   = 1000 // +/-100 dBm: anything beyond is not a real reading and is not drawn
	minEmptyFrac   = 0.22 // a stretch without readings this wide (of the plot) is labelled
	detailFrac     = 4    // the readings span less than 1/detailFrac of the window: plot their span
	endLabelGap    = 8.0
)

func f1(v float64) string { return strconv.FormatFloat(v, 'f', 1, 64) }

func floorDiv(a, b int64) int64 {
	q := a / b
	if a%b != 0 && (a < 0) != (b < 0) {
		q--
	}
	return q
}

func ceilDiv(a, b int64) int64 { return -floorDiv(-a, b) }

// niceStep picks a tick step (in 0.1 dB) giving at most 6 intervals.
func niceStep(rangeX10 int64) int64 {
	for _, s := range []int64{1, 2, 5, 10, 20, 50, 100, 200, 500, 1000} {
		if rangeX10/s <= 6 {
			return s
		}
	}
	return 1000
}

// textW estimates the width of a label at px.
func textW(s string, px float64) float64 { return float64(utf8.RuneCountInString(s)) * px * charW }

// medianSpacing is the median time between consecutive readings.
func medianSpacing(rs []Reading) time.Duration {
	var ds []time.Duration
	for i := 1; i < len(rs); i++ {
		if d := rs[i].T.Sub(rs[i-1].T); d > 0 {
			ds = append(ds, d)
		}
	}
	if len(ds) == 0 {
		return 0
	}
	slices.Sort(ds)
	return ds[len(ds)/2]
}

// niceBuckets are the bucket widths a dense chart is drawn with.
var niceBuckets = []time.Duration{10 * time.Second, 15 * time.Second, 30 * time.Second, time.Minute, 2 * time.Minute,
	5 * time.Minute, 10 * time.Minute, 15 * time.Minute, 30 * time.Minute, time.Hour, 2 * time.Hour, 3 * time.Hour,
	6 * time.Hour, 12 * time.Hour, 24 * time.Hour}

// fmtWidth renders a bucket width: "10 min", "2 h", "30 s".
func fmtWidth(d time.Duration) string {
	switch {
	case d >= time.Hour && d%time.Hour == 0:
		return fmt.Sprintf("%d h", d/time.Hour)
	case d >= time.Minute && d%time.Minute == 0:
		return fmt.Sprintf("%d min", d/time.Minute)
	}
	return fmt.Sprintf("%d s", d/time.Second)
}

// bucketWidth is the narrowest nice width that splits span into at most n buckets.
func bucketWidth(span time.Duration, n int) time.Duration {
	for _, w := range niceBuckets {
		if span <= w*time.Duration(n) {
			return w
		}
	}
	return niceBuckets[len(niceBuckets)-1]
}

type timeTick struct {
	t         time.Time
	label     string
	dateLabel string
}

// timeTicks returns at most 9 ticks on local-time boundaries of a step that suits the span.
func timeTicks(from, to time.Time, loc *time.Location) []timeTick {
	span := to.Sub(from)
	stepsH := []int{1, 2, 3, 4, 6, 12, 24, 48, 96, 168}
	stepH := 168
	for _, s := range stepsH {
		if span/(time.Duration(s)*time.Hour) <= 8 {
			stepH = s
			break
		}
	}
	var out []timeTick
	if span < 2*time.Hour {
		// Short spans: quarter hours (5 minutes up to half an hour, a minute below 6 minutes).
		step := 15 * time.Minute
		switch {
		case span <= 6*time.Minute:
			step = time.Minute
		case span <= 30*time.Minute:
			step = 5 * time.Minute
		}
		for t := from.In(loc).Truncate(step); !t.After(to); t = t.Add(step) {
			if t.Before(from) {
				continue
			}
			out = append(out, timeTick{t: t, label: t.In(loc).Format("15:04")})
		}
	} else {
		lf := from.In(loc)
		day := time.Date(lf.Year(), lf.Month(), lf.Day(), 0, 0, 0, 0, loc)
		for h := 0; h < 24*40; h += stepH {
			t := time.Date(day.Year(), day.Month(), day.Day(), h, 0, 0, 0, loc)
			if t.After(to) {
				break
			}
			if t.Before(from) {
				continue
			}
			label := t.Format("15:04")
			if stepH >= 24 {
				label = t.Format("Jan 2")
			}
			out = append(out, timeTick{t: t, label: label})
		}
	}
	prevDate := ""
	for i := range out {
		d := out[i].t.In(loc).Format("Jan 2")
		if d != prevDate && stepH < 24 {
			out[i].dateLabel = d
		}
		prevDate = d
	}
	return out
}

// pt is a point of a drawn line (for keeping labels clear of it).
type pt struct{ x, y float64 }

type box struct{ x0, y0, x1, y1 float64 }

func (b box) hits(o box) bool { return b.x0 < o.x1 && o.x0 < b.x1 && b.y0 < o.y1 && o.y0 < b.y1 }

// labelBox is the box of a label at (x, y) (its baseline) with the given anchor.
func labelBox(x, y float64, anchor, s string, px float64) box {
	w := textW(s, px)
	switch anchor {
	case "end":
		x -= w
	case "middle":
		x -= w / 2
	}
	return box{x - 2, y - px*0.8 - 1, x + w + 2, y + px*0.25 + 1}
}

func (b box) text(x, y float64, anchor, s string) chartText {
	return chartText{X: f1(x), Y: f1(y), Anchor: anchor, Label: s, BX: f1(b.x0), BY: f1(b.y0), BW: f1(b.x1 - b.x0), BH: f1(b.y1 - b.y0)}
}

// chartBuilder holds the state of one chart while it is drawn.
type chartBuilder struct {
	ch       *Chart
	t0, t1   int64 // the plotted span, Unix ns
	y0, y1   float64
	lo, hi   int64
	drawn    [][]pt // the lines and dots, for label placement
	occupied []box  // labels placed so far
}

// labelPos is a candidate position of a label: its baseline point and text anchor.
type labelPos struct {
	x, y   float64
	anchor string
}

func (b *chartBuilder) xOf(t time.Time) float64 {
	x := plotX0 + (plotX1-plotX0)*float64(t.UnixNano()-b.t0)/float64(b.t1-b.t0)
	return math.Min(math.Max(x, plotX0), plotX1)
}

func (b *chartBuilder) yOf(v int64) float64 {
	return b.y1 - (b.y1-b.y0)*float64(v-b.lo)/float64(b.hi-b.lo)
}

func (b *chartBuilder) yOfF(v float64) float64 {
	return b.y1 - (b.y1-b.y0)*(v-float64(b.lo))/float64(b.hi-b.lo)
}

// free reports whether a label box stays inside the chart, above the flag strips, and clear of
// the drawn lines and of the labels placed so far.
func (b *chartBuilder) free(bx box) bool {
	if bx.x0 < 0 || bx.x1 > chartW || bx.y0 < 0 || bx.y1 > b.y1+2 {
		return false
	}
	for _, o := range b.occupied {
		if bx.hits(o) {
			return false
		}
	}
	grown := box{bx.x0 - 2, bx.y0 - 2, bx.x1 + 2, bx.y1 + 2}
	for _, line := range b.drawn {
		for i, p := range line {
			if grown.contains(p) {
				return false
			}
			if i == 0 {
				continue
			}
			// Sample the segment so a long segment crossing the box is found too.
			q := line[i-1]
			n := int(math.Max(math.Abs(p.x-q.x), math.Abs(p.y-q.y)) / 2)
			for k := 1; k < n; k++ {
				f := float64(k) / float64(n)
				if grown.contains(pt{q.x + (p.x-q.x)*f, q.y + (p.y-q.y)*f}) {
					return false
				}
			}
		}
	}
	return true
}

func (bx box) contains(p pt) bool {
	return p.x >= bx.x0 && p.x <= bx.x1 && p.y >= bx.y0 && p.y <= bx.y1
}

// place puts a label at the first free candidate position (the first one when none is free)
// and remembers its box.
func (b *chartBuilder) place(s string, cands ...labelPos) chartText {
	var first chartText
	var firstBox box
	for i, c := range cands {
		bx := labelBox(c.x, c.y, c.anchor, s, fontPx)
		t := bx.text(c.x, c.y, c.anchor, s)
		if i == 0 {
			first, firstBox = t, bx
		}
		if b.free(bx) {
			b.occupied = append(b.occupied, bx)
			return t
		}
	}
	b.occupied = append(b.occupied, firstBox)
	return first
}

func cand(x, y float64, anchor string) labelPos { return labelPos{x, y, anchor} }

// buildChart draws the window's readings; nil when there is no receive level to draw.
func buildChart(rep *Report) *Chart {
	op := &rep.Optical
	from, to, loc := rep.From, rep.To, rep.loc
	if !to.After(from) {
		return nil
	}
	var all []Reading // every reading of the window
	for _, rd := range op.Readings {
		if !rd.T.Before(from) && rd.T.Before(to) {
			all = append(all, rd)
		}
	}
	isLevel := func(rd Reading) bool {
		return !rd.NoLight && rd.RxX10 >= -plausibleX10 && rd.RxX10 <= plausibleX10
	}
	// The plotted span: the window, or - when the monitored readings (not the setup capture)
	// cover less than a quarter of it - their span, with a bar showing the whole window.
	pFrom, pTo := from, to
	var mon []Reading
	for _, rd := range all {
		if !rd.Setup {
			mon = append(mon, rd)
		}
	}
	if len(mon) >= 2 {
		span := mon[len(mon)-1].T.Sub(mon[0].T)
		if span >= time.Minute && span*detailFrac < to.Sub(from) && slices.ContainsFunc(mon, isLevel) {
			pad := max(span/25, 30*time.Second)
			pFrom, pTo = mon[0].T.Add(-pad), mon[len(mon)-1].T.Add(pad)
			if pFrom.Before(from) {
				pFrom = from
			}
			if pTo.After(to) {
				pTo = to
			}
		}
	}
	detail := !pFrom.Equal(from) || !pTo.Equal(to)
	var in, levels []Reading // the readings of the plotted span; those with a receive level
	ch := &Chart{W: chartW, Title: "Optical receive (Rx) power reported by the AT&T gateway", PlotFrom: pFrom, PlotTo: pTo}
	for _, rd := range all {
		if rd.T.Before(pFrom) || rd.T.After(pTo) {
			if rd.Setup {
				s := rd
				ch.SetupOutside = &s
			}
			continue
		}
		in = append(in, rd)
		switch {
		case rd.NoLight:
			ch.NoLight++
		case !isLevel(rd):
			ch.Implausible++
		default:
			levels = append(levels, rd)
		}
	}
	if len(levels) == 0 {
		return nil
	}
	ch.Levels = len(levels)

	alarmThr, warnThr := op.AlarmThr, op.WarnThr
	if alarmThr != nil && (*alarmThr < -plausibleX10 || *alarmThr > plausibleX10) {
		alarmThr = nil
	}
	if warnThr != nil && (*warnThr < -plausibleX10 || *warnThr > plausibleX10) {
		warnThr = nil
	}
	oy := 0.0
	if detail {
		oy = contextH
	}
	b := &chartBuilder{ch: ch, t0: pFrom.UnixNano(), t1: pTo.UnixNano(), y0: oy + plotTop, y1: oy + plotTop + plotHeight}
	// Y domain: the levels and the thresholds, padded, on tick boundaries.
	lo, hi := levels[0].RxX10, levels[0].RxX10
	for _, p := range levels {
		lo, hi = min(lo, p.RxX10), max(hi, p.RxX10)
	}
	dataLo, dataHi := lo, hi
	for _, t := range []*int64{alarmThr, warnThr} {
		if t != nil {
			lo, hi = min(lo, *t), max(hi, *t)
		}
	}
	pad := max(int64(5), (hi-lo)/10)
	lo, hi = lo-pad, hi+pad
	step := niceStep(hi - lo)
	lo, hi = floorDiv(lo, step)*step, ceilDiv(hi, step)*step
	if hi <= lo {
		hi = lo + step
	}
	b.lo, b.hi = lo, hi

	s1 := b.y1 + stripTop
	xLabelY := s1 + 2*stripStep + stripH + 14
	ch.H = int(xLabelY + 12 + 16 + 6)
	ch.X0, ch.X1, ch.Y0, ch.Y1 = f1(plotX0), f1(plotX1), f1(b.y0), f1(b.y1)
	ch.PlotW, ch.PlotH = f1(plotX1-plotX0), f1(plotHeight)
	ch.YUnitX, ch.YUnitY = f1(plotX0-8), f1(b.y0-10)
	ch.XLabelY, ch.XDateY, ch.TickY2 = f1(xLabelY), f1(xLabelY+12), f1(b.y1+4)
	ch.AxisTitleX, ch.AxisTitleY = f1((plotX0+plotX1)/2), f1(xLabelY+12+16)
	zone := zoneLabel(loc, pTo)
	if detail {
		ch.AxisTitle = fmt.Sprintf("Time, %s: the part of the window with readings, %s to %s", zone, pFrom.In(loc).Format(layoutMin), sameDayClock(pFrom, pTo, loc))
	} else {
		ch.AxisTitle = fmt.Sprintf("Time, %s: window %s to %s", zone, from.In(loc).Format(layoutMin), to.In(loc).Format(layoutMin))
	}
	for v := lo; v <= hi; v += step {
		y := b.yOf(v)
		ch.YTicks = append(ch.YTicks, chartTick{Y: f1(y), TY: f1(y + 3.5), Label: fmtX10(v)})
	}
	for _, tk := range timeTicks(pFrom, pTo, loc) {
		ch.XTicks = append(ch.XTicks, chartTick{X: f1(b.xOf(tk.t)), Label: tk.label, Label2: tk.dateLabel})
	}

	b.drawSeries(in, loc)
	b.drawBands(rep, pFrom, pTo, loc)
	// "No readings" labels for wide stretches without readings (full-window plots only).
	if !detail {
		edges := []time.Time{pFrom}
		for _, p := range in {
			edges = append(edges, p.T)
		}
		edges = append(edges, pTo)
		for i := 1; i < len(edges); i++ {
			a, c := edges[i-1], edges[i]
			if float64(c.Sub(a)) < minEmptyFrac*float64(pTo.Sub(pFrom)) {
				continue
			}
			x, y := (b.xOf(a)+b.xOf(c))/2, (b.y0+b.y1)/2
			bx := labelBox(x, y, "middle", "no readings", fontPx)
			b.occupied = append(b.occupied, bx)
			ch.Empty = append(ch.Empty, chartText{X: f1(x), Y: f1(y), Anchor: "middle", Label: "no readings"})
		}
	}
	b.drawRefs(alarmThr, warnThr)
	b.drawMarkers(in, levels, loc)
	b.drawStrips(in, loc)
	if detail {
		b.drawContext(all, from, to, pFrom, pTo, loc)
	}

	var desc strings.Builder
	fmt.Fprintf(&desc, "%s from the gateway's fiber diagnostics between %s and %s, from %s to %s.",
		plural(len(levels), "Rx power reading", "Rx power readings"), fmtLocal(levels[0].T, loc), fmtLocal(levels[len(levels)-1].T, loc), fmtX10(dataLo), fmtDBm(dataHi))
	if alarmThr != nil {
		fmt.Fprintf(&desc, " Gateway low-Rx alarm threshold %s.", fmtDBm(*alarmThr))
	}
	if warnThr != nil {
		fmt.Fprintf(&desc, " Gateway low-Rx warning threshold %s.", fmtDBm(*warnThr))
	}
	fmt.Fprintf(&desc, " ALARM flag set in %d and WARNING flag set in %d of %s.", countIf(in, func(r Reading) bool { return r.Alarm }),
		countIf(in, func(r Reading) bool { return r.Warn }), plural(len(in), "reading", "readings"))
	if ch.NoLight > 0 {
		fmt.Fprintf(&desc, " %s taken while the gateway reported its fiber link down %s no receive level; %s marked in the fiber link down strip, not drawn as levels.",
			plural(ch.NoLight, "reading", "readings"), noun(ch.NoLight, "has", "have"), noun(ch.NoLight, "it is", "they are"))
	}
	if ch.OutageBands > 0 {
		fmt.Fprintf(&desc, " %s attributed to AT&T %s shaded.", plural(ch.OutageBands, ch.BandsWhat, ch.BandsWhat+"s"), isAre(ch.OutageBands))
	}
	if ch.Implausible > 0 {
		fmt.Fprintf(&desc, " %s outside +/-100 dBm %s not drawn (listed in the records).", plural(ch.Implausible, "value", "values"), isAre(ch.Implausible))
	}
	if detail {
		fmt.Fprintf(&desc, " The plot shows %s to %s, the part of the window with readings; a bar above it shows the whole window.", fmtLocal(pFrom, loc), fmtLocal(pTo, loc))
	}
	ch.Desc = desc.String()
	return ch
}

// sameDayClock renders t to the minute, without its date when it is on from's local day.
func sameDayClock(from, t time.Time, loc *time.Location) string {
	if from.In(loc).Format("2006-01-02") == t.In(loc).Format("2006-01-02") {
		return t.In(loc).Format("15:04")
	}
	return t.In(loc).Format(layoutMin)
}

// drawSeries draws the levels as lines - broken at gaps and at readings without a receive level
// - or, when they are denser than the plot can show, as a mean per bucket with the range shaded.
func (b *chartBuilder) drawSeries(in []Reading, loc *time.Location) {
	ch := b.ch
	var seq []Reading // drawn by the line, in time order (the setup capture is its own marker)
	for _, p := range in {
		if !p.Setup && (p.NoLight || (p.RxX10 >= -plausibleX10 && p.RxX10 <= plausibleX10)) {
			seq = append(seq, p)
		}
	}
	var lvl []Reading
	for _, p := range seq {
		if !p.NoLight {
			lvl = append(lvl, p)
		}
	}
	breakGap := max(5*time.Minute, 4*medianSpacing(lvl))
	pathOf := func(ps []pt) string {
		var s strings.Builder
		for i, p := range ps {
			if i == 0 {
				s.WriteString("M")
			} else {
				s.WriteString(" L")
			}
			s.WriteString(f1(p.x) + "," + f1(p.y))
		}
		return s.String()
	}
	plotWidth := plotX1 - plotX0
	span := time.Duration(b.t1 - b.t0)
	// Readings denser than the plot can show (more than two per bucket of about 3 px, or very
	// many) are drawn as a mean line with their min-max range shaded, so the chart shows the
	// level and its spread instead of a zigzag.
	nb := max(int(plotWidth/bucketPx), 1)
	occupied := map[int]bool{}
	for _, p := range lvl {
		occupied[int(float64(p.T.UnixNano()-b.t0)/float64(span)*float64(nb))] = true
	}
	if len(lvl) <= maxChartPoints && len(lvl) <= 2*len(occupied) {
		var cur []pt
		var curR []Reading
		flush := func() {
			switch len(cur) {
			case 0:
			case 1:
				r := curR[0]
				ch.Dots = append(ch.Dots, chartDot{X: f1(cur[0].x), Y: f1(cur[0].y), Title: fmt.Sprintf("%s: Rx %s (%s)",
					fmtLocal(r.T, loc), fmtDBm(r.RxX10), r.Source())})
			default:
				ch.Lines = append(ch.Lines, pathOf(cur))
			}
			if len(cur) > 0 {
				b.drawn = append(b.drawn, cur)
			}
			cur, curR = nil, nil
		}
		for _, p := range seq {
			if p.NoLight {
				flush() // no receive level: the line stops here
				continue
			}
			if len(curR) > 0 && p.T.Sub(curR[len(curR)-1].T) > breakGap {
				flush()
			}
			cur = append(cur, pt{b.xOf(p.T), b.yOf(p.RxX10)})
			curR = append(curR, p)
		}
		flush()
		return
	}
	w := bucketWidth(span, nb)
	ch.Bucketed, ch.BucketLabel = true, fmtWidth(w)
	start := time.Unix(0, b.t0).Truncate(w)
	type bucket struct {
		n, dark     int
		lo, hi, sum int64
	}
	n := int(time.Unix(0, b.t1).Sub(start)/w) + 1
	bs := make([]bucket, n)
	idx := func(t time.Time) int { return min(max(int(t.Sub(start)/w), 0), n-1) }
	for _, p := range seq {
		bk := &bs[idx(p.T)]
		if p.NoLight {
			bk.dark++
			continue
		}
		if bk.n == 0 {
			bk.lo, bk.hi = p.RxX10, p.RxX10
		}
		bk.lo, bk.hi = min(bk.lo, p.RxX10), max(bk.hi, p.RxX10)
		bk.sum += p.RxX10
		bk.n++
	}
	var cur, top, bottom []pt
	spread := false
	flush := func() {
		if len(cur) == 1 {
			ch.Dots = append(ch.Dots, chartDot{X: f1(cur[0].x), Y: f1(cur[0].y)})
		} else if len(cur) > 1 {
			ch.Lines = append(ch.Lines, pathOf(cur))
			if spread {
				area := append(slices.Clone(top), reversedPts(bottom)...)
				ch.Spreads = append(ch.Spreads, pathOf(area)+" Z")
			}
		}
		if len(cur) > 0 {
			b.drawn = append(b.drawn, cur)
		}
		cur, top, bottom, spread = nil, nil, nil, false
	}
	gapBuckets := max(1, int(breakGap/w))
	empty := 0
	for k := range bs {
		bk := bs[k]
		if bk.dark > 0 {
			flush() // a bucket with a reading without a receive level is a gap in the line
			empty = 0
			continue
		}
		if bk.n == 0 {
			empty++
			if empty >= gapBuckets {
				flush()
			}
			continue
		}
		empty = 0
		x := b.xOf(start.Add(time.Duration(k)*w + w/2))
		cur = append(cur, pt{x, b.yOfF(float64(bk.sum) / float64(bk.n))})
		top = append(top, pt{x, b.yOf(bk.hi)})
		bottom = append(bottom, pt{x, b.yOf(bk.lo)})
		spread = spread || bk.lo != bk.hi
	}
	flush()
}

func reversedPts(ps []pt) []pt {
	out := slices.Clone(ps)
	slices.Reverse(out)
	return out
}

// drawBands shades the incidents the monitor attributed to AT&T (outages, normally) and labels
// them with their ids when every label fits above the plot.
func (b *chartBuilder) drawBands(rep *Report, pFrom, pTo time.Time, loc *time.Location) {
	ch := b.ch
	type band struct {
		x0, x1 float64
		id     string
	}
	var bands []band
	for _, inc := range rep.Incidents {
		if inc.Attribution != model.AttrProvider || inc.OpenedT.IsZero() {
			continue
		}
		end := inc.ClosedT
		if end.IsZero() {
			end = inc.RecTS
		}
		if end.Before(pFrom) || inc.OpenedT.After(pTo) {
			continue
		}
		x0, x1 := b.xOf(inc.OpenedT), b.xOf(end)
		if x1-x0 < 2 {
			c := (x0 + x1) / 2
			x0, x1 = math.Max(c-1, plotX0), math.Min(c+1, plotX1)
		}
		closed := "still open at " + fmtLocal(end, loc)
		if !inc.ClosedT.IsZero() {
			closed = "to " + fmtLocal(end, loc)
		}
		ch.Bands = append(ch.Bands, chartBand{X: f1(x0), W: f1(x1 - x0),
			Title: fmt.Sprintf("%s, %s attributed to AT&T: %s %s", inc.ID, orNA(inc.State), fmtLocal(inc.OpenedT, loc), closed)})
		bands = append(bands, band{x0, x1, inc.ID})
		if inc.State != model.StateISPOutage {
			ch.BandsWhat = "incident"
		}
	}
	ch.OutageBands = len(bands)
	if ch.BandsWhat == "" {
		ch.BandsWhat = "outage"
	}
	if len(bands) == 0 || len(bands) > 3 {
		return
	}
	y := b.y0 - 5
	var boxes []box
	for _, bd := range bands {
		x := (bd.x0 + bd.x1) / 2
		bx := labelBox(x, y, "middle", bd.id, fontPx)
		if bx.x0 < plotX0-20 || bx.x1 > chartW {
			return
		}
		for _, o := range boxes {
			if bx.hits(o) {
				return
			}
		}
		boxes = append(boxes, bx)
	}
	for i, bd := range bands {
		x := (bd.x0 + bd.x1) / 2
		t := boxes[i].text(x, y, "middle", bd.id)
		ch.Bands[i].Label = &t
		b.occupied = append(b.occupied, boxes[i])
	}
}

// drawRefs draws the threshold lines: the higher threshold labelled above its line, the lower
// one below, at the left of the plot or, when the readings run there, at its right.
func (b *chartBuilder) drawRefs(alarmThr, warnThr *int64) {
	type ref struct {
		v           int64
		class, name string
	}
	var refs []ref
	if alarmThr != nil {
		refs = append(refs, ref{*alarmThr, "alarm", "Gateway low-Rx ALARM threshold"})
	}
	if warnThr != nil {
		refs = append(refs, ref{*warnThr, "warning", "Gateway low-Rx WARNING threshold"})
	}
	for i, r := range refs {
		y := b.yOf(r.v)
		above := true
		if len(refs) == 2 {
			o := refs[1-i]
			above = r.v > o.v || (r.v == o.v && i == 0)
		}
		ly := y - 5
		if !above {
			ly = y + 13
		}
		if ly < b.y0+9 {
			ly = y + 13
		} else if ly > b.y1-3 {
			ly = y - 5
		}
		label := fmt.Sprintf("%s %s", r.name, fmtDBm(r.v))
		t := b.place(label, cand(plotX0+6, ly, "start"), cand(plotX1-6, ly, "end"))
		b.ch.Refs = append(b.ch.Refs, chartRef{Y: f1(y), X0: f1(plotX0), X1: f1(plotX1), Class: r.class, Label: t})
	}
}

// drawMarkers marks the setup-time capture (when it lies in the plot) and labels the latest
// level at its end.
func (b *chartBuilder) drawMarkers(in, levels []Reading, loc *time.Location) {
	ch := b.ch
	var last Reading
	for _, p := range levels {
		if !p.Setup {
			last = p
		}
	}
	if !last.T.IsZero() {
		x, y := b.xOf(last.T), b.yOf(last.RxX10)
		label := fmtDBm(last.RxX10) + " latest"
		if latest := in[len(in)-1]; latest.T.After(last.T) {
			label = fmtDBm(last.RxX10) + " last level"
		}
		m := &chartMarker{X: f1(x), Y: f1(y),
			Title: fmt.Sprintf("Latest receive level %s: Rx %s%s (%s)", fmtLocal(last.T, loc), fmtDBm(last.RxX10), flagsPhrase(last), last.Source())}
		ly := y + 3.5
		if x+endLabelGap+textW(label, fontPx) <= chartW {
			m.Label = b.place(label, cand(x+endLabelGap, ly, "start"))
		} else {
			m.Label = b.place(label, cand(x-endLabelGap, ly, "end"))
		}
		ch.End = m
	}
	for _, p := range levels {
		if !p.Setup {
			continue
		}
		x, y := b.xOf(p.T), b.yOf(p.RxX10)
		m := &chartMarker{X: f1(x), Y: f1(y), Path: diamond(x, y, 6),
			Title: fmt.Sprintf("Setup-time capture %s: Rx %s%s (bootstrap_import %s, %s)", fmtLocal(p.T, loc), fmtDBm(p.RxX10), flagsPhrase(p), seqRef(p.Seq), p.Path)}
		const s = "setup capture"
		// Above the marker, else below it, to its right unless the chart ends there; never on
		// the line, a threshold label or another label.
		m.Label = b.place(s, cand(x+8, y-10, "start"), cand(x-8, y-10, "end"), cand(x+8, y+18, "start"), cand(x-8, y+18, "end"),
			cand(x+8, y-24, "start"), cand(x-8, y-24, "end"), cand(x+8, y+32, "start"), cand(x-8, y+32, "end"))
		b.drawn = append(b.drawn, []pt{{x - 6, y}, {x + 6, y}, {x, y - 6}, {x, y + 6}})
		ch.Setup = m
		break
	}
}

// drawStrips draws the flag strips: a thin line where a reading lacks the condition, a full
// block where it has it.
func (b *chartBuilder) drawStrips(in []Reading, loc *time.Location) {
	ch := b.ch
	half := 1.5
	breakGap := max(5*time.Minute, 4*medianSpacing(in))
	runs := func(keep func(Reading) bool, what string) []chartSeg {
		var out []chartSeg
		var run []Reading
		emit := func() {
			if len(run) == 0 {
				return
			}
			xa, xb := b.xOf(run[0].T)-half, b.xOf(run[len(run)-1].T)+half
			xa, xb = math.Max(xa, plotX0), math.Min(xb, plotX1)
			if xb-xa < 2*half {
				xb = math.Min(xa+2*half, plotX1)
				xa = xb - 2*half
			}
			title := fmt.Sprintf("%s: %s, %s to %s", what, plural(len(run), "reading", "readings"), fmtLocal(run[0].T, loc), fmtLocal(run[len(run)-1].T, loc))
			if len(run) == 1 {
				title = fmt.Sprintf("%s: 1 reading, %s (%s)", what, fmtLocal(run[0].T, loc), run[0].Source())
			}
			out = append(out, chartSeg{X: f1(xa), W: f1(xb - xa), Title: title})
			run = nil
		}
		for _, p := range in {
			if !keep(p) || (len(run) > 0 && p.T.Sub(run[len(run)-1].T) > breakGap) {
				emit()
			}
			if keep(p) {
				run = append(run, p)
			}
		}
		emit()
		return out
	}
	every := func(Reading) bool { return true }
	present := runs(every, "Gateway readings")
	y := b.y1 + stripTop
	for _, s := range []struct {
		label, class, what string
		keep               func(Reading) bool
	}{
		{"ALARM flag", "alarm", "Gateway low-Rx ALARM flag set", func(r Reading) bool { return r.Alarm }},
		{"WARNING flag", "warning", "Gateway low-Rx WARNING flag set", func(r Reading) bool { return r.Warn }},
		{"Fiber link down", "nolight", "Gateway reported its fiber link down (no receive level)", func(r Reading) bool { return r.NoLight }},
	} {
		ch.Strips = append(ch.Strips, chartStrip{Y: f1(y), H: f1(stripH), LX: f1(plotX0 - 8), LY: f1(y + stripH - 0.5),
			PY: f1(y + stripH/2 - 1), PH: "2", Label: s.label, Class: s.class, Present: present, Flags: runs(s.keep, s.what)})
		y += stripStep
	}
}

// drawContext draws the whole-window bar above a plot of the readings' span: where readings
// exist, the setup-time capture, and the plotted span outlined.
func (b *chartBuilder) drawContext(all []Reading, from, to, pFrom, pTo time.Time, loc *time.Location) {
	ch := b.ch
	cb := &chartBuilder{t0: from.UnixNano(), t1: to.UnixNano()}
	cx := &chartContext{Y: f1(ctxBarY), H: f1(ctxBarH), PresentH: f1(ctxBarH), LX: f1(plotX0 - 8), LY: f1(ctxBarY + ctxBarH - 1),
		Label: "Whole window", TickY: f1(ctxBarY - 5)}
	prevDate := ""
	for _, tk := range timeTicks(from, to, loc) {
		label := tk.label
		if d := tk.t.In(loc).Format("Jan 2"); d != prevDate {
			label = d + ", " + label
			prevDate = d
		}
		cx.Ticks = append(cx.Ticks, chartTick{X: f1(cb.xOf(tk.t)), Label: label})
	}
	breakGap := max(5*time.Minute, 4*medianSpacing(all))
	var run []Reading
	emit := func() {
		if len(run) == 0 {
			return
		}
		xa, xb := cb.xOf(run[0].T)-1, cb.xOf(run[len(run)-1].T)+1
		xa, xb = math.Max(xa, plotX0), math.Min(xb, plotX1)
		cx.Present = append(cx.Present, chartSeg{X: f1(xa), W: f1(xb - xa),
			Title: fmt.Sprintf("Gateway readings: %s, %s to %s", plural(len(run), "reading", "readings"), fmtLocal(run[0].T, loc), fmtLocal(run[len(run)-1].T, loc))})
		run = nil
	}
	for _, p := range all {
		if p.Setup {
			continue
		}
		if len(run) > 0 && p.T.Sub(run[len(run)-1].T) > breakGap {
			emit()
		}
		run = append(run, p)
	}
	emit()
	ly := ctxBarY + ctxBarH + 12 // the labels under the bar
	var setupBox *box
	if s := ch.SetupOutside; s != nil {
		x, y := cb.xOf(s.T), ctxBarY+ctxBarH/2
		cx.Setup = &chartMarker{X: f1(x), Y: f1(y), Path: diamond(x, y, 5),
			Title: fmt.Sprintf("Setup-time capture %s: Rx %s%s (bootstrap_import %s, %s)", fmtLocal(s.T, loc), fmtDBm(s.RxX10), flagsPhrase(*s), seqRef(s.Seq), s.Path)}
		const label = "setup capture"
		anchor, lx := "start", x+8
		if lx+textW(label, fontPx) > plotX1 {
			anchor, lx = "end", x-8
		}
		bx := labelBox(lx, ly, anchor, label, fontPx)
		cx.Setup.Label = bx.text(lx, ly, anchor, label)
		setupBox = &bx
	}
	zx0, zx1 := cb.xOf(pFrom), cb.xOf(pTo)
	if zx1-zx0 < 4 {
		c := (zx0 + zx1) / 2
		zx0, zx1 = c-2, c+2
	}
	cx.ZoomX, cx.ZoomY, cx.ZoomW, cx.ZoomH = f1(zx0-1.5), f1(ctxBarY-2.5), f1(zx1-zx0+3), f1(ctxBarH+5)
	note := "plotted below"
	anchor, nx := "end", zx1+1.5
	if nx-textW(note, fontPx) < plotX0 {
		anchor, nx = "start", zx0-1.5
	}
	nb := labelBox(nx, ly, anchor, note, fontPx)
	if setupBox != nil && setupBox.hits(nb) {
		// The setup capture's label yields: its marker and tooltip remain.
		cx.Setup.Label = chartText{}
	}
	cx.Note = nb.text(nx, ly, anchor, note)
	ch.Context = cx
}

func countIf(rs []Reading, f func(Reading) bool) int {
	n := 0
	for _, r := range rs {
		if f(r) {
			n++
		}
	}
	return n
}

// diamond is the path of a diamond marker of half-diagonal r centred on (x, y).
func diamond(x, y, r float64) string {
	return fmt.Sprintf("M%s,%s L%s,%s L%s,%s L%s,%s Z", f1(x), f1(y-r), f1(x+r), f1(y), f1(x), f1(y+r), f1(x-r), f1(y))
}
