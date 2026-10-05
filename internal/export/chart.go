package export

import (
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Inline SVG chart of the gateway-reported Rx optical power. Styling follows the dataviz
// basics: one y-axis (dBm), a single 2px series line, recessive solid hairline grid, labeled
// dashed reference lines for the gateway's own thresholds, a light wash where the gateway's
// low-alarm flag was set, and native <title> tooltips (no scripts) on hit areas wider than
// the marks. Gaps in the readings are never bridged.

const (
	chartW, chartH = 960, 320
	plotX0, plotX1 = 64.0, 872.0
	plotY0, plotY1 = 24.0, 280.0
	maxChartPoints = 720

	// plausibleX10 bounds the optical power values that are drawn (±100 dBm, in 0.1 dBm). A
	// value beyond it cannot be a real reading (parser glitch, damaged record); it stays in the
	// tables and report.json but is not plotted, which also keeps the axis and ticks bounded.
	plausibleX10 = 1000
	maxYTicks    = 12
)

func plausible(v *int64) bool { return v != nil && *v >= -plausibleX10 && *v <= plausibleX10 }

type opticalChart struct {
	W, H         int
	X0, X1       string
	Y0, Y1       string
	PlotH        string
	YLabelX      string
	XLabelY      string
	TickY2       string
	AxisTitleY   string
	Title, Desc  string
	YTicks       []chartTick
	XTicks       []chartTick
	Refs         []refLine
	AlarmBands   []chartRect
	Bands        []string
	Lines        []string
	Dots         []chartTick
	End          *endLabel
	Hits         []chartRect
	Bucketed     bool
	BucketLabel  string
	HasAlarmBand bool
	Readings     int
	ZoneLabel    string // local zone of the time axis, e.g. "CDT (UTC-05:00)"
}

type chartTick struct {
	X, Y, TY string
	Label    string
}

type refLine struct {
	Y, LX, LY    string
	Class, Label string
}

type chartRect struct {
	X, W  string
	Title string
}

type endLabel struct {
	X, Y, LX, LY  string
	Anchor, Label string
}

type fpt struct{ x, y float64 }

func f1(v float64) string { return strconv.FormatFloat(v, 'f', 1, 64) }

func (c *collector) opticalChart() *opticalChart {
	var alarm, warn *int64
	if c.rep != nil {
		alarm, warn = c.rep.Optical.LowAlarmThrX10, c.rep.Optical.LowWarnThrX10
	}
	return buildOpticalChart(c.sortedOptPoints(), c.periods, c.from, c.end, alarm, warn, c.loc)
}

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

func medianSpacing(pts []optPoint) time.Duration {
	var ds []int64
	for i := 1; i < len(pts); i++ {
		if d := pts[i].t.Sub(pts[i-1].t); d > 0 {
			ds = append(ds, int64(d))
		}
	}
	if len(ds) == 0 {
		return 0
	}
	sort.Slice(ds, func(i, j int) bool { return ds[i] < ds[j] })
	return time.Duration(ds[len(ds)/2])
}

func flagText(codes []string) string {
	var parts []string
	for _, c := range uniqueSorted(codes) {
		if strings.HasPrefix(c, "OPTICAL_RX_") {
			parts = append(parts, codeLabel(c))
		}
	}
	if len(parts) == 0 {
		return ""
	}
	return "; gateway flags: " + strings.Join(parts, ", ")
}

// buildOpticalChart draws the chart; its time axis and labels use the local zone loc.
func buildOpticalChart(all []optPoint, periods []alarmPeriod, from, end time.Time, alarmThr, warnThr *int64, loc *time.Location) *opticalChart {
	fmtLocal := func(s string) string { return fmtLocalIn(loc, s) }
	var pts []optPoint
	implausible := 0
	for _, p := range all {
		if p.rx == nil || p.t.Before(from) || p.t.After(end) {
			continue
		}
		if !plausible(p.rx) {
			implausible++
			continue
		}
		pts = append(pts, p)
	}
	if len(pts) == 0 || !end.After(from) {
		return nil
	}
	if !plausible(alarmThr) {
		alarmThr = nil
	}
	if !plausible(warnThr) {
		warnThr = nil
	}
	t0, t1 := from.UnixNano(), end.UnixNano()
	xOf := func(t int64) float64 {
		x := plotX0 + (plotX1-plotX0)*float64(t-t0)/float64(t1-t0)
		return math.Min(math.Max(x, plotX0), plotX1)
	}

	// Y domain: all readings plus the thresholds, padded, rounded to ticks.
	dataLo, dataHi := *pts[0].rx, *pts[0].rx
	for _, p := range pts {
		dataLo, dataHi = min(dataLo, *p.rx), max(dataHi, *p.rx)
	}
	lo, hi := dataLo, dataHi
	for _, t := range []*int64{alarmThr, warnThr} {
		if t != nil {
			lo, hi = min(lo, *t), max(hi, *t)
		}
	}
	pad := max(int64(3), (hi-lo)/10)
	lo, hi = lo-pad, hi+pad
	step := niceStep(hi - lo)
	lo, hi = floorDiv(lo, step)*step, ceilDiv(hi, step)*step
	if hi <= lo {
		hi = lo + step
	}
	yOf := func(v float64) float64 { return plotY1 - (plotY1-plotY0)*(v-float64(lo))/float64(hi-lo) }

	ch := &opticalChart{
		W: chartW, H: chartH, X0: f1(plotX0), X1: f1(plotX1), Y0: f1(plotY0), Y1: f1(plotY1),
		PlotH: f1(plotY1 - plotY0), YLabelX: f1(plotX0 - 8), XLabelY: f1(plotY1 + 20), TickY2: f1(plotY1 + 5),
		AxisTitleY: f1(plotY0 - 9), Readings: len(pts), ZoneLabel: zoneLabel(loc, from),
		Title: "Optical receive (Rx) power reported by the AT&T gateway",
	}
	for v := lo; v <= hi && len(ch.YTicks) < maxYTicks; v += step {
		y := yOf(float64(v))
		ch.YTicks = append(ch.YTicks, chartTick{Y: f1(y), TY: f1(y + 4), Label: fmtX10(v)})
	}
	for _, tk := range timeTicks(from, end, loc) {
		ch.XTicks = append(ch.XTicks, chartTick{X: f1(xOf(tk.t.UnixNano())), Label: tk.label})
	}

	// Where the gateway's own low-alarm flag was set.
	for _, ap := range periods {
		if ap.Code != codeRxLowAlarm {
			continue
		}
		f, ok1 := parseTS(ap.FirstSeen)
		l, ok2 := parseTS(ap.LastSeen)
		if !ok1 || !ok2 {
			continue
		}
		xa, xb := xOf(f.UnixNano()), xOf(l.UnixNano())
		if xb-xa < 2 {
			xb = math.Min(xa+2, plotX1)
			xa = xb - 2
		}
		ch.AlarmBands = append(ch.AlarmBands, chartRect{X: f1(xa), W: f1(xb - xa), Title: fmt.Sprintf(
			"Gateway low-alarm flag set from %s to %s (%d readings)", fmtLocal(ap.FirstSeen), fmtLocal(ap.LastSeen), ap.Snapshots)})
	}
	ch.HasAlarmBand = len(ch.AlarmBands) > 0

	// Reference lines: the higher threshold is labeled above its line, the lower one below.
	type ref struct {
		v           int64
		class, name string
	}
	var refs []ref
	if alarmThr != nil {
		refs = append(refs, ref{*alarmThr, "alarm", "Gateway low-alarm threshold"})
	}
	if warnThr != nil {
		refs = append(refs, ref{*warnThr, "warning", "Gateway low-warning threshold"})
	}
	for i, r := range refs {
		y := yOf(float64(r.v))
		above := true
		if len(refs) == 2 {
			o := refs[1-i]
			above = r.v > o.v || (r.v == o.v && i == 0)
		}
		ly := y - 6
		if !above {
			ly = y + 15
		}
		if ly < plotY0+10 {
			ly = y + 15
		} else if ly > plotY1-4 {
			ly = y - 6
		}
		ch.Refs = append(ch.Refs, refLine{Y: f1(y), LX: f1(plotX1 - 6), LY: f1(ly), Class: r.class,
			Label: fmt.Sprintf("%s %s dBm", r.name, fmtX10(r.v))})
	}

	spacing := medianSpacing(pts)
	breakGap := max(5*time.Minute, 4*spacing)
	pathOf := func(run []fpt) string {
		var b strings.Builder
		for i, p := range run {
			if i == 0 {
				b.WriteString("M")
			} else {
				b.WriteString(" L")
			}
			b.WriteString(f1(p.x) + "," + f1(p.y))
		}
		return b.String()
	}
	addRun := func(run []fpt) {
		switch len(run) {
		case 0:
		case 1:
			ch.Dots = append(ch.Dots, chartTick{X: f1(run[0].x), Y: f1(run[0].y)})
		default:
			ch.Lines = append(ch.Lines, pathOf(run))
		}
	}

	if len(pts) <= maxChartPoints {
		var run []fpt
		maxHalf := math.Max(6, (xOf(t0+int64(breakGap))-plotX0)/2)
		for i, p := range pts {
			if i > 0 && p.t.Sub(pts[i-1].t) > breakGap {
				addRun(run)
				run = nil
			}
			x, y := xOf(p.t.UnixNano()), yOf(float64(*p.rx))
			run = append(run, fpt{x, y})
			left, right := math.Max(plotX0, x-maxHalf), math.Min(plotX1, x+maxHalf)
			if i > 0 {
				left = math.Max(left, (x+xOf(pts[i-1].t.UnixNano()))/2)
			}
			if i+1 < len(pts) {
				right = math.Min(right, (x+xOf(pts[i+1].t.UnixNano()))/2)
			}
			if right-left < 1 {
				right = left + 1
			}
			ch.Hits = append(ch.Hits, chartRect{X: f1(left), W: f1(right - left), Title: fmt.Sprintf(
				"%s: Rx %s dBm%s (record seq %d)", fmtLocal(p.t.UTC().Format(time.RFC3339Nano)), fmtX10(*p.rx), flagText(p.alarms), p.seq)})
		}
		addRun(run)
	} else {
		ch.Bucketed = true
		n := maxChartPoints
		if spacing > 0 {
			if k := int((t1 - t0) / int64(2*spacing)); k < n {
				n = max(k, 1)
			}
		}
		bw := float64(t1-t0) / float64(n)
		ch.BucketLabel = fmtDur(int64(bw / float64(time.Second)))
		type bucket struct {
			n                 int
			lo, hi, sum       int64
			alarm, warn       int
			firstSeq, lastSeq uint64
		}
		bs := make([]bucket, n)
		for _, p := range pts {
			k := int(float64(p.t.UnixNano()-t0) / bw)
			k = min(max(k, 0), n-1)
			b := &bs[k]
			v := *p.rx
			if b.n == 0 {
				b.lo, b.hi, b.firstSeq = v, v, p.seq
			}
			b.lo, b.hi = min(b.lo, v), max(b.hi, v)
			b.sum += v
			b.n++
			b.lastSeq = p.seq
			if hasCode(p.alarms, codeRxLowAlarm) {
				b.alarm++
			}
			if hasCode(p.alarms, codeRxLowWarn) {
				b.warn++
			}
		}
		var run, top, bottom []fpt
		spread := false
		flush := func() {
			addRun(run)
			if len(run) > 1 && spread {
				all := append([]fpt(nil), top...)
				for i := len(bottom) - 1; i >= 0; i-- {
					all = append(all, bottom[i])
				}
				ch.Bands = append(ch.Bands, pathOf(all)+" Z")
			}
			run, top, bottom, spread = nil, nil, nil, false
		}
		for k := range bs {
			b := bs[k]
			if b.n == 0 {
				flush()
				continue
			}
			start := float64(t0) + float64(float64(k)*bw) // explicit conversion: no fused multiply-add, the same result on every platform
			x := xOf(int64(start + bw/2))
			mean := float64(b.sum) / float64(b.n)
			run = append(run, fpt{x, yOf(mean)})
			top = append(top, fpt{x, yOf(float64(b.hi))})
			bottom = append(bottom, fpt{x, yOf(float64(b.lo))})
			spread = spread || b.lo != b.hi
			xa, xb := xOf(int64(start)), xOf(int64(start+bw))
			if xb-xa < 1 {
				xb = xa + 1
			}
			bs0 := time.Unix(0, int64(start)).UTC().Format(time.RFC3339Nano)
			bs1 := time.Unix(0, int64(start+bw)).UTC().Format(time.RFC3339Nano)
			ch.Hits = append(ch.Hits, chartRect{X: f1(xa), W: f1(xb - xa), Title: fmt.Sprintf(
				"%s to %s: mean Rx %.1f dBm (min %s, max %s), %d readings, gateway low-alarm flag in %d, low-warning flag in %d (seq %d-%d)",
				fmtLocal(bs0), fmtLocal(bs1), mean/10, fmtX10(b.lo), fmtX10(b.hi), b.n, b.alarm, b.warn, b.firstSeq, b.lastSeq)})
		}
		flush()
	}

	last := pts[len(pts)-1]
	ex, ey := xOf(last.t.UnixNano()), yOf(float64(*last.rx))
	el := &endLabel{X: f1(ex), Y: f1(ey), LY: f1(ey + 4), Label: fmtX10(*last.rx) + " dBm (last)"}
	if ex+8+110 <= chartW {
		el.LX, el.Anchor = f1(ex+8), "start"
	} else {
		el.LX, el.Anchor = f1(ex-8), "end"
	}
	ch.End = el

	desc := fmt.Sprintf("%s taken from the gateway's fiberstat page between %s and %s, ranging from %s to %s dBm.",
		plural(len(pts), "Rx power reading", "Rx power readings"), fmtLocal(from.UTC().Format(time.RFC3339)),
		fmtLocal(end.UTC().Format(time.RFC3339)), fmtX10(dataLo), fmtX10(dataHi))
	if alarmThr != nil {
		desc += " Gateway low-alarm threshold " + fmtX10(*alarmThr) + " dBm."
	}
	if warnThr != nil {
		desc += " Gateway low-warning threshold " + fmtX10(*warnThr) + " dBm."
	}
	if ch.HasAlarmBand {
		desc += " Shaded spans mark readings where the gateway's own low-alarm flag was set."
	}
	switch {
	case implausible == 1:
		desc += " 1 value outside ±100 dBm (not a possible optical power reading) is not plotted; it is listed in the tables."
	case implausible > 1:
		desc += fmt.Sprintf(" %d values outside ±100 dBm (not possible optical power readings) are not plotted; they are listed in the tables.", implausible)
	}
	ch.Desc = desc
	return ch
}

type timeTick struct {
	t     time.Time
	label string
}

// timeTicks returns up to ~8 ticks aligned to clock boundaries in loc.
func timeTicks(from, end time.Time, loc *time.Location) []timeTick {
	span := end.Sub(from)
	if span <= 0 {
		return nil
	}
	const day = 24 * time.Hour
	steps := []time.Duration{time.Minute, 2 * time.Minute, 5 * time.Minute, 10 * time.Minute, 15 * time.Minute,
		30 * time.Minute, time.Hour, 2 * time.Hour, 3 * time.Hour, 6 * time.Hour, 12 * time.Hour, day, 2 * day,
		7 * day, 14 * day, 28 * day, 56 * day, 112 * day}
	step := steps[len(steps)-1]
	for _, s := range steps {
		if span/s <= 7 {
			step = s
			break
		}
	}
	lf := from.In(loc)
	base := time.Date(lf.Year(), lf.Month(), lf.Day(), 0, 0, 0, 0, loc)
	var ts []time.Time
	if step < day {
		t := base.Add(from.Sub(base) / step * step)
		for t.Before(from) {
			t = t.Add(step)
		}
		for ; !t.After(end); t = t.Add(step) {
			ts = append(ts, t)
		}
	} else {
		days := int(step / day)
		t := base
		if t.Before(from) {
			t = t.AddDate(0, 0, 1)
		}
		for ; !t.After(end); t = t.AddDate(0, 0, days) {
			ts = append(ts, t)
		}
	}
	out := make([]timeTick, 0, len(ts))
	for _, t := range ts {
		lt := t.In(loc)
		var label string
		switch {
		case step >= day:
			label = lt.Format("Jan 2")
		case span <= day:
			label = lt.Format("15:04")
			if lt.Hour() == 0 && lt.Minute() == 0 {
				label = lt.Format("Jan 2")
			}
		default:
			label = lt.Format("Jan 2 15:04")
		}
		out = append(out, timeTick{t: t, label: label})
	}
	return out
}
