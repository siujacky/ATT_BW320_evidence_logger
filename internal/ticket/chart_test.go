package ticket

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"

	"attmonitor/internal/model"
)

// pathPoints parses the points of an SVG path drawn by the chart ("M1.0,2.0 L3.0,4.0 ... Z").
func pathPoints(t *testing.T, d string) []pt {
	t.Helper()
	var out []pt
	for _, f := range strings.Fields(d) {
		f = strings.TrimLeft(f, "ML")
		if f == "Z" || f == "" {
			continue
		}
		x, y, ok := strings.Cut(f, ",")
		if !ok {
			t.Fatalf("path %q: bad point %q", d, f)
		}
		xv, err1 := strconv.ParseFloat(x, 64)
		yv, err2 := strconv.ParseFloat(y, 64)
		if err1 != nil || err2 != nil {
			t.Fatalf("path %q: bad point %q", d, f)
		}
		out = append(out, pt{xv, yv})
	}
	return out
}

// xAt is the chart's x of time t.
func xAt(ch *Chart, t time.Time) float64 {
	return plotX0 + (plotX1-plotX0)*float64(t.Sub(ch.PlotFrom))/float64(ch.PlotTo.Sub(ch.PlotFrom))
}

func labelBoxOf(t *testing.T, l chartText) box {
	t.Helper()
	if l.BW == "" {
		t.Fatalf("label %q has no box", l.Label)
	}
	x, y, w, h := mustFloat(t, l.BX), mustFloat(t, l.BY), mustFloat(t, l.BW), mustFloat(t, l.BH)
	return box{x, y, x + w, y + h}
}

// TestChart checks the chart of the real situation: thresholds, markers, strips and the plotted
// span.
func TestChart(t *testing.T) {
	s := realScenario(t)
	rep := mustBuild(t, s, s.options())
	ch := rep.Optical.Chart
	if ch == nil {
		t.Fatal("no chart")
	}
	if len(ch.Refs) != 2 {
		t.Fatalf("refs = %+v", ch.Refs)
	}
	var alarm, warn chartRef
	for _, r := range ch.Refs {
		switch r.Class {
		case "alarm":
			alarm = r
		case "warning":
			warn = r
		}
	}
	if alarm.Label.Label != "Gateway low-Rx ALARM threshold -29.5 dBm" || warn.Label.Label != "Gateway low-Rx WARNING threshold -29.2 dBm" {
		t.Errorf("labels %q / %q", alarm.Label.Label, warn.Label.Label)
	}
	ya, yw := mustFloat(t, alarm.Y), mustFloat(t, warn.Y)
	if ya <= yw { // -29.5 is below -29.2: larger y
		t.Errorf("alarm line y %v should be below warning line y %v", ya, yw)
	}
	if mustFloat(t, alarm.Label.Y) <= ya || mustFloat(t, warn.Label.Y) >= yw {
		t.Errorf("the lower threshold is labelled below its line, the upper one above")
	}
	// Readings -31.5..-30.9 and thresholds -29.5/-29.2, padded by 0.5 dB, on 0.5 dB ticks.
	if ch.YTicks[0].Label != "-32.0" || ch.YTicks[len(ch.YTicks)-1].Label != "-28.5" {
		t.Errorf("y ticks %v .. %v", ch.YTicks[0].Label, ch.YTicks[len(ch.YTicks)-1].Label)
	}
	// 75 snapshots over 1.2 h of a 24 h window were squeezed into the last 0.35 in of the plot:
	// the plot now shows their span, and a bar above it the whole window with the setup capture.
	if ch.Context == nil || ch.PlotFrom.Before(s.start.Add(-10*time.Minute)) || !ch.PlotFrom.After(s.from) || !ch.PlotTo.Equal(s.to) {
		t.Fatalf("plotted span %v .. %v, context %v", ch.PlotFrom, ch.PlotTo, ch.Context)
	}
	if ch.SetupOutside == nil || ch.Context.Setup == nil || ch.Setup != nil || len(ch.Context.Present) != 1 {
		t.Errorf("setup capture: outside %v, on the bar %v, in the plot %v; bar %+v", ch.SetupOutside, ch.Context.Setup, ch.Setup, ch.Context.Present)
	}
	if ch.End == nil || ch.End.Label.Label != "-31.3 dBm latest" {
		t.Errorf("end marker %+v", ch.End)
	}
	if len(ch.Strips) != 3 || ch.Strips[0].Label != "ALARM flag" || ch.Strips[1].Label != "WARNING flag" || ch.Strips[2].Label != "Fiber link down" {
		t.Fatalf("strips = %+v", ch.Strips)
	}
	if len(ch.Strips[0].Flags) != 1 || len(ch.Strips[1].Flags) != 1 || len(ch.Strips[2].Flags) != 0 || len(ch.Strips[2].Present) != 1 {
		t.Errorf("strip segments: %+v", ch.Strips)
	}
	if len(ch.Lines) != 1 || len(ch.Empty) != 0 || ch.NoLight != 0 || ch.Levels != len(s.snaps) {
		t.Errorf("lines %d empty labels %d no-light %d levels %d", len(ch.Lines), len(ch.Empty), ch.NoLight, ch.Levels)
	}
	wantContains(t, "chart desc", ch.Desc, "Gateway low-Rx alarm threshold -29.5 dBm.", "Gateway low-Rx warning threshold -29.2 dBm.",
		"the part of the window with readings")
	// Labels sit on white boxes, never on the line.
	for _, l := range []chartText{alarm.Label, warn.Label, ch.End.Label} {
		bx := labelBoxOf(t, l)
		for _, d := range ch.Lines {
			for _, p := range pathPoints(t, d) {
				if bx.contains(p) {
					t.Errorf("label %q at %+v covers the line point %+v", l.Label, bx, p)
				}
			}
		}
	}
}

// TestChartFullWindow: readings that span most of the window are plotted over the whole window.
func TestChartFullWindow(t *testing.T) {
	fs := newFlapScenario(t)
	rep, err := Build(context.Background(), fs.f, Options{From: fs.from, To: fs.to, Now: func() time.Time { return fs.now }, Location: cdt})
	if err != nil {
		t.Fatal(err)
	}
	ch := rep.Optical.Chart
	if ch == nil || ch.Context != nil || !ch.PlotFrom.Equal(fs.from) || !ch.PlotTo.Equal(fs.to) {
		t.Fatalf("chart %+v", ch)
	}
}

// TestChartNoLight: readings taken while the gateway reported its fiber link down have no receive
// level. They used to be dropped and the line joined across them, so the outage never appeared;
// now the line breaks there, a strip marks them, the outage is shaded and the caption says so.
func TestChartNoLight(t *testing.T) {
	fs := newFlapScenario(t)
	rep, err := Build(context.Background(), fs.f, Options{From: fs.from, To: fs.to, Now: func() time.Time { return fs.now }, Location: cdt})
	if err != nil {
		t.Fatal(err)
	}
	ch := rep.Optical.Chart
	if ch == nil || ch.NoLight != 2 || ch.Bucketed {
		t.Fatalf("chart %+v", ch)
	}
	var dark []time.Time
	for _, rd := range rep.Optical.Readings {
		if rd.NoLight {
			dark = append(dark, rd.T)
		}
	}
	if len(dark) != 2 {
		t.Fatalf("dark readings %v", dark)
	}
	for _, d := range ch.Lines {
		ps := pathPoints(t, d)
		x0, x1 := ps[0].x, ps[len(ps)-1].x
		for _, dt := range dark {
			if x := xAt(ch, dt); x > x0 && x < x1 {
				t.Errorf("a line from x %.1f to %.1f is drawn across the no-light reading at x %.1f (%s)", x0, x1, x, dt)
			}
		}
	}
	if len(ch.Lines) < 2 {
		t.Errorf("the line must break at the outage: %d lines", len(ch.Lines))
	}
	nl := ch.Strips[2]
	if nl.Class != "nolight" || len(nl.Flags) != 1 || !strings.Contains(nl.Flags[0].Title, "2 readings") {
		t.Errorf("fiber link down strip %+v", nl)
	}
	if x := mustFloat(t, nl.Flags[0].X); x > xAt(ch, dark[0]) || x+mustFloat(t, nl.Flags[0].W) < xAt(ch, dark[1]) {
		t.Errorf("the strip segment %+v does not cover the readings", nl.Flags[0])
	}
	if ch.OutageBands != 1 || len(ch.Bands) != 1 || ch.Bands[0].Label == nil || ch.Bands[0].Label.Label != "INC-20261005-130457Z" {
		t.Errorf("outage bands %+v", ch.Bands)
	}
	if b := ch.Bands[0]; mustFloat(t, b.X) > xAt(ch, dark[0]) || mustFloat(t, b.X)+mustFloat(t, b.W) < xAt(ch, dark[1]) {
		t.Errorf("the band %+v does not cover the outage", b)
	}
	page, err := rep.HTML()
	if err != nil {
		t.Fatal(err)
	}
	wantContains(t, "caption", pageText(t, page),
		"broken where readings are missing and where the fiber link was down",
		"2 readings taken while the gateway reported its fiber link down have no receive level; they are marked, not drawn as levels.",
		"Grey band: the outage the monitor attributed to AT&T (see Incidents).")

	// Bucketed: a bucket holding a no-light reading is a gap in the line.
	base := ts("2026-10-04T14:00:00Z")
	var rs []Reading
	var gapAt time.Time
	for i := 0; i < 5760; i++ {
		at := base.Add(time.Duration(i) * 15 * time.Second)
		rd := Reading{T: at, Seq: uint64(i), RxX10: -310 - int64(i%3), Alarm: true, Warn: true}
		if i == 3000 {
			rd.NoLight, rd.RxX10, gapAt = true, 0, at
		}
		rs = append(rs, rd)
	}
	rep2 := &Report{From: base, To: base.Add(24 * time.Hour), loc: time.UTC, Optical: Optical{Readings: rs, AlarmThr: i64(-295), WarnThr: i64(-292)}}
	ch2 := buildChart(rep2)
	if !ch2.Bucketed || ch2.NoLight != 1 || len(ch2.Lines) != 2 {
		t.Fatalf("bucketed %v no-light %d lines %d", ch2.Bucketed, ch2.NoLight, len(ch2.Lines))
	}
	for _, d := range ch2.Lines {
		ps := pathPoints(t, d)
		if x := xAt(ch2, gapAt); x > ps[0].x && x < ps[len(ps)-1].x {
			t.Errorf("a bucketed line is drawn across the no-light reading at x %.1f", x)
		}
	}
}

// TestChartBuckets: dense readings are drawn as a mean per round bucket width, and a gap in the
// readings is never bridged.
func TestChartBuckets(t *testing.T) {
	for _, tc := range []struct {
		span time.Duration
		n    int
		want string
	}{{24 * time.Hour, 172, "10 min"}, {2 * time.Hour, 172, "1 min"}, {7 * 24 * time.Hour, 172, "1 h"}, {30 * time.Minute, 172, "15 s"}} {
		if got := fmtWidth(bucketWidth(tc.span, tc.n)); got != tc.want {
			t.Errorf("bucket width for %v in %d buckets = %s, want %s", tc.span, tc.n, got, tc.want)
		}
	}
	from := ts("2026-10-04T14:00:00Z")
	var many []Reading
	for i := 0; i < 3000; i++ {
		at := from.Add(time.Duration(i) * 15 * time.Second)
		if i >= 1500 && i < 1800 {
			continue // 75 minutes without readings
		}
		many = append(many, Reading{T: at, Seq: uint64(i), RxX10: -310, Alarm: true, Warn: true})
	}
	rep := &Report{From: from, To: from.Add(24 * time.Hour), loc: time.UTC, Optical: Optical{Readings: many, AlarmThr: i64(-295), WarnThr: i64(-292)}}
	ch := buildChart(rep)
	if !ch.Bucketed || ch.BucketLabel != "10 min" || len(ch.Lines) != 2 {
		t.Errorf("bucketed %v label %q lines %d", ch.Bucketed, ch.BucketLabel, len(ch.Lines))
	}
}

// TestChartLabelsClear: on a bad day the setup capture sits among the readings; its label must
// not be drawn over the line (it was), nor over another label.
func TestChartLabelsClear(t *testing.T) {
	ss := stressScenario(t)
	rep := mustBuild(t, ss, ss.options())
	ch := rep.Optical.Chart
	if ch == nil || ch.Setup == nil || ch.Context != nil || !ch.Bucketed {
		t.Fatalf("chart %+v", ch)
	}
	var pts []pt
	for _, d := range ch.Lines {
		pts = append(pts, pathPoints(t, d)...)
	}
	for _, d := range ch.Dots {
		pts = append(pts, pt{mustFloat(t, d.X), mustFloat(t, d.Y)})
	}
	labels := []chartText{ch.Setup.Label, ch.End.Label}
	for _, r := range ch.Refs {
		labels = append(labels, r.Label)
	}
	var boxes []box
	for _, l := range labels {
		bx := labelBoxOf(t, l)
		for _, p := range pts {
			if bx.contains(p) {
				t.Errorf("label %q at %+v covers the line at %+v", l.Label, bx, p)
				break
			}
		}
		for _, o := range boxes {
			if bx.hits(o) {
				t.Errorf("label %q overlaps another label", l.Label)
			}
		}
		boxes = append(boxes, bx)
	}
	// 16 outages: shaded, too many to label.
	if ch.OutageBands != 16 || ch.NoLight != 16 || ch.Bands[0].Label != nil {
		t.Errorf("bands %d no-light %d", ch.OutageBands, ch.NoLight)
	}
}

// TestNoLightOnly: every reading of the window taken while the fiber link was down - no receive
// level to draw or to call the lowest (this used to index readings[-1] for the key facts).
func TestNoLightOnly(t *testing.T) {
	f := newFake(t)
	at := ts("2026-10-05T13:00:00Z")
	for i := 0; i < 3; i++ {
		snap := snapshot(at.Add(time.Duration(i)*time.Minute), 0, true, true, 400000, lastChange)
		snap.Fiber.OpticalStatus, snap.Derived.OpticalUp = "Down", bptr(false)
		f.add(at.Add(time.Duration(i)*time.Minute), model.TypeGatewaySnapshot, snap)
	}
	rep, err := Build(context.Background(), f, Options{To: at.Add(time.Hour), Now: func() time.Time { return at.Add(time.Hour) }, Location: cdt})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Optical.Chart != nil || rep.Optical.NoLightN != 3 || rep.Optical.MinI != -1 {
		t.Errorf("optical %+v", rep.Optical)
	}
	page, err := rep.HTML()
	if err != nil {
		t.Fatal(err)
	}
	wantContains(t, "page", pageText(t, page), "showed no receive level (Rx 0) while reporting its own fiber link down")
}

// TestChartBandWording: a shaded provider incident that is not an outage is not called one.
func TestChartBandWording(t *testing.T) {
	fs := newFlapScenario(t)
	deg := model.Incident{ID: "INC-20261005-133000Z", Opened: ts("2026-10-05T13:30:00Z").Format(time.RFC3339Nano),
		Closed: ts("2026-10-05T13:35:00Z").Format(time.RFC3339Nano), DurationSec: 300, State: model.StateDegraded,
		Cause: model.CausePacketLoss, Attribution: model.AttrProvider, Rules: "2026.10-4", Stats: model.IncidentStats{DegradedSec: 300}}
	fs.f.add(ts("2026-10-05T13:35:30Z"), model.TypeIncidentClose, deg)
	rep, err := Build(context.Background(), fs.f, Options{From: fs.from, To: fs.to, Now: func() time.Time { return fs.now }, Location: cdt})
	if err != nil {
		t.Fatal(err)
	}
	ch := rep.Optical.Chart
	if ch.OutageBands != 2 || ch.BandsWhat != "incident" || !strings.Contains(ch.Bands[1].Title, "INC-20261005-133000Z, DEGRADED attributed to AT&T") {
		t.Fatalf("bands %d %q %+v", ch.OutageBands, ch.BandsWhat, ch.Bands)
	}
	_, text := renderText(t, rep)
	wantContains(t, "caption", text, "Grey bands: the incidents the monitor attributed to AT&T (see Incidents).")
}
