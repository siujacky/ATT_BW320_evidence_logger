package export

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

// The local time zone of a report. REPORT.html and README.txt show local times in the zone of
// the computer that exported the bundle. report.json records that zone - its UTC offsets and
// abbreviations over the stretch of time the report can show (local_time_zone) - and both the
// exporter and the report verification (VerifyReport) render with a location built from that
// record, never with the zone of the computer they run on: a bundle verifies anywhere.

// zoneSpan is one stretch of time with one UTC offset of the exporting computer's zone.
type zoneSpan struct {
	From   string `json:"from"`         // RFC 3339 UTC; the first span also applies before it
	Abbrev string `json:"abbreviation"` // e.g. "PDT"
	Offset int    `json:"utc_offset_s"` // seconds east of UTC
	DST    bool   `json:"dst,omitempty"`
}

// localTimeZone is report.json local_time_zone.
type localTimeZone struct {
	Note  string     `json:"note"`
	Spans []zoneSpan `json:"spans"`
}

const (
	maxZoneSpans = 2000
	// zoneMargin widens the stretch the recorded zone covers beyond the times of the records,
	// for times a record names (an incident's start, a gateway's boot) that lie before it.
	zoneMargin = 400 * 24 * time.Hour
)

const zoneNote = "The local time zone of the computer that exported this bundle, over the times the report can show: " +
	"REPORT.html and README.txt show local times with it (UTC is shown next to them); report verification renders " +
	"them with this record, not with the verifying computer's zone."

// zoneSpans lists the zone of loc from lo to hi (at least one span).
func zoneSpans(loc *time.Location, lo, hi time.Time) []zoneSpan {
	t := lo.Truncate(time.Second)
	var out []zoneSpan
	for n := 0; len(out) < maxZoneSpans && n < 4*maxZoneSpans; n++ {
		lt := t.In(loc)
		name, off := lt.Zone()
		s := zoneSpan{From: t.UTC().Format(time.RFC3339), Abbrev: name, Offset: off, DST: lt.IsDST()}
		// Zones computed from a rule are bounded by years: merge the pieces of one span.
		if k := len(out) - 1; k < 0 || out[k].Abbrev != s.Abbrev || out[k].Offset != s.Offset || out[k].DST != s.DST {
			out = append(out, s)
		}
		_, end := lt.ZoneBounds()
		if end.IsZero() || !end.After(t) || !end.Before(hi) {
			break
		}
		t = end
	}
	return out
}

// zoneRange is the stretch of time a report's zone record covers: the period, the export time
// and the records of the bundle, widened by zoneMargin, within the years the exporter handles.
func zoneRange(times ...time.Time) (lo, hi time.Time) {
	for _, t := range times {
		if t.IsZero() || !plausibleTime(t) {
			continue
		}
		if lo.IsZero() || t.Before(lo) {
			lo = t
		}
		if hi.IsZero() || t.After(hi) {
			hi = t
		}
	}
	if lo.IsZero() {
		lo, hi = minPeriodTime, minPeriodTime
	}
	lo, hi = lo.Add(-zoneMargin), hi.Add(zoneMargin)
	return maxTime(lo, minPeriodTime), minTime(hi, maxPeriodTime.Add(-time.Second))
}

var errZone = errors.New("local_time_zone is not a usable time zone record")

// zoneLocation builds the location a report renders local times with from its zone record.
func zoneLocation(spans []zoneSpan) (*time.Location, error) {
	data, err := tzif(spans)
	if err != nil {
		return nil, err
	}
	loc, err := time.LoadLocationFromTZData("Local", data)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errZone, err)
	}
	return loc, nil
}

// tzif encodes zone spans as TZif version 2 data (RFC 8536), the format time.LoadLocationFromTZData
// reads: one transition at the start of every span (the first span also applies before it).
func tzif(spans []zoneSpan) ([]byte, error) {
	if len(spans) == 0 || len(spans) > maxZoneSpans {
		return nil, fmt.Errorf("%w: %d spans", errZone, len(spans))
	}
	type ttype struct {
		off  int32
		dst  bool
		abbr string
	}
	var (
		types   []ttype
		typeIdx = map[ttype]int{}
		chars   []byte
		charIdx = map[string]int{}
		times   []int64
		txTypes []byte
	)
	var prev int64
	for i, s := range spans {
		t, err := time.Parse(time.RFC3339, s.From)
		if err != nil || !plausibleTime(t) {
			return nil, fmt.Errorf("%w: span %d starts at %q", errZone, i, s.From)
		}
		if i > 0 && t.Unix() <= prev {
			return nil, fmt.Errorf("%w: span %d does not start after span %d", errZone, i, i-1)
		}
		prev = t.Unix()
		// An empty abbreviation is allowed: the zone's times are then shown with their offset.
		if s.Offset <= -26*3600 || s.Offset >= 26*3600 || len(s.Abbrev) > 16 {
			return nil, fmt.Errorf("%w: span %d (offset %d s, abbreviation %q)", errZone, i, s.Offset, truncate(s.Abbrev, 20))
		}
		for j := 0; j < len(s.Abbrev); j++ {
			if c := s.Abbrev[j]; c <= ' ' || c > '~' {
				return nil, fmt.Errorf("%w: span %d abbreviation %q", errZone, i, truncate(s.Abbrev, 20))
			}
		}
		tt := ttype{int32(s.Offset), s.DST, s.Abbrev}
		k, ok := typeIdx[tt]
		if !ok {
			if _, ok := charIdx[s.Abbrev]; !ok {
				charIdx[s.Abbrev] = len(chars)
				chars = append(append(chars, s.Abbrev...), 0)
			}
			if len(types) == 255 || len(chars) > 255 {
				return nil, fmt.Errorf("%w: too many distinct zones", errZone)
			}
			k = len(types)
			typeIdx[tt] = k
			types = append(types, tt)
		}
		times = append(times, t.Unix())
		txTypes = append(txTypes, byte(k))
	}
	var b bytes.Buffer
	header := func(timecnt, typecnt, charcnt int) {
		b.WriteString("TZif2")
		b.Write(make([]byte, 15))
		// UT/local indicators, standard/wall indicators, leap seconds, transitions, types, characters.
		for _, n := range []int{0, 0, 0, timecnt, typecnt, charcnt} {
			binary.Write(&b, binary.BigEndian, uint32(n))
		}
	}
	// A minimal version 1 block (readers of version 2 skip it), then the 64-bit data.
	header(0, 1, 4)
	b.Write([]byte{0, 0, 0, 0, 0, 0})
	b.WriteString("UTC\x00")
	header(len(times), len(types), len(chars))
	for _, t := range times {
		binary.Write(&b, binary.BigEndian, t)
	}
	b.Write(txTypes)
	for _, tt := range types {
		binary.Write(&b, binary.BigEndian, tt.off)
		dst := byte(0)
		if tt.dst {
			dst = 1
		}
		b.WriteByte(dst)
		b.WriteByte(byte(charIdx[tt.abbr]))
	}
	b.Write(chars)
	return b.Bytes(), nil
}

// fmtLocalIn renders an RFC 3339 time in loc with its zone abbreviation.
func fmtLocalIn(loc *time.Location, s string) string {
	t, ok := parseTS(s)
	if !ok {
		return s
	}
	return t.In(loc).Format("2006-01-02 15:04:05 MST")
}

// zoneLabel describes the zone of loc at t, e.g. "PDT (UTC-07:00)".
func zoneLabel(loc *time.Location, t time.Time) string {
	name, off := t.In(loc).Zone()
	sign := '+'
	if off < 0 {
		sign, off = '-', -off
	}
	return fmt.Sprintf("%s (UTC%c%02d:%02d)", name, sign, off/3600, (off%3600)/60)
}
