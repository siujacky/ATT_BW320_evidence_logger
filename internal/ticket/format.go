package ticket

import (
	"fmt"
	"math/bits"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// Formatting helpers. Values in tenths (0.1 dBm) are rendered exactly from integers;
// percentages are truncated, never rounded up ("100%" only for the whole); durations are whole
// seconds, truncated.

// absU returns |v| as an unsigned value (correct for math.MinInt64).
func absU(v int64) uint64 {
	if v < 0 {
		return -uint64(v)
	}
	return uint64(v)
}

// fmtX10 renders a value in tenths as a decimal: -315 -> "-31.5".
func fmtX10(v int64) string {
	u := absU(v)
	s := strconv.FormatUint(u/10, 10) + "." + strconv.FormatUint(u%10, 10)
	if v < 0 {
		return "-" + s
	}
	return s
}

// fmtSignedX10 renders tenths with an explicit sign: 95 -> "+9.5", -95 -> "-9.5".
func fmtSignedX10(v int64) string {
	if v > 0 {
		return "+" + fmtX10(v)
	}
	return fmtX10(v)
}

// fmtDBm renders tenths of a dBm: -315 -> "-31.5 dBm".
func fmtDBm(v int64) string { return fmtX10(v) + " dBm" }

// fmtDBmP is fmtDBm for an optional value ("n/a" when nil).
func fmtDBmP(v *int64) string {
	if v == nil {
		return "n/a"
	}
	return fmtDBm(*v)
}

// fmtDur renders whole seconds as "45 s", "3 min 05 s", "2 h 03 min" or "3 d 04 h".
func fmtDur(sec int64) string {
	if sec < 0 {
		sec = 0
	}
	d, h, m, s := sec/86400, (sec%86400)/3600, (sec%3600)/60, sec%60
	switch {
	case d > 0:
		return fmt.Sprintf("%d d %02d h", d, h)
	case h > 0:
		return fmt.Sprintf("%d h %02d min", h, m)
	case m > 0:
		return fmt.Sprintf("%d min %02d s", m, s)
	}
	return fmt.Sprintf("%d s", s)
}

// fmtHours renders a monitored time compactly and never overstates it: "5.4 h" (truncated to
// a tenth of an hour), "42 min" below an hour, "less than 1 min" below a minute.
func fmtHours(sec int64) string {
	switch {
	case sec <= 0:
		return "0 h"
	case sec < 60:
		return "less than 1 min"
	case sec < 3600:
		return fmt.Sprintf("%d min", sec/60)
	}
	tenths := sec * 10 / 3600
	return fmt.Sprintf("%d.%d h", tenths/10, tenths%10)
}

// fmtWindowHours renders a window length: "24 h", "36.5 h".
func fmtWindowHours(d time.Duration) string {
	sec := int64(d / time.Second)
	if sec%3600 == 0 {
		return fmt.Sprintf("%d h", sec/3600)
	}
	return fmtHours(sec)
}

// floorRatio returns floor(num * scale / den) for num < den without overflow.
func floorRatio(num, den, scale uint64) uint64 {
	if den == 0 || num >= den {
		return scale
	}
	hi, lo := bits.Mul64(num, scale)
	q, _ := bits.Div64(hi, lo, den) // hi < den because num < den
	return q
}

// fmtShare renders n of d as a percentage truncated to 2 decimals: "100%" only when n == d,
// "< 0.01%" for a share too small for 2 decimals (never "0.00%" for a non-zero share).
func fmtShare(n, d int64) string {
	if d <= 0 || n < 0 {
		return "n/a"
	}
	if n >= d {
		return "100%"
	}
	if n == 0 {
		return "0%"
	}
	bp := floorRatio(uint64(n), uint64(d), 10000)
	if bp == 0 {
		return "< 0.01%"
	}
	if bp%100 == 0 {
		return fmt.Sprintf("%d%%", bp/100)
	}
	return fmt.Sprintf("%d.%02d%%", bp/100, bp%100)
}

// fmtInt renders an integer with thousands separators.
func fmtInt(n int64) string {
	s := strconv.FormatUint(absU(n), 10)
	var b strings.Builder
	if n < 0 {
		b.WriteByte('-')
	}
	for i := 0; i < len(s); i++ {
		if i > 0 && (len(s)-i)%3 == 0 {
			b.WriteByte(',')
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// plural renders a count with the right noun: "1 reading", "3 readings".
func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmtInt(int64(n)) + " " + many
}

// fmtMs renders microseconds as milliseconds with one decimal: 2605 -> "2.6 ms".
func fmtMs(us int64) string {
	if us < 0 {
		us = 0
	}
	tenths := (us + 50) / 100
	return fmt.Sprintf("%d.%d ms", tenths/10, tenths%10)
}

// groupFingerprint renders a hex fingerprint as groups of 4 ("abcd ef01 ...").
func groupFingerprint(fp string) string {
	var parts []string
	for i := 0; i < len(fp); i += 4 {
		parts = append(parts, fp[i:min(i+4, len(fp))])
	}
	return strings.Join(parts, " ")
}

// shortHash shortens a long hex digest for running text: "402f3917...8280".
func shortHash(h string) string {
	if len(h) <= 16 {
		return h
	}
	return h[:8] + "..." + h[len(h)-4:]
}

// truncate cuts s to at most n runes, marking the cut with "...". Invalid UTF-8 is replaced.
func truncate(s string, n int) string {
	s = strings.ToValidUTF8(s, "�")
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)
	return string(r[:max(n-3, 0)]) + "..."
}

// oneLine collapses all whitespace runs (including line breaks) into single spaces.
func oneLine(s string) string { return strings.Join(strings.Fields(s), " ") }

// noun returns the singular or plural noun for a count, without the count: "is"/"are" style.
func noun(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// joinAndMore joins at most max parts like joinAnd and counts the rest: "a, b, c and 13 more".
func joinAndMore(parts []string, max int) string {
	if len(parts) <= max {
		return joinAnd(parts)
	}
	shown := append(parts[:max:max], fmt.Sprintf("%d more", len(parts)-max))
	return joinAnd(shown)
}

// ---------------------------------------------------------------- line breaking

// seg is a run of report text for the HTML page. A run with N set is printed on one line:
// browsers break lines after the hyphens of "2026-10-05", "UTC-05:00", "INC-20261005-130457Z"
// or "Wi-Fi" and between a number and its unit, and PDF readers then join the two halves
// without the hyphen when the text is copied or searched ("UTC05:00" reads like the opposite
// sign). Keeping such values whole avoids both; the text itself is unchanged (no special
// space or hyphen characters), so copying and searching find the ordinary characters.
type seg struct {
	T string // the text
	N bool   // keep on one line
	// A: a long value with a hyphen, wrapped where the line is full rather than after its hyphen
	// (a PDF reader drops a line-final hyphen when the text is copied: "ACCT-|123" -> "ACCT123").
	A bool
}

// maxNoWrap bounds a run kept on one line, so no value can be wider than a table column.
const maxNoWrap = 32

// noWrapRE matches the values that must not be split, earliest alternative first: date-times
// with their zone, times with a zone, UTC offsets, incident ids, two-part durations, number
// ranges and number-unit pairs, and hyphenated words.
var noWrapRE = regexp.MustCompile(
	`\d{4}-\d{2}-\d{2}(?:[ T]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:Z| UTC[+-]\d{2}:\d{2}| [A-Z]{2,5}\b)?)?` +
		`|\b\d{2}:\d{2}(?::\d{2})? (?:UTC[+-]\d{2}:\d{2}|[A-Z]{2,5}\b)` +
		`|\bUTC[+-]\d{2}:\d{2}` +
		`|\bINC-\d{8}-\d{6}Z` +
		`|\b\d+ (?:d \d{2} h|h \d{2} min|min \d{2} s)\b` +
		`|\b\d+(?:\.\d+)?-\d+(?:\.\d+)?(?:%| ?(?:dBm|dB|ms|min|s|h|d)\b)?` +
		`|-?\b\d[\d,]*(?:\.\d+)? (?:dBm|dB|ms|min|s|h|d|°C|Mb/s|GHz|MHz|nm|mA)\b` +
		`|\b[A-Za-z][A-Za-z0-9_.]*(?:-[A-Za-z0-9_.]+)+`)

// longHyphenRE matches a run without spaces, longer than maxNoWrap, with a hyphen.
var longHyphenRE = regexp.MustCompile(`[^\s]*-[^\s]*`)

// segs splits s into runs for the page: the values noWrapRE matches (when they could be split
// at all, and are at most maxNoWrap bytes long) are kept on one line; longer runs with a hyphen
// are wrapped where the line is full.
func segs(s string) []seg {
	var out []seg
	plain := func(t string) {
		last := 0
		for _, m := range longHyphenRE.FindAllStringIndex(t, -1) {
			if m[1]-m[0] <= maxNoWrap {
				continue
			}
			if m[0] > last {
				out = append(out, seg{T: t[last:m[0]]})
			}
			out = append(out, seg{T: t[m[0]:m[1]], A: true})
			last = m[1]
		}
		if last < len(t) {
			out = append(out, seg{T: t[last:]})
		}
	}
	last := 0
	for _, m := range noWrapRE.FindAllStringIndex(s, -1) {
		v := s[m[0]:m[1]]
		if len(v) > maxNoWrap || !strings.ContainsAny(v, " -") {
			continue
		}
		if m[0] > last {
			plain(s[last:m[0]])
		}
		out = append(out, seg{T: v, N: true})
		last = m[1]
	}
	if last < len(s) {
		plain(s[last:])
	}
	return out
}

// orNA returns s, or "n/a" when it is blank.
func orNA(s string) string {
	if strings.TrimSpace(s) == "" {
		return "n/a"
	}
	return s
}

// seqRef renders a record reference: "#123".
func seqRef(seq uint64) string { return "#" + strconv.FormatUint(seq, 10) }

// fmtSeqList renders up to max seqs as "#1, #5, #9" with a count of the rest.
func fmtSeqList(seqs []uint64, max int) string {
	var parts []string
	for i, s := range seqs {
		if i == max {
			parts = append(parts, fmt.Sprintf("and %d more", len(seqs)-max))
			break
		}
		parts = append(parts, seqRef(s))
	}
	return strings.Join(parts, ", ")
}

// ---------------------------------------------------------------- times

const (
	layoutSec = "2006-01-02 15:04:05"
	layoutMin = "2006-01-02 15:04"
)

// parseTS parses a record time (RFC 3339, optional fraction).
func parseTS(s string) (time.Time, bool) {
	t, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(s))
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}

// zoneName is the abbreviation of loc at t, or its UTC offset when the zone has no usable
// abbreviation ("UTC-05:00").
func zoneName(loc *time.Location, t time.Time) string {
	name, off := t.In(loc).Zone()
	if name != "" && !strings.ContainsAny(name, "+-0123456789") {
		return name
	}
	return fmtOffset(time.Duration(off) * time.Second)
}

// fmtOffset renders a UTC offset: "UTC-05:00", "UTC+05:30", "UTC".
func fmtOffset(d time.Duration) string {
	if d == 0 {
		return "UTC"
	}
	sign := '+'
	if d < 0 {
		sign, d = '-', -d
	}
	m := int64(d / time.Minute)
	return fmt.Sprintf("UTC%c%02d:%02d", sign, m/60, m%60)
}

// zoneLabel describes the zone of loc at t: "CDT (UTC-05:00)".
func zoneLabel(loc *time.Location, t time.Time) string {
	_, off := t.In(loc).Zone()
	o := fmtOffset(time.Duration(off) * time.Second)
	if n := zoneName(loc, t); n != o {
		return n + " (" + o + ")"
	}
	return o
}

// isUTC reports whether loc shows t as UTC itself (the UTC time then need not be repeated).
func isUTC(loc *time.Location, t time.Time) bool {
	name, off := t.In(loc).Zone()
	return off == 0 && (name == "UTC" || name == "")
}

// fmtLocal renders t in loc with seconds and the zone: "2026-10-05 07:46:49 CDT".
func fmtLocal(t time.Time, loc *time.Location) string {
	return t.In(loc).Format(layoutSec) + " " + zoneName(loc, t)
}

// fmtUTC renders t in UTC with seconds: "2026-10-05 12:46:49 UTC".
func fmtUTC(t time.Time) string { return t.UTC().Format(layoutSec) + " UTC" }

// fmtBoth renders t in loc and in UTC, the UTC date only when it differs:
// "2026-10-05 07:46:49 CDT (12:46:49 UTC)".
func fmtBoth(t time.Time, loc *time.Location) string {
	if isUTC(loc, t) {
		return fmtUTC(t)
	}
	lt, ut := t.In(loc), t.UTC()
	u := ut.Format("15:04:05")
	if lt.Format("2006-01-02") != ut.Format("2006-01-02") {
		u = ut.Format(layoutSec)
	}
	return fmtLocal(t, loc) + " (" + u + " UTC)"
}

// fmtBothMin is fmtBoth to the minute: "2026-10-05 07:46 CDT (12:46 UTC)".
func fmtBothMin(t time.Time, loc *time.Location) string {
	if isUTC(loc, t) {
		return t.UTC().Format(layoutMin) + " UTC"
	}
	lt, ut := t.In(loc), t.UTC()
	u := ut.Format("15:04")
	if lt.Format("2006-01-02") != ut.Format("2006-01-02") {
		u = ut.Format(layoutMin)
	}
	return lt.Format(layoutMin) + " " + zoneName(loc, t) + " (" + u + " UTC)"
}
