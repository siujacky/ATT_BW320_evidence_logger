package export

import (
	"fmt"
	"math"
	"math/bits"
	"strconv"
	"strings"
)

// Formatting helpers shared by REPORT.html, README.txt and keys/public-key.txt. Local times
// use the exporting computer's zone as the report records it (zone.go: fmtLocalIn) and always
// carry the zone abbreviation; UTC is shown next to them.

func fmtUTC(s string) string {
	t, ok := parseTS(s)
	if !ok {
		return s
	}
	return t.UTC().Format("2006-01-02 15:04:05") + " UTC"
}

// fmtDur renders whole seconds as "45s", "3m 05s", "2h 03m 05s" or "3d 04h 05m".
func fmtDur(sec int64) string {
	if sec < 0 {
		sec = 0
	}
	d, h, m, s := sec/86400, (sec%86400)/3600, (sec%3600)/60, sec%60
	switch {
	case d > 0:
		return fmt.Sprintf("%dd %02dh %02dm", d, h, m)
	case h > 0:
		return fmt.Sprintf("%dh %02dm %02ds", h, m, s)
	case m > 0:
		return fmt.Sprintf("%dm %02ds", m, s)
	}
	return fmt.Sprintf("%ds", s)
}

// absU returns |v| as an unsigned value (correct for math.MinInt64, unlike -v).
func absU(v int64) uint64 {
	if v < 0 {
		return -uint64(v)
	}
	return uint64(v)
}

// fmtX10 renders a value in tenths (e.g. 0.1 dBm) as a decimal: -315 -> "-31.5".
func fmtX10(v int64) string {
	u := absU(v)
	s := strconv.FormatUint(u/10, 10) + "." + strconv.FormatUint(u%10, 10)
	if v < 0 {
		return "-" + s
	}
	return s
}

func fmtX10p(v *int64) string {
	if v == nil {
		return "n/a"
	}
	return fmtX10(*v)
}

// fmtPct renders a percentage the way the dashboard does (internal/web/static/app.js fmtPct):
// truncated to 2 decimals, never rounded up - 99.996 % reads "99.99%", never "100.00%" - with
// "100%" only for 100 itself and "< 0.01%" for a share too small for 2 decimals, never "0.00%"
// (a short outage is not no outage).
func fmtPct(f float64) string {
	switch {
	case math.IsNaN(f) || math.IsInf(f, 0):
		return "n/a"
	case f >= 100:
		return "100%"
	case f <= 0:
		return "0.00%"
	case f < 0.01:
		return "< 0.01%"
	}
	// The shortest decimal representation of f, cut (not rounded) after 2 decimals.
	ip, frac, _ := strings.Cut(strconv.FormatFloat(f, 'f', -1, 64), ".")
	return ip + "." + (frac + "00")[:2] + "%"
}

func fmtPctp(f *float64) string {
	if f == nil {
		return "n/a"
	}
	return fmtPct(*f)
}

// fmtShare renders n of d as a percentage with the rules of fmtPct, computed exactly in
// integers: "100%" only when n == d, "< 0.01%" for 0 < n/d < 0.0001.
func fmtShare(n, d int) string {
	if d <= 0 || n < 0 {
		return "n/a"
	}
	if n >= d {
		return "100%"
	}
	bp := floorRatio(uint64(n), uint64(d), 10000) // basis points, truncated
	if n > 0 && bp == 0 {
		return "< 0.01%"
	}
	return fmt.Sprintf("%d.%02d%%", bp/100, bp%100)
}

// floorPct3 returns 100 × num / den truncated to 3 decimals, computed exactly (128-bit
// integers): it is 100 only when num >= den and never rounds a shortfall away.
func floorPct3(num, den uint64) float64 {
	switch {
	case den == 0:
		return 0
	case num >= den:
		return 100
	}
	return float64(floorRatio(num, den, 100000)) / 1000
}

// floorRatio returns floor(num × scale / den) for num < den without overflow.
func floorRatio(num, den, scale uint64) uint64 {
	if den == 0 || num >= den {
		return scale
	}
	hi, lo := bits.Mul64(num, scale)
	q, _ := bits.Div64(hi, lo, den) // hi < den because num < den
	return q
}

// fmtInt renders an integer (or a pointer to one; nil = "n/a") with thousands separators.
func fmtInt(v any) string {
	var n int64
	switch x := v.(type) {
	case int:
		n = int64(x)
	case int64:
		n = x
	case uint64:
		if x > 1<<62 {
			return strconv.FormatUint(x, 10)
		}
		n = int64(x)
	case *int:
		if x == nil {
			return "n/a"
		}
		return fmtInt(*x)
	case *int64:
		if x == nil {
			return "n/a"
		}
		return fmtInt(*x)
	case *uint64:
		if x == nil {
			return "n/a"
		}
		return fmtInt(*x)
	default:
		return fmt.Sprint(v)
	}
	neg := n < 0
	s := strconv.FormatUint(absU(n), 10)
	var b strings.Builder
	for i, r := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			b.WriteByte(',')
		}
		b.WriteRune(r)
	}
	if neg {
		return "-" + b.String()
	}
	return b.String()
}

// plural renders a count with the right noun form: "1 incident", "3 incidents".
func plural(n any, one, many string) string {
	word := many
	switch x := n.(type) {
	case int:
		if x == 1 {
			word = one
		}
	case int64:
		if x == 1 {
			word = one
		}
	case uint64:
		if x == 1 {
			word = one
		}
	}
	return fmtInt(n) + " " + word
}

// groupFingerprint renders a hex fingerprint as groups of 4 ("abcd ef01 ...").
func groupFingerprint(fp string) string {
	var parts []string
	for i := 0; i < len(fp); i += 4 {
		parts = append(parts, fp[i:min(i+4, len(fp))])
	}
	return strings.Join(parts, " ")
}

// fmtSeqs compresses a sorted list of seqs into ranges: "12-15, 19, 30-31".
func fmtSeqs(seqs []uint64) string {
	if len(seqs) == 0 {
		return ""
	}
	var parts []string
	start, prev := seqs[0], seqs[0]
	emit := func() {
		if start == prev {
			parts = append(parts, strconv.FormatUint(start, 10))
		} else {
			parts = append(parts, strconv.FormatUint(start, 10)+"-"+strconv.FormatUint(prev, 10))
		}
	}
	for _, s := range seqs[1:] {
		if s == prev+1 {
			prev = s
			continue
		}
		emit()
		start, prev = s, s
	}
	emit()
	if len(parts) > 12 {
		return strings.Join(parts[:12], ", ") + fmt.Sprintf(", ... (%d seqs in report.json)", len(seqs))
	}
	return strings.Join(parts, ", ")
}
