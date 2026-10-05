package gateway

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// cp1252High maps windows-1252 bytes 0x80-0x9F to Unicode. Bytes that windows-1252 leaves
// undefined (0x81, 0x8D, 0x8F, 0x90, 0x9D) map to the C1 control with the same value, as in
// the WHATWG encoding standard. Bytes 0xA0-0xFF are identical to Latin-1 (U+00A0-U+00FF).
var cp1252High = [32]rune{
	0x20AC, 0x0081, 0x201A, 0x0192, 0x201E, 0x2026, 0x2020, 0x2021,
	0x02C6, 0x2030, 0x0160, 0x2039, 0x0152, 0x008D, 0x017D, 0x008F,
	0x0090, 0x2018, 0x2019, 0x201C, 0x201D, 0x2022, 0x2013, 0x2014,
	0x02DC, 0x2122, 0x0161, 0x203A, 0x0153, 0x009D, 0x017E, 0x0178,
}

// decode converts a gateway response body to a valid UTF-8 string for parsing.
//
// The firmware declares charset=windows-1252 and emits raw single bytes such as 0xA9 (©)
// and 0xA0 (no-break space), while transcribed copies and possible future firmware may be
// UTF-8. Valid UTF-8 sequences are therefore kept as they are and every byte that is not part
// of a valid sequence is decoded as windows-1252. The result is only used for parsing: the
// exact bytes remain the evidence.
func decode(b []byte) string {
	if utf8.Valid(b) {
		return string(b)
	}
	var sb strings.Builder
	sb.Grow(len(b) + len(b)/8)
	for len(b) > 0 {
		r, size := utf8.DecodeRune(b)
		if r == utf8.RuneError && size == 1 {
			c := b[0]
			if c >= 0x80 && c <= 0x9F {
				r = cp1252High[c-0x80]
			} else {
				r = rune(c) // Latin-1 range 0xA0-0xFF (0x00-0x7F is always valid UTF-8)
			}
		}
		sb.WriteRune(r)
		b = b[size:]
	}
	return sb.String()
}

// isSpaceRune reports whether r separates words in gateway text. Besides Unicode white space
// (which includes U+00A0 NO-BREAK SPACE, produced by &nbsp;) it treats as space:
//   - U+FFFD, the replacement character that lossy UTF-8 transcriptions put where the
//     firmware emitted a raw 0xA0/0xA9 byte (it carries no information);
//   - zero-width spaces and the byte-order mark.
func isSpaceRune(r rune) bool {
	switch r {
	case utf8.RuneError, 0x200B, 0x2060, 0xFEFF: // U+FFFD, zero-width space, word joiner, BOM
		return true
	}
	return unicode.IsSpace(r)
}

// normSpace collapses every run of space-like runes (see isSpaceRune) into one ASCII space
// and trims both ends. It makes parsing independent of CRLF/LF, indentation, &nbsp; and
// U+FFFD artifacts.
func normSpace(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	pending := false
	for _, r := range s {
		if isSpaceRune(r) {
			pending = true
			continue
		}
		if pending && b.Len() > 0 {
			b.WriteByte(' ')
		}
		pending = false
		b.WriteRune(r)
	}
	return b.String()
}

// normLabel normalizes a row label: collapsed spaces, trailing colon removed
// ("Secondary DNS Name&nbsp;" -> "Secondary DNS Name", "Status:" -> "Status").
func normLabel(s string) string {
	s = normSpace(s)
	for strings.HasSuffix(s, ":") {
		s = strings.TrimSpace(strings.TrimSuffix(s, ":"))
	}
	return s
}

// alnumKey lower-cases s and drops everything except letters and digits, so that
// "Tx Bias", "Tx  Bias", "TX-BIAS" and "TxBias" all compare equal ("txbias").
func alnumKey(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}
