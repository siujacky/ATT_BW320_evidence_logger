package syslogrx

import (
	"encoding/base64"
	"strconv"
	"strings"
	"unicode/utf8"

	"attmonitor/internal/model"
)

// Values of model.SyslogMessage.Format.
const (
	FormatRFC5424 = "rfc5424"
	FormatRFC3164 = "rfc3164"
	FormatUnknown = "unknown"
)

const (
	maxPRI = 191 // facility 23 (local7) × 8 + severity 7 (debug)
	// maxTag bounds a TAG (RFC 3164 allows 32 characters, RFC 5424's APP-NAME 48): a longer
	// word followed by a colon is part of the message.
	maxTag = 48
	// maxPID bounds the "[PID]" after a TAG (RFC 5424's PROCID has at most 128 characters).
	maxPID = 128
	bom    = "\xef\xbb\xbf" // U+FEFF in UTF-8: the byte-order mark RFC 5424 allows before MSG
)

// months are the month names of RFC 3164 timestamps (matched without regard to case).
var months = [...]string{"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"}

// Parse describes the syslog datagram b (the formats are listed in the package comment). Raw is
// b when it is valid UTF-8, RawB64 (standard base64) otherwise: the exact bytes, never trimmed
// or rewritten. The parsed fields are a convenience taken from them; in a datagram that is not
// valid UTF-8 they show U+FFFD in place of the invalid bytes. A Msg that would be exactly Raw (a
// datagram without a PRI) is left empty: Raw holds it, and the message is not stored twice.
// RX and Src are left for the caller. Parse never panics.
func Parse(b []byte) model.SyslogMessage {
	m, text := rawMessage(b)
	text = strings.TrimRight(text, "\r\n\x00")
	pri, rest, ok := cutPRI(text)
	if !ok {
		if text != m.Raw {
			m.Msg = text
		}
		return m
	}
	facility, severity := pri/8, pri%8
	m.PRI, m.Facility, m.Severity = &pri, &facility, &severity
	if !parse5424(&m, rest) && !parse3164(&m, rest) {
		m.Msg = rest
	}
	return m
}

// rawMessage returns a message that holds only b's exact bytes (Format "unknown"), and b as
// text with every invalid UTF-8 sequence replaced by U+FFFD.
func rawMessage(b []byte) (model.SyslogMessage, string) {
	m := model.SyslogMessage{Format: FormatUnknown}
	text := string(b)
	if utf8.Valid(b) {
		m.Raw = text
	} else {
		m.RawB64 = base64.StdEncoding.EncodeToString(b)
		text = strings.ToValidUTF8(text, string(utf8.RuneError))
	}
	return m, text
}

// cutPRI splits "<N>" off the start of s, N being 1 to 3 digits with a value from 0 to 191.
func cutPRI(s string) (pri int, rest string, ok bool) {
	if len(s) < 3 || s[0] != '<' {
		return 0, "", false
	}
	n := digits(s[1:], 3)
	if n == 0 || 1+n >= len(s) || s[1+n] != '>' {
		return 0, "", false
	}
	pri, _ = strconv.Atoi(s[1 : 1+n]) // at most three ASCII digits
	if pri > maxPRI {
		return 0, "", false
	}
	return pri, s[2+n:], true
}

// parse5424 parses what follows the PRI of an RFC 5424 message: VERSION SP TIMESTAMP SP
// HOSTNAME SP APP-NAME SP PROCID SP MSGID SP STRUCTURED-DATA [SP MSG]. TIMESTAMP must be "-" or
// an ISO 8601 date and time; the other header fields may be any words. It sets the fields only
// when the whole header is there.
func parse5424(m *model.SyslogMessage, s string) bool {
	v := digits(s, 3) // VERSION: 1 to 3 digits, the first not 0 (only 1 is defined)
	if v == 0 || s[0] == '0' || v >= len(s) || s[v] != ' ' {
		return false
	}
	s = s[v+1:]
	var hdr [5]string // TIMESTAMP HOSTNAME APP-NAME PROCID MSGID
	for i := range hdr {
		word, rest, ok := strings.Cut(s, " ")
		if !ok || word == "" {
			return false
		}
		hdr[i], s = word, rest
	}
	if hdr[0] != "-" && isoTimeLen(hdr[0], false) != len(hdr[0]) {
		return false
	}
	n := sdLen(s)
	if n < 0 {
		return false
	}
	msg := s[n:]
	if msg != "" {
		msg = strings.TrimPrefix(msg[1:], bom) // sdLen checked that a space follows
	}
	m.Format = FormatRFC5424
	m.TS, m.Host, m.App = nilValue(hdr[0]), nilValue(hdr[1]), nilValue(hdr[2])
	m.Msg = msg
	return true
}

// nilValue maps RFC 5424's NILVALUE "-" to "".
func nilValue(s string) string {
	if s == "-" {
		return ""
	}
	return s
}

// sdLen returns the length of the STRUCTURED-DATA at the start of s: "-", or one or more
// [SD-ID PARAM="VALUE" ...] elements in which a backslash escapes the next character of a
// value. It is -1 when there is none, or when it is followed by something other than a space.
func sdLen(s string) int {
	n := 0
	if strings.HasPrefix(s, "-") {
		n = 1
	} else {
		for n < len(s) && s[n] == '[' {
			e := sdElementLen(s[n:])
			if e < 0 {
				return -1
			}
			n += e
		}
		if n == 0 {
			return -1
		}
	}
	if n < len(s) && s[n] != ' ' {
		return -1
	}
	return n
}

// sdElementLen returns the length of the SD-ELEMENT that s starts with (s[0] is '['), or -1
// when it does not end.
func sdElementLen(s string) int {
	quoted := false
	for i := 1; i < len(s); i++ {
		switch c := s[i]; {
		case quoted && c == '\\':
			i++
		case c == '"':
			quoted = !quoted
		case c == ']' && !quoted:
			return i + 1
		}
	}
	return -1
}

// parse3164 parses what follows the PRI of a BSD syslog message (RFC 3164): TIMESTAMP
// [SP HOSTNAME] [SP TAG["[" PID "]"] ":"] [SP MSG]. Some devices leave out the HOSTNAME: a
// first word that ends like a TAG ("name:" or "name[pid]:") is taken as the TAG.
func parse3164(m *model.SyslogMessage, s string) bool {
	n := bsdTimeLen(s)
	if n == 0 {
		n = isoTimeLen(s, true)
	}
	if n == 0 || (n < len(s) && s[n] != ' ') {
		return false
	}
	m.Format, m.TS = FormatRFC3164, s[:n]
	rest := ""
	if n < len(s) {
		rest = s[n+1:]
	}
	if tag, msg, ok := cutTag(rest); ok {
		m.App, m.Msg = tag, msg
		return true
	}
	host, after, ok := strings.Cut(rest, " ")
	if !ok || host == "" {
		m.Msg = rest // a single word, or text that starts with a space
		return true
	}
	m.Host = host
	if tag, msg, ok := cutTag(after); ok {
		m.App, m.Msg = tag, msg
	} else {
		m.Msg = after
	}
	return true
}

// cutTag splits "TAG: MSG" or "TAG[PID]: MSG" (the colon may also end s) into the TAG and the
// message. A TAG has 1 to maxTag bytes other than spaces, control characters, '[', ']' and ':'.
func cutTag(s string) (tag, msg string, ok bool) {
	i := 0
	for i < len(s) && i <= maxTag && isTagByte(s[i]) {
		i++
	}
	if i == 0 || i > maxTag {
		return "", "", false
	}
	j := i
	if j < len(s) && s[j] == '[' {
		end := strings.IndexByte(s[j:], ']')
		if end < 0 || end-1 > maxPID || strings.ContainsAny(s[j+1:j+end], " [") {
			return "", "", false
		}
		j += end + 1
	}
	if j >= len(s) || s[j] != ':' {
		return "", "", false
	}
	j++
	switch {
	case j == len(s):
	case s[j] == ' ':
		j++
	default:
		return "", "", false // "name:text" is no TAG (and keeps "fe80::1" a host name)
	}
	return s[:i], s[j:], true
}

func isTagByte(c byte) bool {
	return c > ' ' && c != 0x7f && c != '[' && c != ']' && c != ':'
}

// bsdTimeLen returns the length of the RFC 3164 timestamp that s starts with ("Mmm dd
// hh:mm:ss" with the day as "dd", " d" or "d"; some devices add a year before the time or a
// fraction of a second after it), or 0.
func bsdTimeLen(s string) int {
	if len(s) < 4 || !isMonth(s[:3]) || s[3] != ' ' {
		return 0
	}
	n := 4
	if n < len(s) && s[n] == ' ' {
		n++ // a day below 10, padded with a space
	}
	d := digits(s[n:], 2)
	if d == 0 || n+d >= len(s) || s[n+d] != ' ' {
		return 0
	}
	n += d + 1
	if digits(s[n:], 4) == 4 && n+4 < len(s) && s[n+4] == ' ' {
		n += 5 // a year
	}
	if !isClock(s[n:]) {
		return 0
	}
	n += 8
	return n + fractionLen(s[n:])
}

func isMonth(s string) bool {
	for _, m := range months {
		if strings.EqualFold(s, m) {
			return true
		}
	}
	return false
}

// isoTimeLen returns the length of the ISO 8601 date and time that s starts with
// (YYYY-MM-DDThh:mm:ss, an optional fraction of a second and an optional zone "Z", "±hh:mm" or
// "±hhmm"; with space set, a space may stand for the "T"), or 0.
func isoTimeLen(s string, space bool) int {
	if len(s) < 19 || digits(s, 4) != 4 || s[4] != '-' || digits(s[5:], 2) != 2 || s[7] != '-' ||
		digits(s[8:], 2) != 2 || !isClock(s[11:]) {
		return 0
	}
	switch s[10] {
	case 'T', 't':
	case ' ':
		if !space {
			return 0
		}
	default:
		return 0
	}
	n := 19 + fractionLen(s[19:])
	if n < len(s) {
		switch s[n] {
		case 'Z', 'z':
			n++
		case '+', '-':
			z := s[n+1:]
			switch {
			case len(z) >= 5 && digits(z, 2) == 2 && z[2] == ':' && digits(z[3:], 2) == 2:
				n += 6
			case digits(z, 4) == 4:
				n += 5
			}
		}
	}
	return n
}

// isClock reports whether s starts with hh:mm:ss (two digits each).
func isClock(s string) bool {
	return len(s) >= 8 && digits(s, 2) == 2 && s[2] == ':' && digits(s[3:], 2) == 2 && s[5] == ':' &&
		digits(s[6:], 2) == 2
}

// fractionLen returns the length of the fraction of a second (a dot and digits) that s starts
// with, or 0.
func fractionLen(s string) int {
	if len(s) < 2 || s[0] != '.' {
		return 0
	}
	if n := digits(s[1:], len(s)); n > 0 {
		return 1 + n
	}
	return 0
}

// digits returns how many ASCII digits s starts with, counting at most limit.
func digits(s string, limit int) int {
	n := 0
	for n < len(s) && n < limit && '0' <= s[n] && s[n] <= '9' {
		n++
	}
	return n
}
