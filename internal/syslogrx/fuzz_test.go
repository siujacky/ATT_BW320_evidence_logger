package syslogrx

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// FuzzParse checks that no datagram makes Parse panic, that the message keeps the exact bytes
// and that the parsed fields are consistent with them (datagrams are untrusted input). The seed
// corpus runs with every "go test"; fuzz with
// go test -run=^$ -fuzz=FuzzParse ./internal/syslogrx/
func FuzzParse(f *testing.F) {
	for _, c := range parseCases {
		f.Add([]byte(c.in))
	}
	f.Add([]byte("<13>1 - - - - - [a=\"\\"))
	f.Add([]byte("<13>Jan  1 00:00:00 x[" + strings.Repeat("9", maxPID+1) + "]: y"))
	f.Add([]byte("<7>9999-99-99T99:99:99.9999999999999+99:99 h t: m"))
	f.Add([]byte("<0>1 0000-00-00T00:00:00 0 ] 0 0 -")) // APP-NAME "]"
	f.Fuzz(func(t *testing.T, b []byte) {
		m := Parse(b)
		checkRaw(t, b, m)
		text := strings.TrimRight(strings.ToValidUTF8(string(b), replacement), "\r\n\x00")

		switch m.Format {
		case FormatRFC5424, FormatRFC3164:
			if m.PRI == nil {
				t.Fatalf("%s without PRI: %+v", m.Format, m)
			}
		case FormatUnknown:
			if m.TS != "" || m.Host != "" || m.App != "" {
				t.Fatalf("unknown format with header fields: %+v", m)
			}
		default:
			t.Fatalf("Format %q", m.Format)
		}
		if (m.PRI == nil) != (m.Facility == nil) || (m.PRI == nil) != (m.Severity == nil) {
			t.Fatalf("PRI, Facility, Severity set apart: %v %v %v", deref(m.PRI), deref(m.Facility), deref(m.Severity))
		}
		if m.PRI == nil {
			if m.Format != FormatUnknown || m.Msg != text {
				t.Fatalf("without PRI: Format %q, Msg %q, want the text %q", m.Format, m.Msg, text)
			}
		} else {
			if *m.PRI < 0 || *m.PRI > maxPRI || *m.Facility != *m.PRI/8 || *m.Severity != *m.PRI%8 {
				t.Fatalf("PRI %d, Facility %d, Severity %d", *m.PRI, *m.Facility, *m.Severity)
			}
			if !strings.HasPrefix(text, "<") {
				t.Fatalf("PRI %d from %q", *m.PRI, text)
			}
		}
		for _, s := range []string{m.TS, m.Host, m.App, m.Msg} {
			if !utf8.ValidString(s) {
				t.Fatalf("invalid UTF-8 in a parsed field: %+v", m)
			}
			if !strings.Contains(text, s) {
				t.Fatalf("parsed field %q is not part of the datagram %q", s, text)
			}
		}
		if !strings.HasSuffix(text, m.Msg) || strings.TrimRight(m.Msg, "\r\n\x00") != m.Msg {
			t.Fatalf("Msg %q is not the end of the text %q without line ends", m.Msg, text)
		}
		// An RFC 5424 APP-NAME is any printable word; an RFC 3164 TAG is narrower.
		if strings.Contains(m.Host, " ") || strings.Contains(m.App, " ") ||
			(m.Format == FormatRFC3164 && (strings.ContainsAny(m.App, "[]:") || len(m.App) > maxTag)) {
			t.Fatalf("%s: Host %q, App %q", m.Format, m.Host, m.App)
		}
		if m.RX != "" || m.Src != "" {
			t.Fatalf("RX %q, Src %q", m.RX, m.Src)
		}
	})
}
