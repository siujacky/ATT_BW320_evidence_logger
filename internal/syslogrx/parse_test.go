package syslogrx

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"

	"attmonitor/internal/model"
)

// replacement is U+FFFD in UTF-8: what an invalid byte sequence becomes in the parsed fields.
const replacement = "\xef\xbf\xbd"

// parseCase is a datagram and the fields Parse should find (pri -1: no PRI). Raw and RawB64
// are checked against the datagram itself (checkRaw).
type parseCase struct {
	name               string
	in                 string
	format             string
	pri                int
	ts, host, app, msg string
}

var parseCases = []parseCase{
	// RFC 3164 and the variants devices send.
	{"rfc3164 example", "<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8",
		FormatRFC3164, 34, "Oct 11 22:14:15", "mymachine", "su", "'su root' failed for lonvick on /dev/pts/8"},
	{"padded day, IP host, tag with pid, LF", "<13>Feb  5 17:32:18 10.0.0.99 myapp[123]: Use the BFG!\n",
		FormatRFC3164, 13, "Feb  5 17:32:18", "10.0.0.99", "myapp", "Use the BFG!"},
	{"no host, tag with pid", "<30>Oct  5 21:30:01 dnsmasq-dhcp[1234]: DHCPACK(br0) 192.168.1.64 aa:bb:cc:dd:ee:ff phone",
		FormatRFC3164, 30, "Oct  5 21:30:01", "", "dnsmasq-dhcp", "DHCPACK(br0) 192.168.1.64 aa:bb:cc:dd:ee:ff phone"},
	{"no host, tag", "<4>Oct  5 21:30:01 kernel: [12345.678] eth0: link up",
		FormatRFC3164, 4, "Oct  5 21:30:01", "", "kernel", "[12345.678] eth0: link up"},
	{"host, no tag", "<14>Oct  5 21:30:01 bgw320 PON link state changed to O5",
		FormatRFC3164, 14, "Oct  5 21:30:01", "bgw320", "", "PON link state changed to O5"},
	{"day without padding", "<14>Oct 5 21:30:01 host app: x", FormatRFC3164, 14, "Oct 5 21:30:01", "host", "app", "x"},
	{"zero-padded day", "<14>Oct 05 21:30:01 host app: x", FormatRFC3164, 14, "Oct 05 21:30:01", "host", "app", "x"},
	{"fraction of a second", "<14>Oct  5 21:30:01.123 host app: x", FormatRFC3164, 14, "Oct  5 21:30:01.123", "host", "app", "x"},
	{"year", "<14>Oct  5 2026 21:30:01 host app: x", FormatRFC3164, 14, "Oct  5 2026 21:30:01", "host", "app", "x"},
	{"lower-case month", "<14>oct  5 21:30:01 host app: x", FormatRFC3164, 14, "oct  5 21:30:01", "host", "app", "x"},
	{"ISO timestamp", "<14>2026-10-05T21:30:01Z host app[7]: x", FormatRFC3164, 14, "2026-10-05T21:30:01Z", "host", "app", "x"},
	{"ISO timestamp with fraction and offset", "<14>2026-10-05T21:30:01.123456-05:00 host app: x",
		FormatRFC3164, 14, "2026-10-05T21:30:01.123456-05:00", "host", "app", "x"},
	{"ISO offset without colon", "<14>2026-10-05T21:30:01+0200 host app: x", FormatRFC3164, 14, "2026-10-05T21:30:01+0200", "host", "app", "x"},
	{"ISO timestamp without zone", "<14>2026-10-05T21:30:01 host app: x", FormatRFC3164, 14, "2026-10-05T21:30:01", "host", "app", "x"},
	{"ISO timestamp with a space", "<14>2026-10-05 21:30:01 host app: x", FormatRFC3164, 14, "2026-10-05 21:30:01", "host", "app", "x"},
	{"ISO timestamp, no host", "<14>2026-10-05T21:30:01Z app: x", FormatRFC3164, 14, "2026-10-05T21:30:01Z", "", "app", "x"},
	{"tag ends the datagram", "<14>Oct  5 21:30:01 host app:", FormatRFC3164, 14, "Oct  5 21:30:01", "host", "app", ""},
	{"IPv6 host", "<14>Oct  5 21:30:01 fe80::1 app: x", FormatRFC3164, 14, "Oct  5 21:30:01", "fe80::1", "app", "x"},
	{"timestamp only", "<14>Oct  5 21:30:01", FormatRFC3164, 14, "Oct  5 21:30:01", "", "", ""},
	{"single word", "<14>Oct  5 21:30:01 reboot", FormatRFC3164, 14, "Oct  5 21:30:01", "", "", "reboot"},
	{"colon without a space is no tag", "<14>Oct  5 21:30:01 host kernel:eth0 up",
		FormatRFC3164, 14, "Oct  5 21:30:01", "host", "", "kernel:eth0 up"},
	{"tag too long", "<14>Oct  5 21:30:01 host " + strings.Repeat("a", maxTag+1) + ": x",
		FormatRFC3164, 14, "Oct  5 21:30:01", "host", "", strings.Repeat("a", maxTag+1) + ": x"},
	{"longest tag", "<14>Oct  5 21:30:01 host " + strings.Repeat("a", maxTag) + ": x",
		FormatRFC3164, 14, "Oct  5 21:30:01", "host", strings.Repeat("a", maxTag), "x"},
	{"pid with a space is no tag", "<14>Oct  5 21:30:01 host app[1 2]: x",
		FormatRFC3164, 14, "Oct  5 21:30:01", "host", "", "app[1 2]: x"},
	{"text after two spaces", "<14>Oct  5 21:30:01  x y", FormatRFC3164, 14, "Oct  5 21:30:01", "", "", " x y"},
	{"several lines, CR LF NUL at the end", "<13>Oct 11 22:14:15 host app: line1\nline2\r\n\x00",
		FormatRFC3164, 13, "Oct 11 22:14:15", "host", "app", "line1\nline2"},
	{"control characters are kept", "<13>Oct 11 22:14:15 host app: \x1b[31mred\x07",
		FormatRFC3164, 13, "Oct 11 22:14:15", "host", "app", "\x1b[31mred\x07"},
	{"NUL inside", "<13>Oct 11 22:14:15 host app: a\x00b", FormatRFC3164, 13, "Oct 11 22:14:15", "host", "app", "a\x00b"},
	{"leading spaces of the message are kept", "<13>Oct 11 22:14:15 host app:   x  ",
		FormatRFC3164, 13, "Oct 11 22:14:15", "host", "app", "  x  "},
	{"no month", "<13>Octo 11 22:14:15 host app: x", FormatUnknown, 13, "", "", "", "Octo 11 22:14:15 host app: x"},
	{"timestamp joined to the text", "<13>Oct 11 22:14:15host app: x", FormatUnknown, 13, "", "", "", "Oct 11 22:14:15host app: x"},
	{"time cut short", "<13>Oct 11 22:14", FormatUnknown, 13, "", "", "", "Oct 11 22:14"},
	{"ISO timestamp with a broken zone", "<13>2026-10-05T21:30:01+05 host app: x",
		FormatUnknown, 13, "", "", "", "2026-10-05T21:30:01+05 host app: x"},
	{"ISO timestamp in lower case", "<13>2026-10-05t21:30:01z host app: x", FormatRFC3164, 13, "2026-10-05t21:30:01z", "host", "app", "x"},
	{"ISO date with another separator", "<13>2026-10-05_21:30:01 host app: x", FormatUnknown, 13, "", "", "", "2026-10-05_21:30:01 host app: x"},
	{"dot without a fraction", "<13>Oct 11 22:14:15. host app: x", FormatUnknown, 13, "", "", "", "Oct 11 22:14:15. host app: x"},
	{"month and day only", "<13>Oct 11", FormatUnknown, 13, "", "", "", "Oct 11"},
	{"month without a day", "<13>Oct x 22:14:15 host app: x", FormatUnknown, 13, "", "", "", "Oct x 22:14:15 host app: x"},

	// RFC 5424.
	{"rfc5424 example 1 (BOM)", "<34>1 2003-10-11T22:14:15.003Z mymachine.example.com su - ID47 - " + bom + "'su root' failed for lonvick on /dev/pts/8",
		FormatRFC5424, 34, "2003-10-11T22:14:15.003Z", "mymachine.example.com", "su", "'su root' failed for lonvick on /dev/pts/8"},
	{"rfc5424 example 2", "<165>1 2003-08-24T05:14:15.000003-07:00 192.0.2.1 myproc 8710 - - %% It's time to make the do-nuts.",
		FormatRFC5424, 165, "2003-08-24T05:14:15.000003-07:00", "192.0.2.1", "myproc", "%% It's time to make the do-nuts."},
	{"rfc5424 example 3 (structured data)", `<165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 [exampleSDID@32473 iut="3" eventSource="Application" eventID="1011"] ` + bom + "An application event log entry...",
		FormatRFC5424, 165, "2003-10-11T22:14:15.003Z", "mymachine.example.com", "evntslog", "An application event log entry..."},
	{"rfc5424 example 4 (structured data, no MSG)", `<165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 [exampleSDID@32473 iut="3" eventSource="Application" eventID="1011"][examplePriority@32473 class="high"]`,
		FormatRFC5424, 165, "2003-10-11T22:14:15.003Z", "mymachine.example.com", "evntslog", ""},
	{"rfc5424 nil values", "<13>1 - - - - - -", FormatRFC5424, 13, "", "", "", ""},
	{"rfc5424 nil values and MSG", "<13>1 - - - - - - hello", FormatRFC5424, 13, "", "", "", "hello"},
	{"rfc5424 escapes in a value", `<13>1 2026-10-05T21:30:01Z h a p m [x@1 k="a\"b\]c\\" j="]"] msg`,
		FormatRFC5424, 13, "2026-10-05T21:30:01Z", "h", "a", "msg"},
	{"rfc5424 MSG that looks like structured data", "<13>1 2026-10-05T21:30:01Z h a p m - [x] y",
		FormatRFC5424, 13, "2026-10-05T21:30:01Z", "h", "a", "[x] y"},
	{"rfc5424 trailing LF", "<13>1 2026-10-05T21:30:01Z h a p m - msg\n", FormatRFC5424, 13, "2026-10-05T21:30:01Z", "h", "a", "msg"},
	{"rfc5424 empty MSG after the space", "<13>1 2026-10-05T21:30:01Z h a p m - ", FormatRFC5424, 13, "2026-10-05T21:30:01Z", "h", "a", ""},
	{"rfc5424 structured data joined to MSG", "<13>1 2026-10-05T21:30:01Z h a p m [x]msg",
		FormatUnknown, 13, "", "", "", "1 2026-10-05T21:30:01Z h a p m [x]msg"},
	{"rfc5424 structured data not closed", `<13>1 - h a p m [x k="v] msg`, FormatUnknown, 13, "", "", "", `1 - h a p m [x k="v] msg`},
	{"rfc5424 header cut short", "<13>1 2026-10-05T21:30:01Z host app", FormatUnknown, 13, "", "", "", "1 2026-10-05T21:30:01Z host app"},
	{"rfc5424 without structured data", "<13>1 2026-10-05T21:30:01Z h a p m", FormatUnknown, 13, "", "", "", "1 2026-10-05T21:30:01Z h a p m"},
	{"rfc5424 MSG in place of structured data", "<13>1 - h a p m msg here", FormatUnknown, 13, "", "", "", "1 - h a p m msg here"},
	{"rfc5424 nil structured data joined to MSG", "<13>1 - h a p m -msg", FormatUnknown, 13, "", "", "", "1 - h a p m -msg"},
	{"rfc5424 bad timestamp", "<13>1 yesterday h a p m - msg", FormatUnknown, 13, "", "", "", "1 yesterday h a p m - msg"},
	{"rfc5424 timestamp with a space", "<13>1 2026-10-05 21:30:01Z h a p m - msg", FormatUnknown, 13, "", "", "", "1 2026-10-05 21:30:01Z h a p m - msg"},
	{"version 0", "<13>0 - - - - - - msg", FormatUnknown, 13, "", "", "", "0 - - - - - - msg"},
	{"two spaces in the header", "<13>1  - - - - - msg", FormatUnknown, 13, "", "", "", "1  - - - - - msg"},

	// No PRI, or one that is not valid: the message is the whole text, which Raw holds already
	// unless line ends were cut off (Msg is not a second copy of the datagram).
	{"no PRI", "Use the BFG!", FormatUnknown, -1, "", "", "", ""},
	{"no PRI, line end", "Use the BFG!\r\n", FormatUnknown, -1, "", "", "", "Use the BFG!"},
	{"PRI out of range", "<192>Oct 11 22:14:15 host app: x", FormatUnknown, -1, "", "", "", ""},
	{"PRI of four digits", "<0013>Oct 11 22:14:15 host app: x", FormatUnknown, -1, "", "", "", ""},
	{"empty PRI", "<>Oct 11 22:14:15 host app: x", FormatUnknown, -1, "", "", "", ""},
	{"PRI not closed", "<13", FormatUnknown, -1, "", "", "", ""},
	{"negative PRI", "<-1>x", FormatUnknown, -1, "", "", "", ""},
	{"PRI with a space", "< 13>x", FormatUnknown, -1, "", "", "", ""},
	{"byte-order mark before the PRI", bom + "<13>x", FormatUnknown, -1, "", "", "", ""},
	{"control characters without a PRI", strings.Repeat("\x01", 64), FormatUnknown, -1, "", "", "", ""},
	{"PRI 0", "<0>Oct 11 22:14:15 host app: x", FormatRFC3164, 0, "Oct 11 22:14:15", "host", "app", "x"},
	{"PRI 191", "<191>Oct 11 22:14:15 host app: x", FormatRFC3164, 191, "Oct 11 22:14:15", "host", "app", "x"},
	{"PRI with a leading zero", "<013>Oct 11 22:14:15 host app: x", FormatRFC3164, 13, "Oct 11 22:14:15", "host", "app", "x"},
	{"PRI only", "<13>", FormatUnknown, 13, "", "", "", ""},
	{"PRI and text", "<13>hello world", FormatUnknown, 13, "", "", "", "hello world"},
	{"empty datagram", "", FormatUnknown, -1, "", "", "", ""},
	{"line ends only", "\r\n\x00", FormatUnknown, -1, "", "", "", ""},

	// Not valid UTF-8: RawB64 keeps the bytes, the parsed fields show U+FFFD.
	{"invalid UTF-8 in MSG", "<13>Oct 11 22:14:15 host app: caf\xe9\n", FormatRFC3164, 13, "Oct 11 22:14:15", "host", "app", "caf" + replacement},
	{"invalid UTF-8 without PRI", "\xff\xfe", FormatUnknown, -1, "", "", "", replacement},
	{"invalid UTF-8 in the host", "<13>Oct 11 22:14:15 h\xffst app: x", FormatRFC3164, 13, "Oct 11 22:14:15", "h" + replacement + "st", "app", "x"},
	{"UTF-8 sequence cut short", "<13>Oct 11 22:14:15 host app: \xe2\x82", FormatRFC3164, 13, "Oct 11 22:14:15", "host", "app", replacement},
	{"rfc5424 with invalid UTF-8 after a BOM", "<13>1 - h a - - - " + bom + "\xc3(", FormatRFC5424, 13, "", "h", "a", replacement + "("},
}

func TestParse(t *testing.T) {
	for _, c := range parseCases {
		t.Run(c.name, func(t *testing.T) {
			m := Parse([]byte(c.in))
			checkRaw(t, []byte(c.in), m)
			if m.Format != c.format {
				t.Errorf("Format = %q, want %q", m.Format, c.format)
			}
			checkPRI(t, m, c.pri)
			if m.TS != c.ts || m.Host != c.host || m.App != c.app || m.Msg != c.msg {
				t.Errorf("TS, Host, App, Msg = %q, %q, %q, %q\nwant                 %q, %q, %q, %q",
					m.TS, m.Host, m.App, m.Msg, c.ts, c.host, c.app, c.msg)
			}
			if m.RX != "" || m.Src != "" {
				t.Errorf("Parse set RX %q / Src %q", m.RX, m.Src)
			}
		})
	}
}

// checkRaw checks that m holds exactly the datagram b: as Raw when it is valid UTF-8, as
// RawB64 (standard base64) otherwise.
func checkRaw(t *testing.T, b []byte, m model.SyslogMessage) {
	t.Helper()
	if utf8.Valid(b) {
		if m.Raw != string(b) || m.RawB64 != "" {
			t.Fatalf("Raw %q, RawB64 %q for the valid UTF-8 datagram %q", m.Raw, m.RawB64, b)
		}
		return
	}
	got, err := base64.StdEncoding.DecodeString(m.RawB64)
	if m.Raw != "" || err != nil || !bytes.Equal(got, b) {
		t.Fatalf("Raw %q, RawB64 %q (%v) for the datagram %q", m.Raw, m.RawB64, err, b)
	}
}

// checkPRI checks PRI, Facility and Severity against pri (-1: none).
func checkPRI(t *testing.T, m model.SyslogMessage, pri int) {
	t.Helper()
	if pri < 0 {
		if m.PRI != nil || m.Facility != nil || m.Severity != nil {
			t.Errorf("PRI %v, Facility %v, Severity %v, want none", deref(m.PRI), deref(m.Facility), deref(m.Severity))
		}
		return
	}
	if m.PRI == nil || m.Facility == nil || m.Severity == nil ||
		*m.PRI != pri || *m.Facility != pri/8 || *m.Severity != pri%8 {
		t.Errorf("PRI %v, Facility %v, Severity %v, want %d, %d, %d",
			deref(m.PRI), deref(m.Facility), deref(m.Severity), pri, pri/8, pri%8)
	}
}

func deref(p *int) any {
	if p == nil {
		return nil
	}
	return *p
}

func TestTimestampLengths(t *testing.T) {
	for _, c := range []struct {
		s          string
		space, bsd bool
		want       int
	}{
		{"2026-10-05T21:30:01Z rest", false, false, 20},
		{"2026-10-05T21:30:01.5+01:00", false, false, 27},
		{"2026-10-05T21:30:01-0130 x", false, false, 24},
		{"2026-10-05 21:30:01 x", true, false, 19},
		{"2026-10-05 21:30:01 x", false, false, 0}, // RFC 5424 needs the "T"
		{"2026-10-05/21:30:01", true, false, 0},
		{"2026-10-05T21:30", false, false, 0},
		{"2026-1-05T21:30:01Z", false, false, 0},
		{"Oct  5 21:30:01 x", false, true, 15},
		{"Oct 5 21:30:01.25 x", false, true, 17},
		{"Oct 05 2026 21:30:01", false, true, 20},
		{"Oct 05 2026", false, true, 0},
		{"Oct   5 21:30:01", false, true, 0},
		{"Oct 123 21:30:01", false, true, 0},
		{"Okt 05 21:30:01", false, true, 0},
	} {
		got := isoTimeLen(c.s, c.space)
		if c.bsd {
			got = bsdTimeLen(c.s)
		}
		if got != c.want {
			t.Errorf("timestamp length of %q = %d, want %d", c.s, got, c.want)
		}
	}
}

func TestParseSeverityAndFacility(t *testing.T) {
	// <165> = facility 20 (local4) × 8 + severity 5 (notice); <0> = kernel emergency.
	m := Parse([]byte("<165>Oct 11 22:14:15 host app: x"))
	if *m.Facility != 20 || *m.Severity != 5 {
		t.Errorf("<165>: facility %d severity %d", *m.Facility, *m.Severity)
	}
	m = Parse([]byte("<0>Oct 11 22:14:15 host app: x"))
	if *m.Facility != 0 || *m.Severity != 0 {
		t.Errorf("<0>: facility %d severity %d", *m.Facility, *m.Severity)
	}
	// The pointers are the message's own.
	a, b := Parse([]byte("<13>x")), Parse([]byte("<13>x"))
	if a.PRI == b.PRI || a.PRI == a.Facility {
		t.Error("messages share PRI pointers")
	}
}

// TestRawSurvivesJSON: the ledger stores messages as JSON; the exact datagram must come back
// from it byte for byte.
func TestRawSurvivesJSON(t *testing.T) {
	for _, in := range []string{
		"<13>Oct 11 22:14:15 host app: <script>&amp;\"quoted\" \\ back\x00slash\x1b[0m\x7f\r\n",
		"<13>1 - - - - - - " + bom + "line\xe2\x80\xa8separator\xe2\x80\xa9and \xf0\x9f\x98\x80",
		"\x00\x01\x02 not syslog at all\t",
		"caf\xe9 \xff\xfe\xfd",
		"",
	} {
		m := Parse([]byte(in))
		j, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		var back model.SyslogMessage
		if err := json.Unmarshal(j, &back); err != nil {
			t.Fatal(err)
		}
		checkRaw(t, []byte(in), back)
		if back.Msg != m.Msg || back.Format != m.Format {
			t.Errorf("%q: JSON changed the message: %q / %q", in, back.Msg, m.Msg)
		}
	}
}

func TestParseKeepsMaxSizeDatagram(t *testing.T) {
	b := []byte("<13>Oct 11 22:14:15 host app: " + strings.Repeat("x", DefaultMaxMessage-30))
	if len(b) != DefaultMaxMessage {
		t.Fatalf("test datagram is %d bytes", len(b))
	}
	m := Parse(b)
	checkRaw(t, b, m)
	if m.Format != FormatRFC3164 || len(m.Msg) != DefaultMaxMessage-30 {
		t.Errorf("Format %q, Msg of %d bytes", m.Format, len(m.Msg))
	}
}
