package netmap

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"attmonitor/internal/model"
)

// marshal returns the stored line of m.
func marshal(t testing.TB, m model.SyslogMessage) []byte {
	t.Helper()
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestLineText(t *testing.T) {
	rx := at(1.5)
	ns := rx.UnixNano()
	m := syslogMsg(rx, lineInbound)
	if m.Msg != lineInbound || m.Raw != "<12>"+lineInbound {
		t.Fatalf("the receiver's message: %+v", m) // what the tests assume of syslogrx
	}
	noMsg := m
	noMsg.Msg = ""
	b64 := model.SyslogMessage{RX: m.RX, Src: m.Src, RawB64: base64.StdEncoding.EncodeToString([]byte("\xff" + lineInbound))}
	escaped := m
	escaped.Msg = `a "quoted" \ <tag> & é ` + "\u2028\x01"
	for _, c := range []struct {
		name string
		line []byte
		rx   int64
		text string
		ok   bool
	}{
		{"msg", marshal(t, m), ns, lineInbound, true},
		{"raw without msg", marshal(t, noMsg), ns, "<12>" + lineInbound, true},
		{"raw_b64", marshal(t, b64), ns, "\xff" + lineInbound, true},
		{"escapes", marshal(t, escaped), ns, escaped.Msg, true},
		{"no text", marshal(t, model.SyslogMessage{RX: m.RX, Src: m.Src}), ns, "", true},
		{"other order", []byte(`{"msg":"x y","rx":"` + m.RX + `"}`), ns, "x y", true},
		{"spaces (slow)", []byte(`{ "rx" : "` + m.RX + `", "msg" : "x" }`), ns, "x", true},
		{"msg empty", []byte(`{"rx":"` + m.RX + `","raw":"r","msg":""}`), ns, "r", true},
		{"bad base64", []byte(`{"rx":"` + m.RX + `","raw_b64":"!!"}`), ns, "", true},
		{"key in a value", []byte(`{"rx":"` + m.RX + `","raw":"x\",\"msg\":\"no","app":"a"}`), ns, `x","msg":"no`, true},
		{"cut", marshal(t, m)[:100], 0, "", false},
		{"not json", []byte("P0000-00-00T07:48:34 L4 FIREWALL"), 0, "", false},
		{"empty", nil, 0, "", false},
		{"no rx", []byte(`{"msg":"x"}`), 0, "", false},
		{"bad rx", []byte(`{"rx":"yesterday","msg":"x"}`), 0, "", false},
		{"rx too old", []byte(`{"rx":"1969-12-31T23:59:59Z","msg":"x"}`), 0, "", false},
		{"rx too new", []byte(`{"rx":"2201-01-01T00:00:00Z","msg":"x"}`), 0, "", false},
		{"rx with an offset", []byte(`{"rx":"2026-10-06T09:00:01.5+02:00","msg":"x"}`), ns, "x", true},
		{"msg not ended", []byte(`{"rx":"` + m.RX + `","msg":"abc}`), 0, "", false},
	} {
		rx, text, ok := lineText(c.line)
		if ok != c.ok || rx != c.rx || string(text) != c.text {
			t.Errorf("%s: %d %q %v, want %d %q %v", c.name, rx, text, ok, c.rx, c.text, c.ok)
		}
	}
}

// FuzzLineTextMatchesJSON checks that the fast reading of a stored line gives what decoding it
// gives, for every line json.Marshal can write.
func FuzzLineTextMatchesJSON(f *testing.F) {
	f.Add(int64(0), "<12>"+lineInbound, "", lineInbound, false)
	f.Add(int64(1), "", "\xff\x00", "", true)
	f.Add(int64(-5), `a"b\c`, "", "<x>&\u2028", false)
	f.Add(int64(7), "", "", "", false)
	f.Fuzz(func(t *testing.T, sec int64, raw, rawB64, msg string, b64 bool) {
		m := model.SyslogMessage{RX: t0.Add(time.Duration(sec%1e9) * time.Second).Format(time.RFC3339Nano), Src: "x",
			Raw: raw, Msg: msg}
		if b64 {
			m.Raw, m.RawB64 = "", base64.StdEncoding.EncodeToString([]byte(rawB64))
		}
		line := marshal(t, m)
		rx, text, ok := lineText(line)
		wrx, wtext, wok := slowLineText(line)
		if ok != wok || rx != wrx || !bytes.Equal(text, wtext) {
			t.Fatalf("line %s:\nfast %d %q %v\njson %d %q %v", line, rx, text, ok, wrx, wtext, wok)
		}
	})
}

// FuzzLineText checks that no line makes the reading panic.
func FuzzLineText(f *testing.F) {
	f.Add([]byte(`{"rx":"2026-10-06T07:00:00Z","msg":"x"}`))
	f.Add([]byte(`{"rx":"2026-10-06T07:00:00Z","msg":"\`))
	f.Add([]byte(`{,"rx":"`))
	f.Add([]byte(`{"raw_b64":"","rx":"2026-10-06T07:00:00Z"}`))
	f.Fuzz(func(t *testing.T, line []byte) {
		rx, text, ok := lineText(line)
		if !ok && (rx != 0 || text != nil) {
			t.Fatalf("not ok but %d %q", rx, text)
		}
		if ok && (rx < time.Date(minYear, 1, 1, 0, 0, 0, 0, time.UTC).UnixNano() ||
			rx >= time.Date(maxYear+1, 1, 1, 0, 0, 0, 0, time.UTC).UnixNano()) {
			t.Fatalf("receive time %d", rx)
		}
	})
}

func TestEachLine(t *testing.T) {
	long := strings.Repeat("x", maxLine+1)
	almost := strings.Repeat("y", 70<<10) // longer than the reader's buffer
	for _, c := range []struct {
		name, in string
		want     []string // "<nil>" for a line too long
	}{
		{"empty", "", nil},
		{"lines", "a\nb\n", []string{"a", "b"}},
		{"last without a line feed", "a\nb", []string{"a", "b"}},
		{"empty lines", "\n\na\n", []string{"", "", "a"}},
		{"long", "a\n" + long + "\nb\n", []string{"a", "<nil>", "b"}},
		{"long last", "a\n" + long, []string{"a", "<nil>"}},
		{"longer than the buffer", almost + "\nb\n", []string{almost, "b"}},
	} {
		var got []string
		err := eachLine(strings.NewReader(c.in), func(i int, line []byte) error {
			if i != len(got) {
				t.Fatalf("%s: index %d for line %d", c.name, i, len(got))
			}
			if line == nil {
				got = append(got, "<nil>")
			} else {
				got = append(got, string(line))
			}
			return nil
		})
		if err != nil || strings.Join(got, "|") != strings.Join(c.want, "|") || len(got) != len(c.want) {
			t.Errorf("%s: %d lines %v (err %v), want %d", c.name, len(got), shorten(got), err, len(c.want))
		}
	}
}

func shorten(lines []string) []string {
	out := make([]string, len(lines))
	for i, l := range lines {
		if len(l) > 20 {
			l = l[:20] + "…"
		}
		out[i] = l
	}
	return out
}
