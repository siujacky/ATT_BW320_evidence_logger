package netmap

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"time"
)

// Receive times outside these years are not believed (a damaged line): they could not be
// counted in nanoseconds, and no period near now holds them.
const (
	minYear = 1970
	maxYear = 2200
)

var (
	patRX     = []byte(`"rx":"`)
	patMsg    = []byte(`"msg":"`)
	patRaw    = []byte(`"raw":"`)
	patRawB64 = []byte(`"raw_b64":"`)
)

// lineText returns the receive time (Unix nanoseconds) of one line of a syslog chunk and the
// text of its message: Msg, else Raw, else the bytes RawB64 holds (nil when there is none). The
// lines are model.SyslogMessage objects as json.Marshal writes them, so the fields are found
// without decoding the whole object - several times faster, and the firewall view reads millions
// of lines; text may then be part of line. A line that is not written that way is decoded with
// encoding/json. ok is false for a line that is not a message with a believable receive time.
func lineText(line []byte) (rx int64, text []byte, ok bool) {
	if len(line) < 2 || line[0] != '{' || line[len(line)-1] != '}' {
		return slowLineText(line)
	}
	v, found := jsonString(line, patRX)
	if !found || !v.ok || v.escaped {
		return slowLineText(line)
	}
	if rx, ok = parseRX(string(v.b)); !ok {
		return 0, nil, false
	}
	for _, pat := range [...][]byte{patMsg, patRaw} {
		v, found := jsonString(line, pat)
		switch {
		case !found:
			continue
		case !v.ok:
			return slowLineText(line)
		case len(v.b) == 0:
			continue
		case v.escaped:
			var s string
			if json.Unmarshal(v.quoted, &s) != nil {
				return slowLineText(line)
			}
			if s == "" {
				continue
			}
			return rx, []byte(s), true
		}
		return rx, v.b, true
	}
	v, found = jsonString(line, patRawB64)
	switch {
	case !found:
		return rx, nil, true
	case !v.ok || v.escaped:
		return slowLineText(line)
	}
	b, err := base64.StdEncoding.DecodeString(string(v.b))
	if err != nil {
		return rx, nil, true
	}
	return rx, b, true
}

// jsonValue is a string value found in a line.
type jsonValue struct {
	b       []byte // between the quotes, as written
	quoted  []byte // with the quotes
	escaped bool   // b holds escapes: it is not the value itself
	ok      bool   // the value ends in the line
}

// jsonString finds the string value of the field pat (`"name":"`) at the top level of a line as
// json.Marshal writes it: the field follows '{' or ','. (Inside a string every quote is escaped,
// so `,"name":"` never occurs there.)
func jsonString(line, pat []byte) (v jsonValue, found bool) {
	for off := 1; off < len(line); {
		i := indexFrom(line, pat, off)
		if i < 0 {
			return v, false
		}
		if c := line[i-1]; c != '{' && c != ',' {
			off = i + 1
			continue
		}
		start := i + len(pat)
		// Most values hold no escape: the next quote ends them.
		q := bytes.IndexByte(line[start:], '"')
		if q < 0 {
			return v, true // not ended
		}
		if bytes.IndexByte(line[start:start+q], '\\') < 0 {
			v.b, v.quoted, v.ok = line[start:start+q], line[start-1:start+q+1], true
			return v, true
		}
		v.escaped = true
		for j := start; j < len(line); j++ {
			switch line[j] {
			case '\\':
				j++
			case '"':
				v.b, v.quoted, v.ok = line[start:j], line[start-1:j+1], true
				return v, true
			}
		}
		return v, true // not ended
	}
	return v, false
}

// indexFrom returns the index of pat in line at or after off (-1 when absent).
func indexFrom(line, pat []byte, off int) int {
	if off >= len(line) {
		return -1
	}
	if i := bytes.Index(line[off:], pat); i >= 0 {
		return off + i
	}
	return -1
}

// storedLine is what the firewall view needs of a stored model.SyslogMessage.
type storedLine struct {
	RX     string `json:"rx"`
	Raw    string `json:"raw"`
	RawB64 string `json:"raw_b64"`
	Msg    string `json:"msg"`
}

// slowLineText is lineText for a line decoded with encoding/json.
func slowLineText(line []byte) (int64, []byte, bool) {
	var m storedLine
	if json.Unmarshal(line, &m) != nil {
		return 0, nil, false
	}
	rx, ok := parseRX(m.RX)
	if !ok {
		return 0, nil, false
	}
	return rx, messageText(m.Msg, m.Raw, m.RawB64), true
}

// messageText is the text of a message: Msg, else Raw, else the bytes RawB64 holds (nil when
// there is none, or RawB64 is not base64).
func messageText(msg, raw, rawB64 string) []byte {
	switch {
	case msg != "":
		return []byte(msg)
	case raw != "":
		return []byte(raw)
	case rawB64 != "":
		if b, err := base64.StdEncoding.DecodeString(rawB64); err == nil {
			return b
		}
	}
	return nil
}

// parseRX parses a receive time (RFC 3339) into Unix nanoseconds.
func parseRX(s string) (int64, bool) {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil || t.Year() < minYear || t.Year() > maxYear {
		return 0, false
	}
	return t.UnixNano(), true
}
