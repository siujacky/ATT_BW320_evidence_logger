package connstore

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"time"

	"attmonitor/internal/model"
)

// maxLine bounds a stored line: far beyond a NAT table read of the gateway's session limit
// (tens of thousands of sessions take a few MiB), it keeps a damaged or foreign file from being
// read into memory whole. A longer line is not written, and is skipped when read.
const maxLine = 16 << 20

// sessionInts is the number of integers that encode one NAT session in a natLine.
const sessionInts = 6

// natLine is one NAT table read as a line of a nat- file. Its sessions are a table of the
// distinct strings they use (protocols, TCP states and addresses, each once) and six integers
// per session: protocol, TCP state and source address (indexes into Strs), source port,
// destination address (index), destination port. A read of 400 sessions to a few hundred
// addresses takes about 12 KB this way instead of about 40 KB as objects, and decodes several
// times faster. "t" comes first, so that peekTime can tell a read's time without decoding it.
type natLine struct {
	T         string   `json:"t"`
	InUse     int      `json:"in_use"`
	Available int      `json:"available"`
	Display   string   `json:"display,omitempty"`
	Skipped   int      `json:"skipped,omitempty"`
	Strs      []string `json:"strs"`
	S         []int    `json:"s"`
	buf       []byte   // decodeNAT's scratch space, reused from line to line
}

// devLine is one Device List read as a line of a devices- file: the devices as the gateway
// client parsed them (model.LANDevice's own JSON).
type devLine struct {
	T       string            `json:"t"`
	Devices []model.LANDevice `json:"devices"`
}

// errLineTooLong is returned for a read whose line would exceed maxLine.
var errLineTooLong = fmt.Errorf("connstore: a read takes more than %d MiB as a line", maxLine>>20)

// encodeNAT encodes the NAT table read at t as a line (with its line feed).
func encodeNAT(t time.Time, nat model.NATTable) ([]byte, error) {
	l := natLine{T: formatTime(t), InUse: nat.InUse, Available: nat.Available, Display: nat.Display,
		Skipped: nat.Skipped, Strs: []string{}, S: make([]int, 0, sessionInts*len(nat.Sessions))}
	index := map[string]int{}
	str := func(s string) int {
		i, ok := index[s]
		if !ok {
			i = len(l.Strs)
			index[s] = i
			l.Strs = append(l.Strs, s)
		}
		return i
	}
	for _, x := range nat.Sessions {
		l.S = append(l.S, str(x.Proto), str(x.State), str(x.Src), x.SrcPort, str(x.Dst), x.DstPort)
	}
	return marshalLine(&l)
}

// encodeDevices encodes the Device List read at t as a line (with its line feed).
func encodeDevices(t time.Time, devices []model.LANDevice) ([]byte, error) {
	l := devLine{T: formatTime(t), Devices: devices}
	if l.Devices == nil {
		l.Devices = []model.LANDevice{}
	}
	return marshalLine(&l)
}

// marshalLine encodes v as a line: its JSON and a line feed.
func marshalLine(v any) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("connstore: encode a read: %w", err)
	}
	if len(b)+1 > maxLine {
		return nil, errLineTooLong
	}
	return append(b, '\n'), nil
}

// decodeNAT decodes a NAT line (without its line feed) into l, reusing l's slices, and returns
// the read's time. A line whose time does not parse, or whose sessions are not whole groups of
// six integers, is damaged: an error. Indexes into Strs are checked where they are used.
func decodeNAT(line []byte, l *natLine) (time.Time, error) {
	if !decodeNATFast(line, l) {
		*l = natLine{Strs: l.Strs[:0], S: l.S[:0], buf: l.buf}
		if err := json.Unmarshal(line, l); err != nil {
			return time.Time{}, err
		}
	}
	t, ok := parseTime(l.T)
	if !ok {
		return time.Time{}, errors.New("the read's time is missing or not valid")
	}
	if len(l.S)%sessionInts != 0 {
		return time.Time{}, fmt.Errorf("its sessions are %d integers, not groups of %d", len(l.S), sessionInts)
	}
	return t, nil
}

// sessionsMember is how a line the store writes begins its last member, the sessions' integers.
const sessionsMember = `,"s":[`

// decodeNATFast decodes a line that ends as the store writes it - with the sessions' integers,
// whose decoding takes most of a line's time with encoding/json - by decoding those integers
// itself and the rest of the line with encoding/json. It returns false for a line it does not
// recognize in every detail (decodeNAT then decodes the whole line with encoding/json). For any
// line it accepts, the result is the one encoding/json gives: the text before the member is a
// JSON object once closed (no quote of the member can be inside a string, where quotes are
// escaped), and the member's integers follow JSON's grammar and fit an int.
func decodeNATFast(line []byte, l *natLine) bool {
	body, ok := bytes.CutSuffix(line, []byte("]}"))
	if !ok {
		return false
	}
	i := bytes.LastIndex(body, []byte(sessionsMember))
	if i < 0 {
		return false
	}
	if before := bytes.TrimRight(body[:i], " \t\r\n"); len(before) == 0 || before[len(before)-1] == '{' {
		return false // no member before the sessions' (the comma would make the line invalid)
	}
	*l = natLine{Strs: l.Strs[:0], S: l.S[:0], buf: l.buf}
	l.buf = append(append(l.buf[:0], body[:i]...), '}')
	if json.Unmarshal(l.buf, l) != nil {
		return false
	}
	l.S, ok = appendInts(l.S[:0], body[i+len(sessionsMember):])
	return ok
}

// appendInts appends to dst the integers of b, a JSON array's content without its brackets:
// integers in JSON's grammar (-?(0|[1-9][0-9]*)) separated by commas, without spaces, each
// fitting an int. ok is false for anything else.
func appendInts(dst []int, b []byte) (out []int, ok bool) {
	if len(b) == 0 {
		return dst, true
	}
	for {
		neg := false
		if b[0] == '-' {
			neg, b = true, b[1:]
		}
		n := 0
		for n < len(b) && b[n] >= '0' && b[n] <= '9' {
			n++
		}
		if n == 0 || n > 19 || n > 1 && b[0] == '0' {
			return dst, false
		}
		var v uint64
		for _, c := range b[:n] {
			v = v*10 + uint64(c-'0') // 19 digits cannot overflow a uint64
		}
		switch {
		case !neg && v > math.MaxInt:
			return dst, false
		case neg && v > math.MaxInt+1:
			return dst, false
		case neg:
			dst = append(dst, int(-v))
		default:
			dst = append(dst, int(v))
		}
		b = b[n:]
		if len(b) == 0 {
			return dst, true
		}
		if b[0] != ',' || len(b) == 1 {
			return dst, false
		}
		b = b[1:]
	}
}

// session returns the i-th session of a decoded line; ok is false when one of its indexes is
// outside the string table.
func (l *natLine) session(i int) (s model.NATSession, ok bool) {
	v := l.S[i*sessionInts : (i+1)*sessionInts]
	for _, j := range [...]int{v[0], v[1], v[2], v[4]} {
		if j < 0 || j >= len(l.Strs) {
			return s, false
		}
	}
	return model.NATSession{Proto: l.Strs[v[0]], State: l.Strs[v[1]], Src: l.Strs[v[2]], SrcPort: v[3],
		Dst: l.Strs[v[4]], DstPort: v[5]}, true
}

// sessions returns the number of sessions of a decoded line.
func (l *natLine) sessions() int { return len(l.S) / sessionInts }

// table returns the read a decoded line holds, as model.NATTable, and how many of its sessions
// could not be (an index outside the string table: a damaged line).
func (l *natLine) table() (model.NATTable, int) {
	nt := model.NATTable{InUse: l.InUse, Available: l.Available, Display: l.Display, Skipped: l.Skipped,
		Sessions: make([]model.NATSession, 0, l.sessions())}
	bad := 0
	for i := range l.sessions() {
		s, ok := l.session(i)
		if !ok {
			bad++
			continue
		}
		nt.Sessions = append(nt.Sessions, s)
	}
	return nt, bad
}

// decodeDevices decodes a devices line (without its line feed).
func decodeDevices(line []byte) (time.Time, []model.LANDevice, error) {
	var l devLine
	if err := json.Unmarshal(line, &l); err != nil {
		return time.Time{}, nil, err
	}
	t, ok := parseTime(l.T)
	if !ok {
		return time.Time{}, nil, errors.New("the read's time is missing or not valid")
	}
	if l.Devices == nil {
		l.Devices = []model.LANDevice{}
	}
	return t, l.Devices, nil
}

// timePrefix is how every line the store writes begins: its "t" member comes first.
const timePrefix = `{"t":"`

// peekTime returns the time of a stored line without decoding the line: the readers skip the
// lines outside a query's period this way. ok is false when the line does not begin as the
// store writes it (the caller then decodes it to find out).
func peekTime(line []byte) (time.Time, bool) {
	rest, ok := bytes.CutPrefix(line, []byte(timePrefix))
	if !ok {
		return time.Time{}, false
	}
	i := bytes.IndexByte(rest, '"')
	if i < 0 || i > len("2006-01-02T15:04:05.999999999Z07:00") {
		return time.Time{}, false
	}
	return parseTime(string(rest[:i]))
}
