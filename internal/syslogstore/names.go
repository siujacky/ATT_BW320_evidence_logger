package syslogstore

import (
	"encoding/json"
	"strconv"
	"strings"
	"time"
)

// File names in the store's directory. Times are UTC in a compact form that sorts as text and
// is valid in Windows file names: 20261005T221500.123456789Z.
const (
	timeLayout = "20060102T150405.000000000Z"
	timeLen    = len(timeLayout)

	openPrefix   = "open-"
	openExt      = ".jsonl"
	stateExt     = ".state.json"
	sealedPrefix = "syslog-"
	sealedExt    = ".jsonl.gz"
	sidecarExt   = ".json"
	tmpExt       = ".tmp"

	// maxSuffix bounds the number appended to a name that is taken already (two chunks with
	// the same first and last receive time; in practice only with a clock that stands still).
	maxSuffix = 1000
)

// compact formats t as a name's time.
func compact(t time.Time) string { return t.UTC().Format(timeLayout) }

// parseCompact parses a name's time; only the exact form compact produces is accepted.
func parseCompact(s string) (time.Time, bool) {
	if len(s) != timeLen {
		return time.Time{}, false
	}
	t, err := time.Parse(timeLayout, s)
	if err != nil || compact(t) != s {
		return time.Time{}, false
	}
	return t, true
}

// suffix is the part a name gets when its plain form is taken: "" for n < 2, else "-n".
func suffix(n int) string {
	if n < 2 {
		return ""
	}
	return "-" + strconv.Itoa(n)
}

// parseSuffix parses what follows a name's time(s): "" (n = 1) or "-n" with n from 2 on and no
// leading zero.
func parseSuffix(s string) (int, bool) {
	if s == "" {
		return 1, true
	}
	d, ok := strings.CutPrefix(s, "-")
	if !ok || d == "" || d[0] == '0' || len(d) > 6 {
		return 0, false
	}
	n, err := strconv.Atoi(d)
	if err != nil || n < 2 || strconv.Itoa(n) != d {
		return 0, false
	}
	return n, true
}

// sealedName is the file name of a sealed chunk: syslog-<from>_<to>[-n].jsonl.gz.
func sealedName(from, to time.Time, n int) string {
	return sealedPrefix + compact(from) + "_" + compact(to) + suffix(n) + sealedExt
}

// parseSealedName parses a sealed chunk's file name.
func parseSealedName(name string) (from, to time.Time, n int, ok bool) {
	rest, ok1 := strings.CutPrefix(name, sealedPrefix)
	rest, ok2 := strings.CutSuffix(rest, sealedExt)
	if !ok1 || !ok2 || len(rest) < 2*timeLen+1 || rest[timeLen] != '_' {
		return time.Time{}, time.Time{}, 0, false
	}
	from, ok1 = parseCompact(rest[:timeLen])
	to, ok2 = parseCompact(rest[timeLen+1 : 2*timeLen+1])
	n, ok3 := parseSuffix(rest[2*timeLen+1:])
	if !ok1 || !ok2 || !ok3 {
		return time.Time{}, time.Time{}, 0, false
	}
	return from, to, n, true
}

// openName is the file name of the open chunk: open-<from>[-n].jsonl.
func openName(from time.Time, n int) string {
	return openPrefix + compact(from) + suffix(n) + openExt
}

// parseOpenName parses the open chunk's file name and returns its time.
func parseOpenName(name string) (time.Time, bool) {
	rest, ok1 := strings.CutPrefix(name, openPrefix)
	rest, ok2 := strings.CutSuffix(rest, openExt)
	if !ok1 || !ok2 || len(rest) < timeLen {
		return time.Time{}, false
	}
	t, ok := parseCompact(rest[:timeLen])
	if _, okN := parseSuffix(rest[timeLen:]); !ok || !okN {
		return time.Time{}, false
	}
	return t, true
}

// stateName is the state file of the open chunk named open: open-<from>[-n].state.json.
func stateName(open string) string {
	return strings.TrimSuffix(open, openExt) + stateExt
}

// openOfState returns the open chunk's file name of a state file name, if it is one.
func openOfState(name string) (string, bool) {
	base, ok := strings.CutSuffix(name, stateExt)
	if !ok {
		return "", false
	}
	open := base + openExt
	if _, ok := parseOpenName(open); !ok {
		return "", false
	}
	return open, true
}

// formatRX formats a receive time as the records state it (RFC 3339 UTC with nanoseconds).
func formatRX(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

// parseRX parses a receive time.
func parseRX(s string) (time.Time, bool) {
	t, err := time.Parse(time.RFC3339Nano, s)
	return t, err == nil
}

// lineRX returns the receive time ("rx") of a stored line.
func lineRX(line []byte) (time.Time, bool) {
	var v struct {
		RX string `json:"rx"`
	}
	if json.Unmarshal(line, &v) != nil {
		return time.Time{}, false
	}
	return parseRX(v.RX)
}

// summary describes a chunk's content: its messages (lines) and their receive times.
type summary struct {
	messages int
	timed    bool      // some line has a receive time that parses
	first    time.Time // receive time of the first and the last such line
	last     time.Time
	min, max time.Time // the earliest and latest receive time
}

// add counts one line (without its line feed).
func (s *summary) add(line []byte) {
	s.messages++
	t, ok := lineRX(line)
	if !ok {
		return
	}
	if !s.timed {
		s.timed, s.first, s.min, s.max = true, t, t, t
	}
	s.last = t
	if t.Before(s.min) {
		s.min = t
	}
	if t.After(s.max) {
		s.max = t
	}
}

// span returns the From and To of a chunk with this summary: the receive times of its first
// and last message, or opened for both when no message has a receive time.
func (s summary) span(opened time.Time) (from, to time.Time) {
	if !s.timed {
		return opened, opened
	}
	return s.first, s.last
}
