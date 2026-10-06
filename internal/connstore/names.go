package connstore

import (
	"strings"
	"time"
)

// kind is what a file holds: NAT table reads or Device List reads.
type kind uint8

const (
	kindNAT kind = iota
	kindDevices
	numKinds
)

// kindPrefix is the start of the file names of each kind. The monitor writes other files into
// the same directory (last-nattable.html, last-devices.html): only names that parse as one of
// the store's own (parseFileName) are ever touched.
var kindPrefix = [numKinds]string{"nat-", "devices-"}

// String names the kind in logs and errors.
func (k kind) String() string {
	if k == kindNAT {
		return "nat"
	}
	return "devices"
}

// File name parts: <prefix><YYYY-MM-DD>.jsonl, gzipped once the day is over (.jsonl.gz); a
// compressed file being written is <name>.jsonl.gz.tmp until it is checked and renamed.
const (
	plainExt   = ".jsonl"
	gzExt      = ".gz"
	tmpExt     = ".tmp"
	dateLayout = "2006-01-02"
	dateLen    = len(dateLayout)
)

// The range of days the store accepts. Times are kept as Unix nanoseconds in memory (an int64
// reaches 2262), and the names need four-digit years; a read outside this range comes from a
// clock that is badly wrong and is refused.
var (
	minTime = time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	maxTime = time.Date(2200, 1, 1, 0, 0, 0, 0, time.UTC) // exclusive
)

// secondsPerDay is the length of a UTC day: the store's days ignore leap seconds, like Go's
// time package.
const secondsPerDay = 24 * 60 * 60

// day is a UTC day, counted from 1970-01-01. Every file holds the reads of one day.
type day int32

// dayOf returns the UTC day of t.
func dayOf(t time.Time) day {
	u := t.Unix()
	d := u / secondsPerDay
	if u < 0 && u%secondsPerDay != 0 {
		d-- // floor, also before 1970
	}
	return day(d)
}

// start is the first instant of the day.
func (d day) start() time.Time { return time.Unix(int64(d)*secondsPerDay, 0).UTC() }

// end is the first instant of the next day: a day is [start, end).
func (d day) end() time.Time { return (d + 1).start() }

// String formats the day as its file names state it (YYYY-MM-DD).
func (d day) String() string { return d.start().Format(dateLayout) }

// validTime reports whether t is in the range of times the store keeps.
func validTime(t time.Time) bool { return !t.Before(minTime) && t.Before(maxTime) }

// fileName returns the name of the file of kind k for day d: plain (being appended to) or
// gzipped (the day is over).
func fileName(k kind, d day, gz bool) string {
	name := kindPrefix[k] + d.String() + plainExt
	if gz {
		name += gzExt
	}
	return name
}

// parsedName is what parseFileName found in a file name.
type parsedName struct {
	kind kind
	day  day
	gz   bool // .jsonl.gz
	tmp  bool // .jsonl.gz.tmp: a compressed copy that was being written
}

// parseFileName parses one of the store's file names. Only the exact forms fileName produces
// (and their .tmp) are accepted, with a valid date in the store's range: every other file of the
// directory is someone else's.
func parseFileName(name string) (parsedName, bool) {
	var p parsedName
	k := numKinds
	rest := name
	for i, prefix := range kindPrefix {
		if r, ok := strings.CutPrefix(name, prefix); ok {
			k, rest = kind(i), r
			break
		}
	}
	if k == numKinds || len(rest) < dateLen {
		return p, false
	}
	date, ext := rest[:dateLen], rest[dateLen:]
	switch ext {
	case plainExt:
	case plainExt + gzExt:
		p.gz = true
	case plainExt + gzExt + tmpExt:
		p.gz, p.tmp = true, true
	default:
		return p, false
	}
	t, err := time.Parse(dateLayout, date)
	if err != nil || t.Format(dateLayout) != date || !validTime(t) {
		return p, false
	}
	p.kind, p.day = k, dayOf(t)
	return p, true
}

// formatTime formats a time as the store's lines and results state it: RFC 3339 UTC with
// nanoseconds, like the times of the ledger's records.
func formatTime(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

// parseTime parses a time of a stored line; it must be in the store's range.
func parseTime(s string) (time.Time, bool) {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil || !validTime(t) {
		return time.Time{}, false
	}
	return t.UTC(), true
}
