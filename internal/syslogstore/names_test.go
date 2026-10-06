package syslogstore

import (
	"slices"
	"strings"
	"testing"
	"time"
)

func TestCompactTime(t *testing.T) {
	if got := compact(t0); got != "20261005T221500.123456789Z" {
		t.Fatalf("compact = %q", got)
	}
	// Any zone: the name is UTC.
	if got := compact(t0.In(time.FixedZone("x", -5*3600))); got != "20261005T221500.123456789Z" {
		t.Fatalf("compact in another zone = %q", got)
	}
	got, ok := parseCompact("20261005T221500.123456789Z")
	if !ok || !got.Equal(t0) {
		t.Fatalf("parseCompact = %v, %v", got, ok)
	}
	for _, bad := range []string{"", "20261005T221500Z", "20261005T221500.12345678Z", "20261005T221500.123456789",
		"20261305T221500.123456789Z", "20261005t221500.123456789Z", "20261005T221500.123456789Z0"} {
		if _, ok := parseCompact(bad); ok {
			t.Errorf("parseCompact(%q) accepted", bad)
		}
	}
	// Names sort as their times.
	if a, b := compact(t0), compact(t0.Add(time.Nanosecond)); a >= b {
		t.Fatalf("%s does not sort before %s", a, b)
	}
}

func TestSealedNames(t *testing.T) {
	to := t0.Add(5 * time.Minute)
	name := sealedName(t0, to, 1)
	if name != "syslog-20261005T221500.123456789Z_20261005T222000.123456789Z.jsonl.gz" {
		t.Fatalf("sealedName = %q", name)
	}
	f, tt, n, ok := parseSealedName(name)
	if !ok || !f.Equal(t0) || !tt.Equal(to) || n != 1 {
		t.Fatalf("parseSealedName = %v %v %d %v", f, tt, n, ok)
	}
	name3 := sealedName(t0, to, 3)
	if name3 != "syslog-20261005T221500.123456789Z_20261005T222000.123456789Z-3.jsonl.gz" {
		t.Fatalf("sealedName(3) = %q", name3)
	}
	if _, _, n, ok := parseSealedName(name3); !ok || n != 3 {
		t.Fatalf("parseSealedName(%q) = %d %v", name3, n, ok)
	}
	for _, bad := range []string{
		"", "syslog-.jsonl.gz", name + ".json", name[:len(name)-3], "x" + name,
		"syslog-20261005T221500.123456789Z-20261005T222000.123456789Z.jsonl.gz",
		"syslog-20261005T221500.123456789Z_20261005T222000.123456789Z-1.jsonl.gz",
		"syslog-20261005T221500.123456789Z_20261005T222000.123456789Z-02.jsonl.gz",
		"syslog-20261005T221500.123456789Z_20261005T222000.123456789Z-x.jsonl.gz",
		"syslog-20261005T221500.123456789Z_20261005T222000.123456789Z_.jsonl.gz",
		"SYSLOG-20261005T221500.123456789Z_20261005T222000.123456789Z.JSONL.GZ",
	} {
		if _, _, _, ok := parseSealedName(bad); ok {
			t.Errorf("parseSealedName(%q) accepted", bad)
		}
	}
}

func TestOpenAndStateNames(t *testing.T) {
	name := openName(t0, 1)
	if name != "open-20261005T221500.123456789Z.jsonl" {
		t.Fatalf("openName = %q", name)
	}
	if got, ok := parseOpenName(name); !ok || !got.Equal(t0) {
		t.Fatalf("parseOpenName = %v %v", got, ok)
	}
	if got, ok := parseOpenName(openName(t0, 2)); !ok || !got.Equal(t0) {
		t.Fatalf("parseOpenName(-2) = %v %v", got, ok)
	}
	st := stateName(name)
	if st != "open-20261005T221500.123456789Z.state.json" {
		t.Fatalf("stateName = %q", st)
	}
	if open, ok := openOfState(st); !ok || open != name {
		t.Fatalf("openOfState = %q %v", open, ok)
	}
	for _, bad := range []string{"open-.jsonl", "open-20261005T221500.123456789Z.jsonl.gz", "open-20261005T221500.123456789Z-1.jsonl", "x.state.json"} {
		if _, ok := parseOpenName(bad); ok {
			t.Errorf("parseOpenName(%q) accepted", bad)
		}
		if _, ok := openOfState(bad); ok {
			t.Errorf("openOfState(%q) accepted", bad)
		}
	}
}

func TestDigester(t *testing.T) {
	a, b := msg(t0, "a"), msg(t0.Add(-time.Minute), "b") // the clock was set back
	content := append(append(lineOf(t, a), "not json\n"...), lineOf(t, b)...)
	d := newDigester()
	// Written in small pieces, as a stream would arrive.
	for i := 0; i < len(content); i += 7 {
		d.Write(content[i:min(i+7, len(content))])
	}
	dg := d.finish()
	if dg.bytes != int64(len(content)) || dg.sha != sha(content) || dg.partial != 0 {
		t.Fatalf("digest: %+v", dg)
	}
	s := dg.sum
	if s.messages != 3 || !s.timed || !s.first.Equal(t0) || !s.last.Equal(t0.Add(-time.Minute)) ||
		!s.min.Equal(t0.Add(-time.Minute)) || !s.max.Equal(t0) {
		t.Fatalf("summary: %+v", s)
	}

	// A last line without a line feed counts, and is reported.
	d = newDigester()
	d.Write([]byte("{\"rx\":\"2026-"))
	if dg := d.finish(); dg.sum.messages != 1 || dg.partial != 12 || dg.sum.timed {
		t.Fatalf("partial: %+v", dg)
	}
	// Nothing: no message, no time.
	if dg := newDigester().finish(); dg.sum.messages != 0 || dg.bytes != 0 || dg.sha != sha(nil) {
		t.Fatalf("empty: %+v", dg)
	}
	// A line longer than maxLine is a message without a time.
	d = newDigester()
	long := make([]byte, maxLine+10)
	for i := range long {
		long[i] = 'x'
	}
	d.Write(long)
	d.Write([]byte("\n"))
	d.Write(lineOf(t, a))
	if dg := d.finish(); dg.sum.messages != 2 || !dg.sum.first.Equal(t0) {
		t.Fatalf("long line: %+v", dg.sum)
	}
}

func TestEachLine(t *testing.T) {
	long := make([]byte, maxLine+1)
	for i := range long {
		long[i] = 'y'
	}
	mid := make([]byte, 100<<10) // longer than the reader's buffer, shorter than maxLine
	for i := range mid {
		mid[i] = 'm'
	}
	in := "a\n\nb\n" + string(long) + "\n" + string(mid) + "\nlast"
	var got []string
	collect := func(i int, line []byte) error {
		if line == nil {
			got = append(got, "<nil>")
		} else {
			got = append(got, string(line[:min(len(line), 4)]))
		}
		if len(got)-1 != i {
			t.Fatalf("index %d for line %d", i, len(got)-1)
		}
		return nil
	}
	if err := eachLine(strings.NewReader(in), true, collect); err != nil {
		t.Fatal(err)
	}
	want := []string{"a", "", "b", "<nil>", "mmmm", "last"}
	if !slices.Equal(got, want) {
		t.Fatalf("lines %q, want %q", got, want)
	}
	got = nil
	if err := eachLine(strings.NewReader(in), false, collect); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, want[:5]) {
		t.Fatalf("complete lines %q, want %q", got, want[:5])
	}
}
