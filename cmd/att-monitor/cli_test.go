package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestReorderArgs(t *testing.T) {
	cases := []struct {
		in    []string
		bools []string
		want  []string
	}{
		{[]string{"called AT&T", "--author", "Alex"}, nil, []string{"--author", "Alex", "called AT&T"}},
		{[]string{"--author=Alex", "note text"}, nil, []string{"--author=Alex", "note text"}},
		{[]string{"bundle.zip", "--json"}, []string{"json"}, []string{"--json", "bundle.zip"}},
		{[]string{"--json", "bundle.zip"}, []string{"json"}, []string{"--json", "bundle.zip"}},
		{[]string{"b.zip", "--expect-fingerprint", "abcd", "--json"}, []string{"json"}, []string{"--expect-fingerprint", "abcd", "--json", "b.zip"}},
		{[]string{"--", "--not-a-flag"}, nil, []string{"--not-a-flag"}},
		{[]string{"-", "x"}, nil, []string{"-", "x"}},
	}
	for _, c := range cases {
		if got := reorderArgs(c.in, c.bools...); !reflect.DeepEqual(got, c.want) {
			t.Errorf("reorderArgs(%q, %q) = %q, want %q", c.in, c.bools, got, c.want)
		}
	}
}

func TestParseWhen(t *testing.T) {
	loc := time.Local
	cases := []struct {
		in   string
		want time.Time
	}{
		{"2026-10-05", time.Date(2026, 10, 5, 0, 0, 0, 0, loc)},
		{"2026-10-05T14:30", time.Date(2026, 10, 5, 14, 30, 0, 0, loc)},
		{"2026-10-05 14:30", time.Date(2026, 10, 5, 14, 30, 0, 0, loc)},
		{"2026-10-05T03:14:31Z", time.Date(2026, 10, 5, 3, 14, 31, 0, time.UTC)},
	}
	for _, c := range cases {
		got, err := parseWhen(c.in)
		if err != nil || !got.Equal(c.want) {
			t.Errorf("parseWhen(%q) = %v, %v; want %v", c.in, got, err, c.want)
		}
	}
	if _, err := parseWhen("yesterday"); err == nil {
		t.Error("expected error for unparseable time")
	}
}

func TestPctFloorNeverRoundsUp(t *testing.T) {
	for v, want := range map[float64]string{
		100: "100%", 99.99999: "99.999%", 99.9996: "99.999%", 50.12345: "50.123%", 0.0004: "< 0.001%", 0: "0.000%",
	} {
		if got := pctFloor(v); got != want {
			t.Errorf("pctFloor(%v) = %q, want %q", v, got, want)
		}
	}
}

func TestIsDateOnly(t *testing.T) {
	for s, want := range map[string]bool{
		"2026-10-31": true, " 2026-10-31 ": true, "2026-10-31T23:59": false, "2026-10-31T00:00:00Z": false, "x": false,
	} {
		if got := isDateOnly(s); got != want {
			t.Errorf("isDateOnly(%q) = %v, want %v", s, got, want)
		}
	}
}

// TestMongoCommand: usage errors, and a data directory whose configuration disables the MongoDB
// copy is reported as such (never a connection attempt to some default server).
func TestMongoCommand(t *testing.T) {
	if err := run([]string{"mongo"}); err == nil || !strings.Contains(err.Error(), "usage: att-monitor mongo") {
		t.Errorf("no subcommand: %v", err)
	}
	if err := run([]string{"mongo", "drop"}); err == nil || !strings.Contains(err.Error(), `unknown mongo command "drop"`) {
		t.Errorf("unknown subcommand: %v", err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(`{"version":1,"mongo":{"enabled":false}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"mongo", "verify", "--data", dir}); err == nil || !strings.Contains(err.Error(), "not enabled") {
		t.Errorf("disabled copy: %v", err)
	}
}
