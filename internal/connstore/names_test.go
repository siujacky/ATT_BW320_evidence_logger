package connstore

import (
	"testing"
	"time"
)

func TestFileNamesRoundTrip(t *testing.T) {
	d := dayOf(time.Date(2026, 10, 6, 13, 45, 0, 0, time.UTC))
	cases := []struct {
		k    kind
		gz   bool
		want string
	}{
		{kindNAT, false, "nat-2026-10-06.jsonl"},
		{kindNAT, true, "nat-2026-10-06.jsonl.gz"},
		{kindDevices, false, "devices-2026-10-06.jsonl"},
		{kindDevices, true, "devices-2026-10-06.jsonl.gz"},
	}
	for _, c := range cases {
		if got := fileName(c.k, d, c.gz); got != c.want {
			t.Errorf("fileName(%v, %s, %v) = %q, want %q", c.k, d, c.gz, got, c.want)
		}
		p, ok := parseFileName(c.want)
		if !ok || p.kind != c.k || p.day != d || p.gz != c.gz || p.tmp {
			t.Errorf("parseFileName(%q) = %+v, %v", c.want, p, ok)
		}
		if c.gz {
			p, ok := parseFileName(c.want + tmpExt)
			if !ok || p.kind != c.k || p.day != d || !p.gz || !p.tmp {
				t.Errorf("parseFileName(%q) = %+v, %v", c.want+tmpExt, p, ok)
			}
		}
	}
}

func TestParseFileNameLeavesOtherFilesAlone(t *testing.T) {
	for _, name := range []string{
		"", "last-nattable.html", "last-devices.html", "nat-", "nat-.jsonl",
		"nat-2026-10-06", "nat-2026-10-06.json", "nat-2026-10-06.jsonl.bak", "nat-2026-10-06.jsonl.tmp",
		"nat-2026-10-06.jsonl.gz.tmp.tmp", "nat-2026-10-06.jsonl.gz ", " nat-2026-10-06.jsonl",
		"nat-2026-10-6.jsonl", "nat-2026-13-01.jsonl", "nat-2026-02-30.jsonl", "nat-+026-10-06.jsonl",
		"nat-1999-12-31.jsonl", "nat-2200-01-01.jsonl", "NAT-2026-10-06.jsonl", "xnat-2026-10-06.jsonl",
		"device-2026-10-06.jsonl", "devices-2026-10-06.JSONL", "nat-2026-10-06.jsonl.GZ",
		"nat-2026-10-06T00.jsonl", "syslog-20261005T221500.123456789Z_20261005T221500.123456789Z.jsonl.gz",
	} {
		if p, ok := parseFileName(name); ok {
			t.Errorf("parseFileName(%q) = %+v, want not one of the store's names", name, p)
		}
	}
}

func TestDays(t *testing.T) {
	d := dayOf(time.Date(2026, 10, 6, 0, 0, 0, 0, time.UTC))
	cases := []struct {
		t    time.Time
		want day
	}{
		{time.Date(2026, 10, 6, 0, 0, 0, 0, time.UTC), d},
		{time.Date(2026, 10, 6, 23, 59, 59, 999999999, time.UTC), d},
		{time.Date(2026, 10, 5, 23, 59, 59, 999999999, time.UTC), d - 1},
		{time.Date(2026, 10, 7, 0, 0, 0, 0, time.UTC), d + 1},
		// Another time zone: the UTC day counts.
		{time.Date(2026, 10, 5, 20, 0, 0, 0, time.FixedZone("UTC-7", -7*3600)), d},
		{time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC), 0},
		{time.Date(1969, 12, 31, 23, 0, 0, 0, time.UTC), -1},
		{time.Date(1969, 12, 31, 0, 0, 0, 0, time.UTC), -1},
	}
	for _, c := range cases {
		if got := dayOf(c.t); got != c.want {
			t.Errorf("dayOf(%s) = %d, want %d", c.t, got, c.want)
		}
	}
	if got, want := d.start(), time.Date(2026, 10, 6, 0, 0, 0, 0, time.UTC); !got.Equal(want) {
		t.Errorf("start = %s, want %s", got, want)
	}
	if got, want := d.end(), time.Date(2026, 10, 7, 0, 0, 0, 0, time.UTC); !got.Equal(want) {
		t.Errorf("end = %s, want %s", got, want)
	}
	if got := d.String(); got != "2026-10-06" {
		t.Errorf("String = %q", got)
	}
}

func TestTimes(t *testing.T) {
	tm := time.Date(2026, 10, 6, 8, 0, 0, 123456789, time.FixedZone("UTC+2", 2*3600))
	s := formatTime(tm)
	if s != "2026-10-06T06:00:00.123456789Z" {
		t.Errorf("formatTime = %q", s)
	}
	if got, ok := parseTime(s); !ok || !got.Equal(tm) || got.Location() != time.UTC {
		t.Errorf("parseTime(%q) = %v, %v", s, got, ok)
	}
	for _, bad := range []string{"", "2026-10-06", "1999-12-31T23:59:59Z", "2200-01-01T00:00:00Z", "yesterday"} {
		if _, ok := parseTime(bad); ok {
			t.Errorf("parseTime(%q) accepted", bad)
		}
	}
}
