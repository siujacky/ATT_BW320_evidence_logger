package connstore

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"attmonitor/internal/contracts"
	"attmonitor/internal/model"
)

// The files are not trusted: an administrator, a disk error or another program may have changed
// them. Nothing read from them may crash the store or make a query fail.

// fuzzNATSeeds returns lines (without their line feed) to start the NAT fuzzers from.
func fuzzNATSeeds(f *testing.F) [][]byte {
	f.Helper()
	tables := []model.NATTable{
		{InUse: -1, Available: -1},
		{InUse: 3, Available: 8000, Display: "All", Skipped: 1, Sessions: []model.NATSession{
			tcp(10, 50000, "203.0.113.5", 443), udp(11, 40000, "198.51.100.7", 53),
			session("tcp", "203.0.113.9", 5000, lanIP(20), 8080), session("udp", gatewayIP, 33000, "192.0.2.1", 123),
			session("tcp", "fd00::7", 1, "2001:db8::1", 443), session("icmp", "bogus", -1, "", 70000),
		}},
	}
	var seeds [][]byte
	for _, nt := range tables {
		line, err := encodeNAT(at(0, 10, 0), nt)
		if err != nil {
			f.Fatal(err)
		}
		seeds = append(seeds, bytes.TrimSuffix(line, []byte("\n")))
	}
	seeds = append(seeds,
		[]byte(`{"t":"2026-10-05T10:00:00Z","strs":["tcp"],"s":[0,0,0,1,0,2,-1,5,9,0,0,0]}`),
		[]byte(`{"t":"2026-10-05T10:00:00Z","t":"2026-10-07T10:00:00Z","strs":[],"s":[]}`),
		[]byte(`{"t":"2026-10-05T10:00:00Z","strs":["`+strings.Repeat("9", 50)+`"],"s":[0,0,0,0,0,0]}`),
		[]byte(`{`), []byte(``), []byte(`null`),
		[]byte(`{"t":"2026-10-05T10:00:00Z","strs":[],"s":[-0,9223372036854775807,-9223372036854775808,1,2,3]}`),
		[]byte(`{"t":"2026-10-05T10:00:00Z","strs":[],"s":[9223372036854775808,1,2,3,4,5]}`),
		[]byte(`{"t":"2026-10-05T10:00:00Z","S":[1,2,3,4,5,6],"strs":[",\"s\":["],"s":[]}`),
		[]byte(`{,"s":[1,2,3,4,5,6]}`),
	)
	return seeds
}

func FuzzDecodeNAT(f *testing.F) {
	for _, s := range fuzzNATSeeds(f) {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, line []byte) {
		// The fast path gives what encoding/json gives, whenever it accepts a line.
		var fast, full natLine
		if decodeNATFast(line, &fast) {
			if err := json.Unmarshal(line, &full); err != nil {
				t.Fatalf("the fast path accepted a line encoding/json rejects: %v", err)
			}
			if fast.T != full.T || fast.InUse != full.InUse || fast.Available != full.Available ||
				fast.Display != full.Display || fast.Skipped != full.Skipped ||
				!slices.Equal(fast.Strs, full.Strs) || !slices.Equal(fast.S, full.S) {
				t.Fatalf("fast %+v\nfull %+v", fast, full)
			}
		}
		var l natLine
		tm, err := decodeNAT(line, &l)
		if err != nil {
			return
		}
		if !validTime(tm) || len(l.S)%sessionInts != 0 {
			t.Fatalf("decoded %v with %d integers", tm, len(l.S))
		}
		// Summarizing it never fails: every session counts, or is reported as bad.
		sc := newScanner(maxFlows)
		sc.line = l
		bad := sc.add(tm.UnixNano(), nil, nil)
		s := sc.finish()
		weight := 0
		for _, d := range s.devs {
			weight += d.weight
		}
		if s.reads != 1 || bad < 0 || weight != l.sessions()-bad || s.newest.open != l.sessions() {
			t.Fatalf("summary of %d sessions: %d bad, weight %d, %+v", l.sessions(), bad, weight, s)
		}
		// What it holds is stored again as the same read.
		nt, badIndexes := l.table()
		again, err := encodeNAT(tm, nt)
		if err != nil {
			if err == errLineTooLong {
				return
			}
			t.Fatal(err)
		}
		var l2 natLine
		tm2, err := decodeNAT(bytes.TrimSuffix(again, []byte("\n")), &l2)
		if err != nil || !tm2.Equal(tm) {
			t.Fatalf("re-encoded line: %v, %v", tm2, err)
		}
		nt2, bad2 := l2.table()
		if bad2 != 0 || len(nt2.Sessions)+badIndexes != l.sessions() {
			t.Fatalf("re-encoded line holds %d sessions (%d bad), want %d", len(nt2.Sessions), bad2, l.sessions()-badIndexes)
		}
		if pt, ok := peekTime(bytes.TrimSuffix(again, []byte("\n"))); !ok || !pt.Equal(tm) {
			t.Fatalf("peekTime of a line the store wrote = %v, %v", pt, ok)
		}
	})
}

func FuzzDecodeDevices(f *testing.F) {
	line, err := encodeDevices(at(0, 9, 0), []model.LANDevice{
		device(10, 1, "test-laptop", "Wi-Fi"),
		{MAC: "00-00-5E-00-53-07", IPv4: "bogus", IPv6: []string{"fd00::7/64", "fe80::7%3", "x"}, Status: "on"},
		{MAC: macOf(3), IPv4: lanIP(10), Status: "off"},
	})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(bytes.TrimSuffix(line, []byte("\n")))
	f.Add([]byte(`{"t":"2026-10-05T09:00:00Z","devices":[{"mac":"zz","ipv4":"192.168.1.1","ipv6":["::"]}]}`))
	f.Add([]byte(`{"t":"2026-10-05T09:00:00Z","devices":null}`))
	f.Fuzz(func(t *testing.T, line []byte) {
		tm, devices, err := decodeDevices(line)
		if err != nil {
			return
		}
		r := newDevRead(tm, hashLine(line), devices, map[identity]*identity{})
		for i, e := range r.addrs {
			if i > 0 && r.addrs[i-1].addr.Compare(e.addr) >= 0 {
				t.Fatalf("addresses not sorted and unique: %v", r.addrs)
			}
			if r.lookup(e.addr) != e.id {
				t.Fatalf("lookup(%s) does not find its entry", e.addr)
			}
			if !strings.HasPrefix(e.id.key, "mac:") && e.id.key != "ip:"+e.addr.String() {
				t.Fatalf("key %q of %s", e.id.key, e.addr)
			}
		}
	})
}

func FuzzParseFileName(f *testing.F) {
	for _, s := range []string{"nat-2026-10-06.jsonl", "devices-2026-10-06.jsonl.gz", "nat-2026-10-06.jsonl.gz.tmp",
		"last-nattable.html", "nat-2026-02-29.jsonl", "nat-2028-02-29.jsonl"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, name string) {
		p, ok := parseFileName(name)
		if !ok {
			return
		}
		want := fileName(p.kind, p.day, p.gz)
		if p.tmp {
			want += tmpExt
		}
		if want != name {
			t.Fatalf("parseFileName(%q) = %+v, which names %q", name, p, want)
		}
	})
}

func FuzzEachLine(f *testing.F) {
	for _, s := range []string{"", "\n", "a\nb", "a\nb\n", "\n\n\r\n", "no line feed"} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, content []byte) {
		var got [][]byte
		if err := eachLine(bytes.NewReader(content), func(line []byte) error {
			got = append(got, bytes.Clone(line))
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		end := bytes.LastIndexByte(content, '\n') + 1
		var want [][]byte
		if end > 0 {
			want = bytes.Split(content[:end-1], []byte("\n"))
		}
		if len(got) != len(want) {
			t.Fatalf("%d lines, want %d", len(got), len(want))
		}
		for i := range got {
			if !bytes.Equal(got[i], want[i]) {
				t.Fatalf("line %d = %q, want %q", i, got[i], want[i])
			}
		}
	})
}

// FuzzDayFile stores arbitrary bytes as a day's NAT file and a day's Device List file, opens the
// store and queries it: Open and Aggregate must succeed, with a consistent result.
func FuzzDayFile(f *testing.F) {
	seeds := fuzzNATSeeds(f)
	var good []byte
	for _, s := range seeds[:2] {
		good = append(good, s...)
		good = append(good, '\n')
	}
	dev, _ := encodeDevices(at(0, 9, 0), []model.LANDevice{device(10, 1, "test-laptop", "")})
	f.Add(good, dev, false)
	f.Add(append(bytes.Clone(good), `{"t":"2026-10-05T11:00:00Z","strs":[`...), dev, true)
	f.Add([]byte("\x00\xff\n\n{}\n"), []byte("{\n"), false)
	f.Fuzz(func(t *testing.T, nat, devices []byte, gz bool) {
		dir := t.TempDir()
		write := func(k kind, content []byte) {
			path := filepath.Join(dir, fileName(k, dayOf(day0), gz))
			if gz {
				if _, _, err := writeGzip(path, func(w io.Writer) error { _, err := w.Write(content); return err }); err != nil {
					t.Fatal(err)
				}
				return
			}
			if err := os.WriteFile(path, content, 0o644); err != nil {
				t.Fatal(err)
			}
		}
		write(kindNAT, nat)
		write(kindDevices, devices)
		clk := newClock(at(0, 12, 0))
		s, err := Open(dir, Options{Now: clk.Now})
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		defer s.Close()
		for _, q := range []contracts.ConnQuery{{}, {From: at(0, 10, 0), To: at(0, 10, 30)}, {Device: macKey(1)}} {
			a, err := s.Aggregate(context.Background(), q)
			if err != nil {
				t.Fatalf("Aggregate: %v", err)
			}
			if p := consistent(a); len(p) > 0 {
				t.Fatalf("inconsistent: %v", p)
			}
		}
		// The day is a past day from here on: its summary goes through the cache, twice.
		clk.Set(at(1, 12, 0))
		a, err := s.Aggregate(context.Background(), contracts.ConnQuery{})
		if err != nil {
			t.Fatal(err)
		}
		b, err := s.Aggregate(context.Background(), contracts.ConnQuery{})
		if err != nil || !reflect.DeepEqual(a, b) {
			t.Fatalf("the cached day differs: %v", err)
		}
		s.Usage()
		s.Devices()
		if err := s.AppendNAT(at(1, 12, 0), model.NATTable{}); err != nil {
			t.Fatalf("AppendNAT after a damaged day: %v", err)
		}
	})
}
