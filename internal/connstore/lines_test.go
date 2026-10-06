package connstore

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"attmonitor/internal/model"
)

func TestNATLineRoundTrip(t *testing.T) {
	tm := time.Date(2026, 10, 6, 8, 0, 0, 123456789, time.UTC)
	cases := []struct {
		name string
		nat  model.NATTable
	}{
		{"empty", model.NATTable{InUse: -1, Available: -1}},
		{"typical", model.NATTable{InUse: 3, Available: 8189, Sessions: []model.NATSession{
			tcp(10, 50000, "203.0.113.5", 443), tcp(10, 50001, "203.0.113.5", 443), udp(11, 40000, "198.51.100.7", 53),
		}}},
		{"display, skipped and unusual values", model.NATTable{InUse: 2, Available: 0, Display: "All Sessions", Skipped: 4,
			Sessions: []model.NATSession{
				{Proto: "TCP", State: "TIME_WAIT", Src: lanIP(12), SrcPort: 0, Dst: "2001:db8::5", DstPort: 70000},
				{Proto: "icmp", Src: lanIP(12), Dst: "192.0.2.9", SrcPort: -1},
				{Proto: `we"ird<&>`, State: "ünïcode", Src: "not an address", Dst: ""},
			}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			line, err := encodeNAT(tm, c.nat)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.HasPrefix(line, []byte(timePrefix)) || !bytes.HasSuffix(line, []byte("\n")) || bytes.Count(line, []byte("\n")) != 1 {
				t.Fatalf("line %q is not one line beginning with its time", line)
			}
			body := line[:len(line)-1]
			if pt, ok := peekTime(body); !ok || !pt.Equal(tm) {
				t.Errorf("peekTime = %v, %v", pt, ok)
			}
			var l natLine
			got, err := decodeNAT(body, &l)
			if err != nil || !got.Equal(tm) {
				t.Fatalf("decodeNAT = %v, %v", got, err)
			}
			nt, bad := l.table()
			want := c.nat
			if want.Sessions == nil {
				want.Sessions = []model.NATSession{}
			}
			if bad != 0 || !reflect.DeepEqual(nt, want) {
				t.Errorf("table = %+v (bad %d), want %+v", nt, bad, want)
			}
		})
	}
}

func TestNATLineIsCompact(t *testing.T) {
	// Each distinct string is stored once.
	nat := model.NATTable{InUse: 2, Available: 1}
	for i := range 50 {
		nat.Sessions = append(nat.Sessions, tcp(10, 50000+i, "203.0.113.5", 443))
	}
	line, err := encodeNAT(day0, nat)
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(line), "203.0.113.5"); n != 1 {
		t.Errorf("the remote address appears %d times in %s", n, line)
	}
}

func TestDecodeNATRejectsDamagedLines(t *testing.T) {
	good := `{"t":"2026-10-06T08:00:00Z","in_use":1,"available":2,"strs":["tcp","","192.168.1.10","203.0.113.5"],"s":[0,1,2,50000,3,443]}`
	var l natLine
	if _, err := decodeNAT([]byte(good), &l); err != nil {
		t.Fatalf("the good line: %v", err)
	}
	for _, bad := range []string{
		``, `{`, `[]`, `null`, `{"t":"x"}`, `{"in_use":1}`, `{"t":"1999-12-31T00:00:00Z","strs":[],"s":[]}`,
		`{"t":"2026-10-06T08:00:00Z","strs":[],"s":[0,1,2,3,4]}`,
		`{"t":"2026-10-06T08:00:00Z","strs":[],"s":[0,1,2,3,4,5.5]}`,
		`{"t":"2026-10-06T08:00:00Z","strs":[1],"s":[]}`,
		`{"t":"2026-10-06T08:00:00Z","strs":[],"s":[0,1,2,3,4,1e30]}`,
		strings.Replace(good, `"s":[`, `"s":"`, 1),
		good[:len(good)-5],
	} {
		if _, err := decodeNAT([]byte(bad), &l); err == nil {
			t.Errorf("decodeNAT(%q) accepted", bad)
		}
	}
	// A decoded line reuses the slices it was given and forgets what a longer line held.
	if _, err := decodeNAT([]byte(good), &l); err != nil {
		t.Fatal(err)
	}
	short := `{"t":"2026-10-06T08:00:00Z","strs":[],"s":[]}`
	if _, err := decodeNAT([]byte(short), &l); err != nil || len(l.Strs) != 0 || len(l.S) != 0 || l.InUse != 0 {
		t.Errorf("after a short line: %+v, %v", l, err)
	}
}

func TestNATSessionWithIndexOutsideTheTable(t *testing.T) {
	line := `{"t":"2026-10-06T08:00:00Z","in_use":2,"available":2,"strs":["tcp","","192.168.1.10","203.0.113.5"],"s":[0,1,2,50000,3,443,0,1,2,50001,9,443,-1,1,2,3,3,4]}`
	var l natLine
	if _, err := decodeNAT([]byte(line), &l); err != nil {
		t.Fatal(err)
	}
	nt, bad := l.table()
	if bad != 2 || len(nt.Sessions) != 1 || nt.Sessions[0].Dst != "203.0.113.5" {
		t.Errorf("table = %+v, bad %d", nt, bad)
	}
}

func TestDevicesLineRoundTrip(t *testing.T) {
	tm := time.Date(2026, 10, 6, 8, 15, 0, 5, time.UTC)
	devices := []model.LANDevice{
		device(10, 1, "test-laptop", "Wi-Fi 5 GHz"),
		{MAC: macOf(2), Name: "test-phone", IPv4: lanIP(11), IPv6: []string{"fe80::2", "2001:db8::11"}, Status: "off",
			Allocation: "static", Connection: "Ethernet", Speed: "1000 Mbps", Mesh: true, LastActivity: "Mon Oct 5 21:00:00 2026"},
	}
	for _, in := range [][]model.LANDevice{devices, nil, {}} {
		line, err := encodeDevices(tm, in)
		if err != nil {
			t.Fatal(err)
		}
		body := bytes.TrimSuffix(line, []byte("\n"))
		if pt, ok := peekTime(body); !ok || !pt.Equal(tm) {
			t.Errorf("peekTime = %v, %v", pt, ok)
		}
		got, out, err := decodeDevices(body)
		want := in
		if want == nil {
			want = []model.LANDevice{}
		}
		if err != nil || !got.Equal(tm) || !reflect.DeepEqual(out, want) {
			t.Errorf("decodeDevices = %v, %+v, %v; want %+v", got, out, err, want)
		}
	}
	for _, bad := range []string{``, `{`, `{"devices":[]}`, `{"t":"2026-10-06T08:00:00Z","devices":{}}`, `{"t":"nope","devices":[]}`} {
		if _, _, err := decodeDevices([]byte(bad)); err == nil {
			t.Errorf("decodeDevices(%q) accepted", bad)
		}
	}
}

func TestEncodeRefusesHugeLines(t *testing.T) {
	_, err := encodeDevices(day0, []model.LANDevice{{Name: strings.Repeat("x", maxLine)}})
	if !errors.Is(err, errLineTooLong) {
		t.Errorf("encodeDevices of a huge read: %v", err)
	}
}

func TestPeekTime(t *testing.T) {
	cases := []struct {
		line string
		ok   bool
	}{
		{`{"t":"2026-10-06T08:00:00.5Z","s":[]}`, true},
		{`{"t":"2026-10-06T08:00:00Z"`, true},
		{`{"t" :"2026-10-06T08:00:00Z"}`, false}, // not as the store writes it (a reader decodes it)
		{` {"t":"2026-10-06T08:00:00Z"}`, false},
		{`{"t":"2026-10-06T08:00:00Z`, false},
		{`{"t":"not a time"}`, false},
		{`{"t":"1999-10-06T08:00:00Z"}`, false},
		{`{"t":"` + strings.Repeat("9", 100) + `"}`, false},
		{``, false},
	}
	for _, c := range cases {
		if _, ok := peekTime([]byte(c.line)); ok != c.ok {
			t.Errorf("peekTime(%q) ok = %v, want %v", c.line, ok, c.ok)
		}
	}
}

func TestEachLine(t *testing.T) {
	long := strings.Repeat("a", maxLine+1)
	medium := strings.Repeat("b", 300<<10) // longer than the reader's buffer
	content := "one\n\ntwo\n" + medium + "\n" + long + "\nthree\npartial"
	var got []string
	err := eachLine(strings.NewReader(content), func(line []byte) error {
		if line == nil {
			got = append(got, "<nil>")
		} else {
			got = append(got, string(line))
		}
		return nil
	})
	want := []string{"one", "", "two", medium, "<nil>", "three"}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Errorf("eachLine = %d lines %v, want %d", len(got), err, len(want))
	}
	stop := errors.New("stop")
	n := 0
	err = eachLine(strings.NewReader("a\nb\nc\n"), func([]byte) error {
		n++
		if n == 2 {
			return stop
		}
		return nil
	})
	if !errors.Is(err, stop) || n != 2 {
		t.Errorf("eachLine with a stop: %v after %d lines", err, n)
	}
}

func TestAppendInts(t *testing.T) {
	cases := []struct {
		in   string
		want []int
		ok   bool
	}{
		{"", nil, true},
		{"0", []int{0}, true},
		{"-0", []int{0}, true},
		{"1,22,-333,65535", []int{1, 22, -333, 65535}, true},
		{"9223372036854775807,-9223372036854775808", []int{9223372036854775807, -9223372036854775808}, true},
		{"9223372036854775808", nil, false},
		{"-9223372036854775809", nil, false},
		{"12345678901234567890", nil, false},
		{"01", nil, false},
		{"-01", nil, false},
		{"1.0", nil, false},
		{"1e3", nil, false},
		{"+1", nil, false},
		{"1,", nil, false},
		{",1", nil, false},
		{"1,,2", nil, false},
		{"1, 2", nil, false},
		{"-", nil, false},
		{"--1", nil, false},
		{"0x10", nil, false},
	}
	for _, c := range cases {
		got, ok := appendInts(nil, []byte(c.in))
		if ok != c.ok || ok && !slices.Equal(got, c.want) {
			t.Errorf("appendInts(%q) = %v, %v; want %v, %v", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestDecodeNATFastPath(t *testing.T) {
	// Lines the store writes take the fast path; others are decoded by encoding/json alone.
	line, err := encodeNAT(day0, model.NATTable{InUse: 1, Available: 2, Sessions: []model.NATSession{tcp(10, 1, "203.0.113.5", 443)}})
	if err != nil {
		t.Fatal(err)
	}
	body := bytes.TrimSuffix(line, []byte("\n"))
	var l natLine
	if !decodeNATFast(body, &l) || l.T != rfc(day0) || len(l.S) != 6 || l.InUse != 1 {
		t.Errorf("a line the store wrote: %+v", l)
	}
	for _, other := range []string{
		`{"t":"2026-10-05T00:00:00Z","s":[1,2,3,4,5,6],"strs":[]}`,  // the sessions are not last
		`{"t":"2026-10-05T00:00:00Z","strs":[],"s":[1,2,3,4,5,6] }`, // a space at the end
		`{"t":"2026-10-05T00:00:00Z","strs":[],"s":[1, 2,3,4,5,6]}`, // a space between integers
		`{"t":"2026-10-05T00:00:00Z","strs":[],"s":[1,2,3,4,5,6.5]}`,
		`{,"s":[1,2,3,4,5,6]}`,
		`{ ,"s":[]}`,
		`{"t":"2026-10-05T00:00:00Z","strs":[,"s":[]}`, // the text before is not JSON
	} {
		var l natLine
		if decodeNATFast([]byte(other), &l) {
			t.Errorf("decodeNATFast(%q) accepted", other)
		}
	}
	// Taken or not, decodeNAT gives encoding/json's result.
	var a, b natLine
	other := []byte(`{"t":"2026-10-05T00:00:00Z","s":[1,2,3,4,5,6],"strs":["x"]}`)
	if _, err := decodeNAT(other, &a); err != nil || len(a.S) != 6 || len(a.Strs) != 1 {
		t.Errorf("decodeNAT of a line with its members in another order: %+v, %v", a, err)
	}
	if err := json.Unmarshal(other, &b); err != nil || !slices.Equal(a.S, b.S) || !slices.Equal(a.Strs, b.Strs) {
		t.Errorf("decodeNAT differs from encoding/json: %+v %+v", a, b)
	}
}
