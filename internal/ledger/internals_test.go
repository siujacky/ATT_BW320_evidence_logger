package ledger

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"attmonitor/internal/model"
)

func TestLineReader(t *testing.T) {
	cases := []struct {
		name  string
		input string
		max   int
		want  []lineRec // data, start, n, complete, tooLong
	}{
		{"empty", "", 100, nil},
		{"one line", "abc\n", 100, []lineRec{{data: []byte("abc\n"), start: 0, n: 4, complete: true}}},
		{"partial tail", "abc\nde", 100, []lineRec{
			{data: []byte("abc\n"), n: 4, complete: true},
			{data: []byte("de"), start: 4, n: 2},
		}},
		{"empty lines", "\n\n", 100, []lineRec{
			{data: []byte("\n"), n: 1, complete: true},
			{data: []byte("\n"), start: 1, n: 1, complete: true},
		}},
		{"too long then normal", strings.Repeat("x", 50) + "\nok\n", 10, []lineRec{
			{start: 0, n: 51, complete: true, tooLong: true},
			{data: []byte("ok\n"), start: 51, n: 3, complete: true},
		}},
		{"longer than the buffer", strings.Repeat("y", 40) + "\n", 100, []lineRec{
			{data: []byte(strings.Repeat("y", 40) + "\n"), n: 41, complete: true},
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			lr := newLineReader(strings.NewReader(tc.input), 16) // bufio minimum: forces ErrBufferFull
			lr.max = tc.max
			var got []lineRec
			for {
				rec, err := lr.next()
				if errors.Is(err, io.EOF) {
					break
				}
				if err != nil {
					t.Fatal(err)
				}
				rec.data = bytes.Clone(rec.data)
				got = append(got, rec)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("got %d lines, want %d", len(got), len(tc.want))
			}
			for i, w := range tc.want {
				g := got[i]
				if !bytes.Equal(g.data, w.data) && !(len(g.data) == 0 && len(w.data) == 0) ||
					g.start != w.start || g.n != w.n || g.complete != w.complete || g.tooLong != w.tooLong {
					t.Fatalf("line %d = %+v, want %+v", i, g, w)
				}
			}
		})
	}
}

func TestCompleteSizeAndLastLine(t *testing.T) {
	long := strings.Repeat("z", 200000) // spans several 64 KiB chunks
	cases := []struct {
		in       string
		complete int64
		last     string
	}{
		{"", 0, ""},
		{"no newline", 0, ""},
		{"a\n", 2, "a\n"},
		{"a\nb\n", 4, "b\n"},
		{"a\nb\npartial", 4, "b\n"},
		{"a\n" + long + "\n", int64(len(long) + 3), long + "\n"},
		{long + "\nx", int64(len(long) + 1), long + "\n"},
	}
	for _, tc := range cases {
		r := strings.NewReader(tc.in)
		n, err := completeSize(r, int64(len(tc.in)))
		if err != nil || n != tc.complete {
			t.Fatalf("completeSize(%.20q) = %d, %v", tc.in, n, err)
		}
		line, _, ok, err := lastCompleteLine(r, int64(len(tc.in)))
		if err != nil || ok != (tc.last != "") || string(line) != tc.last {
			t.Fatalf("lastCompleteLine(%.20q) = %.20q %v %v", tc.in, line, ok, err)
		}
	}
}

func TestParseEnvelopeStrict(t *testing.T) {
	good := `{"h":"aa","s":"bb","b":"{\"v\":1}"}`
	cases := []struct {
		line string
		want string // "" = accepted
	}{
		{good + "\n", ""},
		{good + " \r\n", ""},
		{`{"b":"x","s":"y","h":"z"}`, ""}, // order is not significant
		{`{"h":"aa","s":"bb"}`, "missing"},
		{`{"h":"aa","s":"bb","b":"x","b":"y"}`, "duplicate"},
		{`{"h":"aa","s":"bb","B":"x"}`, "unexpected key"},
		{`{"h":"aa","s":"bb","b":"x","x":1}`, "unexpected key"},
		{`{"h":1,"s":"bb","b":"x"}`, "not a string"},
		{`{"h":"aa","s":"bb","b":"x"} {}`, "trailing"},
		{`{"h":"aa","s":"bb","b":"x"}x`, "trailing"},
		{`["h"]`, "not a JSON object"},
		{`{"h":"aa","s":"bb","b":"x"`, "not valid JSON"},
		{`{"h":"aa","s":"bb","b":"x}`, "unterminated string"},
		{`{"h" "aa","s":"bb","b":"x"}`, "expected ':'"},
		{`{"h":"aa" "s":"bb","b":"x"}`, "unterminated object"},
		{`{"h":"a` + bs + `qa","s":"bb","b":"x"}`, "not valid JSON"},     // invalid escape
		{`{"h":"a` + "\x01" + `a","s":"bb","b":"x"}`, "not valid JSON"},  // raw control character
		{`{"` + bs + `u0068":"aa","s":"bb","b":"x"}`, "unexpected key"},  // escaped spelling of "h"
		{`{"h":"aa","s":"bb","b":"x` + bs + `"}`, "unterminated string"}, // escaped closing quote
		{`{}`, "missing"},
		{"", "not JSON"},
		{"   \n", "not JSON"},
		{"\x00\x00", "not a JSON object"},
	}
	for _, tc := range cases {
		_, err := parseEnvelopeStrict([]byte(tc.line))
		if tc.want == "" && err != nil {
			t.Fatalf("%q rejected: %v", tc.line, err)
		}
		if tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)) {
			t.Fatalf("%q: err = %v, want %q", tc.line, err, tc.want)
		}
	}
	// JSON escapes in b (built at run time) are decoded, including a surrogate pair.
	line := `{"h":"aa","s":"bb","b":"line` + bs + `u2028sep ` + bs + `ud83d` + bs + `ude00 ` + bs + `"q` + bs + `""}`
	env, err := parseEnvelopeStrict([]byte(line))
	want := "line" + string(rune(0x2028)) + "sep " + string(rune(0x1F600)) + ` "q"`
	if err != nil || env.B != want {
		t.Fatalf("unescape %q, %v", env.B, err)
	}
}

// bs is a single backslash, used to build JSON escapes at run time.
var bs = string(rune(0x5c))

func TestQuickSeqTSFallsBack(t *testing.T) {
	for _, line := range []string{
		``,
		`{"h":"x","s":"y","b":"{\"seq\":3}"}`, // field order differs
		`{"h":"x","s":"y","b":"{\"v\":1,\"seq\":,\"prev\""}`, // no digits
		`{"h":"x","s":"y","b":"{\"v\":1,\"seq\":5,\"prev\":\"short\"}"}`,
	} {
		if _, _, ok := quickSeqTS([]byte(line)); ok {
			t.Fatalf("quickSeqTS accepted %q", line)
		}
	}
}

func TestSegmentNames(t *testing.T) {
	for in, want := range map[string]string{
		"ledger-2026-10-05":          "ledger-2026-10-05",
		"ledger-2026-10-05.jsonl":    "ledger-2026-10-05",
		"ledger-2026-10-05.jsonl.gz": "ledger-2026-10-05",
		"ledger-2026-1-05":           "",
		"ledger-2026-02-30":          "",
		"Ledger-2026-10-05":          "",
		"ledger-2026-10-05.txt":      "",
		"x":                          "",
	} {
		name, _, ok := parseSegmentName(in)
		if ok != (want != "") || name != want {
			t.Fatalf("parseSegmentName(%q) = %q %v", in, name, ok)
		}
	}
	dir := t.TempDir()
	for _, f := range []string{"ledger-2026-10-07.jsonl", "ledger-2026-10-05.jsonl.gz", "ledger-2026-10-06.jsonl",
		"ledger-2026-10-06.jsonl.gz", ".lock", "ledger-2026-10-08.jsonl.tmp", "notes.txt"} {
		os.WriteFile(filepath.Join(dir, f), nil, 0o644)
	}
	os.Mkdir(filepath.Join(dir, "ledger-2026-10-09.jsonl"), 0o755) // a directory is ignored
	files, err := listSegmentFiles(dir)
	if err != nil || len(files) != 3 {
		t.Fatalf("files %+v %v", files, err)
	}
	if files[0].Name != "ledger-2026-10-05" || !files[0].compressed() ||
		files[1].Name != "ledger-2026-10-06" || files[1].compressed() || files[1].Gz == "" ||
		files[2].Name != "ledger-2026-10-07" || files[2].compressed() {
		t.Fatalf("files %+v", files)
	}
	if segmentName(time.Date(2026, 10, 5, 23, 59, 59, 0, time.FixedZone("CDT", -5*3600))) != "ledger-2026-10-06" {
		t.Fatal("segment names use the UTC date")
	}
}

func TestLargeRecordsVerify(t *testing.T) {
	s, _, clk := newLedger(t)
	big := strings.Repeat("0123456789abcdef", 200000) // 3.2 MB payload: several batches by size
	for i := 0; i < 3; i++ {
		clk.Advance(time.Second)
		mustAppend(t, s, model.TypeOperatorNote, model.OperatorNote{Text: big, Source: "cli"})
	}
	appendSamples(t, s, clk, 100, time.Second)
	rep, err := s.Verify(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	requireOK(t, rep)
	if rep.Records != 104 {
		t.Fatalf("records %d", rep.Records)
	}
}
