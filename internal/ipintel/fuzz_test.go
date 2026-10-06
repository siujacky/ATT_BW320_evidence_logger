package ipintel

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"unicode/utf8"
)

// FuzzParseTable checks that no table content makes the parser panic, and that a table it
// accepts is consistent: sorted, not overlapping, each range found by its first and last
// address (table files are downloaded: untrusted input). The seed corpus runs with every "go
// test"; fuzz with go test -run=^$ -fuzz=FuzzParseTable ./internal/ipintel/
func FuzzParseTable(f *testing.F) {
	var b strings.Builder
	for _, r := range rows4 {
		b.WriteString(r.line() + "\n")
	}
	f.Add([]byte(b.String()))
	b.Reset()
	for _, r := range rows6 {
		b.WriteString(r.line() + "\r\n")
	}
	f.Add([]byte(b.String()))
	f.Add([]byte("1.0.0.0\t1.0.0.255\t13335\tUS\tCLOUDFLARENET\n1.0.1.0\t1.0.1.255\t13335\tUS\tCLOUDFLARENET\n"))
	f.Add([]byte("255.255.255.0\t255.255.255.255\t1\tUS\tEND"))
	f.Add([]byte("ffff:ffff:ffff:ffff:ffff:ffff:ffff:fff0\tffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff\t1\tUS\tEND"))
	f.Add([]byte("::\t::ffff:ffff:ffff\t1\tZZ\tx\n# comment\n\n"))
	f.Add([]byte("1.0.0.0\t1.0.0.255\tAS1\tus\t\xff\x00\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		checkParsed(t, data, spec4)
		checkParsed(t, data, spec6)
	})
}

func checkParsed[K any](t *testing.T, data []byte, sp *famSpec[K]) {
	tb, st, err := parseTable(context.Background(), bytes.NewReader(data), sp)
	if err != nil {
		return
	}
	if st.routed == 0 || st.routed > st.rows || tb.size() == 0 || tb.size() > st.routed {
		t.Fatalf("%s: stats %+v, %d ranges", sp.name, st, tb.size())
	}
	if len(tb.end) != tb.size() || len(tb.info) != tb.size() {
		t.Fatalf("%s: slices of different lengths", sp.name)
	}
	for i := range tb.size() {
		if sp.compare(tb.start[i], tb.end[i]) > 0 {
			t.Fatalf("%s: range %d ends before it starts", sp.name, i)
		}
		if i > 0 && sp.compare(tb.start[i], tb.end[i-1]) <= 0 {
			t.Fatalf("%s: ranges %d and %d overlap or are not sorted", sp.name, i-1, i)
		}
		idx := int(tb.info[i])
		if idx >= len(tb.infos) || len(tb.orgs) != len(tb.infos) {
			t.Fatalf("%s: range %d has no info", sp.name, i)
		}
		if tb.find(tb.start[i], sp.compare) != idx || tb.find(tb.end[i], sp.compare) != idx {
			t.Fatalf("%s: range %d is not found by its ends", sp.name, i)
		}
		in, org := tb.infos[idx], tb.org(idx)
		if in.asn == 0 || !utf8.ValidString(in.name) || !utf8.ValidString(org) || org == "" ||
			(in.country != "" && len(in.country) != 2) || org != tb.org(idx) {
			t.Fatalf("%s: info %+v, org %q", sp.name, in, org)
		}
	}
}

// FuzzPrettyOrg checks that any AS description gives a name without panic, deterministically,
// in valid UTF-8, trimmed and within maxOrgRunes.
func FuzzPrettyOrg(f *testing.F) {
	for _, s := range []string{"WPL-AS-AP Wirefreebroadband Pty Ltd", "CLOUDFLARENET", "AS-ENECOM Energia Communications,Inc.",
		"TOT-NET TOT PUBLIC COMPANY LIMITED", "Example S. de R.L. de C.V.", ", , ,", "-AS-", "ÉÉÉ É", "A" + string(utf8.RuneError) + "B",
		strings.Repeat("WORD ", 40)} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, desc string) {
		desc = cleanName([]byte(desc)) // what the parser hands it
		got := prettyOrg(desc)
		if got != prettyOrg(desc) {
			t.Fatalf("prettyOrg(%q) is not deterministic", desc)
		}
		if !utf8.ValidString(got) || utf8.RuneCountInString(got) > maxOrgRunes || strings.TrimSpace(got) != got {
			t.Fatalf("prettyOrg(%q) = %q", desc, got)
		}
		if strings.TrimSpace(desc) != "" && orgName(64496, desc) == "" {
			t.Fatalf("orgName(%q) is empty", desc)
		}
	})
}

// FuzzSanitizePTR checks that a reverse DNS name either passes, in the allowed form, or is
// dropped (the names come from whoever controls the address's reverse zone).
func FuzzSanitizePTR(f *testing.F) {
	for _, s := range []string{"dns.google.", "a..b", ".", "", "x y", strings.Repeat("a", 300), "Ok-Name_1.test."} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		got := sanitizePTR(s)
		if got == "" {
			return
		}
		if len(got) > maxPTRName || strings.HasPrefix(got, ".") || strings.HasSuffix(got, ".") ||
			strings.Contains(got, "..") || strings.ToLower(got) != got || sanitizePTR(got) != got {
			t.Fatalf("sanitizePTR(%q) = %q", s, got)
		}
		for _, c := range []byte(got) {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.' || c == '-' || c == '_') {
				t.Fatalf("sanitizePTR(%q) = %q", s, got)
			}
		}
	})
}
