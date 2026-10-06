package ipintel

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"
)

// parse4 parses a decompressed IPv4 table.
func parse4(t *testing.T, lines ...string) (*table[uint32], tableStats, error) {
	t.Helper()
	return parseTable(context.Background(), strings.NewReader(strings.Join(lines, "\n")), spec4)
}

func TestParseTableIPv4(t *testing.T) {
	lines := make([]string, len(rows4))
	for i, r := range rows4 {
		lines[i] = r.line()
	}
	tb, st, err := parse4(t, lines...)
	if err != nil {
		t.Fatal(err)
	}
	if st.rows != len(rows4) || st.routed != len(rows4)-2 || st.bad != 0 {
		t.Fatalf("stats %+v", st)
	}
	// 1.0.0.0/24 and 1.1.1.0/24 are not adjacent: no merge; 8.8.4.0 and 8.8.8.0 neither.
	if tb.size() != st.routed {
		t.Fatalf("ranges %d, want %d", tb.size(), st.routed)
	}
	// Equal networks share one info and one name.
	cf := 0
	for _, in := range tb.infos {
		if in.asn == 13335 {
			cf++
		}
	}
	if cf != 1 {
		t.Fatalf("%d infos for AS13335, want 1", cf)
	}
	for i := 1; i < tb.size(); i++ {
		if tb.start[i] <= tb.end[i-1] {
			t.Fatalf("ranges %d and %d overlap", i-1, i)
		}
	}
	li := int(tb.info[tb.size()-1])
	last := tb.infos[li]
	if last.country != "JP" || last.name != "EXAMPLE-NET-AP Example Networks Co., Ltd." || tb.org(li) != "Example Networks" {
		t.Fatalf("last info %+v, org %q", last, tb.org(li))
	}
	// Organisation names are computed when first asked for.
	if tb.orgs[0].Load() != nil || tb.org(0) != "Cloudflare" || tb.orgs[0].Load() == nil {
		t.Fatal("the organisation name is not computed lazily")
	}
	zz := tb.infos[tb.info[tb.size()-2]]
	if zz.country != "" || zz.asn != 64498 {
		t.Fatalf("ZZ info %+v", zz)
	}
}

func TestParseTableIPv6(t *testing.T) {
	lines := make([]string, len(rows6))
	for i, r := range rows6 {
		lines[i] = r.line()
	}
	tb, st, err := parseTable(context.Background(), strings.NewReader(strings.Join(lines, "\r\n")+"\r\n"), spec6)
	if err != nil {
		t.Fatal(err)
	}
	if st.rows != 5 || st.routed != 4 || tb.size() != 4 {
		t.Fatalf("stats %+v, ranges %d", st, tb.size())
	}
	i := tb.find(u128Of(mustAddr(t, "2a00:1450:4001::1")), u128.compare)
	if i < 0 || tb.infos[i].asn != 15169 || tb.org(i) != "Google" {
		t.Fatalf("2a00:1450:4001::1 → %d", i)
	}
	if i := tb.find(u128Of(mustAddr(t, "2001:4900::1")), u128.compare); i >= 0 {
		t.Fatalf("not routed space → %+v", tb.infos[i])
	}
	// A table of the other family has no line understood.
	if _, _, err := parseTable(context.Background(), strings.NewReader(rows4[0].line()), spec6); err == nil {
		t.Fatal("an IPv4 line was read as IPv6")
	}
}

func TestParseTableMergesAdjacentRanges(t *testing.T) {
	tb, st, err := parse4(t,
		"# a comment",
		"",
		"1.0.0.0\t1.0.0.255\t13335\tUS\tCLOUDFLARENET",
		"1.0.1.0\t1.0.1.255\t13335\tUS\tCLOUDFLARENET",
		"1.0.2.0\t1.0.2.255\t13335\tUS\tCLOUDFLARENET",
		"1.0.3.0\t1.0.3.255\t13335\tAU\tCLOUDFLARENET", // another country: another info
		"1.0.4.0\t1.0.4.255\t13335\tAU\tCLOUDFLARENET",
		"1.0.6.0\t1.0.6.255\t13335\tAU\tCLOUDFLARENET",   // a gap
		"255.255.255.0\t255.255.255.255\t64496\tUS\tEND", // the last address: no overflow
	)
	if err != nil {
		t.Fatal(err)
	}
	if st.rows != 7 || st.routed != 7 {
		t.Fatalf("stats %+v", st)
	}
	want := [][2]string{{"1.0.0.0", "1.0.2.255"}, {"1.0.3.0", "1.0.4.255"}, {"1.0.6.0", "1.0.6.255"}, {"255.255.255.0", "255.255.255.255"}}
	if tb.size() != len(want) {
		t.Fatalf("%d ranges, want %d", tb.size(), len(want))
	}
	for i, w := range want {
		if got := [2]string{string32(tb.start[i]), string32(tb.end[i])}; got != w {
			t.Errorf("range %d = %v, want %v", i, got, w)
		}
	}
}

func TestParseTableLenient(t *testing.T) {
	// Odd but understood: no description, AS prefix, spaces around fields, a tab in the
	// description, control characters and invalid UTF-8.
	tb, st, err := parse4(t,
		"1.0.0.0\t1.0.0.255\t13335\tUS",
		"1.0.1.0\t1.0.1.255\tAS13336\t US \tTWO  WORDS\tAND MORE",
		"1.0.2.0\t1.0.2.255\t13337\tUnknown\tBAD\x01\xffNAME",
		"bogus line",                                // not understood
		"1.0.3.0\t1.0.3.255\tAS-X\tUS\tBAD AS",      // not understood
		"1.0.4.0\t1.0.4.0\t13338\tUS\tONE ADDRESS",  // a range of one address
		"1.0.5.0\t1.0.4.255\t13339\tUS\tBACKWARDS",  // not understood (ends before it starts)
		"1.0.6.00\t1.0.6.255\t13340\tUS\tLEADING 0", // not understood
		"1.0.7.0\t1.0.7.255\t4294967296\tUS\tBIG",   // not understood (AS number too large)
	)
	if err != nil {
		t.Fatal(err)
	}
	if st.rows != 4 || st.bad != 5 || !strings.HasPrefix(st.firstBad, "line 4:") {
		t.Fatalf("stats %+v", st)
	}
	names := map[uint32]string{}
	for _, in := range tb.infos {
		names[in.asn] = in.name + "|" + in.country
	}
	want := map[uint32]string{13335: "|US", 13336: "TWO WORDS AND MORE|US", 13337: "BAD " + string(utf8.RuneError) + "NAME|", 13338: "ONE ADDRESS|US"}
	for asn, w := range want {
		if names[asn] != w {
			t.Errorf("AS%d = %q, want %q", asn, names[asn], w)
		}
	}
}

func TestParseTableErrors(t *testing.T) {
	good := rows4[0].line()
	many := func(n int, line string) []string {
		l := make([]string, n)
		for i := range l {
			l[i] = line
		}
		return l
	}
	cases := []struct {
		name  string
		lines []string
		want  string
	}{
		{"empty", nil, "no announced ranges"},
		{"only not routed", []string{"1.0.0.0\t1.0.0.255\t0\tNone\tNot routed"}, "no announced ranges"},
		{"unsorted", []string{rows4[3].line(), rows4[0].line()}, "not sorted"},
		{"overlapping", []string{good, "1.0.0.128\t1.0.1.255\t64496\tUS\tX"}, "not sorted"},
		{"duplicate", []string{good, good}, "not sorted"},
		{"garbage", append([]string{good}, many(101, "<html><body>Not Found</body></html>")...), "101 lines not understood"},
		{"long line", []string{good, "1.0.1.0\t1.0.1.255\t1\tUS\t" + strings.Repeat("x", readBuf+10)}, ""},
	}
	for _, c := range cases {
		_, st, err := parse4(t, c.lines...)
		switch {
		case c.want == "" && err != nil:
			t.Errorf("%s: %v", c.name, err)
		case c.want == "" && st.bad != 1:
			t.Errorf("%s: stats %+v, want one line not understood", c.name, st)
		case c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)):
			t.Errorf("%s: err %v, want %q", c.name, err, c.want)
		}
	}
	// A canceled context stops a long parse.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	big := synthTable(ctxEvery + 10)
	if _, _, err := parseTable(ctx, bytes.NewReader(big), spec4); err != context.Canceled {
		t.Errorf("canceled parse: %v", err)
	}
}

func TestParseGzip(t *testing.T) {
	good := gzRows(rows4)
	ctx := context.Background()
	if l, err := parseGzip(ctx, bytes.NewReader(good), fam4); err != nil || l.ranges() != 10 {
		t.Fatalf("good: %v", err)
	}
	cases := map[string][]byte{
		"not gzip":         []byte("1.0.0.0\t1.0.0.255\t13335\tUS\tCLOUDFLARENET\n"),
		"truncated":        good[:len(good)/2],
		"trailing garbage": append(bytes.Clone(good), "garbage"...),
		"bad checksum":     flipByte(good, len(good)-6),
		"empty":            nil,
	}
	for name, b := range cases {
		if _, err := parseGzip(ctx, bytes.NewReader(b), fam4); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}

// flipByte returns b with the byte at i inverted.
func flipByte(b []byte, i int) []byte {
	b = bytes.Clone(b)
	b[i] ^= 0xff
	return b
}

func TestLoadFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, nameV4)
	if err := os.WriteFile(path, gzRows(rows4), 0o644); err != nil {
		t.Fatal(err)
	}
	l, err := loadFile(context.Background(), path, fam4)
	if err != nil {
		t.Fatal(err)
	}
	fi, _ := os.Stat(path)
	if l.size != fi.Size() || !l.at.Equal(fi.ModTime()) || len(l.sum) != 64 || l.stats.rows != len(rows4) {
		t.Fatalf("loaded %+v", l)
	}
	if _, err := loadFile(context.Background(), filepath.Join(dir, "missing"), fam4); !os.IsNotExist(err) {
		t.Fatalf("missing file: %v", err)
	}
}

func TestParseIPv4(t *testing.T) {
	good := map[string]uint32{
		"0.0.0.0": 0, "1.2.3.4": 0x01020304, "255.255.255.255": 0xffffffff, "10.0.0.255": 0x0a0000ff,
	}
	for s, want := range good {
		if got, ok := parseIPv4([]byte(s)); !ok || got != want {
			t.Errorf("parseIPv4(%q) = %x, %v", s, got, ok)
		}
	}
	for _, s := range []string{"", "1.2.3", "1.2.3.4.5", "256.0.0.0", "01.2.3.4", "1..2.3", ".1.2.3",
		"1.2.3.", "1.2.3.4 ", "a.b.c.d", "1.2.3.-4", "::1", "1.2.3.4000"} {
		if _, ok := parseIPv4([]byte(s)); ok {
			t.Errorf("parseIPv4(%q) accepted", s)
		}
	}
}

func TestParseASN(t *testing.T) {
	for s, want := range map[string]uint32{"0": 0, "13335": 13335, "AS15169": 15169, "as1": 1, "4294967295": 4294967295} {
		if got, ok := parseASN([]byte(s)); !ok || got != want {
			t.Errorf("parseASN(%q) = %d, %v", s, got, ok)
		}
	}
	for _, s := range []string{"", "AS", "-1", "4294967296", "99999999999", "1.5", "AS 1", "１"} {
		if _, ok := parseASN([]byte(s)); ok {
			t.Errorf("parseASN(%q) accepted", s)
		}
	}
}

func TestCountryOf(t *testing.T) {
	for s, want := range map[string]string{"US": "US", "jp": "JP", "Au": "AU", "ZZ": "", "None": "",
		"Unknown": "", "": "", "U1": "", "U": "", "É": ""} {
		cc := countryOf([]byte(s))
		got := ""
		if cc != ([2]byte{}) {
			got = string(cc[:])
		}
		if got != want {
			t.Errorf("countryOf(%q) = %q, want %q", s, got, want)
		}
	}
}

func TestCleanName(t *testing.T) {
	long := strings.Repeat("é", 200) // 400 bytes
	for in, want := range map[string]string{
		"  GOOGLE  ":                          "GOOGLE",
		"A\tB\r\nC":                           "A B C",
		"BAD\xff":                             "BAD" + string(utf8.RuneError),
		"LINE" + string(rune(0x2028)) + "SEP": "LINE SEP", // line separator
		"RTL" + string(rune(0x202e)) + "OVERRIDE": "RTL OVERRIDE",
		"ZERO" + string(rune(0x200b)) + "WIDTH":   "ZERO WIDTH",
		"NO" + string(rune(0xa0)) + "BREAK":       "NO BREAK",
		long:                                      strings.Repeat("é", maxNameBytes/2),
		"Telefônica Brasil S.A":                   "Telefônica Brasil S.A",
	} {
		if got := cleanName([]byte(in)); got != want {
			t.Errorf("cleanName(%q) = %q, want %q", in, got, want)
		}
	}
}

// synthTable returns n announced, sorted /24 ranges from 1.0.0.0 (decompressed).
func synthTable(n int) []byte {
	var b bytes.Buffer
	for i := range n {
		a := uint32(0x01000000) + uint32(i)<<8
		fmt.Fprintf(&b, "%s\t%s\t%d\tUS\tSYNTH-%d\n", string32(a), string32(a+255), 64496+i%16, i%16)
	}
	return b.Bytes()
}

func TestU128(t *testing.T) {
	cases := []struct{ in, next string }{
		{"::", "::1"},
		{"2001:db8::ffff:ffff:ffff:ffff", "2001:db8:0:1::"}, // carry into the high half
		{"ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"},
	}
	for _, c := range cases {
		n, ok := u128Of(mustAddr(t, c.in)).next()
		if !ok || n.String() != c.next {
			t.Errorf("next(%s) = %s, %v; want %s", c.in, n, ok, c.next)
		}
	}
	if _, ok := u128Of(mustAddr(t, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")).next(); ok {
		t.Error("the last address has a next")
	}
	if _, ok := next32(0xffffffff); ok {
		t.Error("255.255.255.255 has a next")
	}
	a, b := u128Of(mustAddr(t, "2001:db8::1")), u128Of(mustAddr(t, "2001:db8::2"))
	if a.compare(b) != -1 || b.compare(a) != 1 || a.compare(a) != 0 {
		t.Error("compare")
	}
}

func TestParseTableIPv6MergeAndOrder(t *testing.T) {
	parse6 := func(lines ...string) (*table[u128], error) {
		tb, _, err := parseTable(context.Background(), strings.NewReader(strings.Join(lines, "\n")), spec6)
		return tb, err
	}
	tb, err := parse6(
		"2001:db8::\t2001:db8::ffff:ffff:ffff:ffff\t64496\tUS\tDOC",
		"2001:db8:0:1::\t2001:db8:0:1:ffff:ffff:ffff:ffff\t64496\tUS\tDOC", // adjacent across the halves
		"2001:db8:0:3::\t2001:db8:0:3::ffff\t64496\tUS\tDOC",               // a gap
		"ffff:ffff:ffff:ffff:ffff:ffff:ffff:fff0\tffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff\t64497\tUS\tEND",
	)
	if err != nil {
		t.Fatal(err)
	}
	if tb.size() != 3 || tb.end[0].String() != "2001:db8:0:1:ffff:ffff:ffff:ffff" {
		t.Fatalf("%d ranges, first ends at %s", tb.size(), tb.end[0])
	}
	_, err = parse6("2001:db8:0:3::\t2001:db8:0:3::ffff\t64496\tUS\tDOC", "2001:db8::\t2001:db8::ffff\t64496\tUS\tDOC")
	if err == nil || !strings.Contains(err.Error(), "2001:db8::-2001:db8::ffff does not come after 2001:db8:0:3::ffff") {
		t.Fatalf("unsorted IPv6: %v", err)
	}
}

func TestParseIPv6(t *testing.T) {
	for _, s := range []string{"::", "2001:db8::1", "::ffff:1.2.3.4", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"} {
		if _, ok := parseIPv6([]byte(s)); !ok {
			t.Errorf("parseIPv6(%q) refused", s)
		}
	}
	for _, s := range []string{"", ":", "1.2.3.4", "fe80::1%eth0", "2001:db8::g", "2001:db8::1/64",
		strings.Repeat("0", 65)} {
		if _, ok := parseIPv6([]byte(s)); ok {
			t.Errorf("parseIPv6(%q) accepted", s)
		}
	}
}

func TestCapReader(t *testing.T) {
	r := &capReader{r: strings.NewReader("0123456789"), left: 10}
	if b, err := io.ReadAll(r); err != nil || len(b) != 10 {
		t.Fatalf("exactly at the limit: %d bytes, %v", len(b), err)
	}
	r = &capReader{r: strings.NewReader("0123456789x"), left: 10}
	if _, err := io.ReadAll(r); err != errTooLarge {
		t.Fatalf("over the limit: %v", err)
	}
}

// TestParseTableGivesUpOnGarbage checks that a file that is not a table is not read to its end.
func TestParseTableGivesUpOnGarbage(t *testing.T) {
	r := &countingReader{r: strings.NewReader(strings.Repeat("<p>not a table</p>\n", 100_000))}
	_, st, err := parseTable(context.Background(), r, spec4)
	if err == nil || st.bad != maxBad(maxRows)+1 {
		t.Fatalf("err %v, stats %+v", err, st)
	}
	if r.n > 1<<20 {
		t.Fatalf("read %d bytes of garbage", r.n)
	}
}

// countingReader counts the bytes read through it.
type countingReader struct {
	r io.Reader
	n int
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += n
	return n, err
}

// countingWriter counts the bytes written through it.
type countingWriter struct {
	w io.Writer
	n int64
}

func (c *countingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}

// gzStream returns a reader of the gzip compression of what table writes, made as it is read, so
// that a test can give the parser a table far larger than it means to read. table stops at its
// first failed write. stop ends the stream - table's writes fail from then on - waits for table to
// return and says how many bytes it wrote (before compression).
func gzStream(table func(w io.Writer)) (r io.Reader, stop func() int64) {
	pr, pw := io.Pipe()
	var written int64
	done := make(chan struct{})
	go func() {
		defer close(done)
		zw := gzip.NewWriter(pw)
		cw := &countingWriter{w: zw}
		table(cw)
		pw.CloseWithError(zw.Close())
		written = cw.n
	}()
	return pr, func() int64 {
		pr.Close()
		<-done
		return written
	}
}

// TestParseGzipLongLinesRefused reads the table of a review's experiment: 110,000 sorted,
// well-formed lines, each with a description of its own of 2.2 KB - 3 MB of gzip for 250 MB of
// text, which the parser accepted after taking about 800 MiB of memory to remember every line's
// rest and description. Lines that long are not understood any more (maxLineBytes): the table is
// refused after a few thousand lines.
func TestParseGzipLongLinesRefused(t *testing.T) {
	pad := strings.Repeat("x", 2200)
	r, stop := gzStream(func(w io.Writer) {
		for i := range 110_000 {
			a := uint32(0x01000000) + uint32(i)<<8
			if _, err := fmt.Fprintf(w, "%s\t%s\t%d\tUS\tD%09d %s\n", string32(a), string32(a+255), 64496+i%1000, i, pad); err != nil {
				return
			}
		}
	})
	_, err := parseGzip(context.Background(), r, fam4)
	written := stop()
	if err == nil || !strings.Contains(err.Error(), "lines not understood (line 1: longer than 1024 bytes)") {
		t.Fatalf("err %v", err)
	}
	if written > 32<<20 {
		t.Fatalf("%d MiB of the table were made before it was refused", written>>20)
	}
}

// TestParseTableLineLimit checks the longest line understood: maxLineBytes, line ending aside.
// Real lines are under 200 bytes.
func TestParseTableLineLimit(t *testing.T) {
	fill := func(prefix string, n int) string { return prefix + strings.Repeat("x", n-len(prefix)) }
	r := strings.NewReader(rows4[0].line() + "\r\n" +
		fill("1.0.1.0\t1.0.1.255\t64496\tUS\t", maxLineBytes) + "\r\n" +
		fill("1.0.2.0\t1.0.2.255\t64497\tUS\t", maxLineBytes+1) + "\n")
	tb, st, err := parseTable(context.Background(), r, spec4)
	if err != nil || st.rows != 2 || st.bad != 1 || st.firstBad != "line 3: longer than 1024 bytes" {
		t.Fatalf("err %v, stats %+v", err, st)
	}
	if n := tb.infos[tb.info[1]].name; n != strings.Repeat("x", maxNameBytes) {
		t.Fatalf("the description of the longest line is kept as %q", n)
	}
}

// TestParseGzipContentBounded checks that a table is read up to maxContentBytes at most, however
// well it compresses: here a line of a table, then a MiB of comment lines over and over (a gzip
// file may be several gzip streams one after the other), which is 65 MiB in 350 KB of gzip.
func TestParseGzipContentBounded(t *testing.T) {
	comments := strings.Repeat("# "+strings.Repeat("-", 1021)+"\n", 1<<10) // 1 MiB
	mib := gzLines(strings.TrimSuffix(comments, "\n"))
	parts := []io.Reader{bytes.NewReader(gzLines(rows4[0].line()))}
	for range maxContentBytes>>20 + 1 {
		parts = append(parts, bytes.NewReader(mib))
	}
	cr := &countingReader{r: io.MultiReader(parts...)}
	_, err := parseGzip(context.Background(), cr, fam4)
	if !errors.Is(err, errTooLarge) || cr.n < len(mib)*(maxContentBytes>>20-1) {
		t.Fatalf("err %v after %d bytes of gzip", err, cr.n)
	}
}

// TestParseTableNetworksBounded checks that a table of more than maxNetworks networks is refused:
// a table of a network of its own on every line made the parser keep a network, an index entry
// and a name for each of up to maxRows lines (about 770 MiB of memory for 20 MB of gzip).
func TestParseTableNetworksBounded(t *testing.T) {
	// Lines of a network of their own each, more than maxNetworks: refused at the first one too
	// many (so the maxNetworks before were accepted).
	var table []byte
	for i := range maxNetworks + 10 {
		a := uint32(0x01000000) + uint32(i)<<8
		table = fmt.Appendf(table, "%s\t%s\t%d\tUS\t\n", string32(a), string32(a+255), 100000+i)
	}
	_, st, err := parseTable(context.Background(), bytes.NewReader(table), spec4)
	if err == nil || !strings.Contains(err.Error(), fmt.Sprintf("more than %d networks", maxNetworks)) ||
		st.routed != maxNetworks+1 {
		t.Fatalf("%d networks: err %v, stats %+v", maxNetworks+10, err, st)
	}
}

// TestBuilderMemoIsBounded checks that builder.raw, the memo of the rests of lines, holds short
// rests only, and within maxMemoBytes however many different ones a table has: it held every rest
// of up to 4 KiB (and a second map every description), so that a table of a new long description
// on every line made a few MB of gzip take most of a GB. A rest not remembered is read the same,
// every time.
func TestBuilderMemoIsBounded(t *testing.T) {
	b := newBuilder[uint32]()
	held := func() int { // what the memo holds, counted from the map itself
		n := 0
		for k := range b.raw {
			n += len(k) + memoEntryBytes
		}
		return n
	}
	// A long rest is understood, not remembered.
	long := "64496\tUS\t" + strings.Repeat("A LONG DESCRIPTION ", 30)
	if ref, why := b.network([]byte(long)); why != "" || ref != 0 || len(b.raw) != 0 {
		t.Fatalf("a long rest: ref %d, why %q, %d rests remembered", ref, why, len(b.raw))
	}
	// The rests of a table of the real one's size (80,000 networks, and the space not routed) are
	// all remembered: the memo does what it is for.
	realRest := func(i int) []byte {
		return fmt.Appendf(nil, "%d\tUS\tEXAMPLE-AS-%d Example Networks %d Ltd", 100000+i, i, i)
	}
	refs := make([]int, 80_000)
	for i := range refs {
		refs[i], _ = b.network(realRest(i))
	}
	b.network([]byte("0\tNone\tNot routed"))
	if len(b.raw) != len(refs)+1 {
		t.Fatalf("%d rests of a table of the real one's size remembered, want %d", len(b.raw), len(refs)+1)
	}
	// Many more different short rests (lines not understood, so no networks): the memo fills up
	// to its bound, and no further.
	pad := strings.Repeat("x", 200)
	bad := func(i int) []byte { return fmt.Appendf(nil, "AS-%07d\tUS\t%s", i, pad) }
	for i := range 2 * maxMemoBytes / (len(pad) + memoEntryBytes) {
		if _, why := b.network(bad(i)); why != "the AS number is not a number" {
			t.Fatalf("rest %d: %q", i, why)
		}
	}
	if h := held(); h > maxMemoBytes || h < maxMemoBytes-(maxMemoKey+memoEntryBytes) {
		t.Fatalf("the memo holds %d bytes, want at most %d, and full", h, maxMemoBytes)
	}
	if h := held(); b.memoBytes != h {
		t.Fatalf("memoBytes = %d, but the memo holds %d", b.memoBytes, h)
	}
	// Past the bound, rests are read the same: remembered or not, of known networks or new ones.
	for _, i := range []int{0, 41_234, len(refs) - 1} {
		if ref, why := b.network(realRest(i)); ref != refs[i] || why != "" {
			t.Fatalf("network %d: ref %d (%q), want %d", i, ref, why, refs[i])
		}
	}
	if _, why := b.network(bad(1 << 30)); why != "the AS number is not a number" {
		t.Fatalf("a bad rest not remembered: %q", why)
	}
	// A new network, of a rest short enough to be remembered but larger than the room left (less
	// than a bad rest's).
	nets := len(b.t.infos)
	name := "NEW NET " + strings.Repeat("Y", 220)
	fresh := []byte("64497\tjp\tNEW  NET " + strings.Repeat("Y", 220))
	r1, _ := b.network(fresh)
	r2, _ := b.network(fresh)
	if _, ok := b.raw[string(fresh)]; ok || len(fresh) > maxMemoKey || r1 != nets || r2 != r1 ||
		len(b.t.infos) != nets+1 || b.t.infos[r1] != (asInfo{asn: 64497, country: "JP", name: name}) {
		t.Fatalf("a new network past the bound: refs %d and %d, %d networks (were %d)", r1, r2, len(b.t.infos), nets)
	}
}
