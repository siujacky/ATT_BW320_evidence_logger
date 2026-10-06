package ipintel

import (
	"bufio"
	"bytes"
	"cmp"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
	"unicode"
	"unicode/utf8"
)

// The limits below bound the work and the memory a table file can cause, whatever it holds: a
// file is downloaded (from a server, through whatever stands between it and this computer) or
// placed by hand, and it is read inside the evidence logger. Each is a few times what the real
// tables need, so that their growth is no concern for years. The reading is bounded by bytes and
// lines (maxContentBytes, maxLineBytes, maxBad), and what is kept while reading by the ranges
// (maxRows), the networks (maxNetworks), their names (maxNamesBytes) and the memo of builder.raw
// (maxMemoBytes) - never by the number of bytes or of different lines a few MB of gzip expand to.
// Measured (BenchmarkLoadHostile): a table of the real IPv4 table's size takes 30 to 50 MiB of
// heap while it is read, and the worst tables within these limits about 200 MiB - an IPv6 table of
// maxRows ranges, whose addresses take 32 bytes each; an IPv4 one less than 150 MiB - for a few
// seconds at most.
const (
	// maxFileBytes bounds a table file, downloaded or found (the real ones are a few MB).
	maxFileBytes = 64 << 20
	// maxContentBytes bounds what a table file decompresses to (the real IPv4 table: about 25 MB),
	// so that a damaged or hostile file cannot be decompressed for ever, nor a few MB of gzip make
	// the parser read hundreds of MB.
	maxContentBytes = 64 << 20
	// maxRows bounds the data lines of a table (the real ones: about 500,000 and 150,000), and so
	// the memory its ranges take.
	maxRows = 2_000_000
	// maxLineBytes is the longest line understood (real ones are under 200 bytes: two addresses,
	// AS number, country code and an AS description of a few words); a longer line is skipped and
	// counted as not understood. maxNameBytes is the longest AS description kept.
	maxLineBytes = 1 << 10
	maxNameBytes = 255
	// readBuf is the line reader's buffer; a longer line is skipped piece by piece.
	readBuf = 64 << 10
	// ctxEvery is the number of lines parsed between two looks at the context.
	ctxEvery = 1 << 16
)

// errTooLarge is returned when a table decompresses to more than maxContentBytes.
var errTooLarge = fmt.Errorf("decompresses to more than %d MiB", maxContentBytes>>20)

// famSpec says how the lines of one family's table are read.
type famSpec[K any] struct {
	name    string // "IPv4", "IPv6"
	parse   func([]byte) (K, bool)
	compare func(K, K) int
	next    func(K) (K, bool)
	format  func(K) string
}

var (
	spec4 = &famSpec[uint32]{name: "IPv4", parse: parseIPv4, compare: cmp.Compare[uint32], next: next32, format: string32}
	spec6 = &famSpec[u128]{name: "IPv6", parse: parseIPv6, compare: u128.compare, next: u128.next, format: u128.String}
)

// tableStats counts the lines of a table file.
type tableStats struct {
	rows   int // data lines understood
	routed int // of them, ranges an AS announces (AS number not 0)
	bad    int // lines not understood, skipped
	// firstBad says which line was the first one not understood, and why.
	firstBad string
}

// skip counts line n as not understood.
func (s *tableStats) skip(n int, why string) {
	if s.bad == 0 {
		s.firstBad = "line " + strconv.Itoa(n) + ": " + why
	}
	s.bad++
}

// maxBad is how many lines a table of rows data lines may have that are not understood: a few,
// so that one odd line (a new comment, a stray character) does not reject the whole database,
// but not so many that a file in another format passes.
func maxBad(rows int) int { return 100 + rows/1000 }

// loaded is a table file read and checked, ready to be swapped in.
type loaded struct {
	fam   family
	t4    *table[uint32]
	t6    *table[u128]
	stats tableStats
	size  int64     // bytes of the file
	sum   string    // SHA-256 of the file, hex
	at    time.Time // the file's write time
}

// ranges is the number of ranges of the table.
func (l *loaded) ranges() int {
	if l.fam == fam4 {
		return l.t4.size()
	}
	return l.t6.size()
}

// loadFile reads and checks the table of family f in the file at path.
func loadFile(ctx context.Context, path string, f family) (*loaded, error) {
	fh, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer fh.Close()
	fi, err := fh.Stat()
	if err != nil {
		return nil, err
	}
	if fi.Size() > maxFileBytes {
		return nil, fmt.Errorf("%d bytes, more than the %d MiB a table may have", fi.Size(), maxFileBytes>>20)
	}
	h := sha256.New()
	l, err := parseGzip(ctx, io.TeeReader(io.LimitReader(fh, maxFileBytes), h), f)
	if err != nil {
		return nil, err
	}
	l.size, l.sum, l.at = fi.Size(), hex.EncodeToString(h.Sum(nil)), fi.ModTime()
	return l, nil
}

// parseGzip reads the gzip-compressed table of family f from r, to its end: a stream that is
// cut short, fails its checksum or has anything after it is an error.
func parseGzip(ctx context.Context, r io.Reader, f family) (*loaded, error) {
	zr, err := gzip.NewReader(r)
	if err != nil {
		return nil, fmt.Errorf("not a gzip file: %w", err)
	}
	defer zr.Close()
	cr := &capReader{r: zr, left: maxContentBytes}
	l := &loaded{fam: f}
	if f == fam4 {
		l.t4, l.stats, err = parseTable(ctx, cr, spec4)
	} else {
		l.t6, l.stats, err = parseTable(ctx, cr, spec6)
	}
	if err != nil {
		return nil, err
	}
	return l, nil
}

// capReader fails with errTooLarge once more than left bytes were read.
type capReader struct {
	r    io.Reader
	left int64
}

func (c *capReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.left -= int64(n)
	if c.left < 0 {
		return n, errTooLarge
	}
	return n, err
}

// parseTable reads an IPtoASN table (decompressed) of one family from r and builds its range
// table. Blank lines and lines starting with '#' are ignored; a line that is not understood is
// skipped and counted (maxBad bounds them). It fails when the ranges are not sorted or overlap,
// when nothing is announced, or when r fails.
func parseTable[K any](ctx context.Context, r io.Reader, sp *famSpec[K]) (*table[K], tableStats, error) {
	var (
		st      tableStats
		b       = newBuilder[K]()
		prevEnd K
		have    bool
	)
	br := bufio.NewReaderSize(r, readBuf)
	for n := 1; ; n++ {
		if n%ctxEvery == 0 {
			if err := ctx.Err(); err != nil {
				return nil, st, err
			}
		}
		line, err := br.ReadSlice('\n')
		long := false
		for errors.Is(err, bufio.ErrBufferFull) {
			long = true
			_, err = br.ReadSlice('\n')
		}
		if err != nil && err != io.EOF {
			return nil, st, fmt.Errorf("line %d: %w", n, err)
		}
		eof := err == io.EOF
		switch line = bytes.TrimRight(line, "\r\n"); {
		case long || len(line) > maxLineBytes:
			st.skip(n, "longer than "+strconv.Itoa(maxLineBytes)+" bytes")
		case len(line) == 0 || line[0] == '#':
			// blank or a comment
		default:
			start, end, ref, why := readLine(sp, b, line)
			if why != "" {
				st.skip(n, why)
				break
			}
			if have && sp.compare(start, prevEnd) <= 0 {
				return nil, st, fmt.Errorf("line %d: %s-%s does not come after %s: the table is not sorted",
					n, sp.format(start), sp.format(end), sp.format(prevEnd))
			}
			have, prevEnd = true, end
			st.rows++
			if st.rows > maxRows {
				return nil, st, fmt.Errorf("more than %d ranges", maxRows)
			}
			if ref >= 0 {
				st.routed++
				b.add(sp, start, end, uint32(ref))
			}
		}
		if b.nameBytes > maxNamesBytes {
			return nil, st, fmt.Errorf("more than %d MiB of AS descriptions", maxNamesBytes>>20)
		}
		if len(b.t.infos) > maxNetworks {
			return nil, st, fmt.Errorf("more than %d networks (AS number, country code, description)", maxNetworks)
		}
		if st.bad > maxBad(maxRows) {
			// More than any table may have: this is not a table, no need to read the rest.
			return nil, st, fmt.Errorf("%d lines not understood (%s)", st.bad, st.firstBad)
		}
		if eof {
			break
		}
	}
	if st.bad > maxBad(st.rows) {
		return nil, st, fmt.Errorf("%d lines not understood (%s)", st.bad, st.firstBad)
	}
	if st.routed == 0 {
		if st.bad > 0 {
			return nil, st, fmt.Errorf("no announced ranges (%d lines not understood: %s)", st.bad, st.firstBad)
		}
		return nil, st, errors.New("no announced ranges")
	}
	return b.table(), st, nil
}

// readLine reads a data line of sp's family: its range, and its network as a reference
// (builder.network); why says what is wrong with the line ("" when nothing).
func readLine[K any](sp *famSpec[K], b *builder[K], line []byte) (start, end K, ref int, why string) {
	s, e, rest, ok := splitRange(line)
	if !ok {
		return start, end, refBad, errFields
	}
	start, ok1 := sp.parse(s)
	end, ok2 := sp.parse(e)
	switch {
	case !ok1 || !ok2:
		return start, end, refBad, "not a range of " + sp.name + " addresses"
	case sp.compare(start, end) > 0:
		return start, end, refBad, "the range ends before it starts"
	}
	ref, why = b.network(rest)
	return start, end, ref, why
}

// errFields says that a line has too few fields.
const errFields = "fewer than 4 tab-separated fields"

// splitRange splits a data line into the range's first and last address and the rest: AS
// number, country code and description, which the lines of a network share.
func splitRange(line []byte) (start, end, rest []byte, ok bool) {
	i := bytes.IndexByte(line, '\t')
	if i < 0 {
		return nil, nil, nil, false
	}
	j := bytes.IndexByte(line[i+1:], '\t')
	if j < 0 {
		return nil, nil, nil, false
	}
	j += i + 1
	return bytes.TrimSpace(line[:i]), bytes.TrimSpace(line[i+1 : j]), line[j+1:], true
}

// splitNetwork reads the rest of a data line: AS number, country code and the AS description
// (the rest of the line; it may be missing). why says what is wrong with it.
func splitNetwork(rest []byte) (asn uint32, cc [2]byte, desc []byte, why string) {
	i := bytes.IndexByte(rest, '\t')
	if i < 0 {
		return 0, cc, nil, errFields
	}
	asnField, ccField := rest[:i], rest[i+1:]
	if j := bytes.IndexByte(ccField, '\t'); j >= 0 {
		ccField, desc = ccField[:j], ccField[j+1:]
	}
	asn, ok := parseASN(bytes.TrimSpace(asnField))
	if !ok {
		return 0, cc, nil, "the AS number is not a number"
	}
	return asn, countryOf(bytes.TrimSpace(ccField)), desc, ""
}

// parseIPv4 reads a dotted-quad IPv4 address (no leading zeros, as IPtoASN writes them).
func parseIPv4(b []byte) (uint32, bool) {
	var v, octet uint32
	digits, dots := 0, 0
	for _, c := range b {
		switch {
		case c >= '0' && c <= '9':
			if digits == 1 && octet == 0 {
				return 0, false // a leading zero
			}
			octet = octet*10 + uint32(c-'0')
			digits++
			if octet > 255 {
				return 0, false
			}
		case c == '.' && digits > 0 && dots < 3:
			v, octet, digits = v<<8|octet, 0, 0
			dots++
		default:
			return 0, false
		}
	}
	if dots != 3 || digits == 0 {
		return 0, false
	}
	return v<<8 | octet, true
}

// parseIPv6 reads an IPv6 address without zone.
func parseIPv6(b []byte) (u128, bool) {
	if len(b) < 2 || len(b) > 64 {
		return u128{}, false
	}
	a, err := netip.ParseAddr(string(b))
	if err != nil || !a.Is6() || a.Zone() != "" {
		return u128{}, false
	}
	return u128Of(a), true
}

// parseASN reads an AS number, with or without "AS" before it.
func parseASN(b []byte) (uint32, bool) {
	if len(b) >= 2 && (b[0]|0x20) == 'a' && (b[1]|0x20) == 's' {
		b = b[2:]
	}
	if len(b) == 0 || len(b) > 10 {
		return 0, false
	}
	var v uint64
	for _, c := range b {
		if c < '0' || c > '9' {
			return 0, false
		}
		v = v*10 + uint64(c-'0')
	}
	if v > math.MaxUint32 {
		return 0, false
	}
	return uint32(v), true
}

// countryOf reads a country code: two letters, upper case. "None", "Unknown", "ZZ" (unknown
// country) and anything else give no country.
func countryOf(b []byte) [2]byte {
	if len(b) != 2 {
		return [2]byte{}
	}
	c0, c1 := b[0]&^0x20, b[1]&^0x20 // upper case, for letters
	if c0 < 'A' || c0 > 'Z' || c1 < 'A' || c1 > 'Z' || (c0 == 'Z' && c1 == 'Z') {
		return [2]byte{}
	}
	return [2]byte{c0, c1}
}

// cleanName makes an AS description safe to show: valid UTF-8, no control or format characters
// (line separators, bidirectional overrides, zero-width spaces: anything unicode.IsPrint refuses)
// - each becomes a space -, single spaces, at most maxNameBytes.
func cleanName(raw []byte) string {
	if len(raw) <= maxNameBytes && plainName(raw) {
		return string(raw) // nearly every description: nothing to clean
	}
	s := strings.ToValidUTF8(string(raw), string(utf8.RuneError))
	s = strings.Map(func(r rune) rune {
		if !unicode.IsPrint(r) {
			return ' '
		}
		return r
	}, s)
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > maxNameBytes {
		cut := maxNameBytes
		for cut > 0 && !utf8.RuneStart(s[cut]) {
			cut--
		}
		s = strings.TrimSpace(s[:cut])
	}
	return s
}

// plainName says whether b is printable ASCII with single spaces between words: clean already.
func plainName(b []byte) bool {
	if len(b) > 0 && (b[0] == ' ' || b[len(b)-1] == ' ') {
		return false
	}
	for i, c := range b {
		if c < 0x20 || c > 0x7e || (c == ' ' && i > 0 && b[i-1] == ' ') {
			return false
		}
	}
	return true
}

const (
	// refNotRouted and refBad are the references of a line's network (builder.network) that are
	// not networks: AS 0 (space nobody announces), and a rest of a line not understood.
	refNotRouted = -1
	refBad       = -2
	// maxNetworks bounds the networks of a table - its distinct (AS number, country code,
	// description) - and so the memory they take (a real IPv4 table: about 80,000, about one per
	// AS announcing IPv4 space; the IPv6 one fewer). A table of a network per line would otherwise
	// make the parser hold a network, an index entry and a name for each of maxRows lines.
	maxNetworks = 1 << 18
	// maxNamesBytes bounds the AS descriptions of a table's networks, together (a real one: about
	// 3 MB).
	maxNamesBytes = 32 << 20
	// maxMemoKey and maxMemoBytes bound builder.raw, which is only a shortcut: the rest of a line
	// is remembered when it is at most maxMemoKey bytes (real ones are under 150) and while the
	// memo takes at most maxMemoBytes (a real IPv4 table: about 8 MB), counting its keys and
	// memoEntryBytes - about what the map needs for an entry besides its key - per entry. Beyond,
	// the rest of a line is read each time: a little slower, no memory.
	maxMemoKey     = 256
	maxMemoBytes   = 16 << 20
	memoEntryBytes = 64
)

// builder builds a table from the lines of a file, sharing one asInfo among the ranges of a
// network.
type builder[K any] struct {
	t table[K]
	// raw is what the rest of a line (AS number, country code, description) stands for: the lines
	// of a network share it, so each is read once. It holds short rests only, up to maxMemoBytes
	// (memoBytes): a table of long or ever different rests must not make it grow with the file.
	raw       map[string]rawRef
	memoBytes int // what raw takes, about: the bytes of its keys and memoEntryBytes per entry
	nameBytes int // the bytes of the networks' names
	ccs       map[[2]byte]string
	index     map[infoKey]uint32
}

// rawRef is what the rest of a line stands for: the index of its network in infos, refNotRouted,
// or refBad with why.
type rawRef struct {
	ref int
	why string
}

type infoKey struct {
	asn  uint32
	cc   [2]byte
	name string
}

func newBuilder[K any]() *builder[K] {
	return &builder[K]{
		raw:   make(map[string]rawRef),
		ccs:   make(map[[2]byte]string),
		index: make(map[infoKey]uint32),
	}
}

// network returns what the rest of a line stands for (see rawRef), and why it is not understood.
func (b *builder[K]) network(rest []byte) (int, string) {
	if r, ok := b.raw[string(rest)]; ok {
		return r.ref, r.why
	}
	r := rawRef{ref: refNotRouted}
	switch asn, cc, desc, why := splitNetwork(rest); {
	case why != "":
		r = rawRef{ref: refBad, why: why}
	case asn != 0:
		r.ref = int(b.infoOf(asn, cc, desc))
	}
	if cost := len(rest) + memoEntryBytes; len(rest) <= maxMemoKey && b.memoBytes+cost <= maxMemoBytes {
		b.raw[string(rest)] = r
		b.memoBytes += cost
	}
	return r.ref, r.why
}

// infoOf returns the index of the network (asn, cc, description) in the table's infos. It is
// called for each rest of a line that raw does not know: once per network for a real table.
func (b *builder[K]) infoOf(asn uint32, cc [2]byte, raw []byte) uint32 {
	name := cleanName(raw)
	k := infoKey{asn, cc, name}
	if i, ok := b.index[k]; ok {
		return i
	}
	i := uint32(len(b.t.infos))
	b.t.infos = append(b.t.infos, asInfo{asn: asn, country: b.country(cc), name: name})
	b.index[k] = i
	b.nameBytes += len(name)
	return i
}

func (b *builder[K]) country(cc [2]byte) string {
	if cc == ([2]byte{}) {
		return ""
	}
	s, ok := b.ccs[cc]
	if !ok {
		s = string(cc[:])
		b.ccs[cc] = s
	}
	return s
}

// add appends a range, merging it into the one before when that one ends just before it and
// belongs to the same network.
func (b *builder[K]) add(sp *famSpec[K], start, end K, info uint32) {
	t := &b.t
	if n := len(t.start); n > 0 && t.info[n-1] == info {
		if nx, ok := sp.next(t.end[n-1]); ok && sp.compare(nx, start) == 0 {
			t.end[n-1] = end
			return
		}
	}
	t.start = append(t.start, start)
	t.end = append(t.end, end)
	t.info = append(t.info, info)
}

// table returns the table built, in slices of their exact size.
func (b *builder[K]) table() *table[K] {
	return &table[K]{
		start: slices.Clone(b.t.start),
		end:   slices.Clone(b.t.end),
		info:  slices.Clone(b.t.info),
		infos: slices.Clone(b.t.infos),
		orgs:  make([]atomic.Pointer[string], len(b.t.infos)),
	}
}
