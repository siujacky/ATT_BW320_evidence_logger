package export

import (
	"archive/zip"
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"attmonitor/internal/contracts"
	"attmonitor/internal/model"
)

// ErrManifest is wrapped by VerifyManifest errors.
var ErrManifest = errors.New("export: bundle manifest verification failed")

const (
	maxLineBytes     = 64 << 20 // longest ledger line accepted from a bundle
	maxBlobBytes     = 1 << 30  // largest blob read from a bundle
	maxSegmentBytes  = 4 << 30  // largest segment cached in memory for Record
	maxManifestBytes = 64 << 20 // largest MANIFEST.sha256
	segmentCacheSize = 2
)

var (
	bundleSegRE    = regexp.MustCompile(`^ledger/(ledger-\d{4}-\d{2}-\d{2})\.jsonl$`)
	manifestLineRE = regexp.MustCompile(`^([0-9a-f]{64}) [ *](.+)$`)
)

// Bundle reads an exported evidence bundle. It implements contracts.LedgerReader over the
// ledger segments and blobs inside the zip, so the same verification code can check a full
// ledger and a bundle. It is safe for concurrent use; call Close when done.
type Bundle struct {
	path  string
	zr    *zip.ReadCloser
	files map[string]*zip.File
	segs  []*bundleSegment

	mu    sync.Mutex
	cache []*cachedSegment // most recently used first
}

type bundleSegment struct {
	info   contracts.SegmentInfo
	file   *zip.File
	seqs   []uint64 // seq of each parsed line, in file order
	offs   []int64  // byte offset of each parsed line
	sorted bool     // seqs strictly increasing
	minTS  time.Time
	maxTS  time.Time
}

type cachedSegment struct {
	seg  *bundleSegment
	data []byte
}

var _ contracts.LedgerReader = (*Bundle)(nil)

// OpenBundle opens a bundle zip and indexes its ledger segments. It fails for archives that
// are not att-monitor bundles or whose entry names are unsafe or ambiguous (duplicates).
func OpenBundle(path string) (*Bundle, error) {
	zr, err := zip.OpenReader(path)
	if err != nil && !errors.Is(err, zip.ErrInsecurePath) {
		return nil, fmt.Errorf("export: open bundle %s: %w", path, err)
	}
	b := &Bundle{path: path, zr: zr, files: map[string]*zip.File{}}
	ok := false
	defer func() {
		if !ok {
			zr.Close()
		}
	}()
	for _, f := range zr.File {
		if strings.HasSuffix(f.Name, "/") {
			continue
		}
		if err := checkEntryName(f.Name); err != nil {
			return nil, fmt.Errorf("export: bundle %s: %w", path, err)
		}
		if _, dup := b.files[f.Name]; dup {
			return nil, fmt.Errorf("export: bundle %s contains more than one entry named %q", path, f.Name)
		}
		b.files[f.Name] = f
	}
	for name, f := range b.files {
		m := bundleSegRE.FindStringSubmatch(name)
		if m == nil {
			continue
		}
		seg, err := indexSegment(m[1], f)
		if err != nil {
			return nil, fmt.Errorf("export: bundle %s: %w", path, err)
		}
		b.segs = append(b.segs, seg)
	}
	if len(b.segs) == 0 {
		return nil, fmt.Errorf("export: %s is not an att-monitor evidence bundle (no ledger/ledger-YYYY-MM-DD.jsonl)", path)
	}
	sort.Slice(b.segs, func(i, j int) bool { return b.segs[i].info.Name < b.segs[j].info.Name })
	ok = true
	return b, nil
}

// checkEntryName rejects absolute, parent-relative, drive-qualified or otherwise unsafe paths.
func checkEntryName(name string) error {
	if name == "" || strings.ContainsAny(name, "\\:") || strings.HasPrefix(name, "/") {
		return fmt.Errorf("unsafe entry name %q", name)
	}
	for _, r := range name {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("unsafe entry name %q", name)
		}
	}
	for _, part := range strings.Split(name, "/") {
		if part == "" || part == "." || part == ".." {
			return fmt.Errorf("unsafe entry name %q", name)
		}
	}
	return nil
}

// readLine reads one '\n'-terminated line (the terminator included), refusing lines longer
// than maxLineBytes. At EOF it returns the remaining bytes (possibly unterminated) and io.EOF.
func readLine(br *bufio.Reader) ([]byte, error) {
	var buf []byte
	for {
		chunk, err := br.ReadSlice('\n')
		if len(buf)+len(chunk) > maxLineBytes {
			return nil, fmt.Errorf("ledger line longer than %d bytes", maxLineBytes)
		}
		buf = append(buf, chunk...)
		if err == bufio.ErrBufferFull {
			continue
		}
		return buf, err
	}
}

type seqTS struct {
	Seq uint64 `json:"seq"`
	TS  string `json:"ts"`
}

func indexSegment(name string, f *zip.File) (*bundleSegment, error) {
	rc, err := f.Open()
	if err != nil {
		return nil, fmt.Errorf("segment %s: %w", name, err)
	}
	defer rc.Close()
	s := &bundleSegment{file: f, sorted: true, info: contracts.SegmentInfo{Name: name, Path: f.Name}}
	if t, err := time.Parse("2006-01-02", strings.TrimPrefix(name, "ledger-")); err == nil {
		s.info.Date = t
	}
	br := bufio.NewReaderSize(rc, 1<<20)
	var off int64
	for {
		line, rerr := readLine(br)
		if len(line) > 0 {
			s.info.Records++
			if seq, ts, ok := lineSeqTS(line); ok {
				if n := len(s.seqs); n > 0 && s.seqs[n-1] >= seq {
					s.sorted = false
				}
				s.seqs = append(s.seqs, seq)
				s.offs = append(s.offs, off)
				if t, ok := parseTS(ts); ok {
					if s.minTS.IsZero() || t.Before(s.minTS) {
						s.minTS = t
					}
					if t.After(s.maxTS) {
						s.maxTS = t
					}
				}
			}
			off += int64(len(line))
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return nil, fmt.Errorf("segment %s: %w", name, rerr)
		}
	}
	if n := len(s.seqs); n > 0 {
		s.info.FirstSeq, s.info.LastSeq = s.seqs[0], s.seqs[n-1]
	}
	return s, nil
}

func lineSeqTS(line []byte) (uint64, string, bool) {
	var env model.Envelope
	if json.Unmarshal(bytes.TrimRight(line, "\r\n"), &env) != nil || env.B == "" {
		return 0, "", false
	}
	var st seqTS
	if json.Unmarshal([]byte(env.B), &st) != nil {
		return 0, "", false
	}
	return st.Seq, st.TS, true
}

// parseLine decodes one ledger line into its envelope and body.
func parseLine(line []byte) (model.Envelope, model.Body, error) {
	var env model.Envelope
	if err := json.Unmarshal(bytes.TrimRight(line, "\r\n"), &env); err != nil {
		return env, model.Body{}, fmt.Errorf("envelope: %w", err)
	}
	if env.B == "" {
		return env, model.Body{}, errors.New("envelope without body")
	}
	var body model.Body
	if err := json.Unmarshal([]byte(env.B), &body); err != nil {
		return env, body, fmt.Errorf("body: %w", err)
	}
	return env, body, nil
}

// Path returns the bundle's file path.
func (b *Bundle) Path() string { return b.path }

// Close releases the zip file.
func (b *Bundle) Close() error { return b.zr.Close() }

// Segments describes the ledger segments in the bundle, oldest first. Path is the path inside
// the zip; Records counts lines; Active is always false.
func (b *Bundle) Segments() ([]contracts.SegmentInfo, error) {
	out := make([]contracts.SegmentInfo, len(b.segs))
	for i, s := range b.segs {
		out[i] = s.info
	}
	return out, nil
}

func (b *Bundle) segment(name string) *bundleSegment {
	name = strings.TrimSuffix(name, ".jsonl")
	for _, s := range b.segs {
		if s.info.Name == name {
			return s
		}
	}
	return nil
}

// OpenSegment returns the exact bytes of a segment ("ledger-YYYY-MM-DD", ".jsonl" optional).
func (b *Bundle) OpenSegment(name string) (io.ReadCloser, error) {
	s := b.segment(name)
	if s == nil {
		return nil, fmt.Errorf("export: segment %s: %w", name, contracts.ErrNotFound)
	}
	return s.file.Open()
}

// GetBlob returns the exact bytes of blobs/<id>; an id whose content does not hash to it is
// an error (not ErrNotFound), so verifiers report it as corrupt.
func (b *Bundle) GetBlob(id string) ([]byte, error) {
	if !isHex64(id) {
		return nil, fmt.Errorf("export: invalid blob id %q: %w", truncate(id, 80), contracts.ErrNotFound)
	}
	f := b.files["blobs/"+id]
	if f == nil {
		return nil, fmt.Errorf("export: blob %s: %w", id, contracts.ErrNotFound)
	}
	data, err := readZipFile(f, maxBlobBytes)
	if err != nil {
		return nil, fmt.Errorf("export: blob %s: %w", id, err)
	}
	if got := sha256Hex(data); got != id {
		return nil, fmt.Errorf("export: blob %s: content hash mismatch (sha256 %s)", id, got)
	}
	return data, nil
}

func readZipFile(f *zip.File, limit int64) ([]byte, error) {
	if f.UncompressedSize64 > uint64(limit) {
		return nil, fmt.Errorf("%s is too large (%d bytes)", f.Name, f.UncompressedSize64)
	}
	rc, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	data, err := io.ReadAll(io.LimitReader(rc, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s is too large", f.Name)
	}
	return data, nil
}

// Scan calls fn for every record with seq >= fromSeq, in bundle order (ascending seq for an
// intact bundle). A line that cannot be parsed ends the scan with an error naming it.
func (b *Bundle) Scan(fromSeq uint64, fn func(env model.Envelope, body model.Body) error) error {
	for _, s := range b.segs {
		if s.sorted && len(s.seqs) > 0 && len(s.seqs) == s.info.Records && s.info.LastSeq < fromSeq {
			continue
		}
		err := scanSegment(s, func(env model.Envelope, body model.Body) error {
			if body.Seq < fromSeq {
				return nil
			}
			return fn(env, body)
		})
		if errors.Is(err, contracts.ErrStop) {
			return nil
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// ScanTime calls fn for records whose ts lies in [from, to).
func (b *Bundle) ScanTime(from, to time.Time, fn func(env model.Envelope, body model.Body) error) error {
	for _, s := range b.segs {
		if len(s.seqs) == s.info.Records && !s.minTS.IsZero() && (s.maxTS.Before(from) || !s.minTS.Before(to)) {
			continue
		}
		err := scanSegment(s, func(env model.Envelope, body model.Body) error {
			t, ok := parseTS(body.TS)
			if !ok || t.Before(from) || !t.Before(to) {
				return nil
			}
			return fn(env, body)
		})
		if errors.Is(err, contracts.ErrStop) {
			return nil
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func scanSegment(s *bundleSegment, fn func(model.Envelope, model.Body) error) error {
	rc, err := s.file.Open()
	if err != nil {
		return fmt.Errorf("export: segment %s: %w", s.info.Name, err)
	}
	defer rc.Close()
	br := bufio.NewReaderSize(rc, 1<<20)
	for ln := 1; ; ln++ {
		line, rerr := readLine(br)
		if len(line) > 0 {
			env, body, err := parseLine(line)
			if err != nil {
				return fmt.Errorf("export: segment %s line %d: %w", s.info.Name, ln, err)
			}
			if err := fn(env, body); err != nil {
				return err
			}
		}
		if rerr == io.EOF {
			return nil
		}
		if rerr != nil {
			return fmt.Errorf("export: segment %s: %w", s.info.Name, rerr)
		}
	}
}

// Record returns the record with the given seq (contracts.ErrNotFound if it is not in the bundle).
func (b *Bundle) Record(seq uint64) (model.Envelope, model.Body, error) {
	for _, s := range b.segs {
		i := s.find(seq)
		if i < 0 {
			continue
		}
		data, err := b.segmentData(s)
		if err != nil {
			return model.Envelope{}, model.Body{}, err
		}
		start := s.offs[i]
		if start >= int64(len(data)) {
			break
		}
		line := data[start:]
		if j := bytes.IndexByte(line, '\n'); j >= 0 {
			line = line[:j+1]
		}
		env, body, err := parseLine(line)
		if err != nil {
			return env, body, fmt.Errorf("export: record %d: %w", seq, err)
		}
		return env, body, nil
	}
	return model.Envelope{}, model.Body{}, fmt.Errorf("export: record %d: %w", seq, contracts.ErrNotFound)
}

func (s *bundleSegment) find(seq uint64) int {
	if s.sorted {
		i := sort.Search(len(s.seqs), func(i int) bool { return s.seqs[i] >= seq })
		if i < len(s.seqs) && s.seqs[i] == seq {
			return i
		}
		return -1
	}
	for i, x := range s.seqs {
		if x == seq {
			return i
		}
	}
	return -1
}

// segmentData returns the decompressed bytes of a segment, keeping the most recently used
// segments in memory so that lookups by seq during a sequential verification stay cheap.
func (b *Bundle) segmentData(s *bundleSegment) ([]byte, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for i, c := range b.cache {
		if c.seg == s {
			copy(b.cache[1:i+1], b.cache[:i])
			b.cache[0] = c
			return c.data, nil
		}
	}
	data, err := readZipFile(s.file, maxSegmentBytes)
	if err != nil {
		return nil, fmt.Errorf("export: segment %s: %w", s.info.Name, err)
	}
	b.cache = append([]*cachedSegment{{seg: s, data: data}}, b.cache...)
	if len(b.cache) > segmentCacheSize {
		b.cache = b.cache[:segmentCacheSize]
	}
	return data, nil
}

// VerifyManifest checks MANIFEST.sha256 of a bundle: every listed file exists and matches its
// SHA-256, every file of the archive is listed, and no entry name is unsafe or duplicated. It
// also checks what a re-computed manifest cannot reveal: the layout of the ledger segments
// (layoutProblems: a segment removed from the middle of a bundle) and the report files, which
// must be exactly what the bundle's records give (VerifyReport: edited figures). The returned
// error wraps ErrManifest (and ErrReportMismatch for the report) and lists the problems.
func VerifyManifest(path string) error {
	zr, err := zip.OpenReader(path)
	if err != nil && !errors.Is(err, zip.ErrInsecurePath) {
		return fmt.Errorf("export: open bundle %s: %w", path, err)
	}
	defer zr.Close()
	var problems []string
	files := map[string]*zip.File{}
	for _, f := range zr.File {
		if strings.HasSuffix(f.Name, "/") {
			continue
		}
		if err := checkEntryName(f.Name); err != nil {
			problems = append(problems, err.Error())
			continue
		}
		if _, dup := files[f.Name]; dup {
			problems = append(problems, fmt.Sprintf("more than one entry named %q", f.Name))
			continue
		}
		files[f.Name] = f
	}
	mf := files[manifestName]
	if mf == nil {
		return manifestError(append(problems, manifestName+" is missing"))
	}
	data, err := readZipFile(mf, maxManifestBytes)
	if err != nil {
		return manifestError(append(problems, fmt.Sprintf("%s unreadable: %v", manifestName, err)))
	}
	listed := map[string]string{}
	var order []string
	for i, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSuffix(line, "\r")
		if line == "" {
			continue
		}
		m := manifestLineRE.FindStringSubmatch(line)
		if m == nil {
			problems = append(problems, fmt.Sprintf("%s line %d is malformed", manifestName, i+1))
			continue
		}
		if _, dup := listed[m[2]]; dup {
			problems = append(problems, fmt.Sprintf("%s lists %s twice", manifestName, m[2]))
			continue
		}
		listed[m[2]] = m[1]
		order = append(order, m[2])
	}
	sort.Strings(order)
	for _, name := range order {
		f := files[name]
		switch {
		case name == manifestName:
			problems = append(problems, manifestName+" lists itself")
		case f == nil:
			problems = append(problems, "listed file is missing: "+name)
		default:
			sum, err := zipFileSHA256(f)
			if err != nil {
				problems = append(problems, fmt.Sprintf("%s unreadable: %v", name, err))
			} else if sum != listed[name] {
				problems = append(problems, fmt.Sprintf("SHA-256 mismatch for %s (manifest %s, actual %s)", name, listed[name], sum))
			}
		}
	}
	var extra []string
	for name := range files {
		if _, ok := listed[name]; !ok && name != manifestName {
			extra = append(extra, name)
		}
	}
	sort.Strings(extra)
	for _, name := range extra {
		problems = append(problems, "file not listed in the manifest: "+name)
	}
	problems = append(problems, layoutProblems(files)...)
	if len(problems) > 0 {
		return manifestError(problems)
	}
	// Nor can a re-computed manifest reveal edited report figures: report.json, REPORT.html,
	// README.txt and keys/public-key.txt must be exactly what the bundle's records give.
	if _, err := VerifyReport(path); err != nil {
		return fmt.Errorf("%w: %w", ErrManifest, err)
	}
	return nil
}

// layoutProblems checks that the ledger segments have the shape the exporter writes: the
// genesis segment plus one contiguous run of daily segments. Only the first segment after the
// genesis segment may follow segments that were left out; any later segment's segment_open
// record must name the included segment before it, otherwise a segment was removed from the
// middle of the bundle (re-computing MANIFEST.sha256 hides that from the manifest check).
// Lines that cannot be read are left to the ledger verification.
func layoutProblems(files map[string]*zip.File) []string {
	var names []string
	for name := range files {
		if m := bundleSegRE.FindStringSubmatch(name); m != nil {
			names = append(names, m[1])
		}
	}
	sort.Strings(names)
	var out []string
	for i := 2; i < len(names); i++ {
		prev, ok := segmentOpenPrev(files["ledger/"+names[i]+".jsonl"])
		if ok && prev != names[i-1] {
			out = append(out, fmt.Sprintf("ledger segment(s) between %s and %s (its segment_open names %q) are missing from the middle of the bundle",
				names[i-1], names[i], truncate(prev, 40)))
		}
	}
	return out
}

// segmentOpenPrev returns prev_segment of the segment_open record that starts a segment.
func segmentOpenPrev(f *zip.File) (string, bool) {
	rc, err := f.Open()
	if err != nil {
		return "", false
	}
	defer rc.Close()
	line, err := readLine(bufio.NewReader(rc))
	if err != nil && !errors.Is(err, io.EOF) {
		return "", false
	}
	_, body, err := parseLine(line)
	if err != nil || body.Type != model.TypeSegmentOpen {
		return "", false
	}
	var so model.SegmentOpen
	if json.Unmarshal(body.Data, &so) != nil {
		return "", false
	}
	return so.PrevSegment, true
}

func manifestError(problems []string) error {
	shown := problems
	if len(shown) > 20 {
		shown = append(append([]string{}, shown[:20]...), fmt.Sprintf("... and %d more", len(problems)-20))
	}
	return fmt.Errorf("%w: %s", ErrManifest, strings.Join(shown, "; "))
}

func zipFileSHA256(f *zip.File) (string, error) {
	rc, err := f.Open()
	if err != nil {
		return "", err
	}
	defer rc.Close()
	h := sha256.New()
	if _, err := io.Copy(h, rc); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
