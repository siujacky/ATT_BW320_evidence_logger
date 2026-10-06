package export

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"attmonitor/internal/contracts"
	"attmonitor/internal/model"
)

// Syslog chunks (docs/syslog-snmp-traffic.md §3.2). The syslog store keeps the gateway's syslog
// messages in gzip chunk files within a size limit, so they cannot live in the ledger, which
// never deletes anything: the ledger holds a syslog_chunk record for every sealed chunk (the
// SHA-256, size and message count of its uncompressed content, and the time range of its
// messages) and a syslog_prune record for every deletion. A bundle includes the chunks of its
// period that the store still keeps, as syslog/<name> with the exact stored bytes (listed in
// MANIFEST.sha256), and VerifySyslogChunks and tools/verify_bundle.py check each against its
// syslog_chunk record. The report files do not describe the chunks: they stay a function of the
// ledger records (VerifyReport).

const (
	// syslogDir is the bundle folder of the syslog chunks.
	syslogDir = "syslog/"
	// maxChunkFileBytes bounds a chunk file read from the syslog store (a sealed chunk holds
	// about 1 MiB of messages before compression).
	maxChunkFileBytes = 256 << 20
	// maxChunkContentBytes bounds the uncompressed content of a chunk that is verified.
	maxChunkContentBytes = 1 << 30
)

// ErrSyslogMismatch is wrapped by VerifySyslogChunks errors when a syslog chunk of a bundle is
// not what its syslog_chunk record states, or no syslog_chunk record of the bundle names it.
var ErrSyslogMismatch = errors.New("export: the syslog chunks of the bundle are not what its syslog_chunk records state")

// errChunkTooLarge: the uncompressed content of a chunk is larger than the reader's limit.
var errChunkTooLarge = errors.New("chunk content larger than the limit")

// syslogRec is a usable syslog_chunk record.
type syslogRec struct {
	seq      uint64
	chunk    model.SyslogChunk
	from, to time.Time // receive times of the chunk's first and last message
	timed    bool      // from and to are valid times
}

// parseSyslogChunk reads a syslog_chunk record. A record whose chunk name is not a plain file
// name (checkChunkName) or that states no SHA-256, or a negative size or message count, is not
// usable: no file of a bundle can be checked against it.
func parseSyslogChunk(body model.Body) (syslogRec, error) {
	var c model.SyslogChunk
	if err := json.Unmarshal(body.Data, &c); err != nil {
		return syslogRec{}, err
	}
	switch {
	case checkChunkName(c.Name) != nil:
		return syslogRec{}, fmt.Errorf("its chunk name %q is not a plain file name", truncate(c.Name, 80))
	case !isHex64(strings.ToLower(c.SHA256)):
		return syslogRec{}, fmt.Errorf("its sha256 %q is not a SHA-256", truncate(c.SHA256, 80))
	case c.Bytes < 0 || c.Messages < 0:
		return syslogRec{}, errors.New("it states a negative size or message count")
	}
	r := syslogRec{seq: body.Seq, chunk: c}
	var fromOK, toOK bool
	r.from, fromOK = parseTS(c.From)
	r.to, toOK = parseTS(c.To)
	r.timed = fromOK && toOK
	return r, nil
}

// overlaps reports whether the chunk's messages, received from r.from to r.to, overlap the
// period [from, to). A chunk without valid times overlaps no period.
func (r *syslogRec) overlaps(from, to time.Time) bool {
	return r.timed && r.from.Before(to) && !r.to.Before(from)
}

// checkChunkName accepts the name of a chunk file that can go into a bundle (syslog/<name>) and
// be extracted anywhere: one plain path element (checkExtraPath), no slash.
func checkChunkName(name string) error {
	if strings.Contains(name, "/") {
		return errors.New("it contains a slash")
	}
	return checkExtraPath(name)
}

// syslogChunk remembers a syslog_chunk record of the bundle being written: its chunk goes into
// the bundle when it overlaps the period (copySyslogChunks). The report does not use it.
func (c *collector) syslogChunk(body model.Body) {
	if r, err := parseSyslogChunk(body); err == nil {
		c.syslog = append(c.syslog, r)
	}
}

// copySyslogChunks puts into the bundle the syslog chunks of the period that the syslog store
// still keeps: those named by the bundle's syslog_chunk records whose messages overlap the
// period, in ledger order, as syslog/<name> with the exact stored bytes. A chunk the store no
// longer has (deleted by the retention limit) is left out, and so is one it cannot read or whose
// name, ignoring case, an earlier chunk took; the verifiers list them. It returns the number of
// chunks written.
func (e *Exporter) copySyslogChunks(ctx context.Context, bw *bundleWriter, col *collector) (int, error) {
	if e.opts.Syslog == nil {
		return 0, nil
	}
	byName := map[string][]syslogRec{}
	for _, r := range col.syslog {
		byName[r.chunk.Name] = append(byName[r.chunk.Name], r)
	}
	taken := map[string]bool{}
	n := 0
	for i := range col.syslog {
		r := &col.syslog[i]
		key := strings.ToLower(r.chunk.Name)
		if taken[key] || !r.overlaps(col.from, col.to) {
			continue
		}
		taken[key] = true
		if err := ctx.Err(); err != nil {
			return n, err
		}
		data, err := readChunkFile(e.opts.Syslog, r.chunk.Name)
		if errors.Is(err, contracts.ErrNotFound) {
			continue // deleted by the retention limit: the records still state its SHA-256
		}
		if err != nil {
			e.log.Warn("export: syslog chunk left out of the bundle: it cannot be read", "chunk", r.chunk.Name, "seq", r.seq, "err", err)
			continue
		}
		if err := bw.addFile(syslogDir+r.chunk.Name, data); err != nil {
			return n, err
		}
		n++
		if problem := matchChunk(bytes.NewReader(data), byName[r.chunk.Name]); problem != "" {
			e.log.Warn("export: syslog chunk does not match its syslog_chunk record; it is exported as stored and the bundle's "+
				"verification will report it", "chunk", r.chunk.Name, "seq", r.seq, "problem", problem)
		}
	}
	return n, nil
}

// readChunkFile reads the exact stored bytes of a sealed chunk (contracts.ErrNotFound when the
// store no longer has it).
func readChunkFile(s contracts.SyslogReader, name string) ([]byte, error) {
	rc, err := s.OpenChunk(name)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	data, err := io.ReadAll(io.LimitReader(rc, maxChunkFileBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxChunkFileBytes {
		return nil, fmt.Errorf("the chunk file is larger than %d bytes", maxChunkFileBytes)
	}
	return data, nil
}

// chunkDigest describes the uncompressed content of a chunk file.
type chunkDigest struct {
	sha256 string
	bytes  int64
	lines  int // line feeds: a chunk holds one message (a JSON object) per line
}

// digestChunk decompresses a chunk file - gzip: one or more members and nothing after them -
// and digests its content, reading at most limit bytes of it (errChunkTooLarge beyond).
func digestChunk(r io.Reader, limit int64) (chunkDigest, error) {
	zr, err := gzip.NewReader(r)
	if errors.Is(err, io.EOF) {
		return chunkDigest{}, errors.New("it is not a valid gzip file: it is empty")
	}
	if err != nil {
		return chunkDigest{}, fmt.Errorf("it is not a valid gzip file: %v", err)
	}
	defer zr.Close()
	h := sha256.New()
	var d chunkDigest
	buf := make([]byte, 64<<10)
	for {
		n, err := zr.Read(buf)
		if n > 0 {
			if d.bytes += int64(n); d.bytes > limit {
				return chunkDigest{}, errChunkTooLarge
			}
			h.Write(buf[:n])
			d.lines += bytes.Count(buf[:n], []byte{'\n'})
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return chunkDigest{}, fmt.Errorf("it is not a valid gzip file: %v", err)
		}
	}
	d.sha256 = hex.EncodeToString(h.Sum(nil))
	return d, nil
}

// matchChunk checks a chunk file against the syslog_chunk records that name it: it must be gzip
// whose uncompressed content has the SHA-256, size and number of lines (messages) one of them
// states. It returns "" when it has, else what is wrong.
func matchChunk(r io.Reader, recs []syslogRec) string {
	if len(recs) == 0 {
		return "no syslog_chunk record in this bundle names it"
	}
	largest := &recs[0]
	for i := range recs {
		if recs[i].chunk.Bytes > largest.chunk.Bytes {
			largest = &recs[i]
		}
	}
	limit := min(largest.chunk.Bytes, maxChunkContentBytes)
	d, err := digestChunk(r, limit)
	switch {
	case errors.Is(err, errChunkTooLarge) && limit < maxChunkContentBytes:
		return fmt.Sprintf("uncompressed it is larger than the %s its syslog_chunk record (seq %d) states",
			plural(largest.chunk.Bytes, "byte", "bytes"), largest.seq)
	case errors.Is(err, errChunkTooLarge):
		return fmt.Sprintf("uncompressed it is larger than %s, more than a chunk can hold", plural(limit, "byte", "bytes"))
	case err != nil:
		return err.Error()
	}
	for i := range recs {
		if chunkDiff(d, &recs[i]) == "" {
			return ""
		}
	}
	last := &recs[len(recs)-1]
	return fmt.Sprintf("it is not what its syslog_chunk record (seq %d) states: %s", last.seq, chunkDiff(d, last))
}

// chunkDiff lists how a chunk's content differs from a record ("" = it matches).
func chunkDiff(d chunkDigest, r *syslogRec) string {
	var out []string
	if !strings.EqualFold(d.sha256, r.chunk.SHA256) {
		out = append(out, fmt.Sprintf("its SHA-256 is %s, the record states %s", d.sha256, strings.ToLower(r.chunk.SHA256)))
	}
	if d.bytes != r.chunk.Bytes {
		out = append(out, fmt.Sprintf("it holds %s, the record states %s", plural(d.bytes, "byte", "bytes"), plural(r.chunk.Bytes, "byte", "bytes")))
	}
	if d.lines != r.chunk.Messages {
		out = append(out, fmt.Sprintf("it holds %s, the record states %s", plural(d.lines, "message (line)", "messages (lines)"),
			plural(r.chunk.Messages, "message", "messages")))
	}
	return strings.Join(out, "; ")
}

// ------------------------------------------------------------------ verification

// SyslogCheck is the outcome of VerifySyslogChunks.
type SyslogCheck struct {
	// Records counts the usable syslog_chunk records of the bundle, OfPeriod those whose
	// messages overlap the period report.json states (all of them when it states none).
	Records, OfPeriod int
	// Files counts the chunk files of the bundle (syslog/<name>), Verified those that match their
	// syslog_chunk record: SHA-256, size and line (message) count of their uncompressed content.
	Files, Verified int
	// Pruned names the chunks of the period that are not in the bundle because the retention
	// limit deleted them (a syslog_prune record of the bundle says so); Absent the other chunks
	// of the period that are not in the bundle (deleted after the bundle's records, or not
	// readable at export). Neither is a failure: their records still state their SHA-256.
	Pruned, Absent []string
	// Problems lists the chunk files that are not what their record states, or that no record
	// names; Notes the records that cannot be used and a period that cannot be read.
	Problems, Notes []string
}

// OK reports whether every chunk file of the bundle matches its syslog_chunk record.
func (c *SyslogCheck) OK() bool { return len(c.Problems) == 0 }

// Summary describes the outcome in one line, without a verdict.
func (c *SyslogCheck) Summary() string {
	if c.Records == 0 && c.Files == 0 {
		return "no syslog chunks in this bundle"
	}
	var s string
	switch {
	case !c.OK():
		s = fmt.Sprintf("%d of %s match their syslog_chunk record; %s, first: %s", c.Verified,
			plural(c.Files, "chunk file", "chunk files"), plural(len(c.Problems), "problem", "problems"), c.Problems[0])
	case c.Files == 0:
		s = "no chunk files in this bundle"
	case c.Files == 1:
		s = "1 chunk file, matching the SHA-256, size and message count its syslog_chunk record states"
	default:
		s = plural(c.Files, "chunk file", "chunk files") + ", each matching the SHA-256, size and message count its syslog_chunk record states"
	}
	if len(c.Pruned) == 0 && len(c.Absent) == 0 {
		return s
	}
	return fmt.Sprintf("%s; of the %s of the period, %d deleted by the retention limit according to a syslog_prune record and %d "+
		"not in the bundle for another reason: deleted after the records of this bundle, or unreadable at export", s,
		plural(c.OfPeriod, "chunk", "chunks"), len(c.Pruned), len(c.Absent))
}

// VerifySyslogChunks checks the syslog chunks of a bundle (syslog/<name>): each must be named by
// a syslog_chunk record of the bundle and be gzip whose uncompressed content has the SHA-256,
// size and number of lines (messages) that record states. It also lists the chunks of the
// period (report.json) that are not in the bundle, deleted by the retention limit (a
// syslog_prune record of the bundle names them) or not kept at export; they are not failures.
// The records themselves are verified by the ledger verification of the bundle. The error is
// nil only when every chunk file matches; it wraps ErrSyslogMismatch otherwise (with the
// SyslogCheck) and is another error when the bundle cannot be read (without one).
func VerifySyslogChunks(path string) (*SyslogCheck, error) {
	b, err := OpenBundle(path)
	if err != nil {
		return nil, err
	}
	defer b.Close()
	return verifySyslogChunks(context.Background(), b)
}

// verifySyslogChunks implements VerifySyslogChunks on an open bundle.
func verifySyslogChunks(ctx context.Context, b *Bundle) (*SyslogCheck, error) {
	chk := &SyslogCheck{}
	recs, pruned, err := b.syslogRecords(ctx, chk)
	if err != nil {
		return nil, err
	}
	chk.Records = len(recs)
	byName := map[string][]syslogRec{}
	for _, r := range recs {
		byName[r.chunk.Name] = append(byName[r.chunk.Name], r)
	}

	var names []string
	for name := range b.files {
		if n, ok := strings.CutPrefix(name, syslogDir); ok {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	for _, name := range names {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		chk.Files++
		problem := "no syslog_chunk record in this bundle names it"
		if cands := byName[name]; len(cands) > 0 {
			rc, err := b.files[syslogDir+name].Open()
			if err != nil {
				problem = "it cannot be read: " + err.Error()
			} else {
				problem = matchChunk(rc, cands)
				rc.Close()
			}
		}
		if problem == "" {
			chk.Verified++
		} else {
			chk.Problems = append(chk.Problems, syslogDir+name+": "+problem)
		}
	}

	from, to, periodOK := bundlePeriod(b)
	if !periodOK && len(recs) > 0 {
		chk.Notes = append(chk.Notes, "report.json states no usable period: every syslog_chunk record of the bundle counts as one of the period")
	}
	listed := map[string]bool{}
	for i := range recs {
		r := &recs[i]
		if periodOK && !r.overlaps(from, to) {
			continue
		}
		chk.OfPeriod++
		name := r.chunk.Name
		if b.files[syslogDir+name] != nil || listed[name] {
			continue
		}
		listed[name] = true
		if prunedChunk(pruned, r) {
			chk.Pruned = append(chk.Pruned, name)
		} else {
			chk.Absent = append(chk.Absent, name)
		}
	}
	if len(chk.Problems) > 0 {
		more := ""
		if n := len(chk.Problems) - 1; n > 0 {
			more = fmt.Sprintf(" (and %s)", plural(n, "more problem", "more problems"))
		}
		return chk, fmt.Errorf("%w: %s%s", ErrSyslogMismatch, chk.Problems[0], more)
	}
	return chk, nil
}

// prunedChunk reports whether a syslog_prune record deleted the chunk of r: one names it, with
// the SHA-256 r states (or none).
func prunedChunk(pruned []model.SyslogChunkRef, r *syslogRec) bool {
	for _, p := range pruned {
		if p.Name == r.chunk.Name && (p.SHA256 == "" || strings.EqualFold(p.SHA256, r.chunk.SHA256)) {
			return true
		}
	}
	return false
}

// syslogRecords reads the usable syslog_chunk records of a bundle and the chunks its
// syslog_prune records name, in bundle order. Records that cannot be used are noted in chk;
// lines that cannot be parsed at all are left to the ledger verification.
func (b *Bundle) syslogRecords(ctx context.Context, chk *SyslogCheck) ([]syslogRec, []model.SyslogChunkRef, error) {
	var recs []syslogRec
	var pruned []model.SyslogChunkRef
	note := func(body model.Body, err error) {
		if len(chk.Notes) < 20 {
			chk.Notes = append(chk.Notes, fmt.Sprintf("%s record seq %d cannot be used: %v", body.Type, body.Seq, err))
		}
	}
	for _, s := range b.segs {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		err := func() error {
			rc, err := s.file.Open()
			if err != nil {
				return fmt.Errorf("export: segment %s: %w", s.info.Name, err)
			}
			defer rc.Close()
			br := bufio.NewReaderSize(rc, 1<<20)
			for {
				line, rerr := readLine(br)
				// The writer never escapes letters in JSON, so a syslog record's line holds its
				// type as written: the other lines are not parsed.
				if bytes.Contains(line, []byte("syslog_")) {
					if _, body, err := parseLine(line); err == nil {
						switch body.Type {
						case model.TypeSyslogChunk:
							if r, err := parseSyslogChunk(body); err != nil {
								note(body, err)
							} else {
								recs = append(recs, r)
							}
						case model.TypeSyslogPrune:
							var p model.SyslogPrune
							if err := json.Unmarshal(body.Data, &p); err != nil {
								note(body, err)
							} else {
								pruned = append(pruned, p.Deleted...)
							}
						}
					}
				}
				if rerr == io.EOF {
					return nil
				}
				if rerr != nil {
					return fmt.Errorf("export: segment %s: %w", s.info.Name, rerr)
				}
			}
		}()
		if err != nil {
			return nil, nil, err
		}
	}
	return recs, pruned, nil
}

// bundlePeriod returns the period [from, to) report.json states (ok false when it states none
// that can be used).
func bundlePeriod(b *Bundle) (from, to time.Time, ok bool) {
	f := b.files["report.json"]
	if f == nil {
		return from, to, false
	}
	data, err := readZipFile(f, maxManifestBytes)
	if err != nil {
		return from, to, false
	}
	var r struct {
		Period struct {
			From string `json:"from"`
			To   string `json:"to"`
		} `json:"period"`
	}
	if json.Unmarshal(data, &r) != nil {
		return from, to, false
	}
	from, fromOK := parseTS(r.Period.From)
	to, toOK := parseTS(r.Period.To)
	return from, to, fromOK && toOK && from.Before(to)
}
