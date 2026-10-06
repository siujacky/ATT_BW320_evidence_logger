package syslogstore

import (
	"cmp"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"attmonitor/internal/config"
	"attmonitor/internal/contracts"
	"attmonitor/internal/model"
)

// Defaults (docs/syslog-snmp-traffic.md §3.2, config.SyslogConfig).
const (
	DefaultKeepMB     = 100
	DefaultChunkBytes = 1 << 20
	DefaultChunkAge   = 5 * time.Minute
)

const (
	// maxContent bounds the uncompressed content read from one chunk file: far beyond any chunk
	// the store writes, it keeps a damaged or hostile file from being decompressed for ever.
	maxContent = 1 << 30
	// maxLine is the longest line read into memory; a stored message takes about 100 KiB at
	// most (an 8 KiB datagram, JSON-escaped, twice). Longer lines count as messages that cannot
	// be read.
	maxLine = 1 << 20
	// Reasons a chunk is sealed for (model.SyslogChunk.Reason).
	reasonSize      = "size"
	reasonAge       = "age"
	reasonStop      = "stop"
	reasonRecovered = "recovered"
)

var (
	// ErrReadOnly is returned by the writing methods of a store opened with ReadOnly.
	ErrReadOnly = errors.New("syslogstore: the store is read-only")
	// ErrClosed is returned by the writing methods after Close.
	ErrClosed = errors.New("syslogstore: the store is closed")
)

var _ contracts.SyslogStore = (*Store)(nil)

// Options configures New. Zero values select the defaults.
type Options struct {
	// Dir is the store's directory (config.Paths.Syslog). New creates it unless ReadOnly.
	Dir string
	// KeepMB and KeepDays are the retention limits (see SetRetention); KeepMB 0 selects
	// DefaultKeepMB.
	KeepMB, KeepDays int
	// ChunkBytes is the content size at which a chunk is sealed (default 1 MiB); ChunkAge the
	// age from its opening at which Seal seals it (default 5 minutes).
	ChunkBytes int64
	ChunkAge   time.Duration
	// ReadOnly opens the store for reading only: New indexes what it finds, the writing methods
	// fail with ErrReadOnly, and nothing in Dir is created or changed.
	ReadOnly bool
	// Now is the time used when a method is given the zero time (default time.Now).
	Now    func() time.Time
	Logger *slog.Logger
}

// Store is the syslog store (contracts.SyslogStore). It is safe for one writer (the monitor,
// which calls Recover, Append, Seal and Prune) and any number of concurrent readers.
type Store struct {
	o   Options
	log *slog.Logger
	dir string

	// wmu serializes the writing methods. Query holds it shared while it reads the open chunk,
	// so the chunk cannot be sealed, and its file deleted, under it.
	wmu    sync.RWMutex
	closed bool
	// pending are files of sealed chunks and open chunks that could not be deleted when they
	// should have been (another program held them); every writing method tries again.
	pending []string
	// plan are the chunks PlanPrune chose, until CommitPrune deletes them or CancelPrune keeps
	// them (each marked deleting).
	plan []*chunk

	// mu guards the fields below. It is never held during file I/O.
	mu       sync.Mutex
	chunks   []*chunk // the sealed chunks, oldest first (chunkCmp)
	byName   map[string]*chunk
	open     *openChunk // the open chunk; nil when there is none
	keepMB   int
	keepDays int
	// carry are counts that no chunk could take (opening one failed); the next chunk takes them.
	carryDropped, carryRejected int
	// warned lists the problems Query has logged already, by chunk.
	warned map[string]map[string]bool
}

// chunk is a sealed chunk in the index.
type chunk struct {
	meta     model.SyslogChunk
	from, to time.Time // meta.From and meta.To
	n        int       // the number in its name (1 when it has none)
	// rxMin and rxMax are the earliest and latest receive time of its messages (zero without
	// messages); they differ from From and To only when the clock was set back meanwhile.
	rxMin, rxMax time.Time
	path         string
	rebuilt      bool // its sidecar was missing or damaged and was rebuilt from the file
	readers      int  // readers of its file (Query, OpenChunk); Prune does not delete it meanwhile
	deleting     bool // Prune is deleting it, or PlanPrune chose it: no new readers
	// recorded is the seq of its syslog_chunk record as the writer noted it (MarkRecorded; its
	// sidecar keeps it), 0 until then.
	recorded uint64
}

// chunkCmp orders chunks oldest first: by From, To and the number in their names.
func chunkCmp(a, b *chunk) int {
	if c := a.from.Compare(b.from); c != 0 {
		return c
	}
	if c := a.to.Compare(b.to); c != 0 {
		return c
	}
	return cmp.Compare(a.n, b.n)
}

// newest is the time a chunk's age is counted from (KeepDays): its To, or its latest receive
// time when the clock was set back while it was open.
func (c *chunk) newest() time.Time {
	if c.rxMax.After(c.to) {
		return c.rxMax
	}
	return c.to
}

// ref is the chunk's entry in a syslog_prune record.
func (c *chunk) ref() model.SyslogChunkRef {
	return model.SyslogChunkRef{Name: c.meta.Name, SHA256: c.meta.SHA256, From: c.meta.From, To: c.meta.To,
		Messages: c.meta.Messages, GzBytes: c.meta.GzBytes}
}

// openChunk is the chunk messages are appended to.
type openChunk struct {
	name, path string
	nameTime   time.Time // the time in its name: its From when it was opened
	opened     time.Time // when it was opened (ChunkAge counts from here; may carry a monotonic reading)
	f          *os.File  // the writer's handle; nil in a read-only or closed store
	dirty      bool      // a failed write may have left bytes after size
	live       bool      // written by another process (read-only store): read it to its end
	// stateDropped and stateRejected are the counts its state file holds.
	stateDropped, stateRejected int

	// Guarded by Store.mu:
	size              int64 // bytes of complete, synced lines
	messages          int
	rxMin, rxMax      time.Time
	dropped, rejected int
}

// holds reports whether the chunk holds anything worth sealing (s.mu held).
func (oc *openChunk) holds() bool {
	return oc.size > 0 || oc.dropped > 0 || oc.rejected > 0
}

// sidecar is the content of a sealed chunk's sidecar file: the payload of its syslog_chunk
// record, the range of its messages' receive times and, once the writer noted it, the seq of
// that record.
type sidecar struct {
	model.SyslogChunk
	RXMin    string `json:"rx_min,omitempty"`
	RXMax    string `json:"rx_max,omitempty"`
	Recorded uint64 `json:"recorded_seq,omitempty"`
}

// sidecar returns the sidecar that describes c (s.mu held).
func (c *chunk) sidecar() sidecar {
	sc := sidecar{SyslogChunk: c.meta, Recorded: c.recorded}
	if !c.rxMin.IsZero() {
		sc.RXMin, sc.RXMax = formatRX(c.rxMin), formatRX(c.rxMax)
	}
	return sc
}

// New opens the store in o.Dir and indexes its sealed chunks from their sidecar files. A
// missing or damaged sidecar is rebuilt from its chunk file (in a read-only store only in
// memory); a chunk file that cannot be read is logged, left as it is and not counted as kept.
// A writer must call Recover before the first Append. With ReadOnly, the open chunk of the
// writer (another process) is read as it grows; o.Dir must exist.
func New(o Options) (*Store, error) {
	if o.Dir == "" {
		return nil, errors.New("syslogstore: Options.Dir is required")
	}
	if o.KeepMB == 0 {
		o.KeepMB = DefaultKeepMB
	}
	o.KeepMB, o.KeepDays = clampRetention(o.KeepMB, o.KeepDays)
	if o.ChunkBytes <= 0 {
		o.ChunkBytes = DefaultChunkBytes
	}
	if o.ChunkAge <= 0 {
		o.ChunkAge = DefaultChunkAge
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
	s := &Store{
		o:        o,
		log:      o.Logger,
		dir:      o.Dir,
		byName:   map[string]*chunk{},
		keepMB:   o.KeepMB,
		keepDays: o.KeepDays,
		warned:   map[string]map[string]bool{},
	}
	if o.ReadOnly {
		st, err := os.Stat(o.Dir)
		if err != nil {
			return nil, fmt.Errorf("syslogstore: %w", err)
		}
		if !st.IsDir() {
			return nil, fmt.Errorf("syslogstore: %s is not a directory", o.Dir)
		}
	} else if err := os.MkdirAll(o.Dir, 0o755); err != nil {
		return nil, fmt.Errorf("syslogstore: %w", err)
	}
	if err := s.index(); err != nil {
		return nil, err
	}
	return s, nil
}

// clampRetention brings retention limits into the range the configuration allows.
func clampRetention(keepMB, keepDays int) (int, int) {
	return min(max(keepMB, config.MinSyslogKeepMB), config.MaxSyslogKeepMB),
		min(max(keepDays, 0), config.MaxSyslogKeepDays)
}

// index reads the directory: the sealed chunks and, in a read-only store, the open chunk.
func (s *Store) index() error {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return fmt.Errorf("syslogstore: %w", err)
	}
	var opens []string
	for _, e := range entries {
		if !e.Type().IsRegular() {
			continue
		}
		name := e.Name()
		if _, ok := parseOpenName(name); ok {
			opens = append(opens, name)
			continue
		}
		if _, _, _, ok := parseSealedName(name); !ok {
			continue
		}
		c, err := s.loadChunk(name)
		if errors.Is(err, fs.ErrNotExist) {
			continue // deleted meanwhile
		}
		if err != nil {
			st, _ := os.Stat(filepath.Join(s.dir, name))
			var size int64
			if st != nil {
				size = st.Size()
			}
			s.log.Warn("syslog store: a chunk cannot be read; it is left as it is and not counted as kept",
				"chunk", name, "bytes", size, "err", err)
			continue
		}
		s.chunks = append(s.chunks, c)
		s.byName[name] = c
	}
	slices.SortFunc(s.chunks, chunkCmp)
	if s.o.ReadOnly {
		s.indexOpen(opens)
	}
	return nil
}

// loadChunk indexes the sealed chunk name from its sidecar, or from its file when the sidecar
// is missing or does not describe it (writing the sidecar again unless read-only).
func (s *Store) loadChunk(name string) (*chunk, error) {
	path := filepath.Join(s.dir, name)
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	sc, why := readSidecar(path+sidecarExt, name, st.Size())
	if why == "" {
		return newChunk(sc, path), nil
	}
	sc, err = describeChunk(path, name)
	if err != nil {
		return nil, err
	}
	c := newChunk(sc, path)
	c.rebuilt = true
	switch {
	case s.o.ReadOnly:
		s.log.Info("syslog store: a chunk's sidecar file is "+why+"; the chunk was described from its file (read-only: not written)",
			"chunk", name)
	default:
		if err := writeSidecar(path, sc); err != nil {
			s.log.Warn("syslog store: a chunk's sidecar file is "+why+" and could not be written again",
				"chunk", name, "err", err)
		} else {
			s.log.Info("syslog store: a chunk's sidecar file was "+why+"; rebuilt from the chunk", "chunk", name)
		}
	}
	return c, nil
}

// readSidecar reads the sidecar file path of the chunk name whose file has gzBytes bytes. why
// is "" when the sidecar describes the chunk, else what is wrong with it.
func readSidecar(path, name string, gzBytes int64) (sc sidecar, why string) {
	b, err := os.ReadFile(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return sc, "missing"
	case err != nil:
		return sc, "unreadable"
	case json.Unmarshal(b, &sc) != nil:
		return sc, "damaged"
	case sc.Name != name:
		return sc, "about another chunk"
	case sc.GzBytes != gzBytes:
		return sc, "not about the chunk file as it is (size)"
	}
	from, ok1 := parseRX(sc.From)
	to, ok2 := parseRX(sc.To)
	sum, err := hex.DecodeString(sc.SHA256)
	if !ok1 || !ok2 || err != nil || len(sum) != sha256.Size || hex.EncodeToString(sum) != sc.SHA256 ||
		sc.Messages < 0 || sc.Dropped < 0 || sc.Rejected < 0 || sc.Bytes < 0 || from.After(to) && sc.Messages == 0 {
		return sc, "damaged"
	}
	for _, v := range []string{sc.RXMin, sc.RXMax} {
		if _, ok := parseRX(v); v != "" && !ok {
			return sc, "damaged"
		}
	}
	return sc, ""
}

// newChunk returns the index entry of a chunk described by sc.
func newChunk(sc sidecar, path string) *chunk {
	from, _ := parseRX(sc.From)
	to, _ := parseRX(sc.To)
	_, _, n, _ := parseSealedName(sc.Name)
	c := &chunk{meta: sc.SyslogChunk, from: from, to: to, n: max(n, 1), path: path, recorded: sc.Recorded}
	if sc.Messages > 0 {
		c.rxMin, c.rxMax = from, to
		if to.Before(from) {
			c.rxMin, c.rxMax = to, from
		}
		if t, ok := parseRX(sc.RXMin); ok && t.Before(c.rxMin) {
			c.rxMin = t
		}
		if t, ok := parseRX(sc.RXMax); ok && t.After(c.rxMax) {
			c.rxMax = t
		}
	}
	return c
}

// describeChunk reads the sealed chunk file path (named name) and describes it as a sidecar
// would. The counts and the reason it was sealed for are not in the file: the description
// says 0 and "recovered" (the chunk's syslog_chunk record keeps them).
func describeChunk(path, name string) (sidecar, error) {
	nameFrom, nameTo, _, _ := parseSealedName(name)
	f, err := openShared(path)
	if err != nil {
		return sidecar{}, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return sidecar{}, err
	}
	zr, err := gzip.NewReader(f)
	if err != nil {
		return sidecar{}, fmt.Errorf("not a gzip file: %w", err)
	}
	d := newDigester()
	n, err := io.Copy(d, io.LimitReader(zr, maxContent+1))
	if err != nil {
		return sidecar{}, fmt.Errorf("cannot be decompressed: %w", err)
	}
	if n > maxContent {
		return sidecar{}, fmt.Errorf("decompresses to more than %d bytes", maxContent)
	}
	dg := d.finish()
	from, to := nameFrom, nameTo
	if dg.sum.timed {
		from, to = dg.sum.first, dg.sum.last
	}
	return dg.sidecar(name, from, to, st.Size(), 0, 0, reasonRecovered), nil
}

// writeSidecar writes the sidecar of the sealed chunk file chunkPath (temporary file, fsync,
// rename).
func writeSidecar(chunkPath string, sc sidecar) error {
	b, err := json.Marshal(sc)
	if err != nil {
		return err
	}
	return writeFileAtomic(chunkPath+sidecarExt, append(b, '\n'))
}

// writeFileAtomic replaces path with data: a temporary file is written, fsynced and renamed.
func writeFileAtomic(path string, data []byte) error {
	tmp := path + tmpExt
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = renameReplace(tmp, path)
	}
	if err != nil {
		os.Remove(tmp)
	}
	return err
}

// indexOpen takes the newest open chunk file of a read-only store's directory as the open
// chunk (older ones are left over from a crash, or sealed already).
func (s *Store) indexOpen(names []string) {
	slices.Sort(names)
	for i := len(names) - 1; i >= 0; i-- {
		name := names[i]
		if st, err := readState(filepath.Join(s.dir, stateName(name))); err == nil && st.Sealed != "" {
			continue
		}
		path := filepath.Join(s.dir, name)
		f, err := openShared(path)
		if err != nil {
			s.log.Warn("syslog store: the open chunk cannot be read", "chunk", name, "err", err)
			return
		}
		d := newDigester()
		_, err = io.Copy(d, io.LimitReader(f, maxContent))
		f.Close()
		if err != nil {
			s.log.Warn("syslog store: the open chunk cannot be read", "chunk", name, "err", err)
			return
		}
		dg := d.finish()
		if dg.partial > 0 {
			dg.bytes -= dg.partial // a line being written
			dg.sum.messages--
		}
		t, _ := parseOpenName(name)
		s.open = &openChunk{name: name, path: path, nameTime: t, opened: t, live: true,
			size: dg.bytes, messages: dg.sum.messages, rxMin: dg.sum.min, rxMax: dg.sum.max}
		return
	}
}

// Usage reports the stored volume and the retention limits: the sealed chunks (their gzip
// size) and the open chunk (its size as written). Chunks that are being deleted, or that
// PlanPrune chose, no longer count. It never waits for file I/O.
func (s *Store) Usage() model.SyslogUsage {
	s.mu.Lock()
	defer s.mu.Unlock()
	u := model.SyslogUsage{KeepMB: s.keepMB, KeepDays: s.keepDays}
	var oldest, newest time.Time
	extend := func(lo, hi time.Time) {
		if lo.IsZero() {
			return
		}
		if oldest.IsZero() || lo.Before(oldest) {
			oldest = lo
		}
		if hi.After(newest) {
			newest = hi
		}
	}
	for _, c := range s.chunks {
		if c.deleting {
			continue
		}
		u.Bytes += c.meta.GzBytes
		u.Chunks++
		u.Messages += int64(c.meta.Messages)
		extend(c.rxMin, c.rxMax)
	}
	if oc := s.open; oc != nil {
		u.Bytes += oc.size
		u.OpenMessages = oc.messages
		u.Messages += int64(oc.messages)
		extend(oc.rxMin, oc.rxMax)
	}
	if !oldest.IsZero() {
		u.Oldest, u.Newest = formatRX(oldest), formatRX(newest)
	}
	return u
}

// Chunks returns the sealed chunks the store keeps, oldest first, as their sidecars describe
// them (for a sidecar rebuilt from its chunk file, the counts and the reason are not known: 0
// and "recovered"). The monitor can compare them with its syslog_chunk records.
func (s *Store) Chunks() []model.SyslogChunk {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]model.SyslogChunk, len(s.chunks))
	for i, c := range s.chunks {
		out[i] = c.meta
	}
	return out
}

// Unrecorded returns the sealed chunks whose syslog_chunk record the writer has not noted
// (MarkRecorded), oldest first, as their sidecars describe them: the chunks sealed since the
// writer could last record one - by Recover, or while the ledger refused records, also in a run
// that ended before it could record them - and chunks whose sidecar was rebuilt from the chunk
// file (their record may well exist: the writer looks for it in the ledger before recording one).
// Chunks chosen for deletion are left out.
func (s *Store) Unrecorded() []model.SyslogChunk {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []model.SyslogChunk
	for _, c := range s.chunks {
		if c.recorded == 0 && !c.deleting {
			out = append(out, c.meta)
		}
	}
	return out
}

// MarkRecorded notes that the sealed chunk name has its syslog_chunk record, the record seq: its
// sidecar keeps the seq (written through a temporary file), so Unrecorded leaves the chunk out
// from now on, also after a restart. The writer calls it after each syslog_chunk record it
// appends. A chunk the store does not keep gives an error wrapping contracts.ErrNotFound.
func (s *Store) MarkRecorded(name string, seq uint64) error {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	if err := s.writable(); err != nil {
		return err
	}
	if seq == 0 {
		return errors.New("syslogstore: a syslog_chunk record cannot have seq 0 (the genesis record's)")
	}
	s.mu.Lock()
	c := s.byName[name]
	var sc sidecar
	if c != nil {
		sc = c.sidecar()
	}
	s.mu.Unlock()
	switch {
	case c == nil:
		return fmt.Errorf("syslogstore: chunk %q: %w", name, contracts.ErrNotFound)
	case sc.Recorded == seq:
		return nil
	}
	sc.Recorded = seq
	if err := writeSidecar(c.path, sc); err != nil {
		return fmt.Errorf("syslogstore: note the record of chunk %s: %w", name, err)
	}
	s.mu.Lock()
	c.recorded = seq
	s.mu.Unlock()
	return nil
}

// SetRetention changes the retention limits: at most keepMB MiB of chunks (at least
// config.MinSyslogKeepMB) and, with keepDays above 0, no chunk older than that many days
// (values beyond the configuration's limits are brought within them). Prune applies them.
func (s *Store) SetRetention(keepMB, keepDays int) {
	keepMB, keepDays = clampRetention(keepMB, keepDays)
	s.mu.Lock()
	s.keepMB, s.keepDays = keepMB, keepDays
	s.mu.Unlock()
}

// Close closes the open chunk's file without sealing it (the next run's Recover seals it).
// Afterwards the writing methods fail with ErrClosed; reading keeps working.
func (s *Store) Close() error {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	if oc := s.open; oc != nil && oc.f != nil {
		err := oc.f.Close()
		oc.f = nil
		if err != nil {
			return fmt.Errorf("syslogstore: %w", err)
		}
	}
	return nil
}

// writable reports why the writing methods cannot run (s.wmu held).
func (s *Store) writable() error {
	switch {
	case s.o.ReadOnly:
		return ErrReadOnly
	case s.closed:
		return ErrClosed
	}
	return nil
}

// when returns now, or the current time when now is the zero time.
func (s *Store) when(now time.Time) time.Time {
	if now.IsZero() {
		return s.o.Now()
	}
	return now
}
