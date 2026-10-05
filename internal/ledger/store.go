// Package ledger implements att-monitor's evidence ledger (docs/DESIGN.md §3, §5-§7): an
// append-only, hash-chained, Ed25519-signed sequence of JSON records stored as one segment file
// per UTC day, a content-addressed blob store for raw evidence, crash recovery that never
// silently discards bytes, and a streaming verifier usable on the live ledger and on exported
// evidence bundles.
//
// Record encoding (normative, docs/DESIGN.md §6): the body is serialized once to the string b;
// h = hex SHA-256 of the bytes of b; s = base64 Ed25519 signature over the bytes of b; each
// line is the JSON object {"h","s","b"} followed by '\n'. Verification never re-serializes.
//
// Reading versus verifying: the reading methods (Scan, ScanTime, Record, Segments, OpenSegment,
// Head) are lenient. They skip lines that cannot be parsed and check neither hashes, signatures
// nor the chain, so they return what the files hold, tampered or not. Verify and VerifyReader are
// authoritative: they check every line strictly and report every problem the readers pass over.
// Anything presented as evidence must rest on a verification result, not on a read alone.
package ledger

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"attmonitor/internal/config"
	"attmonitor/internal/contracts"
	"attmonitor/internal/model"
)

// Compile-time interface conformance.
var (
	_ contracts.Ledger       = (*Store)(nil)
	_ contracts.LedgerReader = (*Store)(nil)
	_ contracts.Verifier     = (*Store)(nil)
)

var (
	// ErrLocked is returned by Open when another writer holds ledger/.lock.
	ErrLocked = errors.New("ledger: the ledger is locked by another writer")
	// ErrReadOnly is returned by write operations on a store opened with ReadOnly.
	ErrReadOnly = errors.New("ledger: store is read-only")
	// ErrClosed is returned by write operations after Close.
	ErrClosed = errors.New("ledger: store is closed")
	// ErrBlobCorrupt is returned by GetBlob when stored content does not match its id.
	ErrBlobCorrupt = errors.New("ledger: blob is corrupt")
)

// DefaultStatement is the genesis statement used when Options.Statement is empty.
const DefaultStatement = "This is the genesis record of an att-monitor evidence ledger. From this record on, " +
	"att-monitor appends what it observes about this computer's Internet connection through the AT&T gateway: " +
	"every probe result and its classification, the gateway's own status pages (every fetch identified by " +
	"its SHA-256 and the values parsed from it; the exact bytes kept in a content-addressed blob store " +
	"whenever a decisive value changes, during incidents and at least every five minutes), incidents, " +
	"monitor starts, stops and gaps, " +
	"power events, clock checks, configuration changes, operator notes and evidence exports. " +
	"Records are only ever appended: each one carries the SHA-256 hash of the previous record and is signed " +
	"with the Ed25519 key whose fingerprint appears in this record, so editing, deleting, inserting or " +
	"reordering any record is detectable. Bytes damaged by a crash are moved to quarantine and documented " +
	"by a recovery record, never silently discarded. RFC 3161 time-stamps from independent authorities " +
	"periodically fix the chain head in time."

// Options configures Open.
type Options struct {
	Paths         config.Paths            // uses Paths.Ledger, Blobs, Keys, Quarantine
	Host          model.HostInfo          // genesis
	Software      model.SoftwareInfo      // genesis
	Statement     string                  // genesis statement ("" → DefaultStatement)
	TokenVerifier contracts.TokenVerifier // optional; used by Verify for anchor records
	FastInterval  time.Duration           // for gap detection in Verify (default 10s)
	Now           func() time.Time        // default time.Now
	Logger        *slog.Logger
	ReadOnly      bool // no lock, no key, no writes (verification/reading)
	// KeyProtect/KeyUnprotect default to DPAPI machine scope (internal/secret); tests may
	// inject identity functions.
	KeyProtect   func([]byte) ([]byte, error)
	KeyUnprotect func([]byte) ([]byte, error)

	// monoClock replaces the monotonic clock in tests: it returns the time elapsed since an
	// arbitrary origin.
	monoClock func() time.Duration
}

// activeSeg is the writer's open segment.
type activeSeg struct {
	name     string
	date     time.Time
	path     string
	f        *os.File // nil until a record must be written (after removal of a damaged segment)
	size     int64    // bytes of complete lines
	records  int
	firstSeq uint64
	lastSeq  uint64
}

// Store is the evidence ledger. All methods are safe for concurrent use.
type Store struct {
	opts     Options
	log      *slog.Logger
	now      func() time.Time
	readOnly bool
	created  bool

	ledgerDir, blobDir, blobTmpDir, keyDir, quarDir string

	runID      string
	monoStart  time.Time     // reference for the real monotonic clock
	monoOrigin time.Duration // monoClock value at Open (tests)

	priv ed25519.PrivateKey // writer only
	pub  ed25519.PublicKey
	fp   string

	lock *fileLock

	// keyConfirmed (set during Open) records that the genesis record verified and named the
	// signing key, or that this Open created the ledger.
	keyConfirmed bool

	// closing is set when Close starts, so that a running CompressSealed stops between
	// segments instead of holding up Close.
	closing atomic.Bool

	mu          sync.Mutex // serializes appends and guards the fields below
	closed      bool
	broken      error     // sticky: a failed write could not be rolled back (wraps contracts.ErrLedgerBroken)
	head        model.Ref // last record written (writer) or found (read-only)
	nextSeq     uint64    // seq of the next record (normally head.Seq+1)
	genesisTS   string
	active      *activeSeg
	clockWarned time.Time
	// pendingAlerts are integrity_alert details waiting for the next successful rotation.
	pendingAlerts []string
	// unopened is a new segment that a failed rotation left in place (renamed, not opened).
	unopened string

	roMu      sync.Mutex // read-only head refresh
	roHeadKey string

	blobMu sync.Mutex // serializes blob writes

	compressMu sync.Mutex

	cacheMu sync.Mutex
	meta    map[string]segMeta // segment metadata by path (validated by size and mtime)
	minTS   map[string]tsMeta  // earliest record ts by path (validated by size and mtime)
	// metaGzReads counts compressed segments decompressed completely for their metadata (tests).
	metaGzReads atomic.Int64

	idx indexCache // line-offset indexes of recently used segments (Record)

	sigs *sigCache // signature outcomes of verified segments (Verify, verifycache.go)
}

// Open opens (and on first use creates) the ledger. A writer takes the exclusive lock, loads
// or creates the signing key, recovers a torn tail of the active segment, validates the active
// segment and appends recovery/integrity_alert records as needed. With ReadOnly nothing is
// locked, decrypted or written.
func Open(opts Options) (*Store, error) {
	if opts.Paths.Ledger == "" || opts.Paths.Blobs == "" {
		return nil, errors.New("ledger: Options.Paths.Ledger and Options.Paths.Blobs are required")
	}
	if !opts.ReadOnly && (opts.Paths.Keys == "" || opts.Paths.Quarantine == "") {
		return nil, errors.New("ledger: Options.Paths.Keys and Options.Paths.Quarantine are required for a writer")
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.DiscardHandler)
	}
	if opts.FastInterval <= 0 {
		opts.FastInterval = defaultFastInterval
	}
	if opts.Statement == "" {
		opts.Statement = DefaultStatement
	}
	if opts.KeyProtect == nil {
		opts.KeyProtect = defaultKeyProtect
	}
	if opts.KeyUnprotect == nil {
		opts.KeyUnprotect = defaultKeyUnprotect
	}
	s := &Store{
		opts:      opts,
		log:       opts.Logger.With("component", "ledger"),
		now:       opts.Now,
		readOnly:  opts.ReadOnly,
		monoStart: time.Now(),
		meta:      map[string]segMeta{},
		minTS:     map[string]tsMeta{},
		sigs:      newSigCache(),
	}
	if opts.monoClock != nil {
		s.monoOrigin = opts.monoClock()
	}
	var err error
	abs := func(p string) string {
		if p == "" || err != nil {
			return p
		}
		var a string
		a, err = filepath.Abs(p)
		return a
	}
	s.ledgerDir = abs(opts.Paths.Ledger)
	s.blobDir = abs(opts.Paths.Blobs)
	s.keyDir = abs(opts.Paths.Keys)
	s.quarDir = abs(opts.Paths.Quarantine)
	if err != nil {
		return nil, fmt.Errorf("ledger: %w", err)
	}
	s.blobTmpDir = filepath.Join(s.blobDir, ".tmp")
	var rid [16]byte
	if _, err := rand.Read(rid[:]); err != nil {
		return nil, fmt.Errorf("ledger: run id: %w", err)
	}
	s.runID = hex.EncodeToString(rid[:])

	if s.readOnly {
		if err := s.openReadOnly(); err != nil {
			return nil, err
		}
		return s, nil
	}
	if err := s.openWriter(); err != nil {
		s.abort()
		return nil, err
	}
	return s, nil
}

// abort releases resources after a failed Open.
func (s *Store) abort() {
	if s.active != nil && s.active.f != nil {
		s.active.f.Close()
		s.active.f = nil
	}
	if s.lock != nil {
		_ = s.lock.release()
		s.lock = nil
	}
	clear(s.priv)
}

// openReadOnly loads the genesis key and head without locking or writing.
func (s *Store) openReadOnly() error {
	files, err := listSegmentFiles(s.ledgerDir)
	if err != nil {
		return fmt.Errorf("ledger: %w", err)
	}
	if len(files) == 0 {
		return fmt.Errorf("ledger: no ledger segments in %s: %w", s.ledgerDir, contracts.ErrNotFound)
	}
	if line, err := readFirstLine(files[0]); err == nil && line != nil {
		if _, body, err := parseRecordLenient(line); err == nil && body.Type == model.TypeGenesis {
			s.genesisTS = body.TS
		}
	}
	if pub, problem := findGenesisKey(lineSource{name: files[0].Name, open: func() (io.ReadCloser, error) {
		return openSegmentFile(files[0], -1)
	}}); problem == "" {
		s.pub, s.fp = pub, Fingerprint(pub)
	} else {
		s.log.Warn("genesis key unavailable", "problem", problem)
	}
	s.refreshReadOnlyHead()
	return nil
}

// Created reports whether this Open created the genesis record.
func (s *Store) Created() bool { return s.created }

// Head returns the last record appended (writer) or found on disk (read-only).
func (s *Store) Head() model.Ref {
	if s.readOnly {
		s.refreshReadOnlyHead()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.head
}

// GenesisTS returns the ts of the genesis record ("" if unknown).
func (s *Store) GenesisTS() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.genesisTS
}

// PublicKey returns the ledger public key (a copy).
func (s *Store) PublicKey() ed25519.PublicKey {
	if s.pub == nil {
		return nil
	}
	return append(ed25519.PublicKey(nil), s.pub...)
}

// Fingerprint returns the lowercase hex SHA-256 of the public key ("" if unknown).
func (s *Store) Fingerprint() string { return s.fp }

// RunID returns this process's random run id (32 hex chars).
func (s *Store) RunID() string { return s.runID }

// MonoNow returns nanoseconds elapsed since Open on the monotonic clock: the "mono" value the
// next record would get.
func (s *Store) MonoNow() int64 {
	if s.opts.monoClock != nil {
		return int64(s.opts.monoClock() - s.monoOrigin)
	}
	return int64(time.Since(s.monoStart))
}

// Close flushes and closes the active segment and releases the writer lock. Reading methods
// keep working after Close; writes return ErrClosed. A running CompressSealed finishes the
// segment it is working on first: the lock must not be released while it still changes files.
func (s *Store) Close() error {
	s.closing.Store(true)
	s.compressMu.Lock()
	defer s.compressMu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	var errs []error
	if s.active != nil && s.active.f != nil {
		errs = append(errs, s.active.f.Sync(), s.active.f.Close())
		s.active.f = nil
	}
	if s.lock != nil {
		errs = append(errs, s.lock.release())
		s.lock = nil
	}
	clear(s.priv)
	s.priv = nil
	return errors.Join(errs...)
}
