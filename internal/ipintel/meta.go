package ipintel

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	// metaVersion is the version of ip2asn.json's format.
	metaVersion = 1
	// maxMetaBytes bounds ip2asn.json (it takes about 1 KB).
	maxMetaBytes = 64 << 10
	// maxValidator bounds an ETag or Last-Modified value kept to be sent back.
	maxValidator = 256
	// maxFailures bounds the failure count kept (the backoff stops growing long before).
	maxFailures = 64
)

// metaFile is ip2asn.json: what was downloaded, and the download schedule, so that a restart
// neither downloads again what it has nor forgets a failure's backoff. It is a cache, not a
// record: a missing or damaged file only costs a full download.
type metaFile struct {
	Version int       `json:"version"`
	V4      *fileMeta `json:"v4,omitempty"`
	V6      *fileMeta `json:"v6,omitempty"`
	// Checked is the newest check that worked; Attempt the newest check; Failures the checks that
	// failed in a row since, and Error why the newest one failed.
	Checked  time.Time `json:"checked,omitzero"`
	Attempt  time.Time `json:"attempt,omitzero"`
	Failures int       `json:"failures,omitempty"`
	Error    string    `json:"error,omitempty"`
}

// fileMeta describes a downloaded table file: where it came from, the validators of a
// conditional request for a newer one, and what it held.
type fileMeta struct {
	URL          string    `json:"url"`
	ETag         string    `json:"etag,omitempty"`
	LastModified string    `json:"last_modified,omitempty"`
	Downloaded   time.Time `json:"downloaded"`
	Rows         int       `json:"rows"`   // data lines
	Ranges       int       `json:"ranges"` // announced ranges, as loaded
	Size         int64     `json:"size"`
	SHA256       string    `json:"sha256"`
}

func (m *metaFile) file(f family) *fileMeta {
	if f == fam4 {
		return m.V4
	}
	return m.V6
}

func (m *metaFile) setFile(f family, fm *fileMeta) {
	if f == fam4 {
		m.V4 = fm
	} else {
		m.V6 = fm
	}
}

// readMeta reads ip2asn.json; what it cannot trust (a validator that cannot be sent back, an
// entry without a SHA-256) is left out.
func readMeta(path string) (metaFile, error) {
	var m metaFile
	f, err := os.Open(path)
	if err != nil {
		return m, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxMetaBytes+1))
	if err != nil {
		return m, err
	}
	if len(b) > maxMetaBytes {
		return metaFile{}, errors.New("larger than expected")
	}
	if err := json.Unmarshal(b, &m); err != nil {
		return metaFile{}, err
	}
	if m.Version != metaVersion {
		return metaFile{}, fmt.Errorf("version %d, not %d", m.Version, metaVersion)
	}
	for _, f := range families {
		fm := m.file(f)
		if fm == nil {
			continue
		}
		if s, err := hex.DecodeString(fm.SHA256); err != nil || len(s) != 32 || fm.URL == "" {
			m.setFile(f, nil)
			continue
		}
		if !validatorOK(fm.ETag) {
			fm.ETag = ""
		}
		if !validatorOK(fm.LastModified) {
			fm.LastModified = ""
		}
	}
	m.Failures = min(max(m.Failures, 0), maxFailures)
	return m, nil
}

// validatorOK says whether an ETag or Last-Modified value may be sent back as is: printable
// ASCII of a sane length.
func validatorOK(v string) bool {
	if len(v) > maxValidator {
		return false
	}
	for i := 0; i < len(v); i++ {
		if v[i] < 0x20 || v[i] > 0x7e {
			return false
		}
	}
	return true
}

// saveMeta writes ip2asn.json from the files' entries and the schedule.
func (d *DB) saveMeta() {
	d.mu.Lock()
	m := d.meta
	m.Version = metaVersion
	m.Checked, m.Attempt, m.Failures, m.Error = d.st.checked, d.st.attempt, d.st.failures, d.st.dlErr
	d.mu.Unlock()
	b, err := json.MarshalIndent(m, "", "  ")
	if err == nil {
		err = writeFileAtomic(filepath.Join(d.dir, nameMeta), append(b, '\n'))
	}
	if err != nil {
		d.log.Warn("ipintel: cannot save the IP database's metadata", "err", err)
	}
}

// fileState is a table file as last seen on disk: whether it exists, its size and write time,
// and, once loaded, its SHA-256.
type fileState struct {
	exists bool
	size   int64
	mtime  time.Time
	sum    string
}

// same says whether two states describe the same file (the SHA-256 aside).
func (s fileState) same(o fileState) bool {
	return s.exists == o.exists && s.size == o.size && s.mtime.Equal(o.mtime)
}

// writeFileAtomic replaces path with data: a temporary file next to it is written, fsynced and
// renamed over it, so a reader finds the old file or the new one, never part of one.
func writeFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, path)
	}
	if err != nil {
		os.Remove(tmp)
	}
	return err
}

// removeTemp deletes the temporary files of the package's files that a crash left in dir.
func removeTemp(dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || !strings.HasSuffix(n, ".tmp") {
			continue
		}
		for _, base := range []string{nameV4, nameV6, nameMeta, namePTR} {
			if strings.HasPrefix(n, base+".") {
				os.Remove(filepath.Join(dir, n))
				break
			}
		}
	}
}
