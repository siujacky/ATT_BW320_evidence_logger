package ledger

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"attmonitor/internal/model"
)

const (
	bootstrapNotesFile = "CAPTURE-NOTES.txt"
	maxBootstrapFile   = 256 << 20
	// maxBootstrapNotes bounds the notes copied into the record (which must stay below
	// maxRecordBytes); the exact file is always stored as a blob and listed in Files.
	maxBootstrapNotes = 1 << 20
)

// ImportBootstrap records evidence collected before the ledger existed (docs/DESIGN.md §7):
// every regular file under dir (recursively, sorted by forward-slash relative path) is stored
// as a blob, and one bootstrap_import record lists each file's path, SHA-256, size and
// modification time, with Notes = the contents of CAPTURE-NOTES.txt at the top of dir if
// present. All blob ids are listed in the record's blobs. Symbolic links and other non-regular
// files are not followed.
func (s *Store) ImportBootstrap(dir string) (model.Ref, error) {
	if s.readOnly {
		return model.Ref{}, ErrReadOnly
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return model.Ref{}, fmt.Errorf("ledger: bootstrap dir: %w", err)
	}
	st, err := os.Stat(abs)
	if err != nil {
		return model.Ref{}, fmt.Errorf("ledger: bootstrap dir: %w", err)
	}
	if !st.IsDir() {
		return model.Ref{}, fmt.Errorf("ledger: bootstrap dir %s is not a directory", abs)
	}

	type found struct {
		rel  string
		path string
		info fs.FileInfo
	}
	var files []found
	var skipped []string
	err = filepath.WalkDir(abs, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(abs, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if !d.Type().IsRegular() {
			skipped = append(skipped, rel)
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		files = append(files, found{rel: rel, path: path, info: info})
		return nil
	})
	if err != nil {
		return model.Ref{}, fmt.Errorf("ledger: walk bootstrap dir: %w", err)
	}
	sort.Slice(files, func(i, j int) bool { return files[i].rel < files[j].rel })

	imp := model.BootstrapImport{SourceDir: abs, Files: make([]model.BootstrapFile, 0, len(files))}
	ids := make([]string, 0, len(files))
	for _, f := range files {
		if f.info.Size() > maxBootstrapFile {
			return model.Ref{}, fmt.Errorf("ledger: bootstrap file %s is larger than %d bytes", f.rel, maxBootstrapFile)
		}
		content, err := os.ReadFile(f.path)
		if err != nil {
			return model.Ref{}, fmt.Errorf("ledger: read bootstrap file %s: %w", f.rel, err)
		}
		id, err := s.PutBlob(content)
		if err != nil {
			return model.Ref{}, err
		}
		imp.Files = append(imp.Files, model.BootstrapFile{
			Path:    f.rel,
			SHA256:  id,
			Size:    int64(len(content)),
			ModTime: f.info.ModTime().UTC().Format(time.RFC3339Nano),
		})
		ids = append(ids, id)
		if !strings.Contains(f.rel, "/") && strings.EqualFold(f.rel, bootstrapNotesFile) {
			imp.Notes = string(content)
			if len(imp.Notes) > maxBootstrapNotes {
				kept := cutUTF8(imp.Notes, maxBootstrapNotes)
				imp.Notes = kept + fmt.Sprintf("\n[truncated after %d of %d bytes; the complete file is blob %s]", len(kept), len(content), id)
			}
		}
	}
	if len(skipped) > 0 {
		s.log.Warn("bootstrap import skipped non-regular files", "files", skipped)
	}
	ref, err := s.Append(model.TypeBootstrapImport, &imp, ids...)
	if err != nil {
		return model.Ref{}, err
	}
	s.log.Info("bootstrap evidence imported", "dir", abs, "files", len(imp.Files), "seq", ref.Seq)
	return ref, nil
}
