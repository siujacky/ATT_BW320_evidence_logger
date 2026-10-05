//go:build !windows

package ledger

import (
	"errors"
	"os"
)

// The product targets Windows. On other platforms the package still builds so that
// read-only verification (e.g. of an exported bundle) works, but writing is refused.

type fileLock struct{}

func acquireLock(path string) (*fileLock, error) {
	return nil, errors.New("ledger: the writer is only supported on Windows (open with ReadOnly)")
}

func (l *fileLock) release() error { return nil }

func openShared(path string) (*os.File, error) { return os.Open(path) }

func openExclusiveRW(path string) (*os.File, error) { return os.OpenFile(path, os.O_RDWR, 0) }

func renameDurable(oldpath, newpath string) error { return os.Rename(oldpath, newpath) }

func renameNoReplace(oldpath, newpath string) error {
	if _, err := os.Lstat(newpath); err == nil {
		return &os.LinkError{Op: "rename", Old: oldpath, New: newpath, Err: os.ErrExist}
	}
	return os.Rename(oldpath, newpath)
}
