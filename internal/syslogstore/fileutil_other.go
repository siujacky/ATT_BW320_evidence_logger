//go:build !windows

package syslogstore

import "os"

// The product targets Windows; elsewhere the package builds with the plain os functions, which
// lack the sharing rules of the Windows versions.

func openShared(path string) (*os.File, error) { return os.Open(path) }

func createExclusive(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o644)
}

func openExclusive(path string) (*os.File, error) { return os.OpenFile(path, os.O_RDWR, 0) }

func renameReplace(oldpath, newpath string) error { return os.Rename(oldpath, newpath) }

func renameNoReplace(oldpath, newpath string) error {
	if _, err := os.Lstat(newpath); err == nil {
		return &os.LinkError{Op: "rename", Old: oldpath, New: newpath, Err: os.ErrExist}
	}
	return os.Rename(oldpath, newpath)
}
