//go:build !windows

package connstore

import "os"

// The product targets Windows; elsewhere the package builds with the plain os functions, which
// lack the sharing rules of the Windows versions.

func openShared(path string) (*os.File, error) { return os.Open(path) }

func openWriter(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o644)
}
