//go:build windows

package connstore

import (
	"os"

	"golang.org/x/sys/windows"
)

// openShared opens path for reading while letting others write, rename and delete it
// (FILE_SHARE_DELETE): a query reading a day never keeps the writer from compressing or pruning
// that day; it keeps reading what it opened.
func openShared(path string) (*os.File, error) {
	return createFile(path, windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, windows.OPEN_EXISTING)
}

// openWriter opens path for the writer, creating it when it does not exist. While the writer
// holds it, others may read it (the store's own readers among them) but can neither write,
// rename nor delete it.
func openWriter(path string) (*os.File, error) {
	return createFile(path, windows.GENERIC_READ|windows.GENERIC_WRITE, windows.FILE_SHARE_READ, windows.OPEN_ALWAYS)
}

func createFile(path string, access, share, disposition uint32) (*os.File, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	h, err := windows.CreateFile(p, access, share, nil, disposition, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	return os.NewFile(uintptr(h), path), nil
}
