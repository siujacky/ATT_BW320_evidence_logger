//go:build windows

package export

import (
	"os"

	"golang.org/x/sys/windows"
)

// commitBundle moves the finished temporary bundle to its final name without ever replacing an
// existing file: os.Rename (MoveFileEx with MOVEFILE_REPLACE_EXISTING) would silently replace a
// bundle another process wrote under the same name, whose SHA-256 may already be in the
// ledger. The move is written through to disk before it returns. An existing final name
// yields an error matching fs.ErrExist.
func commitBundle(tmp, final string) error {
	from, err := windows.UTF16PtrFromString(tmp)
	if err != nil {
		return &os.LinkError{Op: "move", Old: tmp, New: final, Err: err}
	}
	to, err := windows.UTF16PtrFromString(final)
	if err != nil {
		return &os.LinkError{Op: "move", Old: tmp, New: final, Err: err}
	}
	if err := windows.MoveFileEx(from, to, windows.MOVEFILE_WRITE_THROUGH); err != nil {
		return &os.LinkError{Op: "move", Old: tmp, New: final, Err: err}
	}
	return nil
}
