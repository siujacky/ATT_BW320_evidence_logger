//go:build windows

package ledger

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"golang.org/x/sys/windows"
)

// The writer lock covers one byte at offset 4 GiB (beyond any content) so the holder
// description written at the start of the lock file stays readable by other processes.
const lockOffsetHigh = 1

// fileLock is an exclusive LockFileEx lock held for the lifetime of a writer Store.
type fileLock struct {
	f *os.File
}

// acquireLock takes the exclusive writer lock on path, failing fast (ErrLocked) when another
// handle — in this or another process — already holds it.
func acquireLock(path string) (*fileLock, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o644)
	if err != nil {
		return nil, fmt.Errorf("ledger: open lock file: %w", err)
	}
	ol := &windows.Overlapped{OffsetHigh: lockOffsetHigh}
	err = windows.LockFileEx(windows.Handle(f.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, ol)
	if err != nil {
		holder := readHolder(f)
		f.Close()
		if errors.Is(err, windows.ERROR_LOCK_VIOLATION) || errors.Is(err, windows.ERROR_IO_PENDING) {
			if holder != "" {
				holder = " (" + holder + ")"
			}
			return nil, fmt.Errorf("%w: %s is held by another writer%s; stop the ATTMonitor service or use the running service's API", ErrLocked, path, holder)
		}
		return nil, fmt.Errorf("ledger: lock %s: %w", path, err)
	}
	// Describe the holder for the error message another process would show.
	exe, _ := os.Executable()
	info := fmt.Sprintf("pid %d, since %s, exe %s\n", os.Getpid(), time.Now().UTC().Format(time.RFC3339), exe)
	if err := f.Truncate(0); err == nil {
		_, _ = f.WriteAt([]byte(info), 0)
		_ = f.Sync()
	}
	return &fileLock{f: f}, nil
}

func readHolder(f *os.File) string {
	buf := make([]byte, 512)
	n, _ := f.ReadAt(buf, 0)
	return strings.TrimSpace(strings.ToValidUTF8(string(buf[:n]), "?"))
}

func (l *fileLock) release() error {
	if l == nil || l.f == nil {
		return nil
	}
	ol := &windows.Overlapped{OffsetHigh: lockOffsetHigh}
	err1 := windows.UnlockFileEx(windows.Handle(l.f.Fd()), 0, 1, 0, ol)
	err2 := l.f.Close()
	l.f = nil
	return errors.Join(err1, err2)
}

// openShared opens path for reading while allowing other processes to write, rename and
// delete it (FILE_SHARE_DELETE), so readers never block CompressSealed or blob replacement.
func openShared(path string) (*os.File, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	h, err := windows.CreateFile(p, windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	return os.NewFile(uintptr(h), path), nil
}

// openExclusiveRW opens an existing segment for the writer. Other processes may read it
// but cannot open it for writing, renaming or deletion while the writer holds it.
func openExclusiveRW(path string) (*os.File, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	h, err := windows.CreateFile(p, windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	return os.NewFile(uintptr(h), path), nil
}

// renameDurable atomically renames oldpath to newpath, replacing it if it exists, and does not
// return before the rename is on disk (MOVEFILE_WRITE_THROUGH).
func renameDurable(oldpath, newpath string) error {
	from, err := windows.UTF16PtrFromString(oldpath)
	if err != nil {
		return &os.LinkError{Op: "rename", Old: oldpath, New: newpath, Err: err}
	}
	to, err := windows.UTF16PtrFromString(newpath)
	if err != nil {
		return &os.LinkError{Op: "rename", Old: oldpath, New: newpath, Err: err}
	}
	if err := windows.MoveFileEx(from, to, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH); err != nil {
		return &os.LinkError{Op: "rename", Old: oldpath, New: newpath, Err: err}
	}
	return nil
}

// renameNoReplace atomically renames oldpath to newpath, failing if newpath exists.
// MOVEFILE_WRITE_THROUGH makes the rename durable before returning.
func renameNoReplace(oldpath, newpath string) error {
	from, err := windows.UTF16PtrFromString(oldpath)
	if err != nil {
		return &os.LinkError{Op: "rename", Old: oldpath, New: newpath, Err: err}
	}
	to, err := windows.UTF16PtrFromString(newpath)
	if err != nil {
		return &os.LinkError{Op: "rename", Old: oldpath, New: newpath, Err: err}
	}
	if err := windows.MoveFileEx(from, to, windows.MOVEFILE_WRITE_THROUGH); err != nil {
		if errors.Is(err, windows.ERROR_ALREADY_EXISTS) || errors.Is(err, windows.ERROR_FILE_EXISTS) {
			err = os.ErrExist
		}
		return &os.LinkError{Op: "rename", Old: oldpath, New: newpath, Err: err}
	}
	return nil
}
