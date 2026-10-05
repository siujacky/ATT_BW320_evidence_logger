//go:build !windows

package monitor

import "errors"

// systemDiskFree is implemented for Windows only (the product targets windows/amd64).
func systemDiskFree(string) (free, total uint64, err error) {
	return 0, 0, errors.New("free space is not measured on this platform")
}
