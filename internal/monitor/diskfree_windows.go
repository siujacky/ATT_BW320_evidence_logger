//go:build windows

package monitor

import "golang.org/x/sys/windows"

// systemDiskFree returns the bytes free to this process and the size of the volume holding dir.
func systemDiskFree(dir string) (free, total uint64, err error) {
	p, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return 0, 0, err
	}
	var totalFree uint64
	if err := windows.GetDiskFreeSpaceEx(p, &free, &total, &totalFree); err != nil {
		return 0, 0, err
	}
	return free, total, nil
}
