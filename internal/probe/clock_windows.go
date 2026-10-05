//go:build windows

package probe

import (
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modKernel32                        = windows.NewLazySystemDLL("kernel32.dll")
	procQueryPerformanceCounter        = modKernel32.NewProc("QueryPerformanceCounter")
	procQueryPerformanceFrequency      = modKernel32.NewProc("QueryPerformanceFrequency")
	procGetSystemTimePreciseAsFileTime = modKernel32.NewProc("GetSystemTimePreciseAsFileTime")
)

// qpcFrequency returns the performance-counter frequency, or 0 if the counter cannot be
// used (then hrNow falls back to Go's coarser monotonic clock).
var qpcFrequency = sync.OnceValue(func() int64 {
	if procQueryPerformanceCounter.Find() != nil || procQueryPerformanceFrequency.Find() != nil {
		return 0
	}
	var f int64
	if r, _, _ := procQueryPerformanceFrequency.Call(uintptr(unsafe.Pointer(&f))); r == 0 || f <= 0 {
		return 0
	}
	return f
})

// hrNow reads the high-resolution monotonic clock (QueryPerformanceCounter: monotonic,
// consistent across processors, sub-microsecond resolution). Only differences between two
// readings are meaningful.
func hrNow() time.Duration {
	if f := qpcFrequency(); f > 0 {
		var c int64
		if r, _, _ := procQueryPerformanceCounter.Call(uintptr(unsafe.Pointer(&c))); r != 0 {
			return ticksToDuration(c, f)
		}
	}
	return time.Since(hrEpoch)
}

// preciseWallNow returns the system (UTC) time read with GetSystemTimePreciseAsFileTime.
// time.Now's wall clock on Windows is a snapshot taken at the last timer tick, up to
// 15.6 ms old. The result carries no monotonic reading.
func preciseWallNow() time.Time {
	if procGetSystemTimePreciseAsFileTime.Find() == nil {
		var ft windows.Filetime
		procGetSystemTimePreciseAsFileTime.Call(uintptr(unsafe.Pointer(&ft)))
		return time.Unix(0, ft.Nanoseconds()).UTC()
	}
	return time.Now().Round(0).UTC()
}
