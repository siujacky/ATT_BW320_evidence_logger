//go:build !windows

package probe

import "time"

// hrNow reads Go's monotonic clock, which has nanosecond resolution outside Windows.
func hrNow() time.Duration { return time.Since(hrEpoch) }

// preciseWallNow returns the system (UTC) time without a monotonic reading.
func preciseWallNow() time.Time { return time.Now().Round(0).UTC() }
