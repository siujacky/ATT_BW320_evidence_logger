//go:build !windows

package export

import "os"

// commitBundle moves the finished temporary bundle to its final name without replacing an
// existing file (the hard link fails if final exists). The product targets Windows; this
// variant keeps the package portable for tooling.
func commitBundle(tmp, final string) error {
	if err := os.Link(tmp, final); err != nil {
		return err
	}
	return os.Remove(tmp)
}
