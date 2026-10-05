//go:build !windows

package ticket

import "os/exec"

// browserCandidates lists the installed browsers to print with, Microsoft Edge first (the
// product targets Windows; this is for development on other systems).
func browserCandidates() []string {
	var out []string
	for _, name := range []string{"microsoft-edge", "microsoft-edge-stable", "google-chrome", "google-chrome-stable", "chromium", "chromium-browser"} {
		if p, err := exec.LookPath(name); err == nil {
			out = addCandidate(out, p)
		}
	}
	for _, p := range []string{
		"/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
		"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
	} {
		out = addCandidate(out, p)
	}
	return out
}

func hideWindow(*exec.Cmd) {}
