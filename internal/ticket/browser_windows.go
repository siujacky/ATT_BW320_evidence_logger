//go:build windows

package ticket

import (
	"os"
	"os/exec"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/windows/registry"
)

// browserCandidates lists the installed browsers to print with, Microsoft Edge first: for each
// browser, the "App Paths" registration (HKLM, then HKCU) and the standard install folders.
func browserCandidates() []string {
	var out []string
	for _, b := range []struct {
		exe  string
		dirs []string // relative to Program Files (x86), Program Files, %LOCALAPPDATA%
	}{
		{"msedge.exe", []string{`Microsoft\Edge\Application`}},
		{"chrome.exe", []string{`Google\Chrome\Application`}},
	} {
		for _, root := range []registry.Key{registry.LOCAL_MACHINE, registry.CURRENT_USER} {
			out = addCandidate(out, appPath(root, b.exe, 0))
			out = addCandidate(out, appPath(root, b.exe, registry.WOW64_32KEY))
		}
		for _, env := range []string{"ProgramFiles(x86)", "ProgramFiles", "ProgramW6432", "LOCALAPPDATA"} {
			base := os.Getenv(env)
			if base == "" {
				continue
			}
			for _, d := range b.dirs {
				out = addCandidate(out, filepath.Join(base, d, b.exe))
			}
		}
	}
	return out
}

// appPath reads the default value of ...\CurrentVersion\App Paths\<exe>.
func appPath(root registry.Key, exe string, view uint32) string {
	k, err := registry.OpenKey(root, `SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\`+exe, registry.QUERY_VALUE|view)
	if err != nil {
		return ""
	}
	defer k.Close()
	v, typ, err := k.GetStringValue("")
	if err != nil {
		return ""
	}
	if typ == registry.EXPAND_SZ {
		if x, err := registry.ExpandString(v); err == nil {
			v = x
		}
	}
	return v
}

// hideWindow keeps the browser from flashing a window when printing from a console or service.
func hideWindow(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
}
