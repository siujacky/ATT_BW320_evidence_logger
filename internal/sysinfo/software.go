package sysinfo

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"runtime"
	"runtime/debug"

	"attmonitor/internal/model"
)

// softwareName is model.SoftwareInfo.Name for every record this program writes.
const softwareName = "att-monitor"

// Software identifies the running code: version ("" → "dev"), commit ("" → the VCS revision
// embedded by the Go toolchain, if any), Go version, the executable's path and the SHA-256
// of its exact bytes, and the classifier rules version.
//
// If the executable cannot be located or read, ExePath/ExeSHA256 are left empty rather than
// guessed: an empty hash honestly says "unknown".
func Software(version, commit, rules string) model.SoftwareInfo {
	si := model.SoftwareInfo{
		Name:      softwareName,
		Version:   version,
		Commit:    commit,
		GoVersion: runtime.Version(),
		Rules:     rules,
	}
	if si.Version == "" {
		si.Version = "dev"
	}
	if si.Commit == "" {
		si.Commit = vcsRevision()
	}
	if exe, err := os.Executable(); err == nil {
		si.ExePath = exe
		if sum, err := FileSHA256(exe); err == nil {
			si.ExeSHA256 = sum
		}
	}
	return si
}

// FileSHA256 returns the lowercase hex SHA-256 of the file's contents.
func FileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// vcsRevision returns the commit recorded by "go build" (-buildvcs), with "-dirty" appended
// when the working tree had uncommitted changes, or "" when the build carries no VCS stamp.
func vcsRevision() string {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return ""
	}
	var rev string
	var dirty bool
	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision":
			rev = s.Value
		case "vcs.modified":
			dirty = s.Value == "true"
		}
	}
	if rev != "" && dirty {
		rev += "-dirty"
	}
	return rev
}
