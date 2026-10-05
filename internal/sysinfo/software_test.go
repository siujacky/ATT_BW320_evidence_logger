package sysinfo

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"testing"
)

var hex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

func TestSoftware(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	fresh := hex.EncodeToString(sum[:])

	tests := []struct {
		name                    string
		version, commit, rules  string
		wantVersion, wantCommit string
	}{
		{name: "explicit values", version: "1.2.3", commit: "abc1234", rules: "2026.10-1",
			wantVersion: "1.2.3", wantCommit: "abc1234"},
		{name: "empty version is dev", version: "", commit: "deadbeef", rules: "2026.10-1",
			wantVersion: "dev", wantCommit: "deadbeef"},
		{name: "empty commit falls back to build info", version: "v1", commit: "", rules: "r",
			wantVersion: "v1", wantCommit: vcsRevision()},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			si := Software(tc.version, tc.commit, tc.rules)
			if si.Name != "att-monitor" {
				t.Errorf("Name = %q", si.Name)
			}
			if si.Version != tc.wantVersion {
				t.Errorf("Version = %q, want %q", si.Version, tc.wantVersion)
			}
			if si.Commit != tc.wantCommit {
				t.Errorf("Commit = %q, want %q", si.Commit, tc.wantCommit)
			}
			if si.Rules != tc.rules {
				t.Errorf("Rules = %q, want %q", si.Rules, tc.rules)
			}
			if si.GoVersion != runtime.Version() {
				t.Errorf("GoVersion = %q, want %q", si.GoVersion, runtime.Version())
			}
			if si.ExePath != exe {
				t.Errorf("ExePath = %q, want %q", si.ExePath, exe)
			}
			if !hex64.MatchString(si.ExeSHA256) {
				t.Fatalf("ExeSHA256 = %q, want 64 lowercase hex digits", si.ExeSHA256)
			}
			if si.ExeSHA256 != fresh {
				t.Errorf("ExeSHA256 = %s, fresh hash of %s = %s", si.ExeSHA256, exe, fresh)
			}
		})
	}
}

func TestFileSHA256(t *testing.T) {
	dir := t.TempDir()
	empty := filepath.Join(dir, "empty")
	abc := filepath.Join(dir, "abc")
	if err := os.WriteFile(empty, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(abc, []byte("abc"), 0o644); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name    string
		path    string
		want    string
		wantErr bool
	}{
		{"empty file", empty, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", false},
		{"abc (FIPS 180-2 vector)", abc, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", false},
		{"missing file", filepath.Join(dir, "nope"), "", true},
		{"directory", dir, "", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := FileSHA256(tc.path)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}
