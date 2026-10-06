package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"attmonitor/internal/config"
)

// TestInstallRefusesDataDirBeforeChangingAnything: a data directory the installer would refuse -
// here one laid out by a newer version, with a folder this version does not know - is refused
// before the running service is stopped or the installed program replaced. (Before, the program
// was replaced first and the refusal came after: rolling back with an older version's installer
// failed, and restarted the service with the older program.) The service control and the copy are
// fakes: the test can never reach the real service or Program Files.
func TestInstallRefusesDataDirBeforeChangingAnything(t *testing.T) {
	var calls []string
	status, stop, start, cp, target := installStatus, installStop, installStart, installCopy, installTarget
	t.Cleanup(func() {
		installStatus, installStop, installStart, installCopy, installTarget = status, stop, start, cp, target
	})
	installStatus = func() (string, error) { calls = append(calls, "status"); return "running", nil }
	installStop = func(time.Duration) error { calls = append(calls, "stop"); return nil }
	installStart = func() error { calls = append(calls, "start"); return nil }
	installCopy = func(string, string) error { calls = append(calls, "copy"); return nil }
	programDir := filepath.Join(t.TempDir(), "ATT Monitor")
	installTarget = func() string { return programDir }

	data := filepath.Join(t.TempDir(), "ATTMonitor")
	if err := config.PathsFor(data).MkdirAll(); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(data, "newer-feature"), 0o755); err != nil {
		t.Fatal(err)
	}
	var out strings.Builder
	err := installService(installOptions{DataDir: data, NoStart: true, Out: &out})
	if err == nil || !strings.Contains(err.Error(), `"newer-feature"`) || !strings.Contains(err.Error(), "nothing was changed") {
		t.Fatalf("installService: %v", err)
	}
	if len(calls) != 0 {
		t.Errorf("the installer acted before it refused the data directory: %v", calls)
	}
	if _, err := os.Stat(programDir); err == nil {
		t.Error("the program folder was created")
	}
	if out.Len() != 0 {
		t.Errorf("output:\n%s", out.String())
	}
}
