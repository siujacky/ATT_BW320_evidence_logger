//go:build windows

package winsvc

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const (
	// testServiceName is the throwaway service used by the live admin test (never the real
	// ATTMonitor service).
	testServiceName = "ATTMonitorTest"
	// helperMarker tells TestServiceHelper it was started by the SCM as that service.
	helperMarker = "winsvc-test-helper"
)

func TestIsServiceUnderGoTest(t *testing.T) {
	is, err := IsService()
	if err != nil {
		t.Fatalf("IsService: %v", err)
	}
	if is {
		t.Error("IsService() = true under go test")
	}
}

func TestIsAdminMatchesTokenMembership(t *testing.T) {
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		t.Fatal(err)
	}
	// In a filtered (non-elevated) token Administrators is deny-only, so membership is
	// false exactly when the process is not elevated.
	member, err := windows.Token(0).IsMember(admins)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("IsAdmin() = %v, Administrators membership = %v", IsAdmin(), member)
	if IsAdmin() != member {
		t.Errorf("IsAdmin() = %v but Administrators membership = %v", IsAdmin(), member)
	}
}

func TestStatusOfSystemService(t *testing.T) {
	// The RPC server service always runs; querying it needs no elevation.
	st, err := status("RpcSs")
	if err != nil {
		t.Fatalf("status(RpcSs): %v", err)
	}
	if st != StatusRunning {
		t.Errorf("status(RpcSs) = %q, want %q", st, StatusRunning)
	}
}

func TestOperationsOnMissingService(t *testing.T) {
	name := fmt.Sprintf("ATTMonitorTest-missing-%d", os.Getpid())

	st, err := status(name)
	if err != nil || st != StatusNotInstalled {
		t.Errorf("status = %q, %v; want %q, nil", st, err, StatusNotInstalled)
	}
	if err := start(name); !errors.Is(err, ErrNotInstalled) {
		t.Errorf("start = %v, want ErrNotInstalled", err)
	}
	if err := stop(name, time.Second); !errors.Is(err, ErrNotInstalled) {
		t.Errorf("stop = %v, want ErrNotInstalled", err)
	}
	// Nothing exists, so this changes nothing even when elevated.
	if err := uninstall(name); !errors.Is(err, ErrNotInstalled) {
		t.Errorf("uninstall = %v, want ErrNotInstalled", err)
	}
}

func TestInstallValidatesExecutable(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "no-such.exe")
	// Validation happens before the SCM is contacted, so nothing is installed.
	tests := []struct {
		name    string
		exe     string
		wantSub string
	}{
		{"missing file", missing, "no-such.exe"},
		{"directory", dir, "not a regular file"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := install("ATTMonitorTest-validation", InstallOptions{ExePath: tc.exe})
			if err == nil || !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("install = %v, want error containing %q", err, tc.wantSub)
			}
			if errors.Is(err, ErrAlreadyInstalled) {
				t.Fatal("validation error reported as already installed")
			}
		})
	}
}

func TestResolveExe(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if got, err := resolveExe(""); err != nil || got != self {
		t.Errorf(`resolveExe("") = %q, %v; want %q`, got, err, self)
	}
	wd, _ := os.Getwd()
	rel, err := filepath.Rel(wd, self)
	if err != nil {
		t.Skipf("executable not reachable relative to %s: %v", wd, err)
	}
	got, err := resolveExe(rel)
	if err != nil || !filepath.IsAbs(got) || !strings.EqualFold(got, self) {
		t.Errorf("resolveExe(%q) = %q, %v; want absolute %q", rel, got, err, self)
	}
}

func TestInstallWithoutElevationFailsClearly(t *testing.T) {
	if IsAdmin() {
		t.Skip("elevated: this would really install a service")
	}
	const name = "ATTMonitorTest-denied"
	exe, _ := os.Executable()
	err := install(name, InstallOptions{ExePath: exe})
	if err == nil {
		// Only possible with a non-default SCM ACL; never leave the service behind.
		t.Errorf("install without elevation succeeded; removing %s: %v", name, uninstall(name))
		return
	}
	if !errors.Is(err, windows.ERROR_ACCESS_DENIED) || !strings.Contains(err.Error(), "elevated") {
		t.Errorf("install without elevation = %v, want access denied with a hint", err)
	}
	// (Uninstall is deliberately not exercised against a real system service here.)
}

func TestStateString(t *testing.T) {
	tests := []struct {
		s    svc.State
		want string
	}{
		{svc.Stopped, "stopped"},
		{svc.StartPending, "start pending"},
		{svc.StopPending, "stop pending"},
		{svc.Running, "running"},
		{svc.ContinuePending, "continue pending"},
		{svc.PausePending, "pause pending"},
		{svc.Paused, "paused"},
		{svc.State(42), "unknown state 42"},
	}
	for _, tc := range tests {
		if got := stateString(tc.s); got != tc.want {
			t.Errorf("stateString(%d) = %q, want %q", tc.s, got, tc.want)
		}
	}
}

func TestExitCodeString(t *testing.T) {
	specific := uint32(windows.ERROR_SERVICE_SPECIFIC_ERROR)
	tests := []struct {
		st      svc.Status
		wantSub string
	}{
		{svc.Status{}, "exit code 0"},
		{svc.Status{Win32ExitCode: specific, ServiceSpecificExitCode: ExitRunFailed}, "service-specific exit code 1: the monitor failed"},
		{svc.Status{Win32ExitCode: specific, ServiceSpecificExitCode: ExitRunPanicked}, "service-specific exit code 2: the monitor crashed"},
		{svc.Status{Win32ExitCode: specific, ServiceSpecificExitCode: 77}, "service-specific exit code 77"},
		{svc.Status{Win32ExitCode: uint32(windows.ERROR_ACCESS_DENIED)}, "exit code 5: Access is denied"},
	}
	for _, tc := range tests {
		if got := exitCodeString(tc.st); !strings.Contains(got, tc.wantSub) {
			t.Errorf("exitCodeString(%+v) = %q, want it to contain %q", tc.st, got, tc.wantSub)
		}
	}
}

func TestErrorMapping(t *testing.T) {
	tests := []struct {
		name    string
		err     error
		wantIs  []error
		wantSub string
	}{
		{"exists", createServiceError("X", windows.ERROR_SERVICE_EXISTS),
			[]error{ErrAlreadyInstalled, windows.ERROR_SERVICE_EXISTS}, "uninstall it first"},
		{"duplicate display name", createServiceError("X", windows.ERROR_DUPLICATE_SERVICE_NAME),
			[]error{windows.ERROR_DUPLICATE_SERVICE_NAME}, "already used by another service"},
		{"marked for delete", createServiceError("X", windows.ERROR_SERVICE_MARKED_FOR_DELETE),
			[]error{windows.ERROR_SERVICE_MARKED_FOR_DELETE}, "marked for deletion"},
		{"access denied", createServiceError("X", windows.ERROR_ACCESS_DENIED),
			[]error{windows.ERROR_ACCESS_DENIED}, "elevated prompt"},
		{"other", scmError("op", windows.ERROR_INVALID_PARAMETER),
			[]error{windows.ERROR_INVALID_PARAMETER}, "winsvc: op:"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			for _, target := range tc.wantIs {
				if !errors.Is(tc.err, target) {
					t.Errorf("%v does not wrap %v", tc.err, target)
				}
			}
			if !strings.Contains(tc.err.Error(), tc.wantSub) {
				t.Errorf("%q does not contain %q", tc.err, tc.wantSub)
			}
		})
	}
}

// ------------------------------------------------------------------ live (elevated) tests

func requireLiveAdmin(t *testing.T) {
	t.Helper()
	if os.Getenv("ATTMON_LIVE_ADMIN") != "1" {
		t.Skip("set ATTMON_LIVE_ADMIN=1 in an elevated prompt to run service install tests")
	}
	if !IsAdmin() {
		t.Skip("ATTMON_LIVE_ADMIN=1 but the process is not elevated")
	}
}

func removeTestService(t *testing.T) {
	t.Helper()
	if st, err := status(testServiceName); err == nil && st != StatusNotInstalled {
		if err := uninstall(testServiceName); err != nil {
			t.Logf("cleanup: uninstall %s: %v", testServiceName, err)
		}
	}
	if err := removeEventSource(testServiceName); err != nil {
		t.Logf("cleanup: remove event source: %v", err)
	}
}

func waitForFile(t *testing.T, path, want string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var got []byte
	for time.Now().Before(deadline) {
		got, _ = os.ReadFile(path)
		if string(got) == want {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	errText, _ := os.ReadFile(path + ".err")
	t.Fatalf("%s = %q, want %q (helper error: %q)", path, got, want, errText)
}

// TestLiveServiceLifecycle installs the throwaway ATTMonitorTest service whose binary is
// this test executable (running TestServiceHelper), verifies the SCM configuration, starts
// and stops it through Run, and uninstalls it.
func TestLiveServiceLifecycle(t *testing.T) {
	requireLiveAdmin(t)
	removeTestService(t) // leftovers of an aborted earlier run
	t.Cleanup(func() { removeTestService(t) })

	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "helper.txt")
	opts := InstallOptions{
		ExePath:     exe,
		Args:        []string{"-test.run=^TestServiceHelper$", "-test.timeout=2m", "--", helperMarker, out},
		DisplayName: "ATTMonitor test service (safe to delete)",
		Description: "Temporary service created by the att-monitor winsvc tests.",
	}
	if err := install(testServiceName, opts); err != nil {
		t.Fatalf("install: %v", err)
	}
	if err := install(testServiceName, opts); !errors.Is(err, ErrAlreadyInstalled) {
		t.Errorf("second install = %v, want ErrAlreadyInstalled", err)
	}

	checkInstalledConfig(t, exe, opts)

	if st, err := status(testServiceName); err != nil || st != StatusStopped {
		t.Fatalf("status after install = %q, %v; want stopped", st, err)
	}
	if err := start(testServiceName); err != nil {
		t.Fatalf("start: %v", err)
	}
	if err := start(testServiceName); err != nil {
		t.Errorf("start while running = %v, want nil", err)
	}
	if st, err := status(testServiceName); err != nil || st != StatusRunning {
		t.Fatalf("status after start = %q, %v; want running", st, err)
	}
	waitForFile(t, out, "running\n", 30*time.Second)

	if err := stop(testServiceName, 30*time.Second); err != nil {
		t.Fatalf("stop: %v", err)
	}
	if st, err := status(testServiceName); err != nil || st != StatusStopped {
		t.Fatalf("status after stop = %q, %v; want stopped", st, err)
	}
	waitForFile(t, out, "stopped: service stop\n", 10*time.Second)
	if err := stop(testServiceName, time.Second); err != nil {
		t.Errorf("stop while stopped = %v, want nil", err)
	}

	// Uninstall stops a running service first.
	if err := start(testServiceName); err != nil {
		t.Fatalf("restart: %v", err)
	}
	if err := uninstall(testServiceName); err != nil {
		t.Fatalf("uninstall: %v", err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		st, err := status(testServiceName)
		if err == nil && st == StatusNotInstalled {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("status after uninstall = %q, %v; want not installed", st, err)
		}
		time.Sleep(200 * time.Millisecond)
	}
	if eventSourceExists(testServiceName) {
		t.Error("event source still registered after uninstall")
	}
}

func checkInstalledConfig(t *testing.T, exe string, opts InstallOptions) {
	t.Helper()
	m, err := mgr.Connect()
	if err != nil {
		t.Fatal(err)
	}
	defer m.Disconnect()
	s, err := m.OpenService(testServiceName)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close() // must be closed before uninstall, or deletion is deferred

	cfg, err := s.Config()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.StartType != mgr.StartAutomatic || !cfg.DelayedAutoStart {
		t.Errorf("start type %d delayed %v, want automatic (delayed)", cfg.StartType, cfg.DelayedAutoStart)
	}
	if cfg.ServiceType != windows.SERVICE_WIN32_OWN_PROCESS {
		t.Errorf("service type %#x", cfg.ServiceType)
	}
	if !strings.EqualFold(cfg.ServiceStartName, "LocalSystem") {
		t.Errorf("account %q, want LocalSystem", cfg.ServiceStartName)
	}
	if cfg.DisplayName != opts.DisplayName || cfg.Description != opts.Description {
		t.Errorf("display %q / description %q", cfg.DisplayName, cfg.Description)
	}
	if !strings.Contains(cfg.BinaryPathName, exe) || !strings.Contains(cfg.BinaryPathName, helperMarker) {
		t.Errorf("binary path %q lacks the executable or arguments", cfg.BinaryPathName)
	}
	actions, err := s.RecoveryActions()
	if err != nil || !slices.Equal(actions, recoveryActions) {
		t.Errorf("recovery actions %+v, %v; want %+v", actions, err, recoveryActions)
	}
	if reset, err := s.ResetPeriod(); err != nil || reset != 86400 {
		t.Errorf("reset period %d, %v; want 86400", reset, err)
	}
	if flag, err := s.RecoveryActionsOnNonCrashFailures(); err != nil || !flag {
		t.Errorf("recovery on non-crash failures %v, %v; want true", flag, err)
	}

	k, err := registry.OpenKey(registry.LOCAL_MACHINE, eventSourceParentKey+`\`+testServiceName, registry.QUERY_VALUE)
	if err != nil {
		t.Fatalf("event source key: %v", err)
	}
	defer k.Close()
	if types, _, err := k.GetIntegerValue("TypesSupported"); err != nil || types != 7 {
		t.Errorf("TypesSupported = %d, %v; want 7 (error|warning|info)", types, err)
	}
	if file, _, err := k.GetStringValue("EventMessageFile"); err != nil || !strings.Contains(strings.ToLower(file), "eventcreate.exe") {
		t.Errorf("EventMessageFile = %q, %v", file, err)
	}
}

// TestServiceHelper is not a test of its own: it is the body of the throwaway service
// installed by TestLiveServiceLifecycle (the SCM starts this binary with helperMarker).
func TestServiceHelper(t *testing.T) {
	if flag.NArg() != 2 || flag.Arg(0) != helperMarker {
		t.Skip("helper for TestLiveServiceLifecycle; only runs when started by the SCM")
	}
	out := flag.Arg(1)
	err := Run(func(ctx context.Context, _ <-chan string) error {
		if err := os.WriteFile(out, []byte("running\n"), 0o644); err != nil {
			return err
		}
		<-ctx.Done()
		return os.WriteFile(out, []byte("stopped: "+context.Cause(ctx).Error()+"\n"), 0o644)
	})
	if err != nil {
		_ = os.WriteFile(out+".err", []byte(err.Error()), 0o644)
		t.Fatal(err)
	}
}
