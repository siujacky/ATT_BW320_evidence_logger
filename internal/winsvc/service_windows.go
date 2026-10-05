//go:build windows

package winsvc

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"
)

// ServiceName is the SCM service name and the Application event-log source name.
const ServiceName = "ATTMonitor"

// Defaults used by Install when InstallOptions leaves DisplayName/Description empty.
const (
	DefaultDisplayName = "AT&T Internet Monitor (evidence logger)"
	DefaultDescription = "Monitors the AT&T Fiber gateway and the Internet path and keeps a " +
		"tamper-evident, signed and time-stamped evidence ledger of outages (att-monitor)."
)

// Values returned by Status.
const (
	StatusNotInstalled    = "not installed"
	StatusStopped         = "stopped"
	StatusStartPending    = "start pending"
	StatusStopPending     = "stop pending"
	StatusRunning         = "running"
	StatusContinuePending = "continue pending"
	StatusPausePending    = "pause pending"
	StatusPaused          = "paused"
)

var (
	// ErrNotInstalled is returned (wrapped) when the service does not exist.
	ErrNotInstalled = errors.New("service is not installed")
	// ErrAlreadyInstalled is returned (wrapped) by Install when the service already exists.
	ErrAlreadyInstalled = errors.New("service is already installed")
)

// recoveryActions restart the service after 10 s, 30 s and 60 s (the last action repeats);
// the failure count resets after one day without failures (docs/DESIGN.md §14).
var recoveryActions = []mgr.RecoveryAction{
	{Type: mgr.ServiceRestart, Delay: 10 * time.Second},
	{Type: mgr.ServiceRestart, Delay: 30 * time.Second},
	{Type: mgr.ServiceRestart, Delay: 60 * time.Second},
}

const (
	recoveryResetPeriod  = uint32(24 * 60 * 60) // seconds
	eventTypesSupported  = eventlog.Error | eventlog.Warning | eventlog.Info
	eventSourceParentKey = `SYSTEM\CurrentControlSet\Services\EventLog\Application`

	uninstallStopTimeout = 30 * time.Second
	defaultStopTimeout   = 30 * time.Second
	startTimeout         = 30 * time.Second // the SCM's own start timeout
	startGrace           = 1500 * time.Millisecond
	pollInterval         = 250 * time.Millisecond
)

// InstallOptions configures Install.
type InstallOptions struct {
	// ExePath is the service executable; "" means the running executable. It is made
	// absolute and must exist. (The CLI copies the binary to Program Files first, so the
	// SCM never runs a file from a user-writable location.)
	ExePath string
	// Args are the command-line arguments the SCM passes on start, e.g.
	// []string{"service", "--data", `C:\ProgramData\ATTMonitor`}. They are quoted safely.
	Args []string
	// DisplayName and Description default to DefaultDisplayName / DefaultDescription.
	DisplayName, Description string
}

// Install creates the ATTMonitor service: automatic (delayed) start, LocalSystem, recovery
// actions restart after 10 s / 30 s / 60 s with a one-day reset period, also applied when the
// service stops with a non-zero exit code, and the Application event-log source. It does not
// start the service. Requires an elevated administrator. If the service already exists the
// error wraps ErrAlreadyInstalled. On any failure after the service was created, the service
// is deleted again so no half-configured service is left behind.
func Install(o InstallOptions) error { return install(ServiceName, o) }

// Uninstall stops the service if it is running (waiting at most 30 s), deletes it and removes
// the event-log source. Data is never touched. If the service does not exist the error wraps
// ErrNotInstalled (a stale event-log source is still removed). If the service does not stop
// in time it is still marked for deletion (the SCM removes it once it stops) and an error is
// returned.
func Uninstall() error { return uninstall(ServiceName) }

// Start asks the SCM to start the service and waits until it reports running (or stopped,
// which is returned as an error with the exit code). Starting a running service is not an
// error.
func Start() error { return start(ServiceName) }

// Stop asks the service to stop and waits until the SCM reports it stopped, for at most
// timeout (<= 0 means 30 s). Stopping a stopped service is not an error.
func Stop(timeout time.Duration) error { return stop(ServiceName, timeout) }

// Status returns the service state: StatusRunning, StatusStopped, StatusStartPending,
// StatusStopPending, StatusPaused, ... or StatusNotInstalled (with a nil error). It needs
// only query rights, so it works without elevation.
func Status() (string, error) { return status(ServiceName) }

// IsService reports whether this process was started by the SCM as a service.
func IsService() (bool, error) { return svc.IsWindowsService() }

// IsAdmin reports whether this process runs elevated (UAC), as Install/Uninstall require.
// The LocalSystem service itself is elevated too.
func IsAdmin() bool { return windows.GetCurrentProcessToken().IsElevated() }

// ------------------------------------------------------------------ implementation

func install(name string, o InstallOptions) (err error) {
	exe, err := resolveExe(o.ExePath)
	if err != nil {
		return err
	}
	display := o.DisplayName
	if display == "" {
		display = DefaultDisplayName
	}
	desc := o.Description
	if desc == "" {
		desc = DefaultDescription
	}

	m, err := mgr.Connect() // SC_MANAGER_ALL_ACCESS: fails clearly when not elevated
	if err != nil {
		return scmError("connect to the service control manager", err)
	}
	defer m.Disconnect()

	// Report an existing service clearly (CreateService would also fail, less readably).
	if s, err := openService(m.Handle, name, windows.SERVICE_QUERY_STATUS); err == nil {
		s.Close()
		return fmt.Errorf("winsvc: %w: %q (uninstall it first)", ErrAlreadyInstalled, name)
	} else if !errors.Is(err, ErrNotInstalled) {
		return err
	}

	s, err := m.CreateService(name, exe, mgr.Config{
		ServiceType:      windows.SERVICE_WIN32_OWN_PROCESS,
		StartType:        mgr.StartAutomatic,
		DelayedAutoStart: true,
		ErrorControl:     mgr.ErrorNormal,
		ServiceStartName: "", // NULL account = LocalSystem
		DisplayName:      display,
		Description:      desc,
	}, o.Args...)
	if err != nil {
		return createServiceError(name, err)
	}
	defer s.Close()
	sourceTouched := false
	defer func() {
		if err != nil { // roll back: never leave a half-configured service behind
			if derr := s.Delete(); derr != nil {
				err = errors.Join(err, fmt.Errorf("winsvc: rollback: delete service %q: %w", name, derr))
			}
			if sourceTouched { // a partially written source key would be left otherwise
				if rerr := removeEventSource(name); rerr != nil {
					err = errors.Join(err, fmt.Errorf("winsvc: rollback: %w", rerr))
				}
			}
		}
	}()

	if err = s.SetRecoveryActions(recoveryActions, recoveryResetPeriod); err != nil {
		return fmt.Errorf("winsvc: set recovery actions on %q: %w", name, err)
	}
	if err = s.SetRecoveryActionsOnNonCrashFailures(true); err != nil {
		return fmt.Errorf("winsvc: enable recovery on non-crash failures for %q: %w", name, err)
	}
	sourceTouched = true
	if err = installEventSource(name); err != nil {
		return fmt.Errorf("winsvc: install event log source %q: %w", name, err)
	}
	return nil
}

func uninstall(name string) error {
	scm, err := connect(windows.SC_MANAGER_CONNECT)
	if err != nil {
		return err
	}
	defer windows.CloseServiceHandle(scm)

	s, err := openService(scm, name, windows.DELETE|windows.SERVICE_STOP|windows.SERVICE_QUERY_STATUS)
	if errors.Is(err, ErrNotInstalled) {
		// Nothing to delete, but clean up an event source left by an earlier failure.
		return errors.Join(err, removeEventSource(name))
	}
	if err != nil {
		return err
	}
	defer s.Close()

	stopErr := stopAndWait(s, name, uninstallStopTimeout, pollInterval)
	if err := s.Delete(); err != nil && !errors.Is(err, windows.ERROR_SERVICE_MARKED_FOR_DELETE) {
		// The service stays; keep its event source so its messages remain readable.
		return errors.Join(stopErr, scmError(fmt.Sprintf("delete service %q", name), err))
	}
	if stopErr != nil {
		// Still running: keep its event source so what it logs while stopping stays
		// readable (a later Install replaces the leftover source).
		return fmt.Errorf("%w (the service is marked for deletion and will be removed once it stops; "+
			"its event log source was kept)", stopErr)
	}
	return removeEventSource(name)
}

func start(name string) error {
	scm, err := connect(windows.SC_MANAGER_CONNECT)
	if err != nil {
		return err
	}
	defer windows.CloseServiceHandle(scm)

	s, err := openService(scm, name, windows.SERVICE_START|windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return err
	}
	defer s.Close()
	return startAndWait(s, name, startTimeout, startGrace, pollInterval)
}

func stop(name string, timeout time.Duration) error {
	if timeout <= 0 {
		timeout = defaultStopTimeout
	}
	scm, err := connect(windows.SC_MANAGER_CONNECT)
	if err != nil {
		return err
	}
	defer windows.CloseServiceHandle(scm)

	s, err := openService(scm, name, windows.SERVICE_STOP|windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return err
	}
	defer s.Close()
	return stopAndWait(s, name, timeout, pollInterval)
}

func status(name string) (string, error) {
	scm, err := connect(windows.SC_MANAGER_CONNECT)
	if err != nil {
		return "", err
	}
	defer windows.CloseServiceHandle(scm)

	s, err := openService(scm, name, windows.SERVICE_QUERY_STATUS)
	if errors.Is(err, ErrNotInstalled) {
		return StatusNotInstalled, nil
	}
	if err != nil {
		return "", err
	}
	defer s.Close()
	st, err := s.Query()
	if err != nil {
		return "", scmError(fmt.Sprintf("query service %q", name), err)
	}
	return stateString(st.State), nil
}

// serviceControl is the part of *mgr.Service used to start, stop and watch a service (a
// scripted fake in tests, so the waiting logic is tested without an elevated prompt).
type serviceControl interface {
	Query() (svc.Status, error)
	Control(c svc.Cmd) (svc.Status, error)
	Start(args ...string) error
}

var _ serviceControl = (*mgr.Service)(nil)

// startAndWait starts the service and waits until it is running (see waitStarted). If an
// instance is still stopping (StartService then reports "already running"), it waits for that
// instance to stop and starts a new one, so "start" never reports success for a service that
// is about to stop.
func startAndWait(s serviceControl, name string, timeout, grace, poll time.Duration) error {
	err := s.Start()
	if errors.Is(err, windows.ERROR_SERVICE_ALREADY_RUNNING) {
		st, qerr := s.Query()
		if qerr != nil {
			return scmError(fmt.Sprintf("query service %q", name), qerr)
		}
		if st.State != svc.StopPending {
			return waitStarted(s, name, timeout, grace, poll) // running or starting
		}
		if _, werr := waitForState(s, name, svc.Stopped, timeout, poll); werr != nil {
			return fmt.Errorf("winsvc: start %q: the previous instance is still stopping: %w", name, werr)
		}
		err = s.Start()
		if errors.Is(err, windows.ERROR_SERVICE_ALREADY_RUNNING) {
			err = nil // started by someone else meanwhile; waitStarted checks it stays up
		}
	}
	if err != nil {
		switch {
		case errors.Is(err, windows.ERROR_SERVICE_DISABLED):
			return fmt.Errorf("winsvc: start %q: the service is disabled: %w", name, err)
		case errors.Is(err, windows.ERROR_SERVICE_MARKED_FOR_DELETE):
			return fmt.Errorf("winsvc: start %q: the service is marked for deletion: %w", name, err)
		}
		return scmError(fmt.Sprintf("start service %q", name), err)
	}
	return waitStarted(s, name, timeout, grace, poll)
}

// waitStarted waits until the service leaves the start-pending state. A service that stops
// right away (within grace after reporting running) is reported with its exit code, so
// "start" does not claim success for a service that immediately failed.
func waitStarted(s serviceControl, name string, timeout, grace, poll time.Duration) error {
	deadline := time.Now().Add(timeout)
	var runningSince time.Time
	for {
		st, err := s.Query()
		if err != nil {
			return scmError(fmt.Sprintf("query service %q", name), err)
		}
		switch st.State {
		case svc.Stopped:
			return fmt.Errorf("winsvc: service %q stopped right after starting (%s)", name, exitCodeString(st))
		case svc.Running:
			if runningSince.IsZero() {
				runningSince = time.Now()
			}
			if time.Since(runningSince) >= grace {
				return nil
			}
		case svc.StartPending, svc.StopPending:
			runningSince = time.Time{} // still starting, or failing: keep watching
		default: // paused etc.: the service is up
			return nil
		}
		if time.Now().After(deadline) {
			if !runningSince.IsZero() {
				return nil
			}
			return fmt.Errorf("winsvc: service %q is still %s after %s", name, stateString(st.State), timeout)
		}
		time.Sleep(poll)
	}
}

// waitForState polls until the service is in state want, for at most timeout.
func waitForState(s serviceControl, name string, want svc.State, timeout, poll time.Duration) (svc.Status, error) {
	deadline := time.Now().Add(timeout)
	for {
		st, err := s.Query()
		if err != nil {
			return st, scmError(fmt.Sprintf("query service %q", name), err)
		}
		if st.State == want {
			return st, nil
		}
		if time.Now().After(deadline) {
			return st, fmt.Errorf("winsvc: service %q is still %s after %s", name, stateString(st.State), timeout)
		}
		time.Sleep(poll)
	}
}

// stopAndWait sends a stop control (once the service can accept it) and waits for Stopped.
func stopAndWait(s serviceControl, name string, timeout, poll time.Duration) error {
	deadline := time.Now().Add(timeout)
	sent := false
	for {
		st, err := s.Query()
		if err != nil {
			return scmError(fmt.Sprintf("query service %q", name), err)
		}
		if st.State == svc.Stopped {
			return nil
		}
		if !sent && st.State != svc.StopPending && st.State != svc.StartPending {
			_, err := s.Control(svc.Stop)
			switch {
			case err == nil:
				sent = true
			case errors.Is(err, windows.ERROR_SERVICE_NOT_ACTIVE):
				return nil
			case errors.Is(err, windows.ERROR_SERVICE_CANNOT_ACCEPT_CTRL),
				errors.Is(err, windows.ERROR_SERVICE_REQUEST_TIMEOUT):
				// Starting, stopping or busy: try again on the next poll.
			default:
				return scmError(fmt.Sprintf("stop service %q", name), err)
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("winsvc: service %q did not stop within %s (state: %s)", name, timeout, stateString(st.State))
		}
		time.Sleep(poll)
	}
}

func connect(access uint32) (windows.Handle, error) {
	h, err := windows.OpenSCManager(nil, nil, access)
	if err != nil {
		return 0, scmError("connect to the service control manager", err)
	}
	return h, nil
}

// openService opens a service with just the rights needed. The result is a *mgr.Service so
// its helpers (Query, Control, Start, Delete) can be used with the limited handle.
func openService(scm windows.Handle, name string, access uint32) (*mgr.Service, error) {
	p, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, fmt.Errorf("winsvc: invalid service name %q: %w", name, err)
	}
	h, err := windows.OpenService(scm, p, access)
	if err != nil {
		if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
			return nil, fmt.Errorf("winsvc: %q: %w", name, ErrNotInstalled)
		}
		return nil, scmError(fmt.Sprintf("open service %q", name), err)
	}
	return &mgr.Service{Name: name, Handle: h}, nil
}

func resolveExe(p string) (string, error) {
	if p == "" {
		exe, err := os.Executable()
		if err != nil {
			return "", fmt.Errorf("winsvc: locate executable: %w", err)
		}
		p = exe
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", fmt.Errorf("winsvc: service executable %q: %w", p, err)
	}
	fi, err := os.Stat(abs)
	if err != nil {
		return "", fmt.Errorf("winsvc: service executable: %w", err)
	}
	if !fi.Mode().IsRegular() {
		return "", fmt.Errorf("winsvc: service executable %q is not a regular file", abs)
	}
	return abs, nil
}

// installEventSource registers name under the Application log with EventCreate.exe as the
// message file. A key left behind by an earlier installation is replaced.
func installEventSource(name string) error {
	if eventSourceExists(name) {
		if err := eventlog.Remove(name); err != nil {
			return fmt.Errorf("replace existing source: %w", err)
		}
	}
	return eventlog.InstallAsEventCreate(name, eventTypesSupported)
}

func removeEventSource(name string) error {
	if !eventSourceExists(name) {
		return nil
	}
	if err := eventlog.Remove(name); err != nil && !errors.Is(err, registry.ErrNotExist) {
		return scmError(fmt.Sprintf("remove event log source %q", name), err)
	}
	return nil
}

func eventSourceExists(name string) bool {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, eventSourceParentKey+`\`+name, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	k.Close()
	return true
}

func createServiceError(name string, err error) error {
	switch {
	case errors.Is(err, windows.ERROR_SERVICE_EXISTS):
		return fmt.Errorf("winsvc: %w: %q (uninstall it first): %w", ErrAlreadyInstalled, name, err)
	case errors.Is(err, windows.ERROR_DUPLICATE_SERVICE_NAME):
		return fmt.Errorf("winsvc: create service %q: its name or display name is already used by another service: %w", name, err)
	case errors.Is(err, windows.ERROR_SERVICE_MARKED_FOR_DELETE):
		return fmt.Errorf("winsvc: create service %q: a previous instance is still marked for deletion; "+
			"close the Services console (and any tool holding the service open) and retry, or reboot: %w", name, err)
	}
	return scmError(fmt.Sprintf("create service %q", name), err)
}

// scmError wraps err with the operation and, for access denied, how to fix it.
func scmError(op string, err error) error {
	if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		return fmt.Errorf("winsvc: %s: %w (administrator rights are required: run from an elevated prompt)", op, err)
	}
	return fmt.Errorf("winsvc: %s: %w", op, err)
}

func stateString(s svc.State) string {
	switch s {
	case svc.Stopped:
		return StatusStopped
	case svc.StartPending:
		return StatusStartPending
	case svc.StopPending:
		return StatusStopPending
	case svc.Running:
		return StatusRunning
	case svc.ContinuePending:
		return StatusContinuePending
	case svc.PausePending:
		return StatusPausePending
	case svc.Paused:
		return StatusPaused
	}
	return fmt.Sprintf("unknown state %d", uint32(s))
}

// exitCodeString describes how a stopped service exited.
func exitCodeString(st svc.Status) string {
	switch {
	case st.Win32ExitCode == uint32(windows.ERROR_SERVICE_SPECIFIC_ERROR):
		desc := "see the Application event log"
		switch st.ServiceSpecificExitCode {
		case ExitRunFailed:
			desc = "the monitor failed; see the Application event log"
		case ExitRunPanicked:
			desc = "the monitor crashed; see the Application event log"
		case ExitRunReturned:
			desc = "the monitor stopped without being asked to; see the Application event log"
		}
		return fmt.Sprintf("service-specific exit code %d: %s", st.ServiceSpecificExitCode, desc)
	case st.Win32ExitCode != 0:
		return fmt.Sprintf("exit code %d: %v", st.Win32ExitCode, syscall.Errno(st.Win32ExitCode))
	}
	return "exit code 0"
}
