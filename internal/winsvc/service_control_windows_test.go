//go:build windows

package winsvc

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
)

// fakeService scripts the states a service reports to successive Query calls (the last one
// repeats) and lets Control/Start change the script, so the start/stop waiting logic can be
// tested without the SCM or elevation.
type fakeService struct {
	mu        sync.Mutex
	states    []svc.Status
	queryErr  error
	queries   int
	controls  []svc.Cmd
	controlAt []int // query count at each Control call
	starts    int
	onControl func(f *fakeService) error // called with mu held
	onStart   func(f *fakeService) error // called with mu held
}

var _ serviceControl = (*fakeService)(nil)

func states(ss ...svc.State) []svc.Status {
	out := make([]svc.Status, len(ss))
	for i, s := range ss {
		out[i] = svc.Status{State: s}
	}
	return out
}

func (f *fakeService) Query() (svc.Status, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.queries++
	if f.queryErr != nil {
		return svc.Status{}, f.queryErr
	}
	st := f.states[0]
	if len(f.states) > 1 {
		f.states = f.states[1:]
	}
	return st, nil
}

func (f *fakeService) Control(c svc.Cmd) (svc.Status, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.controls = append(f.controls, c)
	f.controlAt = append(f.controlAt, f.queries)
	if f.onControl != nil {
		return svc.Status{}, f.onControl(f)
	}
	return svc.Status{}, nil
}

func (f *fakeService) Start(...string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.starts++
	if f.onStart != nil {
		return f.onStart(f)
	}
	return nil
}

const (
	fastPoll    = time.Millisecond
	fastGrace   = 5 * time.Millisecond
	fastTimeout = 150 * time.Millisecond
)

func TestStopAndWait(t *testing.T) {
	stopping := func(f *fakeService) error {
		f.states = states(svc.StopPending, svc.StopPending, svc.Stopped)
		return nil
	}
	tests := []struct {
		name         string
		f            *fakeService
		wantErrSub   string // "" = success
		wantErrIs    error
		wantControls int
		check        func(t *testing.T, f *fakeService)
	}{
		{name: "already stopped: nothing sent", f: &fakeService{states: states(svc.Stopped)}},
		{name: "running: one stop control, then wait", f: &fakeService{states: states(svc.Running), onControl: stopping},
			wantControls: 1},
		{
			name: "start pending: stop is sent only once running",
			f:    &fakeService{states: states(svc.StartPending, svc.StartPending, svc.Running), onControl: stopping},
			check: func(t *testing.T, f *fakeService) {
				if len(f.controlAt) != 1 || f.controlAt[0] != 3 {
					t.Errorf("stop sent after query %v, want after the third (first running) query", f.controlAt)
				}
			},
			wantControls: 1,
		},
		{name: "already stopping: no control, just wait",
			f: &fakeService{states: states(svc.StopPending, svc.StopPending, svc.Stopped)}},
		{name: "not active is success", wantControls: 1,
			f: &fakeService{states: states(svc.Running), onControl: func(*fakeService) error { return windows.ERROR_SERVICE_NOT_ACTIVE }}},
		{
			name: "cannot accept control yet: retried",
			f: func() *fakeService {
				n := 0
				return &fakeService{states: states(svc.Running), onControl: func(f *fakeService) error {
					if n++; n == 1 {
						return windows.ERROR_SERVICE_CANNOT_ACCEPT_CTRL
					}
					return stopping(f)
				}}
			}(),
			wantControls: 2,
		},
		{name: "access denied is reported with a hint", wantControls: 1, wantErrIs: windows.ERROR_ACCESS_DENIED, wantErrSub: "elevated",
			f: &fakeService{states: states(svc.Running), onControl: func(*fakeService) error { return windows.ERROR_ACCESS_DENIED }}},
		{name: "never stops: timeout names the state", wantControls: 1, wantErrSub: "did not stop within 150ms (state: stop pending)",
			f: &fakeService{states: states(svc.Running), onControl: func(f *fakeService) error { f.states = states(svc.StopPending); return nil }}},
		{name: "query error", wantErrIs: windows.ERROR_INVALID_HANDLE, wantErrSub: "query service",
			f: &fakeService{states: states(svc.Running), queryErr: windows.ERROR_INVALID_HANDLE}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := stopAndWait(tc.f, "ATTMonitorTest", fastTimeout, fastPoll)
			checkErr(t, err, tc.wantErrIs, tc.wantErrSub)
			if len(tc.f.controls) != tc.wantControls {
				t.Errorf("controls %v, want %d", tc.f.controls, tc.wantControls)
			}
			for _, c := range tc.f.controls {
				if c != svc.Stop {
					t.Errorf("control %d sent, want only Stop", c)
				}
			}
			if tc.check != nil {
				tc.check(t, tc.f)
			}
		})
	}
}

func TestWaitStarted(t *testing.T) {
	specific := uint32(windows.ERROR_SERVICE_SPECIFIC_ERROR)
	tests := []struct {
		name       string
		f          *fakeService
		grace      time.Duration
		wantErrSub string
	}{
		{name: "start pending then running", f: &fakeService{states: states(svc.StartPending, svc.StartPending, svc.Running)}, grace: fastGrace},
		{name: "fails right away: exit code reported", grace: fastGrace,
			f: &fakeService{states: []svc.Status{{State: svc.StartPending},
				{State: svc.Stopped, Win32ExitCode: specific, ServiceSpecificExitCode: ExitRunReturned}}},
			wantErrSub: "stopped right after starting (service-specific exit code 3: the monitor stopped without being asked to"},
		{name: "running briefly, then stops within the grace period", grace: time.Second,
			f: &fakeService{states: []svc.Status{{State: svc.Running}, {State: svc.StopPending},
				{State: svc.Stopped, Win32ExitCode: specific, ServiceSpecificExitCode: ExitRunFailed}}},
			wantErrSub: "service-specific exit code 1: the monitor failed"},
		{name: "stuck starting: timeout", grace: fastGrace, f: &fakeService{states: states(svc.StartPending)},
			wantErrSub: "is still start pending after 150ms"},
		{name: "running when the timeout expires counts as started", grace: time.Hour, f: &fakeService{states: states(svc.Running)}},
		{name: "paused is up", grace: fastGrace, f: &fakeService{states: states(svc.Paused)}},
		{name: "query error", grace: fastGrace, f: &fakeService{states: states(svc.Running), queryErr: windows.ERROR_ACCESS_DENIED},
			wantErrSub: "elevated"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := waitStarted(tc.f, "ATTMonitorTest", fastTimeout, tc.grace, fastPoll)
			checkErr(t, err, nil, tc.wantErrSub)
		})
	}
}

func TestStartAndWait(t *testing.T) {
	alreadyRunning := func(next ...svc.State) func(f *fakeService) error {
		return func(f *fakeService) error {
			if f.starts == 1 {
				return windows.ERROR_SERVICE_ALREADY_RUNNING
			}
			f.states = states(next...)
			return nil
		}
	}
	tests := []struct {
		name       string
		f          *fakeService
		wantStarts int
		wantErrIs  error
		wantErrSub string
	}{
		{name: "starts", wantStarts: 1,
			f: &fakeService{states: states(svc.StartPending, svc.Running)}},
		{name: "already running", wantStarts: 1,
			f: &fakeService{states: states(svc.Running), onStart: alreadyRunning()}},
		{name: "already starting", wantStarts: 1,
			f: &fakeService{states: states(svc.StartPending, svc.StartPending, svc.Running), onStart: alreadyRunning()}},
		{
			// "already running" while the old instance is still stopping must not be reported
			// as started: wait for it to stop, then start a new instance.
			name: "previous instance still stopping: waits, then starts again", wantStarts: 2,
			f: &fakeService{states: states(svc.StopPending, svc.StopPending, svc.Stopped),
				onStart: alreadyRunning(svc.StartPending, svc.Running)},
		},
		{name: "previous instance never stops", wantStarts: 1, wantErrSub: "previous instance is still stopping",
			f: &fakeService{states: states(svc.StopPending), onStart: alreadyRunning()}},
		{
			name: "someone else started it meanwhile", wantStarts: 2,
			f: &fakeService{states: states(svc.StopPending, svc.Stopped), onStart: func(f *fakeService) error {
				f.states = states(svc.Running)
				if f.starts == 1 {
					f.states = states(svc.StopPending, svc.Stopped)
				}
				return windows.ERROR_SERVICE_ALREADY_RUNNING
			}},
		},
		{name: "disabled", wantStarts: 1, wantErrIs: windows.ERROR_SERVICE_DISABLED, wantErrSub: "disabled",
			f: &fakeService{states: states(svc.Stopped), onStart: func(*fakeService) error { return windows.ERROR_SERVICE_DISABLED }}},
		{name: "marked for deletion", wantStarts: 1, wantErrIs: windows.ERROR_SERVICE_MARKED_FOR_DELETE, wantErrSub: "marked for deletion",
			f: &fakeService{states: states(svc.Stopped), onStart: func(*fakeService) error { return windows.ERROR_SERVICE_MARKED_FOR_DELETE }}},
		{name: "access denied", wantStarts: 1, wantErrIs: windows.ERROR_ACCESS_DENIED, wantErrSub: "elevated prompt",
			f: &fakeService{states: states(svc.Stopped), onStart: func(*fakeService) error { return windows.ERROR_ACCESS_DENIED }}},
		{name: "starts but dies immediately", wantStarts: 1, wantErrSub: "stopped right after starting",
			f: &fakeService{states: states(svc.StartPending, svc.Stopped)}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := startAndWait(tc.f, "ATTMonitorTest", fastTimeout, fastGrace, fastPoll)
			checkErr(t, err, tc.wantErrIs, tc.wantErrSub)
			if tc.f.starts != tc.wantStarts {
				t.Errorf("Start called %d times, want %d", tc.f.starts, tc.wantStarts)
			}
		})
	}
}

func TestWaitForState(t *testing.T) {
	f := &fakeService{states: states(svc.StopPending, svc.StopPending, svc.Stopped)}
	if st, err := waitForState(f, "X", svc.Stopped, fastTimeout, fastPoll); err != nil || st.State != svc.Stopped {
		t.Errorf("waitForState = %+v, %v; want stopped", st, err)
	}
	f = &fakeService{states: states(svc.Running)}
	start := time.Now()
	_, err := waitForState(f, "X", svc.Stopped, fastTimeout, fastPoll)
	checkErr(t, err, nil, "is still running after 150ms")
	if d := time.Since(start); d < fastTimeout || d > 5*time.Second {
		t.Errorf("gave up after %v, want about %v", d, fastTimeout)
	}
}

func checkErr(t *testing.T, err, wantIs error, wantSub string) {
	t.Helper()
	if wantSub == "" && wantIs == nil {
		if err != nil {
			t.Fatalf("err = %v, want nil", err)
		}
		return
	}
	if err == nil {
		t.Fatalf("err = nil, want an error containing %q", wantSub)
	}
	if wantIs != nil && !errors.Is(err, wantIs) {
		t.Errorf("err = %v, want it to wrap %v", err, wantIs)
	}
	if !strings.Contains(err.Error(), wantSub) {
		t.Errorf("err = %q, want it to contain %q", err, wantSub)
	}
}
