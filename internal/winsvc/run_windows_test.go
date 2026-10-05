//go:build windows

package winsvc

import (
	"context"
	"errors"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
)

const testWait = 5 * time.Second // generous bound for anything that should be immediate

func TestPowerEventName(t *testing.T) {
	tests := []struct {
		eventType uint32
		want      string
	}{
		{4, "suspend"},                // PBT_APMSUSPEND
		{7, "resume"},                 // PBT_APMRESUMESUSPEND
		{18, "resume_automatic"},      // PBT_APMRESUMEAUTOMATIC
		{10, "power_status_change"},   // PBT_APMPOWERSTATUSCHANGE
		{0x8013, "power_event_32787"}, // PBT_POWERSETTINGCHANGE (not registered, but mapped)
		{0, "power_event_0"},          // PBT_APMQUERYSUSPEND (obsolete)
		{9, "power_event_9"},          // PBT_APMBATTERYLOW (obsolete)
		{0xFFFFFFFF, "power_event_4294967295"},
	}
	for _, tc := range tests {
		if got := powerEventName(tc.eventType); got != tc.want {
			t.Errorf("powerEventName(%d) = %q, want %q", tc.eventType, got, tc.want)
		}
	}
}

// harness drives handler.Execute the way golang.org/x/sys/windows/svc does: an unbuffered
// request channel and a status channel.
type harness struct {
	t    *testing.T
	h    *handler
	r    chan svc.ChangeRequest
	s    chan svc.Status
	done chan execResult
}

type execResult struct {
	svcSpecific bool
	code        uint32
}

func startHandler(t *testing.T, run func(ctx context.Context, power <-chan string) error, stopTimeout time.Duration) *harness {
	t.Helper()
	h := newHandler(run)
	h.stopTimeout = stopTimeout
	h.checkpointEvery = 20 * time.Millisecond
	hs := &harness{
		t:    t,
		h:    h,
		r:    make(chan svc.ChangeRequest),
		s:    make(chan svc.Status, 4096),
		done: make(chan execResult, 1),
	}
	go func() {
		ss, code := h.Execute([]string{"ATTMonitorTest"}, hs.r, hs.s)
		hs.done <- execResult{ss, code}
	}()
	return hs
}

func (hs *harness) status() svc.Status {
	hs.t.Helper()
	select {
	case st := <-hs.s:
		return st
	case <-time.After(testWait):
		hs.t.Fatal("timed out waiting for a status report")
		return svc.Status{}
	}
}

// expectRunning consumes StartPending and Running and checks the accepted controls.
func (hs *harness) expectRunning() svc.Status {
	hs.t.Helper()
	if st := hs.status(); st.State != svc.StartPending || st.WaitHint == 0 {
		hs.t.Fatalf("first status = %+v, want StartPending with a wait hint", st)
	}
	st := hs.status()
	want := svc.AcceptStop | svc.AcceptShutdown | svc.AcceptPowerEvent
	if st.State != svc.Running || st.Accepts != want {
		hs.t.Fatalf("second status = %+v, want Running accepting %#x", st, want)
	}
	return st
}

func (hs *harness) send(c svc.ChangeRequest) {
	hs.t.Helper()
	select {
	case hs.r <- c:
	case <-time.After(testWait):
		hs.t.Fatalf("handler did not accept control %d: it is blocked", c.Cmd)
	}
}

func (hs *harness) wait() execResult {
	hs.t.Helper()
	select {
	case res := <-hs.done:
		return res
	case <-time.After(testWait):
		hs.t.Fatal("Execute did not return")
		return execResult{}
	}
}

func TestHandlerStopRequest(t *testing.T) {
	var (
		mu    sync.Mutex
		cause error
	)
	started := make(chan struct{})
	hs := startHandler(t, func(ctx context.Context, _ <-chan string) error {
		close(started)
		<-ctx.Done()
		mu.Lock()
		cause = context.Cause(ctx)
		mu.Unlock()
		return ctx.Err() // a typical run returns the context error: not reported as a failure
	}, time.Second)

	running := hs.expectRunning()
	<-started

	// Interrogate is answered with the current status.
	hs.send(svc.ChangeRequest{Cmd: svc.Interrogate, CurrentStatus: running})
	if st := hs.status(); st != running {
		t.Fatalf("interrogate answered %+v, want %+v", st, running)
	}

	hs.send(svc.ChangeRequest{Cmd: svc.Stop, CurrentStatus: running})
	st := hs.status()
	if st.State != svc.StopPending || st.CheckPoint != 1 || st.WaitHint == 0 || st.Accepts != 0 {
		t.Fatalf("after Stop: %+v, want StopPending checkpoint 1 with wait hint, accepting nothing", st)
	}
	if res := hs.wait(); res != (execResult{false, 0}) {
		t.Fatalf("Execute returned %+v, want clean exit (false, 0)", res)
	}
	mu.Lock()
	defer mu.Unlock()
	if !errors.Is(cause, ErrServiceStop) || cause.Error() != "service stop" {
		t.Errorf("context cause = %v, want %q", cause, "service stop")
	}
	if err := hs.h.result(); err != nil {
		t.Errorf("result = %v, want nil", err)
	}
}

func TestHandlerShutdown(t *testing.T) {
	type outcome struct {
		cause  error
		events []string
	}
	got := make(chan outcome, 1)
	hs := startHandler(t, func(ctx context.Context, power <-chan string) error {
		<-ctx.Done()
		var evs []string
		for {
			select {
			case e := <-power:
				evs = append(evs, e)
				continue
			default:
			}
			break
		}
		got <- outcome{context.Cause(ctx), evs}
		return context.Cause(ctx) // returning the cause itself is not a failure either
	}, time.Second)
	running := hs.expectRunning()
	hs.send(svc.ChangeRequest{Cmd: svc.Shutdown, CurrentStatus: running})
	if res := hs.wait(); res != (execResult{false, 0}) {
		t.Fatalf("Execute returned %+v, want (false, 0)", res)
	}
	o := <-got
	if !errors.Is(o.cause, ErrSystemShutdown) || o.cause.Error() != "system shutdown" {
		t.Errorf("cause = %v, want %q", o.cause, "system shutdown")
	}
	if len(o.events) != 1 || o.events[0] != PowerShutdown {
		t.Errorf("power events = %q, want [shutdown]", o.events)
	}
	if err := hs.h.result(); err != nil {
		t.Errorf("result = %v, want nil", err)
	}
}

func TestHandlerForwardsPowerEvents(t *testing.T) {
	want := []string{"suspend", "resume_automatic", "resume", "power_status_change", "power_event_32787"}
	received := make(chan string, 16)
	hs := startHandler(t, func(ctx context.Context, power <-chan string) error {
		for {
			select {
			case e := <-power:
				received <- e
			case <-ctx.Done():
				return nil
			}
		}
	}, time.Second)
	running := hs.expectRunning()
	for _, et := range []uint32{4, 18, 7, 10, 0x8013} {
		hs.send(svc.ChangeRequest{Cmd: svc.PowerEvent, EventType: et, CurrentStatus: running})
	}
	for i, w := range want {
		select {
		case e := <-received:
			if e != w {
				t.Errorf("event %d = %q, want %q", i, e, w)
			}
		case <-time.After(testWait):
			t.Fatalf("event %d (%q) not received", i, w)
		}
	}
	hs.send(svc.ChangeRequest{Cmd: svc.Stop, CurrentStatus: running})
	if res := hs.wait(); res != (execResult{false, 0}) {
		t.Fatalf("Execute returned %+v", res)
	}
}

// The handler must never block on the power channel, even if run never reads it.
func TestHandlerNeverBlocksOnPowerChannel(t *testing.T) {
	queued := make(chan int, 1)
	hs := startHandler(t, func(ctx context.Context, power <-chan string) error {
		<-ctx.Done()
		queued <- len(power)
		return nil
	}, time.Second)
	running := hs.expectRunning()
	for i := 0; i < 3*powerQueueSize; i++ {
		hs.send(svc.ChangeRequest{Cmd: svc.PowerEvent, EventType: pbtAPMSuspend, CurrentStatus: running})
	}
	hs.send(svc.ChangeRequest{Cmd: svc.Stop, CurrentStatus: running})
	if res := hs.wait(); res != (execResult{false, 0}) {
		t.Fatalf("Execute returned %+v", res)
	}
	if n := <-queued; n != powerQueueSize {
		t.Errorf("queued power events = %d, want the buffer size %d (excess dropped)", n, powerQueueSize)
	}
}

func TestHandlerRunReturnsOnItsOwn(t *testing.T) {
	diskFull := errors.New("ledger: append: disk full")
	tests := []struct {
		name       string
		run        func(ctx context.Context, power <-chan string) error
		want       execResult
		wantErr    error  // errors.Is target for the result, nil = no error expected
		wantErrSub string // substring of the result's text
	}{
		{
			name:    "error requests a restart",
			run:     func(context.Context, <-chan string) error { return diskFull },
			want:    execResult{true, ExitRunFailed},
			wantErr: diskFull, wantErrSub: "run stopped unexpectedly",
		},
		{
			// An evidence logger never stops on its own: a nil return without a stop request
			// is a monitor bug and must be restarted, not end in a silent clean stop.
			name:    "nil without a stop request also requests a restart",
			run:     func(context.Context, <-chan string) error { return nil },
			want:    execResult{true, ExitRunReturned},
			wantErr: errRunReturned, wantErrSub: "without a stop request",
		},
		{
			name:       "panic is recovered with its stack and requests a restart",
			run:        func(context.Context, <-chan string) error { panic("boom in monitor") },
			want:       execResult{true, ExitRunPanicked},
			wantErrSub: "boom in monitor",
		},
		{
			name: "runtime.Goexit is treated as a failure",
			run: func(context.Context, <-chan string) error {
				runtime.Goexit()
				return nil
			},
			want:    execResult{true, ExitRunFailed},
			wantErr: errRunExited,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			hs := startHandler(t, tc.run, time.Second)
			hs.expectRunning()
			if res := hs.wait(); res != tc.want {
				t.Fatalf("Execute returned %+v, want %+v", res, tc.want)
			}
			err := hs.h.result()
			if tc.wantErr == nil && tc.wantErrSub == "" {
				if err != nil {
					t.Fatalf("result = %v, want nil", err)
				}
				return
			}
			if err == nil {
				t.Fatal("result = nil, want an error")
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Errorf("result = %v, want it to wrap %v", err, tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErrSub) {
				t.Errorf("result = %q, want it to contain %q", err, tc.wantErrSub)
			}
			if tc.want.code == ExitRunPanicked && !strings.Contains(err.Error(), "run_windows_test.go") {
				t.Errorf("panic result lacks the stack trace: %q", err)
			}
		})
	}
}

func TestHandlerErrorDuringStop(t *testing.T) {
	flush := errors.New("flush monitor_stop: disk full")
	hs := startHandler(t, func(ctx context.Context, _ <-chan string) error {
		<-ctx.Done()
		return flush
	}, time.Second)
	running := hs.expectRunning()
	hs.send(svc.ChangeRequest{Cmd: svc.Stop, CurrentStatus: running})
	// A requested stop always exits 0 (no restart), but the error is reported to the caller.
	if res := hs.wait(); res != (execResult{false, 0}) {
		t.Fatalf("Execute returned %+v, want (false, 0)", res)
	}
	err := hs.h.result()
	if !errors.Is(err, flush) || !strings.Contains(err.Error(), "after the service stop request") {
		t.Errorf("result = %v, want the run error after service stop", err)
	}
}

func TestHandlerStopTimeout(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	hs := startHandler(t, func(ctx context.Context, _ <-chan string) error {
		<-release // ignores ctx: a hung monitor
		return nil
	}, 300*time.Millisecond)
	running := hs.expectRunning()
	start := time.Now()
	hs.send(svc.ChangeRequest{Cmd: svc.Stop, CurrentStatus: running})
	res := hs.wait()
	elapsed := time.Since(start)
	if res != (execResult{false, 0}) {
		t.Fatalf("Execute returned %+v, want (false, 0): a requested stop must not trigger a restart", res)
	}
	if elapsed < 250*time.Millisecond || elapsed > 3*time.Second {
		t.Errorf("Execute returned after %v, want about the 300ms stop timeout", elapsed)
	}
	if err := hs.h.result(); err == nil || !strings.Contains(err.Error(), "did not return within") {
		t.Errorf("result = %v, want a stop-timeout error", err)
	}
	// The stop-pending checkpoint must advance while waiting.
	var cps []uint32
	for len(hs.s) > 0 {
		if st := <-hs.s; st.State == svc.StopPending {
			cps = append(cps, st.CheckPoint)
		}
	}
	if len(cps) < 3 {
		t.Fatalf("stop-pending reports = %v, want several with advancing checkpoints", cps)
	}
	for i := 1; i < len(cps); i++ {
		if cps[i] != cps[i-1]+1 {
			t.Fatalf("checkpoints %v do not advance by one", cps)
		}
	}
}

// While waiting for run to finish, the handler keeps answering the SCM.
func TestHandlerAnswersControlsWhileStopping(t *testing.T) {
	release := make(chan struct{})
	hs := startHandler(t, func(ctx context.Context, _ <-chan string) error {
		<-ctx.Done()
		<-release
		return nil
	}, testWait)
	running := hs.expectRunning()
	hs.send(svc.ChangeRequest{Cmd: svc.Stop, CurrentStatus: running})
	pending := hs.status()
	if pending.State != svc.StopPending {
		t.Fatalf("status = %+v, want StopPending", pending)
	}
	hs.send(svc.ChangeRequest{Cmd: svc.Interrogate, CurrentStatus: pending})
	for {
		st := hs.status() // checkpoint updates may arrive first
		if st == pending {
			break
		}
		if st.State != svc.StopPending {
			t.Fatalf("unexpected status %+v while stopping", st)
		}
	}
	hs.send(svc.ChangeRequest{Cmd: svc.Shutdown, CurrentStatus: pending})
	hs.send(svc.ChangeRequest{Cmd: svc.PowerEvent, EventType: pbtAPMSuspend, CurrentStatus: pending})
	close(release)
	if res := hs.wait(); res != (execResult{false, 0}) {
		t.Fatalf("Execute returned %+v", res)
	}
}

func TestRunOutsideServiceControlManager(t *testing.T) {
	if err := Run(nil); err == nil {
		t.Error("Run(nil) = nil, want an error")
	}
	if is, err := IsService(); err != nil || is {
		t.Skipf("IsService() = %v, %v: test must run outside the SCM", is, err)
	}
	// Windows allows one StartServiceCtrlDispatcher call per process, so only the first Run
	// in this test process reaches the SCM (go test -count=N repeats this test).
	first := !runCalled.Load()
	for i := 0; i < 2; i++ {
		called := make(chan struct{}, 1)
		errc := make(chan error, 1)
		go func() {
			errc <- Run(func(context.Context, <-chan string) error {
				called <- struct{}{}
				return nil
			})
		}()
		select {
		case err := <-errc:
			if first && i == 0 {
				if !errors.Is(err, windows.ERROR_FAILED_SERVICE_CONTROLLER_CONNECT) {
					t.Fatalf("Run = %v, want ERROR_FAILED_SERVICE_CONTROLLER_CONNECT", err)
				}
				if !strings.Contains(err.Error(), "not started by the service control manager") {
					t.Errorf("Run error %q does not explain the cause", err)
				}
			} else if !errors.Is(err, errRunTwice) {
				t.Fatalf("repeated Run = %v, want errRunTwice", err)
			}
		case <-time.After(15 * time.Second):
			t.Fatal("Run did not return outside the SCM")
		}
		select {
		case <-called:
			t.Error("run was called although the process is not a service")
		default:
		}
	}
}

// raceStopWithExit makes run return on its own while a stop request is already queued, so
// Execute sees both at once (the select may pick either), and returns Execute's result and
// the handler.
func raceStopWithExit(t *testing.T, cmd svc.Cmd, runErr error) (execResult, *handler) {
	t.Helper()
	returned := make(chan struct{})
	h := newHandler(func(context.Context, <-chan string) error {
		defer close(returned)
		return runErr
	})
	h.stopTimeout = time.Second
	r := make(chan svc.ChangeRequest, 1)
	s := make(chan svc.Status) // unbuffered: Execute waits for us before reporting Running
	done := make(chan execResult, 1)
	go func() {
		ss, code := h.Execute(nil, r, s)
		done <- execResult{ss, code}
	}()
	if st := <-s; st.State != svc.StartPending {
		t.Fatalf("first status %+v, want StartPending", st)
	}
	<-returned
	time.Sleep(10 * time.Millisecond) // let run's result reach the done channel
	r <- svc.ChangeRequest{Cmd: cmd}
	drained := make(chan struct{})
	go func() { // consume Running and anything after it
		defer close(drained)
		for range s {
		}
	}()
	defer func() { close(s); <-drained }()
	select {
	case res := <-done:
		return res, h
	case <-time.After(testWait):
		t.Fatal("Execute did not return")
		return execResult{}, nil
	}
}

// A stop request arriving while run returns on its own is still a requested stop: exit code
// 0, so SCM recovery does not restart a service the operator (or Windows) stopped. Repeated
// because Execute's select picks randomly between the two ready channels.
func TestHandlerStopRacingWithRunExit(t *testing.T) {
	diskFull := errors.New("ledger: disk full")
	tests := []struct {
		name    string
		cmd     svc.Cmd
		runErr  error
		wantSub string // "" = no error expected
	}{
		{"stop, run failed", svc.Stop, diskFull, "at the time of the service stop request"},
		{"shutdown, run failed", svc.Shutdown, diskFull, "at the time of the system shutdown request"},
		{"stop, run returned nil", svc.Stop, nil, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			for i := 0; i < 25; i++ {
				res, h := raceStopWithExit(t, tc.cmd, tc.runErr)
				if res != (execResult{false, 0}) {
					t.Fatalf("iteration %d: Execute returned %+v, want (false, 0): the stop was requested", i, res)
				}
				err := h.result()
				if tc.wantSub == "" {
					if err != nil {
						t.Fatalf("iteration %d: result = %v, want nil", i, err)
					}
					continue
				}
				// Either path (stop seen first, or exit seen first) must report run's error.
				if !errors.Is(err, tc.runErr) {
					t.Fatalf("iteration %d: result = %v, want it to wrap %v", i, err, tc.runErr)
				}
			}
		})
	}
}

func TestPendingStop(t *testing.T) {
	running := svc.Status{State: svc.Running}
	tests := []struct {
		name        string
		queued      []svc.ChangeRequest
		wantStop    bool
		wantCmd     svc.Cmd
		wantAnswers int // Interrogate answers written to the status channel
	}{
		{name: "nothing queued"},
		{name: "stop", queued: []svc.ChangeRequest{{Cmd: svc.Stop}}, wantStop: true, wantCmd: svc.Stop},
		{name: "shutdown", queued: []svc.ChangeRequest{{Cmd: svc.Shutdown}}, wantStop: true, wantCmd: svc.Shutdown},
		{name: "interrogate answered, then stop", queued: []svc.ChangeRequest{
			{Cmd: svc.Interrogate, CurrentStatus: running}, {Cmd: svc.Stop}}, wantStop: true, wantCmd: svc.Stop, wantAnswers: 1},
		{name: "power event dropped", queued: []svc.ChangeRequest{{Cmd: svc.PowerEvent, EventType: pbtAPMSuspend}}},
		{name: "bounded: stop behind too many requests is left queued", queued: []svc.ChangeRequest{
			{Cmd: svc.Interrogate, CurrentStatus: running}, {Cmd: svc.Interrogate, CurrentStatus: running},
			{Cmd: svc.Interrogate, CurrentStatus: running}, {Cmd: svc.Interrogate, CurrentStatus: running},
			{Cmd: svc.Stop}}, wantAnswers: maxPendingControls},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := make(chan svc.ChangeRequest, len(tc.queued))
			for _, c := range tc.queued {
				r <- c
			}
			s := make(chan svc.Status, 16)
			c, ok := pendingStop(r, s)
			if ok != tc.wantStop || (ok && c.Cmd != tc.wantCmd) {
				t.Fatalf("pendingStop = %+v, %v; want cmd %d, %v", c, ok, tc.wantCmd, tc.wantStop)
			}
			if len(s) != tc.wantAnswers {
				t.Errorf("%d interrogate answers, want %d", len(s), tc.wantAnswers)
			}
			for len(s) > 0 {
				if st := <-s; st != running {
					t.Errorf("answered %+v, want the current status", st)
				}
			}
		})
	}
}

// captureReports replaces the event-log reporter for the duration of the test.
func captureReports(t *testing.T) func() []error {
	t.Helper()
	var (
		mu  sync.Mutex
		got []error
	)
	old := reportServiceError
	reportServiceError = func(err error) {
		mu.Lock()
		got = append(got, err)
		mu.Unlock()
	}
	t.Cleanup(func() { reportServiceError = old })
	return func() []error {
		mu.Lock()
		defer mu.Unlock()
		return append([]error(nil), got...)
	}
}

// Errors that Run returns after running as a service are also written to the event log (a
// service has no console), and a dispatcher that never ran the handler is an error.
func TestFinishReportsFailures(t *testing.T) {
	crash := errors.New("probe: nil map write")
	tests := []struct {
		name    string
		run     func(context.Context, <-chan string) error // nil: Execute is never called
		stop    bool
		wantErr error
	}{
		{name: "dispatcher returned without running the service", wantErr: errNotExecuted},
		{name: "run failed", run: func(context.Context, <-chan string) error { return crash }, wantErr: crash},
		{name: "run returned on its own", run: func(context.Context, <-chan string) error { return nil }, wantErr: errRunReturned},
		{name: "clean requested stop", run: func(ctx context.Context, _ <-chan string) error {
			<-ctx.Done()
			return ctx.Err()
		}, stop: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			reports := captureReports(t)
			h := newHandler(func(context.Context, <-chan string) error { return nil })
			if tc.run != nil {
				hs := startHandler(t, tc.run, time.Second)
				h = hs.h
				running := hs.expectRunning()
				if tc.stop {
					hs.send(svc.ChangeRequest{Cmd: svc.Stop, CurrentStatus: running})
				}
				hs.wait()
			}
			err := h.finish()
			if tc.wantErr == nil {
				if err != nil || len(reports()) != 0 {
					t.Fatalf("finish = %v, reports %v; want nil and no report", err, reports())
				}
				return
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("finish = %v, want it to wrap %v", err, tc.wantErr)
			}
			if rs := reports(); len(rs) != 1 || rs[0] != err {
				t.Errorf("reports = %v, want exactly the returned error", rs)
			}
		})
	}
}
