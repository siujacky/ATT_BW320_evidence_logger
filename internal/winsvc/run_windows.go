//go:build windows

package winsvc

import (
	"context"
	"errors"
	"fmt"
	"runtime/debug"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
)

// Context causes used by Run when the SCM stops the service. Their texts are the
// model.MonitorStop reasons, so a run function can record context.Cause(ctx).Error().
var (
	ErrServiceStop    = errors.New("service stop")
	ErrSystemShutdown = errors.New("system shutdown")
)

// Service-specific exit codes reported to the SCM. Any non-zero code makes the SCM apply the
// recovery actions (restart), because Install enables them for non-crash failures. A stop
// requested through the SCM always ends with exit code 0.
const (
	ExitRunFailed   = 1 // run returned an error without being asked to stop
	ExitRunPanicked = 2 // run panicked (the panic and stack are returned by Run)
	ExitRunReturned = 3 // run returned nil without being asked to stop
)

// Power event kinds sent on the power channel.
const (
	PowerSuspend         = "suspend"             // PBT_APMSUSPEND: the system is going to sleep
	PowerResume          = "resume"              // PBT_APMRESUMESUSPEND: resumed by user activity
	PowerResumeAutomatic = "resume_automatic"    // PBT_APMRESUMEAUTOMATIC: resumed (always sent)
	PowerStatusChange    = "power_status_change" // PBT_APMPOWERSTATUSCHANGE: AC/battery change
	PowerShutdown        = "shutdown"            // SERVICE_CONTROL_SHUTDOWN: the system is shutting down
	// Other PBT_* values are sent as "power_event_<decimal value>".
)

// PBT_* event types of SERVICE_CONTROL_POWEREVENT (winuser.h).
const (
	pbtAPMSuspend           = 0x4
	pbtAPMResumeSuspend     = 0x7
	pbtAPMPowerStatusChange = 0xA
	pbtAPMResumeAutomatic   = 0x12
)

const (
	// stopTimeout bounds how long Stop/Shutdown waits for run to return.
	stopTimeout = 25 * time.Second
	// powerQueueSize buffers power events so the control handler never blocks.
	powerQueueSize = 64
	// Stop-pending progress reporting: the checkpoint advances every checkpointEvery and each
	// report promises the next one within stopWaitHint.
	checkpointEvery = 2 * time.Second
	stopWaitHint    = 5 * time.Second
	startWaitHint   = 10 * time.Second
	// maxPendingControls bounds how many already-queued control requests are examined when
	// run exits on its own (see pendingStop).
	maxPendingControls = 4
)

var (
	// errRunExited is reported if run exits via runtime.Goexit instead of returning.
	errRunExited = errors.New("run exited without returning")
	// errRunReturned: run returned nil although nobody asked the service to stop. For an
	// always-on monitor that is a failure (it would otherwise leave an unexplained gap).
	errRunReturned = errors.New("winsvc: run returned without a stop request; the monitor must keep running until the service is stopped")
	// errNotExecuted: the dispatcher returned without ever calling the handler.
	errNotExecuted = errors.New("winsvc: the service control dispatcher returned without running the service")
	// errRunTwice: StartServiceCtrlDispatcher may be called only once per process, even if
	// the first call failed.
	errRunTwice = errors.New("winsvc: Run may only be called once per process")
)

// runCalled guards Run (see errRunTwice).
var runCalled atomic.Bool

// Run is the service entry point: it connects to the SCM (blocking until the service
// stops) and executes run(ctx, power) while the service is running.
//
//   - The service reports StartPending, starts run in a goroutine and reports Running,
//     accepting Stop, Shutdown and PowerEvent.
//   - Power events are sent on power ("suspend", "resume", "resume_automatic",
//     "power_status_change", "power_event_<n>"); a Shutdown control first sends "shutdown".
//     The channel is buffered and never closed: if the consumer falls 64 events behind,
//     further events are dropped rather than blocking the SCM. Consumers must stop
//     reading when ctx is done (a consumer that wants the final "shutdown" can drain the
//     channel without blocking at that point; context.Cause(ctx) says the same thing).
//   - Stop/Shutdown cancel ctx with cause ErrServiceStop / ErrSystemShutdown, report
//     StopPending (with advancing checkpoints) and wait up to 25 s for run to return; the
//     service then stops with exit code 0 so the SCM does not restart a deliberate stop.
//     This also holds when run happens to return at the moment the stop request arrives.
//   - If run returns without being asked to stop, the service stops with a service-specific
//     exit code and the SCM recovery actions restart it: ExitRunFailed for an error,
//     ExitRunPanicked for a panic, ExitRunReturned for a nil return (an evidence logger is
//     never supposed to stop on its own, so that is treated as a failure too).
//
// Run returns after the service has stopped: the error from run (with the panic stack if it
// panicked), an unrequested exit, a stop timeout, or a dispatcher error (for example when
// the process was not started by the SCM). Errors that occur while running as a service are
// also written to the Application event log under the ATTMonitor source (best effort),
// because a service has no console to print them on. Run may be called only once per
// process (a Windows restriction).
func Run(run func(ctx context.Context, power <-chan string) error) error {
	if run == nil {
		return errors.New("winsvc: Run: nil run function")
	}
	if !runCalled.CompareAndSwap(false, true) {
		return errRunTwice
	}
	h := newHandler(run)
	// For SERVICE_WIN32_OWN_PROCESS the name in the dispatch table is ignored by the SCM,
	// so this also works for a differently named (test) service using the same binary.
	if err := svc.Run(ServiceName, h); err != nil {
		switch {
		case errors.Is(err, windows.ERROR_FAILED_SERVICE_CONTROLLER_CONNECT):
			return fmt.Errorf("winsvc: this process was not started by the service control manager (use console mode): %w", err)
		case errors.Is(err, windows.ERROR_SERVICE_ALREADY_RUNNING):
			return fmt.Errorf("%w: the service control dispatcher was already started: %w", errRunTwice, err)
		}
		return fmt.Errorf("winsvc: service control dispatcher: %w", err)
	}
	return h.finish()
}

// reportServiceError writes err as an Error event (ID 3) under the ServiceName source, best
// effort. It is a variable so tests can capture reports instead of writing to the real log.
var reportServiceError = func(err error) { _ = reportErrorTo(ServiceName, err) }

// reportErrorTo writes err as an Error event (ID 3) under source.
func reportErrorTo(source string, err error) error {
	l, oerr := eventlog.Open(source)
	if oerr != nil {
		return oerr
	}
	defer l.Close()
	return l.Error(eventIDError, sanitizeEventText("att-monitor service: "+err.Error()))
}

// powerEventName maps a SERVICE_CONTROL_POWEREVENT event type to the string sent on the
// power channel.
func powerEventName(eventType uint32) string {
	switch eventType {
	case pbtAPMSuspend:
		return PowerSuspend
	case pbtAPMResumeSuspend:
		return PowerResume
	case pbtAPMResumeAutomatic:
		return PowerResumeAutomatic
	case pbtAPMPowerStatusChange:
		return PowerStatusChange
	}
	return "power_event_" + strconv.FormatUint(uint64(eventType), 10)
}

// stopCause maps a Stop or Shutdown control to the context cause.
func stopCause(c svc.Cmd) error {
	if c == svc.Shutdown {
		return ErrSystemShutdown
	}
	return ErrServiceStop
}

var _ svc.Handler = (*handler)(nil)

// handler implements svc.Handler around a run function.
type handler struct {
	run             func(ctx context.Context, power <-chan string) error
	stopTimeout     time.Duration
	checkpointEvery time.Duration

	executed atomic.Bool // Execute was called by the dispatcher

	mu  sync.Mutex
	err error // outcome for Run; written by Execute, read after the dispatcher returns
}

func newHandler(run func(ctx context.Context, power <-chan string) error) *handler {
	return &handler{run: run, stopTimeout: stopTimeout, checkpointEvery: checkpointEvery}
}

func (h *handler) setResult(err error) {
	h.mu.Lock()
	h.err = err
	h.mu.Unlock()
}

func (h *handler) result() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.err
}

// finish returns the outcome once the dispatcher has returned and reports a failure to the
// event log (a service has no console; the caller may not log it either).
func (h *handler) finish() error {
	err := h.result()
	if !h.executed.Load() {
		err = errNotExecuted
	}
	if err != nil {
		reportServiceError(err)
	}
	return err
}

// panicError carries a recovered panic from run.
type panicError struct {
	value any
	stack []byte
}

func (e *panicError) Error() string { return fmt.Sprintf("panic: %v\n\n%s", e.value, e.stack) }

// Execute implements svc.Handler. It never blocks on the power channel and keeps serving
// control requests while waiting for run to finish, so the SCM is never left hanging.
func (h *handler) Execute(_ []string, r <-chan svc.ChangeRequest, s chan<- svc.Status) (bool, uint32) {
	h.executed.Store(true)
	const accepts = svc.AcceptStop | svc.AcceptShutdown | svc.AcceptPowerEvent
	s <- svc.Status{State: svc.StartPending, WaitHint: uint32(startWaitHint / time.Millisecond)}

	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	power := make(chan string, powerQueueSize)
	done := make(chan error, 1)
	go func() {
		err := errRunExited // replaced unless run calls runtime.Goexit
		defer func() { done <- err }()
		err = h.safeRun(ctx, power)
	}()

	s <- svc.Status{State: svc.Running, Accepts: accepts}

	for {
		select {
		case err := <-done:
			// A Stop/Shutdown request may be arriving at this very moment (both channels
			// ready, select picked this one): honour it, so a requested stop never turns
			// into a failure exit code and an SCM restart.
			if c, ok := pendingStop(r, s); ok {
				cause := stopCause(c.Cmd)
				cancel(cause)
				return h.requestedStop(ctx, cause, err, "at the time of the")
			}
			return h.unrequestedExit(err)
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				s <- c.CurrentStatus
			case svc.PowerEvent:
				offer(power, powerEventName(c.EventType))
			case svc.Stop, svc.Shutdown:
				cause := stopCause(c.Cmd)
				if c.Cmd == svc.Shutdown {
					offer(power, PowerShutdown) // before cancel, so it is queued first
				}
				cancel(cause)
				return h.waitForRun(ctx, cause, done, r, s, power)
			default:
				// Not accepted, so the SCM does not send it; ignore defensively.
			}
		}
	}
}

// pendingStop takes control requests that are already waiting, without blocking: it answers
// Interrogate, drops power events (run has returned) and reports a Stop or Shutdown.
func pendingStop(r <-chan svc.ChangeRequest, s chan<- svc.Status) (svc.ChangeRequest, bool) {
	for i := 0; i < maxPendingControls; i++ {
		select {
		case c := <-r:
			switch c.Cmd {
			case svc.Stop, svc.Shutdown:
				return c, true
			case svc.Interrogate:
				s <- c.CurrentStatus
			}
		default:
			return svc.ChangeRequest{}, false
		}
	}
	return svc.ChangeRequest{}, false
}

// safeRun calls run, converting a panic into a *panicError (a service has no console, so an
// unrecovered panic would vanish; returned, it can be logged to the event log).
func (h *handler) safeRun(ctx context.Context, power <-chan string) (err error) {
	defer func() {
		if v := recover(); v != nil {
			err = &panicError{value: v, stack: debug.Stack()}
		}
	}()
	return h.run(ctx, power)
}

// unrequestedExit handles run returning while the service was supposed to keep running:
// whatever the reason, the SCM is asked to restart the service.
func (h *handler) unrequestedExit(err error) (bool, uint32) {
	var pe *panicError
	switch {
	case err == nil:
		h.setResult(errRunReturned)
		return true, ExitRunReturned
	case errors.As(err, &pe):
		h.setResult(fmt.Errorf("winsvc: run panicked: %w", err))
		return true, ExitRunPanicked
	}
	h.setResult(fmt.Errorf("winsvc: run stopped unexpectedly: %w", err))
	return true, ExitRunFailed
}

// requestedStop records run's outcome after a requested stop. The exit code is 0 even on
// error: the stop was requested, so the SCM must not restart the service. Returning the
// context error or its cause is the normal way to stop and is not reported.
func (h *handler) requestedStop(ctx context.Context, cause, err error, when string) (bool, uint32) {
	if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.Cause(ctx)) {
		h.setResult(fmt.Errorf("winsvc: run returned an error %s %s request: %w", when, cause, err))
	}
	return false, 0
}

// waitForRun reports StopPending with advancing checkpoints until run returns or the stop
// timeout expires, while still answering control requests.
func (h *handler) waitForRun(ctx context.Context, cause error, done <-chan error, r <-chan svc.ChangeRequest, s chan<- svc.Status, power chan string) (bool, uint32) {
	pending := svc.Status{State: svc.StopPending, CheckPoint: 1, WaitHint: uint32(stopWaitHint / time.Millisecond)}
	s <- pending
	timeout := time.NewTimer(h.stopTimeout)
	defer timeout.Stop()
	tick := time.NewTicker(h.checkpointEvery)
	defer tick.Stop()
	for {
		select {
		case err := <-done:
			return h.requestedStop(ctx, cause, err, "after the")
		case <-timeout.C:
			h.setResult(fmt.Errorf("winsvc: run did not return within %s after the %s request", h.stopTimeout, cause))
			return false, 0
		case <-tick.C:
			pending.CheckPoint++
			s <- pending
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				s <- c.CurrentStatus
			case svc.PowerEvent:
				offer(power, powerEventName(c.EventType))
			case svc.Shutdown:
				offer(power, PowerShutdown)
			}
		}
	}
}

// offer sends v without blocking; it reports whether v was queued.
func offer(ch chan<- string, v string) bool {
	select {
	case ch <- v:
		return true
	default:
		return false
	}
}
