package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"attmonitor/internal/config"
	"attmonitor/internal/gateway"
	"attmonitor/internal/model"
	"attmonitor/internal/winsvc"
)

// fakeChecker answers Identify and Check from a script; it records the codes it was given.
type fakeChecker struct {
	name     string
	identify error
	results  []error // one per Check; nil when the script is exhausted
	on       bool
	codes    []string
}

func (f *fakeChecker) Identify(context.Context) (string, error) { return f.name, f.identify }

func (f *fakeChecker) Check(_ context.Context, code string) (bool, error) {
	f.codes = append(f.codes, code)
	if len(f.results) == 0 {
		return f.on, nil
	}
	err := f.results[0]
	f.results = f.results[1:]
	return f.on, err
}

// setupRig is a wizard wired to fakes.
type setupRig struct {
	w        *wizard
	out      *strings.Builder
	chk      *fakeChecker
	installs []installOptions
	elevated [][]string
	opened   []string
	slept    []time.Duration
}

func newSetupRig(t *testing.T, codes []string, answers string) *setupRig {
	t.Helper()
	r := &setupRig{out: &strings.Builder{}, chk: &fakeChecker{name: "NOKIA BGW320-505, firmware 6.34.7"}}
	now := time.Date(2026, 10, 5, 18, 0, 0, 0, time.UTC)
	r.w = &wizard{
		in:  bufio.NewReader(strings.NewReader(answers)),
		out: r.out,
		readCode: func() (string, error) {
			if len(codes) == 0 {
				return "", errors.New("no more input")
			}
			c := codes[0]
			codes = codes[1:]
			return c, nil
		},
		now:     func() time.Time { return now },
		sleep:   func(d time.Duration) { r.slept = append(r.slept, d); now = now.Add(d) },
		checker: func(host, pin string) codeChecker { return r.chk },
		install: func(o installOptions) error { r.installs = append(r.installs, o); return nil },
		state:   func() string { return winsvc.StatusNotInstalled },
		loadCfg: func(string) *config.Config { return nil },
		admin:   func() bool { return true },
		elevate: func(args []string) (int, error) { r.elevated = append(r.elevated, args); return 0, nil },
		status: func(string) (*model.Status, error) {
			return &model.Status{Monitor: model.MonitorInfo{Version: "1.1.0", Listen: "127.0.0.1:8320"},
				Ledger: model.LedgerStatus{Fingerprint: "6961b23fea2d3b8d795c5ebee895a23ef5754cb3403af32f31c1c7e58b9d577d"}}, nil
		},
		openURL: func(u string) error { r.opened = append(r.opened, u); return nil },
	}
	return r
}

// rejected is the gateway client's error for a rejected login (it wraps contracts.ErrGatewayAuth).
func rejected() error {
	return fmt.Errorf("%w: wrong code (1 of 3 allowed failures within an hour)", gateway.ErrAuth)
}

func (r *setupRig) run(t *testing.T, o setupOptions) error {
	t.Helper()
	if o.dataDir == "" {
		o.dataDir = `C:\ProgramData\ATTMonitor`
	}
	return r.w.run(context.Background(), o)
}

func wantText(t *testing.T, out string, wants ...string) {
	t.Helper()
	for _, w := range wants {
		if !strings.Contains(out, w) {
			t.Errorf("output lacks %q:\n%s", w, out)
		}
	}
}

// TestSetupFreshInstall: the one question is the code; the gateway accepts it and setup installs
// with it.
func TestSetupFreshInstall(t *testing.T) {
	r := newSetupRig(t, []string{"  4#9*1=7%2/ "}, "")
	r.chk.on = true
	if err := r.run(t, setupOptions{}); err != nil {
		t.Fatal(err)
	}
	if len(r.installs) != 1 || r.installs[0].Code != "4#9*1=7%2/" {
		t.Fatalf("installs %+v", r.installs)
	}
	if len(r.chk.codes) != 1 {
		t.Errorf("checked %d times", len(r.chk.codes))
	}
	wantText(t, r.out.String(), "found NOKIA BGW320-505, firmware 6.34.7.", "Device Access Code: ", "Checking the code with the gateway ... accepted.",
		"outage redirect (Broadband Status Notification) is ON: the monitor switches it off", "Installing ...",
		"Done: the AT&T Internet Monitor 1.1.0 is installed and running.", "Evidence key   6961 b23f ea2d 3b8d")
	if strings.Contains(r.out.String(), "4#9*1=7%2/") {
		t.Error("the code was printed")
	}
	if len(r.opened) != 0 {
		t.Error("a browser was opened from the administrator process")
	}
}

// TestSetupWrongCodeThenRight: a rejected code is asked again; the second check waits out the
// gateway client's one-login-per-minute spacing instead of failing.
func TestSetupWrongCodeThenRight(t *testing.T) {
	r := newSetupRig(t, []string{"wrong", "right"}, "")
	until := time.Date(2026, 10, 5, 18, 1, 0, 0, time.UTC)
	r.chk.results = []error{rejected(), &gateway.CooldownError{Err: gateway.ErrLoginThrottled, Until: until}, nil}
	if err := r.run(t, setupOptions{}); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(r.chk.codes, ","); got != "wrong,right,right" {
		t.Errorf("checked %s", got)
	}
	if len(r.slept) != 1 || r.slept[0] != 61*time.Second {
		t.Errorf("slept %v", r.slept)
	}
	if len(r.installs) != 1 || r.installs[0].Code != "right" {
		t.Fatalf("installs %+v", r.installs)
	}
	wantText(t, r.out.String(), "not accepted.", "Check the label on the gateway", "symbols such as # * = %.",
		"Waiting 61 s (the gateway allows one login attempt per minute)", "accepted.")
}

// TestSetupThreeRejections: after three rejections the code is not tried again (the gateway's
// login would lock); the user may install without it.
func TestSetupThreeRejections(t *testing.T) {
	r := newSetupRig(t, []string{"a", "b", "c", "d"}, "y\n")
	r.chk.results = []error{rejected(), rejected(), rejected()}
	if err := r.run(t, setupOptions{}); err != nil {
		t.Fatal(err)
	}
	if len(r.chk.codes) != 3 {
		t.Errorf("checked %d times: %v", len(r.chk.codes), r.chk.codes)
	}
	if len(r.installs) != 1 || r.installs[0].Code != "" {
		t.Fatalf("installs %+v", r.installs)
	}
	wantText(t, r.out.String(), "did not accept the code 3 times", "not tried\nagain for an hour", "Install without the code for now?")

	// Declining cancels setup without installing.
	r = newSetupRig(t, []string{"a", "b", "c"}, "n\n")
	r.chk.results = []error{rejected(), rejected(), &gateway.CooldownError{Err: gateway.ErrAuthLocked, Until: time.Now()}}
	if err := r.run(t, setupOptions{}); err == nil || len(r.installs) != 0 {
		t.Errorf("declined: err %v, installs %+v", err, r.installs)
	}
}

// TestSetupUpdateKeepsCode: on an installed monitor, Enter keeps the stored code: nothing is sent
// to the gateway's login and the update keeps it.
func TestSetupUpdateKeepsCode(t *testing.T) {
	r := newSetupRig(t, []string{""}, "")
	r.w.state = func() string { return "running" }
	r.w.loadCfg = func(string) *config.Config {
		c := config.Default()
		c.Gateway.AccessCodeProtected = "stored"
		c.Gateway.PinnedCertSHA256 = strings.Repeat("ab", 32)
		return c
	}
	var pin string
	r.w.checker = func(host, p string) codeChecker { pin = p; return r.chk }
	if err := r.run(t, setupOptions{}); err != nil {
		t.Fatal(err)
	}
	if len(r.chk.codes) != 0 {
		t.Errorf("logged in with %v", r.chk.codes)
	}
	if pin != strings.Repeat("ab", 32) {
		t.Errorf("the check did not use the service's certificate pin: %q", pin)
	}
	if len(r.installs) != 1 || r.installs[0].Code != "" {
		t.Fatalf("installs %+v", r.installs)
	}
	wantText(t, r.out.String(), "already installed (running). Setup updates it to version", "press Enter without typing to keep it",
		"Keeping the stored code.")
}

// TestSetupNoCode: Enter without a stored code asks whether to install without one.
func TestSetupNoCode(t *testing.T) {
	r := newSetupRig(t, []string{"", "abc"}, "n\n")
	if err := r.run(t, setupOptions{}); err != nil {
		t.Fatal(err)
	}
	if len(r.installs) != 1 || r.installs[0].Code != "abc" {
		t.Fatalf("installs %+v", r.installs)
	}
	r = newSetupRig(t, []string{""}, "y\n")
	if err := r.run(t, setupOptions{}); err != nil || len(r.installs) != 1 || r.installs[0].Code != "" {
		t.Fatalf("without code: %v %+v", err, r.installs)
	}
}

// TestSetupGatewayUnreachable: without an answer from the gateway the code is stored unchecked
// (after asking); no login is attempted.
func TestSetupGatewayUnreachable(t *testing.T) {
	r := newSetupRig(t, []string{"abc"}, "\n")
	r.chk.identify = errors.New("dial tcp 192.168.1.254:443: i/o timeout")
	if err := r.run(t, setupOptions{}); err != nil {
		t.Fatal(err)
	}
	if len(r.chk.codes) != 0 || len(r.installs) != 1 || r.installs[0].Code != "abc" {
		t.Fatalf("checks %v, installs %+v", r.chk.codes, r.installs)
	}
	wantText(t, r.out.String(), "no answer (dial tcp 192.168.1.254:443: i/o timeout)", "Install anyway?", "stored without a check")

	r = newSetupRig(t, nil, "n\n")
	r.chk.identify = errors.New("timeout")
	if err := r.run(t, setupOptions{}); err == nil || len(r.installs) != 0 {
		t.Errorf("declined: %v %+v", err, r.installs)
	}
}

// TestSetupUncheckable: a code the gateway cannot check now (sessions full) is stored.
func TestSetupUncheckable(t *testing.T) {
	r := newSetupRig(t, []string{"abc"}, "")
	r.chk.results = []error{&gateway.CooldownError{Err: gateway.ErrSessionsFull, Until: time.Now()}}
	if err := r.run(t, setupOptions{}); err != nil {
		t.Fatal(err)
	}
	if len(r.installs) != 1 || r.installs[0].Code != "abc" {
		t.Fatalf("installs %+v", r.installs)
	}
	wantText(t, r.out.String(), "not checked (all of the gateway's web sessions are in use)")
}

// TestSetupElevates: without administrator rights setup starts its administrator part and then
// opens the dashboard as the user; a declined UAC prompt or a failed administrator part ends it.
func TestSetupElevates(t *testing.T) {
	r := newSetupRig(t, nil, "")
	r.w.admin = func() bool { return false }
	if err := r.run(t, setupOptions{dataDir: `D:\Evidence`, dataFlag: `D:\Evidence`}); err != nil {
		t.Fatal(err)
	}
	if len(r.elevated) != 1 || strings.Join(r.elevated[0], " ") != `setup --elevated --data D:\Evidence` {
		t.Errorf("elevated %v", r.elevated)
	}
	if len(r.installs) != 0 || len(r.chk.codes) != 0 {
		t.Error("the user's process did the administrator part")
	}
	if len(r.opened) != 1 || r.opened[0] != "http://127.0.0.1:8320/" {
		t.Errorf("opened %v", r.opened)
	}
	wantText(t, r.out.String(), "Windows will now ask for permission", "Evidence key   6961 b23f", "Opening the dashboard")

	r = newSetupRig(t, nil, "")
	r.w.admin = func() bool { return false }
	r.w.elevate = func([]string) (int, error) { return 0, errElevationCancelled }
	var ec exitCode
	if err := r.run(t, setupOptions{}); !errors.As(err, &ec) || ec != 1 || len(r.opened) != 0 {
		t.Errorf("cancelled: %v, opened %v", err, r.opened)
	}
	wantText(t, r.out.String(), "Run it again and choose Yes")

	r = newSetupRig(t, nil, "")
	r.w.admin = func() bool { return false }
	r.w.elevate = func([]string) (int, error) { return 1, nil }
	if err := r.run(t, setupOptions{}); !errors.As(err, &ec) || len(r.opened) != 0 {
		t.Errorf("failed child: %v, opened %v", err, r.opened)
	}
}

// TestSetupElevatedChild: the administrator part says it is complete and leaves the summary to
// the window that started it.
func TestSetupElevatedChild(t *testing.T) {
	r := newSetupRig(t, []string{"abc"}, "")
	if err := r.run(t, setupOptions{elevatedChild: true}); err != nil {
		t.Fatal(err)
	}
	out := r.out.String()
	wantText(t, out, "setup (administrator)", "Setup is complete.")
	if strings.Contains(out, "Done: the AT&T Internet Monitor") || strings.Contains(out, "This installs a Windows service") {
		t.Errorf("the administrator window repeated the banner or the summary:\n%s", out)
	}
}

func TestAskYesNo(t *testing.T) {
	for in, want := range map[string]bool{"y\n": true, "YES\r\n": true, "n\n": false, "\n": true, "maybe\nno\n": false, "": true} {
		if got := askYesNo(bufio.NewReader(strings.NewReader(in)), &strings.Builder{}, "q?", true); got != want {
			t.Errorf("%q: %v", in, got)
		}
	}
}
