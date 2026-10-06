package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"attmonitor/internal/config"
	"attmonitor/internal/gateway"
)

// TestLoginPolicyStore: the gateway client's login policy saved is the one read back; a file that is
// not there, not JSON or of another format gives the zero policy.
func TestLoginPolicyStore(t *testing.T) {
	dir := t.TempDir()
	lg := slog.New(slog.DiscardHandler)
	store, p := openLoginPolicy(dir, lg)
	if !p.LastAttempt.IsZero() || p.Failures != nil || !p.FullUntil.IsZero() {
		t.Fatalf("policy without a file: %+v", p)
	}
	at := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	want := gateway.LoginPolicy{LastAttempt: at, Failures: []time.Time{at.Add(-time.Minute), at}, FullUntil: at.Add(5 * time.Minute)}
	store.save(want)
	_, got := openLoginPolicy(dir, lg)
	if !got.LastAttempt.Equal(want.LastAttempt) || len(got.Failures) != 2 || !got.Failures[1].Equal(at) || !got.FullUntil.Equal(want.FullUntil) {
		t.Fatalf("read back %+v, want %+v", got, want)
	}
	for _, body := range []string{"not json", `{"version":2,"last_attempt":"2026-10-06T12:00:00Z"}`} {
		if err := os.WriteFile(filepath.Join(dir, loginPolicyFile), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, p := openLoginPolicy(dir, lg); !p.LastAttempt.IsZero() {
			t.Errorf("%s: policy %+v", body, p)
		}
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Errorf("the state folder holds %d files (temporary files left?)", len(entries))
	}
}

// TestOpenStackRestoresTheLoginPolicy: a service that starts again after three rejected logins within
// the hour - the service manager restarting it in a loop - makes no login attempt: the gateway client
// it builds is locked by the policy saved before, and refuses without a request.
func TestOpenStackRestoresTheLoginPolicy(t *testing.T) {
	// The gateway of this test is this computer, over plain HTTP: should a request be made after
	// all, it never reaches a real gateway.
	dir := newDataDir(t, `"gateway":{"host":"127.0.0.1","scheme":"http"}`)
	now := time.Now()
	lg := slog.New(slog.DiscardHandler)
	store, _ := openLoginPolicy(config.PathsFor(dir).State, lg)
	store.save(gateway.LoginPolicy{LastAttempt: now.Add(-time.Minute),
		Failures: []time.Time{now.Add(-3 * time.Minute), now.Add(-2 * time.Minute), now.Add(-time.Minute)}})

	s, err := openStack(stackOptions{dataDir: dir, mode: "console"})
	if err != nil {
		t.Fatal(err)
	}
	defer s.close()
	before := s.gw.LoginAttempts()
	_, _, err = s.gw.NATTable(context.Background())
	if !errors.Is(err, gateway.ErrAuthLocked) {
		t.Fatalf("NAT read after the restart: err = %v, want the logins locked", err)
	}
	if s.gw.LoginAttempts() != before {
		t.Error("a login form was posted")
	}
}
