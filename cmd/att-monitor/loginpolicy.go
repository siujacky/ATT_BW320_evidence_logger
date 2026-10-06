package main

import (
	"encoding/json"
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sync"

	"attmonitor/internal/gateway"
)

// The gateway client's login policy outlives the process (docs/DESIGN.md §2): when the latest login
// attempt began, the rejected logins of the last hour and a pause after "all web server sessions are
// in use" are kept in state\gateway-login.json, so that a service the service manager restarts -
// in a loop if need be - never gets a new allowance of login attempts with every start (at most 3
// rejected ones an hour, whatever restarts). Every process that may log in uses it: the service,
// the console mode and the CLI while the service is stopped (the ledger's writer lock keeps two of
// them from running at once). Not evidence: a cache of the policy, like the rest of state\.

// loginPolicyFile is the file in the data directory's state folder.
const loginPolicyFile = "gateway-login.json"

// loginPolicyVersion is the file's format.
const loginPolicyVersion = 1

// loginPolicyRecord is the file: the policy and the format's version.
type loginPolicyRecord struct {
	Version int `json:"version"`
	gateway.LoginPolicy
}

// loginPolicyStore saves the gateway client's login policy (gateway.Options.OnLoginPolicy).
type loginPolicyStore struct {
	path string
	log  *slog.Logger

	mu     sync.Mutex
	failed bool // the latest save failed (logged once until a save works again)
}

// openLoginPolicy returns the store of the login policy in stateDir and the policy saved there (the
// zero policy when there is none, or when the file cannot be read: logged, and the gateway client
// then starts with a fresh allowance - which the next save replaces).
func openLoginPolicy(stateDir string, lg *slog.Logger) (*loginPolicyStore, gateway.LoginPolicy) {
	s := &loginPolicyStore{path: filepath.Join(stateDir, loginPolicyFile), log: lg}
	b, err := os.ReadFile(s.path)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			lg.Warn("the gateway login policy saved by the previous run cannot be read; it starts afresh", "file", s.path, "err", err)
		}
		return s, gateway.LoginPolicy{}
	}
	var rec loginPolicyRecord
	if err := json.Unmarshal(b, &rec); err != nil || rec.Version != loginPolicyVersion {
		lg.Warn("the gateway login policy saved by the previous run is not usable; it starts afresh", "file", s.path, "err", err,
			"version", rec.Version)
		return s, gateway.LoginPolicy{}
	}
	return s, rec.LoginPolicy
}

// save writes the policy (the gateway client serializes the calls).
func (s *loginPolicyStore) save(p gateway.LoginPolicy) {
	b, err := json.Marshal(loginPolicyRecord{Version: loginPolicyVersion, LoginPolicy: p})
	if err == nil {
		err = writeFileSynced(s.path, b)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case err != nil && !s.failed:
		s.failed = true
		s.log.Warn("cannot save the gateway login policy; a restart would forget the latest login attempts", "file", s.path, "err", err)
	case err == nil && s.failed:
		s.failed = false
		s.log.Info("the gateway login policy is saved again", "file", s.path)
	}
}

// writeFileSynced replaces path with data: written to a temporary file in the same folder, synced,
// then renamed over path, so that a crash leaves either the old file or the new one.
func writeFileSynced(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, path)
	}
	if err != nil {
		_ = os.Remove(tmp)
	}
	return err
}
