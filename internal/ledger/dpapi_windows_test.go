//go:build windows

package ledger

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"attmonitor/internal/model"
	"attmonitor/internal/secret"
)

// TestDefaultDPAPIKeyProtection exercises the real machine-scope DPAPI path.
func TestDefaultDPAPIKeyProtection(t *testing.T) {
	dir := t.TempDir()
	clk := newClock(t0)
	opts := testOptions(dir, clk)
	opts.KeyProtect, opts.KeyUnprotect = nil, nil // defaults: internal/secret, machine scope
	s := openStore(t, opts)
	pub := s.PublicKey()
	appendSamples(t, s, clk, 2, time.Second)
	s.Close()

	kb, err := os.ReadFile(filepath.Join(dir, "keys", "ledger-signing.key"))
	if err != nil {
		t.Fatal(err)
	}
	var kf keyFile
	if err := json.Unmarshal(kb, &kf); err != nil {
		t.Fatal(err)
	}
	blob, err := base64.StdEncoding.DecodeString(kf.Protected)
	if err != nil || len(blob) <= ed25519.SeedSize {
		t.Fatalf("protected blob of %d bytes: %v", len(blob), err)
	}
	seed, err := secret.Unprotect(blob, []byte("att-monitor ledger key v1"))
	if err != nil {
		t.Fatalf("DPAPI unprotect with the documented entropy: %v", err)
	}
	if len(seed) != ed25519.SeedSize || !bytes.Equal(ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey), pub) {
		t.Fatal("decrypted seed does not derive the ledger public key")
	}
	if bytes.Contains(kb, []byte(base64.StdEncoding.EncodeToString(seed))) {
		t.Fatal("seed stored in clear text")
	}
	if _, err := secret.Unprotect(blob, []byte("wrong entropy")); err == nil {
		t.Fatal("blob opened with the wrong entropy")
	}

	// Reopen through DPAPI and keep writing.
	s2 := openStore(t, opts)
	if s2.Created() || s2.Fingerprint() != Fingerprint(pub) {
		t.Fatal("reopen with DPAPI failed")
	}
	mustAppend(t, s2, model.TypeOperatorNote, model.OperatorNote{Text: "dpapi", Source: "cli"})
	rep, err := s2.Verify(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	requireOK(t, rep)
}
