//go:build windows

package ledger

import "attmonitor/internal/secret"

// keyEntropy binds the DPAPI blob of the signing seed to this purpose (docs/DESIGN.md §6).
var keyEntropy = []byte("att-monitor ledger key v1")

// defaultKeyProtect encrypts the signing seed with machine-scope DPAPI.
func defaultKeyProtect(seed []byte) ([]byte, error) {
	return secret.Protect(seed, keyEntropy, true)
}

// defaultKeyUnprotect decrypts a blob produced by defaultKeyProtect.
func defaultKeyUnprotect(blob []byte) ([]byte, error) {
	return secret.Unprotect(blob, keyEntropy)
}
