package ledger

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	keyFileName = "ledger-signing.key"
	pubFileName = "ledger-signing.pub.txt"
	keyAlg      = "ed25519"
)

// keyFile is the on-disk form of the signing key (docs/DESIGN.md §5). The seed is never
// stored in clear text: "protected" holds the DPAPI blob (machine scope) of the 32-byte seed.
type keyFile struct {
	Alg       string `json:"alg"`
	Protected string `json:"protected"`
	Public    string `json:"public"`
	Created   string `json:"created"`
}

// Fingerprint returns the lowercase hex SHA-256 of the 32 raw public key bytes.
func Fingerprint(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:])
}

// FormatFingerprint renders a hex fingerprint for humans as 16 groups of 4 characters.
// Input that is not 64 hex characters is returned unchanged.
func FormatFingerprint(fp string) string {
	fp = normalizeFingerprint(fp)
	if len(fp) != 64 {
		return fp
	}
	var b strings.Builder
	for i := 0; i < 64; i += 4 {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(fp[i : i+4])
	}
	return b.String()
}

// normalizeFingerprint lowercases fp and removes separators (spaces, colons, dashes).
func normalizeFingerprint(fp string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(fp) {
		if (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') {
			b.WriteRune(r)
		} else if r != ' ' && r != ':' && r != '-' && r != '\t' {
			return strings.ToLower(fp) // not a fingerprint; let the comparison fail visibly
		}
	}
	return b.String()
}

func keyPath(dir string) string    { return filepath.Join(dir, keyFileName) }
func pubTxtPath(dir string) string { return filepath.Join(dir, pubFileName) }

// generateKey creates a new Ed25519 key from crypto/rand and writes the key file. It never
// overwrites an existing key file.
func generateKey(dir string, now time.Time, protect func([]byte) ([]byte, error)) (ed25519.PrivateKey, keyFile, error) {
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return nil, keyFile{}, fmt.Errorf("ledger: random seed: %w", err)
	}
	defer clear(seed)
	priv := ed25519.NewKeyFromSeed(seed)
	blob, err := protect(seed)
	if err != nil {
		return nil, keyFile{}, fmt.Errorf("ledger: protect signing key: %w", err)
	}
	if len(blob) == 0 {
		return nil, keyFile{}, errors.New("ledger: protect signing key: empty result")
	}
	kf := keyFile{
		Alg:       keyAlg,
		Protected: base64.StdEncoding.EncodeToString(blob),
		Public:    base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey)),
		Created:   now.UTC().Format(time.RFC3339Nano),
	}
	b, err := json.MarshalIndent(&kf, "", "  ")
	if err != nil {
		return nil, keyFile{}, err
	}
	if err := writeFileAtomic(keyPath(dir), append(b, '\n'), 0o600, false); err != nil {
		return nil, keyFile{}, fmt.Errorf("ledger: write signing key: %w", err)
	}
	return priv, kf, nil
}

// readKeyFile reads and syntax-checks the key file without decrypting it.
func readKeyFile(dir string) (keyFile, ed25519.PublicKey, error) {
	var kf keyFile
	b, err := os.ReadFile(keyPath(dir))
	if err != nil {
		return kf, nil, err
	}
	if err := json.Unmarshal(b, &kf); err != nil {
		return kf, nil, fmt.Errorf("ledger: key file %s: %w", keyPath(dir), err)
	}
	if kf.Alg != keyAlg {
		return kf, nil, fmt.Errorf("ledger: key file %s: unsupported alg %q", keyPath(dir), kf.Alg)
	}
	pub, err := base64.StdEncoding.DecodeString(kf.Public)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return kf, nil, fmt.Errorf("ledger: key file %s: invalid public key", keyPath(dir))
	}
	return kf, ed25519.PublicKey(pub), nil
}

// loadKey reads, decrypts and cross-checks the signing key.
func loadKey(dir string, unprotect func([]byte) ([]byte, error)) (ed25519.PrivateKey, keyFile, error) {
	kf, pub, err := readKeyFile(dir)
	if err != nil {
		return nil, kf, err
	}
	blob, err := base64.StdEncoding.DecodeString(kf.Protected)
	if err != nil || len(blob) == 0 {
		return nil, kf, fmt.Errorf("ledger: key file %s: invalid protected seed", keyPath(dir))
	}
	seed, err := unprotect(blob)
	if err != nil {
		return nil, kf, fmt.Errorf("ledger: unprotect signing key %s (DPAPI blobs only open on the machine that created them): %w", keyPath(dir), err)
	}
	defer clear(seed)
	if len(seed) != ed25519.SeedSize {
		return nil, kf, fmt.Errorf("ledger: key file %s: seed has %d bytes", keyPath(dir), len(seed))
	}
	priv := ed25519.NewKeyFromSeed(seed)
	if !bytes.Equal(priv.Public().(ed25519.PublicKey), pub) {
		return nil, kf, fmt.Errorf("ledger: key file %s: public key does not match the protected seed", keyPath(dir))
	}
	return priv, kf, nil
}

// publicKeyText is the human-readable public key file.
func publicKeyText(pub ed25519.PublicKey, created string) string {
	fp := Fingerprint(pub)
	return fmt.Sprintf(`att-monitor evidence ledger - signing public key (Ed25519)

public key (base64): %s
fingerprint (SHA-256 of the 32-byte public key):
  %s
fingerprint (hex): %s
key created: %s

Every ledger record is signed with the matching private key, which never leaves this
computer (it is protected with Windows DPAPI, machine scope). Compare this fingerprint with
the one in an evidence bundle's README.txt and keys/public-key.txt.
`, base64.StdEncoding.EncodeToString(pub), FormatFingerprint(fp), fp, created)
}

// writePublicKeyText (re)writes keys/ledger-signing.pub.txt when missing or different.
func writePublicKeyText(dir string, pub ed25519.PublicKey, created string) error {
	want := []byte(publicKeyText(pub, created))
	if have, err := os.ReadFile(pubTxtPath(dir)); err == nil && bytes.Equal(have, want) {
		return nil
	}
	return writeFileAtomic(pubTxtPath(dir), want, 0o644, true)
}

// writeFileAtomic writes data to a temporary file, fsyncs it and renames it into place; the
// rename is durable before it returns (write-through). With replace=false an existing
// destination is never overwritten.
func writeFileAtomic(path string, data []byte, perm os.FileMode, replace bool) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*"+tmpExt)
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	ok := false
	defer func() {
		if !ok {
			tmp.Close()
			os.Remove(tmpName)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	_ = os.Chmod(tmpName, perm)
	if replace {
		err = renameDurable(tmpName, path)
	} else {
		err = renameNoReplace(tmpName, path)
	}
	if err != nil {
		return err
	}
	ok = true
	return nil
}
