package export

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"attmonitor/internal/model"
)

// findPython returns a command prefix for a working Python >= 3.9, or skips the test. The
// Windows Store "python3" alias exists on PATH but only prints an install hint, so every
// candidate is actually executed.
func findPython(t *testing.T) []string {
	t.Helper()
	for _, c := range [][]string{{"python"}, {"py", "-3"}, {"python3"}} {
		p, err := exec.LookPath(c[0])
		if err != nil {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		err = exec.CommandContext(ctx, p, append(c[1:], "-c", "import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)")...).Run()
		cancel()
		if err == nil {
			return append([]string{p}, c[1:]...)
		}
	}
	t.Skip("Python >= 3.9 is not available")
	return nil
}

// shippedScript extracts tools/verify_bundle.py from a bundle (the copy a recipient runs).
func shippedScript(t *testing.T, bundle string) string {
	t.Helper()
	z := readZip(t, bundle)
	data, ok := z.files["tools/verify_bundle.py"]
	if !ok {
		t.Fatal("bundle has no tools/verify_bundle.py")
	}
	path := filepath.Join(t.TempDir(), "verify_bundle.py")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func runPython(t *testing.T, py []string, args ...string) (string, int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, py[0], append(append([]string{}, py[1:]...), args...)...)
	cmd.Env = append(os.Environ(), "PYTHONIOENCODING=utf-8", "PYTHONDONTWRITEBYTECODE=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			t.Fatalf("run python: %v\n%s", err, out)
		}
		return string(out), ee.ExitCode()
	}
	return string(out), 0
}

// pyLine renders a summary line the way verify_bundle.py prints it ("%-17s %s").
func pyLine(label, value string) string { return fmt.Sprintf("%-17s %s", label, value) }

func hasCryptography(t *testing.T, py []string) bool {
	_, code := runPython(t, py, "-c", "import cryptography.hazmat.primitives.asymmetric.ed25519")
	return code == 0
}

func extractZip(t *testing.T, path string) string {
	t.Helper()
	dir := t.TempDir()
	zr, err := zip.OpenReader(path)
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()
	z := readZip(t, path)
	for _, n := range z.names {
		dst := filepath.Join(dir, filepath.FromSlash(n))
		os.MkdirAll(filepath.Dir(dst), 0o755)
		if err := os.WriteFile(dst, z.files[n], 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestPythonVerifier(t *testing.T) {
	py := findPython(t)
	s, info := buildIncidentBundle(t)
	script := shippedScript(t, info.Path)
	crypto := hasCryptography(t, py)

	t.Run("good bundle", func(t *testing.T) {
		out, code := runPython(t, py, script, info.Path)
		if code != 0 || !strings.Contains(out, "RESULT: PASS") {
			t.Fatalf("exit %d:\n%s", code, out)
		}
		for _, want := range []string{pyLine("Manifest", "OK"), pyLine("Envelope hashes", "OK"), pyLine("Hash chain", "OK"),
			pyLine("Blobs", ""), groupFingerprint(s.f.fingerprint()), "token imprints OK 3", "are not part of this bundle"} {
			if !strings.Contains(out, want) {
				t.Errorf("output lacks %q:\n%s", want, out)
			}
		}
		if crypto && !strings.Contains(out, pyLine("Signatures", "OK")) {
			t.Errorf("signatures not reported as checked:\n%s", out)
		}
		if !crypto && !strings.Contains(out, "NOT CHECKED") {
			t.Errorf("missing signature warning:\n%s", out)
		}
	})

	t.Run("good bundle, pure-Python Ed25519", func(t *testing.T) {
		out, code := runPython(t, py, script, "--pure-python-ed25519", "--openssl-limit", "0", info.Path)
		if code != 0 || !strings.Contains(out, "built-in pure-Python RFC 8032") || !strings.Contains(out, "RESULT: PASS") {
			t.Fatalf("exit %d:\n%s", code, out)
		}
	})

	t.Run("extracted folder", func(t *testing.T) {
		out, code := runPython(t, py, script, "--openssl-limit", "0", extractZip(t, info.Path))
		if code != 0 {
			t.Fatalf("exit %d:\n%s", code, out)
		}
	})

	day3 := "ledger/ledger-2026-10-03.jsonl"
	var victim string
	for id := range blobRefsOf(t, s.f, "ledger-2026-10-03") {
		victim = id
		break
	}
	// A genuine-looking token over a different digest, swapped into the first anchor of day 3.
	otherToken := s.f.tsa.stamp(t, bytes.Repeat([]byte{7}, 32), s.opened)
	otherID := sha256Hex(otherToken)
	retoken := func(seg []byte) []byte {
		lines := bytes.Split(bytes.TrimSuffix(seg, []byte("\n")), []byte("\n"))
		for i, line := range lines {
			_, body, err := parseLine(line)
			if err == nil && body.Type == model.TypeAnchor {
				return replaceRecord(t, seg, i, func(b *model.Body) {
					var a model.Anchor
					json.Unmarshal(b.Data, &a)
					a.TokenSHA256 = otherID
					b.Data, _ = json.Marshal(a)
					b.Blobs = []string{otherID}
				})
			}
		}
		t.Fatal("no anchor in segment")
		return nil
	}
	tampered := []struct {
		name string
		edit zipEdit
		args []string
		want string
	}{
		{"ledger edited, manifest not updated", zipEdit{edit: func(n string, d []byte) ([]byte, bool) {
			if n == day3 {
				return []byte(strings.Replace(string(d), "TestNet", "EvilNet", 1)), true
			}
			return d, true
		}}, nil, "SHA-256 mismatch for " + day3},
		{"record re-hashed, manifest updated", zipEdit{fixManifest: true, edit: func(n string, d []byte) ([]byte, bool) {
			if n == day3 {
				return replaceRecord(t, d, 5, func(b *model.Body) { b.Type = model.TypeHeartbeat }), true
			}
			return d, true
		}}, nil, "prev does not equal h of seq"},
		{"last record re-hashed (only the signature can tell)", zipEdit{fixManifest: true, edit: func(n string, d []byte) ([]byte, bool) {
			if n == day3 {
				return replaceRecord(t, d, -1, func(b *model.Body) { b.TS = "2026-10-03T13:00:00Z" }), true
			}
			return d, true
		}}, []string{"--pure-python-ed25519"}, "Ed25519 signature does not verify"},
		{"record deleted, manifest updated", zipEdit{fixManifest: true, edit: func(n string, d []byte) ([]byte, bool) {
			if n == day3 {
				lines := strings.SplitAfter(string(d), "\n")
				return []byte(strings.Join(append(lines[:9:9], lines[10:]...), "")), true
			}
			return d, true
		}}, nil, "seq gap"},
		{"blob altered, manifest updated", zipEdit{fixManifest: true, edit: func(n string, d []byte) ([]byte, bool) {
			if n == "blobs/"+victim {
				return append([]byte("x"), d...), true
			}
			return d, true
		}}, nil, "does not match its name"},
		{"blob removed, manifest updated", zipEdit{fixManifest: true, edit: func(n string, d []byte) ([]byte, bool) {
			return d, n != "blobs/"+victim
		}}, nil, "is missing"},
		{"anchor token for another digest", zipEdit{fixManifest: true, extra: []zipEntry{{"blobs/" + otherID, otherToken}},
			edit: func(n string, d []byte) ([]byte, bool) {
				if n == day3 {
					return retoken(d), true
				}
				return d, true
			}}, nil, "token message imprint"},
		{"unlisted file added", zipEdit{extra: []zipEntry{{"blobs/extra.txt", []byte("x")}}}, nil, "not listed in MANIFEST.sha256"},
		{"duplicate entry", zipEdit{extra: []zipEntry{{"REPORT.html", []byte("fake")}}}, nil, "more than one entry"},
		{"public key replaced", zipEdit{fixManifest: true, edit: func(n string, d []byte) ([]byte, bool) {
			if n == "keys/public-key.txt" {
				return []byte("Public key (base64): " + strings.Repeat("A", 43) + "=\n"), true
			}
			return d, true
		}}, nil, "keys/public-key.txt does not match"},
	}
	for _, tc := range tampered {
		t.Run(tc.name, func(t *testing.T) {
			path := rewriteZip(t, info.Path, tc.edit)
			args := append(append([]string{script}, tc.args...), "--openssl-limit", "0", path)
			out, code := runPython(t, py, args...)
			if code != 1 || !strings.Contains(out, "RESULT: FAIL") || !strings.Contains(out, tc.want) {
				t.Errorf("exit %d, want 1 with %q:\n%s", code, tc.want, out)
			}
		})
	}

	t.Run("usage errors", func(t *testing.T) {
		if _, code := runPython(t, py, script); code != 2 {
			t.Errorf("no argument: exit %d", code)
		}
		if _, code := runPython(t, py, script, filepath.Join(t.TempDir(), "absent.zip")); code != 2 {
			t.Errorf("missing file: exit %d", code)
		}
	})
}

// TestPythonInspectRealTokens checks the verifier's DER reader against real DigiCert and
// FreeTSA responses (testdata/tsa, digest = SHA-256 of manifest.txt).
func TestPythonInspectRealTokens(t *testing.T) {
	py := findPython(t)
	script := filepath.Join(t.TempDir(), "verify_bundle.py")
	if err := os.WriteFile(script, verifyScript, 0o644); err != nil {
		t.Fatal(err)
	}
	const digest = "0bb4c71bfeddf27eb9647853d1e5aa8f981f222fe4ffac0c7d1d8db73f1d443b"
	for _, name := range []string{"digicert.tsr", "freetsa.tsr"} {
		path := filepath.Join("..", "..", "testdata", "tsa", name)
		if _, err := os.Stat(path); err != nil {
			t.Skipf("%s not available: %v", path, err)
		}
		out, code := runPython(t, py, script, "--inspect-token", path)
		if code != 0 || !strings.Contains(out, `"imprint": "`+digest+`"`) || !strings.Contains(out, `"gen_time": "2026-10-05T03:19:57Z"`) ||
			!strings.Contains(out, `"hash_algorithm": "2.16.840.1.101.3.4.2.1"`) {
			t.Errorf("%s: exit %d\n%s", name, code, out)
		}
	}
	bad := filepath.Join(t.TempDir(), "bad.tsr")
	os.WriteFile(bad, []byte{0x30, 0x05, 0x30, 0x03, 0x02, 0x01, 0x02}, 0o644) // PKIStatusInfo status 2 = rejection
	if out, code := runPython(t, py, script, "--inspect-token", bad); code == 0 || !strings.Contains(out, "did not grant the request (status 2)") {
		t.Errorf("rejected token: exit %d\n%s", code, out)
	}
}
