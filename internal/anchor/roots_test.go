package anchor

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"strings"
	"testing"
	"time"
)

// TestEmbeddedFreeTSARoot pins the embedded FreeTSA root (downloaded from
// https://freetsa.org/files/cacert.pem): SHA-256 of the DER certificate
// a6379e7cecc05faa3cbf076013d745e327bbbaa38c0b9af22469d4701d18aabc.
func TestEmbeddedFreeTSARoot(t *testing.T) {
	const want = "a6379e7cecc05faa3cbf076013d745e327bbbaa38c0b9af22469d4701d18aabc"
	if freeTSARootSHA256 != want {
		t.Fatalf("pinned fingerprint %s, want %s", freeTSARootSHA256, want)
	}
	root, err := parsePinnedRoot(freeTSARootPEM, freeTSARootSHA256)
	if err != nil {
		t.Fatalf("embedded root: %v", err)
	}
	if sum := sha256.Sum256(root.Raw); hex.EncodeToString(sum[:]) != want {
		t.Errorf("fingerprint %x", sum)
	}
	if !root.IsCA || !bytes.Equal(root.RawIssuer, root.RawSubject) {
		t.Error("not a self-issued CA certificate")
	}
	if err := root.CheckSignatureFrom(root); err != nil {
		t.Errorf("self-signature: %v", err)
	}
	if !strings.Contains(root.Subject.String(), "O=Free TSA") || root.SerialNumber.Text(16) != "c1e986160da8e980" {
		t.Errorf("subject %q serial %x", root.Subject, root.SerialNumber)
	}
	if !root.NotBefore.Equal(time.Date(2016, 3, 13, 1, 52, 13, 0, time.UTC)) ||
		!root.NotAfter.Equal(time.Date(2041, 3, 7, 1, 52, 13, 0, time.UTC)) {
		t.Errorf("validity %v .. %v", root.NotBefore, root.NotAfter)
	}

	// FreeTSA ships the same root inside its tokens.
	certs := certsOf(t, readVector(t, "freetsa.tsr"))
	found := false
	for _, c := range certs {
		found = found || c.Equal(root)
	}
	if !found {
		t.Error("the embedded root is not the root carried in testdata/tsa/freetsa.tsr")
	}

	pool, err := embeddedRoots()
	if err != nil || pool == nil {
		t.Fatalf("embeddedRoots: %v", err)
	}
	if !pool.Equal(poolOf(root)) {
		t.Error("embedded pool does not hold exactly the FreeTSA root")
	}
}

func TestEmbeddedRootsPEM(t *testing.T) {
	a := EmbeddedRootsPEM()
	if !bytes.Equal(a, freeTSARootPEM) {
		t.Fatal("EmbeddedRootsPEM differs from the embedded file")
	}
	a[0] ^= 0xff
	if bytes.Equal(EmbeddedRootsPEM(), a) {
		t.Error("EmbeddedRootsPEM returned the package's own buffer")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(EmbeddedRootsPEM()) {
		t.Error("EmbeddedRootsPEM is not usable as a CA file")
	}
}

func TestParsePinnedRootErrors(t *testing.T) {
	leaf := certsOf(t, readVector(t, "freetsa.tsr"))[0] // FreeTSA's TSA certificate (not a CA)
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw})
	leafSum := sha256.Sum256(leaf.Raw)
	garbled := bytes.Clone(freeTSARootPEM)
	garbled[100] ^= 0x01 // one base64 character changed
	tests := []struct {
		name, pin, wantErr string
		pem                []byte
	}{
		{"wrong pin", strings.Repeat("0", 64), "does not match the pinned", freeTSARootPEM},
		{"modified file", freeTSARootSHA256, "", garbled},
		{"not PEM", freeTSARootSHA256, "no PEM CERTIFICATE block", []byte("hello")},
		{"wrong block type", freeTSARootSHA256, "no PEM CERTIFICATE block",
			pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1}})},
		{"two certificates", freeTSARootSHA256, "unexpected data", append(bytes.Clone(freeTSARootPEM), leafPEM...)},
		{"not a CA", hex.EncodeToString(leafSum[:]), "not a CA", leafPEM},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert, err := parsePinnedRoot(tt.pem, tt.pin)
			if err == nil || cert != nil {
				t.Fatalf("parsePinnedRoot accepted it: %v", cert)
			}
			if tt.wantErr != "" && !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("err = %v, want containing %q", err, tt.wantErr)
			}
		})
	}
}
