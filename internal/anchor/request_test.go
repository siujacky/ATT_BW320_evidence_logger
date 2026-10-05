package anchor

import (
	"bytes"
	"crypto"
	"encoding/hex"
	"errors"
	"math/big"
	"strings"
	"testing"

	"github.com/digitorus/timestamp"
)

func TestBuildRequestRoundTrip(t *testing.T) {
	digest := vectorDigest(t)
	huge, _ := new(big.Int).SetString("ffffffffffffffffffffffffffffffffffffffff", 16) // 160 bits
	tests := []struct {
		name  string
		nonce *big.Int
	}{
		{"nil nonce", nil},
		{"zero", big.NewInt(0)},
		{"small", big.NewInt(1)},
		{"vector nonce", new(big.Int).SetUint64(0x1B7DD452A63DB4A8)},
		{"64-bit max", new(big.Int).SetUint64(^uint64(0))},
		{"160-bit", huge},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			der, err := BuildRequest(digest, tt.nonce)
			if err != nil {
				t.Fatal(err)
			}
			req, err := timestamp.ParseRequest(der)
			if err != nil {
				t.Fatalf("ParseRequest: %v", err)
			}
			if req.HashAlgorithm != crypto.SHA256 {
				t.Errorf("hash = %v, want SHA-256", req.HashAlgorithm)
			}
			if !bytes.Equal(req.HashedMessage, digest) {
				t.Errorf("imprint = %x, want %x", req.HashedMessage, digest)
			}
			if !req.Certificates {
				t.Error("certReq = false, want true")
			}
			switch {
			case tt.nonce == nil && req.Nonce != nil:
				t.Errorf("nonce = %v, want absent", req.Nonce)
			case tt.nonce != nil && (req.Nonce == nil || req.Nonce.Cmp(tt.nonce) != 0):
				t.Errorf("nonce = %v, want %v", req.Nonce, tt.nonce)
			}
			if req.TSAPolicyOID != nil || len(req.Extensions) != 0 {
				t.Errorf("unexpected policy %v / extensions %v", req.TSAPolicyOID, req.Extensions)
			}
		})
	}
}

// TestBuildRequestGolden pins the exact DER: the request is all that ever leaves the machine.
func TestBuildRequestGolden(t *testing.T) {
	der, err := BuildRequest(vectorDigest(t), new(big.Int).SetUint64(0x1B7DD452A63DB4A8))
	if err != nil {
		t.Fatal(err)
	}
	want := "3043" + // TimeStampReq SEQUENCE, 67 bytes
		"020101" + // version 1
		"3031" + "300d" + "0609608648016503040201" + "0500" + // messageImprint: sha256, NULL params
		"0420" + vectorDigestHex + // hashedMessage
		"02081b7dd452a63db4a8" + // nonce
		"0101ff" // certReq TRUE
	if got := hex.EncodeToString(der); got != want {
		t.Errorf("DER mismatch\n got %s\nwant %s", got, want)
	}
}

func TestBuildRequestErrors(t *testing.T) {
	tests := []struct {
		name    string
		digest  []byte
		nonce   *big.Int
		wantErr string
	}{
		{"nil digest", nil, big.NewInt(1), "32-byte"},
		{"31 bytes", make([]byte, 31), big.NewInt(1), "32-byte"},
		{"33 bytes", make([]byte, 33), big.NewInt(1), "32-byte"},
		{"sha512-sized", make([]byte, 64), big.NewInt(1), "32-byte"},
		{"negative nonce", make([]byte, 32), big.NewInt(-5), "negative"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			der, err := BuildRequest(tt.digest, tt.nonce)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("err = %v, want containing %q", err, tt.wantErr)
			}
			if der != nil {
				t.Error("DER returned together with an error")
			}
			if strings.Contains(tt.wantErr, "32-byte") && !errors.Is(err, errDigestLength) {
				t.Errorf("err %v is not errDigestLength", err)
			}
		})
	}
}

func TestNewNonce(t *testing.T) {
	seen := make(map[string]bool)
	for range 2000 {
		n, err := newNonce()
		if err != nil {
			t.Fatal(err)
		}
		if n.Sign() <= 0 || n.BitLen() > 64 {
			t.Fatalf("nonce %v out of range", n)
		}
		k := n.Text(16)
		if seen[k] {
			t.Fatalf("duplicate nonce %s", k)
		}
		seen[k] = true
	}
}
