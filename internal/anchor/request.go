package anchor

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"

	"github.com/digitorus/timestamp"
)

// errDigestLength reports a digest that is not a 32-byte SHA-256 value.
var errDigestLength = errors.New("anchor: digest must be a 32-byte SHA-256 value")

// BuildRequest returns a DER-encoded RFC 3161 TimeStampReq for a SHA-256 digest:
// version 1, messageImprint {sha256 (NULL parameters), digest}, nonce (omitted when nil)
// and certReq = true, so the TSA includes its signing certificate in the token. No policy
// and no extensions are requested: the 32-byte digest is the only information about the
// time-stamped data that leaves the machine.
func BuildRequest(digest []byte, nonce *big.Int) ([]byte, error) {
	if len(digest) != sha256.Size {
		return nil, fmt.Errorf("%w (got %d bytes)", errDigestLength, len(digest))
	}
	if nonce != nil && nonce.Sign() < 0 {
		return nil, errors.New("anchor: nonce must not be negative")
	}
	req := timestamp.Request{
		HashAlgorithm: crypto.SHA256,
		HashedMessage: digest,
		Nonce:         nonce,
		Certificates:  true,
	}
	der, err := req.Marshal()
	if err != nil {
		return nil, fmt.Errorf("anchor: encode time-stamp request: %w", err)
	}
	return der, nil
}

// newNonce returns a uniformly random, positive 64-bit nonce (the size `openssl ts -query`
// uses). A fresh nonce per request lets the client prove that the token answers this very
// request (RFC 3161 §2.4.1), not a replayed one.
func newNonce() (*big.Int, error) {
	var b [8]byte
	for {
		if _, err := rand.Read(b[:]); err != nil {
			return nil, fmt.Errorf("anchor: nonce: %w", err)
		}
		if n := new(big.Int).SetBytes(b[:]); n.Sign() > 0 {
			return n, nil
		}
	}
}
