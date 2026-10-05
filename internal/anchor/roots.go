package anchor

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	_ "embed"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"sync"
)

// freeTSARootPEM is FreeTSA's self-signed root CA certificate, downloaded on 2026-10-04 from
// https://freetsa.org/files/cacert.pem. It is not in the Windows root store, so without it a
// FreeTSA token could never be shown to chain to a trust anchor. FreeTSA embeds the very same
// certificate in its own tokens (see testdata/tsa/freetsa.tsr).
//
//	Subject:  O=Free TSA, OU=Root CA, CN=www.freetsa.org, emailAddress=busilezas@gmail.com,
//	          L=Wuerzburg, ST=Bayern, C=DE (self-signed, CA:TRUE, RSA 4096, sha512WithRSA)
//	Serial:   C1E986160DA8E980
//	Validity: 2016-03-13T01:52:13Z .. 2041-03-07T01:52:13Z
//	SHA-256 of the DER certificate (pinned below):
//	          a6379e7cecc05faa3cbf076013d745e327bbbaa38c0b9af22469d4701d18aabc
//
//go:embed roots/freetsa_cacert.pem
var freeTSARootPEM []byte

// freeTSARootSHA256 pins the embedded root: it is trusted only if its DER encoding hashes to
// this value, so replacing the PEM file without changing the source has no effect.
const freeTSARootSHA256 = "a6379e7cecc05faa3cbf076013d745e327bbbaa38c0b9af22469d4701d18aabc"

// embeddedRoots parses the embedded roots once. On failure (a corrupted build) the embedded
// roots are simply not trusted; chain checks then fall back to the other root sources.
var embeddedRoots = sync.OnceValues(func() (*x509.CertPool, error) {
	cert, err := parsePinnedRoot(freeTSARootPEM, freeTSARootSHA256)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return pool, nil
})

// parsePinnedRoot decodes exactly one PEM CERTIFICATE block, checks its SHA-256 fingerprint
// against want and requires a CA certificate.
func parsePinnedRoot(pemBytes []byte, want string) (*x509.Certificate, error) {
	block, rest := pem.Decode(pemBytes)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("anchor: embedded root: no PEM CERTIFICATE block")
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("anchor: embedded root: unexpected data after the certificate")
	}
	sum := sha256.Sum256(block.Bytes)
	if got := hex.EncodeToString(sum[:]); got != want {
		return nil, fmt.Errorf("anchor: embedded root: SHA-256 %s does not match the pinned %s", got, want)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("anchor: embedded root: %w", err)
	}
	if !cert.IsCA {
		return nil, errors.New("anchor: embedded root: not a CA certificate")
	}
	return cert, nil
}

// EmbeddedRootsPEM returns a copy of the PEM-encoded root certificates shipped with this
// package (currently FreeTSA's root CA). They are trusted in addition to the system roots when
// computing TokenInfo.ChainOK. Evidence bundles can include them so that third parties can
// check tokens independently, e.g. with `openssl ts -verify -CAfile`.
func EmbeddedRootsPEM() []byte { return bytes.Clone(freeTSARootPEM) }
