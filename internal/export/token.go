package export

import (
	"bytes"
	"crypto"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/digitorus/timestamp"

	"attmonitor/internal/contracts"
)

// tokenResult is what the bundle check learned from one RFC 3161 time-stamp token.
type tokenResult struct {
	problem string    // integrity failure: unreadable, bad signature, wrong digest or algorithm
	warn    string    // not a failure, but the token cannot vouch for anything here
	genTime time.Time // the token's own genTime (zero if unreadable)
	signed  bool      // the CMS signature verified with the TSA certificate embedded in the token

	// Options.TokenVerifier result (verifierRan is false without a verifier).
	verifierRan bool
	verifierErr string
	info        contracts.TokenInfo
}

// checkToken checks a DER TimeStampResp (or a bare TimeStampToken) as stored in an anchor's
// blob: it must be a granted SHA-256 time-stamp whose message imprint is the 32 bytes of
// headHash (docs/DESIGN.md §11) and whose CMS signature verifies with the embedded TSA
// certificate.
func checkToken(der []byte, headHash string) tokenResult {
	ts, err := timestamp.ParseResponse(der)
	if err != nil {
		bare, berr := timestamp.Parse(der)
		if berr != nil {
			return tokenResult{problem: "the token cannot be read or its signature does not verify: " + err.Error()}
		}
		ts = bare
	}
	res := tokenResult{genTime: ts.Time.UTC(), signed: ts.AddTSACertificate}
	want, herr := hex.DecodeString(headHash)
	switch {
	case ts.HashAlgorithm != crypto.SHA256:
		res.problem = fmt.Sprintf("the token's hash algorithm is %v, not SHA-256", ts.HashAlgorithm)
	case herr != nil || !bytes.Equal(ts.HashedMessage, want):
		res.problem = fmt.Sprintf("the token's message imprint %s does not equal the anchored head hash %s",
			short(hex.EncodeToString(ts.HashedMessage)), short(headHash))
	case !res.signed:
		res.warn = "the token carries no TSA certificate, so its signature cannot be checked"
	}
	return res
}

// runVerifier asks the configured token verifier to check the token against the anchored
// head hash (CMS signature and TSA certificate chain). A panic in the verifier is reported as a
// rejection: the token is evidence from outside and must not take the export down. The
// verifier's text goes into the report as verifierText makes it - except the results report
// verification replays (statedTokenVerifier), which are that text already.
func (r *tokenResult) runVerifier(v contracts.TokenVerifier, der []byte, headHash string) {
	r.verifierRan = true
	digest, err := hex.DecodeString(headHash)
	if err != nil {
		r.verifierErr = "the anchored head hash is not hex"
		return
	}
	norm := verifierText
	if _, stated := v.(statedTokenVerifier); stated {
		norm = func(s string) string { return s }
	}
	defer func() {
		if p := recover(); p != nil {
			r.verifierErr = norm(fmt.Sprintf("token verifier failed: %v", p))
		}
	}()
	info, err := v.VerifyToken(der, digest)
	if err != nil {
		r.verifierErr = norm(err.Error())
		return
	}
	info.TSAName, info.ChainNote = validUTF8(info.TSAName), norm(info.ChainNote)
	r.info = info
}

// verifierText makes text of the token verifier fit for the report: one line of valid UTF-8,
// at most 400 bytes (plus "...").
func verifierText(s string) string { return truncate(oneLine(validUTF8(s)), 400) }
