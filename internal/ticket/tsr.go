package ticket

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// A minimal, read-only RFC 3161 reader for the setup-time time-stamp tokens imported with the
// bootstrap evidence (BOOTSTRAP-MANIFEST.*.tsr). It extracts what the token STATES - status,
// genTime, the hash it covers and the TSA named by its certificate - so the report can relate a
// token to the imported file whose SHA-256 it carries. It does NOT verify the CMS signature or
// the certificate chain: the report says so and prints the OpenSSL command that does.

var (
	oidSignedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidTSTInfo    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}
	oidSHA256     = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
)

// tokenInfo is what a time-stamp token states (unverified).
type tokenInfo struct {
	Granted bool
	GenTime time.Time
	HashAlg string // "SHA-256" or the OID
	Imprint string // lowercase hex of the hashed message
	Serial  string // hex
	TSA     string // organization (or common name) of the time-stamping certificate, "" if not found
}

type tsrPKIStatus struct {
	Status int
}

type tsrResp struct {
	Status tsrPKIStatus
	Token  asn1.RawValue `asn1:"optional"`
}

type tsrContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,tag:0"`
}

type tsrSignedData struct {
	Version          int
	DigestAlgorithms asn1.RawValue
	EncapContentInfo tsrEncap
	Certificates     asn1.RawValue `asn1:"optional,tag:0"`
}

type tsrEncap struct {
	EContentType asn1.ObjectIdentifier
	EContent     asn1.RawValue `asn1:"optional,explicit,tag:0"`
}

type tsrTSTInfo struct {
	Version        int
	Policy         asn1.ObjectIdentifier
	MessageImprint tsrImprint
	SerialNumber   *big.Int
	GenTime        time.Time `asn1:"generalized"`
}

type tsrImprint struct {
	HashAlgorithm pkix.AlgorithmIdentifier
	HashedMessage []byte
}

var errNotToken = errors.New("not an RFC 3161 time-stamp response or token")

// maxTokenBytes bounds the input (real tokens are a few kilobytes).
const maxTokenBytes = 1 << 20

// parseToken reads a DER TimeStampResp, or a bare TimeStampToken (ContentInfo).
func parseToken(der []byte) (tokenInfo, error) {
	if len(der) == 0 || len(der) > maxTokenBytes {
		return tokenInfo{}, errNotToken
	}
	var outer asn1.RawValue
	if _, err := asn1.Unmarshal(der, &outer); err != nil || outer.Tag != asn1.TagSequence || !outer.IsCompound {
		return tokenInfo{}, errNotToken
	}
	var first asn1.RawValue
	if _, err := asn1.Unmarshal(outer.Bytes, &first); err != nil {
		return tokenInfo{}, errNotToken
	}
	info := tokenInfo{}
	tokenDER := der
	if first.Class == asn1.ClassUniversal && first.Tag == asn1.TagSequence {
		// TimeStampResp: PKIStatusInfo, then the token.
		var resp tsrResp
		if _, err := asn1.Unmarshal(der, &resp); err != nil {
			return tokenInfo{}, fmt.Errorf("%w: %v", errNotToken, err)
		}
		info.Granted = resp.Status.Status == 0 || resp.Status.Status == 1
		if len(resp.Token.FullBytes) == 0 {
			return info, fmt.Errorf("time-stamp response without a token (status %d)", resp.Status.Status)
		}
		tokenDER = resp.Token.FullBytes
	} else {
		info.Granted = true // a bare token is only issued when granted
	}

	var ci tsrContentInfo
	if _, err := asn1.Unmarshal(tokenDER, &ci); err != nil {
		return info, fmt.Errorf("%w: %v", errNotToken, err)
	}
	if !ci.ContentType.Equal(oidSignedData) {
		return info, fmt.Errorf("%w: content type %s", errNotToken, ci.ContentType)
	}
	var sd tsrSignedData
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		return info, fmt.Errorf("%w: signed data: %v", errNotToken, err)
	}
	if !sd.EncapContentInfo.EContentType.Equal(oidTSTInfo) {
		return info, fmt.Errorf("%w: encapsulated content %s", errNotToken, sd.EncapContentInfo.EContentType)
	}
	var tstDER []byte
	if _, err := asn1.Unmarshal(sd.EncapContentInfo.EContent.Bytes, &tstDER); err != nil {
		return info, fmt.Errorf("%w: TSTInfo: %v", errNotToken, err)
	}
	var tst tsrTSTInfo
	if _, err := asn1.Unmarshal(tstDER, &tst); err != nil {
		return info, fmt.Errorf("%w: TSTInfo: %v", errNotToken, err)
	}
	info.GenTime = tst.GenTime.UTC()
	info.Imprint = hex.EncodeToString(tst.MessageImprint.HashedMessage)
	info.HashAlg = tst.MessageImprint.HashAlgorithm.Algorithm.String()
	if tst.MessageImprint.HashAlgorithm.Algorithm.Equal(oidSHA256) {
		info.HashAlg = "SHA-256"
	}
	if tst.SerialNumber != nil {
		info.Serial = tst.SerialNumber.Text(16)
	}
	if sd.Certificates.Class == asn1.ClassContextSpecific && sd.Certificates.Tag == 0 {
		info.TSA = tsaFromCerts(sd.Certificates.Bytes)
	}
	return info, nil
}

// tsaFromCerts names the time-stamping certificate among the token's certificates: its
// organization, else its common name ("" when none is marked for time stamping).
func tsaFromCerts(b []byte) string {
	certs, err := x509.ParseCertificates(b)
	if err != nil {
		return ""
	}
	for _, c := range certs {
		for _, u := range c.ExtKeyUsage {
			if u != x509.ExtKeyUsageTimeStamping {
				continue
			}
			if len(c.Subject.Organization) > 0 && strings.TrimSpace(c.Subject.Organization[0]) != "" {
				return c.Subject.Organization[0]
			}
			return c.Subject.CommonName
		}
	}
	return ""
}

// dnAttr returns the value of the first attribute named attr ("O", "CN") in an RFC 4514 style
// distinguished name such as "CN=x,O=DigiCert\, Inc.,C=US" (backslash escapes honored).
func dnAttr(dn, attr string) string {
	var parts []string
	var cur strings.Builder
	esc := false
	for _, r := range dn {
		switch {
		case esc:
			cur.WriteRune(r)
			esc = false
		case r == '\\':
			esc = true
		case r == ',' || r == '+':
			parts = append(parts, cur.String())
			cur.Reset()
		default:
			cur.WriteRune(r)
		}
	}
	parts = append(parts, cur.String())
	for _, p := range parts {
		k, v, ok := strings.Cut(p, "=")
		if ok && strings.EqualFold(strings.TrimSpace(k), attr) {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
