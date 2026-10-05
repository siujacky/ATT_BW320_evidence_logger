package anchor

import (
	"bytes"
	"crypto"
	_ "crypto/sha1" // registers crypto.SHA1 for ESS signingCertificate (v1) hashes
	"crypto/sha256"
	_ "crypto/sha512" // registers crypto.SHA384/SHA512 for ESS signingCertificateV2 hashes
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/digitorus/pkcs7"
	"github.com/digitorus/timestamp"

	"attmonitor/internal/contracts"
)

var (
	oidTSTInfo              = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}  // id-ct-TSTInfo
	oidContentType          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}         // CMS content-type attribute
	oidSigningCertificate   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 12} // ESS signingCertificate (SHA-1)
	oidSigningCertificateV2 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 47} // ESS signingCertificateV2
	oidExtKeyUsage          = asn1.ObjectIdentifier{2, 5, 29, 37}
	oidKeyUsage             = asn1.ObjectIdentifier{2, 5, 29, 15}
)

// essHashes maps the hash algorithms allowed in ESSCertIDv2 to crypto hashes.
var essHashes = []struct {
	oid  asn1.ObjectIdentifier
	hash crypto.Hash
}{
	{asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}, crypto.SHA1},
	{asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}, crypto.SHA256},
	{asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}, crypto.SHA384},
	{asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}, crypto.SHA512},
}

var (
	errImprintMismatch = errors.New("anchor: time-stamp token does not cover the expected digest")
	errNonceMismatch   = errors.New("anchor: time-stamp token nonce does not match the request nonce")
	errNoCertificates  = errors.New("anchor: time-stamp token carries no certificate, so its signature cannot be verified")
)

// ------------------------------------------------------------------ TimeStampResp (RFC 3161 §2.4.2)

// PKIStatus values. statusBareToken marks input that was a bare TimeStampToken.
const (
	statusGranted         = 0
	statusGrantedWithMods = 1
	statusBareToken       = -1
)

var statusNames = [...]string{"granted", "grantedWithMods", "rejection", "waiting", "revocationWarning", "revocationNotification"}

func statusName(s int) string {
	if s >= 0 && s < len(statusNames) {
		return statusNames[s]
	}
	return "unknown"
}

// failInfoNames names the PKIFailureInfo bits defined by RFC 3161.
var failInfoNames = map[int]string{
	0: "badAlg", 2: "badRequest", 5: "badDataFormat", 14: "timeNotAvailable", 15: "unacceptedPolicy",
	16: "unacceptedExtension", 17: "addInfoNotAvailable", 25: "systemFailure",
}

type pkiStatusInfo struct {
	Status       int
	StatusString []string       `asn1:"optional"` // PKIFreeText: SEQUENCE OF UTF8String
	FailInfo     asn1.BitString `asn1:"optional"`
}

type timeStampResp struct {
	Status         pkiStatusInfo
	TimeStampToken asn1.RawValue `asn1:"optional"`
}

// statusError reports a TimeStampResp whose PKIStatus is neither granted nor grantedWithMods.
type statusError struct {
	status   int
	text     []string // PKIFreeText sent by the TSA (untrusted; clipped)
	failInfo []string // names of the PKIFailureInfo bits that are set
}

func (e *statusError) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "anchor: TSA did not grant the time-stamp: PKIStatus %s (%d)", statusName(e.status), e.status)
	if len(e.text) > 0 {
		fmt.Fprintf(&b, ": %q", strings.Join(e.text, "; "))
	}
	if len(e.failInfo) > 0 {
		fmt.Fprintf(&b, " [failInfo: %s]", strings.Join(e.failInfo, ", "))
	}
	return b.String()
}

func newStatusError(si pkiStatusInfo) *statusError {
	e := &statusError{status: si.Status}
	for i, s := range si.StatusString {
		if i == 4 {
			e.text = append(e.text, "...")
			break
		}
		e.text = append(e.text, clip(s, 200))
	}
	for bit := 0; bit < si.FailInfo.BitLength && bit < 64; bit++ {
		if si.FailInfo.At(bit) == 1 {
			name, ok := failInfoNames[bit]
			if !ok {
				name = fmt.Sprintf("bit%d", bit)
			}
			e.failInfo = append(e.failInfo, name)
		}
	}
	return e
}

// extractToken accepts a DER TimeStampResp or a bare TimeStampToken (CMS ContentInfo) and
// returns the token and the response's PKIStatus (statusBareToken for a bare token). Only
// DER is accepted: the strict structural check (checkEnvelope) needs it, and real TSAs send it.
func extractToken(der []byte) (token []byte, status int, err error) {
	if len(der) == 0 {
		return nil, 0, errors.New("anchor: empty time-stamp response")
	}
	var outer asn1.RawValue
	rest, err := asn1.Unmarshal(der, &outer)
	if err != nil {
		return nil, 0, wrapDep("anchor: not a DER time-stamp response or token", err)
	}
	if len(rest) != 0 {
		return nil, 0, fmt.Errorf("anchor: %d bytes of trailing data after the time-stamp response", len(rest))
	}
	if outer.Class != asn1.ClassUniversal || outer.Tag != asn1.TagSequence || !outer.IsCompound {
		return nil, 0, errors.New("anchor: not a time-stamp response or token (outer element is not a SEQUENCE)")
	}
	var first asn1.RawValue
	if _, err := asn1.Unmarshal(outer.Bytes, &first); err != nil {
		return nil, 0, wrapDep("anchor: malformed time-stamp response", err)
	}
	if first.Class == asn1.ClassUniversal && first.Tag == asn1.TagOID {
		return der, statusBareToken, nil // ContentInfo {contentType, content}: a bare token
	}
	var resp timeStampResp
	if _, err := asn1.Unmarshal(der, &resp); err != nil {
		return nil, 0, wrapDep("anchor: malformed TimeStampResp", err)
	}
	st := resp.Status.Status
	if st != statusGranted && st != statusGrantedWithMods {
		return nil, st, newStatusError(resp.Status)
	}
	if len(resp.TimeStampToken.FullBytes) == 0 {
		return nil, st, fmt.Errorf("anchor: TSA status %s but the response carries no time-stamp token", statusName(st))
	}
	return resp.TimeStampToken.FullBytes, st, nil
}

// ------------------------------------------------------------------ token verification

// VerifyToken verifies an RFC 3161 time-stamp over digest (a 32-byte SHA-256 value). token is
// a DER TimeStampResp (PKIStatus granted or grantedWithMods) or a bare DER TimeStampToken.
//
// It returns an error unless the token proves "digest existed at GenTime, signed by the
// certificate inside the token": an envelope with exactly the components RFC 3161 and RFC 5652
// define (checkEnvelope), exactly one signer whose certificate is embedded, a valid CMS
// signature and message digest, content type id-ct-TSTInfo (signed attribute and encapsulated
// type), digest algorithms listed consistently, an ESS signing-certificate attribute that
// identifies the signer certificate (by hash and, when present, issuer and serial number),
// TSTInfo version 1, a tsa name (when present) that names the signer, and a SHA-256 message
// imprint equal to digest. These are the checks `openssl ts -verify` makes. The nonce is
// reported but not checked (only a requester knows it; see Client.Timestamp). TSAName is the
// signer's subject with non-printable characters escaped (see printable).
//
// TokenInfo.ChainOK additionally reports whether the signer certificate meets the RFC 3161 TSA
// certificate profile and chained, at GenTime and through the certificates in the token, to a
// trusted root: the embedded FreeTSA root (pinned by SHA-256), roots (optional extra roots) or
// the system root store. ChainOK == false is not an error; TokenInfo.ChainNote then says why, in
// one printable line of at most 200 bytes naming each root source tried and what it reported
// (empty when ChainOK is true). On error the TokenInfo is zero.
func VerifyToken(token, digest []byte, roots *x509.CertPool) (contracts.TokenInfo, error) {
	v, err := verifyCore(token, digest)
	if err != nil {
		return contracts.TokenInfo{}, err
	}
	_ = v.checkChain(roots) // the diagnostic is summarised in ChainNote
	return v.info, nil
}

// verified is the outcome of verifyCore.
type verified struct {
	info   contracts.TokenInfo // ChainOK and ChainNote not yet set (see checkChain)
	nonce  *big.Int            // nil if the token has no nonce
	status int                 // PKIStatus of the response, or statusBareToken
	signer *x509.Certificate
	certs  []*x509.Certificate // every certificate embedded in the token
}

// checkChain sets info.ChainOK and info.ChainNote (see chainVerify and chainNote) and returns the
// complete diagnostic of a false ChainOK, for logs.
func (v *verified) checkChain(extra *x509.CertPool) error {
	ok, err := chainVerify(v.signer, v.certs, v.info.GenTime, extra)
	v.info.ChainOK, v.info.ChainNote = ok, ""
	if !ok {
		v.info.ChainNote = chainNote(err)
	}
	return err
}

// verifyCore performs every check of VerifyToken except the certificate chain.
func verifyCore(der, digest []byte) (v *verified, err error) {
	// The input comes from the network (and over plain HTTP for some TSAs): never let a parser
	// bug in a dependency take the service down.
	defer func() {
		if r := recover(); r != nil {
			v, err = nil, fmt.Errorf("anchor: malformed time-stamp token (parser panic: %v)", r)
		}
	}()
	if len(digest) != sha256.Size {
		return nil, fmt.Errorf("%w (got %d bytes)", errDigestLength, len(digest))
	}
	tok, status, err := extractToken(der)
	if err != nil {
		return nil, err
	}
	if err := checkEnvelope(der, status == statusBareToken); err != nil {
		return nil, err
	}
	// timestamp.Parse checks the CMS signature (message digest and signature value) with the
	// embedded signer certificate — but silently skips that when there is no certificate.
	ts, err := timestamp.Parse(tok)
	if err != nil {
		return nil, wrapDep("anchor: invalid time-stamp token", err)
	}
	if len(ts.Certificates) == 0 {
		return nil, errNoCertificates
	}
	p7, err := pkcs7.Parse(tok)
	if err != nil {
		return nil, wrapDep("anchor: invalid time-stamp token", err)
	}
	if len(p7.Signers) != 1 {
		return nil, fmt.Errorf("anchor: time-stamp token has %d signers; RFC 3161 allows exactly one", len(p7.Signers))
	}
	signer := p7.GetOnlySigner()
	if signer == nil {
		return nil, errors.New("anchor: the token's signer certificate is not embedded in the token")
	}
	if err := checkContentType(p7); err != nil {
		return nil, err
	}
	if err := checkSignedData(tok, p7); err != nil {
		return nil, err
	}
	if err := checkSigningCertificate(p7, signer); err != nil {
		return nil, err
	}
	if err := checkTSTInfo(p7.Content, signer); err != nil {
		return nil, err
	}
	if ts.HashAlgorithm != crypto.SHA256 {
		return nil, fmt.Errorf("anchor: token message imprint uses %v, expected SHA-256", ts.HashAlgorithm)
	}
	if !bytes.Equal(ts.HashedMessage, digest) {
		return nil, fmt.Errorf("%w: the token covers %s, expected %s", errImprintMismatch,
			clip(hex.EncodeToString(ts.HashedMessage), 128), hex.EncodeToString(digest))
	}
	return &verified{
		info: contracts.TokenInfo{
			GenTime: ts.Time.UTC(),
			Serial:  bigHex(ts.SerialNumber),
			Policy:  ts.Policy.String(),
			Nonce:   bigHex(ts.Nonce),
			// The name comes from whoever made the token; it is shown in reports and consoles.
			TSAName: printable(signer.Subject.String()),
		},
		nonce:  ts.Nonce,
		status: status,
		signer: signer,
		certs:  p7.Certificates,
	}, nil
}

// signedAttribute returns the DER encoding of the single value of signed attribute oid of the
// token's only signer; present is false when the attribute is absent. RFC 5652 §11 forbids
// repeating these attributes and requires exactly one value each.
func signedAttribute(p7 *pkcs7.PKCS7, oid asn1.ObjectIdentifier) (value []byte, present bool, err error) {
	var set []byte
	n := 0
	for _, a := range p7.Signers[0].AuthenticatedAttributes {
		if a.Type.Equal(oid) {
			n++
			set = a.Value.Bytes // contents of the SET OF AttributeValue
		}
	}
	switch {
	case n == 0:
		return nil, false, nil
	case n > 1:
		return nil, true, fmt.Errorf("anchor: signed attribute %v appears %d times", oid, n)
	}
	var v asn1.RawValue
	rest, err := asn1.Unmarshal(set, &v)
	if err != nil {
		return nil, true, fmt.Errorf("anchor: signed attribute %v: %w", oid, err)
	}
	if len(rest) != 0 {
		return nil, true, fmt.Errorf("anchor: signed attribute %v has more than one value", oid)
	}
	return v.FullBytes, true, nil
}

// cmsContentInfo and cmsSignedDataHead decode the unsigned CMS fields that the pkcs7 package
// does not check (only the leading SignedData fields are needed).
type cmsContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"tag:0"` // the [0] EXPLICIT wrapper; Bytes is the SignedData
}

type cmsSignedDataHead struct {
	Version          int
	DigestAlgorithms []pkix.AlgorithmIdentifier `asn1:"set"`
	EncapContentInfo struct {
		EContentType asn1.ObjectIdentifier
		EContent     asn1.RawValue `asn1:"optional,tag:0"`
	}
}

// digestOIDs are the digest algorithms a SignedData may list (SHA-1, SHA-2 and SHA-3 families).
var digestOIDs = []asn1.ObjectIdentifier{
	{1, 3, 14, 3, 2, 26},
	{2, 16, 840, 1, 101, 3, 4, 2, 1}, {2, 16, 840, 1, 101, 3, 4, 2, 2}, {2, 16, 840, 1, 101, 3, 4, 2, 3},
	{2, 16, 840, 1, 101, 3, 4, 2, 4}, {2, 16, 840, 1, 101, 3, 4, 2, 5}, {2, 16, 840, 1, 101, 3, 4, 2, 6},
	{2, 16, 840, 1, 101, 3, 4, 2, 7}, {2, 16, 840, 1, 101, 3, 4, 2, 8}, {2, 16, 840, 1, 101, 3, 4, 2, 9},
	{2, 16, 840, 1, 101, 3, 4, 2, 10},
}

// checkSignedData checks the unsigned SignedData fields that the pkcs7 package ignores but
// `openssl ts -verify` relies on: the encapsulated content type must be id-ct-TSTInfo (RFC
// 3161 §2.4.2; RFC 5652 §11.1 requires it to equal the content-type attribute), and
// digestAlgorithms must list only digest algorithms, including the signer's.
func checkSignedData(tok []byte, p7 *pkcs7.PKCS7) error {
	var ci cmsContentInfo
	if _, err := asn1.Unmarshal(tok, &ci); err != nil {
		return wrapDep("anchor: malformed ContentInfo", err)
	}
	var sd cmsSignedDataHead
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		return wrapDep("anchor: malformed SignedData", err)
	}
	if ct := sd.EncapContentInfo.EContentType; !ct.Equal(oidTSTInfo) {
		return fmt.Errorf("anchor: encapsulated content type is %v, not id-ct-TSTInfo (%v)", ct, oidTSTInfo)
	}
	signerDigest := p7.Signers[0].DigestAlgorithm.Algorithm
	listed := false
	for _, a := range sd.DigestAlgorithms {
		if !slices.ContainsFunc(digestOIDs, a.Algorithm.Equal) {
			return fmt.Errorf("anchor: SignedData lists %v, which is not a digest algorithm", a.Algorithm)
		}
		listed = listed || a.Algorithm.Equal(signerDigest)
	}
	if !listed {
		return fmt.Errorf("anchor: the signer's digest algorithm %v is not listed in SignedData", signerDigest)
	}
	return nil
}

// checkContentType requires the signed content-type attribute to be id-ct-TSTInfo, so that a
// CMS signature the TSA key made over something else cannot pass as a time-stamp.
func checkContentType(p7 *pkcs7.PKCS7) error {
	val, present, err := signedAttribute(p7, oidContentType)
	if err != nil {
		return err
	}
	if !present {
		return errors.New("anchor: time-stamp token has no signed content-type attribute")
	}
	var ct asn1.ObjectIdentifier
	if _, err := asn1.Unmarshal(val, &ct); err != nil {
		return fmt.Errorf("anchor: malformed content-type attribute: %w", err)
	}
	if !ct.Equal(oidTSTInfo) {
		return fmt.Errorf("anchor: signed content type is %v, not id-ct-TSTInfo (%v)", ct, oidTSTInfo)
	}
	return nil
}

// tstInfo is RFC 3161 TSTInfo. The timestamp package decodes the same signed bytes for the
// values reported in TokenInfo; this decoding serves the checks it does not make.
type tstInfo struct {
	Version        int
	Policy         asn1.ObjectIdentifier
	MessageImprint struct {
		HashAlgorithm pkix.AlgorithmIdentifier
		HashedMessage []byte
	}
	SerialNumber *big.Int
	GenTime      asn1.RawValue // GeneralizedTime
	Accuracy     struct {
		Seconds int64 `asn1:"optional"`
		Millis  int64 `asn1:"tag:0,optional"`
		Micros  int64 `asn1:"tag:1,optional"`
	} `asn1:"optional"`
	Ordering   bool             `asn1:"optional,default:false"`
	Nonce      *big.Int         `asn1:"optional"`
	TSA        asn1.RawValue    `asn1:"tag:0,optional"` // [0] EXPLICIT GeneralName
	Extensions []pkix.Extension `asn1:"tag:1,optional"`
}

// checkTSTInfo makes the TSTInfo checks of `openssl ts -verify` that the timestamp package
// does not: version 1, and a tsa field (when present) that names the signer certificate. A
// token failing them would verify here but fail the third-party check of an evidence bundle.
func checkTSTInfo(content []byte, signer *x509.Certificate) error {
	var inf tstInfo
	if _, err := asn1.Unmarshal(content, &inf); err != nil {
		return wrapDep("anchor: malformed TSTInfo", err)
	}
	if inf.Version != 1 {
		return fmt.Errorf("anchor: unsupported TSTInfo version %d (RFC 3161 defines version 1)", inf.Version)
	}
	if len(inf.TSA.FullBytes) != 0 {
		return checkTSAName(inf.TSA.Bytes, signer)
	}
	return nil
}

// ESS signing-certificate attributes (RFC 2634 §5.4, RFC 5035 §3).
type essCertID struct {
	CertHash     []byte
	IssuerSerial asn1.RawValue `asn1:"optional"`
}

type signingCertificate struct {
	Certs    []essCertID
	Policies asn1.RawValue `asn1:"optional"`
}

type essCertIDv2 struct {
	HashAlgorithm pkix.AlgorithmIdentifier `asn1:"optional"` // DEFAULT id-sha256
	CertHash      []byte
	IssuerSerial  asn1.RawValue `asn1:"optional"`
}

type signingCertificateV2 struct {
	Certs    []essCertIDv2
	Policies asn1.RawValue `asn1:"optional"`
}

// checkSigningCertificate verifies that the ESS signing-certificate attribute(s), which RFC 3161
// requires and which are covered by the signature, identify exactly the certificate that
// verified the signature. This binds the embedded certificate (and so the TSA name and the
// chain check) to the signature: altering the certificate inside a token is detected.
func checkSigningCertificate(p7 *pkcs7.PKCS7, cert *x509.Certificate) error {
	found := false
	val, present, err := signedAttribute(p7, oidSigningCertificateV2)
	if err != nil {
		return err
	}
	if present {
		var sc signingCertificateV2
		if _, err := asn1.Unmarshal(val, &sc); err != nil || len(sc.Certs) == 0 {
			return errors.New("anchor: malformed ESS signingCertificateV2 attribute")
		}
		h := crypto.SHA256
		if alg := sc.Certs[0].HashAlgorithm.Algorithm; len(alg) > 0 {
			if h, err = essHash(alg); err != nil {
				return err
			}
		}
		if err := matchCertHash(h, cert, sc.Certs[0].CertHash, "signingCertificateV2"); err != nil {
			return err
		}
		if err := checkIssuerSerial(sc.Certs[0].IssuerSerial, cert, "signingCertificateV2"); err != nil {
			return err
		}
		found = true
	}
	val, present, err = signedAttribute(p7, oidSigningCertificate)
	if err != nil {
		return err
	}
	if present {
		var sc signingCertificate
		if _, err := asn1.Unmarshal(val, &sc); err != nil || len(sc.Certs) == 0 {
			return errors.New("anchor: malformed ESS signingCertificate attribute")
		}
		if err := matchCertHash(crypto.SHA1, cert, sc.Certs[0].CertHash, "signingCertificate"); err != nil {
			return err
		}
		if err := checkIssuerSerial(sc.Certs[0].IssuerSerial, cert, "signingCertificate"); err != nil {
			return err
		}
		found = true
	}
	if !found {
		return errors.New("anchor: time-stamp token lacks the ESS signing-certificate attribute required by RFC 3161")
	}
	return nil
}

func essHash(oid asn1.ObjectIdentifier) (crypto.Hash, error) {
	for _, e := range essHashes {
		if e.oid.Equal(oid) {
			return e.hash, nil
		}
	}
	return 0, fmt.Errorf("anchor: ESS signingCertificateV2 uses unsupported hash algorithm %v", oid)
}

func matchCertHash(h crypto.Hash, cert *x509.Certificate, want []byte, attr string) error {
	if !h.Available() {
		return fmt.Errorf("anchor: ESS %s: hash %v unavailable", attr, h)
	}
	hh := h.New()
	hh.Write(cert.Raw)
	if !bytes.Equal(hh.Sum(nil), want) {
		return fmt.Errorf("anchor: ESS %s does not identify the certificate that signed the token", attr)
	}
	return nil
}

// essIssuerSerial is IssuerSerial (RFC 5035 §4): the issuer's GeneralNames and the serial number.
type essIssuerSerial struct {
	Issuer []asn1.RawValue
	Serial *big.Int
}

// checkIssuerSerial checks the optional issuerSerial of an ESSCertID as OpenSSL does: when
// present it must hold exactly one directoryName, equal to the certificate's issuer, and the
// certificate's serial number.
func checkIssuerSerial(raw asn1.RawValue, cert *x509.Certificate, attr string) error {
	if len(raw.FullBytes) == 0 {
		return nil
	}
	var is essIssuerSerial
	if _, err := asn1.Unmarshal(raw.FullBytes, &is); err == nil &&
		len(is.Issuer) == 1 && isDirectoryName(is.Issuer[0]) && nameEqual(is.Issuer[0].Bytes, cert.RawIssuer) &&
		is.Serial != nil && is.Serial.Cmp(cert.SerialNumber) == 0 {
		return nil
	}
	return fmt.Errorf("anchor: ESS %s issuer/serial does not identify the certificate that signed the token", attr)
}

// ------------------------------------------------------------------ certificate chain

// rootSource is one set of trust anchors for the chain check.
type rootSource struct {
	name  string                         // as ChainNote and the logs show it, e.g. sourceSystem
	roots func() (*x509.CertPool, error) // nil pool: source not configured
}

// defaultRootSources lists the trust anchors from cheapest to most expensive to consult: the
// embedded roots and the caller's extra roots are checked by Go's verifier; the system roots
// use, on Windows, the platform chain engine, which may contact Windows Update to fetch a root.
func defaultRootSources(extra *x509.CertPool) []rootSource {
	return []rootSource{
		{sourceEmbedded, embeddedRoots},
		{sourceExtra, func() (*x509.CertPool, error) { return extra, nil }},
		{sourceSystem, x509.SystemCertPool},
	}
}

// chainVerify reports whether signer meets the RFC 3161 TSA certificate profile and chained, at
// time at (the token's genTime), to a trusted root (embedded, extra or system), using the token's
// other certificates as intermediates. err explains a false result (usually a *chainError, see
// chainNote); it is diagnostic only.
func chainVerify(signer *x509.Certificate, certs []*x509.Certificate, at time.Time, extra *x509.CertPool) (bool, error) {
	return chainVerifyWith(signer, certs, at, defaultRootSources(extra))
}

// chainVerifyWith is chainVerify with explicit root sources.
//
// The chain must be self-contained, as for a third party who checks the token offline with
// `openssl ts -verify -CAfile <root>`: built from the token's own certificates up to a trusted
// root. Windows' chain engine (used for the system roots) completes chains with intermediates
// from its certificate stores or downloaded via AIA; and the token's certificate set is not
// signed, so anyone on the path to a plain-HTTP TSA can remove or damage an intermediate
// without invalidating the token. So every chain found is re-verified with Go's verifier from
// the token's certificates to the root that was chosen.
func chainVerifyWith(signer *x509.Certificate, certs []*x509.Certificate, at time.Time, sources []rootSource) (ok bool, err error) {
	defer func() {
		if r := recover(); r != nil {
			ok, err = false, fmt.Errorf("anchor: certificate chain check panicked: %v", r)
		}
	}()
	if err := checkTSAProfile(signer); err != nil {
		return false, &chainError{profile: err}
	}
	inter := x509.NewCertPool()
	for _, c := range certs {
		if !c.Equal(signer) {
			inter.AddCert(c)
		}
	}
	opts := x509.VerifyOptions{
		Intermediates: inter,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
		CurrentTime:   at,
	}
	failed := &chainError{}
	for _, src := range sources {
		roots, err := src.roots()
		if err != nil {
			failed.add(src.name, "unavailable: "+reasonText(err), err)
			continue
		}
		if roots == nil {
			failed.add(src.name, "none", nil)
			continue
		}
		opts.Roots = roots
		chains, err := signer.Verify(opts)
		if err == nil {
			err = selfContained(signer, certs, chains, opts)
		}
		if err != nil {
			failed.add(src.name, reasonText(err), err)
			continue
		}
		return true, nil
	}
	return false, failed
}

// selfContained succeeds if one of the chains found leads from the token's own certificates to
// its root: either every intermediate of the chain is a certificate of the token (always so
// for Go's verifier with a plain pool), or Go's verifier, given only the token's certificates
// (opts.Intermediates) and that chain's root, finds such a chain.
func selfContained(signer *x509.Certificate, certs []*x509.Certificate, chains [][]*x509.Certificate, opts x509.VerifyOptions) error {
	notInToken := func(c *x509.Certificate) bool { return !slices.ContainsFunc(certs, c.Equal) }
	for _, chain := range chains {
		// chain = [signer, intermediates..., root]; a one-element chain is a trusted signer.
		if len(chain) > 0 && !slices.ContainsFunc(chain[1:max(1, len(chain)-1)], notInToken) {
			return nil
		}
	}
	err := errors.New("no chain")
	for _, chain := range chains {
		if len(chain) == 0 {
			continue
		}
		root := x509.NewCertPool() // not a system pool: Go's verifier, nothing fetched
		root.AddCert(chain[len(chain)-1])
		opts.Roots = root
		if _, err = signer.Verify(opts); err == nil {
			return nil
		}
	}
	// Kept short: it goes into ChainNote. It means the token does not carry its own chain.
	return fmt.Errorf("chain needs certificates not in the token (%w)", err)
}

// checkTSAProfile applies the RFC 3161 §2.3 requirements for a TSA signing certificate — the
// same checks as OpenSSL's "timestampsign" purpose used by `openssl ts -verify`: the extended
// key usage extension is present, critical and contains exactly id-kp-timeStamping; a key
// usage extension, when present, allows only digitalSignature and/or nonRepudiation.
func checkTSAProfile(c *x509.Certificate) error {
	var eku *pkix.Extension
	hasKeyUsage := false
	for i := range c.Extensions {
		switch id := c.Extensions[i].Id; {
		case id.Equal(oidExtKeyUsage):
			eku = &c.Extensions[i]
		case id.Equal(oidKeyUsage):
			hasKeyUsage = true
		}
	}
	switch {
	case eku == nil:
		return errors.New("anchor: TSA certificate has no extended key usage extension")
	case !eku.Critical:
		return errors.New("anchor: TSA certificate extended key usage is not marked critical")
	case len(c.ExtKeyUsage) != 1 || c.ExtKeyUsage[0] != x509.ExtKeyUsageTimeStamping || len(c.UnknownExtKeyUsage) != 0:
		return errors.New("anchor: TSA certificate extended key usage is not exactly timeStamping")
	}
	if hasKeyUsage {
		const allowed = x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment
		if c.KeyUsage&^allowed != 0 || c.KeyUsage&allowed == 0 {
			return errors.New("anchor: TSA certificate key usage must be digitalSignature and/or nonRepudiation only")
		}
	}
	return nil
}

// ------------------------------------------------------------------ helpers

// bigHex renders an ASN.1 INTEGER as lowercase hex of its big-endian magnitude, padded to whole
// bytes ("08e3867d"), with a leading "-" if negative; "" for nil.
func bigHex(n *big.Int) string {
	if n == nil {
		return ""
	}
	b := n.Bytes()
	if len(b) == 0 {
		b = []byte{0}
	}
	s := hex.EncodeToString(b)
	if n.Sign() < 0 {
		s = "-" + s
	}
	return s
}

// clip shortens untrusted text for error messages to at most n bytes (plus "..."), cutting at
// a UTF-8 character boundary.
func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n] + "..."
}

// printable returns untrusted text (e.g. a certificate name from a token) with every character
// that is not printable — control characters, format characters such as U+202E RIGHT-TO-LEFT
// OVERRIDE, invalid UTF-8 — escaped as \xHH, \uHHHH or \UHHHHHHHH. Printable text, which
// includes the names of every real CA, is returned unchanged.
func printable(s string) string {
	bad := func(r rune, size int) bool { return r == utf8.RuneError && size <= 1 || !unicode.IsPrint(r) }
	clean := true
	for i := 0; i < len(s) && clean; {
		r, size := utf8.DecodeRuneInString(s[i:])
		clean = !bad(r, size)
		i += size
	}
	if clean {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && size <= 1:
			fmt.Fprintf(&b, `\x%02x`, s[i])
		case !bad(r, size):
			b.WriteString(s[i : i+size])
		case r < utf8.RuneSelf:
			fmt.Fprintf(&b, `\x%02x`, r)
		case r <= 0xffff:
			fmt.Fprintf(&b, `\u%04x`, r)
		default:
			fmt.Fprintf(&b, `\U%08x`, r)
		}
		i += size
	}
	return b.String()
}

// oneLine makes text safe for a one-line message: whitespace runs (including newlines and tabs)
// become one space, and if any non-printable character remains (e.g. a terminal escape) the
// text is escaped like a Go string literal, without the quotes.
func oneLine(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if strings.IndexFunc(s, func(r rune) bool { return !unicode.IsPrint(r) }) < 0 {
		return s
	}
	q := strconv.Quote(s)
	return q[1 : len(q)-1]
}

// depError reports an error from a dependency (CMS, ASN.1 or X.509 parsing). The text ends up
// in verification reports, logs and console output, so it is printed on one line; the original
// error stays available to errors.Is and errors.As.
type depError struct {
	msg string
	err error
}

func wrapDep(msg string, err error) error { return &depError{msg: msg, err: err} }

func (e *depError) Error() string { return e.msg + ": " + oneLine(e.err.Error()) }

func (e *depError) Unwrap() error { return e.err }
