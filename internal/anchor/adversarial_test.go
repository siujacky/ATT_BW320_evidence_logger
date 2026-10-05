package anchor

// Adversarial tests added in review: tokens that `openssl ts -verify` (the third-party check
// shipped with evidence bundles) rejects must not verify here either, replies must have the
// form the contract promises, and server-controlled text must not reach logs unescaped.

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"io"
	"math/big"
	"net"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/digitorus/pkcs7"

	"attmonitor/internal/contracts"
)

// ------------------------------------------------------------------ DER building blocks

var oidSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}

func mustMarshal(t testing.TB, v any) []byte {
	t.Helper()
	b, err := asn1.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func derTLV(t testing.TB, class, tag int, compound bool, content []byte) []byte {
	t.Helper()
	return mustMarshal(t, asn1.RawValue{Class: class, Tag: tag, IsCompound: compound, Bytes: content})
}

func derSeq(t testing.TB, parts ...[]byte) []byte {
	t.Helper()
	return derTLV(t, asn1.ClassUniversal, asn1.TagSequence, true, bytes.Join(parts, nil))
}

// directoryName and dnsName build GeneralName encodings ([4] EXPLICIT Name, [2] IA5String).
func directoryName(t testing.TB, rawName []byte) []byte {
	t.Helper()
	return derTLV(t, asn1.ClassContextSpecific, 4, true, rawName)
}

func dnsGeneralName(t testing.TB, name string) []byte {
	t.Helper()
	return derTLV(t, asn1.ClassContextSpecific, 2, false, []byte(name))
}

// testAVA / testRDNSET mirror an X.501 Name with raw attribute values (a slice type whose
// name ends in SET is a SET OF for encoding/asn1).
type testAVA struct {
	Type  asn1.ObjectIdentifier
	Value asn1.RawValue
}

type testRDNSET []testAVA

// reencodeName rewrites every string value of the DER Name raw as a UTF8String transformed by
// f, keeping the RDN structure, so the result differs in bytes but not necessarily in meaning.
func reencodeName(t testing.TB, raw []byte, f func(string) string) []byte {
	t.Helper()
	var rdns []testRDNSET
	if rest, err := asn1.Unmarshal(raw, &rdns); err != nil || len(rest) != 0 {
		t.Fatalf("parse name: %v", err)
	}
	for _, rdn := range rdns {
		for i := range rdn {
			var s string
			if _, err := asn1.Unmarshal(rdn[i].Value.FullBytes, &s); err != nil {
				t.Fatalf("name value: %v", err)
			}
			rdn[i].Value = asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagUTF8String, Bytes: []byte(f(s))}
		}
	}
	return mustMarshal(t, rdns)
}

// ------------------------------------------------------------------ DER tree editing

// derNode is a parsed DER element whose constructed values can be edited and re-encoded.
type derNode struct {
	class, tag int
	compound   bool
	content    []byte     // primitive content
	kids       []*derNode // constructed content
}

func parseDER(t testing.TB, der []byte) *derNode {
	t.Helper()
	var v asn1.RawValue
	if rest, err := asn1.Unmarshal(der, &v); err != nil || len(rest) != 0 {
		t.Fatalf("parseDER: %v (%d trailing bytes)", err, len(rest))
	}
	n := &derNode{class: v.Class, tag: v.Tag, compound: v.IsCompound}
	if !v.IsCompound {
		n.content = bytes.Clone(v.Bytes)
		return n
	}
	for b := v.Bytes; len(b) > 0; {
		var k asn1.RawValue
		rest, err := asn1.Unmarshal(b, &k)
		if err != nil {
			t.Fatal(err)
		}
		n.kids = append(n.kids, parseDER(t, k.FullBytes))
		b = rest
	}
	return n
}

func (n *derNode) encode(t testing.TB) []byte {
	t.Helper()
	content := n.content
	if n.compound {
		var parts [][]byte
		for _, k := range n.kids {
			parts = append(parts, k.encode(t))
		}
		content = bytes.Join(parts, nil)
	}
	return derTLV(t, n.class, n.tag, n.compound, content)
}

// at follows child indexes from n.
func (n *derNode) at(path ...int) *derNode {
	for _, i := range path {
		n = n.kids[i]
	}
	return n
}

// Paths into a granted TimeStampResp of the real vectors.
var (
	pathSignedData = []int{1, 1, 0}          // resp → token → [0] → SignedData
	pathSignerInfo = []int{1, 1, 0, 4, 0}    // … → signerInfos → SignerInfo
	pathEncap      = []int{1, 1, 0, 2}       // … → encapContentInfo
	pathCerts      = []int{1, 1, 0, 3}       // … → [0] certificates
	pathDigestAlgs = []int{1, 1, 0, 1}       // … → digestAlgorithms
	pathSignedAttr = []int{1, 1, 0, 4, 0, 3} // … → SignerInfo → [0] signedAttrs
)

func appendTo(path []int, elem []byte) func(*testing.T, *derNode) {
	return func(t *testing.T, n *derNode) {
		p := n.at(path...)
		p.kids = append(p.kids, parseDER(t, elem))
	}
}

// TestVerifyTokenEnvelopeStructure changes the unsigned envelope of a genuine token. Go's
// encoding/asn1 ignores elements appended to a SEQUENCE, x509 ignores an element after a
// certificate's signature, and pkcs7 verifies a re-encoding of the parsed signed attributes,
// so before the structural check every "rejected" case but one (the 8-unused-bits BIT STRING,
// which x509 rejects too) still verified here — while `openssl ts -verify` (OpenSSL 3.2,
// checked case by case) rejects every one of them. The "accepted" cases are valid CMS that
// OpenSSL accepts too.
func TestVerifyTokenEnvelopeStructure(t *testing.T) {
	digest := vectorDigest(t)
	for _, tt := range envelopeCases(t) {
		t.Run(tt.name, func(t *testing.T) {
			info, err := VerifyToken(tt.build(t), digest, nil)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("VerifyToken: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("err = %v, want containing %q", err, tt.wantErr)
			}
			if info != (contracts.TokenInfo{}) {
				t.Errorf("info %+v with an error", info)
			}
		})
	}
}

// envelopeCase is one change to the envelope of a real vector.
type envelopeCase struct {
	name    string
	file    string
	edit    func(*testing.T, *derNode) // nil: indefinite-length (BER) outer SEQUENCE
	wantErr string                     // "" → verifies
}

func (c envelopeCase) build(t *testing.T) []byte {
	t.Helper()
	orig := readVector(t, c.file)
	if c.edit == nil {
		var v asn1.RawValue
		if _, err := asn1.Unmarshal(orig, &v); err != nil {
			t.Fatal(err)
		}
		return append(append([]byte{0x30, 0x80}, v.Bytes...), 0, 0)
	}
	n := parseDER(t, orig)
	c.edit(t, n)
	return n.encode(t)
}

func envelopeCases(t *testing.T) []envelopeCase {
	extra := mustMarshal(t, 5)
	unsignedAttr := derTLV(t, asn1.ClassContextSpecific, 1, true,
		derSeq(t, mustMarshal(t, asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1}), derTLV(t, 0, asn1.TagSet, true, []byte{0x05, 0x00})))
	sha384 := derSeq(t, mustMarshal(t, asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}))
	unknownAlg := derSeq(t, mustMarshal(t, asn1.ObjectIdentifier{1, 2, 3, 4}))

	return []envelopeCase{
		{"identity re-encoding", "freetsa.tsr", func(*testing.T, *derNode) {}, ""},
		{"unsigned attribute added", "freetsa.tsr", appendTo(pathSignerInfo, unsignedAttr), ""},
		{"digestAlgorithms lists SHA-384 too", "freetsa.tsr", appendTo(pathDigestAlgs, sha384), ""},
		{"freetext UTF8String", "freetsa.tsr", func(t *testing.T, n *derNode) {
			n.kids[0].kids = append(n.kids[0].kids, parseDER(t, derSeq(t, derTLV(t, 0, asn1.TagUTF8String, false, []byte("Operation Okay")))))
		}, ""},

		{"element after the token", "freetsa.tsr", appendTo(nil, extra), "unexpected element"},
		{"element in PKIStatusInfo", "digicert.tsr", appendTo([]int{0}, []byte{0x05, 0x00}), "unexpected element"},
		{"freetext PrintableString", "freetsa.tsr", func(t *testing.T, n *derNode) {
			n.kids[0].kids = append(n.kids[0].kids, parseDER(t, derSeq(t, derTLV(t, 0, asn1.TagPrintableString, false, []byte("OK")))))
		}, "statusString"},
		{"element after SignedData content", "freetsa.tsr", appendTo([]int{1}, extra), "unexpected element"},
		{"element after SignerInfos", "digicert.tsr", appendTo(pathSignedData, extra), "unexpected element"},
		{"element in SignerInfo", "freetsa.tsr", appendTo(pathSignerInfo, extra), "unexpected element"},
		{"element in issuerAndSerialNumber", "digicert.tsr", appendTo(slices.Concat(pathSignerInfo, []int{1}), extra), "unexpected element"},
		{"element in digestAlgorithm", "freetsa.tsr", appendTo(slices.Concat(pathSignerInfo, []int{2}), extra), "unexpected element"},
		{"element in signatureAlgorithm", "digicert.tsr", appendTo(slices.Concat(pathSignerInfo, []int{4}), extra), "unexpected element"},
		{"element in a signed Attribute", "digicert.tsr", appendTo(slices.Concat(pathSignedAttr, []int{0}), extra), "unexpected element"},
		{"element after eContent", "freetsa.tsr", appendTo(slices.Concat(pathEncap, []int{1}), extra), "unexpected element"},
		{"eContent not an OCTET STRING", "freetsa.tsr", func(t *testing.T, n *derNode) {
			n.at(slices.Concat(pathEncap, []int{1, 0})...).tag = asn1.TagUTF8String
		}, "OCTET STRING"},
		{"element after a CA certificate's signature", "freetsa.tsr", appendTo(slices.Concat(pathCerts, []int{1}), extra), "unexpected element"},
		{"eContentType id-data", "digicert.tsr", func(t *testing.T, n *derNode) {
			n.at(slices.Concat(pathEncap, []int{0})...).content = mustMarshal(t, asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1})[2:]
		}, "not id-ct-TSTInfo"},
		{"digestAlgorithms lists an unknown algorithm", "freetsa.tsr", appendTo(pathDigestAlgs, unknownAlg), "not a digest algorithm"},
		{"digestAlgorithms without the signer's", "freetsa.tsr", func(t *testing.T, n *derNode) {
			n.at(pathDigestAlgs...).kids = []*derNode{parseDER(t, sha384)}
		}, "not listed"},
		// Certificates carried in the token but not on the chain (FreeTSA's copy of its root,
		// DigiCert's cross-signed root) are parsed by OpenSSL, and Go's x509 parser is more
		// lenient than OpenSSL's in places.
		{"Name value of context-specific class (FreeTSA root copy)", "freetsa.tsr", func(t *testing.T, n *derNode) {
			n.at(slices.Concat(pathCerts, []int{1, 0, 3, 0, 0, 1})...).class = asn1.ClassContextSpecific
		}, "AttributeTypeAndValue"},
		{"Name value of context-specific class (DigiCert cross certificate)", "digicert.tsr", func(t *testing.T, n *derNode) {
			n.at(slices.Concat(pathCerts, []int{2, 0, 5, 1, 0, 1})...).class = asn1.ClassContextSpecific
		}, "AttributeTypeAndValue"},
		{"extensions retagged [2]", "freetsa.tsr", func(t *testing.T, n *derNode) {
			n.at(slices.Concat(pathCerts, []int{1, 0, 7})...).tag = 2
		}, "unexpected element"},
		{"extensions retagged universal", "freetsa.tsr", func(t *testing.T, n *derNode) {
			n.at(slices.Concat(pathCerts, []int{1, 0, 7})...).class = asn1.ClassUniversal
		}, "unexpected element"},
		{"certificate signature BIT STRING with 8 unused bits", "digicert.tsr", func(t *testing.T, n *derNode) {
			n.at(slices.Concat(pathCerts, []int{2, 2})...).content[0] = 8
		}, "invalid BIT STRING"},
		{"element after the TBSCertificate extensions", "freetsa.tsr", appendTo(slices.Concat(pathCerts, []int{1, 0}), extra), "unexpected element"},

		// The one deliberate difference: OpenSSL accepts BER; this package requires DER (real
		// TSAs send DER, and the structural check needs it). Stricter is the safe direction.
		{"BER indefinite length", "freetsa.tsr", nil, "not a DER"},
	}
}

// ------------------------------------------------------------------ hand-made TSTInfo

// tstSpec describes a TSTInfo (RFC 3161 §2.4.2) encoded by hand, for tokens that
// digitorus/timestamp cannot produce.
type tstSpec struct {
	version      int    // 0 → 1
	params       []byte // DER imprint AlgorithmIdentifier parameters; nil → NULL
	paramsAbsent bool
	imprint      []byte
	nonce        *big.Int
	tsa          []byte // DER GeneralName for the tsa field; nil → absent
}

func (s tstSpec) encode(t testing.TB) []byte {
	t.Helper()
	version := s.version
	if version == 0 {
		version = 1
	}
	alg := [][]byte{mustMarshal(t, oidSHA256)}
	switch {
	case s.paramsAbsent:
	case s.params != nil:
		alg = append(alg, s.params)
	default:
		alg = append(alg, []byte{0x05, 0x00})
	}
	gen, err := asn1.MarshalWithParams(time.Now().UTC().Truncate(time.Second), "generalized")
	if err != nil {
		t.Fatal(err)
	}
	parts := [][]byte{
		mustMarshal(t, version),
		mustMarshal(t, testPolicy),
		derSeq(t, derSeq(t, alg...), mustMarshal(t, s.imprint)),
		mustMarshal(t, big.NewInt(0x5151)),
		gen,
	}
	if s.nonce != nil {
		parts = append(parts, mustMarshal(t, s.nonce))
	}
	if s.tsa != nil {
		parts = append(parts, derTLV(t, asn1.ClassContextSpecific, 0, true, s.tsa))
	}
	return derSeq(t, parts...)
}

// signTST signs a TSTInfo as a TSA would (content type id-ct-TSTInfo, ESS attribute) and
// returns the granted TimeStampResp.
func signTST(t testing.TB, signer keyCert, tst []byte, ess ...pkcs7.Attribute) []byte {
	t.Helper()
	if ess == nil {
		ess = []pkcs7.Attribute{essV2Attr(t, signer.cert, 0, nil)}
	}
	tok := resignSpec{attrs: ess, signers: []keyCert{signer}}.sign(t, tst)
	return wrapResp(t, statusGranted, tok)
}

// ------------------------------------------------------------------ TSTInfo checks

// TestVerifyTokenTSTInfoFields covers TSTInfo checks that `openssl ts -verify` makes and the
// timestamp package does not: version 1 and the optional tsa field naming the signer (RFC 3161
// §2.4.2: it "MUST correspond to one of the subject names included in the certificate that is
// to be used to verify the token"). Each verdict was cross-checked with OpenSSL 3.2
// (`openssl ts -verify -digest … -CAfile …`), including the cases that must still verify:
// OpenSSL compares names in canonical form and, with -digest, ignores the imprint algorithm
// parameters (the algorithm OID itself is checked here).
func TestVerifyTokenTSTInfoFields(t *testing.T) {
	digest := randomDigest(t)
	spec := tsaSpec(t, "Hand-made TSA")
	spec.dnsNames = []string{"tsa.example.test"}
	tsa := newCert(t, spec, nil)
	other := newCert(t, tsaSpec(t, "Another TSA"), nil)
	subject := tsa.cert.RawSubject
	shouting := reencodeName(t, subject, func(s string) string { return "  " + strings.ToUpper(strings.ReplaceAll(s, " ", "   ")) + " " })
	typo := reencodeName(t, subject, func(s string) string { return strings.Replace(s, "TSA", "TSB", 1) })
	var rdns []testRDNSET
	if _, err := asn1.Unmarshal(subject, &rdns); err != nil || len(rdns) < 2 {
		t.Fatalf("subject RDNs: %v (%d)", err, len(rdns))
	}
	rdns[0], rdns[1] = rdns[1], rdns[0]
	reordered := mustMarshal(t, rdns)

	tests := []struct {
		name    string
		tst     tstSpec
		wantErr string // "" → verifies
	}{
		{name: "baseline (no tsa field)", tst: tstSpec{}},
		{name: "tsa = signer subject", tst: tstSpec{tsa: directoryName(t, subject)}},
		{name: "tsa = signer subject, other string type, case and spacing", tst: tstSpec{tsa: directoryName(t, shouting)}},
		{name: "tsa = dNSName of the signer's subjectAltName", tst: tstSpec{tsa: dnsGeneralName(t, "tsa.example.test")}},
		{name: "imprint parameters absent", tst: tstSpec{paramsAbsent: true}},
		{name: "imprint parameters INTEGER (OpenSSL accepts it too)", tst: tstSpec{params: mustMarshal(t, 5)}},

		{name: "version 2", tst: tstSpec{version: 2}, wantErr: "version"},
		{name: "version 3 with tsa", tst: tstSpec{version: 3, tsa: directoryName(t, subject)}, wantErr: "version"},
		{name: "tsa = another certificate's subject", tst: tstSpec{tsa: directoryName(t, other.cert.RawSubject)}, wantErr: "TSA name"},
		{name: "tsa = signer subject with one letter changed", tst: tstSpec{tsa: directoryName(t, typo)}, wantErr: "TSA name"},
		{name: "tsa = signer subject with RDNs reordered", tst: tstSpec{tsa: directoryName(t, reordered)}, wantErr: "TSA name"},
		{name: "tsa = issuer-like dNSName not in subjectAltName", tst: tstSpec{tsa: dnsGeneralName(t, "timestamp.digicert.com")}, wantErr: "TSA name"},
		{name: "tsa = two GeneralNames", tst: tstSpec{tsa: append(directoryName(t, subject), dnsGeneralName(t, "tsa.example.test")...)}, wantErr: "TSA name"},
		{name: "tsa = garbage", tst: tstSpec{tsa: []byte{0xff}}, wantErr: "TSA name"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tst := tt.tst
			tst.imprint, tst.nonce = digest, big.NewInt(99)
			der := signTST(t, tsa, tst.encode(t))
			info, err := VerifyToken(der, digest, poolOf(tsa.cert))
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("VerifyToken: %v", err)
				}
				if !info.ChainOK || info.Nonce != "63" || info.TSAName != tsa.cert.Subject.String() {
					t.Errorf("info = %+v", info)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("err = %v, want containing %q", err, tt.wantErr)
			}
			if info != (contracts.TokenInfo{}) {
				t.Errorf("info %+v returned with an error", info)
			}
		})
	}
}

// TestVerifyTokenTSANameRealVector: FreeTSA's tokens carry a tsa field; it must keep verifying.
func TestVerifyTokenTSANameRealVector(t *testing.T) {
	digest := vectorDigest(t)
	der := readVector(t, "freetsa.tsr")
	v := mustCore(t, der, digest)
	p7, err := pkcs7.Parse(tokenOf(t, der))
	if err != nil {
		t.Fatal(err)
	}
	var inf tstInfo
	if _, err := asn1.Unmarshal(p7.Content, &inf); err != nil {
		t.Fatal(err)
	}
	if len(inf.TSA.FullBytes) == 0 {
		t.Fatal("expected a tsa field in the FreeTSA token")
	}
	if err := checkTSAName(inf.TSA.Bytes, v.signer); err != nil {
		t.Errorf("checkTSAName(FreeTSA): %v", err)
	}
	// The same field does not name DigiCert's signer.
	dc := mustCore(t, readVector(t, "digicert.tsr"), digest)
	if err := checkTSAName(inf.TSA.Bytes, dc.signer); err == nil {
		t.Error("FreeTSA's tsa name accepted for DigiCert's signer")
	}
}

// ------------------------------------------------------------------ ESS issuerSerial

// essV2WithIssuerSerial builds a signingCertificateV2 attribute whose ESSCertIDv2 carries the
// right certificate hash plus the given issuerSerial DER.
func essV2WithIssuerSerial(t testing.TB, cert *x509.Certificate, issuerSerial []byte) pkcs7.Attribute {
	t.Helper()
	a := essV2Attr(t, cert, 0, nil)
	var sc signingCertificateV2
	if _, err := asn1.Unmarshal(a.Value.(asn1.RawValue).FullBytes, &sc); err != nil {
		t.Fatal(err)
	}
	sc.Certs[0].IssuerSerial = asn1.RawValue{FullBytes: issuerSerial}
	return pkcs7.Attribute{Type: oidSigningCertificateV2, Value: asn1.RawValue{FullBytes: mustMarshal(t, sc)}}
}

// essV1WithIssuerSerial is the signingCertificate (SHA-1) variant.
func essV1WithIssuerSerial(t testing.TB, cert *x509.Certificate, issuerSerial []byte) pkcs7.Attribute {
	t.Helper()
	a := essV1Attr(t, cert)
	var sc signingCertificate
	if _, err := asn1.Unmarshal(a.Value.(asn1.RawValue).FullBytes, &sc); err != nil {
		t.Fatal(err)
	}
	sc.Certs[0].IssuerSerial = asn1.RawValue{FullBytes: issuerSerial}
	return pkcs7.Attribute{Type: oidSigningCertificate, Value: asn1.RawValue{FullBytes: mustMarshal(t, sc)}}
}

// TestVerifyTokenESSIssuerSerial: when an ESSCertID carries issuerSerial, `openssl ts -verify`
// requires it to name the signer certificate's issuer and serial number as well.
func TestVerifyTokenESSIssuerSerial(t *testing.T) {
	digest := randomDigest(t)
	root := newCert(t, caSpec("ESS Root"), nil)
	tsa := newCert(t, tsaSpec(t, "ESS TSA"), &root)
	other := newCert(t, caSpec("Other Root"), nil)
	tst := tstSpec{imprint: digest, nonce: big.NewInt(1)}.encode(t)
	is := func(names [][]byte, serial *big.Int) []byte {
		return derSeq(t, derSeq(t, names...), mustMarshal(t, serial))
	}
	issuer := directoryName(t, tsa.cert.RawIssuer)
	issuerLoud := directoryName(t, reencodeName(t, tsa.cert.RawIssuer, strings.ToUpper))
	serial := tsa.cert.SerialNumber
	wrongSerial := new(big.Int).Add(serial, big.NewInt(1))

	tests := []struct {
		name    string
		attr    pkcs7.Attribute
		wantErr string
	}{
		{"v2 issuerSerial matches", essV2WithIssuerSerial(t, tsa.cert, is([][]byte{issuer}, serial)), ""},
		{"v2 issuerSerial matches canonically", essV2WithIssuerSerial(t, tsa.cert, is([][]byte{issuerLoud}, serial)), ""},
		{"v1 issuerSerial matches", essV1WithIssuerSerial(t, tsa.cert, is([][]byte{issuer}, serial)), ""},
		{"v2 wrong serial", essV2WithIssuerSerial(t, tsa.cert, is([][]byte{issuer}, wrongSerial)), "issuer/serial"},
		{"v2 wrong issuer", essV2WithIssuerSerial(t, tsa.cert, is([][]byte{directoryName(t, other.cert.RawSubject)}, serial)), "issuer/serial"},
		{"v2 issuer is a dNSName", essV2WithIssuerSerial(t, tsa.cert, is([][]byte{dnsGeneralName(t, "ess.example")}, serial)), "issuer/serial"},
		{"v2 two issuer names", essV2WithIssuerSerial(t, tsa.cert, is([][]byte{issuer, issuer}, serial)), "issuer/serial"},
		{"v2 malformed issuerSerial", essV2WithIssuerSerial(t, tsa.cert, mustMarshal(t, 7)), "issuer/serial"},
		{"v1 wrong serial", essV1WithIssuerSerial(t, tsa.cert, is([][]byte{issuer}, wrongSerial)), "issuer/serial"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			der := signTST(t, tsa, tst, tt.attr)
			info, err := VerifyToken(der, digest, poolOf(root.cert))
			if tt.wantErr == "" {
				if err != nil || !info.ChainOK {
					t.Fatalf("VerifyToken = %+v, %v", info, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("err = %v, want containing %q", err, tt.wantErr)
			}
		})
	}
}

// ------------------------------------------------------------------ name comparison

func TestNameEqual(t *testing.T) {
	tsa := newCert(t, certSpec{cn: "Name  Test", ca: true}, nil)
	raw := tsa.cert.RawSubject
	same := func(s string) string { return s }
	tests := []struct {
		name string
		b    []byte
		want bool
	}{
		{"identical bytes", raw, true},
		{"UTF8String re-encoding", reencodeName(t, raw, same), true},
		{"ASCII case", reencodeName(t, raw, strings.ToLower), true},
		{"leading/trailing/internal whitespace", reencodeName(t, raw, func(s string) string { return "\t " + strings.ReplaceAll(s, " ", " \n ") + "  " }), true},
		{"different text", reencodeName(t, raw, func(s string) string { return s + "x" }), false},
		{"not a name", []byte{0x05, 0x00}, false},
		{"empty", nil, false},
	}
	for _, tt := range tests {
		if got := nameEqual(raw, tt.b); got != tt.want {
			t.Errorf("%s: nameEqual = %v, want %v", tt.name, got, tt.want)
		}
		if got := nameEqual(tt.b, raw); got != tt.want {
			t.Errorf("%s (swapped): nameEqual = %v, want %v", tt.name, got, tt.want)
		}
	}
	// Non-ASCII case folding stays significant even in both operands.
	a := reencodeName(t, raw, func(s string) string { return s + "Ä" })
	b := reencodeName(t, raw, func(s string) string { return s + "ä" })
	if nameEqual(a, b) {
		t.Error("non-ASCII letters folded")
	}
}

// ------------------------------------------------------------------ HTTP exchange

// TestClientRejectsBareTokenReply: RFC 3161 §3.4 replies are TimeStampResp, and the contract
// stores Token as "DER TimeStampResp as received" — the form `openssl ts -verify -in` and the
// bundle verifier expect. A bare token over HTTP must be an error, not an anchor.
func TestClientRejectsBareTokenReply(t *testing.T) {
	tsa := newCert(t, tsaSpec(t, "Fake TSA"), nil)
	f := &fakeTSA{signer: tsa, tamper: func(resp []byte) []byte {
		tok, _, err := extractToken(resp)
		if err != nil {
			panic(err)
		}
		return tok
	}}
	c := New(Options{URLs: []string{serve(t, f).URL}, Roots: poolOf(tsa.cert)})
	r := c.Timestamp(context.Background(), randomDigest(t))[0]
	if r.Err == nil {
		t.Fatalf("bare token accepted as a TimeStampResp (Token %d bytes)", len(r.Token))
	}
	if !strings.Contains(r.Err.Error(), "TimeStampResp") || r.Token != nil {
		t.Errorf("Err = %v, Token %d bytes", r.Err, len(r.Token))
	}
	// The same bytes remain acceptable to VerifyToken (stored bare tokens, other tools).
	if _, err := VerifyToken(f.replies()[0], f.lastImprint(t), poolOf(tsa.cert)); err != nil {
		t.Errorf("VerifyToken(bare token) = %v", err)
	}
}

// lastImprint returns the imprint of the last request the fake TSA received.
func (f *fakeTSA) lastImprint(t testing.TB) []byte {
	t.Helper()
	reqs := f.requests()
	if len(reqs) == 0 {
		t.Fatal("no request")
	}
	var req struct {
		Version        int
		MessageImprint struct {
			Alg    asn1.RawValue
			Digest []byte
		}
	}
	if _, err := asn1.Unmarshal(reqs[len(reqs)-1].body, &req); err != nil {
		t.Fatal(err)
	}
	return req.MessageImprint.Digest
}

// rawHTTPServer answers every connection with the given raw bytes.
func rawHTTPServer(t testing.TB, reply string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(5 * time.Second))
				// Read the request head and body (small) before answering.
				buf := make([]byte, 64<<10)
				n := 0
				for n < len(buf) {
					m, err := conn.Read(buf[n:])
					n += m
					if err != nil || bytes.Contains(buf[:n], []byte("\r\n\r\n")) && n > 100 {
						break
					}
				}
				io.WriteString(conn, reply)
			}()
		}
	}()
	return "http://" + ln.Addr().String() + "/tsr"
}

// TestClientHTTPStatusSanitized: Go's client accepts any bytes except CR/LF in the reason
// phrase. Server-controlled text must not reach errors/logs/consoles raw (terminal escapes).
func TestClientHTTPStatusSanitized(t *testing.T) {
	hostile := rawHTTPServer(t, "HTTP/1.1 500 \x1b[2J\x1b[31mEVIL\x07"+strings.Repeat("A", 400)+"\r\n"+
		"Content-Type: text/plain\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
	plain := rawHTTPServer(t, "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
	c := New(Options{URLs: []string{hostile, plain}, Timeout: 5 * time.Second})
	res := c.Timestamp(context.Background(), randomDigest(t))
	for i, r := range res {
		if r.Err == nil {
			t.Fatalf("result %d succeeded", i)
		}
		msg := r.Err.Error()
		if strings.IndexFunc(msg, func(r rune) bool { return r < 0x20 || r == 0x7f || !unicode.IsPrint(r) }) >= 0 {
			t.Errorf("result %d: control characters in the error: %q", i, msg)
		}
		if !strings.Contains(msg, "HTTP 50") || len(msg) > 400 {
			t.Errorf("result %d: err = %q", i, msg)
		}
	}
	if msg := res[1].Err.Error(); !strings.Contains(msg, "HTTP 503 Service Unavailable") {
		t.Errorf("plain status mangled: %q", msg)
	}
}

// TestTSANameIsPrintable: TSAName comes from a certificate inside the token, i.e. from whoever
// made the token. Go's RFC 2253 rendering escapes ',' '+' etc. but not control characters, and
// the name is printed by `att-monitor verify` and `verify-bundle`. Names of real CAs are
// unchanged; control characters and invalid UTF-8 are escaped.
func TestTSANameIsPrintable(t *testing.T) {
	// Invisible characters are spelled out here (rlo = U+202E RIGHT-TO-LEFT OVERRIDE, zwsp =
	// U+200B ZERO WIDTH SPACE) instead of appearing in the source; bs is one backslash.
	rlo, zwsp, bs := string(rune(0x202e)), string(rune(0x200b)), `\`
	digest := randomDigest(t)
	hostile := newCert(t, tsaSpec(t, "Evil\x1b[2J\x1b]0;pwned\x07\nTSA\t"+rlo), nil)
	der := tokenSpec{signer: hostile, imprint: digest, nonce: big.NewInt(5)}.mustSign(t)
	info, err := VerifyToken(der, digest, poolOf(hostile.cert))
	if err != nil {
		t.Fatal(err)
	}
	if strings.IndexFunc(info.TSAName, func(r rune) bool { return !unicode.IsPrint(r) }) >= 0 {
		t.Errorf("TSAName carries control characters: %q", info.TSAName)
	}
	for _, want := range []string{`Evil\x1b[2J`, `pwned\x07\x0aTSA\x09` + bs + "u202e", "O=att-monitor tests"} {
		if !strings.Contains(info.TSAName, want) {
			t.Errorf("TSAName %q lacks %q", info.TSAName, want)
		}
	}

	tests := []struct{ in, want string }{
		{`CN=DigiCert SHA256 RSA4096 Timestamp Responder 2026 1,O=DigiCert\, Inc.,C=US`, `CN=DigiCert SHA256 RSA4096 Timestamp Responder 2026 1,O=DigiCert\, Inc.,C=US`},
		{"CN=Würzburg  Ünïcödé", "CN=Würzburg  Ünïcödé"},
		{"a\tb", `a\x09b`},
		{"\xff\xfeT61", `\xff\xfeT61`},
		{"zero\x00width" + zwsp, `zero\x00width` + bs + "u200b"},
		{"astral " + string(rune(0xe0001)), "astral " + bs + "U000e0001"},
		{"", ""},
	}
	for _, tt := range tests {
		if got := printable(tt.in); got != tt.want {
			t.Errorf("printable(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// TestErrorsAreOneLine: dependency errors (e.g. pkcs7's multi-line message-digest mismatch)
// end up in verification reports and CLI output; they must stay on one line.
func TestErrorsAreOneLine(t *testing.T) {
	digest := vectorDigest(t)
	for _, file := range []string{"digicert.tsr", "freetsa.tsr"} {
		der := readVector(t, file)
		tst := tstInfoOf(t, der)
		off := uniqueIndex(t, der, tst) + len(tst) - 1 // last byte of the signed TSTInfo
		_, err := VerifyToken(flip(der, off, 0x01), digest, nil)
		if err == nil {
			t.Fatalf("%s: tampered TSTInfo verified", file)
		}
		if strings.ContainsAny(err.Error(), "\n\r\t") {
			t.Errorf("%s: multi-line error %q", file, err)
		}
		var mdErr *pkcs7.MessageDigestMismatchError
		if !errors.As(err, &mdErr) {
			t.Errorf("%s: the dependency's error is no longer wrapped: %v", file, err)
		}
	}
}

// ------------------------------------------------------------------ fuzzing the new parsers

// FuzzCheckEnvelope: the structural check runs on untrusted bytes before any signature check.
// It must never panic, and must accept the genuine responses and tokens.
func FuzzCheckEnvelope(f *testing.F) {
	for _, file := range []string{"digicert.tsr", "freetsa.tsr"} {
		der := readVector(f, file)
		if err := checkEnvelope(der, false); err != nil {
			f.Fatalf("%s: %v", file, err)
		}
		tok := tokenOf(f, der)
		if err := checkEnvelope(tok, true); err != nil {
			f.Fatalf("%s token: %v", file, err)
		}
		f.Add(der, false)
		f.Add(tok, true)
	}
	f.Add([]byte{0x30, 0x00}, false)
	f.Add([]byte{0x30, 0x03, 0x02, 0x01, 0x00}, false)
	f.Fuzz(func(t *testing.T, der []byte, bare bool) {
		err1 := checkEnvelope(der, bare)
		err2 := checkEnvelope(der, bare)
		if (err1 == nil) != (err2 == nil) {
			t.Fatal("non-deterministic")
		}
		if err1 != nil && strings.ContainsAny(err1.Error(), "\n\r") {
			t.Fatalf("multi-line error %q", err1)
		}
	})
}

// FuzzNameEqual: name comparison runs on certificate and token contents. It must never panic,
// must be symmetric, and every parseable name must equal itself.
func FuzzNameEqual(f *testing.F) {
	for _, file := range []string{"digicert.tsr", "freetsa.tsr"} {
		for _, c := range certsOf(f, readVector(f, file)) {
			f.Add(c.RawSubject, c.RawIssuer)
			f.Add(c.RawSubject, reencodeName(f, c.RawSubject, strings.ToUpper))
		}
	}
	f.Add([]byte{0x30, 0x00}, []byte{0x30, 0x00})
	f.Fuzz(func(t *testing.T, a, b []byte) {
		if nameEqual(a, b) != nameEqual(b, a) {
			t.Fatalf("not symmetric: %x vs %x", a, b)
		}
		if _, ok := canonicalName(a); ok && !nameEqual(a, a) {
			t.Fatalf("not reflexive: %x", a)
		}
		cert := &x509.Certificate{RawSubject: a, RawIssuer: b, SerialNumber: big.NewInt(1)}
		_ = checkTSAName(b, cert)
		_ = checkIssuerSerial(asn1.RawValue{FullBytes: b}, cert, "fuzz")
	})
}

// FuzzPrintable: the output is always printable, printable input is unchanged, and escaping
// is idempotent.
func FuzzPrintable(f *testing.F) {
	f.Add("CN=DigiCert SHA256 RSA4096 Timestamp Responder 2026 1")
	f.Add("Evil\x1b[2J\x07\n\t\xff")
	f.Fuzz(func(t *testing.T, s string) {
		p := printable(s)
		if strings.IndexFunc(p, func(r rune) bool { return !unicode.IsPrint(r) }) >= 0 || !utf8.ValidString(p) {
			t.Fatalf("printable(%q) = %q", s, p)
		}
		if printable(p) != p {
			t.Fatalf("not idempotent: %q", p)
		}
		if utf8.ValidString(s) && strings.IndexFunc(s, func(r rune) bool { return !unicode.IsPrint(r) }) < 0 && p != s {
			t.Fatalf("printable input changed: %q → %q", s, p)
		}
	})
}

// BenchmarkVerifyToken measures re-verification cost (the ledger re-verifies every stored
// token): parsing, structural check, CMS signature, ESS/TSTInfo checks and the chain.
func BenchmarkVerifyToken(b *testing.B) {
	digest := vectorDigest(b)
	for _, file := range []string{"digicert.tsr", "freetsa.tsr"} {
		der := readVector(b, file)
		b.Run(file, func(b *testing.B) {
			for b.Loop() {
				if _, err := VerifyToken(der, digest, nil); err != nil {
					b.Fatal(err)
				}
			}
		})
		b.Run(file+"/structure-only", func(b *testing.B) {
			for b.Loop() {
				if err := checkEnvelope(der, false); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// ------------------------------------------------------------------ self-contained chains

// TestChainMustBeSelfContained: the token's certificate set is not signed, so certificates can
// be removed or damaged on the way from a plain-HTTP TSA without invalidating the token. With
// the Windows root store, the platform chain engine then completes the chain from its own
// certificate stores (or AIA downloads) and reported ChainOK = true — yet a third party, who
// has only the token and the root (`openssl ts -verify -CAfile`), cannot verify it.
func TestChainMustBeSelfContained(t *testing.T) {
	digest := vectorDigest(t)
	dcCerts := certsOf(t, readVector(t, "digicert.tsr"))
	var crossG4 *x509.Certificate
	for _, c := range dcCerts {
		if c.Subject.CommonName == "DigiCert Trusted Root G4" {
			crossG4 = c
		}
	}
	if crossG4 == nil {
		t.Fatal("cross-signed G4 not found")
	}
	removeCert := func(i int) func(*testing.T, *derNode) {
		return func(t *testing.T, n *derNode) {
			set := n.at(pathCerts...)
			set.kids = slices.Delete(set.kids, i, i+1)
		}
	}
	// Index of the DigiCert intermediate ("… TimeStamping … CA1") in the certificate set.
	inter := slices.IndexFunc(dcCerts, func(c *x509.Certificate) bool {
		return c.IsCA && strings.Contains(c.Subject.CommonName, "TimeStamping")
	})
	if inter < 0 {
		t.Fatal("DigiCert intermediate not found")
	}
	crossIdx := slices.IndexFunc(dcCerts, func(c *x509.Certificate) bool { return c.Equal(crossG4) })
	tests := []struct {
		name  string
		file  string
		edit  func(*testing.T, *derNode)
		roots *x509.CertPool
		want  bool
	}{
		{"DigiCert intermediate removed, system roots", "digicert.tsr", removeCert(inter), nil, false},
		{"DigiCert intermediate signature damaged, system roots", "digicert.tsr", func(t *testing.T, n *derNode) {
			sig := n.at(slices.Concat(pathCerts, []int{inter, 2})...)
			sig.content[len(sig.content)-1] ^= 0x01
		}, nil, false},
		{"DigiCert intermediate removed, cross root trusted", "digicert.tsr", removeCert(inter), poolOf(crossG4), false},
		{"DigiCert cross certificate removed, cross root trusted", "digicert.tsr", removeCert(crossIdx), poolOf(crossG4), true},
		{"DigiCert unchanged, cross root trusted", "digicert.tsr", func(*testing.T, *derNode) {}, poolOf(crossG4), true},
		{"FreeTSA root copy removed (embedded root)", "freetsa.tsr", removeCert(1), nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := parseDER(t, readVector(t, tt.file))
			tt.edit(t, n)
			info, err := VerifyToken(n.encode(t), digest, tt.roots)
			if err != nil {
				t.Fatalf("VerifyToken: %v (the certificate set is unsigned: the token stays genuine)", err)
			}
			v := mustCore(t, n.encode(t), digest)
			if info.ChainOK != tt.want {
				_, why := chainVerify(v.signer, v.certs, info.GenTime, tt.roots)
				t.Errorf("ChainOK = %v, want %v (%v)", info.ChainOK, tt.want, why)
			}
			if info.ChainOK {
				if info.ChainNote != "" {
					t.Errorf("ChainNote = %q with ChainOK", info.ChainNote)
				}
				return
			}
			// ChainNote names every source and why it failed. Whether the platform completes the
			// chain from its own stores (which the token then cannot back up) or finds no chain
			// at all depends on this machine, so ask it.
			t.Logf("ChainNote: %s", info.ChainNote)
			extra, system := "none", "x509: "
			if tt.roots != nil {
				extra = unknownCA
			}
			if platformFindsChain(t, v) {
				system = "chain needs certificates not in the token (x509: "
			}
			checkNoteForm(t, info.ChainNote, defaultLabels...)
			checkNoteHas(t, info.ChainNote, "embedded FreeTSA root: "+unknownCA, "; extra roots: "+extra, "; system roots: "+system)
		})
	}
}

// platformFindsChain reports whether the system roots' verifier (on Windows the platform chain
// engine) finds a chain for the token's signer, possibly with certificates the token lacks.
func platformFindsChain(t *testing.T, v *verified) bool {
	t.Helper()
	sys, err := x509.SystemCertPool()
	if err != nil {
		t.Fatalf("system roots: %v", err)
	}
	inter := x509.NewCertPool()
	for _, c := range v.certs {
		if !c.Equal(v.signer) {
			inter.AddCert(c)
		}
	}
	_, err = v.signer.Verify(x509.VerifyOptions{Roots: sys, Intermediates: inter,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping}, CurrentTime: v.info.GenTime})
	return err == nil
}

// TestSelfContained covers the decision on chains as the platform verifier may return them.
func TestSelfContained(t *testing.T) {
	root := newCert(t, caSpec("SC Root"), nil)
	inter := newCert(t, caSpec("SC Intermediate"), &root)
	leaf := newCert(t, tsaSpec(t, "SC TSA"), &inter)
	// The same intermediate re-issued: same subject and key, different certificate bytes.
	reissued := keyCert{key: inter.key}
	{
		tmpl := *inter.cert
		tmpl.SerialNumber = big.NewInt(424242)
		der, err := x509.CreateCertificate(rand.Reader, &tmpl, root.cert, inter.key.Public(), root.key)
		if err != nil {
			t.Fatal(err)
		}
		if reissued.cert, err = x509.ParseCertificate(der); err != nil {
			t.Fatal(err)
		}
	}
	stranger := newCert(t, caSpec("SC Stranger"), &root)
	opts := func(token ...*x509.Certificate) x509.VerifyOptions {
		return x509.VerifyOptions{Intermediates: poolOf(token...), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping}}
	}
	tests := []struct {
		name   string
		token  []*x509.Certificate // certificates in the token (besides the signer)
		chains [][]*x509.Certificate
		ok     bool
	}{
		{"intermediate from the token", []*x509.Certificate{inter.cert}, [][]*x509.Certificate{{leaf.cert, inter.cert, root.cert}}, true},
		{"signer is the root", nil, [][]*x509.Certificate{{leaf.cert}}, true},
		{"signer issued by the root", nil, [][]*x509.Certificate{{leaf.cert, root.cert}}, true},
		{"platform used its own copy; token carries another valid one", []*x509.Certificate{inter.cert}, [][]*x509.Certificate{{leaf.cert, reissued.cert, root.cert}}, true},
		{"platform supplied the missing intermediate", nil, [][]*x509.Certificate{{leaf.cert, inter.cert, root.cert}}, false},
		{"token carries an unrelated certificate only", []*x509.Certificate{stranger.cert}, [][]*x509.Certificate{{leaf.cert, inter.cert, root.cert}}, false},
		{"second chain is self-contained", []*x509.Certificate{inter.cert}, [][]*x509.Certificate{{leaf.cert, reissued.cert, stranger.cert}, {leaf.cert, inter.cert, root.cert}}, true},
		{"no chains", []*x509.Certificate{inter.cert}, nil, false},
		{"empty chain", []*x509.Certificate{inter.cert}, [][]*x509.Certificate{{}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := selfContained(leaf.cert, append([]*x509.Certificate{leaf.cert}, tt.token...), tt.chains, opts(tt.token...))
			if (err == nil) != tt.ok {
				t.Errorf("selfContained = %v, want ok=%v", err, tt.ok)
			}
		})
	}
}
