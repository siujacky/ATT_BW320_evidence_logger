package anchor

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"slices"
	"strconv"
	"strings"
	"unicode/utf16"
)

// Name matching for the TSTInfo tsa field and the ESS issuerSerial. Both are checked by
// `openssl ts -verify`, the tool third parties use on evidence bundles; the comparison follows
// OpenSSL's X509_NAME_cmp canonical form so that the two verifiers agree on every token:
// string values are compared after ASCII lower-casing and whitespace normalisation, whatever
// their ASN.1 string type, while RDN order and all other values must match exactly.

var oidSubjectAltName = asn1.ObjectIdentifier{2, 5, 29, 17}

// ASN.1 universal string tags without constants in encoding/asn1.
const (
	tagVisibleString   = 26
	tagUniversalString = 28
)

// isDirectoryName reports whether gn is the GeneralName choice directoryName ([4] EXPLICIT Name).
func isDirectoryName(gn asn1.RawValue) bool {
	return gn.Class == asn1.ClassContextSpecific && gn.Tag == 4 && gn.IsCompound
}

// checkTSAName applies RFC 3161 §2.4.2 to the optional tsa field of TSTInfo (gn is its DER
// GeneralName): it "MUST correspond to one of the subject names included in the certificate
// that is to be used to verify the token" — the subject (as a directoryName) or one of the
// subjectAltNames.
func checkTSAName(gn []byte, signer *x509.Certificate) error {
	var name asn1.RawValue
	if rest, err := asn1.Unmarshal(gn, &name); err == nil && len(rest) == 0 {
		if isDirectoryName(name) && nameEqual(name.Bytes, signer.RawSubject) {
			return nil
		}
		if subjectAltNamesContain(signer, name) {
			return nil
		}
	}
	return errors.New("anchor: the TSA name in the token does not name the certificate that signed it (RFC 3161 §2.4.2)")
}

// subjectAltNamesContain reports whether cert's subjectAltName extension lists gn.
func subjectAltNamesContain(cert *x509.Certificate, gn asn1.RawValue) bool {
	for _, ext := range cert.Extensions {
		if !ext.Id.Equal(oidSubjectAltName) {
			continue
		}
		var names []asn1.RawValue
		if rest, err := asn1.Unmarshal(ext.Value, &names); err != nil || len(rest) != 0 {
			return false
		}
		for _, n := range names {
			if bytes.Equal(n.FullBytes, gn.FullBytes) ||
				isDirectoryName(n) && isDirectoryName(gn) && nameEqual(n.Bytes, gn.Bytes) {
				return true
			}
		}
	}
	return false
}

// nameEqual reports whether two DER-encoded X.501 Names are equal: byte-identical, or equal in
// OpenSSL's canonical form.
func nameEqual(a, b []byte) bool {
	if len(a) > 0 && bytes.Equal(a, b) {
		return true
	}
	ca, ok := canonicalName(a)
	if !ok {
		return false
	}
	cb, ok := canonicalName(b)
	return ok && ca == cb
}

// nameAVA and nameRDNSET decode a Name keeping each attribute value raw (encoding/asn1 decodes
// a slice type whose name ends in SET as SET OF).
type nameAVA struct {
	Type  asn1.ObjectIdentifier
	Value asn1.RawValue
}

type nameRDNSET []nameAVA

// canonicalName renders a DER Name as an unambiguous string: RDNs in order, the attributes of
// each RDN sorted (an RDN is a SET), each value canonicalised by canonicalValue.
func canonicalName(der []byte) (string, bool) {
	var rdns []nameRDNSET
	if rest, err := asn1.Unmarshal(der, &rdns); err != nil || len(rest) != 0 {
		return "", false
	}
	var b strings.Builder
	for _, rdn := range rdns {
		keys := make([]string, len(rdn))
		for i, ava := range rdn {
			keys[i] = strconv.Quote(ava.Type.String() + "=" + canonicalValue(ava.Value))
		}
		slices.Sort(keys)
		b.WriteString("{" + strings.Join(keys, ",") + "}")
	}
	return b.String(), true
}

// canonicalValue returns "s:" + the canonical text of a string value of one of the types
// OpenSSL canonicalises (UTF8String, BMPString, UniversalString, PrintableString, T61String,
// IA5String, VisibleString), and "r:" + the hex DER of any other value.
func canonicalValue(v asn1.RawValue) string {
	if v.Class == asn1.ClassUniversal && !v.IsCompound {
		if s, ok := decodeString(v); ok {
			return "s:" + canonicalString(s)
		}
	}
	return "r:" + hex.EncodeToString(v.FullBytes)
}

// decodeString decodes the canonicalisable string types to UTF-8.
func decodeString(v asn1.RawValue) (string, bool) {
	switch v.Tag {
	case asn1.TagUTF8String, asn1.TagPrintableString, asn1.TagIA5String, asn1.TagBMPString:
		var s string
		if _, err := asn1.Unmarshal(v.FullBytes, &s); err != nil {
			return "", false
		}
		return s, true
	case asn1.TagT61String: // OpenSSL reads T61String as Latin-1
		r := make([]rune, len(v.Bytes))
		for i, c := range v.Bytes {
			r[i] = rune(c)
		}
		return string(r), true
	case tagVisibleString:
		for _, c := range v.Bytes {
			if c < 0x20 || c > 0x7e {
				return "", false
			}
		}
		return string(v.Bytes), true
	case tagUniversalString: // UCS-4 big-endian
		if len(v.Bytes)%4 != 0 {
			return "", false
		}
		r := make([]rune, 0, len(v.Bytes)/4)
		for i := 0; i < len(v.Bytes); i += 4 {
			c := rune(v.Bytes[i])<<24 | rune(v.Bytes[i+1])<<16 | rune(v.Bytes[i+2])<<8 | rune(v.Bytes[i+3])
			if c < 0 || c > 0x10ffff || utf16.IsSurrogate(c) {
				return "", false
			}
			r = append(r, c)
		}
		return string(r), true
	}
	return "", false
}

// canonicalString applies OpenSSL's string canonicalisation: leading and trailing ASCII
// whitespace removed, inner runs collapsed to one space, ASCII letters lower-cased. Other
// characters are kept as they are (no Unicode case folding).
func canonicalString(s string) string {
	var b strings.Builder
	pendingSpace := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case ' ', '\t', '\n', '\v', '\f', '\r':
			pendingSpace = b.Len() > 0
			continue
		}
		if pendingSpace {
			b.WriteByte(' ')
			pendingSpace = false
		}
		if 'A' <= c && c <= 'Z' {
			c += 'a' - 'A'
		}
		b.WriteByte(c)
	}
	return b.String()
}
