package anchor

import (
	"encoding/asn1"
	"errors"
	"fmt"
)

// Structural check of a time-stamp response or token (RFC 3161 §2.4.2 TimeStampResp and
// TSTInfo, RFC 5652 ContentInfo/SignedData/SignerInfo).
//
// Why: Go's encoding/asn1 silently ignores elements appended to a SEQUENCE, x509 tolerates an
// element after a certificate's signature, and the CMS library verifies the signature over a
// re-encoding of the parsed signed attributes. So bytes can be added to the unsigned envelope
// of a genuine token — by anyone on the path to a plain-HTTP TSA — and the token still
// verifies here, while OpenSSL, whose template decoder accepts only the defined components,
// rejects it ("sequence length mismatch"). Such a token would be recorded as a valid anchor
// and fail the third-party check of an evidence bundle (`openssl ts -verify`). The check below
// accepts exactly the defined components, in order, in strict DER, so the two verifiers agree.
// Embedded certificates get the same treatment down to the TBSCertificate components, because
// a certificate carried in the token but not on the chain is checked by nobody yet still parsed
// by OpenSSL. Values whose meaning is verified elsewhere (attribute values, extension values,
// algorithm parameters, the values of the TSTInfo fields) are not descended into.

// shape checks one DER element.
type shape func(v asn1.RawValue) error

// component describes one element of a constructed value.
type component struct {
	name         string
	any          bool        // matches any single element
	anyUniversal bool        // matches any universal-class element
	alts         []component // a CHOICE: matches if one alternative matches
	class        int
	tag          int
	compound     bool
	optional     bool
	check        shape // nil: content not inspected
}

func universal(tag int, name string, check shape) component {
	return component{name: name, class: asn1.ClassUniversal, tag: tag, check: check,
		compound: tag == asn1.TagSequence || tag == asn1.TagSet}
}

// tagged describes a context-specific component ([n]); compound for EXPLICIT tags and
// IMPLICIT SET/SEQUENCE types.
func tagged(tag int, compound bool, name string, check shape) component {
	return component{name: name, class: asn1.ClassContextSpecific, tag: tag, compound: compound, check: check}
}

func anyElement(name string) component { return component{name: name, any: true} }

func choice(name string, alts ...component) component { return component{name: name, alts: alts} }

func (c component) opt() component { c.optional = true; return c }

func (c component) matches(v asn1.RawValue) bool {
	switch {
	case c.any:
		return true
	case c.anyUniversal:
		return v.Class == asn1.ClassUniversal
	case c.alts != nil:
		for _, a := range c.alts {
			if a.matches(v) {
				return true
			}
		}
		return false
	}
	return v.Class == c.class && v.Tag == c.tag && v.IsCompound == c.compound
}

func (c component) validate(v asn1.RawValue) error {
	for _, a := range c.alts {
		if a.matches(v) {
			c = a
			break
		}
	}
	if c.check == nil {
		return nil
	}
	if err := c.check(v); err != nil {
		return fmt.Errorf("%s: %w", c.name, err)
	}
	return nil
}

// bitStringContent accepts a BIT STRING's content as OpenSSL does: an unused-bits count of at
// most 7, and 0 when there are no content bits.
func bitStringContent(v asn1.RawValue) error {
	if len(v.Bytes) == 0 || v.Bytes[0] > 7 || len(v.Bytes) == 1 && v.Bytes[0] != 0 {
		return errors.New("invalid BIT STRING")
	}
	return nil
}

func bitString(name string) component { return universal(asn1.TagBitString, name, bitStringContent) }

// derChildren returns the elements inside a constructed DER value.
func derChildren(v asn1.RawValue) ([]asn1.RawValue, error) {
	if !v.IsCompound {
		return nil, errors.New("not a constructed value")
	}
	var kids []asn1.RawValue
	for b := v.Bytes; len(b) > 0; {
		var k asn1.RawValue
		rest, err := asn1.Unmarshal(b, &k)
		if err != nil {
			return nil, fmt.Errorf("not DER: %v", err)
		}
		kids = append(kids, k)
		b = rest
	}
	return kids, nil
}

// sequence accepts the components in order (optional ones may be absent) and nothing else.
func sequence(comps ...component) shape {
	return func(v asn1.RawValue) error {
		kids, err := derChildren(v)
		if err != nil {
			return err
		}
		i := 0
		for _, c := range comps {
			if i < len(kids) && c.matches(kids[i]) {
				if err := c.validate(kids[i]); err != nil {
					return err
				}
				i++
			} else if !c.optional {
				return fmt.Errorf("%s missing", c.name)
			}
		}
		if i < len(kids) {
			return fmt.Errorf("unexpected element (class %d, tag %d) after the defined components", kids[i].Class, kids[i].Tag)
		}
		return nil
	}
}

// listOf accepts a SET OF / SEQUENCE OF whose every element matches elem.
func listOf(elem component) shape {
	return func(v asn1.RawValue) error {
		kids, err := derChildren(v)
		if err != nil {
			return err
		}
		for i, k := range kids {
			if !elem.matches(k) {
				return fmt.Errorf("element %d is not a %s", i, elem.name)
			}
			if err := elem.validate(k); err != nil {
				return fmt.Errorf("element %d: %w", i, err)
			}
		}
		return nil
	}
}

// encapsulated checks the DER value inside an OCTET STRING. Like OpenSSL, bytes after that
// value are not examined (they are covered by the signature anyway).
func encapsulated(c component) shape {
	return func(v asn1.RawValue) error {
		var inner asn1.RawValue
		if _, err := asn1.Unmarshal(v.Bytes, &inner); err != nil {
			return fmt.Errorf("not DER: %v", err)
		}
		if !c.matches(inner) {
			return fmt.Errorf("not a %s", c.name)
		}
		return c.validate(inner)
	}
}

// The envelope schemas. Package-level funcs (not vars) avoid initialisation-order concerns.

func algorithmIdentifier() shape {
	return sequence(universal(asn1.TagOID, "algorithm", nil), anyElement("parameters").opt())
}

// signedObject is the outer form of Certificate and CertificateList (RFC 5280).
func signedObject(tbs string, tbsShape shape) shape {
	return sequence(
		universal(asn1.TagSequence, tbs, tbsShape),
		universal(asn1.TagSequence, "signatureAlgorithm", algorithmIdentifier()),
		bitString("signature"),
	)
}

// nameShape is an X.501 Name: a SEQUENCE OF RelativeDistinguishedName (SET OF
// AttributeTypeAndValue) whose values are of universal class (OpenSSL decodes them as
// DirectoryString-like types and rejects other classes).
func nameShape() shape {
	return listOf(universal(asn1.TagSet, "RelativeDistinguishedName", listOf(
		universal(asn1.TagSequence, "AttributeTypeAndValue", sequence(
			universal(asn1.TagOID, "type", nil),
			component{name: "value", anyUniversal: true},
		)))))
}

func timeChoice(name string) component {
	return choice(name, universal(asn1.TagUTCTime, name, nil), universal(asn1.TagGeneralizedTime, name, nil))
}

// tbsCertificateShape is RFC 5280 TBSCertificate. Extension values are not descended into.
func tbsCertificateShape() shape {
	return sequence(
		tagged(0, true, "version", sequence(universal(asn1.TagInteger, "version", nil))).opt(),
		universal(asn1.TagInteger, "serialNumber", nil),
		universal(asn1.TagSequence, "signature", algorithmIdentifier()),
		universal(asn1.TagSequence, "issuer", nameShape()),
		universal(asn1.TagSequence, "validity", sequence(timeChoice("notBefore"), timeChoice("notAfter"))),
		universal(asn1.TagSequence, "subject", nameShape()),
		universal(asn1.TagSequence, "subjectPublicKeyInfo", sequence(
			universal(asn1.TagSequence, "algorithm", algorithmIdentifier()),
			bitString("subjectPublicKey"),
		)),
		tagged(1, false, "issuerUniqueID", bitStringContent).opt(),
		tagged(2, false, "subjectUniqueID", bitStringContent).opt(),
		tagged(3, true, "extensions", sequence(universal(asn1.TagSequence, "Extensions", listOf(
			universal(asn1.TagSequence, "Extension", sequence(
				universal(asn1.TagOID, "extnID", nil),
				universal(asn1.TagBoolean, "critical", nil).opt(),
				universal(asn1.TagOctetString, "extnValue", nil),
			)))))).opt(),
	)
}

func attributeSet() shape {
	return listOf(universal(asn1.TagSequence, "Attribute", sequence(
		universal(asn1.TagOID, "attrType", nil),
		universal(asn1.TagSet, "attrValues", nil),
	)))
}

func tstInfoShape() shape {
	return sequence(
		universal(asn1.TagInteger, "version", nil),
		universal(asn1.TagOID, "policy", nil),
		universal(asn1.TagSequence, "messageImprint", sequence(
			universal(asn1.TagSequence, "hashAlgorithm", algorithmIdentifier()),
			universal(asn1.TagOctetString, "hashedMessage", nil),
		)),
		universal(asn1.TagInteger, "serialNumber", nil),
		universal(asn1.TagGeneralizedTime, "genTime", nil),
		universal(asn1.TagSequence, "accuracy", sequence(
			universal(asn1.TagInteger, "seconds", nil).opt(),
			tagged(0, false, "millis", nil).opt(),
			tagged(1, false, "micros", nil).opt(),
		)).opt(),
		universal(asn1.TagBoolean, "ordering", nil).opt(),
		universal(asn1.TagInteger, "nonce", nil).opt(),
		tagged(0, true, "tsa", nil).opt(),
		tagged(1, true, "extensions", nil).opt(),
	)
}

func signerInfoShape() shape {
	return sequence(
		universal(asn1.TagInteger, "version", nil),
		universal(asn1.TagSequence, "issuerAndSerialNumber", sequence(
			universal(asn1.TagSequence, "issuer", nil),
			universal(asn1.TagInteger, "serialNumber", nil),
		)),
		universal(asn1.TagSequence, "digestAlgorithm", algorithmIdentifier()),
		tagged(0, true, "signedAttrs", attributeSet()).opt(),
		universal(asn1.TagSequence, "signatureAlgorithm", algorithmIdentifier()),
		universal(asn1.TagOctetString, "signature", nil),
		tagged(1, true, "unsignedAttrs", attributeSet()).opt(),
	)
}

// contentInfoShape is a TimeStampToken: ContentInfo { id-signedData, [0] EXPLICIT SignedData }.
func contentInfoShape() shape {
	signedData := sequence(
		universal(asn1.TagInteger, "version", nil),
		universal(asn1.TagSet, "digestAlgorithms", listOf(universal(asn1.TagSequence, "AlgorithmIdentifier", algorithmIdentifier()))),
		universal(asn1.TagSequence, "encapContentInfo", sequence(
			universal(asn1.TagOID, "eContentType", nil),
			tagged(0, true, "eContent", sequence(
				universal(asn1.TagOctetString, "OCTET STRING", encapsulated(universal(asn1.TagSequence, "TSTInfo", tstInfoShape()))),
			)).opt(),
		)),
		tagged(0, true, "certificates", listOf(universal(asn1.TagSequence, "Certificate",
			signedObject("tbsCertificate", tbsCertificateShape())))).opt(),
		tagged(1, true, "crls", listOf(universal(asn1.TagSequence, "CertificateList",
			signedObject("tbsCertList", nil)))).opt(),
		universal(asn1.TagSet, "signerInfos", listOf(universal(asn1.TagSequence, "SignerInfo", signerInfoShape()))),
	)
	return sequence(
		universal(asn1.TagOID, "contentType", nil),
		tagged(0, true, "content", sequence(universal(asn1.TagSequence, "SignedData", signedData))),
	)
}

func timeStampRespShape() shape {
	return sequence(
		universal(asn1.TagSequence, "status", sequence(
			universal(asn1.TagInteger, "status", nil),
			universal(asn1.TagSequence, "statusString", listOf(universal(asn1.TagUTF8String, "UTF8String", nil))).opt(),
			bitString("failInfo").opt(),
		)),
		universal(asn1.TagSequence, "timeStampToken", contentInfoShape()).opt(),
	)
}

// checkEnvelope checks the structure of a DER TimeStampResp, or of a bare token when bare.
func checkEnvelope(der []byte, bare bool) error {
	var v asn1.RawValue
	if _, err := asn1.Unmarshal(der, &v); err != nil {
		return fmt.Errorf("anchor: time-stamp token is not DER: %v", oneLine(err.Error()))
	}
	s, what := timeStampRespShape(), "TimeStampResp"
	if bare {
		s, what = contentInfoShape(), "TimeStampToken"
	}
	if err := s(v); err != nil {
		return fmt.Errorf("anchor: malformed %s (%s); `openssl ts -verify` rejects such tokens", what, oneLine(err.Error()))
	}
	return nil
}
