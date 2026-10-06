package mongostore

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"go.mongodb.org/mongo-driver/v2/bson"

	"attmonitor/internal/model"
)

// Collection names and the id of the replication state document.
const (
	collRecords   = "records"
	collBlobs     = "blobs"
	collIncidents = "incidents"
	collSyslog    = "syslog"
	collMeta      = "meta"
	metaID        = "replication"
)

const (
	// copyFormat versions the layout of the documents this package writes ("copy_format" in
	// record documents, "format" in meta). Verify re-derives documents of this format byte for
	// byte, so any change of layout must increase it.
	copyFormat = 1
	// maxDocBytes is MongoDB's maximum BSON document size.
	maxDocBytes = 16 << 20
	// maxBlobBytes: larger blobs are recorded without their content (16 MB document limit).
	maxBlobBytes = 15 << 20
	// maxDataDepth bounds the nesting of converted data (MongoDB refuses documents nested more
	// than 100 levels deep).
	maxDataDepth = 64
	// maxProblemLen caps one problem or error text.
	maxProblemLen = 512
)

// Notes stored in documents. They are part of the documents, which Verify re-derives and compares
// byte for byte, so they must not change within one copyFormat.
const (
	noteServerRejected = "the MongoDB server rejected the converted data, so it is kept as JSON text"
	noteDataTooLarge   = "the converted data would exceed the 16 MB MongoDB document limit; b holds the exact body"
	noteBlobTooLarge   = "larger than 15 MB: MongoDB documents are limited to 16 MB, so the exact bytes are only in the ledger blob store"
	noteBlobNotStored  = "content not copied (blob storage is off): the exact bytes are in the ledger blob store"
)

// item is one ledger record.
type item struct {
	env  model.Envelope
	body model.Body
}

// dataMode selects how a body's data is represented.
type dataMode int

const (
	dataConvert dataMode = iota // BSON when the conversion is faithful, else JSON text
	dataAsJSON                  // JSON text (the server rejected the converted data)
	dataOmitted                 // a note only (the document would be too large)
)

// recordDoc builds the records document of one ledger record. The layout is deterministic: the
// same record always gives the same bytes (Verify relies on it). A document that would exceed the
// MongoDB limit is rebuilt without its converted data.
func recordDoc(env model.Envelope, body model.Body, mode dataMode) (bson.Raw, error) {
	if body.Seq > math.MaxInt64 {
		return nil, fmt.Errorf("seq %d is outside the int64 range of MongoDB", body.Seq)
	}
	seq := int64(body.Seq)
	d := make(bson.D, 0, 20)
	d = append(d, bson.E{Key: "_id", Value: seq}, bson.E{Key: "seq", Value: seq})
	if t, ok := parseTS(body.TS); ok {
		d = append(d, bson.E{Key: "ts", Value: bson.NewDateTimeFromTime(t)})
	}
	d = append(d,
		bson.E{Key: "ts_text", Value: body.TS},
		bson.E{Key: "type", Value: body.Type},
		bson.E{Key: "run", Value: body.Run},
		bson.E{Key: "mono", Value: body.Mono},
		bson.E{Key: "prev", Value: body.Prev},
		bson.E{Key: "v", Value: int64(body.V)},
		bson.E{Key: "h", Value: env.H},
		bson.E{Key: "s", Value: env.S},
		bson.E{Key: "b", Value: env.B},
	)
	if len(body.Blobs) > 0 {
		d = append(d, bson.E{Key: "blobs", Value: body.Blobs})
	}
	d = appendData(d, "data", body.Data, mode)
	d = append(d, bson.E{Key: "copy_format", Value: int32(copyFormat)})
	raw, err := bson.Marshal(d)
	if err != nil {
		return nil, fmt.Errorf("encode record %d: %w", body.Seq, err)
	}
	if len(raw) > maxDocBytes {
		if mode != dataOmitted {
			return recordDoc(env, body, dataOmitted)
		}
		return nil, fmt.Errorf("record %d needs %d bytes even without its converted data, more than the %d byte MongoDB document limit", body.Seq, len(raw), maxDocBytes)
	}
	return raw, nil
}

// incidentDoc builds the incidents document for incident id from one of its records.
func incidentDoc(id string, env model.Envelope, body model.Body, mode dataMode, updated time.Time) (bson.Raw, error) {
	if body.Seq > math.MaxInt64 {
		return nil, fmt.Errorf("seq %d is outside the int64 range of MongoDB", body.Seq)
	}
	d := make(bson.D, 0, 12)
	d = append(d,
		bson.E{Key: "_id", Value: id},
		bson.E{Key: "seq", Value: int64(body.Seq)},
		bson.E{Key: "type", Value: body.Type},
	)
	if t, ok := parseTS(body.TS); ok {
		d = append(d, bson.E{Key: "ts", Value: bson.NewDateTimeFromTime(t)})
	}
	d = append(d, bson.E{Key: "ts_text", Value: body.TS}, bson.E{Key: "h", Value: env.H})
	d = appendData(d, "incident", body.Data, mode)
	d = append(d, bson.E{Key: "updated", Value: bson.NewDateTimeFromTime(updated)})
	raw, err := bson.Marshal(d)
	if err != nil {
		return nil, fmt.Errorf("encode incident %s: %w", id, err)
	}
	if len(raw) > maxDocBytes {
		if mode != dataOmitted {
			return incidentDoc(id, env, body, dataOmitted, updated)
		}
		return nil, fmt.Errorf("incident %s needs %d bytes, more than the MongoDB document limit", id, len(raw))
	}
	return raw, nil
}

// blobDoc builds the blobs document of a blob whose SHA-256 has been checked.
func blobDoc(id string, content []byte, firstSeq uint64, storeContent bool, now time.Time) bson.D {
	d := bson.D{
		{Key: "_id", Value: id},
		{Key: "size", Value: int64(len(content))},
		{Key: "first_seq", Value: int64(min(firstSeq, math.MaxInt64))},
		{Key: "stored_at", Value: bson.NewDateTimeFromTime(now)},
	}
	switch {
	case !storeContent:
		d = append(d, bson.E{Key: "note", Value: noteBlobNotStored})
	case len(content) > maxBlobBytes:
		d = append(d, bson.E{Key: "too_large", Value: true}, bson.E{Key: "note", Value: noteBlobTooLarge})
	default:
		d = append(d, bson.E{Key: "data", Value: bson.Binary{Subtype: 0x00, Data: content}})
	}
	return d
}

// appendData appends the elements that represent the JSON value data under name.
func appendData(d bson.D, name string, data json.RawMessage, mode dataMode) bson.D {
	if len(data) == 0 {
		return d // the body has no data member
	}
	var note string
	switch mode {
	case dataOmitted:
		return append(d,
			bson.E{Key: name + "_undecoded", Value: true},
			bson.E{Key: name + "_note", Value: noteDataTooLarge})
	case dataAsJSON:
		note = noteServerRejected
	default:
		v, why := convertJSON(data)
		if why == "" {
			return append(d, bson.E{Key: name, Value: v})
		}
		note = why
	}
	return append(d,
		bson.E{Key: name + "_json", Value: string(data)},
		bson.E{Key: name + "_undecoded", Value: true},
		bson.E{Key: name + "_note", Value: note})
}

// convertJSON converts one JSON value to BSON with the driver's Extended JSON parser (relaxed
// mode). It returns a non-empty reason instead when the result would not be faithful.
func convertJSON(data []byte) (bson.RawValue, string) {
	if why := extJSONHazard(data); why != "" {
		return bson.RawValue{}, why
	}
	wrapped := make([]byte, 0, len(data)+6)
	wrapped = append(wrapped, `{"d":`...)
	wrapped = append(wrapped, data...)
	wrapped = append(wrapped, '}')
	var doc bson.Raw
	if err := bson.UnmarshalExtJSON(wrapped, false, &doc); err != nil {
		return bson.RawValue{}, "not convertible by the Extended JSON parser: " + clip(err.Error(), 200)
	}
	elems, err := doc.Elements()
	if err != nil || len(elems) != 1 || elems[0].Key() != "d" {
		return bson.RawValue{}, "not a single JSON value"
	}
	return elems[0].Value(), ""
}

// extJSONHazard returns why the Extended JSON parser would not convert data faithfully ("" when
// it would): an object key starting with "$" (read as a type marker such as {"$date": …}, or
// rejected), a key containing NUL (impossible in BSON), an integer outside the int64 range (the
// parser stores a rounded double) or nesting deeper than maxDataDepth. Malformed JSON is left to
// the parser, which rejects it.
func extJSONHazard(data []byte) string {
	depth := 0
	for i := 0; i < len(data); {
		c := data[i]
		switch {
		case c == '"':
			end, escaped := jsonStringEnd(data, i)
			if end < 0 {
				return ""
			}
			if j := skipSpace(data, end); j < len(data) && data[j] == ':' {
				if why := keyHazard(data[i:end], escaped); why != "" {
					return why
				}
			}
			i = end
		case c == '{' || c == '[':
			depth++
			if depth > maxDataDepth {
				return fmt.Sprintf("nested deeper than %d levels", maxDataDepth)
			}
			i++
		case c == '}' || c == ']':
			depth--
			i++
		case c == '-' || (c >= '0' && c <= '9'):
			j := i + 1
			for j < len(data) && isNumberByte(data[j]) {
				j++
			}
			if why := numberHazard(data[i:j]); why != "" {
				return why
			}
			i = j
		default:
			i++
		}
	}
	return ""
}

// jsonStringEnd returns the index just past the JSON string starting at b[i] == '"' (-1 if it is
// unterminated) and whether the string contains escapes.
func jsonStringEnd(b []byte, i int) (end int, escaped bool) {
	for j := i + 1; j < len(b); j++ {
		switch b[j] {
		case '\\':
			escaped = true
			j++
		case '"':
			return j + 1, escaped
		}
	}
	return -1, escaped
}

func skipSpace(b []byte, i int) int {
	for i < len(b) && (b[i] == ' ' || b[i] == '\t' || b[i] == '\n' || b[i] == '\r') {
		i++
	}
	return i
}

func isNumberByte(c byte) bool {
	return (c >= '0' && c <= '9') || c == '.' || c == 'e' || c == 'E' || c == '+' || c == '-'
}

// keyHazard checks one object key (quoted, as in the JSON text).
func keyHazard(quoted []byte, escaped bool) string {
	key := quoted[1 : len(quoted)-1]
	if escaped {
		var s string
		if err := json.Unmarshal(quoted, &s); err != nil {
			return "" // malformed: the parser rejects it
		}
		key = []byte(s)
	}
	if len(key) > 0 && key[0] == '$' {
		return fmt.Sprintf("object key %s starts with \"$\" (Extended JSON would read it as a type marker)", strconv.Quote(clip(string(key), 40)))
	}
	if bytes.IndexByte(key, 0) >= 0 {
		return "an object key contains a NUL character (not representable in BSON)"
	}
	return ""
}

// numberHazard checks one JSON number token.
func numberHazard(tok []byte) string {
	if bytes.ContainsAny(tok, ".eE") {
		return "" // a double: an out-of-range value is rejected by the parser
	}
	digits := len(tok)
	if tok[0] == '-' {
		digits--
	}
	if digits < 19 {
		return ""
	}
	if _, err := strconv.ParseInt(string(tok), 10, 64); err != nil {
		return fmt.Sprintf("integer %s is outside the int64 range (Extended JSON would store a rounded double)", clip(string(tok), 40))
	}
	return ""
}

// parseTS parses a record time (RFC 3339 with optional fraction).
func parseTS(s string) (time.Time, bool) {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}

// isIncidentType reports whether a record type carries an incident payload.
func isIncidentType(t string) bool {
	return t == model.TypeIncidentOpen || t == model.TypeIncidentUpdate || t == model.TypeIncidentClose
}

// incidentID returns the id of an incident payload ("" if absent).
func incidentID(data json.RawMessage) string {
	var v struct {
		ID string `json:"id"`
	}
	if json.Unmarshal(data, &v) != nil {
		return ""
	}
	return v.ID
}

// ledgerIdent identifies a ledger by its genesis record.
type ledgerIdent struct {
	fingerprint string // genesis data.fingerprint (or derived from data.public_key)
	genesisHash string // h of seq 0
}

// identFromGenesis extracts the identity of a ledger from its genesis record.
func identFromGenesis(env model.Envelope, body model.Body) ledgerIdent {
	id := ledgerIdent{}
	if body.Seq != 0 || body.Type != model.TypeGenesis {
		return id
	}
	id.genesisHash = env.H
	var g model.Genesis
	if json.Unmarshal(body.Data, &g) == nil {
		id.fingerprint = g.Fingerprint
		if id.fingerprint == "" {
			if pub, err := base64.StdEncoding.DecodeString(g.PublicKey); err == nil && len(pub) == ed25519.PublicKeySize {
				id.fingerprint = fingerprintOf(pub)
			}
		}
	}
	return id
}

// fingerprintOf returns the ledger key fingerprint: hex SHA-256 of the raw public key.
func fingerprintOf(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:])
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// isBlobID reports whether id is a lowercase hex SHA-256.
func isBlobID(id string) bool { return len(id) == 64 && isHex(id) }

// decodeSignature decodes s, insisting on canonical padded base64 of 64 bytes.
func decodeSignature(s string) ([]byte, error) {
	sig, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, errors.New("signature is not base64")
	}
	if len(sig) != ed25519.SignatureSize {
		return nil, fmt.Errorf("signature has %d bytes", len(sig))
	}
	if base64.StdEncoding.EncodeToString(sig) != s {
		return nil, errors.New("signature is not canonical base64")
	}
	return sig, nil
}

// authenticGenesis reports whether doc, a records document, holds an authentic genesis record:
// b is the body of a genesis record (seq 0), h its SHA-256 and s its signature under the public
// key that the record itself names. It returns the fingerprint of that key.
func authenticGenesis(doc bson.Raw) (string, bool) {
	h, _ := rawString(doc, "h")
	s, _ := rawString(doc, "s")
	b, ok := rawString(doc, "b")
	if !ok || sha256Hex([]byte(b)) != h {
		return "", false
	}
	var body model.Body
	if json.Unmarshal([]byte(b), &body) != nil || body.Seq != 0 || body.Type != model.TypeGenesis {
		return "", false
	}
	var g model.Genesis
	if json.Unmarshal(body.Data, &g) != nil {
		return "", false
	}
	pub, err := base64.StdEncoding.DecodeString(g.PublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return "", false
	}
	sig, err := decodeSignature(s)
	if err != nil || !ed25519.Verify(pub, []byte(b), sig) {
		return "", false
	}
	return fingerprintOf(pub), true
}

// short abbreviates a hash for messages. A value that is not lowercase hex (it may come from a
// MongoDB document that anyone can write) is quoted instead, so it cannot pass for a hash or
// carry control characters.
func short(h string) string {
	switch {
	case h == "":
		return `""`
	case !isHex(h):
		return quote(clip(h, 24))
	case len(h) > 16:
		return h[:16] + "…"
	}
	return h
}

// isHex reports whether s consists of lowercase hex digits.
func isHex(s string) bool {
	for i := 0; i < len(s); i++ {
		if c := s[i]; (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// quote returns s (at most 80 bytes of it) as a quoted Go string literal: a string taken from a
// MongoDB document is shown with clear bounds and with every control or invisible character
// escaped.
func quote(s string) string { return strconv.Quote(clip(s, 80)) }

// printable escapes, as in a Go string literal, every character of s that a terminal could
// interpret or that is invisible (control and format characters such as ESC, CR, LF or bidi
// overrides, invalid UTF-8): problems and errors may contain text from MongoDB documents, which
// any local process can write, and are printed as is by the command line.
func printable(s string) string {
	if utf8.ValidString(s) && !strings.ContainsFunc(s, unprintable) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && size == 1:
			fmt.Fprintf(&b, `\x%02x`, s[i])
		case unprintable(r):
			q := strconv.QuoteRune(r)
			b.WriteString(q[1 : len(q)-1])
		default:
			b.WriteString(s[i : i+size])
		}
		i += size
	}
	return b.String()
}

func unprintable(r rune) bool { return r != ' ' && !strconv.IsPrint(r) }

// clip shortens s to at most n bytes without splitting a UTF-8 sequence.
func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "…"
}

// rawString returns the string field key of doc ("" and false when absent or not a string).
func rawString(doc bson.Raw, key string) (string, bool) {
	v, err := doc.LookupErr(key)
	if err != nil {
		return "", false
	}
	return v.StringValueOK()
}

// rawSeq returns the int64 or int32 field key of doc when it is a valid seq (>= 0).
func rawSeq(doc bson.Raw, key string) (uint64, bool) {
	v, err := doc.LookupErr(key)
	if err != nil {
		return 0, false
	}
	if n, ok := v.Int64OK(); ok && n >= 0 {
		return uint64(n), true
	}
	if n, ok := v.Int32OK(); ok && n >= 0 {
		return uint64(n), true
	}
	return 0, false
}

// diffKeys lists the top-level keys whose values differ between got and want (and keys present
// in only one of them), in want's order followed by got's extra keys, each quoted (a key of got
// may come from anyone who can write to MongoDB); "(field order)" when only the order differs.
// Keys in ignore are skipped.
func diffKeys(got, want bson.Raw, ignore ...string) []string {
	skip := map[string]bool{}
	for _, k := range ignore {
		skip[k] = true
	}
	ge, err1 := got.Elements()
	we, err2 := want.Elements()
	if err1 != nil || err2 != nil {
		return []string{"(malformed document)"}
	}
	gm := make(map[string]bson.RawValue, len(ge))
	var gkeys []string
	for _, e := range ge {
		if k := e.Key(); !skip[k] {
			if _, dup := gm[k]; dup {
				return []string{"(duplicate field " + quote(clip(k, 40)) + ")"}
			}
			gm[k] = e.Value()
			gkeys = append(gkeys, k)
		}
	}
	var out, wkeys []string
	seen := map[string]bool{}
	for _, e := range we {
		k := e.Key()
		if skip[k] {
			continue
		}
		seen[k] = true
		wkeys = append(wkeys, k)
		gv, ok := gm[k]
		if !ok || !rawValueEqual(gv, e.Value()) {
			out = append(out, quote(k))
		}
	}
	for _, k := range gkeys {
		if !seen[k] {
			out = append(out, quote(k))
		}
	}
	if len(out) == 0 && !equalStrings(gkeys, wkeys) {
		out = append(out, "(field order)")
	}
	return out
}

// rawValueEqual compares two BSON values exactly (type and bytes).
func rawValueEqual(a, b bson.RawValue) bool {
	return a.Type == b.Type && bytes.Equal(a.Value, b.Value)
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
