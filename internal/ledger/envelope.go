package ledger

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"unicode/utf8"

	"attmonitor/internal/model"
)

// maxRecordBytes caps one encoded line written by Append. Large evidence belongs in blobs.
const maxRecordBytes = 16 << 20

// marshalJSON encodes v without HTML escaping and without the encoder's trailing newline.
func marshalJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte{'\n'}), nil
}

// encodeRecord serializes body exactly once (docs/DESIGN.md §6), hashes and signs those
// bytes, and returns the complete envelope line (terminated by '\n') and the record hash.
func encodeRecord(priv ed25519.PrivateKey, body *model.Body) (line []byte, hash string, err error) {
	b, err := marshalJSON(body)
	if err != nil {
		return nil, "", fmt.Errorf("ledger: encode body: %w", err)
	}
	if !utf8.Valid(b) {
		// json.Marshal never produces invalid UTF-8, but a caller-supplied json.RawMessage
		// could; the envelope encoder would then silently alter b and break the hash.
		return nil, "", errors.New("ledger: record body is not valid UTF-8")
	}
	sum := sha256.Sum256(b)
	hash = hex.EncodeToString(sum[:])
	env := model.Envelope{
		H: hash,
		S: base64.StdEncoding.EncodeToString(ed25519.Sign(priv, b)),
		B: string(b),
	}
	l, err := marshalJSON(&env)
	if err != nil {
		return nil, "", fmt.Errorf("ledger: encode envelope: %w", err)
	}
	line = append(l, '\n')
	if len(line) > maxRecordBytes {
		return nil, "", fmt.Errorf("ledger: record of %d bytes exceeds the %d byte limit (store large content as a blob)", len(line), maxRecordBytes)
	}
	// Self-check: the line must parse back to the exact bytes that were hashed and signed.
	back, err := parseEnvelopeStrict(line)
	if err != nil || back.B != env.B || back.H != env.H || back.S != env.S {
		return nil, "", fmt.Errorf("ledger: internal error: envelope does not round-trip (%v)", err)
	}
	return line, hash, nil
}

// parseEnvelopeStrict parses one ledger line. The line must be a JSON object with exactly the
// keys "h", "s" and "b" (byte-exact, each once) whose values are strings, optionally followed
// by whitespace. Strictness guarantees that every JSON parser sees the same b.
func parseEnvelopeStrict(line []byte) (model.Envelope, error) {
	var env model.Envelope
	if err := scanEnvelopeKeys(line); err != nil {
		return env, err
	}
	// The structure is known to be exact; Unmarshal validates the string contents (escapes,
	// control characters) and unescapes them.
	if err := json.Unmarshal(line, &env); err != nil {
		return env, fmt.Errorf("envelope is not valid JSON: %v", err)
	}
	return env, nil
}

// scanEnvelopeKeys checks the top-level structure of an envelope line without decoding it.
func scanEnvelopeKeys(line []byte) error {
	i := skipJSONSpace(line, 0)
	if i == len(line) {
		return errors.New("envelope is empty (not JSON)")
	}
	if line[i] != '{' {
		return errors.New("envelope is not a JSON object")
	}
	i = skipJSONSpace(line, i+1)
	var seen uint8
	if i < len(line) && line[i] == '}' {
		i++
	} else {
		for {
			if i >= len(line) || line[i] != '"' {
				return errors.New("envelope is not valid JSON: expected a key")
			}
			end, err := jsonStringEnd(line, i)
			if err != nil {
				return err
			}
			key := line[i:end]
			var bit uint8
			switch string(key) {
			case `"h"`:
				bit = 1
			case `"s"`:
				bit = 2
			case `"b"`:
				bit = 4
			default:
				return fmt.Errorf("envelope has unexpected key %s", key)
			}
			if seen&bit != 0 {
				return fmt.Errorf("envelope has duplicate key %s", key)
			}
			seen |= bit
			i = skipJSONSpace(line, end)
			if i >= len(line) || line[i] != ':' {
				return errors.New("envelope is not valid JSON: expected ':'")
			}
			i = skipJSONSpace(line, i+1)
			if i >= len(line) || line[i] != '"' {
				return fmt.Errorf("envelope key %s is not a string", key)
			}
			if end, err = jsonStringEnd(line, i); err != nil {
				return err
			}
			i = skipJSONSpace(line, end)
			if i < len(line) && line[i] == ',' {
				i = skipJSONSpace(line, i+1)
				continue
			}
			if i < len(line) && line[i] == '}' {
				i++
				break
			}
			return errors.New("envelope is not valid JSON: unterminated object")
		}
	}
	if skipJSONSpace(line, i) != len(line) {
		return errors.New("envelope has trailing data")
	}
	if seen != 7 {
		return errors.New(`envelope is missing one of the keys "h", "s", "b"`)
	}
	return nil
}

func skipJSONSpace(b []byte, i int) int {
	for i < len(b) && (b[i] == ' ' || b[i] == '\t' || b[i] == '\n' || b[i] == '\r') {
		i++
	}
	return i
}

// jsonStringEnd returns the index just past the JSON string starting at b[i] == '"'.
func jsonStringEnd(b []byte, i int) (int, error) {
	for j := i + 1; j < len(b); j++ {
		switch b[j] {
		case '\\':
			j++ // skip the escaped character
		case '"':
			return j + 1, nil
		}
	}
	return 0, errors.New("envelope is not valid JSON: unterminated string")
}

// parseRecordLenient decodes a line for readers (Scan & co.), without the strict checks.
func parseRecordLenient(line []byte) (model.Envelope, model.Body, error) {
	var env model.Envelope
	var body model.Body
	if err := json.Unmarshal(line, &env); err != nil {
		return env, body, fmt.Errorf("envelope: %w", err)
	}
	if env.B == "" {
		return env, body, errors.New("envelope: empty body")
	}
	if err := json.Unmarshal([]byte(env.B), &body); err != nil {
		return env, body, fmt.Errorf("body: %w", err)
	}
	return env, body, nil
}

// decodeSignature decodes s and insists on the canonical encoding (base64 std, padded),
// because the decoder would otherwise silently ignore inserted newlines.
func decodeSignature(s string) ([]byte, error) {
	sig, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("signature is not base64: %v", err)
	}
	if len(sig) != ed25519.SignatureSize {
		return nil, fmt.Errorf("signature has %d bytes, want %d", len(sig), ed25519.SignatureSize)
	}
	if base64.StdEncoding.EncodeToString(sig) != s {
		return nil, errors.New("signature is not canonical base64")
	}
	return sig, nil
}

// quickMarker locates the start of the body in a line written by this package.
var quickMarker = []byte(`"b":"{\"v\":1,\"seq\":`)

// quickSeqTS extracts seq and ts from a line in this package's canonical layout without a
// full JSON decode. ok=false means the caller must fall back to a full parse. It is used only
// to skip records cheaply in readers, never for verification.
func quickSeqTS(line []byte) (seq uint64, ts []byte, ok bool) {
	i := bytes.Index(line, quickMarker)
	if i < 0 {
		return 0, nil, false
	}
	p := line[i+len(quickMarker):]
	n := 0
	for n < len(p) && n <= 20 && p[n] >= '0' && p[n] <= '9' {
		n++
	}
	if n == 0 || n > 20 {
		return 0, nil, false
	}
	seq, err := strconv.ParseUint(string(p[:n]), 10, 64)
	if err != nil {
		return 0, nil, false
	}
	p = p[n:]
	const prevKey = `,\"prev\":\"`
	if !bytes.HasPrefix(p, []byte(prevKey)) || len(p) < len(prevKey)+64 {
		return 0, nil, false
	}
	p = p[len(prevKey)+64:]
	const tsKey = `\",\"ts\":\"`
	if !bytes.HasPrefix(p, []byte(tsKey)) {
		return 0, nil, false
	}
	p = p[len(tsKey):]
	j := bytes.Index(p, []byte(`\"`))
	if j <= 0 || j > 64 {
		return 0, nil, false
	}
	return seq, p[:j], true
}

// isBlobID reports whether id is a lowercase hex SHA-256.
func isBlobID(id string) bool {
	return isLowerHex(id, 64)
}

func isLowerHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// sha256Hex returns the lowercase hex SHA-256 of b.
func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
