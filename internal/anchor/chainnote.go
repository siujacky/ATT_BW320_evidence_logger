package anchor

import (
	"cmp"
	"errors"
	"slices"
	"strings"
	"unicode/utf8"
)

// TokenInfo.ChainNote says why ChainOK is false, in one printable line of at most maxChainNote
// bytes. It names every trust-anchor source in the order tried and what each one reported:
//
//	embedded FreeTSA root: x509: certificate signed by unknown authority; extra roots: none; system roots: x509: certificate signed by unknown authority
//
// or, when the signer certificate breaks the TSA certificate profile (no source is tried then):
//
//	TSA certificate extended key usage is not marked critical (RFC 3161 TSA profile); root sources: not tried
//
// Parts of the text come from the token (certificate names quoted in x509 messages), so it is
// escaped with printable. When it would be too long, the longest reasons are shortened (marked
// "..."), never the source names. The note is a diagnostic: ChainOK alone is the verdict.

// maxChainNote bounds TokenInfo.ChainNote, in bytes.
const maxChainNote = 200

// Names of the trust-anchor sources, as ChainNote and the logs show them.
const (
	sourceEmbedded = "embedded FreeTSA root"
	sourceExtra    = "extra roots"
	sourceSystem   = "system roots"
)

// chainError explains a failed chain check: the signer certificate breaks the TSA certificate
// profile (no root source is tried then), or no root source led to a trusted root.
type chainError struct {
	profile error          // the profile violation, or nil
	sources []sourceResult // otherwise every root source, in the order tried
}

// sourceResult is why one root source did not lead to a trusted root.
type sourceResult struct {
	name   string // e.g. sourceSystem
	reason string // printable: "none" (not configured), "unavailable: ..." or the chain error
	err    error  // nil when the source is not configured
}

func (e *chainError) add(name, reason string, err error) {
	e.sources = append(e.sources, sourceResult{name: name, reason: reason, err: err})
}

// Error is the complete diagnostic, for logs: what ChainNote says, never shortened.
func (e *chainError) Error() string {
	switch {
	case e.profile != nil:
		return e.profile.Error()
	case len(e.sources) == 0:
		return "anchor: no trust anchors available"
	}
	parts := make([]string, len(e.sources))
	for i, s := range e.sources {
		parts[i] = s.name + ": " + s.reason
	}
	return strings.Join(parts, "; ")
}

// Unwrap returns the profile violation or the errors of the root sources.
func (e *chainError) Unwrap() []error {
	if e.profile != nil {
		return []error{e.profile}
	}
	var errs []error
	for _, s := range e.sources {
		if s.err != nil {
			errs = append(errs, s.err)
		}
	}
	return errs
}

// note renders e as a ChainNote.
func (e *chainError) note() string {
	switch {
	case e.profile != nil:
		return joinNote([]notePart{
			{reason: reasonText(e.profile) + " (RFC 3161 TSA profile)"},
			{label: "root sources", reason: "not tried"},
		}, maxChainNote)
	case len(e.sources) == 0:
		return "no trust anchors available"
	}
	parts := make([]notePart, len(e.sources))
	for i, s := range e.sources {
		parts[i] = notePart{label: s.name, reason: s.reason}
	}
	return joinNote(parts, maxChainNote)
}

// chainNote returns the ChainNote for a chain check that failed with diagnostic err (see
// chainVerify). It is never empty.
func chainNote(err error) string {
	var note string
	var ce *chainError
	switch {
	case errors.As(err, &ce):
		note = ce.note()
	case err != nil: // e.g. a recovered panic
		note = fit(reasonText(err), maxChainNote)
	}
	if note == "" {
		note = "not chained to a trusted root (no reason recorded)"
	}
	return note
}

// reasonText renders an error of the chain check for ChainNote and logs: escaped with printable,
// without this package's "anchor: " prefix, validity-period messages phrased for genTime.
func reasonText(err error) string {
	return printable(atGenTime(strings.TrimPrefix(err.Error(), "anchor: ")))
}

// atGenTime rewords x509's validity-period messages. The chain is checked as of the token's
// genTime (VerifyOptions.CurrentTime), but Go's verifier calls that instant "current time"
// ("current time <genTime> is after <notAfter>"), which reads like the time of the check, and the
// Windows chain engine gives no detail ("... not yet valid: ").
//
// One pass, linear time: s can quote certificate names from the token (x509's hints), and the
// token's certificate set is not signed.
func atGenTime(s string) string {
	const current = "current time "
	var b strings.Builder
	for {
		i := strings.Index(s, current)
		if i < 0 {
			break
		}
		rest := s[i+len(current):] // "<genTime> is after <notAfter>..."
		j := strings.IndexByte(rest, ' ')
		if j < 0 || !strings.HasPrefix(rest[j:], " is ") {
			b.WriteString(s[:i+len(current)]) // not x509's phrase: keep it
		} else {
			b.WriteString(s[:i])
			b.WriteString("genTime")
			rest = rest[j:]
		}
		s = rest
	}
	if b.Len() > 0 {
		b.WriteString(s)
		s = b.String()
	}
	const invalid, atGen = "has expired or is not yet valid: ", "has expired or is not yet valid at genTime"
	if strings.HasSuffix(s, invalid) {
		s = strings.TrimSuffix(s, invalid) + atGen
	}
	return strings.ReplaceAll(s, invalid+")", atGen+")")
}

// notePart is one "label: reason" item of a note; without a label, the reason alone.
type notePart struct{ label, reason string }

// joinNote joins parts as "label: reason; label: reason" in at most limit bytes. If that is too
// long, the reasons are shortened, longest first: each gets at most an equal share of the room
// the shorter ones leave. Labels are kept whole, so every source stays named.
func joinNote(parts []notePart, limit int) string {
	room := limit - len("; ")*(len(parts)-1)
	for _, p := range parts {
		if p.label != "" {
			room -= len(p.label) + len(": ")
		}
	}
	order := make([]int, len(parts))
	for i := range order {
		order[i] = i
	}
	slices.SortStableFunc(order, func(a, b int) int { return cmp.Compare(len(parts[a].reason), len(parts[b].reason)) })
	keep := make([]int, len(parts))
	for k, i := range order {
		keep[i] = min(len(parts[i].reason), max(room, 0)/(len(order)-k))
		room -= keep[i]
	}
	var b strings.Builder
	for i, p := range parts {
		if i > 0 {
			b.WriteString("; ")
		}
		if p.label != "" {
			b.WriteString(p.label + ": ")
		}
		b.WriteString(fit(p.reason, keep[i]))
	}
	return fit(b.String(), limit) // only if the labels alone exceed limit
}

// fit returns s if it has at most n bytes, else the longest prefix of s, cut at a character
// boundary, that fits in n bytes together with the marker "..." ("" if n < 3).
func fit(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n < len("...") {
		return ""
	}
	cut := n - len("...")
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "..."
}
