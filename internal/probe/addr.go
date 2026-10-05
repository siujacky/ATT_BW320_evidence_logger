package probe

import (
	"fmt"
	"net/netip"
	"strings"
	"unicode/utf8"
)

// Hijack reasons are short summaries; the complete data (all DNS answers, the full Location
// header) is in the result's own fields. maxReasonLen bounds a DNS reason and each finding
// of an HTTP reason; maxReasonItem bounds a single value quoted in a reason.
const (
	maxReasonLen     = 256
	maxReasonItem    = 120
	maxReasonAnswers = 3
)

// clipText shortens s to at most n bytes without splitting a UTF-8 sequence, marking the
// cut with "...".
func clipText(s string, n int) string {
	if len(s) <= n {
		return s
	}
	const mark = "..."
	cut := max(n-len(mark), 0)
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + mark
}

// listForReason renders up to maxReasonAnswers values (each clipped) as list, and the
// number of values left out as more (" (+N more)", or "").
func listForReason(values []string) (list, more string) {
	shown := values
	if len(shown) > maxReasonAnswers {
		shown = shown[:maxReasonAnswers]
		more = fmt.Sprintf(" (+%d more)", len(values)-maxReasonAnswers)
	}
	parts := make([]string, len(shown))
	for i, v := range shown {
		parts[i] = clipText(v, maxReasonItem)
	}
	return strings.Join(parts, ", "), more
}

// boundedReason joins text (clipped) and a suffix that is always kept, within maxReasonLen.
func boundedReason(text, suffix string) string {
	return clipText(text, maxReasonLen-len(suffix)) + suffix
}

// cgnat is the shared address space of RFC 6598 (carrier-grade NAT).
var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// nonPublicReason returns a short phrase ("a private (RFC 1918) address", ...) when a is not
// a plausible public Internet address, or "" when it is. The categories are the ones
// docs/DESIGN.md §8 lists for hijack detection: private, loopback, link-local, CGNAT and
// unspecified (0.0.0.0/8 "this network" is treated as unspecified).
func nonPublicReason(a netip.Addr) string {
	a = a.Unmap()
	switch {
	case !a.IsValid():
		return "an invalid address"
	case a.IsUnspecified(), a.Is4() && a.As4()[0] == 0:
		return "an unspecified address"
	case a.IsLoopback():
		return "a loopback address"
	case a.IsPrivate() && a.Is4():
		return "a private (RFC 1918) address"
	case a.IsPrivate():
		return "a unique-local (fc00::/7) address"
	case a.IsLinkLocalUnicast():
		return "a link-local address"
	case a.Is4() && cgnat.Contains(a):
		return "a carrier-grade NAT (100.64.0.0/10) address"
	}
	return ""
}

// suspiciousAddr is nonPublicReason extended with an exact match on the gateway address
// (which is reported even if the gateway were numbered from public space).
func suspiciousAddr(a netip.Addr, gatewayIP string) string {
	a = a.Unmap()
	if gw, err := netip.ParseAddr(strings.TrimSpace(gatewayIP)); err == nil && gw.Unmap() == a {
		return "the gateway's own address"
	}
	return nonPublicReason(a)
}

// localSuffixes are DNS suffixes that legitimately resolve to private addresses
// (attlocal.net is the AT&T gateway's own LAN domain, e.g. dsldevice.attlocal.net).
var localSuffixes = []string{
	"localhost", "local", "lan", "home", "home.arpa", "internal", "intranet",
	"localdomain", "attlocal.net", "in-addr.arpa", "ip6.arpa",
}

// normalizeName lower-cases a DNS name and strips surrounding space and the root dot.
func normalizeName(name string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
}

// isLocalName reports whether a DNS name is a local (non-public) name: single-label names
// and names under localSuffixes. IP literals are not names and return false.
func isLocalName(name string) bool {
	n := normalizeName(name)
	if n == "" {
		return false
	}
	if _, err := netip.ParseAddr(n); err == nil {
		return false
	}
	if !strings.Contains(n, ".") {
		return true
	}
	for _, s := range localSuffixes {
		if n == s || strings.HasSuffix(n, "."+s) {
			return true
		}
	}
	return false
}

// isLocalHost reports whether a URL host (name or IP literal) is itself local, in which
// case answers from local addresses are expected rather than a sign of hijacking.
func isLocalHost(host string) bool {
	if a, err := netip.ParseAddr(strings.TrimSpace(host)); err == nil {
		return nonPublicReason(a) != ""
	}
	return isLocalName(host)
}
