package anchor

// Tests of TokenInfo.ChainNote: why ChainOK is false, as one printable line of at most 200
// bytes that names every trust-anchor source tried and what each one reported.

import (
	"crypto/x509"
	"errors"
	"strings"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"
)

// unknownCA is what Go's verifier and the Windows chain engine report for a certificate that
// chains to none of the roots offered.
const unknownCA = "x509: certificate signed by unknown authority"

// defaultLabels name the default root sources, in the order they are tried.
var defaultLabels = []string{"embedded FreeTSA root", "extra roots", "system roots"}

// note3 is the ChainNote of a check that tried the three default root sources.
func note3(embedded, extra, system string) string {
	return "embedded FreeTSA root: " + embedded + "; extra roots: " + extra + "; system roots: " + system
}

// profileNote is the ChainNote of a signer certificate that breaks the RFC 3161 TSA certificate
// profile (no root source is tried then).
func profileNote(problem string) string {
	return "TSA certificate " + problem + " (RFC 3161 TSA profile); root sources: not tried"
}

// checkNoteForm checks what every ChainNote of a false ChainOK must be: non-empty, at most 200
// bytes, valid UTF-8 made of printable characters only (so on one line), naming each label
// ("label: ") in the given order.
func checkNoteForm(t testing.TB, note string, labels ...string) {
	t.Helper()
	if note == "" {
		t.Error("ChainNote is empty although ChainOK is false")
		return
	}
	if len(note) > 200 {
		t.Errorf("ChainNote has %d bytes, more than 200: %q", len(note), note)
	}
	if !utf8.ValidString(note) || strings.IndexFunc(note, func(r rune) bool { return !unicode.IsPrint(r) }) >= 0 {
		t.Errorf("ChainNote is not printable one-line text: %q", note)
	}
	checkNoteHas(t, note, labelsWithColon(labels)...)
}

func labelsWithColon(labels []string) []string {
	out := make([]string, len(labels))
	for i, l := range labels {
		out[i] = l + ": "
	}
	return out
}

// checkNoteHas checks that note contains frags in this order, without overlap.
func checkNoteHas(t testing.TB, note string, frags ...string) {
	t.Helper()
	at := 0
	for _, f := range frags {
		i := strings.Index(note[at:], f)
		if i < 0 {
			t.Errorf("ChainNote %q lacks %q (after byte %d)", note, f, at)
			return
		}
		at += i + len(f)
	}
}

func TestFit(t *testing.T) {
	tests := []struct {
		s    string
		n    int
		want string
	}{
		{"abc", 3, "abc"},
		{"abc", 10, "abc"},
		{"abcd", 3, "..."},
		{"abcdef", 5, "ab..."},
		{"abc", 2, ""},
		{"", 0, ""},
		{"héllo", 5, "h..."}, // the two bytes of é are never split
		{"日本語", 6, "日..."},
		{"日本語", 5, "..."},
	}
	for _, tt := range tests {
		got := fit(tt.s, tt.n)
		if got != tt.want || len(got) > max(tt.n, 0) || !utf8.ValidString(got) {
			t.Errorf("fit(%q, %d) = %q, want %q", tt.s, tt.n, got, tt.want)
		}
	}
}

func TestJoinNote(t *testing.T) {
	long := strings.Repeat("x", 300)
	tests := []struct {
		name  string
		parts []notePart
		limit int
		want  string
	}{
		{"fits", []notePart{{sourceEmbedded, "a"}, {sourceExtra, "none"}, {sourceSystem, "b"}}, 200,
			"embedded FreeTSA root: a; extra roots: none; system roots: b"},
		// 54 bytes of labels and separators leave 146: "none" keeps its 4, the two long
		// reasons share the rest equally.
		{"two long reasons", []notePart{{sourceEmbedded, long}, {sourceExtra, "none"}, {sourceSystem, long + "yz"}}, 200,
			"embedded FreeTSA root: " + strings.Repeat("x", 68) + "...; extra roots: none; system roots: " + strings.Repeat("x", 68) + "..."},
		{"one long reason takes what the others leave", []notePart{{sourceEmbedded, unknownCA}, {sourceExtra, "none"}, {sourceSystem, long}}, 200,
			"embedded FreeTSA root: " + unknownCA + "; extra roots: none; system roots: " + strings.Repeat("x", 94) + "..."},
		{"unlabelled part, multibyte text", []notePart{{reason: strings.Repeat("é", 100)}, {label: "root sources", reason: "not tried"}}, 60,
			strings.Repeat("é", 16) + "...; root sources: not tried"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := joinNote(tt.parts, tt.limit)
			if got != tt.want {
				t.Errorf("joinNote = %q\n      want %q", got, tt.want)
			}
			if len(got) > tt.limit || !utf8.ValidString(got) {
				t.Errorf("%d bytes (limit %d), valid UTF-8 %v", len(got), tt.limit, utf8.ValidString(got))
			}
		})
	}
}

func TestAtGenTime(t *testing.T) {
	tests := []struct{ in, want string }{
		// Go's verifier: the instant compared is the genTime the chain is checked at.
		{"x509: certificate has expired or is not yet valid: current time 2026-10-07T05:56:29Z is after 2026-10-06T05:56:29Z",
			"x509: certificate has expired or is not yet valid: genTime is after 2026-10-06T05:56:29Z"},
		{"x509: certificate has expired or is not yet valid: current time 2026-01-01T00:00:00Z is before 2026-02-15T19:44:22Z",
			"x509: certificate has expired or is not yet valid: genTime is before 2026-02-15T19:44:22Z"},
		// The Windows chain engine gives no detail.
		{"x509: certificate has expired or is not yet valid: ", "x509: certificate has expired or is not yet valid at genTime"},
		{"chain needs certificates not in the token (x509: certificate has expired or is not yet valid: )",
			"chain needs certificates not in the token (x509: certificate has expired or is not yet valid at genTime)"},
		// Inside the quoted hint of an unknown-authority error, and more than once.
		{`x509: certificate signed by unknown authority (possibly because of "x509: certificate has expired or is not yet valid: current time 2032-01-01T00:00:00Z is after 2031-11-09T23:59:59Z" while trying to verify candidate authority certificate "DigiCert Trusted Root G4")`,
			`x509: certificate signed by unknown authority (possibly because of "x509: certificate has expired or is not yet valid: genTime is after 2031-11-09T23:59:59Z" while trying to verify candidate authority certificate "DigiCert Trusted Root G4")`},
		{"a: current time 1 is after 2; b: current time 3 is before 4", "a: genTime is after 2; b: genTime is before 4"},
		// Anything else is unchanged.
		{unknownCA, unknownCA},
		{"current time", "current time"},
		{"current time unknown", "current time unknown"},
		{"", ""},
	}
	for _, tt := range tests {
		if got := atGenTime(tt.in); got != tt.want {
			t.Errorf("atGenTime(%q)\n = %q\nwant %q", tt.in, got, tt.want)
		}
	}
}

// TestAtGenTimeLinear: x509's hints quote certificate names from the token, whose certificate set
// anyone on the path to a plain-HTTP TSA can extend. A name made of the phrase atGenTime looks
// for must not make it quadratic; a copy of the text per match would show as one allocation each.
func TestAtGenTimeLinear(t *testing.T) {
	const n = 20000
	for name, unit := range map[string]string{"rewritten": "current time x is after y; ", "kept": "current time xy; "} {
		in := strings.Repeat(unit, n)
		want := strings.Repeat(unit, n)
		if name == "rewritten" {
			want = strings.Repeat("genTime is after y; ", n)
		}
		if got := atGenTime(in); got != want {
			t.Fatalf("%s: atGenTime changed the text wrongly (%d bytes, want %d)", name, len(got), len(want))
		}
		if allocs := testing.AllocsPerRun(3, func() { atGenTime(in) }); allocs > 64 {
			t.Errorf("%s: %v allocations for %d matches, want a handful", name, allocs, n)
		}
	}
}

// TestChainNoteEscapesHostileText: reasons can carry text from the token or the platform. They
// are escaped (printable), so the note stays on one line and cannot drive a terminal.
func TestChainNoteEscapesHostileText(t *testing.T) {
	ft := mustCore(t, readVector(t, "freetsa.tsr"), vectorDigest(t))
	hostile := "boom\x1b[2J\x07\nsystem roots: ok" + string(rune(0x202e)) + "\xff"
	ok, err := chainVerifyWith(ft.signer, ft.certs, vectorGenTime, []rootSource{
		{sourceEmbedded, func() (*x509.CertPool, error) { return nil, errors.New("anchor: " + hostile) }},
		{sourceExtra, func() (*x509.CertPool, error) { return nil, nil }},
		{sourceSystem, func() (*x509.CertPool, error) { return x509.NewCertPool(), nil }},
	})
	if ok {
		t.Fatal("chain verified without a root")
	}
	want := `embedded FreeTSA root: unavailable: boom\x1b[2J\x07\x0asystem roots: ok` + `\` + `u202e\xff; extra roots: none; system roots: ` + unknownCA
	note := chainNote(err)
	if note != want {
		t.Errorf("ChainNote = %q\n      want %q", note, want)
	}
	checkNoteForm(t, note, defaultLabels...)
	if err.Error() != want { // the diagnostic for logs is escaped the same way
		t.Errorf("diagnostic = %q", err)
	}
}

// TestChainNoteBounded: however long the reasons, the note keeps to 200 bytes and names every
// source; the diagnostic for logs keeps everything.
func TestChainNoteBounded(t *testing.T) {
	ft := mustCore(t, readVector(t, "freetsa.tsr"), vectorDigest(t))
	long := errors.New(strings.Repeat("é", 2000) + "\n")
	src := func() (*x509.CertPool, error) { return nil, long }
	ok, err := chainVerifyWith(ft.signer, ft.certs, vectorGenTime, []rootSource{{sourceEmbedded, src}, {sourceExtra, src}, {sourceSystem, src}})
	if ok {
		t.Fatal("chain verified without a root")
	}
	note := chainNote(err)
	checkNoteForm(t, note, defaultLabels...)
	if n := strings.Count(note, "..."); n != 3 {
		t.Errorf("%d shortened reasons in %q, want 3", n, note)
	}
	if !strings.Contains(err.Error(), strings.Repeat("é", 2000)+`\x0a; extra roots: `) {
		t.Error("the diagnostic was shortened")
	}
}

func TestChainNoteFallbacks(t *testing.T) {
	ft := mustCore(t, readVector(t, "freetsa.tsr"), vectorDigest(t))
	ok, err := chainVerifyWith(ft.signer, ft.certs, vectorGenTime, []rootSource{
		{sourceSystem, func() (*x509.CertPool, error) { panic("kaboom\n") }},
	})
	if ok || err == nil {
		t.Fatalf("panicking source: ok = %v, err = %v", ok, err)
	}
	for _, tt := range []struct {
		name string
		err  error
		want string
	}{
		{"panic", err, `certificate chain check panicked: kaboom\x0a`},
		{"no sources", &chainError{}, "no trust anchors available"},
		{"no reason", nil, "not chained to a trusted root (no reason recorded)"},
		{"long foreign error", errors.New(strings.Repeat("z", 500)), strings.Repeat("z", 197) + "..."},
	} {
		if got := chainNote(tt.err); got != tt.want {
			t.Errorf("%s: chainNote = %q, want %q", tt.name, got, tt.want)
		}
	}
}

// TestChainErrorUnwrap: the verifier's own errors stay reachable with errors.As.
func TestChainErrorUnwrap(t *testing.T) {
	dc := mustCore(t, readVector(t, "digicert.tsr"), vectorDigest(t))
	_, err := chainVerifyWith(dc.signer, dc.certs, vectorGenTime, []rootSource{
		{sourceEmbedded, embeddedRoots}, {sourceExtra, func() (*x509.CertPool, error) { return nil, nil }},
	})
	var ua x509.UnknownAuthorityError
	if !errors.As(err, &ua) {
		t.Errorf("errors.As(%v, UnknownAuthorityError) = false", err)
	}
	tsa := newCert(t, certSpec{cn: "No EKU", keyUsage: x509.KeyUsageDigitalSignature}, nil)
	_, err = chainVerifyWith(tsa.cert, []*x509.Certificate{tsa.cert}, time.Now(), defaultRootSources(nil))
	var ce *chainError
	if !errors.As(err, &ce) || ce.profile == nil || !errors.Is(err, ce.profile) {
		t.Errorf("profile violation not reported as such: %v", err)
	}
}

// FuzzChainNote: whatever the root sources report, the note is one printable line of at most 200
// bytes naming every source in order, and it is the whole diagnostic when that fits.
func FuzzChainNote(f *testing.F) {
	f.Add(unknownCA, "", unknownCA)
	f.Add("x509: certificate has expired or is not yet valid: current time 2026-10-07T05:56:29Z is after 2026-10-06T05:56:29Z",
		"", "x509: certificate has expired or is not yet valid: ")
	f.Add(strings.Repeat("é", 150), "\x1b[2J\n\xff", strings.Repeat("x", 500))
	f.Add("current time current time  is  is current time x is", "anchor: anchor: ", "system roots: ok; extra roots: none")
	f.Fuzz(func(t *testing.T, embedded, extra, system string) {
		ce := &chainError{}
		for i, msg := range []string{embedded, extra, system} {
			if msg == "" {
				ce.add(defaultLabels[i], "none", nil)
				continue
			}
			err := errors.New(msg)
			ce.add(defaultLabels[i], reasonText(err), err)
		}
		note := chainNote(ce)
		checkNoteForm(t, note, defaultLabels...)
		if full := ce.Error(); len(full) <= 200 && note != full {
			t.Errorf("note %q differs from the diagnostic %q, which fits", note, full)
		}
	})
}
