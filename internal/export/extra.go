package export

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)

// extraFile is an additional bundle file (Options.ExtraFiles).
type extraFile struct {
	path string
	data []byte
}

// generatedFiles are the files every bundle contains besides the ledger/ and blobs/ entries;
// generatedDirs hold generated entries only.
var (
	generatedFiles = []string{"README.txt", "REPORT.html", "report.json", "keys/public-key.txt", "tools/verify_bundle.py", manifestName}
	generatedDirs  = []string{"ledger", "blobs"}
)

// extraElemRE: a path element is a plain name - letters, digits, '.', '_' and '-', starting
// with a letter or digit (no separators, drive letters, spaces or control characters).
var extraElemRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

// checkExtraPath accepts a relative path of plain elements separated by single forward slashes.
func checkExtraPath(p string) error {
	if p == "" || len(p) > 200 {
		return fmt.Errorf("the path is empty or longer than 200 bytes")
	}
	for _, el := range strings.Split(p, "/") {
		switch {
		case !extraElemRE.MatchString(el):
			return fmt.Errorf("element %q is not a plain name (letters, digits, '.', '_' and '-' only; forward slashes "+
				"between elements; no drive, absolute or '..' paths)", truncate(el, 40))
		case strings.Contains(el, ".."), strings.HasSuffix(el, "."):
			return fmt.Errorf("element %q contains \"..\" or ends with '.'", el)
		case isDeviceName(el):
			return fmt.Errorf("element %q is a Windows device name", el)
		}
	}
	return nil
}

// isDeviceName reports a Windows device name (CON, PRN, AUX, NUL, COM0-9, LPT0-9), with any
// extension: such files cannot be created on Windows.
func isDeviceName(elem string) bool {
	base := elem
	if i := strings.IndexByte(base, '.'); i >= 0 {
		base = base[:i]
	}
	base = strings.ToUpper(base)
	return reservedNames[base] || ((strings.HasPrefix(base, "COM") || strings.HasPrefix(base, "LPT")) &&
		len(base) == 4 && base[3] >= '0' && base[3] <= '9')
}

// checkExtraFiles validates Options.ExtraFiles and returns them sorted by path. A path may not
// collide with a generated file or with another extra file - also not when letter case is
// ignored, since the bundle is extracted on case-insensitive file systems - and may not be
// both a file and a directory.
func checkExtraFiles(m map[string][]byte) ([]extraFile, error) {
	if len(m) == 0 {
		return nil, nil
	}
	names := make([]string, 0, len(m))
	for n := range m {
		names = append(names, n)
	}
	sort.Strings(names)
	taken := map[string]string{} // lower-case path -> path
	for _, g := range generatedFiles {
		taken[strings.ToLower(g)] = g
	}
	var problems []string
	var out []extraFile
	for _, name := range names {
		if err := checkExtraPath(name); err != nil {
			problems = append(problems, fmt.Sprintf("%q: %v", truncate(name, 80), err))
			continue
		}
		l := strings.ToLower(name)
		if g, ok := taken[l]; ok {
			problems = append(problems, fmt.Sprintf("%q collides with %q", name, g))
			continue
		}
		bad := false
		for _, d := range generatedDirs {
			if l == d || strings.HasPrefix(l, d+"/") {
				problems = append(problems, fmt.Sprintf("%q is inside %s/, which holds only generated entries", name, d))
				bad = true
			}
		}
		for t, orig := range taken {
			if strings.HasPrefix(t, l+"/") || strings.HasPrefix(l, t+"/") {
				problems = append(problems, fmt.Sprintf("%q and %q would be a file and a directory of the same name", name, orig))
				bad = true
			}
		}
		if bad {
			continue
		}
		taken[l] = name
		out = append(out, extraFile{path: name, data: m[name]})
	}
	if len(problems) > 0 {
		sort.Strings(problems)
		return nil, fmt.Errorf("%w: %s", ErrInvalidExtraFile, strings.Join(problems, "; "))
	}
	return out, nil
}

// describeExtraFiles lists the extra files in the report and, for keys/tsa-roots.pem, the
// certificates it holds.
func describeExtraFiles(r *report, extra []extraFile) {
	for _, x := range extra {
		e := extraFileEntry{Path: x.path, SHA256: sha256Hex(x.data), Bytes: len(x.data)}
		if x.path == tsaRootsPath {
			e.Description = "root certificates of the Time-Stamp Authorities, for openssl ts -verify -CAfile " + tsaRootsPath
			r.Bundle.TSARoots, r.Bundle.TSARootsNote = parseRootCerts(x.data)
		} else {
			e.Description = "additional file supplied by the exporting software"
		}
		r.Bundle.ExtraFiles = append(r.Bundle.ExtraFiles, e)
	}
}

// parseRootCerts lists the certificates of a PEM file with their SHA-256 fingerprints.
func parseRootCerts(data []byte) ([]rootCertEntry, string) {
	var out []rootCertEntry
	var notes []string
	rest := data
	for n := 1; ; n++ {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		if blk.Type != "CERTIFICATE" {
			notes = append(notes, fmt.Sprintf("PEM block %d is a %q block, not a certificate", n, truncate(blk.Type, 40)))
			continue
		}
		cert, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			notes = append(notes, fmt.Sprintf("PEM block %d is not a readable certificate: %v", n, err))
			continue
		}
		out = append(out, rootCertEntry{Subject: subjectText(cert), SHA256: sha256Hex(blk.Bytes),
			NotBefore: cert.NotBefore.UTC().Format(time.RFC3339), NotAfter: cert.NotAfter.UTC().Format(time.RFC3339)})
	}
	if len(out) == 0 {
		notes = append(notes, tsaRootsPath+" contains no certificate")
	}
	if len(bytes.TrimSpace(rest)) > 0 && len(out) > 0 {
		notes = append(notes, "data after the last PEM block is ignored")
	}
	return out, strings.Join(notes, "; ")
}

// subjectText renders the main subject attributes of a certificate: "CN=..., OU=..., O=..., C=...".
func subjectText(c *x509.Certificate) string {
	s := c.Subject
	var parts []string
	add := func(k string, vs ...string) {
		for _, v := range vs {
			if v != "" {
				parts = append(parts, k+"="+v)
			}
		}
	}
	add("CN", s.CommonName)
	add("OU", s.OrganizationalUnit...)
	add("O", s.Organization...)
	add("L", s.Locality...)
	add("C", s.Country...)
	if len(parts) == 0 {
		return s.String()
	}
	return strings.Join(parts, ", ")
}
