package ticket

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path"
	"strings"
	"time"

	"attmonitor/internal/gateway"
	"attmonitor/internal/model"
)

// The setup-time capture: gateway pages saved before the monitor existed and imported into the
// ledger right after its genesis (bootstrap_import). The pages are read from the blob store,
// checked against the SHA-256 the import recorded and parsed with the gateway package's
// parsers. Time-stamp tokens imported with them are related to the imported files by hash:
// a token whose imprint is the SHA-256 of a manifest that lists a page's SHA-256 shows that
// the page existed when the token was issued (once the token is verified - see tsr.go).

// setupPages are the gateway pages the report reads from the capture.
var setupPages = []string{"fiberstat", "sysinfo", "broadbandstatistics"}

// maxSetupBlob bounds a capture file read for parsing or hash listing.
const maxSetupBlob = 8 << 20

// setupPageOf returns the gateway page an imported file is, from its name
// ("initial-snapshot/fiberstat.anon.html" -> "fiberstat"), or "".
func setupPageOf(p string) string {
	base := strings.ToLower(path.Base(strings.ReplaceAll(p, "\\", "/")))
	if !strings.HasSuffix(base, ".html") && !strings.HasSuffix(base, ".htm") {
		return ""
	}
	for _, pg := range setupPages {
		if strings.HasPrefix(base, pg+".") {
			return pg
		}
	}
	return ""
}

// tsaFromName names a token's TSA from its file name ("BOOTSTRAP-MANIFEST.digicert.tsr").
func tsaFromName(p string) string {
	base := strings.TrimSuffix(path.Base(strings.ReplaceAll(p, "\\", "/")), path.Ext(p))
	if i := strings.LastIndexByte(base, '.'); i >= 0 {
		base = base[i+1:]
	}
	switch strings.ToLower(base) {
	case "digicert":
		return "DigiCert"
	case "freetsa":
		return "FreeTSA"
	}
	return base
}

// blob reads an imported file and checks it against its recorded SHA-256.
func (c *collector) setupBlob(st *Setup, f model.BootstrapFile) ([]byte, bool) {
	id := strings.ToLower(strings.TrimSpace(f.SHA256))
	if f.Size > maxSetupBlob {
		return nil, false
	}
	data, err := c.r.GetBlob(id)
	if err != nil {
		st.Problems = append(st.Problems, fmt.Sprintf("%s: its stored copy (blob %s) is not available: %s", f.Path, shortHash(id), truncate(err.Error(), 100)))
		return nil, false
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != id {
		st.Problems = append(st.Problems, fmt.Sprintf("%s: its stored copy does not match the SHA-256 recorded at import; it is not used", f.Path))
		return nil, false
	}
	return data, true
}

// captureTime is the time of the capture's fiberstat page (else of its first page).
func (s *Setup) captureTime() time.Time {
	if s.Fiber != nil {
		return s.Fiber.Time
	}
	for _, p := range s.Pages {
		if !p.Time.IsZero() {
			return p.Time
		}
	}
	return s.TS
}

func (c *collector) setupCapture() *Setup {
	b := c.bootstrap
	if b == nil {
		return nil
	}
	st := &Setup{Seq: b.seq, TS: b.ts, SourceDir: b.b.SourceDir, Files: len(b.b.Files), UptimeSec: -1}
	bySHA := map[string]model.BootstrapFile{}
	for _, f := range b.b.Files {
		bySHA[strings.ToLower(f.SHA256)] = f
	}
	var snap model.GatewaySnapshot
	var sysTime time.Time
	for _, f := range b.b.Files {
		pg := setupPageOf(f.Path)
		if pg == "" {
			continue
		}
		sp := SetupPage{Page: pg, Path: f.Path, SHA256: strings.ToLower(f.SHA256)}
		sp.Time, _ = parseTS(f.ModTime)
		data, ok := c.setupBlob(st, f)
		if ok {
			var err error
			switch pg {
			case "fiberstat":
				if snap.Fiber == nil {
					snap.Fiber, err = gateway.ParseFiber(data)
				}
			case "sysinfo":
				if snap.System == nil {
					snap.System, err = gateway.ParseSysInfo(data)
					sysTime = sp.Time
				}
			case "broadbandstatistics":
				if snap.Broadband == nil {
					snap.Broadband, err = gateway.ParseBroadband(data)
				}
			}
			if err != nil {
				st.Problems = append(st.Problems, fmt.Sprintf("%s could not be parsed: %s", f.Path, truncate(err.Error(), 100)))
				ok = false
			}
		}
		sp.OK = ok
		st.Pages = append(st.Pages, sp)
	}
	for i := range st.Pages {
		if st.Pages[i].Page == "fiberstat" && st.Pages[i].OK && st.Fiber == nil {
			st.Fiber = &st.Pages[i]
		}
	}
	st.sys, st.bb, st.fiber = snap.System, snap.Broadband, snap.Fiber
	st.derived = gateway.Derive(&snap, sysTime, time.UTC)
	if st.Fiber != nil && snap.Fiber != nil {
		st.LastChange = snap.Fiber.LastChangeUnix
		d := gateway.Derive(&model.GatewaySnapshot{Fiber: snap.Fiber}, time.Time{}, time.UTC)
		if rd, ok := readingFromDerived(d, st.Fiber.Time, st.Seq); ok {
			rd.Setup, rd.Path = true, st.Fiber.Path
			st.Rx = &rd
		}
		st.InWindow = !st.Fiber.Time.IsZero() && !st.Fiber.Time.Before(c.from) && st.Fiber.Time.Before(c.to)
	}
	if si := snap.System; si != nil && !sysTime.IsZero() {
		if si.UptimeSec >= 0 {
			st.UptimeSec = si.UptimeSec
			st.Boot = sysTime.Add(-time.Duration(si.UptimeSec) * time.Second).UTC().Truncate(time.Second)
		}
		st.ClockRaw = strings.TrimSpace(si.GatewayTimeRaw)
		if off, ok := clockOffset(si.GatewayTimeRaw, sysTime); ok {
			st.Offset = &off
		}
	}

	// Time-stamp tokens, related to the imported files by hash.
	listed := map[string][]byte{} // imprint -> content of the time-stamped file
	for _, f := range b.b.Files {
		if !strings.EqualFold(path.Ext(f.Path), ".tsr") {
			continue
		}
		tk := SetupToken{Path: f.Path, SHA256: strings.ToLower(f.SHA256), TSA: tsaFromName(f.Path)}
		data, ok := c.setupBlob(st, f)
		if !ok {
			tk.Err = "its stored copy is not available"
			st.Tokens = append(st.Tokens, tk)
			continue
		}
		info, err := parseToken(data)
		if err != nil {
			tk.Err = truncate(err.Error(), 120)
			st.Tokens = append(st.Tokens, tk)
			continue
		}
		tk.Granted, tk.GenTime, tk.Imprint = info.Granted, info.GenTime, info.Imprint
		if info.TSA != "" {
			tk.TSA = info.TSA
		}
		if info.HashAlg == "SHA-256" {
			if cf, ok := bySHA[info.Imprint]; ok {
				tk.Covers = cf.Path
				if _, done := listed[info.Imprint]; !done {
					if content, ok := c.setupBlob(st, cf); ok {
						listed[info.Imprint] = bytes.ToLower(content)
					}
				}
			}
		}
		st.Tokens = append(st.Tokens, tk)
	}
	for i := range st.Pages {
		p := &st.Pages[i]
		for _, tk := range st.Tokens {
			content, ok := listed[tk.Imprint]
			if tk.Covers == "" || !ok || !tk.Granted || len(p.SHA256) != 64 {
				continue
			}
			if bytes.Contains(content, []byte(p.SHA256)) && !containsStr(p.ListedIn, tk.Covers) {
				p.ListedIn = append(p.ListedIn, tk.Covers)
			}
		}
	}
	for _, pr := range st.Problems {
		c.note("Setup-time capture: " + pr)
	}
	return st
}

func containsStr(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
