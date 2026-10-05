package export

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/digitorus/timestamp"

	"attmonitor/internal/contracts"
	"attmonitor/internal/model"
)

// fakeLedger is an in-memory ledger whose segments contain envelopes written exactly as
// docs/DESIGN.md §6 specifies (body serialized once, h = sha256(b), s = Ed25519(b), seq/prev
// chain, one segment per UTC day starting with segment_open). It implements
// contracts.LedgerReader for the exporter under test.
type fakeLedger struct {
	t      testing.TB
	priv   ed25519.PrivateKey
	pub    ed25519.PublicKey
	segs   []*fakeSeg
	blobs  map[string][]byte
	next   uint64
	head   model.Ref
	run    string
	monoT0 time.Time
	tsa    *testTSA

	// lastActive marks the last segment as the active one; tail is appended to its bytes as
	// an incomplete line (a record being written while the export reads the segment).
	lastActive bool
	tail       []byte
	hidden     map[string]bool // blobs GetBlob pretends not to have

	// cfgState, when set, is the configuration of the running process: like the monitor, the
	// fake then writes a config_state record right after the record that opened a new daily
	// segment (segment_open, that record, config_state).
	cfgState json.RawMessage

	// monoShift is added to the "mono" of every record written from now on: a wall clock
	// stepped back by d while the monotonic clock ran on is simulated by writing the later
	// records with ts - d and monoShift + d.
	monoShift time.Duration
}

type fakeSeg struct {
	name    string
	date    time.Time
	data    []byte
	first   uint64
	last    uint64
	records int
}

var _ contracts.LedgerReader = (*fakeLedger)(nil)

func newFakeLedger(t testing.TB) *fakeLedger {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &fakeLedger{t: t, priv: priv, pub: pub, blobs: map[string][]byte{}, run: "0123456789abcdef0123456789abcdef",
		tsa: newTestTSA(t), hidden: map[string]bool{}}
}

func (f *fakeLedger) fingerprint() string {
	s := sha256.Sum256(f.pub)
	return hex.EncodeToString(s[:])
}

func (f *fakeLedger) putBlob(content []byte) string {
	id := sha256Hex(content)
	f.blobs[id] = append([]byte(nil), content...)
	return id
}

// append writes one record, opening a new daily segment (with its segment_open record) when
// the record's UTC date is later than the active segment's.
func (f *fakeLedger) append(ts time.Time, typ string, data any, blobs ...string) model.Ref {
	f.t.Helper()
	ts = ts.UTC()
	if typ == model.TypeMonitorStart {
		// Every process start has its own run id (deterministic here).
		f.run = fmt.Sprintf("%032x", f.next+1)
	}
	day := time.Date(ts.Year(), ts.Month(), ts.Day(), 0, 0, 0, 0, time.UTC)
	opened := false
	if len(f.segs) == 0 {
		f.monoT0 = ts
		f.segs = append(f.segs, &fakeSeg{name: "ledger-" + day.Format("2006-01-02"), date: day})
	} else if cur := f.segs[len(f.segs)-1]; day.After(cur.date) {
		next := &fakeSeg{name: "ledger-" + day.Format("2006-01-02"), date: day}
		f.segs = append(f.segs, next)
		f.write(ts, model.TypeSegmentOpen, model.SegmentOpen{Segment: next.name, PrevSegment: cur.name,
			PrevSegmentSHA256: sha256Hex(cur.data), PrevSegmentRecords: cur.records, PrevSegmentLastSeq: cur.last})
		opened = true
	}
	ref := f.write(ts, typ, data, blobs...)
	if opened && f.cfgState != nil {
		f.write(ts, model.TypeConfigState, model.ConfigState{ConfigSHA256: sha256Hex(f.cfgState), Config: f.cfgState,
			Rules: rulesDescribed, Reason: "new_segment"})
	}
	return ref
}

// recordsOfType returns the (seq, ts) of every record of the given type, in ledger order.
func (f *fakeLedger) recordsOfType(typ string) []model.Ref {
	var out []model.Ref
	for _, r := range f.records() {
		if r.body.Type == typ {
			out = append(out, model.Ref{Seq: r.body.Seq, Hash: r.env.H, TS: r.body.TS})
		}
	}
	return out
}

func (f *fakeLedger) write(ts time.Time, typ string, data any, blobs ...string) model.Ref {
	f.t.Helper()
	for _, id := range blobs {
		if _, ok := f.blobs[id]; !ok {
			f.t.Fatalf("blob %s referenced before it was stored", id)
		}
	}
	raw, err := json.Marshal(data)
	if err != nil {
		f.t.Fatal(err)
	}
	prev := f.head.Hash
	if f.next == 0 {
		prev = model.ZeroHash
	}
	body := model.Body{V: model.FormatVersion, Seq: f.next, Prev: prev, TS: ts.Format(time.RFC3339Nano),
		Mono: ts.Sub(f.monoT0).Nanoseconds() + int64(f.monoShift), Run: f.run, Type: typ, Blobs: blobs, Data: raw}
	b, err := json.Marshal(body)
	if err != nil {
		f.t.Fatal(err)
	}
	env := model.Envelope{H: sha256Hex(b), S: base64.StdEncoding.EncodeToString(ed25519.Sign(f.priv, b)), B: string(b)}
	line, err := json.Marshal(env)
	if err != nil {
		f.t.Fatal(err)
	}
	seg := f.segs[len(f.segs)-1]
	seg.data = append(append(seg.data, line...), '\n')
	if seg.records == 0 {
		seg.first = f.next
	}
	seg.last = f.next
	seg.records++
	f.head = model.Ref{Seq: f.next, Hash: env.H, TS: body.TS}
	f.next++
	return f.head
}

// anchor time-stamps the current head with the test TSA and appends the anchor record.
func (f *fakeLedger) anchor(ts time.Time, tsaURL, reason string) model.Ref {
	f.t.Helper()
	digest, err := hex.DecodeString(f.head.Hash)
	if err != nil {
		f.t.Fatal(err)
	}
	token := f.tsa.stamp(f.t, digest, ts)
	id := f.putBlob(token)
	return f.append(ts, model.TypeAnchor, model.Anchor{TSAURL: tsaURL, TSAName: "CN=att-monitor test TSA", HeadSeq: f.head.Seq,
		HeadHash: f.head.Hash, TokenSHA256: id, GenTime: ts.UTC().Truncate(time.Second).Format(time.RFC3339),
		Serial: "01", Policy: "1.2.3.4.1", Nonce: "0102", Verified: true, ChainOK: true, Reason: reason}, id)
}

// segmentBytes returns the bytes OpenSegment serves for a segment.
func (f *fakeLedger) segmentBytes(name string) []byte {
	for i, s := range f.segs {
		if s.name == name {
			data := s.data
			if f.lastActive && i == len(f.segs)-1 && len(f.tail) > 0 {
				data = append(append([]byte(nil), data...), f.tail...)
			}
			return data
		}
	}
	return nil
}

// ----------------------------------------------------------------- contracts.LedgerReader

func (f *fakeLedger) records() []struct {
	env  model.Envelope
	body model.Body
} {
	var out []struct {
		env  model.Envelope
		body model.Body
	}
	for _, s := range f.segs {
		for _, line := range bytes.Split(bytes.TrimSuffix(s.data, []byte("\n")), []byte("\n")) {
			if len(line) == 0 {
				continue
			}
			env, body, err := parseLine(line)
			if err != nil {
				continue // tampered test data: unparseable lines are skipped by this fake
			}
			out = append(out, struct {
				env  model.Envelope
				body model.Body
			}{env, body})
		}
	}
	return out
}

func (f *fakeLedger) Scan(fromSeq uint64, fn func(model.Envelope, model.Body) error) error {
	for _, r := range f.records() {
		if r.body.Seq < fromSeq {
			continue
		}
		if err := fn(r.env, r.body); err != nil {
			if errors.Is(err, contracts.ErrStop) {
				return nil
			}
			return err
		}
	}
	return nil
}

func (f *fakeLedger) ScanTime(from, to time.Time, fn func(model.Envelope, model.Body) error) error {
	return f.Scan(0, func(env model.Envelope, body model.Body) error {
		t, ok := parseTS(body.TS)
		if !ok || t.Before(from) || !t.Before(to) {
			return nil
		}
		return fn(env, body)
	})
}

func (f *fakeLedger) Record(seq uint64) (model.Envelope, model.Body, error) {
	for _, r := range f.records() {
		if r.body.Seq == seq {
			return r.env, r.body, nil
		}
	}
	return model.Envelope{}, model.Body{}, contracts.ErrNotFound
}

func (f *fakeLedger) Segments() ([]contracts.SegmentInfo, error) {
	out := make([]contracts.SegmentInfo, 0, len(f.segs))
	for i, s := range f.segs {
		out = append(out, contracts.SegmentInfo{Name: s.name, Path: "mem:" + s.name, Date: s.date, FirstSeq: s.first,
			LastSeq: s.last, Records: s.records, Active: f.lastActive && i == len(f.segs)-1})
	}
	return out, nil
}

func (f *fakeLedger) OpenSegment(name string) (io.ReadCloser, error) {
	data := f.segmentBytes(name)
	if data == nil {
		return nil, contracts.ErrNotFound
	}
	return io.NopCloser(bytes.NewReader(data)), nil
}

func (f *fakeLedger) GetBlob(id string) ([]byte, error) {
	b, ok := f.blobs[id]
	if !ok || f.hidden[id] {
		return nil, fmt.Errorf("blob %s: %w", id, contracts.ErrNotFound)
	}
	return append([]byte(nil), b...), nil
}

// ----------------------------------------------------------------- test TSA

// testTSA issues real RFC 3161 TimeStampResp tokens (signed with a throw-away ECDSA key) so
// that bundle verifiers can parse them and compare their message imprint.
type testTSA struct {
	key  *ecdsa.PrivateKey
	cert *x509.Certificate
}

func newTestTSA(t testing.TB) *testTSA {
	return newTestTSAValid(t, "att-monitor test TSA", time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2036, 1, 1, 0, 0, 0, 0, time.UTC))
}

// newTestTSAValid creates a self-signed TSA certificate valid from notBefore to notAfter. Its
// extended key usage is timeStamping and critical (RFC 3161 §2.3), so that OpenSSL accepts
// tokens it signs when the certificate is given as -CAfile.
func newTestTSAValid(t testing.TB, cn string, notBefore, notAfter time.Time) *testTSA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	eku, err := asn1.Marshal([]asn1.ObjectIdentifier{{1, 3, 6, 1, 5, 5, 7, 3, 8}})
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		ExtraExtensions:       []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 37}, Critical: true, Value: eku}},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &testTSA{key: key, cert: cert}
}

// rootPEM returns the TSA certificate as PEM (it is its own root).
func (a *testTSA) rootPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: a.cert.Raw})
}

func (a *testTSA) stamp(t testing.TB, digest []byte, at time.Time) []byte {
	t.Helper()
	ts := &timestamp.Timestamp{
		HashAlgorithm:     crypto.SHA256,
		HashedMessage:     digest,
		Time:              at.UTC().Truncate(time.Second),
		Policy:            asn1.ObjectIdentifier{1, 2, 3, 4, 1},
		Nonce:             big.NewInt(0x0102),
		AddTSACertificate: true,
	}
	der, err := ts.CreateResponseWithOpts(a.cert, a.key, crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// ----------------------------------------------------------------- scenario

var testSoftware = model.SoftwareInfo{Name: "att-monitor", Version: "1.0.0-test", GoVersion: "go1.27", ExePath: `C:\Program Files\ATT Monitor\att-monitor.exe`,
	ExeSHA256: "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90", Rules: rulesDescribed}

var testHost = model.HostInfo{Hostname: "TESTHOST", OS: "Windows 11 Pro", OSVersion: "10.0.26200", TimeZone: "Pacific Standard Time"}

// scenario describes the synthetic ledger built by buildScenario.
type scenario struct {
	f          *fakeLedger
	incidentID string
	opened     time.Time
	closed     time.Time
	now        time.Time
	day2Blob   string // referenced only by a day-2 record
	pageBlob   string // fiberstat page referenced on day 3
	noteText   string
}

func ip(v int64) *int64 { return &v }

func bp(v bool) *bool { return &v }

func testProbes(gwOK, inetOK bool, inetPartial bool) []model.ProbeResult {
	p := func(name, kind, role, target string, ok bool, rtt int64) model.ProbeResult {
		r := model.ProbeResult{Name: name, Kind: kind, Role: role, Target: target, OK: ok}
		if ok {
			r.RTTus, r.Status = rtt, "IP_SUCCESS"
		} else {
			r.Status = "IP_REQ_TIMED_OUT"
		}
		return r
	}
	return []model.ProbeResult{
		p("gateway_icmp", model.KindICMP, model.RoleGateway, "192.168.1.254", gwOK, 1900),
		p("gateway_tcp", model.KindTCP, model.RoleGateway, "192.168.1.254:443", gwOK, 2100),
		p("isp_hop_icmp", model.KindICMP, model.RoleISPHop, "203.0.113.1", inetOK, 3500),
		p("inet_icmp_cloudflare", model.KindICMP, model.RoleInet, "1.1.1.1", inetOK, 9000),
		p("inet_icmp_google", model.KindICMP, model.RoleInet, "8.8.8.8", inetOK && !inetPartial, 11000),
		p("inet_tcp_cloudflare", model.KindTCP, model.RoleInet, "1.1.1.1:443", inetOK && !inetPartial, 12000),
	}
}

func (s *scenario) sample(start time.Time, cycle uint64, state, cause, attr, incident string) {
	gwOK, inetOK, partial := true, true, false
	switch state {
	case model.StateISPOutage:
		inetOK = false
	case model.StateDegraded:
		partial = true
	case model.StateLocalFault:
		gwOK, inetOK = false, false
	}
	v := model.Verdict{State: state, Cause: cause, Attribution: attr, Rules: rulesDescribed}
	if state == model.StateISPOutage {
		v.Reasons = []string{"gateway 192.168.1.254 answered ICMP in 1.9 ms", "0/4 internet probes succeeded"}
	}
	s.f.append(start.Add(1500*time.Millisecond), model.TypeSample, model.Sample{Cycle: cycle, Started: start.UTC().Format(time.RFC3339Nano),
		DurMs: 1500, Probes: testProbes(gwOK, inetOK, partial), Verdict: v, IncidentID: incident})
}

func (s *scenario) snapshot(at time.Time, rx int64, up bool, pon string, alarms []string, trigger string) model.Ref {
	page := []byte(fmt.Sprintf("<html><body><h1>Rx Power Currently %d</h1><p>\xa9 AT&T fiberstat %s</p></body></html>", rx, at.UTC().Format(time.RFC3339)))
	id := s.f.putBlob(page)
	s.pageBlob = id
	optical := "Up"
	if !up {
		optical = "Down"
	}
	conn := "Up"
	if !up {
		conn = "Down"
	}
	fetched := at.UTC().Format(time.RFC3339Nano)
	g := model.GatewaySnapshot{
		Pages: []model.PageCapture{
			{Page: "broadbandstatistics", URL: "https://192.168.1.254/cgi-bin/broadbandstatistics.ha", Status: 200, FetchedAt: fetched, DurMs: 900, Bytes: 9000, SHA256: sha256Hex([]byte("bb" + fetched))},
			{Page: "fiberstat", URL: "https://192.168.1.254/cgi-bin/fiberstat.ha", Status: 200, FetchedAt: fetched, DurMs: 700, Bytes: len(page), SHA256: id, Stored: true},
			{Page: "sysinfo", URL: "https://192.168.1.254/cgi-bin/sysinfo.ha", Status: 200, FetchedAt: fetched, DurMs: 500, Bytes: 4000, SHA256: sha256Hex([]byte("si" + fetched))},
		},
		System: &model.SystemInfo{Manufacturer: "NOKIA", Model: "BGW320-505", Serial: "TESTSERIAL0001", SoftwareVersion: "6.34.7",
			HardwareVersion: "02001E0046004D", UptimeRaw: "274686", UptimeSec: 274686, GatewayTimeRaw: "2026-10-03T05:00:00"},
		Broadband: &model.BroadbandStatus{ConnectionSource: "FIBER", Connection: conn, IPv4: "198.51.100.7", GatewayIPv4: "203.0.113.1", PONLinkStatus: pon},
		Fiber: &model.FiberStatus{OpticalStatus: optical, Measures: []model.DMIMeasure{
			{Name: "Rx Power", CurrentRaw: fmt.Sprint(rx), Current: ip(rx), Unit: "0.1dBm",
				LowAlarm:  model.Threshold{Active: true, Raw: "1 (Threshold -295)", Threshold: ip(-295)},
				LowWarn:   model.Threshold{Active: true, Raw: "1 (Threshold -292)", Threshold: ip(-292)},
				HighAlarm: model.Threshold{Raw: "0 (Threshold -70)", Threshold: ip(-70)}, HighWarn: model.Threshold{Raw: "0 (Threshold -80)", Threshold: ip(-80)}},
			{Name: "Tx Power", CurrentRaw: "56", Current: ip(56), Unit: "0.1dBm"},
		}},
		Derived: model.GatewayDerived{Reachable: true, BroadbandUp: bp(up), PONOperational: bp(pon == "OPERATION (O5)"), OpticalUp: bp(up),
			WANIPv4: "198.51.100.7", ISPNextHop: "203.0.113.1", RxPowerX10: ip(rx), TxPowerX10: ip(56), RxLowAlarmX10: ip(-295), RxLowWarnX10: ip(-292),
			Alarms: alarms, UptimeSec: 274686, Firmware: "6.34.7", Serial: "TESTSERIAL0001", Model: "BGW320-505", GatewayClockBlank: !up},
		Trigger: trigger,
	}
	return s.f.append(at.Add(2*time.Second), model.TypeGatewaySnapshot, g, id)
}

// buildScenario writes four daily segments:
//
//	2026-10-01 genesis, bootstrap import, anchor, monitor start/stop, config change
//	2026-10-02 a short monitoring session (outside the incident export)
//	2026-10-03 optical alarm snapshots, an ISP_OUTAGE incident 12:05:10-12:07:10, a blip,
//	           notes, a suspend/resume gap and anchors
//	2026-10-04 a short session (the last, possibly active, segment)
func buildScenario(t testing.TB) *scenario {
	t.Helper()
	f := newFakeLedger(t)
	s := &scenario{f: f, now: time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC)}
	d1 := time.Date(2026, 10, 1, 10, 0, 0, 0, time.UTC)
	f.append(d1, model.TypeGenesis, model.Genesis{PublicKey: base64.StdEncoding.EncodeToString(f.pub), Fingerprint: f.fingerprint(),
		Created: d1.Format(time.RFC3339Nano), Host: testHost, Software: testSoftware, Statement: "Evidence ledger for the AT&T Fiber service at this address."})
	notes := "BOOTSTRAP EVIDENCE - CAPTURE NOTES\r\nBroadband Status Notification changed from ON to OFF <b>at the owner's request</b> & verified.\r\n"
	n1 := f.putBlob([]byte(notes))
	n2 := f.putBlob([]byte("<html>events.before (bbevent checked)</html>"))
	f.append(d1.Add(time.Second), model.TypeBootstrapImport, model.BootstrapImport{SourceDir: `C:\RC\att_monitor\evidence\bootstrap`,
		Files: []model.BootstrapFile{{Path: "CAPTURE-NOTES.txt", SHA256: n1, Size: int64(len(notes)), ModTime: "2026-10-05T03:19:00Z"},
			{Path: "events.before.html", SHA256: n2, Size: 44, ModTime: "2026-10-05T03:14:30Z"}}, Notes: notes}, n1, n2)
	f.anchor(d1.Add(2*time.Second), "http://timestamp.digicert.com", "genesis")
	// Every monitor_start records the (default) configuration, as rules 2026.10-3 monitors do.
	cfg := testConfigJSON(t, "10s", "2m30s", 3, 3, 6, 20, 150, 20, defaultTargetSpecs()...)
	f.append(d1.Add(3*time.Second), model.TypeMonitorStart, model.MonitorStart{Software: testSoftware, Host: testHost, ConfigSHA256: sha256Hex(cfg),
		Config: cfg, Mode: "service", PrevHead: f.head})
	for i := 0; i < 6; i++ {
		s.sample(d1.Add(time.Duration(10+10*i)*time.Second), uint64(i+1), model.StateOnline, "", model.AttrNone, "")
	}
	f.append(d1.Add(70*time.Second), model.TypeConfigChange, model.ConfigChange{Target: "gateway", What: "events.bbevent (Broadband Status Notification)",
		Before: "on", After: "off", Actor: "operator via web", Result: "verified"})
	f.append(d1.Add(80*time.Second), model.TypeMonitorStop, model.MonitorStop{Reason: "service stop", UptimeSec: 77})

	d2 := time.Date(2026, 10, 2, 8, 0, 0, 0, time.UTC)
	f.append(d2, model.TypeMonitorStart, model.MonitorStart{Software: testSoftware, Host: testHost, Mode: "service", PrevHead: f.head, GapSeconds: 79000, PrevStopped: true,
		ConfigSHA256: sha256Hex(cfg), Config: cfg})
	for i := 0; i < 3; i++ {
		s.sample(d2.Add(time.Duration(10+10*i)*time.Second), uint64(i+1), model.StateOnline, "", model.AttrNone, "")
	}
	s.day2Blob = f.putBlob([]byte("<html>day 2 page</html>"))
	f.append(d2.Add(45*time.Second), model.TypeLocalLink, model.LocalLink{Interface: "Wi-Fi", Type: "wifi", State: "connected", RawSHA256: s.day2Blob}, s.day2Blob)
	f.append(d2.Add(50*time.Second), model.TypeMonitorStop, model.MonitorStop{Reason: "service stop", UptimeSec: 50})

	d3 := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	f.append(d3, model.TypeMonitorStart, model.MonitorStart{Software: testSoftware, Host: testHost, Mode: "service", PrevHead: f.head, GapSeconds: 100000, PrevStopped: true,
		ConfigSHA256: sha256Hex(cfg), Config: cfg})
	f.append(d3.Add(time.Second), model.TypeLocalLink, model.LocalLink{Interface: "Wi-Fi", Type: "wifi", State: "connected", SSID: "TestNet", BSSID: "aa:bb:cc:dd:ee:ff", SignalPct: 80})
	alarms := []string{codeRxLowAlarm, codeRxLowWarn}
	cycle := uint64(0)
	at := d3.Add(10 * time.Second)
	next := func() time.Time { cycle++; t := at; at = at.Add(10 * time.Second); return t }
	var lastSnap model.Ref
	for i := 0; i < 30; i++ { // 12:00:10 .. 12:05:00 ONLINE
		st := next()
		s.sample(st, cycle, model.StateOnline, "", model.AttrNone, "")
		if i%6 == 0 {
			lastSnap = s.snapshot(st.Add(3*time.Second), -315, true, "OPERATION (O5)", alarms, "periodic")
			f.append(st.Add(6*time.Second), model.TypeServiceCheck, model.ServiceCheck{
				DNS:  []model.DNSResult{{Server: "192.168.1.254:53", ServerRole: "gateway", Name: "www.google.com", QType: "A", OK: true, RCode: "NOERROR", Answers: []string{"142.250.72.4"}}},
				HTTP: []model.HTTPResult{{Name: "msft_connecttest", URL: "http://www.msftconnecttest.com/connecttest.txt", OK: true, Status: 200}},
			})
		}
	}
	// ISP outage: 12:05:10 .. 12:07:00 (12 bad cycles), closed at 12:07:10.
	s.opened = at
	s.incidentID = "INC-20261003-120510Z"
	var firstBad uint64
	for i := 0; i < 12; i++ {
		st := next()
		inc := ""
		if i >= 2 {
			inc = s.incidentID
		}
		s.sample(st, cycle, model.StateISPOutage, model.CauseFiberLinkDown, model.AttrProvider, inc)
		if i == 0 {
			firstBad = f.head.Seq
		}
		if i == 2 {
			f.append(st.Add(2*time.Second), model.TypeIncidentOpen, model.Incident{ID: s.incidentID, Opened: s.opened.Format(time.RFC3339Nano), Open: true,
				State: model.StateISPOutage, Cause: model.CauseFiberLinkDown, Attribution: model.AttrProvider, Causes: []string{model.CauseFiberLinkDown},
				Summary: "Internet unreachable while the AT&T gateway answered; gateway reports PON link down", Rules: rulesDescribed, FirstSeq: firstBad,
				Reasons: []string{"AT&T gateway reports PON Link Status: LOS (O1)", "0/4 internet probes succeeded"}})
			snap := s.snapshot(st.Add(3*time.Second), -402, false, "LOS (O1)", alarms, "incident")
			f.append(st.Add(6*time.Second), model.TypeGatewayEvent, model.GatewayEvent{Kind: model.GwEvPONState, Before: "OPERATION (O5)", After: "LOS (O1)", Evidence: []uint64{lastSnap.Seq, snap.Seq}})
			f.append(st.Add(7*time.Second), model.TypeGatewayEvent, model.GatewayEvent{Kind: model.GwEvBroadbandState, Before: "Up", After: "Down", Evidence: []uint64{lastSnap.Seq, snap.Seq}})
			f.append(st.Add(8*time.Second), model.TypeTraceroute, model.Traceroute{Target: "8.8.8.8", Trigger: "incident_open", Incident: s.incidentID,
				Hops: []model.Hop{{TTL: 1, Addr: "192.168.1.254", RTTus: 1800, Status: "IP_TTL_EXPIRED_TRANSIT"}, {TTL: 2, Status: "IP_REQ_TIMED_OUT"}}})
		}
		if i == 4 { // the gateway's outage redirect answering DNS and HTTP
			f.append(st.Add(6*time.Second), model.TypeServiceCheck, model.ServiceCheck{
				DNS: []model.DNSResult{{Server: "192.168.1.254:53", ServerRole: "gateway", Name: "www.google.com", QType: "A", OK: true, RCode: "NOERROR",
					Answers: []string{"192.168.1.254"}, Hijacked: true, HijackWhy: "answer is the gateway address"}},
				HTTP: []model.HTTPResult{{Name: "msft_connecttest", URL: "http://www.msftconnecttest.com/connecttest.txt", Status: 302,
					Location: "http://192.168.1.254/cgi-bin/redirect.ha", RemoteAddr: "192.168.1.254:80", Hijacked: true, HijackWhy: "redirect to the gateway"}},
			})
		}
	}
	s.closed = at
	var lastBad uint64
	for i := 0; i < 3; i++ {
		st := next()
		s.sample(st, cycle, model.StateOnline, "", model.AttrNone, s.incidentID)
		lastBad = f.head.Seq
	}
	snapAfter := s.snapshot(at.Add(-5*time.Second), -316, true, "OPERATION (O5)", alarms, "incident")
	f.append(at.Add(-2*time.Second), model.TypeIncidentClose, model.Incident{ID: s.incidentID, Opened: s.opened.Format(time.RFC3339Nano),
		Closed: s.closed.Format(time.RFC3339Nano), DurationSec: 120, Open: false, State: model.StateISPOutage, Cause: model.CauseFiberLinkDown,
		Attribution: model.AttrProvider, Causes: []string{model.CauseFiberLinkDown}, Summary: "Internet unreachable for 2m 00s; AT&T gateway reported its PON link down",
		Rules: rulesDescribed, FirstSeq: firstBad, LastSeq: lastBad,
		Evidence: []model.EvidenceRef{{Seq: snapAfter.Seq, Type: model.TypeGatewaySnapshot, Blob: s.pageBlob}},
		Stats: model.IncidentStats{Cycles: 15, BadCycles: 12, ProbeOK: map[string]int{"gateway_icmp": 15, "inet_icmp_google": 3},
			ProbeTotal: map[string]int{"gateway_icmp": 15, "inet_icmp_google": 15}, GatewayFetches: 9, GatewayDownSeen: true, PONDownSeen: true, OpticalAlarm: true,
			DowntimeSec: 120}})
	f.append(at.Add(-time.Second), model.TypeGatewayEvent, model.GatewayEvent{Kind: model.GwEvOpticalLinkChange, Before: "1791151188", After: "1791158830"})
	f.anchor(at.Add(-500*time.Millisecond), "https://freetsa.org/tsr", "incident_close")
	for i := 0; i < 6; i++ {
		s.sample(next(), cycle, model.StateOnline, "", model.AttrNone, "")
	}
	for i := 0; i < 2; i++ { // blip
		s.sample(next(), cycle, model.StateDegraded, model.CausePacketLoss, model.AttrUndetermined, "")
	}
	for i := 0; i < 6; i++ {
		s.sample(next(), cycle, model.StateOnline, "", model.AttrNone, "")
	}
	s.noteText = "AT&T ticket #12345 opened <script>alert(1)</script>"
	f.append(at, model.TypeOperatorNote, model.OperatorNote{Text: s.noteText, Author: "Owner", Source: "web"})
	f.append(at.Add(time.Second), model.TypeCustodyExport, model.CustodyExport{From: "2026-10-01T00:00:00Z", To: "2026-10-02T00:00:00Z",
		FileName: "att-evidence_20261001T0000Z_20261002T0000Z_deadbeef.zip", BundleSHA256: sha256Hex([]byte("old bundle")), Records: 12, Blobs: 3, PreparedBy: "Owner", Requester: "web 127.0.0.1"})
	f.append(at.Add(2*time.Second), model.TypeClockCheck, model.ClockCheck{Results: []model.ClockResult{{Server: "time.windows.com", OK: true, OffsetMs: -12, RTTms: 30}}})
	f.append(at.Add(3*time.Second), model.TypePowerEvent, model.PowerEvent{Kind: "suspend"})
	resume := at.Add(20 * time.Minute)
	f.append(resume, model.TypePowerEvent, model.PowerEvent{Kind: "resume_automatic"})
	at = resume.Add(10 * time.Second)
	for i := 0; i < 6; i++ {
		s.sample(next(), cycle, model.StateOnline, "", model.AttrNone, "")
	}
	f.append(at, model.TypeHeartbeat, model.Heartbeat{UptimeSec: 2000, Cycles: cycle, State: model.StateOnline})
	f.anchor(at.Add(time.Second), "http://timestamp.digicert.com", "periodic")

	d4 := time.Date(2026, 10, 4, 9, 0, 0, 0, time.UTC)
	f.append(d4, model.TypeMonitorStart, model.MonitorStart{Software: testSoftware, Host: testHost, Mode: "service", PrevHead: f.head, GapSeconds: 70000, PrevStopped: false,
		ConfigSHA256: sha256Hex(cfg), Config: cfg})
	for i := 0; i < 3; i++ {
		s.sample(d4.Add(time.Duration(10+10*i)*time.Second), uint64(i+1), model.StateOnline, "", model.AttrNone, "")
	}
	f.append(d4.Add(time.Minute), model.TypeHeartbeat, model.Heartbeat{UptimeSec: 60, Cycles: 3, State: model.StateOnline})
	return s
}

// ----------------------------------------------------------------- fakes for Verifier/Actions

type fakeVerifier struct {
	rep model.VerifyReport
	err error
}

func (v *fakeVerifier) Verify(context.Context) (model.VerifyReport, error) { return v.rep, v.err }

type fakeActions struct {
	mu      sync.Mutex
	exports []model.CustodyExport
	err     error
}

func (a *fakeActions) Note(context.Context, string, string, string) (model.Ref, error) {
	return model.Ref{}, errors.New("not implemented")
}

func (a *fakeActions) SetGatewayNotification(context.Context, bool, string) (model.ConfigChange, error) {
	return model.ConfigChange{}, errors.New("not implemented")
}

func (a *fakeActions) AnchorNow(context.Context, string) ([]model.Anchor, error) {
	return nil, errors.New("not implemented")
}

// TrustCert is never used by the exporter; the fake only completes contracts.Actions
// (actor, expectedSHA256: the pending fingerprint the operator reviewed).
func (a *fakeActions) TrustCert(context.Context, string, string) (model.ConfigChange, error) {
	return model.ConfigChange{}, errors.New("not implemented")
}

func (a *fakeActions) RecordExport(ctx context.Context, e model.CustodyExport) (model.Ref, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.err != nil {
		return model.Ref{}, a.err
	}
	a.exports = append(a.exports, e)
	return model.Ref{Seq: 4242, Hash: sha256Hex([]byte(e.BundleSHA256)), TS: "2026-10-05T00:00:01Z"}, nil
}

var (
	_ contracts.Verifier = (*fakeVerifier)(nil)
	_ contracts.Actions  = (*fakeActions)(nil)
)
