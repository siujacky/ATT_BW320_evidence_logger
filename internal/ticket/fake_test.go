package ticket

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"attmonitor/internal/contracts"
	"attmonitor/internal/model"
)

// fakeReader is an in-memory contracts.LedgerReader. Envelopes carry h = SHA-256(b) and the
// prev chain; they are not signed (the ticket does not check signatures - the bundle verifier
// does).
type fakeReader struct {
	t     testing.TB
	recs  []fakeRec
	blobs map[string][]byte
	run   string
	head  string
	t0    time.Time
	// scanErr, when set, is returned by ScanTime.
	scanErr error
}

type fakeRec struct {
	env  model.Envelope
	body model.Body
	ts   time.Time
}

var _ contracts.LedgerReader = (*fakeReader)(nil)

func newFake(t testing.TB) *fakeReader {
	return &fakeReader{t: t, blobs: map[string][]byte{}, run: "4c3a84f36e0e30805c97de5c200bb064", head: model.ZeroHash}
}

func sha256Hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func (f *fakeReader) putBlob(b []byte) string {
	id := sha256Hex(b)
	f.blobs[id] = append([]byte(nil), b...)
	return id
}

// add appends a record and returns its seq.
func (f *fakeReader) add(ts time.Time, typ string, data any, blobs ...string) uint64 {
	f.t.Helper()
	raw, err := json.Marshal(data)
	if err != nil {
		f.t.Fatal(err)
	}
	if f.t0.IsZero() {
		f.t0 = ts
	}
	seq := uint64(len(f.recs))
	body := model.Body{V: model.FormatVersion, Seq: seq, Prev: f.head, TS: ts.UTC().Format(time.RFC3339Nano),
		Mono: int64(ts.Sub(f.t0)), Run: f.run, Type: typ, Blobs: blobs, Data: raw}
	b, err := json.Marshal(body)
	if err != nil {
		f.t.Fatal(err)
	}
	env := model.Envelope{H: sha256Hex(b), B: string(b)}
	f.head = env.H
	f.recs = append(f.recs, fakeRec{env: env, body: body, ts: ts.UTC()})
	return seq
}

// addRaw appends a record whose data is the given JSON text (possibly invalid).
func (f *fakeReader) addRaw(ts time.Time, typ string, data string) uint64 {
	f.t.Helper()
	seq := uint64(len(f.recs))
	body := model.Body{V: model.FormatVersion, Seq: seq, Prev: f.head, TS: ts.UTC().Format(time.RFC3339Nano), Run: f.run, Type: typ, Data: json.RawMessage(data)}
	env := model.Envelope{H: sha256Hex([]byte(data)), B: data}
	f.head = env.H
	f.recs = append(f.recs, fakeRec{env: env, body: body, ts: ts.UTC()})
	return seq
}

func (f *fakeReader) Scan(fromSeq uint64, fn func(model.Envelope, model.Body) error) error {
	for _, r := range f.recs {
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

func (f *fakeReader) ScanTime(from, to time.Time, fn func(model.Envelope, model.Body) error) error {
	if f.scanErr != nil {
		return f.scanErr
	}
	for _, r := range f.recs {
		if r.ts.Before(from) || !r.ts.Before(to) {
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

func (f *fakeReader) Record(seq uint64) (model.Envelope, model.Body, error) {
	if seq >= uint64(len(f.recs)) {
		return model.Envelope{}, model.Body{}, contracts.ErrNotFound
	}
	r := f.recs[seq]
	return r.env, r.body, nil
}

func (f *fakeReader) Segments() ([]contracts.SegmentInfo, error) { return nil, nil }

func (f *fakeReader) OpenSegment(string) (io.ReadCloser, error) { return nil, contracts.ErrNotFound }

func (f *fakeReader) GetBlob(id string) ([]byte, error) {
	b, ok := f.blobs[id]
	if !ok {
		return nil, fmt.Errorf("blob %s: %w", id, contracts.ErrNotFound)
	}
	return append([]byte(nil), b...), nil
}

// ---------------------------------------------------------------- fixtures

func fixture(t testing.TB, rel string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "testdata", filepath.FromSlash(rel)))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func ts(s string) time.Time {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		panic(err)
	}
	return t
}

func i64(v int64) *int64 { return &v }
func bptr(v bool) *bool  { return &v }

// Real-situation constants (docs/DESIGN.md §2, testdata/gateway/README.md).
const (
	lastChange   = int64(1791151188) // 2026-10-04T21:59:48Z read as UTC
	fixSerial    = "N00SERIAL00000"  // testdata/gateway/sysinfo.html (sanitized)
	fixFirmware  = "6.34.7"
	fixModel     = "BGW320-505"
	gatewayBoot  = "2026-10-01T22:52:37Z"
	cdtOffsetSec = -5 * 3600
)

var cdt = time.FixedZone("CDT", cdtOffsetSec)

// opts are the scenario's report options.
type scenario struct {
	f        *fakeReader
	now      time.Time
	from, to time.Time
	start    time.Time // monitor start
	snaps    []uint64
	samples  []uint64
	links    []uint64
	boot     uint64 // bootstrap_import seq
}

func (s *scenario) options() Options {
	return Options{From: s.from, To: s.to, Now: func() time.Time { return s.now }, Location: cdt, Generator: "att-monitor test",
		BundleName: "att-evidence_20261004T140000Z_20261005T140000Z_6961b23f.zip", BundleSHA256: sha256Hex([]byte("bundle")),
		Verification: "OK: 512 records, 0 failures, 4 time-stamps chain-verified (att-monitor verify-bundle)"}
}

// genesisData is a genesis payload with a matching fingerprint.
func genesisData() model.Genesis {
	pub := make([]byte, 32)
	for i := range pub {
		pub[i] = byte(i + 1)
	}
	return model.Genesis{PublicKey: "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=", Fingerprint: sha256Hex(pub),
		Created: "2026-10-05T12:45:47.5635624Z", Host: model.HostInfo{Hostname: "DESKTOP-TEST"},
		Software: model.SoftwareInfo{Name: "att-monitor", Version: "1.0.0", Rules: "2026.10-4"}, Statement: "genesis"}
}

// setupGenTime is the genTime of the real setup-time tokens (testdata/tsa).
var setupGenTime = ts("2026-10-05T03:19:57Z")

// addBootstrap imports the setup-time capture as the real installation did: the gateway pages
// under their initial-snapshot names (the sanitized fixtures), a BOOTSTRAP-MANIFEST.sha256 in
// the real manifest's format listing their SHA-256, and two time-stamp tokens over that manifest
// stating the real tokens' genTime. The tokens are synthetic and unsigned (the report reads
// what a token states and never claims to verify it): the real tokens cover the real manifest,
// which lists the real pages, not the sanitized fixtures - see addRealBootstrap.
func (s *scenario) addBootstrap(at time.Time) { s.addBootstrapFiles(at, false) }

// addRealBootstrap imports the sanitized fixture pages with the real manifest and its two real
// tokens: the manifest does not list the fixtures' SHA-256.
func (s *scenario) addRealBootstrap(at time.Time) { s.addBootstrapFiles(at, true) }

// setupManifest is the manifest addBootstrap imports.
func setupManifest(t testing.TB) []byte {
	var m []byte
	for _, p := range []struct{ name, fixture, at string }{
		{"broadbandstatistics.anon.html", "gateway/broadbandstatistics.html", "2026-10-05T03:10:45Z"},
		{"fiberstat.anon.html", "gateway/fiberstat.html", "2026-10-05T03:10:46Z"},
		{"sysinfo.anon.html", "gateway/sysinfo.html", "2026-10-05T03:10:44Z"},
	} {
		m = append(m, fmt.Sprintf("%s  initial-snapshot/%s  %s\n", sha256Hex(fixture(t, p.fixture)), p.at, p.name)...)
	}
	return m
}

func (s *scenario) addBootstrapFiles(at time.Time, realTokens bool) {
	f := s.f
	file := func(path, mod string, content []byte) model.BootstrapFile {
		return model.BootstrapFile{Path: path, SHA256: f.putBlob(content), Size: int64(len(content)), ModTime: mod}
	}
	manifest := setupManifest(f.t)
	sum := sha256.Sum256(manifest)
	digicert, freetsa := syntheticTokenSerial(f.t, sum[:], setupGenTime, 0, 1), syntheticTokenSerial(f.t, sum[:], setupGenTime, 0, 2)
	if realTokens {
		manifest, digicert, freetsa = fixture(f.t, "tsa/manifest.txt"), fixture(f.t, "tsa/digicert.tsr"), fixture(f.t, "tsa/freetsa.tsr")
	}
	files := []model.BootstrapFile{
		file("BOOTSTRAP-MANIFEST.digicert.tsr", "2026-10-05T03:19:57.5354461Z", digicert),
		file("BOOTSTRAP-MANIFEST.freetsa.tsr", "2026-10-05T03:19:57.8392252Z", freetsa),
		file("BOOTSTRAP-MANIFEST.sha256", "2026-10-05T03:19:57.14148Z", manifest),
		file("CAPTURE-NOTES.txt", "2026-10-05T03:24:03.2304066Z", []byte("BOOTSTRAP EVIDENCE - CAPTURE NOTES\n")),
		file("initial-snapshot/broadbandstatistics.anon.html", "2026-10-05T03:10:45.4986997Z", fixture(f.t, "gateway/broadbandstatistics.html")),
		file("initial-snapshot/fiberstat.anon.html", "2026-10-05T03:10:46.3389106Z", fixture(f.t, "gateway/fiberstat.html")),
		file("initial-snapshot/sysinfo.anon.html", "2026-10-05T03:10:44.2000000Z", fixture(f.t, "gateway/sysinfo.html")),
	}
	ids := make([]string, len(files))
	for i, fl := range files {
		ids[i] = fl.SHA256
	}
	s.boot = f.add(at, model.TypeBootstrapImport, model.BootstrapImport{SourceDir: `C:\RC\att_monitor\evidence\bootstrap`, Files: files, Notes: "notes"}, ids...)
}

// snapshot builds a gateway_snapshot like the monitor's, with the gateway's own Rx reading and
// flags.
func snapshot(at time.Time, rx int64, alarm, warn bool, uptime int64, last int64) model.GatewaySnapshot {
	fetched := at.Add(-1200 * time.Millisecond)
	var codes []string
	if alarm {
		codes = append(codes, codeRxLowAlarm)
	}
	if warn {
		codes = append(codes, codeRxLowWarn)
	}
	flag := func(on bool, thr int64) model.Threshold {
		v := "0"
		if on {
			v = "1"
		}
		return model.Threshold{Active: on, Raw: fmt.Sprintf("%s (Threshold %d)", v, thr), Threshold: i64(thr)}
	}
	boot := fetched.Add(-time.Duration(uptime) * time.Second).UTC().Format(time.RFC3339)
	return model.GatewaySnapshot{
		Pages: []model.PageCapture{
			{Page: "broadbandstatistics", Status: 200, FetchedAt: fetched.Add(-2 * time.Second).Format(time.RFC3339Nano)},
			{Page: "fiberstat", Status: 200, FetchedAt: fetched.Add(-time.Second).Format(time.RFC3339Nano)},
			{Page: "sysinfo", Status: 200, FetchedAt: fetched.Format(time.RFC3339Nano)},
		},
		System: &model.SystemInfo{Manufacturer: "NOKIA", Model: fixModel, Serial: fixSerial, SoftwareVersion: fixFirmware,
			HardwareVersion: "02001E0046004F", UptimeRaw: fmt.Sprint(uptime), UptimeSec: uptime,
			GatewayTimeRaw: fetched.In(cdt).Format("2006-01-02T15:04:05"), GatewayTimePresent: true},
		Broadband: &model.BroadbandStatus{ConnectionSource: "FIBER", Connection: "Up", NetworkType: "Lightspeed", IPv4: "203.0.113.20",
			GatewayIPv4: "203.0.113.1", PrimaryDNS: "68.94.156.9", SecondaryDNS: "68.94.157.9", PONLinkStatus: "OPERATION (O5)", UNIStatus: "up"},
		Fiber: &model.FiberStatus{OpticalStatus: "Up", LinkState: "Up", LastChangeRaw: fmt.Sprint(last), LastChangeUnix: last,
			VendorName: "HUMAX Networks", VendorPN: "HNXGSPP-MAAMC", WaveLength: "1270 nm", RxLOSState: "1", OptLOS: "0", TxFaultState: "0",
			Measures: []model.DMIMeasure{
				{Name: "Temperature", CurrentRaw: "34", Current: i64(34), Unit: "C"},
				{Name: "Rx Power", CurrentRaw: fmt.Sprint(rx), Current: i64(rx), Unit: "0.1dBm",
					LowAlarm: flag(alarm, -295), HighAlarm: flag(false, -90), LowWarn: flag(warn, -292), HighWarn: flag(false, -100)},
			}},
		Derived: model.GatewayDerived{Reachable: true, BroadbandUp: bptr(true), PONOperational: bptr(true), OpticalUp: bptr(true),
			WANIPv4: "203.0.113.20", ISPNextHop: "203.0.113.1", ISPDNS: "68.94.156.9",
			RxPowerX10: i64(rx), TxPowerX10: i64(48), RxLowAlarmX10: i64(-295), RxLowWarnX10: i64(-292), Alarms: codes,
			UptimeSec: uptime, BootTimeEstimate: boot, Firmware: fixFirmware, Serial: fixSerial, Model: fixModel, FiberLastChange: last},
		Trigger: "periodic",
	}
}

// sample builds an ONLINE (or other state) cycle with the gateway answering in rttUs.
func sample(cycle uint64, started time.Time, state, attr string, gwOK bool, rttUs int64, inetOK bool, incident string) model.Sample {
	p := func(name, kind, role, target string, ok bool, rtt int64) model.ProbeResult {
		st := "IP_SUCCESS"
		if kind == model.KindTCP {
			st = "connected"
		}
		if !ok {
			st, rtt = "IP_REQ_TIMED_OUT", 0
			if kind == model.KindTCP {
				st = "timeout"
			}
		}
		return model.ProbeResult{Name: name, Kind: kind, Role: role, Target: target, OK: ok, RTTus: rtt, Status: st}
	}
	return model.Sample{Cycle: cycle, Started: started.UTC().Format(time.RFC3339Nano), DurMs: 12, IncidentID: incident,
		Probes: []model.ProbeResult{
			p("gateway_icmp", model.KindICMP, model.RoleGateway, "192.168.1.254", gwOK, rttUs),
			p("gateway_tcp", model.KindTCP, model.RoleGateway, "192.168.1.254:443", gwOK, rttUs+300),
			p("inet_icmp_cloudflare", model.KindICMP, model.RoleInet, "1.1.1.1", inetOK, 6000),
			p("inet_icmp_google", model.KindICMP, model.RoleInet, "8.8.8.8", inetOK, 6100),
			p("inet_tcp_google", model.KindTCP, model.RoleInet, "8.8.8.8:443", inetOK, 8200),
		},
		Verdict: model.Verdict{State: state, Attribution: attr, Rules: "2026.10-4"}}
}

func wifi(signal int, bypass bool) model.LocalLink {
	return model.LocalLink{Interface: "Wi-Fi", Type: "wifi", State: "connected", LocalIP: "192.168.1.71", GatewayIP: "192.168.1.254",
		SSID: "ATTtest", BSSID: "00:00:5e:00:53:02", SignalPct: signal, RSSIdBm: -58, Channel: 149, Band: "5 GHz", RadioType: "802.11ax",
		RxMbps: 721, TxMbps: 576, LinkMbps: 576,
		Egress: &model.EgressCheck{Gateway: "192.168.1.254", Bypass: bypass, Routes: []model.EgressRoute{
			{Target: "1.1.1.1", NextHop: "192.168.1.254", ViaGateway: !bypass}, {Target: "8.8.8.8", NextHop: "192.168.1.254", ViaGateway: true}}}}
}

var testConfig = json.RawMessage(`{"version":1,"probes":{"fast_interval":"10s","timeout":"2s"},"incident":{"open_after_cycles":3,"gateway_latency_ok_ms":20}}`)

// realScenario mirrors the real installation: a setup-time capture at 03:10 UTC, the ledger
// created and the monitor started at 12:45:47 UTC, 10-second cycles until the end of the window
// at 14:00 UTC, a gateway snapshot every minute with Rx -309..-315 and both low-Rx flags set,
// Wi-Fi 5 GHz at 82-84 %, and trusted anchors.
func realScenario(t testing.TB) *scenario {
	f := newFake(t)
	s := &scenario{f: f, now: ts("2026-10-05T14:00:00Z")}
	s.to, s.from = s.now, s.now.Add(-24*time.Hour)
	g := ts("2026-10-05T12:45:47.5635624Z")
	f.add(g, model.TypeGenesis, genesisData())
	s.addBootstrap(g.Add(68 * time.Millisecond))
	s.start = g.Add(81 * time.Millisecond)
	f.add(s.start, model.TypeMonitorStart, model.MonitorStart{Mode: "service", Config: testConfig, ConfigSHA256: sha256Hex(testConfig)})
	tok := f.putBlob([]byte("token-genesis-digicert"))
	f.add(s.start.Add(150*time.Millisecond), model.TypeAnchor, model.Anchor{TSAURL: "http://timestamp.digicert.com",
		TSAName: `CN=DigiCert SHA256 RSA4096 Timestamp Responder 2026 1,O=DigiCert\, Inc.,C=US`, HeadSeq: 2, HeadHash: f.recs[2].env.H,
		TokenSHA256: tok, GenTime: "2026-10-05T12:45:47Z", Verified: true, ChainOK: true, Reason: "genesis"}, tok)

	cycle := uint64(0)
	rx := []int64{-309, -311, -313, -315, -312, -310}
	uptime0 := int64(309201) // at the first snapshot: boot 2026-10-01T22:52:37Z, as observed
	nsnap := 0
	nextAnchor := s.start.Add(30 * time.Minute)
	for at := s.start; at.Before(s.to); at = at.Add(10 * time.Second) {
		cycle++
		rtt := int64(2000 + (cycle%7)*150)
		s.samples = append(s.samples, f.add(at.Add(15*time.Millisecond), model.TypeSample,
			sample(cycle, at, model.StateOnline, model.AttrNone, true, rtt, true, "")))
		if cycle%6 == 2 { // a snapshot every minute
			snapAt := at.Add(2 * time.Second)
			up := uptime0 + int64(snapAt.Sub(s.start.Add(12*time.Second))/time.Second)
			seq := f.add(snapAt, model.TypeGatewaySnapshot, snapshot(snapAt, rx[nsnap%len(rx)], true, true, up, lastChange))
			s.snaps = append(s.snaps, seq)
			if nsnap == 0 {
				f.add(snapAt.Add(time.Millisecond), model.TypeGatewayEvent, model.GatewayEvent{Kind: model.GwEvOpticalAlarm,
					After: "OPTICAL_RX_LOW_ALARM,OPTICAL_RX_LOW_WARNING", Detail: "alarm flags already raised at the first gateway observation by this monitor; Rx -30.9 dBm, Tx 4.8 dBm", Evidence: []uint64{seq}})
				f.add(snapAt.Add(2*time.Millisecond), model.TypeGatewayEvent, model.GatewayEvent{Kind: model.GwEvCertPinned, After: "49cd292d"})
			}
			nsnap++
		}
		if cycle%60 == 1 { // local link every 10 minutes
			s.links = append(s.links, f.add(at.Add(20*time.Millisecond), model.TypeLocalLink, wifi(82+int(cycle/60)%3, false)))
		}
		if at.After(nextAnchor) {
			tk := f.putBlob([]byte("token-" + at.String()))
			head := uint64(len(f.recs) - 1)
			f.add(at.Add(30*time.Millisecond), model.TypeAnchor, model.Anchor{TSAURL: "https://freetsa.org/tsr",
				TSAName: "CN=www.freetsa.org,OU=TSA,O=Free TSA,L=Wuerzburg,ST=Bayern,C=DE", HeadSeq: head, HeadHash: f.recs[head].env.H,
				TokenSHA256: tk, GenTime: at.Add(time.Second).UTC().Truncate(time.Second).Format(time.RFC3339), Verified: true, ChainOK: true, Reason: "periodic"}, tk)
			nextAnchor = nextAnchor.Add(30 * time.Minute)
		}
	}
	return s
}

// recordsOf returns the seqs of the records of type typ.
func (f *fakeReader) recordsOf(typ string) []uint64 {
	var out []uint64
	for _, r := range f.recs {
		if r.body.Type == typ {
			out = append(out, r.body.Seq)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
