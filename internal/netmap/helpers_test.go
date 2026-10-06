package netmap

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"attmonitor/internal/contracts"
	"attmonitor/internal/model"
	"attmonitor/internal/syslogrx"
	"attmonitor/internal/syslogstore"
)

// t0 is the tests' base time (on the hour).
var t0 = time.Date(2026, 10, 6, 7, 0, 0, 0, time.UTC)

// at returns t0 plus sec seconds.
func at(sec float64) time.Time { return t0.Add(time.Duration(sec * float64(time.Second))) }

// The lines of the gateway's syslog as they arrive (the format of the BGW320's real lines, with
// documentation addresses: the gateway's WAN address 198.51.100.1, the LAN 192.168.1.x).
const (
	lineInbound  = "P0000-00-00T07:48:34.329154 L4 FIREWALL[8512]: nflog_log_fw(), action=DROP reason=POLICY-INPUT-GEN-DISCARD hook=INPUT mark=136314880 IN=veip0.0 OUT= MAC=00:00:5e:00:53:01:00:00:5e:0000:53:02:SRC=203.0.113.66 DST=198.51.100.1 LEN=44 TOS=0x00 PREC=0x00 TTL=55 ID=19286 PROTO=TCP SPT=21110 DPT=8071 SEQ=2082050321 ACK=0 WINDOW=1025 RES=0x00 SYN URGP=0 OPT (MSS=1460 )"
	lineOutbound = "P0000-00-00T07:50:02.114201 L4 FIREWALL[8512]: nflog_log_fw(), action=DROP reason=POLICY hook=FORWARD mark= IN=br1 OUT=veip0.0 MAC=00:00:5e:00:53:03:00:00:5e:0000:53:04:SRC=192.168.1.64 DST=192.0.2.44 LEN=40 TOS=0x00 PREC=0x00 TTL=127 ID=0 DF PROTO=TCP SPT=51544 DPT=443 WINDOW=0 RES=0x00 ACK RST URGP=0"
	lineToLAN    = "P0000-00-00T07:51:10.000001 L4 FIREWALL[8512]: nflog_log_fw(), action=DROP reason=OTHER-DoS hook=FORWARD mark=136314880 IN=veip0.0 OUT=br1 MAC=00:00:5e:00:53:01:00:00:5e:0000:53:02:SRC=192.0.2.17 DST=192.168.1.64 LEN=1228 TOS=0x00 PREC=0x00 TTL=57 ID=0 DF PROTO=UDP SPT=443 DPT=60512 LEN=1208"
	lineGateway  = "P0000-00-00T07:51:30.000002 L4 FIREWALL[8512]: nflog_log_fw(), action=DROP reason=POLICY hook=POSTROUTING mark= IN= OUT=veip0.0 SRC=198.51.100.1 DST=203.0.113.5 LEN=76 TOS=0x00 PREC=0x00 TTL=64 ID=0 DF PROTO=UDP SPT=123 DPT=123 LEN=56"
	linePing     = "P0000-00-00T07:52:00.000003 L4 FIREWALL[8512]: nflog_log_fw(), action=DROP reason=POLICY-ICMP-ECHO hook=INPUT mark=136314880 IN=veip0.0 OUT= MAC=00:00:5e:00:53:01:00:00:5e:0000:53:02:SRC=203.0.113.140 DST=198.51.100.1 LEN=84 TOS=0x00 PREC=0x00 TTL=52 ID=0 DF PROTO=ICMP TYPE=8 CODE=0 ID=4411 SEQ=1"
	lineV6       = "P0000-00-00T07:52:10.000004 L4 FIREWALL[8512]: nflog_log_fw(), action=DROP reason=POLICY-INPUT-GEN-DISCARD hook=INPUT mark=136314880 IN=veip0.0 OUT= MAC=00:00:5e:00:53:01:00:00:5e:0000:53:02:SRC=2001:db8:1::1 DST=2001:db8:2::1 LEN=72 TC=0 HOPLIMIT=255 FLOWLBL=0 PROTO=ICMPv6 TYPE=135 CODE=0"
	lineRepeat3  = "P0000-00-00T07:53:47.832643 L4 Last message 'FIREWALL[8512]: nflo' repeated 3 times, suppressed by syslog-ng on dsldevice"
	lineDHCP     = "P0000-00-00T07:54:00.000000 L4 dnsmasq-dhcp[1234]: DHCPACK(br1) 192.168.1.64 00:00:5e:00:53:03 laptop"
)

// macFragment is in every MAC field of the sample lines; it must never reach a view.
const macFragment = "00:00:5e:00:53"

// fwLine returns an inbound drop from src (an IPv4 or IPv6 address) to dport.
func fwLine(src string, proto string, dport int) string {
	return fmt.Sprintf("P0000-00-00T07:48:34.329154 L4 FIREWALL[8512]: nflog_log_fw(), action=DROP reason=POLICY-INPUT-GEN-DISCARD hook=INPUT mark=136314880 IN=veip0.0 OUT= MAC=00:00:5e:00:53:01:00:00:5e:0000:53:02:SRC=%s DST=198.51.100.1 LEN=44 TOS=0x00 PREC=0x00 TTL=55 ID=1 PROTO=%s SPT=40000 DPT=%d SEQ=1 ACK=0 WINDOW=1025 RES=0x00 SYN URGP=0", src, proto, dport)
}

// outLine returns an outbound drop from the LAN address lan to remote:dport.
func outLine(lan, remote string, dport int, reason string) string {
	return fmt.Sprintf("P0000-00-00T07:50:02.114201 L4 FIREWALL[8512]: nflog_log_fw(), action=DROP reason=%s hook=FORWARD mark= IN=br1 OUT=veip0.0 MAC=00:00:5e:00:53:03:00:00:5e:0000:53:04:SRC=%s DST=%s LEN=40 TOS=0x00 PREC=0x00 TTL=127 ID=0 DF PROTO=TCP SPT=51544 DPT=%d WINDOW=0 RES=0x00 ACK RST URGP=0", reason, lan, remote, dport)
}

// repeatLine returns a syslog-ng repeat line.
func repeatLine(n int) string {
	return "P0000-00-00T07:53:47.832643 L4 Last message 'FIREWALL[8512]: nflo' repeated " + strconv.Itoa(n) + " times, suppressed by syslog-ng on dsldevice"
}

// syslogMsg returns the message the receiver makes of the datagram "<12>"+text received at rx.
func syslogMsg(rx time.Time, text string) model.SyslogMessage {
	m := syslogrx.Parse([]byte("<12>" + text))
	m.RX = rx.UTC().Format(time.RFC3339Nano)
	m.Src = "192.168.1.254:514"
	return m
}

// ---------------------------------------------------------------- the syslog store

// testStore opens a syslog store in a new directory: chunks are sealed only when a test seals
// them.
func testStore(t testing.TB) *syslogstore.Store {
	t.Helper()
	s, err := syslogstore.New(syslogstore.Options{Dir: t.TempDir(), ChunkBytes: 64 << 20})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	if _, err := s.Recover(t0); err != nil {
		t.Fatal(err)
	}
	return s
}

// appendMsgs stores msgs; seal also seals them as one chunk, whose name it returns.
func appendMsgs(t testing.TB, s *syslogstore.Store, seal bool, msgs ...model.SyslogMessage) string {
	t.Helper()
	if _, err := s.Append(msgs, 0, 0, t0); err != nil {
		t.Fatal(err)
	}
	if !seal {
		return ""
	}
	c, err := s.Seal(t0, "stop", true)
	if err != nil || c == nil {
		t.Fatalf("Seal: %v %v", c, err)
	}
	return c.Name
}

// countingSource counts the calls to a chunk source.
type countingSource struct {
	contracts.SyslogChunkSource
	mu     sync.Mutex
	opens  map[string]int
	chunks int
	each   int
}

func newCounting(s contracts.SyslogChunkSource) *countingSource {
	return &countingSource{SyslogChunkSource: s, opens: map[string]int{}}
}

func (c *countingSource) Chunks() []model.SyslogChunkRef {
	c.mu.Lock()
	c.chunks++
	c.mu.Unlock()
	return c.SyslogChunkSource.Chunks()
}

func (c *countingSource) OpenChunk(name string) (io.ReadCloser, error) {
	c.mu.Lock()
	c.opens[name]++
	c.mu.Unlock()
	return c.SyslogChunkSource.OpenChunk(name)
}

func (c *countingSource) EachOpen(ctx context.Context, from, to time.Time, fn func(*model.SyslogMessage) error) error {
	c.mu.Lock()
	c.each++
	c.mu.Unlock()
	return c.SyslogChunkSource.EachOpen(ctx, from, to, fn)
}

// reads returns how many chunk files were opened since the last call.
func (c *countingSource) reads() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for k, v := range c.opens {
		n += v
		delete(c.opens, k)
	}
	return n
}

// ---------------------------------------------------------------- the IP database

// fakeIntel is an IP database that knows some addresses. Documentation addresses it does not
// know count as public (they stand for Internet addresses in the tests).
type fakeIntel struct {
	mu       sync.Mutex
	infos    map[netip.Addr]model.IPInfo
	services map[string]string // "tcp/443" → "HTTPS"
	ptrs     map[netip.Addr]string
	asked    []netip.Addr // PTR calls with resolve
	updated  time.Time
}

func newFakeIntel() *fakeIntel {
	return &fakeIntel{
		infos: map[netip.Addr]model.IPInfo{},
		services: map[string]string{"tcp/443": "HTTPS", "udp/443": "QUIC", "udp/53": "DNS", "tcp/80": "HTTP",
			"udp/123": "NTP", "tcp/22": "SSH", "tcp/23": "Telnet"},
		ptrs:    map[netip.Addr]string{},
		updated: time.Date(2026, 10, 1, 4, 0, 0, 0, time.UTC),
	}
}

// know adds what the database says about addr.
func (f *fakeIntel) know(addr string, asn int, org, country string) {
	f.infos[netip.MustParseAddr(addr)] = model.IPInfo{Kind: model.IPKindPublic, ASN: asn, Org: org,
		ASName: strings.ToUpper(org) + "-AS", Country: country}
}

var docPrefixes = []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("2001:db8::/32")}

func (f *fakeIntel) Lookup(a netip.Addr) model.IPInfo {
	f.mu.Lock()
	defer f.mu.Unlock()
	if i, ok := f.infos[a]; ok {
		return i
	}
	for _, p := range docPrefixes {
		if p.Contains(a) {
			return model.IPInfo{Kind: model.IPKindPublic}
		}
	}
	return model.IPInfo{Kind: classify(a)}
}

func (f *fakeIntel) Service(proto string, port int) string {
	return f.services[proto+"/"+strconv.Itoa(port)]
}

func (f *fakeIntel) PTR(a netip.Addr, resolve bool) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if resolve {
		f.asked = append(f.asked, a)
	}
	return f.ptrs[a]
}

func (f *fakeIntel) Updated() time.Time { return f.updated }

func (f *fakeIntel) Status() model.IPIntelStatus {
	return model.IPIntelStatus{Enabled: true, Loaded: true, V4Ranges: 3, Updated: f.updated.Format(time.RFC3339)}
}

func (f *fakeIntel) askedPTR() []netip.Addr {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := f.asked
	f.asked = nil
	return out
}

// ---------------------------------------------------------------- the connection store

// fakeConns is a connection store whose aggregate a test gives.
type fakeConns struct {
	mu      sync.Mutex
	agg     model.ConnAggregate // every device; a device filter keeps that device's
	err     error
	devices []model.LANDevice
	queries []contracts.ConnQuery
}

func (f *fakeConns) AppendNAT(time.Time, model.NATTable) error        { return nil }
func (f *fakeConns) AppendDevices(time.Time, []model.LANDevice) error { return nil }
func (f *fakeConns) Prune(time.Time) error                            { return nil }
func (f *fakeConns) SetRetention(int, int)                            {}
func (f *fakeConns) Usage() model.ConnStoreUsage                      { return model.ConnStoreUsage{Files: 2, KeepDays: 30} }

func (f *fakeConns) Devices() ([]model.LANDevice, time.Time) { return f.devices, t0 }

func (f *fakeConns) Aggregate(ctx context.Context, q contracts.ConnQuery) (model.ConnAggregate, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.queries = append(f.queries, q)
	if f.err != nil {
		return model.ConnAggregate{}, f.err
	}
	if err := ctx.Err(); err != nil {
		return model.ConnAggregate{}, err
	}
	agg := f.agg
	agg.From, agg.To = q.From.Format(time.RFC3339Nano), q.To.Format(time.RFC3339Nano)
	if q.Device == "" {
		return agg, nil
	}
	agg.Devices, agg.Flows = nil, nil
	for _, d := range f.agg.Devices {
		if d.Key == q.Device {
			agg.Devices = append(agg.Devices, d)
		}
	}
	for _, fl := range f.agg.Flows {
		if fl.Device == q.Device {
			agg.Flows = append(agg.Flows, fl)
		}
	}
	return agg, nil
}

func (f *fakeConns) calls() []contracts.ConnQuery {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := f.queries
	f.queries = nil
	return out
}

// ---------------------------------------------------------------- logs

// logBuffer collects log records.
type logBuffer struct {
	mu   sync.Mutex
	recs []string
}

func (l *logBuffer) Enabled(context.Context, slog.Level) bool { return true }
func (l *logBuffer) Handle(_ context.Context, r slog.Record) error {
	var b strings.Builder
	b.WriteString(r.Level.String() + " " + r.Message)
	r.Attrs(func(a slog.Attr) bool {
		b.WriteString(" " + a.String())
		return true
	})
	l.mu.Lock()
	l.recs = append(l.recs, b.String())
	l.mu.Unlock()
	return nil
}
func (l *logBuffer) WithAttrs([]slog.Attr) slog.Handler { return l }
func (l *logBuffer) WithGroup(string) slog.Handler      { return l }

// count returns how many records contain sub.
func (l *logBuffer) count(sub string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for _, r := range l.recs {
		if strings.Contains(r, sub) {
			n++
		}
	}
	return n
}

func (l *logBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Join(l.recs, "\n")
}
