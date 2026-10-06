package connstore

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"attmonitor/internal/contracts"
	"attmonitor/internal/model"
)

// The tests use documentation addresses only: the LAN 192.168.1.0/24, remote sides in
// 192.0.2.0/24, 198.51.100.0/24 and 203.0.113.0/24 (the gateway's public address 203.0.113.1),
// IPv6 2001:db8::/32 and MAC addresses 00:00:5e:00:53:xx.

// day0 is the tests' first day: 2026-10-05 UTC.
var day0 = time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC)

// at returns day0 plus d days and the given hour and minute.
func at(d, hour, minute int) time.Time {
	return day0.AddDate(0, 0, d).Add(time.Duration(hour)*time.Hour + time.Duration(minute)*time.Minute)
}

// lanIP returns the LAN address 192.168.1.n.
func lanIP(n int) string { return fmt.Sprintf("192.168.1.%d", n) }

// macOf returns the MAC address 00:00:5e:00:53:<n>.
func macOf(n int) string { return fmt.Sprintf("00:00:5e:00:53:%02x", n) }

// macKey returns the device key of macOf(n).
func macKey(n int) string { return "mac:" + macOf(n) }

// gatewayIP is the gateway's public address in the tests.
const gatewayIP = "203.0.113.1"

// ---------------------------------------------------------------- logs

// captureHandler records every log record.
type captureHandler struct {
	mu   sync.Mutex
	recs []slog.Record
}

func (h *captureHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h *captureHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	h.recs = append(h.recs, r)
	h.mu.Unlock()
	return nil
}
func (h *captureHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *captureHandler) WithGroup(string) slog.Handler      { return h }

// count returns how many records contain sub in their message.
func (h *captureHandler) count(sub string) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	n := 0
	for _, r := range h.recs {
		if strings.Contains(r.Message, sub) {
			n++
		}
	}
	return n
}

// attr returns the value of key in the last record whose message contains sub ("" if absent).
func (h *captureHandler) attr(sub, key string) string {
	h.mu.Lock()
	defer h.mu.Unlock()
	v := ""
	for _, r := range h.recs {
		if !strings.Contains(r.Message, sub) {
			continue
		}
		v = ""
		r.Attrs(func(a slog.Attr) bool {
			if a.Key == key {
				v = a.Value.String()
				return false
			}
			return true
		})
	}
	return v
}

// all returns every logged message with its attributes, for failure output.
func (h *captureHandler) all() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	var b strings.Builder
	for _, r := range h.recs {
		b.WriteString(r.Level.String() + " " + r.Message)
		r.Attrs(func(a slog.Attr) bool {
			b.WriteString(" " + a.String())
			return true
		})
		b.WriteString("\n")
	}
	return b.String()
}

// ---------------------------------------------------------------- clock

// clock is a settable clock with its monotonic clock, safe for concurrent use. Set moves both
// (time passes, or - backwards - the test pretends it had not yet); Step moves the wall clock
// alone, as when the system clock is set.
type clock struct {
	mu   sync.Mutex
	t    time.Time
	mono time.Duration
}

func newClock(t time.Time) *clock { return &clock{t: t} }

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

// Mono returns the monotonic clock: the time elapsed since the clock was made.
func (c *clock) Mono() time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.mono
}

// Set sets the clock to t: the monotonic clock moves by the same amount.
func (c *clock) Set(t time.Time) {
	c.mu.Lock()
	c.mono += t.Sub(c.t)
	c.t = t
	c.mu.Unlock()
}

// Step sets the wall clock to t, and advances the monotonic clock by elapsed: the system clock
// was set (stepped) while elapsed passed.
func (c *clock) Step(t time.Time, elapsed time.Duration) {
	c.mu.Lock()
	c.mono += elapsed
	c.t = t
	c.mu.Unlock()
}

// ---------------------------------------------------------------- stores

// harness is a store under test with its directory, clock and captured log.
type harness struct {
	t   testing.TB
	dir string
	clk *clock
	log *captureHandler
	s   *Store
	o   Options
}

// newHarness opens a store in a new directory with the clock at now.
func newHarness(t testing.TB, now time.Time, o Options) *harness {
	t.Helper()
	h := &harness{t: t, dir: t.TempDir(), clk: newClock(now), o: o}
	h.open()
	return h
}

// open opens the store (again) on the harness's directory, with a new captured log.
func (h *harness) open() {
	h.t.Helper()
	h.log = &captureHandler{}
	o := h.o
	o.Logger = slog.New(h.log)
	o.Now = h.clk.Now
	o.mono = h.clk.Mono
	s, err := Open(h.dir, o)
	if err != nil {
		h.t.Fatalf("Open: %v", err)
	}
	if o.settleStart == nil {
		<-s.settled // what Open leaves to the background (compression, the size limit) is done
	}
	h.s = s
	h.t.Cleanup(func() { s.Close() })
}

// reopen closes the store and opens it again (a restart).
func (h *harness) reopen() {
	h.t.Helper()
	if err := h.s.Close(); err != nil {
		h.t.Fatalf("Close: %v", err)
	}
	h.open()
}

// nat appends a NAT table read at t.
func (h *harness) nat(t time.Time, sessions ...model.NATSession) {
	h.t.Helper()
	h.natTable(t, model.NATTable{Sessions: sessions, InUse: len(sessions), Available: 8192 - len(sessions)})
}

// natTable appends a NAT table read at t.
func (h *harness) natTable(t time.Time, nat model.NATTable) {
	h.t.Helper()
	if err := h.s.AppendNAT(t, nat); err != nil {
		h.t.Fatalf("AppendNAT(%s): %v", t, err)
	}
}

// devices appends a Device List read at t.
func (h *harness) devices(t time.Time, devices ...model.LANDevice) {
	h.t.Helper()
	if err := h.s.AppendDevices(t, devices); err != nil {
		h.t.Fatalf("AppendDevices(%s): %v", t, err)
	}
}

// agg aggregates [from, to) for every device.
func (h *harness) agg(from, to time.Time) model.ConnAggregate {
	h.t.Helper()
	return h.aggDevice(from, to, "")
}

// aggDevice aggregates [from, to) for one device.
func (h *harness) aggDevice(from, to time.Time, device string) model.ConnAggregate {
	h.t.Helper()
	a, err := h.s.Aggregate(context.Background(), contracts.ConnQuery{From: from, To: to, Device: device})
	if err != nil {
		h.t.Fatalf("Aggregate: %v", err)
	}
	return a
}

// file returns the path of a file of the store.
func (h *harness) file(name string) string { return filepath.Join(h.dir, name) }

// exists reports whether the store's directory has the file name.
func (h *harness) exists(name string) bool {
	_, err := os.Lstat(h.file(name))
	return err == nil
}

// lines returns the lines of a file of the store (decompressed when it is gzip).
func (h *harness) lines(name string) []string {
	h.t.Helper()
	b := h.content(name)
	s := strings.TrimSuffix(string(b), "\n")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

// content returns the content of a file of the store (decompressed when it is gzip).
func (h *harness) content(name string) []byte {
	h.t.Helper()
	b, err := os.ReadFile(h.file(name))
	if err != nil {
		h.t.Fatalf("read %s: %v", name, err)
	}
	if strings.HasSuffix(name, gzExt) {
		zr, err := gzip.NewReader(bytes.NewReader(b))
		if err != nil {
			h.t.Fatalf("gunzip %s: %v", name, err)
		}
		b, err = io.ReadAll(zr)
		if err != nil {
			h.t.Fatalf("gunzip %s: %v", name, err)
		}
	}
	return b
}

// ---------------------------------------------------------------- reads

// tcp returns an established TCP session from LAN address n (source port sport) to remote:port.
func tcp(n, sport int, remote string, port int) model.NATSession {
	return model.NATSession{Proto: "tcp", State: "ESTABLISHED", Src: lanIP(n), SrcPort: sport, Dst: remote, DstPort: port}
}

// udp returns a UDP session from LAN address n to remote:port.
func udp(n, sport int, remote string, port int) model.NATSession {
	return model.NATSession{Proto: "udp", Src: lanIP(n), SrcPort: sport, Dst: remote, DstPort: port}
}

// session returns a session between any two addresses.
func session(proto, src string, sport int, dst string, dport int) model.NATSession {
	return model.NATSession{Proto: proto, Src: src, SrcPort: sport, Dst: dst, DstPort: dport}
}

// device returns a Device List entry that is on: LAN address n, MAC address mac (0: none).
func device(n, mac int, name, connection string) model.LANDevice {
	d := model.LANDevice{Name: name, IPv4: lanIP(n), Status: "on", Allocation: "dhcp", Connection: connection}
	if mac > 0 {
		d.MAC = macOf(mac)
	}
	return d
}

// mustTime parses a time of a result.
func mustTime(t testing.TB, s string) time.Time {
	t.Helper()
	v, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		t.Fatalf("time %q: %v", s, err)
	}
	return v
}

// rfc formats a time as the results state it.
func rfc(t time.Time) string { return formatTime(t) }

// findFlow returns the flow of a result with this device, remote address, port and protocol.
func findFlow(t testing.TB, a model.ConnAggregate, dev, remote string, port int, proto string) model.ConnFlow {
	t.Helper()
	for _, f := range a.Flows {
		if f.Device == dev && f.Remote == remote && f.Port == port && f.Proto == proto {
			return f
		}
	}
	t.Fatalf("no flow %s -> %s:%d/%s in %+v", dev, remote, port, proto, a.Flows)
	return model.ConnFlow{}
}

// findDevice returns the device of a result with this key.
func findDevice(t testing.TB, a model.ConnAggregate, key string) model.ConnDevice {
	t.Helper()
	for _, d := range a.Devices {
		if d.Key == key {
			return d
		}
	}
	t.Fatalf("no device %s in %+v", key, a.Devices)
	return model.ConnDevice{}
}

// deviceKeys returns the keys of a result's devices, in order.
func deviceKeys(a model.ConnAggregate) []string {
	var keys []string
	for _, d := range a.Devices {
		keys = append(keys, d.Key)
	}
	return keys
}

// checkConsistent checks the invariants every aggregate keeps (consistent).
func checkConsistent(t testing.TB, a model.ConnAggregate) {
	t.Helper()
	for _, p := range consistent(a) {
		t.Error(p)
	}
}

// consistent returns how an aggregate breaks the invariants every aggregate keeps: each
// device's weight is the sum of its flows' weights, no flow or device is seen in more reads than
// the period has, and the flows' first and last reads are within the period's. It may be called
// from any goroutine.
func consistent(a model.ConnAggregate) []string {
	var problems []string
	parse := func(s string) time.Time {
		v, err := time.Parse(time.RFC3339Nano, s)
		if err != nil {
			problems = append(problems, fmt.Sprintf("time %q: %v", s, err))
		}
		return v
	}
	sum := map[string]int{}
	for _, f := range a.Flows {
		sum[f.Device] += f.Weight
		if f.Samples < 1 || f.Samples > a.Samples || f.Weight < f.Samples {
			problems = append(problems, fmt.Sprintf("flow %+v: samples %d of %d reads, weight %d", f, f.Samples, a.Samples, f.Weight))
		}
		first, last := parse(f.First), parse(f.Last)
		if first.Before(parse(a.First)) || last.After(parse(a.Last)) || first.After(last) {
			problems = append(problems, fmt.Sprintf("flow %+v outside the reads %s .. %s", f, a.First, a.Last))
		}
	}
	for _, d := range a.Devices {
		if d.Weight != sum[d.Key] {
			problems = append(problems, fmt.Sprintf("device %s: weight %d, its flows' %d", d.Key, d.Weight, sum[d.Key]))
		}
		if d.Samples < 1 || d.Samples > a.Samples {
			problems = append(problems, fmt.Sprintf("device %s: samples %d of %d reads", d.Key, d.Samples, a.Samples))
		}
		delete(sum, d.Key)
	}
	if len(sum) > 0 {
		problems = append(problems, fmt.Sprintf("flows of devices the result does not list: %v", sum))
	}
	return problems
}
