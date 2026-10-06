package netmap

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"attmonitor/internal/contracts"
	"attmonitor/internal/model"
	"attmonitor/internal/syslogstore"
)

// sampleIntel knows the sample lines' Internet addresses.
func sampleIntel() *fakeIntel {
	in := newFakeIntel()
	in.know("203.0.113.66", 64496, "Example Scanner", "NL")
	in.know("203.0.113.140", 64497, "Example Pinger", "US")
	in.know("192.0.2.44", 15169, "Google", "US")
	return in
}

// sampleDevices is the Device List of the sample LAN.
var sampleDevices = []model.LANDevice{
	{MAC: "00:00:5e:00:53:10", Name: "Study PC", IPv4: "192.168.1.64", IPv6: []string{"2001:db8:5::64"}, Status: "on"},
	{MAC: "00:00:5e:00:53:11", Name: "", IPv4: "192.168.1.65"},
}

// sampleStore stores the gateway's sample lines: a sealed chunk in the hour from t0, and the
// open chunk in the next hour, which starts with a repeat of the sealed chunk's last drop.
func sampleStore(t *testing.T) *syslogstore.Store {
	s := testStore(t)
	appendMsgs(t, s, true,
		syslogMsg(at(10), lineInbound),
		syslogMsg(at(20), lineRepeat3),
		syslogMsg(at(30), lineOutbound),
		syslogMsg(at(40), lineToLAN),
		syslogMsg(at(50), lineGateway),
		syslogMsg(at(60), linePing),
		syslogMsg(at(70), lineV6),
		syslogMsg(at(80), lineDHCP))
	appendMsgs(t, s, false,
		syslogMsg(at(3605), repeatLine(2)), // repeats the IPv6 drop
		syslogMsg(at(3610), lineOutbound))
	return s
}

func TestFirewallOfTheSampleLines(t *testing.T) {
	s := sampleStore(t)
	v := New(Options{Syslog: s, Intel: sampleIntel(), Conns: &fakeConns{devices: sampleDevices}})
	fw, err := v.Firewall(context.Background(), contracts.NetQuery{From: t0, To: t0.Add(2 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	ts := func(sec float64) string { return at(sec).Format(time.RFC3339Nano) }
	want := model.NetFirewall{
		From: t0.Format(time.RFC3339Nano), To: t0.Add(2 * time.Hour).Format(time.RFC3339Nano), Oldest: ts(10),
		Drops: 12, Inbound: 9, Outbound: 2, Local: 1, Sources: 4,
		Hours: []model.FwHour{{T: "2026-10-06T07:00:00Z", In: 7, Out: 1, Local: 1}, {T: "2026-10-06T08:00:00Z", In: 2, Out: 1}},
		Countries: []model.NetCountry{{Code: "", Sites: 2, Weight: 4}, {Code: "NL", Sites: 1, Weight: 4},
			{Code: "US", Sites: 1, Weight: 1}},
		TopSources: []model.FwSource{
			{Addr: "203.0.113.66", Org: "Example Scanner", ASN: 64496, Country: "NL", Count: 4, Ports: 1, Last: ts(20)},
			{Addr: "2001:db8:1::1", Count: 3, Last: ts(3605)},
			{Addr: "203.0.113.140", Org: "Example Pinger", ASN: 64497, Country: "US", Count: 1, Last: ts(60)},
			{Addr: "192.0.2.17", Count: 1, Ports: 1, Last: ts(40)},
		},
		Services: []model.FwService{
			{Name: "tcp 8071", Proto: "tcp", Port: 8071, Count: 4},
			{Name: "ICMPv6", Proto: "icmpv6", Count: 3},
			{Name: "ICMP", Proto: "icmp", Count: 1},
			{Name: "udp 60512", Proto: "udp", Port: 60512, Count: 1},
		},
		Reasons: []model.FwReason{
			{Reason: "POLICY-INPUT-GEN-DISCARD", Label: "Unsolicited, to the gateway", Count: 7},
			{Reason: "POLICY", Label: "Firewall policy", Count: 3},
			{Reason: "OTHER-DoS", Label: "Flood (DoS) protection", Count: 1},
			{Reason: "POLICY-ICMP-ECHO", Label: "Ping to the gateway", Count: 1},
		},
		OutboundRows: []model.FwOutRow{{Device: "mac:00:00:5e:00:53:10", Name: "Study PC", LAN: "192.168.1.64",
			Remote: "192.0.2.44", Org: "Google", ASN: 15169, Country: "US", Service: "HTTPS", Proto: "tcp", Port: 443,
			Reason: "POLICY", Label: "Firewall policy", Count: 2, Last: ts(3610)}},
		OutboundTotal:   1,
		OutboundDevices: 1,
		IPDB:            "2026-10-01T04:00:00Z",
	}
	if !reflect.DeepEqual(fw, want) {
		t.Fatalf("view\n%s\nwant\n%s", js(t, fw), js(t, want))
	}
	// The MAC fields of the lines are never kept.
	if b := js(t, fw); strings.Contains(b, "5e:0000:53") {
		t.Fatalf("a MAC field reached the view: %s", b)
	}
	// Only the second hour: the repeat line counts its drop from the sealed chunk.
	fw, err = v.Firewall(context.Background(), contracts.NetQuery{From: t0.Add(time.Hour), To: t0.Add(2 * time.Hour)})
	if err != nil || fw.Inbound != 2 || fw.Outbound != 1 || fw.Drops != 3 || len(fw.TopSources) != 1 ||
		fw.TopSources[0].Addr != "2001:db8:1::1" || len(fw.Hours) != 1 {
		t.Fatalf("the second hour: %s %v", js(t, fw), err)
	}
}

// diffFields describes the fields in which two views differ.
func diffFields(t testing.TB, got, want any) string {
	t.Helper()
	g, w := reflect.ValueOf(got), reflect.ValueOf(want)
	var b strings.Builder
	for i := range g.NumField() {
		if gf, wf := g.Field(i).Interface(), w.Field(i).Interface(); !reflect.DeepEqual(gf, wf) {
			fmt.Fprintf(&b, "%s:\n got %s\nwant %s\n", g.Type().Field(i).Name, js(t, gf), js(t, wf))
		}
	}
	return b.String()
}

func js(t testing.TB, v any) string {
	t.Helper()
	b, err := json.MarshalIndent(v, "", " ")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestFirewallWithoutTheIPDatabase(t *testing.T) {
	v := New(Options{Syslog: sampleStore(t)})
	fw, err := v.Firewall(context.Background(), contracts.NetQuery{From: t0, To: t0.Add(2 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	// Documentation addresses are reserved, not public: no countries, no organisations.
	if fw.Drops != 12 || len(fw.Countries) != 0 || fw.TopSources[0].Org != "" || fw.IPDB != "" {
		t.Fatalf("%s", js(t, fw))
	}
	if fw.OutboundRows[0].Service != "" || fw.OutboundRows[0].Device != "ip:192.168.1.64" || fw.OutboundRows[0].Name != "192.168.1.64" {
		t.Fatalf("outbound %+v", fw.OutboundRows[0])
	}
	if fw.Services[0].Name != "tcp 8071" {
		t.Fatalf("services %+v", fw.Services)
	}
}

func TestFirewallErrors(t *testing.T) {
	ctx := context.Background()
	if _, err := New(Options{}).Firewall(ctx, contracts.NetQuery{From: t0, To: t0.Add(time.Hour)}); !errors.Is(err, contracts.ErrUnavailable) {
		t.Fatalf("without a syslog store: %v", err)
	}
	v := New(Options{Syslog: testStore(t)})
	for _, q := range []contracts.NetQuery{
		{From: t0, To: t0},
		{From: t0, To: t0.Add(-time.Second)},
		{From: t0, To: t0.Add(MaxRange + time.Second)},
	} {
		if _, err := v.Firewall(ctx, q); !errors.Is(err, ErrRange) {
			t.Errorf("%v - %v: %v", q.From, q.To, err)
		}
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := v.Firewall(cancelled, contracts.NetQuery{From: t0, To: t0.Add(time.Hour)}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled: %v", err)
	}
}

func TestFirewallHours(t *testing.T) {
	now := t0.Add(30 * time.Minute)
	v := New(Options{Syslog: testStore(t), Now: func() time.Time { return now }})
	for _, c := range []struct {
		q     contracts.NetQuery
		hours int
		first string
	}{
		{contracts.NetQuery{From: t0.Add(-MaxRange).Add(time.Minute), To: t0.Add(time.Minute)}, 745, "2026-09-05T07:00:00Z"},
		{contracts.NetQuery{From: t0.Add(-MaxRange), To: t0}, 744, "2026-09-05T07:00:00Z"},
		{contracts.NetQuery{From: t0, To: t0.Add(time.Nanosecond)}, 1, "2026-10-06T07:00:00Z"},
		{contracts.NetQuery{}, 25, "2026-10-05T07:00:00Z"}, // the 24 hours up to now
		{contracts.NetQuery{To: t0}, 24, "2026-10-05T07:00:00Z"},
		{contracts.NetQuery{From: t0.In(time.FixedZone("x", 5*3600+1800))}, 1, "2026-10-06T07:00:00Z"},
	} {
		fw, err := v.Firewall(context.Background(), c.q)
		if err != nil || len(fw.Hours) != c.hours || fw.Hours[0].T != c.first || fw.Drops != 0 {
			t.Errorf("%v - %v: %d hours from %s (%v)", c.q.From, c.q.To, len(fw.Hours), fw.Hours[0].T, err)
		}
		for i := 1; i < len(fw.Hours); i++ {
			a, _ := time.Parse(time.RFC3339, fw.Hours[i-1].T)
			b, _ := time.Parse(time.RFC3339, fw.Hours[i].T)
			if b.Sub(a) != time.Hour {
				t.Fatalf("hours %s, %s", fw.Hours[i-1].T, fw.Hours[i].T)
			}
		}
	}
}

func TestFirewallRepeatsAcrossChunks(t *testing.T) {
	s := testStore(t)
	appendMsgs(t, s, true, syslogMsg(at(1), lineDHCP)) // no drop before the first one
	appendMsgs(t, s, true, syslogMsg(at(2), repeatLine(9)), syslogMsg(at(3), linePing))
	appendMsgs(t, s, true, syslogMsg(at(4), repeatLine(5)), syslogMsg(at(5), lineDHCP)) // repeats the ping
	appendMsgs(t, s, true, syslogMsg(at(6), lineDHCP))                                  // no drop
	appendMsgs(t, s, true, syslogMsg(at(7), repeatLine(2)), syslogMsg(at(8), lineGateway))
	appendMsgs(t, s, false, syslogMsg(at(9), repeatLine(4)), syslogMsg(at(10), lineInbound))
	v := New(Options{Syslog: s, Intel: sampleIntel(), ResultTTL: -1})
	for _, c := range []struct {
		from, to float64
		in, loc  int
	}{
		{0, 100, 1 + 5 + 2 + 1, 1 + 4}, // the repeat before any drop counts nothing
		{2, 3, 0, 0},
		{4, 5, 5, 0},     // a chunk's first line repeats the previous chunk's last drop
		{7, 8, 2, 0},     // ... through a chunk without drops
		{9, 10, 0, 4},    // ... also at the start of the open chunk
		{3.5, 9.5, 7, 5}, // partly read chunks at both ends
		{8.5, 100, 1, 4}, // the open chunk only: its repeat line repeats a sealed chunk's drop
		{9, 9.000001, 0, 4},
	} {
		fw, err := v.Firewall(context.Background(), contracts.NetQuery{From: at(c.from), To: at(c.to)})
		if err != nil || fw.Inbound != c.in || fw.Local != c.loc || fw.Outbound != 0 {
			t.Errorf("[%v, %v): inbound %d local %d (%v), want %d %d", c.from, c.to, fw.Inbound, fw.Local, err, c.in, c.loc)
		}
	}
}

func TestFirewallUsesTheChunkCache(t *testing.T) {
	s := testStore(t)
	for i := range 5 {
		appendMsgs(t, s, true, syslogMsg(at(float64(10*i)), lineInbound), syslogMsg(at(float64(10*i+5)), lineOutbound))
	}
	src := newCounting(s)
	v := New(Options{Syslog: src, ResultTTL: -1})
	ctx := context.Background()
	query := func(from, to float64) model.NetFirewall {
		t.Helper()
		fw, err := v.Firewall(ctx, contracts.NetQuery{From: at(from), To: at(to)})
		if err != nil {
			t.Fatal(err)
		}
		return fw
	}
	all := query(0, 100)
	if all.Drops != 10 || src.reads() != 5 {
		t.Fatalf("drops %d", all.Drops)
	}
	if again := query(0, 100); !reflect.DeepEqual(again, all) || src.reads() != 0 {
		t.Fatalf("the same period read chunks again: %s", js(t, again))
	}
	// Chunks wholly inside come from the cache; the two at the ends are read again.
	if part := query(3, 33); part.Drops != 6 || src.reads() != 2 {
		t.Fatalf("drops %d", part.Drops)
	}
	if entries, _ := v.chunks.stats(); entries != 5 {
		t.Fatalf("%d summaries kept", entries)
	}
	// A pruned chunk leaves the cache.
	s.SetRetention(100, 1)
	if pruned, err := s.Prune(at(2 * 86400)); err != nil || len(pruned) != 5 {
		t.Fatalf("Prune: %v %v", pruned, err)
	}
	if none := query(0, 100); none.Drops != 0 || src.reads() != 0 {
		t.Fatalf("after pruning: %d drops", none.Drops)
	}
	if entries, bytes := v.chunks.stats(); entries != 0 || bytes != 0 {
		t.Fatalf("%d summaries (%d bytes) kept after pruning", entries, bytes)
	}
}

func TestFirewallCacheBounds(t *testing.T) {
	s := testStore(t)
	for i := range 5 {
		appendMsgs(t, s, true, syslogMsg(at(float64(10*i)), lineInbound))
	}
	src := newCounting(s)
	ctx := context.Background()
	q := contracts.NetQuery{From: at(0), To: at(100)}

	// Room for two summaries: the newest two are kept, and only the others are read again.
	v := New(Options{Syslog: src, ResultTTL: -1, CacheChunks: 2})
	for i, want := range []int{5, 3, 3} {
		if fw, err := v.Firewall(ctx, q); err != nil || fw.Drops != 5 {
			t.Fatalf("drops %d %v", fw.Drops, err)
		}
		if n := src.reads(); n != want {
			t.Fatalf("query %d read %d chunks, want %d", i, n, want)
		}
	}
	if e, _ := v.chunks.stats(); e != 2 {
		t.Fatalf("%d summaries kept", e)
	}
	refs := s.Chunks()
	if v.chunks.peek(refs[4].Name, refs[4].SHA256) == nil || v.chunks.peek(refs[3].Name, refs[3].SHA256) == nil {
		t.Fatal("the newest chunks are not the ones kept")
	}

	// No room: every query reads every chunk.
	v = New(Options{Syslog: src, ResultTTL: -1, CacheBytes: 100})
	for range 2 {
		if fw, err := v.Firewall(ctx, q); err != nil || fw.Drops != 5 || src.reads() != 5 {
			t.Fatalf("drops %d %v", fw.Drops, err)
		}
	}
	// Disabled.
	v = New(Options{Syslog: src, ResultTTL: -1, CacheChunks: -1})
	for range 2 {
		if fw, err := v.Firewall(ctx, q); err != nil || fw.Drops != 5 || src.reads() != 5 {
			t.Fatalf("drops %d %v", fw.Drops, err)
		}
	}
}

func TestFirewallResultCache(t *testing.T) {
	now := t0
	src := newCounting(sampleStore(t))
	v := New(Options{Syslog: src, Now: func() time.Time { return now }})
	ctx := context.Background()
	q := contracts.NetQuery{From: t0, To: t0.Add(2 * time.Hour)}
	a, err := v.Firewall(ctx, q)
	if err != nil {
		t.Fatal(err)
	}
	perBuild := src.chunks // listed at the start of a build, and again at its end
	a.Hours[0].In = 999    // the caller's copy
	b, _ := v.Firewall(ctx, q)
	if src.chunks != perBuild || b.Hours[0].In != 7 {
		t.Fatalf("Chunks called %d times; hours %+v", src.chunks, b.Hours[0])
	}
	q.Limit = 5 // another request
	if _, err := v.Firewall(ctx, q); err != nil || src.chunks != 2*perBuild {
		t.Fatalf("Chunks called %d times (%v)", src.chunks, err)
	}
	now = now.Add(DefaultResultTTL)
	if _, err := v.Firewall(ctx, q); err != nil || src.chunks != 3*perBuild {
		t.Fatalf("Chunks called %d times after the result went stale (%v)", src.chunks, err)
	}
}

// brokenSource damages one chunk and makes another one disappear.
type brokenSource struct {
	contracts.SyslogChunkSource
	damaged, gone string
}

func (b *brokenSource) OpenChunk(name string) (io.ReadCloser, error) {
	switch name {
	case b.damaged:
		return io.NopCloser(strings.NewReader("this is not gzip")), nil
	case b.gone:
		return nil, fmt.Errorf("chunk %q: %w", name, contracts.ErrNotFound)
	}
	return b.SyslogChunkSource.OpenChunk(name)
}

func TestFirewallLeavesOutChunksItCannotRead(t *testing.T) {
	s := testStore(t)
	for i := range 3 {
		appendMsgs(t, s, true, syslogMsg(at(float64(10*i)), lineInbound))
	}
	refs := s.Chunks()
	logs := &logBuffer{}
	v := New(Options{Syslog: &brokenSource{SyslogChunkSource: s, damaged: refs[0].Name, gone: refs[1].Name},
		Logger: slog.New(logs), ResultTTL: -1})
	for range 2 {
		fw, err := v.Firewall(context.Background(), contracts.NetQuery{From: at(0), To: at(100)})
		if err != nil || fw.Drops != 1 {
			t.Fatalf("drops %d %v", fw.Drops, err)
		}
	}
	if n := logs.count("cannot be read"); n != 1 || !strings.Contains(logs.String(), refs[0].Name) {
		t.Fatalf("logged %d times:\n%s", n, logs)
	}
	if e, _ := v.chunks.stats(); e != 1 {
		t.Fatalf("%d summaries kept (a damaged chunk's is not kept)", e)
	}
}

// TestFirewallMatchesOnePass stores random messages in chunks, prunes the oldest, and checks
// the view of random periods - with a cache kept between them and without - against one pass
// over the messages kept, in the store's order: the chunks oldest first (by the receive time of
// their first message, which is not the order they were stored in when the clock was set back),
// then the open chunk.
func TestFirewallMatchesOnePass(t *testing.T) {
	ctx := context.Background()
	for seed := range uint64(8) {
		r := rand.New(rand.NewPCG(seed, 99))
		s := testStore(t)
		byChunk := map[string][]model.SyslogMessage{} // "" is the open chunk
		var first, last time.Time
		start := t0.Add(-72 * time.Hour) // the first two chunks: three days old
		chunks := 9
		for c := range chunks {
			if c == 2 {
				start = t0
			}
			evs := randomEvents(r, start, 5+r.IntN(40))
			if c < chunks-1 { // the clock set back now and then (not in the open chunk)
				for i := range evs {
					if r.IntN(25) == 0 {
						evs[i].rx = evs[i].rx.Add(-time.Duration(r.IntN(1800)) * time.Second)
					}
				}
			}
			start = evs[len(evs)-1].rx.Add(time.Duration(1+r.IntN(900)) * time.Second)
			msgs := make([]model.SyslogMessage, len(evs))
			for i, e := range evs {
				msgs[i] = syslogMsg(e.rx, e.text)
				if first.IsZero() || e.rx.Before(first) {
					first = e.rx
				}
				if e.rx.After(last) {
					last = e.rx
				}
			}
			byChunk[appendMsgs(t, s, c < chunks-1, msgs...)] = msgs
		}
		intel := sampleIntel()
		conns := &fakeConns{devices: sampleDevices}
		warm := New(Options{Syslog: s, Intel: intel, Conns: conns, ResultTTL: -1, CacheChunks: 4})
		check := func(when string) {
			t.Helper()
			var kept []model.SyslogMessage
			for _, c := range s.Chunks() {
				kept = append(kept, byChunk[c.Name]...)
			}
			kept = append(kept, byChunk[""]...)
			for i := range 30 {
				from := first.Add(time.Duration(r.Int64N(int64(last.Sub(first)+2*time.Hour))) - time.Hour)
				to := from.Add(time.Duration(1 + r.Int64N(int64(6*time.Hour))))
				if i == 0 {
					from, to = first.Add(-time.Hour), last.Add(time.Hour)
				}
				limit := []int{0, 1, 3}[r.IntN(3)]
				q := contracts.NetQuery{From: from, To: to, Limit: limit}
				cold := New(Options{Syslog: s, Intel: intel, Conns: conns, ResultTTL: -1})
				want := onePass(cold, s, kept, from, to, rowLimit(limit))
				checkSums(t, want)
				for name, v := range map[string]*View{"warm": warm, "cold": cold} {
					got, err := v.Firewall(ctx, q)
					if err != nil {
						t.Fatal(err)
					}
					if !reflect.DeepEqual(got, want) {
						t.Fatalf("seed %d, %s, %s view of [%s, %s) differs:\n%s", seed, when, name,
							from.Format(time.RFC3339Nano), to.Format(time.RFC3339Nano), diffFields(t, got, want))
					}
				}
			}
		}
		check("before pruning")
		s.SetRetention(100, 2)
		if pruned, err := s.Prune(t0.Add(time.Hour)); err != nil || len(pruned) != 2 {
			t.Fatalf("Prune: %+v %v", pruned, err)
		}
		check("after pruning")
	}
}

// checkSums checks what every firewall view adds up to: the hours and the reasons to the drops,
// the services and the sources' countries to (at most) the inbound drops.
func checkSums(t testing.TB, fw model.NetFirewall) {
	t.Helper()
	hours, reasons, services, countries := 0, 0, 0, 0
	for _, h := range fw.Hours {
		hours += h.In + h.Out + h.Local
	}
	for _, r := range fw.Reasons {
		reasons += r.Count
	}
	for _, s := range fw.Services {
		services += s.Count
	}
	for _, c := range fw.Countries {
		countries += c.Weight
	}
	rowDevices := map[string]bool{}
	for _, r := range fw.OutboundRows {
		rowDevices[r.Device] = true
	}
	if fw.Drops != fw.Inbound+fw.Outbound+fw.Local || hours != fw.Drops || reasons != fw.Drops ||
		services != fw.Inbound || countries > fw.Inbound || len(fw.TopSources) > min(fw.Sources, topSources) ||
		len(fw.OutboundRows) > fw.OutboundTotal || fw.OutboundDevices > fw.OutboundTotal ||
		(fw.OutboundTotal > 0) != (fw.OutboundDevices > 0) || len(rowDevices) > fw.OutboundDevices {
		t.Fatalf("sums: drops %d (%d+%d+%d), hours %d, reasons %d, services %d, countries %d, sources %d/%d, rows %d/%d, devices %d (%d in the rows)",
			fw.Drops, fw.Inbound, fw.Outbound, fw.Local, hours, reasons, services, countries, len(fw.TopSources), fw.Sources,
			len(fw.OutboundRows), fw.OutboundTotal, fw.OutboundDevices, len(rowDevices))
	}
}

// FuzzFirewallOfAnyLines checks that no syslog text - as the lines of two chunks, the second
// partly in the period - makes the firewall view panic or count what does not add up.
func FuzzFirewallOfAnyLines(f *testing.F) {
	f.Add([]byte(strings.Join([]string{lineInbound, lineRepeat3, lineOutbound, lineDHCP, lineV6, repeatLine(2), linePing,
		lineGateway, lineToLAN}, "\n")), uint8(4))
	f.Add([]byte("last message repeated 5 times\naction=DROP IN=veip0.0 SRC=203.0.113.1 DPT=1\n"), uint8(1))
	f.Add([]byte("action=DROP IN=veip0.0 SRC=203.0.113.1 DPT=1\nlast message repeated 5 times\nlast message repeated 2 times\n"), uint8(1))
	f.Fuzz(func(t *testing.T, data []byte, split uint8) {
		v := New(Options{Intel: sampleIntel(), Conns: &fakeConns{devices: sampleDevices}})
		lines := bytes.Split(data, []byte("\n"))
		k := min(int(split), len(lines))
		from, to := at(0), at(float64(len(lines))/2)
		ctx := context.Background()
		b := newRequestBuilder(v.bounds, lookup{intel: v.intel}, v.devNames(ctx, from, to))
		var prev drop
		hasPrev := false
		tail := uint8(tailNone)
		for c, part := range [][][]byte{lines[:k], lines[k:]} {
			sc := &scan{codes: v.codes, full: newBuilder(), part: newBuilder(), from: from.UnixNano(), to: to.UnixNano()}
			for i, l := range part {
				sc.message(at(float64(c*k+i)).UnixNano(), l)
			}
			a := sc.partAgg()
			if full := sc.fullAgg(); full.counts[0]+full.counts[1]+full.counts[2] < a.counts[0]+a.counts[1]+a.counts[2] {
				t.Fatalf("the part counts more than the whole: %v %v", a.counts, full.counts)
			}
			b.merge(a)
			for _, r := range a.leading {
				if hasPrev && (!r.cond || tail == tailDrop) {
					b.add(prev, r.rx, int(r.n))
				}
			}
			if a.hasLast {
				prev, hasPrev = a.last, true
			}
			if a.tail != tailNone {
				tail = a.tail
			}
		}
		fw, err := v.finishFirewall(ctx, b, from, to, DefaultLimit, model.SyslogUsage{})
		if err != nil {
			t.Fatal(err)
		}
		checkSums(t, fw)
	})
}

// onePass returns the firewall view of [from, to) counted in one pass over msgs: every message
// the store keeps, in its order. A repeat line counts more drops like the previous drop -
// syslog-ng's always, BSD syslogd's only right after a drop or a repeat line counting drops.
func onePass(v *View, s *syslogstore.Store, msgs []model.SyslogMessage, from, to time.Time, limit int) model.NetFirewall {
	ctx := context.Background()
	b := newRequestBuilder(v.bounds, lookup{intel: v.intel}, v.devNames(ctx, from, to))
	var prev drop
	hasPrev := false
	tail := uint8(tailNone)
	f, t := from.UnixNano(), to.UnixNano()
	for _, m := range msgs {
		rx, ok := parseRX(m.RX)
		if !ok {
			continue
		}
		kind, d, n := v.codes.parse(messageText(m.Msg, m.Raw, m.RawB64))
		in := rx >= f && rx < t
		switch kind {
		case lineDrop:
			if in {
				b.add(d, rx, 1)
			}
			prev, hasPrev, tail = d, true, tailDrop
		case lineRepeat:
			if in && hasPrev {
				b.add(prev, rx, n)
			}
			tail = tailDrop
		case lineRepeatPrev:
			if in && hasPrev && tail == tailDrop {
				b.add(prev, rx, n)
			}
		default:
			tail = tailOther
		}
	}
	fw, err := v.finishFirewall(ctx, b, from.UTC(), to.UTC(), limit, s.Usage())
	if err != nil {
		panic(err)
	}
	return fw
}

func TestFirewallOutboundRowsAreLimited(t *testing.T) {
	s := testStore(t)
	var msgs []model.SyslogMessage
	for i := range 250 {
		msgs = append(msgs, syslogMsg(at(float64(i)), outLine("192.168.1.65", fmt.Sprintf("203.0.113.%d", i), 443, "POLICY")))
	}
	msgs = append(msgs, syslogMsg(at(300), outLine("192.168.1.65", "203.0.113.7", 443, "POLICY")))
	appendMsgs(t, s, false, msgs...)
	v := New(Options{Syslog: s, Conns: &fakeConns{devices: sampleDevices}})
	for _, c := range []struct{ limit, rows int }{{0, DefaultLimit}, {5, 5}, {5000, 250}} {
		fw, err := v.Firewall(context.Background(), contracts.NetQuery{From: at(0), To: at(400), Limit: c.limit})
		if err != nil || len(fw.OutboundRows) != c.rows || fw.OutboundTotal != 250 || fw.OutboundDevices != 1 {
			t.Fatalf("limit %d: %d rows of %d from %d devices (%v)", c.limit, len(fw.OutboundRows), fw.OutboundTotal, fw.OutboundDevices, err)
		}
		// The most first; a device without a name is named after its address.
		r := fw.OutboundRows[0]
		if r.Remote != "203.0.113.7" || r.Count != 2 || r.Device != "mac:00:00:5e:00:53:11" || r.Name != "192.168.1.65" {
			t.Fatalf("first row %+v", r)
		}
	}
}

func TestFirewallNamesIPv6Devices(t *testing.T) {
	s := testStore(t)
	appendMsgs(t, s, false,
		syslogMsg(at(1), outLine("2001:db8:5::64", "2001:db8:9::1", 443, "POLICY")),
		syslogMsg(at(2), outLine("2001:db8:5::99", "2001:db8:9::1", 443, "POLICY")),
		syslogMsg(at(3), outLine("192.168.1.80", "2001:db8:9::1", 443, "POLICY")))
	devices := append(slices.Clone(sampleDevices),
		model.LANDevice{MAC: "00:00:5e:00:53:20", Name: "Old phone", IPv4: "192.168.1.80", Status: "off"},
		model.LANDevice{MAC: "00:00:5e:00:53:21", Name: "Tablet", IPv4: "192.168.1.80", Status: "on"})
	v := New(Options{Syslog: s, Conns: &fakeConns{devices: devices}})
	fw, err := v.Firewall(context.Background(), contracts.NetQuery{From: at(0), To: at(10)})
	if err != nil || len(fw.OutboundRows) != 3 {
		t.Fatalf("%s %v", js(t, fw), err)
	}
	byLAN := map[string]model.FwOutRow{}
	for _, r := range fw.OutboundRows {
		byLAN[r.LAN] = r
	}
	if r := byLAN["2001:db8:5::64"]; r.Device != "mac:00:00:5e:00:53:10" || r.Name != "Study PC" {
		t.Fatalf("known device %+v", r)
	}
	if r := byLAN["2001:db8:5::99"]; r.Device != "ip:2001:db8:5::99" || r.Name != "2001:db8:5::99" {
		t.Fatalf("unknown device %+v", r)
	}
	// Of two devices with one address, the one that is on.
	if r := byLAN["192.168.1.80"]; r.Device != "mac:00:00:5e:00:53:21" || r.Name != "Tablet" {
		t.Fatalf("device that is on %+v", r)
	}
}

// TestFirewallCountsOutboundDevices: OutboundDevices counts the devices whose outbound packets
// were dropped, before the row limit, a device by its key: the Device List's device once,
// whichever of its addresses sent the packets; an address it does not know on its own.
func TestFirewallCountsOutboundDevices(t *testing.T) {
	s := testStore(t)
	appendMsgs(t, s, false,
		syslogMsg(at(1), outLine("192.168.1.64", "192.0.2.44", 443, "POLICY")),      // Study PC (IPv4)
		syslogMsg(at(2), outLine("192.168.1.64", "192.0.2.44", 443, "POLICY")),      // the same row again
		syslogMsg(at(3), outLine("2001:db8:5::64", "2001:db8:9::1", 443, "POLICY")), // Study PC (IPv6)
		syslogMsg(at(4), outLine("192.168.1.65", "192.0.2.45", 80, "POLICY")),       // a device without a name
		syslogMsg(at(5), outLine("192.168.1.99", "192.0.2.46", 53, "POLICY")),       // not in the Device List
		syslogMsg(at(6), lineInbound))
	v := New(Options{Syslog: s, Conns: &fakeConns{devices: sampleDevices}, ResultTTL: -1})
	for _, limit := range []int{0, 1, 2} {
		fw, err := v.Firewall(context.Background(), contracts.NetQuery{From: at(0), To: at(10), Limit: limit})
		if err != nil {
			t.Fatal(err)
		}
		if fw.OutboundTotal != 4 || fw.OutboundDevices != 3 || fw.Outbound != 5 {
			t.Fatalf("limit %d: %d rows of %d, from %d devices, %d packets", limit, len(fw.OutboundRows), fw.OutboundTotal,
				fw.OutboundDevices, fw.Outbound)
		}
		checkSums(t, fw)
	}
	// Without the Device List every address is a device of its own.
	v = New(Options{Syslog: s})
	fw, err := v.Firewall(context.Background(), contracts.NetQuery{From: at(0), To: at(10), Limit: 1})
	if err != nil || len(fw.OutboundRows) != 1 || fw.OutboundDevices != 4 {
		t.Fatalf("without the Device List: %s %v", js(t, fw), err)
	}
	// No outbound drop, no device.
	fw, err = v.Firewall(context.Background(), contracts.NetQuery{From: at(5.5), To: at(10)})
	if err != nil || fw.Inbound != 1 || fw.OutboundTotal != 0 || fw.OutboundDevices != 0 {
		t.Fatalf("inbound only: %s %v", js(t, fw), err)
	}
}

func TestNetworkStatus(t *testing.T) {
	if st := New(Options{}).NetworkStatus(); st.Store != nil || st.IPIntel != nil || st.Syslog != nil || st.Samplers != nil {
		t.Fatalf("%+v", st)
	}
	s := sampleStore(t)
	st := New(Options{Syslog: s, Intel: sampleIntel(), Conns: &fakeConns{}}).NetworkStatus()
	if st.Store == nil || st.Store.KeepDays != 30 || st.IPIntel == nil || !st.IPIntel.Loaded || st.Syslog == nil ||
		st.Syslog.Messages != 10 || st.Samplers != nil {
		t.Fatalf("%+v", st)
	}
}
