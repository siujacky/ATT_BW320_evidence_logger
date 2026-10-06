package netmap

import (
	"context"
	"reflect"
	"sync"
	"testing"
	"time"

	"attmonitor/internal/contracts"
	"attmonitor/internal/model"
	"attmonitor/internal/syslogstore"
)

// TestFirewallBSDRepeats: BSD syslogd's "last message repeated N times" repeats the message right
// before it: it counts drops only when that was a drop, within a chunk and across chunks (a
// chunk of such lines alone passes on what came before it).
func TestFirewallBSDRepeats(t *testing.T) {
	const bsd50, bsd5, bsd7 = "last message repeated 50 times", "last message repeated 5 times", "last message repeated 7 times"
	for _, c := range []struct {
		name   string
		chunks [][]string // the last one stays open
		in     int
	}{
		{"after another program's line", [][]string{{lineInbound, lineDHCP, bsd50}}, 1},
		{"after a drop", [][]string{{lineInbound, bsd50}}, 51},
		{"after another program's line, in the next chunk", [][]string{{lineInbound, lineDHCP}, {bsd50}}, 1},
		{"after a drop, in the next chunk", [][]string{{lineInbound}, {bsd50}}, 51},
		{"through a chunk of BSD lines", [][]string{{lineInbound}, {bsd5}, {bsd7}}, 1 + 5 + 7},
		{"through a chunk of BSD lines after another line", [][]string{{lineInbound, lineDHCP}, {bsd5}, {bsd7}}, 1},
		{"quoted ones still count", [][]string{{lineInbound, lineDHCP}, {bsd5}, {repeatLine(2)}}, 1 + 2},
		{"after a quoted repeat at a chunk's start", [][]string{{lineInbound, lineDHCP}, {repeatLine(2), bsd5}}, 1 + 2 + 5},
	} {
		s := testStore(t)
		var msgs []model.SyslogMessage
		sec := 0.0
		for i, texts := range c.chunks {
			var ms []model.SyslogMessage
			for _, text := range texts {
				sec++
				ms = append(ms, syslogMsg(at(sec), text))
			}
			appendMsgs(t, s, i < len(c.chunks)-1, ms...)
			msgs = append(msgs, ms...)
		}
		v := New(Options{Syslog: s, ResultTTL: -1})
		for _, from := range []float64{0, 1.5} { // the whole of it; without the first drop (read for the repeats)
			fw, err := v.Firewall(context.Background(), contracts.NetQuery{From: at(from), To: at(100)})
			want := c.in
			if from > 1 {
				want--
			}
			if err != nil || fw.Inbound != want || fw.Drops != want {
				t.Errorf("%s, from %v: inbound %d of %d drops (%v), want %d", c.name, from, fw.Inbound, fw.Drops, err, want)
			}
			if oracle := onePass(v, s, msgs, at(from), at(100), DefaultLimit); !reflect.DeepEqual(fw, oracle) {
				t.Errorf("%s, from %v: differs from one pass:\n%s", c.name, from, diffFields(t, fw, oracle))
			}
		}
	}
}

// sealingSource seals the store's open chunk - and appends after - just before the view reads
// the open chunk, once: as the monitor's flush may while a view is being built.
type sealingSource struct {
	*syslogstore.Store
	t     *testing.T
	once  sync.Once
	after []model.SyslogMessage // appended to a new open chunk after the seal
}

func (s *sealingSource) EachOpen(ctx context.Context, from, to time.Time, fn func(*model.SyslogMessage) error) error {
	s.once.Do(func() {
		if c, err := s.Store.Seal(t0, "stop", true); err != nil || c == nil {
			s.t.Errorf("Seal: %v %v", c, err)
		}
		if len(s.after) > 0 {
			if _, err := s.Store.Append(s.after, 0, 0, t0); err != nil {
				s.t.Error(err)
			}
		}
	})
	return s.Store.EachOpen(ctx, from, to, fn)
}

// TestFirewallSealDuringBuild: a chunk sealed while a view is being built - after the sealed
// chunks were listed, before the open chunk is read - is not left out of the view.
func TestFirewallSealDuringBuild(t *testing.T) {
	ctx := context.Background()
	q := contracts.NetQuery{From: at(0), To: at(100)}

	s := testStore(t)
	appendMsgs(t, s, true, syslogMsg(at(1), lineInbound), syslogMsg(at(2), linePing))
	appendMsgs(t, s, false, syslogMsg(at(3), lineOutbound), syslogMsg(at(4), lineOutbound), syslogMsg(at(5), repeatLine(7)))
	v := New(Options{Syslog: &sealingSource{Store: s, t: t}, ResultTTL: -1})
	for i := range 2 {
		fw, err := v.Firewall(ctx, q)
		if err != nil || fw.Drops != 11 || fw.Inbound != 2 || fw.Outbound != 9 {
			t.Fatalf("request %d: %d drops (%d in, %d out) %v; want 11 (2, 9)", i, fw.Drops, fw.Inbound, fw.Outbound, err)
		}
	}

	// The new open chunk starts with a repeat line: it repeats the last drop of the chunk sealed
	// meanwhile, not one of an earlier chunk.
	s = testStore(t)
	appendMsgs(t, s, true, syslogMsg(at(1), lineInbound))
	appendMsgs(t, s, false, syslogMsg(at(2), lineOutbound), syslogMsg(at(3), repeatLine(7)))
	v = New(Options{Syslog: &sealingSource{Store: s, t: t, after: []model.SyslogMessage{syslogMsg(at(4), repeatLine(5))}}, ResultTTL: -1})
	if fw, err := v.Firewall(ctx, q); err != nil || fw.Inbound != 1 || fw.Outbound != 1+7+5 {
		t.Fatalf("inbound %d, outbound %d (%v); want 1, 13", fw.Inbound, fw.Outbound, err)
	}
}

// historyConns is a connection store that gives its Device List reads by time (deviceHistory).
type historyConns struct {
	*fakeConns
	reads []deviceRead // oldest first
}

type deviceRead struct {
	at      time.Time
	devices []model.LANDevice
}

func (h *historyConns) EachDevices(ctx context.Context, from, to time.Time, fn func(time.Time, []model.LANDevice) error) error {
	first := 0
	for i, r := range h.reads {
		if !r.at.After(from) {
			first = i // the newest at or before from
		}
	}
	for _, r := range h.reads[first:] {
		if r.at.After(from) && !r.at.Before(to) {
			break
		}
		if err := fn(r.at, r.devices); err != nil {
			return err
		}
	}
	return nil
}

// TestFirewallNamesDropsAfterTheDeviceListOfTheirTime: a LAN address's dropped packets are named
// after the Device List read in effect when they were received, so a device whose address DHCP
// gave to another one is not blamed for the other's packets; rows split by device.
func TestFirewallNamesDropsAfterTheDeviceListOfTheirTime(t *testing.T) {
	const day = 24 * time.Hour
	phone := func(ip string) model.LANDevice {
		return model.LANDevice{MAC: "00:00:5E:00:53:70", Name: "Phone", IPv4: ip, Status: "on"}
	}
	laptop := func(ip string) model.LANDevice {
		return model.LANDevice{MAC: "00:00:5e:00:53:71", Name: "Laptop", IPv4: ip, Status: "on"}
	}
	conns := &historyConns{fakeConns: &fakeConns{devices: []model.LANDevice{laptop("192.168.1.70"), phone("192.168.1.90")}},
		reads: []deviceRead{
			{t0.Add(-25 * day), []model.LANDevice{phone("192.168.1.70"), laptop("192.168.1.71")}},
			{t0.Add(-20 * day), []model.LANDevice{phone("192.168.1.70"), laptop("192.168.1.71")}}, // the same again
			{t0.Add(-1 * day), []model.LANDevice{laptop("192.168.1.70"), phone("192.168.1.90")}},  // DHCP moved them
		}}
	s := testStore(t)
	appendMsgs(t, s, true, syslogMsg(t0.Add(-20*day+time.Hour), outLine("192.168.1.70", "192.0.2.44", 443, "POLICY")))
	appendMsgs(t, s, false,
		syslogMsg(t0.Add(time.Minute), outLine("192.168.1.70", "192.0.2.44", 443, "POLICY")),
		syslogMsg(t0.Add(2*time.Minute), outLine("192.168.1.90", "192.0.2.45", 443, "POLICY")))
	q := contracts.NetQuery{From: t0.Add(-21 * day), To: t0.Add(time.Hour)}
	type row struct{ device, name, lan, remote string }
	rowsOf := func(fw model.NetFirewall) map[row]int {
		out := map[row]int{}
		for _, r := range fw.OutboundRows {
			out[row{r.Device, r.Name, r.LAN, r.Remote}] = r.Count
		}
		return out
	}
	fw, err := New(Options{Syslog: s, Conns: conns}).Firewall(context.Background(), q)
	if err != nil {
		t.Fatal(err)
	}
	want := map[row]int{
		{"mac:00:00:5e:00:53:70", "Phone", "192.168.1.70", "192.0.2.44"}:  1, // 20 days ago .70 was the phone's
		{"mac:00:00:5e:00:53:71", "Laptop", "192.168.1.70", "192.0.2.44"}: 1,
		{"mac:00:00:5e:00:53:70", "Phone", "192.168.1.90", "192.0.2.45"}:  1,
	}
	if got := rowsOf(fw); !reflect.DeepEqual(got, want) || fw.OutboundTotal != 3 || fw.OutboundDevices != 2 {
		t.Fatalf("rows %+v (%d, from %d devices); want %+v", got, fw.OutboundTotal, fw.OutboundDevices, want)
	}
	// Before the first read, the first read names them; a store that gives only its newest read
	// has every packet named after it.
	fw, err = New(Options{Syslog: s, Conns: conns.fakeConns}).Firewall(context.Background(), q)
	want = map[row]int{
		{"mac:00:00:5e:00:53:71", "Laptop", "192.168.1.70", "192.0.2.44"}: 2,
		{"mac:00:00:5e:00:53:70", "Phone", "192.168.1.90", "192.0.2.45"}:  1,
	}
	if got := rowsOf(fw); err != nil || !reflect.DeepEqual(got, want) || fw.OutboundDevices != 2 {
		t.Fatalf("with the newest read only: rows %+v (%v)", got, err)
	}
	n := newDevNamer()
	n.add(nanos(t0), []model.LANDevice{phone("192.168.1.70")})
	if num := n.device(srcKey("192.168.1.70"), nanos(t0.Add(-day))); num == 0 {
		t.Fatal("before the first read: not named after it")
	}
}
