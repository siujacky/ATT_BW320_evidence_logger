package probe

import (
	"context"
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"time"

	"attmonitor/internal/model"
)

// timeToNTP encodes t as a 64-bit NTP timestamp (era wrapping is implicit in uint32).
func timeToNTP(t time.Time) [8]byte {
	var b [8]byte
	secs := uint64(t.Unix() + ntpEpochOffset)
	frac := (uint64(t.Nanosecond()) << 32) / 1e9
	binary.BigEndian.PutUint32(b[0:4], uint32(secs))
	binary.BigEndian.PutUint32(b[4:8], uint32(frac))
	return b
}

// fakeNTP configures the in-process NTP server.
type fakeNTP struct {
	offset       time.Duration // server clock minus real time
	stratum      byte
	li           byte
	mode         byte // 0 → 4 (server)
	refID        string
	decoyFirst   bool // send a reply with a wrong originate and a runt first
	noReply      bool
	shortOnly    bool // reply with a 40-byte runt only
	zeroTransmit bool
	zeroReceive  bool          // receive timestamp left zero (a broken or hostile server)
	backwards    bool          // transmit timestamp one second before the receive timestamp
	hold         time.Duration // server "processing" time between receive and transmit
}

func startFakeNTP(t *testing.T, cfg fakeNTP) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		buf := make([]byte, 512)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			recv := time.Now().Add(cfg.offset)
			if n < ntpPacketLen || cfg.noReply {
				continue
			}
			req := append([]byte(nil), buf[:n]...)
			if req[0]&7 != 3 || (req[0]>>3)&7 != 4 {
				t.Errorf("request header %#x, want NTPv4 client", req[0])
			}
			resp := make([]byte, ntpPacketLen)
			mode := cfg.mode
			if mode == 0 {
				mode = 4
			}
			resp[0] = cfg.li<<6 | 4<<3 | mode
			resp[1] = cfg.stratum
			resp[2], resp[3] = 6, 0xEC
			copy(resp[12:16], cfg.refID)
			copy(resp[24:32], req[40:48]) // originate = the client's transmit timestamp
			r := timeToNTP(recv)
			copy(resp[32:40], r[:])
			if cfg.hold > 0 {
				time.Sleep(cfg.hold)
			}
			x := timeToNTP(time.Now().Add(cfg.offset))
			copy(resp[40:48], x[:])
			if cfg.zeroTransmit {
				clear(resp[40:48])
			}
			if cfg.zeroReceive {
				clear(resp[32:40])
			}
			if cfg.backwards {
				b := timeToNTP(recv.Add(-time.Second))
				copy(resp[40:48], b[:])
			}
			if cfg.decoyFirst {
				decoy := append([]byte(nil), resp...)
				decoy[24] ^= 0xff
				_, _ = pc.WriteTo(decoy, from)
				_, _ = pc.WriteTo([]byte{1, 2, 3}, from)
			}
			if cfg.shortOnly {
				resp = resp[:40]
			}
			_, _ = pc.WriteTo(resp, from)
		}
	}()
	t.Cleanup(func() { pc.Close() })
	return pc.LocalAddr().String()
}

func TestSNTP(t *testing.T) {
	tests := []struct {
		name       string
		srv        fakeNTP
		timeout    time.Duration
		wantOK     bool
		wantOffset int64 // ms, checked when wantOK
		errIn      string
		stratum    int
	}{
		{name: "server ahead 1.5s", srv: fakeNTP{offset: 1500 * time.Millisecond, stratum: 2}, wantOK: true, wantOffset: 1500, stratum: 2},
		{name: "server behind 2.5s", srv: fakeNTP{offset: -2500 * time.Millisecond, stratum: 1, refID: "GPS"}, wantOK: true, wantOffset: -2500, stratum: 1},
		{name: "in sync", srv: fakeNTP{stratum: 3}, wantOK: true, wantOffset: 0, stratum: 3},
		{name: "server processing time is not offset", srv: fakeNTP{offset: 700 * time.Millisecond, stratum: 2, hold: 80 * time.Millisecond},
			wantOK: true, wantOffset: 700, stratum: 2},
		{name: "decoys ignored", srv: fakeNTP{offset: 1500 * time.Millisecond, stratum: 2, decoyFirst: true}, wantOK: true, wantOffset: 1500, stratum: 2},
		{name: "kiss-o'-death", srv: fakeNTP{stratum: 0, refID: "RATE"}, errIn: "kiss-o'-death from server: RATE"},
		{name: "unsynchronized leap indicator", srv: fakeNTP{stratum: 2, li: 3}, errIn: "not synchronized (leap indicator 3)", stratum: 2},
		{name: "stratum 16", srv: fakeNTP{stratum: 16}, errIn: "stratum 16", stratum: 16},
		{name: "wrong mode", srv: fakeNTP{stratum: 2, mode: 3}, errIn: "unexpected NTP mode 3", stratum: 2},
		{name: "zero transmit timestamp", srv: fakeNTP{stratum: 2, zeroTransmit: true}, errIn: "zero transmit", stratum: 2},
		{name: "runt only times out", srv: fakeNTP{stratum: 2, shortOnly: true}, timeout: 300 * time.Millisecond, errIn: "timeout: no reply within 300ms"},
		{name: "no reply times out", srv: fakeNTP{noReply: true}, timeout: 300 * time.Millisecond, errIn: "timeout: no reply within 300ms"},
	}
	p := New(Options{})
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr := startFakeNTP(t, tt.srv)
			timeout := tt.timeout
			if timeout == 0 {
				timeout = 2 * time.Second
			}
			start := time.Now()
			r := p.SNTP(context.Background(), addr, timeout)
			el := time.Since(start)
			if r.Server != addr || r.Addr != addr {
				t.Errorf("Server/Addr = %q/%q, want %q", r.Server, r.Addr, addr)
			}
			if r.OK != tt.wantOK || !strings.Contains(r.Err, tt.errIn) || (tt.wantOK && r.Err != "") {
				t.Fatalf("OK/Err = %v/%q, want %v/%q", r.OK, r.Err, tt.wantOK, tt.errIn)
			}
			if r.Stratum != tt.stratum {
				t.Errorf("Stratum = %d, want %d", r.Stratum, tt.stratum)
			}
			if tt.wantOK {
				if d := r.OffsetMs - tt.wantOffset; d < -50 || d > 50 {
					t.Errorf("OffsetMs = %d, want %d ± 50", r.OffsetMs, tt.wantOffset)
				}
				if r.RTTms < 0 || r.RTTms > 50 {
					t.Errorf("RTTms = %d, want a small loopback delay (server hold excluded)", r.RTTms)
				}
			} else if r.OffsetMs != 0 || r.RTTms != 0 {
				t.Errorf("failed measurement carries offset/rtt: %+v", r)
			}
			if el > timeout+500*time.Millisecond {
				t.Errorf("took %v", el)
			}
		})
	}
}

func TestSNTPFailures(t *testing.T) {
	p := New(Options{})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if r := p.SNTP(ctx, "127.0.0.1:123", time.Second); r.OK || !strings.HasPrefix(r.Err, "canceled") {
		t.Errorf("pre-canceled: %+v", r)
	}

	addr := startFakeNTP(t, fakeNTP{noReply: true})
	ctx, cancel = context.WithCancel(context.Background())
	time.AfterFunc(50*time.Millisecond, cancel)
	start := time.Now()
	r := p.SNTP(ctx, addr, 5*time.Second)
	if el := time.Since(start); el > time.Second || r.OK || !strings.HasPrefix(r.Err, "canceled") {
		t.Errorf("cancel while waiting: %+v after %v", r, el)
	}

	for _, server := range []string{"", "a:b:c", "[::1"} {
		if r := p.SNTP(context.Background(), server, 200*time.Millisecond); r.OK || !strings.HasPrefix(r.Err, "server") {
			t.Errorf("SNTP(%q) = %+v", server, r)
		}
	}

	// A name that cannot resolve fails with the resolver's error (offline: also an error).
	start = time.Now()
	r = p.SNTP(context.Background(), "ntp.att-monitor-test.invalid", 500*time.Millisecond)
	if r.OK || r.Err == "" || r.Addr != "" || time.Since(start) > 3*time.Second {
		t.Errorf("unresolvable: %+v", r)
	}
}

func TestEvalNTPReply(t *testing.T) {
	t1 := time.Date(2026, 10, 5, 3, 20, 0, 0, time.UTC)
	t4 := t1.Add(10 * time.Millisecond)
	mk := func(t2, t3 time.Time) []byte {
		pkt := make([]byte, ntpPacketLen)
		pkt[0] = 4<<3 | 4
		pkt[1] = 2
		a, b := timeToNTP(t2), timeToNTP(t3)
		copy(pkt[32:40], a[:])
		copy(pkt[40:48], b[:])
		return pkt
	}
	rtt := t4.Sub(t1)
	// Symmetric path: server 1s ahead, 4 ms each way, 2 ms processing.
	var r model.ClockResult
	evalNTPReply(&r, mk(t1.Add(time.Second+4*time.Millisecond), t1.Add(time.Second+6*time.Millisecond)), t1, rtt)
	if !r.OK || r.OffsetMs != 1000 || r.RTTms != 8 {
		t.Fatalf("got %+v, want offset 1000 rtt 8", r)
	}
	// Server timestamps spanning more than our round trip: delay clamps to 0.
	r = model.ClockResult{}
	evalNTPReply(&r, mk(t1.Add(time.Second+2*time.Millisecond), t1.Add(time.Second+22*time.Millisecond)), t1, rtt)
	if !r.OK || r.RTTms != 0 || r.OffsetMs != 1007 {
		t.Fatalf("got %+v, want offset 1007 rtt 0", r)
	}
	// A send time that carries a monotonic reading is used by its wall value:
	// (2.002 + (2.004-0.006))/2 = 2.000 s, delay 6-2 = 4 ms.
	tm := time.Now()
	r = model.ClockResult{}
	evalNTPReply(&r, mk(tm.Round(0).Add(2002*time.Millisecond), tm.Round(0).Add(2004*time.Millisecond)), tm, 6*time.Millisecond)
	if !r.OK || r.OffsetMs != 2000 || r.RTTms != 4 {
		t.Fatalf("monotonic t1: got %+v, want offset 2000 rtt 4", r)
	}
	// Equal receive and transmit timestamps (coarse server clock) are fine.
	r = model.ClockResult{}
	evalNTPReply(&r, mk(t1.Add(5*time.Millisecond), t1.Add(5*time.Millisecond)), t1, rtt)
	if !r.OK || r.OffsetMs != 0 || r.RTTms != 10 {
		t.Fatalf("equal t2/t3: got %+v, want offset 0 rtt 10", r)
	}
	// Transmit before receive: rejected, with no offset.
	r = model.ClockResult{}
	evalNTPReply(&r, mk(t1.Add(6*time.Millisecond), t1.Add(5*time.Millisecond)), t1, rtt)
	if r.OK || r.OffsetMs != 0 || !strings.Contains(r.Err, "before its receive timestamp") {
		t.Fatalf("t3 < t2: got %+v", r)
	}
	// Zero receive timestamp: rejected (it would decode as the 2036 era boundary).
	r = model.ClockResult{}
	pkt := mk(t1, t1.Add(time.Millisecond))
	clear(pkt[32:40])
	evalNTPReply(&r, pkt, t1, rtt)
	if r.OK || r.OffsetMs != 0 || r.Err != "reply has a zero receive timestamp" {
		t.Fatalf("zero t2: got %+v", r)
	}
}

func TestNTPToTime(t *testing.T) {
	ref := time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC)
	for _, want := range []time.Time{
		time.Date(2026, 10, 5, 3, 19, 57, 123456789, time.UTC),
		time.Date(1999, 12, 31, 23, 59, 59, 999999999, time.UTC),
		time.Date(2036, 2, 7, 6, 28, 15, 500000000, time.UTC), // last second of era 0
		time.Date(2036, 2, 7, 6, 28, 16, 0, time.UTC),         // first second of era 1
		time.Date(2050, 1, 1, 0, 0, 0, 1, time.UTC),
	} {
		b := timeToNTP(want)
		// Reference within half an era of the true time picks the right era.
		for _, r := range []time.Time{ref, want, want.Add(-30 * 365 * 24 * time.Hour), want.Add(30 * 365 * 24 * time.Hour)} {
			got := ntpToTime(b[:], r)
			if d := got.Sub(want); d < -2 || d > 2 {
				t.Errorf("ntpToTime(%v, ref %v) = %v (off by %v)", want, r, got, d)
			}
		}
	}
	// Era 1 seconds value 0 decodes to the 2036 rollover instant when the reference is near it.
	if got := ntpToTime(make([]byte, 8), time.Date(2036, 3, 1, 0, 0, 0, 0, time.UTC)); !got.Equal(time.Date(2036, 2, 7, 6, 28, 16, 0, time.UTC)) {
		t.Errorf("era 1 zero = %v", got)
	}
	if got := ntpToTime(make([]byte, 8), time.Date(1950, 1, 1, 0, 0, 0, 0, time.UTC)); !got.Equal(time.Date(1900, 1, 1, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("era 0 zero = %v", got)
	}
	// Before 1900 the nearest era is negative (floor division): the last second of era -1.
	last := []byte{0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0}
	if got := ntpToTime(last, time.Date(1840, 1, 1, 0, 0, 0, 0, time.UTC)); !got.Equal(time.Date(1899, 12, 31, 23, 59, 59, 0, time.UTC)) {
		t.Errorf("era -1 = %v", got)
	}
}

func TestKissCodeAndRounding(t *testing.T) {
	for in, want := range map[string]string{
		"RATE": "RATE", "DENY": "DENY", "RST\x00": "RST", "\x00\x00\x00\x00": "(empty code)", "\x01\x02ab": "0x01026162",
	} {
		if got := kissCode([]byte(in)); got != want {
			t.Errorf("kissCode(%q) = %q, want %q", in, got, want)
		}
	}
	for d, want := range map[time.Duration]int64{
		0: 0, 1499 * time.Microsecond: 1, 1500 * time.Microsecond: 2, -1500 * time.Microsecond: -2,
		-1499 * time.Microsecond: -1, 2500 * time.Millisecond: 2500,
	} {
		if got := roundMs(d); got != want {
			t.Errorf("roundMs(%v) = %d, want %d", d, got, want)
		}
	}
}
