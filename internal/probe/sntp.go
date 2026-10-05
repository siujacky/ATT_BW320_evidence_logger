package probe

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"strings"
	"time"

	"attmonitor/internal/model"
)

const (
	ntpPacketLen = 48
	// ntpEpochOffset is the number of seconds from the NTP epoch (1900-01-01T00:00:00Z) to
	// the Unix epoch.
	ntpEpochOffset = 2208988800
	ntpEraSeconds  = int64(1) << 32 // one NTP era (≈136 years)
)

// SNTP measures the local clock against server ("host" or "host:port", default port 123)
// with one NTPv4 client-mode request (RFC 4330/5905). The transmit timestamp is a random
// cookie that the server must echo as its originate timestamp; other datagrams are ignored.
//
// With t1/t4 the local send/receive times and t2/t3 the server receive/transmit times,
// OffsetMs = ((t2-t1)+(t3-t4))/2 (server minus local) and RTTms = (t4-t1)-(t3-t2). t1 is read
// from the system clock at full resolution (preciseWallNow) and t4 = t1 + the round trip
// measured on the high-resolution monotonic clock, so a clock step during the exchange
// does not distort the result. Kiss-o'-death replies (stratum 0), unsynchronized servers
// (leap indicator 3 or stratum ≥ 16), replies with a zero receive or transmit timestamp or
// a transmit timestamp before the receive timestamp, and resolution or network failures
// give OK=false with the reason in Err. Host names are resolved to IPv4, the same path as
// the fast-cycle probes; Addr is the address actually queried.
func (p *Prober) SNTP(ctx context.Context, server string, timeout time.Duration) model.ClockResult {
	res := model.ClockResult{Server: server}
	host, port, err := hostPort(server, "123")
	if err != nil {
		res.Err = "server: " + err.Error()
		return res
	}
	to := effectiveTimeout(ctx, timeout)
	if ctx.Err() != nil || to <= 0 {
		res.Err = StatusCanceled + ": " + ctxErr(ctx).Error()
		return res
	}
	qctx, cancel := context.WithTimeout(ctx, to)
	defer cancel()

	network := "udp4"
	if _, err := netip.ParseAddr(host); err == nil {
		network = "udp" // an explicit literal of either family is used as given
	}
	var d net.Dialer
	conn, err := d.DialContext(qctx, network, net.JoinHostPort(host, port))
	if err != nil {
		res.Err = err.Error()
		return res
	}
	defer conn.Close()
	if ra := conn.RemoteAddr(); ra != nil {
		res.Addr = ra.String()
	}
	if dl, ok := qctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	stop := context.AfterFunc(qctx, func() { _ = conn.SetDeadline(time.Unix(1, 0)) })
	defer stop()

	var req [ntpPacketLen]byte
	req[0] = 0<<6 | 4<<3 | 3 // LI 0 (no warning), VN 4, Mode 3 (client)
	var cookie [8]byte
	_, _ = rand.Read(cookie[:])
	copy(req[40:48], cookie[:])

	t1 := preciseWallNow()
	sw := startStopwatch()
	if _, err := conn.Write(req[:]); err != nil {
		res.Err = err.Error()
		return res
	}
	buf := make([]byte, 1024) // 48-byte header plus any extension fields / MAC
	for {
		n, err := conn.Read(buf)
		rtt := sw.elapsed()
		if err != nil {
			var ne net.Error
			switch {
			case errors.Is(ctx.Err(), context.Canceled):
				res.Err = StatusCanceled + ": " + ctx.Err().Error()
			case errors.As(err, &ne) && ne.Timeout():
				res.Err = fmt.Sprintf("%s: no reply within %v", StatusTimeout, to.Round(time.Millisecond))
			default:
				res.Err = err.Error()
			}
			return res
		}
		pkt := buf[:n]
		if n < ntpPacketLen || !bytes.Equal(pkt[24:32], cookie[:]) {
			p.log.Debug("sntp: ignored datagram", "server", res.Addr, "bytes", n)
			continue
		}
		evalNTPReply(&res, pkt, t1, rtt)
		return res
	}
}

// evalNTPReply validates a reply to our request and fills res. t1 is the local (wall) send
// time and rtt the locally measured time from sending to receiving (t4 - t1).
func evalNTPReply(res *model.ClockResult, pkt []byte, t1 time.Time, rtt time.Duration) {
	li := pkt[0] >> 6
	mode := pkt[0] & 7
	stratum := int(pkt[1])
	res.Stratum = stratum
	switch {
	case mode != 4:
		res.Err = fmt.Sprintf("unexpected NTP mode %d in reply (want 4, server)", mode)
		return
	case stratum == 0:
		res.Err = "kiss-o'-death from server: " + kissCode(pkt[12:16])
		return
	case li == 3:
		res.Err = "server clock not synchronized (leap indicator 3)"
		return
	case stratum >= 16:
		res.Err = fmt.Sprintf("server not synchronized (stratum %d)", stratum)
		return
	}
	if binary.BigEndian.Uint64(pkt[40:48]) == 0 {
		res.Err = "reply has a zero transmit timestamp"
		return
	}
	// A zero receive timestamp would be decoded as the 1900/2036 era boundary and yield an
	// offset of years presented as a valid measurement.
	if binary.BigEndian.Uint64(pkt[32:40]) == 0 {
		res.Err = "reply has a zero receive timestamp"
		return
	}
	t1w := t1.Round(0)
	t4w := t1w.Add(rtt) // wall time consistent with t1, immune to clock steps meanwhile
	t2 := ntpToTime(pkt[32:40], t1w)
	t3 := ntpToTime(pkt[40:48], t1w)
	if t3.Before(t2) {
		res.Err = fmt.Sprintf("server transmit timestamp %s is before its receive timestamp %s",
			t3.Format(time.RFC3339Nano), t2.Format(time.RFC3339Nano))
		return
	}
	offset := (t2.Sub(t1w) + t3.Sub(t4w)) / 2
	delay := rtt - t3.Sub(t2)
	if delay < 0 { // server timestamp granularity can exceed a loopback round trip
		delay = 0
	}
	res.OK = true
	res.OffsetMs = roundMs(offset)
	res.RTTms = roundMs(delay)
}

// ntpToTime converts a 64-bit NTP timestamp, choosing the NTP era that puts the result
// closest to ref (correct across the 2036 era rollover).
func ntpToTime(b []byte, ref time.Time) time.Time {
	sec := int64(binary.BigEndian.Uint32(b[0:4]))
	frac := uint64(binary.BigEndian.Uint32(b[4:8]))
	nanos := int64((frac*1e9 + 1<<31) >> 32) // rounded
	// Nearest era: floor((refNTP - sec + era/2) / era).
	num := ref.Unix() + ntpEpochOffset - sec + ntpEraSeconds/2
	era := num / ntpEraSeconds
	if num < 0 && num%ntpEraSeconds != 0 {
		era-- // Go's division truncates toward zero
	}
	return time.Unix(sec+era*ntpEraSeconds-ntpEpochOffset, nanos).UTC()
}

// kissCode renders a kiss-o'-death reference ID ("RATE", "DENY", ...) printably.
func kissCode(b []byte) string {
	s := strings.TrimRight(string(b), "\x00")
	for _, r := range s {
		if r < 0x20 || r > 0x7e {
			return fmt.Sprintf("0x%x", b)
		}
	}
	if s == "" {
		return "(empty code)"
	}
	return s
}

// roundMs rounds a duration to whole milliseconds (half away from zero).
func roundMs(d time.Duration) int64 {
	return int64(math.Round(float64(d) / float64(time.Millisecond)))
}
