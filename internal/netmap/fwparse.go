package netmap

import (
	"bytes"
	"net/netip"
)

// Directions of a dropped packet; they index the counts.
const (
	dirIn    = 0 // from the Internet, to the gateway or toward the LAN (model.FwInbound)
	dirOut   = 1 // from the LAN toward the Internet (model.FwOutbound)
	dirLocal = 2 // sent by the gateway itself, or between the LAN and the gateway (model.FwLocal)
	nDirs    = 3
)

const (
	// maxRepeat bounds what one "repeated N times" line counts: syslog-ng states the repeats of a
	// few seconds, so a larger number is not believed.
	maxRepeat = 100000
	// maxReason and maxProto bound the reason and protocol names kept (longer ones are cut).
	maxReason = 64
	maxProto  = 16
)

// drop is a packet the firewall dropped, as its syslog line describes it. The line's MAC field
// is never kept: it holds this network's hardware addresses.
type drop struct {
	src, dst     [16]byte // the addresses (IPv4 as IPv4-mapped IPv6)
	srcOK, dstOK bool     // whether the line stated them
	spt, dpt     uint16   // the ports (0 when not stated: ICMP, a line cut short)
	proto        uint8    // codes.protos
	reason       uint8    // codes.reasons
	dir          uint8
}

// Kinds of a syslog line.
const (
	lineOther  = iota // anything else (also a line about another program)
	lineDrop          // a packet the firewall dropped
	lineRepeat        // syslog-ng: the previous message, a firewall line as its quote shows, repeated N more times
	// lineRepeatPrev is BSD syslogd's "last message repeated N times": the message before it,
	// whatever it was, repeated N more times. The BGW320's syslog-ng always quotes the message it
	// repeats, so such a line comes from another sender (syslog.allow); it counts drops only
	// when the message before it was a drop.
	lineRepeatPrev
)

var (
	keyAction  = []byte("action=")
	keyLastMsg = []byte("ast message ") // "Last message" (syslog-ng), "last message" (BSD syslogd)
	keyRepeat  = []byte("' repeated ")
)

// parse classifies the text of one syslog message: a dropped packet (d), a repeat of the
// previous message (n more; lineRepeat when the line quotes a firewall line, lineRepeatPrev when
// it quotes nothing), or anything else. It never panics, whatever the text.
func (c *codes) parse(text []byte) (kind int, d drop, n int) {
	if d, ok := c.parseDrop(text); ok {
		return lineDrop, d, 0
	}
	if n, quoted, ok := parseRepeat(text); ok {
		if quoted {
			return lineRepeat, drop{}, n
		}
		return lineRepeatPrev, drop{}, n
	}
	return lineOther, drop{}, 0
}

// fwFields are the fields of a firewall line that the view uses, as the line states them.
type fwFields struct {
	action, reason, in, out, src, dst, proto, spt, dpt []byte
	seen                                               uint16 // the fields found (the first of each counts)
}

const (
	fAction = 1 << iota
	fReason
	fIn
	fOut
	fSrc
	fDst
	fProto
	fSpt
	fDpt
	fAll = 1<<iota - 1
)

// fieldStarts marks the first bytes of the fields the view reads (MAC: the source address is
// written right after it), so that the others are skipped at once.
var fieldStarts = func() (t [256]bool) {
	for _, c := range "arIOSDPM[" {
		t[c] = true
	}
	return t
}()

// parseDrop parses a line of the gateway's packet filter (nflog_log_fw): "action=DROP" (or
// REJECT) followed by KEY=VALUE fields separated by spaces, of which it needs IN= (empty for a
// packet the gateway sent itself). The line's header before "action=" does not matter, nor do
// the fields it does not use; only the first of each field counts, and the packet an ICMP error
// quotes in brackets after the dropped packet's fields ("[SRC=… DST=… DPT=53]") is not read.
func (c *codes) parseDrop(text []byte) (drop, bool) {
	i := fieldStart(text, keyAction)
	if i < 0 {
		return drop{}, false
	}
	var f fwFields
	for rest := text[i:]; len(rest) > 0 && f.seen != fAll; {
		tok := rest
		if j := bytes.IndexByte(rest, ' '); j >= 0 {
			tok, rest = rest[:j], rest[j+1:]
		} else {
			rest = nil
		}
		if len(tok) == 0 || !fieldStarts[tok[0]] {
			continue
		}
		if tok[0] == '[' {
			break // the packet an ICMP error is about: its fields are not the dropped packet's
		}
		f.take(tok)
	}
	if f.seen&fAction == 0 || !bytes.EqualFold(f.action, []byte("DROP")) && !bytes.EqualFold(f.action, []byte("REJECT")) ||
		f.seen&fIn == 0 {
		return drop{}, false
	}
	d := drop{dir: direction(f.in, f.out)}
	d.src, d.srcOK = parseAddr(f.src)
	d.dst, d.dstOK = parseAddr(f.dst)
	d.spt, d.dpt = parsePort(f.spt), parsePort(f.dpt)
	var buf [maxReason]byte
	d.proto = c.protos.id(cleanProto(buf[:0], f.proto))
	d.reason = c.reasons.id(cleanReason(buf[:0], f.reason))
	return d, true
}

// take notes one KEY=VALUE token.
func (f *fwFields) take(tok []byte) {
	eq := bytes.IndexByte(tok, '=')
	if eq <= 0 {
		return
	}
	key, val := tok[:eq], tok[eq+1:]
	switch string(key) {
	case "action":
		f.set(fAction, &f.action, val)
	case "reason":
		f.set(fReason, &f.reason, val)
	case "IN":
		f.set(fIn, &f.in, val)
	case "OUT":
		f.set(fOut, &f.out, val)
	case "SRC":
		f.set(fSrc, &f.src, val)
	case "DST":
		f.set(fDst, &f.dst, val)
	case "PROTO":
		f.set(fProto, &f.proto, val)
	case "SPT":
		f.set(fSpt, &f.spt, val)
	case "DPT":
		f.set(fDpt, &f.dpt, val)
	case "MAC":
		// The gateway writes the source address right after the MAC addresses, without a
		// space ("MAC=…:53:02:SRC=203.0.113.66"). The addresses themselves are skipped, never
		// kept.
		if k := bytes.Index(val, []byte("SRC=")); k >= 0 {
			f.set(fSrc, &f.src, val[k+len("SRC="):])
		}
	}
}

// set keeps the first value of a field.
func (f *fwFields) set(bit uint16, dst *[]byte, val []byte) {
	if f.seen&bit == 0 {
		f.seen |= bit
		*dst = val
	}
}

// fieldStart returns where key starts text or follows a space in it (-1 when it does not).
func fieldStart(text, key []byte) int {
	for off := 0; off < len(text); {
		i := bytes.Index(text[off:], key)
		if i < 0 {
			return -1
		}
		i += off
		if i == 0 || text[i-1] == ' ' {
			return i
		}
		off = i + 1
	}
	return -1
}

// direction tells from the interfaces a packet came in on and was to go out on where it was
// going. A packet the gateway sent itself has no IN; LAN interfaces are the bridges (br*), lan*
// and the Wi-Fi radios (wl*); every other interface but the loopback is the WAN side (veip0.0
// on the BGW320: the fiber).
func direction(in, out []byte) uint8 {
	switch {
	case len(in) == 0:
		return dirLocal
	case lanLike(in):
		if len(out) > 0 && !lanLike(out) && string(out) != "lo" {
			return dirOut
		}
		return dirLocal // to the gateway, or from LAN to LAN
	case string(in) == "lo":
		return dirLocal
	}
	return dirIn // to the gateway when OUT is empty, toward the LAN otherwise
}

// lanLike reports whether an interface is on the LAN side.
func lanLike(name []byte) bool {
	return bytes.HasPrefix(name, []byte("br")) || bytes.HasPrefix(name, []byte("lan")) ||
		bytes.HasPrefix(name, []byte("wl"))
}

// parseRepeat parses syslog-ng's "Last message 'FIREWALL[8512]: nflo' repeated 3 times,
// suppressed by syslog-ng on dsldevice" (quoted: the line names the message it repeats) and BSD
// syslogd's "last message repeated 3 times" (not quoted: it repeats the message before it,
// whatever that was): the previous message was repeated n more times. A line that quotes another
// program's message is no repeat of a drop: ok is false for it.
func parseRepeat(text []byte) (n int, quoted, ok bool) {
	i := bytes.Index(text, keyLastMsg)
	if i < 1 || text[i-1] != 'L' && text[i-1] != 'l' {
		return 0, false, false
	}
	rest := text[i+len(keyLastMsg):]
	if len(rest) > 0 && rest[0] == '\'' {
		j := bytes.Index(rest[1:], keyRepeat)
		if j < 0 || !firewallQuote(rest[1:1+j]) {
			return 0, false, false
		}
		rest, quoted = rest[1+j+2:], true // "repeated …"
	}
	rest, ok = bytes.CutPrefix(rest, []byte("repeated "))
	if !ok {
		return 0, false, false
	}
	k := 0
	for k < len(rest) && k < 10 && rest[k] >= '0' && rest[k] <= '9' {
		n = n*10 + int(rest[k]-'0')
		k++
	}
	if k == 0 || k == 10 || n == 0 || !bytes.HasPrefix(rest[k:], []byte(" time")) {
		return 0, false, false
	}
	return min(n, maxRepeat), quoted, true
}

// firewallQuote reports whether the start of a message that syslog-ng quotes in a repeat line
// is the start of a firewall line ("FIREWALL[8512]: nflo").
func firewallQuote(q []byte) bool {
	q = bytes.TrimLeft(q, " ")
	return len(q) >= 8 && bytes.EqualFold(q[:8], []byte("FIREWALL")) ||
		bytes.Contains(q, []byte("nflog")) || bytes.Contains(q, keyAction)
}

// parseAddr parses an IPv4 or IPv6 address of a firewall line into its 16-byte form (an IPv6
// zone is dropped).
func parseAddr(b []byte) ([16]byte, bool) {
	if len(b) == 0 || len(b) > 64 {
		return [16]byte{}, false
	}
	if a, ok := parseIPv4(b); ok {
		return netip.AddrFrom4(a).As16(), true
	}
	if bytes.IndexByte(b, ':') < 0 {
		return [16]byte{}, false
	}
	a, err := netip.ParseAddr(string(b))
	if err != nil {
		return [16]byte{}, false
	}
	return a.Unmap().As16(), true
}

// parseIPv4 parses a dotted-quad IPv4 address as netip.ParseAddr does (no leading zeros),
// without the string it would need.
func parseIPv4(b []byte) ([4]byte, bool) {
	var a [4]byte
	part, digits, val := 0, 0, 0
	for i := 0; i <= len(b); i++ {
		if i == len(b) || b[i] == '.' {
			if digits == 0 || part > 3 {
				return a, false
			}
			a[part] = byte(val)
			part, digits, val = part+1, 0, 0
			continue
		}
		c := b[i]
		if c < '0' || c > '9' || digits > 0 && val == 0 { // not a digit, or a leading zero
			return a, false
		}
		val = val*10 + int(c-'0')
		digits++
		if val > 255 {
			return a, false
		}
	}
	return a, part == 4
}

// parsePort parses a port number (0 when b is not one).
func parsePort(b []byte) uint16 {
	if len(b) == 0 || len(b) > 5 {
		return 0
	}
	n := 0
	for _, c := range b {
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int(c-'0')
	}
	if n > 65535 {
		return 0
	}
	return uint16(n)
}

// cleanProto returns the protocol name in lower case ("TCP" → "tcp", "ICMPv6" → "icmpv6"),
// appended to buf; nil for a value that is no protocol name (too long, odd characters).
func cleanProto(buf, b []byte) []byte {
	if len(b) == 0 || len(b) > maxProto {
		return nil
	}
	for _, c := range b {
		switch {
		case c >= 'A' && c <= 'Z':
			buf = append(buf, c+'a'-'A')
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_':
			buf = append(buf, c)
		default:
			return nil
		}
	}
	return buf
}

// cleanReason returns the reason as it is when it is printable ASCII of at most maxReason
// bytes, else cut to that and with '?' for every other byte (in buf).
func cleanReason(buf, b []byte) []byte {
	clean := len(b) <= maxReason
	for _, c := range b {
		if c <= ' ' || c > '~' {
			clean = false
			break
		}
	}
	if clean {
		return b
	}
	for _, c := range b[:min(len(b), maxReason)] {
		if c <= ' ' || c > '~' {
			c = '?'
		}
		buf = append(buf, c)
	}
	return buf
}
