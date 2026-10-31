package web

import (
	"encoding/base64"
	"math"
	"net"
	"net/netip"
	"strings"
	"time"

	"attmonitor/internal/model"
)

// Finding a device's syslog messages (GET /api/network/device): the terms of its details
// (model.NetSyslogTerm, made by the network view) are looked for in each message's text - the
// exact datagram (Raw, else the bytes RawB64 holds, else the parsed message) - as whole addresses:
//
//   - an IPv4 address only as a whole number - 192.168.1.7 is never found in 192.168.1.70, in
//     10.192.168.1.7 or in 192.168.1.7.5 - and only in a message received within the term's times
//     (From and To, RFC 3339: [From, To); "" leaves that side open), since DHCP gives the address
//     to other devices at other times;
//   - an IPv6 address in its canonical form (as Go's net/netip writes it) or written out in full,
//     ignoring case, as a whole address (2001:db8::1 is not found in 2001:db8::10 or
//     2001:db8::1:5);
//   - a MAC address in either notation (00:00:5e:00:53:01, 00-00-5e-00-53-01), ignoring case, as a
//     whole address, and also as the destination or the source address of the firewall's MAC field
//     (MAC=<destination>:<source>:<type>), where the gateway writes them run together.
//
// A term of another kind, or one that does not parse, is left out; at most maxDeviceTerms are used.

// maxDeviceTerms bounds the terms one request looks for (the network view gives a device's IPv4
// holds, at most 128, its IPv6 addresses, at most 32, and its MAC address).
const maxDeviceTerms = 256

// Kinds of a syslog term (model.NetSyslogTerm.Kind).
const (
	termIPv4 = "ipv4"
	termIPv6 = "ipv6"
	termMAC  = "mac"
)

// maxTermRun is the longest run of address characters that can be one of the terms' forms (an
// IPv6 address written out in full has 39); longer runs are no address the terms name.
const maxTermRun = 45

// rxWindow is a time an IPv4 term counts: [from, to), Unix nanoseconds.
type rxWindow struct{ from, to int64 }

// syslogMatcher finds the messages that name a device's terms.
type syslogMatcher struct {
	v4  map[string][]rxWindow // by the address as written (canonical: no leading zeros)
	v6  map[string]bool       // canonical and full forms, lower case
	mac map[string]bool       // colon and dash forms, lower case
}

// newSyslogMatcher returns the matcher of terms; nil when none of them can find anything.
func newSyslogMatcher(terms []model.NetSyslogTerm) *syslogMatcher {
	m := &syslogMatcher{v4: map[string][]rxWindow{}, v6: map[string]bool{}, mac: map[string]bool{}}
	for i, t := range terms {
		if i == maxDeviceTerms {
			break
		}
		text := strings.TrimSpace(t.Text)
		switch strings.ToLower(strings.TrimSpace(t.Kind)) {
		case termIPv4:
			a, err := netip.ParseAddr(text)
			w, ok := termWindow(t)
			if err != nil || !a.Is4() || !ok {
				continue
			}
			m.v4[a.String()] = append(m.v4[a.String()], w)
		case termIPv6:
			a, err := netip.ParseAddr(text)
			if err != nil || !a.Is6() || a.Is4In6() {
				continue
			}
			a = a.WithZone("")
			m.v6[a.String()] = true
			m.v6[a.StringExpanded()] = true
		case termMAC:
			hw, err := net.ParseMAC(text)
			if err != nil || len(hw) != 6 {
				continue
			}
			colon := strings.ToLower(hw.String())
			m.mac[colon] = true
			m.mac[strings.ReplaceAll(colon, ":", "-")] = true
		}
	}
	if len(m.v4) == 0 && len(m.v6) == 0 && len(m.mac) == 0 {
		return nil
	}
	return m
}

// termWindow returns when an IPv4 term counts ([From, To), an open side for ""); false when a
// time is given that does not parse.
func termWindow(t model.NetSyslogTerm) (rxWindow, bool) {
	w := rxWindow{from: math.MinInt64, to: math.MaxInt64}
	for _, side := range []struct {
		s   string
		dst *int64
	}{{t.From, &w.from}, {t.To, &w.to}} {
		if s := strings.TrimSpace(side.s); s != "" {
			at, err := time.Parse(time.RFC3339Nano, s)
			if err != nil {
				return rxWindow{}, false
			}
			*side.dst = at.UnixNano()
		}
	}
	return w, w.from < w.to
}

// match reports whether the message names one of the terms. It looks at each run of address
// characters of the text once, and only at those that can be one of the terms' forms (an IPv4
// address has three dots, an IPv6 address or a MAC address in colon notation two colons or more, a
// MAC address in dash notation five dashes).
func (m *syslogMatcher) match(msg *model.SyslogMessage) bool {
	text := matchText(msg)
	return len(m.v4) > 0 && m.findV4(text, msg.RX) ||
		(len(m.v6) > 0 || len(m.mac) > 0) && m.findColon(text) ||
		len(m.mac) > 0 && m.findDash(text)
}

// findV4 reports whether text names an IPv4 term at a time it counts (rxText: the message's receive
// time, parsed only when an address is found).
func (m *syslogMatcher) findV4(text, rxText string) bool {
	parsed, rxOK, rx := false, false, int64(0)
	for i := 0; i < len(text); {
		if !v4Chars[text[i]] {
			i++
			continue
		}
		j, dots := i, 0
		for ; j < len(text) && v4Chars[text[j]]; j++ {
			if text[j] == '.' {
				dots++
			}
		}
		run := text[i:j]
		i = j
		if dots < 3 || len(run) < len("0.0.0.0") {
			continue
		}
		wins, ok := m.v4[strings.Trim(run, ".")]
		if !ok {
			continue
		}
		if !parsed {
			parsed = true
			if at, err := time.Parse(time.RFC3339Nano, rxText); err == nil {
				rx, rxOK = at.UnixNano(), true
			}
		}
		for _, w := range wins {
			if w.from == math.MinInt64 && w.to == math.MaxInt64 || rxOK && w.from <= rx && rx < w.to {
				return true
			}
		}
	}
	return false
}

// findColon reports whether text names an IPv6 term, or a MAC term in colon notation - also in the
// firewall's MAC field.
func (m *syslogMatcher) findColon(text string) bool {
	var buf [maxTermRun]byte
	for i := 0; i < len(text); {
		if !v6Chars[text[i]] {
			i++
			continue
		}
		j, colons := i, 0
		for ; j < len(text) && v6Chars[text[j]]; j++ {
			if text[j] == ':' {
				colons++
			}
		}
		start, run := i, text[i:j]
		i = j
		if colons < 2 {
			continue
		}
		if len(m.mac) > 0 && start >= 4 && strings.EqualFold(text[start-4:start], "MAC=") && m.macField(run) {
			return true
		}
		if run = trimRun(run); len(run) > maxTermRun {
			continue
		}
		if key := lowerInto(buf[:0], run); m.v6[string(key)] || m.mac[string(key)] {
			return true
		}
	}
	return false
}

// findDash reports whether text names a MAC term in dash notation.
func (m *syslogMatcher) findDash(text string) bool {
	var buf [maxTermRun]byte
	for i := 0; i < len(text); {
		if !dashChars[text[i]] {
			i++
			continue
		}
		j, dashes := i, 0
		for ; j < len(text) && dashChars[text[j]]; j++ {
			if text[j] == '-' {
				dashes++
			}
		}
		run := text[i:j]
		i = j
		if dashes < 5 {
			continue
		}
		if run = strings.Trim(run, "-"); len(run) <= maxTermRun && m.mac[string(lowerInto(buf[:0], run))] {
			return true
		}
	}
	return false
}

// macField reports whether the firewall's MAC field (run: what follows "MAC=", as far as it is
// made of address characters) names one of the MAC terms as its destination (its first six
// octets) or its source (the next six).
func (m *syslogMatcher) macField(run string) bool {
	groups := strings.Split(strings.TrimRight(run, ":."), ":")
	var buf [17]byte
	for _, part := range [][2]int{{0, 6}, {6, 12}} {
		if len(groups) < part[1] {
			break
		}
		key := buf[:0]
		ok := true
		for i, g := range groups[part[0]:part[1]] {
			if len(g) != 2 || !isHex(g[0]) || !isHex(g[1]) {
				ok = false
				break
			}
			if i > 0 {
				key = append(key, ':')
			}
			key = append(key, lower(g[0]), lower(g[1]))
		}
		if ok && m.mac[string(key)] {
			return true
		}
	}
	return false
}

// matchText is the text a message's terms are looked for in: the exact datagram (Raw, else the
// bytes RawB64 holds), else the parsed message.
func matchText(msg *model.SyslogMessage) string {
	switch {
	case msg.Raw != "":
		return msg.Raw
	case msg.RawB64 != "":
		if b, err := base64.StdEncoding.DecodeString(msg.RawB64); err == nil {
			return string(b)
		}
	}
	return msg.Msg
}

// trimRun trims what ends a run of IPv6 or MAC address characters without being part of the
// address: dots (a sentence's end), and a single colon at either end ("::" is part of an IPv6
// address).
func trimRun(run string) string {
	run = strings.Trim(run, ".")
	if strings.HasSuffix(run, ":") && !strings.HasSuffix(run, "::") {
		run = run[:len(run)-1]
	}
	if strings.HasPrefix(run, ":") && !strings.HasPrefix(run, "::") {
		run = run[1:]
	}
	return run
}

// lowerInto appends s to buf in lower case (ASCII).
func lowerInto(buf []byte, s string) []byte {
	for i := 0; i < len(s); i++ {
		buf = append(buf, lower(s[i]))
	}
	return buf
}

func lower(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + 'a' - 'A'
	}
	return c
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func isHex(c byte) bool { return isDigit(c) || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F' }

// v4Chars, v6Chars and dashChars are the characters of an IPv4 address; of an IPv6 address (and of
// a MAC address in colon notation); of a MAC address in dash notation.
var v4Chars, v6Chars, dashChars = func() (v4, v6, dash [256]bool) {
	for c := range 256 {
		b := byte(c)
		v4[c] = isDigit(b) || b == '.'
		v6[c] = isHex(b) || b == ':' || b == '.'
		dash[c] = isHex(b) || b == '-'
	}
	return
}()
