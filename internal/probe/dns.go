package probe

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"attmonitor/internal/model"
)

// dnsReadBuf is large enough for any UDP datagram, so a large response is never cut short.
const dnsReadBuf = 64 << 10

// DNS sends one A query (random ID, RD set) for name to server ("ip", "ip:port" or a host
// name; default port 53) over a connected UDP socket and waits up to timeout for the
// matching response. Datagrams with the wrong ID, without the response flag or with a
// different question are ignored (they may be spoofed or late answers to other queries).
//
// OK means a well-formed response was received; RCode is its mnemonic ("NOERROR",
// "NXDOMAIN", "SERVFAIL", ...); Answers lists A records as dotted quads and CNAMEs as
// "CNAME:<target>"; RawB64 is the exact response datagram; RTTus spans the request write to
// the response read. Hijacked/HijackWhy come from DetectDNSHijack (the gateway address
// is Options.GatewayIP). ServerRole is left for the caller. Truncated reports the TC bit:
// the response is valid (OK) but its answer section may be incomplete, and there is no
// retry over TCP. Err is only set for real errors (on a response: a malformed answer
// section, which makes OK false; the answers read before the damage are kept).
func (p *Prober) DNS(ctx context.Context, server, name string, timeout time.Duration) model.DNSResult {
	res := model.DNSResult{Server: server, Name: name, QType: "A"}
	host, port, err := hostPort(server, "53")
	if err != nil {
		res.Err = "server: " + err.Error()
		return res
	}
	addr := net.JoinHostPort(host, port)
	res.Server = addr

	qname := strings.TrimSpace(name)
	if qname == "" || qname == "." {
		res.Err = "empty query name"
		return res
	}
	if !strings.HasSuffix(qname, ".") {
		qname += "."
	}
	dn, err := dnsmessage.NewName(qname)
	if err != nil {
		res.Err = "query name: " + err.Error()
		return res
	}
	id := randomDNSID()
	query := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: id, RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: dn, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}},
	}
	packed, err := query.Pack()
	if err != nil {
		res.Err = "query name: " + err.Error()
		return res
	}

	to := effectiveTimeout(ctx, timeout)
	if ctx.Err() != nil || to <= 0 {
		res.Err = StatusCanceled + ": " + ctxErr(ctx).Error()
		return res
	}
	qctx, cancel := context.WithTimeout(ctx, to)
	defer cancel()
	var d net.Dialer
	conn, err := d.DialContext(qctx, "udp", addr)
	if err != nil {
		res.Err = err.Error()
		return res
	}
	defer conn.Close()
	if dl, ok := qctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	// Unblock the read as soon as the caller cancels.
	stop := context.AfterFunc(qctx, func() { _ = conn.SetDeadline(time.Unix(1, 0)) })
	defer stop()

	sw := startStopwatch()
	if _, err := conn.Write(packed); err != nil {
		res.Err = err.Error()
		return res
	}
	buf := make([]byte, dnsReadBuf)
	ignored := 0
	for {
		n, err := conn.Read(buf)
		rtt := sw.elapsed()
		if err != nil {
			res.Err = dnsReadError(ctx, to, err, ignored)
			return res
		}
		msg := buf[:n]
		hdr, answers, ansErr, why := parseDNSResponse(msg, id, dn)
		if why != "" {
			ignored++
			p.log.Debug("dns: ignored datagram", "server", addr, "reason", why, "bytes", n)
			continue
		}
		res.RTTus = micros(rtt)
		res.RawB64 = base64.StdEncoding.EncodeToString(msg)
		res.RCode = rcodeName(hdr.RCode)
		res.Answers = answers
		res.OK = ansErr == nil
		res.Truncated = hdr.Truncated // a valid response; this probe does not retry over TCP
		if ansErr != nil {
			res.Err = "malformed answer section: " + ansErr.Error()
		}
		res.Hijacked, res.HijackWhy = DetectDNSHijack(name, answers, p.gatewayIP)
		return res
	}
}

// dnsReadError explains why no acceptable response arrived.
func dnsReadError(ctx context.Context, timeout time.Duration, err error, ignored int) string {
	var msg string
	var ne net.Error
	switch {
	case errors.Is(ctx.Err(), context.Canceled):
		msg = StatusCanceled + ": " + ctx.Err().Error()
	case errors.As(err, &ne) && ne.Timeout():
		msg = fmt.Sprintf("%s: no response within %v", StatusTimeout, timeout.Round(time.Millisecond))
	default:
		msg = err.Error()
	}
	if ignored > 0 {
		msg += fmt.Sprintf(" (%d unrelated datagram(s) ignored)", ignored)
	}
	return msg
}

// parseDNSResponse checks that msg answers query id for name. A non-empty why means the
// datagram is not the response and must be ignored. Otherwise the header and the answer
// section are returned; ansErr reports a malformed answer section (answers parsed before
// the error are kept).
func parseDNSResponse(msg []byte, id uint16, name dnsmessage.Name) (hdr dnsmessage.Header, answers []string, ansErr error, why string) {
	var p dnsmessage.Parser
	hdr, err := p.Start(msg)
	if err != nil {
		return hdr, nil, nil, "unparseable header: " + err.Error()
	}
	if hdr.ID != id {
		return hdr, nil, nil, fmt.Sprintf("id %d, want %d", hdr.ID, id)
	}
	if !hdr.Response {
		return hdr, nil, nil, "not a response"
	}
	qs, err := p.AllQuestions()
	if err != nil {
		return hdr, nil, nil, "malformed question section: " + err.Error()
	}
	// The question is normally echoed; some servers omit it in error responses.
	if len(qs) > 1 || len(qs) == 1 && (!strings.EqualFold(qs[0].Name.String(), name.String()) ||
		qs[0].Type != dnsmessage.TypeA || qs[0].Class != dnsmessage.ClassINET) {
		return hdr, nil, nil, "question does not match the query"
	}
	answers, ansErr = readAnswers(&p)
	return hdr, answers, ansErr, ""
}

// readAnswers renders the answer section: A as dotted quad, CNAME as "CNAME:<target>",
// AAAA as "AAAA:<addr>", anything else as "TYPE<n>" (RFC 3597 notation).
func readAnswers(p *dnsmessage.Parser) ([]string, error) {
	var out []string
	for {
		h, err := p.AnswerHeader()
		if errors.Is(err, dnsmessage.ErrSectionDone) {
			return out, nil
		}
		if err != nil {
			return out, err
		}
		switch h.Type {
		case dnsmessage.TypeA:
			r, err := p.AResource()
			if err != nil {
				return out, err
			}
			out = append(out, netip.AddrFrom4(r.A).String())
		case dnsmessage.TypeCNAME:
			r, err := p.CNAMEResource()
			if err != nil {
				return out, err
			}
			out = append(out, "CNAME:"+strings.TrimSuffix(r.CNAME.String(), "."))
		case dnsmessage.TypeAAAA:
			r, err := p.AAAAResource()
			if err != nil {
				return out, err
			}
			out = append(out, "AAAA:"+netip.AddrFrom16(r.AAAA).String())
		default:
			if err := p.SkipAnswer(); err != nil {
				return out, err
			}
			out = append(out, "TYPE"+strconv.Itoa(int(h.Type)))
		}
	}
}

// rcodeName returns the IANA mnemonic of a DNS RCODE.
func rcodeName(r dnsmessage.RCode) string {
	names := [...]string{"NOERROR", "FORMERR", "SERVFAIL", "NXDOMAIN", "NOTIMP", "REFUSED",
		"YXDOMAIN", "YXRRSET", "NXRRSET", "NOTAUTH", "NOTZONE"}
	if int(r) < len(names) {
		return names[r]
	}
	return "RCODE" + strconv.Itoa(int(r))
}

// randomDNSID returns an unpredictable 16-bit query ID (crypto/rand never fails).
func randomDNSID() uint16 {
	var b [2]byte
	_, _ = rand.Read(b[:])
	return binary.BigEndian.Uint16(b[:])
}

// DetectDNSHijack decides whether DNS answers for name show the resolver path being
// hijacked, and returns a short reason:
//
//   - for a name under the reserved ".invalid" TLD (RFC 6761: must not resolve), any
//     answer at all is a hijack;
//   - for a public name, an A (or AAAA) answer equal to gatewayIP or in a non-public range
//     (private RFC 1918, loopback, link-local, CGNAT 100.64/10, unspecified 0.0.0.0/8), or
//     a CNAME into a local domain (e.g. *.attlocal.net), is a hijack.
//
// Local names (single-label, .local, .lan, .home.arpa, .attlocal.net, ...) legitimately
// resolve to private addresses and are never reported. answers use the format of
// model.DNSResult.Answers; gatewayIP may be empty.
func DetectDNSHijack(name string, answers []string, gatewayIP string) (bool, string) {
	n := normalizeName(name)
	if n == "" || len(answers) == 0 {
		return false, ""
	}
	if n == "invalid" || strings.HasSuffix(n, ".invalid") {
		list, more := listForReason(answers)
		return true, boundedReason(fmt.Sprintf("reserved name %s must not resolve (RFC 6761) but got: %s",
			clipText(n, maxReasonItem/2), list), more)
	}
	if _, err := netip.ParseAddr(n); err == nil || isLocalName(n) {
		return false, ""
	}
	var first string
	count := 0
	for _, ans := range answers {
		why := answerHijackReason(n, ans, gatewayIP)
		if why == "" {
			continue
		}
		if count == 0 {
			first = why
		}
		count++
	}
	if count == 0 {
		return false, ""
	}
	more := ""
	if count > 1 {
		more = fmt.Sprintf(" (+%d more)", count-1)
	}
	return true, boundedReason(first, more)
}

// answerHijackReason explains why one answer for the public name n is suspicious ("" if not).
func answerHijackReason(n, answer, gatewayIP string) string {
	v := strings.TrimSpace(answer)
	if target, ok := strings.CutPrefix(v, "CNAME:"); ok {
		if isLocalName(target) {
			return fmt.Sprintf("%s is an alias (CNAME) of the local name %s",
				clipText(n, maxReasonItem/2), clipText(normalizeName(target), maxReasonItem))
		}
		return ""
	}
	v, _ = strings.CutPrefix(v, "AAAA:")
	a, err := netip.ParseAddr(v)
	if err != nil {
		return ""
	}
	if why := suspiciousAddr(a, gatewayIP); why != "" {
		return fmt.Sprintf("%s resolved to %s, %s", clipText(n, maxReasonItem/2), a.Unmap(), why)
	}
	return ""
}
