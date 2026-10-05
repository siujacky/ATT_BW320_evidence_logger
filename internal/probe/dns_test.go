package probe

import (
	"bytes"
	"context"
	"encoding/base64"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// fakeDNS is an in-process UDP DNS server whose handler returns the datagrams to send
// back, in order, for each query.
type fakeDNS struct {
	pc      net.PacketConn
	mu      sync.Mutex
	queries []dnsmessage.Message
}

func startFakeDNS(t *testing.T, handler func(q dnsmessage.Message) [][]byte) *fakeDNS {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeDNS{pc: pc}
	go func() {
		buf := make([]byte, 4096)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			var q dnsmessage.Message
			if err := q.Unpack(buf[:n]); err != nil {
				continue
			}
			f.mu.Lock()
			f.queries = append(f.queries, q)
			f.mu.Unlock()
			for _, pkt := range handler(q) {
				_, _ = pc.WriteTo(pkt, from)
			}
		}
	}()
	t.Cleanup(func() { pc.Close() })
	return f
}

func (f *fakeDNS) addr() string { return f.pc.LocalAddr().String() }

func (f *fakeDNS) received() []dnsmessage.Message {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]dnsmessage.Message(nil), f.queries...)
}

// dnsReply packs a response to q; mutate may alter the message before packing.
func dnsReply(t *testing.T, q dnsmessage.Message, rcode dnsmessage.RCode, mutate func(*dnsmessage.Message), answers ...dnsmessage.Resource) []byte {
	m := dnsmessage.Message{
		Header: dnsmessage.Header{ID: q.Header.ID, Response: true, RecursionDesired: q.Header.RecursionDesired,
			RecursionAvailable: true, RCode: rcode},
		Questions: q.Questions,
		Answers:   answers,
	}
	if mutate != nil {
		mutate(&m)
	}
	b, err := m.Pack()
	if err != nil {
		t.Errorf("pack reply: %v", err)
	}
	return b
}

func rrHeader(name string, typ dnsmessage.Type) dnsmessage.ResourceHeader {
	return dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName(name), Type: typ, Class: dnsmessage.ClassINET, TTL: 60}
}

func rrA(name, ip string) dnsmessage.Resource {
	return dnsmessage.Resource{Header: rrHeader(name, dnsmessage.TypeA),
		Body: &dnsmessage.AResource{A: netip.MustParseAddr(ip).As4()}}
}

func rrCNAME(name, target string) dnsmessage.Resource {
	return dnsmessage.Resource{Header: rrHeader(name, dnsmessage.TypeCNAME),
		Body: &dnsmessage.CNAMEResource{CNAME: dnsmessage.MustNewName(target)}}
}

func rrAAAA(name, ip string) dnsmessage.Resource {
	return dnsmessage.Resource{Header: rrHeader(name, dnsmessage.TypeAAAA),
		Body: &dnsmessage.AAAAResource{AAAA: netip.MustParseAddr(ip).As16()}}
}

func rrTXT(name, txt string) dnsmessage.Resource {
	return dnsmessage.Resource{Header: rrHeader(name, dnsmessage.TypeTXT),
		Body: &dnsmessage.TXTResource{TXT: []string{txt}}}
}

func TestDNS(t *testing.T) {
	const name = "www.google.com"
	const fqdn = name + "."
	tests := []struct {
		name        string
		qname       string // default name
		handler     func(t *testing.T, q dnsmessage.Message) [][]byte
		timeout     time.Duration
		wantOK      bool
		wantRCode   string
		wantAnswers []string
		wantHijack  bool
		whyIn       string
		errIn       string
		rawIndex    int // which handler datagram must be RawB64 (-1: none)
	}{
		{
			name: "normal answer",
			handler: func(t *testing.T, q dnsmessage.Message) [][]byte {
				return [][]byte{dnsReply(t, q, dnsmessage.RCodeSuccess, nil, rrA(fqdn, "203.0.113.10"))}
			},
			wantOK: true, wantRCode: "NOERROR", wantAnswers: []string{"203.0.113.10"},
		},
		{
			name: "cname chain",
			handler: func(t *testing.T, q dnsmessage.Message) [][]byte {
				return [][]byte{dnsReply(t, q, dnsmessage.RCodeSuccess, nil,
					rrCNAME(fqdn, "forcesafesearch.google.com."), rrA("forcesafesearch.google.com.", "216.239.38.120"))}
			},
			wantOK: true, wantRCode: "NOERROR",
			wantAnswers: []string{"CNAME:forcesafesearch.google.com", "216.239.38.120"},
		},
		{
			name: "hijacked to the gateway",
			handler: func(t *testing.T, q dnsmessage.Message) [][]byte {
				return [][]byte{dnsReply(t, q, dnsmessage.RCodeSuccess, nil, rrA(fqdn, "192.168.1.254"))}
			},
			wantOK: true, wantRCode: "NOERROR", wantAnswers: []string{"192.168.1.254"},
			wantHijack: true, whyIn: "gateway's own address",
		},
		{
			name: "NXDOMAIN",
			handler: func(t *testing.T, q dnsmessage.Message) [][]byte {
				return [][]byte{dnsReply(t, q, dnsmessage.RCodeNameError, nil)}
			},
			wantOK: true, wantRCode: "NXDOMAIN",
		},
		{
			name: "SERVFAIL",
			handler: func(t *testing.T, q dnsmessage.Message) [][]byte {
				return [][]byte{dnsReply(t, q, dnsmessage.RCodeServerFailure, nil)}
			},
			wantOK: true, wantRCode: "SERVFAIL",
		},
		{
			name: "REFUSED without question section is accepted",
			handler: func(t *testing.T, q dnsmessage.Message) [][]byte {
				return [][]byte{dnsReply(t, q, dnsmessage.RCodeRefused, func(m *dnsmessage.Message) { m.Questions = nil })}
			},
			wantOK: true, wantRCode: "REFUSED",
		},
		{
			name: "decoy with wrong id then the real reply",
			handler: func(t *testing.T, q dnsmessage.Message) [][]byte {
				decoy := dnsReply(t, q, dnsmessage.RCodeSuccess, func(m *dnsmessage.Message) { m.Header.ID ^= 0x5a5a },
					rrA(fqdn, "192.168.1.254"))
				real := dnsReply(t, q, dnsmessage.RCodeSuccess, nil, rrA(fqdn, "203.0.113.10"))
				return [][]byte{decoy, real}
			},
			wantOK: true, wantRCode: "NOERROR", wantAnswers: []string{"203.0.113.10"}, rawIndex: 1,
		},
		{
			name: "decoy for another question then the real reply",
			handler: func(t *testing.T, q dnsmessage.Message) [][]byte {
				decoy := dnsReply(t, q, dnsmessage.RCodeSuccess, func(m *dnsmessage.Message) {
					m.Questions = []dnsmessage.Question{{Name: dnsmessage.MustNewName("evil.example."),
						Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}
				}, rrA("evil.example.", "10.0.0.1"))
				real := dnsReply(t, q, dnsmessage.RCodeSuccess, nil, rrA(fqdn, "203.0.113.10"))
				return [][]byte{decoy, real}
			},
			wantOK: true, wantRCode: "NOERROR", wantAnswers: []string{"203.0.113.10"}, rawIndex: 1,
		},
		{
			name: "decoy without the response flag then the real reply",
			handler: func(t *testing.T, q dnsmessage.Message) [][]byte {
				decoy := dnsReply(t, q, dnsmessage.RCodeSuccess, func(m *dnsmessage.Message) { m.Header.Response = false },
					rrA(fqdn, "10.0.0.1"))
				real := dnsReply(t, q, dnsmessage.RCodeSuccess, nil, rrA(fqdn, "203.0.113.10"))
				return [][]byte{decoy, real}
			},
			wantOK: true, wantRCode: "NOERROR", wantAnswers: []string{"203.0.113.10"}, rawIndex: 1,
		},
		{
			name: "garbage then the real reply",
			handler: func(t *testing.T, q dnsmessage.Message) [][]byte {
				return [][]byte{{0x01, 0x02, 0x03}, dnsReply(t, q, dnsmessage.RCodeSuccess, nil, rrA(fqdn, "203.0.113.10"))}
			},
			wantOK: true, wantRCode: "NOERROR", wantAnswers: []string{"203.0.113.10"}, rawIndex: 1,
		},
		{
			name: "AAAA and unknown types are rendered",
			handler: func(t *testing.T, q dnsmessage.Message) [][]byte {
				return [][]byte{dnsReply(t, q, dnsmessage.RCodeSuccess, nil,
					rrAAAA(fqdn, "2001:db8::1"), rrTXT(fqdn, "hello"), rrA(fqdn, "203.0.113.10"))}
			},
			wantOK: true, wantRCode: "NOERROR", wantAnswers: []string{"AAAA:2001:db8::1", "TYPE16", "203.0.113.10"},
		},
		{
			name: "malformed answer section keeps the evidence",
			handler: func(t *testing.T, q dnsmessage.Message) [][]byte {
				b := dnsReply(t, q, dnsmessage.RCodeSuccess, nil, rrA(fqdn, "203.0.113.10"))
				return [][]byte{b[:len(b)-2]}
			},
			wantOK: false, wantRCode: "NOERROR", errIn: "malformed answer section",
		},
		{
			name:  "reserved .invalid name answered",
			qname: "x7f3k2.invalid",
			handler: func(t *testing.T, q dnsmessage.Message) [][]byte {
				return [][]byte{dnsReply(t, q, dnsmessage.RCodeSuccess, nil, rrA("x7f3k2.invalid.", "203.0.113.99"))}
			},
			wantOK: true, wantRCode: "NOERROR", wantAnswers: []string{"203.0.113.99"},
			wantHijack: true, whyIn: "must not resolve",
		},
		{
			name: "no reply times out",
			handler: func(t *testing.T, q dnsmessage.Message) [][]byte {
				return nil
			},
			timeout: 200 * time.Millisecond,
			wantOK:  false, errIn: "timeout: no response within 200ms", rawIndex: -1,
		},
		{
			name: "only decoys time out and are counted",
			handler: func(t *testing.T, q dnsmessage.Message) [][]byte {
				d1 := dnsReply(t, q, dnsmessage.RCodeSuccess, func(m *dnsmessage.Message) { m.Header.ID++ })
				return [][]byte{d1, {0xff}}
			},
			timeout: 200 * time.Millisecond,
			wantOK:  false, errIn: "2 unrelated datagram(s) ignored", rawIndex: -1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			qname := tt.qname
			if qname == "" {
				qname = name
			}
			var mu sync.Mutex
			var sent [][]byte
			srv := startFakeDNS(t, func(q dnsmessage.Message) [][]byte {
				pkts := tt.handler(t, q)
				mu.Lock()
				sent = pkts
				mu.Unlock()
				return pkts
			})
			timeout := tt.timeout
			if timeout == 0 {
				timeout = 2 * time.Second
			}
			start := time.Now()
			r := New(Options{}).DNS(context.Background(), srv.addr(), qname, timeout)
			el := time.Since(start)

			if r.Server != srv.addr() || r.Name != qname || r.QType != "A" || r.ServerRole != "" {
				t.Errorf("identity fields: %+v", r)
			}
			if r.OK != tt.wantOK || r.RCode != tt.wantRCode {
				t.Errorf("OK/RCode = %v/%q, want %v/%q (err %q)", r.OK, r.RCode, tt.wantOK, tt.wantRCode, r.Err)
			}
			if strings.Join(r.Answers, ",") != strings.Join(tt.wantAnswers, ",") {
				t.Errorf("Answers = %q, want %q", r.Answers, tt.wantAnswers)
			}
			if r.Hijacked != tt.wantHijack || !strings.Contains(r.HijackWhy, tt.whyIn) {
				t.Errorf("Hijacked/why = %v/%q, want %v/%q", r.Hijacked, r.HijackWhy, tt.wantHijack, tt.whyIn)
			}
			if tt.errIn == "" && r.Err != "" || !strings.Contains(r.Err, tt.errIn) {
				t.Errorf("Err = %q, want containing %q", r.Err, tt.errIn)
			}
			if tt.rawIndex < 0 {
				if r.RawB64 != "" || r.RTTus != 0 {
					t.Errorf("no response but RawB64/RTT set: %+v", r)
				}
				if el > timeout+500*time.Millisecond {
					t.Errorf("took %v", el)
				}
			} else {
				raw, err := base64.StdEncoding.DecodeString(r.RawB64)
				mu.Lock()
				want := sent[tt.rawIndex]
				mu.Unlock()
				if err != nil || !bytes.Equal(raw, want) {
					t.Errorf("RawB64 is not the accepted datagram")
				}
				if r.RTTus <= 0 {
					t.Errorf("RTTus = %d", r.RTTus)
				}
			}

			qs := srv.received()
			if len(qs) != 1 {
				t.Fatalf("server saw %d queries", len(qs))
			}
			q := qs[0]
			if !q.Header.RecursionDesired || q.Header.Response || len(q.Questions) != 1 {
				t.Errorf("query header %+v questions %d", q.Header, len(q.Questions))
			}
			if got := q.Questions[0]; got.Name.String() != qname+"." || got.Type != dnsmessage.TypeA || got.Class != dnsmessage.ClassINET {
				t.Errorf("question %+v", got)
			}
		})
	}
}

func TestDNSRandomIDs(t *testing.T) {
	srv := startFakeDNS(t, func(q dnsmessage.Message) [][]byte {
		return [][]byte{dnsReply(t, q, dnsmessage.RCodeSuccess, nil, rrA("www.google.com.", "203.0.113.10"))}
	})
	p := New(Options{})
	for i := 0; i < 4; i++ {
		if r := p.DNS(context.Background(), srv.addr(), "www.google.com", time.Second); !r.OK {
			t.Fatalf("query %d: %+v", i, r)
		}
	}
	ids := map[uint16]bool{}
	for _, q := range srv.received() {
		ids[q.Header.ID] = true
	}
	if len(ids) < 2 { // P(all four equal) = 2^-48
		t.Fatalf("query IDs are not random: %v", ids)
	}
}

func TestDNSGatewayOption(t *testing.T) {
	// A public gateway address (hypothetical) is still recognised by exact match.
	srv := startFakeDNS(t, func(q dnsmessage.Message) [][]byte {
		return [][]byte{dnsReply(t, q, dnsmessage.RCodeSuccess, nil, rrA("www.google.com.", "203.0.113.254"))}
	})
	r := New(Options{GatewayIP: "203.0.113.254"}).DNS(context.Background(), srv.addr(), "www.google.com", time.Second)
	if !r.Hijacked || !strings.Contains(r.HijackWhy, "gateway's own address") {
		t.Fatalf("got %+v", r)
	}
	r = New(Options{}).DNS(context.Background(), srv.addr(), "www.google.com", time.Second)
	if r.Hijacked {
		t.Fatalf("public answer flagged with default gateway: %+v", r)
	}
}

func TestDNSCancel(t *testing.T) {
	srv := startFakeDNS(t, func(dnsmessage.Message) [][]byte { return nil })
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(50*time.Millisecond, cancel)
	start := time.Now()
	r := New(Options{}).DNS(ctx, srv.addr(), "www.google.com", 5*time.Second)
	if el := time.Since(start); el > time.Second {
		t.Fatalf("returned after %v", el)
	}
	if r.OK || !strings.HasPrefix(r.Err, "canceled") {
		t.Fatalf("got %+v", r)
	}
	// Pre-canceled: nothing is sent.
	r = New(Options{}).DNS(ctx, srv.addr(), "www.google.com", time.Second)
	if r.OK || !strings.HasPrefix(r.Err, "canceled") {
		t.Fatalf("pre-canceled: %+v", r)
	}
}

func TestDNSInputErrors(t *testing.T) {
	p := New(Options{})
	tests := []struct{ server, name, errIn string }{
		{"", "www.google.com", "server"},
		{"1.1.1.1:53:53", "www.google.com", "server"},
		{"127.0.0.1:1", "", "empty query name"},
		{"127.0.0.1:1", strings.Repeat("a", 64) + ".com", "query name"},
		{"127.0.0.1:1", strings.Repeat("abcdefghi.", 30) + "com", "query name"},
	}
	for _, tt := range tests {
		r := p.DNS(context.Background(), tt.server, tt.name, 200*time.Millisecond)
		if r.OK || !strings.Contains(r.Err, tt.errIn) {
			t.Errorf("DNS(%q, %q) = %+v, want error containing %q", tt.server, tt.name, r, tt.errIn)
		}
	}
	// Default port 53 is applied to a bare address.
	r := p.DNS(context.Background(), "127.0.0.1", "www.google.com", 100*time.Millisecond)
	if r.Server != "127.0.0.1:53" {
		t.Errorf("Server = %q, want 127.0.0.1:53", r.Server)
	}
}

func TestParseDNSResponseTruncatedRecords(t *testing.T) {
	name := dnsmessage.MustNewName("www.google.com.")
	q := dnsmessage.Message{Header: dnsmessage.Header{ID: 77, RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}}
	for _, tc := range []struct {
		name string
		rr   dnsmessage.Resource // damaged by cutting its last two bytes
	}{
		{"A", rrA("www.google.com.", "203.0.113.10")},
		{"CNAME", rrCNAME("www.google.com.", "forcesafesearch.google.com.")},
		{"AAAA", rrAAAA("www.google.com.", "2001:db8::1")},
		{"TXT", rrTXT("www.google.com.", "hello world")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			full := dnsReply(t, q, dnsmessage.RCodeSuccess, nil, rrA("www.google.com.", "203.0.113.1"), tc.rr)
			hdr, answers, ansErr, why := parseDNSResponse(full[:len(full)-2], 77, name)
			if why != "" || ansErr == nil || hdr.ID != 77 {
				t.Fatalf("why %q ansErr %v", why, ansErr)
			}
			if len(answers) != 1 || answers[0] != "203.0.113.1" {
				t.Fatalf("answers before the damage must be kept: %q", answers)
			}
		})
	}
	// A truncated question section means the datagram is not ours to judge.
	full := dnsReply(t, q, dnsmessage.RCodeSuccess, nil)
	if _, _, _, why := parseDNSResponse(full[:14], 77, name); why == "" {
		t.Fatal("truncated question accepted")
	}
	// Two questions do not match a single-question query.
	two := dnsReply(t, q, dnsmessage.RCodeSuccess, func(m *dnsmessage.Message) {
		m.Questions = append(m.Questions, m.Questions[0])
	})
	if _, _, _, why := parseDNSResponse(two, 77, name); why == "" {
		t.Fatal("two-question response accepted")
	}
	// The question match is case-insensitive.
	upper := dnsReply(t, q, dnsmessage.RCodeSuccess, func(m *dnsmessage.Message) {
		m.Questions[0].Name = dnsmessage.MustNewName("WWW.Google.COM.")
	})
	if _, _, _, why := parseDNSResponse(upper, 77, name); why != "" {
		t.Fatalf("case-insensitive match rejected: %s", why)
	}
}

func TestRCodeName(t *testing.T) {
	for code, want := range map[dnsmessage.RCode]string{
		0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED",
		9: "NOTAUTH", 10: "NOTZONE", 11: "RCODE11", 15: "RCODE15",
	} {
		if got := rcodeName(code); got != want {
			t.Errorf("rcodeName(%d) = %q, want %q", code, got, want)
		}
	}
}
