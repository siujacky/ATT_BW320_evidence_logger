package monitor

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"attmonitor/internal/config"
	"attmonitor/internal/model"
)

const gwIP = "192.168.1.254"

func gwICMP(ok bool, rttUs int64) model.ProbeResult {
	r := model.ProbeResult{Name: "gateway_icmp", Kind: model.KindICMP, Role: model.RoleGateway, Target: gwIP, OK: ok}
	if ok {
		r.RTTus, r.Status = rttUs, "IP_SUCCESS"
	} else {
		r.Status = "IP_REQ_TIMED_OUT"
	}
	return r
}

func gwTCP(ok bool, rttUs int64) model.ProbeResult {
	r := model.ProbeResult{Name: "gateway_tcp", Kind: model.KindTCP, Role: model.RoleGateway, Target: gwIP + ":443", OK: ok}
	if ok {
		r.RTTus, r.Status = rttUs, "connected"
	} else {
		r.Status = "timeout"
	}
	return r
}

func hopICMP(ok bool, rttUs int64) model.ProbeResult {
	r := model.ProbeResult{Name: "isp_hop_icmp", Kind: model.KindICMP, Role: model.RoleISPHop, Target: "203.0.113.1", OK: ok}
	if ok {
		r.RTTus, r.Status = rttUs, "IP_SUCCESS"
	} else {
		r.Status = "IP_REQ_TIMED_OUT"
	}
	return r
}

func inetProbe(name, kind, target string, ok bool, rttUs int64) model.ProbeResult {
	r := model.ProbeResult{Name: name, Kind: kind, Role: model.RoleInet, Target: target, OK: ok}
	if ok {
		r.RTTus, r.Status = rttUs, "IP_SUCCESS"
	} else {
		r.Status = "IP_REQ_TIMED_OUT"
	}
	return r
}

// inet returns the five default internet probes.
func inet(okICMP, okTCP bool, rttUs int64) []model.ProbeResult {
	return []model.ProbeResult{
		inetProbe("inet_icmp_cloudflare", model.KindICMP, "1.1.1.1", okICMP, rttUs),
		inetProbe("inet_icmp_google", model.KindICMP, "8.8.8.8", okICMP, rttUs),
		inetProbe("inet_icmp_quad9", model.KindICMP, "9.9.9.9", okICMP, rttUs),
		inetProbe("inet_tcp_cloudflare", model.KindTCP, "1.1.1.1:443", okTCP, rttUs),
		inetProbe("inet_tcp_google", model.KindTCP, "8.8.8.8:443", okTCP, rttUs),
	}
}

// inetN returns the five internet probes with the first `fail` of them failing.
func inetN(fail int, rttUs int64) []model.ProbeResult {
	ps := inet(true, true, rttUs)
	for i := 0; i < fail && i < len(ps); i++ {
		ps[i].OK, ps[i].RTTus, ps[i].Status = false, 0, "IP_REQ_TIMED_OUT"
	}
	return ps
}

func cyc(parts ...any) []model.ProbeResult {
	var out []model.ProbeResult
	for _, p := range parts {
		switch v := p.(type) {
		case model.ProbeResult:
			out = append(out, v)
		case []model.ProbeResult:
			out = append(out, v...)
		default:
			panic("cyc: bad part")
		}
	}
	return out
}

// gwRefused: the gateway's TCP port refused the connection (an RST: its IP stack answered).
func gwRefused() model.ProbeResult {
	return model.ProbeResult{Name: "gateway_tcp", Kind: model.KindTCP, Role: model.RoleGateway, Target: gwIP + ":443", Status: "refused", Err: "connectex: No connection could be made because the target machine actively refused it."}
}

// lossyAB: a cycle where the internet probes of 1.1.1.1 and 8.8.8.8 at offset (0: ICMP,
// 3: TCP) failed.
func lossyAB(offset int) []model.ProbeResult {
	ps := inet(true, true, 9000)
	for _, i := range []int{offset, offset + 1} {
		ps[i].OK, ps[i].RTTus, ps[i].Status = false, 0, "IP_REQ_TIMED_OUT"
	}
	return cyc(gwICMP(true, 1900), ps)
}

func outageCycle() []model.ProbeResult {
	return cyc(gwICMP(true, 1900), gwTCP(true, 2300), inet(false, false, 0))
}

func lanDownCycle() []model.ProbeResult {
	return cyc(gwICMP(false, 0), gwTCP(false, 0), inet(false, false, 0))
}

func healthy() []model.ProbeResult {
	return cyc(gwICMP(true, 1900), gwTCP(true, 2300), hopICMP(true, 3000), inet(true, true, 12000))
}

func win(cycles ...[]model.ProbeResult) [][]model.ProbeResult { return cycles }

// repeat returns n copies of c followed by last.
func repeat(n int, c, last []model.ProbeResult) [][]model.ProbeResult {
	var w [][]model.ProbeResult
	for i := 0; i < n; i++ {
		w = append(w, c)
	}
	return append(w, last)
}

func snapWith(mut func(*model.GatewaySnapshot)) *model.GatewaySnapshot {
	s := okSnapshot(nil, time.Date(2026, 10, 5, 3, 20, 0, 0, time.UTC))
	if mut != nil {
		mut(&s)
	}
	return &s
}

func svc(rs ...model.DNSResult) *model.ServiceCheck { return &model.ServiceCheck{DNS: rs} }

// twice gives the input a previous service check (#41, a minute earlier) with the same results:
// a DNS failure that persists over two consecutive checks.
func twice(in ClassifyInput) ClassifyInput {
	in.PrevService, in.PrevServiceGap, in.PrevServiceSeq = in.Service, time.Minute, 41
	return in
}

func dnsOK(role, server string) model.DNSResult {
	return model.DNSResult{Server: server + ":53", ServerRole: role, Name: "www.google.com", QType: "A", OK: true, RCode: "NOERROR", Answers: []string{"142.250.72.36"}}
}

func TestClassify(t *testing.T) {
	cfg := config.Default().Incident
	wifiDown := &model.LocalLink{Interface: "Wi-Fi", Type: "wifi", State: "disconnected"}
	lanDown := cyc(gwICMP(false, 0), gwTCP(false, 0), inet(false, false, 0))
	outage := func(hopOK *bool) []model.ProbeResult {
		c := cyc(gwICMP(true, 1900), gwTCP(true, 2300), inet(false, false, 0))
		if hopOK != nil {
			c = append(c, hopICMP(*hopOK, 3000))
		}
		return c
	}
	bbDown := snapWith(func(s *model.GatewaySnapshot) {
		s.Broadband.Connection = "Down"
		s.Derived.BroadbandUp = boolp(false)
	})

	tests := []struct {
		name               string
		in                 ClassifyInput
		cfg                *config.IncidentConfig
		state, cause, attr string
		reasons            []string // substrings that must appear in some reason
	}{
		{name: "all healthy", in: ClassifyInput{Cycle: healthy(), Window: win(healthy())},
			state: model.StateOnline, attr: model.AttrNone,
			reasons: []string{"5/5 internet probes succeeded", "gateway 192.168.1.254 answered ICMP in 1.9 ms", "median internet RTT over the last 1 non-outage cycles is 12.0 ms"}},
		{name: "empty cycle", in: ClassifyInput{},
			state: model.StateUnknown, attr: model.AttrUndetermined, reasons: []string{"no probe results"}},
		{name: "no gateway probes", in: ClassifyInput{Cycle: inet(true, true, 1000)},
			state: model.StateUnknown, attr: model.AttrUndetermined, reasons: []string{"no gateway probe ran"}},
		{name: "no internet probes", in: ClassifyInput{Cycle: cyc(gwICMP(true, 1000))},
			state: model.StateUnknown, attr: model.AttrUndetermined, reasons: []string{"no internet probe ran"}},
		{name: "gateway unreachable", in: ClassifyInput{Cycle: lanDown},
			state: model.StateLocalFault, cause: model.CauseGatewayUnreachable, attr: model.AttrUndetermined,
			reasons: []string{"gateway 192.168.1.254 did not answer ICMP (IP_REQ_TIMED_OUT)", "gateway 192.168.1.254:443 did not accept a TCP connection (timeout)", "0/5 internet probes succeeded", "cannot be attributed"}},
		{name: "local link down (wifi disconnected)", in: ClassifyInput{Cycle: lanDown, Link: wifiDown},
			state: model.StateLocalFault, cause: model.CauseLocalLinkDown, attr: model.AttrLocal,
			reasons: []string{`Wi-Fi adapter "Wi-Fi" reports state: disconnected`, "local side"}},
		{name: "wifi authenticating counts as down", in: ClassifyInput{Cycle: lanDown, Link: &model.LocalLink{Interface: "Wi-Fi", Type: "wifi", State: "authenticating"}},
			state: model.StateLocalFault, cause: model.CauseLocalLinkDown, attr: model.AttrLocal},
		{name: "wifi connected: gateway itself unreachable", in: ClassifyInput{Cycle: lanDown, Link: &model.LocalLink{Interface: "Wi-Fi", Type: "wifi", State: "connected", SSID: "home", SignalPct: 80}},
			state: model.StateLocalFault, cause: model.CauseGatewayUnreachable, attr: model.AttrUndetermined,
			reasons: []string{`(SSID "home", signal 80%)`}},
		{name: "ethernet disconnected is not the wifi rule", in: ClassifyInput{Cycle: lanDown, Link: &model.LocalLink{Interface: "Ethernet", Type: "ethernet", State: "disconnected"}},
			state: model.StateLocalFault, cause: model.CauseGatewayUnreachable, attr: model.AttrUndetermined,
			reasons: []string{`ethernet adapter "Ethernet" reports state: disconnected`}},
		{name: "link unreadable", in: ClassifyInput{Cycle: lanDown, Link: &model.LocalLink{Type: "unknown", Err: "netsh failed"}},
			state: model.StateLocalFault, cause: model.CauseGatewayUnreachable, attr: model.AttrUndetermined,
			reasons: []string{"local link state could not be read: netsh failed"}},
		{name: "gateway silent but internet answers: rule 1 still applies", in: ClassifyInput{Cycle: cyc(gwICMP(false, 0), gwTCP(false, 0), inet(true, true, 9000))},
			state: model.StateLocalFault, cause: model.CauseGatewayUnreachable, attr: model.AttrUndetermined,
			reasons: []string{"5/5 internet probes succeeded"}},
		{name: "gateway ICMP blocked but TCP ok", in: ClassifyInput{Cycle: cyc(gwICMP(false, 0), gwTCP(true, 2300), inet(true, true, 12000))},
			state: model.StateOnline, attr: model.AttrNone,
			reasons: []string{"gateway 192.168.1.254:443 accepted a TCP connection in 2.3 ms"}},
		{name: "fiber: PON not O5", in: ClassifyInput{Cycle: outage(nil), Snapshot: snapWith(func(s *model.GatewaySnapshot) {
			s.Broadband.PONLinkStatus = "POPUP (O6)"
			s.Derived.PONOperational = boolp(false)
		}), SnapshotAge: 20 * time.Second},
			state: model.StateISPOutage, cause: model.CauseFiberLinkDown, attr: model.AttrProvider,
			reasons: []string{"AT&T gateway reports PON Link Status: POPUP (O6)", "0/5 internet probes succeeded", "gateway 192.168.1.254 answered ICMP in 1.9 ms"}},
		{name: "fiber: optical WAN status down", in: ClassifyInput{Cycle: outage(nil), Snapshot: snapWith(func(s *model.GatewaySnapshot) {
			s.Fiber.OpticalStatus = "Down"
			s.Derived.OpticalUp = boolp(false)
		}), SnapshotAge: time.Second},
			state: model.StateISPOutage, cause: model.CauseFiberLinkDown, attr: model.AttrProvider,
			reasons: []string{"AT&T gateway reports Optical WAN Operational Status: Down"}},
		{name: "fiber outranks WAN down", in: ClassifyInput{Cycle: outage(nil), Snapshot: snapWith(func(s *model.GatewaySnapshot) {
			s.Derived.OpticalUp = boolp(false)
			s.Derived.BroadbandUp = boolp(false)
		})},
			state: model.StateISPOutage, cause: model.CauseFiberLinkDown, attr: model.AttrProvider},
		{name: "WAN down: broadband connection Down", in: ClassifyInput{Cycle: outage(boolp(false)), Snapshot: bbDown, SnapshotAge: 30 * time.Second},
			state: model.StateISPOutage, cause: model.CauseWANDown, attr: model.AttrProvider,
			reasons: []string{"AT&T gateway reports Broadband Connection: Down"}},
		{name: "WAN down: no WAN IPv4", in: ClassifyInput{Cycle: outage(nil), Snapshot: snapWith(func(s *model.GatewaySnapshot) {
			s.Broadband.IPv4, s.Derived.WANIPv4 = "", ""
		})},
			state: model.StateISPOutage, cause: model.CauseWANDown, attr: model.AttrProvider,
			reasons: []string{"AT&T gateway reports no WAN IPv4 address"}},
		{name: "WAN IPv4 0.0.0.0 is no address", in: ClassifyInput{Cycle: outage(nil), Snapshot: snapWith(func(s *model.GatewaySnapshot) {
			s.Broadband.IPv4, s.Derived.WANIPv4 = "0.0.0.0", "0.0.0.0"
		})},
			state: model.StateISPOutage, cause: model.CauseWANDown, attr: model.AttrProvider},
		{name: "missing IPv4 row is not an absent address", in: ClassifyInput{Cycle: outage(boolp(true)), Snapshot: snapWith(func(s *model.GatewaySnapshot) {
			s.Broadband.IPv4, s.Derived.WANIPv4 = "", ""
			s.Broadband.Values = map[string]string{"Broadband/Broadband Connection": "Up"}
		})},
			state: model.StateISPOutage, cause: model.CauseUpstreamUnreachable, attr: model.AttrProvider},
		{name: "snapshot exactly at freshness limit is used", in: ClassifyInput{Cycle: outage(nil), Snapshot: bbDown, SnapshotAge: 150 * time.Second},
			state: model.StateISPOutage, cause: model.CauseWANDown, attr: model.AttrProvider},
		{name: "negative snapshot age (clock step) counts as fresh", in: ClassifyInput{Cycle: outage(nil), Snapshot: bbDown, SnapshotAge: -5 * time.Second},
			state: model.StateISPOutage, cause: model.CauseWANDown, attr: model.AttrProvider},
		{name: "stale snapshot is ignored; next hop failed", in: ClassifyInput{Cycle: outage(boolp(false)), Snapshot: bbDown, SnapshotAge: 400 * time.Second},
			state: model.StateISPOutage, cause: model.CauseISPEdgeUnreachable, attr: model.AttrProvider,
			reasons: []string{"is 400 s old (older than 150 s), so its status was not used", "AT&T next hop 203.0.113.1 did not answer ICMP (IP_REQ_TIMED_OUT)"}},
		{name: "stale snapshot, next hop answers", in: ClassifyInput{Cycle: outage(boolp(true)), Snapshot: bbDown, SnapshotAge: 151 * time.Second},
			state: model.StateISPOutage, cause: model.CauseUpstreamUnreachable, attr: model.AttrProvider,
			reasons: []string{"AT&T next hop 203.0.113.1 answered ICMP in 3.0 ms"}},
		{name: "no snapshot, unknown ISP hop", in: ClassifyInput{Cycle: outage(nil)},
			state: model.StateISPOutage, cause: model.CauseUpstreamUnreachable, attr: model.AttrProvider,
			reasons: []string{"no AT&T gateway status snapshot is available yet", "AT&T next hop is unknown"}},
		{name: "gateway up, next hop unreachable", in: ClassifyInput{Cycle: outage(boolp(false)), Snapshot: snapWith(nil), SnapshotAge: 10 * time.Second},
			state: model.StateISPOutage, cause: model.CauseISPEdgeUnreachable, attr: model.AttrProvider,
			reasons: []string{"AT&T gateway reports Broadband Connection: Up", "AT&T next hop 203.0.113.1 did not answer ICMP"}},
		{name: "next hop failure reply from another router", in: ClassifyInput{Cycle: cyc(gwICMP(true, 1900), inet(false, false, 0), model.ProbeResult{Name: "isp_hop_icmp", Kind: model.KindICMP, Role: model.RoleISPHop, Target: "203.0.113.1", Status: "IP_DEST_NET_UNREACHABLE", ReplyFrom: gwIP})},
			state: model.StateISPOutage, cause: model.CauseISPEdgeUnreachable, attr: model.AttrProvider,
			reasons: []string{"(IP_DEST_NET_UNREACHABLE from 192.168.1.254)"}},
		{name: "gateway and next hop up, upstream unreachable", in: ClassifyInput{Cycle: outage(boolp(true)), Snapshot: snapWith(nil), SnapshotAge: 10 * time.Second},
			state: model.StateISPOutage, cause: model.CauseUpstreamUnreachable, attr: model.AttrProvider},
		{name: "only TCP ok (ICMP to the internet blocked): 3/5 failed", in: ClassifyInput{Cycle: cyc(gwICMP(true, 1900), gwTCP(true, 2300), inet(false, true, 15000))},
			state: model.StateDegraded, cause: model.CausePacketLoss, attr: model.AttrProvider,
			reasons: []string{"3/5 internet probes failed this cycle", "gateway probes had no loss over the last 1 cycles (2/2 answered)",
				"internet probe loss by provider over the last 1 non-outage cycles: 1.1.1.1 1/2 (50.0%), 8.8.8.8 1/2 (50.0%), 9.9.9.9 1/1 (100.0%)",
				"3 of 3 providers lost at least 20% of their probes (1.1.1.1, 8.8.8.8, 9.9.9.9)"}},
		{name: "exactly 50% failed this cycle", in: ClassifyInput{Cycle: cyc(gwICMP(true, 1900), inetN(0, 9000)[:2], inetN(2, 9000)[:2])},
			state: model.StateDegraded, cause: model.CausePacketLoss, attr: model.AttrProvider,
			reasons: []string{"2/4 internet probes failed this cycle"}},
		{name: "40% this cycle but window loss low: online", in: ClassifyInput{Cycle: cyc(gwICMP(true, 1900), inetN(2, 9000)),
			Window: repeat(5, cyc(gwICMP(true, 1900), inetN(0, 9000)), cyc(gwICMP(true, 1900), inetN(2, 9000)))},
			state: model.StateOnline, attr: model.AttrNone, reasons: []string{"3/5 internet probes succeeded"}},
		{name: "two providers at exactly 20% window loss", in: ClassifyInput{Cycle: cyc(gwICMP(true, 1900), inetN(0, 9000)),
			Window: win(lossyAB(0), lossyAB(3), cyc(gwICMP(true, 1900), inetN(0, 9000)), cyc(gwICMP(true, 1900), inetN(0, 9000)), cyc(gwICMP(true, 1900), inetN(0, 9000)))},
			state: model.StateDegraded, cause: model.CausePacketLoss, attr: model.AttrProvider,
			reasons: []string{"0/5 internet probes failed this cycle", "internet probe loss by provider over the last 5 non-outage cycles: 1.1.1.1 2/10 (20.0%), 8.8.8.8 2/10 (20.0%), 9.9.9.9 0/5 (0.0%)",
				"2 of 3 providers lost at least 20% of their probes (1.1.1.1, 8.8.8.8)"}},
		{name: "one lossy provider never implicates the ISP", in: ClassifyInput{Cycle: cyc(gwICMP(true, 1900), inetN(1, 9000)),
			Window: repeat(5, cyc(gwICMP(true, 1900), inetN(1, 9000)), cyc(gwICMP(true, 1900), inetN(1, 9000)))},
			state: model.StateOnline, attr: model.AttrNone,
			reasons: []string{"4/5 internet probes succeeded", "only 1 of 3 providers lost at least 20% over the last 6 non-outage cycles (1.1.1.1): one unreachable destination does not implicate the ISP"}},
		{name: "a single configured provider: its loss is enough", in: ClassifyInput{Cycle: cyc(gwICMP(true, 1900), inetN(1, 9000)[0], inetN(1, 9000)[3])},
			state: model.StateDegraded, cause: model.CausePacketLoss, attr: model.AttrProvider,
			reasons: []string{"1 of 1 providers lost at least 20% of their probes (1.1.1.1)"}},
		{name: "outage cycles are excluded from the window loss", in: ClassifyInput{Cycle: healthy(),
			Window: win(lanDownCycle(), outageCycle(), outageCycle(), healthy(), healthy(), healthy())},
			state: model.StateOnline, attr: model.AttrNone,
			reasons: []string{"median internet RTT over the last 3 non-outage cycles (3 other cycles of the window excluded) is 12.0 ms"}},
		{name: "outage cycles are excluded from the latency median", in: ClassifyInput{Cycle: cyc(gwICMP(true, 2000), inet(true, true, 20000)),
			Window: win(cyc(gwICMP(false, 0), inet(true, true, 900000)), cyc(gwICMP(false, 0), inet(true, true, 900000)), cyc(gwICMP(true, 2000), inet(true, true, 20000)))},
			state: model.StateOnline, attr: model.AttrNone,
			reasons: []string{"median internet RTT over the last 1 non-outage cycles (2 other cycles of the window excluded) is 20.0 ms"}},
		{name: "refused gateway TCP proves LAN (rule 1 does not apply)", in: ClassifyInput{Cycle: cyc(gwICMP(false, 0), gwRefused(), inet(true, true, 12000))},
			state: model.StateOnline, attr: model.AttrNone,
			reasons: []string{"gateway 192.168.1.254:443 refused the TCP connection (it answered with a reset)"}},
		{name: "refused gateway TCP and no internet is an ISP outage", in: ClassifyInput{Cycle: cyc(gwICMP(false, 0), gwRefused(), inet(false, false, 0))},
			state: model.StateISPOutage, cause: model.CauseUpstreamUnreachable, attr: model.AttrProvider,
			reasons: []string{"gateway 192.168.1.254:443 refused the TCP connection (it answered with a reset)", "0/5 internet probes succeeded"}},
		{name: "refused gateway TCP counts as an answer for the attribution", in: ClassifyInput{Cycle: cyc(gwICMP(true, 1900), gwRefused(), inet(false, true, 9000))},
			state: model.StateDegraded, cause: model.CausePacketLoss, attr: model.AttrProvider,
			reasons: []string{"gateway probes had no loss over the last 1 cycles (2/2 answered)"}},
		{name: "a refused internet TCP probe is a failure", in: ClassifyInput{Cycle: cyc(gwICMP(true, 1900), inetProbe("inet_tcp_cloudflare", model.KindTCP, "1.1.1.1:443", false, 0), inetProbe("inet_icmp_cloudflare", model.KindICMP, "1.1.1.1", false, 0))},
			state: model.StateISPOutage, cause: model.CauseUpstreamUnreachable, attr: model.AttrProvider},
		{name: "IPv6 provider: ICMP and TCP to the same address are one provider", in: ClassifyInput{Cycle: cyc(gwICMP(true, 1900),
			inetProbe("v6_icmp", model.KindICMP, "2606:4700::1111", false, 0), inetProbe("v6_tcp", model.KindTCP, "[2606:4700::1111]:443", true, 9000),
			inetProbe("inet_icmp_google", model.KindICMP, "8.8.8.8", true, 9000))},
			state: model.StateOnline, attr: model.AttrNone,
			reasons: []string{"only 1 of 2 providers lost at least 20% over the last 1 non-outage cycles (2606:4700::1111)"}},
		{name: "window loss 16.7% stays online", in: ClassifyInput{Cycle: cyc(gwICMP(true, 1900), inetN(0, 9000)),
			Window: append(repeat(4, cyc(gwICMP(true, 1900), inetN(1, 9000)), cyc(gwICMP(true, 1900), inetN(1, 9000))), cyc(gwICMP(true, 1900), inetN(0, 9000)))},
			state: model.StateOnline, attr: model.AttrNone},
		{name: "packet loss with gateway loss in window: undetermined", in: ClassifyInput{Cycle: cyc(gwICMP(true, 1900), gwTCP(true, 2300), inet(false, true, 9000)),
			Window: win(cyc(gwICMP(false, 0), gwTCP(true, 2300), inet(true, true, 9000)), cyc(gwICMP(true, 1900), gwTCP(true, 2300), inet(false, true, 9000)))},
			state: model.StateDegraded, cause: model.CausePacketLoss, attr: model.AttrUndetermined,
			reasons: []string{"gateway probes lost 1/4 over the last 2 cycles"}},
		{name: "high latency with healthy gateway", in: ClassifyInput{Cycle: cyc(gwICMP(true, 2000), gwTCP(true, 2000), inet(true, true, 200000)),
			Window: repeat(5, cyc(gwICMP(true, 2000), gwTCP(true, 2000), inet(true, true, 200000)), cyc(gwICMP(true, 2000), gwTCP(true, 2000), inet(true, true, 200000)))},
			state: model.StateDegraded, cause: model.CauseHighLatency, attr: model.AttrProvider,
			reasons: []string{"median internet RTT over the last 6 non-outage cycles is 200.0 ms (threshold 150 ms)", "median gateway RTT over the same cycles is 2.0 ms"}},
		{name: "latency with unhealthy gateway (loss): undetermined", in: ClassifyInput{Cycle: cyc(gwICMP(true, 2000), gwTCP(true, 2000), inet(true, true, 200000)),
			Window: win(cyc(gwICMP(false, 0), gwTCP(true, 2000), inet(true, true, 200000)), cyc(gwICMP(true, 2000), gwTCP(true, 2000), inet(true, true, 200000)))},
			state: model.StateDegraded, cause: model.CauseHighLatency, attr: model.AttrUndetermined,
			reasons: []string{"gateway probes lost 1/4 over the last 2 cycles, so the degradation cannot be attributed to the provider"}},
		{name: "latency with slow gateway is not provider latency", in: ClassifyInput{Cycle: cyc(gwICMP(true, 35000), gwTCP(true, 35000), inet(true, true, 200000))},
			state: model.StateOnline, attr: model.AttrNone,
			reasons: []string{"median 35.0 ms (not below 20 ms), so the latency is not attributed to the provider"}},
		{name: "median exactly at latency threshold is not high", in: ClassifyInput{Cycle: cyc(gwICMP(true, 2000), inet(true, true, 150000))},
			state: model.StateOnline, attr: model.AttrNone},
		{name: "even count median uses both middle values", in: ClassifyInput{Cycle: cyc(gwICMP(true, 2000), inetProbe("a", model.KindICMP, "1.1.1.1", true, 100000), inetProbe("b", model.KindICMP, "8.8.8.8", true, 210000))},
			state: model.StateDegraded, cause: model.CauseHighLatency, attr: model.AttrProvider,
			reasons: []string{"is 155.0 ms"}},
		{name: "packet loss outranks high latency", in: ClassifyInput{Cycle: cyc(gwICMP(true, 2000), inet(false, true, 300000))},
			state: model.StateDegraded, cause: model.CausePacketLoss, attr: model.AttrProvider},
		{name: "ISP DNS failure while public answers", in: twice(ClassifyInput{Cycle: healthy(), Service: svc(
			dnsOK("gateway", gwIP),
			model.DNSResult{Server: "68.94.156.9:53", ServerRole: "isp", Name: "www.google.com", OK: true, RCode: "SERVFAIL"},
			dnsOK("public", "1.1.1.1"),
		), ServiceAge: 30 * time.Second}),
			state: model.StateDegraded, cause: model.CauseISPDNSFailure, attr: model.AttrProvider,
			reasons: []string{"ISP resolver 68.94.156.9 failed (SERVFAIL) while public resolver 1.1.1.1 answered, as in the previous service check #41 (ISP resolver 68.94.156.9 failed (SERVFAIL)"}},
		{name: "a failed query answered by its retry is no failure", in: twice(ClassifyInput{Cycle: healthy(), Service: svc(
			dnsOK("gateway", gwIP),
			model.DNSResult{Server: "68.94.156.9:53", ServerRole: "isp", Name: "www.google.com", Err: "timeout: no response within 2s"},
			model.DNSResult{Server: "68.94.156.9:53", ServerRole: "isp", Name: "www.google.com", OK: true, RCode: "NOERROR", Answers: []string{"142.250.72.36"}},
			dnsOK("public", "1.1.1.1"),
		)}),
			state: model.StateOnline, attr: model.AttrNone},
		{name: "ISP DNS failing now but not in the previous check", in: ClassifyInput{Cycle: healthy(), Service: svc(
			dnsOK("gateway", gwIP),
			model.DNSResult{Server: "68.94.156.9:53", ServerRole: "isp", Name: "www.google.com", Err: "timeout: no response within 2s"},
			model.DNSResult{Server: "68.94.156.9:53", ServerRole: "isp", Name: "www.google.com", Err: "timeout: no response within 2s"},
			dnsOK("public", "1.1.1.1"),
		), PrevService: svc(dnsOK("gateway", gwIP), dnsOK("isp", "68.94.156.9"), dnsOK("public", "1.1.1.1")), PrevServiceGap: time.Minute, PrevServiceSeq: 41},
			state: model.StateOnline, attr: model.AttrNone,
			reasons: []string{"ISP resolver 68.94.156.9 failed (timeout: no response within 2s; retried: timeout: no response within 2s) while public resolver 1.1.1.1 answered in this service check, but not in the previous one (#41): one failing check is not counted as a resolver failure"}},
		{name: "ISP DNS failing without a recent previous check", in: func() ClassifyInput {
			in := twice(ClassifyInput{Cycle: healthy(), Service: svc(dnsOK("gateway", gwIP),
				model.DNSResult{Server: "68.94.156.9:53", ServerRole: "isp", Name: "www.google.com", OK: true, RCode: "SERVFAIL"}, dnsOK("public", "1.1.1.1"))})
			in.PrevServiceGap = 151 * time.Second
			return in
		}(),
			state: model.StateOnline, attr: model.AttrNone, reasons: []string{"no recent previous check confirms it"}},
		{name: "gateway DNS failure while ISP answers", in: twice(ClassifyInput{Cycle: healthy(), Service: svc(
			model.DNSResult{Server: gwIP + ":53", ServerRole: "gateway", Name: "www.google.com", Err: "i/o timeout"},
			dnsOK("isp", "68.94.156.9"),
			dnsOK("public", "1.1.1.1"),
		)}),
			state: model.StateDegraded, cause: model.CauseGatewayDNSFailure, attr: model.AttrProvider,
			reasons: []string{"gateway DNS 192.168.1.254 failed (i/o timeout) while ISP resolver 68.94.156.9 answered"}},
		{name: "gateway DNS hijacked answer counts as failure", in: twice(ClassifyInput{Cycle: healthy(), Service: svc(
			model.DNSResult{Server: gwIP + ":53", ServerRole: "gateway", Name: "www.google.com", OK: true, RCode: "NOERROR", Answers: []string{gwIP}, Hijacked: true, HijackWhy: "answer is the gateway"},
			dnsOK("isp", "68.94.156.9"),
		)}),
			state: model.StateDegraded, cause: model.CauseGatewayDNSFailure, attr: model.AttrProvider,
			reasons: []string{"failed (hijacked: answer is the gateway)"}},
		{name: "ISP DNS rule outranks gateway DNS rule", in: twice(ClassifyInput{Cycle: healthy(), Service: svc(
			model.DNSResult{Server: gwIP, ServerRole: "gateway", Name: "www.google.com", Err: "timeout"},
			model.DNSResult{Server: "68.94.156.9", ServerRole: "isp", Name: "www.google.com", Err: "timeout"},
			dnsOK("public", "1.1.1.1"),
		)}),
			state: model.StateDegraded, cause: model.CauseISPDNSFailure, attr: model.AttrProvider},
		{name: "a different DNS failure in the previous check does not confirm", in: ClassifyInput{Cycle: healthy(), Service: svc(
			model.DNSResult{Server: "68.94.156.9", ServerRole: "isp", Name: "www.google.com", Err: "timeout"},
			dnsOK("public", "1.1.1.1"),
		), PrevService: svc(model.DNSResult{Server: gwIP, ServerRole: "gateway", Name: "www.google.com", Err: "timeout"}, dnsOK("isp", "68.94.156.9")),
			PrevServiceGap: time.Minute, PrevServiceSeq: 41},
			state: model.StateOnline, attr: model.AttrNone},
		{name: "stale service check is ignored", in: ClassifyInput{Cycle: healthy(), Service: svc(
			dnsOK("gateway", gwIP), model.DNSResult{ServerRole: "isp", Name: "www.google.com", Err: "timeout"}, dnsOK("public", "1.1.1.1"),
		), ServiceAge: 151 * time.Second},
			state: model.StateOnline, attr: model.AttrNone},
		{name: "wildcard .invalid answer is not a resolution failure", in: ClassifyInput{Cycle: healthy(), Service: svc(
			dnsOK("gateway", gwIP), dnsOK("isp", "68.94.156.9"), dnsOK("public", "1.1.1.1"),
			model.DNSResult{Server: gwIP, ServerRole: "gateway", Name: "0123456789abcdef.invalid", OK: true, Answers: []string{"192.168.1.254"}, Hijacked: true},
		)},
			state: model.StateOnline, attr: model.AttrNone},
		{name: "ISP and public DNS both failing: no DNS rule", in: ClassifyInput{Cycle: healthy(), Service: svc(
			model.DNSResult{ServerRole: "gateway", Name: "www.google.com", Err: "timeout"},
			model.DNSResult{ServerRole: "isp", Name: "www.google.com", Err: "timeout"},
			model.DNSResult{ServerRole: "public", Name: "www.google.com", Err: "timeout"},
		)},
			state: model.StateOnline, attr: model.AttrNone},
		{name: "rcode spelled RCodeSuccess is success", in: ClassifyInput{Cycle: healthy(), Service: svc(
			dnsOK("gateway", gwIP),
			model.DNSResult{Server: "68.94.156.9", ServerRole: "isp", Name: "www.google.com", OK: true, RCode: "RCodeSuccess", Answers: []string{"142.250.72.36"}},
			dnsOK("public", "1.1.1.1"),
		)},
			state: model.StateOnline, attr: model.AttrNone},
		{name: "NODATA (no answers) is a failure", in: twice(ClassifyInput{Cycle: healthy(), Service: svc(
			model.DNSResult{Server: "68.94.156.9", ServerRole: "isp", Name: "www.google.com", OK: true, RCode: "NOERROR"},
			dnsOK("public", "1.1.1.1"),
		)}),
			state: model.StateDegraded, cause: model.CauseISPDNSFailure, attr: model.AttrProvider,
			reasons: []string{"failed (no answers)"}},
		{name: "zero thresholds fall back to defaults", in: ClassifyInput{Cycle: healthy()}, cfg: &config.IncidentConfig{},
			state: model.StateOnline, attr: model.AttrNone},
		{name: "custom loss threshold", in: ClassifyInput{Cycle: cyc(gwICMP(true, 1900), inetN(1, 9000))},
			cfg:   &config.IncidentConfig{LossDegradedPct: 25},
			state: model.StateOnline, attr: model.AttrNone},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := cfg
			if tc.cfg != nil {
				c = *tc.cfg
			}
			got := Classify(tc.in, c)
			if got.State != tc.state || got.Cause != tc.cause || got.Attribution != tc.attr {
				t.Fatalf("got %s/%s/%s, want %s/%s/%s\nreasons: %q", got.State, got.Cause, got.Attribution, tc.state, tc.cause, tc.attr, got.Reasons)
			}
			if got.Rules != RulesVersion {
				t.Fatalf("rules %q", got.Rules)
			}
			if len(got.Reasons) == 0 {
				t.Fatal("verdict without reasons")
			}
			all := strings.Join(got.Reasons, "\n")
			for _, want := range tc.reasons {
				if !strings.Contains(all, want) {
					t.Errorf("reasons lack %q:\n%s", want, all)
				}
			}
			// Pure and deterministic.
			if again := Classify(tc.in, c); !reflect.DeepEqual(got, again) {
				t.Fatalf("not deterministic:\n%#v\n%#v", got, again)
			}
		})
	}
}

func TestClassifyZeroConfigEqualsDefaults(t *testing.T) {
	inputs := []ClassifyInput{
		{Cycle: healthy()},
		{Cycle: cyc(gwICMP(true, 1900), inetN(1, 9000))},
		{Cycle: cyc(gwICMP(true, 2000), inet(true, true, 200000))},
		{Cycle: cyc(gwICMP(true, 1900), inet(false, false, 0)), Snapshot: snapWith(nil), SnapshotAge: 140 * time.Second},
	}
	for i, in := range inputs {
		a := Classify(in, config.IncidentConfig{})
		b := Classify(in, config.Default().Incident)
		if !reflect.DeepEqual(a, b) {
			t.Errorf("input %d: zero config %v != defaults %v", i, a, b)
		}
	}
}

func TestMedianMs(t *testing.T) {
	tests := []struct {
		in   []int64
		want float64
		ok   bool
	}{
		{nil, 0, false},
		{[]int64{1500}, 1.5, true},
		{[]int64{3000, 1000}, 2, true},
		{[]int64{5000, 1000, 3000}, 3, true},
	}
	for _, tc := range tests {
		got, ok := medianMs(tc.in)
		if got != tc.want || ok != tc.ok {
			t.Errorf("medianMs(%v) = %v,%v want %v,%v", tc.in, got, ok, tc.want, tc.ok)
		}
	}
	in := []int64{3, 1, 2}
	medianMs(in)
	if in[0] != 3 {
		t.Error("medianMs must not reorder its input")
	}
}
