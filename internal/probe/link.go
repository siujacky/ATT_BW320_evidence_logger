package probe

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"strings"

	"attmonitor/internal/model"
)

// Interface types (IANA ifType, as reported in IP_ADAPTER_ADDRESSES.IfType).
const (
	ifTypeEthernet  = 6
	ifTypeLoopback  = 24
	ifTypeIEEE80211 = 71
)

// Operational states (IF_OPER_STATUS).
const (
	operUp             = 1
	operDown           = 2
	operTesting        = 3
	operUnknown        = 4
	operDormant        = 5
	operNotPresent     = 6
	operLowerLayerDown = 7
)

// adapterInfo is the platform-neutral subset of IP_ADAPTER_ADDRESSES that LocalLink uses.
type adapterInfo struct {
	Name        string // AdapterName: stable GUID string
	Friendly    string // FriendlyName / interface alias, e.g. "Wi-Fi" (same as netsh "Name")
	Description string
	IfIndex     uint32 // IPv4 interface index
	Luid        uint64 // NET_LUID: identifies the interface for GetIfEntry2Ex (0 = unknown)
	IfType      uint32
	OperStatus  uint32
	TxSpeed     uint64         // TransmitLinkSpeed, bits/s (0 or MaxUint64 = unknown)
	IPv4        []netip.Prefix // unicast addresses with their on-link prefix length
	Gateways    []netip.Addr   // IPv4 gateways
}

// How an adapter was selected for the gateway.
const (
	selOnLink   = "on-link"  // has an IPv4 address in the gateway's subnet
	selGateway  = "gateway"  // lists the gateway among its gateways
	selPrevious = "previous" // was on the gateway's subnet before (now e.g. disconnected)
	selRoute    = "route"    // the routing table's best interface towards the gateway
)

// selectAdapter picks the adapter used to reach gw: an adapter on the gateway's subnet,
// else one listing gw as a gateway (ties broken by the routing table's best interface,
// then by being up), else the adapter last seen on the gateway's subnet (identified by
// GUID: an adapter that lost its link keeps its identity), else the best-route interface.
func selectAdapter(list []adapterInfo, gw netip.Addr, bestIdx uint32, last string) (adapterInfo, string, bool) {
	pick := func(cands []adapterInfo) adapterInfo {
		for _, a := range cands {
			if bestIdx != 0 && a.IfIndex == bestIdx {
				return a
			}
		}
		for _, a := range cands {
			if a.OperStatus == operUp {
				return a
			}
		}
		return cands[0]
	}
	var onLink, viaGateway []adapterInfo
	for _, a := range list {
		for _, p := range a.IPv4 {
			if p.Bits() > 0 && p.Masked().Contains(gw) {
				onLink = append(onLink, a)
				break
			}
		}
		for _, g := range a.Gateways {
			if g == gw {
				viaGateway = append(viaGateway, a)
				break
			}
		}
	}
	if len(onLink) > 0 {
		return pick(onLink), selOnLink, true
	}
	if len(viaGateway) > 0 {
		return pick(viaGateway), selGateway, true
	}
	if last != "" {
		for _, a := range list {
			if a.Name == last {
				return a, selPrevious, true
			}
		}
	}
	if bestIdx != 0 {
		for _, a := range list {
			if a.IfIndex == bestIdx {
				return a, selRoute, true
			}
		}
	}
	return adapterInfo{}, "", false
}

// linkType maps an IANA ifType to the model's link type.
func linkType(t uint32) string {
	switch t {
	case ifTypeIEEE80211:
		return "wifi"
	case ifTypeEthernet:
		return "ethernet"
	}
	return "unknown"
}

// operState maps IF_OPER_STATUS to the model's link state. Down and LowerLayerDown both
// mean the link cannot carry traffic and are reported as "disconnected".
func operState(s uint32) string {
	switch s {
	case operUp:
		return "connected"
	case operDown, operLowerLayerDown:
		return "disconnected"
	case operTesting:
		return "testing"
	case operDormant:
		return "dormant"
	case operNotPresent:
		return "not_present"
	case operUnknown:
		return "unknown"
	}
	return fmt.Sprintf("oper_status_%d", s)
}

// linkFromAdapter describes a selected adapter. LocalIP prefers the address in the
// gateway's subnet, then any non-link-local address; GatewayIP is the adapter's own first
// IPv4 gateway (which may differ from gw, e.g. behind a mesh router or another network).
func linkFromAdapter(a adapterInfo, gw netip.Addr) model.LocalLink {
	l := model.LocalLink{
		Interface: a.Friendly,
		Type:      linkType(a.IfType),
		State:     operState(a.OperStatus),
	}
	if l.Interface == "" {
		l.Interface = a.Description
	}
	if l.Interface == "" {
		l.Interface = a.Name
	}
	var local netip.Addr
	for _, p := range a.IPv4 {
		if p.Bits() > 0 && p.Masked().Contains(gw) {
			local = p.Addr()
			break
		}
	}
	if !local.IsValid() {
		for _, p := range a.IPv4 {
			if !p.Addr().IsLinkLocalUnicast() {
				local = p.Addr()
				break
			}
		}
	}
	if !local.IsValid() && len(a.IPv4) > 0 {
		local = a.IPv4[0].Addr()
	}
	if local.IsValid() {
		l.LocalIP = local.String()
	}
	if len(a.Gateways) > 0 {
		l.GatewayIP = a.Gateways[0].String()
	}
	// Rounded to the nearest Mbps without adding first (which could wrap around). 0 and
	// MaxUint64 mean "unknown"; so does a value too large for an int32 (over 2 Pb/s), which
	// can only be garbage and must not be recorded as a wrapped-around number.
	if mbps := a.TxSpeed/1_000_000 + (a.TxSpeed%1_000_000)/500_000; a.TxSpeed != math.MaxUint64 && mbps <= math.MaxInt32 {
		l.LinkMbps = int(mbps)
	}
	return l
}

// mergeWLAN copies the Wi-Fi details parsed from netsh into the adapter description. The
// netsh state ("connected", "disconnected", "associating", ...) is more specific than the
// adapter's operational status and replaces it.
func mergeWLAN(l *model.LocalLink, w model.LocalLink) {
	if w.State != "" {
		l.State = w.State
	}
	l.SSID = w.SSID
	l.BSSID = w.BSSID
	l.SignalPct = w.SignalPct
	l.RSSIdBm = w.RSSIdBm
	l.Channel = w.Channel
	l.Band = w.Band
	l.RadioType = w.RadioType
	l.RxMbps = w.RxMbps
	l.TxMbps = w.TxMbps
	if w.Err != "" {
		appendLinkErr(l, w.Err)
	}
}

// readCounters sets the octet counters of the adapter the reading describes: what this computer
// received and sent on it (GetIfEntry2Ex). The adapter is identified by its NET_LUID, which is
// unique and stays the same while the adapter exists (an interface index can be reused, an alias
// renamed), else by its interface index. Counters that cannot be read stay nil: they measure
// traffic, not the link, and never go into Err.
func (p *Prober) readCounters(l *model.LocalLink, a adapterInfo) {
	rx, tx, err := p.ifCounters(a.Luid, a.IfIndex)
	if err != nil {
		p.log.Debug("interface counters not read", "interface", l.Interface, "err", err)
		return
	}
	l.RxBytes, l.TxBytes = &rx, &tx
}

func appendLinkErr(l *model.LocalLink, msg string) {
	if l.Err == "" {
		l.Err = msg
	} else {
		l.Err += "; " + msg
	}
}

// LocalLink describes the adapter used to reach gatewayIP (see selectAdapter): alias,
// type (IfType 71 wifi, 6 ethernet), state (IF_OPER_STATUS), local IPv4, the adapter's
// gateway, link speed (TransmitLinkSpeed) and its 64-bit octet counters (RxBytes/TxBytes, see
// readCounters). For Wi-Fi adapters it runs
// "netsh wlan show interfaces" (5 s limit, no console window), merges SSID, BSSID, band,
// channel, radio type, rates, signal and RSSI, and returns netsh's exact output as raw (with its
// SHA-256 in RawSHA256) for the evidence store; for other adapters raw is nil.
//
// The returned LocalLink is always usable: problems are described in LocalLink.Err. The
// error is non-nil only when no adapter could be identified at all (it equals Err);
// a netsh failure on an identified adapter is reported in Err only.
func (p *Prober) LocalLink(ctx context.Context, gatewayIP string) (model.LocalLink, []byte, error) {
	fail := func(err error) (model.LocalLink, []byte, error) {
		return model.LocalLink{Type: "unknown", State: "unknown", Err: err.Error()}, nil, err
	}
	gw, err := netip.ParseAddr(strings.TrimSpace(gatewayIP))
	if err != nil || !gw.Unmap().Is4() {
		return fail(fmt.Errorf("local link: gateway %q is not an IPv4 address", gatewayIP))
	}
	gw = gw.Unmap()
	if err := ctx.Err(); err != nil {
		return fail(fmt.Errorf("local link: %w", err))
	}
	adapters, err := p.adapters()
	if err != nil {
		return fail(fmt.Errorf("local link: %w", err))
	}
	best, berr := p.bestIf(gw)
	if berr != nil {
		best = 0 // no route (e.g. the link is down); selection falls back to other evidence
	}
	p.mu.Lock()
	last := p.lastAdapter
	p.mu.Unlock()

	a, how, ok := selectAdapter(adapters, gw, best, last)
	if !ok {
		return fail(errors.New("local link: no network adapter is on the gateway " + gw.String() + "'s subnet"))
	}
	if how == selOnLink || how == selGateway {
		p.mu.Lock()
		p.lastAdapter = a.Name
		p.mu.Unlock()
	}
	link := linkFromAdapter(a, gw)
	p.log.Debug("local link adapter", "interface", link.Interface, "selected_by", how, "best_if", best)
	p.readCounters(&link, a) // before netsh, which may take seconds: the reading's time is now
	if a.IfType != ifTypeIEEE80211 {
		return link, nil, nil
	}

	raw, nerr := p.runNetsh(ctx)
	if len(raw) > 0 {
		sum := sha256.Sum256(raw)
		link.RawSHA256 = hex.EncodeToString(sum[:])
	}
	if nerr != nil {
		appendLinkErr(&link, "netsh wlan show interfaces: "+nerr.Error())
	}
	switch {
	case len(raw) == 0:
	case strings.TrimSpace(a.Friendly) == "":
		// ParseNetshWLAN("") would take the first connected interface, which may be another
		// adapter: its SSID and state must not be attributed to this one.
		appendLinkErr(&link, "netsh: the adapter has no interface alias to match netsh's interfaces by name")
	default:
		w, perr := ParseNetshWLAN(raw, a.Friendly)
		if perr != nil {
			appendLinkErr(&link, perr.Error())
		} else {
			mergeWLAN(&link, w)
		}
	}
	return link, raw, nil
}
