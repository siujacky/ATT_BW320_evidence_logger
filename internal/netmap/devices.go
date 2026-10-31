package netmap

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"time"

	"attmonitor/internal/contracts"
	"attmonitor/internal/model"
)

// Devices returns the gateway's Device List - its DHCP table: which device has which address - as
// its newest read shows it, with what the period [q.From, q.To) says about each device and its
// issues, the LAN addresses that no Device List read of the period names, and the period's address
// history (contracts.NetworkView; docs/dhcp-table.md). Its sources are the connection store - its
// newest Device List read (the devices listed), the period's reads (EachDevices, when the store
// has it: deviceHistory) and the period's NAT samples - the syslog store's firewall drops, added
// up by LAN address, and the LAN scans of the period (Options.Scans). Without a connection store
// it fails with an error wrapping contracts.ErrUnavailable; a period that is not valid gives
// ErrRange. Without NAT samples, a syslog store or scans - or when they cannot be read - the
// figures they give are 0 (NATReads and Scans say whether the period has NAT reads and scans).
// q.Limit bounds the unknown addresses listed (Totals.Unknown counts them all); q.Device is not
// used.
func (v *View) Devices(ctx context.Context, q contracts.NetQuery) (model.NetDevicesView, error) {
	b, err := v.devicesBuild(ctx, q, rowLimit(q.Limit), "devices view")
	if err != nil {
		return model.NetDevicesView{}, err
	}
	return cloneDevicesView(b.view), nil
}

// devicesBuild returns the Devices view of q's period that lists at most limit unknown addresses,
// with what a device's details need (what: the request, for the error without a connection
// store): the one built for the same request within the reuse time, else a new one.
func (v *View) devicesBuild(ctx context.Context, q contracts.NetQuery, limit int, what string) (*devBuild, error) {
	if v.conns == nil {
		return nil, fmt.Errorf("netmap: %s: no connection store: %w", what, contracts.ErrUnavailable)
	}
	from, to, err := v.period(q)
	if err != nil {
		return nil, err
	}
	key := periodKey(q, from, to) + "|" + strconv.Itoa(limit)
	return v.devResults.get(ctx, key, func() (*devBuild, error) {
		return v.buildDevices(ctx, from, to, limit)
	})
}

// buildDevices builds the Devices view of [from, to), one at a time: the period's Device List
// reads, then its NAT samples (in the connections slot), then its dropped packets by LAN address
// (in the firewall slot) - one slot after the other - then its LAN scans.
func (v *View) buildDevices(ctx context.Context, from, to time.Time, limit int) (*devBuild, error) {
	if err := v.acquireDev(ctx); err != nil {
		return nil, fmt.Errorf("netmap: devices view: %w", err)
	}
	defer v.releaseDev()
	began := time.Now()
	list, listAt := v.conns.Devices()
	reads, err := v.deviceReads(ctx, from, to, list, listAt)
	if err != nil {
		return nil, fmt.Errorf("netmap: devices view: %w", err)
	}
	agg, err := v.devicesNAT(ctx, from, to)
	if err != nil {
		return nil, fmt.Errorf("netmap: devices view: %w", err)
	}
	drops, err := v.devicesFirewall(ctx, from, to, reads.namer)
	if err != nil {
		return nil, fmt.Errorf("netmap: devices view: %w", err)
	}
	a := &devAssembly{from: from, to: to, limit: limit, list: list, listAt: listAt, reads: reads, agg: agg, drops: drops,
		exact: len(agg.Flows) <= v.bounds.flows, gateway: v.gateway, lans: v.bounds.lans}
	if v.scans != nil {
		a.eachScan = func(ctx context.Context, fn func(model.LANScan) error) error {
			return v.scans.EachScan(ctx, from, to, fn)
		}
	}
	b, err := a.build(ctx)
	if err != nil {
		return nil, fmt.Errorf("netmap: devices view: %w", err)
	}
	switch {
	case a.scanErr != nil && !v.devWarned.scans:
		v.devWarned.scans = true
		v.log.Warn("network view: the LAN scans of the period cannot be read; the Devices tab shows no scan figures", "err", a.scanErr)
	case a.scanErr == nil && a.eachScan != nil:
		v.devWarned.scans = false
	}
	skipped := 0
	if drops != nil {
		skipped = drops.lim.lanSkipped
	}
	dv := b.view
	v.log.Debug("network view: devices view built", "from", dv.From, "to", dv.To, "devices", len(dv.Devices),
		"unknown", dv.Totals.Unknown, "reads", dv.Reads, "nat_reads", dv.NATReads, "scans", dv.Scans, "addresses", len(dv.Addresses),
		"drops_not_by_address", skipped, "took", time.Since(began).Round(time.Millisecond))
	return b, nil
}

// devicesNAT adds up the NAT samples of [from, to) for every device (in the connections slot). A
// failure other than ctx's is logged - once while it lasts - and gives no samples: the Devices tab
// still shows the Device List.
func (v *View) devicesNAT(ctx context.Context, from, to time.Time) (model.ConnAggregate, error) {
	if err := v.acquireConn(ctx); err != nil {
		return model.ConnAggregate{}, err
	}
	defer v.releaseConn()
	agg, err := v.conns.Aggregate(ctx, contracts.ConnQuery{From: from, To: to})
	switch {
	case err == nil:
		v.devWarned.nat = false
		return agg, nil
	case ctx.Err() != nil:
		return model.ConnAggregate{}, ctx.Err()
	}
	if !v.devWarned.nat {
		v.devWarned.nat = true
		v.log.Warn("network view: the NAT samples of the period cannot be added up; the Devices tab shows no connections", "err", err)
	}
	return model.ConnAggregate{InUse: -1, Available: -1}, nil
}

// devicesFirewall adds up the dropped packets of [from, to) by LAN address (newLANBuilder), naming
// each address after the Device List reads of names, in the firewall slot: it shares the firewall
// view's cache of sealed chunks, and reads again, as the firewall view does, when a chunk was
// sealed meanwhile (maxBuilds). nil without a syslog store. It fails only when ctx ends.
func (v *View) devicesFirewall(ctx context.Context, from, to time.Time, names *devNamer) (*builder, error) {
	if v.syslog == nil {
		return nil, nil
	}
	if err := v.acquireFW(ctx); err != nil {
		return nil, err
	}
	defer v.releaseFW()
	for build := 1; ; build++ {
		r, _, err := v.runFirewall(ctx, from, to, newLANBuilder(v.bounds, names))
		if err != nil {
			return nil, err
		}
		if build < maxBuilds && sealedSince(r.refs, v.syslog.Chunks()) {
			v.log.Debug("network view: a syslog chunk was sealed while the devices view was built; its drops are read again",
				"build", build)
			continue
		}
		return r.b, nil
	}
}

// cloneDevicesView returns a copy of a view whose slices (and scan) the caller may change.
func cloneDevicesView(dv model.NetDevicesView) model.NetDevicesView {
	dv.Devices = slices.Clone(dv.Devices)
	for i := range dv.Devices {
		dv.Devices[i] = cloneLANDevice(dv.Devices[i])
	}
	dv.Unknown = slices.Clone(dv.Unknown)
	for i := range dv.Unknown {
		dv.Unknown[i].Issues = slices.Clone(dv.Unknown[i].Issues)
	}
	dv.Addresses = slices.Clone(dv.Addresses)
	if dv.Scan != nil {
		scan := *dv.Scan
		dv.Scan = &scan
	}
	return dv
}

// cloneLANDevice returns a copy of a device whose slices the caller may change.
func cloneLANDevice(d model.NetLANDevice) model.NetLANDevice {
	d.IPv6 = slices.Clone(d.IPv6)
	d.Addresses = slices.Clone(d.Addresses)
	d.Issues = slices.Clone(d.Issues)
	return d
}
