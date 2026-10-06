package netmap

import (
	"bytes"
	"cmp"
	"context"
	"net/netip"
	"slices"
	"strings"
	"time"

	"attmonitor/internal/model"
)

// Sizes of the firewall view's lists.
const (
	topSources = 10 // NetFirewall.TopSources
	topFwSvcs  = 8  // NetFirewall.Services, before "Other"
	maxReasons = 20 // NetFirewall.Reasons, before the other reasons
)

// finishEvery is how many sources or rows the finish goes through between two checks of the
// request's context.
const finishEvery = 4096

// finishFirewall turns the drops added up for [from, to) into the view. b is normally the
// request's builder (newRequestBuilder); a builder without bounds names no device.
func (v *View) finishFirewall(ctx context.Context, b *builder, from, to time.Time, limit int, usage model.SyslogUsage) (model.NetFirewall, error) {
	lk := lookup{intel: v.intel}
	fw := model.NetFirewall{
		From:     rfc3339(from),
		To:       rfc3339(to),
		Oldest:   usage.Oldest,
		Inbound:  b.counts[dirIn],
		Outbound: b.counts[dirOut],
		Local:    b.counts[dirLocal],
		Hours:    fwHours(b, from, to),
		IPDB:     v.ipdb(),
	}
	fw.Drops = fw.Inbound + fw.Outbound + fw.Local
	var err error
	if fw.Countries, fw.TopSources, fw.Sources, err = fwSources(ctx, b, lk); err != nil {
		return model.NetFirewall{}, err
	}
	fw.Services = v.fwServices(b, lk)
	fw.Reasons = v.fwReasons(b)
	if fw.OutboundRows, fw.OutboundTotal, fw.OutboundDevices, err = v.fwOutbound(ctx, b, lk, limit); err != nil {
		return model.NetFirewall{}, err
	}
	return fw, nil
}

// fwHours returns every hour of [from, to) (UTC hours), oldest first, with its drops.
func fwHours(b *builder, from, to time.Time) []model.FwHour {
	start := from.Truncate(time.Hour)
	out := make([]model.FwHour, 0, int((to.Sub(start)+time.Hour-1)/time.Hour))
	for t := start; t.Before(to); t = t.Add(time.Hour) {
		h := model.FwHour{T: t.Format(time.RFC3339)}
		if c := b.hours[unixHour(t)]; c != nil {
			h.In, h.Out, h.Local = c[dirIn], c[dirOut], c[dirLocal]
		}
		out = append(out, h)
	}
	return out
}

// unixHour returns the hour (Unix hours, as hourOf) that t starts.
func unixHour(t time.Time) int64 {
	s := t.Unix()
	h := s / 3600
	if s < 0 && s%3600 != 0 {
		h--
	}
	return h
}

// srcCand is a candidate for the top sources.
type srcCand struct {
	addr  [16]byte
	count int
	last  int64
	ports int
}

// fwSources returns the countries of the inbound packets' public sources, by drops, the sources
// that sent the most, and how many distinct sources there were. Beyond the request's bound the
// countries' sources and the distinct sources are estimates (srcOver), and the top sources are
// chosen among those counted one by one and the heaviest of the others, each with the packets
// counted since it was kept.
func fwSources(ctx context.Context, b *builder, lk lookup) ([]model.NetCountry, []model.FwSource, int, error) {
	var over *srcOver
	if b.lim != nil {
		over = b.lim.src
	}
	countries := map[string]*model.NetCountry{}
	country := func(code string) *model.NetCountry {
		c := countries[code]
		if c == nil {
			c = &model.NetCountry{Code: code}
			countries[code] = c
		}
		return c
	}
	top := newTop(topSources, func(x, y srcCand) int {
		return cmp.Or(cmp.Compare(y.count, x.count), cmp.Compare(y.last, x.last),
			netip.AddrFrom16(x.addr).Unmap().Compare(netip.AddrFrom16(y.addr).Unmap()))
	})
	for i := range b.srcs {
		if i%finishEvery == finishEvery-1 {
			if err := ctx.Err(); err != nil {
				return nil, nil, 0, err
			}
		}
		s := &b.srcs[i]
		if info := lk.info(netip.AddrFrom16(s.addr).Unmap()); info.Kind == model.IPKindPublic {
			c := country(info.Country)
			c.Sites++
			c.Weight += s.count
		}
		top.offer(srcCand{addr: s.addr, count: s.count, last: s.last, ports: len(s.ports)})
	}
	sources := len(b.srcs)
	if over != nil {
		sources += over.distinct.count()
		for code, o := range over.countries {
			c := country(code)
			c.Sites += o.sites.count()
			c.Weight += o.weight
		}
		for _, it := range over.heavy.items {
			top.offer(srcCand{addr: it.key, count: it.count, last: it.last, ports: len(it.ports)})
		}
	}
	cs := make([]model.NetCountry, 0, len(countries))
	for _, c := range countries {
		cs = append(cs, *c)
	}
	slices.SortFunc(cs, func(x, y model.NetCountry) int {
		return cmp.Or(cmp.Compare(y.Weight, x.Weight), cmp.Compare(y.Sites, x.Sites), strings.Compare(x.Code, y.Code))
	})
	best := top.sorted()
	srcs := make([]model.FwSource, 0, len(best))
	for _, it := range best {
		a := netip.AddrFrom16(it.addr).Unmap()
		src := model.FwSource{Addr: a.String(), Count: it.count, Ports: it.ports, Last: rfc3339(time.Unix(0, it.last))}
		if info := lk.info(a); info.Kind == model.IPKindPublic {
			src.Org, src.ASN, src.Country = orgName(info), info.ASN, info.Country
		}
		srcs = append(srcs, src)
	}
	return cs, srcs, sources, nil
}

// fwServices returns the destinations of the inbound packets that were tried most, by name
// (the port table's, else "tcp 8071"), and the others together as "Other" - with those beyond
// the request's bound.
func (v *View) fwServices(b *builder, lk lookup) []model.FwService {
	type item struct {
		proto string
		port  int
		n     int
	}
	items := make([]item, 0, len(b.services))
	for k, n := range b.services {
		items = append(items, item{proto: v.codes.protos.name(k.proto), port: int(k.port), n: n})
	}
	slices.SortFunc(items, func(x, y item) int {
		return cmp.Or(cmp.Compare(y.n, x.n), strings.Compare(x.proto, y.proto), cmp.Compare(x.port, y.port))
	})
	out := make([]model.FwService, 0, min(len(items), topFwSvcs+1))
	other := 0
	if b.lim != nil {
		other = b.lim.otherServices
	}
	for i, it := range items {
		if i >= topFwSvcs {
			other += it.n
			continue
		}
		name := lk.service(it.proto, it.port)
		if name == "" {
			name = serviceLabel(it.proto, it.port)
		}
		out = append(out, model.FwService{Name: name, Proto: it.proto, Port: it.port, Count: it.n})
	}
	if other > 0 {
		out = append(out, model.FwService{Name: "Other", Count: other})
	}
	return out
}

// fwReasons returns the drops by the gateway's reason, most first, with plain descriptions;
// reasons beyond maxReasons are grouped (otherReasons).
func (v *View) fwReasons(b *builder) []model.FwReason {
	counts := map[string]int{}
	for id, n := range b.reasons {
		counts[v.codes.reasons.name(id)] += n
	}
	other := counts[otherReasons]
	delete(counts, otherReasons)
	out := make([]model.FwReason, 0, min(len(counts), maxReasons)+1)
	for r, n := range counts {
		out = append(out, model.FwReason{Reason: r, Label: reasonLabel(r), Count: n})
	}
	slices.SortFunc(out, func(x, y model.FwReason) int {
		return cmp.Or(cmp.Compare(y.Count, x.Count), strings.Compare(x.Reason, y.Reason))
	})
	if len(out) > maxReasons {
		for _, r := range out[maxReasons:] {
			other += r.Count
		}
		out = out[:maxReasons]
	}
	if other > 0 {
		out = append(out, model.FwReason{Reason: otherReasons, Label: reasonLabel(otherReasons), Count: other})
	}
	return out
}

// outCand is a candidate for the outbound rows.
type outCand struct {
	k             outKey
	count         int
	last          int64
	proto, reason string
}

// fwOutbound returns the LAN devices' dropped packets by device and destination, most first, at
// most limit, how many rows there are and how many distinct devices sent them - both counted
// before the limit. A device is told by its key as the rows name it (devNamer), so a device the
// Device List knows counts once whichever of its addresses sent the packets. Beyond the
// request's bound the rows and the devices that name themselves are estimates (outOver), and the
// rows are chosen among those counted one by one and the heaviest of the others.
func (v *View) fwOutbound(ctx context.Context, b *builder, lk lookup, limit int) (rows []model.FwOutRow, total, devices int, err error) {
	var names *devNamer
	var over *outOver
	if b.lim != nil {
		names, over = b.lim.names, b.lim.out
	}
	cand := func(k outKey, count int, last int64) outCand {
		return outCand{k: k, count: count, last: last, proto: v.codes.protos.name(k.proto), reason: v.codes.reasons.name(k.reason)}
	}
	top := newTop(limit, func(x, y outCand) int {
		return cmp.Or(cmp.Compare(y.count, x.count), cmp.Compare(y.last, x.last),
			bytes.Compare(x.k.lan[:], y.k.lan[:]), bytes.Compare(x.k.remote[:], y.k.remote[:]),
			cmp.Compare(x.k.port, y.k.port), strings.Compare(x.proto, y.proto), strings.Compare(x.reason, y.reason),
			cmp.Compare(x.k.dev, y.k.dev)) // the same address held by two devices in the period
	})
	named := map[int32]struct{}{}   // the devices of the rows that the Device List names
	self := map[[16]byte]struct{}{} // the addresses of the rows that name themselves
	for i := range b.outs {
		if i%finishEvery == finishEvery-1 {
			if err := ctx.Err(); err != nil {
				return nil, 0, 0, err
			}
		}
		o := &b.outs[i]
		if o.key.dev > 0 {
			named[o.key.dev] = struct{}{}
		} else {
			self[o.key.lan] = struct{}{}
		}
		top.offer(cand(o.key, o.count, o.last))
	}
	total, devices = len(b.outs), len(named)+len(self)-names.sameKeys(named, self)
	if over != nil {
		// The named devices of the rows beyond the bound are known by number; the addresses that
		// name themselves are counted in a sketch, together with those of the rows counted one
		// by one.
		for num := range over.devs {
			named[num] = struct{}{}
		}
		for lan := range self {
			over.lans.add(hash16(lan))
		}
		total += over.distinct.count()
		devices = len(named) + over.lans.count()
		for _, it := range over.heavy.items {
			top.offer(cand(it.key, it.count, it.last))
		}
	}
	best := top.sorted()
	rows = make([]model.FwOutRow, 0, len(best))
	for _, it := range best {
		lan := netip.AddrFrom16(it.k.lan).Unmap()
		remote := netip.AddrFrom16(it.k.remote).Unmap()
		key, name := names.describe(it.k.dev, lan)
		row := model.FwOutRow{Device: key, Name: name, LAN: lan.String(), Remote: remote.String(),
			Service: lk.service(it.proto, int(it.k.port)), Proto: it.proto, Port: int(it.k.port),
			Reason: it.reason, Label: reasonLabel(it.reason), Count: it.count, Last: rfc3339(time.Unix(0, it.last))}
		if info := lk.info(remote); info.Kind == model.IPKindPublic {
			row.Org, row.ASN, row.Country = orgName(info), info.ASN, info.Country
		}
		rows = append(rows, row)
	}
	return rows, total, devices, nil
}

// top keeps the first n of the items offered in the order of compare, in a heap of n (the last of
// them at its root): choosing the top of a long list costs little more than reading it, and
// never more memory than n items.
type top[T any] struct {
	n       int
	compare func(a, b T) int
	h       []T
}

func newTop[T any](n int, compare func(a, b T) int) *top[T] {
	return &top[T]{n: max(n, 0), compare: compare}
}

// offer offers an item.
func (t *top[T]) offer(x T) {
	switch {
	case t.n == 0:
		return
	case len(t.h) < t.n:
		t.h = append(t.h, x)
		for i := len(t.h) - 1; i > 0; {
			p := (i - 1) / 2
			if t.compare(t.h[i], t.h[p]) <= 0 {
				break
			}
			t.h[i], t.h[p] = t.h[p], t.h[i]
			i = p
		}
		return
	case t.compare(x, t.h[0]) >= 0:
		return // not before the last kept
	}
	t.h[0] = x
	for i := 0; ; {
		l := 2*i + 1
		if l >= len(t.h) {
			return
		}
		c := l
		if r := l + 1; r < len(t.h) && t.compare(t.h[r], t.h[l]) > 0 {
			c = r
		}
		if t.compare(t.h[c], t.h[i]) <= 0 {
			return
		}
		t.h[i], t.h[c] = t.h[c], t.h[i]
		i = c
	}
}

// sorted returns the items kept, in the order of compare. The top is not used afterwards.
func (t *top[T]) sorted() []T {
	slices.SortFunc(t.h, t.compare)
	if t.h == nil {
		return []T{}
	}
	return t.h
}

// topK returns the first k items in the order of compare, in that order.
func topK[T any](items []T, k int, compare func(a, b T) int) []T {
	if k >= len(items) {
		out := slices.Clone(items)
		slices.SortFunc(out, compare)
		if out == nil {
			return []T{}
		}
		return out
	}
	t := newTop(k, compare)
	t.h = make([]T, 0, t.n)
	for _, it := range items {
		t.offer(it)
	}
	return t.sorted()
}
