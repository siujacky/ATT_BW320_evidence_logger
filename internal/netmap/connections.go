package netmap

import (
	"cmp"
	"context"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"attmonitor/internal/contracts"
	"attmonitor/internal/model"
)

// Keys of the flow diagram's groups (model.NetOrg, model.NetService).
const (
	orgOther   = "other"   // the organisations beyond the diagram's top ones
	orgLocal   = "local"   // private and other non-public addresses
	orgUnknown = "unknown" // public addresses the IP database does not know
	svcOther   = "other"   // unnamed services, and the named ones beyond the top ones
	gatewayKey = "gateway" // model.ConnDevice.Key of the gateway's own connections
)

// Sizes of the flow diagram.
const (
	topOrgs     = 12
	topServices = 8
)

// Connections returns which device talked to which remote address in [q.From, q.To) according
// to the samples of the gateway's NAT table (contracts.NetworkView). With q.Device only that
// device's flows are shown, while Devices still lists every device of the period (for the
// device filter). Without a connection store it fails with an error wrapping
// contracts.ErrUnavailable; a period that is not valid gives ErrRange. The rows' reverse DNS
// names are the ones known when it is called (it asks for the missing ones in the background).
func (v *View) Connections(ctx context.Context, q contracts.NetQuery) (model.NetConnections, error) {
	if v.conns == nil {
		return model.NetConnections{}, fmt.Errorf("netmap: connections view: no connection store: %w", contracts.ErrUnavailable)
	}
	from, to, err := v.period(q)
	if err != nil {
		return model.NetConnections{}, err
	}
	limit := rowLimit(q.Limit)
	key := periodKey(q, from, to) + "|" + strconv.Itoa(limit) + "|" + q.Device
	nc, err := v.connResults.get(ctx, key, func() (model.NetConnections, error) {
		return v.buildConnections(ctx, from, to, q.Device, limit)
	})
	if err != nil {
		return model.NetConnections{}, err
	}
	nc = cloneConnections(nc)
	v.addPTR(nc.Rows)
	return nc, nil
}

// named is what a flow is named after.
type named struct {
	remote  string // the remote address in its canonical form (as given when it is no address)
	info    model.IPInfo
	org     string // its organisation's key, before grouping
	svc     string // its service's key, before grouping
	svcName string // the service's name in the flow diagram ("" for svcOther)
	known   string // the port table's name of the service ("" when it has none)
}

// addrInfo is what is known about a remote address.
type addrInfo struct {
	remote string
	info   model.IPInfo
}

// buildConnections builds the connections view of [from, to) for device ("" = every device).
//
// Its work is bounded by the flows it draws (bounds.flows): a period with more is drawn from its
// heaviest flows - they alone are named and make the flow diagram's organisations, services and
// bands, and the countries - while the lighter ones count in the diagram as "Other" (weight
// only, from each device), in the totals (the distinct remote addresses then estimated) and in
// the rows, which are the most seen flows of all.
func (v *View) buildConnections(ctx context.Context, from, to time.Time, device string, limit int) (model.NetConnections, error) {
	if err := v.acquireConn(ctx); err != nil {
		return model.NetConnections{}, fmt.Errorf("netmap: connections view: %w", err)
	}
	defer v.releaseConn()
	agg, err := v.conns.Aggregate(ctx, contracts.ConnQuery{From: from, To: to, Device: device})
	if err != nil {
		return model.NetConnections{}, fmt.Errorf("netmap: connections view: %w", err)
	}
	all := agg
	if device != "" {
		// The device filter lists every device of the period.
		if all, err = v.conns.Aggregate(ctx, contracts.ConnQuery{From: from, To: to}); err != nil {
			return model.NetConnections{}, fmt.Errorf("netmap: connections view: %w", err)
		}
	}
	lk := lookup{intel: v.intel}
	flows := topK(agg.Flows, v.bounds.flows, compareFlows) // the drawn flows, heaviest first
	if err := ctx.Err(); err != nil {
		return model.NetConnections{}, fmt.Errorf("netmap: connections view: %w", err)
	}
	infos := map[string]addrInfo{}
	names := make([]named, len(flows))
	for i, f := range flows {
		if i%finishEvery == finishEvery-1 {
			if err := ctx.Err(); err != nil {
				return model.NetConnections{}, fmt.Errorf("netmap: connections view: %w", err)
			}
		}
		names[i] = v.name(f, lk, infos)
	}
	rest, err := restOf(ctx, agg.Flows, flows, lk)
	if err != nil {
		return model.NetConnections{}, fmt.Errorf("netmap: connections view: %w", err)
	}
	rest.addLeftOut(agg.Devices)
	devices, err := netDevices(ctx, all, v.bounds.flows)
	if err != nil {
		return model.NetConnections{}, fmt.Errorf("netmap: connections view: %w", err)
	}
	nc := model.NetConnections{
		From:         rfc3339(from),
		To:           rfc3339(to),
		Device:       device,
		Samples:      agg.Samples,
		First:        agg.First,
		Last:         agg.Last,
		InUse:        agg.InUse,
		Available:    agg.Available,
		Open:         agg.Open,
		OpenDevice:   agg.OpenDevice,
		Devices:      devices,
		FlowsLeftOut: agg.FlowsLeftOut,
		IPDB:         v.ipdb(),
	}
	var orgOf, svcOf map[string]string
	nc.Orgs, orgOf = groupOrgs(flows, names, rest.weight)
	nc.Services, svcOf = groupServices(flows, names, rest.weight)
	nc.Links = links(flows, names, orgOf, svcOf, rest.byDevice)
	nc.Countries = connCountries(flows, names)
	if nc.Totals, err = connTotals(ctx, agg, flows, names, rest); err != nil {
		return model.NetConnections{}, fmt.Errorf("netmap: connections view: %w", err)
	}
	if device == "" {
		listed, _ := v.conns.Devices()
		nc.Totals.Listed = listedDevices(devices, listed)
	}
	nc.Rows = connRows(agg.Flows, limit, func(f model.ConnFlow) named { return v.name(f, lk, infos) })
	nc.RowsTotal = len(agg.Flows)
	if err := ctx.Err(); err != nil {
		return model.NetConnections{}, fmt.Errorf("netmap: connections view: %w", err)
	}
	return nc, nil
}

// listedDevices counts the devices of a period (devices) that the gateway's newest Device List
// read (listed) lists - by the key the connection store names a device by: "mac:<mac>" for an
// entry with a MAC address, else "ip:<address>".
func listedDevices(devices []model.NetDevice, listed []model.LANDevice) int {
	keys := map[string]bool{}
	for _, d := range listed {
		if d.MAC != "" {
			keys["mac:"+strings.ToLower(d.MAC)] = true
			continue
		}
		for _, a := range append([]string{d.IPv4}, d.IPv6...) {
			if a != "" {
				keys["ip:"+canonical(a)] = true
			}
		}
	}
	n := 0
	for _, d := range devices {
		if keys[d.Key] {
			n++
		}
	}
	return n
}

// restSums are the flows of a period beyond those drawn (bounds.flows) - and the weight of the
// flows the connection store left out (addLeftOut) - their weight, in all and by device, and - over
// every flow - a sketch of the distinct remote addresses and the organisations and countries of
// the public ones (nil sets when every flow is drawn).
type restSums struct {
	weight    int
	byDevice  map[string]int
	sites     *hll
	orgs      map[string]struct{}
	countries map[string]struct{}
}

// addLeftOut adds the weight of the flows the connection store left out beyond its bound
// (ConnDevice.LeftOut) to the rest: they count as "Other", from their device.
func (r *restSums) addLeftOut(devices []model.ConnDevice) {
	for _, d := range devices {
		if d.LeftOut <= 0 {
			continue
		}
		if r.byDevice == nil {
			r.byDevice = map[string]int{}
		}
		r.weight += d.LeftOut
		r.byDevice[d.Key] += d.LeftOut
	}
}

// restOf sums up the flows of all that are not among drawn (the first ones of all in the order of
// compareFlows): nothing when drawn holds them all.
func restOf(ctx context.Context, all, drawn []model.ConnFlow, lk lookup) (*restSums, error) {
	rest := &restSums{}
	if len(drawn) == len(all) {
		return rest, nil
	}
	rest.byDevice, rest.sites = map[string]int{}, newHLL(hllPrecision)
	rest.orgs, rest.countries = map[string]struct{}{}, map[string]struct{}{}
	var cut *model.ConnFlow // the last drawn flow: those after it are not drawn
	if len(drawn) > 0 {
		cut = &drawn[len(drawn)-1]
	}
	for i := range all {
		if i%finishEvery == finishEvery-1 {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
		}
		f := &all[i]
		a, ok := remoteAddr(f.Remote)
		rest.sites.add(remoteHash(f.Remote, a, ok))
		if cut != nil && compareFlows(*f, *cut) <= 0 {
			continue // drawn
		}
		rest.weight += f.Weight
		rest.byDevice[f.Device] += f.Weight
		if !ok {
			continue
		}
		if info := lk.info(a); info.Kind == model.IPKindPublic {
			if k := orgKey(info); k != orgUnknown {
				rest.orgs[k] = struct{}{}
			}
			if info.Country != "" {
				rest.countries[info.Country] = struct{}{}
			}
		}
	}
	return rest, nil
}

// compareFlows orders flows heaviest first (and fully, so the view does not depend on the
// store's order).
func compareFlows(a, b model.ConnFlow) int {
	return cmp.Or(cmp.Compare(b.Weight, a.Weight), cmp.Compare(b.Samples, a.Samples),
		strings.Compare(a.Device, b.Device), strings.Compare(a.Remote, b.Remote), cmp.Compare(a.Port, b.Port),
		strings.Compare(a.Proto, b.Proto), compareBool(a.Inbound, b.Inbound))
}

func compareBool(a, b bool) int {
	switch {
	case a == b:
		return 0
	case a:
		return 1
	}
	return -1
}

// name names a flow after its remote address's organisation and its port's service.
func (v *View) name(f model.ConnFlow, lk lookup, infos map[string]addrInfo) named {
	ai, ok := infos[f.Remote]
	if !ok {
		if a, err := netip.ParseAddr(f.Remote); err == nil {
			a = a.Unmap()
			ai = addrInfo{remote: a.String(), info: lk.info(a)}
		} else {
			ai = addrInfo{remote: f.Remote, info: model.IPInfo{Kind: model.IPKindInvalid}}
		}
		infos[f.Remote] = ai
	}
	n := named{remote: ai.remote, info: ai.info}
	if ai.info.Kind != model.IPKindPublic {
		n.org = orgLocal
	} else {
		n.org = orgKey(ai.info)
	}
	proto := strings.ToLower(f.Proto)
	switch name := lk.service(proto, f.Port); {
	case name != "":
		n.svc, n.svcName, n.known = proto+"/"+strconv.Itoa(f.Port), name, name
	case v.intel == nil:
		// Without the port table every port is its own service, named after itself.
		n.svc, n.svcName = proto+"/"+strconv.Itoa(f.Port), serviceLabel(proto, f.Port)
	default:
		n.svc = svcOther
	}
	return n
}

// orgKey is the key of a public address's organisation in the flow diagram: "org:" and its name,
// when the IP database names it - several ASes of one company (Google's AS15169 and AS36040,
// Amazon's AS16509 and AS14618) are one organisation - else "as<ASN>", else orgUnknown.
func orgKey(info model.IPInfo) string {
	if name := strings.ToLower(strings.TrimSpace(info.Org)); name != "" {
		return "org:" + name
	}
	if info.ASN > 0 {
		return "as" + strconv.Itoa(info.ASN)
	}
	return orgUnknown
}

// orgAcc adds up an organisation of the flow diagram: its sites, and its ASes with their weights.
type orgAcc struct {
	org   model.NetOrg
	sites map[string]struct{}
	asns  map[int]int
}

// groupOrgs returns the flow diagram's organisations - the topOrgs heaviest and the rest as
// "other", with rest, the weight of the flows not drawn - and the diagram key of every
// organisation key.
func groupOrgs(flows []model.ConnFlow, names []named, rest int) ([]model.NetOrg, map[string]string) {
	byKey := map[string]*orgAcc{}
	for i, f := range flows {
		n := names[i]
		o := byKey[n.org]
		if o == nil {
			o = &orgAcc{org: model.NetOrg{Key: n.org}, sites: map[string]struct{}{}, asns: map[int]int{}}
			switch n.org {
			case orgLocal:
				o.org.Name = "Local network"
			case orgUnknown:
				o.org.Name = "Unknown network"
			default:
				o.org.Name = orgName(n.info)
			}
			byKey[n.org] = o
		}
		o.org.Weight += f.Weight
		o.sites[n.remote] = struct{}{}
		if n.org != orgLocal && n.org != orgUnknown && n.info.ASN > 0 {
			o.asns[n.info.ASN] += f.Weight
			// The organisation's country and AS are those of its heaviest AS.
			if best := o.asns[o.org.ASN]; o.org.ASN == 0 || o.asns[n.info.ASN] > best ||
				o.asns[n.info.ASN] == best && n.info.ASN < o.org.ASN {
				o.org.ASN, o.org.Country = n.info.ASN, n.info.Country
			}
		}
	}
	accs := make([]*orgAcc, 0, len(byKey))
	for _, o := range byKey {
		o.org.Sites = len(o.sites)
		if len(o.asns) > 1 {
			o.org.ASNs = slices.Sorted(maps.Keys(o.asns))
		}
		accs = append(accs, o)
	}
	slices.SortFunc(accs, func(a, b *orgAcc) int {
		return cmp.Or(cmp.Compare(b.org.Weight, a.org.Weight), cmp.Compare(b.org.Sites, a.org.Sites),
			strings.Compare(a.org.Key, b.org.Key))
	})
	out := make([]model.NetOrg, 0, min(len(accs), topOrgs+1))
	group := make(map[string]string, len(accs))
	var other *orgAcc
	newOther := func() *orgAcc {
		if other == nil {
			other = &orgAcc{org: model.NetOrg{Key: orgOther, Name: "Other"}, sites: map[string]struct{}{}}
		}
		return other
	}
	for i, o := range accs {
		if i < topOrgs {
			out = append(out, o.org)
			group[o.org.Key] = o.org.Key
			continue
		}
		g := newOther()
		g.org.Weight += o.org.Weight
		g.org.Members++
		for s := range o.sites {
			g.sites[s] = struct{}{}
		}
		group[o.org.Key] = orgOther
	}
	if rest > 0 {
		newOther().org.Weight += rest
	}
	if other != nil {
		other.org.Sites = len(other.sites)
		out = append(out, other.org)
	}
	return out, group
}

// groupServices returns the flow diagram's services - the topServices heaviest named ones, and
// the unnamed and the rest as "other", with rest, the weight of the flows not drawn - and the
// diagram key of every service key.
func groupServices(flows []model.ConnFlow, names []named, rest int) ([]model.NetService, map[string]string) {
	byKey := map[string]*model.NetService{}
	for i, f := range flows {
		n := names[i]
		s := byKey[n.svc]
		if s == nil {
			s = &model.NetService{Key: n.svc, Name: "Other"}
			if n.svc != svcOther {
				s.Name, s.Proto, s.Port = n.svcName, strings.ToLower(f.Proto), f.Port
			}
			byKey[n.svc] = s
		}
		s.Weight += f.Weight
	}
	svcs := make([]*model.NetService, 0, len(byKey))
	for _, s := range byKey {
		if s.Key != svcOther {
			svcs = append(svcs, s)
		}
	}
	slices.SortFunc(svcs, func(a, b *model.NetService) int {
		return cmp.Or(cmp.Compare(b.Weight, a.Weight), strings.Compare(a.Key, b.Key))
	})
	out := make([]model.NetService, 0, min(len(svcs), topServices)+1)
	group := make(map[string]string, len(byKey))
	other, grouped := byKey[svcOther], byKey[svcOther] != nil || rest > 0
	otherWeight := rest
	if other != nil {
		otherWeight += other.Weight
	}
	group[svcOther] = svcOther
	for i, s := range svcs {
		if i < topServices {
			out = append(out, *s)
			group[s.Key] = s.Key
			continue
		}
		otherWeight += s.Weight
		group[s.Key] = svcOther
		grouped = true
	}
	if grouped {
		out = append(out, model.NetService{Key: svcOther, Name: "Other", Weight: otherWeight})
	}
	return out, group
}

// links returns the flow diagram's bands: device → organisation, then organisation → service,
// each heaviest first. The flows not drawn (rest, their weight by device) go from their device
// to "other", and from there to "other".
func links(flows []model.ConnFlow, names []named, orgOf, svcOf map[string]string, rest map[string]int) []model.NetLink {
	type key struct{ from, to string }
	devOrg, orgSvc := map[key]int{}, map[key]int{}
	for i, f := range flows {
		o, s := orgOf[names[i].org], svcOf[names[i].svc]
		devOrg[key{f.Device, o}] += f.Weight
		orgSvc[key{o, s}] += f.Weight
	}
	for dev, w := range rest {
		if w > 0 {
			devOrg[key{dev, orgOther}] += w
			orgSvc[key{orgOther, svcOther}] += w
		}
	}
	out := make([]model.NetLink, 0, len(devOrg)+len(orgSvc))
	for _, m := range []map[key]int{devOrg, orgSvc} {
		start := len(out)
		for k, w := range m {
			out = append(out, model.NetLink{From: k.from, To: k.to, Weight: w})
		}
		slices.SortFunc(out[start:], func(a, b model.NetLink) int {
			return cmp.Or(cmp.Compare(b.Weight, a.Weight), strings.Compare(a.From, b.From), strings.Compare(a.To, b.To))
		})
	}
	return out
}

// connCountries returns the countries of the public remote addresses ("" for those the IP
// database does not place), most addresses first.
func connCountries(flows []model.ConnFlow, names []named) []model.NetCountry {
	type acc struct {
		c     model.NetCountry
		sites map[string]struct{}
	}
	byCode := map[string]*acc{}
	for i, f := range flows {
		n := names[i]
		if n.info.Kind != model.IPKindPublic {
			continue
		}
		a := byCode[n.info.Country]
		if a == nil {
			a = &acc{c: model.NetCountry{Code: n.info.Country}, sites: map[string]struct{}{}}
			byCode[n.info.Country] = a
		}
		a.sites[n.remote] = struct{}{}
		a.c.Weight += f.Weight
	}
	out := make([]model.NetCountry, 0, len(byCode))
	for _, a := range byCode {
		a.c.Sites = len(a.sites)
		out = append(out, a.c)
	}
	slices.SortFunc(out, func(a, b model.NetCountry) int {
		return cmp.Or(cmp.Compare(b.Sites, a.Sites), cmp.Compare(b.Weight, a.Weight), strings.Compare(a.Code, b.Code))
	})
	return out
}

// connTotals returns the summary tiles: devices, distinct remote addresses, and the distinct
// organisations (orgKey: an organisation with several ASes counts once) and countries of the public
// ones - of every flow: those not drawn come from rest, which estimates the distinct remote
// addresses of every flow when there are such flows. It fails only when ctx ends.
func connTotals(ctx context.Context, agg model.ConnAggregate, flows []model.ConnFlow, names []named, rest *restSums) (model.NetTotals, error) {
	devices := map[string]struct{}{}
	for _, d := range agg.Devices {
		devices[d.Key] = struct{}{}
	}
	for i := range agg.Flows {
		if i%finishEvery == finishEvery-1 {
			if err := ctx.Err(); err != nil {
				return model.NetTotals{}, err
			}
		}
		devices[agg.Flows[i].Device] = struct{}{}
	}
	sites, orgs, countries := map[string]struct{}{}, map[string]struct{}{}, map[string]struct{}{}
	for i := range flows {
		n := names[i]
		if rest.sites == nil {
			sites[n.remote] = struct{}{}
		}
		if n.info.Kind != model.IPKindPublic {
			continue
		}
		if n.org != orgUnknown {
			orgs[n.org] = struct{}{}
		}
		if n.info.Country != "" {
			countries[n.info.Country] = struct{}{}
		}
	}
	t := model.NetTotals{Devices: len(devices), Sites: len(sites)}
	if rest.sites != nil {
		t.Sites = rest.sites.count()
		for o := range rest.orgs {
			orgs[o] = struct{}{}
		}
		for c := range rest.countries {
			countries[c] = struct{}{}
		}
	}
	t.Orgs, t.Countries = len(orgs), len(countries)
	return t, nil
}

// connRows returns the flows as table rows: the most seen first, at most limit, named by name.
func connRows(flows []model.ConnFlow, limit int, name func(model.ConnFlow) named) []model.NetConnRow {
	best := topK(flows, limit, func(fa, fb model.ConnFlow) int {
		return cmp.Or(cmp.Compare(fb.Samples, fa.Samples), cmp.Compare(fb.Weight, fa.Weight), compareFlows(fa, fb))
	})
	rows := make([]model.NetConnRow, 0, len(best))
	for _, f := range best {
		n := name(f)
		row := model.NetConnRow{Device: f.Device, LAN: f.LAN, Remote: n.remote, Kind: n.info.Kind,
			Service: n.known, Proto: strings.ToLower(f.Proto), Port: f.Port, Inbound: f.Inbound,
			First: f.First, Last: f.Last, Samples: f.Samples, Weight: f.Weight}
		if n.info.Kind == model.IPKindPublic {
			row.Org, row.ASN, row.Country = orgName(n.info), n.info.ASN, n.info.Country
		}
		rows = append(rows, row)
	}
	return rows
}

// netDevices returns every device of the period (for the device filter), heaviest first, each
// with its number of distinct remote addresses: counted exactly when the period has at most
// bound flows, else counted exactly up to a few per device and estimated beyond (distinct). It
// fails only when ctx ends.
func netDevices(ctx context.Context, all model.ConnAggregate, bound int) ([]model.NetDevice, error) {
	exact := len(all.Flows) <= bound
	sites := map[string]*distinct{}
	weights := map[string]int{}
	lans := map[string]string{}
	for i := range all.Flows {
		if i%finishEvery == finishEvery-1 {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
		}
		f := &all.Flows[i]
		s := sites[f.Device]
		if s == nil {
			s = &distinct{exact: exact}
			sites[f.Device] = s
		}
		if exact {
			s.addString(canonical(f.Remote))
		} else {
			a, ok := remoteAddr(f.Remote)
			s.addHash(remoteHash(f.Remote, a, ok))
		}
		weights[f.Device] += f.Weight
		if lans[f.Device] == "" {
			lans[f.Device] = f.LAN
		}
	}
	count := func(key string) int {
		if s := sites[key]; s != nil {
			return s.count()
		}
		return 0
	}
	out := make([]model.NetDevice, 0, len(all.Devices))
	listed := map[string]bool{}
	for _, d := range all.Devices {
		listed[d.Key] = true
		out = append(out, model.NetDevice{Key: d.Key, Name: deviceName(d.Key, d.Name, d.IPv4), IPv4: d.IPv4,
			MAC: d.MAC, Connection: d.Connection, Weight: d.Weight, Sites: count(d.Key)})
	}
	// A device with flows that the store did not list (it should not happen) is listed too.
	for key := range sites {
		if !listed[key] {
			out = append(out, model.NetDevice{Key: key, Name: deviceName(key, "", lans[key]), Weight: weights[key], Sites: count(key)})
		}
	}
	slices.SortFunc(out, func(a, b model.NetDevice) int {
		return cmp.Or(cmp.Compare(b.Weight, a.Weight), cmp.Compare(b.Sites, a.Sites), strings.Compare(a.Name, b.Name),
			strings.Compare(a.Key, b.Key))
	})
	return out, nil
}

// deviceName names a device: its Device List name, else "Gateway" for the gateway itself, else
// its address, else what its key holds.
func deviceName(key, name, addr string) string {
	switch {
	case name != "":
		return name
	case key == gatewayKey:
		return "Gateway"
	case addr != "":
		return addr
	}
	if a, ok := strings.CutPrefix(key, "ip:"); ok {
		return a
	}
	if m, ok := strings.CutPrefix(key, "mac:"); ok {
		return m
	}
	return key
}

// canonical returns an address in its canonical form (as given when it is no address).
func canonical(s string) string {
	if a, err := netip.ParseAddr(s); err == nil {
		return a.Unmap().String()
	}
	return s
}

// remoteAddr parses a remote address (IPv4-mapped addresses as IPv4).
func remoteAddr(s string) (netip.Addr, bool) {
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, false
	}
	return a.Unmap(), true
}

// remoteHash hashes a remote address s - a when it parsed (ok), so that every spelling of an
// address hashes alike - for the sketches.
func remoteHash(s string, a netip.Addr, ok bool) uint64 {
	if ok {
		return hash16(a.As16())
	}
	return hashString(s)
}

// addPTR fills in the reverse DNS names known for the rows' public remote addresses, and asks
// for the others in the background (only the rows shown are looked up).
func (v *View) addPTR(rows []model.NetConnRow) {
	if v.intel == nil {
		return
	}
	for i := range rows {
		if rows[i].Kind != model.IPKindPublic {
			continue
		}
		if a, err := netip.ParseAddr(rows[i].Remote); err == nil {
			rows[i].PTR = v.intel.PTR(a, true)
		}
	}
}

// cloneConnections returns a copy of a view whose slices the caller may change.
func cloneConnections(nc model.NetConnections) model.NetConnections {
	nc.Devices = slices.Clone(nc.Devices)
	nc.Orgs = slices.Clone(nc.Orgs)
	nc.Services = slices.Clone(nc.Services)
	nc.Links = slices.Clone(nc.Links)
	nc.Countries = slices.Clone(nc.Countries)
	nc.Rows = slices.Clone(nc.Rows)
	return nc
}
