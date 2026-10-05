package gateway

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"attmonitor/internal/model"
)

// Parse errors.
var (
	// ErrLoginRequired means the gateway answered with its login page instead of the
	// requested page (the page needs authentication, or the session expired).
	ErrLoginRequired = errors.New("gateway: login page returned (authentication required)")
	// ErrUnexpectedPage means the body is not the page the parser expects (none of its
	// labels were found).
	ErrUnexpectedPage = errors.New("gateway: unexpected page content")
)

// IsLoginPage reports whether body is the gateway's login page: <title>Login</title>, the
// "Access Code Required" banner, or the login form (docs/DESIGN.md §2). Status pages that
// merely carry a form nonce (broadbandstatistics, lanstatistics) are not login pages.
func IsLoginPage(body []byte) bool { return scan(body).isLogin() }

// SessionsFull reports whether body says "all web server sessions are in use"
// (case-insensitive; the gateway's session pool is exhausted, back off >= 5 minutes).
func SessionsFull(body []byte) bool { return scan(body).sessionsFull() }

// ---------------------------------------------------------------- label/value rows

// kvRow is a table row read as "label: value".
type kvRow struct {
	section string
	label   string
	value   string
}

// isHeaderRow reports whether r is a column-header row: at least two non-empty <th> cells
// and no non-empty <td> cell ("&nbsp; | Low | High", "Interface | Status | ...").
func isHeaderRow(r row) bool {
	th := 0
	for _, c := range r.cells {
		if c.text == "" {
			continue
		}
		if !c.th {
			return false
		}
		th++
	}
	return th >= 2
}

// joinValues returns the text of the value cells: "" if all are empty, the single non-empty
// text, or all non-empty texts joined with " | ".
func joinValues(cells []cell) string {
	var vals []string
	for _, c := range cells {
		if c.text != "" {
			vals = append(vals, c.text)
		}
	}
	return strings.Join(vals, " | ")
}

// kvRows returns every row that has a non-empty first cell (the label) and at least one more
// cell (the value), excluding column-header rows.
func (p *page) kvRows() []kvRow {
	var out []kvRow
	for _, r := range p.rows {
		if len(r.cells) < 2 || isHeaderRow(r) {
			continue
		}
		label := normLabel(r.cells[0].text)
		if label == "" {
			continue
		}
		out = append(out, kvRow{section: p.sectionName(r.section), label: label, value: joinValues(r.cells[1:])})
	}
	return out
}

// sectionKey returns "Section/Label" ("Label" when the row precedes every heading).
func sectionKey(section, label string) string {
	if section == "" {
		return label
	}
	return section + "/" + label
}

// valueSet fills a Values map without ever dropping a row: a repeated key gets a " (2)",
// " (3)", ... suffix. Suffix search resumes where it stopped for that key, so a page with many
// identical labels is still processed in linear time.
type valueSet struct {
	m    map[string]string
	next map[string]int // key -> next suffix to try
}

func newValueSet(m map[string]string) *valueSet {
	return &valueSet{m: m, next: map[string]int{}}
}

func (vs *valueSet) put(k, v string) {
	if _, dup := vs.m[k]; !dup {
		vs.m[k] = v
		return
	}
	n := vs.next[k]
	if n < 2 {
		n = 2
	}
	for ; ; n++ {
		kk := k + " (" + strconv.Itoa(n) + ")"
		if _, dup := vs.m[kk]; !dup {
			vs.m[kk] = v
			vs.next[k] = n + 1
			return
		}
	}
}

// ---------------------------------------------------------------- sysinfo

// ParseSysInfo parses sysinfo.ha. UptimeSec is -1 when "Time Since Last Reboot" is missing or
// not in a supported form (plain seconds, D:H:M:S or H:M:S); GatewayTimeRaw is "" when the
// gateway leaves "Current Date/Time" blank (it does so while the WAN is down) and when the page
// has no such row at all - GatewayTimePresent tells the two apart (true = the row, label and
// value cell, is on the page, whatever its value).
//
// A page is only accepted as System Information when it has at least one row that no other
// gateway page has (Model/Serial Number, Software/Hardware Version, First Use Date, Time Since
// Last Reboot, Current Date/Time): "MAC Address" and "Manufacturer" alone also appear
// elsewhere, and accepting such a page would report its absent clock as the gateway's blank
// clock, which Derive presents as the gateway's own WAN-down indicator.
func ParseSysInfo(body []byte) (*model.SystemInfo, error) { return parseSysInfo(scan(body)) }

func parseSysInfo(p *page) (*model.SystemInfo, error) {
	if p.isLogin() {
		return nil, fmt.Errorf("sysinfo: %w", ErrLoginRequired)
	}
	si := &model.SystemInfo{UptimeSec: -1}
	seen := map[string]bool{}
	identified := false
	for _, r := range p.kvRows() {
		key := strings.ToLower(r.label)
		if seen[key] {
			continue // first occurrence wins
		}
		var dst *string
		switch key {
		case "manufacturer":
			dst = &si.Manufacturer
		case "model number":
			dst = &si.Model
		case "serial number":
			dst = &si.Serial
		case "software version":
			dst = &si.SoftwareVersion
		case "mac address":
			dst = &si.WANMAC
		case "first use date":
			dst = &si.FirstUseDate
		case "hardware version":
			dst = &si.HardwareVersion
		case "time since last reboot":
			si.UptimeRaw = r.value
			si.UptimeSec = parseUptime(r.value)
		case "current date/time":
			dst = &si.GatewayTimeRaw
			si.GatewayTimePresent = true
		default:
			continue
		}
		seen[key] = true
		if key != "manufacturer" && key != "mac address" {
			identified = true
		}
		if dst != nil {
			*dst = r.value
		}
	}
	if !identified {
		return nil, fmt.Errorf("sysinfo: %w (no System Information rows)", ErrUnexpectedPage)
	}
	return si, nil
}

// maxUptimeSec bounds a believable uptime (100 years) so later arithmetic cannot overflow.
const maxUptimeSec = 100 * 365 * 24 * 3600

// parseUptime accepts the forms the firmware uses for "Time Since Last Reboot": plain
// seconds ("274686", observed on 6.34.7) and the documented "D:H:M:S" (also "H:M:S").
// It returns -1 for anything else.
func parseUptime(s string) int64 {
	s = normSpace(s)
	if s == "" {
		return -1
	}
	parts := strings.Split(s, ":")
	nums := make([]int64, len(parts))
	for i, part := range parts {
		if part == "" || len(part) > 12 {
			return -1
		}
		for j := 0; j < len(part); j++ {
			if part[j] < '0' || part[j] > '9' {
				return -1
			}
		}
		n, err := strconv.ParseInt(part, 10, 64)
		if err != nil {
			return -1
		}
		nums[i] = n
	}
	var total int64
	switch len(nums) {
	case 1:
		total = nums[0]
	case 3: // H:M:S
		h, m, sec := nums[0], nums[1], nums[2]
		if m > 59 || sec > 59 {
			return -1
		}
		total = h*3600 + m*60 + sec
	case 4: // D:H:M:S
		d, h, m, sec := nums[0], nums[1], nums[2], nums[3]
		if h > 23 || m > 59 || sec > 59 {
			return -1
		}
		total = d*86400 + h*3600 + m*60 + sec
	default:
		return -1
	}
	if total < 0 || total > maxUptimeSec {
		return -1
	}
	return total
}

// ---------------------------------------------------------------- broadbandstatistics

// ParseBroadband parses broadbandstatistics.ha. Labels repeat across sections ("Primary DNS"
// and "MTU" exist for IPv4 and IPv6), so rows are read per section (nearest preceding
// heading): Values holds every row as "Section/Label", the named IPv4 fields come from the
// section that holds "Broadband Connection", and Counters holds the integer rows of the
// "IPv4 Statistics" (and "IPv6 Statistics", if present) sections.
//
// A page is only accepted when it has at least one row that only the Broadband Status page
// has (Broadband Connection [Source], Broadband Network Type, Broadband/Gateway IPv4 Address,
// PON Link Status, UNI Status): lanstatistics also has "IPv4 Statistics" and "IPv6" sections,
// whose LAN-side counters and addresses must never be reported as the WAN's.
func ParseBroadband(body []byte) (*model.BroadbandStatus, error) { return parseBroadband(scan(body)) }

func parseBroadband(p *page) (*model.BroadbandStatus, error) {
	if p.isLogin() {
		return nil, fmt.Errorf("broadbandstatistics: %w", ErrLoginRequired)
	}
	rows := p.kvRows()
	bs := &model.BroadbandStatus{Values: map[string]string{}, Counters: map[string]int64{}}
	values := newValueSet(bs.Values)
	for _, r := range rows {
		values.put(sectionKey(r.section, r.label), r.value)
	}

	// set stores the first row labeled label whose section satisfies pref (any section when
	// pref is nil); with fallback, a row from any section is used when no preferred one exists.
	// It reports whether such a row exists (even with an empty value).
	set := func(dst *string, label string, pref func(string) bool, fallback bool) bool {
		v, ok := findRow(rows, label, pref)
		if !ok && fallback {
			v, ok = findRow(rows, label, nil)
		}
		if ok {
			*dst = v
		}
		return ok
	}

	// The primary (IPv4 WAN) section is the one that reports the connection itself.
	primary, havePrimary := "", false
	for _, r := range rows {
		if l := strings.ToLower(r.label); l == "broadband connection" || l == "broadband ipv4 address" {
			primary, havePrimary = r.section, true
			break
		}
	}
	inPrimary := func(sec string) bool {
		if havePrimary {
			return sec == primary
		}
		return !strings.Contains(strings.ToLower(sec), "ipv6")
	}
	isIPv6 := func(sec string) bool {
		l := strings.ToLower(sec)
		return strings.Contains(l, "ipv6") && !strings.Contains(l, "statistic")
	}
	isEthernet := func(sec string) bool { return strings.Contains(strings.ToLower(sec), "ethernet") }

	// Rows that only the Broadband Status page has (see ParseBroadband).
	wanRows := 0
	for _, f := range []struct {
		dst   *string
		label string
	}{
		{&bs.ConnectionSource, "Broadband Connection Source"},
		{&bs.Connection, "Broadband Connection"},
		{&bs.NetworkType, "Broadband Network Type"},
		{&bs.IPv4, "Broadband IPv4 Address"},
		{&bs.GatewayIPv4, "Gateway IPv4 Address"},
		{&bs.PONLinkStatus, "PON Link Status"},
		{&bs.UNIStatus, "UNI Status"},
	} {
		if set(f.dst, f.label, nil, false) {
			wanRows++
		}
	}
	set(&bs.PrimaryDNS, "Primary DNS", inPrimary, false)
	set(&bs.SecondaryDNS, "Secondary DNS", inPrimary, false)
	set(&bs.MTU, "MTU", inPrimary, false)
	set(&bs.LineState, "Line State", isEthernet, true)
	set(&bs.SpeedMbps, "Current Speed (Mbps)", isEthernet, true)
	set(&bs.Duplex, "Current Duplex", isEthernet, true)
	set(&bs.IPv6Status, "Status", isIPv6, false)
	set(&bs.IPv6Global, "Global Unicast IPv6 Address", isIPv6, true)
	set(&bs.IPv6Gateway, "Default IPv6 Gateway Address", isIPv6, true)

	for _, r := range rows {
		sec := strings.ToLower(r.section)
		if !strings.Contains(sec, "statistic") || !(strings.Contains(sec, "ipv4") || strings.Contains(sec, "ipv6")) {
			continue
		}
		n, err := strconv.ParseInt(strings.ReplaceAll(r.value, ",", ""), 10, 64)
		if err != nil {
			continue // non-numeric rows stay in Values only
		}
		key := sectionKey(r.section, r.label)
		if _, dup := bs.Counters[key]; !dup {
			bs.Counters[key] = n
		}
	}
	if wanRows == 0 {
		return nil, fmt.Errorf("broadbandstatistics: %w (no Broadband Status rows)", ErrUnexpectedPage)
	}
	return bs, nil
}

// findRow returns the value of the first row labeled label (case-insensitive) whose section
// satisfies pref; a nil pref accepts every section.
func findRow(rows []kvRow, label string, pref func(section string) bool) (string, bool) {
	for _, r := range rows {
		if strings.EqualFold(r.label, label) && (pref == nil || pref(r.section)) {
			return r.value, true
		}
	}
	return "", false
}

// ---------------------------------------------------------------- fiberstat

// dmiKind describes one of the five SFP digital diagnostics the gateway reports.
type dmiKind struct {
	key  string // alnumKey of the page name
	code string // condition code prefix (DESIGN §9)
	unit string // raw unit of Current and thresholds
}

var dmiKinds = []dmiKind{
	{key: "temperature", code: "TEMPERATURE", unit: "C"},
	{key: "vcc", code: "VCC", unit: "V"},
	{key: "txbias", code: "TX_BIAS", unit: "mA"},
	{key: "txpower", code: "OPTICAL_TX", unit: "0.1dBm"},
	{key: "rxpower", code: "OPTICAL_RX", unit: "0.1dBm"},
}

// dmiKindOf returns the known diagnostic for a measure name, or nil.
func dmiKindOf(name string) *dmiKind {
	k := alnumKey(name)
	for i := range dmiKinds {
		if dmiKinds[i].key == k {
			return &dmiKinds[i]
		}
	}
	return nil
}

// reCurrently splits a DMI heading "NAME Currently VALUE". Headings are whitespace-normalized
// first, so &nbsp;, U+00A0, U+FFFD and line breaks between NAME and "Currently" have become a
// single space; a missing separator ("Rx PowerCurrently -315") is accepted too. The value must
// not continue the word "Currently" (it starts with a non-letter, or is empty).
var reCurrently = regexp.MustCompile(`(?i)^(.*?\S)\s*currently\s*:?([^\pL].*|)$`)

// splitCurrently parses a DMI heading; ok is false when h is not one.
func splitCurrently(h string) (name, current string, ok bool) {
	m := reCurrently.FindStringSubmatch(normSpace(h))
	if m == nil {
		return "", "", false
	}
	name = normLabel(m[1])
	if name == "" {
		return "", "", false
	}
	return name, strings.TrimSpace(m[2]), true
}

var (
	reFlag      = regexp.MustCompile(`^\s*(\d{1,9})\s*(?:\(|$)`)
	reThreshold = regexp.MustCompile(`(?i)threshold\s*:?\s*([+-]?\d{1,15})`)
	reInt       = regexp.MustCompile(`^[+-]?\d{1,15}$`)
)

// parseThreshold parses an alarm/warning cell such as "1 (Threshold -295)": the leading
// number is the gateway's flag (non-zero = active), the number after "Threshold" is the
// limit in the measurement's raw units.
func parseThreshold(raw string) model.Threshold {
	raw = normSpace(raw)
	t := model.Threshold{Raw: raw}
	if m := reFlag.FindStringSubmatch(raw); m != nil {
		if n, err := strconv.ParseInt(m[1], 10, 64); err == nil {
			t.Active = n != 0
		}
	}
	if m := reThreshold.FindStringSubmatch(raw); m != nil {
		if n, err := strconv.ParseInt(m[1], 10, 64); err == nil {
			t.Threshold = &n
		}
	}
	return t
}

// parseInt64 parses a plain integer ("-315", "+37"); nil when s is anything else.
func parseInt64(s string) *int64 {
	s = strings.TrimSpace(s)
	if !reInt.MatchString(s) {
		return nil
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return nil
	}
	return &n
}

// ParseFiber parses fiberstat.ha: every label/value row of the status table goes into
// Values (keyed by label), the well-known rows into named fields, and each DMI block
// "<h1>NAME Currently VALUE</h1>" plus its Alarm/Warning x Low/High table into Measures
// (also mirrored into Values as "NAME/Current", "NAME/Low Alarm", ...; any other row inside a
// DMI block is kept as "NAME/Label").
// Units: Temperature C, Vcc V (integer, lossy), Tx Bias mA, Tx/Rx Power 0.1 dBm.
func ParseFiber(body []byte) (*model.FiberStatus, error) { return parseFiber(scan(body)) }

func parseFiber(p *page) (*model.FiberStatus, error) {
	if p.isLogin() {
		return nil, fmt.Errorf("fiberstat: %w", ErrLoginRequired)
	}
	fs := &model.FiberStatus{Values: map[string]string{}}
	values := newValueSet(fs.Values)

	// DMI blocks, keyed by heading index.
	dmi := map[int]int{} // heading index -> index into fs.Measures
	for i, h := range p.headings {
		name, cur, ok := splitCurrently(h)
		if !ok {
			continue
		}
		m := model.DMIMeasure{Name: name, CurrentRaw: cur, Current: parseInt64(cur)}
		if k := dmiKindOf(name); k != nil {
			m.Unit = k.unit
		}
		dmi[i] = len(fs.Measures)
		fs.Measures = append(fs.Measures, m)
	}
	type cols struct{ low, high int }
	tableCols := map[int]cols{} // table index -> Low/High column positions
	var other []kvRow           // other label/value rows inside DMI blocks (kept in Values)
	for _, r := range p.rows {
		mi, isDMI := dmi[r.section]
		if !isDMI {
			continue
		}
		c, ok := tableCols[r.table]
		if !ok {
			c = cols{low: 1, high: 2} // default layout: label | Low | High
		}
		if isHeaderRow(r) {
			col := 0
			for _, cl := range r.cells {
				switch strings.ToLower(cl.text) {
				case "low":
					c.low = col
				case "high":
					c.high = col
				}
				col += cl.span
			}
			tableCols[r.table] = c
			continue
		}
		if len(r.cells) < 2 {
			continue
		}
		m := &fs.Measures[mi]
		var lowDst, highDst *model.Threshold
		switch label := normLabel(r.cells[0].text); strings.ToLower(label) {
		case "alarm", "alarms":
			lowDst, highDst = &m.LowAlarm, &m.HighAlarm
		case "warning", "warnings":
			lowDst, highDst = &m.LowWarn, &m.HighWarn
		default:
			if label != "" { // e.g. a firmware adding rows to a DMI table: never drop them
				other = append(other, kvRow{section: m.Name, label: label, value: joinValues(r.cells[1:])})
			}
			continue
		}
		col := r.cells[0].span
		for _, cl := range r.cells[1:] {
			switch col {
			case c.low:
				*lowDst = parseThreshold(cl.text)
			case c.high:
				*highDst = parseThreshold(cl.text)
			}
			col += cl.span
		}
	}
	for _, m := range fs.Measures {
		values.put(m.Name+"/Current", m.CurrentRaw)
		for _, th := range []struct {
			label string
			t     model.Threshold
		}{{"Low Alarm", m.LowAlarm}, {"High Alarm", m.HighAlarm}, {"Low Warning", m.LowWarn}, {"High Warning", m.HighWarn}} {
			if th.t.Raw != "" {
				values.put(m.Name+"/"+th.label, th.t.Raw)
			}
		}
	}
	for _, r := range other {
		values.put(r.section+"/"+r.label, r.value)
	}

	// Label/value rows of the status table(s).
	matched := 0
	seen := map[string]bool{}
	for _, r := range p.rows {
		if _, isDMI := dmi[r.section]; isDMI || len(r.cells) < 2 || isHeaderRow(r) {
			continue
		}
		label := normLabel(r.cells[0].text)
		if label == "" {
			continue
		}
		value := joinValues(r.cells[1:])
		values.put(label, value)
		key := strings.ToLower(label)
		if seen[key] {
			continue
		}
		seen[key] = true
		var dst *string
		switch key {
		case "optical wan operational status":
			dst = &fs.OpticalStatus
		case "fiber module":
			dst = &fs.FiberModule
		case "last change":
			fs.LastChangeRaw = value
			if n := parseInt64(value); n != nil {
				fs.LastChangeUnix = *n
			}
			matched++
		case "link state":
			dst = &fs.LinkState
		case "wave length", "wavelength":
			dst = &fs.WaveLength
		case "vendor name":
			dst = &fs.VendorName
		case "vendor pn":
			dst = &fs.VendorPN
		case "vendor sn":
			dst = &fs.VendorSN
		case "rx los state":
			dst = &fs.RxLOSState
		case "opt los":
			dst = &fs.OptLOS
		case "tx fault state":
			dst = &fs.TxFaultState
		}
		if dst != nil {
			*dst = value
			matched++
		}
	}
	if matched == 0 && len(fs.Measures) == 0 {
		return nil, fmt.Errorf("fiberstat: %w (no Fiber Status rows)", ErrUnexpectedPage)
	}
	return fs, nil
}

// ---------------------------------------------------------------- lanstatistics

// maxColumns bounds the header width ParseLAN expands from colspan attributes.
const maxColumns = 256

// ParseLAN is a light parse of lanstatistics.ha (the raw page is the evidence). Two-column
// rows become "Section/Label"; rows of multi-column tables become "Section/Label/Column"
// using the table's header row (e.g. "Wi-Fi Status/Mode/5 GHz", "LAN Ethernet
// Statistics/State/Port 1", "Interfaces/Wi-Fi 5 GHz/Status"); a row with a single value
// cell keeps the "Section/Label" form.
func ParseLAN(body []byte) (*model.LANStatus, error) { return parseLAN(scan(body)) }

func parseLAN(p *page) (*model.LANStatus, error) {
	if p.isLogin() {
		return nil, fmt.Errorf("lanstatistics: %w", ErrLoginRequired)
	}
	ls := &model.LANStatus{Values: map[string]string{}}
	values := newValueSet(ls.Values)
	headers := map[int][]string{} // table index -> column headers (expanded by colspan)
	for _, r := range p.rows {
		if isHeaderRow(r) {
			var h []string
		expand:
			for _, c := range r.cells {
				for i := 0; i < c.span; i++ {
					if len(h) == maxColumns {
						break expand
					}
					h = append(h, c.text)
				}
			}
			headers[r.table] = h
			continue
		}
		if len(r.cells) < 2 {
			continue
		}
		label := normLabel(r.cells[0].text)
		if label == "" {
			continue
		}
		base := sectionKey(p.sectionName(r.section), label)
		vals := r.cells[1:]
		hdr := headers[r.table]
		if len(vals) == 1 || hdr == nil {
			values.put(base, joinValues(vals))
			continue
		}
		col := r.cells[0].span
		for i, c := range vals {
			name := ""
			if col < len(hdr) {
				name = normLabel(hdr[col])
			}
			if name == "" {
				name = "col" + strconv.Itoa(i+2)
			}
			values.put(base+"/"+name, c.text)
			col += c.span
		}
	}
	if len(ls.Values) == 0 {
		return nil, fmt.Errorf("lanstatistics: %w (no rows)", ErrUnexpectedPage)
	}
	return ls, nil
}

// ---------------------------------------------------------------- events (notification)

// ParseNotification reports whether the "Broadband Status Notification" checkbox
// (name="bbevent") on events.ha is checked, i.e. whether the gateway redirects web browsing
// to AT&T instructional pages while the WAN is down.
func ParseNotification(body []byte) (enabled bool, err error) { return parseNotification(scan(body)) }

func parseNotification(p *page) (bool, error) {
	found, checked := false, false
	for _, in := range p.inputs {
		if in.name != "bbevent" {
			continue
		}
		if in.typ == "checkbox" {
			return in.checked, nil
		}
		if !found {
			found, checked = true, in.checked
		}
	}
	if found {
		return checked, nil
	}
	if p.isLogin() {
		return false, fmt.Errorf("events: %w", ErrLoginRequired)
	}
	return false, fmt.Errorf("events: %w (no bbevent checkbox)", ErrUnexpectedPage)
}
