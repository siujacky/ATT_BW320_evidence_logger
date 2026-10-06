package gateway

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/net/html"

	"attmonitor/internal/model"
)

// The Network page's readers (docs/syslog-map-graphic.md §2.1): the NAT table - every
// connection the gateway is translating at the moment it is read - and the Device List - the
// names and addresses of the devices of the home network, which name the NAT table's LAN
// addresses. What they read describes the household's own traffic, not the gateway's faults, so
// none of it is evidence. Both only read: neither page's form is ever posted, because posting it
// would change something on the gateway (the NAT table's display selection; the Device List's
// "Clear and Rescan for Devices" empties the gateway's device table), and the monitor never
// changes the gateway to watch it.

const (
	natPage     = "nattable" // Diagnostics > NAT Table: behind the login
	devicesPage = "devices"  // Device > Device List: readable without login
)

// Errors of the Network page's readers. Neither has a counterpart in internal/contracts: the
// monitor shows them as the sampler's problem and does not react to them otherwise.
var (
	// ErrNATPage means the NAT table page is not understood: no table on it has a header row
	// naming a source and a destination address column. The page is still returned as raw, so
	// that what the gateway showed can be looked at.
	ErrNATPage = errors.New("gateway: NAT table page not understood")
	// ErrDevicesPage means the page is not understood as the Device List: no table on it has the
	// Device List's rows (a "MAC Address" or "IPv4 Address / Name" row together with rows such as
	// "Last Activity" or "Connection Type"), so no device can be read from it. A Device List
	// without devices is not an error.
	ErrDevicesPage = errors.New("gateway: Device List page not understood")
)

// ---------------------------------------------------------------- Client

// NATTable reads the NAT table page (Diagnostics > NAT Table, nattable.ha; see ParseNATTable).
// The page needs the login, so the read goes through the login policy (see the error variables
// of auth.go: one attempt a minute, none after three rejections within an hour, none while the
// gateway's session pool is full) and shares the session with the other authenticated
// operations: within 5 minutes of the previous authenticated request it reuses that session and
// costs one GET, which is why the monitor reads it every 4 minutes at most. A read that fails
// otherwise than with the login page - an error status, a page over NATMaxBodyBytes or not read
// whole in time - keeps the session (authPage): it never leads to a new login by itself. It only
// reads: the page's "Select display option" form is never posted. raw is the exact page read, also
// returned with a parse error, and as much of it as arrived with such a failure; with an error the
// table is empty and its totals unknown (-1).
func (c *Client) NATTable(ctx context.Context) (model.NATTable, []byte, error) {
	if err := c.acquire(ctx); err != nil {
		return noNATTable(), nil, err
	}
	defer c.release()
	_, body, err := c.authPage(ctx, natPage)
	if err != nil {
		return noNATTable(), body, err
	}
	t, err := ParseNATTable(body)
	if err != nil {
		return noNATTable(), body, err
	}
	c.log.Debug("gateway NAT table read", "sessions", len(t.Sessions), "skipped", t.Skipped,
		"in_use", t.InUse, "available", t.Available)
	return t, body, nil
}

// Devices reads the Device List page (devices.ha; see ParseDevices) the way Snapshot reads the
// status pages: one GET without login, in the status pages' own cookie session - never in the
// authenticated one - so it costs no login and is not subject to the login policy. It only
// reads: the page's form (a nonce and the "Clear and Rescan for Devices" button, which empties
// the gateway's device table) is never posted. A login page in its place is ErrLoginRequired
// (no login is attempted), and "all web server sessions are in use" pauses the logins as on any
// page (ErrSessionsFull in a *CooldownError, matching contracts.ErrGatewaySessionsFull). raw is
// the exact page read, also returned with an error once an answer arrived.
func (c *Client) Devices(ctx context.Context) ([]model.LANDevice, []byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, fmt.Errorf("gateway: GET %s.ha: %w", devicesPage, err)
	}
	ex := c.do(ctx, c.snapClient, http.MethodGet, c.pageURL(devicesPage), "", "")
	if !ex.responded {
		return nil, nil, fmt.Errorf("gateway: GET %s.ha: %w", devicesPage, ex.err)
	}
	p := scan(ex.body)
	c.log.Debug("gateway page fetched", "page", devicesPage, "status", ex.status, "bytes", len(ex.body),
		"dur_ms", ex.dur.Milliseconds(), "login_page", p.isLogin())
	switch {
	case ex.err != nil: // the body could not be read whole
		return nil, ex.body, fmt.Errorf("gateway: GET %s.ha: %w", devicesPage, ex.err)
	case p.sessionsFull():
		return nil, ex.body, fmt.Errorf("gateway: GET %s.ha: %w", devicesPage, c.noteSessionsFull())
	case p.isLogin(), isLoginRedirect(ex):
		return nil, ex.body, fmt.Errorf("gateway: GET %s.ha: %w", devicesPage, ErrLoginRequired)
	case ex.status != http.StatusOK:
		return nil, ex.body, fmt.Errorf("gateway: GET %s.ha: unexpected HTTP status %s", devicesPage, statusText(ex.status))
	}
	devices, err := parseDevices(p, ex.body)
	if err != nil {
		return nil, ex.body, err
	}
	return devices, ex.body, nil
}

// ---------------------------------------------------------------- NAT table

// ParseNATTable parses the NAT table page (nattable.ha): a table with the columns "Protocol", "TCP
// State", "Source Address", "Source Port", "Destination Address" and "Destination Port" (one row
// per session), the rows "Total sessions available" and "Total sessions in use", and a list of the
// clients to display. On the real page (firmware 6.34.7, testdata/gateway/nattable_real.html) the
// table has fourteen columns - also "IP Family", "Protocol Number", "Lifetime", the translated "NAT
// Source/Destination Address/Port" and "Bidirectional" - and lists IPv6 connections too; a session
// is the connection as the device opened it, never its translated columns. The parser goes by the
// labels, never by positions, and accepts what may differ on another firmware:
//
//   - The session table is any table with a header row (<th> or <td> cells) naming a source and
//     a destination address column. Labels are compared by alnumKey (case, white space and
//     punctuation aside) and close variants are accepted ("Src IP", "Dest Port", "Proto",
//     "State", ...), in any order; columns it does not know are ignored. A header repeated
//     within the table, and every further table with such a header, are read too.
//   - Every later row of that table with at least two non-empty cells and a digit is a session
//     (rows without, such as "No sessions" or a sub-header, are not). An address cell may carry
//     the port as well ("192.0.2.1:443", "[2001:db8::1]:443"); the port column wins when it holds
//     a number. Addresses are kept in canonical form, IPv6 ones as IPv6. The protocol is lower
//     case (the numbers 1, 6, 17 and 58 named); an empty, "-" or "N/A" protocol or TCP State is
//     "", as the TCP State of UDP and ICMP sessions; a port that is not a number is 0. A row
//     whose cells do not line up with the header (a cell left out) is read by its content when it
//     holds exactly two addresses. A row that cannot be read - an address that is not an IP
//     address, a missing column - is counted in Skipped, never fatal.
//   - InUse and Available come from the rows "Total sessions in use" and "Total sessions
//     available" (labels compared as above), or from the page's text ("Total sessions in use:
//     123"); -1 when the page shows neither.
//   - Display is the text of the option selected in the "Select display option" list (else in
//     the page's only list); "" when there is none.
//
// The page's sloppy markup (unclosed rows and cells, stray end tags), windows-1252 bytes and any
// line endings do not matter (scan.go). A page with no session header at all is ErrNATPage; one
// whose session table has no rows has no sessions. The login page is ErrLoginRequired. The work
// is linear in the size of the page.
func ParseNATTable(body []byte) (model.NATTable, error) {
	p := scan(body)
	if p.isLogin() {
		return noNATTable(), fmt.Errorf("nattable: %w", ErrLoginRequired)
	}
	t := model.NATTable{Sessions: []model.NATSession{}}
	headers := map[int]natHeader{} // table index -> the session header read last in that table
	for _, r := range p.rows {
		if h, ok := natHeaderOf(r); ok {
			headers[r.table] = h
			continue
		}
		h, ok := headers[r.table]
		if !ok || !natDataRow(r) {
			continue
		}
		if s, ok := h.session(r.cells); ok {
			t.Sessions = append(t.Sessions, s)
		} else {
			t.Skipped++
		}
	}
	if len(headers) == 0 {
		return noNATTable(), fmt.Errorf("%w: no table has the session columns (%q and %q)",
			ErrNATPage, "Source Address", "Destination Address")
	}
	t.InUse, t.Available = natTotals(p)
	t.Display = natDisplay(body)
	return t, nil
}

// noNATTable is the table returned with an error: no sessions, totals unknown.
func noNATTable() model.NATTable { return model.NATTable{InUse: -1, Available: -1} }

// natColumn is what a column of the session table holds.
type natColumn int

const (
	natColNone natColumn = iota
	natColProto
	natColState
	natColSrcAddr // an address; its cells may carry the port too
	natColSrcPort
	natColDstAddr
	natColDstPort
	natColumns // the number of kinds
)

// natSides are the label prefixes that name a session's two ends, longest first ("dest" is a
// prefix of "destination"), with the columns of each end.
var natSides = []struct {
	prefix     string
	addr, port natColumn
}{
	{"destination", natColDstAddr, natColDstPort},
	{"dest", natColDstAddr, natColDstPort},
	{"dst", natColDstAddr, natColDstPort},
	{"source", natColSrcAddr, natColSrcPort},
	{"src", natColSrcAddr, natColSrcPort},
}

// natColumnOf classifies a header label (see ParseNATTable): "Source Address", "Src IP",
// "Source" and "Source Address:Port" are the source's address column, "Source Port" and
// "SPort" its port; the same for the destination; "Protocol"/"Proto" the protocol, "TCP State",
// "State" and "Status" the state. Anything else - "Translated Address", "Source MAC",
// "Timeout" - is not a session column.
func natColumnOf(label string) natColumn {
	k := alnumKey(label)
	switch k {
	case "sport":
		return natColSrcPort
	case "dport":
		return natColDstPort
	case "saddr", "sip":
		return natColSrcAddr
	case "daddr", "dip":
		return natColDstAddr
	}
	for _, side := range natSides {
		rest, ok := strings.CutPrefix(k, side.prefix)
		if !ok {
			continue
		}
		switch {
		case rest == "", strings.HasPrefix(rest, "addr"), strings.HasPrefix(rest, "ip"), strings.HasPrefix(rest, "host"):
			return side.addr
		case strings.HasPrefix(rest, "port"):
			return side.port
		}
		return natColNone
	}
	switch {
	case k == "proto", k == "prot", strings.HasPrefix(k, "protocol"), strings.HasSuffix(k, "protocol"):
		return natColProto
	case k == "status", k == "tcpstatus", strings.HasSuffix(k, "state"):
		return natColState
	}
	return natColNone
}

// natHeader is a session table's header row: the column of each kind it names (-1 when it names
// none), counted in columns - a cell spanning n columns takes n.
type natHeader struct {
	col [natColumns]int
	// srcFirst: the source columns come before the destination columns (the order a row read by
	// its content assumes).
	srcFirst bool
}

// natHeaderOf reads r as a session table's header row: ok when it names a source and a
// destination address column (the first cell of each kind counts). An address column spanning
// two or more columns, with no port column for its side, is the address followed by the port
// (a "Source" heading over both).
func natHeaderOf(r row) (h natHeader, ok bool) {
	if len(r.cells) < 2 {
		return h, false
	}
	for i := range h.col {
		h.col[i] = -1
	}
	var spans [natColumns]int
	pos := 0
	for _, c := range r.cells {
		if c.text != "" && pos < maxColumns {
			if k := natColumnOf(c.text); k != natColNone && h.col[k] < 0 {
				h.col[k], spans[k] = pos, c.span
			}
		}
		pos += c.span
	}
	if h.col[natColSrcAddr] < 0 || h.col[natColDstAddr] < 0 {
		return h, false
	}
	for _, side := range [][2]natColumn{{natColSrcAddr, natColSrcPort}, {natColDstAddr, natColDstPort}} {
		if addr, port := side[0], side[1]; h.col[port] < 0 && spans[addr] >= 2 {
			h.col[port] = h.col[addr] + 1
		}
	}
	h.srcFirst = h.col[natColSrcAddr] < h.col[natColDstAddr]
	return h, true
}

// natDataRow reports whether a row below a session header can be a session: at least two
// non-empty cells and a digit somewhere (every session has an address), and not a totals row
// ("Total sessions in use | 25").
func natDataRow(r row) bool {
	n, digit, first := 0, false, ""
	for _, c := range r.cells {
		if c.text == "" {
			continue
		}
		if n == 0 {
			first = c.text
		}
		n++
		digit = digit || strings.ContainsAny(c.text, "0123456789")
	}
	return n >= 2 && digit && !strings.Contains(alnumKey(first), "session")
}

// cellAt returns the text of the cell covering column col ("" when col < 0 or the row is
// shorter).
func cellAt(cells []cell, col int) string {
	if col < 0 {
		return ""
	}
	pos := 0
	for _, c := range cells {
		pos += c.span
		if col < pos {
			return c.text
		}
	}
	return ""
}

// session reads a data row by the header's columns; a row whose addresses are not where the
// header says is read by its content (salvage).
func (h natHeader) session(cells []cell) (model.NATSession, bool) {
	src, sport, okSrc := natEndpoint(cellAt(cells, h.col[natColSrcAddr]), cellAt(cells, h.col[natColSrcPort]))
	dst, dport, okDst := natEndpoint(cellAt(cells, h.col[natColDstAddr]), cellAt(cells, h.col[natColDstPort]))
	if !okSrc || !okDst {
		return h.salvage(cells)
	}
	return model.NATSession{
		Proto:   natProto(cellAt(cells, h.col[natColProto])),
		State:   natState(cellAt(cells, h.col[natColState])),
		Src:     src,
		SrcPort: sport,
		Dst:     dst,
		DstPort: dport,
	}, true
}

// natKnownProtocols are the protocol names by which a row read by its content shows its protocol.
var natKnownProtocols = map[string]bool{
	"tcp": true, "udp": true, "icmp": true, "icmpv6": true, "ipv6-icmp": true, "gre": true,
	"esp": true, "ah": true, "sctp": true, "igmp": true, "udplite": true,
}

// reWord matches a cell that is a word or two of letters, such as a TCP state ("ESTABLISHED",
// "TIME_WAIT", "Time Wait").
var reWord = regexp.MustCompile(`^[A-Za-z][A-Za-z_ -]{2,23}$`)

// salvage reads a row whose cells do not line up with the header - most likely a cell the
// gateway leaves out, such as an empty TCP State - by its content. It needs exactly two cells
// that hold an address: the first is the source when the header's source columns come first.
// When the header has a port column for a side, the cell right after that side's address is its
// port if it holds a port number; the protocol is a cell naming a known protocol, the state
// another cell that is a word (not a protocol's name), each only when the header has such a
// column. Anything else is not read (false): the row is counted as skipped.
func (h natHeader) salvage(cells []cell) (model.NATSession, bool) {
	type endpoint struct {
		cell int
		addr string
		port int
	}
	var eps []endpoint
	used := make([]bool, len(cells))
	for i, c := range cells {
		if a, port, _, ok := parseEndpoint(c.text); ok {
			if len(eps) == 2 {
				return model.NATSession{}, false
			}
			eps = append(eps, endpoint{cell: i, addr: a.Unmap().String(), port: port})
			used[i] = true
		}
	}
	if len(eps) != 2 {
		return model.NATSession{}, false
	}
	src, dst := eps[0], eps[1]
	if !h.srcFirst {
		src, dst = dst, src
	}
	for _, e := range []struct {
		ep   *endpoint
		port natColumn
	}{{&src, natColSrcPort}, {&dst, natColDstPort}} {
		if i := e.ep.cell + 1; h.col[e.port] >= 0 && i < len(cells) && !used[i] {
			if n, ok := natPortNumber(cells[i].text); ok {
				e.ep.port, used[i] = n, true
			}
		}
	}
	s := model.NATSession{Src: src.addr, SrcPort: src.port, Dst: dst.addr, DstPort: dst.port}
	if h.col[natColProto] >= 0 {
		for i, c := range cells {
			if p := strings.ToLower(c.text); !used[i] && natKnownProtocols[p] {
				s.Proto, used[i] = p, true
				break
			}
		}
	}
	if h.col[natColState] >= 0 {
		for i, c := range cells {
			if !used[i] && reWord.MatchString(c.text) && !natKnownProtocols[strings.ToLower(c.text)] {
				s.State = natState(c.text)
				break
			}
		}
	}
	return s, true
}

// natEndpoint reads one end of a session: its address cell (which may carry the port) and its
// port cell (which wins when it holds a port number). ok is false when the address cell does not
// hold an IP address.
func natEndpoint(addrText, portText string) (addr string, port int, ok bool) {
	a, p, _, ok := parseEndpoint(addrText)
	if !ok {
		return "", 0, false
	}
	if n, isPort := natPortNumber(portText); isPort {
		p = n
	}
	return a.Unmap().String(), p, true
}

// parseEndpoint reads a cell holding an IP address, possibly with a port: "192.0.2.1",
// "192.0.2.1:443", "192.0.2.1 : 443", "2001:db8::1", "[2001:db8::1]" and "[2001:db8::1]:443".
// Text after the address and a space is an annotation and ignored ("192.0.2.1 (example)").
func parseEndpoint(s string) (addr netip.Addr, port int, hasPort, ok bool) {
	if strings.Contains(s, " :") || strings.Contains(s, ": ") {
		s = strings.ReplaceAll(strings.ReplaceAll(s, " :", ":"), ": ", ":")
	}
	if i := strings.IndexByte(s, ' '); i >= 0 {
		s = s[:i]
	}
	if s == "" {
		return netip.Addr{}, 0, false, false
	}
	if a, ok := parseIPText(s); ok {
		return a, 0, false, true
	}
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return ap.Addr().WithZone(""), int(ap.Port()), true, true
	}
	return netip.Addr{}, 0, false, false
}

// parseIPText reads an IP address as a page may show it: plain, in brackets, with a zone (which
// is dropped: it names an interface of the gateway), or an IPv4 address with zero-padded parts
// ("192.168.001.010"), which netip refuses.
func parseIPText(s string) (netip.Addr, bool) {
	if len(s) > 2 && s[0] == '[' && s[len(s)-1] == ']' {
		s = s[1 : len(s)-1]
	}
	if a, err := netip.ParseAddr(s); err == nil {
		return a.WithZone(""), true
	}
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return netip.Addr{}, false
	}
	var b [4]byte
	for i, part := range parts {
		n, err := strconv.Atoi(part)
		if err != nil || len(part) == 0 || len(part) > 3 || part[0] == '+' || part[0] == '-' || n > 255 {
			return netip.Addr{}, false
		}
		b[i] = byte(n)
	}
	return netip.AddrFrom4(b), true
}

// natPortNumber reads a port cell: a number from 0 to 65535, alone or followed by a space or a
// parenthesis ("443 (https)"). ok is false for anything else ("", "-", "N/A", "1.2.3.4:80").
func natPortNumber(s string) (port int, ok bool) {
	i := 0
	for i < len(s) && i <= 5 && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	if i == 0 || i > 5 || i < len(s) && s[i] != ' ' && s[i] != '(' {
		return 0, false
	}
	n, _ := strconv.Atoi(s[:i]) // at most 5 digits: cannot fail
	if n > 65535 {
		return 0, false
	}
	return n, true
}

// natProtocolNumbers name the IP protocol numbers a NAT table may show instead of names.
var natProtocolNumbers = map[string]string{"1": "icmp", "6": "tcp", "17": "udp", "58": "icmpv6"}

// natProto returns a protocol cell in lower case ("TCP" -> "tcp", "6" -> "tcp"), "" for a
// placeholder.
func natProto(s string) string {
	p := strings.ToLower(s)
	if name, ok := natProtocolNumbers[p]; ok {
		return name
	}
	if placeholder(p) {
		return ""
	}
	return p
}

// natState returns a TCP State cell as shown, "" for a placeholder (UDP and ICMP sessions).
func natState(s string) string {
	if placeholder(s) {
		return ""
	}
	return s
}

// placeholder reports whether a cell holds no value: nothing, only punctuation ("-", "--",
// "*") or "N/A".
func placeholder(s string) bool {
	k := alnumKey(s)
	return k == "" || k == "na"
}

// reNATTotal finds the totals in the page's text when no row holds them: "Total sessions in
// use: 123", "Sessions available 8,192", "Available sessions: 8192".
var reNATTotal = regexp.MustCompile(`(?i)\b(?:sessions?\s+(in\s+use|available)|(available)\s+sessions?)\s*[:=]?\s*(\d[\d,]{0,12})\b`)

// natTotals returns "Total sessions in use" and "Total sessions available" (-1 when absent):
// from a label/value row whose label names sessions and "in use" (or "used") or "available",
// else from the page's text. The first one found of each counts.
func natTotals(p *page) (inUse, available int) {
	inUse, available = -1, -1
	for _, r := range p.rows {
		if len(r.cells) < 2 || isHeaderRow(r) {
			continue
		}
		k := alnumKey(r.cells[0].text)
		if !strings.Contains(k, "session") {
			continue
		}
		n := leadingCount(joinValues(r.cells[1:]))
		switch {
		case n < 0:
		case inUse < 0 && (strings.Contains(k, "inuse") || strings.Contains(k, "used") && !strings.Contains(k, "unused")):
			inUse = n
		case available < 0 && strings.Contains(k, "available"):
			available = n
		}
	}
	if inUse >= 0 && available >= 0 {
		return inUse, available
	}
	for _, m := range reNATTotal.FindAllStringSubmatch(p.text, -1) {
		kind := strings.ToLower(m[1]) // "in use" or "available" ("sessions in use 25")
		if m[2] != "" {
			kind = "available" // "available sessions 8192"
		}
		n := leadingCount(m[3])
		switch {
		case n < 0:
		case inUse < 0 && kind != "available":
			inUse = n
		case available < 0 && kind == "available":
			available = n
		}
	}
	return inUse, available
}

// maxCount bounds a count read from the page (a gateway shows thousands of sessions).
const maxCount = 1 << 30

// leadingCount reads the number a value starts with ("356", "8,192", "356 of 8192"): -1 when it
// starts with none, or when the number runs into something other than a space or a parenthesis
// ("1.5", "12abc").
func leadingCount(v string) int {
	v = strings.TrimSpace(v)
	i := 0
	for i < len(v) && (v[i] >= '0' && v[i] <= '9' || v[i] == ',' && i > 0) {
		i++
	}
	if i == 0 || i < len(v) && v[i] != ' ' && v[i] != '(' {
		return -1
	}
	digits := strings.ReplaceAll(v[:i], ",", "")
	if len(digits) > 10 {
		return -1
	}
	n, err := strconv.Atoi(digits)
	if err != nil || n > maxCount {
		return -1
	}
	return n
}

// natDisplay returns the text of the option selected in the "Select display option" list - a
// list whose label or table row mentions "display" - else in the page's only list ("" when
// there is none, or several and none of them so labelled). As in a browser, a drop-down list
// with no option marked selected shows its first enabled option.
func natDisplay(body []byte) string {
	var only *formControl
	lists := 0
	for _, f := range parseForms(body) {
		for _, c := range f.controls {
			if c.tag != "select" {
				continue
			}
			if strings.Contains(c.labelKey, "display") || strings.Contains(c.rowKey, "display") {
				return selectedText(c)
			}
			only, lists = c, lists+1
		}
	}
	if lists == 1 {
		return selectedText(only)
	}
	return ""
}

// selectedText returns the text of a list's first selected option (its value when it has no
// text), "" when none is selected.
func selectedText(c *formControl) string {
	for _, o := range c.options {
		if !o.selected {
			continue
		}
		if o.text != "" {
			return o.text
		}
		return o.value
	}
	return ""
}

// ---------------------------------------------------------------- Device List

// ParseDevices parses the Device List page (devices.ha), as captured from the owner's gateway
// (firmware 6.34.7; testdata/gateway/devices_real.html): one table in which each device is a
// block of label rows (<th scope="row"> label, <td> value), the blocks separated by a row holding
// only an <hr>. The labels, compared by alnumKey:
//
//   - "MAC Address": MAC, lower case and colon separated ("" when it is not a MAC address, or
//     all zeros: such a value cannot identify a device).
//   - "IPv4 Address / Name" ("192.168.1.101 / laptop"), or just "Name" for a device without an
//     IPv4 address: IPv4 (canonical; "" when it is not an IPv4 address) and Name, as shown.
//   - "Last Activity", "Status", "Allocation": as shown.
//   - "Connection Type": a <pre> of lines such as "Wi-Fi", "5 GHz Radio-1", "Type: Home" and
//     "Name: <the Wi-Fi network's name>", or "Ethernet LAN-1". Connection summarizes it as
//     "Wi-Fi 5 GHz", "Wi-Fi 2.4 GHz", "Wi-Fi", "Ethernet LAN-1" or "Ethernet" (see
//     connectionSummary); the Wi-Fi network's name is never kept.
//   - "Connection Speed": as shown, "" when it holds no number (an Ethernet port that is down
//     shows the bare template "Mbps duplex").
//   - "Mesh Client": Mesh is true for "Yes".
//   - "IPv6 Address", repeated with its "Type", "Valid Lifetime" and "Preferred Lifetime":
//     IPv6 lists the IPv6 addresses (canonical, each once).
//
// Other labels are ignored. Only a table with a row that identifies a device and a row that only
// the Device List has is read (see devicesFrom), so that the gateway's own "MAC Address" on the
// status pages is never taken for a device. A label met a second time in a block (other than the
// IPv6 ones) starts the next device, should the separator rows go missing, and a block that names
// neither a MAC, an IPv4 address, a name nor an IPv6 address is left out. The gateway's sloppy
// markup - rows such as "<th>Connection Speed</th></td></tr>" without a value cell - is read as
// an empty value. A Device List without devices (no such table, and no other rows with values,
// on a page titled "Device List") gives an empty list; any other page is ErrDevicesPage, the
// login page ErrLoginRequired.
func ParseDevices(body []byte) ([]model.LANDevice, error) { return parseDevices(scan(body), body) }

// parseDevices parses the Device List: p is body scanned (for the login page, the title and the
// headings); the device rows are read again by readLineRows, which keeps each cell's lines.
func parseDevices(p *page, body []byte) ([]model.LANDevice, error) {
	if p.isLogin() {
		return nil, fmt.Errorf("devices: %w", ErrLoginRequired)
	}
	rows := readLineRows(body)
	devices, found := devicesFrom(rows)
	if found {
		return devices, nil
	}
	// No device table: a Device List without devices, or a page that is not understood.
	for _, r := range rows {
		filled := 0
		for _, c := range r.cells {
			if len(c.lines) > 0 {
				filled++
			}
		}
		if filled >= 2 {
			return nil, fmt.Errorf("%w: no table with the Device List's rows (%q, %q, %q, ...)",
				ErrDevicesPage, "MAC Address", "IPv4 Address / Name", "Last Activity")
		}
	}
	if !isDevicesPage(p) {
		return nil, fmt.Errorf("%w: neither device rows nor the Device List's title", ErrDevicesPage)
	}
	return []model.LANDevice{}, nil
}

// isDevicesPage reports whether the page says it is the Device List: its title or a heading.
func isDevicesPage(p *page) bool {
	if alnumKey(p.title) == "devicelist" {
		return true
	}
	for _, h := range p.headings {
		if k := alnumKey(h); k == "devicelist" || k == "homenetworkdevices" {
			return true
		}
	}
	return false
}

// deviceField is the device property a Device List label sets.
type deviceField int

const (
	devNone deviceField = iota
	devMAC
	devName
	devIPv4Name // "IPv4 Address / Name"
	devIPv4
	devLastActivity
	devStatus
	devAllocation
	devConnection
	devSpeed
	devMesh
	devIPv6
	devFields // the number of fields
)

// deviceFields maps the alnumKey of a Device List label to the field it sets.
var deviceFields = map[string]deviceField{
	"macaddress":        devMAC,
	"mac":               devMAC,
	"name":              devName,
	"devicename":        devName,
	"hostname":          devName,
	"ipv4addressname":   devIPv4Name,
	"ipaddressname":     devIPv4Name,
	"ipv4address":       devIPv4,
	"ipaddress":         devIPv4,
	"lastactivity":      devLastActivity,
	"status":            devStatus,
	"allocation":        devAllocation,
	"connectiontype":    devConnection,
	"connectionspeed":   devSpeed,
	"meshclient":        devMesh,
	"ipv6address":       devIPv6,
	"globalipv6address": devIPv6,
}

// deviceBuilder collects the rows of one device block.
type deviceBuilder struct {
	d    model.LANDevice
	seen [devFields]bool
	ipv6 map[string]bool
}

// set applies one label row to the device. value is the row's value cells: their text, and
// their lines for "Connection Type".
func (b *deviceBuilder) set(f deviceField, cells []lineCell) {
	b.seen[f] = true
	var lines []string
	for _, c := range cells {
		lines = append(lines, c.lines...)
	}
	value := normSpace(strings.Join(lines, " "))
	d := &b.d
	switch f {
	case devMAC:
		d.MAC = deviceMAC(value)
	case devName:
		if d.Name == "" {
			d.Name = value
		}
	case devIPv4Name:
		addr, name, found := strings.Cut(value, "/")
		if !found {
			if a, ok := deviceIPv4(value); ok {
				d.IPv4 = a
			} else if d.Name == "" {
				d.Name = value
			}
			return
		}
		if a, ok := deviceIPv4(strings.TrimSpace(addr)); ok {
			d.IPv4 = a
		}
		if name = strings.TrimSpace(name); name != "" && d.Name == "" {
			d.Name = name
		}
	case devIPv4:
		if a, ok := deviceIPv4(value); ok {
			d.IPv4 = a
		}
	case devLastActivity:
		d.LastActivity = value
	case devStatus:
		d.Status = value
	case devAllocation:
		d.Allocation = value
	case devConnection:
		d.Connection = connectionSummary(lines)
	case devSpeed:
		if strings.ContainsAny(value, "0123456789") {
			d.Speed = value
		}
	case devMesh:
		d.Mesh = strings.EqualFold(value, "yes")
	case devIPv6:
		a, ok := parseIPText(value)
		if !ok || !a.Is6() {
			return
		}
		s := a.String()
		if b.ipv6 == nil {
			b.ipv6 = map[string]bool{}
		}
		if !b.ipv6[s] {
			b.ipv6[s] = true
			d.IPv6 = append(d.IPv6, s)
		}
	}
}

// identified reports whether the block names the device in a way that can be used: by MAC, by
// IPv4 or IPv6 address, or by name.
func (b *deviceBuilder) identified() bool {
	return b.d.MAC != "" || b.d.IPv4 != "" || b.d.Name != "" || len(b.d.IPv6) > 0
}

// devicesFrom groups the label rows of the Device List's table(s) into devices (see
// ParseDevices). A Device List table has a row that identifies a device ("MAC Address", "IPv4
// Address / Name" or "IPv4 Address") and a row that only the Device List has ("IPv4 Address /
// Name", "Last Activity", "Allocation", "Connection Type", "Connection Speed" or "Mesh Client"):
// the status pages have "MAC Address" and "IP Address" rows too - the gateway's own, which must
// never be taken for a device. found reports whether there is such a table at all.
func devicesFrom(rows []lineRow) (devices []model.LANDevice, found bool) {
	identifies, listOnly := map[int]bool{}, map[int]bool{}
	for _, r := range rows {
		if len(r.cells) == 0 {
			continue
		}
		switch deviceFields[alnumKey(r.cells[0].text())] {
		case devIPv4Name:
			identifies[r.table], listOnly[r.table] = true, true
		case devMAC, devIPv4:
			identifies[r.table] = true
		case devLastActivity, devAllocation, devConnection, devSpeed, devMesh:
			listOnly[r.table] = true
		}
	}
	tables := map[int]bool{}
	for t := range identifies {
		if listOnly[t] {
			tables[t] = true
		}
	}
	devices = []model.LANDevice{}
	var cur *deviceBuilder
	flush := func() {
		if cur != nil && cur.identified() {
			devices = append(devices, cur.d)
		}
		cur = nil
	}
	last := -1
	for _, r := range rows {
		if !tables[r.table] {
			continue
		}
		if r.table != last {
			flush()
			last = r.table
		}
		if r.rule && r.empty() {
			flush() // the separator between two devices
			continue
		}
		if len(r.cells) == 0 {
			continue
		}
		f := deviceFields[alnumKey(r.cells[0].text())]
		if f == devNone {
			continue
		}
		if cur != nil && f != devIPv6 && cur.seen[f] {
			flush() // a label met again: the next device (its separator row is missing)
		}
		if cur == nil {
			cur = &deviceBuilder{}
		}
		cur.set(f, r.cells[1:])
	}
	flush()
	return devices, len(tables) > 0
}

// deviceMAC returns a MAC address lower case and colon separated, "" when s is not a 48-bit MAC
// address or is all zeros.
func deviceMAC(s string) string {
	hw, err := net.ParseMAC(s)
	if err != nil || len(hw) != 6 {
		return ""
	}
	for _, b := range hw {
		if b != 0 {
			return hw.String()
		}
	}
	return ""
}

// deviceIPv4 returns s as a canonical IPv4 address.
func deviceIPv4(s string) (string, bool) {
	a, ok := parseIPText(s)
	if !ok {
		return "", false
	}
	if a = a.Unmap(); !a.Is4() {
		return "", false
	}
	return a.String(), true
}

var (
	// reWiFiBand finds a Wi-Fi band: "5 GHz Radio-1" -> "5", "2.4GHz" -> "2.4".
	reWiFiBand = regexp.MustCompile(`(?i)\b(\d{1,2}(?:\.\d{1,2})?)\s*GHz\b`)
	// reLANPort finds an Ethernet port: "Ethernet LAN-1" -> "1".
	reLANPort = regexp.MustCompile(`(?i)\bLAN\s*-?\s*(\d{1,2})\b`)
	// reMedium is what an unknown connection medium may look like to be kept as shown.
	reMedium = regexp.MustCompile(`^[A-Za-z0-9 ._()/+-]{1,40}$`)
)

// connectionSummary summarizes the lines of a "Connection Type" cell: "Wi-Fi" with the band
// ("Wi-Fi 5 GHz") or "Ethernet" with the port ("Ethernet LAN-1"), else the first line when it
// is a short plain phrase. Only lines without a colon are read: the cell's "label: value" lines
// - "Type: Home" and above all "Name: <the Wi-Fi network's name>" - are never looked at, so
// that the network's name cannot end up in the summary (the summary itself is built from the
// band and the port, never copied from a line, for Wi-Fi and Ethernet alike).
func connectionSummary(lines []string) string {
	var facts []string
	for _, l := range lines {
		if !strings.Contains(l, ":") {
			facts = append(facts, l)
		}
	}
	for _, l := range facts {
		k := alnumKey(l)
		switch {
		case strings.HasPrefix(k, "wifi"), strings.HasPrefix(k, "wireless"), strings.HasPrefix(k, "wlan"):
			for _, l := range facts {
				if m := reWiFiBand.FindStringSubmatch(l); m != nil {
					return "Wi-Fi " + m[1] + " GHz"
				}
			}
			return "Wi-Fi"
		case strings.HasPrefix(k, "ethernet"), strings.HasPrefix(k, "wired"), reLANPort.MatchString(l):
			for _, l := range facts {
				if m := reLANPort.FindStringSubmatch(l); m != nil {
					return "Ethernet LAN-" + m[1]
				}
			}
			return "Ethernet"
		}
	}
	if len(facts) > 0 && reMedium.MatchString(facts[0]) {
		return facts[0]
	}
	return ""
}

// ---------------------------------------------------------------- reading cells by line

// The Device List's "Connection Type" cell holds several facts, each on its own line (<br>, or
// a line break inside its <pre>), one of them the Wi-Fi network's name, which must be left out.
// scan.go joins a cell's lines into one text, so the Device List's rows are read once more by
// the reader below, which keeps them apart and also notes the <hr> rows that separate devices.
// Like scan.go it uses the x/net/html tokenizer and reads the page in source order.

// lineCell is a table cell read line by line.
type lineCell struct {
	lines []string // visible text lines, white space normalized, empty lines dropped
}

// text returns the cell's lines joined by spaces.
func (c lineCell) text() string { return strings.Join(c.lines, " ") }

// lineRow is one table row: its cells, and whether it holds an <hr>.
type lineRow struct {
	table int // document-order index of the innermost enclosing <table>
	cells []lineCell
	rule  bool
}

// empty reports whether no cell of the row has text (the Device List's separator rows hold
// only an <hr>).
func (r lineRow) empty() bool {
	for _, c := range r.cells {
		if len(c.lines) > 0 {
			return false
		}
	}
	return true
}

// lineTable is an open <table>: its open row and cell.
type lineTable struct {
	index int
	row   *lineRow
	cell  *lineCell
	line  strings.Builder // the open cell's current line
	pre   int             // <pre> elements open in the open cell
}

type lineReader struct {
	rows     []lineRow
	tables   []*lineTable
	count    int    // tables opened so far
	overflow int    // <table> tags ignored beyond maxTableDepth and not yet closed
	skip     string // raw-text element whose content is being skipped
}

// readLineRows returns the table rows of body (any encoding, see decode) with the lines of each
// cell. It never fails: malformed markup yields whatever could be recognized.
func readLineRows(body []byte) []lineRow {
	r := &lineReader{}
	z := html.NewTokenizer(strings.NewReader(decode(body)))
	for {
		switch tt := z.Next(); tt {
		case html.ErrorToken: // io.EOF or a tokenizer error: finish with what we have
			for len(r.tables) > 0 {
				r.closeRow(r.top())
				r.tables = r.tables[:len(r.tables)-1]
			}
			return r.rows
		case html.TextToken:
			r.onText(string(z.Text()))
		case html.StartTagToken, html.SelfClosingTagToken:
			name, _ := z.TagName()
			r.onStart(string(name), tt == html.SelfClosingTagToken)
		case html.EndTagToken:
			name, _ := z.TagName()
			r.onEnd(string(name))
		}
	}
}

func (r *lineReader) top() *lineTable {
	if len(r.tables) == 0 {
		return nil
	}
	return r.tables[len(r.tables)-1]
}

func (r *lineReader) onText(s string) {
	t := r.top()
	if r.skip != "" || t == nil || t.cell == nil {
		return
	}
	if t.pre == 0 {
		t.line.WriteString(s)
		return
	}
	// Inside <pre> a line break is a line break.
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	for {
		i := strings.IndexByte(s, '\n')
		if i < 0 {
			t.line.WriteString(s)
			return
		}
		t.line.WriteString(s[:i])
		r.breakLine(t)
		s = s[i+1:]
	}
}

func (r *lineReader) onStart(tag string, selfClosing bool) {
	if r.skip != "" {
		return
	}
	if !inlineTags[tag] {
		r.breakLine(r.top()) // "<br>", "<p>", "<div>": a new line
	}
	switch tag {
	case "table":
		if selfClosing {
			break
		}
		if len(r.tables) >= maxTableDepth {
			r.overflow++
			break
		}
		r.tables = append(r.tables, &lineTable{index: r.count})
		r.count++
	case "tr":
		if t := r.top(); t != nil {
			r.closeRow(t)
			t.row = &lineRow{table: t.index}
		}
	case "td", "th":
		if t := r.top(); t != nil {
			r.closeCell(t)
			if t.row == nil { // a cell without <tr>: an implicit row
				t.row = &lineRow{table: t.index}
			}
			t.cell = &lineCell{}
			if selfClosing {
				r.closeCell(t)
			}
		}
	case "thead", "tbody", "tfoot":
		if t := r.top(); t != nil {
			r.closeRow(t)
		}
	case "hr":
		if t := r.top(); t != nil {
			if t.row == nil {
				t.row = &lineRow{table: t.index}
			}
			t.row.rule = true
		}
	case "pre":
		if t := r.top(); t != nil && t.cell != nil && !selfClosing {
			t.pre++
		}
	}
	if skippedRaw[tag] {
		// The tokenizer returns the content of these elements as raw text, also when they are
		// written self-closing: skip exactly what it treats as raw (as scan.go does).
		r.skip = tag
	}
}

func (r *lineReader) onEnd(tag string) {
	if r.skip != "" {
		if tag == r.skip {
			r.skip = ""
		}
		return
	}
	switch tag {
	case "table":
		if r.overflow > 0 {
			r.overflow--
			break
		}
		if t := r.top(); t != nil {
			r.closeRow(t)
			r.tables = r.tables[:len(r.tables)-1]
		}
	case "tr", "thead", "tbody", "tfoot":
		if t := r.top(); t != nil {
			r.closeRow(t)
		}
	case "td", "th":
		if t := r.top(); t != nil {
			r.closeCell(t)
		}
	case "pre":
		if t := r.top(); t != nil && t.pre > 0 {
			t.pre--
		}
	}
	if !inlineTags[tag] {
		r.breakLine(r.top())
	}
}

// breakLine ends the open cell's current line (nothing without an open cell).
func (r *lineReader) breakLine(t *lineTable) {
	if t == nil || t.cell == nil {
		return
	}
	if l := normSpace(t.line.String()); l != "" {
		t.cell.lines = append(t.cell.lines, l)
	}
	t.line.Reset()
}

func (r *lineReader) closeCell(t *lineTable) {
	if t.cell == nil {
		return
	}
	r.breakLine(t)
	if t.row != nil {
		t.row.cells = append(t.row.cells, *t.cell)
	}
	t.cell, t.pre = nil, 0 // a <pre> left open ends with its cell, as in a browser
}

func (r *lineReader) closeRow(t *lineTable) {
	r.closeCell(t)
	if t.row != nil && (len(t.row.cells) > 0 || t.row.rule) {
		r.rows = append(r.rows, *t.row)
	}
	t.row = nil
}
