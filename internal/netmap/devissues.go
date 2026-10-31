package netmap

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"attmonitor/internal/model"
)

// Thresholds of the Devices tab's issues (docs/dhcp-table.md §2).
const (
	// blockedPerDay is how many of a device's packets the gateway's firewall must drop per day of a
	// period - those it sent and those sent to it from the Internet together; in a period of a day
	// or less, that many - for the issue "blocked" (blockedThreshold): a device that keeps trying
	// what the gateway refuses, or one the Internet keeps knocking at, rather than the odd packet
	// every device has dropped. Per day, not per period: on the owner's network a month brought a
	// handful of devices to 100-200 drops, while the one worth a look had thousands a day.
	blockedPerDay = 100
	// weakBars is the most bars a weak Wi-Fi signal is drawn with (of maxBars).
	weakBars = 2
	maxBars  = 5
	// slowMbps is the speed of a slow wired link: 10 Mb/s, the slowest Ethernet runs at - a port,
	// a cable or a device that settled for less than the 100 or 1000 Mb/s Ethernet normally runs.
	slowMbps = 10
	// maxNamedAddrs bounds the addresses the text of the issue "address_changed" names.
	maxNamedAddrs = 5
)

// issueRank orders issue levels: critical first.
func issueRank(level string) int {
	switch level {
	case model.IssueCritical:
		return 0
	case model.IssueWarning:
		return 1
	}
	return 2
}

// issueOrder orders the issues of one level by code, the most telling first.
var issueOrder = map[string]int{
	model.IssueAddressShared: 0, model.IssueUnlisted: 1, model.IssueScanMAC: 2, model.IssueBlocked: 3, model.IssueWeakWiFi: 4,
	model.IssueSlowLink: 5, model.IssueAddressChanged: 6, model.IssueScanAddr: 7, model.IssueNoAnswer: 8, model.IssueOffline: 9,
}

// worst returns the rank of the most severe of issues (3 without any).
func worst(issues []model.NetIssue) int {
	r := 3
	for _, is := range issues {
		r = min(r, issueRank(is.Level))
	}
	return r
}

// counts reports whether issues hold a warning or a critical one (NetDeviceTotals.Issues).
func counts(issues []model.NetIssue) bool { return worst(issues) <= 1 }

// who names a device of the newest Device List read in an issue's text: "laptop
// (00:00:5e:00:53:02)", "laptop", "00:00:5e:00:53:02", else what is left to name it by.
func who(d model.NetLANDevice) string {
	switch {
	case d.Name != "" && d.MAC != "":
		return d.Name + " (" + d.MAC + ")"
	case d.Name != "":
		return d.Name
	case d.MAC != "":
		return d.MAC
	}
	return "an entry without a name or MAC address"
}

// sharedIssue is the issue of a device whose IPv4 address other entries of the newest read claim
// too - entries that are not shown off (an entry that is off shows the last address of a device
// that left, which DHCP may have given to another one since): two devices answering to one
// address, so that what is sent to either may reach the other.
func sharedIssue(addr string, others []model.NetLANDevice) model.NetIssue {
	names := make([]string, len(others))
	for i, o := range others {
		names[i] = who(o)
	}
	return model.NetIssue{Code: model.IssueAddressShared, Level: model.IssueCritical,
		Text: addr + " is also claimed by " + joinAnd(names) + " in the newest Device List read (an address conflict)."}
}

// weakIssue is the issue of a device whose Wi-Fi signal the gateway draws with weakBars bars or
// fewer (0: none shown, no issue).
func weakIssue(d model.NetLANDevice) (model.NetIssue, bool) {
	if d.Signal < 1 || d.Signal > weakBars {
		return model.NetIssue{}, false
	}
	text := fmt.Sprintf("Its Wi-Fi signal is weak: the gateway draws it with %s of %d", plural(d.Signal, "bar", "bars"), maxBars)
	if d.Connection != "" && d.Connection != "Wi-Fi" {
		text += " (" + d.Connection + ")"
	}
	return model.NetIssue{Code: model.IssueWeakWiFi, Level: model.IssueWarning, Text: text + "."}, true
}

// reSpeed finds a link's speed in the gateway's "Connection Speed" ("1000Mbps fullduplex",
// "100 Mbps half duplex", "1Gbps"): the number and the unit after it.
var reSpeed = regexp.MustCompile(`(\d+(?:\.\d+)?)\s*([A-Za-z]*)`)

// linkSpeed reads a wired link's speed: in Mb/s (0 when the text gives none) and whether it runs
// at half duplex.
func linkSpeed(s string) (mbps float64, half bool) {
	if m := reSpeed.FindStringSubmatch(s); m != nil {
		if v, err := strconv.ParseFloat(m[1], 64); err == nil {
			switch u := strings.ToLower(m[2]); {
			case strings.HasPrefix(u, "g"):
				v *= 1000
			case strings.HasPrefix(u, "k"):
				v /= 1000
			}
			mbps = v
		}
	}
	return mbps, strings.Contains(strings.ToLower(s), "half")
}

// slowIssue is the issue of a wired device whose link runs at slowMbps or slower, or at half
// duplex (a Wi-Fi device has no such link; the gateway shows no speed for it).
func slowIssue(d model.NetLANDevice) (model.NetIssue, bool) {
	if d.Speed == "" || isWiFi(d.Connection) {
		return model.NetIssue{}, false
	}
	mbps, half := linkSpeed(d.Speed)
	slow := mbps > 0 && mbps <= slowMbps
	if !slow && !half {
		return model.NetIssue{}, false
	}
	var how []string
	if mbps > 0 {
		how = append(how, strconv.FormatFloat(mbps, 'f', -1, 64)+" Mb/s")
	}
	if half {
		how = append(how, "half duplex")
	}
	return model.NetIssue{Code: model.IssueSlowLink, Level: model.IssueWarning,
		Text: fmt.Sprintf("Its Ethernet link runs at %s (the gateway shows %q); Ethernet normally runs at 100 or 1000 Mb/s, full duplex.",
			strings.Join(how, ", "), d.Speed)}, true
}

// blockedDays is how many days a period of length span counts for blockedThreshold: whole days,
// rounded up, and at least one.
func blockedDays(span time.Duration) int {
	const day = 24 * time.Hour
	return max(1, int((span+day-1)/day))
}

// blockedThreshold is the least number of dropped packets for the issue "blocked" in a period of
// length span: blockedPerDay for each of its days (blockedDays).
func blockedThreshold(span time.Duration) int { return blockedPerDay * blockedDays(span) }

// blockedIssue is the issue of a device that blockedThreshold or more of whose packets the
// gateway's firewall dropped in the period (of length span); for a period of more than a day the
// text also says how many a day that is.
func blockedIssue(d model.NetLANDevice, span time.Duration) (model.NetIssue, bool) {
	n := d.Blocked + d.BlockedIn
	if n < blockedThreshold(span) {
		return model.NetIssue{}, false
	}
	text := fmt.Sprintf("In this period the gateway's firewall dropped %s it sent toward the Internet and %s sent to it from the Internet.",
		plural(d.Blocked, "packet", "packets"), plural(d.BlockedIn, "packet", "packets"))
	if days := blockedDays(span); days > 1 {
		text += fmt.Sprintf(" That is about %s a day.", plural((n+days/2)/days, "packet", "packets"))
	}
	return model.NetIssue{Code: model.IssueBlocked, Level: model.IssueWarning, Text: text}, true
}

// changedIssue is the issue of a device that held more than one IPv4 address in the period.
func changedIssue(d model.NetLANDevice) (model.NetIssue, bool) {
	if len(d.Addresses) < 2 {
		return model.NetIssue{}, false
	}
	named := d.Addresses[:min(len(d.Addresses), maxNamedAddrs)]
	list := strings.Join(named, ", ")
	if more := len(d.Addresses) - len(named); more > 0 {
		list += " and " + strconv.Itoa(more) + " more"
	}
	return model.NetIssue{Code: model.IssueAddressChanged, Level: model.IssueInfo,
		Text: fmt.Sprintf("It held %d IPv4 addresses in this period, the newest first: %s.", len(d.Addresses), list)}, true
}

// offlineIssue is the issue of a device the newest read (made at listAt) shows off: since when it
// was last seen on - by the period's reads, else as the gateway's last activity says - and who
// claims its last address now, if another device does (takers).
func offlineIssue(d model.NetLANDevice, listAt time.Time, takers []model.NetLANDevice) model.NetIssue {
	text := "The newest Device List read shows it off"
	seen, err := time.Parse(time.RFC3339Nano, d.Seen)
	switch {
	case err == nil && !listAt.IsZero() && seen.Before(listAt):
		text += "; the last read that showed it on was made " + span(listAt.Sub(seen)) + " before."
	case err == nil:
		text += "."
	default:
		text += ", and no read of this period showed it on."
	}
	if d.LastActivity != "" {
		text += " The gateway gives its last activity as " + d.LastActivity + "."
	}
	if len(takers) > 0 && d.IPv4 != "" {
		names := make([]string, len(takers))
		for i, o := range takers {
			names[i] = who(o)
		}
		text += " Its last address, " + d.IPv4 + ", is now claimed by " + joinAnd(names) + "."
	}
	return model.NetIssue{Code: model.IssueOffline, Level: model.IssueInfo, Text: text}
}

// unlistedIssue is the issue of a LAN address that no Device List read of the period names: what
// showed it (the NAT samples: nat; the firewall's drops) and, for a self-assigned address, what
// that means.
func unlistedIssue(u model.NetUnknownAddr, nat bool) model.NetIssue {
	return unknownIssue(u, nat, 0, false)
}

// fixedAddress is what an unknown address that answered a LAN scan may be.
const fixedAddress = " Perhaps a device with a fixed address, which the gateway does not list."

// unknownIssue is the issue "unlisted" of an unknown address: what showed it - the NAT samples
// (nat), the firewall's drops, the LAN scans (scans of them it answered, from u.MAC at the newest)
// - and what it may be. named: Device List reads of the period name the address (a device of the
// list held it), but not the MAC address that answered for it in the scans.
func unknownIssue(u model.NetUnknownAddr, nat bool, scans int, named bool) model.NetIssue {
	mac := u.MAC
	if mac == "" {
		mac = "a MAC address that is not valid"
	}
	if named && scans > 0 {
		return model.NetIssue{Code: model.IssueUnlisted, Level: model.IssueWarning,
			Text: fmt.Sprintf("%s answered %s of this period from %s, which no Device List read of this period names (the reads give the address to another device).",
				u.Addr, plural(scans, "LAN scan", "LAN scans"), mac) + fixedAddress}
	}
	var seen []string
	if nat {
		s := "the NAT table showed its connections"
		if u.Open > 0 {
			s += " (" + plural(u.Open, "open connection", "open connections") + " in the newest read)"
		}
		seen = append(seen, s)
	}
	switch {
	case u.Blocked > 0 && u.BlockedIn > 0:
		seen = append(seen, fmt.Sprintf("the gateway's firewall dropped %s it sent and %s sent to it from the Internet",
			plural(u.Blocked, "packet", "packets"), plural(u.BlockedIn, "packet", "packets")))
	case u.Blocked > 0:
		seen = append(seen, "the gateway's firewall dropped "+plural(u.Blocked, "packet", "packets")+" it sent")
	case u.BlockedIn > 0:
		seen = append(seen, "the gateway's firewall dropped "+plural(u.BlockedIn, "packet", "packets")+" sent to it from the Internet")
	}
	if scans > 0 {
		seen = append(seen, "it answered "+plural(scans, "LAN scan", "LAN scans")+" of this period (from "+mac+")")
	}
	text := "No Device List read of this period names " + u.Addr
	if len(seen) > 0 {
		text += ", yet " + joinAnd(seen)
	}
	text += "."
	a, ok := deviceIPv4(u.Addr)
	switch {
	case ok && a.IsLinkLocalUnicast():
		text += " A device gives itself an address in 169.254.0.0/16 when it gets none from the gateway's DHCP server."
	case scans > 0:
		text += fixedAddress
	}
	return model.NetIssue{Code: model.IssueUnlisted, Level: model.IssueWarning, Text: text}
}

// noAnswerIssue is the issue no_answer of a device that the newest Device List read (made at
// listAt) shows on and that did not answer the newest LAN scan (begun at scanAt, within scanFresh
// of the read).
func noAnswerIssue(scanAt, listAt time.Time) model.NetIssue {
	when := "after"
	d := scanAt.Sub(listAt)
	if d < 0 {
		when, d = "before", -d
	}
	return model.NetIssue{Code: model.IssueNoAnswer, Level: model.IssueInfo,
		Text: "The newest Device List read shows it on, but it did not answer the newest LAN scan (made " + span(d) + " " + when +
			" that read); a device that sleeps may not answer."}
}

// scanAddrIssue is the issue scan_addr of a device that answered the newest LAN scan at addr, not
// at the IPv4 address it is listed with (listed; "" when the gateway lists none).
func scanAddrIssue(addr, listed string) model.NetIssue {
	text := "It answered the newest LAN scan at " + addr + ", not at " + listed + ", the address the gateway lists for it."
	if listed == "" {
		text = "It answered the newest LAN scan at " + addr + "; the gateway lists no IPv4 address for it."
	}
	return model.NetIssue{Code: model.IssueScanAddr, Level: model.IssueInfo, Text: text}
}

// scanMACIssue is the issue scan_mac of a device listed (and on) at addr, which the newest LAN
// scan found answered by another MAC address, mac: one the newest read gives to another device
// (other), one an earlier read of the period named (named, with the name it gave: earlier), or one
// no read names.
func scanMACIssue(addr, mac string, other *model.NetLANDevice, earlier string, named bool) model.NetIssue {
	text := "The newest LAN scan found " + addr + " answered by another MAC address, " + mac
	const two = ": two devices may be using the address, or the list is out of date."
	switch {
	case other != nil && other.Name != "":
		text += ", which the newest Device List read gives to " + other.Name + two
	case other != nil:
		text += ", which the newest Device List read gives to another entry (without a name)" + two
	case named && earlier != "":
		text += ", which a Device List read of this period gave to " + earlier + " (no longer listed)" + two
	case named:
		text += ", which a Device List read of this period named (no longer listed)" + two
	default:
		text += ", which no Device List read of this period names: a device the gateway does not list may be using the address."
	}
	return model.NetIssue{Code: model.IssueScanMAC, Level: model.IssueWarning, Text: text}
}

// isWiFi and isWired tell a device's connection as the Device List summarizes it ("Wi-Fi 5 GHz",
// "Ethernet LAN-1").
func isWiFi(conn string) bool  { return hasPrefixFold(conn, "wi-fi") }
func isWired(conn string) bool { return hasPrefixFold(conn, "ethernet") }

func hasPrefixFold(s, prefix string) bool {
	return len(s) >= len(prefix) && strings.EqualFold(s[:len(prefix)], prefix)
}

// plural writes n and the noun in its form for n ("1 bar", "2 bars").
func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return strconv.Itoa(n) + " " + many
}

// joinAnd joins names as a sentence lists them: "a", "a and b", "a, b and c".
func joinAnd(names []string) string {
	switch len(names) {
	case 0:
		return ""
	case 1:
		return names[0]
	}
	return strings.Join(names[:len(names)-1], ", ") + " and " + names[len(names)-1]
}

// span says how long d is in round words: "less than a minute", "40 min", "2 h 15 min", "3 days
// 4 h".
func span(d time.Duration) string {
	switch {
	case d < time.Minute:
		return "less than a minute"
	case d < time.Hour:
		return strconv.Itoa(int(d/time.Minute)) + " min"
	case d < 24*time.Hour:
		h, m := int(d/time.Hour), int(d%time.Hour/time.Minute)
		if m == 0 {
			return strconv.Itoa(h) + " h"
		}
		return strconv.Itoa(h) + " h " + strconv.Itoa(m) + " min"
	}
	days, h := int(d/(24*time.Hour)), int(d%(24*time.Hour)/time.Hour)
	s := plural(days, "day", "days")
	if h > 0 {
		s += " " + strconv.Itoa(h) + " h"
	}
	return s
}
