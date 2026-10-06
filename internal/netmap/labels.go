package netmap

import (
	"strconv"
	"strings"

	"attmonitor/internal/model"
)

// otherReasons is FwReason.Reason of the reasons grouped together: those beyond maxReasons and
// those beyond what the reason table numbers.
const otherReasons = "*"

// reasonLabels says in plain words what the reasons the BGW320 gives mean (by upper case).
var reasonLabels = map[string]string{
	"POLICY-INPUT-GEN-DISCARD": "Unsolicited, to the gateway",
	"POLICY":                   "Firewall policy",
	"OTHER-DOS":                "Flood (DoS) protection",
	"POLICY-ICMP-ECHO":         "Ping to the gateway",
	"IP-INVALID":               "Invalid packet",
	"UDP-DST-PORT":             "Blocked UDP port",
}

// acronyms keep their spelling when a reason is made readable (by upper case).
var acronyms = map[string]string{
	"ACK": "ACK", "ALG": "ALG", "DDOS": "DDoS", "DNS": "DNS", "DOS": "DoS", "ESP": "ESP", "FIN": "FIN",
	"GRE": "GRE", "ICMP": "ICMP", "ICMPV6": "ICMPv6", "IGMP": "IGMP", "IP": "IP", "IPSEC": "IPsec",
	"IPV4": "IPv4", "IPV6": "IPv6", "LAN": "LAN", "MTU": "MTU", "NAT": "NAT", "PPTP": "PPTP", "RST": "RST",
	"SIP": "SIP", "SYN": "SYN", "TCP": "TCP", "TTL": "TTL", "UDP": "UDP", "UPNP": "UPnP", "VPN": "VPN", "WAN": "WAN",
}

// reasonLabel describes a firewall reason in plain words: the BGW320's known reasons by what they
// mean, any other one made readable ("TCP-SYN-FLOOD" → "TCP SYN flood").
func reasonLabel(reason string) string {
	switch reason {
	case "":
		return "Not stated"
	case otherReasons:
		return "Other reasons"
	}
	if l, ok := reasonLabels[strings.ToUpper(reason)]; ok {
		return l
	}
	words := strings.FieldsFunc(reason, func(r rune) bool { return r == '-' || r == '_' || r == '.' || r == ' ' })
	if len(words) == 0 {
		return reason
	}
	for i, w := range words {
		if a, ok := acronyms[strings.ToUpper(w)]; ok {
			words[i] = a
			continue
		}
		w = strings.ToLower(w)
		if i == 0 {
			w = strings.ToUpper(w[:1]) + w[1:] // reasons are ASCII (fwparse.go)
		}
		words[i] = w
	}
	return strings.Join(words, " ")
}

// serviceLabel names a port the port table does not know: "tcp 8443"; a protocol without
// ports by the protocol ("ICMP").
func serviceLabel(proto string, port int) string {
	switch {
	case port > 0 && proto != "":
		return proto + " " + strconv.Itoa(port)
	case port > 0:
		return "port " + strconv.Itoa(port)
	}
	return protoLabel(proto)
}

// protoLabel names a protocol as people write it.
func protoLabel(proto string) string {
	switch proto {
	case "":
		return "Unknown"
	case "icmp":
		return "ICMP"
	case "icmpv6":
		return "ICMPv6"
	}
	if _, err := strconv.Atoi(proto); err == nil {
		return "IP protocol " + proto
	}
	return strings.ToUpper(proto)
}

// orgName is the readable name of the network that announces an address: the IP database's
// organisation, else its AS description, else "AS<n>" ("" when nothing is known).
func orgName(info model.IPInfo) string {
	switch {
	case info.Org != "":
		return info.Org
	case info.ASName != "":
		return info.ASName
	case info.ASN > 0:
		return "AS" + strconv.Itoa(info.ASN)
	}
	return ""
}
