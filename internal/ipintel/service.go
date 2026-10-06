package ipintel

import "strings"

// serviceTable names the well-known services by protocol and port range: what a port most likely
// carries, for the flow diagram and the firewall view (the gateway shows ports, not services).
// An entry never replaces an earlier one, so a more specific entry comes first (tcp 27017,
// MongoDB, inside Steam's range).
var serviceTable = []struct {
	proto    string // "tcp", "udp" or "both"
	from, to int
	name     string
}{
	{"tcp", 20, 20, "FTP data"},
	{"tcp", 21, 21, "FTP"},
	{"tcp", 22, 22, "SSH"},
	{"tcp", 23, 23, "Telnet"},
	{"tcp", 25, 25, "SMTP"},
	{"tcp", 43, 43, "WHOIS"},
	{"both", 53, 53, "DNS"},
	{"udp", 67, 68, "DHCP"},
	{"udp", 69, 69, "TFTP"},
	{"tcp", 80, 80, "HTTP"},
	{"both", 88, 88, "Kerberos"},
	{"tcp", 110, 110, "POP3"},
	{"both", 111, 111, "RPC"},
	{"tcp", 119, 119, "NNTP"},
	{"udp", 123, 123, "NTP"},
	{"both", 135, 135, "MS RPC"},
	{"both", 137, 139, "NetBIOS"},
	{"tcp", 143, 143, "IMAP"},
	{"both", 161, 161, "SNMP"},
	{"both", 162, 162, "SNMP trap"},
	{"tcp", 179, 179, "BGP"},
	{"both", 389, 389, "LDAP"},
	{"tcp", 443, 443, "HTTPS"},
	{"udp", 443, 443, "QUIC"},
	{"tcp", 445, 445, "SMB"},
	{"tcp", 465, 465, "SMTP submission"},
	{"udp", 500, 500, "IPsec"},
	{"both", 514, 514, "Syslog"},
	{"tcp", 515, 515, "LPD"},
	{"tcp", 548, 548, "AFP"},
	{"both", 554, 554, "RTSP"},
	{"tcp", 587, 587, "SMTP submission"},
	{"both", 631, 631, "IPP"},
	{"tcp", 636, 636, "LDAPS"},
	{"tcp", 853, 853, "DNS over TLS"},
	{"udp", 853, 853, "DNS over QUIC"},
	{"tcp", 873, 873, "rsync"},
	{"tcp", 990, 990, "FTPS"},
	{"tcp", 993, 993, "IMAPS"},
	{"tcp", 995, 995, "POP3S"},
	{"tcp", 1080, 1080, "SOCKS"},
	{"both", 1194, 1194, "OpenVPN"},
	{"tcp", 1433, 1433, "SQL Server"},
	{"udp", 1701, 1701, "L2TP"},
	{"tcp", 1723, 1723, "PPTP"},
	{"udp", 1812, 1813, "RADIUS"},
	{"tcp", 1883, 1883, "MQTT"},
	{"udp", 1900, 1900, "SSDP"},
	{"tcp", 1935, 1935, "RTMP"},
	{"both", 2049, 2049, "NFS"},
	{"tcp", 2375, 2376, "Docker"},
	{"both", 3074, 3074, "Xbox Live"},
	{"tcp", 3306, 3306, "MySQL"},
	{"both", 3389, 3389, "RDP"},
	{"both", 3478, 3481, "STUN/TURN"},
	{"udp", 3544, 3544, "Teredo"},
	{"udp", 3702, 3702, "WS-Discovery"},
	{"udp", 4500, 4500, "IPsec"},
	{"both", 5060, 5060, "SIP"},
	{"tcp", 5061, 5061, "SIP over TLS"},
	{"tcp", 5222, 5222, "XMPP"},
	{"tcp", 5223, 5223, "Apple Push"},
	{"tcp", 5228, 5228, "Google Push"},
	{"udp", 5353, 5353, "mDNS"},
	{"udp", 5355, 5355, "LLMNR"},
	{"tcp", 5432, 5432, "PostgreSQL"},
	{"tcp", 5555, 5555, "Android debug"},
	{"udp", 5683, 5683, "CoAP"},
	{"tcp", 5900, 5900, "VNC"},
	{"tcp", 6379, 6379, "Redis"},
	{"tcp", 6443, 6443, "Kubernetes API"},
	{"both", 6881, 6889, "BitTorrent"},
	{"tcp", 7547, 7547, "TR-069"},
	{"tcp", 8080, 8080, "HTTP alt"},
	{"tcp", 8291, 8291, "MikroTik Winbox"},
	{"tcp", 8443, 8443, "HTTPS alt"},
	{"tcp", 8883, 8883, "MQTT over TLS"},
	{"tcp", 9100, 9100, "Printer"},
	{"tcp", 9200, 9200, "Elasticsearch"},
	{"both", 11211, 11211, "Memcached"},
	{"both", 19302, 19309, "Google STUN"},
	{"tcp", 25565, 25565, "Minecraft"},
	{"tcp", 27017, 27017, "MongoDB"},
	{"both", 27015, 27030, "Steam"},
	{"tcp", 32400, 32400, "Plex"},
	{"udp", 41641, 41641, "Tailscale"},
	{"udp", 51820, 51820, "WireGuard"},
}

// svcKey is a TCP or UDP port.
type svcKey struct {
	tcp  bool
	port uint16
}

// services is serviceTable by port.
var services = func() map[svcKey]string {
	m := make(map[svcKey]string, 256)
	for _, s := range serviceTable {
		for p := s.from; p <= s.to; p++ {
			for _, tcp := range []bool{true, false} {
				if (tcp && s.proto == "udp") || (!tcp && s.proto == "tcp") {
					continue
				}
				if k := (svcKey{tcp, uint16(p)}); m[k] == "" {
					m[k] = s.name
				}
			}
		}
	}
	return m
}()

// protoAliases are the protocol names and numbers a caller may give (the NAT table shows
// "tcp"; netfilter logs "TCP", "ICMPv6", or a number for protocols it has no name for).
var protoAliases = []struct{ alias, proto string }{
	{"tcp", "tcp"}, {"6", "tcp"},
	{"udp", "udp"}, {"17", "udp"},
	{"icmp", "icmp"}, {"1", "icmp"}, {"icmpv6", "icmp"}, {"ipv6-icmp", "icmp"}, {"icmp6", "icmp"}, {"58", "icmp"},
	{"igmp", "igmp"}, {"2", "igmp"},
	{"gre", "gre"}, {"47", "gre"},
	{"esp", "ipsec"}, {"50", "ipsec"}, {"ah", "ipsec"}, {"51", "ipsec"},
}

// serviceName names the service of a port ("tcp", 443 → "HTTPS"; "udp", 443 → "QUIC"), or of a
// protocol that has no ports ("icmp" → "ICMP"); "" when unknown.
func serviceName(proto string, port int) string {
	p := ""
	proto = strings.TrimSpace(proto)
	for _, a := range protoAliases {
		if strings.EqualFold(proto, a.alias) {
			p = a.proto
			break
		}
	}
	switch p {
	case "icmp":
		return "ICMP"
	case "igmp":
		return "IGMP"
	case "gre":
		return "GRE"
	case "ipsec":
		return "IPsec"
	case "tcp", "udp":
		if port < 1 || port > 65535 {
			return ""
		}
		return services[svcKey{p == "tcp", uint16(port)}]
	}
	return ""
}
