package ipintel

import "testing"

func TestService(t *testing.T) {
	cases := []struct {
		proto string
		port  int
		want  string
	}{
		{"tcp", 443, "HTTPS"},
		{"udp", 443, "QUIC"},
		{"TCP", 443, "HTTPS"},
		{" Udp ", 443, "QUIC"},
		{"6", 443, "HTTPS"},
		{"17", 443, "QUIC"},
		{"tcp", 80, "HTTP"},
		{"udp", 80, ""},
		{"tcp", 53, "DNS"},
		{"udp", 53, "DNS"},
		{"tcp", 853, "DNS over TLS"},
		{"udp", 853, "DNS over QUIC"},
		{"udp", 123, "NTP"},
		{"tcp", 123, ""},
		{"tcp", 8080, "HTTP alt"},
		{"tcp", 8443, "HTTPS alt"},
		{"tcp", 20, "FTP data"},
		{"tcp", 21, "FTP"},
		{"tcp", 22, "SSH"},
		{"tcp", 23, "Telnet"},
		{"tcp", 25, "SMTP"},
		{"tcp", 465, "SMTP submission"},
		{"tcp", 587, "SMTP submission"},
		{"tcp", 110, "POP3"},
		{"tcp", 995, "POP3S"},
		{"tcp", 143, "IMAP"},
		{"tcp", 993, "IMAPS"},
		{"tcp", 445, "SMB"},
		{"udp", 137, "NetBIOS"},
		{"udp", 138, "NetBIOS"},
		{"tcp", 139, "NetBIOS"},
		{"udp", 161, "SNMP"},
		{"udp", 162, "SNMP trap"},
		{"tcp", 389, "LDAP"},
		{"tcp", 3389, "RDP"},
		{"udp", 3389, "RDP"},
		{"tcp", 5900, "VNC"},
		{"udp", 1194, "OpenVPN"},
		{"tcp", 1194, "OpenVPN"},
		{"udp", 51820, "WireGuard"},
		{"udp", 500, "IPsec"},
		{"udp", 4500, "IPsec"},
		{"tcp", 1723, "PPTP"},
		{"udp", 5060, "SIP"},
		{"tcp", 5060, "SIP"},
		{"tcp", 5061, "SIP over TLS"},
		{"udp", 3478, "STUN/TURN"},
		{"udp", 3481, "STUN/TURN"},
		{"udp", 3482, ""},
		{"udp", 19302, "Google STUN"},
		{"udp", 19309, "Google STUN"},
		{"udp", 19310, ""},
		{"tcp", 5222, "XMPP"},
		{"tcp", 5223, "Apple Push"},
		{"tcp", 5228, "Google Push"},
		{"tcp", 1883, "MQTT"},
		{"tcp", 8883, "MQTT over TLS"},
		{"udp", 5353, "mDNS"},
		{"udp", 1900, "SSDP"},
		{"tcp", 7547, "TR-069"},
		{"udp", 3074, "Xbox Live"},
		{"tcp", 3074, "Xbox Live"},
		{"udp", 27015, "Steam"},
		{"udp", 27030, "Steam"},
		{"udp", 27031, ""},
		{"tcp", 27016, "Steam"},
		{"tcp", 27017, "MongoDB"},
		{"udp", 27017, "Steam"},
		{"tcp", 32400, "Plex"},
		{"tcp", 9100, "Printer"},
		{"tcp", 631, "IPP"},
		{"tcp", 1433, "SQL Server"},
		{"tcp", 3306, "MySQL"},
		{"tcp", 5432, "PostgreSQL"},
		{"tcp", 6379, "Redis"},
		{"udp", 69, "TFTP"},
		{"udp", 67, "DHCP"},
		{"udp", 68, "DHCP"},
		{"udp", 514, "Syslog"},
		{"tcp", 873, "rsync"},
		// Protocols without ports.
		{"icmp", 0, "ICMP"},
		{"ICMPv6", 0, "ICMP"},
		{"ipv6-icmp", 3, "ICMP"},
		{"1", 8, "ICMP"},
		{"58", 0, "ICMP"},
		{"igmp", 0, "IGMP"},
		{"2", 0, "IGMP"},
		{"GRE", 0, "GRE"},
		{"esp", 0, "IPsec"},
		{"AH", 0, "IPsec"},
		// Unknown.
		{"tcp", 0, ""},
		{"tcp", -1, ""},
		{"tcp", 65536, ""},
		{"tcp", 1, ""},
		{"tcp", 49152, ""},
		{"sctp", 443, ""},
		{"", 443, ""},
		{"t cp", 443, ""},
	}
	var d *DB // Service needs nothing of the DB
	for _, c := range cases {
		if got := d.Service(c.proto, c.port); got != c.want {
			t.Errorf("Service(%q, %d) = %q, want %q", c.proto, c.port, got, c.want)
		}
	}
}

// TestServiceTable checks the entries, and that the only port two entries claim is the one
// meant to be (tcp 27017: MongoDB, not Steam).
func TestServiceTable(t *testing.T) {
	claimed := map[svcKey]string{}
	for _, s := range serviceTable {
		if s.name == "" || s.from < 1 || s.to > 65535 || s.from > s.to ||
			(s.proto != "tcp" && s.proto != "udp" && s.proto != "both") {
			t.Errorf("bad entry %+v", s)
		}
		for p := s.from; p <= s.to; p++ {
			for _, tcp := range []bool{true, false} {
				if (tcp && s.proto == "udp") || (!tcp && s.proto == "tcp") {
					continue
				}
				k := svcKey{tcp, uint16(p)}
				if prev, ok := claimed[k]; ok && !(k == svcKey{true, 27017} && prev == "MongoDB") {
					t.Errorf("%v claimed by %q and %q", k, prev, s.name)
				}
				if _, ok := claimed[k]; !ok {
					claimed[k] = s.name
				}
			}
		}
	}
	if len(claimed) != len(services) {
		t.Fatalf("services has %d ports, the table %d", len(services), len(claimed))
	}
}
