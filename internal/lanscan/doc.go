// Package lanscan sweeps the home network by ARP for the dashboard's Network page
// (docs/dhcp-table.md §6): which addresses of this PC's own IPv4 network answer, and with which
// MAC address. The gateway's Device List is the gateway's own view (its DHCP table); a sweep asks
// the network itself, so that a device the gateway does not list (one with a fixed address), a
// device the gateway shows on that does not answer, and an address answered by another MAC address
// than the gateway lists can be told.
//
// # What a sweep sends
//
// One ARP question ("who has 192.168.1.64?") per address of the network of this PC's interface
// that holds the gateway's address (gateway.host): Windows' SendARP (iphlpapi.dll), which needs no
// administrator rights and no raw socket. ARP never leaves the home network, and nothing else is
// sent to the devices - no ping, no port. Windows answers a question from this PC's own ARP cache
// when it holds the address already; otherwise it asks the network, and waits a few seconds for
// an answer. This PC's own addresses are not asked: they are listed with their interfaces' MAC
// addresses.
//
// # Bounds
//
//   - Only a private network (RFC 1918: 10/8, 172.16/12, 192.168/16) of at most MaxAddresses
//     (1,024: a /22) is swept; any other network is refused with an error that says why.
//   - At most InFlight (32) questions are asked at a time.
//   - A sweep ends after Timeout (2 minutes): what answered by then is kept, and the scan's
//     Problem says that it stopped short. A sweep whose context ends returns what answered with
//     the context's error.
//
// The hosts of a scan are in address order, their MAC addresses in lower case, colon separated.
// On other systems than Windows, Scan fails with contracts.ErrUnavailable.
//
// None of it is evidence: the monitor keeps the scans in the connection store (contracts.ScanStore),
// never in the ledger.
package lanscan
