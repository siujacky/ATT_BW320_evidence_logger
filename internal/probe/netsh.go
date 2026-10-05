package probe

import (
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"unicode/utf8"

	"attmonitor/internal/model"
)

// Errors ParseNetshWLAN reports for netsh output that describes no interface.
var (
	errNoWirelessInterface = errors.New("netsh: there is no wireless interface on the system")
	errWLANServiceStopped  = errors.New("netsh: the WLAN AutoConfig service (wlansvc) is not running")
	errLocationPermission  = errors.New("netsh: Location permission is required to read WLAN information")
	errNetshUnrecognized   = errors.New("netsh: no interface found in output (unexpected or non-English format)")
)

// locationNote is put in LocalLink.Err when netsh withheld details for lack of Location
// permission (Windows 11 24H2 and later) but still listed the interface.
const locationNote = "netsh reports that Location permission is required; SSID/BSSID may be withheld"

// ParseNetshWLAN parses the English output of "netsh wlan show interfaces" and returns the
// interface named iface (case-insensitive; "" selects the first connected interface, else
// the first one). It fills Interface, Type ("wifi"), State, SSID, BSSID ("AP BSSID" on
// Windows 11, "BSSID" before), Band, Channel, RadioType, RxMbps, TxMbps (rounded),
// SignalPct and RSSIdBm (the "Rssi" line of Windows 11, e.g. "Rssi : -56"; 0 when absent or
// not a plausible dBm reading, see parseRSSI); adapter facts (LocalIP, LinkMbps, ...) are not
// in this output.
//
// Lines are "<label> : <value>" (the first colon separates them, values may contain
// colons); lines without a colon (e.g. the continuation of "Radio status") are skipped and
// each "Name" line starts a new interface block. Invalid UTF-8 (netsh writes in the OEM code
// page) is replaced by U+FFFD; the raw bytes are the evidence.
func ParseNetshWLAN(out []byte, iface string) (model.LocalLink, error) {
	text := string(out)
	if !utf8.ValidString(text) {
		text = strings.ToValidUTF8(text, string(utf8.RuneError))
	}
	text = strings.ReplaceAll(text, "\r\n", "\n")
	text = strings.ReplaceAll(text, "\r", "\n")

	var blocks []map[string]string
	var cur map[string]string
	for _, line := range strings.Split(text, "\n") {
		label, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key := strings.ToLower(strings.Join(strings.Fields(label), " "))
		if key == "" {
			continue
		}
		if key == "name" {
			cur = map[string]string{}
			blocks = append(blocks, cur)
		}
		if cur == nil {
			continue // header lines such as "There is 1 interface on the system:"
		}
		if _, dup := cur[key]; !dup {
			cur[key] = strings.TrimSpace(value)
		}
	}
	lower := strings.ToLower(text)
	locationBlocked := strings.Contains(lower, "location permission")

	if len(blocks) == 0 {
		switch {
		case strings.Contains(lower, "no wireless interface"):
			return model.LocalLink{Type: "wifi"}, errNoWirelessInterface
		case strings.Contains(lower, "wlansvc") || strings.Contains(lower, "wireless autoconfig service"):
			return model.LocalLink{Type: "wifi"}, errWLANServiceStopped
		case locationBlocked:
			return model.LocalLink{Type: "wifi"}, errLocationPermission
		}
		return model.LocalLink{Type: "wifi"}, errNetshUnrecognized
	}

	var b map[string]string
	if want := strings.TrimSpace(iface); want != "" {
		var names []string
		for _, c := range blocks {
			if strings.EqualFold(c["name"], want) {
				b = c
				break
			}
			names = append(names, strconv.Quote(c["name"]))
		}
		if b == nil {
			return model.LocalLink{Interface: want, Type: "wifi"},
				fmt.Errorf("netsh: no wireless interface named %q (found %s)", want, strings.Join(names, ", "))
		}
	} else {
		for _, c := range blocks {
			if strings.EqualFold(c["state"], "connected") {
				b = c
				break
			}
		}
		if b == nil {
			b = blocks[0]
		}
	}

	link := model.LocalLink{
		Interface: b["name"],
		Type:      "wifi",
		State:     strings.ToLower(b["state"]),
		SSID:      b["ssid"],
		BSSID:     b["ap bssid"],
		Band:      b["band"],
		RadioType: b["radio type"],
		Channel:   parseInt(b["channel"]),
		SignalPct: parseInt(strings.TrimSuffix(strings.TrimSpace(b["signal"]), "%")),
		RSSIdBm:   parseRSSI(b["rssi"]),
		RxMbps:    parseRate(b["receive rate (mbps)"]),
		TxMbps:    parseRate(b["transmit rate (mbps)"]),
	}
	if link.BSSID == "" {
		link.BSSID = b["bssid"]
	}
	if locationBlocked {
		link.Err = locationNote
	}
	return link, nil
}

// parseInt parses a non-negative decimal integer (channel, signal %), returning 0 (unknown)
// when the text is not one.
func parseInt(s string) int {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || n < 0 {
		return 0
	}
	return n
}

// parseRate parses a rate such as "721" or "144.4" and rounds it to whole Mbps, returning 0
// (unknown) for anything else. ParseFloat accepts "NaN" and "Inf", which the range test
// written as !(f >= 0 && f <= max) rejects (NaN fails every comparison).
func parseRate(s string) int {
	f, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	if err != nil || !(f >= 0 && f <= math.MaxInt32) {
		return 0
	}
	return int(math.Round(f))
}

// minRSSIdBm is the lowest received signal strength accepted as a reading. Wi-Fi drivers
// report RSSI as a signed 8-bit dBm value (radiotap's antenna signal is s8), and real
// readings lie far above it: below about -100 dBm a Wi-Fi signal is under the thermal noise
// of its channel.
const minRSSIdBm = -128

// parseRSSI parses netsh's "Rssi" value, a received signal strength in whole dBm such as
// "-56", returning 0 (not reported) for anything that is not a reading: absent or
// unparseable text, zero or positive values, and values below minRSSIdBm.
func parseRSSI(s string) int {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || n >= 0 || n < minRSSIdBm {
		return 0
	}
	return n
}
