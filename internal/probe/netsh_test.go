package probe

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"attmonitor/internal/model"
)

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "testdata", "probe", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// lineEndingVariants returns the fixture as stored (CRLF) and with LF-only endings.
func lineEndingVariants(b []byte) map[string][]byte {
	lf := bytes.ReplaceAll(b, []byte("\r\n"), []byte("\n"))
	crlf := bytes.ReplaceAll(lf, []byte("\n"), []byte("\r\n"))
	return map[string][]byte{"as-stored": b, "lf": lf, "crlf": crlf}
}

// connectedSample is the real reading from the target PC (identifiers sanitized).
var connectedSample = model.LocalLink{
	Interface: "Wi-Fi", Type: "wifi", State: "connected", SSID: "ATTexample",
	BSSID: "00:00:5e:00:53:1c", Band: "5 GHz", Channel: 149, RadioType: "802.11ax",
	RxMbps: 721, TxMbps: 649, SignalPct: 84, RSSIdBm: -56,
}

func TestParseNetshWLAN(t *testing.T) {
	tests := []struct {
		name    string
		fixture string
		iface   string
		want    model.LocalLink
		wantErr error  // sentinel, checked with errors.Is
		errIn   string // substring, for non-sentinel errors
	}{
		{name: "connected interface by name", fixture: "netsh_two_interfaces.txt", iface: "Wi-Fi", want: connectedSample},
		{
			// The current Windows 11 layout exactly as captured on the target PC (identifiers
			// replaced): "Rssi : -60" follows "Signal : 82% ".
			name: "real windows 11 capture with Rssi", fixture: "netsh_win11_rssi.txt", iface: "Wi-Fi",
			want: model.LocalLink{Interface: "Wi-Fi", Type: "wifi", State: "connected", SSID: "ATTexample",
				BSSID: "00:00:5e:00:53:1c", Band: "5 GHz", Channel: 149, RadioType: "802.11ax",
				RxMbps: 721, TxMbps: 551, SignalPct: 82, RSSIdBm: -60},
		},
		{name: "name match is case-insensitive", fixture: "netsh_two_interfaces.txt", iface: "wi-fi", want: connectedSample},
		{name: "first connected when no name", fixture: "netsh_two_interfaces.txt", want: connectedSample},
		{
			name: "disconnected interface", fixture: "netsh_two_interfaces.txt", iface: "Wi-Fi 2",
			want: model.LocalLink{Interface: "Wi-Fi 2", Type: "wifi", State: "disconnected"},
		},
		{
			name: "unknown interface", fixture: "netsh_two_interfaces.txt", iface: "Ethernet",
			want:  model.LocalLink{Interface: "Ethernet", Type: "wifi"},
			errIn: `no wireless interface named "Ethernet" (found "Wi-Fi", "Wi-Fi 2")`,
		},
		{
			name: "windows 10 BSSID label and fractional rates", fixture: "netsh_win10_bssid.txt", iface: "WLAN",
			want: model.LocalLink{Interface: "WLAN", Type: "wifi", State: "connected", SSID: "ATTexample-2G",
				BSSID: "00:00:5e:00:53:2a", Channel: 6, RadioType: "802.11n", RxMbps: 144, TxMbps: 72, SignalPct: 99},
		},
		{name: "no wireless interface", fixture: "netsh_no_interface.txt", want: model.LocalLink{Type: "wifi"}, wantErr: errNoWirelessInterface},
		{name: "wlansvc stopped", fixture: "netsh_wlansvc_stopped.txt", want: model.LocalLink{Type: "wifi"}, wantErr: errWLANServiceStopped},
		{name: "location notice only", fixture: "netsh_location_only.txt", want: model.LocalLink{Type: "wifi"}, wantErr: errLocationPermission},
		{
			name: "location notice with partial block", fixture: "netsh_location_notice.txt", iface: "Wi-Fi",
			want: model.LocalLink{Interface: "Wi-Fi", Type: "wifi", State: "connected", Band: "5 GHz", Channel: 149,
				RadioType: "802.11ax", RxMbps: 721, TxMbps: 649, SignalPct: 84, Err: locationNote},
		},
	}
	for _, tt := range tests {
		for variant, out := range lineEndingVariants(readFixture(t, tt.fixture)) {
			t.Run(tt.name+"/"+variant, func(t *testing.T) {
				got, err := ParseNetshWLAN(out, tt.iface)
				switch {
				case tt.wantErr != nil:
					if !errors.Is(err, tt.wantErr) {
						t.Fatalf("err = %v, want %v", err, tt.wantErr)
					}
				case tt.errIn != "":
					if err == nil || !strings.Contains(err.Error(), tt.errIn) {
						t.Fatalf("err = %v, want containing %q", err, tt.errIn)
					}
				case err != nil:
					t.Fatalf("unexpected error: %v", err)
				}
				if !reflect.DeepEqual(got, tt.want) {
					t.Errorf("got  %+v\nwant %+v", got, tt.want)
				}
			})
		}
	}
}

func TestParseNetshWLANEdgeCases(t *testing.T) {
	tests := []struct {
		name  string
		out   string
		iface string
		check func(t *testing.T, l model.LocalLink, err error)
	}{
		{
			name: "empty output",
			out:  "",
			check: func(t *testing.T, l model.LocalLink, err error) {
				if !errors.Is(err, errNetshUnrecognized) {
					t.Fatalf("err = %v", err)
				}
			},
		},
		{
			name: "localized output is not guessed",
			out:  "    Nom                    : Wi-Fi\r\n    État                   : connecté\r\n",
			check: func(t *testing.T, l model.LocalLink, err error) {
				if !errors.Is(err, errNetshUnrecognized) {
					t.Fatalf("err = %v", err)
				}
			},
		},
		{
			name: "values containing colons and invalid UTF-8",
			out: "    Name : Wi-Fi\n    State : connected\n    SSID : caf\xe9 net\n    AP BSSID : aa:bb:cc:dd:ee:ff\n" +
				"    Signal : 7 %\n    Channel : abc\n    Receive rate (Mbps) : n/a\n",
			check: func(t *testing.T, l model.LocalLink, err error) {
				if err != nil {
					t.Fatal(err)
				}
				if l.SSID != "caf"+rep+" net" || l.BSSID != "aa:bb:cc:dd:ee:ff" || l.SignalPct != 7 ||
					l.Channel != 0 || l.RxMbps != 0 {
					t.Fatalf("got %+v", l)
				}
			},
		},
		{
			name: "duplicate label keeps the first value",
			out:  "    Name : Wi-Fi\n    State : connected\n    State : disconnected\n",
			check: func(t *testing.T, l model.LocalLink, err error) {
				if err != nil || l.State != "connected" {
					t.Fatalf("got %+v, %v", l, err)
				}
			},
		},
		{
			name: "no connected interface falls back to the first",
			out:  "    Name : A\n    State : disconnected\n\n    Name : B\n    State : associating\n",
			check: func(t *testing.T, l model.LocalLink, err error) {
				if err != nil || l.Interface != "A" || l.State != "disconnected" {
					t.Fatalf("got %+v, %v", l, err)
				}
			},
		},
		{
			name: "state is lower-cased",
			out:  "    Name : Wi-Fi\n    State : Connected\n",
			check: func(t *testing.T, l model.LocalLink, err error) {
				if err != nil || l.State != "connected" {
					t.Fatalf("got %+v, %v", l, err)
				}
			},
		},
		{
			name: "rssi in the short form",
			out:  "    Name : Wi-Fi\n    State : connected\n    Signal : 90%\n    Rssi : -52\n",
			check: func(t *testing.T, l model.LocalLink, err error) {
				if err != nil || l.RSSIdBm != -52 || l.SignalPct != 90 {
					t.Fatalf("got %+v, %v", l, err)
				}
			},
		},
		{
			name: "rssi absent (older Windows) is not reported",
			out:  "    Name : Wi-Fi\n    State : connected\n    Signal : 90%\n",
			check: func(t *testing.T, l model.LocalLink, err error) {
				if err != nil || l.RSSIdBm != 0 {
					t.Fatalf("got %+v, %v", l, err)
				}
			},
		},
		{
			name: "rssi label in another case",
			out:  "    Name : Wi-Fi\n    RSSI : -71 \n",
			check: func(t *testing.T, l model.LocalLink, err error) {
				if err != nil || l.RSSIdBm != -71 {
					t.Fatalf("got %+v, %v", l, err)
				}
			},
		},
		{
			name: "unparseable rssi is ignored, the rest is kept",
			out:  "    Name : Wi-Fi\n    State : connected\n    Rssi : n/a\n    Channel : 36\n",
			check: func(t *testing.T, l model.LocalLink, err error) {
				if err != nil || l.RSSIdBm != 0 || l.Channel != 36 || l.State != "connected" {
					t.Fatalf("got %+v, %v", l, err)
				}
			},
		},
		{
			name:  "rssi of the selected interface, not of another block",
			out:   "    Name : A\n    State : connected\n    Rssi : -40\n\n    Name : B\n    State : connected\n    Rssi : -80\n",
			iface: "B",
			check: func(t *testing.T, l model.LocalLink, err error) {
				if err != nil || l.Interface != "B" || l.RSSIdBm != -80 {
					t.Fatalf("got %+v, %v", l, err)
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l, err := ParseNetshWLAN([]byte(tt.out), tt.iface)
			tt.check(t, l, err)
		})
	}
}

func TestParseRateAndInt(t *testing.T) {
	for in, want := range map[string]int{"721": 721, "144.4": 144, "866.7": 867, " 54 ": 54, "": 0, "x": 0, "-5": 0, "1e12": 0} {
		if got := parseRate(in); got != want {
			t.Errorf("parseRate(%q) = %d, want %d", in, got, want)
		}
	}
	for in, want := range map[string]int{"149": 149, " 6 ": 6, "": 0, "6.5": 0, "x": 0} {
		if got := parseInt(in); got != want {
			t.Errorf("parseInt(%q) = %d, want %d", in, got, want)
		}
	}
}

// TestParseRSSI: only a negative whole number of dBm within the 8-bit range Wi-Fi drivers
// report is a reading; anything else is "not reported" (0, omitted from the record) rather
// than a made-up value. The raw netsh output stays the evidence either way.
func TestParseRSSI(t *testing.T) {
	for in, want := range map[string]int{
		"-56": -56, " -60 ": -60, "-1": -1, "-128": -128, // readings
		"": 0, "n/a": 0, "-52 dBm": 0, "-52.5": 0, "--52": 0, // absent or unparseable
		"0": 0, "-0": 0, "12": 0, "+5": 0, // not negative: no received-signal reading
		"-129": 0, "-1000": 0, "-9223372036854775808": 0, "-99999999999999999999": 0, // implausible
	} {
		if got := parseRSSI(in); got != want {
			t.Errorf("parseRSSI(%q) = %d, want %d", in, got, want)
		}
	}
}
