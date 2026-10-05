# testdata/probe

Fixtures for `internal/probe` (`ParseNetshWLAN`). All files use CRLF line endings and keep
the trailing spaces `netsh.exe` emits (e.g. `Signal : 84% `). Do not let an editor or git
normalise them; the tests also re-run every fixture with LF-only endings.

| file | provenance |
|---|---|
| `netsh_two_interfaces.txt` | `netsh wlan show interfaces` layout captured on the target PC (Windows 11 25H2, Intel AX201) with a second, disconnected USB adapter added in the layout Windows prints for a disconnected interface (`Radio status` continuation line). |
| `netsh_win11_rssi.txt` | Unmodified layout of a capture on the target PC on 2026-10-05 (single interface; Windows 11 prints `Rssi : <dBm>` after `Signal`). Only SSID, AP BSSID, GUID, physical address and profile were replaced; every other byte, including the readings (82 %, -60 dBm, 721/551 Mbps), is as captured. |
| `netsh_win10_bssid.txt` | Older Windows 10 layout: `BSSID` instead of `AP BSSID`, fractional rates, no `Band`, trailing `Hosted network status`. |
| `netsh_no_interface.txt` | Output on a PC without a wireless adapter. |
| `netsh_wlansvc_stopped.txt` | Output when the WLAN AutoConfig service is stopped. |
| `netsh_location_notice.txt` | Synthetic: Windows 11 24H2+ location-permission notice followed by an interface block without SSID/BSSID. |
| `netsh_location_only.txt` | Synthetic: the location-permission notice alone. |

Sanitised: SSIDs are placeholders (`ATTexample`), MAC/BSSID values come from the IANA
documentation range `00:00:5e:00:53:xx` (RFC 7042), and GUIDs are made up. The connected
interface's numeric values (channel 149, 5 GHz, 802.11ax, 721/649 Mbps, 84 %) are the real
readings from the target PC.
