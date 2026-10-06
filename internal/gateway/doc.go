// Package gateway is the client for the AT&T BGW320-505 gateway web UI
// (docs/DESIGN.md §2 and §8).
//
// It has three layers:
//
//   - Page parsers (ParseSysInfo, ParseBroadband, ParseFiber, ParseLAN, ParseNotification,
//     ParseSyslog, ParseNATTable, ParseDevices, IsLoginPage, SessionsFull). They work on the exact response bytes, never
//     assume valid UTF-8 (the firmware serves windows-1252 and lossy transcriptions contain
//     U+FFFD), never depend on CRLF vs LF, and tolerate the gateway's sloppy markup (unclosed
//     rows, nested forms, labels with trailing &nbsp;). A form reader (form.go) reads a
//     settings page's forms as a browser without JavaScript does, finds controls by their
//     labels and encodes the body such a browser posts.
//   - Derive, a pure function that turns parsed pages into model.GatewayDerived facts using
//     only the gateway's own statements (no inference beyond the documented rules).
//   - Client, which implements contracts.Gateway: sequential, unauthenticated GETs of status
//     pages for snapshots (TLS certificate pinned, redirects recorded but never followed,
//     bodies capped and hashed exactly as received) and rare, rate-limited authenticated
//     operations on the "Broadband Status Notification" (bbevent) setting and the Syslog page
//     (read by its labels; a change is posted only when the form is fully understood, and
//     read back). For the dashboard's Network page it also reads the NAT table (authenticated)
//     and the Device List (unauthenticated); both only read: their forms are never posted.
//
// The gateway access code is only ever used to compute the login form's hashpassword field;
// it never appears in errors, logs or returned data.
package gateway
