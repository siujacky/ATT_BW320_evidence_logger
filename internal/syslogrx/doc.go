// Package syslogrx receives the gateway's syslog messages (docs/syslog-snmp-traffic.md §3.2): a
// UDP listener (RFC 5426 transport, port 514 by default) that keeps every datagram from an
// allowed sender exactly as it arrived, with the time it was read and its sender, until the
// monitor drains it into a signed syslog record of the evidence ledger.
//
// # Trust
//
// Syslog over UDP has no authentication, no integrity protection and no delivery guarantee.
// Anything that can reach this computer's port can send datagrams, and on the home network the
// source address of a UDP datagram can be forged. The allow list (the gateway's address, plus
// syslog.allow) keeps other devices' traffic and noise out of the evidence; it is not
// authentication. The records show what this computer received: the exact bytes, the sender's
// address and port as the operating system reported them, and the time this computer's clock
// showed when the datagram was read. They do not prove that the gateway sent a message, nor
// that it sent nothing else: UDP datagrams can be lost on the way, and the limits below drop
// some. The timestamp, host name and the other header fields are what the sender wrote; they
// are never taken as this computer's time.
//
// # Limits
//
// Datagrams from other senders are counted as rejected and never kept (the log names the
// sender, never the content). From the allowed senders, a datagram larger than
// Options.MaxMessage (8 KiB), one beyond Options.MaxPerMinute (2,000) in a minute of receive
// time (UTC calendar minutes, so the records show the cap per minute of their rx times), and one
// that arrives while Options.MaxPending messages wait to be drained are counted as dropped and
// not kept. Drain hands both counts over with the messages, so every record says what it lacks.
// Log entries about these events and about receive errors are rate-limited (one a minute per
// kind, with the number held back), so a flood cannot fill the event log either.
//
// # Messages
//
// Raw is the exact datagram when it is valid UTF-8, RawB64 (standard base64) otherwise; an
// empty datagram has neither. It is never trimmed or rewritten and is the authoritative content.
// The other fields are parsed from it as a convenience (Parse):
//
//	PRI, Facility, Severity  from "<N>" (N from 0 to 191 = facility × 8 + severity)
//	Format "rfc5424"  <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA [MSG]
//	                  ("-" is an empty field; a byte-order mark before MSG is not part of Msg)
//	Format "rfc3164"  <PRI>TIMESTAMP [HOSTNAME] [TAG[[PID]]:] MSG, the TIMESTAMP as
//	                  "Mmm dd hh:mm:ss" (some devices add a year or a fraction of a second) or
//	                  ISO 8601 ("2026-10-05T21:30:01Z"); without HOSTNAME when the first word
//	                  ends like a TAG ("name:" or "name[pid]:")
//	Format "unknown"  anything else: Msg is the text after a valid PRI, or the whole text
//
// TS is the timestamp as written, App the APP-NAME or the TAG, Msg the message without trailing
// CR, LF and NUL characters. Control characters are kept (escaping them is the display's job).
// In a datagram that is not valid UTF-8 the parsed fields show U+FFFD in place of the invalid
// bytes.
package syslogrx
