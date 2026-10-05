// Package ticket builds the printable "AT&T service ticket" report of the last 24 hours (or any
// window) of an att-monitor evidence ledger or exported evidence bundle, written for an AT&T agent
// who has to decide whether to send a technician. Page 1 is a summary sheet that stands alone:
// the customer, four statements (the gateway's own optical level and alarm flags, fiber link
// changes and restarts, outages, the home network), the requested action and the monitoring
// coverage. The details and the evidence follow on the next pages - normally two or three, more on
// a day with many outages. Every page is numbered ("Page 2 of 4") and carries the report's window
// (and account) in its margin.
//
// Build reads only records whose ts lies in the window [From, To), plus the records that state
// setup-time evidence and the signing key (genesis and bootstrap_import, near the start of the
// ledger) and the anchor records that time-stamp the window. Every figure in the report is
// computed from those records - nothing is assumed, and a statement is only made when records
// support it: an empty window yields explicit "no data" wording, an outage is never inferred
// from missing measurements, and the gateway's fiber "Last Change" value is always shown with
// both of its possible readings (UTC or the gateway's local time), because the gateway does not
// say which one it uses. The evidence bundle's name, SHA-256 and verification result are the
// inputs the records cannot give; the report marks them as stated by the program that generated
// it. The raw gateway pages of the setup-time capture are re-parsed with the gateway package's
// pure parsers.
//
// Report.HTML renders a self-contained print document (inline CSS and inline SVG, no scripts,
// no external references, US Letter pages). PrintPDF turns it into a PDF with a headless
// Microsoft Edge (or Google Chrome) found on the computer.
package ticket
