// Package sysinfo describes the monitoring computer (model.HostInfo) and the code that is
// running (model.SoftwareInfo). Both are recorded in the genesis and monitor_start ledger
// records (docs/DESIGN.md §7), so a reader of the evidence can tell which machine, operating
// system and exact executable (by SHA-256) produced every record.
//
// Every value is best effort: a field that cannot be determined is left empty (or, for the
// OS name, falls back to a generic "Windows" description) instead of failing, because a
// monitor that refused to start over a descriptive field would lose evidence.
package sysinfo
