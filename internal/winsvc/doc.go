// Package winsvc integrates att-monitor with Windows (docs/DESIGN.md §5, §14):
//
//   - Install / Uninstall / Start / Stop / Status manage the "ATTMonitor" service through the
//     Service Control Manager (automatic delayed start, LocalSystem, restart-on-failure
//     recovery actions, Application event-log source);
//   - Run is the SCM entry point: it reports service state, turns Stop/Shutdown into context
//     cancellation (with a cause that becomes the monitor_stop reason), forwards power
//     events (suspend/resume) so they can be recorded in the evidence ledger, and makes the
//     SCM restart the service whenever the monitor exits without being asked to stop;
//   - NewEventLogHandler is a log/slog handler writing to the Application event log (secret
//     attributes are redacted: every local user can read that log);
//   - SecureDataDir applies the protected data-directory ACL (SecurePrivateDir the
//     administrators-only variant for the key folder). Both refuse system and profile
//     folders, volume roots and folders holding unrelated files, because the change
//     propagates through the whole tree.
//
// Query-only operations (Status) open the SCM with the minimum rights so they work without
// elevation; Install and Uninstall require an elevated administrator.
package winsvc
