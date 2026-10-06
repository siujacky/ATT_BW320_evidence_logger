package web

import (
	"context"
	"net/http"
	"time"
)

// liveTrafficTimeout bounds one reading of the flow meter: the monitor may read the gateway's
// counters for it, and the dashboard asks again 5 seconds after an answer.
const liveTrafficTimeout = 10 * time.Second

// msgNoLiveTraffic answers GET /api/traffic/live when the monitor offers no flow meter.
const msgNoLiveTraffic = "the live traffic meter is not available: this att-monitor offers no live reading of the gateway's counters"

// handleLiveTraffic serves GET /api/traffic/live: the flow meter (model.LiveTraffic, docs/
// syslog-snmp-traffic.md §3.3), the newest WAN rates from the gateway's own counters and this
// computer's, with their recent history. The monitor reads the gateway's counters for it at
// most every few seconds whoever asks; nothing of it is recorded (the gateway snapshots are the
// evidence). Without a live traffic source the endpoint answers 404.
func (s *Server) handleLiveTraffic(w http.ResponseWriter, r *http.Request) {
	if s.live == nil {
		writeError(w, http.StatusNotFound, msgNoLiveTraffic)
		return
	}
	// Read-only: tied to the request, so a closed tab stops the work.
	ctx, cancel := context.WithTimeout(r.Context(), liveTrafficTimeout)
	defer cancel()
	lt, err := s.live.LiveTraffic(ctx)
	if err != nil {
		s.writeErr(w, "live traffic", err)
		return
	}
	writeJSON(w, http.StatusOK, lt)
}
