package monitor

import (
	"context"
	"errors"

	"attmonitor/internal/model"
)

// SetGatewaySyslog is a stub: phase 2 of docs/syslog-snmp-traffic.md replaces it with the
// enforced, read-back and recorded setting of the gateway's Syslog page.
func (m *Monitor) SetGatewaySyslog(ctx context.Context, enabled bool, actor string) (model.ConfigChange, error) {
	return model.ConfigChange{}, errors.New("monitor: setting the gateway's Syslog page is not available yet")
}
