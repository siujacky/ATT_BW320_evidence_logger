package gateway

import (
	"context"
	"errors"

	"attmonitor/internal/model"
)

// TEMPORARY stubs so the module builds while the Syslog page support is written (phase 1 of
// docs/syslog-snmp-traffic.md replaces this file).

var errSyslogNotImplemented = errors.New("gateway: the Syslog page is not supported yet")

// Syslog reads the gateway's Syslog page.
func (c *Client) Syslog(ctx context.Context) (model.SyslogSetting, []byte, error) {
	return model.SyslogSetting{}, nil, errSyslogNotImplemented
}

// SetSyslog sets the gateway's Syslog page.
func (c *Client) SetSyslog(ctx context.Context, want model.SyslogTarget) ([]byte, []byte, error) {
	return nil, nil, errSyslogNotImplemented
}
