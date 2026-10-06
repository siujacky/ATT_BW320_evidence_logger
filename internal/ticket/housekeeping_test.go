package ticket

import (
	"testing"
	"time"

	"attmonitor/internal/model"
)

// TestHousekeepingEvents: the gateway events about this monitor - the pinned certificate and the
// reads of the gateway's own settings, the outage redirect and the syslog (a syslog_setting event
// is recorded with every daily settings check, also when the page was not understood) - are
// counted among the other events, never listed; the events about the service are.
func TestHousekeepingEvents(t *testing.T) {
	for _, k := range []string{model.GwEvCertPinned, model.GwEvNotificationSetting, model.GwEvSyslogSetting} {
		if !housekeeping(k) {
			t.Errorf("%s is housekeeping", k)
		}
	}
	for _, k := range []string{model.GwEvReboot, model.GwEvOpticalAlarm, model.GwEvOpticalLinkChange, model.GwEvCertChanged, model.GwEvUnreachable} {
		if housekeeping(k) {
			t.Errorf("%s concerns the service and is listed", k)
		}
	}

	s := realScenario(t)
	at := s.to.Add(-time.Second) // after the scenario's last record, inside the window
	s.f.add(at, model.TypeGatewayEvent, model.GatewayEvent{Kind: model.GwEvSyslogSetting,
		After: "on -> 192.168.1.71:514, level Informational", Detail: "Syslog page (Diagnostics > Syslog) read: ..."})
	s.f.add(at.Add(time.Millisecond), model.TypeGatewayEvent, model.GatewayEvent{Kind: model.GwEvSyslogSetting,
		Before: "on -> 192.168.1.71:514, level Informational", After: "unknown", Detail: "Syslog page read but not understood: ..."})
	s.f.add(at.Add(2*time.Millisecond), model.TypeGatewayEvent, model.GatewayEvent{Kind: model.GwEvNotificationSetting, After: "off"})
	rep := mustBuild(t, s, s.options())
	// The scenario's own events: the optical alarm (listed) and the pinned certificate (not).
	if len(rep.Events) != 1 || rep.Events[0].Kind != model.GwEvOpticalAlarm || rep.EventsOther != 4 {
		t.Errorf("events = %+v other %d", rep.Events, rep.EventsOther)
	}
}
