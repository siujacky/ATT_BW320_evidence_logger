//go:build windows

package export

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"attmonitor/internal/config"
	"attmonitor/internal/model"
)

// The defaults quoted by the report are the ones of internal/config (which only builds on
// Windows, so this package decodes the recorded configuration itself), and the recorded
// configuration - the JSON of config.Config that monitor_start carries - decodes to the values
// the monitor uses.
func TestThresholdDefaultsMatchConfig(t *testing.T) {
	c := config.Default()
	d := defaultParams()
	if d.fast != c.Probes.FastInterval.Duration || d.timeout != c.Probes.Timeout.Duration || d.fresh != c.Incident.SnapshotFreshness.Duration ||
		d.open != c.Incident.OpenAfterCycles || d.close != c.Incident.CloseAfterCycles || d.window != c.Incident.WindowCycles ||
		d.loss != c.Incident.LossDegradedPct || d.lat != c.Incident.LatencyDegradedMs || d.gwLat != c.Incident.GatewayLatencyOkMs {
		t.Errorf("local defaults %+v differ from config.Default() %+v / %+v", d, c.Probes, c.Incident)
	}
	var targets []string
	for _, p := range c.Probes.Targets {
		if p.Role == model.RoleInet {
			targets = append(targets, p.Target)
		}
	}
	if strings.Join(targets, ",") != strings.Join(defaultInternetTargets, ",") {
		t.Errorf("default internet targets %v, config %v", defaultInternetTargets, targets)
	}

	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	p, err := parseRecordedConfig(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.diff(d)) != 0 {
		t.Errorf("recorded defaults decode with differences: %v", p.diff(d))
	}

	c.Probes.FastInterval = config.D(5 * time.Second)
	c.Incident.WindowCycles = 10
	c.Incident.LossDegradedPct = 12.5
	c.Incident.SnapshotFreshness = config.D(90 * time.Second)
	c.Probes.Targets = c.Probes.Targets[:4] // gateway, gateway TCP, next hop, Cloudflare ICMP
	raw, _ = json.Marshal(c)
	p, err = parseRecordedConfig(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(p.diff(d), "; "); got != "fast_interval 10s -> 5s; window_cycles 6 -> 10; loss_degraded_pct 20 -> 12.5; snapshot_freshness 2m30s -> 1m30s; internet targets 1.1.1.1, 8.8.8.8, 9.9.9.9, 1.1.1.1:443, 8.8.8.8:443 -> 1.1.1.1" {
		t.Errorf("diff = %s", got)
	}
}
