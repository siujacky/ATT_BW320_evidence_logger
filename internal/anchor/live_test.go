package anchor

import (
	"context"
	"log/slog"
	"os"
	"testing"
	"time"

	"attmonitor/internal/config"
)

// TestLiveTimestamp time-stamps a random digest at the default public TSAs (DigiCert, FreeTSA).
// Only the 32-byte digest is sent. Run with ATTMON_LIVE=1.
func TestLiveTimestamp(t *testing.T) {
	if os.Getenv("ATTMON_LIVE") != "1" {
		t.Skip("set ATTMON_LIVE=1 to contact the public TSAs")
	}
	urls := config.Default().Anchoring.TSAURLs
	digest := randomDigest(t)
	c := New(Options{
		URLs:      urls,
		Timeout:   30 * time.Second,
		UserAgent: "att-monitor-live-test",
		Logger:    slog.New(slog.NewTextHandler(testWriter{t}, &slog.HandlerOptions{Level: slog.LevelDebug})),
	})
	start := time.Now()
	results := c.Timestamp(context.Background(), digest)
	if len(results) != len(urls) {
		t.Fatalf("%d results for %d URLs", len(results), len(urls))
	}
	for _, r := range results {
		t.Run(r.URL, func(t *testing.T) {
			if r.Err != nil {
				t.Fatalf("Err = %v", r.Err)
			}
			t.Logf("genTime=%s serial=%s policy=%s nonce=%s chainOK=%v tsa=%q token=%d bytes",
				r.Info.GenTime.Format(time.RFC3339Nano), r.Info.Serial, r.Info.Policy, r.Info.Nonce,
				r.Info.ChainOK, r.Info.TSAName, len(r.Token))
			if skew := r.Info.GenTime.Sub(start); skew < -5*time.Minute || skew > 5*time.Minute {
				t.Errorf("genTime %v is %v away from the local clock", r.Info.GenTime, skew)
			}
			if !r.Info.ChainOK {
				t.Errorf("ChainOK = false: TSA certificate did not chain to a trusted root (%s)", r.Info.ChainNote)
			} else if r.Info.ChainNote != "" {
				t.Errorf("ChainNote = %q with ChainOK", r.Info.ChainNote)
			}
			// The stored token verifies again, and only for this digest.
			if info, err := c.VerifyToken(r.Token, digest); err != nil || info != r.Info {
				t.Errorf("re-verify = %+v, %v", info, err)
			}
			if _, err := c.VerifyToken(r.Token, flip(digest, 0, 1)); err == nil {
				t.Error("token verified for another digest")
			}
		})
	}
}

// testWriter routes log output to t.Log.
type testWriter struct{ t *testing.T }

func (w testWriter) Write(p []byte) (int, error) {
	w.t.Log(string(p))
	return len(p), nil
}
