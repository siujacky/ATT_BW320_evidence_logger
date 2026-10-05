package monitor

import (
	"testing"

	"attmonitor/internal/model"
)

// TestStatusMongo: the status carries the MongoDB copy's state when one is configured, and
// nothing otherwise; the callback runs without the monitor's lock held (it may call Status-free
// code that takes time, and must never deadlock against a cycle).
func TestStatusMongo(t *testing.T) {
	r := newRig(t, nil, nil)
	if st := r.m.Status(); st.Mongo != nil {
		t.Fatalf("no MongoDB configured: %+v", st.Mongo)
	}
	want := model.MongoStatus{Enabled: true, Connected: true, Database: "attmonitor", URI: "mongodb://127.0.0.1:27017", LastSeq: 41, HasData: true, Lag: 2}
	r.m.opts.MongoStatus = func() model.MongoStatus {
		if !r.m.mu.TryLock() {
			t.Error("MongoStatus called with the monitor's lock held")
		} else {
			r.m.mu.Unlock()
		}
		return want
	}
	if st := r.m.Status(); st.Mongo == nil || *st.Mongo != want {
		t.Fatalf("mongo %+v, want %+v", st.Mongo, want)
	}
}
