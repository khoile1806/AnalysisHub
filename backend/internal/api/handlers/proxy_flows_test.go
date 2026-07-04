package handlers

import (
	"strconv"
	"testing"

	"github.com/analysishub/backend/internal/egress"
	"github.com/analysishub/backend/internal/models"
)

// TestRingWrapAroundOrder exercises the O(1) circular buffer directly (no DB /
// writer goroutine — Sink's DB send hits the select default on a nil channel).
func TestRingWrapAroundOrder(t *testing.T) {
	r := &ProxyFlowRecorder{ring: make([]models.ProxyFlow, flowRingCap)}

	total := flowRingCap + 5 // force a wrap
	for i := 0; i < total; i++ {
		r.Sink(egress.Flow{Host: strconv.Itoa(i)})
	}

	if r.count != flowRingCap {
		t.Fatalf("count = %d; want %d (capped)", r.count, flowRingCap)
	}

	got := r.recent(3)
	if len(got) != 3 {
		t.Fatalf("recent(3) len = %d; want 3", len(got))
	}
	// Newest first: the last three hosts pushed were total-1, total-2, total-3.
	want := []string{strconv.Itoa(total - 1), strconv.Itoa(total - 2), strconv.Itoa(total - 3)}
	for i, w := range want {
		if got[i].Host != w {
			t.Errorf("recent[%d].Host = %q; want %q", i, got[i].Host, w)
		}
	}

	// The oldest survivor should be index (total - flowRingCap); anything older
	// must have been overwritten.
	all := r.recent(flowRingCap)
	oldest := all[len(all)-1].Host
	if oldest != strconv.Itoa(total-flowRingCap) {
		t.Errorf("oldest survivor = %q; want %q", oldest, strconv.Itoa(total-flowRingCap))
	}
}

func TestClearRingResets(t *testing.T) {
	r := &ProxyFlowRecorder{ring: make([]models.ProxyFlow, flowRingCap), aggByProxy: map[string]int{}}
	r.Sink(egress.Flow{Host: "a"})
	r.Sink(egress.Flow{Host: "b"})
	r.clearRing()
	s := r.snapshot()
	if r.count != 0 || len(r.recent(10)) != 0 || s.count != 0 || len(s.byProxy) != 0 {
		t.Errorf("after clear: count=%d recent=%d aggCount=%d; want all 0", r.count, len(r.recent(10)), s.count)
	}
}

// TestSnapshotMatchesRing verifies the incrementally-maintained aggregates equal
// a fresh recompute over the ring, including after eviction (wrap-around).
func TestSnapshotMatchesRing(t *testing.T) {
	r := &ProxyFlowRecorder{ring: make([]models.ProxyFlow, flowRingCap), aggByProxy: map[string]int{}}
	labels := []string{"osint", "direct", "default"}
	total := flowRingCap + 137 // force eviction
	for i := 0; i < total; i++ {
		via := i%3 != 0
		host := "8.8.8.8"
		if i%5 == 0 {
			host = "127.0.0.1" // loopback direct
		}
		r.Sink(egress.Flow{
			ProxyLabel: labels[i%len(labels)], ViaProxy: via, Host: host,
			BytesIn: int64(i % 10), BytesOut: int64(i % 4),
			Status: []int{200, 404, 500}[i%3], Leaked: i%7 == 0 && !via,
		})
	}

	// Recompute from the ring contents.
	all := r.recent(flowRingCap)
	var wantIn, wantOut int64
	wErr, wProx, wDir, wLeak, wDirEx := 0, 0, 0, 0, 0
	wByProxy := map[string]int{}
	for _, f := range all {
		wantIn += f.BytesIn
		wantOut += f.BytesOut
		if f.Error != "" || f.Status >= 400 {
			wErr++
		}
		if f.ViaProxy {
			wProx++
		} else {
			wDir++
			if !isLoopbackFlowHost(f.Host) {
				wDirEx++
			}
		}
		if f.Leaked {
			wLeak++
		}
		wByProxy[f.ProxyLabel]++
	}

	s := r.snapshot()
	if s.count != len(all) || s.bytesIn != wantIn || s.bytesOut != wantOut ||
		s.errs != wErr || s.proxied != wProx || s.direct != wDir ||
		s.leaked != wLeak || s.directExternal != wDirEx {
		t.Fatalf("snapshot mismatch: got %+v; want in=%d out=%d err=%d prox=%d dir=%d leak=%d dirEx=%d",
			s, wantIn, wantOut, wErr, wProx, wDir, wLeak, wDirEx)
	}
	for k, v := range wByProxy {
		if s.byProxy[k] != v {
			t.Errorf("byProxy[%q] = %d; want %d", k, s.byProxy[k], v)
		}
	}
}
