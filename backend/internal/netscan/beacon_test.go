package netscan

import (
	"fmt"
	"math"
	"strings"
	"testing"
	"time"
)

// flowsAt builds a channel of flows starting at t0 and repeating every `period`
// seconds, with each gap displaced by the matching fraction in `jitter`.
func flowsAt(dst string, dport int, period float64, jitter []float64, toServer int64) []Flow {
	base := time.Date(2026, 3, 4, 10, 0, 0, 0, time.UTC)
	var out []Flow
	at := 0.0
	for i := 0; i <= len(jitter); i++ {
		ts := base.Add(time.Duration(at * float64(time.Second)))
		out = append(out, Flow{
			Src: "10.1.1.50", Sport: 40000 + i, Dst: dst, Dport: dport, Proto: "TCP",
			Bytes: 900, ToServer: toServer, ToClient: 400, Pkts: 12,
			Start: ts.Format("2006-01-02T15:04:05.999999-0700"),
		})
		if i < len(jitter) {
			at += period * (1 + jitter[i])
		}
	}
	return out
}

func evenJitter(n int, amt float64) []float64 {
	j := make([]float64, n)
	for i := range j {
		if i%2 == 0 {
			j[i] = amt
		} else {
			j[i] = -amt
		}
	}
	return j
}

func findingFor(fs []NetworkFinding, indicator string) *NetworkFinding {
	for i := range fs {
		if fs[i].Indicator == indicator {
			return &fs[i]
		}
	}
	return nil
}

func TestBeaconDetectsRegularCheckIn(t *testing.T) {
	res := &NetworkResult{Flows: flowsAt("203.0.113.9", 443, 60, evenJitter(11, 0.05), 512)}
	res.DNS = []DNSRec{{Query: "cdn-telemetry.example", Answers: []string{"203.0.113.9"}}}

	got := beaconFindings(res)
	f := findingFor(got, "203.0.113.9")
	if f == nil {
		t.Fatalf("a 60s check-in with 5%% jitter must be reported, got %d finding(s)", len(got))
	}
	if f.Severity != "high" {
		t.Errorf("severity = %q, want high (low jitter + constant request size)", f.Severity)
	}
	if f.Category != "c2" {
		t.Errorf("category = %q, want c2", f.Category)
	}
	// The finding has to name the domain, because that is what gets blocked.
	if !strings.Contains(f.Title, "cdn-telemetry.example") {
		t.Errorf("title should resolve the address to its queried name: %s", f.Title)
	}
}

func TestBeaconSurvivesMissedCheckIn(t *testing.T) {
	// One doubled gap is a missed beacon, not a different pattern. A mean/stddev
	// measure would be dragged out of range by it; the MAD must not be.
	j := evenJitter(11, 0.05)
	j[4] = 1.0 // one interval twice as long
	res := &NetworkResult{Flows: flowsAt("203.0.113.9", 8443, 30, j, 256)}
	if findingFor(beaconFindings(res), "203.0.113.9") == nil {
		t.Fatal("a single missed check-in must not hide the schedule")
	}
}

func TestBeaconIgnoresIrregularTraffic(t *testing.T) {
	// Human-driven traffic: gaps scattered across an order of magnitude.
	j := []float64{2.4, -0.7, 5.1, -0.85, 1.2, 3.9, -0.6, 8.0, -0.9, 4.4, 0.3}
	res := &NetworkResult{Flows: flowsAt("198.51.100.7", 443, 40, j, 1500)}
	if got := beaconFindings(res); len(got) != 0 {
		t.Fatalf("irregular browsing must not be called a beacon, got: %s", got[0].Title)
	}
}

func TestBeaconIgnoresFloods(t *testing.T) {
	// Sub-second regularity is a flood; volumetric.go owns it and reporting it
	// here as well would double-count the same evidence.
	res := &NetworkResult{Flows: flowsAt("192.0.2.5", 80, 0.02, evenJitter(40, 0.02), 60)}
	if got := beaconFindings(res); len(got) != 0 {
		t.Fatalf("a sub-second flood must be left to volumetric detection, got: %s", got[0].Title)
	}
}

func TestBeaconIgnoresTooFewSamples(t *testing.T) {
	res := &NetworkResult{Flows: flowsAt("203.0.113.9", 443, 60, evenJitter(4, 0.02), 512)}
	if got := beaconFindings(res); len(got) != 0 {
		t.Fatalf("5 connections cannot establish a period, got: %s", got[0].Title)
	}
}

func TestBeaconSkipsFlowsWithoutTimestamps(t *testing.T) {
	// A missing timestamp must drop the flow, never default to zero: a run of
	// zeroes would manufacture a perfectly regular period out of nothing.
	flows := flowsAt("203.0.113.9", 443, 60, evenJitter(11, 0.02), 512)
	for i := range flows {
		flows[i].Start = ""
	}
	if got := beaconFindings(&NetworkResult{Flows: flows}); len(got) != 0 {
		t.Fatalf("flows without timestamps must yield nothing, got: %s", got[0].Title)
	}
}

func TestBeaconNTPIsInformationalOnly(t *testing.T) {
	res := &NetworkResult{Flows: flowsAt("203.0.113.123", 123, 64, evenJitter(11, 0.03), 48)}
	f := findingFor(beaconFindings(res), "203.0.113.123")
	if f == nil {
		t.Fatal("NTP is still reported — a beacon can hide on any port")
	}
	if f.Severity != "info" {
		t.Errorf("severity = %q, want info: NTP is periodic by design", f.Severity)
	}
}

func TestParseFlowTimeLayouts(t *testing.T) {
	for _, s := range []string{
		"2026-03-04T10:00:00.123456+0000",
		"2026-03-04T10:00:00.123456Z",
		"2026-03-04T10:00:00Z",
		"2026-03-04 10:00:00.123456",
	} {
		if _, ok := parseFlowTime(s); !ok {
			t.Errorf("parseFlowTime(%q) failed", s)
		}
	}
	if _, ok := parseFlowTime("not a time"); ok {
		t.Error("parseFlowTime accepted garbage")
	}
}

func TestMadRatioIsOutlierResistant(t *testing.T) {
	v := []float64{60, 60, 61, 59, 60, 60, 61, 240} // one missed check-in
	got := madRatio(v, median(v))
	if got > 0.05 {
		t.Errorf("madRatio = %.3f, want <= 0.05 despite the outlier", got)
	}
	if math.IsInf(madRatio(nil, 0), 1) != true {
		t.Error("madRatio of an empty sample must be +Inf so nothing is reported")
	}
}

func TestHumanInterval(t *testing.T) {
	for _, c := range []struct{ in, want float64 }{{30, 30}, {600, 600}, {7200, 7200}} {
		if s := humanInterval(c.in); s == "" {
			t.Errorf("humanInterval(%v) empty", c.in)
		}
	}
	if s := humanInterval(45); s != "45s" {
		t.Errorf("humanInterval(45) = %s", s)
	}
	if s := humanInterval(600); s != "10.0m" {
		t.Errorf("humanInterval(600) = %s", s)
	}
	if s := humanInterval(7200); s != "2.0h" {
		t.Errorf("humanInterval(7200) = %s", s)
	}
	_ = fmt.Sprint()
}
