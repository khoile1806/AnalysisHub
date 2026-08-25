package netscan

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"time"
)

// beacon.go — detection for command-and-control channels that carry no signature.
//
// This is the same argument volumetric.go makes, moved from the space axis to the
// time axis. A flood is recognisable because thousands of flows are too thin to be
// conversations; a beacon is recognisable because a handful of flows arrive on a
// schedule. Neither contains a malicious byte pattern, so neither can be matched by
// a rule, however many rules there are.
//
// Flow.Start was already being collected — its declaration in netscan.go even
// carries the comment "(for beaconing)". The timestamps were there the whole time
// and nothing read them in this direction.
//
// What separates an implant from ordinary periodic traffic is regularity under
// jitter. Malware sleeps for an interval and adds a random fraction to defeat
// exactly this analysis, so the mean is useless (one outlier drags it) and the
// standard deviation is worse. The median and the median absolute deviation
// survive both the jitter and the occasional missed check-in.

const (
	// beaconMinFlows: fewer connections than this cannot establish a period. Seven
	// intervals is the smallest sample where a coincidence is not the likely
	// explanation.
	beaconMinFlows = 8
	// beaconMinInterval keeps floods out. Anything faster than this is volumetric,
	// belongs to volumetric.go, and would otherwise be reported twice.
	beaconMinInterval = 1.0
	// beaconMaxInterval: beyond this the capture almost never holds enough
	// check-ins for the finding to mean anything.
	beaconMaxInterval = 6 * 3600.0
	// beaconStrongJitter / beaconWeakJitter are MAD/median ratios. Cobalt Strike's
	// default 0% jitter lands near 0.0; its common 20-30% setting still lands well
	// under the weak bound, while human-driven traffic scatters far above it.
	beaconStrongJitter = 0.15
	beaconWeakJitter   = 0.35
	// beaconSizeRegular: request sizes this consistent mean a fixed-format
	// check-in rather than content that varies with what the user is doing.
	beaconSizeRegular = 0.15
	beaconMaxReported = 5
)

// beaconChannel is one (src → dst:port) pair considered as a candidate channel.
type beaconChannel struct {
	src, dst string
	dport    int
	proto    string
	times    []float64 // flow start, seconds since epoch
	sizes    []float64
	bytes    int64
}

// beaconFindings reports destinations contacted on a schedule.
func beaconFindings(res *NetworkResult) []NetworkFinding {
	if res == nil || len(res.Flows) < beaconMinFlows {
		return nil
	}

	channels := map[string]*beaconChannel{}
	for i := range res.Flows {
		f := &res.Flows[i]
		ts, ok := parseFlowTime(f.Start)
		if !ok {
			continue
		}
		key := fmt.Sprintf("%s|%s|%d|%s", f.Src, f.Dst, f.Dport, f.Proto)
		c := channels[key]
		if c == nil {
			c = &beaconChannel{src: f.Src, dst: f.Dst, dport: f.Dport, proto: f.Proto}
			channels[key] = c
		}
		c.times = append(c.times, ts)
		c.sizes = append(c.sizes, float64(f.ToServer))
		c.bytes += f.Bytes
	}
	if len(channels) == 0 {
		return nil // no usable timestamps — say nothing rather than guess
	}

	// Resolve destinations to the name that was looked up, so the finding names the
	// domain an analyst can block rather than an address they have to pivot on.
	names := map[string]string{}
	for _, d := range res.DNS {
		for _, a := range d.Answers {
			if _, seen := names[a]; !seen && d.Query != "" {
				names[a] = d.Query
			}
		}
	}

	type scored struct {
		f     NetworkFinding
		order float64 // lower jitter first
	}
	var out []scored

	for _, c := range channels {
		if len(c.times) < beaconMinFlows {
			continue
		}
		sort.Float64s(c.times)
		gaps := make([]float64, 0, len(c.times)-1)
		for i := 1; i < len(c.times); i++ {
			if g := c.times[i] - c.times[i-1]; g > 0 {
				gaps = append(gaps, g)
			}
		}
		if len(gaps) < beaconMinFlows-1 {
			continue
		}
		period := median(gaps)
		if period < beaconMinInterval || period > beaconMaxInterval {
			continue
		}
		jitter := madRatio(gaps, period)
		if jitter > beaconWeakJitter {
			continue
		}

		severity := "medium"
		if jitter <= beaconStrongJitter {
			severity = "high"
		}
		// A fixed-size check-in on top of a fixed interval is the signature of a
		// generated implant rather than of software that happens to poll.
		sizeNote := ""
		if sm := median(c.sizes); sm > 0 {
			if sr := madRatio(c.sizes, sm); sr <= beaconSizeRegular {
				sizeNote = fmt.Sprintf(" Request sizes are equally regular (median %.0f bytes, %.0f%% deviation), "+
					"so each check-in carries the same fixed-format message.", sm, sr*100)
				if severity == "medium" {
					severity = "high"
				}
			}
		}
		// NTP is periodic by design and by far the most common benign match. Report
		// it — a beacon can hide on any port — but do not rank it as a likely implant.
		if c.dport == 123 {
			severity = "info"
		}

		target := fmt.Sprintf("%s:%d/%s", c.dst, c.dport, strings.ToLower(c.proto))
		label := c.dst
		if n := names[c.dst]; n != "" {
			label = fmt.Sprintf("%s (%s)", n, c.dst)
		}
		out = append(out, scored{
			order: jitter,
			f: NetworkFinding{
				Severity: severity, Category: "c2", Source: "flow-analysis",
				Indicator: c.dst,
				Title: fmt.Sprintf("Beaconing: %s contacted %s every %s (jitter %.0f%%)",
					c.src, label, humanInterval(period), jitter*100),
				Detail: fmt.Sprintf(
					"%d connections to %s spaced a median of %s apart, deviating by only %.0f%%. Traffic a person "+
						"generates is bursty and irregular; a schedule this steady is a program checking in.%s "+
						"Total %d bytes. No signature matches this — the evidence is the timing, not the payload.",
					len(c.times), target, humanInterval(period), jitter*100, sizeNote, c.bytes),
			},
		})
	}

	sort.Slice(out, func(i, j int) bool { return out[i].order < out[j].order })
	findings := make([]NetworkFinding, 0, beaconMaxReported)
	for i, s := range out {
		if i >= beaconMaxReported {
			break
		}
		findings = append(findings, s.f)
	}
	return findings
}

// parseFlowTime accepts the timestamp layouts Suricata and Zeek emit. A flow whose
// time cannot be read is skipped rather than defaulted: a fabricated timestamp
// would manufacture a period out of nothing.
func parseFlowTime(s string) (float64, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, false
	}
	for _, layout := range []string{
		"2006-01-02T15:04:05.999999-0700",
		"2006-01-02T15:04:05.999999Z0700",
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02 15:04:05.999999",
	} {
		if t, err := time.Parse(layout, s); err == nil {
			return float64(t.UnixNano()) / 1e9, true
		}
	}
	return 0, false
}

func median(v []float64) float64 {
	if len(v) == 0 {
		return 0
	}
	c := append([]float64(nil), v...)
	sort.Float64s(c)
	n := len(c)
	if n%2 == 1 {
		return c[n/2]
	}
	return (c[n/2-1] + c[n/2]) / 2
}

// madRatio is the median absolute deviation expressed as a fraction of the median:
// a scale-free measure of "how regular is this". Chosen over the standard deviation
// because one missed check-in produces a double-length gap, and a mean-based
// measure would let that single outlier hide the pattern.
func madRatio(v []float64, med float64) float64 {
	if med <= 0 || len(v) == 0 {
		return math.Inf(1)
	}
	dev := make([]float64, len(v))
	for i, x := range v {
		dev[i] = math.Abs(x - med)
	}
	return median(dev) / med
}

func humanInterval(sec float64) string {
	switch {
	case sec < 90:
		return fmt.Sprintf("%.0fs", sec)
	case sec < 5400:
		return fmt.Sprintf("%.1fm", sec/60)
	default:
		return fmt.Sprintf("%.1fh", sec/3600)
	}
}
