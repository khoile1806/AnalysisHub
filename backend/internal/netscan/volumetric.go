package netscan

import (
	"fmt"
	"sort"
	"strings"
)

// volumetric.go — detection for attacks that have no signature.
//
// The gap this fills was found by running the pipeline over real capture files: a
// pcap of an hping3 flood produced 191 alerts, every one of them a Suricata
// stream-state event, and a capture explicitly named for DoS indicators produced
// ZERO alerts and a verdict of "benign" — 55,611 packets spread over 18,540 flows,
// roughly three packets per flow, which is a flood by inspection.
//
// Signature matching cannot see this. A SYN flood contains no malicious byte
// pattern; what makes it an attack is its SHAPE — thousands of flows that never
// complete, one source touching hundreds of ports, one port touched across a
// whole subnet. Those are properties of the flow table, and the flow table was
// already being collected; nothing was reading it this way.

const (
	// floodMinFlows is the smallest flow count worth calling a flood. Below this a
	// short capture of ordinary browsing can look bursty.
	floodMinFlows = 500
	// floodMaxPktsPerFlow: a completed TCP conversation costs far more than this.
	// Flows this thin are handshakes that never finished — the definition of a
	// SYN/connection flood.
	floodMaxPktsPerFlow = 5.0
	// scanMinPorts is how many distinct ports one source must touch on one target
	// before it is a port scan rather than an application using a few channels.
	scanMinPorts = 100
	// sweepMinHosts is how many distinct destinations one source must touch on the
	// SAME port before it is a host sweep.
	sweepMinHosts = 50
	// topTalkerShare: one source responsible for this much of all flows is driving
	// the capture, not participating in it.
	topTalkerShare = 0.60
)

// volumetricFindings inspects the flow table for attacks that have shape rather
// than content: floods, port scans and host sweeps.
func volumetricFindings(res *NetworkResult) []NetworkFinding {
	if res == nil || len(res.Flows) < floodMinFlows/10 {
		return nil
	}
	var out []NetworkFinding

	total := len(res.Flows)
	var totalPkts int64
	bySrc := map[string]int{}
	portsBySrcDst := map[string]map[int]bool{}
	hostsBySrcPort := map[string]map[string]bool{}
	flowsByTarget := map[string]int{}
	pktsByTarget := map[string]int64{}

	for i := range res.Flows {
		f := &res.Flows[i]
		totalPkts += f.Pkts
		bySrc[f.Src]++

		sd := f.Src + "->" + f.Dst
		if portsBySrcDst[sd] == nil {
			portsBySrcDst[sd] = map[int]bool{}
		}
		portsBySrcDst[sd][f.Dport] = true

		sp := fmt.Sprintf("%s:%d", f.Src, f.Dport)
		if hostsBySrcPort[sp] == nil {
			hostsBySrcPort[sp] = map[string]bool{}
		}
		hostsBySrcPort[sp][f.Dst] = true

		tgt := fmt.Sprintf("%s:%d/%s", f.Dst, f.Dport, strings.ToLower(f.Proto))
		flowsByTarget[tgt]++
		pktsByTarget[tgt] += f.Pkts
	}

	// ── Flood ────────────────────────────────────────────────────────────────
	// Many flows at one target, each too thin to be a real conversation.
	for _, tgt := range sortedByCount(flowsByTarget) {
		n := flowsByTarget[tgt]
		if n < floodMinFlows {
			break // sorted descending — nothing after this qualifies either
		}
		perFlow := float64(pktsByTarget[tgt]) / float64(n)
		if perFlow > floodMaxPktsPerFlow {
			continue // conversations completed; volume alone is not an attack
		}
		out = append(out, NetworkFinding{
			Severity: "high", Category: "dos", Source: "flow-analysis",
			Indicator: tgt,
			Title:     fmt.Sprintf("Connection flood against %s", tgt),
			Detail: fmt.Sprintf(
				"%d flows to this target average %.1f packets each. A completed TCP conversation costs far more "+
					"than that, so these are connection attempts that never finish — the shape of a SYN/connection "+
					"flood. No signature can match this: what identifies it is the flow pattern, not the payload.",
				n, perFlow),
		})
		if len(out) >= 3 {
			break
		}
	}

	// ── Port scan ────────────────────────────────────────────────────────────
	for _, sd := range sortedBySetSize(portsBySrcDst) {
		ports := len(portsBySrcDst[sd])
		if ports < scanMinPorts {
			break
		}
		parts := strings.SplitN(sd, "->", 2)
		out = append(out, NetworkFinding{
			Severity: "medium", Category: "recon", Source: "flow-analysis",
			Indicator: sd,
			Title:     fmt.Sprintf("Port scan: %s probed %d ports on %s", parts[0], ports, parts[1]),
			Detail: fmt.Sprintf(
				"One source touched %d distinct destination ports on a single host. Legitimate software uses a "+
					"handful of ports; enumerating this many is reconnaissance.", ports),
		})
		if len(out) >= 6 {
			break
		}
	}

	// ── Host sweep ───────────────────────────────────────────────────────────
	for _, sp := range sortedBySetSize(hostsBySrcPort) {
		hosts := len(hostsBySrcPort[sp])
		if hosts < sweepMinHosts {
			break
		}
		out = append(out, NetworkFinding{
			Severity: "medium", Category: "recon", Source: "flow-analysis",
			Indicator: sp,
			Title:     fmt.Sprintf("Host sweep: %s contacted %d hosts on the same port", sp, hosts),
			Detail: fmt.Sprintf(
				"One source probed the same service across %d distinct destinations — a sweep looking for that "+
					"service, which is how lateral movement and worm propagation begin.", hosts),
		})
		if len(out) >= 9 {
			break
		}
	}

	// ── Single source dominating the capture ─────────────────────────────────
	// Context rather than a verdict on its own: it tells the reader which host to
	// look at first when the capture is otherwise a wall of flows.
	if total >= floodMinFlows {
		for src, n := range bySrc {
			if float64(n)/float64(total) >= topTalkerShare {
				out = append(out, NetworkFinding{
					Severity: "info", Category: "dos", Source: "flow-analysis",
					Indicator: src,
					Title:     fmt.Sprintf("%s originated %d%% of all flows", src, n*100/total),
					Detail: fmt.Sprintf(
						"%d of %d flows in this capture come from one address. Whatever else the capture shows, "+
							"that host is driving it.", n, total),
				})
				break
			}
		}
	}
	return out
}

// sortedByCount returns keys ordered by value descending, so a scan can stop at
// the first entry below the threshold.
func sortedByCount(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if m[keys[i]] != m[keys[j]] {
			return m[keys[i]] > m[keys[j]]
		}
		return keys[i] < keys[j] // stable for equal counts
	})
	return keys
}

// sortedBySetSize orders keys by the size of their set value, descending.
func sortedBySetSize[T comparable](m map[string]map[T]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if len(m[keys[i]]) != len(m[keys[j]]) {
			return len(m[keys[i]]) > len(m[keys[j]])
		}
		return keys[i] < keys[j]
	})
	return keys
}
