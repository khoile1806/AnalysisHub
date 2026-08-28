package threatintel

import "fmt"

// score.go — how a source's raw answer becomes a 0-100 maliciousness score.
//
// The scores are consumed by code that makes decisions: the malware verdict
// floor treats >= 50 as a detection and >= 20 as corroboration, and the intel
// modal calls >= 70 MALICIOUS. A number that does not mean what those thresholds
// assume produces wrong verdicts in both directions, so the mapping is written
// down here rather than being an expression buried in each provider.

// vtScore turns VirusTotal's engine tally into a score.
//
// The previous formula was flagged*100/total, which divides by the ~70-90
// engines VirusTotal runs. Real malware detected by 25 of them scored 35 — below
// the 70 the UI needs to say MALICIOUS, and below the 50 the verdict engine
// needs to call it a detection. Only something as extreme as EICAR (61/63)
// crossed the line, which is why the mis-calibration survived: the one sample
// everybody tests with is the one case the formula gets right.
//
// What actually matters is the COUNT of engines that flagged it, not the share.
// Antivirus coverage of any given family is partial by nature; five independent
// engines agreeing is strong evidence even though it is only 7% of the panel.
// One or two is the range where false positives live, so it scores as
// corroboration rather than proof.
func vtScore(malicious, suspicious, total int) int {
	if total <= 0 {
		return 0
	}
	// A "suspicious" verdict is a weaker claim than "malicious"; count it as half.
	weighted := float64(malicious) + float64(suspicious)/2
	switch {
	case weighted <= 0:
		return 0
	case weighted < 1.5:
		return 25 // a lone engine: plausible false positive
	case weighted < 3:
		return 45
	case weighted < 6:
		return 65
	case weighted < 11:
		return 80
	default:
		return 90
	}
}

// vtMalicious reports whether the tally is strong enough to call a detection.
// Two engines can and do agree on a false positive — most often on packers and
// on dual-use tooling — so the bar is three.
func vtMalicious(malicious, suspicious int) bool {
	return malicious >= 3 || (malicious >= 2 && suspicious >= 2)
}

// otxScore turns an OTX pulse count into a score.
//
// A pulse means "somebody put this indicator in a collection". Researchers
// publish pulses of sinkholes, of popular CDNs, and of every address in a
// report's appendix, so presence in one pulse is not evidence of anything. This
// was the root cause of Microsoft's own signed binaries being reported as
// suspicious: `malicious = count > 0` promoted a single mention to a verdict.
//
// Corroboration grows with independent mentions, so the curve rises, but it is
// capped below the detection threshold: OTX on its own must never be able to
// carry a verdict.
func otxScore(pulses int) int {
	switch {
	case pulses <= 0:
		return 0
	case pulses < 3:
		return 15
	case pulses < 8:
		return 30
	case pulses < 20:
		return 40
	default:
		return 45
	}
}

// otxMalicious is deliberately hard to satisfy. Below this many independent
// pulses the finding contributes a score and nothing more.
func otxMalicious(pulses int) bool { return pulses >= 20 }

// otxSummary states what the number means, so an analyst reading the finding is
// not left to assume a pulse is a detection.
func otxSummary(pulses int) string {
	switch {
	case pulses <= 0:
		return "not present in any community pulse"
	case pulses == 1:
		return "1 community pulse — a single mention, not a detection"
	case pulses < 20:
		return fmt.Sprintf("%d community pulses — corroboration, not a detection", pulses)
	default:
		return fmt.Sprintf("%d community pulses — widely reported", pulses)
	}
}
