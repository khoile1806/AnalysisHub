package netscan

// ja3_blocklist.go — an offline, bundled blocklist of TLS client fingerprints
// (JA3 MD5) associated with malware / offensive-security tooling. It is a curated
// SEED set drawn from public research (abuse.ch SSLBL JA3, sslbl.abuse.ch and
// community reports); extend it as your own intel matures. Matching is offline —
// no external lookup — so it works in an air-gapped SOC.
//
// NOTE: JA3 alone is a weak signal (TLS stacks are shared across many programs),
// so a hit is treated as a strong lead that raises the verdict floor to
// suspicious/malicious via the deterministic fusion, not an automatic conviction.
var maliciousJA3 = map[string]string{
	// Widely-cited malware/tooling JA3 client fingerprints. Keys MUST be lowercase
	// 32-hex MD5. Extend this map as your own intel matures.
	"e7d705a3286e19ea42f587b344ee6865": "Metasploit/Meterpreter (reverse_https)",
	"72a589da586844d7f0818ce684948eea": "Trickbot",
	"6734f37431670b3ab4292b8f60f29984": "Cobalt Strike (malleable C2 profile)",
	"a0e9f5d64349fb13191bc781f81f42e1": "Standard TLS client seen in commodity malware",
}
