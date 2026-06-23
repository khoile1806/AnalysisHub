package osint

import (
	"strings"

	"github.com/forensichub/backend/internal/models"
)

// computeExposure rolls a scan's findings up into a single 0-100 exposure score
// and a grade band. It reloads the findings so it runs on the post-corroboration
// severities/confidence (after corroborateFindings has adjusted them). The score
// is bucketed by exposure type with per-bucket caps so one noisy collector can't
// dominate, then summed and capped at 100.
func (e *Engine) computeExposure(scan *models.OsintScan) {
	var fs []models.OsintFinding
	e.db.Where("scan_id = ?", scan.ID).Find(&fs)

	score := exposureScore(fs)
	grade := exposureGrade(score)
	e.db.Model(&models.OsintScan{}).Where("id = ?", scan.ID).
		Updates(map[string]interface{}{"exposure_score": score, "exposure_grade": grade})
	scan.ExposureScore = score
	scan.ExposureGrade = grade
}

// exposureScore weighs findings into exposure buckets and sums them. Each bucket
// is capped so one noisy collector cannot dominate, then the total is capped at
// 100. The "attack" bucket captures internet-facing attack surface (known CVEs
// and dangerous exposed services) that earlier scoring ignored entirely.
func exposureScore(fs []models.OsintFinding) int {
	var ransom, stealer, breach, reputation, darkweb, attack int

	for i := range fs {
		f := &fs[i]
		switch f.Category {
		case "ransomware":
			if f.Severity == "critical" {
				ransom += 50 // a DLS listing is the worst-case exposure
			}
		case "darkweb":
			darkweb += 12 // each dark-web selector match
		case "breach":
			switch f.Source {
			case "stealer_intel":
				if f.Severity == "critical" || f.Severity == "high" {
					stealer += 25
				}
			case "breach_leak":
				if f.Title == "Leaked credential" {
					breach += confWeight(f.Confidence, 6, 3, 1)
				}
			case "hibp", "xposed":
				// A named breach from a reputable breach database is real, durable
				// exposure - credit it even when the combolist source is silent.
				if strings.HasPrefix(f.Title, "Breach: ") {
					breach += 3
				}
			}
		case "ports":
			// Exposed dangerous services widen the attack surface.
			if strings.HasPrefix(f.Title, "Open ports") {
				attack += riskyPortScore(f.Value)
			}
		case "vulnerability":
			// CVEs matched from a detected service version (webtech/portscan).
			switch f.Severity {
			case "critical":
				attack += 10
			case "high":
				attack += 6
			case "medium":
				attack += 3
			}
		case "reputation":
			// Known CVEs from infrastructure scanners are attack surface, not a
			// malicious-reputation verdict - route them to their own bucket so they
			// neither inflate reputation nor get lost.
			if isAttackSurfaceVuln(f) {
				attack += 8
				continue
			}
			// Use the corroborated threat verdict: confidence reflects how many
			// independent sources agreed, so weight verified higher.
			switch f.Severity {
			case "critical":
				reputation += confWeight(f.Confidence, 20, 12, 8)
			case "high":
				reputation += confWeight(f.Confidence, 12, 8, 5)
			case "medium":
				reputation += 4
			}
		}
	}

	ransom = capAt(ransom, 50)
	stealer = capAt(stealer, 25)
	breach = capAt(breach, 25)
	reputation = capAt(reputation, 25)
	darkweb = capAt(darkweb, 25)
	attack = capAt(attack, 25)

	return capAt(ransom+stealer+breach+reputation+darkweb+attack, 100)
}

// isAttackSurfaceVuln reports whether a reputation finding is in fact a known
// vulnerability (CVE) reported by an infrastructure scanner rather than a
// malicious-reputation verdict.
func isAttackSurfaceVuln(f *models.OsintFinding) bool {
	if f.Source != "shodan" && f.Source != "shodan_internetdb" {
		return false
	}
	return strings.Contains(strings.ToLower(f.Title), "vulnerab")
}

// riskyPorts maps internet-exposed ports that should not normally face the
// public internet to a risk weight. Exposing them materially widens attack
// surface (remote access, file shares, unauthenticated databases, admin UIs).
var riskyPorts = map[string]int{
	"21": 3, "23": 5, "25": 1, "135": 4, "139": 4, "445": 5, // FTP/Telnet/SMTP/RPC/SMB
	"1433": 4, "1521": 4, "3306": 4, "5432": 4, "27017": 4, // SQL Server/Oracle/MySQL/Postgres/Mongo
	"6379": 5, "9200": 4, "11211": 4, "5984": 4, // Redis/Elastic/Memcached/CouchDB
	"3389": 5, "5900": 4, "5901": 4, // RDP/VNC
	"2375": 5, "2376": 4, "9000": 2, "8080": 1, // Docker/admin UIs
}

// riskyPortScore sums the risk weights of dangerous ports in a comma-separated
// "Open ports" value (e.g. "22, 80, 443, 3389").
func riskyPortScore(value string) int {
	total := 0
	for _, p := range strings.Split(value, ",") {
		if w, ok := riskyPorts[strings.TrimSpace(p)]; ok {
			total += w
		}
	}
	return total
}

// confWeight returns a weight scaled by a finding's self-verification verdict.
func confWeight(confidence string, verified, likely, unverified int) int {
	switch confidence {
	case "verified":
		return verified
	case "likely":
		return likely
	default:
		return unverified
	}
}

func capAt(v, max int) int {
	if v > max {
		return max
	}
	return v
}

// exposureGrade bands the 0-100 score.
func exposureGrade(score int) string {
	switch {
	case score >= 80:
		return "critical"
	case score >= 55:
		return "high"
	case score >= 30:
		return "elevated"
	case score >= 10:
		return "low"
	default:
		return "minimal"
	}
}
