package osint

import "github.com/forensichub/backend/internal/models"

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

// exposureScore weighs findings into four exposure buckets and sums them.
func exposureScore(fs []models.OsintFinding) int {
	var ransom, stealer, breach, reputation, darkweb int

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
			}
		case "reputation":
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

	return capAt(ransom+stealer+breach+reputation+darkweb, 100)
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
