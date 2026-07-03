package osint

import (
	"testing"

	"github.com/analysishub/backend/internal/models"
)

func mkFinding(source, category, title, value, sev string) models.OsintFinding {
	return models.OsintFinding{Source: source, Category: category, Title: title, Value: value, Severity: sev}
}

// TestExposureAttackSurface verifies known CVEs and dangerous exposed ports now
// feed the exposure score (previously ignored entirely).
func TestExposureAttackSurface(t *testing.T) {
	fs := []models.OsintFinding{
		mkFinding("shodan_internetdb", "reputation", "Known vulnerability", "CVE-2021-44228", "high"),
		mkFinding("shodan_internetdb", "ports", "Open ports", "22, 80, 443, 3389, 445", "info"),
	}
	if score := exposureScore(fs); score == 0 {
		t.Fatal("expected attack-surface exposure > 0, got 0")
	}
}

// TestExposureNamedBreach verifies HIBP/XposedOrNot named breaches contribute to
// the breach exposure bucket.
func TestExposureNamedBreach(t *testing.T) {
	fs := []models.OsintFinding{
		mkFinding("xposed", "breach", "Breach: LinkedIn", "x", "high"),
		mkFinding("hibp", "breach", "Breach: Adobe", "x", "high"),
	}
	if score := exposureScore(fs); score == 0 {
		t.Fatal("expected breach exposure > 0 from named breaches, got 0")
	}
}

func TestRiskyPortScore(t *testing.T) {
	if riskyPortScore("22, 80, 443") != 0 {
		t.Error("ports 22/80/443 should be safe per the risk map")
	}
	if riskyPortScore("3389, 445") <= 0 {
		t.Error("RDP+SMB should score > 0")
	}
}

// TestAttackVulnRouting guards that a Shodan CVE is classed as attack surface
// while a reputation verdict is not (prevents double counting).
func TestAttackVulnRouting(t *testing.T) {
	cve := mkFinding("shodan_internetdb", "reputation", "Known vulnerability", "CVE-2020-0001", "high")
	rep := mkFinding("abuseipdb", "reputation", "AbuseIPDB verdict", "malicious", "high")
	if !isAttackSurfaceVuln(&cve) {
		t.Error("shodan CVE should be classed as attack surface")
	}
	if isAttackSurfaceVuln(&rep) {
		t.Error("abuseipdb verdict must not be classed as attack surface")
	}
}
