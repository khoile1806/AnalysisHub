package vulnscan

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"strings"

	"gorm.io/gorm/clause"

	"github.com/analysishub/backend/internal/models"
	"github.com/analysishub/backend/internal/notify"
)

// enrichAndReport runs after nuclei finishes: it cross-references CVE findings
// with EPSS + CISA-KEV intel, then closes the defence loop by pushing
// high-impact findings into the case timeline, promoting affected hosts to the
// IOC store, and notifying on critical / known-exploited findings. All steps are
// best-effort and gated on configuration (case linkage, notify channels).
func (e *Engine) enrichAndReport(ctx context.Context, scan *models.VulnScan) {
	scanID := scan.ID.String()

	// ── CVE intel (EPSS + KEV) ────────────────────────────────────────────────
	if e.enricher != nil {
		var cves []string
		e.db.Model(&models.VulnFinding{}).
			Where("scan_id = ? AND cve_id <> ''", scan.ID).
			Distinct().Pluck("cve_id", &cves)
		if len(cves) > 0 {
			intel := e.enricher.EnrichCVEs(ctx, cves)
			kev := 0
			for id, in := range intel {
				e.db.Model(&models.VulnFinding{}).
					Where("scan_id = ? AND cve_id = ?", scan.ID, id).
					Updates(map[string]interface{}{"epss_score": in.EPSS, "is_kev": in.KEV})
				if in.KEV {
					kev++
				}
			}
			msg := fmt.Sprintf("[*] CVE intel: enriched %d CVE(s) with EPSS", len(intel))
			if kev > 0 {
				msg += fmt.Sprintf("; %d KNOWN-EXPLOITED (CISA-KEV)", kev)
			}
			e.emit(scanID, msg)
		}
	}

	// ── Defence loop on high-impact findings ──────────────────────────────────
	var impactful []models.VulnFinding
	e.db.Where("scan_id = ? AND (severity IN ? OR is_kev = ?)",
		scan.ID, []string{"critical", "high"}, true).
		Find(&impactful)
	if len(impactful) == 0 {
		return
	}

	notifier := notify.New(e.cfg.NotifyWebhookURL, e.cfg.NotifyTelegramToken, e.cfg.NotifyTelegramChat)
	iocSeen := map[string]bool{}
	timelinePushed, iocAdded, notified := 0, 0, 0

	for i := range impactful {
		f := &impactful[i]

		// Timeline: file the finding under the scan's case (if any).
		if scan.CaseID != nil && e.pushTimeline(scan, f) {
			timelinePushed++
		}

		// IOC store: promote the affected host once.
		if host := cleanHost(f.Host); host != "" && !iocSeen[host] {
			iocSeen[host] = true
			if e.promoteIOC(host, f) {
				iocAdded++
			}
		}

		// Notify: critical or known-exploited findings only.
		if notifier.Enabled() && (f.Severity == "critical" || f.IsKEV) {
			tag := "CRITICAL"
			if f.IsKEV {
				tag = "KEV/CRITICAL"
			}
			notifier.Send(ctx,
				fmt.Sprintf("[%s] %s", tag, f.Name),
				fmt.Sprintf("Host: %s\nWhere: %s\nCVE: %s  EPSS: %.2f", f.Host, f.MatchedAt, f.CVEID, f.EPSSScore))
			notified++
		}
	}

	parts := []string{}
	if timelinePushed > 0 {
		parts = append(parts, fmt.Sprintf("%d → case timeline", timelinePushed))
	}
	if iocAdded > 0 {
		parts = append(parts, fmt.Sprintf("%d host(s) → IOC store", iocAdded))
	}
	if notified > 0 {
		parts = append(parts, fmt.Sprintf("%d alert(s) sent", notified))
	}
	if len(parts) > 0 {
		e.emit(scanID, "[+] Defence loop: "+strings.Join(parts, ", "))
	}
}

// pushTimeline files a finding into its case's timeline, idempotently.
func (e *Engine) pushTimeline(scan *models.VulnScan, f *models.VulnFinding) bool {
	sum := sha256.Sum256([]byte(scan.CaseID.String() + "|vulnscan|" + f.Host + "|" + f.Name + "|" + f.MatchedAt))
	detail := f.MatchedAt
	if f.CVEID != "" {
		detail = fmt.Sprintf("%s (CVE: %s, EPSS %.2f%s)", f.MatchedAt, f.CVEID, f.EPSSScore, kevTag(f.IsKEV))
	}
	ev := models.TimelineEvent{
		CaseID:    *scan.CaseID,
		EventTime: f.CreatedAt,
		Source:    "vulnscan",
		SourceRef: f.ID.String(),
		Host:      f.Host,
		Severity:  f.Severity,
		Title:     "Vuln: " + f.Name,
		Detail:    detail,
		DedupeKey: hex.EncodeToString(sum[:]),
		CreatedBy: scan.CreatedBy,
	}
	res := e.db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "case_id"}, {Name: "dedupe_key"}},
		DoNothing: true,
	}).Create(&ev)
	return res.Error == nil && res.RowsAffected > 0
}

// promoteIOC adds the affected host to the IOC store (idempotent upsert).
func (e *Engine) promoteIOC(host string, f *models.VulnFinding) bool {
	iocType := "Domain-Name"
	if ip := net.ParseIP(host); ip != nil {
		if ip.To4() != nil {
			iocType = "IPv4-Addr"
		} else {
			iocType = "IPv6-Addr"
		}
	}
	ioc := models.IOC{Value: host, Type: iocType, Source: "vulnscan", Description: "Vulnerable: " + f.Name}
	res := e.db.Where("value = ? AND type = ?", ioc.Value, ioc.Type).FirstOrCreate(&ioc)
	return res.Error == nil && res.RowsAffected > 0
}

func kevTag(kev bool) string {
	if kev {
		return ", KEV"
	}
	return ""
}

// cleanHost strips a scheme/port from a host string so it promotes cleanly.
func cleanHost(host string) string {
	h := strings.TrimSpace(host)
	if h == "" {
		return ""
	}
	if i := strings.Index(h, "://"); i >= 0 {
		h = h[i+3:]
	}
	if i := strings.IndexAny(h, "/?"); i >= 0 {
		h = h[:i]
	}
	if hh, _, err := net.SplitHostPort(h); err == nil {
		h = hh
	}
	return h
}
