package vulnscan

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"github.com/analysishub/backend/internal/models"
)

// maxVerify bounds how many high-impact findings the verification pass re-checks,
// so a noisy scan can't make the confirm step run unbounded.
const maxVerify = 150

// verifyFindings independently re-runs nuclei against the high-impact findings
// (critical/high/KEV) using only their own template ids, and flags the ones that
// re-match as Confirmed — a corroborated finding is far less likely to be a false
// positive. Best-effort: a missing binary or error just leaves findings
// unconfirmed.
func (e *Engine) verifyFindings(ctx context.Context, scan *models.VulnScan, proxyURL string) {
	if ctx.Err() != nil {
		return
	}
	scanID := scan.ID.String()
	bin, err := exec.LookPath("nuclei")
	if err != nil {
		return
	}

	var findings []models.VulnFinding
	e.db.Where("scan_id = ? AND tool = ? AND template_id <> '' AND (severity IN ? OR is_kev = ?)",
		scan.ID, "nuclei", []string{"critical", "high"}, true).
		Limit(maxVerify).Find(&findings)
	if len(findings) == 0 {
		return
	}

	tplSet := map[string]bool{}
	urlSet := map[string]bool{}
	for _, f := range findings {
		tplSet[f.TemplateID] = true
		if f.MatchedAt != "" {
			urlSet[f.MatchedAt] = true
		}
	}
	if len(urlSet) == 0 {
		return
	}
	tpls := make([]string, 0, len(tplSet))
	for t := range tplSet {
		tpls = append(tpls, t)
	}
	urls := make([]string, 0, len(urlSet))
	for u := range urlSet {
		urls = append(urls, u)
	}

	e.emit(scanID, fmt.Sprintf("[*] verification — re-checking %d high-impact finding(s)...", len(findings)))

	listFile, cleanup, err := writeListFile(urls)
	if err != nil {
		return
	}
	defer cleanup()

	cctx, cancel := context.WithTimeout(ctx, e.nucleiTimeout())
	defer cancel()
	args := []string{
		"-l", listFile, "-jsonl", "-silent", "-no-color", "-disable-update-check",
		"-id", strings.Join(tpls, ","), "-timeout", "10",
		"-rate-limit", fmt.Sprintf("%d", e.rateLimit()),
	}
	args = append(args, e.nucleiOOBArgs()...)
	if proxyURL != "" {
		args = append(args, "-proxy", proxyURL)
	}
	if tdir := e.nucleiTemplatesDir(); tdir != "" {
		args = append(args, "-templates", tdir)
	}
	cmd := exec.CommandContext(cctx, bin, args...)
	cmd.Env = proxyEnv(proxyURL)

	rematched := map[string]bool{} // key: templateID|matchedAt
	streamLines(cmd, func(line string) {
		var n nucleiLine
		if json.Unmarshal([]byte(line), &n) != nil || n.TemplateID == "" {
			return
		}
		rematched[n.TemplateID+"|"+n.MatchedAt] = true
	})

	confirmed := 0
	for _, f := range findings {
		if rematched[f.TemplateID+"|"+f.MatchedAt] {
			e.db.Model(&models.VulnFinding{}).Where("id = ?", f.ID).Update("confirmed", true)
			confirmed++
		}
	}
	e.emit(scanID, fmt.Sprintf("[+] verification done — %d/%d confirmed", confirmed, len(findings)))
}
