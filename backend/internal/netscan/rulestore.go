package netscan

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"gorm.io/gorm"

	"github.com/analysishub/backend/internal/models"
)

// rulestore.go — operator-managed Suricata rulesets and the retro-hunt that
// replays them over captures already analysed.
//
// Intel almost never arrives before the traffic does: a capture is taken on
// Monday and the signature that explains it is published on Thursday. Without a
// retro-hunt the team has to remember which captures to re-run by hand, which in
// practice means the old captures are never looked at again.
//
// Validation is not optional. Suricata DROPS a rule it cannot parse and carries
// on with the rest, so a typo produces a run that reports nothing — indistinguish-
// able from clean traffic. Every ruleset is therefore compile-checked by Suricata
// itself (in the sidecar, the only place the binary exists) before it is stored.

const (
	retroPerCapture = 5 * time.Minute
	// retroDefaultLimit bounds an automatic hunt: newest captures first. A rule
	// added on a 5000-capture archive must not stall the request that added it.
	retroDefaultLimit = 200
)

var (
	reSID = regexp.MustCompile(`(?i)\bsid\s*:\s*(\d+)`)
	reMsg = regexp.MustCompile(`(?i)\bmsg\s*:\s*"([^"]{1,200})"`)
)

// RuleSIDs lists the signature ids declared by a ruleset.
func RuleSIDs(src string) []string {
	return uniqueMatches(reSID.FindAllStringSubmatch(src, -1))
}

// RuleMsgs lists the human-readable messages declared by a ruleset.
func RuleMsgs(src string) []string {
	return uniqueMatches(reMsg.FindAllStringSubmatch(src, -1))
}

func uniqueMatches(all [][]string) []string {
	var out []string
	seen := map[string]bool{}
	for _, m := range all {
		if len(m) < 2 {
			continue
		}
		v := strings.TrimSpace(m[1])
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
		if len(out) >= 200 {
			break
		}
	}
	return out
}

// ValidationResult is the sidecar's verdict on a ruleset.
type ValidationResult struct {
	OK    bool     `json:"ok"`
	Error string   `json:"error"`
	SIDs  []string `json:"sids"`
	Msgs  []string `json:"msgs"`
}

// ValidateRuleset asks Suricata to parse the ruleset. An unreachable sidecar is
// reported as such — never as "valid", which would let a broken rule in.
func (e *Engine) ValidateRuleset(ctx context.Context, src string) (*ValidationResult, error) {
	if !e.Available() {
		return nil, fmt.Errorf("network analyzer (Suricata sidecar) is not configured")
	}
	var body bytes.Buffer
	w := multipart.NewWriter(&body)
	_ = w.WriteField("rules", src)
	w.Close()

	raw, err := e.postSidecar(ctx, "/rules/validate", w.FormDataContentType(), &body, 60*time.Second)
	if err != nil {
		return nil, err
	}
	var res ValidationResult
	if err := json.Unmarshal(raw, &res); err != nil {
		return nil, fmt.Errorf("unreadable sidecar response: %w", err)
	}
	return &res, nil
}

// RetroAlert is one signature hit found while replaying a stored capture.
type RetroAlert struct {
	Signature string `json:"signature"`
	SID       int    `json:"sid"`
	Category  string `json:"category"`
	Severity  int    `json:"severity"`
	Src       string `json:"src"`
	Dst       string `json:"dst"`
	DPort     int    `json:"dport"`
	Proto     string `json:"proto"`
	Timestamp string `json:"timestamp"`
}

// RetroHuntCapture replays one stored pcap against `rules` only.
func (e *Engine) RetroHuntCapture(ctx context.Context, rules string, pcap []byte, filename string) ([]RetroAlert, error) {
	if !e.Available() {
		return nil, fmt.Errorf("network analyzer (Suricata sidecar) is not configured")
	}
	var body bytes.Buffer
	w := multipart.NewWriter(&body)
	fw, err := w.CreateFormFile("file", filename)
	if err != nil {
		return nil, err
	}
	if _, err := fw.Write(pcap); err != nil {
		return nil, err
	}
	_ = w.WriteField("rules", rules)
	w.Close()

	raw, err := e.postSidecar(ctx, "/retrohunt", w.FormDataContentType(), &body, retroPerCapture)
	if err != nil {
		return nil, err
	}
	var res struct {
		Alerts []RetroAlert `json:"alerts"`
		Error  string       `json:"error"`
	}
	if err := json.Unmarshal(raw, &res); err != nil {
		return nil, fmt.Errorf("unreadable sidecar response: %w", err)
	}
	if res.Error != "" {
		return nil, fmt.Errorf("%s", res.Error)
	}
	return res.Alerts, nil
}

func (e *Engine) postSidecar(ctx context.Context, path, contentType string, body io.Reader, timeout time.Duration) ([]byte, error) {
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodPost, e.sidecar+path, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", contentType)
	resp, err := e.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("network-analyzer sidecar unreachable: %w", err)
	}
	defer resp.Body.Close()
	raw, rerr := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if rerr != nil {
		return nil, fmt.Errorf("reading sidecar response: %w", rerr)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("sidecar HTTP %d: %s", resp.StatusCode, firstLine(string(raw)))
	}
	return raw, nil
}

// RetroMatch is one capture a ruleset fired on.
type RetroMatch struct {
	ScanID    string   `json:"scan_id"`
	FileName  string   `json:"file_name"`
	Alerts    int      `json:"alerts"`
	Signature []string `json:"signatures"`
}

// RetroHuntStored replays `rules` over the stored captures, newest first, and
// records every hit as a finding on the capture it fired on. Returns the matches
// and how many captures were actually replayed.
//
// A capture whose pcap is gone is SKIPPED, not counted: reporting it as scanned
// would claim coverage the hunt never had.
func (e *Engine) RetroHuntStored(ctx context.Context, rules, ruleName string, limit int) (matches []RetroMatch, scanned int, err error) {
	if limit <= 0 {
		limit = retroDefaultLimit
	}
	var scans []models.NetworkScan
	e.db.Where("stored_path <> '' AND status = ?", "done").
		Order("created_at desc").Limit(limit).Find(&scans)
	if len(scans) == 0 {
		return nil, 0, nil
	}

	var lastErr error
	failed := 0
	for i := range scans {
		if ctx.Err() != nil {
			break
		}
		s := scans[i]
		data, rerr := os.ReadFile(e.store.GetAnalysisUploadPath(s.StoredPath))
		if rerr != nil || len(data) == 0 {
			continue // the capture's bytes are gone — not a scan, not a failure
		}
		alerts, herr := e.RetroHuntCapture(ctx, rules, data, s.FileName)
		if herr != nil {
			failed++
			lastErr = herr
			continue
		}
		scanned++
		if len(alerts) == 0 {
			continue
		}
		sigs := e.recordRetroFindings(&s, ruleName, alerts)
		matches = append(matches, RetroMatch{ScanID: s.ID.String(), FileName: s.FileName,
			Alerts: len(alerts), Signature: sigs})
	}
	if scanned == 0 && failed > 0 {
		return nil, 0, fmt.Errorf("suricata failed on %d capture(s): %v", failed, lastErr)
	}
	return matches, scanned, nil
}

// recordRetroFindings appends the hits to the capture's finding list, tagged with
// the ruleset that produced them so an analyst can tell a retro-hunt hit from what
// the original run saw. Returns the distinct signature names.
func (e *Engine) recordRetroFindings(scan *models.NetworkScan, ruleName string, alerts []RetroAlert) []string {
	var existing []NetworkFinding
	if strings.TrimSpace(scan.Findings) != "" {
		_ = json.Unmarshal([]byte(scan.Findings), &existing)
	}
	have := map[string]bool{}
	for _, f := range existing {
		have[f.Title+"|"+f.Indicator] = true
	}

	var sigs []string
	seenSig := map[string]bool{}
	added := 0
	for _, a := range alerts {
		name := strings.TrimSpace(a.Signature)
		if name == "" {
			name = fmt.Sprintf("sid %d", a.SID)
		}
		if !seenSig[name] {
			seenSig[name] = true
			sigs = append(sigs, name)
		}
		indicator := a.Dst
		key := name + "|" + indicator
		if have[key] {
			continue
		}
		have[key] = true
		detail := fmt.Sprintf("%s → %s", a.Src, a.Dst)
		if a.DPort > 0 {
			detail += fmt.Sprintf(":%d", a.DPort)
		}
		if a.Timestamp != "" {
			detail += " at " + a.Timestamp
		}
		detail += fmt.Sprintf(" (retro-hunt with %s, sid %d)", ruleName, a.SID)
		existing = append(existing, NetworkFinding{
			Severity: retroSeverity(a.Severity), Category: "signature", Source: "retrohunt",
			Title: name, Detail: detail, Indicator: indicator,
		})
		added++
	}
	if added == 0 {
		return sigs
	}
	blob, merr := json.Marshal(existing)
	if merr != nil {
		return sigs
	}
	// The alert count is what the list view shows; a retro-hunt hit that does not
	// move it would stay invisible until someone opened the capture.
	e.db.Model(&models.NetworkScan{}).Where("id = ?", scan.ID).
		Updates(map[string]interface{}{"findings": string(blob), "alert_count": scan.AlertCount + added})
	return sigs
}

// retroSeverity maps Suricata's numeric priority (1 = most severe) to our labels.
func retroSeverity(sev int) string {
	switch {
	case sev == 1:
		return "high"
	case sev == 2:
		return "medium"
	case sev >= 3:
		return "low"
	}
	return "medium"
}

// EnabledRuleSources returns the enabled rulesets, concatenated per ruleset so a
// hunt can report WHICH set fired.
func EnabledRuleSources(db *gorm.DB) []models.NetworkSuricataRule {
	var rules []models.NetworkSuricataRule
	db.Where("enabled = ?", true).Order("id asc").Find(&rules)
	return rules
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexAny(s, "\r\n"); i > 0 {
		return s[:i]
	}
	if len(s) > 300 {
		return s[:300]
	}
	return s
}
