package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/analysishub/backend/internal/ws"
	"github.com/gin-gonic/gin"
)

type CollectedCVE struct {
	ID            string   `json:"id"`
	Description   string   `json:"description"`
	Severity      string   `json:"severity"`
	CVSSScore     float64  `json:"cvss_score"`
	EPSSScore     float64  `json:"epss_score"`
	IsKEV         bool     `json:"is_kev"`
	ExploitStatus string   `json:"exploit_status"`
	PublishedDate string   `json:"published_date"`
	PoCLinks      []string `json:"poc_links"`
	Tags          []string `json:"tags"`
	AddedAt       string   `json:"added_at"`
	Source        string   `json:"source"`
}

var cveCollectionFile = "data/cve_collection.json"
var cveMutex sync.Mutex

// CISA KEV Cache
var (
	cisaKEVCatalog map[string]bool
	cisaMu         sync.RWMutex
	lastCISASync   time.Time
)

// WarmCISACatalog primes the CISA KEV catalog in the background at startup so
// the first CVE search doesn't pay the multi-MB synchronous download on its
// critical path.
func WarmCISACatalog() {
	go updateCISACatalog()
}

// updateCISACatalog refreshes the in-memory KEV catalog at most once per 24h. Used
// by the cve-worker and lazily on CVE searches.
func updateCISACatalog() {
	cisaMu.RLock()
	fresh := time.Since(lastCISASync) < 24*time.Hour && cisaKEVCatalog != nil
	cisaMu.RUnlock()
	if fresh {
		return
	}
	if err := UpdateCISAKEV(context.Background()); err != nil {
		log.Printf("[cve-worker] CISA KEV update failed: %v", err)
	}
}

// cisaKEVSources are the KEV catalog URLs, tried in order. The cisagov GitHub
// mirror is primary: cisa.gov's Akamai WAF returns 403 to non-browser (datacenter)
// clients, so the direct feed is unreliable from a server — it stays as a fallback.
var cisaKEVSources = []string{
	"https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json",
	"https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
}

// UpdateCISAKEV fetches the CISA Known Exploited Vulnerabilities catalog and swaps
// it in unconditionally (no debounce). Exported for the unified updater registry
// and its manual "update now" trigger.
func UpdateCISAKEV(ctx context.Context) error {
	var lastErr error
	for _, src := range cisaKEVSources {
		newMap, err := fetchCISAKEV(ctx, src)
		if err != nil {
			lastErr = err
			continue
		}
		cisaMu.Lock()
		cisaKEVCatalog = newMap
		lastCISASync = time.Now()
		cisaMu.Unlock()
		log.Printf("[updater] CISA KEV catalog updated: %d entries (from %s)", len(newMap), src)
		return nil
	}
	return fmt.Errorf("all KEV sources failed: %w", lastErr)
}

func fetchCISAKEV(ctx context.Context, url string) (map[string]bool, error) {
	cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; AnalysisHub/1.0; +https://analysishub.local)")
	req.Header.Set("Accept", "application/json")
	resp, err := cveHTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	var catalog struct {
		Vulnerabilities []struct {
			CveID string `json:"cveID"`
		} `json:"vulnerabilities"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&catalog); err != nil {
		return nil, err
	}
	newMap := make(map[string]bool, len(catalog.Vulnerabilities))
	for _, v := range catalog.Vulnerabilities {
		newMap[v.CveID] = true
	}
	if len(newMap) == 0 {
		return nil, fmt.Errorf("empty catalog")
	}
	return newMap, nil
}

func isCISAExploited(cveID string) bool {
	cisaMu.RLock()
	defer cisaMu.RUnlock()
	if cisaKEVCatalog == nil {
		return false
	}
	return cisaKEVCatalog[cveID]
}

func fetchEPSSScore(cveID string) float64 {
	m := fetchEPSSBatch(context.Background(), []string{cveID})
	if e, ok := m[cveID]; ok {
		return e.Score
	}
	return 0
}

func getCVEFilePath() string {
	// If running in Docker or from project root, data/cve_collection.json should be accessible
	path := cveCollectionFile
	if _, err := os.Stat(path); os.IsNotExist(err) {
		// Fallback to absolute path or assume it's created dynamically
		// We'll try to create the directory if it doesn't exist
		os.MkdirAll(filepath.Dir(path), 0755)
	}
	return path
}

func readCVEs() ([]CollectedCVE, error) {
	cveMutex.Lock()
	defer cveMutex.Unlock()

	path := getCVEFilePath()
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return []CollectedCVE{}, nil
		}
		return nil, err
	}

	var cves []CollectedCVE
	if err := json.Unmarshal(data, &cves); err != nil {
		return nil, err
	}
	return cves, nil
}

func writeCVEs(cves []CollectedCVE) error {
	cveMutex.Lock()
	defer cveMutex.Unlock()

	data, err := json.MarshalIndent(cves, "", "  ")
	if err != nil {
		return err
	}

	path := getCVEFilePath()
	return os.WriteFile(path, data, 0644)
}

func GetCVECollection(c *gin.Context) {
	cves, err := readCVEs()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "failed to read cve collection"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": cves})
}

func AddToCVECollection(c *gin.Context) {
	var input CollectedCVE
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
		return
	}

	if input.ID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "CVE ID is required"})
		return
	}

	input.AddedAt = time.Now().Format(time.RFC3339)

	// Enrich missing data
	if input.Source == "" {
		input.Source = "Manual"
	}
	if input.EPSSScore == 0 {
		input.EPSSScore = fetchEPSSScore(input.ID)
	}
	updateCISACatalog() // Ensure catalog is loaded
	if !input.IsKEV {
		input.IsKEV = isCISAExploited(input.ID)
	}
	if input.IsKEV && input.ExploitStatus == "" {
		input.ExploitStatus = "Actively Exploited"
	}

	cves, err := readCVEs()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "failed to read cve collection"})
		return
	}

	// Check if exists
	for i, cve := range cves {
		if cve.ID == input.ID {
			// Update existing
			input.AddedAt = cves[i].AddedAt // Preserve original added time
			cves[i] = input
			if err := writeCVEs(cves); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "failed to write cve collection"})
				return
			}
			c.JSON(http.StatusOK, gin.H{"success": true, "data": input})
			return
		}
	}

	// Add new
	cves = append([]CollectedCVE{input}, cves...) // prepend
	if err := writeCVEs(cves); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "failed to write cve collection"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "data": input})
}

func DeleteFromCVECollection(c *gin.Context) {
	id := c.Param("id")

	cves, err := readCVEs()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "failed to read cve collection"})
		return
	}

	newCVEs := []CollectedCVE{}
	found := false
	for _, cve := range cves {
		if cve.ID != id {
			newCVEs = append(newCVEs, cve)
		} else {
			found = true
		}
	}

	if !found {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "cve not found in collection"})
		return
	}

	if err := writeCVEs(newCVEs); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "failed to write cve collection"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true})
}

// StartCVEUpdateWorker starts a background goroutine that periodically syncs latest CVEs.
func StartCVEUpdateWorker(hub *ws.Hub) {
	log.Println("[cve-worker] starting background CVE update worker...")
	go func() {
		// Run first sync immediately on startup
		safeLoop("cve-worker", func() { syncLatestCVEs(hub) })
		safeLoop("cve-worker", func() { syncFromCIRCL(hub) })

		runWorker("cve-worker", 6*time.Hour, func() {
			syncLatestCVEs(hub)
			syncFromCIRCL(hub)
		})
	}()
}

func syncLatestCVEs(hub *ws.Hub) {
	log.Println("[cve-worker] syncing latest CVEs...")

	// 0. Update CISA KEV Catalog
	updateCISACatalog()

	// 1. Get recently modified/published CVEs from NVD (official source)
	// We'll look at the last 48 hours to ensure we don't miss anything
	now := time.Now().UTC()
	yesterday := now.Add(-48 * time.Hour)

	// Format: 2023-01-01T00:00:00.000
	dateLayout := "2006-01-02T15:04:05.000"
	pubStartDate := yesterday.Format(dateLayout)
	pubEndDate := now.Format(dateLayout)

	u := "https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate=" + pubStartDate + "&pubEndDate=" + pubEndDate
	log.Printf("[cve-worker] fetching from NVD: %s", u)

	req, _ := http.NewRequest("GET", u, nil)
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[cve-worker] error fetching from NVD: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("[cve-worker] NVD returned status %d", resp.StatusCode)
		return
	}

	var nvdResp nvdResponse
	if err := json.NewDecoder(resp.Body).Decode(&nvdResp); err != nil {
		log.Printf("[cve-worker] error decoding NVD response: %v", err)
		return
	}

	// 2. Load current collection
	existing, err := readCVEs()
	if err != nil {
		log.Printf("[cve-worker] error reading collection: %v", err)
		return
	}

	existingMap := make(map[string]bool)
	for _, c := range existing {
		if c.ID != "" {
			existingMap[c.ID] = true
		}
	}

	// 3. Collect all new CVEs first (capped per batch) so risk data can be fetched
	// in bulk rather than one HTTP round-trip per CVE.
	const maxPerBatch = 50
	var additions []CollectedCVE
	var newIDs []string
	for _, v := range nvdResp.Vulnerabilities {
		item := v.CVE
		if item.ID == "" || existingMap[item.ID] {
			continue
		}
		summary := summaryFromCVE(item)
		cveDetail := CollectedCVE{
			ID:            summary.ID,
			Description:   summary.Description,
			Severity:      summary.Severity,
			CVSSScore:     summary.CVSSScore,
			PublishedDate: summary.PublishedDate,
			AddedAt:       time.Now().Format(time.RFC3339),
			Tags:          []string{"auto-synced"},
			Source:        "NVD",
			IsKEV:         isCISAExploited(item.ID),
		}
		if cveDetail.IsKEV {
			cveDetail.ExploitStatus = "Actively Exploited"
			cveDetail.Tags = append(cveDetail.Tags, "CISA-KEV")
		}
		additions = append(additions, cveDetail)
		newIDs = append(newIDs, item.ID)
		if len(additions) >= maxPerBatch {
			break
		}
	}

	if len(additions) == 0 {
		log.Printf("[cve-worker] sync complete, no new CVEs")
		return
	}

	// 4. Batch EPSS for every new CVE in one (chunked) call.
	epss := fetchEPSSBatch(context.Background(), newIDs)

	// 5. Enrich each addition. PoC lookups hit the GitHub search API, which is
	// rate-limited, so we pace them modestly and stop calling GitHub for the rest
	// of the batch once it rate-limits (403) — the CVEs are still recorded; PoCs
	// can be fetched on demand from the detail view later.
	pocRateLimited := false
	for i := range additions {
		id := additions[i].ID
		if e, ok := epss[id]; ok {
			additions[i].EPSSScore = e.Score
		}
		if pocRateLimited {
			continue
		}
		if i > 0 {
			time.Sleep(2 * time.Second) // pace GitHub search calls
		}
		pocs, status, err := fetchGitHubPocs(context.Background(), nil, id)
		if status == http.StatusForbidden || status == http.StatusTooManyRequests {
			log.Printf("[cve-worker] GitHub PoC search rate-limited (%d) — skipping PoC lookups for rest of batch", status)
			pocRateLimited = true
			continue
		}
		if err == nil {
			additions[i].PoCLinks = make([]string, 0, len(pocs))
			for _, p := range pocs {
				additions[i].PoCLinks = append(additions[i].PoCLinks, p.HTMLURL)
			}
		}
	}

	// 6. Prepend the batch (newest first) and write the collection ONCE.
	existing = append(additions, existing...)
	if err := writeCVEs(existing); err != nil {
		log.Printf("[cve-worker] error writing collection: %v", err)
	} else if hub != nil {
		hub.PublishCVEUpdate()
	}

	log.Printf("[cve-worker] sync complete, added %d new CVEs", len(additions))
}

func syncFromCIRCL(hub *ws.Hub) {
	log.Println("[cve-worker] syncing from CIRCL (alternative source)...")
	updateCISACatalog()

	req, err := http.NewRequest(http.MethodGet, "https://cve.circl.lu/api/last", nil)
	if err != nil {
		log.Printf("[cve-worker] error building CIRCL request: %v", err)
		return
	}
	resp, err := cveHTTPClient.Do(req)
	if err != nil {
		log.Printf("[cve-worker] error fetching from CIRCL: %v", err)
		return
	}
	defer resp.Body.Close()

	var circlCVEs []struct {
		ID        string  `json:"id"`
		Summary   string  `json:"summary"`
		CVSS      float64 `json:"cvss"`
		Published string  `json:"Published"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&circlCVEs); err != nil {
		log.Printf("[cve-worker] error decoding CIRCL response: %v", err)
		return
	}

	existing, _ := readCVEs()
	existingMap := make(map[string]bool)
	for _, c := range existing {
		existingMap[c.ID] = true
	}

	var additions []CollectedCVE
	var newIDs []string
	for _, item := range circlCVEs {
		if item.ID == "" || existingMap[item.ID] {
			continue
		}
		cveDetail := CollectedCVE{
			ID:            item.ID,
			Description:   item.Summary,
			CVSSScore:     item.CVSS,
			PublishedDate: item.Published,
			AddedAt:       time.Now().Format(time.RFC3339),
			Tags:          []string{"auto-synced", "circl"},
			Source:        "CIRCL",
			IsKEV:         isCISAExploited(item.ID),
			Severity:      normalizeSeverity("", item.CVSS),
		}
		if cveDetail.IsKEV {
			cveDetail.ExploitStatus = "Actively Exploited"
			cveDetail.Tags = append(cveDetail.Tags, "CISA-KEV")
		}
		additions = append(additions, cveDetail)
		newIDs = append(newIDs, item.ID)
		if len(additions) >= 20 { // Limit CIRCL batch
			break
		}
	}

	if len(additions) == 0 {
		log.Printf("[cve-worker] CIRCL sync complete, no new CVEs")
		return
	}

	// Batch EPSS for all new CVEs in one (chunked) call.
	epss := fetchEPSSBatch(context.Background(), newIDs)
	for i := range additions {
		if e, ok := epss[additions[i].ID]; ok {
			additions[i].EPSSScore = e.Score
		}
	}

	existing = append(additions, existing...)
	writeCVEs(existing)
	if hub != nil {
		hub.PublishCVEUpdate()
	}
	log.Printf("[cve-worker] CIRCL sync complete, added %d new CVEs", len(additions))
}

// StreamCVECollection pushes signals to the client over SSE whenever the collection changes.
func StreamCVECollection(c *gin.Context) {
	hub, ok := mustGetHub(c)
	if !ok {
		return
	}

	ch := hub.SubscribeCVE()
	defer hub.UnsubscribeCVE(ch)

	c.Header("Content-Type", "text/event-stream")
	c.Header("Cache-Control", "no-cache")
	c.Header("Connection", "keep-alive")
	c.Header("X-Accel-Buffering", "no")
	c.Writer.WriteHeader(http.StatusOK)
	c.Writer.Flush()

	clientGone := c.Request.Context().Done()
	ping := time.NewTicker(30 * time.Second)
	defer ping.Stop()

	for {
		select {
		case <-clientGone:
			return
		case <-ping.C:
			fmt.Fprintf(c.Writer, "event: ping\ndata: {}\n\n")
			c.Writer.Flush()
		case _, ok := <-ch:
			if !ok {
				return
			}
			fmt.Fprintf(c.Writer, "event: update\ndata: {\"updated\": true}\n\n")
			c.Writer.Flush()
		}
	}
}
