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

func updateCISACatalog() {
	cisaMu.Lock()
	defer cisaMu.Unlock()

	// Update every 24 hours
	if time.Since(lastCISASync) < 24*time.Hour && cisaKEVCatalog != nil {
		return
	}

	log.Println("[cve-worker] updating CISA KEV catalog...")
	req, err := http.NewRequest(http.MethodGet, "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", nil)
	if err != nil {
		log.Printf("[cve-worker] error building CISA KEV request: %v", err)
		return
	}
	resp, err := cveHTTPClient.Do(req)
	if err != nil {
		log.Printf("[cve-worker] error fetching CISA KEV: %v", err)
		return
	}
	defer resp.Body.Close()

	var catalog struct {
		Vulnerabilities []struct {
			CveID string `json:"cveID"`
		} `json:"vulnerabilities"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&catalog); err != nil {
		log.Printf("[cve-worker] error decoding CISA KEV: %v", err)
		return
	}

	newMap := make(map[string]bool)
	for _, v := range catalog.Vulnerabilities {
		newMap[v.CveID] = true
	}
	cisaKEVCatalog = newMap
	lastCISASync = time.Now()
	log.Printf("[cve-worker] CISA KEV catalog updated: %d entries", len(newMap))
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
	ticker := time.NewTicker(6 * time.Hour)
	go func() {
		// Run first sync immediately on startup
		syncLatestCVEs(hub)
		syncFromCIRCL(hub)

		for range ticker.C {
			syncLatestCVEs(hub)
			syncFromCIRCL(hub)
		}
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

	newCount := 0
	for _, v := range nvdResp.Vulnerabilities {
		item := v.CVE
		if item.ID == "" || existingMap[item.ID] {
			continue
		}

		// 3. Process new CVE
		log.Printf("[cve-worker] adding new CVE: %s", item.ID)

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

		// Fetch EPSS Score
		cveDetail.EPSSScore = fetchEPSSScore(item.ID)

		// Fetch PoCs (with delay to avoid rate limit)
		time.Sleep(3 * time.Second)
		pocs, _, err := fetchGitHubPocs(context.Background(), nil, item.ID)
		if err == nil {
			cveDetail.PoCLinks = make([]string, 0, len(pocs))
			for _, p := range pocs {
				cveDetail.PoCLinks = append(cveDetail.PoCLinks, p.HTMLURL)
			}
		}

		// Prepend and SAVE IMMEDIATELY so user sees progress
		existing = append([]CollectedCVE{cveDetail}, existing...)
		if err := writeCVEs(existing); err != nil {
			log.Printf("[cve-worker] error writing collection: %v", err)
		} else {
			// Signal live subscribers
			if hub != nil {
				hub.PublishCVEUpdate()
			}
		}

		newCount++
		// Limit per batch
		if newCount >= 50 {
			break
		}
	}

	log.Printf("[cve-worker] sync complete, added %d new CVEs", newCount)
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

	newCount := 0
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
		}

		if cveDetail.IsKEV {
			cveDetail.ExploitStatus = "Actively Exploited"
			cveDetail.Tags = append(cveDetail.Tags, "CISA-KEV")
		}

		cveDetail.EPSSScore = fetchEPSSScore(item.ID)

		// Set severity based on score
		cveDetail.Severity = normalizeSeverity("", cveDetail.CVSSScore)

		existing = append([]CollectedCVE{cveDetail}, existing...)
		newCount++

		if newCount >= 20 { // Limit CIRCL batch
			break
		}
	}

	if newCount > 0 {
		writeCVEs(existing)
		if hub != nil {
			hub.PublishCVEUpdate()
		}
	}
	log.Printf("[cve-worker] CIRCL sync complete, added %d new CVEs", newCount)
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
