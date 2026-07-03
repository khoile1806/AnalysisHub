package handlers

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"github.com/analysishub/backend/internal/api/middleware"
	"github.com/analysishub/backend/internal/crypto"
	"github.com/analysishub/backend/internal/models"
)

type SplunkConfigPayload struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	URL         string `json:"url"`
	Username    string `json:"username"`
	Password    string `json:"password"`
	APIKey      string `json:"api_key"`
}

func sanitizeSplunk(c *models.SplunkConfig) {
	c.Password = ""
	c.APIKey = ""
	c.HasAuth = true
}

func GetSplunkConfig(c *gin.Context) {
	db := c.MustGet("db").(*gorm.DB)
	var cfg models.SplunkConfig
	err := db.Where("is_active = ?", true).First(&cfg).Error
	if err != nil {
		c.JSON(http.StatusOK, gin.H{})
		return
	}
	sanitizeSplunk(&cfg)
	c.JSON(http.StatusOK, cfg)
}

func ListSplunkConfigs(c *gin.Context) {
	db := c.MustGet("db").(*gorm.DB)
	var cfgs []models.SplunkConfig
	if err := db.Order("is_active desc, updated_at desc").Find(&cfgs).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to load profiles"})
		return
	}
	for i := range cfgs {
		sanitizeSplunk(&cfgs[i])
	}
	c.JSON(http.StatusOK, cfgs)
}

func CreateSplunkConfig(c *gin.Context) {
	db := c.MustGet("db").(*gorm.DB)
	aesKey := c.GetString("aesEncryptionKey")

	var payload SplunkConfigPayload
	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if strings.TrimSpace(payload.Name) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Name is required"})
		return
	}

	cfg := models.SplunkConfig{
		Name:        strings.TrimSpace(payload.Name),
		Description: payload.Description,
		URL:         payload.URL,
		Username:    payload.Username,
	}

	if payload.Password != "" {
		enc, _ := crypto.Encrypt(payload.Password, aesKey)
		cfg.Password = enc
	}
	if payload.APIKey != "" {
		enc, _ := crypto.Encrypt(payload.APIKey, aesKey)
		cfg.APIKey = enc
	}

	var count int64
	db.Model(&models.SplunkConfig{}).Count(&count)
	if count == 0 {
		cfg.IsActive = true
	}

	if err := db.Create(&cfg).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create profile"})
		return
	}

	if uid, ok := middleware.GetUserID(c); ok {
		writeAudit(c, db, &uid, nil, "splunk.config.create", fmt.Sprintf("splunk:%d", cfg.ID), fmt.Sprintf("created Splunk profile %q", cfg.Name))
	}

	sanitizeSplunk(&cfg)
	c.JSON(http.StatusCreated, cfg)
}

func UpdateSplunkConfig(c *gin.Context) {
	db := c.MustGet("db").(*gorm.DB)
	aesKey := c.GetString("aesEncryptionKey")
	id := c.Param("id")

	var payload SplunkConfigPayload
	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var cfg models.SplunkConfig
	if err := db.First(&cfg, "id = ?", id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "profile not found"})
		return
	}

	if strings.TrimSpace(payload.Name) != "" {
		cfg.Name = strings.TrimSpace(payload.Name)
	}
	cfg.Description = payload.Description
	cfg.URL = payload.URL
	cfg.Username = payload.Username

	if payload.Password != "" {
		enc, _ := crypto.Encrypt(payload.Password, aesKey)
		cfg.Password = enc
	}
	if payload.APIKey != "" {
		enc, _ := crypto.Encrypt(payload.APIKey, aesKey)
		cfg.APIKey = enc
	}

	if err := db.Save(&cfg).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update config"})
		return
	}

	sanitizeSplunk(&cfg)
	c.JSON(http.StatusOK, cfg)
}

func DeleteSplunkConfig(c *gin.Context) {
	db := c.MustGet("db").(*gorm.DB)
	id := c.Param("id")

	var cfg models.SplunkConfig
	if err := db.First(&cfg, "id = ?", id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "profile not found"})
		return
	}

	db.Delete(&models.SplunkConfig{}, "id = ?", id)

	if cfg.IsActive {
		var next models.SplunkConfig
		if err := db.Order("updated_at desc").First(&next).Error; err == nil {
			db.Model(&next).Update("is_active", true)
		}
	}
	c.JSON(http.StatusOK, gin.H{"message": "Profile deleted"})
}

func ActivateSplunkConfig(c *gin.Context) {
	db := c.MustGet("db").(*gorm.DB)
	id := c.Param("id")

	var cfg models.SplunkConfig
	if err := db.First(&cfg, "id = ?", id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "profile not found"})
		return
	}

	db.Transaction(func(tx *gorm.DB) error {
		tx.Model(&models.SplunkConfig{}).Where("id <> ?", cfg.ID).Update("is_active", false)
		return tx.Model(&cfg).Update("is_active", true).Error
	})

	cfg.IsActive = true
	sanitizeSplunk(&cfg)
	c.JSON(http.StatusOK, cfg)
}

// --- HUNTING HANDLERS ---

func loadSplunkAuth(db *gorm.DB, aesKey string) (models.SplunkConfig, string, error) {
	var cfg models.SplunkConfig
	if err := db.Where("is_active = ?", true).First(&cfg).Error; err != nil {
		return cfg, "", fmt.Errorf("no active Splunk profile found")
	}

	authHeader := ""
	if cfg.Username != "" && cfg.Password != "" {
		dec, err := crypto.Decrypt(cfg.Password, aesKey)
		if err != nil {
			return cfg, "", fmt.Errorf("failed to decrypt Splunk password")
		}
		authHeader = "Basic " + base64.StdEncoding.EncodeToString([]byte(cfg.Username+":"+dec))
	} else if cfg.APIKey != "" {
		dec, err := crypto.Decrypt(cfg.APIKey, aesKey)
		if err != nil {
			return cfg, "", fmt.Errorf("failed to decrypt Splunk API key")
		}
		authHeader = "Bearer " + dec
	}
	return cfg, authHeader, nil
}

// splunkSearch runs a query against Splunk using the /services/search/jobs/export API.
// It buffers the JSON lines and returns them as a single slice of maps.
func splunkSearch(baseURL, authHeader, query, timeRange string, timeout time.Duration) ([]map[string]interface{}, int, error) {
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	apiURL := strings.TrimRight(baseURL, "/") + "/services/search/jobs/export"

	data := url.Values{}
	// Splunk requires queries to start with "search "
	if !strings.HasPrefix(strings.TrimSpace(query), "search ") && !strings.HasPrefix(strings.TrimSpace(query), "| ") {
		query = "search " + query
	}
	data.Set("search", query)
	data.Set("output_mode", "json")

	if timeRange != "" {
		// Convert 'now-7d' to '-7d'
		splunkTime := strings.Replace(timeRange, "now", "", 1)
		data.Set("earliest_time", splunkTime)
	}

	req, err := http.NewRequest("POST", apiURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, resp.StatusCode, fmt.Errorf("splunk returned %d: %s", resp.StatusCode, string(body))
	}

	// The export API returns NDJSON (one JSON object per line)
	scanner := bufio.NewScanner(resp.Body)
	var results []map[string]interface{}
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var hit map[string]interface{}
		if err := json.Unmarshal(line, &hit); err == nil {
			if res, ok := hit["result"].(map[string]interface{}); ok {
				results = append(results, res)
			}
		}
	}

	return results, http.StatusOK, nil
}

type splunkHuntRequest struct {
	Query     string `json:"query"`
	TimeRange string `json:"timeRange"`
	Indices   string `json:"indices"` // Map to Splunk "index=" if not present
}

func RunSplunkHunt(c *gin.Context) {
	db := c.MustGet("db").(*gorm.DB)
	aesKey := c.GetString("aesEncryptionKey")

	var req splunkHuntRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	config, authHeader, err := loadSplunkAuth(db, aesKey)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	query := req.Query
	if req.Indices != "" && req.Indices != "*" {
		// Add index=... if it doesn't already contain index
		if !strings.Contains(query, "index=") {
			query = fmt.Sprintf("search index=%s %s", req.Indices, strings.TrimPrefix(query, "search "))
		}
	}

	started := time.Now()
	hits, status, err := splunkSearch(config.URL, authHeader, query, req.TimeRange, 60*time.Second)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}
	if status != http.StatusOK {
		c.JSON(http.StatusBadGateway, gin.H{"error": "Splunk search failed"})
		return
	}

	// Format to match the ELK hit format so frontend doesn't break
	formattedHits := make([]map[string]interface{}, len(hits))
	for i, h := range hits {
		formattedHits[i] = map[string]interface{}{
			"_id":     fmt.Sprintf("splunk-%d", i),
			"_index":  h["index"],
			"_source": h,
		}
	}

	elkResp := gin.H{
		"took":      time.Since(started).Milliseconds(),
		"timed_out": false,
		"hits": gin.H{
			"total": gin.H{"value": len(formattedHits), "relation": "eq"},
			"hits":  formattedHits,
		},
	}

	c.JSON(http.StatusOK, elkResp)
}

func GetSplunkIndices(c *gin.Context) {
	db := c.MustGet("db").(*gorm.DB)
	aesKey := c.GetString("aesEncryptionKey")

	config, authHeader, err := loadSplunkAuth(db, aesKey)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	apiURL := strings.TrimRight(config.URL, "/") + "/services/data/indexes?output_mode=json"
	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "build request failed"})
		return
	}
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}

	resp, err := client.Do(req)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": fmt.Sprintf("Splunk request failed: %v", err)})
		return
	}
	defer resp.Body.Close()

	var body struct {
		Entry []struct {
			Name string `json:"name"`
		} `json:"entry"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to parse Splunk response"})
		return
	}

	indices := make([]string, 0, len(body.Entry))
	for _, item := range body.Entry {
		indices = append(indices, item.Name)
	}

	c.JSON(http.StatusOK, indices)
}
