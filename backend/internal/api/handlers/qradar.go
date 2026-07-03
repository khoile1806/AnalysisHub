package handlers

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"github.com/analysishub/backend/internal/api/middleware"
	"github.com/analysishub/backend/internal/crypto"
	"github.com/analysishub/backend/internal/models"
)

type QRadarConfigPayload struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	URL         string `json:"url"`
	Username    string `json:"username"`
	Password    string `json:"password"`
	APIKey      string `json:"api_key"` // QRadar SEC token
}

func sanitizeQRadar(c *models.QRadarConfig) {
	c.Password = ""
	c.APIKey = ""
	c.HasAuth = true
}

func GetQRadarConfig(c *gin.Context) {
	db := c.MustGet("db").(*gorm.DB)
	var cfg models.QRadarConfig
	err := db.Where("is_active = ?", true).First(&cfg).Error
	if err != nil {
		c.JSON(http.StatusOK, gin.H{})
		return
	}
	sanitizeQRadar(&cfg)
	c.JSON(http.StatusOK, cfg)
}

func ListQRadarConfigs(c *gin.Context) {
	db := c.MustGet("db").(*gorm.DB)
	var cfgs []models.QRadarConfig
	if err := db.Order("is_active desc, updated_at desc").Find(&cfgs).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to load profiles"})
		return
	}
	for i := range cfgs {
		sanitizeQRadar(&cfgs[i])
	}
	c.JSON(http.StatusOK, cfgs)
}

func CreateQRadarConfig(c *gin.Context) {
	db := c.MustGet("db").(*gorm.DB)
	aesKey := c.GetString("aesEncryptionKey")

	var payload QRadarConfigPayload
	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if strings.TrimSpace(payload.Name) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Name is required"})
		return
	}

	cfg := models.QRadarConfig{
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
	db.Model(&models.QRadarConfig{}).Count(&count)
	if count == 0 {
		cfg.IsActive = true
	}

	if err := db.Create(&cfg).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create profile"})
		return
	}

	if uid, ok := middleware.GetUserID(c); ok {
		writeAudit(c, db, &uid, nil, "qradar.config.create", fmt.Sprintf("qradar:%d", cfg.ID), fmt.Sprintf("created QRadar profile %q", cfg.Name))
	}

	sanitizeQRadar(&cfg)
	c.JSON(http.StatusCreated, cfg)
}

func UpdateQRadarConfig(c *gin.Context) {
	db := c.MustGet("db").(*gorm.DB)
	aesKey := c.GetString("aesEncryptionKey")
	id := c.Param("id")

	var payload QRadarConfigPayload
	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var cfg models.QRadarConfig
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

	sanitizeQRadar(&cfg)
	c.JSON(http.StatusOK, cfg)
}

func DeleteQRadarConfig(c *gin.Context) {
	db := c.MustGet("db").(*gorm.DB)
	id := c.Param("id")

	var cfg models.QRadarConfig
	if err := db.First(&cfg, "id = ?", id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "profile not found"})
		return
	}

	db.Delete(&models.QRadarConfig{}, "id = ?", id)

	if cfg.IsActive {
		var next models.QRadarConfig
		if err := db.Order("updated_at desc").First(&next).Error; err == nil {
			db.Model(&next).Update("is_active", true)
		}
	}
	c.JSON(http.StatusOK, gin.H{"message": "Profile deleted"})
}

func ActivateQRadarConfig(c *gin.Context) {
	db := c.MustGet("db").(*gorm.DB)
	id := c.Param("id")

	var cfg models.QRadarConfig
	if err := db.First(&cfg, "id = ?", id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "profile not found"})
		return
	}

	db.Transaction(func(tx *gorm.DB) error {
		tx.Model(&models.QRadarConfig{}).Where("id <> ?", cfg.ID).Update("is_active", false)
		return tx.Model(&cfg).Update("is_active", true).Error
	})

	cfg.IsActive = true
	sanitizeQRadar(&cfg)
	c.JSON(http.StatusOK, cfg)
}

func loadQRadarAuth(db *gorm.DB, aesKey string) (models.QRadarConfig, string, error) {
	var cfg models.QRadarConfig
	if err := db.Where("is_active = ?", true).First(&cfg).Error; err != nil {
		return cfg, "", fmt.Errorf("no active QRadar profile found")
	}

	authHeader := ""
	if cfg.APIKey != "" {
		dec, err := crypto.Decrypt(cfg.APIKey, aesKey)
		if err != nil {
			return cfg, "", fmt.Errorf("failed to decrypt QRadar API key")
		}
		authHeader = dec
	} else if cfg.Username != "" && cfg.Password != "" {
		dec, err := crypto.Decrypt(cfg.Password, aesKey)
		if err != nil {
			return cfg, "", fmt.Errorf("failed to decrypt QRadar password")
		}
		authHeader = "Basic " + base64.StdEncoding.EncodeToString([]byte(cfg.Username+":"+dec))
	}
	return cfg, authHeader, nil
}

func qradarSearch(baseURL, authHeader, query, timeRange string, timeout time.Duration) ([]map[string]interface{}, int, error) {
	// Due to QRadar Ariel polling requirement, we do a synchronous wait loop.
	// 1. POST /api/ariel/searches?query_expression=...
	// 2. GET /api/ariel/searches/{search_id} until status=COMPLETED
	// 3. GET /api/ariel/searches/{search_id}/results

	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: siemTLSConfig(),
		},
	}

	// Apply TimeRange if present
	if timeRange != "" {
		// e.g. now-7d -> START PARSEDATETIME('now-7d') or similar AQL.
		// We'll just append "LAST 7 DAYS" if missing.
		if !strings.Contains(strings.ToUpper(query), "LAST") && !strings.Contains(strings.ToUpper(query), "START") {
			query = fmt.Sprintf("%s LAST %s", query, strings.Replace(timeRange, "now-", "", 1))
		}
	}

	apiURL := strings.TrimRight(baseURL, "/") + "/api/ariel/searches"

	payloadStr := fmt.Sprintf(`{"query_expression": "%s"}`, strings.ReplaceAll(query, `"`, `\"`))
	req, err := http.NewRequest("POST", apiURL, strings.NewReader(payloadStr))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("SEC", authHeader)
	if strings.HasPrefix(authHeader, "Basic ") {
		req.Header.Set("Authorization", authHeader)
		req.Header.Del("SEC")
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, resp.StatusCode, fmt.Errorf("qradar create search returned %d: %s", resp.StatusCode, string(body))
	}

	var searchResp struct {
		SearchID string `json:"search_id"`
		Status   string `json:"status"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&searchResp); err != nil {
		return nil, 0, fmt.Errorf("failed to parse QRadar response: %v", err)
	}

	// Poll for completion
	start := time.Now()
	for {
		if time.Since(start) > timeout {
			return nil, 0, fmt.Errorf("qradar search timeout")
		}
		statusURL := fmt.Sprintf("%s/%s", apiURL, searchResp.SearchID)
		statusReq, _ := http.NewRequest("GET", statusURL, nil)
		statusReq.Header.Set("Accept", "application/json")
		statusReq.Header.Set("SEC", authHeader)

		sResp, err := client.Do(statusReq)
		if err == nil && sResp.StatusCode == http.StatusOK {
			var pollResp struct {
				Status string `json:"status"`
			}
			json.NewDecoder(sResp.Body).Decode(&pollResp)
			sResp.Body.Close()

			if pollResp.Status == "COMPLETED" {
				break
			} else if pollResp.Status == "ERROR" || pollResp.Status == "CANCELED" {
				return nil, 0, fmt.Errorf("qradar search ended with status %s", pollResp.Status)
			}
		}
		time.Sleep(2 * time.Second)
	}

	// Get results
	resultURL := fmt.Sprintf("%s/%s/results", apiURL, searchResp.SearchID)
	resultReq, _ := http.NewRequest("GET", resultURL, nil)
	resultReq.Header.Set("Accept", "application/json")
	resultReq.Header.Set("SEC", authHeader)

	rResp, err := client.Do(resultReq)
	if err != nil {
		return nil, 0, err
	}
	defer rResp.Body.Close()

	var res struct {
		Events []map[string]interface{} `json:"events"`
	}
	if err := json.NewDecoder(rResp.Body).Decode(&res); err != nil {
		return nil, 0, err
	}

	return res.Events, http.StatusOK, nil
}

type qradarHuntRequest struct {
	Query     string `json:"query"`
	TimeRange string `json:"timeRange"`
}

func RunQRadarHunt(c *gin.Context) {
	db := c.MustGet("db").(*gorm.DB)
	aesKey := c.GetString("aesEncryptionKey")

	var req qradarHuntRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	config, authHeader, err := loadQRadarAuth(db, aesKey)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	query := req.Query
	if !strings.HasPrefix(strings.ToUpper(strings.TrimSpace(query)), "SELECT ") {
		query = "SELECT * FROM events WHERE " + query
	}

	started := time.Now()
	hits, status, err := qradarSearch(config.URL, authHeader, query, req.TimeRange, 120*time.Second)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}
	if status != http.StatusOK {
		c.JSON(http.StatusBadGateway, gin.H{"error": "QRadar search failed"})
		return
	}

	// Format to match ELK hit format
	formattedHits := make([]map[string]interface{}, len(hits))
	for i, h := range hits {
		formattedHits[i] = map[string]interface{}{
			"_id":     fmt.Sprintf("qradar-%d", i),
			"_index":  "events",
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
