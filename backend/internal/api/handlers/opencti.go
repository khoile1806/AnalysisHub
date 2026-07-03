package handlers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"github.com/analysishub/backend/internal/crypto"
	"github.com/analysishub/backend/internal/models"
)

type OpenCTIConfigPayload struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	URL         string `json:"url"`
	Username    string `json:"username"`
	Password    string `json:"password"`
	Token       string `json:"token"`
}

// sanitizeOpenCTI strips secrets and adds the has_auth flag for client responses.
func sanitizeOpenCTI(cfg *models.OpenCTIConfig) {
	cfg.HasAuth = cfg.Token != "" || cfg.Password != ""
	cfg.Password = ""
	cfg.Token = ""
}

// ListOpenCTIConfigs returns all saved OpenCTI profiles.
func ListOpenCTIConfigs(c *gin.Context) {
	db := c.MustGet("db").(*gorm.DB)

	var configs []models.OpenCTIConfig
	if err := db.Order("is_active desc, created_at asc").Find(&configs).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list configs"})
		return
	}
	for i := range configs {
		sanitizeOpenCTI(&configs[i])
	}
	c.JSON(http.StatusOK, configs)
}

// GetOpenCTIConfig (legacy singular) returns the currently ACTIVE profile.
func GetOpenCTIConfig(c *gin.Context) {
	db := c.MustGet("db").(*gorm.DB)

	var config models.OpenCTIConfig
	err := db.Where("is_active = ?", true).First(&config).Error
	if err == gorm.ErrRecordNotFound {
		err = db.First(&config).Error
	}
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusOK, models.OpenCTIConfig{})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get config"})
		return
	}
	sanitizeOpenCTI(&config)
	c.JSON(http.StatusOK, config)
}

// CreateOpenCTIConfig adds a new OpenCTI profile (auto-active when first).
func CreateOpenCTIConfig(c *gin.Context) {
	db := c.MustGet("db").(*gorm.DB)
	aesKey := c.GetString("aesEncryptionKey")
	if aesKey == "" {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Server missing AES_ENCRYPTION_KEY config"})
		return
	}

	var payload OpenCTIConfigPayload
	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if strings.TrimSpace(payload.Name) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name is required"})
		return
	}

	cfg := models.OpenCTIConfig{
		Name:        strings.TrimSpace(payload.Name),
		Description: payload.Description,
		URL:         payload.URL,
		Username:    payload.Username,
	}
	if payload.Password != "" {
		enc, err := crypto.Encrypt(payload.Password, aesKey)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Encryption failed"})
			return
		}
		cfg.Password = enc
	}
	if payload.Token != "" {
		enc, err := crypto.Encrypt(payload.Token, aesKey)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Encryption failed"})
			return
		}
		cfg.Token = enc
	}

	var count int64
	db.Model(&models.OpenCTIConfig{}).Count(&count)
	if count == 0 {
		cfg.IsActive = true
	}

	if err := db.Create(&cfg).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save config"})
		return
	}

	sanitizeOpenCTI(&cfg)
	c.JSON(http.StatusCreated, cfg)
}

// UpdateOpenCTIConfig modifies a profile; leaves secrets in place when blank.
func UpdateOpenCTIConfig(c *gin.Context) {
	db := c.MustGet("db").(*gorm.DB)
	aesKey := c.GetString("aesEncryptionKey")
	if aesKey == "" {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Server missing AES_ENCRYPTION_KEY config"})
		return
	}

	id := c.Param("id")
	var cfg models.OpenCTIConfig
	if err := db.First(&cfg, "id = ?", id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "profile not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
		return
	}

	var payload OpenCTIConfigPayload
	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if strings.TrimSpace(payload.Name) != "" {
		cfg.Name = strings.TrimSpace(payload.Name)
	}
	cfg.Description = payload.Description
	cfg.URL = payload.URL
	cfg.Username = payload.Username

	if payload.Password != "" {
		enc, err := crypto.Encrypt(payload.Password, aesKey)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Encryption failed"})
			return
		}
		cfg.Password = enc
	}
	if payload.Token != "" {
		enc, err := crypto.Encrypt(payload.Token, aesKey)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Encryption failed"})
			return
		}
		cfg.Token = enc
	}

	if err := db.Save(&cfg).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update config"})
		return
	}
	sanitizeOpenCTI(&cfg)
	c.JSON(http.StatusOK, cfg)
}

// DeleteOpenCTIConfig removes a profile; auto-promotes another when needed.
func DeleteOpenCTIConfig(c *gin.Context) {
	db := c.MustGet("db").(*gorm.DB)
	id := c.Param("id")

	var cfg models.OpenCTIConfig
	if err := db.First(&cfg, "id = ?", id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "profile not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
		return
	}
	if err := db.Delete(&models.OpenCTIConfig{}, "id = ?", id).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete profile"})
		return
	}
	if cfg.IsActive {
		var next models.OpenCTIConfig
		if err := db.Order("updated_at desc").First(&next).Error; err == nil {
			db.Model(&next).Update("is_active", true)
		}
	}
	c.JSON(http.StatusOK, gin.H{"message": "Profile deleted", "id": cfg.ID})
}

// ActivateOpenCTIConfig marks the chosen profile active and clears the rest.
func ActivateOpenCTIConfig(c *gin.Context) {
	db := c.MustGet("db").(*gorm.DB)
	id := c.Param("id")

	var cfg models.OpenCTIConfig
	if err := db.First(&cfg, "id = ?", id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "profile not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
		return
	}

	err := db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&models.OpenCTIConfig{}).Where("id <> ?", cfg.ID).Update("is_active", false).Error; err != nil {
			return err
		}
		return tx.Model(&cfg).Update("is_active", true).Error
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to activate profile"})
		return
	}

	cfg.IsActive = true
	sanitizeOpenCTI(&cfg)
	c.JSON(http.StatusOK, cfg)
}

// SaveOpenCTIConfig is kept for backward compatibility — upserts active profile.
func SaveOpenCTIConfig(c *gin.Context) {
	db := c.MustGet("db").(*gorm.DB)
	aesKey := c.GetString("aesEncryptionKey")
	if aesKey == "" {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Server missing AES_ENCRYPTION_KEY config"})
		return
	}

	var payload OpenCTIConfigPayload
	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var cfg models.OpenCTIConfig
	err := db.Where("is_active = ?", true).First(&cfg).Error
	if err == gorm.ErrRecordNotFound {
		err = db.First(&cfg).Error
	}
	creating := err == gorm.ErrRecordNotFound
	if err != nil && !creating {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
		return
	}

	if creating {
		cfg.Name = "Default"
		cfg.IsActive = true
	}
	if strings.TrimSpace(payload.Name) != "" {
		cfg.Name = strings.TrimSpace(payload.Name)
	}
	cfg.Description = payload.Description
	cfg.URL = payload.URL
	cfg.Username = payload.Username

	if payload.Password != "" {
		enc, err := crypto.Encrypt(payload.Password, aesKey)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Encryption failed"})
			return
		}
		cfg.Password = enc
	}
	if payload.Token != "" {
		enc, err := crypto.Encrypt(payload.Token, aesKey)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Encryption failed"})
			return
		}
		cfg.Token = enc
	}

	if creating {
		if err := db.Create(&cfg).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save config"})
			return
		}
	} else {
		if err := db.Save(&cfg).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update config"})
			return
		}
	}

	c.JSON(http.StatusOK, gin.H{"message": "Configuration saved"})
}

// SyncOpenCTI triggers a fetch from OpenCTI
func SyncOpenCTI(c *gin.Context) {
	db := c.MustGet("db").(*gorm.DB)
	aesKey := c.GetString("aesEncryptionKey")

	var config models.OpenCTIConfig
	if err := db.Where("is_active = ?", true).First(&config).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			if err := db.First(&config).Error; err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "OpenCTI is not configured"})
				return
			}
		} else {
			c.JSON(http.StatusBadRequest, gin.H{"error": "OpenCTI is not configured"})
			return
		}
	}

	if config.URL == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "OpenCTI URL is empty"})
		return
	}

	// Decrypt token or password
	var token string
	var err error
	if config.Token != "" {
		token, err = crypto.Decrypt(config.Token, aesKey)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to decrypt token"})
			return
		}
	} else if config.Password != "" {
		// NOTE: In a real production scenario, we'd implement OpenCTI's local login here.
		// For now, we assume Token is the primary method for API access.
		_, _ = crypto.Decrypt(config.Password, aesKey)
		c.JSON(http.StatusNotImplemented, gin.H{"error": "Username/Password auth not fully implemented for Sync. Please provide an API Token."})
		return
	}

	if token == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No valid authentication token found"})
		return
	}

	// Execute GraphQL Query
	query := `
	query {
		stixCyberObservables(first: 5000, orderBy: created_at, orderMode: desc) {
			edges {
				node {
					id
					entity_type
					observable_value
					x_opencti_description
				}
			}
		}
	}
	`

	payloadObj := map[string]string{
		"query": query,
	}
	payloadBytes, _ := json.Marshal(payloadObj)

	req, err := http.NewRequest("POST", fmt.Sprintf("%s/graphql", config.URL), bytes.NewBuffer(payloadBytes))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create request"})
		return
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	tr := &http.Transport{
		TLSClientConfig: siemTLSConfig(),
	}
	client := &http.Client{
		Timeout:   30 * time.Second,
		Transport: tr,
	}
	resp, err := client.Do(req)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": fmt.Sprintf("OpenCTI request failed: %v", err)})
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		log.Printf("[opencti] Error response: %s", string(bodyBytes))
		c.JSON(http.StatusBadGateway, gin.H{"error": fmt.Sprintf("OpenCTI returned status %d", resp.StatusCode)})
		return
	}

	var gqlResp struct {
		Data struct {
			StixCyberObservables struct {
				Edges []struct {
					Node struct {
						ID          string `json:"id"`
						EntityType  string `json:"entity_type"`
						Value       string `json:"observable_value"`
						Description string `json:"x_opencti_description"`
					} `json:"node"`
				} `json:"edges"`
			} `json:"stixCyberObservables"`
		} `json:"data"`
		Errors []interface{} `json:"errors"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&gqlResp); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to parse OpenCTI response"})
		return
	}

	if len(gqlResp.Errors) > 0 {
		c.JSON(http.StatusBadGateway, gin.H{"error": "OpenCTI GraphQL returned errors"})
		return
	}

	addedCount := 0
	for _, edge := range gqlResp.Data.StixCyberObservables.Edges {
		node := edge.Node
		if node.Value == "" {
			continue
		}

		ioc := models.IOC{
			Value:       node.Value,
			Type:        node.EntityType,
			Source:      "OpenCTI",
			Description: node.Description,
		}

		// Use FirstOrCreate or clause to ignore duplicates based on value and type
		// Because value and type combination is unique in the model
		result := db.Where("value = ? AND type = ?", ioc.Value, ioc.Type).FirstOrCreate(&ioc)
		if result.RowsAffected > 0 {
			addedCount++
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"message": fmt.Sprintf("Successfully synced %d new IOCs", addedCount),
		"added":   addedCount,
	})
}

// ListIOCs returns the synchronized IOCs
// ListIOCs returns a PAGE of the IOC store with server-side search/filter so the
// endpoint stays responsive even when the store holds millions of indicators
// (TB-scale). Response: { data, total, limit, offset }.
//
// GET /api/v1/iocs?search=&type=&source=&limit=&offset=
func ListIOCs(c *gin.Context) {
	db := c.MustGet("db").(*gorm.DB)

	q := db.Model(&models.IOC{})
	if s := strings.TrimSpace(c.Query("search")); s != "" {
		like := "%" + s + "%"
		q = q.Where("value ILIKE ? OR description ILIKE ?", like, like)
	}
	if t := strings.TrimSpace(c.Query("type")); t != "" {
		q = q.Where("type = ?", t)
	}
	if src := strings.TrimSpace(c.Query("source")); src != "" {
		q = q.Where("source = ?", src)
	}

	var total int64
	q.Count(&total)

	limit := atoiDefault(c.Query("limit"), 100)
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	offset := atoiDefault(c.Query("offset"), 0)
	if offset < 0 {
		offset = 0
	}

	var iocs []models.IOC
	if err := q.Order("created_at desc").Limit(limit).Offset(offset).Find(&iocs).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"data": iocs, "total": total, "limit": limit, "offset": offset})
}

// CreateManualIOC allows manual entry of indicators
func CreateManualIOC(c *gin.Context) {
	db := c.MustGet("db").(*gorm.DB)

	var payload struct {
		Type        string `json:"type" binding:"required"`
		Value       string `json:"value" binding:"required"`
		Description string `json:"description"`
	}

	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ioc := models.IOC{
		Value:       payload.Value,
		Type:        payload.Type,
		Source:      "Manual",
		Description: payload.Description,
	}

	result := db.Where("value = ? AND type = ?", ioc.Value, ioc.Type).FirstOrCreate(&ioc)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error while saving IOC"})
		return
	}

	if result.RowsAffected == 0 {
		c.JSON(http.StatusConflict, gin.H{"error": "This IOC already exists in the database"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"message": "Manual IOC added successfully", "ioc": ioc})
}
