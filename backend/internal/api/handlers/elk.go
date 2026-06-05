package handlers

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"github.com/forensichub/backend/internal/api/middleware"
	"github.com/forensichub/backend/internal/crypto"
	"github.com/forensichub/backend/internal/models"
)

// Hunt tuning constants. Batch size keeps each Lucene/terms query well under
// the default Elasticsearch max_clause_count (1024). Sleep between batches
// gives the cluster room to breathe when scanning very large IOC sets.
const (
	elkBatchSize       = 500
	elkPerBatchHits    = 100
	elkBetweenBatches  = 200 * time.Millisecond
	elkBatchTimeoutSec = 60
	elkMaxDSLSizeBytes = 64 * 1024
)

type ELKConfigPayload struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	URL         string `json:"url"`
	Username    string `json:"username"`
	Password    string `json:"password"`
	APIKey      string `json:"api_key"`
}

// sanitizeELK strips secrets and adds the has_auth flag for client responses.
func sanitizeELK(cfg *models.ELKConfig) {
	cfg.HasAuth = cfg.APIKey != "" || cfg.Password != ""
	cfg.Password = ""
	cfg.APIKey = ""
}

// ListELKConfigs returns all saved ELK profiles. Secrets are never exposed.
func ListELKConfigs(c *gin.Context) {
	db := c.MustGet("db").(*gorm.DB)

	var configs []models.ELKConfig
	if err := db.Order("is_active desc, created_at asc").Find(&configs).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list configs"})
		return
	}
	for i := range configs {
		sanitizeELK(&configs[i])
	}
	c.JSON(http.StatusOK, configs)
}

// GetELKConfig (legacy singular endpoint) returns the currently ACTIVE profile,
// keeping older callers / FE pages working without changes.
func GetELKConfig(c *gin.Context) {
	db := c.MustGet("db").(*gorm.DB)

	var config models.ELKConfig
	err := db.Where("is_active = ?", true).First(&config).Error
	if err != nil {
		// Fallback for very old single-row deployments that haven't been
		// migrated yet.
		err = db.First(&config).Error
	}
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusOK, models.ELKConfig{})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get config"})
		return
	}
	sanitizeELK(&config)
	c.JSON(http.StatusOK, config)
}

// CreateELKConfig adds a new ELK profile. If it is the very first profile in
// the DB it is automatically marked active so hunts work out of the box.
func CreateELKConfig(c *gin.Context) {
	db := c.MustGet("db").(*gorm.DB)
	aesKey := c.GetString("aesEncryptionKey")
	if aesKey == "" {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Server missing AES_ENCRYPTION_KEY config"})
		return
	}

	var payload ELKConfigPayload
	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if strings.TrimSpace(payload.Name) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name is required"})
		return
	}

	cfg := models.ELKConfig{
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
	if payload.APIKey != "" {
		enc, err := crypto.Encrypt(payload.APIKey, aesKey)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Encryption failed"})
			return
		}
		cfg.APIKey = enc
	}

	var count int64
	db.Model(&models.ELKConfig{}).Count(&count)
	if count == 0 {
		cfg.IsActive = true
	}

	if err := db.Create(&cfg).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save config"})
		return
	}

	if uid, ok := middleware.GetUserID(c); ok {
		writeAudit(c, db, &uid, nil, "elk.config.create", fmt.Sprintf("elk:%d", cfg.ID), fmt.Sprintf("created ELK profile %q", cfg.Name))
	}

	sanitizeELK(&cfg)
	c.JSON(http.StatusCreated, cfg)
}

// UpdateELKConfig modifies an existing profile. Secrets are only re-encrypted
// if a non-empty value is supplied — submitting blank Password/APIKey leaves
// the stored secret intact (so the FE can avoid round-tripping passwords).
func UpdateELKConfig(c *gin.Context) {
	db := c.MustGet("db").(*gorm.DB)
	aesKey := c.GetString("aesEncryptionKey")
	if aesKey == "" {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Server missing AES_ENCRYPTION_KEY config"})
		return
	}

	id := c.Param("id")
	var cfg models.ELKConfig
	if err := db.First(&cfg, "id = ?", id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "profile not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
		return
	}

	var payload ELKConfigPayload
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
	if payload.APIKey != "" {
		enc, err := crypto.Encrypt(payload.APIKey, aesKey)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Encryption failed"})
			return
		}
		cfg.APIKey = enc
	}

	if err := db.Save(&cfg).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update config"})
		return
	}

	if uid, ok := middleware.GetUserID(c); ok {
		writeAudit(c, db, &uid, nil, "elk.config.update", fmt.Sprintf("elk:%d", cfg.ID), fmt.Sprintf("updated ELK profile %q", cfg.Name))
	}

	sanitizeELK(&cfg)
	c.JSON(http.StatusOK, cfg)
}

// DeleteELKConfig removes a profile. Refuses to delete the last active profile
// unless another one would be promoted — admin must explicitly activate another
// profile first. This guards against the user accidentally losing all access.
func DeleteELKConfig(c *gin.Context) {
	db := c.MustGet("db").(*gorm.DB)
	id := c.Param("id")

	var cfg models.ELKConfig
	if err := db.First(&cfg, "id = ?", id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "profile not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
		return
	}

	if err := db.Delete(&models.ELKConfig{}, "id = ?", id).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete profile"})
		return
	}

	// If the deleted profile was active, auto-promote the most recently
	// updated remaining profile so the user is never left without a target.
	if cfg.IsActive {
		var next models.ELKConfig
		if err := db.Order("updated_at desc").First(&next).Error; err == nil {
			db.Model(&next).Update("is_active", true)
		}
	}

	if uid, ok := middleware.GetUserID(c); ok {
		writeAudit(c, db, &uid, nil, "elk.config.delete", fmt.Sprintf("elk:%d", cfg.ID), fmt.Sprintf("deleted ELK profile %q", cfg.Name))
	}

	c.JSON(http.StatusOK, gin.H{"message": "Profile deleted", "id": cfg.ID})
}

// ActivateELKConfig marks the given profile active and clears IsActive on all
// others in a single transaction.
func ActivateELKConfig(c *gin.Context) {
	db := c.MustGet("db").(*gorm.DB)
	id := c.Param("id")

	var cfg models.ELKConfig
	if err := db.First(&cfg, "id = ?", id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "profile not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
		return
	}

	err := db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&models.ELKConfig{}).Where("id <> ?", cfg.ID).Update("is_active", false).Error; err != nil {
			return err
		}
		return tx.Model(&cfg).Update("is_active", true).Error
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to activate profile"})
		return
	}

	if uid, ok := middleware.GetUserID(c); ok {
		writeAudit(c, db, &uid, nil, "elk.config.activate", fmt.Sprintf("elk:%d", cfg.ID), fmt.Sprintf("activated ELK profile %q", cfg.Name))
	}

	cfg.IsActive = true
	sanitizeELK(&cfg)
	c.JSON(http.StatusOK, cfg)
}

// SaveELKConfig is kept for backward compatibility: it upserts the currently
// active profile (or creates a "Default" one). New UIs should use the
// multi-profile endpoints above.
func SaveELKConfig(c *gin.Context) {
	db := c.MustGet("db").(*gorm.DB)
	aesKey := c.GetString("aesEncryptionKey")
	if aesKey == "" {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Server missing AES_ENCRYPTION_KEY config"})
		return
	}

	var payload ELKConfigPayload
	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var cfg models.ELKConfig
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
		enc, encErr := crypto.Encrypt(payload.Password, aesKey)
		if encErr != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Encryption failed"})
			return
		}
		cfg.Password = enc
	}
	if payload.APIKey != "" {
		enc, encErr := crypto.Encrypt(payload.APIKey, aesKey)
		if encErr != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Encryption failed"})
			return
		}
		cfg.APIKey = enc
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

	if uid, ok := middleware.GetUserID(c); ok {
		writeAudit(c, db, &uid, nil, "elk.config.update", "elk", "updated ELK active profile")
	}

	c.JSON(http.StatusOK, gin.H{"message": "Configuration saved"})
}

// huntRequest is the body for POST /elk/hunt.
//
//   - mode "lucene": wrap Query into a query_string search (legacy behaviour).
//   - mode "dsl":    forward Body as a full Elasticsearch _search request.
//
// Empty mode is treated as "lucene" with an empty Query, which is rejected.
type huntRequest struct {
	Mode  string                 `json:"mode"`
	Query string                 `json:"query"`
	Body  map[string]interface{} `json:"body"`
}

// RunELKHunt performs a single synchronous search against Elasticsearch.
// Used for manual searches (Lucene string or raw DSL). For the all-IOC
// batched auto hunt, use StreamELKAutoHunt instead.
func RunELKHunt(c *gin.Context) {
	db := c.MustGet("db").(*gorm.DB)
	aesKey := c.GetString("aesEncryptionKey")

	config, authHeader, err := loadELKAuth(db, aesKey)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var req huntRequest
	_ = c.ShouldBindJSON(&req)

	var bodyBytes []byte

	switch req.Mode {
	case "dsl":
		if len(req.Body) == 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "DSL body is empty"})
			return
		}
		bodyBytes, err = json.Marshal(req.Body)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid DSL body"})
			return
		}
		if len(bodyBytes) > elkMaxDSLSizeBytes {
			c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("DSL body exceeds %d bytes", elkMaxDSLSizeBytes)})
			return
		}
	default:
		// "lucene" or unspecified — wrap into query_string.
		if strings.TrimSpace(req.Query) == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Empty query. Use mode=dsl for raw bodies, or provide a Lucene query string."})
			return
		}
		bodyBytes, _ = json.Marshal(luceneBody(req.Query, elkPerBatchHits))
	}

	respBody, status, err := elkSearch(config.URL, authHeader, "*", bodyBytes, 30*time.Second)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}
	if status != http.StatusOK {
		log.Printf("[elk] manual search non-200: status=%d", status)
		c.JSON(http.StatusBadGateway, gin.H{"error": fmt.Sprintf("ELK returned status %d: %s", status, string(respBody))})
		return
	}

	var elkResp map[string]interface{}
	if err := json.Unmarshal(respBody, &elkResp); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to parse ELK response"})
		return
	}

	if uid, ok := middleware.GetUserID(c); ok {
		writeAudit(c, db, &uid, nil, "elk.hunt.manual", "elk", fmt.Sprintf("mode=%s", firstNonEmpty(req.Mode, "lucene")))
	}

	c.JSON(http.StatusOK, elkResp)
}

// StreamELKAutoHunt streams a batched auto-hunt over all IOCs in the database
// via Server-Sent Events. Results are persisted to ELKHuntResult for later AI
// analysis. The client receives:
//
//	event: progress  data: {"batch":N,"total_batches":M,"batch_hits":X,"total_hits":Y}
//	event: hits      data: {"batch":N,"hits":[...]}
//	event: error     data: {"batch":N,"error":"..."}
//	event: done      data: {"total_hits":Y,"total_batches":M,"took_ms":Z,"result_id":"..."}
//
// JWT is supplied via ?token= (EventSource cannot set headers); the standard
// AuthMiddleware handles that.
func StreamELKAutoHunt(c *gin.Context) {
	db := c.MustGet("db").(*gorm.DB)
	aesKey := c.GetString("aesEncryptionKey")

	config, authHeader, err := loadELKAuth(db, aesKey)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Load every IOC. The batching below keeps each upstream query bounded
	// regardless of how large this set is.
	var iocs []models.IOC
	if err := db.Order("created_at desc").Find(&iocs).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to load IOCs"})
		return
	}
	if len(iocs) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No IOCs in database to hunt"})
		return
	}

	// Create a persistent result record before streaming begins.
	userID, _ := middleware.GetUserID(c)
	huntResult := models.ELKHuntResult{
		ConfigID:  config.ID,
		Title:     fmt.Sprintf("Auto Hunt — %d IOCs (%s)", len(iocs), time.Now().Format("2006-01-02 15:04")),
		IOCsUsed:  len(iocs),
		Status:    "running",
		CreatedBy: userID,
	}
	db.Create(&huntResult)

	c.Header("Content-Type", "text/event-stream")
	c.Header("Cache-Control", "no-cache")
	c.Header("Connection", "keep-alive")
	c.Header("X-Accel-Buffering", "no")
	c.Writer.WriteHeader(http.StatusOK)
	c.Writer.Flush()

	clientGone := c.Request.Context().Done()
	sendEvent := func(event string, data interface{}) bool {
		payload, _ := json.Marshal(data)
		_, werr := fmt.Fprintf(c.Writer, "event: %s\ndata: %s\n\n", event, string(payload))
		if werr != nil {
			return false
		}
		c.Writer.Flush()
		return true
	}

	// Group IOCs by bucket — each bucket maps to a set of ECS field names so
	// terms queries target the right schema columns instead of scanning *.
	buckets := groupIOCs(iocs)

	type batchPlan struct {
		bucket string
		fields []string // empty → query_string fallback over values
		values []string
	}
	var plans []batchPlan
	for _, b := range bucketOrder {
		vals := buckets[b.name]
		if len(vals) == 0 {
			continue
		}
		for i := 0; i < len(vals); i += elkBatchSize {
			end := i + elkBatchSize
			if end > len(vals) {
				end = len(vals)
			}
			plans = append(plans, batchPlan{bucket: b.name, fields: b.fields, values: vals[i:end]})
		}
	}

	const maxStoredHits = 5000
	totalBatches := len(plans)
	seen := make(map[string]struct{})
	totalHits := 0
	startedAt := time.Now()
	allHits := make([]map[string]interface{}, 0, 256) // accumulated for persistence

	for idx, plan := range plans {
		select {
		case <-clientGone:
			now := time.Now()
			db.Model(&huntResult).Updates(map[string]interface{}{"status": "failed", "finished_at": now})
			return
		default:
		}

		var body map[string]interface{}
		if len(plan.fields) == 0 {
			// Fallback for unknown IOC types: search the values across all
			// fields with a quoted query_string OR-chain.
			body = luceneBody(luceneOR(plan.values), elkPerBatchHits)
		} else {
			body = termsBatchBody(plan.fields, plan.values, elkPerBatchHits)
		}
		bodyBytes, _ := json.Marshal(body)

		respBody, status, err := elkSearch(config.URL, authHeader, "*", bodyBytes, time.Duration(elkBatchTimeoutSec)*time.Second)
		if err != nil {
			sendEvent("error", gin.H{"batch": idx + 1, "bucket": plan.bucket, "error": err.Error()})
			time.Sleep(elkBetweenBatches)
			continue
		}
		if status != http.StatusOK {
			snippet := string(respBody)
			if len(snippet) > 500 {
				snippet = snippet[:500] + "..."
			}
			log.Printf("[elk] batch %d/%d status=%d", idx+1, totalBatches, status)
			sendEvent("error", gin.H{"batch": idx + 1, "bucket": plan.bucket, "error": fmt.Sprintf("status %d: %s", status, snippet)})
			time.Sleep(elkBetweenBatches)
			continue
		}

		var parsed struct {
			Hits struct {
				Hits []map[string]interface{} `json:"hits"`
			} `json:"hits"`
		}
		if err := json.Unmarshal(respBody, &parsed); err != nil {
			sendEvent("error", gin.H{"batch": idx + 1, "bucket": plan.bucket, "error": "parse failed"})
			continue
		}

		// Deduplicate hits across batches (the same document can match multiple
		// IOC values when bucketing splits values into chunks).
		fresh := make([]map[string]interface{}, 0, len(parsed.Hits.Hits))
		for _, h := range parsed.Hits.Hits {
			id, _ := h["_id"].(string)
			ix, _ := h["_index"].(string)
			key := ix + "|" + id
			if _, dup := seen[key]; dup {
				continue
			}
			seen[key] = struct{}{}
			fresh = append(fresh, h)
		}
		totalHits += len(fresh)

		// Accumulate hits for persistence (cap to avoid unbounded memory usage).
		if len(allHits) < maxStoredHits {
			remaining := maxStoredHits - len(allHits)
			if len(fresh) <= remaining {
				allHits = append(allHits, fresh...)
			} else {
				allHits = append(allHits, fresh[:remaining]...)
			}
		}

		if len(fresh) > 0 {
			if !sendEvent("hits", gin.H{"batch": idx + 1, "bucket": plan.bucket, "hits": fresh}) {
				now := time.Now()
				db.Model(&huntResult).Updates(map[string]interface{}{"status": "failed", "finished_at": now})
				return
			}
		}
		if !sendEvent("progress", gin.H{
			"batch":         idx + 1,
			"total_batches": totalBatches,
			"bucket":        plan.bucket,
			"batch_hits":    len(fresh),
			"total_hits":    totalHits,
		}) {
			now := time.Now()
			db.Model(&huntResult).Updates(map[string]interface{}{"status": "failed", "finished_at": now})
			return
		}

		if idx < len(plans)-1 {
			time.Sleep(elkBetweenBatches)
		}
	}

	// Persist all accumulated hits.
	now := time.Now()
	if hitsJSON, jerr := json.Marshal(allHits); jerr == nil {
		db.Model(&huntResult).Updates(map[string]interface{}{
			"status":      "done",
			"total_hits":  totalHits,
			"results":     string(hitsJSON),
			"finished_at": now,
		})
	} else {
		db.Model(&huntResult).Updates(map[string]interface{}{
			"status":      "done",
			"total_hits":  totalHits,
			"finished_at": now,
		})
	}

	sendEvent("done", gin.H{
		"total_hits":    totalHits,
		"total_batches": totalBatches,
		"total_iocs":    len(iocs),
		"took_ms":       time.Since(startedAt).Milliseconds(),
		"result_id":     huntResult.ID.String(),
	})

	writeAudit(c, db, &userID, nil, "elk.hunt.auto", "elk", fmt.Sprintf("iocs=%d batches=%d hits=%d", len(iocs), totalBatches, totalHits))
}

// loadELKAuth fetches the saved ELK config and returns it together with a
// ready-to-use Authorization header value (Basic or ApiKey).
func loadELKAuth(db *gorm.DB, aesKey string) (models.ELKConfig, string, error) {
	var config models.ELKConfig
	err := db.Where("is_active = ?", true).First(&config).Error
	if err == gorm.ErrRecordNotFound {
		// Fall back to any profile so legacy single-row deployments still work.
		err = db.First(&config).Error
	}
	if err != nil {
		return config, "", fmt.Errorf("ELK is not configured")
	}
	if strings.TrimSpace(config.URL) == "" {
		return config, "", fmt.Errorf("ELK URL is empty")
	}

	if config.APIKey != "" {
		decKey, err := crypto.Decrypt(config.APIKey, aesKey)
		if err != nil {
			return config, "", fmt.Errorf("failed to decrypt API Key")
		}
		return config, "ApiKey " + decKey, nil
	}
	if config.Password != "" && config.Username != "" {
		decPass, err := crypto.Decrypt(config.Password, aesKey)
		if err != nil {
			return config, "", fmt.Errorf("failed to decrypt password")
		}
		return config, "Basic " + base64.StdEncoding.EncodeToString([]byte(config.Username+":"+decPass)), nil
	}
	return config, "", fmt.Errorf("no valid ELK authentication configured")
}

// elkSearch issues a POST {baseURL}/{indexPattern}/_search request.
func elkSearch(baseURL, authHeader, indexPattern string, body []byte, timeout time.Duration) ([]byte, int, error) {
	if indexPattern == "" {
		indexPattern = "*"
	}
	url := fmt.Sprintf("%s/%s/_search", strings.TrimRight(baseURL, "/"), indexPattern)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(body))
	if err != nil {
		return nil, 0, fmt.Errorf("build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", authHeader)

	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("ELK request failed: %v", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	return respBody, resp.StatusCode, nil
}

// luceneBody wraps a Lucene query string into a query_string search.
func luceneBody(query string, size int) map[string]interface{} {
	return map[string]interface{}{
		"query": map[string]interface{}{
			"query_string": map[string]interface{}{
				"query":   query,
				"fields":  []string{"*"},
				"lenient": true,
			},
		},
		"size": size,
		"sort": []map[string]interface{}{
			{"@timestamp": map[string]interface{}{"order": "desc", "unmapped_type": "boolean"}},
		},
	}
}

// termsBatchBody builds a bool.should query that runs the same terms list
// against multiple ECS field names. Lenient + unmapped_type avoid failures
// when an index does not have one of the candidate fields.
func termsBatchBody(fields []string, values []string, size int) map[string]interface{} {
	should := make([]map[string]interface{}, 0, len(fields))
	for _, f := range fields {
		should = append(should, map[string]interface{}{
			"terms": map[string]interface{}{f: values},
		})
	}
	return map[string]interface{}{
		"query": map[string]interface{}{
			"bool": map[string]interface{}{
				"should":               should,
				"minimum_should_match": 1,
			},
		},
		"size": size,
		"sort": []map[string]interface{}{
			{"@timestamp": map[string]interface{}{"order": "desc", "unmapped_type": "boolean"}},
		},
	}
}

// bucketDef declares an IOC bucket together with the ECS field names the
// terms query should target. Order is preserved so the FE sees results in
// a predictable sequence (IPs first, etc.).
type bucketDef struct {
	name   string
	fields []string
}

var bucketOrder = []bucketDef{
	{name: "ip", fields: []string{"source.ip", "destination.ip", "client.ip", "server.ip", "host.ip"}},
	{name: "domain", fields: []string{"dns.question.name", "url.domain", "destination.domain", "source.domain", "host.hostname"}},
	{name: "url", fields: []string{"url.full", "url.original"}},
	{name: "hash", fields: []string{"file.hash.md5", "file.hash.sha1", "file.hash.sha256", "process.hash.md5", "process.hash.sha1", "process.hash.sha256"}},
	{name: "email", fields: []string{"user.email", "source.user.email", "destination.user.email", "email.from.address", "email.to.address"}},
	{name: "mac", fields: []string{"source.mac", "destination.mac", "host.mac"}},
	{name: "other", fields: nil}, // handled specially via query_string fallback
}

// groupIOCs sorts the IOC list into buckets keyed by their normalised type.
// Anything that doesn't map to a known bucket falls through to "other" and
// is later searched with a per-value query_string fallback.
func groupIOCs(iocs []models.IOC) map[string][]string {
	out := make(map[string][]string)
	for _, ioc := range iocs {
		v := strings.TrimSpace(ioc.Value)
		if v == "" {
			continue
		}
		switch strings.ToLower(ioc.Type) {
		case "ipv4-addr", "ipv6-addr":
			out["ip"] = append(out["ip"], v)
		case "domain-name":
			out["domain"] = append(out["domain"], v)
		case "url":
			out["url"] = append(out["url"], v)
		case "file-hash", "file":
			out["hash"] = append(out["hash"], v)
		case "email-address":
			out["email"] = append(out["email"], v)
		case "mac-addr":
			out["mac"] = append(out["mac"], v)
		default:
			out["other"] = append(out["other"], v)
		}
	}
	return out
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// luceneOR joins values into a quoted OR chain suitable for query_string.
// Each value is double-quoted with embedded quotes escaped so Lucene treats
// the whole token as a literal rather than parsing operators/special chars.
func luceneOR(values []string) string {
	parts := make([]string, 0, len(values))
	for _, v := range values {
		v = strings.ReplaceAll(v, `\`, `\\`)
		v = strings.ReplaceAll(v, `"`, `\"`)
		parts = append(parts, `"`+v+`"`)
	}
	return strings.Join(parts, " OR ")
}
