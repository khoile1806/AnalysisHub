package handlers

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/analysishub/backend/internal/api/middleware"
	"github.com/analysishub/backend/internal/models"
)

// ListTools returns all tools, optionally filtered by category and/or platform.
//
// GET /api/v1/tools?category=memory&platform=windows
func ListTools(c *gin.Context) {
	db, ok := mustGetDB(c)
	if !ok {
		return
	}

	query := db.Model(&models.Tool{})

	if cat := c.Query("category"); cat != "" {
		query = query.Where("category = ?", cat)
	}
	if plat := c.Query("platform"); plat != "" {
		query = query.Where("platform = ?", plat)
	}

	var tools []models.Tool
	if err := query.Order("created_at desc").Find(&tools).Error; err != nil {
		log.Printf("[tools] list error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "failed to list tools"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "data": tools})
}

// UploadTool handles multipart/form-data uploads of new tool binaries.
//
// POST /api/v1/tools
// Form fields: name, category, platform, version, description, args, file (multipart)
func UploadTool(c *gin.Context) {
	db, ok := mustGetDB(c)
	if !ok {
		return
	}
	store, ok := mustGetStorage(c)
	if !ok {
		return
	}

	userID, _ := middleware.GetUserID(c)

	// Parse multipart file
	fileHeader, err := c.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "file is required"})
		return
	}

	name := c.PostForm("name")
	category := c.PostForm("category")
	platform := c.PostForm("platform")
	if name == "" || category == "" || platform == "" {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "name, category, and platform are required"})
		return
	}

	// Validate category
	validCategories := map[string]bool{
		"memory": true, "triage": true, "process": true,
		"network": true, "disk": true, "log": true, "other": true,
	}
	if !validCategories[category] {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid category"})
		return
	}

	// Validate platform
	validPlatforms := map[string]bool{"windows": true, "linux": true, "both": true}
	if !validPlatforms[platform] {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid platform"})
		return
	}

	// Open the uploaded file
	f, err := fileHeader.Open()
	if err != nil {
		log.Printf("[tools] open upload: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "failed to read uploaded file"})
		return
	}
	defer f.Close()

	ext := filepath.Ext(fileHeader.Filename)

	// Build a unique storage filename to avoid collisions
	toolID := uuid.New()
	storedFilename := toolID.String() + ext

	savedName, err := store.SaveTool(storedFilename, f)
	if err != nil {
		log.Printf("[tools] save tool: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "failed to store tool file"})
		return
	}

	maxResultMB, _ := strconv.Atoi(c.PostForm("max_result_mb"))
	tool := models.Tool{
		ID:             toolID,
		Name:           name,
		Category:       category,
		Platform:       platform,
		Version:        c.PostForm("version"),
		Description:    c.PostForm("description"),
		Args:           c.PostForm("args"),
		ExecutablePath: c.PostForm("executable_path"),
		FileName:       fileHeader.Filename,
		FileSize:       fileHeader.Size,
		CreatedBy:      userID,
		// Result-collection spec (all optional).
		CollectResult:   c.PostForm("collect_result") == "true",
		OutputGlobs:     c.PostForm("output_globs"),
		OutputScope:     c.PostForm("output_scope"),
		ResultProcessor: c.PostForm("result_processor"),
		AIDefault:       c.PostForm("ai_default") == "true",
		AutoAnalyze:     c.PostForm("auto_analyze") == "true",
		MaxResultMB:     maxResultMB,
	}

	if err := db.Create(&tool).Error; err != nil {
		log.Printf("[tools] db create: %v", err)
		// Best-effort cleanup of the stored file.
		os.Remove(store.GetToolPath(savedName))
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "failed to save tool record"})
		return
	}

	writeAudit(c, db, &userID, nil, "tool.upload", tool.ID.String(), fmt.Sprintf("uploaded tool %q (%s)", name, category))

	c.JSON(http.StatusCreated, gin.H{"success": true, "data": tool})
}

// GetTool returns a single tool by its UUID.
//
// GET /api/v1/tools/:id
func GetTool(c *gin.Context) {
	db, ok := mustGetDB(c)
	if !ok {
		return
	}

	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid tool ID"})
		return
	}

	var tool models.Tool
	if err := db.First(&tool, "id = ?", id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "tool not found"})
			return
		}
		log.Printf("[tools] get error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "internal server error"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "data": tool})
}

// UpdateTool updates the metadata of a tool. The binary file itself is not
// replaced — callers that need to swap the file must delete and re-upload.
//
// PUT /api/v1/tools/:id
// JSON body: { name, category, platform, version, description, args, executable_path }
func UpdateTool(c *gin.Context) {
	db, ok := mustGetDB(c)
	if !ok {
		return
	}
	userID, _ := middleware.GetUserID(c)

	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid tool ID"})
		return
	}

	var body struct {
		Name            string `json:"name"`
		Category        string `json:"category"`
		Platform        string `json:"platform"`
		Version         string `json:"version"`
		Description     string `json:"description"`
		Args            string `json:"args"`
		ExecutablePath  string `json:"executable_path"`
		CollectResult   bool   `json:"collect_result"`
		OutputGlobs     string `json:"output_globs"`
		OutputScope     string `json:"output_scope"`
		ResultProcessor string `json:"result_processor"`
		AIDefault       bool   `json:"ai_default"`
		AutoAnalyze     bool   `json:"auto_analyze"`
		MaxResultMB     int    `json:"max_result_mb"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid request body"})
		return
	}
	if body.Name == "" || body.Category == "" || body.Platform == "" {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "name, category, and platform are required"})
		return
	}

	validCategories := map[string]bool{
		"memory": true, "triage": true, "process": true,
		"network": true, "disk": true, "log": true, "other": true,
	}
	if !validCategories[body.Category] {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid category"})
		return
	}
	validPlatforms := map[string]bool{"windows": true, "linux": true, "both": true}
	if !validPlatforms[body.Platform] {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid platform"})
		return
	}

	var tool models.Tool
	if err := db.First(&tool, "id = ?", id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "tool not found"})
			return
		}
		log.Printf("[tools] update fetch error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "internal server error"})
		return
	}

	updates := map[string]interface{}{
		"name":             body.Name,
		"category":         body.Category,
		"platform":         body.Platform,
		"version":          body.Version,
		"description":      body.Description,
		"args":             body.Args,
		"entrypoint":       body.ExecutablePath,
		"collect_result":   body.CollectResult,
		"output_globs":     body.OutputGlobs,
		"output_scope":     body.OutputScope,
		"result_processor": body.ResultProcessor,
		"ai_default":       body.AIDefault,
		"auto_analyze":     body.AutoAnalyze,
		"max_result_mb":    body.MaxResultMB,
	}
	if err := db.Model(&tool).Updates(updates).Error; err != nil {
		log.Printf("[tools] update error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "failed to update tool"})
		return
	}

	writeAudit(c, db, &userID, nil, "tool.update", tool.ID.String(), fmt.Sprintf("updated tool %q", body.Name))

	c.JSON(http.StatusOK, gin.H{"success": true, "data": tool})
}

// DeleteTool removes a tool record and its associated file from storage.
//
// DELETE /api/v1/tools/:id
func DeleteTool(c *gin.Context) {
	db, ok := mustGetDB(c)
	if !ok {
		return
	}
	store, ok := mustGetStorage(c)
	if !ok {
		return
	}
	userID, _ := middleware.GetUserID(c)

	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid tool ID"})
		return
	}

	var tool models.Tool
	if err := db.First(&tool, "id = ?", id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "tool not found"})
			return
		}
		log.Printf("[tools] delete fetch error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "internal server error"})
		return
	}

	// Delete the file first.
	storedName := tool.ID.String() + filepath.Ext(tool.FileName)
	filePath := store.GetToolPath(storedName)
	if err := os.Remove(filePath); err != nil && !os.IsNotExist(err) {
		log.Printf("[tools] remove file %s: %v", filePath, err)
	}

	if err := db.Delete(&tool).Error; err != nil {
		log.Printf("[tools] db delete error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "failed to delete tool"})
		return
	}

	writeAudit(c, db, &userID, nil, "tool.delete", tool.ID.String(), fmt.Sprintf("deleted tool %q", tool.Name))

	c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{"id": id}})
}

// DownloadTool streams the binary file to the caller.
// Used by agents to fetch tools before execution.
//
// GET /api/v1/tools/:id/download
func DownloadTool(c *gin.Context) {
	db, ok := mustGetDB(c)
	if !ok {
		return
	}
	store, ok := mustGetStorage(c)
	if !ok {
		return
	}

	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid tool ID"})
		return
	}

	var tool models.Tool
	if err := db.First(&tool, "id = ?", id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "tool not found"})
			return
		}
		log.Printf("[tools] download fetch error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "internal server error"})
		return
	}

	storedName := tool.ID.String() + filepath.Ext(tool.FileName)
	filePath := store.GetToolPath(storedName)
	c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, tool.FileName))
	c.Header("Content-Length", strconv.FormatInt(tool.FileSize, 10))
	c.File(filePath)
}
