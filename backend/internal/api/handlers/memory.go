package handlers

import (
	"net/http"
	"os"
	"path/filepath"

	"github.com/gin-gonic/gin"
)

// ListMemoryDumps lists all memory dumps available in the shared storage volume
func ListMemoryDumps(c *gin.Context) {
	dumpDir := "/app/storage/memory_dumps"
	os.MkdirAll(dumpDir, 0755)

	entries, err := os.ReadDir(dumpDir)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read memory dumps directory"})
		return
	}

	type FileInfo struct {
		Name string `json:"name"`
		Size int64  `json:"size"`
	}

	var files []FileInfo
	for _, entry := range entries {
		if !entry.IsDir() {
			info, err := entry.Info()
			if err == nil {
				files = append(files, FileInfo{Name: entry.Name(), Size: info.Size()})
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{"dumps": files})
}

// UploadMemoryDump handles manual upload of memory dump files
func UploadMemoryDump(c *gin.Context) {
	file, err := c.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No file uploaded"})
		return
	}

	dumpDir := "/app/storage/memory_dumps"
	os.MkdirAll(dumpDir, 0755)
	
	// Prevent directory traversal
	fileName := filepath.Base(file.Filename)
	destPath := filepath.Join(dumpDir, fileName)

	if err := c.SaveUploadedFile(file, destPath); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save file"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "File uploaded successfully", "filename": fileName})
}

// DeleteMemoryDump deletes a memory dump file
func DeleteMemoryDump(c *gin.Context) {
	fileName := filepath.Base(c.Param("filename"))
	dumpDir := "/app/storage/memory_dumps"
	destPath := filepath.Join(dumpDir, fileName)

	if err := os.Remove(destPath); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete file"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "File deleted successfully"})
}
