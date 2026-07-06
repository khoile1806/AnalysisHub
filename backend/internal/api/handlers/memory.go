package handlers

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

const memoryDumpDir = "/app/storage/memory_dumps"

// memoryPartDir holds in-progress chunked uploads until they are finalized.
var memoryPartDir = filepath.Join(memoryDumpDir, ".parts")

// safeUploadID restricts a client-supplied upload id to a path-safe charset so it
// can never escape the parts directory.
var safeUploadID = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

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

// maxMemoryDumpBytes is a generous upper bound on an uploaded memory dump — well
// above any realistic physical-RAM capture — that only exists to stop an abusive
// unbounded upload from filling the storage volume.
const maxMemoryDumpBytes = 128 << 30 // 128 GB

// UploadMemoryDump handles manual upload of memory dump files
func UploadMemoryDump(c *gin.Context) {
	file, err := c.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No file uploaded"})
		return
	}
	if file.Size > maxMemoryDumpBytes {
		c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": "file exceeds maximum allowed size"})
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

// UploadMemoryDumpChunk assembles a large memory dump from sequential chunks so
// uploads survive a 100 MB request-body cap on an upstream proxy (e.g.
// Cloudflare). Each request carries one chunk plus its byte offset; the chunk is
// written into a per-upload .part file and, on the final chunk, atomically
// renamed into place. Form fields: upload_id, filename, offset, total_size,
// final(0|1), file. Admin-only (same as the single-shot upload).
func UploadMemoryDumpChunk(c *gin.Context) {
	uploadID := strings.TrimSpace(c.PostForm("upload_id"))
	filename := filepath.Base(strings.TrimSpace(c.PostForm("filename")))
	if !safeUploadID.MatchString(uploadID) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid upload_id"})
		return
	}
	if filename == "" || filename == "." || filename == ".." {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid filename"})
		return
	}
	offset, err := strconv.ParseInt(c.PostForm("offset"), 10, 64)
	if err != nil || offset < 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid offset"})
		return
	}
	totalSize, _ := strconv.ParseInt(c.PostForm("total_size"), 10, 64)
	if totalSize > maxMemoryDumpBytes {
		c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": "file exceeds maximum allowed size"})
		return
	}
	final := c.PostForm("final") == "1" || c.PostForm("final") == "true"

	fh, err := c.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no chunk uploaded"})
		return
	}

	if err := os.MkdirAll(memoryPartDir, 0755); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "cannot create upload dir"})
		return
	}
	// Opportunistically drop abandoned parts (aborted uploads) older than 24h.
	sweepStaleParts(24 * time.Hour)

	partPath := filepath.Join(memoryPartDir, uploadID+".part")
	f, err := os.OpenFile(partPath, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "cannot open part file"})
		return
	}
	src, err := fh.Open()
	if err != nil {
		f.Close()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "cannot read chunk"})
		return
	}
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		src.Close()
		f.Close()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "seek failed"})
		return
	}
	written, copyErr := io.Copy(f, src)
	src.Close()
	f.Close()
	if copyErr != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "write chunk failed: " + copyErr.Error()})
		return
	}

	if !final {
		c.JSON(http.StatusOK, gin.H{"done": false, "received": offset + written})
		return
	}

	// Final chunk: verify assembled size, then move into place atomically.
	info, statErr := os.Stat(partPath)
	if statErr != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "cannot stat assembled file"})
		return
	}
	if totalSize > 0 && info.Size() != totalSize {
		os.Remove(partPath)
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("assembled size %d != expected %d — upload incomplete", info.Size(), totalSize)})
		return
	}
	if err := os.MkdirAll(memoryDumpDir, 0755); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "cannot create dump dir"})
		return
	}
	dest := filepath.Join(memoryDumpDir, filename)
	if err := os.Rename(partPath, dest); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "finalize failed: " + err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"done": true, "filename": filename, "size": info.Size()})
}

// sweepStaleParts removes .part files older than maxAge (best-effort cleanup of
// aborted chunked uploads so they don't leak disk).
func sweepStaleParts(maxAge time.Duration) {
	entries, err := os.ReadDir(memoryPartDir)
	if err != nil {
		return
	}
	cutoff := time.Now().Add(-maxAge)
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".part") {
			continue
		}
		if info, err := e.Info(); err == nil && info.ModTime().Before(cutoff) {
			os.Remove(filepath.Join(memoryPartDir, e.Name()))
		}
	}
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
