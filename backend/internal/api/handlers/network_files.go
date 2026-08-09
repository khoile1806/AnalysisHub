package handlers

import (
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/analysishub/backend/internal/api/middleware"
	"github.com/analysishub/backend/internal/models"
)

// network_files.go — inspect the files reconstructed from a capture. A carved
// file is stored under analysis-uploads/network-carved/<scanID>/<sha>.bin and
// registered in the Evidence Store. These admin-only endpoints let an analyst
// (A) preview its content in-app (type + hex + strings) and download it, and
// (B) pivot it straight into the full Malware Analysis pipeline.

var carvedShaRe = regexp.MustCompile(`^[a-fA-F0-9]{64}$`)

const (
	carvedReadCap    = 8 << 20 // read at most 8 MB for preview/strings
	carvedHexBytes   = 4096    // hex-dump the first 4 KB
	carvedMaxStrings = 500
)

// carvedFile resolves and reads a carved file for the given scan + sha256. It
// guards against path traversal (scanID must be a UUID, sha a 64-hex string) and
// returns the bytes (capped), the full on-disk size, and a display name.
func (h *NetworkHandler) carvedFile(scanID, sha string, cap int64) ([]byte, int64, string, bool) {
	if _, err := uuid.Parse(scanID); err != nil {
		return nil, 0, "", false
	}
	if !carvedShaRe.MatchString(sha) {
		return nil, 0, "", false
	}
	sha = strings.ToLower(sha)
	rel := "analysis-uploads/network-carved/" + scanID + "/" + sha + ".bin"
	abs := h.Store.AbsPath(rel)
	st, err := os.Stat(abs)
	if err != nil || st.IsDir() {
		return nil, 0, "", false
	}
	f, err := os.Open(abs)
	if err != nil {
		return nil, 0, "", false
	}
	defer f.Close()
	buf := make([]byte, cap)
	n, _ := f.Read(buf)
	data := buf[:n]

	name := "carved-" + sha[:12] + ".bin"
	var ev models.CaseEvidence
	if h.DB.Where("sha256 = ? AND stored_path = ?", sha, rel).First(&ev).Error == nil && ev.FileName != "" {
		name = ev.FileName
	}
	return data, st.Size(), name, true
}

// PreviewCarvedFile returns type + hex + strings for a carved file (admin only).
// GET /api/v1/network/:id/files/:sha/preview
func (h *NetworkHandler) PreviewCarvedFile(c *gin.Context) {
	if middleware.GetRole(c) != "admin" {
		c.JSON(http.StatusForbidden, gin.H{"success": false, "error": "admin role required"})
		return
	}
	data, size, name, ok := h.carvedFile(c.Param("id"), c.Param("sha"), carvedReadCap)
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "carved file not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{
		"name":       name,
		"size":       size,
		"sha256":     strings.ToLower(c.Param("sha")),
		"type":       sniffType(data),
		"truncated":  size > int64(len(data)),
		"hex":        hexDump(data, carvedHexBytes),
		"strings":    extractStrings(data, 4, carvedMaxStrings),
		"string_cap": carvedMaxStrings,
	}})
}

// DownloadCarvedFile streams the raw carved file (admin only, audited).
// GET /api/v1/network/:id/files/:sha/download
func (h *NetworkHandler) DownloadCarvedFile(c *gin.Context) {
	if middleware.GetRole(c) != "admin" {
		c.JSON(http.StatusForbidden, gin.H{"success": false, "error": "admin role required"})
		return
	}
	scanID, sha := c.Param("id"), c.Param("sha")
	if _, err := uuid.Parse(scanID); err != nil || !carvedShaRe.MatchString(sha) {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid id or sha"})
		return
	}
	rel := "analysis-uploads/network-carved/" + scanID + "/" + strings.ToLower(sha) + ".bin"
	abs := h.Store.AbsPath(rel)
	if st, err := os.Stat(abs); err != nil || st.IsDir() {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "carved file not found"})
		return
	}
	name := "carved-" + strings.ToLower(sha)[:12] + ".bin"
	var ev models.CaseEvidence
	if h.DB.Where("sha256 = ? AND stored_path = ?", strings.ToLower(sha), rel).First(&ev).Error == nil && ev.FileName != "" {
		name = ev.FileName
	}
	var uid *uuid.UUID
	if id, ok := middleware.GetUserID(c); ok {
		uid = &id
	}
	writeAudit(c, h.DB, uid, nil, "network.file_download", name, "downloaded a carved file from a capture")
	c.FileAttachment(abs, name)
}

// AnalyzeCarvedInMalware pivots a carved file into the Malware Analysis pipeline
// (admin only). Returns the new malware scan id so the UI can open it.
// POST /api/v1/network/:id/files/:sha/analyze-malware
func (h *NetworkHandler) AnalyzeCarvedInMalware(c *gin.Context) {
	if middleware.GetRole(c) != "admin" {
		c.JSON(http.StatusForbidden, gin.H{"success": false, "error": "admin role required"})
		return
	}
	if h.Malware == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"success": false, "error": "malware analysis is not available"})
		return
	}
	// Read the whole file (up to the malware size cap) for a faithful analysis.
	data, _, name, ok := h.carvedFile(c.Param("id"), c.Param("sha"), h.Malware.maxUpload())
	if !ok || len(data) == 0 {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "carved file not found"})
		return
	}
	var userID uuid.UUID
	if uid, ok := middleware.GetUserID(c); ok {
		userID = uid
	}
	scanID, err := h.Malware.AnalyzeBytes(data, name, "", nil, userID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
		return
	}
	writeAudit(c, h.DB, &userID, nil, "network.file_to_malware", name, "sent a carved file to Malware Analysis")
	c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{"malware_scan_id": scanID}})
}

// ── content helpers ──────────────────────────────────────────────────────────

// sniffType identifies a file from its magic bytes (best-effort).
func sniffType(b []byte) string {
	switch {
	case len(b) >= 2 && b[0] == 'M' && b[1] == 'Z':
		return "PE / DOS executable (MZ)"
	case len(b) >= 4 && string(b[:4]) == "\x7fELF":
		return "ELF executable"
	case len(b) >= 4 && string(b[:4]) == "%PDF":
		return "PDF document"
	case len(b) >= 4 && string(b[:4]) == "PK\x03\x04":
		return "ZIP / OOXML (docx/xlsx/jar/apk)"
	case len(b) >= 4 && string(b[:4]) == "Rar!":
		return "RAR archive"
	case len(b) >= 8 && string(b[:8]) == "\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
		return "OLE / legacy Office (doc/xls/ppt)"
	case len(b) >= 3 && b[0] == 0x1f && b[1] == 0x8b:
		return "gzip"
	case len(b) >= 4 && string(b[:4]) == "\x89PNG":
		return "PNG image"
	case len(b) >= 3 && b[0] == 0xff && b[1] == 0xd8 && b[2] == 0xff:
		return "JPEG image"
	case len(b) >= 4 && (string(b[:4]) == "GIF8"):
		return "GIF image"
	case len(b) >= 4 && string(b[:4]) == "\xca\xfe\xba\xbe":
		return "Java class / Mach-O fat binary"
	case looksTextual(b):
		return "text / script"
	default:
		return "unknown / raw binary"
	}
}

// looksTextual reports whether the leading bytes are mostly printable.
func looksTextual(b []byte) bool {
	n := len(b)
	if n == 0 {
		return false
	}
	if n > 512 {
		n = 512
	}
	printable := 0
	for i := 0; i < n; i++ {
		c := b[i]
		if c == 9 || c == 10 || c == 13 || (c >= 0x20 && c < 0x7f) {
			printable++
		}
	}
	return printable*100/n >= 90
}

// extractStrings pulls printable ASCII and UTF-16LE runs of >= minLen chars,
// deduplicated and capped.
func extractStrings(b []byte, minLen, capN int) []string {
	seen := map[string]bool{}
	out := []string{}
	add := func(s string) {
		if len(s) < minLen || seen[s] || len(out) >= capN {
			return
		}
		if len(s) > 200 {
			s = s[:200]
		}
		seen[s] = true
		out = append(out, s)
	}
	// ASCII
	var cur []byte
	for _, c := range b {
		if c >= 0x20 && c < 0x7f {
			cur = append(cur, c)
		} else {
			add(string(cur))
			cur = cur[:0]
		}
		if len(out) >= capN {
			break
		}
	}
	add(string(cur))
	// UTF-16LE (printable byte followed by 0x00)
	cur = cur[:0]
	for i := 0; i+1 < len(b); i += 2 {
		if b[i] >= 0x20 && b[i] < 0x7f && b[i+1] == 0x00 {
			cur = append(cur, b[i])
		} else {
			add(string(cur))
			cur = cur[:0]
		}
		if len(out) >= capN {
			break
		}
	}
	add(string(cur))
	return out
}

// hexDump renders a classic offset/hex/ascii dump of the first `limit` bytes.
func hexDump(b []byte, limit int) string {
	if len(b) > limit {
		b = b[:limit]
	}
	var sb strings.Builder
	for i := 0; i < len(b); i += 16 {
		fmt.Fprintf(&sb, "%08x  ", i)
		for j := i; j < i+16; j++ {
			if j < len(b) {
				fmt.Fprintf(&sb, "%02x ", b[j])
			} else {
				sb.WriteString("   ")
			}
			if j == i+7 {
				sb.WriteByte(' ')
			}
		}
		sb.WriteString(" |")
		for j := i; j < i+16 && j < len(b); j++ {
			if b[j] >= 0x20 && b[j] < 0x7f {
				sb.WriteByte(b[j])
			} else {
				sb.WriteByte('.')
			}
		}
		sb.WriteString("|\n")
	}
	return sb.String()
}
