package handlers

import (
	"fmt"
	"io"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/analysishub/backend/internal/models"
	"github.com/analysishub/backend/internal/osint"
)

// imageGeoMaxBytes caps an uploaded image for EXIF GPS extraction.
const imageGeoMaxBytes = 25 << 20 // 25 MB (photos can be large; we only read EXIF)

// GetOsintLocation aggregates every located finding across an investigation
// graph (IP geolocation, image EXIF GPS, phone region …) and returns the single
// best coordinate estimate plus all points, so the UI can pin the target on a
// map and show "where the target is" with a confidence/precision label.
//
// GET /api/v1/osint/:id/location
func GetOsintLocation(c *gin.Context) {
	db, ok := mustGetDB(c)
	if !ok {
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid scan id"})
		return
	}
	var scan models.OsintScan
	if err := db.First(&scan, "id = ?", id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "scan not found"})
		return
	}
	root := scan.ID
	if scan.RootScanID != nil {
		root = *scan.RootScanID
	}

	var scans []models.OsintScan
	db.Where("root_scan_id = ? OR id = ?", root, root).Find(&scans)
	targetByScan := make(map[uuid.UUID]string, len(scans))
	ids := make([]uuid.UUID, 0, len(scans))
	for i := range scans {
		targetByScan[scans[i].ID] = scans[i].Target
		ids = append(ids, scans[i].ID)
	}

	var findings []models.OsintFinding
	if len(ids) > 0 {
		db.Where("scan_id IN ? AND data <> ''", ids).
			Where("category = ?", "geolocation").
			Find(&findings)
	}

	points := make([]osint.GeoPoint, 0, len(findings))
	for i := range findings {
		gp, ok := osint.GeoPointFromData(findings[i].Data)
		if !ok {
			continue
		}
		gp.Target = targetByScan[findings[i].ScanID]
		if findings[i].Confidence != "" {
			gp.Confidence = findings[i].Confidence
		}
		gp.SourceURL = findings[i].SourceURL
		points = append(points, gp)
	}

	best, found := osint.AggregateLocations(points)
	resp := gin.H{
		"points": points,
		"count":  len(points),
		"found":  found,
	}
	if found {
		resp["best"] = best
		resp["maps_url"] = mapsURL(best.Lat, best.Lon)
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": resp})
}

// ExtractImageGeo reads the EXIF GPS tags of an uploaded photo and returns the
// exact coordinates where it was taken (the most precise location an OSINT
// investigation can recover). Native EXIF parsing — no AI provider required.
//
// POST /api/v1/osint/extract-image-geo  (multipart/form-data: image=<file>)
func ExtractImageGeo(c *gin.Context) {
	fileHdr, err := c.FormFile("image")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "image file is required"})
		return
	}
	if fileHdr.Size > imageGeoMaxBytes {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "image exceeds the 25 MB limit"})
		return
	}
	f, err := fileHdr.Open()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "cannot read uploaded image"})
		return
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, imageGeoMaxBytes+1))
	if err != nil || len(raw) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "empty or unreadable image"})
		return
	}

	lat, lon, ok := osint.ParseImageGPS(raw)
	if !ok {
		c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{
			"found": false,
			"note":  "no EXIF GPS data in this image (it may have been stripped by the platform it was downloaded from)",
		}})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{
		"found":     true,
		"lat":       lat,
		"lon":       lon,
		"maps_url":  mapsURL(lat, lon),
		"precision": "exact",
		"source":    "exif",
	}})
}

func mapsURL(lat, lon float64) string {
	return fmt.Sprintf("https://www.google.com/maps?q=%.6f,%.6f", lat, lon)
}

// AddScanPhotoGeo reads the EXIF GPS of an uploaded photo and, if present,
// persists it as an exact-precision geolocation finding ON THE SCAN — so it
// appears on the scan's map, location aggregate and report. Native EXIF parsing,
// no AI; the image itself is not stored, only the coordinates.
//
// POST /api/v1/osint/:id/add-photo-geo  (multipart/form-data: image=<file>)
func AddScanPhotoGeo(c *gin.Context) {
	db, ok := mustGetDB(c)
	if !ok {
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid scan id"})
		return
	}
	var scan models.OsintScan
	if err := db.First(&scan, "id = ?", id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "scan not found"})
		return
	}

	fileHdr, err := c.FormFile("image")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "image file is required"})
		return
	}
	if fileHdr.Size > imageGeoMaxBytes {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "image exceeds the 25 MB limit"})
		return
	}
	f, err := fileHdr.Open()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "cannot read uploaded image"})
		return
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, imageGeoMaxBytes+1))
	if err != nil || len(raw) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "empty or unreadable image"})
		return
	}

	lat, lon, found := osint.ParseImageGPS(raw)
	if !found {
		c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{
			"found": false,
			"note":  "no EXIF GPS in this image (likely stripped by the platform it came from)",
		}})
		return
	}

	finding := osint.NewPhotoGeoFinding(lat, lon)
	finding.ScanID = id
	osint.PersistFindings(db, []models.OsintFinding{finding})

	c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{
		"found":    true,
		"lat":      lat,
		"lon":      lon,
		"maps_url": mapsURL(lat, lon),
	}})
}
