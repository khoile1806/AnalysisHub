package osint

import (
	"encoding/json"
	"fmt"
	"math"
	"strings"

	"github.com/forensichub/backend/internal/models"
)

// geo.go — location intelligence. Every collector that learns *where* a target
// is (IP geolocation, image EXIF GPS, phone region, WHOIS address) stamps a
// standard geo payload onto its finding's Data. The location-aggregation
// endpoint then reads them all across the investigation graph and picks the most
// precise, best-corroborated estimate — so an analyst gets one answer ("the
// target is here") with coordinates, not a dozen scattered hints.

// GeoPoint is a single located observation about a target.
type GeoPoint struct {
	Lat        float64 `json:"lat"`
	Lon        float64 `json:"lon"`
	Place      string  `json:"place,omitempty"`  // human label, e.g. "Hanoi, Vietnam"
	Precision  string  `json:"precision"`        // exact | city | region | country
	Source     string  `json:"source"`           // exif | geoip | phone | whois | profile
	Confidence string  `json:"confidence"`       // high | medium | low
	Target     string  `json:"target,omitempty"` // the entity this point describes
	SourceURL  string  `json:"source_url,omitempty"`
}

// geoData is the shape persisted in OsintFinding.Data for any located finding.
// It carries lat/lon plus precision/source so the aggregator can rank it.
type geoData struct {
	Lat       float64 `json:"lat"`
	Lon       float64 `json:"lon"`
	Place     string  `json:"place,omitempty"`
	Precision string  `json:"precision,omitempty"`
	GeoSource string  `json:"geo_source,omitempty"`
}

// geoPayload builds the Data JSON for a located finding.
func geoPayload(lat, lon float64, place, precision, source string) string {
	b, _ := json.Marshal(geoData{Lat: lat, Lon: lon, Place: place, Precision: precision, GeoSource: source})
	return string(b)
}

// validCoord rejects the null-island / out-of-range coordinates that broken
// lookups emit, so they never pollute the location estimate.
func validCoord(lat, lon float64) bool {
	if lat == 0 && lon == 0 {
		return false
	}
	return lat >= -90 && lat <= 90 && lon >= -180 && lon <= 180
}

// parseGeoData extracts a GeoPoint from a finding's Data JSON, returning ok=false
// when the finding carries no usable coordinate.
func parseGeoData(data string) (geoData, bool) {
	if strings.TrimSpace(data) == "" {
		return geoData{}, false
	}
	var g geoData
	if json.Unmarshal([]byte(data), &g) != nil {
		return geoData{}, false
	}
	if !validCoord(g.Lat, g.Lon) {
		return geoData{}, false
	}
	return g, true
}

// NewPhotoGeoFinding builds an exact-precision geolocation finding from a photo's
// EXIF GPS coordinates (analyst-uploaded). Caller sets ScanID before persisting.
func NewPhotoGeoFinding(lat, lon float64) models.OsintFinding {
	maps := fmt.Sprintf("https://www.google.com/maps?q=%.6f,%.6f", lat, lon)
	f := newFinding("photo_exif", "geolocation", "GPS location from uploaded photo (EXIF)", fmt.Sprintf("%.6f, %.6f", lat, lon))
	f.Data = geoPayload(lat, lon, "Photo EXIF GPS", "exact", "exif")
	f.Confidence = "high"
	f.SourceURL = maps
	f.VerifyNote = "exact coordinates extracted from an uploaded photo's EXIF GPS metadata"
	return f
}

// GeoPointFromData builds a GeoPoint from a finding's stored geo Data payload.
// Exported for the API layer's location-aggregation endpoint. ok is false when
// the finding carries no usable coordinate.
func GeoPointFromData(data string) (GeoPoint, bool) {
	g, ok := parseGeoData(data)
	if !ok {
		return GeoPoint{}, false
	}
	conf := "medium"
	return GeoPoint{
		Lat: g.Lat, Lon: g.Lon, Place: g.Place,
		Precision: g.Precision, Source: g.GeoSource, Confidence: conf,
	}, true
}

// precisionRank orders precision from coarse to fine so the aggregator prefers an
// exact GPS fix over a city-level geoIP guess over a country-level phone hint.
func precisionRank(p string) int {
	switch strings.ToLower(p) {
	case "exact":
		return 3
	case "city":
		return 2
	case "region":
		return 1
	case "country":
		return 0
	default:
		return 0
	}
}

func confidenceRank(c string) int {
	switch strings.ToLower(c) {
	case "high":
		return 2
	case "medium":
		return 1
	default:
		return 0
	}
}

// haversineKm returns the great-circle distance between two points in km.
func haversineKm(lat1, lon1, lat2, lon2 float64) float64 {
	const r = 6371.0
	dLat := (lat2 - lat1) * math.Pi / 180
	dLon := (lon2 - lon1) * math.Pi / 180
	a := math.Sin(dLat/2)*math.Sin(dLat/2) +
		math.Cos(lat1*math.Pi/180)*math.Cos(lat2*math.Pi/180)*math.Sin(dLon/2)*math.Sin(dLon/2)
	return r * 2 * math.Atan2(math.Sqrt(a), math.Sqrt(1-a))
}

// AggregateLocations picks the single best location estimate from all geo points
// gathered across an investigation graph. It prefers higher precision, then
// higher confidence; ties are broken by corroboration — a point that other
// independent points cluster near (within ~50 km) is preferred, because
// agreement across sources is the strongest accuracy signal. Returns the best
// point and whether one was found.
func AggregateLocations(points []GeoPoint) (GeoPoint, bool) {
	if len(points) == 0 {
		return GeoPoint{}, false
	}

	// corroboration count: how many OTHER points (different source) agree with p.
	corrob := make([]int, len(points))
	for i := range points {
		for j := range points {
			if i == j || points[i].Source == points[j].Source {
				continue
			}
			if haversineKm(points[i].Lat, points[i].Lon, points[j].Lat, points[j].Lon) <= 50 {
				corrob[i]++
			}
		}
	}

	best, bestIdx := points[0], 0
	for i := 1; i < len(points); i++ {
		if betterGeo(points[i], corrob[i], best, corrob[bestIdx]) {
			best, bestIdx = points[i], i
		}
	}
	return best, true
}

// betterGeo reports whether candidate (with cc corroborators) beats current.
func betterGeo(cand GeoPoint, cc int, cur GeoPoint, curC int) bool {
	if pr := precisionRank(cand.Precision) - precisionRank(cur.Precision); pr != 0 {
		return pr > 0
	}
	if cf := confidenceRank(cand.Confidence) - confidenceRank(cur.Confidence); cf != 0 {
		return cf > 0
	}
	return cc > curC
}
