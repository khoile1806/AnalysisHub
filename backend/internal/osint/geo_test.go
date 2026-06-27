package osint

import "testing"

func TestGeoPointFromData(t *testing.T) {
	d := geoPayload(21.0, 105.0, "Hanoi, Vietnam", "city", "geoip")
	gp, ok := GeoPointFromData(d)
	if !ok {
		t.Fatal("expected geo payload to parse")
	}
	if gp.Lat != 21.0 || gp.Lon != 105.0 || gp.Precision != "city" || gp.Source != "geoip" {
		t.Fatalf("unexpected geo point: %+v", gp)
	}
	// Null island / blank → rejected.
	if _, ok := GeoPointFromData(geoPayload(0, 0, "", "city", "geoip")); ok {
		t.Error("0,0 must be rejected")
	}
	if _, ok := GeoPointFromData(""); ok {
		t.Error("empty data must be rejected")
	}
}

func TestAggregateLocations_PrefersPrecision(t *testing.T) {
	points := []GeoPoint{
		{Lat: 21.0, Lon: 105.0, Precision: "country", Source: "phone", Confidence: "low"},
		{Lat: 21.02, Lon: 105.84, Precision: "city", Source: "geoip", Confidence: "high"},
		{Lat: 21.0285, Lon: 105.8542, Precision: "exact", Source: "exif", Confidence: "high"},
	}
	best, ok := AggregateLocations(points)
	if !ok {
		t.Fatal("expected a best location")
	}
	if best.Precision != "exact" || best.Source != "exif" {
		t.Fatalf("expected the EXIF exact fix to win, got %+v", best)
	}
}

func TestAggregateLocations_CorroborationTieBreak(t *testing.T) {
	// Two city-level fixes of equal confidence; one is corroborated by a nearby
	// independent source, the other is an outlier — the corroborated one wins.
	points := []GeoPoint{
		{Lat: 10.0, Lon: 20.0, Precision: "city", Source: "geoip", Confidence: "medium"},    // outlier
		{Lat: 48.85, Lon: 2.35, Precision: "city", Source: "profile", Confidence: "medium"}, // Paris
		{Lat: 48.86, Lon: 2.34, Precision: "country", Source: "phone", Confidence: "low"},   // near Paris (different source)
	}
	best, ok := AggregateLocations(points)
	if !ok {
		t.Fatal("expected a best location")
	}
	if best.Source != "profile" {
		t.Fatalf("expected the corroborated Paris fix to win, got %+v", best)
	}
}

func TestAggregateLocations_Empty(t *testing.T) {
	if _, ok := AggregateLocations(nil); ok {
		t.Error("no points → no best")
	}
}
