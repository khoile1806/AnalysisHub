package osint

import (
	"encoding/binary"
	"math"
	"testing"
)

// buildExifJPEG synthesises a minimal little-endian JPEG carrying a GPS fix at
// (latDeg N, lonDeg E) so the parser can be tested without a real photo.
func buildExifJPEG(latDeg, lonDeg uint32) []byte {
	o := binary.LittleEndian
	tiff := make([]byte, 128)
	copy(tiff[0:2], "II")
	o.PutUint16(tiff[2:4], 42)
	o.PutUint32(tiff[4:8], 8)

	putEntry := func(off int, tag, typ uint16, count, val uint32) {
		o.PutUint16(tiff[off:off+2], tag)
		o.PutUint16(tiff[off+2:off+4], typ)
		o.PutUint32(tiff[off+4:off+8], count)
		o.PutUint32(tiff[off+8:off+12], val)
	}
	putRat := func(off int, num, den uint32) {
		o.PutUint32(tiff[off:off+4], num)
		o.PutUint32(tiff[off+4:off+8], den)
	}

	// IFD0: one entry → GPS IFD pointer at offset 26.
	o.PutUint16(tiff[8:10], 1)
	putEntry(10, 0x8825, 4, 1, 26)
	o.PutUint32(tiff[22:26], 0)

	// GPS IFD (offset 26): 4 entries; data blocks at 80 (lat) and 104 (lon).
	o.PutUint16(tiff[26:28], 4)
	putEntry(28, 0x0001, 2, 2, uint32('N')) // GPSLatitudeRef inline
	putEntry(40, 0x0002, 5, 3, 80)          // GPSLatitude → offset 80
	putEntry(52, 0x0003, 2, 2, uint32('E')) // GPSLongitudeRef inline
	putEntry(64, 0x0004, 5, 3, 104)         // GPSLongitude → offset 104
	o.PutUint32(tiff[76:80], 0)

	putRat(80, latDeg, 1)
	putRat(88, 0, 1)
	putRat(96, 0, 1)
	putRat(104, lonDeg, 1)
	putRat(112, 0, 1)
	putRat(120, 0, 1)

	segLen := 2 + 6 + len(tiff) // length field + "Exif\0\0" + TIFF
	jpeg := []byte{0xFF, 0xD8, 0xFF, 0xE1, byte(segLen >> 8), byte(segLen)}
	jpeg = append(jpeg, []byte("Exif\x00\x00")...)
	jpeg = append(jpeg, tiff...)
	jpeg = append(jpeg, 0xFF, 0xD9) // EOI
	return jpeg
}

func TestParseImageGPS_RoundTrip(t *testing.T) {
	img := buildExifJPEG(21, 105) // Hanoi-ish, N/E
	lat, lon, ok := ParseImageGPS(img)
	if !ok {
		t.Fatal("expected GPS fix to parse")
	}
	if math.Abs(lat-21.0) > 0.0001 || math.Abs(lon-105.0) > 0.0001 {
		t.Fatalf("got (%.4f,%.4f) want (21,105)", lat, lon)
	}
}

func TestParseImageGPS_NoExif(t *testing.T) {
	// A bare JPEG SOI/EOI with no APP1 → no GPS.
	if _, _, ok := ParseImageGPS([]byte{0xFF, 0xD8, 0xFF, 0xD9}); ok {
		t.Error("expected no GPS for an image without EXIF")
	}
	// Non-JPEG bytes.
	if _, _, ok := ParseImageGPS([]byte("not an image")); ok {
		t.Error("expected no GPS for non-JPEG input")
	}
}
