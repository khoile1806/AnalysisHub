package osint

import "encoding/binary"

// exifgps.go — a self-contained JPEG EXIF GPS extractor (no external deps, works
// offline). A photo a target posts often embeds the EXACT coordinates where it
// was taken in its EXIF GPS tags; this is the single most precise location an
// OSINT investigation can recover. ParseImageGPS pulls that fix out of a raw
// JPEG byte slice. It reads only the small EXIF/TIFF metadata block, never
// decodes pixels, so it is cheap and safe on attacker-supplied images.

// ParseImageGPS returns the decimal lat/lon stored in a JPEG's EXIF GPS IFD.
// ok is false when the image is not a JPEG, carries no EXIF, or has no GPS fix.
func ParseImageGPS(data []byte) (lat, lon float64, ok bool) {
	tiff, found := exifSegment(data)
	if !found {
		return 0, 0, false
	}
	return parseTIFFGPS(tiff)
}

// exifSegment walks JPEG markers and returns the TIFF block inside the APP1
// "Exif" segment (the bytes after the "Exif\0\0" header).
func exifSegment(data []byte) ([]byte, bool) {
	if len(data) < 4 || data[0] != 0xFF || data[1] != 0xD8 { // SOI
		return nil, false
	}
	i := 2
	for i+4 <= len(data) {
		if data[i] != 0xFF {
			return nil, false
		}
		marker := data[i+1]
		// SOS (start of scan) / EOI — no metadata beyond here.
		if marker == 0xDA || marker == 0xD9 {
			return nil, false
		}
		segLen := int(binary.BigEndian.Uint16(data[i+2 : i+4]))
		if segLen < 2 || i+2+segLen > len(data) {
			return nil, false
		}
		payload := data[i+4 : i+2+segLen]
		if marker == 0xE1 && len(payload) >= 6 && string(payload[:6]) == "Exif\x00\x00" {
			return payload[6:], true
		}
		i += 2 + segLen
	}
	return nil, false
}

type ifdEntry struct {
	typ    uint16
	count  uint32
	valOff uint32 // raw 4-byte value/offset field, decoded as a number
	raw    []byte // the 4 raw bytes of the value field (for inline ASCII/SHORT)
}

// parseTIFFGPS reads the TIFF header, locates the GPS IFD and decodes lat/lon.
func parseTIFFGPS(tiff []byte) (lat, lon float64, ok bool) {
	if len(tiff) < 8 {
		return 0, 0, false
	}
	var order binary.ByteOrder
	switch string(tiff[0:2]) {
	case "II":
		order = binary.LittleEndian
	case "MM":
		order = binary.BigEndian
	default:
		return 0, 0, false
	}
	if order.Uint16(tiff[2:4]) != 42 {
		return 0, 0, false
	}
	ifd0Off := int(order.Uint32(tiff[4:8]))

	ifd0, okr := readIFD(tiff, order, ifd0Off)
	if !okr {
		return 0, 0, false
	}
	gpsPtr, okg := ifd0[0x8825] // GPS Info IFD pointer
	if !okg {
		return 0, 0, false
	}
	gps, okr := readIFD(tiff, order, int(gpsPtr.valOff))
	if !okr {
		return 0, 0, false
	}

	latDMS, ok1 := readRationals(tiff, order, gps[0x0002], 3)
	lonDMS, ok2 := readRationals(tiff, order, gps[0x0004], 3)
	if !ok1 || !ok2 {
		return 0, 0, false
	}
	lat = dmsToDecimal(latDMS)
	lon = dmsToDecimal(lonDMS)

	if ref := asciiRef(gps[0x0001]); ref == "S" {
		lat = -lat
	}
	if ref := asciiRef(gps[0x0003]); ref == "W" {
		lon = -lon
	}
	if !validCoord(lat, lon) {
		return 0, 0, false
	}
	return lat, lon, true
}

// readIFD parses an Image File Directory at off into a tag→entry map.
func readIFD(tiff []byte, order binary.ByteOrder, off int) (map[uint16]ifdEntry, bool) {
	if off < 0 || off+2 > len(tiff) {
		return nil, false
	}
	n := int(order.Uint16(tiff[off : off+2]))
	entries := make(map[uint16]ifdEntry, n)
	p := off + 2
	for i := 0; i < n; i++ {
		if p+12 > len(tiff) {
			break
		}
		tag := order.Uint16(tiff[p : p+2])
		typ := order.Uint16(tiff[p+2 : p+4])
		count := order.Uint32(tiff[p+4 : p+8])
		raw := append([]byte(nil), tiff[p+8:p+12]...)
		entries[tag] = ifdEntry{typ: typ, count: count, valOff: order.Uint32(tiff[p+8 : p+12]), raw: raw}
		p += 12
	}
	return entries, true
}

// readRationals reads count RATIONAL (num/den) values pointed to by e.
func readRationals(tiff []byte, order binary.ByteOrder, e ifdEntry, count int) ([]float64, bool) {
	if e.count < uint32(count) {
		return nil, false
	}
	off := int(e.valOff) // RATIONALs are 8 bytes each, always out-of-line for count≥1
	if off < 0 || off+count*8 > len(tiff) {
		return nil, false
	}
	out := make([]float64, count)
	for i := 0; i < count; i++ {
		num := order.Uint32(tiff[off+i*8 : off+i*8+4])
		den := order.Uint32(tiff[off+i*8+4 : off+i*8+8])
		if den == 0 {
			out[i] = 0
			continue
		}
		out[i] = float64(num) / float64(den)
	}
	return out, true
}

// asciiRef returns the first ASCII char of an inline 1-char ref tag (N/S/E/W).
func asciiRef(e ifdEntry) string {
	if len(e.raw) == 0 || e.raw[0] == 0 {
		return ""
	}
	return string(e.raw[:1])
}

// dmsToDecimal converts [degrees, minutes, seconds] to signed decimal degrees.
func dmsToDecimal(dms []float64) float64 {
	if len(dms) < 3 {
		return 0
	}
	return dms[0] + dms[1]/60 + dms[2]/3600
}
