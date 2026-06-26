package parser

// ShimEntry is one AppCompatCache (Shimcache) record: a binary the OS recorded
// as present/executed, with the backing file's last-modified time. Platform-
// neutral model; Windows impl in shimcache_windows.go, stub in _other.go.
type ShimEntry struct {
	Path         string   `json:"path"`
	Name         string   `json:"name"`
	LastModified string   `json:"last_modified,omitempty"`
	Suspicious   []string `json:"suspicious,omitempty"`
}
