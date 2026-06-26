package parser

// DllRec is one unique loaded module plus which processes map it in — the data
// model for the ListDLLs-style view (platform-neutral; Windows impl in
// dlls_windows.go, stub in dlls_other.go).
type DllRec struct {
	Name         string   `json:"name"`
	Path         string   `json:"path"`
	ProcessCount int      `json:"process_count"`
	Processes    []string `json:"processes"` // sample "name (pid)" loaders
	MD5          string   `json:"md5,omitempty"`
	SHA256       string   `json:"sha256,omitempty"`
	Hashed       bool     `json:"hashed"`
	Signature    string   `json:"signature,omitempty"` // Signed | Unsigned | Untrusted
	Suspicious   []string `json:"suspicious,omitempty"`
}
