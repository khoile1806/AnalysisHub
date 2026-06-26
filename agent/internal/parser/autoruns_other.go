//go:build !windows

package parser

import "fmt"

// AutorunEntry mirrors the Windows definition so JSON consumers / callers
// compile on every platform. Autoruns enumeration is Windows-only.
type AutorunEntry struct {
	Category   string   `json:"category"`
	Name       string   `json:"name"`
	Location   string   `json:"location"`
	Command    string   `json:"command"`
	ImagePath  string   `json:"image_path"`
	User       string   `json:"user,omitempty"`
	Enabled    bool     `json:"enabled"`
	MD5        string   `json:"md5,omitempty"`
	SHA256     string   `json:"sha256,omitempty"`
	Hashed     bool     `json:"hashed"`
	Signature  string   `json:"signature,omitempty"`
	Suspicious []string `json:"suspicious,omitempty"`
}

// ScanAutoruns is only implemented on Windows.
func ScanAutoruns() ([]AutorunEntry, error) {
	return nil, fmt.Errorf("autoruns enumeration is only supported on Windows agents")
}
