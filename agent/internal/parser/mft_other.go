//go:build !windows

package parser

import (
	"fmt"
	"time"
)

// MFTResult mirrors the Windows definition so callers (and JSON consumers)
// compile on every platform. The scan itself is Windows-only.
type MFTResult struct {
	FilePath   string    `json:"file_path"`
	Name       string    `json:"name"`
	Ext        string    `json:"ext"`
	Size       int64     `json:"size"`
	IsDir      bool      `json:"is_dir"`
	Created    time.Time `json:"created"`
	Modified   time.Time `json:"mod_time"`
	Accessed   time.Time `json:"accessed"`
	Attributes []string  `json:"attributes"`
	MD5        string    `json:"md5,omitempty"`
	SHA1       string    `json:"sha1,omitempty"`
	SHA256     string    `json:"sha256,omitempty"`
	Hashed     bool      `json:"hashed"`
	Suspicious []string  `json:"suspicious,omitempty"`
}

// ParseMFT is only implemented on Windows (NTFS timestamps / attributes).
func ParseMFT(target string) ([]MFTResult, error) {
	return nil, fmt.Errorf("file-system forensic scan is only supported on Windows agents")
}
