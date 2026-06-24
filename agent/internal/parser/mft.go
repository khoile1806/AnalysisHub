package parser

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type MFTResult struct {
	FilePath  string    `json:"file_path"`
	Size      int64     `json:"size"`
	IsDir     bool      `json:"is_dir"`
	ModTime   time.Time `json:"mod_time"`
	IsDeleted bool      `json:"is_deleted"`
}

// ParseMFT scans the raw disk. In this implementation, it performs a simulated
// fast deep scan of C:\Windows\System32 as a proof of concept for the architecture.
// A full implementation would use github.com/Velocidex/velociraptor/parser/ntfs
func ParseMFT() ([]MFTResult, error) {
	// Require Admin test: Try to open a restricted directory
	f, err := os.Open(`C:\Windows\System32\config`)
	if err != nil {
		return nil, fmt.Errorf("raw disk access requires Administrator privileges: %v", err)
	}
	f.Close()

	var results []MFTResult
	count := 0
	
	// Simulate finding files from MFT
	filepath.Walk(`C:\Windows\System32`, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if count > 500 {
			return filepath.SkipDir
		}
		
		// Randomly simulate a "deleted" file finding for demonstration
		isDeleted := (count % 42 == 0)

		results = append(results, MFTResult{
			FilePath:  path,
			Size:      info.Size(),
			IsDir:     info.IsDir(),
			ModTime:   info.ModTime(),
			IsDeleted: isDeleted,
		})
		count++
		return nil
	})

	return results, nil
}
