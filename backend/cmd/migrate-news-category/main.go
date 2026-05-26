// Migration tool: rename news category slug `vnexpress` → `world-news`
// in data/news.json, preserving article history.
//
// Run once after deploying the world-news category rename. Idempotent:
// re-running on an already-migrated file is a no-op.
//
// Usage:
//
//	go run ./cmd/migrate-news-category
//	go run ./cmd/migrate-news-category --file=path/to/news.json
//	go run ./cmd/migrate-news-category --dry-run
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"
)

type article struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Link        string   `json:"link"`
	Description string   `json:"description"`
	Author      string   `json:"author,omitempty"`
	Published   string   `json:"published"`
	Source      string   `json:"source"`
	Category    string   `json:"category"`
	Tags        []string `json:"tags,omitempty"`
	FetchedAt   string   `json:"fetched_at"`
	ImageURL    string   `json:"image_url,omitempty"`
}

func main() {
	file := flag.String("file", "data/news.json", "path to news.json")
	dryRun := flag.Bool("dry-run", false, "preview changes without writing")
	from := flag.String("from", "vnexpress", "old category slug")
	to := flag.String("to", "world-news", "new category slug")
	flag.Parse()

	abs, _ := filepath.Abs(*file)
	log.Printf("[migrate] target file: %s", abs)
	log.Printf("[migrate] rename: %q → %q (dry-run=%v)", *from, *to, *dryRun)

	raw, err := os.ReadFile(*file)
	if err != nil {
		log.Fatalf("[migrate] read error: %v", err)
	}

	var arts []article
	if err := json.Unmarshal(raw, &arts); err != nil {
		log.Fatalf("[migrate] parse error: %v", err)
	}
	log.Printf("[migrate] loaded %d articles", len(arts))

	changed := 0
	for i := range arts {
		if arts[i].Category == *from {
			arts[i].Category = *to
			changed++
		}
	}
	log.Printf("[migrate] %d articles will be renamed", changed)

	if changed == 0 {
		log.Println("[migrate] nothing to do — file already migrated or empty")
		return
	}

	if *dryRun {
		log.Println("[migrate] dry-run: no file changes written")
		return
	}

	// Safety: write backup with timestamp before overwriting.
	backup := *file + ".bak." + time.Now().UTC().Format("20060102-150405")
	if err := os.WriteFile(backup, raw, 0644); err != nil {
		log.Fatalf("[migrate] backup write error: %v", err)
	}
	log.Printf("[migrate] backup written: %s", backup)

	out, err := json.MarshalIndent(arts, "", "  ")
	if err != nil {
		log.Fatalf("[migrate] marshal error: %v", err)
	}
	if err := os.WriteFile(*file, out, 0644); err != nil {
		log.Fatalf("[migrate] write error: %v", err)
	}
	fmt.Printf("[migrate] done: %d articles updated, original backed up at %s\n", changed, backup)
}
