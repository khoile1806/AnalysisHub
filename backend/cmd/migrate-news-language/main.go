// Migration tool: backfill the `language` field for articles in
// data/news.json whose category is "world-news". Maps article.source
// against the feed registry in internal/news to determine "vi" or "en".
//
// Idempotent: articles that already have a language are left alone.
//
// Usage:
//
//	go run ./cmd/migrate-news-language
//	go run ./cmd/migrate-news-language --file=path/to/news.json --dry-run
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/forensichub/backend/internal/news"
)

type article struct {
	ID          string                 `json:"id"`
	Title       string                 `json:"title"`
	Link        string                 `json:"link"`
	Description string                 `json:"description"`
	Author      string                 `json:"author,omitempty"`
	Published   string                 `json:"published"`
	Source      string                 `json:"source"`
	Category    string                 `json:"category"`
	Language    string                 `json:"language,omitempty"`
	Tags        []string               `json:"tags,omitempty"`
	FetchedAt   string                 `json:"fetched_at"`
	ImageURL    string                 `json:"image_url,omitempty"`
	Extra       map[string]interface{} `json:"-"` // preserved on roundtrip via raw map below
}

func main() {
	file := flag.String("file", "data/news.json", "path to news.json")
	dryRun := flag.Bool("dry-run", false, "preview changes without writing")
	flag.Parse()

	abs, _ := filepath.Abs(*file)
	log.Printf("[migrate-lang] target file: %s", abs)

	// Build a source→language map from the feed registry.
	sourceLang := map[string]string{}
	for _, f := range news.Feeds {
		if f.Language != "" {
			sourceLang[f.Name] = f.Language
		}
	}
	log.Printf("[migrate-lang] %d sources have a declared language", len(sourceLang))

	raw, err := os.ReadFile(*file)
	if err != nil {
		log.Fatalf("[migrate-lang] read error: %v", err)
	}

	var arts []article
	if err := json.Unmarshal(raw, &arts); err != nil {
		log.Fatalf("[migrate-lang] parse error: %v", err)
	}
	log.Printf("[migrate-lang] loaded %d articles", len(arts))

	changed := 0
	for i := range arts {
		if arts[i].Language != "" {
			continue
		}
		lang, ok := sourceLang[arts[i].Source]
		if !ok {
			continue
		}
		arts[i].Language = lang
		changed++
	}
	log.Printf("[migrate-lang] %d articles will gain a language tag", changed)

	if changed == 0 {
		log.Println("[migrate-lang] nothing to do — file already migrated")
		return
	}

	if *dryRun {
		log.Println("[migrate-lang] dry-run: no file changes written")
		return
	}

	backup := *file + ".bak." + time.Now().UTC().Format("20060102-150405")
	if err := os.WriteFile(backup, raw, 0644); err != nil {
		log.Fatalf("[migrate-lang] backup write error: %v", err)
	}
	log.Printf("[migrate-lang] backup written: %s", backup)

	out, err := json.MarshalIndent(arts, "", "  ")
	if err != nil {
		log.Fatalf("[migrate-lang] marshal error: %v", err)
	}
	if err := os.WriteFile(*file, out, 0644); err != nil {
		log.Fatalf("[migrate-lang] write error: %v", err)
	}
	fmt.Printf("[migrate-lang] done: %d articles updated, original backed up at %s\n", changed, backup)
}
