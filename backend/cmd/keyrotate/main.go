// Command keyrotate re-encrypts stored secrets from an OLD AES key to a NEW one.
//
// Rotating AES_ENCRYPTION_KEY without this leaves every encrypted value
// undecryptable (the app would fail to use AI providers). Run this OFFLINE while
// the server is stopped:
//
//	POSTGRES_DSN='host=... user=... dbname=... port=5432 sslmode=disable' \
//	AES_OLD_KEY=<current 32-char key> AES_NEW_KEY=<new 32-char key> \
//	go run ./cmd/keyrotate            # add -commit to actually write
//
// Without -commit it runs a dry-run (decrypts with the old key to verify, but
// does not write). Currently rotates AI provider API keys; extend the models
// slice as other encrypted fields are added.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	"github.com/analysishub/backend/internal/crypto"
	"github.com/analysishub/backend/internal/models"
)

func main() {
	commit := flag.Bool("commit", false, "write the re-encrypted values (default: dry-run)")
	flag.Parse()

	dsn := os.Getenv("POSTGRES_DSN")
	oldKey := os.Getenv("AES_OLD_KEY")
	newKey := os.Getenv("AES_NEW_KEY")
	if dsn == "" || oldKey == "" || newKey == "" {
		log.Fatal("POSTGRES_DSN, AES_OLD_KEY and AES_NEW_KEY are all required")
	}
	if len(newKey) != 32 {
		log.Fatalf("AES_NEW_KEY must be exactly 32 bytes (got %d)", len(newKey))
	}

	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatalf("open db: %v", err)
	}

	var providers []models.AIProvider
	if err := db.Find(&providers).Error; err != nil {
		log.Fatalf("load providers: %v", err)
	}

	rotated, skipped := 0, 0
	for i := range providers {
		p := &providers[i]
		if p.APIKey == "" {
			continue
		}
		plain, derr := crypto.Decrypt(p.APIKey, oldKey)
		if derr != nil {
			log.Printf("SKIP provider %s (%s): decrypt with old key failed: %v", p.ID, p.Name, derr)
			skipped++
			continue
		}
		enc, eerr := crypto.Encrypt(plain, newKey)
		if eerr != nil {
			log.Printf("SKIP provider %s (%s): re-encrypt failed: %v", p.ID, p.Name, eerr)
			skipped++
			continue
		}
		if *commit {
			if uerr := db.Model(p).Update("api_key", enc).Error; uerr != nil {
				log.Printf("SKIP provider %s (%s): update failed: %v", p.ID, p.Name, uerr)
				skipped++
				continue
			}
		}
		rotated++
	}

	mode := "DRY-RUN (no changes written)"
	if *commit {
		mode = "COMMITTED"
	}
	fmt.Printf("keyrotate %s: %d provider key(s) rotated, %d skipped\n", mode, rotated, skipped)
	if !*commit && rotated > 0 {
		fmt.Println("re-run with -commit to persist.")
	}
}
