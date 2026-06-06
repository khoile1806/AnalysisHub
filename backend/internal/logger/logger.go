// Package logger initialises file-based logging for the ForensicHub backend.
// All output is tee'd to stdout so `docker logs` still works, but every log
// line is also persisted to date-stamped files under the configured log
// directory for easy offline debugging.
//
// Two files are created per calendar day (UTC):
//
//	app-YYYY-MM-DD.log    — log.Printf / log.Fatal / startup messages
//	access-YYYY-MM-DD.log — Gin HTTP access log (one line per request)
//
// Both files are opened in append mode so a server restart on the same day
// continues the existing file rather than truncating it.
package logger

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/gin-gonic/gin"
)

// Setup configures file-based logging.  Call it once at startup, before the
// Gin router is built.  The returned cleanup func flushes and closes the log
// files; call it via defer in main.
//
// If dir is empty or cannot be created, Setup falls back to stdout-only
// logging and returns a no-op cleanup so the caller never needs to branch.
func Setup(dir string) (cleanup func()) {
	if dir == "" {
		log.SetFlags(log.LstdFlags | log.Lmicroseconds)
		return func() {}
	}

	if err := os.MkdirAll(dir, 0o755); err != nil {
		log.Printf("[logger] WARNING: cannot create log dir %q: %v — falling back to stdout-only", dir, err)
		log.SetFlags(log.LstdFlags | log.Lmicroseconds)
		return func() {}
	}

	today := time.Now().UTC().Format("2006-01-02")

	appFile, err := openLogFile(dir, "app-"+today+".log")
	if err != nil {
		log.Printf("[logger] WARNING: cannot open app log: %v — falling back to stdout-only", err)
		log.SetFlags(log.LstdFlags | log.Lmicroseconds)
		return func() {}
	}

	accessFile, err := openLogFile(dir, "access-"+today+".log")
	if err != nil {
		log.Printf("[logger] WARNING: cannot open access log: %v — access log disabled", err)
		accessFile = appFile // fall back: write access log into app log
	}

	// Standard library logger → stdout + app file
	log.SetOutput(io.MultiWriter(os.Stdout, appFile))
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	// Gin access logger → stdout + access file
	gin.DefaultWriter = io.MultiWriter(os.Stdout, accessFile)
	// Gin error output (panic recovery, binding errors) → stdout + app file
	gin.DefaultErrorWriter = io.MultiWriter(os.Stderr, appFile)

	log.Printf("[logger] logging to %s  (app: app-%s.log, access: access-%s.log)", dir, today, today)

	return func() {
		appFile.Sync()    //nolint:errcheck
		accessFile.Sync() //nolint:errcheck
		appFile.Close()   //nolint:errcheck
		if accessFile != appFile {
			accessFile.Close() //nolint:errcheck
		}
	}
}

// openLogFile opens (or creates) a log file in append mode with buffered
// writes.  Returns the *os.File so the caller can sync/close it.
func openLogFile(dir, name string) (*os.File, error) {
	path := filepath.Join(dir, name)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	return f, nil
}
