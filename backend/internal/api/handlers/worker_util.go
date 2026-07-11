package handlers

import (
	"context"
	"log"
	"time"
)

// safeLoop runs one worker-tick body with panic recovery, so a single bad tick
// (e.g. a parse error on untrusted feed/CVE data) can never kill the worker
// goroutine and silently stop the feature for the rest of the process lifetime.
func safeLoop(name string, fn func()) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[%s] PANIC recovered in worker tick: %v", name, r)
		}
	}()
	fn()
}

// workerCtx is the shared lifecycle context for all background workers. It is
// cancelled on graceful shutdown so tick loops stop starting new work instead of
// leaking goroutines (and racing the DB pool close) during the drain window.
// Defaults to Background so workers still run if SetWorkerContext is never called
// (e.g. tests).
var workerCtx = context.Background()

// SetWorkerContext installs the shutdown context used by every background worker.
// Call once at startup, before the workers are started.
func SetWorkerContext(ctx context.Context) { workerCtx = ctx }

// runWorker drives fn every interval until the worker context is cancelled, with
// each tick panic-recovered. It is the standard shape for the handler-package
// background workers so shutdown and crash-safety are handled in one place.
func runWorker(name string, interval time.Duration, fn func()) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-workerCtx.Done():
			return
		case <-ticker.C:
			safeLoop(name, fn)
		}
	}
}
