package handlers

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"
)

// Worker heartbeats: each worker tick stamps its name here so a watchdog can spot
// a loop that has stopped ticking (stalled or wedged). Observe-only — the
// watchdog records an event/log, it does not restart the goroutine.
var (
	workerBeats   = map[string]time.Time{}
	workerBeatsMu sync.Mutex
)

// workerBeat records that the named worker just completed a tick.
func workerBeat(name string) {
	workerBeatsMu.Lock()
	workerBeats[name] = time.Now()
	workerBeatsMu.Unlock()
}

// WorkerHeartbeats returns a copy of the last-tick time per worker (for health).
func WorkerHeartbeats() map[string]time.Time {
	workerBeatsMu.Lock()
	defer workerBeatsMu.Unlock()
	out := make(map[string]time.Time, len(workerBeats))
	for k, v := range workerBeats {
		out[k] = v
	}
	return out
}

// StartWorkerWatchdog periodically checks every registered worker's heartbeat and
// records a system event when one has not ticked for staleAfter. It never
// restarts a worker (observe-only) to avoid double-running side effects.
func StartWorkerWatchdog(staleAfter time.Duration) {
	go runWorker("worker-watchdog", time.Minute, func() {
		now := time.Now()
		for name, last := range WorkerHeartbeats() {
			if name == "worker-watchdog" {
				continue
			}
			if now.Sub(last) > staleAfter {
				RecordSystemEvent("worker", "warn", name,
					"worker heartbeat stale",
					fmt.Sprintf("no tick for %s (last %s)", now.Sub(last).Round(time.Second), last.Format(time.RFC3339)))
			}
		}
	})
}

// safeLoop runs one worker-tick body with panic recovery, so a single bad tick
// (e.g. a parse error on untrusted feed/CVE data) can never kill the worker
// goroutine and silently stop the feature for the rest of the process lifetime.
func safeLoop(name string, fn func()) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[%s] PANIC recovered in worker tick: %v", name, r)
			RecordSystemEvent("worker", "error", name, "panic recovered in worker tick", fmt.Sprintf("%v", r))
		}
		workerBeat(name) // heartbeat: record a successful (or recovered) tick
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
