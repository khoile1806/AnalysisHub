package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/forensichub/agent/internal/config"
	"github.com/forensichub/agent/internal/ws"
)

func main() {
	// Configure the standard logger to include timestamps.
	log.SetFlags(log.LstdFlags | log.Lmsgprefix)
	log.SetPrefix("[forensichub-agent] ")
	log.SetOutput(os.Stdout)

	// ------------------------------------------------------------------
	// Load configuration.
	// ------------------------------------------------------------------
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "fatal: %v\n", err)
		os.Exit(1)
	}

	// Ensure the working directory exists before the agent starts accepting
	// jobs; create it (and all parents) with standard permissions.
	if err := os.MkdirAll(cfg.WorkDir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "fatal: create workdir %s: %v\n", cfg.WorkDir, err)
		os.Exit(1)
	}

	// Tee logs to WORK_DIR/agent.log so operators can diagnose issues even
	// when the agent runs detached (Windows service, background shell).
	logPath := filepath.Join(cfg.WorkDir, "agent.log")
	if logFile, ferr := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644); ferr == nil {
		log.SetOutput(io.MultiWriter(os.Stdout, logFile))
	} else {
		fmt.Fprintf(os.Stderr, "warn: cannot open log file %s: %v\n", logPath, ferr)
	}

	log.Printf("starting — server=%s name=%s workdir=%s log=%s",
		cfg.ServerURL, cfg.AgentName, cfg.WorkDir, logPath)

	// ------------------------------------------------------------------
	// Set up a context that is cancelled on SIGINT or SIGTERM so every
	// component can shut down gracefully.
	// ------------------------------------------------------------------
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// ------------------------------------------------------------------
	// Start the WebSocket client. Run() blocks until ctx is cancelled.
	// ------------------------------------------------------------------
	client := ws.NewClient(cfg)
	client.Run(ctx)

	log.Println("agent stopped")
}
