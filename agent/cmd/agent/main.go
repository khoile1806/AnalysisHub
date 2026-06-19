package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"log/slog"
	"strings"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"gopkg.in/natefinch/lumberjack.v2"

	"github.com/forensichub/agent/internal/config"
	"github.com/forensichub/agent/internal/ws"
)

func main() {
	// The standard logger is bridged to slog later.

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

	logLevelStr := os.Getenv("LOG_LEVEL")
	var level slog.Level
	switch strings.ToUpper(logLevelStr) {
	case "DEBUG":
		level = slog.LevelDebug
	case "WARN":
		level = slog.LevelWarn
	case "ERROR":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}

	logPath := filepath.Join(cfg.WorkDir, "agent.log")
	fileLogger := &lumberjack.Logger{
		Filename:   logPath,
		MaxSize:    50, // MB
		MaxBackups: 5,
		MaxAge:     14, // days
		Compress:   true,
	}
	defer fileLogger.Close()

	w := io.MultiWriter(os.Stdout, fileLogger)
	// Use TextHandler instead of JSON for easy reading in Notepad on endpoints.
	handler := slog.NewTextHandler(w, &slog.HandlerOptions{Level: level})
	slog.SetDefault(slog.New(handler))

	// Bridge standard log to slog
	log.SetOutput(w)
	log.SetFlags(0)

	slog.Info("starting agent", "server", cfg.ServerURL, "name", cfg.AgentName, "workdir", cfg.WorkDir, "log_path", logPath)

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

	slog.Info("agent stopped")
}
