package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"log/slog"
	"strconv"
	"strings"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"gopkg.in/natefinch/lumberjack.v2"

	"github.com/forensichub/agent/internal/config"
	"github.com/forensichub/agent/internal/executor"
	"github.com/forensichub/agent/internal/ws"
	"github.com/forensichub/agent/internal/parser"
)

func main() {
	// Check for elevated subprocess commands first
	if len(os.Args) >= 3 && os.Args[1] == "scan-mft" {
		outPath := os.Args[2]
		target := ""
		if len(os.Args) >= 4 {
			target = os.Args[3]
		}
		res, err := parser.ParseMFT(target)
		if err != nil {
			os.WriteFile(outPath, []byte(fmt.Sprintf(`{"error":"%v"}`, err)), 0644)
			os.Exit(1)
		}
		b, _ := json.Marshal(res)
		os.WriteFile(outPath, b, 0644)
		os.Exit(0)
	}
	if len(os.Args) >= 3 && os.Args[1] == "scan-prefetch" {
		outPath := os.Args[2]
		res, err := parser.ParsePrefetch()
		if err != nil {
			os.WriteFile(outPath, []byte(fmt.Sprintf(`{"error":"%v"}`, err)), 0644)
			os.Exit(1)
		}
		b, _ := json.Marshal(res)
		os.WriteFile(outPath, b, 0644)
		os.Exit(0)
	}
	if len(os.Args) >= 3 && os.Args[1] == "scan-processes" {
		outPath := os.Args[2]
		res, err := parser.ScanProcesses()
		if err != nil {
			os.WriteFile(outPath, []byte(fmt.Sprintf(`{"error":"%v"}`, err)), 0644)
			os.Exit(1)
		}
		b, _ := json.Marshal(res)
		os.WriteFile(outPath, b, 0644)
		os.Exit(0)
	}
	if len(os.Args) >= 3 && os.Args[1] == "scan-autoruns" {
		outPath := os.Args[2]
		res, err := parser.ScanAutoruns()
		if err != nil {
			os.WriteFile(outPath, []byte(fmt.Sprintf(`{"error":"%v"}`, err)), 0644)
			os.Exit(1)
		}
		b, _ := json.Marshal(res)
		os.WriteFile(outPath, b, 0644)
		os.Exit(0)
	}
	if len(os.Args) >= 3 && os.Args[1] == "scan-dlls" {
		outPath := os.Args[2]
		res, err := parser.ScanLoadedDLLs()
		if err != nil {
			os.WriteFile(outPath, []byte(fmt.Sprintf(`{"error":"%v"}`, err)), 0644)
			os.Exit(1)
		}
		b, _ := json.Marshal(res)
		os.WriteFile(outPath, b, 0644)
		os.Exit(0)
	}
	if len(os.Args) >= 3 && os.Args[1] == "scan-shimcache" {
		outPath := os.Args[2]
		res, err := parser.ScanShimcache()
		if err != nil {
			os.WriteFile(outPath, []byte(fmt.Sprintf(`{"error":"%v"}`, err)), 0644)
			os.Exit(1)
		}
		b, _ := json.Marshal(res)
		os.WriteFile(outPath, b, 0644)
		os.Exit(0)
	}
	if len(os.Args) >= 3 && os.Args[1] == "kill" {
		pid, _ := strconv.Atoi(os.Args[2])
		if err := executor.KillProcess(pid); err != nil {
			os.Exit(1)
		}
		os.Exit(0)
	}

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
