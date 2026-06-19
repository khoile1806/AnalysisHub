package logger

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/gin-gonic/gin"
	"gopkg.in/natefinch/lumberjack.v2"
)

func Setup(dir string) (cleanup func()) {
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

	if dir == "" {
		handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level})
		slog.SetDefault(slog.New(handler))
		return func() {}
	}

	if err := os.MkdirAll(dir, 0o755); err != nil {
		handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level})
		slog.SetDefault(slog.New(handler))
		slog.Warn("cannot create log dir, falling back to stdout", "dir", dir, "error", err)
		return func() {}
	}

	appLog := &lumberjack.Logger{
		Filename:   filepath.Join(dir, "app.log"),
		MaxSize:    100, // MB
		MaxBackups: 10,
		MaxAge:     30, // days
		Compress:   true,
	}

	accessLog := &lumberjack.Logger{
		Filename:   filepath.Join(dir, "access.log"),
		MaxSize:    100,
		MaxBackups: 10,
		MaxAge:     30,
		Compress:   true,
	}

	appWriter := io.MultiWriter(os.Stdout, appLog)
	accessWriter := io.MultiWriter(os.Stdout, accessLog)

	handler := slog.NewJSONHandler(appWriter, &slog.HandlerOptions{Level: level})
	// Use SetDefault so global slog functions write to our JSON handler
	slog.SetDefault(slog.New(handler))

	gin.DefaultWriter = accessWriter
	gin.DefaultErrorWriter = appWriter

	slog.Info("logging configured", "dir", dir, "level", level.String())

	return func() {
		_ = appLog.Close()
		_ = accessLog.Close()
	}
}
