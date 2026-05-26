package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/joho/godotenv"
)

// Config holds all agent configuration values.
type Config struct {
	// ServerURL is the base HTTP(S) URL of the ForensicHub server (no trailing slash).
	// Example: http://localhost:8080
	ServerURL string

	// AgentToken is the authentication token used for WebSocket and download requests.
	AgentToken string

	// AgentName is a human-readable name for this agent instance.
	// Defaults to the system hostname if not set.
	AgentName string

	// WorkDir is the local directory used to store downloaded tools and job outputs.
	// Defaults to <OS temp dir>/forensichub.
	WorkDir string
}

// Load reads configuration from environment variables, falling back to a
// forensichub-agent.conf file located in the same directory as the running binary.
//
// Environment variables always take precedence over values in the conf file.
//
// Required keys: SERVER_URL, AGENT_TOKEN
// Optional keys:  AGENT_NAME, WORK_DIR
func Load() (*Config, error) {
	// Attempt to load the conf file. godotenv.Load only sets variables that are
	// NOT already present in the environment, so real env vars win.
	confPath := confFilePath()
	if confPath != "" {
		// Use Overload=false behaviour: godotenv.Load skips keys already set.
		// We parse the file manually into a map and set only missing keys so
		// that actual environment variables always take precedence.
		if err := loadConfFilePreserveEnv(confPath); err != nil && !os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "warn: could not read conf file %s: %v\n", confPath, err)
		}
	}

	cfg := &Config{
		ServerURL:  strings.TrimRight(getEnv("SERVER_URL", ""), "/"),
		AgentToken: getEnv("AGENT_TOKEN", ""),
		AgentName:  getEnv("AGENT_NAME", ""),
		WorkDir:    getEnv("WORK_DIR", ""),
	}

	// Validate required fields.
	if cfg.ServerURL == "" {
		return nil, fmt.Errorf("config: SERVER_URL is required (set via env or forensichub-agent.conf)")
	}
	if cfg.AgentToken == "" {
		return nil, fmt.Errorf("config: AGENT_TOKEN is required (set via env or forensichub-agent.conf)")
	}

	// Apply defaults for optional fields.
	if cfg.AgentName == "" {
		hostname, err := os.Hostname()
		if err != nil {
			hostname = "unknown-host"
		}
		cfg.AgentName = hostname
	}

	if cfg.WorkDir == "" {
		if home, err := os.UserHomeDir(); err == nil {
			cfg.WorkDir = filepath.Join(home, "Desktop", "ForensicHub_Tools")
		} else {
			cfg.WorkDir = filepath.Join(os.TempDir(), "forensichub")
		}
	}

	return cfg, nil
}

// confFilePath returns the path to the conf file next to the running binary.
// Returns "" if os.Executable() fails.
func confFilePath() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	return filepath.Join(filepath.Dir(exe), "forensichub-agent.conf")
}

// loadConfFilePreserveEnv uses godotenv to parse the KEY=VALUE conf file and
// injects values into the process environment for any key that is not already
// set. This ensures real environment variables always win over the file.
func loadConfFilePreserveEnv(path string) error {
	envMap, err := godotenv.Read(path)
	if err != nil {
		return err
	}

	for key, val := range envMap {
		if _, exists := os.LookupEnv(key); !exists {
			os.Setenv(key, val)
		}
	}
	return nil
}

// getEnv returns the value of the named environment variable or fallback.
func getEnv(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return fallback
}
