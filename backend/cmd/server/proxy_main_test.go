package main

import (
	"os"
	"strings"
	"testing"

	"github.com/analysishub/backend/internal/config"
)

// snapshotProxyEnv saves and restores the proxy-related env vars around a test.
func snapshotProxyEnv(t *testing.T) {
	t.Helper()
	keys := []string{"HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "NO_PROXY", "no_proxy"}
	saved := map[string]string{}
	for _, k := range keys {
		saved[k] = os.Getenv(k)
		os.Unsetenv(k)
	}
	t.Cleanup(func() {
		for k, v := range saved {
			if v == "" {
				os.Unsetenv(k)
			} else {
				os.Setenv(k, v)
			}
		}
	})
}

func TestApplyOutboundProxy_SetsEnv(t *testing.T) {
	snapshotProxyEnv(t)

	applyOutboundProxy(&config.Config{
		OutboundProxy:   "http://10.0.0.5:8080",
		OutboundNoProxy: "10.0.0.0/8,.corp.local",
	})

	for _, k := range []string{"HTTP_PROXY", "https_proxy"} {
		if got := os.Getenv(k); got != "http://10.0.0.5:8080" {
			t.Errorf("%s = %q, want http://10.0.0.5:8080", k, got)
		}
	}
	np := os.Getenv("NO_PROXY")
	for _, must := range []string{"localhost", "127.0.0.1", "10.0.0.0/8", ".corp.local"} {
		if !strings.Contains(np, must) {
			t.Errorf("NO_PROXY %q missing %q", np, must)
		}
	}
}

func TestApplyOutboundProxy_EmptyIsNoOp(t *testing.T) {
	snapshotProxyEnv(t)

	applyOutboundProxy(&config.Config{OutboundProxy: ""})

	if got := os.Getenv("HTTP_PROXY"); got != "" {
		t.Errorf("HTTP_PROXY should stay empty, got %q", got)
	}
	if got := os.Getenv("NO_PROXY"); got != "" {
		t.Errorf("NO_PROXY should stay empty, got %q", got)
	}
}
