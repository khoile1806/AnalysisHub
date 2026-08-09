package vulnscan

import (
	"context"
	"fmt"
	"log"
	"os/exec"

	"github.com/analysishub/backend/internal/config"
)

// UpdateNucleiTemplates refreshes the bundled nuclei templates and returns an
// error on failure. Exported for the unified updater registry.
func UpdateNucleiTemplates(ctx context.Context, cfg *config.Config) error {
	bin, err := exec.LookPath("nuclei")
	if err != nil {
		return fmt.Errorf("nuclei not installed")
	}
	dir := "/app/nuclei-templates"
	if cfg != nil && cfg.VulnScanNucleiTemplates != "" {
		dir = cfg.VulnScanNucleiTemplates
	}
	cmd := exec.CommandContext(ctx, bin,
		"-update-templates", "-update-template-dir", dir,
		"-disable-update-check", "-silent")
	cmd.Env = proxyEnv(updaterProxy(cfg))
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%v: %s", err, trimTail(out, 200))
	}
	log.Printf("[updater] nuclei templates updated in %s", dir)
	return nil
}

// UpdateCdncheck refreshes cdncheck (its CDN/WAF provider IP ranges ship with the
// binary) via `cdncheck -update`. Best-effort: in a read-only container the binary
// self-update may fail — that surfaces in the updater status rather than silently.
func UpdateCdncheck(ctx context.Context, cfg *config.Config) error {
	bin, err := exec.LookPath("cdncheck")
	if err != nil {
		return fmt.Errorf("cdncheck not installed")
	}
	cmd := exec.CommandContext(ctx, bin, "-update")
	cmd.Env = proxyEnv(updaterProxy(cfg))
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%v: %s", err, trimTail(out, 200))
	}
	return nil
}

// UpdateWpscan refreshes WPScan's local WordPress vulnerability database via
// `wpscan --update`. Best-effort — it needs network and (for full data) an API
// token at scan time, but the local DB refresh itself is token-free.
func UpdateWpscan(ctx context.Context, cfg *config.Config) error {
	bin, err := exec.LookPath("wpscan")
	if err != nil {
		return fmt.Errorf("wpscan not installed")
	}
	cmd := exec.CommandContext(ctx, bin, "--update", "--no-banner")
	cmd.Env = proxyEnv(updaterProxy(cfg))
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%v: %s", err, trimTail(out, 200))
	}
	return nil
}

// updaterProxy resolves the egress proxy for the updater (Tor-preferred), mirroring
// Engine.resolveProxy but without an engine instance.
func updaterProxy(cfg *config.Config) string {
	if cfg == nil {
		return ""
	}
	switch {
	case cfg.VulnScanProxy != "":
		return cfg.VulnScanProxy
	case cfg.TorProxy != "":
		return cfg.TorProxy
	case cfg.OutboundProxy != "":
		return cfg.OutboundProxy
	}
	return ""
}

func trimTail(b []byte, n int) string {
	s := string(b)
	if len(s) > n {
		return s[len(s)-n:]
	}
	return s
}
