package vulnscan

import (
	"context"
	"fmt"
	"log"
	"os/exec"
	"time"

	"github.com/analysishub/backend/internal/config"
)

// templatesUpdateInterval is how often the bundled nuclei templates are refreshed
// so the scanner keeps detecting newly-published CVEs without rebuilding the image.
const templatesUpdateInterval = 24 * time.Hour

// StartAutoUpdate launches a background worker that keeps nuclei's templates
// current: it runs `nuclei -update-templates` on startup (after a short delay so
// it doesn't compete with boot) and then daily. Best-effort and routed through
// the configured egress proxy so the update transits Tor like every other fetch.
// A no-op when disabled or nuclei isn't installed.
func StartAutoUpdate(cfg *config.Config) {
	if cfg == nil || !cfg.VulnScanAutoUpdate {
		return
	}
	if _, err := exec.LookPath("nuclei"); err != nil {
		return
	}
	go func() {
		time.Sleep(30 * time.Second) // let the server finish booting first
		updateNucleiTemplates(cfg)
		t := time.NewTicker(templatesUpdateInterval)
		defer t.Stop()
		for range t.C {
			updateNucleiTemplates(cfg)
		}
	}()
}

// updateNucleiTemplates runs one template refresh into the bundled directory.
func updateNucleiTemplates(cfg *config.Config) {
	bin, err := exec.LookPath("nuclei")
	if err != nil {
		return
	}
	dir := "/app/nuclei-templates"
	if cfg != nil && cfg.VulnScanNucleiTemplates != "" {
		dir = cfg.VulnScanNucleiTemplates
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin,
		"-update-templates", "-update-template-dir", dir,
		"-disable-update-check", "-silent")
	cmd.Env = proxyEnv(updaterProxy(cfg))
	if out, err := cmd.CombinedOutput(); err != nil {
		log.Printf("[vulnscan] nuclei template update failed: %v (%s)", err, trimTail(out, 200))
		return
	}
	log.Printf("[vulnscan] nuclei templates updated in %s", dir)
}

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
