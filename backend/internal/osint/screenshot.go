package osint

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// screenshot.go — on-demand "web triage": a headless-browser screenshot of a host
// plus its security-header and TLS grade. It shells out to a headless Chromium
// (added to the runtime image), matching how the vuln-scan engine drives its
// external tools, so the Go backend gains no browser dependency. Capture is
// best-effort: if no Chromium is on PATH the grades still return and the caller
// sees why the image is missing.

const (
	// maxShotBytes caps a returned PNG so a runaway render can't bloat the response.
	maxShotBytes = 6 << 20
	// shotTimeout bounds one headless render.
	shotTimeout = 45 * time.Second
)

var (
	errNoChromium = errors.New("no headless Chromium found on PATH (screenshot unavailable)")
	shotTitleRe   = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
)

// WebTriageResult is the combined visual + posture triage of a single web host.
type WebTriageResult struct {
	URL            string   `json:"url"`
	Status         int      `json:"status,omitempty"`
	Title          string   `json:"title,omitempty"`
	Server         string   `json:"server,omitempty"`
	HeaderGrade    string   `json:"header_grade,omitempty"`
	MissingHeaders []string `json:"missing_headers,omitempty"`
	TLSGrade       string   `json:"tls_grade,omitempty"`
	TLSDetail      string   `json:"tls_detail,omitempty"`
	ScreenshotB64  string   `json:"screenshot_b64,omitempty"`
	ScreenshotErr  string   `json:"screenshot_error,omitempty"`
}

// WebTriage fetches the host's web root (HTTPS first), grades its headers/TLS,
// pulls the page title, and captures a headless screenshot of the reachable URL.
func WebTriage(ctx context.Context, host string) (*WebTriageResult, error) {
	host = normalizeHost(host)
	if host == "" {
		return nil, errors.New("empty host")
	}

	resp, usedTLS, err := fetchRoot(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("web root not reachable over HTTP(S)")
	}
	defer resp.Body.Close()

	scheme := "http://"
	if usedTLS {
		scheme = "https://"
	}
	url := scheme + host + "/"

	res := &WebTriageResult{URL: url, Status: resp.StatusCode}
	res.Server = strings.TrimSpace(resp.Header.Get("Server"))
	res.HeaderGrade, res.MissingHeaders = gradeSecurityHeaders(resp.Header)
	if usedTLS && resp.TLS != nil {
		res.TLSGrade, res.TLSDetail = gradeTLS(resp.TLS)
	}
	if body, _ := io.ReadAll(io.LimitReader(resp.Body, 256<<10)); len(body) > 0 {
		res.Title = extractTitle(body)
	}

	if shot, serr := CaptureWebScreenshot(ctx, url); serr != nil {
		res.ScreenshotErr = serr.Error()
	} else {
		res.ScreenshotB64 = base64.StdEncoding.EncodeToString(shot)
	}
	return res, nil
}

// CaptureWebScreenshot renders a URL to a PNG using a headless Chromium and
// returns the image bytes. Returns errNoChromium when no browser is installed.
func CaptureWebScreenshot(ctx context.Context, rawURL string) ([]byte, error) {
	bin := chromiumBinary()
	if bin == "" {
		return nil, errNoChromium
	}
	dir, err := os.MkdirTemp("", "ah-shot-")
	if err != nil {
		return nil, fmt.Errorf("temp dir: %w", err)
	}
	defer os.RemoveAll(dir)
	out := filepath.Join(dir, "shot.png")

	cctx, cancel := context.WithTimeout(ctx, shotTimeout)
	defer cancel()

	// --no-sandbox is required to run headless Chromium as an unprivileged user in
	// a container; --disable-dev-shm-usage avoids the small default /dev/shm.
	args := []string{
		"--headless=new", "--disable-gpu", "--no-sandbox", "--disable-dev-shm-usage",
		"--hide-scrollbars", "--disable-extensions", "--disable-background-networking",
		"--force-color-profile=srgb", "--window-size=1366,900",
		"--virtual-time-budget=8000", "--screenshot=" + out, rawURL,
	}
	cmd := exec.CommandContext(cctx, bin, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("render failed: %v", shotFirstLine(stderr.String(), err))
	}

	data, err := os.ReadFile(out)
	if err != nil || len(data) == 0 {
		return nil, fmt.Errorf("render produced no image")
	}
	if len(data) > maxShotBytes {
		return nil, fmt.Errorf("screenshot exceeds size cap")
	}
	return data, nil
}

// chromiumBinary locates a usable headless-browser binary.
func chromiumBinary() string {
	for _, name := range []string{
		"chromium-browser", "chromium", "chromium-headless-shell",
		"headless-shell", "google-chrome", "google-chrome-stable", "chrome",
	} {
		if p, err := exec.LookPath(name); err == nil {
			return p
		}
	}
	return ""
}

// normalizeHost strips any scheme/path/trailing dot so a pasted URL still works.
func normalizeHost(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	if i := strings.Index(h, "://"); i >= 0 {
		h = h[i+3:]
	}
	if i := strings.IndexAny(h, "/?#"); i >= 0 {
		h = h[:i]
	}
	return strings.TrimSuffix(h, ".")
}

// extractTitle pulls the <title> text from an HTML body, collapsed to one line.
func extractTitle(body []byte) string {
	m := shotTitleRe.FindSubmatch(body)
	if m == nil {
		return ""
	}
	t := strings.Join(strings.Fields(string(m[1])), " ")
	if len(t) > 200 {
		t = t[:200]
	}
	return t
}

func shotFirstLine(s string, fallback error) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return fallback.Error()
	}
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return s
}
