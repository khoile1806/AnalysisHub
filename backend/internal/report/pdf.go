package report

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"time"
)

// pdf.go — optional native PDF rendering. To keep the backend dependency-free
// (no bundled headless Chrome), PDF generation is delegated to an external
// HTML→PDF service (e.g. Gotenberg's chromium route) configured via the
// PDF_RENDERER_URL env var. When unset, callers fall back to the HTML report and
// the browser's own print-to-PDF — so this is a pure enhancement, never a hard
// dependency.

// PDFEnabled reports whether an external PDF renderer is configured.
func PDFEnabled() bool { return os.Getenv("PDF_RENDERER_URL") != "" }

// RenderPDF converts a full HTML document to PDF via the configured renderer.
// It posts the HTML as multipart "files=index.html", matching Gotenberg's
// /forms/chromium/convert/html endpoint (the de-facto standard). Returns an
// error (so the caller can fall back to HTML) when no renderer is configured or
// the render fails.
func RenderPDF(ctx context.Context, html string) ([]byte, error) {
	endpoint := os.Getenv("PDF_RENDERER_URL")
	if endpoint == "" {
		return nil, fmt.Errorf("no PDF renderer configured (set PDF_RENDERER_URL)")
	}

	var body bytes.Buffer
	w := multipart.NewWriter(&body)
	part, err := w.CreateFormFile("files", "index.html")
	if err != nil {
		return nil, err
	}
	if _, err := io.WriteString(part, html); err != nil {
		return nil, err
	}
	_ = w.Close()

	rctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(rctx, http.MethodPost, endpoint, &body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", w.FormDataContentType())

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("PDF renderer request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("PDF renderer returned HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 64<<20)) // 64 MB cap
}
