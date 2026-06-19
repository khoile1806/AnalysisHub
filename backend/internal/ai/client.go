// Package ai provides a unified interface for streaming chat completion
// across multiple AI provider APIs (OpenAI-compatible, Anthropic, Google Gemini).
package ai

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/forensichub/backend/internal/models"
)

// Message is a single chat turn.
type Message struct {
	Role    string // "system" | "user" | "assistant"
	Content string
}

// Options controls generation parameters.
type Options struct {
	MaxTokens   int     // 0 = provider default
	Temperature float64 // 0 = provider default
	// JSON requests structured JSON output where the provider supports a JSON
	// mode (OpenAI json_object, Gemini responseMimeType). Anthropic has no
	// schema-less JSON mode, so callers should still instruct JSON in the prompt
	// and parse defensively with ExtractJSON.
	JSON bool
}

// Usage reports token consumption for one completion. Fields are best-effort:
// a provider that does not surface a value leaves it at zero.
type Usage struct {
	InputTokens     int
	OutputTokens    int
	CacheReadTokens int
}

// Total returns input+output tokens (cache reads are a subset of input).
func (u Usage) Total() int { return u.InputTokens + u.OutputTokens }

// Client streams chat completions from an AI provider.
// Tokens are sent to out as they arrive; the channel is closed by the caller.
// The returned Usage is populated once the stream completes (zero on error or
// when the provider does not report usage). A non-nil error means the stream
// could not be initiated or was interrupted.
type Client interface {
	StreamChat(ctx context.Context, msgs []Message, opts Options, out chan<- string) (Usage, error)
	// TestConnection sends a minimal request to verify the credentials work.
	TestConnection(ctx context.Context) error
}

// NewClient returns a Client implementation appropriate for provider.ProviderType.
// decryptedKey is the already-decrypted API key.
func NewClient(provider *models.AIProvider, decryptedKey string) (Client, error) {
	switch provider.ProviderType {
	case "openai":
		baseURL := provider.BaseURL
		if baseURL == "" {
			baseURL = "https://api.openai.com/v1"
		}
		return &openAIClient{
			baseURL: baseURL,
			apiKey:  decryptedKey,
			model:   provider.Model,
			maxTok:  provider.MaxTokens,
		}, nil
	case "anthropic":
		return &anthropicClient{
			apiKey: decryptedKey,
			model:  provider.Model,
			maxTok: provider.MaxTokens,
		}, nil
	case "google":
		return &googleClient{
			apiKey: decryptedKey,
			model:  provider.Model,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported provider type: %q", provider.ProviderType)
	}
}

// streamTimeout is generous because forensic reports can stream for minutes at
// high max_tokens; the old 5-minute cap truncated long outputs.
const streamTimeout = 10 * time.Minute

// postSSE issues the POST that opens an SSE stream, retrying transient failures
// (network errors, HTTP 429, and 5xx) with exponential backoff. Retry applies
// only to opening the connection — once the caller starts reading the body, a
// mid-stream drop surfaces as a scanner error. The returned response is the
// caller's to close; it may carry a non-retryable 4xx the caller must inspect.
func postSSE(ctx context.Context, url string, headers map[string]string, body []byte) (*http.Response, error) {
	var lastErr error
	backoff := 500 * time.Millisecond
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
			backoff *= 2
		}
		req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
		if err != nil {
			return nil, fmt.Errorf("build request: %w", err)
		}
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		client := &http.Client{Timeout: streamTimeout}
		resp, err := client.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("send request: %w", err)
			continue
		}
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
			b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
			resp.Body.Close()
			lastErr = fmt.Errorf("provider returned %d: %s", resp.StatusCode, truncate(string(b), 300))
			continue
		}
		return resp, nil
	}
	return nil, lastErr
}

// ExtractJSON pulls the first JSON object or array out of a model response,
// tolerating markdown code fences and surrounding prose. Returns the input
// trimmed if no JSON delimiters are found.
func ExtractJSON(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.Index(s, "```"); i >= 0 {
		s = s[i+3:]
		s = strings.TrimPrefix(s, "json")
		s = strings.TrimPrefix(s, "JSON")
		if j := strings.LastIndex(s, "```"); j >= 0 {
			s = s[:j]
		}
		s = strings.TrimSpace(s)
	}
	start := strings.IndexAny(s, "{[")
	if start < 0 {
		return s
	}
	closer := byte('}')
	if s[start] == '[' {
		closer = ']'
	}
	end := strings.LastIndexByte(s, closer)
	if end < start {
		return s
	}
	return s[start : end+1]
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
