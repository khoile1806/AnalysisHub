// Package ai provides a unified interface for streaming chat completion
// across multiple AI provider APIs (OpenAI-compatible, Anthropic, Google Gemini).
package ai

import (
	"context"
	"fmt"

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
}

// Client streams chat completions from an AI provider.
// Tokens are sent to out as they arrive; the channel is closed when done.
// An error return means the stream could not be initiated or was interrupted.
type Client interface {
	StreamChat(ctx context.Context, msgs []Message, opts Options, out chan<- string) error
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
