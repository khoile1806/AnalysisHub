package ai

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// openAIClient handles OpenAI-compatible streaming APIs.
// Compatible providers: OpenAI, Groq, Together AI, Mistral, OpenRouter,
// Cerebras, SambaNova, Cloudflare AI Workers, and any other
// provider that implements the /chat/completions SSE protocol.
type openAIClient struct {
	baseURL string
	apiKey  string
	model   string
	maxTok  int
}

type openAIChatRequest struct {
	Model       string          `json:"model"`
	Messages    []openAIMessage `json:"messages"`
	Stream      bool            `json:"stream"`
	MaxTokens   int             `json:"max_tokens,omitempty"`
	Temperature float64         `json:"temperature,omitempty"`
}

type openAIMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

func (c *openAIClient) StreamChat(ctx context.Context, msgs []Message, opts Options, out chan<- string) error {
	omgs := make([]openAIMessage, len(msgs))
	for i, m := range msgs {
		omgs[i] = openAIMessage{Role: m.Role, Content: m.Content}
	}

	maxTok := opts.MaxTokens
	if maxTok == 0 {
		maxTok = c.maxTok
	}

	reqBody := openAIChatRequest{
		Model:    c.model,
		Messages: omgs,
		Stream:   true,
	}
	if maxTok > 0 {
		reqBody.MaxTokens = maxTok
	}
	if opts.Temperature > 0 {
		reqBody.Temperature = opts.Temperature
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}

	url := strings.TrimRight(c.baseURL, "/") + "/chat/completions"
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(bodyBytes))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	// OpenRouter requires a Referer header for free-tier routing.
	req.Header.Set("HTTP-Referer", "https://forensichub.local")
	req.Header.Set("X-Title", "ForensicHub")

	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("provider returned %d: %s", resp.StatusCode, truncate(string(body), 300))
	}

	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		payload := strings.TrimPrefix(line, "data: ")
		if payload == "[DONE]" {
			break
		}

		var chunk struct {
			Choices []struct {
				Delta struct {
					Content string `json:"content"`
				} `json:"delta"`
			} `json:"choices"`
		}
		if err := json.Unmarshal([]byte(payload), &chunk); err != nil {
			continue
		}
		if len(chunk.Choices) > 0 {
			token := chunk.Choices[0].Delta.Content
			if token != "" {
				select {
				case out <- token:
				case <-ctx.Done():
					return ctx.Err()
				}
			}
		}
	}
	return scanner.Err()
}

func (c *openAIClient) TestConnection(ctx context.Context) error {
	_, err := c.collectAll(ctx, []Message{{Role: "user", Content: "Hi"}}, Options{MaxTokens: 5})
	return err
}

func (c *openAIClient) collectAll(ctx context.Context, msgs []Message, opts Options) (string, error) {
	ch := make(chan string, 64)
	errCh := make(chan error, 1)
	go func() {
		errCh <- c.StreamChat(ctx, msgs, opts, ch)
		close(ch)
	}()
	var sb strings.Builder
	for tok := range ch {
		sb.WriteString(tok)
	}
	return sb.String(), <-errCh
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
