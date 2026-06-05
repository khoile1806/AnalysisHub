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

// anthropicClient handles Anthropic's native Messages API with streaming.
type anthropicClient struct {
	apiKey string
	model  string
	maxTok int
}

func (c *anthropicClient) StreamChat(ctx context.Context, msgs []Message, opts Options, out chan<- string) error {
	// Anthropic requires system message to be a top-level field, not in messages.
	var system string
	var anthropicMsgs []map[string]string
	for _, m := range msgs {
		if m.Role == "system" {
			system = m.Content
			continue
		}
		anthropicMsgs = append(anthropicMsgs, map[string]string{
			"role":    m.Role,
			"content": m.Content,
		})
	}
	if len(anthropicMsgs) == 0 {
		return fmt.Errorf("no user/assistant messages provided")
	}

	maxTok := opts.MaxTokens
	if maxTok == 0 {
		maxTok = c.maxTok
	}
	if maxTok == 0 {
		maxTok = 4096
	}

	reqMap := map[string]interface{}{
		"model":      c.model,
		"messages":   anthropicMsgs,
		"max_tokens": maxTok,
		"stream":     true,
	}
	if system != "" {
		reqMap["system"] = system
	}

	bodyBytes, err := json.Marshal(reqMap)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", "https://api.anthropic.com/v1/messages", bytes.NewBuffer(bodyBytes))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", c.apiKey)
	req.Header.Set("anthropic-version", "2023-06-01")

	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("anthropic returned %d: %s", resp.StatusCode, truncate(string(body), 300))
	}

	// Anthropic SSE format:
	// event: content_block_delta
	// data: {"type":"content_block_delta","delta":{"type":"text_delta","text":"..."}}
	var eventType string
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "event: ") {
			eventType = strings.TrimPrefix(line, "event: ")
			continue
		}
		if strings.HasPrefix(line, "data: ") && eventType == "content_block_delta" {
			payload := strings.TrimPrefix(line, "data: ")
			var chunk struct {
				Delta struct {
					Text string `json:"text"`
				} `json:"delta"`
			}
			if err := json.Unmarshal([]byte(payload), &chunk); err == nil && chunk.Delta.Text != "" {
				select {
				case out <- chunk.Delta.Text:
				case <-ctx.Done():
					return ctx.Err()
				}
			}
		}
	}
	return scanner.Err()
}

func (c *anthropicClient) TestConnection(ctx context.Context) error {
	ch := make(chan string, 8)
	errCh := make(chan error, 1)
	go func() {
		errCh <- c.StreamChat(ctx, []Message{{Role: "user", Content: "Hi"}}, Options{MaxTokens: 5}, ch)
		close(ch)
	}()
	for range ch {
	}
	return <-errCh
}
