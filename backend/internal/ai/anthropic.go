package ai

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// anthropicClient handles Anthropic's native Messages API with streaming.
type anthropicClient struct {
	apiKey string
	model  string
	maxTok int
}

func (c *anthropicClient) StreamChat(ctx context.Context, msgs []Message, opts Options, out chan<- string) (Usage, error) {
	var usage Usage

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
		return usage, fmt.Errorf("no user/assistant messages provided")
	}

	maxTok := opts.MaxTokens
	if maxTok == 0 {
		maxTok = c.maxTok
	}
	if maxTok == 0 {
		// Forensic reports are long; 4096 truncated them. Streaming means a high
		// ceiling carries no timeout risk.
		maxTok = 8192
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
		return usage, fmt.Errorf("marshal request: %w", err)
	}

	resp, err := postSSE(ctx, "https://api.anthropic.com/v1/messages", map[string]string{
		"Content-Type":      "application/json",
		"x-api-key":         c.apiKey,
		"anthropic-version": "2023-06-01",
	}, bodyBytes)
	if err != nil {
		return usage, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return usage, fmt.Errorf("anthropic returned %d: %s", resp.StatusCode, truncate(string(body), 300))
	}

	// Anthropic SSE format:
	// event: message_start    data: {"message":{"usage":{"input_tokens":N,"cache_read_input_tokens":M}}}
	// event: content_block_delta  data: {"delta":{"type":"text_delta","text":"..."}}
	// event: message_delta    data: {"usage":{"output_tokens":K}}
	var eventType string
	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "event: ") {
			eventType = strings.TrimPrefix(line, "event: ")
			continue
		}
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		payload := strings.TrimPrefix(line, "data: ")

		switch eventType {
		case "content_block_delta":
			var chunk struct {
				Delta struct {
					Text string `json:"text"`
				} `json:"delta"`
			}
			if err := json.Unmarshal([]byte(payload), &chunk); err == nil && chunk.Delta.Text != "" {
				select {
				case out <- chunk.Delta.Text:
				case <-ctx.Done():
					return usage, ctx.Err()
				}
			}
		case "message_start":
			var chunk struct {
				Message struct {
					Usage struct {
						InputTokens     int `json:"input_tokens"`
						CacheReadTokens int `json:"cache_read_input_tokens"`
					} `json:"usage"`
				} `json:"message"`
			}
			if err := json.Unmarshal([]byte(payload), &chunk); err == nil {
				usage.InputTokens = chunk.Message.Usage.InputTokens
				usage.CacheReadTokens = chunk.Message.Usage.CacheReadTokens
			}
		case "message_delta":
			var chunk struct {
				Usage struct {
					OutputTokens int `json:"output_tokens"`
				} `json:"usage"`
			}
			if err := json.Unmarshal([]byte(payload), &chunk); err == nil && chunk.Usage.OutputTokens > 0 {
				usage.OutputTokens = chunk.Usage.OutputTokens
			}
		}
	}
	return usage, scanner.Err()
}

func (c *anthropicClient) TestConnection(ctx context.Context) error {
	ch := make(chan string, 8)
	errCh := make(chan error, 1)
	go func() {
		_, err := c.StreamChat(ctx, []Message{{Role: "user", Content: "Hi"}}, Options{MaxTokens: 5}, ch)
		close(ch)
		errCh <- err
	}()
	for range ch {
	}
	return <-errCh
}
