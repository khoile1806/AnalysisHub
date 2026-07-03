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

// openAIClient handles OpenAI-compatible streaming APIs.
// Compatible providers: OpenAI, Groq, Together AI, Mistral, OpenRouter,
// Cerebras, SambaNova, Cloudflare AI Workers, Ollama, and any other
// provider that implements the /chat/completions SSE protocol.
type openAIClient struct {
	baseURL string
	apiKey  string
	model   string
	maxTok  int
}

type openAIMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

func (c *openAIClient) StreamChat(ctx context.Context, msgs []Message, opts Options, out chan<- string) (Usage, error) {
	var usage Usage

	omgs := make([]openAIMessage, len(msgs))
	for i, m := range msgs {
		omgs[i] = openAIMessage{Role: m.Role, Content: m.Content}
	}

	maxTok := opts.MaxTokens
	if maxTok == 0 {
		maxTok = c.maxTok
	}

	reqBody := map[string]interface{}{
		"model":    c.model,
		"messages": omgs,
		"stream":   true,
		// Ask the provider to emit a final usage chunk; ignored by providers that
		// don't support it.
		"stream_options": map[string]interface{}{"include_usage": true},
	}
	if maxTok > 0 {
		reqBody["max_tokens"] = maxTok
	}
	if opts.Temperature > 0 {
		reqBody["temperature"] = opts.Temperature
	}
	if opts.JSON {
		reqBody["response_format"] = map[string]string{"type": "json_object"}
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return usage, fmt.Errorf("marshal request: %w", err)
	}

	url := strings.TrimRight(c.baseURL, "/") + "/chat/completions"
	resp, err := postSSE(ctx, url, map[string]string{
		"Content-Type":  "application/json",
		"Authorization": "Bearer " + c.apiKey,
		// OpenRouter requires these for free-tier routing; harmless elsewhere.
		"HTTP-Referer": "https://analysishub.local",
		"X-Title":      "AnalysisHub",
	}, bodyBytes)
	if err != nil {
		return usage, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return usage, fmt.Errorf("provider returned %d: %s", resp.StatusCode, truncate(string(body), 300))
	}

	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
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
			Usage *struct {
				PromptTokens     int `json:"prompt_tokens"`
				CompletionTokens int `json:"completion_tokens"`
			} `json:"usage"`
		}
		if err := json.Unmarshal([]byte(payload), &chunk); err != nil {
			continue
		}
		if chunk.Usage != nil {
			usage.InputTokens = chunk.Usage.PromptTokens
			usage.OutputTokens = chunk.Usage.CompletionTokens
		}
		if len(chunk.Choices) > 0 {
			token := chunk.Choices[0].Delta.Content
			if token != "" {
				select {
				case out <- token:
				case <-ctx.Done():
					return usage, ctx.Err()
				}
			}
		}
	}
	return usage, scanner.Err()
}

func (c *openAIClient) TestConnection(ctx context.Context) error {
	ch := make(chan string, 64)
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
