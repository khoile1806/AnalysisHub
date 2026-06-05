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

// googleClient handles Google Gemini's streamGenerateContent API.
type googleClient struct {
	apiKey string
	model  string
}

func (c *googleClient) StreamChat(ctx context.Context, msgs []Message, opts Options, out chan<- string) error {
	// Gemini uses "contents" with "parts". System messages become a leading user turn.
	type part struct {
		Text string `json:"text"`
	}
	type content struct {
		Role  string `json:"role"` // "user" | "model"
		Parts []part `json:"parts"`
	}

	var contents []content
	var systemText string

	for _, m := range msgs {
		switch m.Role {
		case "system":
			systemText = m.Content
		case "user":
			contents = append(contents, content{Role: "user", Parts: []part{{Text: m.Content}}})
		case "assistant":
			contents = append(contents, content{Role: "model", Parts: []part{{Text: m.Content}}})
		}
	}

	// Prepend system instruction as a user turn (Gemini 1.5+ supports systemInstruction field,
	// but the simple prepend approach works across all model versions).
	if systemText != "" && len(contents) > 0 {
		merged := systemText + "\n\n" + contents[0].Parts[0].Text
		contents[0].Parts[0].Text = merged
	}

	reqMap := map[string]interface{}{
		"contents": contents,
	}

	model := c.model
	if model == "" {
		model = "gemini-1.5-flash"
	}

	bodyBytes, err := json.Marshal(reqMap)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}

	url := fmt.Sprintf(
		"https://generativelanguage.googleapis.com/v1beta/models/%s:streamGenerateContent?alt=sse&key=%s",
		model, c.apiKey,
	)
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(bodyBytes))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("google returned %d: %s", resp.StatusCode, truncate(string(body), 300))
	}

	// Google SSE: data: {"candidates":[{"content":{"parts":[{"text":"..."}]}}]}
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		payload := strings.TrimPrefix(line, "data: ")

		var chunk struct {
			Candidates []struct {
				Content struct {
					Parts []struct {
						Text string `json:"text"`
					} `json:"parts"`
				} `json:"content"`
			} `json:"candidates"`
		}
		if err := json.Unmarshal([]byte(payload), &chunk); err != nil {
			continue
		}
		if len(chunk.Candidates) > 0 && len(chunk.Candidates[0].Content.Parts) > 0 {
			token := chunk.Candidates[0].Content.Parts[0].Text
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

func (c *googleClient) TestConnection(ctx context.Context) error {
	ch := make(chan string, 8)
	errCh := make(chan error, 1)
	go func() {
		errCh <- c.StreamChat(ctx, []Message{{Role: "user", Content: "Hi"}}, Options{}, ch)
		close(ch)
	}()
	for range ch {
	}
	return <-errCh
}
