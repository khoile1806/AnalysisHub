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

// googleClient handles Google Gemini's streamGenerateContent API.
type googleClient struct {
	apiKey string
	model  string
}

func (c *googleClient) StreamChat(ctx context.Context, msgs []Message, opts Options, out chan<- string) (Usage, error) {
	var usage Usage

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

	// Prepend system instruction into the first user turn — works across all
	// Gemini model versions without the systemInstruction field.
	if systemText != "" && len(contents) > 0 {
		contents[0].Parts[0].Text = systemText + "\n\n" + contents[0].Parts[0].Text
	}

	reqMap := map[string]interface{}{
		"contents": contents,
	}
	if opts.JSON {
		reqMap["generationConfig"] = map[string]interface{}{
			"responseMimeType": "application/json",
		}
	}

	model := c.model
	if model == "" {
		model = "gemini-1.5-flash"
	}

	bodyBytes, err := json.Marshal(reqMap)
	if err != nil {
		return usage, fmt.Errorf("marshal request: %w", err)
	}

	url := fmt.Sprintf(
		"https://generativelanguage.googleapis.com/v1beta/models/%s:streamGenerateContent?alt=sse&key=%s",
		model, c.apiKey,
	)
	resp, err := postSSE(ctx, url, map[string]string{
		"Content-Type": "application/json",
	}, bodyBytes)
	if err != nil {
		return usage, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return usage, fmt.Errorf("google returned %d: %s", resp.StatusCode, truncate(string(body), 300))
	}

	// Google SSE: data: {"candidates":[{"content":{"parts":[{"text":"..."}]}}],"usageMetadata":{...}}
	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
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
			UsageMetadata *struct {
				PromptTokenCount     int `json:"promptTokenCount"`
				CandidatesTokenCount int `json:"candidatesTokenCount"`
			} `json:"usageMetadata"`
		}
		if err := json.Unmarshal([]byte(payload), &chunk); err != nil {
			continue
		}
		if chunk.UsageMetadata != nil {
			usage.InputTokens = chunk.UsageMetadata.PromptTokenCount
			usage.OutputTokens = chunk.UsageMetadata.CandidatesTokenCount
		}
		if len(chunk.Candidates) > 0 && len(chunk.Candidates[0].Content.Parts) > 0 {
			token := chunk.Candidates[0].Content.Parts[0].Text
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

func (c *googleClient) TestConnection(ctx context.Context) error {
	ch := make(chan string, 8)
	errCh := make(chan error, 1)
	go func() {
		_, err := c.StreamChat(ctx, []Message{{Role: "user", Content: "Hi"}}, Options{}, ch)
		close(ch)
		errCh <- err
	}()
	for range ch {
	}
	return <-errCh
}
