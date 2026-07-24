package ai

import (
	"strings"
	"testing"
)

func TestEndpointHint(t *testing.T) {
	cases := []struct {
		name    string
		baseURL string
		model   string
		want    string // substring that must appear; "" = no hint at all
	}{
		{
			// The reported failure: a DeepSeek provider saved without a Base URL,
			// so the request went to OpenAI and came back "model_not_found".
			name:    "deepseek model against the OpenAI default",
			baseURL: "https://api.openai.com/v1", model: "deepseek-chat",
			want: "api.deepseek.com",
		},
		{
			name:    "deepseek model against DeepSeek is fine",
			baseURL: "https://api.deepseek.com/v1", model: "deepseek-chat",
			want: "",
		},
		{
			name:    "gateways legitimately serve other vendors' models",
			baseURL: "https://openrouter.ai/api/v1", model: "deepseek-chat",
			want: "",
		},
		{
			name:    "a local runtime is a gateway too",
			baseURL: "http://localhost:11434/v1", model: "qwen2.5-coder",
			want: "",
		},
		{
			name:    "qwen against OpenAI",
			baseURL: "https://api.openai.com/v1", model: "qwen-max",
			want: "dashscope",
		},
		{
			name:    "claude on the OpenAI-compatible client is a wrong provider type",
			baseURL: "https://api.openai.com/v1", model: "claude-sonnet-4",
			want: "provider type to Anthropic",
		},
		{
			name:    "gemini on the OpenAI-compatible client is a wrong provider type",
			baseURL: "https://api.openai.com/v1", model: "gemini-2.0-flash",
			want: "provider type to Google",
		},
		{
			name:    "a real OpenAI model gets no hint",
			baseURL: "https://api.openai.com/v1", model: "gpt-4o-mini",
			want: "",
		},
		{
			// Guessing wrong would be worse than staying quiet.
			name:    "an unrecognised model gets no hint",
			baseURL: "https://api.openai.com/v1", model: "my-private-model-v3",
			want: "",
		},
		{
			name:    "empty model gets no hint",
			baseURL: "https://api.openai.com/v1", model: "",
			want: "",
		},
	}

	for _, c := range cases {
		got := endpointHint(c.baseURL, c.model)
		if c.want == "" {
			if got != "" {
				t.Errorf("%s: expected no hint, got %q", c.name, got)
			}
			continue
		}
		if !strings.Contains(strings.ToLower(got), strings.ToLower(c.want)) {
			t.Errorf("%s: hint %q does not mention %q", c.name, got, c.want)
		}
	}
}

func TestHostOf(t *testing.T) {
	if got := hostOf("https://api.deepseek.com/v1"); got != "api.deepseek.com" {
		t.Errorf("hostOf = %q", got)
	}
	if got := hostOf("http://localhost:11434/v1"); got != "localhost:11434" {
		t.Errorf("hostOf = %q", got)
	}
}
