package ai

import (
	"fmt"
	"net/url"
	"strings"
)

// vendorEndpoint ties a model-name prefix to the vendor that serves it.
type vendorEndpoint struct {
	vendor string
	url    string
}

// vendorEndpoints recognises model families that are NOT served by OpenAI. The
// OpenAI-compatible client defaults its Base URL to api.openai.com when the
// field is left blank, so configuring, say, DeepSeek by entering only the model
// name and the API key sends the request to OpenAI — which answers with a bare
// "model_not_found" that says nothing about the real problem.
var vendorEndpoints = []struct {
	prefix string
	vendorEndpoint
}{
	{"deepseek", vendorEndpoint{"DeepSeek", "https://api.deepseek.com/v1"}},
	{"qwen", vendorEndpoint{"Alibaba DashScope", "https://dashscope-intl.aliyuncs.com/compatible-mode/v1"}},
	{"moonshot", vendorEndpoint{"Moonshot", "https://api.moonshot.cn/v1"}},
	{"kimi", vendorEndpoint{"Moonshot", "https://api.moonshot.cn/v1"}},
	{"glm", vendorEndpoint{"Zhipu AI", "https://open.bigmodel.cn/api/paas/v4"}},
	{"grok", vendorEndpoint{"xAI", "https://api.x.ai/v1"}},
	{"mistral", vendorEndpoint{"Mistral", "https://api.mistral.ai/v1"}},
	{"codestral", vendorEndpoint{"Mistral", "https://api.mistral.ai/v1"}},
	{"command-", vendorEndpoint{"Cohere", "https://api.cohere.ai/compatibility/v1"}},
}

// endpointHint returns an actionable suffix when the model name belongs to a
// vendor other than the host the request was sent to. It returns "" whenever the
// two are consistent, or when the model is not recognised — a wrong guess here
// would be worse than no hint at all.
func endpointHint(baseURL, model string) string {
	m := strings.ToLower(strings.TrimSpace(model))
	if m == "" {
		return ""
	}
	host := hostOf(baseURL)

	// Anthropic and Google have their own provider types in this app, so a
	// model from either reaching the OpenAI-compatible client is a misconfigured
	// provider type rather than a missing Base URL.
	switch {
	case strings.HasPrefix(m, "claude"):
		if !strings.Contains(host, "anthropic") && !isThirdPartyGateway(host) {
			return fmt.Sprintf(" — %q is an Anthropic model but this provider is configured as OpenAI-compatible and the request went to %s; set the provider type to Anthropic", model, host)
		}
		return ""
	case strings.HasPrefix(m, "gemini"):
		if !strings.Contains(host, "googleapis") && !isThirdPartyGateway(host) {
			return fmt.Sprintf(" — %q is a Google model but this provider is configured as OpenAI-compatible and the request went to %s; set the provider type to Google", model, host)
		}
		return ""
	}

	for _, v := range vendorEndpoints {
		if !strings.HasPrefix(m, v.prefix) {
			continue
		}
		// A gateway (OpenRouter, Together, Groq, a local Ollama …) legitimately
		// serves other vendors' models, so only complain when the request went
		// somewhere that clearly is not the vendor and is not a gateway.
		if strings.Contains(host, v.prefix) || isThirdPartyGateway(host) {
			return ""
		}
		return fmt.Sprintf(" — %q is a %s model but the request went to %s; set this provider's Base URL to %s",
			model, v.vendor, host, v.url)
	}
	return ""
}

// isThirdPartyGateway reports hosts that aggregate models from many vendors, for
// which a foreign-looking model name is expected and correct.
func isThirdPartyGateway(host string) bool {
	for _, g := range []string{
		"openrouter", "together", "groq", "fireworks", "deepinfra", "novita",
		"siliconflow", "cerebras", "sambanova", "hyperbolic", "nebius", "lepton",
		"localhost", "127.0.0.1", "ollama", "lmstudio", "vllm", "litellm", "azure",
	} {
		if strings.Contains(host, g) {
			return true
		}
	}
	return false
}

func hostOf(raw string) string {
	if raw == "" {
		return "api.openai.com (the default when Base URL is left empty)"
	}
	if u, err := url.Parse(raw); err == nil && u.Host != "" {
		return u.Host
	}
	return raw
}
