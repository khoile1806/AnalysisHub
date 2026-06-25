// Package notify fans alert messages out to optional external channels — an
// outbound webhook and/or a Telegram chat. It is intentionally tiny and
// dependency-free: every Send is best-effort and never blocks the caller's
// critical path (failures are swallowed). It is shared by the canary-token hit
// alerts and can be reused by OSINT watches.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Notifier delivers short alert messages to whichever channels are configured.
// A zero/empty Notifier is valid and simply delivers nowhere (Enabled == false).
type Notifier struct {
	webhookURL string
	tgToken    string
	tgChat     string
	client     *http.Client
}

// New builds a Notifier from explicit channel settings. Any empty field
// disables that channel.
func New(webhookURL, telegramToken, telegramChat string) *Notifier {
	return &Notifier{
		webhookURL: strings.TrimSpace(webhookURL),
		tgToken:    strings.TrimSpace(telegramToken),
		tgChat:     strings.TrimSpace(telegramChat),
		client:     &http.Client{Timeout: 10 * time.Second},
	}
}

// Enabled reports whether at least one delivery channel is configured.
func (n *Notifier) Enabled() bool {
	if n == nil {
		return false
	}
	return n.webhookURL != "" || (n.tgToken != "" && n.tgChat != "")
}

// Send delivers the alert to every configured channel, best-effort. It returns
// no error: a notification failure must never break the action that raised it.
func (n *Notifier) Send(ctx context.Context, title, body string) {
	if !n.Enabled() {
		return
	}
	if n.webhookURL != "" {
		n.sendWebhook(ctx, title, body)
	}
	if n.tgToken != "" && n.tgChat != "" {
		n.sendTelegram(ctx, title, body)
	}
}

func (n *Notifier) sendWebhook(ctx context.Context, title, body string) {
	payload, err := json.Marshal(map[string]string{
		"title": title,
		"text":  body,
		// "text" + "content" cover the common Slack/Discord/generic shapes.
		"content": title + "\n" + body,
	})
	if err != nil {
		return
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.webhookURL, bytes.NewReader(payload))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := n.client.Do(req)
	if err != nil {
		return
	}
	_ = resp.Body.Close()
}

func (n *Notifier) sendTelegram(ctx context.Context, title, body string) {
	endpoint := "https://api.telegram.org/bot" + n.tgToken + "/sendMessage"
	form := url.Values{}
	form.Set("chat_id", n.tgChat)
	form.Set("text", title+"\n"+body)
	form.Set("disable_web_page_preview", "true")
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := n.client.Do(req)
	if err != nil {
		return
	}
	_ = resp.Body.Close()
}
