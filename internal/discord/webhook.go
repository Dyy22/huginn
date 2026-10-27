package discord

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/bwmarrin/discordgo"
)

type WebhookSender struct {
	webhookURL string
	httpClient *http.Client
}

func NewWebhookSender(webhookURL string) *WebhookSender {
	return &WebhookSender{
		webhookURL: strings.TrimSpace(webhookURL),
		httpClient: &http.Client{Timeout: 15 * time.Second},
	}
}

func (w *WebhookSender) Enabled() bool {
	return w.webhookURL != "" &&
		strings.HasPrefix(w.webhookURL, "https://") &&
		!strings.Contains(w.webhookURL, "/xxx/yyy")
}

type webhookPayload struct {
	Username  string                    `json:"username,omitempty"`
	AvatarURL string                    `json:"avatar_url,omitempty"`
	Content   string                    `json:"content,omitempty"`
	Embeds    []*discordgo.MessageEmbed `json:"embeds,omitempty"`
}

// SendEmbeds posts rich embeds to the configured Discord Webhook in batches of up to 10 embeds.
func (w *WebhookSender) SendEmbeds(ctx context.Context, content string, embeds []*discordgo.MessageEmbed) error {
	if !w.Enabled() {
		return fmt.Errorf("DISCORD_WEBHOOK_URL is not configured")
	}
	if len(embeds) == 0 && content == "" {
		return nil
	}

	const batchSize = 10
	for i := 0; i < len(embeds); i += batchSize {
		end := i + batchSize
		if end > len(embeds) {
			end = len(embeds)
		}
		batchContent := ""
		if i == 0 {
			batchContent = content
		}

		payload := webhookPayload{
			Username: "Huginn",
			Content:  batchContent,
			Embeds:   embeds[i:end],
		}

		body, err := json.Marshal(payload)
		if err != nil {
			return err
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.webhookURL, bytes.NewReader(body))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := w.httpClient.Do(req)
		if err != nil {
			return fmt.Errorf("webhook HTTP error: %w", err)
		}
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		_ = resp.Body.Close()

		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("webhook returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
		}

		if end < len(embeds) {
			time.Sleep(1200 * time.Millisecond)
		}
	}
	return nil
}
