package exporters

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/backbay-labs/clawdstrike-go/siem"
)

// WebhookExporter sends security events to an arbitrary HTTP endpoint.
type WebhookExporter struct {
	endpoint string
	headers  map[string]string
	client   *http.Client
}

// NewWebhookExporter creates a generic webhook exporter.
func NewWebhookExporter(endpoint string, headers map[string]string) *WebhookExporter {
	return &WebhookExporter{
		endpoint: endpoint,
		headers:  headers,
		client:   &http.Client{},
	}
}

// Export sends a batch of events as a JSON array to the webhook endpoint.
func (w *WebhookExporter) Export(ctx context.Context, events []siem.SecurityEvent) error {
	if len(events) == 0 {
		return nil
	}

	payload, err := json.Marshal(events)
	if err != nil {
		return fmt.Errorf("webhook: marshal events: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.endpoint, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("webhook: create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range w.headers {
		req.Header.Set(k, v)
	}

	resp, err := w.client.Do(req)
	if err != nil {
		return fmt.Errorf("webhook: send request: %w", err)
	}
	defer func() { _, _ = io.Copy(io.Discard, resp.Body); resp.Body.Close() }()

	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook: unexpected status %d", resp.StatusCode)
	}
	return nil
}

// Close is a no-op for WebhookExporter.
func (w *WebhookExporter) Close() error {
	return nil
}
