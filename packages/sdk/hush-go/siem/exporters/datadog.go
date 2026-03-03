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

// DatadogExporter sends security events to Datadog Logs API.
type DatadogExporter struct {
	endpoint string
	apiKey   string
	client   *http.Client
}

// NewDatadogExporter creates an exporter for Datadog.
func NewDatadogExporter(endpoint, apiKey string) *DatadogExporter {
	return &DatadogExporter{
		endpoint: endpoint,
		apiKey:   apiKey,
		client:   &http.Client{},
	}
}

// Export sends a batch of events to Datadog.
func (d *DatadogExporter) Export(ctx context.Context, events []siem.SecurityEvent) error {
	if len(events) == 0 {
		return nil
	}

	payload, err := json.Marshal(events)
	if err != nil {
		return fmt.Errorf("datadog: marshal events: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.endpoint, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("datadog: create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("DD-API-KEY", d.apiKey)

	resp, err := d.client.Do(req)
	if err != nil {
		return fmt.Errorf("datadog: send request: %w", err)
	}
	defer func() { _, _ = io.Copy(io.Discard, resp.Body); resp.Body.Close() }()

	if resp.StatusCode >= 300 {
		return fmt.Errorf("datadog: unexpected status %d", resp.StatusCode)
	}
	return nil
}

// Close is a no-op for DatadogExporter.
func (d *DatadogExporter) Close() error {
	return nil
}
