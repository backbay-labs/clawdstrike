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

// SplunkExporter sends security events to Splunk HTTP Event Collector (HEC).
type SplunkExporter struct {
	endpoint string
	token    string
	index    string
	client   *http.Client
}

// NewSplunkExporter creates an exporter for Splunk HEC.
func NewSplunkExporter(endpoint, token, index string) *SplunkExporter {
	return &SplunkExporter{
		endpoint: endpoint,
		token:    token,
		index:    index,
		client:   &http.Client{},
	}
}

type splunkEvent struct {
	Index  string              `json:"index,omitempty"`
	Source string              `json:"source"`
	Event  siem.SecurityEvent  `json:"event"`
}

// Export sends a batch of events to Splunk HEC.
func (s *SplunkExporter) Export(ctx context.Context, events []siem.SecurityEvent) error {
	if len(events) == 0 {
		return nil
	}

	var buf bytes.Buffer
	for _, ev := range events {
		wrapped := splunkEvent{
			Index:  s.index,
			Source: "clawdstrike",
			Event:  ev,
		}
		data, err := json.Marshal(wrapped)
		if err != nil {
			return fmt.Errorf("splunk: marshal event: %w", err)
		}
		buf.Write(data)
		buf.WriteByte('\n')
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.endpoint, &buf)
	if err != nil {
		return fmt.Errorf("splunk: create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Splunk "+s.token)

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("splunk: send request: %w", err)
	}
	defer func() { _, _ = io.Copy(io.Discard, resp.Body); resp.Body.Close() }()

	if resp.StatusCode >= 300 {
		return fmt.Errorf("splunk: unexpected status %d", resp.StatusCode)
	}
	return nil
}

// Close is a no-op for SplunkExporter.
func (s *SplunkExporter) Close() error {
	return nil
}
