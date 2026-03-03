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

// SumoLogicExporter sends security events to Sumo Logic HTTP Source.
type SumoLogicExporter struct {
	endpoint string
	client   *http.Client
}

// NewSumoLogicExporter creates an exporter for Sumo Logic. The endpoint is the
// HTTP Source URL which includes authentication.
func NewSumoLogicExporter(endpoint string) *SumoLogicExporter {
	return &SumoLogicExporter{
		endpoint: endpoint,
		client:   &http.Client{},
	}
}

// Export sends a batch of events to Sumo Logic.
func (s *SumoLogicExporter) Export(ctx context.Context, events []siem.SecurityEvent) error {
	if len(events) == 0 {
		return nil
	}

	var buf bytes.Buffer
	for _, ev := range events {
		data, err := json.Marshal(ev)
		if err != nil {
			return fmt.Errorf("sumologic: marshal event: %w", err)
		}
		buf.Write(data)
		buf.WriteByte('\n')
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.endpoint, &buf)
	if err != nil {
		return fmt.Errorf("sumologic: create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Sumo-Category", "clawdstrike/security")

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("sumologic: send request: %w", err)
	}
	defer func() { _, _ = io.Copy(io.Discard, resp.Body); resp.Body.Close() }()

	if resp.StatusCode >= 300 {
		return fmt.Errorf("sumologic: unexpected status %d", resp.StatusCode)
	}
	return nil
}

// Close is a no-op for SumoLogicExporter.
func (s *SumoLogicExporter) Close() error {
	return nil
}
