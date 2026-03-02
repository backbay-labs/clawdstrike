// Package exporters provides SIEM event exporters for various platforms.
package exporters

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/backbay/clawdstrike-go/siem"
)

// ElasticExporter sends security events to an Elasticsearch cluster.
type ElasticExporter struct {
	endpoint string
	index    string
	apiKey   string
	client   *http.Client
}

// NewElasticExporter creates an exporter for Elasticsearch.
func NewElasticExporter(endpoint, index, apiKey string) *ElasticExporter {
	return &ElasticExporter{
		endpoint: endpoint,
		index:    index,
		apiKey:   apiKey,
		client:   &http.Client{},
	}
}

// Export sends a batch of events to Elasticsearch using the _bulk API.
func (e *ElasticExporter) Export(ctx context.Context, events []siem.SecurityEvent) error {
	if len(events) == 0 {
		return nil
	}

	var buf bytes.Buffer
	for _, ev := range events {
		meta := map[string]interface{}{
			"index": map[string]string{"_index": e.index},
		}
		metaBytes, err := json.Marshal(meta)
		if err != nil {
			return fmt.Errorf("elastic: marshal meta: %w", err)
		}
		buf.Write(metaBytes)
		buf.WriteByte('\n')
		docBytes, err := json.Marshal(ev)
		if err != nil {
			return fmt.Errorf("elastic: marshal event: %w", err)
		}
		buf.Write(docBytes)
		buf.WriteByte('\n')
	}

	url := fmt.Sprintf("%s/_bulk", e.endpoint)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, &buf)
	if err != nil {
		return fmt.Errorf("elastic: create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-ndjson")
	if e.apiKey != "" {
		req.Header.Set("Authorization", "ApiKey "+e.apiKey)
	}

	resp, err := e.client.Do(req)
	if err != nil {
		return fmt.Errorf("elastic: send request: %w", err)
	}
	defer func() { _, _ = io.Copy(io.Discard, resp.Body); resp.Body.Close() }()

	if resp.StatusCode >= 300 {
		return fmt.Errorf("elastic: unexpected status %d", resp.StatusCode)
	}
	return nil
}

// Close is a no-op for ElasticExporter.
func (e *ElasticExporter) Close() error {
	return nil
}
