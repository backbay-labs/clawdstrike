// Package threat_intel provides async guards that check external threat
// intelligence APIs.
package threat_intel

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// ThreatResult holds the result of a threat intelligence lookup.
type ThreatResult struct {
	Malicious bool                   `json:"malicious"`
	Score     float64                `json:"score"`
	Details   map[string]interface{} `json:"details,omitempty"`
}

// VirusTotalClient queries the VirusTotal API.
type VirusTotalClient struct {
	apiKey   string
	endpoint string
	client   *http.Client
}

// NewVirusTotalClient creates a new VirusTotal client.
func NewVirusTotalClient(apiKey string) *VirusTotalClient {
	return &VirusTotalClient{
		apiKey:   apiKey,
		endpoint: "https://www.virustotal.com/api/v3",
		client:   &http.Client{},
	}
}

// CheckURL checks a URL against VirusTotal.
func (c *VirusTotalClient) CheckURL(ctx context.Context, url string) (*ThreatResult, error) {
	urlID := strings.TrimRight(base64.URLEncoding.EncodeToString([]byte(url)), "=")
	reqURL := fmt.Sprintf("%s/urls/%s", c.endpoint, urlID)
	return c.doGet(ctx, reqURL)
}

// CheckHash checks a file hash against VirusTotal.
func (c *VirusTotalClient) CheckHash(ctx context.Context, hash string) (*ThreatResult, error) {
	reqURL := fmt.Sprintf("%s/files/%s", c.endpoint, hash)
	return c.doGet(ctx, reqURL)
}

func (c *VirusTotalClient) doGet(ctx context.Context, url string) (*ThreatResult, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("virustotal: create request: %w", err)
	}
	req.Header.Set("x-apikey", c.apiKey)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("virustotal: send request: %w", err)
	}
	defer func() { _, _ = io.Copy(io.Discard, resp.Body); resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("virustotal: unexpected status %d", resp.StatusCode)
	}

	var raw struct {
		Data struct {
			Attributes struct {
				LastAnalysisStats map[string]int `json:"last_analysis_stats"`
			} `json:"attributes"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, fmt.Errorf("virustotal: decode response: %w", err)
	}

	stats := raw.Data.Attributes.LastAnalysisStats
	maliciousCount := stats["malicious"]
	total := 0
	for _, count := range stats {
		if count > 0 {
			total += count
		}
	}
	score := 0.0
	if total > 0 {
		score = float64(maliciousCount) / float64(total)
	}

	return &ThreatResult{
		Malicious: maliciousCount > 0,
		Score:     score,
		Details: map[string]interface{}{
			"analysis_stats": stats,
		},
	}, nil
}
