package threat_intel

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// SafeBrowsingClient queries the Google Safe Browsing API.
type SafeBrowsingClient struct {
	apiKey   string
	endpoint string
	client   *http.Client
}

// NewSafeBrowsingClient creates a new Safe Browsing client.
func NewSafeBrowsingClient(apiKey string) *SafeBrowsingClient {
	return &SafeBrowsingClient{
		apiKey:   apiKey,
		endpoint: "https://safebrowsing.googleapis.com/v4/threatMatches:find",
		client:   &http.Client{},
	}
}

// CheckURL checks a URL against Google Safe Browsing.
func (c *SafeBrowsingClient) CheckURL(ctx context.Context, url string) (*ThreatResult, error) {
	body := map[string]interface{}{
		"client": map[string]string{
			"clientId":      "clawdstrike",
			"clientVersion": "1.0.0",
		},
		"threatInfo": map[string]interface{}{
			"threatTypes":      []string{"MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"},
			"platformTypes":    []string{"ANY_PLATFORM"},
			"threatEntryTypes": []string{"URL"},
			"threatEntries":    []map[string]string{{"url": url}},
		},
	}

	payload, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("safebrowsing: marshal request: %w", err)
	}

	reqURL := fmt.Sprintf("%s?key=%s", c.endpoint, c.apiKey)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("safebrowsing: create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("safebrowsing: send request: %w", err)
	}
	defer func() { _, _ = io.Copy(io.Discard, resp.Body); resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("safebrowsing: unexpected status %d", resp.StatusCode)
	}

	var raw struct {
		Matches []struct {
			ThreatType string `json:"threatType"`
		} `json:"matches"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, fmt.Errorf("safebrowsing: decode response: %w", err)
	}

	malicious := len(raw.Matches) > 0
	score := 0.0
	if malicious {
		score = 1.0
	}

	details := map[string]interface{}{
		"match_count": len(raw.Matches),
	}
	if malicious {
		threats := make([]string, len(raw.Matches))
		for i, m := range raw.Matches {
			threats[i] = m.ThreatType
		}
		details["threat_types"] = threats
	}

	return &ThreatResult{
		Malicious: malicious,
		Score:     score,
		Details:   details,
	}, nil
}
