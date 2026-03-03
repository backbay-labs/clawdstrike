package threat_intel

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	neturl "net/url"
)

// SnykClient queries the Snyk API for vulnerability information.
type SnykClient struct {
	apiKey   string
	endpoint string
	client   *http.Client
}

// NewSnykClient creates a new Snyk client.
func NewSnykClient(apiKey string) *SnykClient {
	return &SnykClient{
		apiKey:   apiKey,
		endpoint: "https://api.snyk.io/v1",
		client:   &http.Client{},
	}
}

// CheckPackage checks a package for known vulnerabilities.
func (c *SnykClient) CheckPackage(ctx context.Context, ecosystem, pkg, version string) (*ThreatResult, error) {
	requestURL := fmt.Sprintf(
		"%s/test/%s/%s/%s",
		c.endpoint,
		neturl.PathEscape(ecosystem),
		neturl.PathEscape(pkg),
		neturl.PathEscape(version),
	)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
	if err != nil {
		return nil, fmt.Errorf("snyk: create request: %w", err)
	}
	req.Header.Set("Authorization", "token "+c.apiKey)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("snyk: send request: %w", err)
	}
	defer func() { _, _ = io.Copy(io.Discard, resp.Body); resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("snyk: unexpected status %d", resp.StatusCode)
	}

	var raw struct {
		OK     bool `json:"ok"`
		Issues struct {
			Vulnerabilities []struct {
				Severity string `json:"severity"`
				Title    string `json:"title"`
			} `json:"vulnerabilities"`
		} `json:"issues"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, fmt.Errorf("snyk: decode response: %w", err)
	}

	vulnCount := len(raw.Issues.Vulnerabilities)
	score := 0.0
	for _, v := range raw.Issues.Vulnerabilities {
		switch v.Severity {
		case "critical", "high":
			score = 1.0
		case "medium":
			if score < 0.7 {
				score = 0.7
			}
		case "low":
			if score < 0.4 {
				score = 0.4
			}
		default:
			if score < 0.2 {
				score = 0.2
			}
		}
	}

	return &ThreatResult{
		Malicious: !raw.OK,
		Score:     score,
		Details: map[string]interface{}{
			"vulnerability_count": vulnCount,
			"ok":                  raw.OK,
		},
	}, nil
}
