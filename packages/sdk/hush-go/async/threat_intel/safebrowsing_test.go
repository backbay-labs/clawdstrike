package threat_intel

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCheckURLURLencodesAPIKey(t *testing.T) {
	const (
		apiKey    = "my+api&key=with spaces#fragment"
		targetURL = "https://example.com/path?q=1"
	)

	var gotKey string
	var gotThreatURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey = r.URL.Query().Get("key")

		var req struct {
			ThreatInfo struct {
				ThreatEntries []struct {
					URL string `json:"url"`
				} `json:"threatEntries"`
			} `json:"threatInfo"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if len(req.ThreatInfo.ThreatEntries) != 1 {
			t.Fatalf("expected 1 threat entry, got %d", len(req.ThreatInfo.ThreatEntries))
		}
		gotThreatURL = req.ThreatInfo.ThreatEntries[0].URL

		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	client := NewSafeBrowsingClient(apiKey)
	client.endpoint = srv.URL
	client.client = srv.Client()

	result, err := client.CheckURL(context.Background(), targetURL)
	if err != nil {
		t.Fatalf("CheckURL failed: %v", err)
	}
	if gotKey != apiKey {
		t.Fatalf("expected key %q, got %q", apiKey, gotKey)
	}
	if gotThreatURL != targetURL {
		t.Fatalf("expected threat URL %q, got %q", targetURL, gotThreatURL)
	}
	if result.Malicious {
		t.Fatal("expected non-malicious result for empty matches")
	}
}
