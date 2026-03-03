package threat_intel

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCheckURLUsesEncodedURLIdentifier(t *testing.T) {
	rawURL := "https://example.com/path?q=1#frag"
	expectedID := strings.TrimRight(base64.URLEncoding.EncodeToString([]byte(rawURL)), "=")

	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"data":{"attributes":{"last_analysis_stats":{"malicious":1,"harmless":9,"suspicious":2,"undetected":60,"timeout":3}}}}`)
	}))
	defer srv.Close()

	client := NewVirusTotalClient("test-key")
	client.endpoint = srv.URL
	client.client = srv.Client()

	result, err := client.CheckURL(context.Background(), rawURL)
	if err != nil {
		t.Fatalf("CheckURL failed: %v", err)
	}
	if gotPath != "/urls/"+expectedID {
		t.Fatalf("unexpected request path: got %q want %q", gotPath, "/urls/"+expectedID)
	}
	if !result.Malicious {
		t.Fatal("expected malicious=true for malicious count > 0")
	}
	expectedScore := 1.0 / 75.0
	if result.Score != expectedScore {
		t.Fatalf("unexpected score: got %v want %v", result.Score, expectedScore)
	}
}
