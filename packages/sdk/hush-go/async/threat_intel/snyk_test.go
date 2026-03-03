package threat_intel

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCheckPackageSeverityScore(t *testing.T) {
	tests := []struct {
		name       string
		payload    string
		wantScore  float64
		wantStatus bool
	}{
		{
			name:       "no vulnerabilities",
			payload:    `{"ok":true,"issues":{"vulnerabilities":[]}}`,
			wantScore:  0.0,
			wantStatus: false,
		},
		{
			name:       "low vulnerability",
			payload:    `{"ok":false,"issues":{"vulnerabilities":[{"severity":"low","title":"low"}]}}`,
			wantScore:  0.4,
			wantStatus: true,
		},
		{
			name:       "medium vulnerability",
			payload:    `{"ok":false,"issues":{"vulnerabilities":[{"severity":"medium","title":"med"}]}}`,
			wantScore:  0.7,
			wantStatus: true,
		},
		{
			name:       "high vulnerability",
			payload:    `{"ok":false,"issues":{"vulnerabilities":[{"severity":"high","title":"high"}]}}`,
			wantScore:  1.0,
			wantStatus: true,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, tc.payload)
			}))
			defer srv.Close()

			client := NewSnykClient("test-key")
			client.endpoint = srv.URL
			client.client = srv.Client()

			result, err := client.CheckPackage(context.Background(), "npm", "left-pad", "1.0.0")
			if err != nil {
				t.Fatalf("CheckPackage failed: %v", err)
			}
			if result.Score != tc.wantScore {
				t.Fatalf("unexpected score: got %v want %v", result.Score, tc.wantScore)
			}
			if result.Malicious != tc.wantStatus {
				t.Fatalf("unexpected malicious flag: got %v want %v", result.Malicious, tc.wantStatus)
			}
		})
	}
}

func TestCheckPackageEscapesPathSegments(t *testing.T) {
	var gotEscapedPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotEscapedPath = r.URL.EscapedPath()
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"ok":true,"issues":{"vulnerabilities":[]}}`)
	}))
	defer srv.Close()

	client := NewSnykClient("test-key")
	client.endpoint = srv.URL
	client.client = srv.Client()

	_, err := client.CheckPackage(context.Background(), "npm", "@scope/pkg", "1.0.0-beta/1")
	if err != nil {
		t.Fatalf("CheckPackage failed: %v", err)
	}

	const expectedEscapedPath = "/test/npm/@scope%2Fpkg/1.0.0-beta%2F1"
	if gotEscapedPath != expectedEscapedPath {
		t.Fatalf("unexpected escaped path: got %q want %q", gotEscapedPath, expectedEscapedPath)
	}
}
