package clawdstrike

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/backbay-labs/clawdstrike-go/guards"
)

func TestFromPolicyBuildsEngine(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(policyPath, []byte(`
version: "1.2.0"
name: "from-policy-test"
guards:
  forbidden_path:
    enabled: true
    patterns:
      - "/etc/**"
`), 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}

	cs, err := FromPolicy(policyPath)
	if err != nil {
		t.Fatalf("FromPolicy: %v", err)
	}
	if cs.Engine() == nil {
		t.Fatal("expected local engine for FromPolicy")
	}

	decision := cs.CheckFileAccess("/etc/passwd")
	if decision.Status != StatusDeny {
		t.Fatalf("expected deny for forbidden path, got %s", decision.Status)
	}
}

func TestFromDaemonRemoteEvaluation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/check" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if got := r.Header.Get("authorization"); got != "Bearer test-key" {
			t.Fatalf("unexpected authorization header: %q", got)
		}

		var req map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if req["action_type"] != "file_access" {
			t.Fatalf("unexpected action_type: %v", req["action_type"])
		}
		if req["target"] != "/etc/passwd" {
			t.Fatalf("unexpected target: %v", req["target"])
		}

		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"allowed":  false,
			"guard":    "forbidden_path",
			"severity": "critical",
			"message":  "blocked by daemon",
		})
	}))
	defer srv.Close()

	cs, err := FromDaemon(srv.URL+"/", "test-key")
	if err != nil {
		t.Fatalf("FromDaemon: %v", err)
	}
	if cs.Engine() != nil {
		t.Fatal("expected nil local engine for daemon-backed Clawdstrike")
	}

	decision := cs.CheckFileAccess("/etc/passwd")
	if decision.Status != StatusDeny {
		t.Fatalf("expected deny decision, got %s", decision.Status)
	}
	if decision.Guard != "forbidden_path" {
		t.Fatalf("expected daemon guard mapping, got %q", decision.Guard)
	}
}

func TestFromDaemonSessionForwardsContext(t *testing.T) {
	var gotSession string
	var gotAgent string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if sid, ok := req["session_id"].(string); ok {
			gotSession = sid
		}
		if aid, ok := req["agent_id"].(string); ok {
			gotAgent = aid
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"allowed":  true,
			"guard":    "daemon",
			"severity": "info",
			"message":  "ok",
		})
	}))
	defer srv.Close()

	cs, err := FromDaemon(srv.URL)
	if err != nil {
		t.Fatalf("FromDaemon: %v", err)
	}
	sess := cs.Session(SessionOptions{ID: "sess-123", AgentID: "agent-007"})
	decision := sess.Check(guards.FileAccess("/tmp/example.txt"))

	if decision.Status != guards.StatusAllow {
		t.Fatalf("expected allow decision, got %s", decision.Status)
	}
	if gotSession != "sess-123" {
		t.Fatalf("expected session_id sess-123, got %q", gotSession)
	}
	if gotAgent != "agent-007" {
		t.Fatalf("expected agent_id agent-007, got %q", gotAgent)
	}
}

func TestFromDaemonNetworkEgressUsesDaemonActionType(t *testing.T) {
	var gotActionType string
	var gotTarget string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if actionType, ok := req["action_type"].(string); ok {
			gotActionType = actionType
		}
		if target, ok := req["target"].(string); ok {
			gotTarget = target
		}

		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"allowed":  true,
			"guard":    "egress_allowlist",
			"severity": "info",
			"message":  "ok",
		})
	}))
	defer srv.Close()

	cs, err := FromDaemon(srv.URL)
	if err != nil {
		t.Fatalf("FromDaemon: %v", err)
	}

	decision := cs.CheckEgress("api.example.com", 443)
	if decision.Status != StatusAllow {
		t.Fatalf("expected allow decision, got %s", decision.Status)
	}
	if gotActionType != "egress" {
		t.Fatalf("expected action_type egress, got %q", gotActionType)
	}
	if gotTarget != "api.example.com:443" {
		t.Fatalf("expected target api.example.com:443, got %q", gotTarget)
	}
}

func TestFromDaemonFailsClosedOnTransportError(t *testing.T) {
	cs, err := FromDaemon("http://127.0.0.1:65530")
	if err != nil {
		t.Fatalf("FromDaemon: %v", err)
	}

	decision := cs.CheckFileAccess("/etc/passwd")
	if decision.Status != StatusDeny {
		t.Fatalf("expected deny decision, got %s", decision.Status)
	}
	if decision.Guard != "daemon" {
		t.Fatalf("expected daemon guard, got %s", decision.Guard)
	}
	if !strings.Contains(decision.Message, "Daemon check failed") {
		t.Fatalf("expected daemon error message, got %q", decision.Message)
	}
}

func TestFromDaemonRejectsInvalidURL(t *testing.T) {
	if _, err := FromDaemon("not-a-url"); err == nil {
		t.Fatal("expected error for invalid daemon URL")
	}
}

type staticRoundTripper struct {
	statusCode int
	header     http.Header
	body       string
	err        error
	calls      atomic.Int64
}

func (s *staticRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	s.calls.Add(1)
	if s.err != nil {
		return nil, s.err
	}
	statusCode := s.statusCode
	if statusCode == 0 {
		statusCode = http.StatusOK
	}

	header := make(http.Header, len(s.header))
	for key, values := range s.header {
		clone := make([]string, len(values))
		copy(clone, values)
		header[key] = clone
	}

	return &http.Response{
		StatusCode: statusCode,
		Header:     header,
		Body:       io.NopCloser(strings.NewReader(s.body)),
		Request:    req,
	}, nil
}

type cancelAwareRoundTripper struct {
	calls atomic.Int64
}

func (c *cancelAwareRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	c.calls.Add(1)
	<-req.Context().Done()
	return nil, req.Context().Err()
}

func TestFromDaemonWithConfigRetryPolicy(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&calls, 1) < 3 {
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte("busy"))
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"allowed":  false,
			"guard":    "forbidden_path",
			"severity": "critical",
			"message":  "blocked after retries",
		})
	}))
	defer srv.Close()

	cs, err := FromDaemonWithConfig(srv.URL, DaemonConfig{
		RetryAttempts: 3,
		RetryBackoff:  1 * time.Millisecond,
		Timeout:       2 * time.Second,
	})
	if err != nil {
		t.Fatalf("FromDaemonWithConfig: %v", err)
	}

	decision := cs.CheckFileAccess("/etc/passwd")
	if decision.Status != StatusDeny {
		t.Fatalf("expected deny, got %s", decision.Status)
	}
	if got := atomic.LoadInt32(&calls); got != 3 {
		t.Fatalf("expected 3 daemon attempts, got %d", got)
	}
}

func TestFromDaemonWithConfigHTTPClientOverride(t *testing.T) {
	rt := &staticRoundTripper{
		statusCode: http.StatusOK,
		header:     make(http.Header),
		body:       `{"allowed":true,"guard":"daemon","severity":"info","message":"ok"}`,
	}

	client := &http.Client{Transport: rt, Timeout: 50 * time.Millisecond}
	cs, err := FromDaemonWithConfig("http://daemon.example.com", DaemonConfig{
		HTTPClient: client,
	})
	if err != nil {
		t.Fatalf("FromDaemonWithConfig: %v", err)
	}

	decision := cs.CheckFileAccess("/tmp/x")
	if decision.Status != StatusAllow {
		t.Fatalf("expected allow decision, got %s", decision.Status)
	}
	if rt.calls.Load() != 1 {
		t.Fatalf("expected custom roundtripper to be called once, got %d", rt.calls.Load())
	}
}

func TestFromDaemonWithConfigHTTPClientOverrideResponseBodyReusable(t *testing.T) {
	rt := &staticRoundTripper{
		statusCode: http.StatusOK,
		header:     make(http.Header),
		body:       `{"allowed":true,"guard":"daemon","severity":"info","message":"ok"}`,
	}

	client := &http.Client{Transport: rt, Timeout: 50 * time.Millisecond}
	cs, err := FromDaemonWithConfig("http://daemon.example.com", DaemonConfig{
		HTTPClient: client,
	})
	if err != nil {
		t.Fatalf("FromDaemonWithConfig: %v", err)
	}

	first := cs.CheckFileAccess("/tmp/one")
	if first.Status != StatusAllow {
		t.Fatalf("expected first check to allow, got %s", first.Status)
	}
	second := cs.CheckFileAccess("/tmp/two")
	if second.Status != StatusAllow {
		t.Fatalf("expected second check to allow, got %s", second.Status)
	}
	if rt.calls.Load() != 2 {
		t.Fatalf("expected custom roundtripper to be called twice, got %d", rt.calls.Load())
	}
}

func TestFromDaemonWithConfigRequestContextCancellation(t *testing.T) {
	rt := &cancelAwareRoundTripper{}
	client := &http.Client{
		Transport: rt,
		Timeout:   5 * time.Second,
	}

	cs, err := FromDaemonWithConfig("http://daemon.example.com", DaemonConfig{
		HTTPClient:    client,
		RetryAttempts: 5,
		RetryBackoff:  10 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("FromDaemonWithConfig: %v", err)
	}

	reqCtx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()

	start := time.Now()
	decision := cs.CheckWithContext(
		guards.FileAccess("/tmp/cancel"),
		guards.NewContext().WithContext(reqCtx),
	)
	if decision.Status != StatusDeny {
		t.Fatalf("expected deny, got %s", decision.Status)
	}
	if !strings.Contains(decision.Message, "Daemon check canceled") {
		t.Fatalf("expected cancellation message, got %q", decision.Message)
	}
	if elapsed := time.Since(start); elapsed > 200*time.Millisecond {
		t.Fatalf("expected cancellation to return quickly, took %s", elapsed)
	}
	if got := rt.calls.Load(); got < 1 {
		t.Fatalf("expected at least one daemon request, got %d", got)
	}
}
