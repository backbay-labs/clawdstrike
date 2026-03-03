package cli

import (
	"context"
	"testing"
	"time"
)

func TestNewCLIBridge(t *testing.T) {
	bridge := NewCLIBridge("/usr/local/bin/hush")
	if bridge.binaryPath != "/usr/local/bin/hush" {
		t.Errorf("expected binary path '/usr/local/bin/hush', got %q", bridge.binaryPath)
	}
	if bridge.timeout != defaultTimeout {
		t.Errorf("expected default timeout %v, got %v", defaultTimeout, bridge.timeout)
	}
}

func TestWithTimeout(t *testing.T) {
	bridge := NewCLIBridge("/usr/local/bin/hush").WithTimeout(5 * time.Second)
	if bridge.timeout != 5*time.Second {
		t.Errorf("expected 5s timeout, got %v", bridge.timeout)
	}
}

func TestCheckBinaryNotFound(t *testing.T) {
	bridge := NewCLIBridge("/nonexistent/hush-binary")
	decision, err := bridge.Check(context.Background(), PolicyEvent{
		Type: "file_access",
		Path: "/etc/passwd",
	})
	if err != nil {
		t.Fatalf("expected no error (fail-closed returns decision), got: %v", err)
	}
	if decision.Status != "deny" {
		t.Errorf("expected deny on missing binary, got %s", decision.Status)
	}
	if decision.Guard != "cli_bridge" {
		t.Errorf("expected guard 'cli_bridge', got %q", decision.Guard)
	}
}

func TestCheckTimeout(t *testing.T) {
	// Use 'sleep' as a binary that will exceed the timeout.
	bridge := NewCLIBridge("sleep").WithTimeout(50 * time.Millisecond)
	decision, err := bridge.Check(context.Background(), PolicyEvent{
		Type: "file_access",
		Path: "/tmp/test",
	})
	if err != nil {
		t.Fatalf("expected no error (fail-closed), got: %v", err)
	}
	if decision.Status != "deny" {
		t.Errorf("expected deny on timeout, got %s", decision.Status)
	}
}

func TestPolicyEventJSON(t *testing.T) {
	event := PolicyEvent{
		Type:     "mcp_tool",
		ToolName: "write_file",
		Args:     map[string]interface{}{"path": "/tmp/out"},
	}
	if event.Type != "mcp_tool" {
		t.Errorf("unexpected type: %s", event.Type)
	}
	if event.ToolName != "write_file" {
		t.Errorf("unexpected tool_name: %s", event.ToolName)
	}
}

func TestShellMetacharacterRejection(t *testing.T) {
	metacharPaths := []string{
		"/usr/bin/hush;rm -rf /",
		"/usr/bin/hush|cat",
		"/usr/bin/hush&",
		"/usr/bin/hush$(cmd)",
		"/usr/bin/hush`cmd`",
		"/usr/bin/hush()",
	}
	for _, p := range metacharPaths {
		t.Run(p, func(t *testing.T) {
			bridge := NewCLIBridge(p)
			decision, err := bridge.Check(context.Background(), PolicyEvent{
				Type: "file_access",
				Path: "/tmp/test",
			})
			if err != nil {
				t.Fatalf("expected no error (fail-closed), got: %v", err)
			}
			if decision.Status != "deny" {
				t.Errorf("expected deny for shell metacharacter path, got %s", decision.Status)
			}
		})
	}
}

func TestValidBinaryPath(t *testing.T) {
	bridge := NewCLIBridge("/usr/local/bin/hush")
	if bridge.pathErr != nil {
		t.Errorf("expected no path error for valid path, got: %v", bridge.pathErr)
	}
}

func TestDenyDecision(t *testing.T) {
	d := denyDecision("test_guard", "something failed")
	if d.Status != "deny" {
		t.Errorf("expected deny, got %s", d.Status)
	}
	if d.Guard != "test_guard" {
		t.Errorf("expected guard 'test_guard', got %q", d.Guard)
	}
	if d.Severity != "critical" {
		t.Errorf("expected severity 'critical', got %q", d.Severity)
	}
}
