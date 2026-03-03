package policy_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/backbay-labs/clawdstrike-go/engine"
	"github.com/backbay-labs/clawdstrike-go/guards"
	"github.com/backbay-labs/clawdstrike-go/policy"
)

type conformanceCheck struct {
	Kind           string                 `json:"kind"`
	Path           string                 `json:"path"`
	Host           string                 `json:"host"`
	Port           int                    `json:"port"`
	Tool           string                 `json:"tool"`
	Args           map[string]interface{} `json:"args"`
	Diff           string                 `json:"diff"`
	ExpectedStatus string                 `json:"expected_status"`
	ExpectedGuard  string                 `json:"expected_guard"`
}

type conformanceVector struct {
	Name   string             `json:"name"`
	Entry  string             `json:"entry"`
	Files  map[string]string  `json:"files"`
	Checks []conformanceCheck `json:"checks"`
}

func TestPolicyConformanceVectors(t *testing.T) {
	vectorsPath := filepath.Clean(filepath.Join("..", "..", "..", "..", "fixtures", "policy", "conformance_vectors.json"))
	raw, err := os.ReadFile(vectorsPath)
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}

	var vectors []conformanceVector
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatalf("decode vectors: %v", err)
	}

	for _, vector := range vectors {
		t.Run(vector.Name, func(t *testing.T) {
			dir := t.TempDir()
			for name, content := range vector.Files {
				if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
					t.Fatalf("write %s: %v", name, err)
				}
			}

			p, err := policy.Resolve(filepath.Join(dir, vector.Entry))
			if err != nil {
				t.Fatalf("Resolve: %v", err)
			}
			eng, err := engine.BuildFromPolicy(p)
			if err != nil {
				t.Fatalf("BuildFromPolicy: %v", err)
			}

			for _, check := range vector.Checks {
				action, err := checkToAction(check)
				if err != nil {
					t.Fatalf("invalid check %q: %v", check.Kind, err)
				}
				result := eng.CheckAction(action, guards.NewContext())
				decision := guards.DecisionFromResult(result)

				if got := string(decision.Status); got != check.ExpectedStatus {
					t.Fatalf("%s: expected status %s, got %s", check.Kind, check.ExpectedStatus, got)
				}
				if check.ExpectedGuard != "" && decision.Guard != check.ExpectedGuard {
					t.Fatalf("%s: expected guard %s, got %s", check.Kind, check.ExpectedGuard, decision.Guard)
				}
			}
		})
	}
}

func checkToAction(check conformanceCheck) (guards.GuardAction, error) {
	switch check.Kind {
	case "file_access":
		return guards.FileAccess(check.Path), nil
	case "network_egress":
		return guards.NetworkEgress(check.Host, check.Port), nil
	case "mcp_tool":
		return guards.McpTool(check.Tool, check.Args), nil
	case "patch":
		return guards.Patch(check.Path, check.Diff), nil
	default:
		return guards.GuardAction{}, fmt.Errorf("unknown check kind %q", check.Kind)
	}
}
