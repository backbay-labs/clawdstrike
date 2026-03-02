package engine

import (
	"errors"
	"testing"

	"github.com/backbay/clawdstrike-go/guards"
)

func TestBuildWithConfigErrReturnsError(t *testing.T) {
	b := NewBuilder()
	b.configErr = errors.New("bad config")

	eng, err := b.Build()
	if err == nil {
		t.Fatal("expected error from Build when configErr is set")
	}
	if eng != nil {
		t.Fatal("expected nil engine when configErr is set")
	}
}

func TestFromRulesetStrict(t *testing.T) {
	eng, err := FromRuleset("strict")
	if err != nil {
		t.Fatalf("FromRuleset(strict): %v", err)
	}
	if eng == nil {
		t.Fatal("expected non-nil engine")
	}
	if len(eng.guards) == 0 {
		t.Error("expected guards to be instantiated from strict ruleset")
	}
}

func TestFromRulesetDefault(t *testing.T) {
	eng, err := FromRuleset("default")
	if err != nil {
		t.Fatalf("FromRuleset(default): %v", err)
	}
	if eng == nil {
		t.Fatal("expected non-nil engine")
	}
	if len(eng.guards) == 0 {
		t.Error("expected guards to be instantiated from default ruleset")
	}
}

func TestFromRulesetInvalid(t *testing.T) {
	_, err := FromRuleset("nonexistent")
	if err == nil {
		t.Fatal("expected error for unknown ruleset")
	}
}

// stubGuard is a guard that always returns a fixed result.
type stubGuard struct {
	name     string
	result   guards.GuardResult
	handles  bool
}

func (g *stubGuard) Name() string                                          { return g.name }
func (g *stubGuard) Handles(_ guards.GuardAction) bool                    { return g.handles }
func (g *stubGuard) Check(_ guards.GuardAction, _ *guards.GuardContext) guards.GuardResult {
	return g.result
}

func TestCheckActionWorstSeverityDeny(t *testing.T) {
	// Two guards that both deny: one with Error severity, one with Critical.
	// The engine should return the Critical-severity deny.
	eng, err := NewBuilder().
		WithGuard(&stubGuard{
			name:    "low",
			handles: true,
			result:  guards.Block("low", guards.Error, "low severity deny"),
		}).
		WithGuard(&stubGuard{
			name:    "high",
			handles: true,
			result:  guards.Block("high", guards.Critical, "high severity deny"),
		}).
		Build()
	if err != nil {
		t.Fatal(err)
	}

	result := eng.CheckAction(guards.FileAccess("/tmp/test"), nil)
	if result.Allowed {
		t.Fatal("expected deny")
	}
	if result.Severity != guards.Critical {
		t.Errorf("expected Critical severity, got %v", result.Severity)
	}
	if result.Guard != "high" {
		t.Errorf("expected guard 'high', got %q", result.Guard)
	}
}

func TestCheckActionFailFastReturnsFirst(t *testing.T) {
	eng, err := NewBuilder().
		WithFailFast(true).
		WithGuard(&stubGuard{
			name:    "first",
			handles: true,
			result:  guards.Block("first", guards.Warning, "first deny"),
		}).
		WithGuard(&stubGuard{
			name:    "second",
			handles: true,
			result:  guards.Block("second", guards.Critical, "second deny"),
		}).
		Build()
	if err != nil {
		t.Fatal(err)
	}

	result := eng.CheckAction(guards.FileAccess("/tmp/test"), nil)
	if result.Allowed {
		t.Fatal("expected deny")
	}
	// In fail-fast mode, should return the first deny, not worst.
	if result.Guard != "first" {
		t.Errorf("expected guard 'first' in fail-fast mode, got %q", result.Guard)
	}
}

func TestConvenienceMethodsWork(t *testing.T) {
	eng, err := NewBuilder().Build()
	if err != nil {
		t.Fatal(err)
	}

	// With no guards, all checks should allow.
	if r := eng.CheckFileAccess("/tmp/test"); !r.Allowed {
		t.Error("expected allow for CheckFileAccess")
	}
	if r := eng.CheckFileWrite("/tmp/test", []byte("data")); !r.Allowed {
		t.Error("expected allow for CheckFileWrite")
	}
	if r := eng.CheckEgress("example.com", 443); !r.Allowed {
		t.Error("expected allow for CheckEgress")
	}
	if r := eng.CheckShell("ls"); !r.Allowed {
		t.Error("expected allow for CheckShell")
	}
	if r := eng.CheckMcpTool("read_file", nil); !r.Allowed {
		t.Error("expected allow for CheckMcpTool")
	}
	if r := eng.CheckPatch("file.go", "+line\n-line"); !r.Allowed {
		t.Error("expected allow for CheckPatch")
	}
	if r := eng.CheckUntrustedText("hello world"); !r.Allowed {
		t.Error("expected allow for CheckUntrustedText")
	}
}

func TestCheckActionAllowWhenNoGuards(t *testing.T) {
	eng, err := NewBuilder().Build()
	if err != nil {
		t.Fatal(err)
	}

	result := eng.CheckAction(guards.FileAccess("/tmp/test"), nil)
	if !result.Allowed {
		t.Error("expected allow when no guards are configured")
	}
}

func TestCheckActionConfigErrorDenies(t *testing.T) {
	eng, err := NewBuilder().Build()
	if err != nil {
		t.Fatal(err)
	}
	eng.SetConfigError(errors.New("broken"))

	result := eng.CheckAction(guards.FileAccess("/tmp/test"), nil)
	if result.Allowed {
		t.Error("expected deny when config error is set")
	}
}
