// Package engine implements the HushEngine, the core orchestrator for
// Clawdstrike guard evaluation and receipt signing.
package engine

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/backbay/clawdstrike-go/crypto"
	"github.com/backbay/clawdstrike-go/guards"
	"github.com/backbay/clawdstrike-go/receipt"
)

// HushEngine orchestrates guards and signs receipts. Fail-closed: if a
// configuration error is stored, all subsequent checks return deny.
type HushEngine struct {
	mu sync.RWMutex

	keypair   *crypto.Keypair
	guards    []guards.Guard
	failFast  bool
	configErr error
	ruleset   string
}

// Builder constructs a HushEngine step by step.
type Builder struct {
	keypair    *crypto.Keypair
	guards     []guards.Guard
	failFast   bool
	configErr  error
	ruleset    string
}

// NewBuilder creates a new engine builder.
func NewBuilder() *Builder {
	return &Builder{}
}

// WithKeypair sets the signing keypair for receipt signing.
func (b *Builder) WithKeypair(kp *crypto.Keypair) *Builder {
	b.keypair = kp
	return b
}

// WithGuard adds a guard to the pipeline.
func (b *Builder) WithGuard(g guards.Guard) *Builder {
	b.guards = append(b.guards, g)
	return b
}

// WithExtraGuard is an alias for WithGuard for backward compatibility.
func (b *Builder) WithExtraGuard(g guards.Guard) *Builder {
	return b.WithGuard(g)
}

// WithFailFast enables fail-fast mode: stop after first deny.
func (b *Builder) WithFailFast(ff bool) *Builder {
	b.failFast = ff
	return b
}

// WithRuleset sets the ruleset name (informational, used in receipts).
func (b *Builder) WithRuleset(name string) *Builder {
	b.ruleset = name
	return b
}

// Build creates the HushEngine. Returns an error if configuration is invalid.
func (b *Builder) Build() (*HushEngine, error) {
	if b.configErr != nil {
		return &HushEngine{configErr: b.configErr}, nil
	}
	return &HushEngine{
		keypair:  b.keypair,
		guards:   b.guards,
		failFast: b.failFast,
		ruleset:  b.ruleset,
	}, nil
}

// FromRuleset creates a HushEngine from a named built-in ruleset.
// Guard instantiation from policy config is deferred to the policy/guards packages;
// this constructor stores the ruleset name for provenance.
func FromRuleset(name string) (*HushEngine, error) {
	switch name {
	case "permissive", "default", "strict", "ai-agent", "cicd":
		return &HushEngine{
			ruleset: name,
		}, nil
	default:
		return nil, fmt.Errorf("unknown ruleset: %q", name)
	}
}

// SetConfigError marks the engine as misconfigured. All subsequent checks
// will return deny (fail-closed).
func (e *HushEngine) SetConfigError(err error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.configErr = err
}

// AddGuard appends a guard to the engine pipeline.
func (e *HushEngine) AddGuard(g guards.Guard) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.guards = append(e.guards, g)
}

// Ruleset returns the configured ruleset name.
func (e *HushEngine) Ruleset() string {
	return e.ruleset
}

// Keypair returns the engine's signing keypair, or nil if not set.
func (e *HushEngine) Keypair() *crypto.Keypair {
	return e.keypair
}

// CheckAction evaluates the action against all guards and returns an
// aggregated GuardResult. Returns deny on configuration error (fail-closed).
func (e *HushEngine) CheckAction(action guards.GuardAction, ctx *guards.GuardContext) guards.GuardResult {
	e.mu.RLock()
	defer e.mu.RUnlock()

	// Fail-closed: config error → deny
	if e.configErr != nil {
		return guards.Block("engine", guards.Critical,
			fmt.Sprintf("engine configuration error: %v", e.configErr))
	}

	if ctx == nil {
		ctx = guards.NewContext()
	}

	var firstDeny *guards.GuardResult
	for _, g := range e.guards {
		if !g.Handles(action) {
			continue
		}
		result := g.Check(action, ctx)
		if !result.Allowed {
			if e.failFast {
				return result
			}
			if firstDeny == nil {
				r := result
				firstDeny = &r
			}
		}
	}

	if firstDeny != nil {
		return *firstDeny
	}
	return guards.Allow("engine")
}

// CheckActionReport evaluates the action and returns a detailed report
// with per-guard timing.
func (e *HushEngine) CheckActionReport(action guards.GuardAction, ctx *guards.GuardContext) *GuardReport {
	e.mu.RLock()
	defer e.mu.RUnlock()

	report := &GuardReport{Allowed: true}
	start := time.Now()

	// Fail-closed: config error → deny
	if e.configErr != nil {
		report.Allowed = false
		report.Results = append(report.Results, GuardResultEntry{
			GuardName: "engine",
			Result: guards.Block("engine", guards.Critical,
				fmt.Sprintf("engine configuration error: %v", e.configErr)),
			Duration: time.Since(start),
		})
		report.TotalDuration = time.Since(start)
		return report
	}

	if ctx == nil {
		ctx = guards.NewContext()
	}

	for _, g := range e.guards {
		if !g.Handles(action) {
			continue
		}
		guardStart := time.Now()
		result := g.Check(action, ctx)
		elapsed := time.Since(guardStart)

		report.Results = append(report.Results, GuardResultEntry{
			GuardName: g.Name(),
			Result:    result,
			Duration:  elapsed,
		})

		if !result.Allowed {
			report.Allowed = false
			if e.failFast {
				break
			}
		}
	}

	report.TotalDuration = time.Since(start)
	return report
}

// --- Convenience check methods ---

// CheckFileAccess checks a file read action.
func (e *HushEngine) CheckFileAccess(path string) guards.GuardResult {
	return e.CheckAction(guards.FileAccess(path), nil)
}

// CheckFileWrite checks a file write action.
func (e *HushEngine) CheckFileWrite(path string, content []byte) guards.GuardResult {
	return e.CheckAction(guards.FileWrite(path, content), nil)
}

// CheckEgress checks an outbound network connection.
func (e *HushEngine) CheckEgress(host string, port int) guards.GuardResult {
	return e.CheckAction(guards.NetworkEgress(host, port), nil)
}

// CheckShell checks a shell command execution.
func (e *HushEngine) CheckShell(cmd string) guards.GuardResult {
	return e.CheckAction(guards.ShellCommand(cmd), nil)
}

// CheckMcpTool checks an MCP tool invocation.
func (e *HushEngine) CheckMcpTool(name string, args interface{}) guards.GuardResult {
	return e.CheckAction(guards.McpTool(name, args), nil)
}

// CheckPatch checks a patch application.
func (e *HushEngine) CheckPatch(file, diff string) guards.GuardResult {
	return e.CheckAction(guards.Patch(file, diff), nil)
}

// CheckUntrustedText checks untrusted text for injection/jailbreak.
func (e *HushEngine) CheckUntrustedText(text string) guards.GuardResult {
	return e.CheckAction(guards.Custom("untrusted_text", text), nil)
}

// SignReceipt signs a receipt with the engine's keypair.
func (e *HushEngine) SignReceipt(r receipt.Receipt) (*receipt.SignedReceipt, error) {
	if e.keypair == nil {
		return nil, errors.New("engine has no signing keypair")
	}
	return receipt.Sign(r, e.keypair)
}
