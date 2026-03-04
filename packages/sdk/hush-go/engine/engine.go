// Package engine implements the HushEngine, the core orchestrator for
// Clawdstrike guard evaluation and receipt signing.
package engine

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/backbay-labs/clawdstrike-go/crypto"
	"github.com/backbay-labs/clawdstrike-go/guards"
	"github.com/backbay-labs/clawdstrike-go/policy"
	"github.com/backbay-labs/clawdstrike-go/receipt"
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

func NewBuilder() *Builder {
	return &Builder{}
}

func (b *Builder) WithKeypair(kp *crypto.Keypair) *Builder {
	b.keypair = kp
	return b
}

func (b *Builder) WithGuard(g guards.Guard) *Builder {
	b.guards = append(b.guards, g)
	return b
}

func (b *Builder) WithFailFast(ff bool) *Builder {
	b.failFast = ff
	return b
}

func (b *Builder) WithRuleset(name string) *Builder {
	b.ruleset = name
	return b
}

// Build creates the HushEngine. Returns an error if configuration is invalid.
func (b *Builder) Build() (*HushEngine, error) {
	if b.configErr != nil {
		return nil, b.configErr
	}
	return &HushEngine{
		keypair:  b.keypair,
		guards:   b.guards,
		failFast: b.failFast,
		ruleset:  b.ruleset,
	}, nil
}

// FromRuleset creates a HushEngine from a named built-in ruleset.
// Guards are instantiated from the policy's guard configurations.
func FromRuleset(name string) (*HushEngine, error) {
	p, err := policy.ByName(name)
	if err != nil {
		return nil, err
	}
	return BuildFromPolicy(p)
}

// BuildFromPolicy creates a HushEngine from a resolved policy, instantiating
// all guards that have configuration entries.
func BuildFromPolicy(p *policy.Policy) (*HushEngine, error) {
	b := NewBuilder().WithRuleset(p.Name).WithFailFast(p.Settings.FailFast)

	if cfg := p.Guards.ForbiddenPath; cfg != nil && policy.GuardEnabled(cfg.Enabled) {
		b.WithGuard(guards.NewForbiddenPathGuard(cfg))
	}
	if cfg := p.Guards.EgressAllowlist; cfg != nil && policy.GuardEnabled(cfg.Enabled) {
		b.WithGuard(guards.NewEgressAllowlistGuard(cfg))
	}
	if cfg := p.Guards.SecretLeak; cfg != nil && policy.GuardEnabled(cfg.Enabled) {
		g, err := guards.NewSecretLeakGuard(cfg)
		if err != nil {
			return nil, fmt.Errorf("engine: instantiate secret_leak guard: %w", err)
		}
		b.WithGuard(g)
	}
	if cfg := p.Guards.PatchIntegrity; cfg != nil && policy.GuardEnabled(cfg.Enabled) {
		g, err := guards.NewPatchIntegrityGuard(cfg)
		if err != nil {
			return nil, fmt.Errorf("engine: instantiate patch_integrity guard: %w", err)
		}
		b.WithGuard(g)
	}
	if cfg := p.Guards.McpTool; cfg != nil && policy.GuardEnabled(cfg.Enabled) {
		b.WithGuard(guards.NewMcpToolGuard(cfg))
	}
	if cfg := p.Guards.PromptInjection; cfg != nil && policy.GuardEnabled(cfg.Enabled) {
		b.WithGuard(guards.NewPromptInjectionGuard(cfg))
	}
	if cfg := p.Guards.Jailbreak; cfg != nil && policy.GuardEnabled(cfg.Enabled) {
		b.WithGuard(guards.NewJailbreakGuard())
	}
	if cfg := p.Guards.SpiderSense; cfg != nil && policy.GuardEnabled(cfg.Enabled) {
		g, err := guards.NewSpiderSenseGuard(cfg)
		if err != nil {
			return nil, fmt.Errorf("engine: instantiate spider_sense guard: %w", err)
		}
		b.WithGuard(g)
	}

	return b.Build()
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
// Ruleset is safe for concurrent use; the field is immutable after Build().
func (e *HushEngine) Ruleset() string {
	return e.ruleset
}

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

	var worstDeny *guards.GuardResult
	for _, g := range e.guards {
		if !g.Handles(action) {
			continue
		}
		result := g.Check(action, ctx)
		if !result.Allowed {
			if e.failFast {
				return result
			}
			if worstDeny == nil || result.Severity > worstDeny.Severity {
				r := result
				worstDeny = &r
			}
		}
	}

	if worstDeny != nil {
		return *worstDeny
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

func (e *HushEngine) CheckFileAccess(path string) guards.GuardResult {
	return e.CheckAction(guards.FileAccess(path), nil)
}

func (e *HushEngine) CheckFileWrite(path string, content []byte) guards.GuardResult {
	return e.CheckAction(guards.FileWrite(path, content), nil)
}

func (e *HushEngine) CheckEgress(host string, port int) guards.GuardResult {
	return e.CheckAction(guards.NetworkEgress(host, port), nil)
}

func (e *HushEngine) CheckShell(cmd string) guards.GuardResult {
	return e.CheckAction(guards.ShellCommand(cmd), nil)
}

func (e *HushEngine) CheckMcpTool(name string, args interface{}) guards.GuardResult {
	return e.CheckAction(guards.McpTool(name, args), nil)
}

func (e *HushEngine) CheckPatch(file, diff string) guards.GuardResult {
	return e.CheckAction(guards.Patch(file, diff), nil)
}

func (e *HushEngine) CheckUntrustedText(text string) guards.GuardResult {
	return e.CheckAction(guards.Custom("untrusted_text", text), nil)
}

func (e *HushEngine) SignReceipt(r receipt.Receipt) (*receipt.SignedReceipt, error) {
	if e.keypair == nil {
		return nil, errors.New("engine has no signing keypair")
	}
	return receipt.Sign(r, e.keypair)
}
