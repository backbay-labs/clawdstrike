// Package clawdstrike is the top-level facade for the Clawdstrike Go SDK,
// providing a simple API for runtime security enforcement of AI agents.
package clawdstrike

import (
	"net/http"
	"time"

	"github.com/backbay-labs/clawdstrike-go/engine"
	"github.com/backbay-labs/clawdstrike-go/guards"
	"github.com/backbay-labs/clawdstrike-go/policy"
	"github.com/backbay-labs/clawdstrike-go/session"
)

// Re-export Decision types from guards package for top-level API convenience.
type Decision = guards.Decision
type DecisionStatus = guards.DecisionStatus

const (
	StatusAllow = guards.StatusAllow
	StatusWarn  = guards.StatusWarn
	StatusDeny  = guards.StatusDeny
)

// Clawdstrike is the main entry point for the SDK. It wraps a HushEngine
// and exposes convenience methods for common security checks.
type Clawdstrike struct {
	checker checker
	engine  *engine.HushEngine
}

type checker interface {
	CheckAction(action guards.GuardAction, ctx *guards.GuardContext) guards.GuardResult
}

// DaemonConfig configures daemon-backed policy evaluation.
type DaemonConfig struct {
	APIKey        string
	HTTPClient    *http.Client
	Timeout       time.Duration
	RetryAttempts int
	RetryBackoff  time.Duration
}

// DefaultDaemonConfig returns the default daemon configuration.
func DefaultDaemonConfig() DaemonConfig {
	return DaemonConfig{
		Timeout:       10 * time.Second,
		RetryAttempts: 1,
		RetryBackoff:  0,
	}
}

type denyChecker struct {
	guard   string
	message string
}

func (d denyChecker) CheckAction(_ guards.GuardAction, _ *guards.GuardContext) guards.GuardResult {
	return guards.Block(d.guard, guards.Critical, d.message)
}

// WithDefaults creates a Clawdstrike instance from a named built-in ruleset.
// Valid rulesets: "permissive", "default", "strict", "ai-agent", "cicd".
func WithDefaults(ruleset string) (*Clawdstrike, error) {
	eng, err := engine.FromRuleset(ruleset)
	if err != nil {
		return nil, err
	}
	return &Clawdstrike{checker: eng, engine: eng}, nil
}

// FromPolicy creates a Clawdstrike instance from a policy spec.
// The spec can be a built-in ruleset name (e.g. "strict") or a YAML file path.
func FromPolicy(spec string) (*Clawdstrike, error) {
	p, err := policy.Resolve(spec)
	if err != nil {
		return nil, err
	}
	eng, err := engine.BuildFromPolicy(p)
	if err != nil {
		return nil, err
	}
	return &Clawdstrike{checker: eng, engine: eng}, nil
}

// FromDaemon creates a Clawdstrike instance that evaluates checks via a daemon.
// The optional apiKey is sent as a Bearer token.
func FromDaemon(url string, apiKey ...string) (*Clawdstrike, error) {
	cfg := DefaultDaemonConfig()
	key := ""
	if len(apiKey) > 0 {
		key = apiKey[0]
	}
	cfg.APIKey = key
	return FromDaemonWithConfig(url, cfg)
}

// FromDaemonWithConfig creates a daemon-backed Clawdstrike instance with explicit
// HTTP client, timeout, and retry configuration.
func FromDaemonWithConfig(url string, cfg DaemonConfig) (*Clawdstrike, error) {
	dc, err := newDaemonChecker(url, cfg)
	if err != nil {
		return nil, err
	}
	return &Clawdstrike{checker: dc}, nil
}

// FromEngine wraps an existing HushEngine in a Clawdstrike facade.
func FromEngine(eng *engine.HushEngine) *Clawdstrike {
	return &Clawdstrike{checker: eng, engine: eng}
}

func (c *Clawdstrike) Engine() *engine.HushEngine {
	if c == nil {
		return nil
	}
	return c.engine
}

func (c *Clawdstrike) Check(action guards.GuardAction) Decision {
	return c.CheckWithContext(action, nil)
}

func (c *Clawdstrike) CheckWithContext(action guards.GuardAction, ctx *guards.GuardContext) Decision {
	result := c.effectiveChecker().CheckAction(action, ctx)
	return guards.DecisionFromResult(result)
}

func (c *Clawdstrike) CheckFileAccess(path string) Decision {
	return c.Check(guards.FileAccess(path))
}

func (c *Clawdstrike) CheckFileWrite(path string, content []byte) Decision {
	return c.Check(guards.FileWrite(path, content))
}

func (c *Clawdstrike) CheckEgress(host string, port int) Decision {
	return c.Check(guards.NetworkEgress(host, port))
}

func (c *Clawdstrike) CheckShell(cmd string) Decision {
	return c.Check(guards.ShellCommand(cmd))
}

func (c *Clawdstrike) CheckMcpTool(name string, args interface{}) Decision {
	return c.Check(guards.McpTool(name, args))
}

func (c *Clawdstrike) CheckPatch(file, diff string) Decision {
	return c.Check(guards.Patch(file, diff))
}

func (c *Clawdstrike) CheckUntrustedText(text string) Decision {
	return c.Check(guards.Custom("untrusted_text", text))
}

// SessionOptions configures a new ClawdstrikeSession.
type SessionOptions struct {
	ID      string
	AgentID string
}

func (c *Clawdstrike) Session(opts SessionOptions) *session.ClawdstrikeSession {
	sopts := session.Options{
		ID:      opts.ID,
		AgentID: opts.AgentID,
	}
	return session.NewSession(c.effectiveChecker(), sopts)
}

func (c *Clawdstrike) effectiveChecker() checker {
	if c != nil && c.checker != nil {
		return c.checker
	}
	return denyChecker{
		guard:   "clawdstrike",
		message: "clawdstrike checker is not initialized",
	}
}
