// Package clawdstrike is the top-level facade for the Clawdstrike Go SDK,
// providing a simple API for runtime security enforcement of AI agents.
package clawdstrike

import (
	"github.com/backbay/clawdstrike-go/engine"
	"github.com/backbay/clawdstrike-go/guards"
	"github.com/backbay/clawdstrike-go/session"
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
	engine *engine.HushEngine
}

// WithDefaults creates a Clawdstrike instance from a named built-in ruleset.
// Valid rulesets: "permissive", "default", "strict", "ai-agent", "cicd".
func WithDefaults(ruleset string) (*Clawdstrike, error) {
	eng, err := engine.FromRuleset(ruleset)
	if err != nil {
		return nil, err
	}
	return &Clawdstrike{engine: eng}, nil
}

// FromEngine wraps an existing HushEngine in a Clawdstrike facade.
func FromEngine(eng *engine.HushEngine) *Clawdstrike {
	return &Clawdstrike{engine: eng}
}

func (c *Clawdstrike) Engine() *engine.HushEngine {
	return c.engine
}

func (c *Clawdstrike) Check(action guards.GuardAction) Decision {
	result := c.engine.CheckAction(action, nil)
	return guards.DecisionFromResult(result)
}

func (c *Clawdstrike) CheckWithContext(action guards.GuardAction, ctx *guards.GuardContext) Decision {
	result := c.engine.CheckAction(action, ctx)
	return guards.DecisionFromResult(result)
}

func (c *Clawdstrike) CheckFileAccess(path string) Decision {
	return guards.DecisionFromResult(c.engine.CheckFileAccess(path))
}

func (c *Clawdstrike) CheckFileWrite(path string, content []byte) Decision {
	return guards.DecisionFromResult(c.engine.CheckFileWrite(path, content))
}

func (c *Clawdstrike) CheckEgress(host string, port int) Decision {
	return guards.DecisionFromResult(c.engine.CheckEgress(host, port))
}

func (c *Clawdstrike) CheckShell(cmd string) Decision {
	return guards.DecisionFromResult(c.engine.CheckShell(cmd))
}

func (c *Clawdstrike) CheckMcpTool(name string, args interface{}) Decision {
	return guards.DecisionFromResult(c.engine.CheckMcpTool(name, args))
}

func (c *Clawdstrike) CheckPatch(file, diff string) Decision {
	return guards.DecisionFromResult(c.engine.CheckPatch(file, diff))
}

func (c *Clawdstrike) CheckUntrustedText(text string) Decision {
	return guards.DecisionFromResult(c.engine.CheckUntrustedText(text))
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
	return session.NewSession(c.engine, sopts)
}
