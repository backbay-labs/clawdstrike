// Package clawdstrike is the top-level facade for the Clawdstrike Go SDK,
// providing a simple API for runtime security enforcement of AI agents.
package clawdstrike

import (
	"github.com/backbay/clawdstrike-go/engine"
	"github.com/backbay/clawdstrike-go/guards"
	"github.com/backbay/clawdstrike-go/session"
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

// Engine returns the underlying HushEngine.
func (c *Clawdstrike) Engine() *engine.HushEngine {
	return c.engine
}

// Check evaluates a GuardAction and returns a Decision.
func (c *Clawdstrike) Check(action guards.GuardAction) Decision {
	result := c.engine.CheckAction(action, nil)
	return decisionFromGuardResult(result)
}

// CheckWithContext evaluates a GuardAction with context and returns a Decision.
func (c *Clawdstrike) CheckWithContext(action guards.GuardAction, ctx *guards.GuardContext) Decision {
	result := c.engine.CheckAction(action, ctx)
	return decisionFromGuardResult(result)
}

// CheckFileAccess checks whether a file path can be read.
func (c *Clawdstrike) CheckFileAccess(path string) Decision {
	return decisionFromGuardResult(c.engine.CheckFileAccess(path))
}

// CheckFileWrite checks whether content can be written to a file path.
func (c *Clawdstrike) CheckFileWrite(path string, content []byte) Decision {
	return decisionFromGuardResult(c.engine.CheckFileWrite(path, content))
}

// CheckEgress checks whether an outbound network connection is permitted.
func (c *Clawdstrike) CheckEgress(host string, port int) Decision {
	return decisionFromGuardResult(c.engine.CheckEgress(host, port))
}

// CheckShell checks whether a shell command can be executed.
func (c *Clawdstrike) CheckShell(cmd string) Decision {
	return decisionFromGuardResult(c.engine.CheckShell(cmd))
}

// CheckMcpTool checks whether an MCP tool invocation is permitted.
func (c *Clawdstrike) CheckMcpTool(name string, args interface{}) Decision {
	return decisionFromGuardResult(c.engine.CheckMcpTool(name, args))
}

// CheckPatch checks whether a patch can be applied.
func (c *Clawdstrike) CheckPatch(file, diff string) Decision {
	return decisionFromGuardResult(c.engine.CheckPatch(file, diff))
}

// CheckUntrustedText checks text for prompt injection or jailbreak.
func (c *Clawdstrike) CheckUntrustedText(text string) Decision {
	return decisionFromGuardResult(c.engine.CheckUntrustedText(text))
}

// SessionOptions configures a new ClawdstrikeSession.
type SessionOptions struct {
	ID      string
	AgentID string
}

// Session creates a new ClawdstrikeSession for tracking check state over time.
func (c *Clawdstrike) Session(opts SessionOptions) *session.ClawdstrikeSession {
	sopts := session.Options{
		ID:      opts.ID,
		AgentID: opts.AgentID,
	}
	return session.NewSession(c.engine, sopts)
}
