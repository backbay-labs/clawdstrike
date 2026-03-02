package guards

import (
	"encoding/json"
	"fmt"

	"github.com/backbay/clawdstrike-go/policy"
)

// Default MCP tool configuration values.
const DefaultMaxArgsSize = 1048576 // 1MB

// DefaultBlockedTools are blocked by default.
var DefaultBlockedTools = []string{
	"shell_exec",
	"run_command",
	"raw_file_write",
	"raw_file_delete",
}

// DefaultRequireConfirmationTools require confirmation by default.
var DefaultRequireConfirmationTools = []string{
	"file_write",
	"file_delete",
	"git_push",
}

// ToolDecision is the decision for a tool invocation.
type ToolDecision int

const (
	ToolAllow               ToolDecision = iota
	ToolBlock
	ToolRequireConfirmation
)

func (d ToolDecision) String() string {
	switch d {
	case ToolAllow:
		return "allow"
	case ToolBlock:
		return "block"
	case ToolRequireConfirmation:
		return "require_confirmation"
	default:
		return "unknown"
	}
}

// McpToolGuard restricts MCP tool invocations.
type McpToolGuard struct {
	allow               map[string]bool
	block               map[string]bool
	requireConfirmation map[string]bool
	defaultAction       string
	maxArgsSize         int
}

// NewMcpToolGuard creates a guard with the given config. Nil config uses defaults.
func NewMcpToolGuard(cfg *policy.McpToolConfig) *McpToolGuard {
	g := &McpToolGuard{
		defaultAction: "allow",
		maxArgsSize:   DefaultMaxArgsSize,
	}

	allowList := []string(nil)
	blockList := DefaultBlockedTools
	confirmList := DefaultRequireConfirmationTools

	if cfg != nil {
		allowList = cfg.Allow
		if cfg.Block != nil {
			blockList = cfg.Block
		}
		if cfg.RequireConfirmation != nil {
			confirmList = cfg.RequireConfirmation
		}
		if cfg.DefaultAction != "" {
			// Validate default_action; fail-closed to "block" for invalid values.
			if cfg.DefaultAction == "allow" || cfg.DefaultAction == "block" {
				g.defaultAction = cfg.DefaultAction
			} else {
				g.defaultAction = "block"
			}
		}
		if cfg.MaxArgsSize > 0 {
			g.maxArgsSize = cfg.MaxArgsSize
		}
	}

	g.allow = toSet(allowList)
	g.block = toSet(blockList)
	g.requireConfirmation = toSet(confirmList)

	return g
}

func toSet(items []string) map[string]bool {
	m := make(map[string]bool, len(items))
	for _, item := range items {
		m[item] = true
	}
	return m
}

func (g *McpToolGuard) Name() string { return "mcp_tool" }

func (g *McpToolGuard) Handles(action GuardAction) bool {
	return action.Type == "mcp_tool"
}

func (g *McpToolGuard) Check(action GuardAction, ctx *GuardContext) GuardResult {
	toolName := action.ToolName

	// Check args size (fail-closed: marshal error blocks)
	if action.ToolArgs != nil {
		data, err := json.Marshal(action.ToolArgs)
		if err != nil {
			return Block(g.Name(), Error,
				fmt.Sprintf("failed to serialize tool args: %v", err))
		}
		if len(data) > g.maxArgsSize {
			return Block(g.Name(), Error,
				fmt.Sprintf("tool %q args size %d exceeds max %d", toolName, len(data), g.maxArgsSize))
		}
	}

	decision := g.Decide(toolName)

	switch decision {
	case ToolBlock:
		return Block(g.Name(), Error,
			fmt.Sprintf("tool %q is blocked", toolName))
	case ToolRequireConfirmation:
		return Block(g.Name(), Warning,
			fmt.Sprintf("tool %q requires confirmation", toolName)).
			WithDetails(map[string]interface{}{
				"decision": "require_confirmation",
			})
	default:
		return Allow(g.Name())
	}
}

// Decide returns the decision for a tool name.
func (g *McpToolGuard) Decide(name string) ToolDecision {
	if g.block[name] {
		return ToolBlock
	}
	if g.allow[name] {
		return ToolAllow
	}
	if g.requireConfirmation[name] {
		return ToolRequireConfirmation
	}
	if g.defaultAction == "block" {
		return ToolBlock
	}
	return ToolAllow
}
