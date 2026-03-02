// Package guards implements the 7 built-in Clawdstrike security guards.
package guards

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Severity levels for guard results.
type Severity int

const (
	Info     Severity = iota
	Warning
	Error
	Critical
)

var severityNames = [...]string{"info", "warning", "error", "critical"}

func (s Severity) String() string {
	if int(s) < len(severityNames) {
		return severityNames[s]
	}
	return fmt.Sprintf("severity(%d)", int(s))
}

// MarshalJSON encodes severity as a lowercase string.
func (s Severity) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}

// UnmarshalJSON decodes severity from a lowercase string.
func (s *Severity) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return err
	}
	switch strings.ToLower(str) {
	case "info":
		*s = Info
	case "warning":
		*s = Warning
	case "error":
		*s = Error
	case "critical":
		*s = Critical
	default:
		return fmt.Errorf("unknown severity %q", str)
	}
	return nil
}

// MarshalYAML encodes severity as a lowercase string for YAML.
func (s Severity) MarshalYAML() (interface{}, error) {
	return s.String(), nil
}

// UnmarshalYAML decodes severity from a lowercase string for YAML.
func (s *Severity) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var str string
	if err := unmarshal(&str); err != nil {
		return err
	}
	switch strings.ToLower(str) {
	case "info":
		*s = Info
	case "warning":
		*s = Warning
	case "error":
		*s = Error
	case "critical":
		*s = Critical
	default:
		return fmt.Errorf("unknown severity %q", str)
	}
	return nil
}

// ParseSeverity parses a severity string.
func ParseSeverity(s string) (Severity, error) {
	switch strings.ToLower(s) {
	case "info":
		return Info, nil
	case "warning":
		return Warning, nil
	case "error":
		return Error, nil
	case "critical":
		return Critical, nil
	default:
		return Error, fmt.Errorf("unknown severity %q", s)
	}
}

// GuardAction describes an action to be checked by guards.
type GuardAction struct {
	Type       string      `json:"type"`
	Path       string      `json:"path,omitempty"`
	Content    []byte      `json:"content,omitempty"`
	Host       string      `json:"host,omitempty"`
	Port       int         `json:"port,omitempty"`
	Command    string      `json:"command,omitempty"`
	ToolName   string      `json:"tool_name,omitempty"`
	ToolArgs   interface{} `json:"tool_args,omitempty"`
	Diff       string      `json:"diff,omitempty"`
	CustomType string      `json:"custom_type,omitempty"`
	CustomData interface{} `json:"custom_data,omitempty"`
}

// Factory methods for creating GuardAction values.

// FileAccess creates a file access action.
func FileAccess(path string) GuardAction {
	return GuardAction{Type: "file_access", Path: path}
}

// FileWrite creates a file write action.
func FileWrite(path string, content []byte) GuardAction {
	return GuardAction{Type: "file_write", Path: path, Content: content}
}

// NetworkEgress creates a network egress action.
func NetworkEgress(host string, port int) GuardAction {
	return GuardAction{Type: "network_egress", Host: host, Port: port}
}

// ShellCommand creates a shell command action.
func ShellCommand(cmd string) GuardAction {
	return GuardAction{Type: "shell_command", Command: cmd}
}

// McpTool creates an MCP tool action.
func McpTool(name string, args interface{}) GuardAction {
	return GuardAction{Type: "mcp_tool", ToolName: name, ToolArgs: args}
}

// Patch creates a patch action.
func Patch(file, diff string) GuardAction {
	return GuardAction{Type: "patch", Path: file, Diff: diff}
}

// Custom creates a custom action.
func Custom(customType string, data interface{}) GuardAction {
	return GuardAction{Type: "custom", CustomType: customType, CustomData: data}
}

// GuardResult is the outcome of a guard check.
type GuardResult struct {
	Allowed  bool        `json:"allowed"`
	Guard    string      `json:"guard"`
	Severity Severity    `json:"severity"`
	Message  string      `json:"message,omitempty"`
	Details  interface{} `json:"details,omitempty"`
}

// Allow creates an allowing result.
func Allow(guard string) GuardResult {
	return GuardResult{Allowed: true, Guard: guard, Severity: Info}
}

// Block creates a blocking result.
func Block(guard string, severity Severity, message string) GuardResult {
	return GuardResult{Allowed: false, Guard: guard, Severity: severity, Message: message}
}

// Warn creates a warning result (allowed but flagged).
func Warn(guard string, message string) GuardResult {
	return GuardResult{Allowed: true, Guard: guard, Severity: Warning, Message: message}
}

// WithDetails adds details to a GuardResult.
func (r GuardResult) WithDetails(details interface{}) GuardResult {
	r.Details = details
	return r
}

// GuardContext provides execution context to guards.
type GuardContext struct {
	Cwd       string                 `json:"cwd,omitempty"`
	SessionID string                 `json:"session_id,omitempty"`
	AgentID   string                 `json:"agent_id,omitempty"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

// NewContext creates a new empty guard context.
func NewContext() *GuardContext {
	return &GuardContext{
		Metadata: make(map[string]interface{}),
	}
}

// WithCwd sets the working directory.
func (c *GuardContext) WithCwd(cwd string) *GuardContext {
	c.Cwd = cwd
	return c
}

// WithSessionID sets the session ID.
func (c *GuardContext) WithSessionID(id string) *GuardContext {
	c.SessionID = id
	return c
}

// WithAgentID sets the agent ID.
func (c *GuardContext) WithAgentID(id string) *GuardContext {
	c.AgentID = id
	return c
}

// Guard is the interface that all guards implement.
type Guard interface {
	// Name returns the guard's unique name.
	Name() string
	// Handles reports whether this guard applies to the given action.
	Handles(action GuardAction) bool
	// Check evaluates the action against this guard's rules.
	Check(action GuardAction, ctx *GuardContext) GuardResult
}
