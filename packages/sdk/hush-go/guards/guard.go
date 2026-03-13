// Package guards implements the 7 built-in Clawdstrike security guards.
package guards

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// Severity levels for guard results.
type Severity int

const (
	Info Severity = iota
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

func (s Severity) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}

// parseSeverityString is the shared implementation for all severity parsing.
func parseSeverityString(s string) (Severity, error) {
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

func (s *Severity) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return err
	}
	sev, err := parseSeverityString(str)
	if err != nil {
		return err
	}
	*s = sev
	return nil
}

func (s Severity) MarshalYAML() (interface{}, error) {
	return s.String(), nil
}

func (s *Severity) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var str string
	if err := unmarshal(&str); err != nil {
		return err
	}
	sev, err := parseSeverityString(str)
	if err != nil {
		return err
	}
	*s = sev
	return nil
}

func ParseSeverity(s string) (Severity, error) {
	return parseSeverityString(s)
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

func FileAccess(path string) GuardAction {
	return GuardAction{Type: "file_access", Path: path}
}

func FileWrite(path string, content []byte) GuardAction {
	return GuardAction{Type: "file_write", Path: path, Content: content}
}

func NetworkEgress(host string, port int) GuardAction {
	return GuardAction{Type: "network_egress", Host: host, Port: port}
}

func ShellCommand(cmd string) GuardAction {
	return GuardAction{Type: "shell_command", Command: cmd}
}

func McpTool(name string, args interface{}) GuardAction {
	return GuardAction{Type: "mcp_tool", ToolName: name, ToolArgs: args}
}

func Patch(file, diff string) GuardAction {
	return GuardAction{Type: "patch", Path: file, Diff: diff}
}

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

func Allow(guard string) GuardResult {
	return GuardResult{Allowed: true, Guard: guard, Severity: Info}
}

func Block(guard string, severity Severity, message string) GuardResult {
	return GuardResult{Allowed: false, Guard: guard, Severity: severity, Message: message}
}

func Warn(guard string, message string) GuardResult {
	return GuardResult{Allowed: true, Guard: guard, Severity: Warning, Message: message}
}

func (r GuardResult) WithDetails(details interface{}) GuardResult {
	r.Details = details
	return r
}

// GuardContext provides execution context to guards.
type GuardContext struct {
	Cwd       string                 `json:"cwd,omitempty"`
	SessionID string                 `json:"session_id,omitempty"`
	AgentID   string                 `json:"agent_id,omitempty"`
	Context   context.Context        `json:"-"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
	Origin    *OriginContext         `json:"origin,omitempty"`
}

func NewContext() *GuardContext {
	return &GuardContext{
		Metadata: make(map[string]interface{}),
	}
}

func (c *GuardContext) WithCwd(cwd string) *GuardContext {
	c.Cwd = cwd
	return c
}

func (c *GuardContext) WithSessionID(id string) *GuardContext {
	c.SessionID = id
	return c
}

func (c *GuardContext) WithAgentID(id string) *GuardContext {
	c.AgentID = id
	return c
}

func (c *GuardContext) WithContext(ctx context.Context) *GuardContext {
	c.Context = ctx
	return c
}

func (c *GuardContext) WithOrigin(origin *OriginContext) *GuardContext {
	c.Origin = origin
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

// DecisionStatus represents the outcome of a security check.
type DecisionStatus string

const (
	StatusAllow DecisionStatus = "allow"
	StatusWarn  DecisionStatus = "warn"
	StatusDeny  DecisionStatus = "deny"
)

// Decision is the user-facing result of a Clawdstrike security check.
type Decision struct {
	Status   DecisionStatus
	Guard    string
	Severity string
	Message  string
	Details  interface{}
}

func DecisionFromResult(r GuardResult) Decision {
	status := StatusAllow
	if !r.Allowed {
		status = StatusDeny
	} else if r.Severity >= Warning {
		status = StatusWarn
	}
	return Decision{
		Status:   status,
		Guard:    r.Guard,
		Severity: r.Severity.String(),
		Message:  r.Message,
		Details:  r.Details,
	}
}
