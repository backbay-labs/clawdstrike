// Package adapter provides the ToolInterceptor interface and supporting types
// for integrating Clawdstrike into AI agent frameworks.
package adapter

import (
	"context"
	"time"
)

// Decision mirrors the top-level Decision type to avoid import cycles.
type Decision struct {
	Status   string
	Guard    string
	Severity string
	Message  string
	Details  interface{}
}

// ToolInterceptor is the interface for intercepting tool calls in an
// AI agent framework. Implementations wrap around tool execution to
// enforce security policy.
type ToolInterceptor interface {
	// BeforeExecute is called before a tool runs. If the result's Proceed
	// field is false, the tool must not be executed.
	BeforeExecute(ctx context.Context, toolName string, params interface{}) (*InterceptResult, error)

	// AfterExecute is called after a tool runs to inspect/sanitize output.
	AfterExecute(ctx context.Context, toolName string, output interface{}) (*ProcessedOutput, error)

	// OnError is called when a tool execution fails.
	OnError(ctx context.Context, toolName string, err error) error
}

// InterceptResult is returned by BeforeExecute.
type InterceptResult struct {
	// Proceed indicates whether the tool should be executed.
	Proceed bool
	// ModifiedParameters contains parameters after potential sanitization.
	ModifiedParameters interface{}
	// Decision is the security decision that led to this result.
	Decision *Decision
	// Duration is how long the security check took.
	Duration time.Duration
}

// ProcessedOutput is returned by AfterExecute.
type ProcessedOutput struct {
	// Output is the (potentially modified) tool output.
	Output interface{}
	// Modified indicates whether the output was changed.
	Modified bool
	// Redactions lists descriptions of any redacted content.
	Redactions []string
}
