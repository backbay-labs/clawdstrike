// Package adapter provides the ToolInterceptor interface and supporting types
// for integrating Clawdstrike into AI agent frameworks.
package adapter

import (
	"context"
	"time"

	"github.com/backbay/clawdstrike-go/guards"
)

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
	Proceed            bool
	ModifiedParameters interface{}
	Decision           *guards.Decision
	Duration           time.Duration
}

// ProcessedOutput is returned by AfterExecute.
type ProcessedOutput struct {
	Output     interface{}
	Modified   bool
	Redactions []string
}
