package adapter

import (
	"context"
	"fmt"
	"time"

	"github.com/backbay/clawdstrike-go/engine"
	"github.com/backbay/clawdstrike-go/guards"
)

// BaseToolInterceptor is a default ToolInterceptor implementation that uses
// a HushEngine for security evaluation. Fail-closed: errors produce deny.
type BaseToolInterceptor struct {
	engine  *engine.HushEngine
	logger  AuditLogger
	secCtx  *SecurityContext
}

// NewBaseToolInterceptor creates a new interceptor backed by a HushEngine.
func NewBaseToolInterceptor(eng *engine.HushEngine, logger AuditLogger, secCtx *SecurityContext) *BaseToolInterceptor {
	return &BaseToolInterceptor{
		engine: eng,
		logger: logger,
		secCtx: secCtx,
	}
}

// BeforeExecute checks whether a tool invocation is allowed. Fail-closed:
// any error during evaluation results in a deny decision.
func (b *BaseToolInterceptor) BeforeExecute(ctx context.Context, toolName string, params interface{}) (*InterceptResult, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	start := time.Now()

	action := guards.McpTool(toolName, toArgsMap(params))
	result := b.engine.CheckAction(action, nil)

	d := guards.DecisionFromResult(result)
	decision := &d
	proceed := result.Allowed

	elapsed := time.Since(start)

	if b.secCtx != nil {
		b.secCtx.RecordCheck()
		if !proceed {
			b.secCtx.RecordViolation(toolName)
		}
	}

	if b.logger != nil {
		event := NewAuditEvent("before_execute", toolName, decision)
		if b.secCtx != nil {
			event.ContextID = b.secCtx.ID
			event.SessionID = b.secCtx.SessionID
		}
		// Best effort: log errors are not propagated (fail-closed already handled).
		_ = b.logger.Log(event)
	}

	return &InterceptResult{
		Proceed:            proceed,
		ModifiedParameters: params,
		Decision:           decision,
		Duration:           elapsed,
	}, nil
}

// AfterExecute processes tool output. The base implementation passes through
// without modification.
func (b *BaseToolInterceptor) AfterExecute(_ context.Context, toolName string, output interface{}) (*ProcessedOutput, error) {
	if b.logger != nil {
		event := NewAuditEvent("after_execute", toolName, nil)
		if b.secCtx != nil {
			event.ContextID = b.secCtx.ID
			event.SessionID = b.secCtx.SessionID
		}
		_ = b.logger.Log(event)
	}

	return &ProcessedOutput{
		Output:   output,
		Modified: false,
	}, nil
}

// OnError handles tool execution errors. Fail-closed: the error is logged
// and returned as-is.
func (b *BaseToolInterceptor) OnError(_ context.Context, toolName string, err error) error {
	decision := &guards.Decision{
		Status:   guards.StatusDeny,
		Guard:    "error_handler",
		Severity: "error",
		Message:  fmt.Sprintf("tool execution error: %v", err),
	}

	if b.logger != nil {
		event := NewAuditEvent("error", toolName, decision)
		if b.secCtx != nil {
			event.ContextID = b.secCtx.ID
			event.SessionID = b.secCtx.SessionID
		}
		_ = b.logger.Log(event)
	}

	return err
}

// toArgsMap converts params to map[string]interface{} on a best-effort basis.
func toArgsMap(params interface{}) map[string]interface{} {
	if params == nil {
		return nil
	}
	if m, ok := params.(map[string]interface{}); ok {
		return m
	}
	return map[string]interface{}{"_raw": params}
}
