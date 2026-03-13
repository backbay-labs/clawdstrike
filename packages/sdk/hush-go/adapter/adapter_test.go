package adapter

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/backbay-labs/clawdstrike-go/engine"
	"github.com/backbay-labs/clawdstrike-go/guards"
)

func TestBaseToolInterceptorAllow(t *testing.T) {
	eng, err := engine.NewBuilder().Build()
	if err != nil {
		t.Fatal(err)
	}

	logger := NewInMemoryAuditLogger()
	secCtx := NewSecurityContext("test-session")
	interceptor := NewBaseToolInterceptor(eng, logger, secCtx)

	result, err := interceptor.BeforeExecute(context.Background(), "read_file", map[string]interface{}{"path": "/tmp/test"})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Proceed {
		t.Error("expected Proceed=true for engine with no guards")
	}
	if result.Decision.Status != guards.StatusAllow {
		t.Errorf("expected allow, got %s", result.Decision.Status)
	}
	if secCtx.CheckCount.Load() != 1 {
		t.Errorf("expected CheckCount=1, got %d", secCtx.CheckCount.Load())
	}
}

func TestBaseToolInterceptorDenyOnConfigError(t *testing.T) {
	eng, err := engine.NewBuilder().Build()
	if err != nil {
		t.Fatal(err)
	}
	eng.SetConfigError(errors.New("bad config"))

	logger := NewInMemoryAuditLogger()
	secCtx := NewSecurityContext("test-session")
	interceptor := NewBaseToolInterceptor(eng, logger, secCtx)

	result, err := interceptor.BeforeExecute(context.Background(), "write_file", nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.Proceed {
		t.Error("expected Proceed=false when engine has config error")
	}
	if result.Decision.Status != guards.StatusDeny {
		t.Errorf("expected deny, got %s", result.Decision.Status)
	}
	if secCtx.ViolationCount.Load() != 1 {
		t.Errorf("expected ViolationCount=1, got %d", secCtx.ViolationCount.Load())
	}
}

func TestBaseToolInterceptorNilEngineFailsClosed(t *testing.T) {
	logger := NewInMemoryAuditLogger()
	secCtx := NewSecurityContext("test-session")
	interceptor := NewBaseToolInterceptor(nil, logger, secCtx)

	result, err := interceptor.BeforeExecute(context.Background(), "write_file", nil)
	if err != nil {
		t.Fatal(err)
	}
	if result == nil {
		t.Fatal("expected non-nil intercept result")
	}
	if result.Proceed {
		t.Error("expected Proceed=false when engine is nil")
	}
	if result.Decision == nil || result.Decision.Status != guards.StatusDeny {
		t.Fatalf("expected deny decision, got %#v", result.Decision)
	}
	if secCtx.CheckCount.Load() != 1 {
		t.Errorf("expected CheckCount=1, got %d", secCtx.CheckCount.Load())
	}
	if secCtx.ViolationCount.Load() != 1 {
		t.Errorf("expected ViolationCount=1, got %d", secCtx.ViolationCount.Load())
	}
}

func TestBaseToolInterceptorAfterExecute(t *testing.T) {
	eng, err := engine.NewBuilder().Build()
	if err != nil {
		t.Fatal(err)
	}

	interceptor := NewBaseToolInterceptor(eng, nil, nil)
	output, err := interceptor.AfterExecute(context.Background(), "read_file", "file contents")
	if err != nil {
		t.Fatal(err)
	}
	if output.Modified {
		t.Error("expected Modified=false for base interceptor")
	}
	if output.Output != "file contents" {
		t.Errorf("expected passthrough output, got %v", output.Output)
	}
}

func TestBaseToolInterceptorOnError(t *testing.T) {
	eng, err := engine.NewBuilder().Build()
	if err != nil {
		t.Fatal(err)
	}

	logger := NewInMemoryAuditLogger()
	secCtx := NewSecurityContext("test-session")
	interceptor := NewBaseToolInterceptor(eng, logger, secCtx)

	origErr := errors.New("tool failed")
	retErr := interceptor.OnError(context.Background(), "run_cmd", origErr)
	if retErr != origErr {
		t.Error("expected original error to be returned")
	}

	events, _ := logger.GetSessionEvents("test-session")
	if len(events) != 1 {
		t.Errorf("expected 1 audit event, got %d", len(events))
	}
}

func TestInMemoryAuditLoggerExport(t *testing.T) {
	logger := NewInMemoryAuditLogger()
	decision := &guards.Decision{Status: guards.StatusAllow, Guard: "test"}
	event := NewAuditEvent("check", "my_tool", decision)
	event.SessionID = "sess-1"

	if err := logger.Log(event); err != nil {
		t.Fatal(err)
	}

	data, err := logger.Export("json")
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 {
		t.Error("expected non-empty JSON export")
	}

	_, err = logger.Export("xml")
	if err == nil {
		t.Error("expected error for unsupported format")
	}
}

func TestBeforeExecuteContextCancellation(t *testing.T) {
	eng, err := engine.NewBuilder().Build()
	if err != nil {
		t.Fatal(err)
	}

	interceptor := NewBaseToolInterceptor(eng, nil, nil)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	result, err := interceptor.BeforeExecute(ctx, "read_file", nil)
	if err == nil {
		t.Fatal("expected error from cancelled context")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got %v", err)
	}
	if result != nil {
		t.Error("expected nil result on context cancellation")
	}
}

type contextAwareGuard struct {
	started chan struct{}
}

func (g *contextAwareGuard) Name() string { return "context_aware" }

func (g *contextAwareGuard) Handles(_ guards.GuardAction) bool { return true }

func (g *contextAwareGuard) Check(_ guards.GuardAction, ctx *guards.GuardContext) guards.GuardResult {
	if ctx == nil || ctx.Context == nil {
		return guards.Block(g.Name(), guards.Critical, "missing guard context")
	}
	select {
	case <-g.started:
	default:
		close(g.started)
	}
	<-ctx.Context.Done()
	return guards.Block(g.Name(), guards.Critical, ctx.Context.Err().Error())
}

func TestBeforeExecutePropagatesContextToGuards(t *testing.T) {
	guard := &contextAwareGuard{started: make(chan struct{})}
	eng, err := engine.NewBuilder().WithGuard(guard).Build()
	if err != nil {
		t.Fatal(err)
	}

	interceptor := NewBaseToolInterceptor(eng, nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	type outcome struct {
		result *InterceptResult
		err    error
	}
	done := make(chan outcome, 1)
	go func() {
		result, err := interceptor.BeforeExecute(ctx, "read_file", nil)
		done <- outcome{result: result, err: err}
	}()

	select {
	case <-guard.started:
	case <-time.After(250 * time.Millisecond):
		t.Fatal("guard did not start")
	}

	cancel()

	select {
	case out := <-done:
		if out.err != nil {
			t.Fatalf("BeforeExecute returned error: %v", out.err)
		}
		if out.result == nil {
			t.Fatal("expected non-nil intercept result")
		}
		if out.result.Proceed {
			t.Fatal("expected proceed=false after context cancellation")
		}
		if out.result.Decision == nil || !strings.Contains(out.result.Decision.Message, "canceled") {
			t.Fatalf("expected cancellation message, got %#v", out.result.Decision)
		}
	case <-time.After(250 * time.Millisecond):
		t.Fatal("BeforeExecute did not finish after context cancellation")
	}
}

type originAwareGuard struct {
	origin *guards.OriginContext
}

func (g *originAwareGuard) Name() string { return "origin_aware" }

func (g *originAwareGuard) Handles(_ guards.GuardAction) bool { return true }

func (g *originAwareGuard) Check(_ guards.GuardAction, ctx *guards.GuardContext) guards.GuardResult {
	if ctx != nil {
		g.origin = ctx.Origin
	}
	return guards.Allow(g.Name())
}

func TestBeforeExecuteFailsClosedForOriginAwareLocalChecks(t *testing.T) {
	guard := &originAwareGuard{}
	eng, err := engine.NewBuilder().WithGuard(guard).Build()
	if err != nil {
		t.Fatal(err)
	}

	origin := guards.NewOriginContext(guards.OriginProviderSlack).WithTenantID("T123")
	secCtx := NewSecurityContext("test-session").WithOrigin(origin)
	interceptor := NewBaseToolInterceptor(eng, nil, secCtx)

	result, err := interceptor.BeforeExecute(context.Background(), "read_file", map[string]interface{}{"path": "/tmp/test"})
	if err != nil {
		t.Fatal(err)
	}
	if result.Proceed {
		t.Fatal("expected proceed=false for origin-aware local check")
	}
	if result.Decision == nil || result.Decision.Status != guards.StatusDeny {
		t.Fatalf("expected deny decision, got %#v", result.Decision)
	}
	if result.Decision.Message != guards.LocalOriginUnsupportedMessage {
		t.Fatalf("expected local origin unsupported message, got %q", result.Decision.Message)
	}
	if guard.origin != nil {
		t.Fatal("expected local fail-closed gate to stop before invoking guards")
	}
}

func TestSecurityContextThreadSafety(t *testing.T) {
	secCtx := NewSecurityContext("test")
	done := make(chan struct{})

	go func() {
		for i := 0; i < 100; i++ {
			secCtx.RecordCheck()
			secCtx.RecordViolation("tool")
		}
		close(done)
	}()

	for i := 0; i < 100; i++ {
		secCtx.RecordCheck()
		secCtx.GetBlockedTools()
	}
	<-done

	if secCtx.CheckCount.Load() != 200 {
		t.Errorf("expected 200 checks, got %d", secCtx.CheckCount.Load())
	}
}
