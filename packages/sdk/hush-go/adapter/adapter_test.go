package adapter

import (
	"context"
	"errors"
	"testing"

	"github.com/backbay/clawdstrike-go/engine"
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
	if result.Decision.Status != "allow" {
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
	if result.Decision.Status != "deny" {
		t.Errorf("expected deny, got %s", result.Decision.Status)
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
	decision := &Decision{Status: "allow", Guard: "test"}
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
