package async_test

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/backbay/clawdstrike-go/async"
)

// slowGuard simulates a guard that takes time to execute.
type slowGuard struct {
	name     string
	duration time.Duration
	result   interface{}
	err      error
	calls    atomic.Int32
}

func (g *slowGuard) Name() string { return g.name }

func (g *slowGuard) Check(ctx context.Context, _ interface{}, _ interface{}) (interface{}, error) {
	g.calls.Add(1)
	select {
	case <-time.After(g.duration):
		return g.result, g.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func TestAsyncRuntime_ConcurrentExecution(t *testing.T) {
	config := async.DefaultAsyncGuardConfig()
	config.Timeout = 2 * time.Second
	runtime := async.NewAsyncGuardRuntime(config)

	g1 := &slowGuard{name: "guard-1", duration: 50 * time.Millisecond, result: "ok-1"}
	g2 := &slowGuard{name: "guard-2", duration: 50 * time.Millisecond, result: "ok-2"}
	g3 := &slowGuard{name: "guard-3", duration: 50 * time.Millisecond, result: "ok-3"}

	runtime.AddGuard(g1)
	runtime.AddGuard(g2)
	runtime.AddGuard(g3)

	start := time.Now()
	results, err := runtime.CheckAll(context.Background(), nil, nil)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(results))
	}

	// If run concurrently, total time should be close to 50ms, not 150ms.
	if elapsed > 300*time.Millisecond {
		t.Errorf("guards appear to run sequentially: %v elapsed", elapsed)
	}

	for _, r := range results {
		if r.Err != nil {
			t.Errorf("guard %s failed: %v", r.Guard, r.Err)
		}
	}
}

func TestAsyncRuntime_Timeout(t *testing.T) {
	config := async.DefaultAsyncGuardConfig()
	config.Timeout = 100 * time.Millisecond
	config.MaxRetries = 0
	runtime := async.NewAsyncGuardRuntime(config)

	slow := &slowGuard{name: "slow", duration: 5 * time.Second, result: "never"}
	runtime.AddGuard(slow)

	results, err := runtime.CheckAll(context.Background(), nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Err == nil {
		t.Fatal("expected timeout error, got nil")
	}
}

func TestAsyncRuntime_CircuitBreaker(t *testing.T) {
	config := async.DefaultAsyncGuardConfig()
	config.Timeout = 2 * time.Second
	config.MaxRetries = 0
	config.CircuitBreaker = &async.CircuitBreakerConfig{
		FailureThreshold: 2,
		ResetTimeout:     1 * time.Second,
	}
	runtime := async.NewAsyncGuardRuntime(config)

	failing := &slowGuard{
		name:     "failing",
		duration: 1 * time.Millisecond,
		err:      errors.New("always fails"),
	}
	runtime.AddGuard(failing)

	// First two calls should actually call the guard (and fail).
	for i := 0; i < 2; i++ {
		results, _ := runtime.CheckAll(context.Background(), nil, nil)
		if results[0].Err == nil {
			t.Fatalf("call %d: expected error", i)
		}
	}

	// Third call: circuit should be open, guard should not be called.
	callsBefore := failing.calls.Load()
	results, _ := runtime.CheckAll(context.Background(), nil, nil)
	callsAfter := failing.calls.Load()

	if results[0].Err == nil {
		t.Fatal("expected circuit breaker error")
	}
	if callsAfter != callsBefore {
		t.Error("guard was called despite circuit breaker being open")
	}
}

func TestAsyncRuntime_NoGuards(t *testing.T) {
	config := async.DefaultAsyncGuardConfig()
	runtime := async.NewAsyncGuardRuntime(config)

	results, err := runtime.CheckAll(context.Background(), nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if results != nil {
		t.Fatalf("expected nil results for empty runtime, got %v", results)
	}
}
