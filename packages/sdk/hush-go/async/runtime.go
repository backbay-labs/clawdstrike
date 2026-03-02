package async

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// AsyncGuard is a guard that performs potentially slow or external checks.
type AsyncGuard interface {
	Name() string
	Check(ctx context.Context, action interface{}, guardCtx interface{}) (interface{}, error)
}

// GuardResult holds the outcome of a single guard check.
type GuardResult struct {
	Guard  string
	Result interface{}
	Err    error
}

// AsyncGuardRuntime executes guards concurrently with timeout, circuit breaker,
// and rate limiting support.
type AsyncGuardRuntime struct {
	guards   []AsyncGuard
	config   AsyncGuardConfig
	breakers map[string]*circuitBreaker
	limiter  *rateLimiter
	mu       sync.RWMutex
}

func NewAsyncGuardRuntime(config AsyncGuardConfig) *AsyncGuardRuntime {
	r := &AsyncGuardRuntime{
		config:   config,
		breakers: make(map[string]*circuitBreaker),
	}
	if config.RateLimit != nil {
		r.limiter = newRateLimiter(config.RateLimit.RequestsPerSecond, config.RateLimit.BurstSize)
	}
	return r
}

func (r *AsyncGuardRuntime) AddGuard(g AsyncGuard) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.guards = append(r.guards, g)
	if r.config.CircuitBreaker != nil {
		r.breakers[g.Name()] = newCircuitBreaker(
			r.config.CircuitBreaker.FailureThreshold,
			r.config.CircuitBreaker.ResetTimeout,
		)
	}
}

// CheckAll runs all registered guards concurrently and returns their results.
// Fail-closed: any error causes an error result for that guard.
func (r *AsyncGuardRuntime) CheckAll(ctx context.Context, action, guardCtx interface{}) ([]GuardResult, error) {
	r.mu.RLock()
	guards := make([]AsyncGuard, len(r.guards))
	copy(guards, r.guards)
	r.mu.RUnlock()

	if len(guards) == 0 {
		return nil, nil
	}

	// Apply global timeout.
	ctx, cancel := context.WithTimeout(ctx, r.config.Timeout)
	defer cancel()

	// Default MaxConcurrency to number of guards if not set.
	maxConcurrency := r.config.MaxConcurrency
	if maxConcurrency <= 0 {
		maxConcurrency = len(guards)
	}

	// Semaphore for concurrency control.
	sem := make(chan struct{}, maxConcurrency)

	var wg sync.WaitGroup
	results := make([]GuardResult, len(guards))

	for i, g := range guards {
		wg.Add(1)
		go func(idx int, guard AsyncGuard) {
			defer wg.Done()

			// Panic recovery for guard goroutines.
			defer func() {
				if r := recover(); r != nil {
					results[idx] = GuardResult{
						Guard: guard.Name(),
						Err:   fmt.Errorf("guard %q panicked: %v", guard.Name(), r),
					}
				}
			}()

			// Respect context cancellation on semaphore acquire.
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				results[idx] = GuardResult{Guard: guard.Name(), Err: ctx.Err()}
				return
			}

			results[idx] = r.runGuard(ctx, guard, action, guardCtx)
		}(i, g)
	}

	wg.Wait()
	return results, nil
}

func (r *AsyncGuardRuntime) runGuard(ctx context.Context, guard AsyncGuard, action, guardCtx interface{}) GuardResult {
	name := guard.Name()

	// Check circuit breaker.
	r.mu.RLock()
	cb := r.breakers[name]
	r.mu.RUnlock()

	if cb != nil && !cb.allow() {
		return GuardResult{
			Guard: name,
			Err:   fmt.Errorf("circuit breaker open for guard %q", name),
		}
	}

	// Check rate limiter.
	if r.limiter != nil && !r.limiter.allow() {
		return GuardResult{
			Guard: name,
			Err:   fmt.Errorf("rate limit exceeded for guard %q", name),
		}
	}

	// Retry loop.
	var lastErr error
	for attempt := 0; attempt <= r.config.MaxRetries; attempt++ {
		if attempt > 0 {
			backoff := r.config.BackoffBase * time.Duration(1<<uint(attempt-1))
			timer := time.NewTimer(backoff)
			select {
			case <-timer.C:
				// Timer fired, continue with retry.
			case <-ctx.Done():
				timer.Stop()
				return GuardResult{Guard: name, Err: ctx.Err()}
			}
			timer.Stop()
		}

		result, err := guard.Check(ctx, action, guardCtx)
		if err == nil {
			if cb != nil {
				cb.recordSuccess()
			}
			return GuardResult{Guard: name, Result: result}
		}
		lastErr = err
	}

	// All retries exhausted.
	if cb != nil {
		cb.recordFailure()
	}
	return GuardResult{Guard: name, Err: lastErr}
}

// circuitBreaker implements a simple circuit breaker pattern.
type circuitBreaker struct {
	mu               sync.Mutex
	failures         int
	failureThreshold int
	resetTimeout     time.Duration
	lastFailure      time.Time
	open             bool
}

func newCircuitBreaker(threshold int, resetTimeout time.Duration) *circuitBreaker {
	return &circuitBreaker{
		failureThreshold: threshold,
		resetTimeout:     resetTimeout,
	}
}

func (cb *circuitBreaker) allow() bool {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	if !cb.open {
		return true
	}

	// Check if reset timeout has elapsed.
	if time.Since(cb.lastFailure) >= cb.resetTimeout {
		cb.open = false
		cb.failures = 0
		return true
	}
	return false
}

func (cb *circuitBreaker) recordSuccess() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.failures = 0
	cb.open = false
}

func (cb *circuitBreaker) recordFailure() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.failures++
	cb.lastFailure = time.Now()
	if cb.failures >= cb.failureThreshold {
		cb.open = true
	}
}

// rateLimiter implements a simple token bucket rate limiter.
type rateLimiter struct {
	mu         sync.Mutex
	tokens     float64
	maxTokens  float64
	refillRate float64 // tokens per nanosecond
	lastRefill time.Time
}

func newRateLimiter(requestsPerSecond float64, burstSize int) *rateLimiter {
	return &rateLimiter{
		tokens:     float64(burstSize),
		maxTokens:  float64(burstSize),
		refillRate: requestsPerSecond / 1e9, // convert to per-nanosecond
		lastRefill: time.Now(),
	}
}

func (rl *rateLimiter) allow() bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	elapsed := float64(now.Sub(rl.lastRefill).Nanoseconds())
	rl.tokens += elapsed * rl.refillRate
	if rl.tokens > rl.maxTokens {
		rl.tokens = rl.maxTokens
	}
	rl.lastRefill = now

	if rl.tokens >= 1 {
		rl.tokens--
		return true
	}
	return false
}
