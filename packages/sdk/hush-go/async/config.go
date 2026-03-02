// Package async provides a concurrent guard runtime with circuit breaker
// and rate limiting support.
package async

import "time"

// AsyncGuardConfig controls the behavior of the async guard runtime.
type AsyncGuardConfig struct {
	Timeout        time.Duration
	MaxRetries     int
	BackoffBase    time.Duration
	MaxConcurrency int
	CircuitBreaker *CircuitBreakerConfig
	RateLimit      *RateLimitConfig
}

// CircuitBreakerConfig controls the circuit breaker behavior for guards.
type CircuitBreakerConfig struct {
	FailureThreshold int
	ResetTimeout     time.Duration
}

// RateLimitConfig controls the rate limiter for guard invocations.
type RateLimitConfig struct {
	RequestsPerSecond float64
	BurstSize         int
}

// DefaultAsyncGuardConfig returns a sensible default configuration.
func DefaultAsyncGuardConfig() AsyncGuardConfig {
	return AsyncGuardConfig{
		Timeout:        5 * time.Second,
		MaxRetries:     2,
		BackoffBase:    100 * time.Millisecond,
		MaxConcurrency: 10,
	}
}
