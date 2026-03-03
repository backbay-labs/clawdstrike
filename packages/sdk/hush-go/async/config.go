// Package async provides a concurrent guard runtime with circuit breaker
// and rate limiting support.
package async

import (
	"errors"
	"time"
)

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

// Validate checks that the configuration values are reasonable.
func (c AsyncGuardConfig) Validate() error {
	if c.Timeout <= 0 {
		return errors.New("async: Timeout must be positive")
	}
	if c.MaxRetries < 0 {
		return errors.New("async: MaxRetries must be non-negative")
	}
	if c.BackoffBase < 0 {
		return errors.New("async: BackoffBase must be non-negative")
	}
	if c.CircuitBreaker != nil {
		if c.CircuitBreaker.FailureThreshold <= 0 {
			return errors.New("async: CircuitBreaker.FailureThreshold must be positive")
		}
		if c.CircuitBreaker.ResetTimeout <= 0 {
			return errors.New("async: CircuitBreaker.ResetTimeout must be positive")
		}
	}
	if c.RateLimit != nil {
		if c.RateLimit.RequestsPerSecond <= 0 {
			return errors.New("async: RateLimit.RequestsPerSecond must be positive")
		}
		if c.RateLimit.BurstSize <= 0 {
			return errors.New("async: RateLimit.BurstSize must be positive")
		}
	}
	return nil
}

func DefaultAsyncGuardConfig() AsyncGuardConfig {
	return AsyncGuardConfig{
		Timeout:        5 * time.Second,
		MaxRetries:     2,
		BackoffBase:    100 * time.Millisecond,
		MaxConcurrency: 10,
	}
}
