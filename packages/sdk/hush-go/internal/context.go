package internal

import (
	"context"
	"time"
)

// SleepWithContext waits for d to elapse or for ctx to be canceled.
// Returns true when the full duration elapsed, false when canceled.
func SleepWithContext(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return true
	}
	if ctx == nil {
		ctx = context.Background()
	}

	timer := time.NewTimer(d)
	defer timer.Stop()

	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		return false
	}
}
