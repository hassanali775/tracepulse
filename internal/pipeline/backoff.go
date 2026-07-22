package pipeline

import (
	"context"
	"math"
	"math/rand"
	"sync"
	"time"
)

// BackoffStrategy computes backoff sleep duration per retry attempt.
type BackoffStrategy interface {
	Duration(attempt int) time.Duration
}

// FullJitterBackoff implements AWS Full Jitter: Sleep = rand(0, min(maxDuration, baseDuration * 2^attempt))
type FullJitterBackoff struct {
	BaseDuration time.Duration
	MaxDuration  time.Duration
	mu           sync.Mutex
	rng          *rand.Rand
}

func NewFullJitterBackoff(baseDuration, maxDuration time.Duration) *FullJitterBackoff {
	if baseDuration <= 0 {
		baseDuration = 100 * time.Millisecond
	}
	if maxDuration <= 0 {
		maxDuration = 10 * time.Second
	}
	return &FullJitterBackoff{
		BaseDuration: baseDuration,
		MaxDuration:  maxDuration,
		rng:          rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

func (b *FullJitterBackoff) Duration(attempt int) time.Duration {
	if attempt < 0 {
		attempt = 0
	}

	temp := float64(b.BaseDuration) * math.Pow(2, float64(attempt))
	if temp > float64(b.MaxDuration) || temp < 0 {
		temp = float64(b.MaxDuration)
	}

	b.mu.Lock()
	sleep := time.Duration(b.rng.Float64() * temp)
	b.mu.Unlock()

	return sleep
}

// RetryOptions configures execution retries.
type RetryOptions struct {
	MaxAttempts int
	Backoff     BackoffStrategy
	IsRetryable func(error) bool
}

// Retry executes fn with exponential backoff retries until success, max attempts reached,
// or context cancellation.
func Retry(ctx context.Context, opts RetryOptions, fn func() error) error {
	if opts.MaxAttempts <= 0 {
		opts.MaxAttempts = 3
	}
	if opts.Backoff == nil {
		opts.Backoff = NewFullJitterBackoff(100*time.Millisecond, 5*time.Second)
	}

	var lastErr error
	for attempt := 0; attempt < opts.MaxAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}

		lastErr = fn()
		if lastErr == nil {
			return nil
		}

		if opts.IsRetryable != nil && !opts.IsRetryable(lastErr) {
			return lastErr
		}

		if attempt == opts.MaxAttempts-1 {
			break
		}

		sleep := opts.Backoff.Duration(attempt)
		select {
		case <-time.After(sleep):
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	return lastErr
}
