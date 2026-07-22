package pipeline

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hassan/tracepulse/internal/domain"
)

func TestDedupStore_SlidingWindowAndEviction(t *testing.T) {
	windowDuration := 100 * time.Millisecond
	cleanupInterval := 50 * time.Millisecond
	ds := NewDedupStore(windowDuration, cleanupInterval)
	defer ds.Close()

	sig := "a1b2c3d4e5f6"

	// First time seen -> novel
	isNovel, count := ds.Allow(sig)
	if !isNovel || count != 1 {
		t.Fatalf("expected (true, 1) on first allow, got (%v, %d)", isNovel, count)
	}

	// Second time seen immediately -> duplicate
	isNovel, count = ds.Allow(sig)
	if isNovel || count != 2 {
		t.Fatalf("expected (false, 2) on second allow, got (%v, %d)", isNovel, count)
	}

	// Wait for window to expire
	time.Sleep(150 * time.Millisecond)

	// Third time seen after window expiry -> novel again
	isNovel, count = ds.Allow(sig)
	if !isNovel || count != 1 {
		t.Fatalf("expected (true, 1) after window expiry, got (%v, %d)", isNovel, count)
	}
}

func TestDedupStore_ConcurrentAccess(t *testing.T) {
	ds := NewDedupStore(1*time.Minute, 1*time.Minute)
	defer ds.Close()

	const numGoroutines = 50
	const opsPerGoroutine = 100
	sig := "shared-signature-hash"

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < opsPerGoroutine; j++ {
				ds.Allow(sig)
			}
		}()
	}

	wg.Wait()

	rec, ok := ds.GetRecord(sig)
	if !ok {
		t.Fatal("expected record to exist in store")
	}

	expectedCount := int64(numGoroutines * opsPerGoroutine)
	if rec.Count != expectedCount {
		t.Errorf("record count = %d, want %d", rec.Count, expectedCount)
	}
}

func TestCircuitBreaker_StateTransitions(t *testing.T) {
	cfg := CircuitBreakerConfig{
		MaxFailures:         3,
		ResetTimeout:        100 * time.Millisecond,
		HalfOpenMaxRequests: 1,
	}
	cb := NewCircuitBreaker(cfg)

	dummyErr := errors.New("backend error")

	// 1. Initial State: CLOSED
	if state := cb.State(); state != StateClosed {
		t.Fatalf("initial state = %v, want CLOSED", state)
	}

	// 2. Fail 3 times to trip breaker to OPEN
	for i := 0; i < 3; i++ {
		_ = cb.Execute(func() error { return dummyErr })
	}

	if state := cb.State(); state != StateOpen {
		t.Fatalf("state after 3 failures = %v, want OPEN", state)
	}

	// Immediate execution should fail fast with ErrCircuitOpen
	err := cb.Execute(func() error { return nil })
	if !errors.Is(err, ErrCircuitOpen) {
		t.Fatalf("expected ErrCircuitOpen when open, got %v", err)
	}

	// 3. Wait for ResetTimeout to expire -> HALF-OPEN
	time.Sleep(120 * time.Millisecond)

	if state := cb.State(); state != StateHalfOpen {
		t.Fatalf("state after timeout = %v, want HALF-OPEN", state)
	}

	// 4. Successful request in HALF-OPEN transitions back to CLOSED
	err = cb.Execute(func() error { return nil })
	if err != nil {
		t.Fatalf("unexpected error in half-open probe: %v", err)
	}

	if state := cb.State(); state != StateClosed {
		t.Fatalf("state after half-open success = %v, want CLOSED", state)
	}
}

func TestBackoff_Retry(t *testing.T) {
	ctx := context.Background()

	// Test immediate success
	attempts := 0
	err := Retry(ctx, RetryOptions{MaxAttempts: 3}, func() error {
		attempts++
		return nil
	})
	if err != nil || attempts != 1 {
		t.Errorf("expected immediate success (1 attempt), got err=%v, attempts=%d", err, attempts)
	}

	// Test retries until success
	attempts = 0
	dummyErr := errors.New("transient error")
	err = Retry(ctx, RetryOptions{
		MaxAttempts: 5,
		Backoff:     NewFullJitterBackoff(1*time.Millisecond, 5*time.Millisecond),
	}, func() error {
		attempts++
		if attempts < 3 {
			return dummyErr
		}
		return nil
	})
	if err != nil || attempts != 3 {
		t.Errorf("expected success on attempt 3, got err=%v, attempts=%d", err, attempts)
	}

	// Test non-retryable error
	nonRetryable := errors.New("fatal auth error")
	attempts = 0
	err = Retry(ctx, RetryOptions{
		MaxAttempts: 5,
		IsRetryable: func(e error) bool { return !errors.Is(e, nonRetryable) },
	}, func() error {
		attempts++
		return nonRetryable
	})
	if !errors.Is(err, nonRetryable) || attempts != 1 {
		t.Errorf("expected non-retryable error to fail fast (1 attempt), got err=%v, attempts=%d", err, attempts)
	}
}

func TestDLQWriter_WriteAndClose(t *testing.T) {
	var buf bytes.Buffer
	dw := NewDLQWriter(&buf)

	raw := domain.RawEvent{
		Source:     domain.SourceJSON,
		Payload:    []byte(`{"bad":"json"`),
		StreamID:   "stream-dlq",
		SeqNo:      42,
		ReceivedAt: time.Now().UTC(),
	}

	err := dw.Write(raw, "JSON syntax error", 2)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	line := buf.String()
	if !strings.Contains(line, `"stream_id":"stream-dlq"`) || !strings.Contains(line, `"reason":"JSON syntax error"`) {
		t.Errorf("unexpected DLQ record content: %s", line)
	}

	var rec DLQRecord
	if err := json.Unmarshal([]byte(strings.TrimSpace(line)), &rec); err != nil {
		t.Fatalf("failed to unmarshal DLQ record: %v", err)
	}
	if rec.SeqNo != 42 || rec.AttemptCount != 2 {
		t.Errorf("DLQRecord fields mismatch: %+v", rec)
	}

	if err := dw.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Writing after Close should fail
	err = dw.Write(raw, "another error", 1)
	if !errors.Is(err, ErrDLQClosed) {
		t.Errorf("expected ErrDLQClosed after Close, got %v", err)
	}
}

func TestDLQFileWriter_Integration(t *testing.T) {
	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "dlq", "events.jsonl")

	dw, err := NewDLQFileWriter(filePath)
	if err != nil {
		t.Fatalf("NewDLQFileWriter failed: %v", err)
	}

	raw := domain.RawEvent{
		Source:     domain.SourceSyslog,
		Payload:    []byte("malformed syslog"),
		StreamID:   "syslog-stream",
		SeqNo:      100,
		ReceivedAt: time.Now().UTC(),
	}

	if err := dw.Write(raw, "parse error", 1); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	if err := dw.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}
}

func BenchmarkDedupStore_Allow(b *testing.B) {
	ds := NewDedupStore(5*time.Minute, 1*time.Minute)
	defer ds.Close()

	sig := "benchmark-signature-hash"

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		ds.Allow(sig)
	}
}
