package ingest

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hassan/tracepulse/internal/domain"
)

func TestJSONParser_Parse(t *testing.T) {
	parser := NewJSONParser()
	now := time.Now().UTC()

	tests := []struct {
		name        string
		raw         domain.RawEvent
		wantErr     bool
		wantService string
		wantSev     domain.Severity
		wantMsg     string
		wantFrames  int
	}{
		{
			name: "valid JSON with standard fields",
			raw: domain.RawEvent{
				Source:     domain.SourceJSON,
				Payload:    []byte(`{"service":"checkout-api","level":"error","msg":"database connection failed","timestamp":"2026-07-22T10:00:00Z"}`),
				StreamID:   "stream-1",
				ReceivedAt: now,
			},
			wantErr:     false,
			wantService: "checkout-api",
			wantSev:     domain.SeverityError,
			wantMsg:     "database connection failed",
		},
		{
			name: "JSON with stacktrace string",
			raw: domain.RawEvent{
				Source:     domain.SourceJSON,
				Payload:    []byte(`{"service":"payment-svc","level":"fatal","message":"panic dereference","stack":"main.pay:pay.go:10\nmain.serve:server.go:20"}`),
				StreamID:   "stream-2",
				ReceivedAt: now,
			},
			wantErr:     false,
			wantService: "payment-svc",
			wantSev:     domain.SeverityFatal,
			wantMsg:     "panic dereference",
			wantFrames:  2,
		},
		{
			name: "invalid JSON payload",
			raw: domain.RawEvent{
				Source:     domain.SourceJSON,
				Payload:    []byte(`{bad json`),
				StreamID:   "stream-3",
				ReceivedAt: now,
			},
			wantErr: true,
		},
		{
			name: "empty payload",
			raw: domain.RawEvent{
				Source:     domain.SourceJSON,
				Payload:    []byte(``),
				StreamID:   "stream-4",
				ReceivedAt: now,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ne, err := parser.Parse(tt.raw)
			if (err != nil) != tt.wantErr {
				t.Fatalf("JSONParser.Parse() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr {
				if ne.Service != tt.wantService {
					t.Errorf("Service = %q, want %q", ne.Service, tt.wantService)
				}
				if ne.Severity != tt.wantSev {
					t.Errorf("Severity = %v, want %v", ne.Severity, tt.wantSev)
				}
				if ne.Message != tt.wantMsg {
					t.Errorf("Message = %q, want %q", ne.Message, tt.wantMsg)
				}
				if len(ne.StackFrames) != tt.wantFrames {
					t.Errorf("StackFrames count = %d, want %d", len(ne.StackFrames), tt.wantFrames)
				}
			}
		})
	}
}

func TestSyslogParser_Parse(t *testing.T) {
	parser := NewSyslogParser()
	now := time.Date(2026, 7, 22, 10, 0, 0, 0, time.UTC)

	tests := []struct {
		name        string
		raw         domain.RawEvent
		wantService string
		wantSev     domain.Severity
		wantHost    string
		wantMsg     string
		wantPID     string
	}{
		{
			name: "RFC3164 error log with PID",
			raw: domain.RawEvent{
				Source:     domain.SourceSyslog,
				Payload:    []byte(`<27>Jul 22 10:00:00 worker-host checkout-api[4012]: failed to process payment request`),
				StreamID:   "syslog-stream",
				ReceivedAt: now,
			},
			wantService: "checkout-api",
			wantSev:     domain.SeverityError, // PRI 27 -> Sev 27%8 = 3 (Error)
			wantHost:    "worker-host",
			wantMsg:     "failed to process payment request",
			wantPID:     "4012",
		},
		{
			name: "RFC3164 warning log without PID",
			raw: domain.RawEvent{
				Source:     domain.SourceSyslog,
				Payload:    []byte(`<12>Jul 22 10:00:00 node-01 auth-service: high memory consumption warning`),
				StreamID:   "syslog-stream",
				ReceivedAt: now,
			},
			wantService: "auth-service",
			wantSev:     domain.SeverityWarn, // PRI 12 -> Sev 12%8 = 4 (Warn)
			wantHost:    "node-01",
			wantMsg:     "high memory consumption warning",
			wantPID:     "",
		},
		{
			name: "non-PRI fallback syslog line",
			raw: domain.RawEvent{
				Source:     domain.SourceSyslog,
				Payload:    []byte(`plain syslog entry without header`),
				StreamID:   "syslog-stream",
				ReceivedAt: now,
			},
			wantService: "syslog-stream",
			wantSev:     domain.SeverityInfo,
			wantMsg:     "plain syslog entry without header",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ne, err := parser.Parse(tt.raw)
			if err != nil {
				t.Fatalf("SyslogParser.Parse() unexpected error: %v", err)
			}
			if ne.Service != tt.wantService {
				t.Errorf("Service = %q, want %q", ne.Service, tt.wantService)
			}
			if ne.Severity != tt.wantSev {
				t.Errorf("Severity = %v, want %v", ne.Severity, tt.wantSev)
			}
			if ne.Host != tt.wantHost {
				t.Errorf("Host = %q, want %q", ne.Host, tt.wantHost)
			}
			if ne.Message != tt.wantMsg {
				t.Errorf("Message = %q, want %q", ne.Message, tt.wantMsg)
			}
			if pid, ok := ne.Fields["pid"]; ok && pid != tt.wantPID {
				t.Errorf("PID field = %q, want %q", pid, tt.wantPID)
			}
		})
	}
}

func TestStackTraceParser_Parse(t *testing.T) {
	parser := NewStackTraceParser()
	now := time.Now().UTC()

	payload := []byte("panic: runtime error: invalid memory address\n" +
		"\tgoroutine 1 [running]:\n" +
		"\tmain.processOrder(0xc00012e000)\n" +
		"\t\t/app/main.go:142 +0x1a2b\n" +
		"\tmain.handleRequest(...)\n" +
		"\t\t/app/main.go:88 +0x3fce")

	raw := domain.RawEvent{
		Source:     domain.SourceStackTrace,
		Payload:    payload,
		StreamID:   "app-stream",
		ReceivedAt: now,
	}

	ne, err := parser.Parse(raw)
	if err != nil {
		t.Fatalf("StackTraceParser.Parse() unexpected error: %v", err)
	}

	if ne.Message != "panic: runtime error: invalid memory address" {
		t.Errorf("Message = %q, want %q", ne.Message, "panic: runtime error: invalid memory address")
	}
	if ne.Severity != domain.SeverityFatal {
		t.Errorf("Severity = %v, want %v", ne.Severity, domain.SeverityFatal)
	}
	if len(ne.StackFrames) != 5 {
		t.Errorf("StackFrames count = %d, want 5", len(ne.StackFrames))
	}
}

func TestFrameReader_ReadStream(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	logLines := "line 1\nline 2\nline 3\n"
	reader := NewFrameReader("test-stream", domain.SourceJSON)

	out := make(chan domain.RawEvent, 10)
	err := reader.ReadStream(ctx, strings.NewReader(logLines), out)
	if err != nil {
		t.Fatalf("ReadStream failed: %v", err)
	}

	close(out)

	var events []domain.RawEvent
	for ev := range out {
		events = append(events, ev)
	}

	if len(events) != 3 {
		t.Fatalf("expected 3 RawEvents, got %d", len(events))
	}

	for i, ev := range events {
		expectedSeq := uint64(i + 1)
		if ev.SeqNo != expectedSeq {
			t.Errorf("event %d SeqNo = %d, want %d", i, ev.SeqNo, expectedSeq)
		}
		if ev.StreamID != "test-stream" {
			t.Errorf("event %d StreamID = %q, want %q", i, ev.StreamID, "test-stream")
		}
	}
}

func TestWorkerPool_ExecutionAndBackpressure(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	outCh := make(chan *domain.NormalizedEvent, 100)
	hasher := domain.NewHasher()
	parser := NewMultiParser()

	pool, err := NewWorkerPool(4, 10, hasher, parser, outCh)
	if err != nil {
		t.Fatalf("NewWorkerPool failed: %v", err)
	}

	pool.Start(ctx)

	// Submit 20 raw JSON error events
	for i := 1; i <= 20; i++ {
		raw := domain.RawEvent{
			Source:     domain.SourceJSON,
			Payload:    []byte(fmt.Sprintf(`{"service":"checkout","level":"error","msg":"failure %d"}`, i)),
			StreamID:   "test-stream",
			SeqNo:      uint64(i),
			ReceivedAt: time.Now().UTC(),
		}
		if err := pool.Submit(ctx, raw); err != nil {
			t.Fatalf("Submit event %d failed: %v", i, err)
		}
	}

	pool.Stop()
	close(outCh)

	var received []*domain.NormalizedEvent
	for ne := range outCh {
		received = append(received, ne)
	}

	if len(received) != 20 {
		t.Errorf("received %d normalized events, want 20", len(received))
	}

	stats := pool.Stats()
	if stats.IngestedCount != 20 {
		t.Errorf("IngestedCount = %d, want 20", stats.IngestedCount)
	}
	if stats.ParsedCount != 20 {
		t.Errorf("ParsedCount = %d, want 20", stats.ParsedCount)
	}
	if stats.ErrorCount != 0 {
		t.Errorf("ErrorCount = %d, want 0", stats.ErrorCount)
	}

	// Verify signatures were computed on error events
	for _, ne := range received {
		if ne.Signature == "" {
			t.Errorf("expected non-empty Signature for error event ID %s", ne.ID)
		}
	}
}

func TestWorkerPool_GracefulShutdownContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	outCh := make(chan *domain.NormalizedEvent, 5)
	pool, err := NewWorkerPool(2, 5, domain.NewHasher(), NewMultiParser(), outCh)
	if err != nil {
		t.Fatalf("NewWorkerPool failed: %v", err)
	}

	pool.Start(ctx)

	// Cancel context immediately
	cancel()

	// Submitting after context cancel should return context error
	raw := domain.RawEvent{
		Source:     domain.SourceJSON,
		Payload:    []byte(`{"service":"svc","level":"info","msg":"test"}`),
		StreamID:   "stream",
		SeqNo:      1,
		ReceivedAt: time.Now().UTC(),
	}

	err = pool.Submit(ctx, raw)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled on Submit after context cancel, got: %v", err)
	}

	pool.Stop()
}

func BenchmarkParsers(b *testing.B) {
	jsonRaw := domain.RawEvent{
		Source:     domain.SourceJSON,
		Payload:    []byte(`{"service":"checkout-api","level":"error","msg":"database timeout","timestamp":"2026-07-22T10:00:00Z"}`),
		StreamID:   "s1",
		ReceivedAt: time.Now().UTC(),
	}
	syslogRaw := domain.RawEvent{
		Source:     domain.SourceSyslog,
		Payload:    []byte(`<27>Jul 22 10:00:00 host-1 checkout-api[4012]: failed connection`),
		StreamID:   "s2",
		ReceivedAt: time.Now().UTC(),
	}

	jp := NewJSONParser()
	sp := NewSyslogParser()

	b.Run("JSONParser", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, err := jp.Parse(jsonRaw); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("SyslogParser", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, err := sp.Parse(syslogRaw); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkWorkerPool_Throughput(b *testing.B) {
	ctx := context.Background()
	outCh := make(chan *domain.NormalizedEvent, 1000)

	// Consume downstream events in background
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for range outCh {
		}
	}()

	pool, _ := NewWorkerPool(8, 1000, domain.NewHasher(), NewMultiParser(), outCh)
	pool.Start(ctx)

	raw := domain.RawEvent{
		Source:     domain.SourceJSON,
		Payload:    []byte(`{"service":"bench-svc","level":"error","msg":"failure in bench"}`),
		StreamID:   "bench-stream",
		ReceivedAt: time.Now().UTC(),
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		raw.SeqNo = uint64(i)
		_ = pool.Submit(ctx, raw)
	}

	pool.Stop()
	close(outCh)
	wg.Wait()
}
