package llm

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/hassan/tracepulse/internal/domain"
)

func TestPromptBuilder_BuildPrompt(t *testing.T) {
	pb := NewPromptBuilder()

	ev := &domain.NormalizedEvent{
		ID:        "evt-101",
		Service:   "checkout-api",
		Host:      "pod-checkout-77",
		Severity:  domain.SeverityError,
		Timestamp: time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC),
		Message:   "nil pointer dereference at 0xc00012e000",
		Signature: "sig-hash-99",
		StackFrames: []string{
			"main.processOrder:file.go:142",
			"main.handleRequest:file.go:88",
		},
		Fields: map[string]string{
			"env": "production",
		},
	}

	req := DiagnosisRequest{
		Event:          ev,
		DedupCount:     1420,
		WindowDuration: 5 * time.Minute,
	}

	prompt := pb.BuildPrompt(req)

	if !strings.Contains(prompt, "Service: checkout-api") {
		t.Errorf("prompt missing service name")
	}
	if !strings.Contains(prompt, "Occurrence Frequency: 1420 times in the last 5m0s") {
		t.Errorf("prompt missing occurrence count")
	}
	if !strings.Contains(prompt, "nil pointer dereference at 0xc00012e000") {
		t.Errorf("prompt missing error message")
	}
	if !strings.Contains(prompt, "[1] main.processOrder:file.go:142") {
		t.Errorf("prompt missing stack frame")
	}
}

func TestMockLLMClient_Diagnose(t *testing.T) {
	ctx := context.Background()
	mock := NewMockLLMClient()
	mock.SimulatedLatency = 5 * time.Millisecond

	ev := &domain.NormalizedEvent{
		ID:        "evt-202",
		Service:   "payment-service",
		Severity:  domain.SeverityFatal,
		Timestamp: time.Now().UTC(),
		Message:   "panic: nil pointer dereference",
	}

	req := DiagnosisRequest{
		Event:      ev,
		DedupCount: 1,
	}

	resp, err := mock.Diagnose(ctx, req)
	if err != nil {
		t.Fatalf("Diagnose failed: %v", err)
	}

	if resp.EventID != "evt-202" {
		t.Errorf("EventID = %q, want evt-202", resp.EventID)
	}
	if resp.Severity != "fatal" {
		t.Errorf("Severity = %q, want fatal", resp.Severity)
	}
	if len(resp.FixCommands) == 0 {
		t.Errorf("expected non-empty FixCommands")
	}
}

func TestMockLLMClient_StreamDiagnose(t *testing.T) {
	ctx := context.Background()
	mock := NewMockLLMClient()
	mock.SimulatedLatency = 2 * time.Millisecond

	ev := &domain.NormalizedEvent{
		ID:        "evt-303",
		Service:   "auth-service",
		Severity:  domain.SeverityError,
		Timestamp: time.Now().UTC(),
		Message:   "connection refused calling DB",
	}

	tokenCh, errCh := mock.StreamDiagnose(ctx, DiagnosisRequest{Event: ev, DedupCount: 10})

	var tokens []string
	for token := range tokenCh {
		tokens = append(tokens, token)
	}

	if err := <-errCh; err != nil {
		t.Fatalf("StreamDiagnose returned error: %v", err)
	}

	if len(tokens) == 0 {
		t.Fatalf("expected streamed tokens, got 0")
	}
}

func BenchmarkPromptBuilder(b *testing.B) {
	pb := NewPromptBuilder()
	ev := &domain.NormalizedEvent{
		ID:        "evt-bench",
		Service:   "checkout-api",
		Severity:  domain.SeverityError,
		Timestamp: time.Now().UTC(),
		Message:   "database connection timeout",
		StackFrames: []string{
			"main.a:a.go:1",
			"main.b:b.go:2",
		},
	}
	req := DiagnosisRequest{Event: ev, DedupCount: 500}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = pb.BuildPrompt(req)
	}
}
