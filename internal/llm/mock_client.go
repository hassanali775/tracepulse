package llm

import (
	"context"
	"strings"
	"time"

	"github.com/hassan/tracepulse/internal/domain"
)

// MockLLMClient provides production-like offline LLM responses and SSE streaming simulation.
type MockLLMClient struct {
	SimulatedLatency time.Duration
}

func NewMockLLMClient() *MockLLMClient {
	return &MockLLMClient{
		SimulatedLatency: 50 * time.Millisecond,
	}
}

func (m *MockLLMClient) Diagnose(ctx context.Context, req DiagnosisRequest) (*DiagnosisResponse, error) {
	if req.Event == nil {
		return nil, ErrNilRequest
	}

	if m.SimulatedLatency > 0 {
		select {
		case <-time.After(m.SimulatedLatency):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	resp := m.generateDiagnosis(req.Event, req.DedupCount)
	return resp, nil
}

func (m *MockLLMClient) StreamDiagnose(ctx context.Context, req DiagnosisRequest) (<-chan string, <-chan error) {
	tokenCh := make(chan string, 50)
	errCh := make(chan error, 1)

	go func() {
		defer close(tokenCh)
		defer close(errCh)

		if req.Event == nil {
			errCh <- ErrNilRequest
			return
		}

		resp := m.generateDiagnosis(req.Event, req.DedupCount)
		text := resp.RootCause + "\nFixes: " + strings.Join(resp.FixCommands, "; ")

		words := strings.Fields(text)
		for _, word := range words {
			select {
			case tokenCh <- word + " ":
				if m.SimulatedLatency > 0 {
					time.Sleep(m.SimulatedLatency / 5)
				}
			case <-ctx.Done():
				errCh <- ctx.Err()
				return
			}
		}
	}()

	return tokenCh, errCh
}

func (m *MockLLMClient) generateDiagnosis(ev *domain.NormalizedEvent, dedupCount int64) *DiagnosisResponse {
	msg := strings.ToLower(ev.Message)

	resp := &DiagnosisResponse{
		EventID:         ev.ID,
		Signature:       ev.Signature,
		ConfidenceScore: 0.94,
		TokensUsed:      320,
	}

	switch {
	case strings.Contains(msg, "nil pointer") || strings.Contains(msg, "dereference"):
		resp.RootCause = "Nil pointer dereference when accessing uninitialized object instance in application code."
		resp.Severity = "fatal"
		resp.AffectedComponent = ev.Service
		resp.FixCommands = []string{
			"kubectl rollout undo deployment/" + ev.Service,
			"git log -n 1 --stat",
		}

	case strings.Contains(msg, "connection refused") || strings.Contains(msg, "timeout") || strings.Contains(msg, "dial tcp"):
		resp.RootCause = "Upstream network failure or database connection pool exhaustion."
		resp.Severity = "error"
		resp.AffectedComponent = "database-pool"
		resp.FixCommands = []string{
			"kubectl scale deployment/" + ev.Service + " --replicas=5",
			"pg_isready -h db-cluster.internal -p 5432",
		}

	case strings.Contains(msg, "out of memory") || strings.Contains(msg, "oom") || strings.Contains(msg, "cannot allocate"):
		resp.RootCause = "Container memory limit exceeded causing Linux kernel OOM killer trigger."
		resp.Severity = "fatal"
		resp.AffectedComponent = "k8s-pod-memory"
		resp.FixCommands = []string{
			"kubectl top pod -l app=" + ev.Service,
			"kubectl edit deployment/" + ev.Service + " # increase memory limit to 2Gi",
		}

	default:
		resp.RootCause = "Unhandled application error: " + ev.Message
		resp.Severity = ev.Severity.String()
		resp.AffectedComponent = ev.Service
		resp.FixCommands = []string{
			"kubectl logs -l app=" + ev.Service + " --tail=100",
		}
	}

	return resp
}
