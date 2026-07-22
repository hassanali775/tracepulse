package llm

import (
	"context"
	"errors"
)

var (
	ErrNilRequest      = errors.New("llm: nil diagnosis request")
	ErrProviderFailed  = errors.New("llm: provider request failed")
	ErrInvalidResponse = errors.New("llm: invalid json response from provider")
)

// LLMProvider abstracts execution of LLM incident diagnosis calls.
type LLMProvider interface {
	// Diagnose runs a synchronous diagnosis request.
	Diagnose(ctx context.Context, req DiagnosisRequest) (*DiagnosisResponse, error)

	// StreamDiagnose streams diagnostic response chunks (tokens) over a channel for real-time SSE UI.
	StreamDiagnose(ctx context.Context, req DiagnosisRequest) (<-chan string, <-chan error)
}
