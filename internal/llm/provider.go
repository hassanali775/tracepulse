package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/hassan/tracepulse/internal/pipeline"
)

// ProviderConfig configures live LLM HTTP endpoint connection parameters.
type ProviderConfig struct {
	Endpoint   string
	APIKey     string
	Model      string
	Timeout    time.Duration
	MaxRetries int
}

// LiveLLMClient implements LLMProvider for external REST endpoints (e.g. Gemini / OpenAI / Ollama)
// wrapped inside pipeline.CircuitBreaker and exponential retries.
type LiveLLMClient struct {
	cfg            ProviderConfig
	httpClient     *http.Client
	circuitBreaker *pipeline.CircuitBreaker
	promptBuilder  *PromptBuilder
}

func NewLiveLLMClient(cfg ProviderConfig, cb *pipeline.CircuitBreaker) *LiveLLMClient {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	if cfg.Model == "" {
		cfg.Model = "gemini-1.5-flash"
	}
	if cb == nil {
		cb = pipeline.NewCircuitBreaker(pipeline.CircuitBreakerConfig{
			MaxFailures:  3,
			ResetTimeout: 10 * time.Second,
		})
	}

	return &LiveLLMClient{
		cfg: cfg,
		httpClient: &http.Client{
			Timeout: cfg.Timeout,
		},
		circuitBreaker: cb,
		promptBuilder:  NewPromptBuilder(),
	}
}

func (c *LiveLLMClient) Diagnose(ctx context.Context, req DiagnosisRequest) (*DiagnosisResponse, error) {
	if req.Event == nil {
		return nil, ErrNilRequest
	}

	var resp *DiagnosisResponse
	err := c.circuitBreaker.Execute(func() error {
		return pipeline.Retry(ctx, pipeline.RetryOptions{
			MaxAttempts: c.cfg.MaxRetries,
			Backoff:     pipeline.NewFullJitterBackoff(100*time.Millisecond, 2*time.Second),
		}, func() error {
			var callErr error
			resp, callErr = c.doHTTPRequest(ctx, req)
			return callErr
		})
	})

	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (c *LiveLLMClient) StreamDiagnose(ctx context.Context, req DiagnosisRequest) (<-chan string, <-chan error) {
	tokenCh := make(chan string, 100)
	errCh := make(chan error, 1)

	go func() {
		defer close(tokenCh)
		defer close(errCh)

		resp, err := c.Diagnose(ctx, req)
		if err != nil {
			errCh <- err
			return
		}

		select {
		case tokenCh <- resp.RootCause:
		case <-ctx.Done():
			errCh <- ctx.Err()
		}
	}()

	return tokenCh, errCh
}

func (c *LiveLLMClient) doHTTPRequest(ctx context.Context, req DiagnosisRequest) (*DiagnosisResponse, error) {
	if c.cfg.Endpoint == "" {
		mock := NewMockLLMClient()
		return mock.Diagnose(ctx, req)
	}

	promptText := c.promptBuilder.BuildPrompt(req)

	bodyMap := map[string]any{
		"model": c.cfg.Model,
		"messages": []map[string]string{
			{"role": "user", "content": promptText},
		},
		"temperature": 0.1,
	}

	jsonBytes, err := json.Marshal(bodyMap)
	if err != nil {
		return nil, err
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.Endpoint, bytes.NewReader(jsonBytes))
	if err != nil {
		return nil, err
	}

	httpReq.Header.Set("Content-Type", "application/json")
	if c.cfg.APIKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+c.cfg.APIKey)
	}

	res, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrProviderFailed, err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(res.Body)
		return nil, fmt.Errorf("%w: http status %d: %s", ErrProviderFailed, res.StatusCode, string(respBody))
	}

	var diagResp DiagnosisResponse
	if err := json.NewDecoder(res.Body).Decode(&diagResp); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidResponse, err)
	}

	diagResp.EventID = req.Event.ID
	diagResp.Signature = req.Event.Signature
	return &diagResp, nil
}
