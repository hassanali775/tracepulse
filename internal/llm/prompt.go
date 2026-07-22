package llm

import (
	"fmt"
	"strings"
	"time"

	"github.com/hassan/tracepulse/internal/domain"
)

// DiagnosisRequest holds the normalized incident data and deduplication context needed to construct an LLM diagnosis prompt.
type DiagnosisRequest struct {
	Event          *domain.NormalizedEvent
	DedupCount     int64
	WindowDuration time.Duration
}

// DiagnosisResponse is the structured output returned by the LLM diagnosis engine.
type DiagnosisResponse struct {
	EventID           string   `json:"event_id"`
	Signature         string   `json:"signature"`
	RootCause         string   `json:"root_cause"`
	Severity          string   `json:"severity"`
	AffectedComponent string   `json:"affected_component"`
	FixCommands       []string `json:"fix_commands"`
	ConfidenceScore   float64  `json:"confidence_score"`
	RawResponse       string   `json:"raw_response,omitempty"`
	TokensUsed        int      `json:"tokens_used,omitempty"`
}

// PromptBuilder formats NormalizedEvents and deduplication statistics into high-precision, zero-noise LLM prompts.
type PromptBuilder struct{}

func NewPromptBuilder() *PromptBuilder {
	return &PromptBuilder{}
}

// BuildPrompt constructs a system/user prompt for LLM incident diagnosis.
func (pb *PromptBuilder) BuildPrompt(req DiagnosisRequest) string {
	var sb strings.Builder

	ev := req.Event
	sb.WriteString("You are an expert Reliability Engineer & Incident Root-Cause Engine.\n")
	sb.WriteString("Analyze the following high-throughput error event and provide a precise, actionable diagnosis.\n\n")

	sb.WriteString("=== INCIDENT CONTEXT ===\n")
	fmt.Fprintf(&sb, "Service: %s\n", ev.Service)
	if ev.Host != "" {
		fmt.Fprintf(&sb, "Host: %s\n", ev.Host)
	}
	fmt.Fprintf(&sb, "Severity: %s\n", ev.Severity.String())
	fmt.Fprintf(&sb, "Timestamp: %s\n", ev.Timestamp.Format(time.RFC3339))
	fmt.Fprintf(&sb, "Event ID: %s\n", ev.ID)
	if ev.Signature != "" {
		fmt.Fprintf(&sb, "Signature Hash: %s\n", ev.Signature)
	}

	window := req.WindowDuration
	if window <= 0 {
		window = 5 * time.Minute
	}
	fmt.Fprintf(&sb, "Occurrence Frequency: %d times in the last %v\n\n", req.DedupCount, window)

	sb.WriteString("=== ERROR MESSAGE ===\n")
	sb.WriteString(ev.Message)
	sb.WriteString("\n\n")

	if len(ev.StackFrames) > 0 {
		sb.WriteString("=== STACK TRACE FRAMES ===\n")
		for i, frame := range ev.StackFrames {
			fmt.Fprintf(&sb, "[%d] %s\n", i+1, frame)
		}
		sb.WriteString("\n")
	}

	if len(ev.Fields) > 0 {
		sb.WriteString("=== METADATA & FIELDS ===\n")
		for k, v := range ev.Fields {
			fmt.Fprintf(&sb, "- %s: %s\n", k, v)
		}
		sb.WriteString("\n")
	}

	sb.WriteString("=== REQUIRED OUTPUT FORMAT ===\n")
	sb.WriteString("Respond strictly in valid JSON format with the following keys:\n")
	sb.WriteString("{\n")
	sb.WriteString(`  "root_cause": "<concise summary of why this error happened>",` + "\n")
	sb.WriteString(`  "severity": "<fatal|error|warn>",` + "\n")
	sb.WriteString(`  "affected_component": "<service/db/network component>",` + "\n")
	sb.WriteString(`  "fix_commands": ["<cli command 1>", "<cli command 2>"],` + "\n")
	sb.WriteString(`  "confidence_score": 0.95` + "\n")
	sb.WriteString("}\n")

	return sb.String()
}
