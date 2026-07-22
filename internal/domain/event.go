package domain

import (
	"fmt"
	"time"
)

// SourceType identifies which streaming parser produced an event. Kept as a
// distinct string type (not an int enum) so DLQ records and API responses
// remain human-readable without a lookup table.
type SourceType string

const (
	SourceUnknown    SourceType = ""
	SourceJSON       SourceType = "json"
	SourceSyslog     SourceType = "syslog"
	SourceStackTrace SourceType = "stacktrace"
)

// Valid reports whether s is one of the supported parser source types.
func (s SourceType) Valid() bool {
	switch s {
	case SourceJSON, SourceSyslog, SourceStackTrace:
		return true
	default:
		return false
	}
}

// Severity is an ordered log level. Ordering matters: callers compare
// severities (e.g. "at least Error") rather than just equality-checking.
type Severity int8

const (
	SeverityUnknown Severity = iota
	SeverityDebug
	SeverityInfo
	SeverityWarn
	SeverityError
	SeverityFatal
)

func (sv Severity) String() string {
	switch sv {
	case SeverityDebug:
		return "debug"
	case SeverityInfo:
		return "info"
	case SeverityWarn:
		return "warn"
	case SeverityError:
		return "error"
	case SeverityFatal:
		return "fatal"
	default:
		return "unknown"
	}
}

// AtLeast reports whether sv is equally or more severe than min.
func (sv Severity) AtLeast(min Severity) bool {
	return sv >= min
}

// ParseSeverity maps common textual levels (case-insensitive callers should
// lowercase before calling) from JSON, syslog PRI-derived text, and stack
// trace framing onto the canonical Severity scale. Unrecognized input maps
// to SeverityUnknown rather than erroring — severity inference is
// best-effort and must never block ingestion.
func ParseSeverity(s string) Severity {
	switch s {
	case "debug", "trace":
		return SeverityDebug
	case "info", "notice", "informational":
		return SeverityInfo
	case "warn", "warning":
		return SeverityWarn
	case "error", "err":
		return SeverityError
	case "fatal", "panic", "critical", "crit", "emerg", "alert":
		return SeverityFatal
	default:
		return SeverityUnknown
	}
}

// RawEvent is the unit of work handed from a transport (TCP listener, file
// tailer, HTTP upload) into the ingestion worker pool. It is intentionally
// minimal and copy-cheap: Payload is the only heap-referencing field beyond
// the strings, so a []RawEvent channel does not become an allocation
// bottleneck under high throughput.
type RawEvent struct {
	// Source is set by the transport/parser that produced this event, not
	// inferred later — the caller already knows which parser it invoked.
	Source SourceType

	// Payload is the unparsed line/frame/record exactly as read from the
	// io.Reader. Ownership: the ingestion engine must not retain a
	// RawEvent's Payload slice past handoff without copying it, since
	// parsers may reuse read buffers between calls.
	Payload []byte

	// StreamID correlates raw lines belonging to the same logical stream
	// (TCP connection, file descriptor, syslog session) so multi-line
	// stack trace parsers can buffer and join frames from the *same*
	// stream and never interleave two concurrent producers.
	StreamID string

	// ReceivedAt is stamped at the ingestion boundary (not parse time),
	// used for ingestion-lag metrics independent of parser latency.
	ReceivedAt time.Time

	// SeqNo is a per-stream monotonically increasing counter assigned by
	// the transport. Used to detect gaps/reordering ahead of DLQ replay.
	SeqNo uint64
}

// Validate checks the minimal invariants an ingestion worker must enforce
// before a RawEvent is handed to a parser. Returns a *ValidationError (or
// nil) so callers can log every violation, not just the first.
func (re *RawEvent) Validate() error {
	ve := &ValidationError{}
	if len(re.Payload) == 0 {
		ve.add("payload", ErrEmptyPayload)
	}
	if !re.Source.Valid() {
		ve.add("source", ErrUnknownSource)
	}
	if re.ReceivedAt.IsZero() {
		ve.add("received_at", ErrInvalidTimestamp)
	}
	return ve.asError()
}

// NormalizedEvent is the canonical, parser-agnostic representation that
// every downstream stage (dedup, LLM context builder, API stream) operates
// on. Every parser (JSON/Syslog/StackTrace) converges onto this shape.
type NormalizedEvent struct {
	// ID uniquely identifies this normalized event, independent of
	// ErrorSignature (which intentionally collides across occurrences of
	// the "same" error). Assigned by the ingestion engine, not the parser.
	ID string

	Source   SourceType
	Severity Severity

	// Timestamp is the event's own time if the source line carried one
	// (JSON "ts" field, syslog header); falls back to RawEvent.ReceivedAt
	// when absent. Never zero-valued after normalization.
	Timestamp time.Time

	Service string
	Host    string

	// Message is the single-line, human-readable error/log message with
	// any embedded stack trace split out into StackFrames.
	Message string

	// StackFrames holds parsed stack trace lines in top-to-bottom order
	// (innermost frame first) for multi-line stack trace sources. Empty
	// for plain JSON/syslog lines with no trace.
	StackFrames []string

	// Fields carries source-specific structured data that doesn't map to
	// a first-class field (JSON extra keys, syslog structured-data). Kept
	// as map[string]string, not map[string]any, so downstream hashing and
	// serialization never need reflection or a type switch.
	Fields map[string]string

	// Signature is populated by the Hasher after normalization; empty
	// immediately after parsing. Kept on the struct (rather than a
	// side-table) so a NormalizedEvent is self-describing once the
	// pipeline has run.
	Signature string

	// RawSize is the byte length of the originating RawEvent.Payload,
	// retained for ingestion throughput metrics without holding the raw
	// bytes themselves.
	RawSize int
}

// Validate enforces the invariants downstream stages are allowed to assume
// hold for every NormalizedEvent — in particular the dedup and LLM context
// stages must never see a zero Timestamp or empty Service/Message.
func (ne *NormalizedEvent) Validate() error {
	ve := &ValidationError{}
	if !ne.Source.Valid() {
		ve.add("source", ErrUnknownSource)
	}
	if ne.Service == "" {
		ve.add("service", ErrMissingService)
	}
	if ne.Message == "" {
		ve.add("message", ErrMissingMessage)
	}
	if ne.Timestamp.IsZero() {
		ve.add("timestamp", ErrInvalidTimestamp)
	}
	return ve.asError()
}

// IsErrorLevel reports whether this event is severe enough to enter the
// error-correlation / signature-hashing path at all. Debug/info noise never
// reaches the LLM context pipeline.
func (ne *NormalizedEvent) IsErrorLevel() bool {
	return ne.Severity.AtLeast(SeverityError)
}

// GenerateEventID constructs a deterministic or fallback unique event identifier
// from the stream ID and monotonically increasing sequence number.
func GenerateEventID(streamID string, seqNo uint64) string {
	if streamID != "" {
		return fmt.Sprintf("%s-%d", streamID, seqNo)
	}
	return fmt.Sprintf("evt-%d", seqNo)
}
