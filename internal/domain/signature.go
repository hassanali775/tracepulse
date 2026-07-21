package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"
	"sync"
)

// Precompiled once at package init. These run on every ingested error-level
// event, so compiling per-call would turn signature hashing into the
// pipeline's hottest allocation source.
var (
	reUUID       = regexp.MustCompile(`(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)
	reHexAddr    = regexp.MustCompile(`0x[0-9a-fA-F]+`)
	reIPv4       = regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?\b`)
	reNumber     = regexp.MustCompile(`\d+`)
	reQuoted     = regexp.MustCompile(`"[^"]*"|'[^']*'`)
	reWhitespace = regexp.MustCompile(`\s+`)

	// Strips trailing "file.go:123" line numbers and "+0x1a2b" program
	// counter offsets from stack frames, leaving the function/symbol name
	// as the stable part of the frame.
	reFrameLine = regexp.MustCompile(`:\d+(\s*\+0x[0-9a-fA-F]+)?\s*$`)
)

// builderPool reuses strings.Builder instances across Compute calls to keep
// the hot path allocation-free for the builder itself; only the final
// string materialization allocates.
var builderPool = sync.Pool{
	New: func() any { return new(strings.Builder) },
}

// Signature is the result of hashing a NormalizedEvent's error identity.
// Hash is the stable, compact identifier used for dedup lookups; Template
// is retained for debugging/observability (e.g. surfacing "what pattern
// did this collapse to" in the web playground).
type Signature struct {
	Hash     string
	Template string
}

// Hasher computes ErrorSignatures from NormalizedEvents. It is stateless
// and safe for concurrent use by every ingestion worker goroutine — no
// locking needed on the hot path.
type Hasher struct {
	// MaxFrames bounds how many top stack frames participate in the
	// signature. Bounded deliberately: unbounded frame inclusion would
	// make near-identical panics at different call depths hash
	// differently, defeating deduplication.
	MaxFrames int
}

// NewHasher returns a Hasher with a sane default frame depth. Callers
// needing a different depth can construct Hasher{MaxFrames: n} directly.
func NewHasher() *Hasher {
	return &Hasher{MaxFrames: 5}
}

// Compute derives a Signature from ne. It never mutates ne. Returns
// ErrEmptySignatureIn if both Service and Message are empty, since no
// stable identity can be derived from nothing.
func (h *Hasher) Compute(ne *NormalizedEvent) (Signature, error) {
	if ne.Service == "" && ne.Message == "" {
		return Signature{}, ErrEmptySignatureIn
	}

	maxFrames := h.MaxFrames
	if maxFrames <= 0 {
		maxFrames = 5
	}

	b := builderPool.Get().(*strings.Builder)
	b.Reset()
	defer builderPool.Put(b)

	b.WriteString(ne.Service)
	b.WriteByte('|')
	b.WriteString(normalizeMessage(ne.Message))

	frames := ne.StackFrames
	if len(frames) > maxFrames {
		frames = frames[:maxFrames]
	}
	for _, f := range frames {
		b.WriteByte('\n')
		b.WriteString(normalizeFrame(f))
	}

	template := b.String()

	sum := sha256.Sum256([]byte(template))
	// First 16 bytes (128 bits) hex-encoded: ample collision resistance
	// for a dedup key while keeping IDs short enough to log and to use as
	// DLQ/metrics label values.
	hash := hex.EncodeToString(sum[:16])

	return Signature{Hash: hash, Template: template}, nil
}

// normalizeMessage strips high-cardinality, run-specific tokens (UUIDs,
// hex addresses, IPs, bare numbers, quoted literals) from a message so
// that structurally identical errors differing only in their dynamic
// values collapse to the same template.
func normalizeMessage(msg string) string {
	s := reUUID.ReplaceAllString(msg, "<uuid>")
	s = reHexAddr.ReplaceAllString(s, "<hex>")
	s = reIPv4.ReplaceAllString(s, "<ip>")
	s = reQuoted.ReplaceAllString(s, "<str>")
	s = reNumber.ReplaceAllString(s, "<n>")
	s = reWhitespace.ReplaceAllString(s, " ")
	return strings.TrimSpace(s)
}

// normalizeFrame strips the line-number/PC-offset suffix from a stack
// frame, keeping the function/file symbol stable across builds where line
// numbers shift but the call site does not.
func normalizeFrame(frame string) string {
	s := reFrameLine.ReplaceAllString(strings.TrimSpace(frame), "")
	s = reHexAddr.ReplaceAllString(s, "<hex>")
	return s
}
