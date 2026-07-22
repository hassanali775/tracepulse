package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"sync"
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
	appendNormalizedMessage(b, ne.Message)

	frames := ne.StackFrames
	if len(frames) > maxFrames {
		frames = frames[:maxFrames]
	}
	for _, f := range frames {
		b.WriteByte('\n')
		appendNormalizedFrame(b, f)
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
// hex addresses, IPs, bare numbers, quoted literals) from a message using
// a single-pass byte scanner (zero regex) so that structurally identical
// errors collapse to the same template with zero allocations.
func normalizeMessage(msg string) string {
	var b strings.Builder
	appendNormalizedMessage(&b, msg)
	return b.String()
}

func appendNormalizedMessage(b *strings.Builder, msg string) {
	pendingSpace := false
	writtenAny := false
	var prevByte byte

	for i := 0; i < len(msg); {
		ch := msg[i]

		if isSpace(ch) {
			if writtenAny {
				pendingSpace = true
			}
			i++
			continue
		}

		if pendingSpace {
			b.WriteByte(' ')
			pendingSpace = false
			prevByte = ' '
		}

		// 1. Quoted literal: "..." or '...'
		if ch == '"' || ch == '\'' {
			q := ch
			end := -1
			for j := i + 1; j < len(msg); j++ {
				if msg[j] == q {
					end = j
					break
				}
			}
			if end != -1 {
				b.WriteString("<str>")
				i = end + 1
				writtenAny = true
				prevByte = '>'
				continue
			}
		}

		// 2. Hex address: 0x...
		if n := matchHexAddr(msg[i:]); n > 0 {
			b.WriteString("<hex>")
			i += n
			writtenAny = true
			prevByte = '>'
			continue
		}

		// 3. UUID: 8-4-4-4-12
		if isUUID(msg[i:]) {
			b.WriteString("<uuid>")
			i += 36
			writtenAny = true
			prevByte = '>'
			continue
		}

		// 4. IPv4 with optional port
		if n := matchIPv4(msg[i:], prevByte, !writtenAny); n > 0 {
			b.WriteString("<ip>")
			i += n
			writtenAny = true
			prevByte = '>'
			continue
		}

		// 5. Numbers: \d+
		if isDigit(ch) {
			for i < len(msg) && isDigit(msg[i]) {
				i++
			}
			b.WriteString("<n>")
			writtenAny = true
			prevByte = '>'
			continue
		}

		// 6. Default byte
		b.WriteByte(ch)
		writtenAny = true
		prevByte = ch
		i++
	}
}

// normalizeFrame strips line-number/PC-offset suffixes and hex addresses
// from a stack frame string using hand-rolled byte scanning.
func normalizeFrame(frame string) string {
	var b strings.Builder
	appendNormalizedFrame(&b, frame)
	return b.String()
}

func appendNormalizedFrame(b *strings.Builder, frame string) {
	s := strings.TrimSpace(frame)

	// Strip +0x... PC offset suffix if present
	if idx := strings.LastIndex(s, "+0x"); idx != -1 || strings.LastIndex(s, "+0X") != -1 {
		plusIdx := strings.LastIndex(s, "+")
		if plusIdx != -1 {
			valid := true
			for j := plusIdx + 3; j < len(s); j++ {
				if !isHexDigit(s[j]) && !isSpace(s[j]) {
					valid = false
					break
				}
			}
			if valid {
				s = strings.TrimSpace(s[:plusIdx])
			}
		}
	}

	// Strip :line_number suffix if present
	if colonIdx := strings.LastIndex(s, ":"); colonIdx != -1 && colonIdx < len(s)-1 {
		allDigits := true
		for j := colonIdx + 1; j < len(s); j++ {
			if !isDigit(s[j]) {
				allDigits = false
				break
			}
		}
		if allDigits {
			s = s[:colonIdx]
		}
	}

	s = strings.TrimSpace(s)

	// Replace any 0x... in frame with <hex>
	for i := 0; i < len(s); {
		if n := matchHexAddr(s[i:]); n > 0 {
			b.WriteString("<hex>")
			i += n
		} else {
			b.WriteByte(s[i])
			i++
		}
	}
}

func isDigit(c byte) bool {
	return c >= '0' && c <= '9'
}

func isHexDigit(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

func isSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f'
}

func isWordByte(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_'
}

func matchHexAddr(s string) int {
	if len(s) < 3 || s[0] != '0' || (s[1] != 'x' && s[1] != 'X') || !isHexDigit(s[2]) {
		return 0
	}
	n := 2
	for n < len(s) && isHexDigit(s[n]) {
		n++
	}
	return n
}

func isUUID(s string) bool {
	if len(s) < 36 {
		return false
	}
	if s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
		return false
	}
	for i := 0; i < 36; i++ {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			continue
		}
		if !isHexDigit(s[i]) {
			return false
		}
	}
	return true
}

func matchIPv4(s string, prevByte byte, isStart bool) int {
	if !isStart && isWordByte(prevByte) {
		return 0
	}
	idx := 0
	for octet := 0; octet < 4; octet++ {
		if octet > 0 {
			if idx >= len(s) || s[idx] != '.' {
				return 0
			}
			idx++
		}
		startNum := idx
		num := 0
		for idx < len(s) && isDigit(s[idx]) && idx-startNum < 3 {
			num = num*10 + int(s[idx]-'0')
			idx++
		}
		if idx == startNum || num > 255 {
			return 0
		}
	}
	if idx < len(s) && s[idx] == ':' {
		portStart := idx + 1
		portIdx := portStart
		for portIdx < len(s) && isDigit(s[portIdx]) {
			portIdx++
		}
		if portIdx > portStart {
			idx = portIdx
		}
	}
	if idx < len(s) && isWordByte(s[idx]) {
		return 0
	}
	return idx
}
