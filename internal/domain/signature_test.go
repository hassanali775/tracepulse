package domain

import (
	"errors"
	"testing"
)

func TestHasher_Compute_Deduplication(t *testing.T) {
	h := NewHasher()

	// Two events that are "the same" error occurring twice, differing
	// only in request ID, timestamp-derived number, and memory address —
	// exactly the noise a production incident spams repeatedly.
	e1 := &NormalizedEvent{
		Service: "checkout-api",
		Message: `nil pointer dereference for request "req-8231" at 0xc00012e000`,
		StackFrames: []string{
			"main.processOrder:file.go:142",
			"main.handleRequest:file.go:88 +0x1a2b",
		},
	}
	e2 := &NormalizedEvent{
		Service: "checkout-api",
		Message: `nil pointer dereference for request "req-9542" at 0xc0004b2100`,
		StackFrames: []string{
			"main.processOrder:file.go:142",
			"main.handleRequest:file.go:91 +0x3fce",
		},
	}

	sig1, err := h.Compute(e1)
	if err != nil {
		t.Fatalf("Compute(e1) unexpected error: %v", err)
	}
	sig2, err := h.Compute(e2)
	if err != nil {
		t.Fatalf("Compute(e2) unexpected error: %v", err)
	}

	if sig1.Hash != sig2.Hash {
		t.Errorf("expected identical hashes for structurally identical errors, got %q vs %q\ntemplate1: %q\ntemplate2: %q",
			sig1.Hash, sig2.Hash, sig1.Template, sig2.Template)
	}
}

func TestHasher_Compute_DistinctErrorsDiffer(t *testing.T) {
	h := NewHasher()

	e1 := &NormalizedEvent{
		Service: "checkout-api",
		Message: "connection refused to payments-db",
	}
	e2 := &NormalizedEvent{
		Service: "checkout-api",
		Message: "context deadline exceeded calling inventory-service",
	}

	sig1, _ := h.Compute(e1)
	sig2, _ := h.Compute(e2)

	if sig1.Hash == sig2.Hash {
		t.Errorf("expected distinct hashes for distinct errors, both got %q", sig1.Hash)
	}
}

func TestHasher_Compute_DifferentServiceDiffers(t *testing.T) {
	h := NewHasher()

	e1 := &NormalizedEvent{Service: "checkout-api", Message: "timeout"}
	e2 := &NormalizedEvent{Service: "inventory-api", Message: "timeout"}

	sig1, _ := h.Compute(e1)
	sig2, _ := h.Compute(e2)

	if sig1.Hash == sig2.Hash {
		t.Error("expected same message on different services to produce different signatures")
	}
}

func TestHasher_Compute_FrameDepthBounded(t *testing.T) {
	h := &Hasher{MaxFrames: 2}

	base := &NormalizedEvent{
		Service: "checkout-api",
		Message: "panic: index out of range",
		StackFrames: []string{
			"main.a:file.go:1",
			"main.b:file.go:2",
			"main.c:file.go:3",
		},
	}
	deeper := &NormalizedEvent{
		Service: "checkout-api",
		Message: "panic: index out of range",
		StackFrames: []string{
			"main.a:file.go:1",
			"main.b:file.go:2",
			"main.z:file.go:999", // differs only beyond MaxFrames
		},
	}

	sig1, _ := h.Compute(base)
	sig2, _ := h.Compute(deeper)

	if sig1.Hash != sig2.Hash {
		t.Errorf("expected frames beyond MaxFrames to be ignored, got %q vs %q", sig1.Hash, sig2.Hash)
	}
}

func TestHasher_Compute_EmptyInputs(t *testing.T) {
	h := NewHasher()
	_, err := h.Compute(&NormalizedEvent{})
	if !errors.Is(err, ErrEmptySignatureIn) {
		t.Fatalf("expected ErrEmptySignatureIn, got %v", err)
	}
}

func TestHasher_Compute_HashFormat(t *testing.T) {
	h := NewHasher()
	sig, err := h.Compute(&NormalizedEvent{Service: "svc", Message: "boom"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(sig.Hash) != 32 { // 16 bytes hex-encoded
		t.Errorf("expected 32-char hex hash, got %d chars: %q", len(sig.Hash), sig.Hash)
	}
}

func TestNormalizeMessage(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "collapses numbers",
			in:   "retry attempt 3 of 5 failed",
			want: "retry attempt <n> of <n> failed",
		},
		{
			name: "collapses quoted literals",
			in:   `user "alice" not found`,
			want: `user <str> not found`,
		},
		{
			name: "collapses uuid",
			in:   "order 550e8400-e29b-41d4-a716-446655440000 missing",
			want: "order <uuid> missing",
		},
		{
			name: "collapses hex address",
			in:   "segfault at 0xc00012e000",
			want: "segfault at <hex>",
		},
		{
			name: "collapses ipv4 with port",
			in:   "dial tcp 10.0.0.5:5432: connect: connection refused",
			want: "dial tcp <ip>: connect: connection refused",
		},
		{
			name: "collapses whitespace",
			in:   "too    many\tspaces\nhere",
			want: "too many spaces here",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := normalizeMessage(tc.in); got != tc.want {
				t.Errorf("normalizeMessage(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestNormalizeFrame(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "strips line number",
			in:   "main.processOrder:file.go:142",
			want: "main.processOrder:file.go",
		},
		{
			name: "strips line number and pc offset",
			in:   "main.handleRequest:file.go:88 +0x1a2b",
			want: "main.handleRequest:file.go",
		},
		{
			name: "no trailing numeric suffix left unchanged",
			in:   "runtime.gopanic",
			want: "runtime.gopanic",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := normalizeFrame(tc.in); got != tc.want {
				t.Errorf("normalizeFrame(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func BenchmarkHasher_Compute(b *testing.B) {
	h := NewHasher()
	ne := &NormalizedEvent{
		Service: "checkout-api",
		Message: `nil pointer dereference for request "req-8231" at 0xc00012e000`,
		StackFrames: []string{
			"main.processOrder:file.go:142",
			"main.handleRequest:file.go:88 +0x1a2b",
			"main.serveHTTP:server.go:301",
		},
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := h.Compute(ne); err != nil {
			b.Fatal(err)
		}
	}
}
