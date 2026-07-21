package domain

import (
	"errors"
	"testing"
	"time"
)

func TestSourceType_Valid(t *testing.T) {
	cases := []struct {
		name string
		src  SourceType
		want bool
	}{
		{"json", SourceJSON, true},
		{"syslog", SourceSyslog, true},
		{"stacktrace", SourceStackTrace, true},
		{"unknown", SourceUnknown, false},
		{"garbage", SourceType("csv"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.src.Valid(); got != tc.want {
				t.Errorf("Valid() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestParseSeverity(t *testing.T) {
	cases := []struct {
		in   string
		want Severity
	}{
		{"debug", SeverityDebug},
		{"trace", SeverityDebug},
		{"info", SeverityInfo},
		{"notice", SeverityInfo},
		{"warn", SeverityWarn},
		{"warning", SeverityWarn},
		{"error", SeverityError},
		{"err", SeverityError},
		{"fatal", SeverityFatal},
		{"panic", SeverityFatal},
		{"critical", SeverityFatal},
		{"nonsense", SeverityUnknown},
		{"", SeverityUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			if got := ParseSeverity(tc.in); got != tc.want {
				t.Errorf("ParseSeverity(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestSeverity_AtLeast(t *testing.T) {
	if !SeverityFatal.AtLeast(SeverityError) {
		t.Error("fatal should be at least error")
	}
	if SeverityWarn.AtLeast(SeverityError) {
		t.Error("warn should not be at least error")
	}
}

func TestRawEvent_Validate(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name    string
		event   RawEvent
		wantErr bool
		wantIs  error
	}{
		{
			name: "valid",
			event: RawEvent{
				Source:     SourceJSON,
				Payload:    []byte(`{"msg":"boom"}`),
				ReceivedAt: now,
			},
			wantErr: false,
		},
		{
			name: "empty payload",
			event: RawEvent{
				Source:     SourceJSON,
				Payload:    nil,
				ReceivedAt: now,
			},
			wantErr: true,
			wantIs:  ErrEmptyPayload,
		},
		{
			name: "unknown source",
			event: RawEvent{
				Source:     SourceType("csv"),
				Payload:    []byte("a,b,c"),
				ReceivedAt: now,
			},
			wantErr: true,
			wantIs:  ErrUnknownSource,
		},
		{
			name: "zero timestamp",
			event: RawEvent{
				Source:  SourceSyslog,
				Payload: []byte("<34>1 msg"),
			},
			wantErr: true,
			wantIs:  ErrInvalidTimestamp,
		},
		{
			name:    "all invalid",
			event:   RawEvent{},
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.event.Validate()
			if (err != nil) != tc.wantErr {
				t.Fatalf("Validate() error = %v, wantErr %v", err, tc.wantErr)
			}
			if tc.wantIs != nil && !errors.Is(err, tc.wantIs) {
				t.Errorf("Validate() error = %v, want errors.Is match for %v", err, tc.wantIs)
			}
		})
	}
}

func TestNormalizedEvent_Validate(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name    string
		event   NormalizedEvent
		wantErr bool
		wantIs  error
	}{
		{
			name: "valid",
			event: NormalizedEvent{
				Source:    SourceJSON,
				Service:   "checkout-api",
				Message:   "nil pointer dereference",
				Timestamp: now,
			},
			wantErr: false,
		},
		{
			name: "missing service",
			event: NormalizedEvent{
				Source:    SourceJSON,
				Message:   "boom",
				Timestamp: now,
			},
			wantErr: true,
			wantIs:  ErrMissingService,
		},
		{
			name: "missing message",
			event: NormalizedEvent{
				Source:    SourceJSON,
				Service:   "checkout-api",
				Timestamp: now,
			},
			wantErr: true,
			wantIs:  ErrMissingMessage,
		},
		{
			name: "zero timestamp",
			event: NormalizedEvent{
				Source:  SourceJSON,
				Service: "checkout-api",
				Message: "boom",
			},
			wantErr: true,
			wantIs:  ErrInvalidTimestamp,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.event.Validate()
			if (err != nil) != tc.wantErr {
				t.Fatalf("Validate() error = %v, wantErr %v", err, tc.wantErr)
			}
			if tc.wantIs != nil && !errors.Is(err, tc.wantIs) {
				t.Errorf("Validate() error = %v, want errors.Is match for %v", err, tc.wantIs)
			}
		})
	}
}

func TestNormalizedEvent_IsErrorLevel(t *testing.T) {
	cases := []struct {
		sev  Severity
		want bool
	}{
		{SeverityDebug, false},
		{SeverityInfo, false},
		{SeverityWarn, false},
		{SeverityError, true},
		{SeverityFatal, true},
	}
	for _, tc := range cases {
		ne := NormalizedEvent{Severity: tc.sev}
		if got := ne.IsErrorLevel(); got != tc.want {
			t.Errorf("IsErrorLevel() with severity %v = %v, want %v", tc.sev, got, tc.want)
		}
	}
}
