package domain

import (
	"errors"
	"fmt"
	"strings"
)

// Sentinel errors. Compared with errors.Is by callers across package
// boundaries (ingestion, pipeline, API layers).
var (
	ErrEmptyPayload     = errors.New("domain: empty raw payload")
	ErrUnknownSource    = errors.New("domain: unknown source type")
	ErrMissingService   = errors.New("domain: missing service name")
	ErrMissingMessage   = errors.New("domain: missing message body")
	ErrInvalidTimestamp = errors.New("domain: invalid or zero timestamp")
	ErrEmptySignatureIn = errors.New("domain: cannot compute signature from empty inputs")
)

// FieldError describes a single field-level validation failure.
type FieldError struct {
	Field string
	Err   error
}

func (fe *FieldError) Error() string {
	return fmt.Sprintf("%s: %v", fe.Field, fe.Err)
}

func (fe *FieldError) Unwrap() error {
	return fe.Err
}

// ValidationError aggregates one or more FieldErrors so callers can report
// every violation at once instead of failing fast on the first field. It
// implements error and supports errors.Is/As against the underlying
// sentinel errors via Unwrap.
type ValidationError struct {
	Fields []*FieldError
}

func (ve *ValidationError) Error() string {
	if len(ve.Fields) == 0 {
		return "domain: validation failed"
	}
	parts := make([]string, 0, len(ve.Fields))
	for _, fe := range ve.Fields {
		parts = append(parts, fe.Error())
	}
	return "domain: validation failed: " + strings.Join(parts, "; ")
}

// Unwrap exposes all underlying field errors so errors.Is(err, ErrX) works
// through a ValidationError without callers needing to type-assert first.
func (ve *ValidationError) Unwrap() []error {
	errs := make([]error, len(ve.Fields))
	for i, fe := range ve.Fields {
		errs[i] = fe
	}
	return errs
}

func (ve *ValidationError) add(field string, err error) {
	ve.Fields = append(ve.Fields, &FieldError{Field: field, Err: err})
}

func (ve *ValidationError) HasErrors() bool {
	return len(ve.Fields) > 0
}

// asError returns nil if ve carries no field errors, otherwise ve itself.
// Lets Validate() methods return a typed *ValidationError while still
// satisfying a plain nil-on-success error contract.
func (ve *ValidationError) asError() error {
	if !ve.HasErrors() {
		return nil
	}
	return ve
}
