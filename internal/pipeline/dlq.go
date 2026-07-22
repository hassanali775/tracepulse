package pipeline

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/hassan/tracepulse/internal/domain"
)

var (
	ErrDLQClosed = errors.New("dlq: writer is closed")
)

// DLQRecord represents an unparseable or unprocessable event saved to the Dead-Letter Queue.
type DLQRecord struct {
	EventID      string            `json:"event_id"`
	StreamID     string            `json:"stream_id"`
	SeqNo        uint64            `json:"seq_no"`
	Source       domain.SourceType `json:"source"`
	RawPayload   string            `json:"raw_payload"`
	Reason       string            `json:"reason"`
	FailedAt     time.Time         `json:"failed_at"`
	AttemptCount int               `json:"attempt_count"`
}

// DLQWriter provides thread-safe, buffered writing of failed events to a Dead-Letter Queue file or io.Writer.
type DLQWriter struct {
	mu     sync.Mutex
	w      io.Writer
	closer io.Closer
	closed bool
}

// NewDLQFileWriter opens or creates a JSON Lines file for DLQ storage.
func NewDLQFileWriter(filePath string) (*DLQWriter, error) {
	dir := filepath.Dir(filePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, err
	}

	f, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, err
	}

	return &DLQWriter{
		w:      f,
		closer: f,
	}, nil
}

// NewDLQWriter creates a DLQWriter from an arbitrary io.Writer (e.g. bytes.Buffer or stdout for testing).
func NewDLQWriter(w io.Writer) *DLQWriter {
	return &DLQWriter{
		w: w,
	}
}

// Write records a failure into the DLQ.
func (dw *DLQWriter) Write(raw domain.RawEvent, reason string, attempts int) error {
	dw.mu.Lock()
	defer dw.mu.Unlock()

	if dw.closed {
		return ErrDLQClosed
	}

	rec := DLQRecord{
		EventID:      domain.GenerateEventID(raw.StreamID, raw.SeqNo),
		StreamID:     raw.StreamID,
		SeqNo:        raw.SeqNo,
		Source:       raw.Source,
		RawPayload:   string(raw.Payload),
		Reason:       reason,
		FailedAt:     time.Now().UTC(),
		AttemptCount: attempts,
	}

	data, err := json.Marshal(rec)
	if err != nil {
		return err
	}

	data = append(data, '\n')
	_, err = dw.w.Write(data)
	return err
}

// Close flushes and closes the underlying file if owned.
func (dw *DLQWriter) Close() error {
	dw.mu.Lock()
	defer dw.mu.Unlock()

	if dw.closed {
		return nil
	}
	dw.closed = true

	if dw.closer != nil {
		return dw.closer.Close()
	}
	return nil
}
