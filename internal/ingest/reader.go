package ingest

import (
	"bufio"
	"context"
	"io"
	"strings"
	"sync/atomic"
	"time"

	"github.com/hassan/tracepulse/internal/domain"
)

const defaultMaxLineSize = 64 * 1024

// FrameReader reads raw data streams from an io.Reader line-by-line or
// multi-line block and sends discrete RawEvents into a channel for processing.
type FrameReader struct {
	StreamID    string
	Source      domain.SourceType
	MaxLineSize int
}

func NewFrameReader(streamID string, source domain.SourceType) *FrameReader {
	return &FrameReader{
		StreamID:    streamID,
		Source:      source,
		MaxLineSize: defaultMaxLineSize,
	}
}

// ReadStream reads from r until EOF or ctx is done, emitting RawEvents to out.
func (fr *FrameReader) ReadStream(ctx context.Context, r io.Reader, out chan<- domain.RawEvent) error {
	if fr.Source == domain.SourceStackTrace {
		return fr.readStackTraceStream(ctx, r, out)
	}
	return fr.readLineStream(ctx, r, out)
}

func (fr *FrameReader) readLineStream(ctx context.Context, r io.Reader, out chan<- domain.RawEvent) error {
	scanner := bufio.NewScanner(r)
	maxBuf := fr.MaxLineSize
	if maxBuf <= 0 {
		maxBuf = defaultMaxLineSize
	}
	scanner.Buffer(make([]byte, 4096), maxBuf)

	var seqNo uint64

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		payloadCopy := make([]byte, len(line))
		copy(payloadCopy, line)

		seq := atomic.AddUint64(&seqNo, 1)

		raw := domain.RawEvent{
			Source:     fr.Source,
			Payload:    payloadCopy,
			StreamID:   fr.StreamID,
			ReceivedAt: time.Now().UTC(),
			SeqNo:      seq,
		}

		select {
		case out <- raw:
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	return scanner.Err()
}

func (fr *FrameReader) readStackTraceStream(ctx context.Context, r io.Reader, out chan<- domain.RawEvent) error {
	scanner := bufio.NewScanner(r)
	maxBuf := fr.MaxLineSize
	if maxBuf <= 0 {
		maxBuf = defaultMaxLineSize
	}
	scanner.Buffer(make([]byte, 4096), maxBuf)

	var (
		seqNo     uint64
		traceBuf  []string
		flushPrev = func() error {
			if len(traceBuf) == 0 {
				return nil
			}
			payload := []byte(strings.Join(traceBuf, "\n"))
			seq := atomic.AddUint64(&seqNo, 1)

			raw := domain.RawEvent{
				Source:     domain.SourceStackTrace,
				Payload:    payload,
				StreamID:   fr.StreamID,
				ReceivedAt: time.Now().UTC(),
				SeqNo:      seq,
			}

			traceBuf = traceBuf[:0]

			select {
			case out <- raw:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	)

	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimRight(line, "\r\n")
		if trimmed == "" {
			if err := flushPrev(); err != nil {
				return err
			}
			continue
		}

		isContinuation := strings.HasPrefix(line, "\t") ||
			strings.HasPrefix(line, "    ") ||
			strings.HasPrefix(strings.TrimSpace(line), "at ")

		if isContinuation && len(traceBuf) > 0 {
			traceBuf = append(traceBuf, trimmed)
		} else {
			if err := flushPrev(); err != nil {
				return err
			}
			traceBuf = append(traceBuf, trimmed)
		}
	}

	if err := flushPrev(); err != nil {
		return err
	}

	return scanner.Err()
}
