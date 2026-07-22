package ingest

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"

	"github.com/hassan/tracepulse/internal/domain"
)

var (
	ErrPoolClosed   = errors.New("ingest: worker pool is closed")
	ErrPoolFull     = errors.New("ingest: worker pool buffer is full")
	ErrNilNextStage = errors.New("ingest: nil output channel provided")
)

// Stats carries runtime performance metrics for the WorkerPool.
type Stats struct {
	IngestedCount uint64
	ParsedCount   uint64
	ErrorCount    uint64
	DroppedCount  uint64
}

// WorkerPool manages a pool of concurrent worker goroutines that parse
// RawEvents, apply validation rules, compute error signatures, and push
// NormalizedEvents to downstream channels with backpressure control.
type WorkerPool struct {
	numWorkers int
	bufferSize int
	hasher     *domain.Hasher
	parser     Parser
	in         chan domain.RawEvent
	out        chan<- *domain.NormalizedEvent

	wg      sync.WaitGroup
	closed  atomic.Bool
	started atomic.Bool

	// Metrics
	ingestedCount uint64
	parsedCount   uint64
	errorCount    uint64
	droppedCount  uint64
}

func NewWorkerPool(
	numWorkers int,
	bufferSize int,
	hasher *domain.Hasher,
	parser Parser,
	out chan<- *domain.NormalizedEvent,
) (*WorkerPool, error) {
	if numWorkers <= 0 {
		numWorkers = 4
	}
	if bufferSize <= 0 {
		bufferSize = 256
	}
	if hasher == nil {
		hasher = domain.NewHasher()
	}
	if parser == nil {
		parser = NewMultiParser()
	}
	if out == nil {
		return nil, ErrNilNextStage
	}

	return &WorkerPool{
		numWorkers: numWorkers,
		bufferSize: bufferSize,
		hasher:     hasher,
		parser:     parser,
		in:         make(chan domain.RawEvent, bufferSize),
		out:        out,
	}, nil
}

// InChannel returns the bounded channel used to submit raw events to the pool.
func (wp *WorkerPool) InChannel() chan<- domain.RawEvent {
	return wp.in
}

// Start launches worker goroutines that listen on the input channel.
func (wp *WorkerPool) Start(ctx context.Context) {
	if !wp.started.CompareAndSwap(false, true) {
		return
	}

	for i := 0; i < wp.numWorkers; i++ {
		wp.wg.Add(1)
		go wp.worker(ctx)
	}
}

// Submit sends a RawEvent to the pool. Blocks if the pool buffer is full,
// respecting context cancellation. Returns ErrPoolClosed if pool is closed.
func (wp *WorkerPool) Submit(ctx context.Context, raw domain.RawEvent) error {
	if wp.closed.Load() {
		return ErrPoolClosed
	}
	if err := ctx.Err(); err != nil {
		atomic.AddUint64(&wp.droppedCount, 1)
		return err
	}

	select {
	case wp.in <- raw:
		atomic.AddUint64(&wp.ingestedCount, 1)
		return nil
	case <-ctx.Done():
		atomic.AddUint64(&wp.droppedCount, 1)
		return ctx.Err()
	}
}

// TrySubmit non-blockingly attempts to submit a RawEvent. Returns ErrPoolFull if buffer is full.
func (wp *WorkerPool) TrySubmit(raw domain.RawEvent) error {
	if wp.closed.Load() {
		return ErrPoolClosed
	}

	select {
	case wp.in <- raw:
		atomic.AddUint64(&wp.ingestedCount, 1)
		return nil
	default:
		atomic.AddUint64(&wp.droppedCount, 1)
		return ErrPoolFull
	}
}

func (wp *WorkerPool) worker(ctx context.Context) {
	defer wp.wg.Done()

	for {
		select {
		case raw, ok := <-wp.in:
			if !ok {
				return
			}
			wp.processRaw(ctx, raw)
		case <-ctx.Done():
			for {
				select {
				case raw, ok := <-wp.in:
					if !ok {
						return
					}
					wp.processRaw(ctx, raw)
				default:
					return
				}
			}
		}
	}
}

func (wp *WorkerPool) processRaw(ctx context.Context, raw domain.RawEvent) {
	if err := raw.Validate(); err != nil {
		atomic.AddUint64(&wp.errorCount, 1)
		return
	}

	ne, err := wp.parser.Parse(raw)
	if err != nil {
		atomic.AddUint64(&wp.errorCount, 1)
		return
	}

	if ne.ID == "" {
		ne.ID = domain.GenerateEventID(raw.StreamID, raw.SeqNo)
	}

	if err := ne.Validate(); err != nil {
		atomic.AddUint64(&wp.errorCount, 1)
		return
	}

	if ne.IsErrorLevel() {
		sig, err := wp.hasher.Compute(ne)
		if err == nil {
			ne.Signature = sig.Hash
		}
	}

	atomic.AddUint64(&wp.parsedCount, 1)

	select {
	case wp.out <- ne:
	case <-ctx.Done():
		atomic.AddUint64(&wp.droppedCount, 1)
	}
}

// Stop closes the input channel and waits for all active workers to finish draining.
func (wp *WorkerPool) Stop() {
	if wp.closed.CompareAndSwap(false, true) {
		close(wp.in)
		wp.wg.Wait()
	}
}

// Stats returns current operational metrics.
func (wp *WorkerPool) Stats() Stats {
	return Stats{
		IngestedCount: atomic.LoadUint64(&wp.ingestedCount),
		ParsedCount:   atomic.LoadUint64(&wp.parsedCount),
		ErrorCount:    atomic.LoadUint64(&wp.errorCount),
		DroppedCount:  atomic.LoadUint64(&wp.droppedCount),
	}
}
