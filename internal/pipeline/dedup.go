package pipeline

import (
	"sync"
	"time"
)

// DedupRecord tracks aggregation metrics for a unique error signature within a sliding window.
type DedupRecord struct {
	Signature string
	FirstSeen time.Time
	LastSeen  time.Time
	Count     int64
}

// DedupStore provides concurrent, sliding time-window deduplication for Error Signatures.
// Identical errors occurring within the WindowDuration window share a single record,
// ensuring only novel errors pass downstream to LLM diagnosis.
type DedupStore struct {
	mu             sync.RWMutex
	windowDuration time.Duration
	records        map[string]*DedupRecord
	stopCleanup    chan struct{}
	cleanupWg      sync.WaitGroup
}

// NewDedupStore creates a DedupStore with a sliding window duration (e.g. 5 minutes)
// and starts a background cleanup ticker to sweep expired records.
func NewDedupStore(windowDuration time.Duration, cleanupInterval time.Duration) *DedupStore {
	if windowDuration <= 0 {
		windowDuration = 5 * time.Minute
	}
	if cleanupInterval <= 0 {
		cleanupInterval = 1 * time.Minute
	}

	ds := &DedupStore{
		windowDuration: windowDuration,
		records:        make(map[string]*DedupRecord),
		stopCleanup:    make(chan struct{}),
	}

	ds.cleanupWg.Add(1)
	go ds.startCleanupLoop(cleanupInterval)

	return ds
}

// Allow evaluates an Error Signature.
// Returns isNovel=true if this signature is newly seen within the current window,
// along with the updated total count for this signature in the window.
func (ds *DedupStore) Allow(sig string) (isNovel bool, count int64) {
	if sig == "" {
		return true, 1
	}

	now := time.Now().UTC()

	ds.mu.Lock()
	defer ds.mu.Unlock()

	rec, exists := ds.records[sig]
	if !exists || now.Sub(rec.FirstSeen) >= ds.windowDuration {
		ds.records[sig] = &DedupRecord{
			Signature: sig,
			FirstSeen: now,
			LastSeen:  now,
			Count:     1,
		}
		return true, 1
	}

	rec.Count++
	rec.LastSeen = now
	return false, rec.Count
}

// GetRecord returns a snapshot copy of a DedupRecord for a given signature.
func (ds *DedupStore) GetRecord(sig string) (DedupRecord, bool) {
	ds.mu.RLock()
	defer ds.mu.RUnlock()

	rec, exists := ds.records[sig]
	if !exists {
		return DedupRecord{}, false
	}
	return *rec, true
}

// Size returns the current number of active tracked signatures in the store.
func (ds *DedupStore) Size() int {
	ds.mu.RLock()
	defer ds.mu.RUnlock()
	return len(ds.records)
}

func (ds *DedupStore) startCleanupLoop(interval time.Duration) {
	defer ds.cleanupWg.Done()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			ds.evictExpired()
		case <-ds.stopCleanup:
			return
		}
	}
}

func (ds *DedupStore) evictExpired() {
	now := time.Now().UTC()

	ds.mu.Lock()
	defer ds.mu.Unlock()

	for sig, rec := range ds.records {
		if now.Sub(rec.LastSeen) >= ds.windowDuration {
			delete(ds.records, sig)
		}
	}
}

// Close stops the background eviction goroutine gracefully.
func (ds *DedupStore) Close() {
	close(ds.stopCleanup)
	ds.cleanupWg.Wait()
}
