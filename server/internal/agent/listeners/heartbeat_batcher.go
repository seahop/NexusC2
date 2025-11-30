// server/internal/agent/listeners/heartbeat_batcher.go
package listeners

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/lib/pq"
)

// HeartbeatBatcher batches lastSEEN updates to reduce database load
// Instead of updating on every GET request (100+/second), batches are flushed every 5 seconds
type HeartbeatBatcher struct {
	updates map[string]time.Time
	mu      sync.Mutex
	ticker  *time.Ticker
	db      *sql.DB
	done    chan struct{}
	wg      sync.WaitGroup

	// Metrics
	totalUpdates   uint64
	batchesFlushed uint64
	flushErrors    uint64
}

// NewHeartbeatBatcher creates a new heartbeat batcher with configurable flush interval
func NewHeartbeatBatcher(db *sql.DB, flushInterval time.Duration) *HeartbeatBatcher {
	if flushInterval == 0 {
		flushInterval = 5 * time.Second // Default: batch every 5 seconds
	}

	return &HeartbeatBatcher{
		updates: make(map[string]time.Time, 1000), // Pre-allocate for ~1000 agents
		db:      db,
		ticker:  time.NewTicker(flushInterval),
		done:    make(chan struct{}),
	}
}

// Start begins the background flushing goroutine
func (hb *HeartbeatBatcher) Start() {
	hb.wg.Add(1)
	go hb.flushLoop()
	log.Printf("HeartbeatBatcher started (flush interval: %v)", hb.ticker.C)
}

// Stop gracefully stops the batcher and flushes remaining updates
func (hb *HeartbeatBatcher) Stop() {
	close(hb.done)
	hb.ticker.Stop()
	hb.wg.Wait()

	// Final flush
	hb.flush()

	log.Printf("HeartbeatBatcher stopped (batches: %d, updates: %d, errors: %d)",
		hb.batchesFlushed, hb.totalUpdates, hb.flushErrors)
}

// RecordHeartbeat records an agent heartbeat for batched update
// This is non-blocking and returns immediately
func (hb *HeartbeatBatcher) RecordHeartbeat(clientID string) {
	hb.mu.Lock()
	hb.updates[clientID] = time.Now()
	hb.totalUpdates++
	hb.mu.Unlock()
}

// flushLoop runs in background and flushes batches on ticker
func (hb *HeartbeatBatcher) flushLoop() {
	defer hb.wg.Done()

	for {
		select {
		case <-hb.done:
			return
		case <-hb.ticker.C:
			hb.flush()
		}
	}
}

// flush executes the batched database update
func (hb *HeartbeatBatcher) flush() {
	// Swap maps under lock (minimize critical section)
	hb.mu.Lock()
	if len(hb.updates) == 0 {
		hb.mu.Unlock()
		return
	}

	updates := hb.updates
	hb.updates = make(map[string]time.Time, len(updates)) // Reuse capacity
	hb.mu.Unlock()

	// Process batch outside lock
	if err := hb.flushBatch(updates); err != nil {
		hb.mu.Lock()
		hb.flushErrors++
		hb.mu.Unlock()
		log.Printf("HeartbeatBatcher flush error: %v (lost %d updates)", err, len(updates))
	} else {
		hb.mu.Lock()
		hb.batchesFlushed++
		hb.mu.Unlock()
		log.Printf("HeartbeatBatcher flushed %d updates", len(updates))
	}
}

// flushBatch performs the actual database update using PostgreSQL-specific array syntax
func (hb *HeartbeatBatcher) flushBatch(updates map[string]time.Time) error {
	if len(updates) == 0 {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Convert map to slices for PostgreSQL unnest
	clientIDs := make([]string, 0, len(updates))
	timestamps := make([]time.Time, 0, len(updates))

	for id, ts := range updates {
		clientIDs = append(clientIDs, id)
		timestamps = append(timestamps, ts)
	}

	// Use PostgreSQL's unnest to perform bulk update
	// This is vastly more efficient than N separate UPDATE statements
	query := `
		UPDATE connections
		SET lastSEEN = u.seen
		FROM (
			SELECT
				unnest($1::uuid[]) as id,
				unnest($2::timestamp[]) as seen
		) as u
		WHERE newclientID = u.id
	`

	result, err := hb.db.ExecContext(ctx, query, pq.Array(clientIDs), pq.Array(timestamps))
	if err != nil {
		return fmt.Errorf("batch update failed: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err == nil && int(rowsAffected) != len(clientIDs) {
		log.Printf("Warning: Expected %d updates, got %d (some agents may be deleted)",
			len(clientIDs), rowsAffected)
	}

	return nil
}

// GetMetrics returns current batcher metrics
func (hb *HeartbeatBatcher) GetMetrics() map[string]interface{} {
	hb.mu.Lock()
	defer hb.mu.Unlock()

	return map[string]interface{}{
		"pending_updates":  len(hb.updates),
		"total_updates":    hb.totalUpdates,
		"batches_flushed":  hb.batchesFlushed,
		"flush_errors":     hb.flushErrors,
		"batch_efficiency": float64(hb.totalUpdates) / float64(max(hb.batchesFlushed, 1)),
	}
}

func max(a, b uint64) uint64 {
	if a > b {
		return a
	}
	return b
}
