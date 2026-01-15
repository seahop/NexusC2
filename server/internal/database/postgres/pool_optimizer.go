// internal/database/postgres/pool_optimizer.go
package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"sync/atomic"
	"time"

	_ "github.com/lib/pq"
)

// PoolOptimizer manages and optimizes database connection pools
type PoolOptimizer struct {
	db           *sql.DB
	config       *PoolConfig
	metrics      *PoolMetrics
	healthTicker *time.Ticker
	stopChan     chan struct{}
}

// PoolConfig holds optimized pool configuration
type PoolConfig struct {
	MaxOpenConns      int
	MaxIdleConns      int
	ConnMaxLifetime   time.Duration
	ConnMaxIdleTime   time.Duration
	HealthCheckPeriod time.Duration
	AutoScale         bool
	ScaleThreshold    float64 // Percentage of connections in use to trigger scaling
}

// PoolMetrics tracks pool performance
type PoolMetrics struct {
	ConnectionsOpened   atomic.Uint64
	ConnectionsClosed   atomic.Uint64
	ConnectionsRecycled atomic.Uint64
	WaitCount           atomic.Uint64
	WaitDuration        atomic.Int64 // in milliseconds
	MaxWaitDuration     atomic.Int64
}

// DefaultOptimizedPoolConfig returns performance-optimized settings
func DefaultOptimizedPoolConfig() *PoolConfig {
	return &PoolConfig{
		MaxOpenConns:      50,
		MaxIdleConns:      25,
		ConnMaxLifetime:   10 * time.Minute,
		ConnMaxIdleTime:   5 * time.Minute,
		HealthCheckPeriod: 30 * time.Second,
		AutoScale:         true,
		ScaleThreshold:    0.8, // Scale when 80% connections are in use
	}
}

// NewPoolOptimizer creates a new pool optimizer
func NewPoolOptimizer(dsn string, config *PoolConfig) (*PoolOptimizer, error) {
	if config == nil {
		config = DefaultOptimizedPoolConfig()
	}

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Apply initial configuration
	db.SetMaxOpenConns(config.MaxOpenConns)
	db.SetMaxIdleConns(config.MaxIdleConns)
	db.SetConnMaxLifetime(config.ConnMaxLifetime)
	db.SetConnMaxIdleTime(config.ConnMaxIdleTime)

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	optimizer := &PoolOptimizer{
		db:       db,
		config:   config,
		metrics:  &PoolMetrics{},
		stopChan: make(chan struct{}),
	}

	// Start health monitoring
	optimizer.startHealthMonitor()

	// Start auto-scaling if enabled
	if config.AutoScale {
		optimizer.startAutoScaler()
	}

	log.Printf("[PoolOptimizer] Initialized with config: %+v", config)

	return optimizer, nil
}

// startHealthMonitor monitors pool health
func (po *PoolOptimizer) startHealthMonitor() {
	po.healthTicker = time.NewTicker(po.config.HealthCheckPeriod)

	go func() {
		for {
			select {
			case <-po.stopChan:
				return
			case <-po.healthTicker.C:
				po.performHealthCheck()
			}
		}
	}()
}

// performHealthCheck checks pool health and logs metrics
func (po *PoolOptimizer) performHealthCheck() {
	stats := po.db.Stats()

	// Update metrics (silently)
	po.metrics.WaitCount.Store(uint64(stats.WaitCount))
	if stats.WaitDuration > 0 {
		waitMs := stats.WaitDuration.Milliseconds()
		po.metrics.WaitDuration.Store(waitMs)

		// Track max wait duration
		currentMax := po.metrics.MaxWaitDuration.Load()
		if waitMs > currentMax {
			po.metrics.MaxWaitDuration.Store(waitMs)
		}
	}

	// Only log when there are issues
	if stats.OpenConnections >= stats.MaxOpenConnections {
		log.Printf("[DB] WARNING: Connection pool at capacity (%d/%d)",
			stats.OpenConnections, stats.MaxOpenConnections)
	}

	if stats.WaitCount > 100 {
		log.Printf("[DB] WARNING: High connection wait count: %d", stats.WaitCount)
	}
}

// startAutoScaler automatically adjusts pool size based on usage
func (po *PoolOptimizer) startAutoScaler() {
	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()

		for {
			select {
			case <-po.stopChan:
				return
			case <-ticker.C:
				po.autoScale()
			}
		}
	}()
}

// autoScale adjusts pool size based on usage patterns
func (po *PoolOptimizer) autoScale() {
	stats := po.db.Stats()

	utilizationRate := float64(stats.InUse) / float64(stats.MaxOpenConnections)

	if utilizationRate > po.config.ScaleThreshold {
		// Scale up
		newMax := int(float64(po.config.MaxOpenConns) * 1.2)
		if newMax > 100 {
			newMax = 100 // Cap at 100 connections
		}

		if newMax > po.config.MaxOpenConns {
			po.config.MaxOpenConns = newMax
			po.config.MaxIdleConns = newMax / 2

			po.db.SetMaxOpenConns(po.config.MaxOpenConns)
			po.db.SetMaxIdleConns(po.config.MaxIdleConns)

			log.Printf("[PoolOptimizer] Scaled UP: MaxOpen=%d, MaxIdle=%d (utilization: %.2f%%)",
				po.config.MaxOpenConns, po.config.MaxIdleConns, utilizationRate*100)
		}
	} else if utilizationRate < 0.3 && po.config.MaxOpenConns > 20 {
		// Scale down
		newMax := int(float64(po.config.MaxOpenConns) * 0.8)
		if newMax < 20 {
			newMax = 20 // Minimum 20 connections
		}

		po.config.MaxOpenConns = newMax
		po.config.MaxIdleConns = newMax / 2

		po.db.SetMaxOpenConns(po.config.MaxOpenConns)
		po.db.SetMaxIdleConns(po.config.MaxIdleConns)

		log.Printf("[PoolOptimizer] Scaled DOWN: MaxOpen=%d, MaxIdle=%d (utilization: %.2f%%)",
			po.config.MaxOpenConns, po.config.MaxIdleConns, utilizationRate*100)
	}
}

// GetDB returns the underlying database connection
func (po *PoolOptimizer) GetDB() *sql.DB {
	return po.db
}

// GetMetrics returns current pool metrics
func (po *PoolOptimizer) GetMetrics() map[string]interface{} {
	stats := po.db.Stats()

	return map[string]interface{}{
		"pool_stats": map[string]interface{}{
			"open_connections": stats.OpenConnections,
			"in_use":           stats.InUse,
			"idle":             stats.Idle,
			"wait_count":       stats.WaitCount,
			"wait_duration_ms": stats.WaitDuration.Milliseconds(),
			"max_open":         stats.MaxOpenConnections,
			"max_idle":         stats.MaxIdleClosed,
			"max_lifetime":     stats.MaxLifetimeClosed,
		},
		"metrics": map[string]interface{}{
			"connections_opened":   po.metrics.ConnectionsOpened.Load(),
			"connections_closed":   po.metrics.ConnectionsClosed.Load(),
			"connections_recycled": po.metrics.ConnectionsRecycled.Load(),
			"wait_count_total":     po.metrics.WaitCount.Load(),
			"wait_duration_ms":     po.metrics.WaitDuration.Load(),
			"max_wait_duration_ms": po.metrics.MaxWaitDuration.Load(),
		},
		"config": map[string]interface{}{
			"max_open_conns":  po.config.MaxOpenConns,
			"max_idle_conns":  po.config.MaxIdleConns,
			"auto_scale":      po.config.AutoScale,
			"scale_threshold": po.config.ScaleThreshold,
		},
	}
}

// Stop gracefully stops the pool optimizer
func (po *PoolOptimizer) Stop() error {
	close(po.stopChan)
	if po.healthTicker != nil {
		po.healthTicker.Stop()
	}
	return po.db.Close()
}
