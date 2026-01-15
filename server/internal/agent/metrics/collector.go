// internal/agent/metrics/collector.go
package metrics

import (
	"encoding/json"
	"fmt"
	"net/http"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

// Collector provides comprehensive metrics for agent service
type Collector struct {
	// Request metrics
	RequestsProcessed atomic.Uint64
	RequestsActive    atomic.Int32
	GetRequests       atomic.Uint64
	PostRequests      atomic.Uint64

	// Processing metrics
	BatchesQueued    atomic.Uint64
	BatchesProcessed atomic.Uint64
	ResultsProcessed atomic.Uint64

	// Performance tracking
	avgProcessingTime *MovingAverage
	avgBatchSize      *MovingAverage
	avgQueueDepth     *MovingAverage
	responseHistogram *Histogram

	// Database metrics
	DBQueries           atomic.Uint64
	DBErrors            atomic.Uint64
	DBConnectionsActive atomic.Int32
	avgDBLatency        *MovingAverage

	// gRPC metrics
	GRPCCalls      atomic.Uint64
	GRPCErrors     atomic.Uint64
	GRPCReconnects atomic.Uint64

	// Worker metrics
	ActiveWorkers atomic.Int32
	MaxWorkers    int32
	MinWorkers    int32

	// Agent metrics
	ActiveAgents    atomic.Int32
	TotalAgents     atomic.Uint64
	AgentReconnects atomic.Uint64

	// System info
	startTime time.Time

	// Error tracking
	errorsByType sync.Map

	// Custom metrics
	customMetrics sync.Map
}

// MovingAverage tracks moving average
type MovingAverage struct {
	values []float64
	index  int
	count  int
	sum    float64
	mu     sync.RWMutex
}

// NewMovingAverage creates moving average tracker
func NewMovingAverage(size int) *MovingAverage {
	return &MovingAverage{
		values: make([]float64, size),
	}
}

// Add adds value to moving average
func (ma *MovingAverage) Add(value float64) {
	ma.mu.Lock()
	defer ma.mu.Unlock()

	if ma.count >= len(ma.values) {
		ma.sum -= ma.values[ma.index]
	} else {
		ma.count++
	}

	ma.values[ma.index] = value
	ma.sum += value
	ma.index = (ma.index + 1) % len(ma.values)
}

// Get returns current average
func (ma *MovingAverage) Get() float64 {
	ma.mu.RLock()
	defer ma.mu.RUnlock()

	if ma.count == 0 {
		return 0
	}
	return ma.sum / float64(ma.count)
}

// Histogram tracks value distribution
type Histogram struct {
	buckets []float64
	counts  []atomic.Uint64
	total   atomic.Uint64
}

// NewHistogram creates histogram
func NewHistogram(buckets []float64) *Histogram {
	return &Histogram{
		buckets: buckets,
		counts:  make([]atomic.Uint64, len(buckets)+1),
	}
}

// Record adds value to histogram
func (h *Histogram) Record(value float64) {
	h.total.Add(1)

	for i, bucket := range h.buckets {
		if value <= bucket {
			h.counts[i].Add(1)
			return
		}
	}
	h.counts[len(h.buckets)].Add(1)
}

// GetDistribution returns distribution
func (h *Histogram) GetDistribution() map[string]interface{} {
	result := make(map[string]interface{})
	total := h.total.Load()

	if total == 0 {
		return result
	}

	distribution := make(map[string]float64)
	for i, count := range h.counts[:len(h.counts)-1] {
		label := fmt.Sprintf("≤%.0fms", h.buckets[i])
		distribution[label] = float64(count.Load()) / float64(total) * 100
	}

	if len(h.buckets) > 0 {
		label := fmt.Sprintf(">%.0fms", h.buckets[len(h.buckets)-1])
		distribution[label] = float64(h.counts[len(h.counts)-1].Load()) / float64(total) * 100
	}

	result["distribution"] = distribution
	result["total"] = total
	return result
}

// NewCollector creates new metrics collector
func NewCollector(maxWorkers, minWorkers int32) *Collector {
	return &Collector{
		MaxWorkers:        maxWorkers,
		MinWorkers:        minWorkers,
		avgProcessingTime: NewMovingAverage(100),
		avgBatchSize:      NewMovingAverage(100),
		avgQueueDepth:     NewMovingAverage(100),
		avgDBLatency:      NewMovingAverage(100),
		responseHistogram: NewHistogram([]float64{10, 25, 50, 100, 250, 500, 1000}),
		startTime:         time.Now(),
	}
}

// RecordRequest records incoming request
func (c *Collector) RecordRequest(method string) {
	c.RequestsProcessed.Add(1)
	c.RequestsActive.Add(1)

	switch method {
	case "GET":
		c.GetRequests.Add(1)
	case "POST":
		c.PostRequests.Add(1)
	}
}

// RecordRequestComplete records request completion
func (c *Collector) RecordRequestComplete(duration time.Duration) {
	c.RequestsActive.Add(-1)
	ms := float64(duration.Milliseconds())
	c.avgProcessingTime.Add(ms)
	c.responseHistogram.Record(ms)
}

// RecordBatch records batch processing
func (c *Collector) RecordBatch(size int, duration time.Duration) {
	c.BatchesProcessed.Add(1)
	c.ResultsProcessed.Add(uint64(size))
	c.avgBatchSize.Add(float64(size))
	c.avgProcessingTime.Add(float64(duration.Milliseconds()))
}

// RecordDBOperation records database operation
func (c *Collector) RecordDBOperation(duration time.Duration, err error) {
	c.DBQueries.Add(1)
	c.avgDBLatency.Add(float64(duration.Milliseconds()))

	if err != nil {
		c.DBErrors.Add(1)
		c.RecordError("database")
	}
}

// RecordGRPCCall records gRPC call
func (c *Collector) RecordGRPCCall(err error) {
	c.GRPCCalls.Add(1)
	if err != nil {
		c.GRPCErrors.Add(1)
		c.RecordError("grpc")
	}
}

// RecordError records error by type
func (c *Collector) RecordError(errorType string) {
	val, _ := c.errorsByType.LoadOrStore(errorType, &atomic.Uint64{})
	counter := val.(*atomic.Uint64)
	counter.Add(1)
}

// SetCustomMetric sets custom metric
func (c *Collector) SetCustomMetric(key string, value interface{}) {
	c.customMetrics.Store(key, value)
}

// GetSummary returns metrics summary
func (c *Collector) GetSummary() map[string]interface{} {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	// Collect error counts
	errors := make(map[string]uint64)
	c.errorsByType.Range(func(key, value interface{}) bool {
		counter := value.(*atomic.Uint64)
		errors[key.(string)] = counter.Load()
		return true
	})

	// Collect custom metrics
	custom := make(map[string]interface{})
	c.customMetrics.Range(func(key, value interface{}) bool {
		custom[key.(string)] = value
		return true
	})

	summary := map[string]interface{}{
		"uptime": time.Since(c.startTime).String(),
		"requests": map[string]interface{}{
			"total":  c.RequestsProcessed.Load(),
			"active": c.RequestsActive.Load(),
			"get":    c.GetRequests.Load(),
			"post":   c.PostRequests.Load(),
		},
		"batches": map[string]interface{}{
			"queued":    c.BatchesQueued.Load(),
			"processed": c.BatchesProcessed.Load(),
			"results":   c.ResultsProcessed.Load(),
			"avg_size":  c.avgBatchSize.Get(),
		},
		"performance": map[string]interface{}{
			"avg_processing_ms": c.avgProcessingTime.Get(),
			"avg_queue_depth":   c.avgQueueDepth.Get(),
			"response_time":     c.responseHistogram.GetDistribution(),
		},
		"database": map[string]interface{}{
			"queries":        c.DBQueries.Load(),
			"errors":         c.DBErrors.Load(),
			"active_conns":   c.DBConnectionsActive.Load(),
			"avg_latency_ms": c.avgDBLatency.Get(),
		},
		"grpc": map[string]interface{}{
			"calls":      c.GRPCCalls.Load(),
			"errors":     c.GRPCErrors.Load(),
			"reconnects": c.GRPCReconnects.Load(),
		},
		"workers": map[string]interface{}{
			"active": c.ActiveWorkers.Load(),
			"max":    c.MaxWorkers,
			"min":    c.MinWorkers,
		},
		"agents": map[string]interface{}{
			"active":     c.ActiveAgents.Load(),
			"total":      c.TotalAgents.Load(),
			"reconnects": c.AgentReconnects.Load(),
		},
		"system": map[string]interface{}{
			"goroutines": runtime.NumGoroutine(),
			"heap_mb":    memStats.HeapAlloc / 1024 / 1024,
			"gc_runs":    memStats.NumGC,
			"cpu_count":  runtime.NumCPU(),
		},
		"errors": errors,
		"custom": custom,
	}

	return summary
}

// Handler returns HTTP handler for metrics endpoint
func (c *Collector) Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		summary := c.GetSummary()

		if err := json.NewEncoder(w).Encode(summary); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}
}

// StartBackgroundCollector starts periodic collection
func (c *Collector) StartBackgroundCollector(interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for range ticker.C {
			var memStats runtime.MemStats
			runtime.ReadMemStats(&memStats)

			c.SetCustomMetric("memory_heap_mb", memStats.HeapAlloc/1024/1024)
			c.SetCustomMetric("goroutines", runtime.NumGoroutine())
			// Metrics are collected silently - available via /metrics endpoint
		}
	}()
}
