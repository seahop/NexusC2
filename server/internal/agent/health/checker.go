// internal/agent/health/checker.go
package health

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"runtime"
	"sync"
	"time"
)

// HealthChecker performs comprehensive health checks
type HealthChecker struct {
	db             *sql.DB
	grpcHealthFunc func() error
	components     map[string]ComponentChecker
	mu             sync.RWMutex
	lastCheck      time.Time
	lastStatus     *HealthStatus
	checkInterval  time.Duration
}

// ComponentChecker checks component health
type ComponentChecker interface {
	Check(ctx context.Context) ComponentStatus
	Name() string
}

// HealthStatus represents overall health
type HealthStatus struct {
	Status     string                     `json:"status"`
	Timestamp  time.Time                  `json:"timestamp"`
	Uptime     time.Duration              `json:"uptime"`
	Components map[string]ComponentStatus `json:"components"`
	Metrics    map[string]interface{}     `json:"metrics"`
	Issues     []string                   `json:"issues,omitempty"`
}

// ComponentStatus represents component health
type ComponentStatus struct {
	Status      string        `json:"status"`
	Message     string        `json:"message,omitempty"`
	Latency     time.Duration `json:"latency"`
	LastChecked time.Time     `json:"last_checked"`
	Metadata    interface{}   `json:"metadata,omitempty"`
}

// NewHealthChecker creates health checker with default configuration
func NewHealthChecker(db *sql.DB, grpcHealthFunc func() error) *HealthChecker {
	hc := &HealthChecker{
		db:             db,
		grpcHealthFunc: grpcHealthFunc,
		components:     make(map[string]ComponentChecker),
		checkInterval:  30 * time.Second, // Default check interval
	}

	// Register default components
	hc.RegisterComponent(&DatabaseChecker{db: db})
	hc.RegisterComponent(&GRPCChecker{healthFunc: grpcHealthFunc})
	hc.RegisterComponent(&SystemChecker{})

	// Start background checks
	go hc.runPeriodicChecks()

	return hc
}

// RegisterComponent registers component for checking
func (hc *HealthChecker) RegisterComponent(checker ComponentChecker) {
	hc.mu.Lock()
	defer hc.mu.Unlock()
	hc.components[checker.Name()] = checker
}

// Check performs comprehensive health check
func (hc *HealthChecker) Check(ctx context.Context) *HealthStatus {
	hc.mu.Lock()
	defer hc.mu.Unlock()

	startTime := time.Now()
	status := &HealthStatus{
		Timestamp:  time.Now(),
		Components: make(map[string]ComponentStatus),
		Metrics:    make(map[string]interface{}),
		Issues:     []string{},
	}

	// Check all components
	overallHealthy := true
	degraded := false

	for name, checker := range hc.components {
		compStatus := checker.Check(ctx)
		status.Components[name] = compStatus

		switch compStatus.Status {
		case "unhealthy":
			overallHealthy = false
			status.Issues = append(status.Issues, fmt.Sprintf("%s: %s", name, compStatus.Message))
		case "degraded":
			degraded = true
			status.Issues = append(status.Issues, fmt.Sprintf("%s: %s (degraded)", name, compStatus.Message))
		}
	}

	// Determine overall status
	if !overallHealthy {
		status.Status = "unhealthy"
	} else if degraded {
		status.Status = "degraded"
	} else {
		status.Status = "healthy"
	}

	// Add system metrics
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	status.Metrics["goroutines"] = runtime.NumGoroutine()
	status.Metrics["heap_mb"] = memStats.HeapAlloc / 1024 / 1024
	status.Metrics["gc_runs"] = memStats.NumGC
	status.Metrics["check_duration_ms"] = time.Since(startTime).Milliseconds()

	hc.lastCheck = time.Now()
	hc.lastStatus = status

	return status
}

// runPeriodicChecks runs background health checks
func (hc *HealthChecker) runPeriodicChecks() {
	ticker := time.NewTicker(hc.checkInterval)
	defer ticker.Stop()

	for range ticker.C {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		status := hc.Check(ctx)
		cancel()

		if status.Status != "healthy" {
			log.Printf("[HealthChecker] Status: %s, Issues: %v", status.Status, status.Issues)
		}
	}
}

// Handler returns HTTP handler for health endpoint
func (hc *HealthChecker) Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		status := hc.Check(ctx)

		// Set status code based on health
		switch status.Status {
		case "unhealthy":
			w.WriteHeader(http.StatusServiceUnavailable)
		case "degraded":
			w.WriteHeader(http.StatusOK) // Still return 200 for degraded
		default:
			w.WriteHeader(http.StatusOK)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(status)
	}
}

// DatabaseChecker checks database health
type DatabaseChecker struct {
	db *sql.DB
}

func (dc *DatabaseChecker) Name() string {
	return "database"
}

func (dc *DatabaseChecker) Check(ctx context.Context) ComponentStatus {
	startTime := time.Now()
	status := ComponentStatus{
		LastChecked: time.Now(),
	}

	// Ping database
	if err := dc.db.PingContext(ctx); err != nil {
		status.Status = "unhealthy"
		status.Message = fmt.Sprintf("ping failed: %v", err)
		status.Latency = time.Since(startTime)
		return status
	}

	// Check connection pool
	stats := dc.db.Stats()
	status.Metadata = map[string]interface{}{
		"open_connections": stats.OpenConnections,
		"in_use":           stats.InUse,
		"idle":             stats.Idle,
	}

	// Determine status based on pool usage
	if stats.OpenConnections >= stats.MaxOpenConnections*9/10 {
		status.Status = "degraded"
		status.Message = fmt.Sprintf("connection pool near capacity: %d/%d",
			stats.OpenConnections, stats.MaxOpenConnections)
	} else {
		status.Status = "healthy"
	}

	status.Latency = time.Since(startTime)
	return status
}

// GRPCChecker checks gRPC health
type GRPCChecker struct {
	healthFunc func() error
}

func (gc *GRPCChecker) Name() string {
	return "grpc"
}

func (gc *GRPCChecker) Check(ctx context.Context) ComponentStatus {
	startTime := time.Now()
	status := ComponentStatus{
		LastChecked: time.Now(),
	}

	if gc.healthFunc == nil {
		status.Status = "unhealthy"
		status.Message = "health function not configured"
		status.Latency = time.Since(startTime)
		return status
	}

	// Check gRPC health
	if err := gc.healthFunc(); err != nil {
		status.Status = "unhealthy"
		status.Message = fmt.Sprintf("gRPC check failed: %v", err)
	} else {
		status.Status = "healthy"
	}

	status.Latency = time.Since(startTime)
	return status
}

// SystemChecker checks system resources
type SystemChecker struct{}

func (sc *SystemChecker) Name() string {
	return "system"
}

func (sc *SystemChecker) Check(ctx context.Context) ComponentStatus {
	startTime := time.Now()
	status := ComponentStatus{
		LastChecked: time.Now(),
		Status:      "healthy",
	}

	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	// Check memory usage
	heapMB := memStats.HeapAlloc / 1024 / 1024
	if heapMB > 1024 { // Over 1GB
		status.Status = "degraded"
		status.Message = fmt.Sprintf("high memory usage: %d MB", heapMB)
	}

	// Check goroutine count
	goroutines := runtime.NumGoroutine()
	if goroutines > 10000 {
		status.Status = "degraded"
		status.Message = fmt.Sprintf("high goroutine count: %d", goroutines)
	}

	status.Metadata = map[string]interface{}{
		"heap_mb":    heapMB,
		"goroutines": goroutines,
		"gc_runs":    memStats.NumGC,
		"cpu_count":  runtime.NumCPU(),
	}

	status.Latency = time.Since(startTime)
	return status
}
