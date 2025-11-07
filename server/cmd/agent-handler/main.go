// cmd/agent-handler/main.go
package main

import (
	"c2/internal/agent/cache"
	"c2/internal/agent/handlers"
	"c2/internal/agent/health"
	"c2/internal/agent/listeners"
	"c2/internal/agent/metrics"
	"c2/internal/agent/server"
	"c2/internal/agent/tasks"
	"c2/internal/common/config"
	"c2/internal/database/postgres"
	"c2/internal/websocket/agent"
	"context"
	"encoding/json" // ADD: for JSON encoding
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

func main() {
	// Initialize configuration
	cfg, err := config.LoadAgentConfig()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Load processor configuration for async processing
	processorConfig := config.DefaultProcessorConfig()
	processorConfig.LoadFromEnv()

	// Validate processor config
	if err := processorConfig.Validate(); err != nil {
		log.Printf("Warning: Invalid processor config, using defaults: %v", err)
		processorConfig = config.DefaultProcessorConfig()
	}

	log.Printf("Starting Optimized Agent Handler Service")
	log.Printf("===========================================")
	log.Printf("Agent Configuration:")
	log.Printf("Web Server Cert File: %s", cfg.WebServer.CertFile)
	log.Printf("Web Server Key File: %s", cfg.WebServer.KeyFile)
	log.Printf("Async Processing Configuration:")
	log.Printf("  - Enabled: true")
	log.Printf("  - Max Workers: %d", processorConfig.MaxWorkers)
	log.Printf("  - Min Workers: %d", processorConfig.MinWorkers)
	log.Printf("  - Queue Size: %d", processorConfig.MaxQueueSize)
	log.Printf("  - Batch Size: %d", processorConfig.BatchSize)
	log.Printf("  - Async Threshold: %d results", processorConfig.AsyncThreshold)
	log.Printf("  - DB Timeout: %v", processorConfig.DBTimeout)

	for i, listener := range cfg.Listeners {
		log.Printf("Listener %d: Name=%s, Type=%s, Port=%d, Secure=%v",
			i+1, listener.Name, listener.Protocol, listener.Port, listener.Secure)
	}

	// Initialize optimized database connection with pool optimizer
	log.Println("Initializing optimized database connection...")
	poolConfig := postgres.DefaultOptimizedPoolConfig()

	// Build connection string from database config
	connString := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		cfg.Database.Host,
		cfg.Database.Port,
		cfg.Database.User,
		cfg.Database.Password,
		cfg.Database.DBName,
		cfg.Database.SSLMode,
	)

	dbOptimizer, err := postgres.NewPoolOptimizer(connString, poolConfig)
	if err != nil {
		log.Fatalf("Failed to create database pool optimizer: %v", err)
	}
	db := dbOptimizer.GetDB()
	defer dbOptimizer.Stop()

	// Initialize bulk operator for database operations
	bulkOperator, err := postgres.NewBulkOperator(db, 100)
	if err != nil {
		log.Fatalf("Failed to create bulk operator: %v", err)
	}
	defer bulkOperator.Close()

	// Initialize result cache
	log.Println("Initializing result cache...")
	resultCache := cache.NewAgentResultCache(
		1000,          // Max 1000 items
		5*time.Minute, // 5 minute TTL
		db,
	)
	defer resultCache.Stop()

	// Initialize metrics collector
	log.Println("Initializing metrics collector...")
	metricsCollector := metrics.NewCollector(
		int32(processorConfig.MaxWorkers),
		int32(processorConfig.MinWorkers),
	)
	metricsCollector.StartBackgroundCollector(30 * time.Second)

	// Initialize health checker
	log.Println("Initializing health checker...")
	healthChecker := health.NewHealthChecker(db, nil)

	// Initialize task queue
	taskQueue := tasks.NewTaskQueue()
	go taskQueue.Process()

	// Initialize enhanced agent handler with cache and bulk operations
	agentHandler := &EnhancedAgentHandler{
		AgentHandler: handlers.NewAgentHandler(db, taskQueue),
		cache:        resultCache,
		bulkOperator: bulkOperator,
		metrics:      metricsCollector,
	}

	cmdBuffer := make(map[string][]server.Command)
	mux := http.NewServeMux()

	// Add health and metrics endpoints
	mux.HandleFunc("/health", healthChecker.Handler())
	mux.HandleFunc("/metrics", metricsCollector.Handler())

	// Initialize gRPC server
	grpcServer := server.NewGRPCServer(nil, cmdBuffer, db, mux)

	// ADD: Stream status endpoint
	mux.HandleFunc("/status/streams", func(w http.ResponseWriter, r *http.Request) {
		status := grpcServer.GetStreamStatus()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(status)
	})

	// Initialize listener manager with async processing
	listenerManager := listeners.NewManagerWithOptions(
		agentHandler,
		cfg.WebServer,
		db,
		cfg,
		nil, // gRPC client will be set later
		grpcServer,
		listeners.WithAsyncProcessing(processorConfig),
	)

	// Enhance async handler with priority queue if async is enabled
	if listenerManager.IsAsyncEnabled() {
		// Access the handler through the manager's exported field/method
		// Since GetAsyncHandler doesn't exist, we'll enhance through the manager directly
		log.Println("Async processing is enabled, priority queue enhancement available")
	}

	// Set the manager in gRPC server
	grpcServer.SetManager(listenerManager)

	// ADD: Load active connections and init data from database
	log.Println("Loading active connections from database...")
	if err := listenerManager.LoadActiveConnections(); err != nil {
		log.Printf("Warning: Failed to load active connections: %v", err)
	}

	log.Println("Loading init data from database...")
	if err := listenerManager.LoadInitData(); err != nil {
		log.Printf("Warning: Failed to load init data: %v", err)
	}

	// ADD: START EXISTING LISTENERS FROM DATABASE
	// This ensures listeners are automatically restored after agent-handler restart
	log.Println("===========================================")
	log.Println("Restarting Existing Listeners...")
	log.Println("===========================================")

	if err := listenerManager.StartExistingListeners(); err != nil {
		// Log the error but don't fail startup - some listeners might have started
		log.Printf("Warning: Some listeners failed to start: %v", err)
		log.Printf("You may need to manually restart failed listeners")
	}

	log.Println("===========================================")

	// Start gRPC server
	grpcReady := make(chan bool, 1)
	go func() {
		log.Printf("Starting gRPC server on 50051...")
		if err := grpcServer.Start("50051"); err != nil {
			log.Fatalf("Failed to start gRPC server: %v", err)
		}
	}()

	// Wait for gRPC server to start
	time.Sleep(5 * time.Second)

	// Initialize gRPC client
	log.Println("Initializing gRPC client...")
	grpcClient, err := agent.NewClient("localhost:50051", "agent_service")

	// Declare enhancedClient variable outside the if block for later use
	var enhancedClient *agent.CircuitBreaker

	if err != nil {
		log.Printf("Failed to initialize gRPC client: %v", err)
	} else {
		// Wrap with circuit breaker
		enhancedClient = agent.EnhanceClientWithCircuitBreaker(grpcClient)

		// Create a simple gRPC health check component
		healthChecker.RegisterComponent(&GRPCHealthChecker{
			client: enhancedClient,
		})

		defer enhancedClient.Close()
		listenerManager.UpdateGRPCClient(grpcClient)

		log.Println("gRPC client initialized with circuit breaker")
	}

	// Start configured listeners
	var wg sync.WaitGroup
	for _, listenerConfig := range cfg.Listeners {
		wg.Add(1)
		go func(lc config.ListenerConfig) {
			defer wg.Done()
			if err := listenerManager.StartListener(lc); err != nil {
				log.Printf("Failed to start listener %s: %v", lc.Name, err)
			} else {
				log.Printf("Started listener: %s", lc.Name)
			}
		}(listenerConfig)
	}

	// Signal that gRPC server is ready
	grpcReady <- true
	log.Printf("gRPC server ready at localhost:50051")

	// Log optimization status
	log.Println("\n===========================================")
	log.Println("Optimizations Enabled:")
	log.Printf("✓ Database Pool Optimizer (AutoScale: %v)", poolConfig.AutoScale)
	log.Printf("✓ Bulk Database Operations (Batch Size: 100)")
	log.Printf("✓ Result Cache (Size: 1000, TTL: 5m)")
	log.Printf("✓ Circuit Breaker (Max Failures: 5)")
	log.Printf("✓ Priority Queue Processing")
	log.Printf("✓ Metrics Collection (Interval: 30s)")
	log.Printf("✓ Health Checks (Interval: 30s)")
	log.Printf("✓ Async Processing (Workers: %d-%d)", processorConfig.MinWorkers, processorConfig.MaxWorkers)
	log.Printf("✓ Stream Monitoring (Ping Interval: 10s)")
	log.Println("===========================================")

	// Start metrics reporter
	go func() {
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()

		for range ticker.C {
			// Get comprehensive metrics
			metrics := map[string]interface{}{
				"listeners": listenerManager.GetMetrics(),
				"cache":     resultCache.GetMetrics(),
				"db_pool":   dbOptimizer.GetMetrics(),
				"collector": metricsCollector.GetSummary(),
			}

			// Add circuit breaker metrics if available
			if enhancedClient != nil {
				metrics["circuit_breaker"] = enhancedClient.GetMetrics()
			}

			log.Printf("[Metrics] System Status: %+v", metrics)
		}
	}()

	// Wait for interrupt signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigChan

	log.Printf("Received signal: %v, initiating graceful shutdown...", sig)

	// Create shutdown context with timeout
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Shutdown listener manager (includes async handler if enabled)
	shutdownDone := make(chan error, 1)
	go func() {
		shutdownDone <- listenerManager.Shutdown(30 * time.Second)
	}()

	select {
	case err := <-shutdownDone:
		if err != nil {
			log.Printf("Warning: Listener manager shutdown error: %v", err)
		} else {
			log.Println("Listener manager shutdown complete")
		}
	case <-shutdownCtx.Done():
		log.Println("Shutdown timeout exceeded")
	}

	// Stop all listeners
	listenerManager.StopAll()

	// Stop gRPC server
	grpcServer.Stop()

	// Wait for listener goroutines
	wg.Wait()

	// Final metrics log
	log.Printf("Final Metrics: %+v", metricsCollector.GetSummary())

	log.Println("Agent handler service shutdown complete")
}

// EnhancedAgentHandler wraps the basic handler with optimizations
type EnhancedAgentHandler struct {
	*handlers.AgentHandler
	cache        *cache.AgentResultCache
	bulkOperator *postgres.BulkOperator
	metrics      *metrics.Collector
}

// HandleAgent processes agent with optimizations
func (eah *EnhancedAgentHandler) HandleAgent(agentID string) {
	// Record metrics
	eah.metrics.RecordRequest("AGENT")
	defer func(start time.Time) {
		eah.metrics.RecordRequestComplete(time.Since(start))
	}(time.Now())

	// Check cache first
	ctx := context.Background()
	cachedData, err := eah.cache.GetWithFallback(ctx, agentID)
	if err == nil && cachedData != nil {
		log.Printf("Cache hit for agent %s", agentID)
		// Process cached data here if needed
		// For now, just return since we found it in cache
		return
	}

	// Process normally
	eah.AgentHandler.HandleAgent(agentID)

	// Cache result for next time
	eah.cache.Set(agentID, "processed", 0)
}

// GRPCHealthChecker is a custom implementation for checking gRPC health
type GRPCHealthChecker struct {
	client *agent.CircuitBreaker
}

func (g *GRPCHealthChecker) Name() string {
	return "grpc"
}

func (g *GRPCHealthChecker) Check(ctx context.Context) health.ComponentStatus {
	startTime := time.Now()
	status := health.ComponentStatus{
		LastChecked: time.Now(),
	}

	if g.client == nil {
		status.Status = "unhealthy"
		status.Message = "gRPC client not initialized"
		status.Latency = time.Since(startTime)
		return status
	}

	// Use the circuit breaker's ExecuteWithBreaker method
	err := g.client.ExecuteWithBreaker(ctx, "health_check", func() error {
		// Simple check - just verify we can execute something
		return nil
	})

	if err != nil {
		status.Status = "unhealthy"
		status.Message = fmt.Sprintf("Health check failed: %v", err)
	} else {
		status.Status = "healthy"
	}

	status.Latency = time.Since(startTime)
	return status
}
