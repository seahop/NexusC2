// cmd/websocket/main.go
package main

import (
	"c2/internal/common/config"
	"c2/internal/database/postgres"
	"c2/internal/logging"
	"c2/internal/websocket/agent"
	"c2/internal/websocket/handlers"
	"c2/internal/websocket/hub"
	"c2/internal/websocket/reconnect"
	"context"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"syscall"
	"time"
)

// retryWithExponentialBackoff attempts an operation with exponential backoff
func retryWithExponentialBackoff(operation func() error) error {
	maxRetries := 30 // 30 retries = ~5 minutes total with exponential backoff
	baseDelay := 1 * time.Second
	maxDelay := 30 * time.Second
	var lastErr error
	for attempt := 0; attempt < maxRetries; attempt++ {
		err := operation()
		if err == nil {
			return nil
		}
		lastErr = err
		delay := baseDelay * time.Duration(1<<uint(attempt))
		if delay > maxDelay {
			delay = maxDelay
		}
		log.Printf("Attempt %d failed: %v. Retrying in %v...", attempt+1, err, delay)
		time.Sleep(delay)
	}
	return lastErr
}

func configureRuntime() {
	// Set GOMAXPROCS to use all available CPUs
	runtime.GOMAXPROCS(runtime.NumCPU())

	// Configure GC for lower latency
	debug.SetGCPercent(100)

	log.Printf("Runtime configured: GOMAXPROCS=%d", runtime.GOMAXPROCS(0))
}

func monitorServerHealth(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			var m runtime.MemStats
			runtime.ReadMemStats(&m)

			goroutines := runtime.NumGoroutine()
			heapMB := m.HeapAlloc / 1024 / 1024

			// Trigger GC if memory usage is high
			if m.HeapAlloc > 500*1024*1024 { // 500MB
				runtime.GC()
				log.Printf("[HEALTH] High memory, GC triggered: Heap=%dMB, Goroutines=%d", heapMB, goroutines)
			}

			// Check for goroutine leaks
			if goroutines > 10000 {
				log.Printf("[HEALTH] WARNING: High goroutine count: %d", goroutines)
			}
		}
	}
}

// handleHealthCheck provides a health endpoint
func handleHealthCheck(streamManager *reconnect.StreamManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		status := streamManager.GetStatus()
		connected := status["connected"].(bool)

		health := map[string]interface{}{
			"status":     "running",
			"grpc":       status,
			"goroutines": runtime.NumGoroutine(),
		}

		// Add memory stats
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		health["memory_mb"] = m.HeapAlloc / 1024 / 1024

		w.Header().Set("Content-Type", "application/json")

		if connected {
			w.WriteHeader(http.StatusOK)
			health["status"] = "healthy"
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
			health["status"] = "degraded"
		}

		json.NewEncoder(w).Encode(health)
	}
}

func main() {
	// Initialize persistent file logging
	logger, err := logging.SetupDefaultLogger("websocket")
	if err != nil {
		log.Printf("Warning: Failed to setup file logging: %v", err)
	} else {
		defer logger.Close()
	}

	// Optimize runtime settings
	configureRuntime()

	// Initialize configuration
	log.Println("Loading WebSocket configuration...")
	cfg, err := config.LoadWSConfig()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}
	log.Println("Successfully loaded WebSocket configuration")

	// Initialize database with connection pooling
	log.Println("Connecting to the database...")
	var db *sql.DB
	err = retryWithExponentialBackoff(func() error {
		var connErr error
		db, connErr = postgres.NewConnection(cfg.Database)
		if connErr != nil {
			return connErr
		}

		// Configure connection pool
		// Increased from 25 to 50 to prevent connection exhaustion under load
		// With agent-handler using 50-100 connections, total is 100-150
		// Ensure PostgreSQL max_connections >= 200
		db.SetMaxOpenConns(50)
		db.SetMaxIdleConns(25)
		db.SetConnMaxLifetime(5 * time.Minute)
		db.SetConnMaxIdleTime(10 * time.Minute)

		// Test the connection with timeout
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		return db.PingContext(ctx)
	})
	if err != nil {
		log.Fatalf("Failed to establish database connection after retries: %v", err)
	}
	log.Println("Successfully connected to the database with connection pooling")

	// Setup graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, os.Interrupt, syscall.SIGTERM)

	// Create new hub
	log.Println("Creating WebSocket hub...")
	h := hub.NewHub(db)
	log.Println("WebSocket hub created successfully")

	// Create WebSocket handler first (with nil agent client)
	log.Println("Creating WebSocket handler...")
	wsHandler, err := handlers.NewWSHandler(h, db, nil)
	if err != nil {
		log.Fatalf("Failed to create WebSocket handler: %v", err)
	}
	h.SetWSHandler(wsHandler)
	log.Println("WebSocket handler created successfully")

	// Create stream manager for auto-reconnection
	clientID := "websocket_service"
	// Use agent-handler service name in Docker, localhost for local development
	grpcAddress := os.Getenv("GRPC_ADDRESS")
	if grpcAddress == "" {
		grpcAddress = "agent-handler:50051" // Default to Docker service name
	}
	log.Printf("Creating stream manager for gRPC connection to %s", grpcAddress)
	streamManager := reconnect.NewStreamManager(grpcAddress, clientID, h)

	// Set the stream manager in the handler
	wsHandler.SetStreamManager(streamManager)

	// Start the stream manager (handles connection and reconnection)
	log.Println("Starting stream manager...")
	if err := streamManager.Start(ctx); err != nil {
		log.Printf("Warning: Stream manager start returned error: %v (will continue retrying)", err)
	}

	// Try to establish initial connection with old method for compatibility
	// This provides backward compatibility while the stream manager handles reconnection
	var agentClient *agent.Client
	err = retryWithExponentialBackoff(func() error {
		var connErr error
		agentClient, connErr = agent.NewClient(grpcAddress, clientID)
		if connErr != nil {
			return connErr
		}
		// Start the bidirectional stream
		streamErr := agentClient.StartBiDiStream(context.Background(), h)
		if streamErr != nil {
			agentClient.Close() // Clean up the failed client
			return streamErr
		}
		return nil
	})

	if err != nil {
		log.Printf("Initial gRPC connection failed: %v (stream manager will handle reconnection)", err)
		// Don't fail here - the stream manager will keep trying
	} else {
		// Set the agent client in the handler for initial connection
		wsHandler.SetAgentClient(agentClient)
		log.Println("Initial gRPC connection established successfully")
	}

	// Configure TLS for WebSocket server with better settings
	log.Println("Configuring TLS for WebSocket server...")
	tlsConfig := &tls.Config{
		MinVersion:               tls.VersionTLS12,
		PreferServerCipherSuites: true,
		CurvePreferences: []tls.CurveID{
			tls.X25519,
			tls.CurveP256,
		},
	}
	log.Printf("TLS Cert File: %s, Key File: %s", cfg.TLS.CertFile, cfg.TLS.KeyFile)

	// Create HTTP mux for multiple endpoints
	mux := http.NewServeMux()

	// IMPORTANT: Register the WebSocket handler at /ws
	mux.HandleFunc("/ws", wsHandler.HandleWebSocket)

	// Register the health check endpoint
	mux.HandleFunc("/health", handleHealthCheck(streamManager))

	// For backward compatibility, also handle all other paths as WebSocket
	// This ensures that direct connections to wss://localhost:3131 still work
	mux.HandleFunc("/", wsHandler.HandleWebSocket)

	// Setup HTTP server with TLS and timeouts
	server := &http.Server{
		Addr:              cfg.ListenAddr,
		TLSConfig:         tlsConfig,
		Handler:           mux, // Use the mux instead of direct handler
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20, // 1MB
		ReadHeaderTimeout: 10 * time.Second,
	}

	// Start health monitoring
	go monitorServerHealth(ctx)

	// Monitor stream manager status
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()

		wasConnected := false
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				status := streamManager.GetStatus()
				isConnected := status["connected"].(bool)

				if isConnected && !wasConnected {
					log.Println("gRPC stream connection restored")
					wasConnected = true

					// Update the handler with the new client
					if client, err := streamManager.GetClient(); err == nil {
						wsHandler.SetAgentClient(client)
					}
				} else if !isConnected && wasConnected {
					log.Println("gRPC stream connection lost")
					wasConnected = false
				}

				// Log status if not connected
				if !isConnected {
					log.Printf("Stream manager status: %v", status)
				}
			}
		}
	}()

	// Start server in a goroutine
	go func() {
		log.Printf("Starting WebSocket server on %s", cfg.ListenAddr)
		if err := server.ListenAndServeTLS(cfg.TLS.CertFile, cfg.TLS.KeyFile); err != nil && err != http.ErrServerClosed {
			log.Printf("WebSocket server failed: %v", err)
			shutdown <- syscall.SIGTERM // Trigger shutdown
		}
	}()

	log.Println("WebSocket service started successfully")
	log.Printf("WebSocket endpoint available at: wss://localhost%s/ws", cfg.ListenAddr)
	log.Printf("Health endpoint available at: https://localhost%s/health", cfg.ListenAddr)

	// Wait for shutdown signal
	<-shutdown
	log.Println("Shutdown signal received, starting graceful shutdown...")

	// Cancel context to stop health monitoring and stream manager
	cancel()

	// Stop the stream manager
	streamManager.Stop()

	// Create shutdown context with timeout
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	// Shutdown server
	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Printf("Server shutdown error: %v", err)
		server.Close() // Force close if graceful shutdown fails
	}

	// Close WebSocket handler (which will clean up workers and gRPC)
	wsHandler.Close()

	// Close hub's prepared statements
	if err := h.Close(); err != nil {
		log.Printf("Error closing hub: %v", err)
	}

	// Close database connection
	if err := db.Close(); err != nil {
		log.Printf("Error closing database connection: %v", err)
	}

	log.Println("Shutdown complete")
}
