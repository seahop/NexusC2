// cmd/rest-api/main.go
package main

import (
	"c2/internal/common/config"
	"c2/internal/database/postgres"
	"c2/internal/logging"
	"c2/internal/rest/server"
	"c2/internal/rest/sse"
	"c2/internal/websocket/agent"
	pb "c2/proto"
	"context"
	"database/sql"
	"encoding/json"
	"log"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"sync"
	"syscall"
	"time"
)

func configureRuntime() {
	runtime.GOMAXPROCS(runtime.NumCPU())
	debug.SetGCPercent(100)
	log.Printf("Runtime configured: GOMAXPROCS=%d", runtime.GOMAXPROCS(0))
}

func retryWithExponentialBackoff(operation func() error) error {
	maxRetries := 30
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

func main() {
	// Initialize persistent file logging
	logger, err := logging.SetupDefaultLogger("rest-api")
	if err != nil {
		log.Printf("Warning: Failed to setup file logging: %v", err)
	} else {
		defer logger.Close()
	}

	log.Println("Starting NexusC2 REST API Service...")

	// Configure runtime
	configureRuntime()

	// Load configuration
	log.Println("Loading REST API configuration...")
	cfg, err := config.LoadRESTConfig()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}
	log.Println("Configuration loaded successfully")

	// Connect to database
	log.Println("Connecting to database...")
	var db *sql.DB
	err = retryWithExponentialBackoff(func() error {
		var connErr error
		db, connErr = postgres.NewConnection(cfg.Database)
		if connErr != nil {
			return connErr
		}

		// Configure connection pool
		db.SetMaxOpenConns(50)
		db.SetMaxIdleConns(25)
		db.SetConnMaxLifetime(5 * time.Minute)
		db.SetConnMaxIdleTime(10 * time.Minute)

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return db.PingContext(ctx)
	})
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	log.Println("Connected to database successfully")

	// Create server
	log.Println("Creating REST API server...")
	srv, err := server.NewServer(cfg, db)
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}
	log.Println("REST API server created successfully")

	// Setup graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, os.Interrupt, syscall.SIGTERM)

	// Connect to agent-handler via gRPC
	clientID := "rest_api_service"
	grpcAddress := os.Getenv("GRPC_ADDRESS")
	if grpcAddress == "" {
		grpcAddress = "host.docker.internal:50051"
	}

	log.Printf("Connecting to gRPC agent service at %s", grpcAddress)

	// Create a hub adapter for the agent client
	hubAdapter := &sseHubAdapter{sseHub: srv.GetSSEHub(), srv: srv}

	// Try to establish initial gRPC connection
	var agentClient *agent.Client
	var agentClientMu sync.RWMutex

	connectToAgent := func() (*agent.Client, error) {
		client, err := agent.NewClient(grpcAddress, clientID)
		if err != nil {
			return nil, err
		}
		if err := client.StartBiDiStream(context.Background(), hubAdapter); err != nil {
			client.Close()
			return nil, err
		}
		return client, nil
	}

	err = retryWithExponentialBackoff(func() error {
		var connErr error
		agentClient, connErr = connectToAgent()
		return connErr
	})

	if err != nil {
		log.Printf("Initial gRPC connection failed: %v (will retry in background)", err)
	} else {
		srv.SetAgentClient(agentClient)
		log.Println("Initial gRPC connection established")
	}

	// Monitor and reconnect gRPC connection
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				agentClientMu.RLock()
				currentClient := agentClient
				agentClientMu.RUnlock()

				// Check if we need to reconnect
				if currentClient == nil {
					log.Println("Attempting to reconnect to gRPC agent service...")
					newClient, err := connectToAgent()
					if err != nil {
						log.Printf("Reconnection failed: %v", err)
						continue
					}

					agentClientMu.Lock()
					agentClient = newClient
					agentClientMu.Unlock()

					srv.SetAgentClient(newClient)
					log.Println("gRPC connection restored")
				}
			}
		}
	}()

	// Start server in goroutine
	go func() {
		log.Printf("Starting HTTPS server on %s", cfg.ListenAddr)
		if err := srv.Start(); err != nil {
			log.Printf("Server error: %v", err)
			shutdown <- syscall.SIGTERM
		}
	}()

	log.Println("REST API service started successfully")
	log.Printf("API endpoint: https://localhost%s/api/v1", cfg.ListenAddr)
	log.Printf("Health endpoint: https://localhost%s/health", cfg.ListenAddr)

	// Wait for shutdown signal
	<-shutdown
	log.Println("Shutdown signal received, starting graceful shutdown...")

	// Cancel context
	cancel()

	// Shutdown server
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("Server shutdown error: %v", err)
	}

	// Close gRPC client
	if agentClient != nil {
		agentClient.Close()
	}

	// Close database
	if err := db.Close(); err != nil {
		log.Printf("Database close error: %v", err)
	}

	log.Println("Shutdown complete")
}

// sseHubAdapter adapts the SSE hub to the hub.HubInterface expected by the agent client
type sseHubAdapter struct {
	sseHub *sse.Hub
	srv    *server.Server
}

// HandleNewConnection handles new agent connection notifications from gRPC
func (a *sseHubAdapter) HandleNewConnection(notification *pb.ConnectionNotification) {
	// Convert notification to JSON and broadcast via SSE
	data, err := json.Marshal(map[string]interface{}{
		"event":        "agent_connection",
		"newclientID":  notification.NewClientId,
		"clientID":     notification.ClientId,
		"protocol":     notification.Protocol,
		"extIP":        notification.ExtIp,
		"intIP":        notification.IntIp,
		"username":     notification.Username,
		"hostname":     notification.Hostname,
		"process":      notification.Process,
		"pid":          notification.Pid,
		"arch":         notification.Arch,
		"os":           notification.Os,
		"timestamp":    time.Now().Format(time.RFC3339),
	})
	if err != nil {
		log.Printf("[SSE] Failed to marshal connection notification: %v", err)
		return
	}

	a.sseHub.BroadcastJSON("agent_connection", string(data))
	log.Printf("[SSE] Broadcast new agent connection: %s", notification.NewClientId)
}

// BroadcastToAll broadcasts a message to all connected SSE clients
func (a *sseHubAdapter) BroadcastToAll(ctx context.Context, message []byte) error {
	// Parse message and broadcast via SSE
	a.sseHub.BroadcastJSON("message", string(message))
	return nil
}
