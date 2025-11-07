// internal/websocket/reconnect/manager.go
package reconnect

import (
	"c2/internal/websocket/agent"
	"c2/internal/websocket/hub"
	"context"
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"
)

// StreamManager manages the gRPC bidirectional stream with auto-reconnection
type StreamManager struct {
	mu             sync.RWMutex
	grpcAddress    string
	clientID       string
	hub            *hub.Hub
	currentClient  *agent.Client
	isConnected    atomic.Bool
	reconnecting   atomic.Bool
	shutdownCh     chan struct{}
	reconnectCh    chan struct{}
	lastError      error
	reconnectDelay time.Duration
	maxRetryDelay  time.Duration
	retryCount     atomic.Int32
	stopOnce       sync.Once   // Added to prevent double close
	stopped        atomic.Bool // Added to track stop state
}

// NewStreamManager creates a new stream manager
func NewStreamManager(grpcAddress, clientID string, hub *hub.Hub) *StreamManager {
	return &StreamManager{
		grpcAddress:    grpcAddress,
		clientID:       clientID,
		hub:            hub,
		shutdownCh:     make(chan struct{}),
		reconnectCh:    make(chan struct{}, 1),
		reconnectDelay: time.Second,
		maxRetryDelay:  30 * time.Second,
	}
}

// Start begins the connection management
func (sm *StreamManager) Start(ctx context.Context) error {
	log.Printf("[StreamManager] Starting connection management to %s", sm.grpcAddress)

	// Start the monitoring goroutine
	go sm.monitorConnection(ctx)

	// Attempt initial connection
	if err := sm.connect(ctx); err != nil {
		log.Printf("[StreamManager] Initial connection failed: %v, will retry", err)
		sm.triggerReconnect()
	}

	return nil
}

// connect establishes a new gRPC connection and bidirectional stream
func (sm *StreamManager) connect(ctx context.Context) error {
	// Check if we're stopping
	if sm.stopped.Load() {
		return fmt.Errorf("stream manager is stopped")
	}

	sm.mu.Lock()
	defer sm.mu.Unlock()

	log.Printf("[StreamManager] Attempting to connect to agent service at %s", sm.grpcAddress)

	// Clean up any existing connection
	if sm.currentClient != nil {
		sm.currentClient.Close()
		sm.currentClient = nil
	}

	// Create new client
	client, err := agent.NewClient(sm.grpcAddress, sm.clientID)
	if err != nil {
		sm.lastError = err
		sm.isConnected.Store(false)
		return fmt.Errorf("failed to create gRPC client: %v", err)
	}

	// Create a context for the stream that we can monitor
	streamCtx, cancel := context.WithCancel(ctx)

	// Start the bidirectional stream
	if err := client.StartBiDiStream(streamCtx, sm.hub); err != nil {
		cancel()
		client.Close()
		sm.lastError = err
		sm.isConnected.Store(false)
		return fmt.Errorf("failed to start bidirectional stream: %v", err)
	}

	// Monitor the stream in a separate goroutine
	go sm.monitorStream(streamCtx, cancel, client)

	sm.currentClient = client
	sm.isConnected.Store(true)
	sm.retryCount.Store(0)
	sm.reconnectDelay = time.Second // Reset delay on successful connection

	log.Printf("[StreamManager] Successfully connected to agent service")

	return nil
}

// monitorStream monitors the health of a stream and triggers reconnection if needed
func (sm *StreamManager) monitorStream(ctx context.Context, cancel context.CancelFunc, client *agent.Client) {
	defer cancel()

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	failureCount := 0

	for {
		select {
		case <-ctx.Done():
			log.Printf("[StreamManager] Stream monitoring stopped")
			if !sm.stopped.Load() {
				sm.handleStreamLoss()
			}
			return

		case <-ticker.C:
			// Check if we're stopping
			if sm.stopped.Load() {
				return
			}

			// Send a ping to check stream health
			err := client.SendToStream("ping", map[string]interface{}{
				"timestamp": time.Now().Unix(),
				"source":    sm.clientID,
			})

			if err != nil {
				failureCount++
				log.Printf("[StreamManager] Stream health check failed (%d): %v", failureCount, err)

				if failureCount >= 3 {
					log.Printf("[StreamManager] Stream appears to be dead, triggering reconnection")
					if !sm.stopped.Load() {
						sm.handleStreamLoss()
					}
					return
				}
			} else {
				failureCount = 0 // Reset on successful ping
			}
		}
	}
}

// handleStreamLoss handles when a stream is lost
func (sm *StreamManager) handleStreamLoss() {
	// Don't handle stream loss if we're stopping
	if sm.stopped.Load() {
		return
	}

	sm.mu.Lock()
	sm.isConnected.Store(false)
	if sm.currentClient != nil {
		sm.currentClient.Close()
		sm.currentClient = nil
	}
	sm.mu.Unlock()

	sm.triggerReconnect()
}

// monitorConnection is the main connection monitoring loop
func (sm *StreamManager) monitorConnection(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			log.Printf("[StreamManager] Stopping connection monitor")
			return

		case <-sm.shutdownCh:
			log.Printf("[StreamManager] Shutdown requested")
			return

		case <-sm.reconnectCh:
			// Check if we're stopping
			if sm.stopped.Load() {
				return
			}

			if sm.isConnected.Load() {
				continue // Already connected
			}

			if sm.reconnecting.CompareAndSwap(false, true) {
				sm.doReconnect(ctx)
				sm.reconnecting.Store(false)
			}
		}
	}
}

// doReconnect performs the reconnection logic with exponential backoff
func (sm *StreamManager) doReconnect(ctx context.Context) {
	for {
		// Check if we're stopping
		if sm.stopped.Load() {
			return
		}

		select {
		case <-ctx.Done():
			return
		case <-sm.shutdownCh:
			return
		default:
		}

		attempts := sm.retryCount.Add(1)
		log.Printf("[StreamManager] Reconnection attempt %d", attempts)

		if err := sm.connect(ctx); err != nil {
			// Calculate next delay with exponential backoff
			delay := sm.reconnectDelay * time.Duration(attempts)
			if delay > sm.maxRetryDelay {
				delay = sm.maxRetryDelay
			}

			log.Printf("[StreamManager] Reconnection failed: %v, retrying in %v", err, delay)

			select {
			case <-time.After(delay):
				continue
			case <-ctx.Done():
				return
			case <-sm.shutdownCh:
				return
			}
		} else {
			// Successfully reconnected
			log.Printf("[StreamManager] Reconnection successful after %d attempts", attempts)
			return
		}
	}
}

// triggerReconnect triggers a reconnection attempt
func (sm *StreamManager) triggerReconnect() {
	// Don't trigger reconnect if we're stopping
	if sm.stopped.Load() {
		return
	}

	select {
	case sm.reconnectCh <- struct{}{}:
	default:
		// Channel is full, reconnection already scheduled
	}
}

// GetClient returns the current gRPC client if connected
func (sm *StreamManager) GetClient() (*agent.Client, error) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	if !sm.isConnected.Load() {
		return nil, fmt.Errorf("not connected to agent service")
	}

	if sm.currentClient == nil {
		return nil, fmt.Errorf("client is nil despite being connected")
	}

	return sm.currentClient, nil
}

// IsConnected returns the connection status
func (sm *StreamManager) IsConnected() bool {
	return sm.isConnected.Load()
}

// Stop gracefully stops the stream manager
func (sm *StreamManager) Stop() {
	sm.stopOnce.Do(func() {
		log.Printf("[StreamManager] Stopping stream manager")

		// Mark as stopped first to prevent any new operations
		sm.stopped.Store(true)

		// Close the shutdown channel safely
		close(sm.shutdownCh)

		// Clean up the client connection
		sm.mu.Lock()
		defer sm.mu.Unlock()

		if sm.currentClient != nil {
			sm.currentClient.Close()
			sm.currentClient = nil
		}

		sm.isConnected.Store(false)
	})
}

// GetStatus returns the current status of the stream manager
func (sm *StreamManager) GetStatus() map[string]interface{} {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	status := map[string]interface{}{
		"connected":    sm.isConnected.Load(),
		"reconnecting": sm.reconnecting.Load(),
		"retry_count":  sm.retryCount.Load(),
		"grpc_address": sm.grpcAddress,
		"client_id":    sm.clientID,
		"stopped":      sm.stopped.Load(),
	}

	if sm.lastError != nil {
		status["last_error"] = sm.lastError.Error()
	}

	return status
}
