// internal/agent/listeners/listeners.go
package listeners

import (
	"c2/internal/common/config"
	"c2/internal/common/interfaces"
	"c2/internal/websocket/agent"
	pb "c2/proto"
	"context"
	"crypto/tls"
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"
)

// ManagerOption allows for optional configuration
type ManagerOption func(*Manager)

// WithAsyncProcessing enables async processing with the given configuration
func WithAsyncProcessing(cfg *config.ProcessorConfig) ManagerOption {
	return func(m *Manager) {
		// Wrap the manager with async handler
		asyncHandler := NewAsyncHandler(m, cfg)
		m.handler = asyncHandler
		m.asyncEnabled = true
		log.Printf("[Manager] Async processing enabled with config: %+v", cfg)
	}
}

type Manager struct {
	handler           interface{}
	listeners         map[string]*http.Server
	mutex             sync.Mutex
	webCerts          config.WebServerConfig
	initData          map[string]*InitData
	db                *sql.DB
	routes            *config.AgentConfig
	activeConnections *ActiveConnectionManager
	grpcClient        *agent.Client
	commandBuffer     interfaces.CommandBuffer
	downloadTracker   *DownloadTracker
	uploadTracker     *UploadTracker
	socksRoutes       *SocksRoutes
	asyncEnabled      bool              // Add this flag for async processing
	heartbeatBatcher  *HeartbeatBatcher // Batches lastSEEN updates to reduce DB load
	linkRouting       *LinkRouting      // Manages SMB link routing for lateral movement
}

// NewManagerWithOptions creates a manager with optional configurations
func NewManagerWithOptions(
	handler interface{},
	webCerts config.WebServerConfig,
	db *sql.DB,
	agentConfig *config.AgentConfig,
	grpcClient *agent.Client,
	commandBuffer interfaces.CommandBuffer,
	opts ...ManagerOption,
) *Manager {
	m := &Manager{
		handler:           handler,
		listeners:         make(map[string]*http.Server),
		webCerts:          webCerts,
		initData:          make(map[string]*InitData),
		db:                db,
		routes:            agentConfig,
		activeConnections: newActiveConnectionManager(db),
		grpcClient:        grpcClient,
		commandBuffer:     commandBuffer,
		downloadTracker:   NewDownloadTracker("/app/temp", "/app/downloads"),
		uploadTracker:     NewUploadTracker("/app/temp", "/app/uploads"),
		socksRoutes:       NewSocksRoutes(),
		asyncEnabled:      false,
		heartbeatBatcher:  NewHeartbeatBatcher(db, 5*time.Second), // Batch every 5 seconds
	}

	// Start the heartbeat batcher background process
	m.heartbeatBatcher.Start()
	log.Println("[Manager] Heartbeat batcher started (DB load optimization)")

	// Load existing init data from database
	if err := m.loadInitDataFromDB(); err != nil {
		log.Printf("Warning: Failed to load init data from database: %v", err)
	}

	// Apply options
	for _, opt := range opts {
		opt(m)
	}

	return m
}

// Keep the original NewManager for backward compatibility
func NewManager(
	handler interface{},
	webCerts config.WebServerConfig,
	db *sql.DB,
	agentConfig *config.AgentConfig,
	grpcClient *agent.Client,
	commandBuffer interfaces.CommandBuffer,
) *Manager {
	return NewManagerWithOptions(
		handler,
		webCerts,
		db,
		agentConfig,
		grpcClient,
		commandBuffer,
	)
}

func (m *Manager) createHTTPHandler(cfg config.ListenerConfig) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("[%s] Received request to %s from %s", r.Method, r.URL.Path, r.RemoteAddr)

		// Check for SOCKS WebSocket upgrade first
		if m.socksRoutes != nil {
			if handler := m.socksRoutes.GetHandler(r.URL.Path); handler != nil {
				log.Printf("[SOCKS] Found handler for path: %s", r.URL.Path)
				handler(w, r)
				return
			}
		}

		// Apply configured headers
		for k, v := range cfg.Headers {
			w.Header().Set(k, v)
		}

		// Check GET handlers (which may use custom methods)
		for _, handler := range m.routes.Routes.Get {
			// Check if the path matches AND the method matches (custom or default)
			if handler.Path == r.URL.Path && handler.Method == r.Method && handler.Enabled {
				log.Printf("[%s] Found matching GET-type handler for path %s", r.Method, r.URL.Path)

				clientID, err := m.extractClientID(r, handler)
				if err != nil {
					http.Error(w, err.Error(), http.StatusBadRequest)
					return
				}

				// Use GET request handler (since this is a GET-type operation)
				m.handleGetRequest(w, clientID, m.commandBuffer)
				return
			}
		}

		// Check POST handlers (which may use custom methods)
		for _, handler := range m.routes.Routes.Post {
			// Check if the path matches AND the method matches (custom or default)
			if handler.Path == r.URL.Path && handler.Method == r.Method && handler.Enabled {
				log.Printf("[%s] Found matching POST-type handler for path %s", r.Method, r.URL.Path)

				// Use POST request handler (since this is a POST-type operation)
				m.handlePostRequest(w, r)
				return
			}
		}

		// No matching handler found
		log.Printf("[%s] No matching handler found for path %s", r.Method, r.URL.Path)

		// Check if this method is even allowed
		allowed := false
		for _, handler := range m.routes.Routes.Get {
			if handler.Enabled && handler.Method == r.Method {
				allowed = true
				break
			}
		}
		if !allowed {
			for _, handler := range m.routes.Routes.Post {
				if handler.Enabled && handler.Method == r.Method {
					allowed = true
					break
				}
			}
		}

		if !allowed && !methodAllowed(cfg.AllowedMethods, r.Method) {
			log.Printf("[%s] Method not allowed", r.Method)
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		} else {
			log.Printf("[%s] Path not found: %s", r.Method, r.URL.Path)
			http.Error(w, "Not found", http.StatusNotFound)
		}
	})
}

// setupTLSConfig sets up the TLS configuration for HTTPS
func (m *Manager) setupTLSConfig(cfg config.ListenerConfig) (*tls.Config, error) {
	certPath := m.webCerts.CertFile
	keyPath := m.webCerts.KeyFile

	log.Printf("[StartListener] Loading certificate and key for HTTPS listener %s", cfg.Name)
	log.Printf("[StartListener] Cert Path: %s, Key Path: %s", certPath, keyPath)

	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load cert and key: %v", err)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
	}, nil
}

// createServer creates an HTTP/HTTPS server based on configuration
func (m *Manager) createServer(cfg config.ListenerConfig, handler http.Handler) (*http.Server, error) {
	server := &http.Server{
		Addr:    fmt.Sprintf("0.0.0.0:%d", cfg.Port),
		Handler: handler,
	}

	if cfg.Protocol == "HTTPS" {
		tlsConfig, err := m.setupTLSConfig(cfg)
		if err != nil {
			return nil, fmt.Errorf("failed to setup TLS: %v", err)
		}
		server.TLSConfig = tlsConfig
	}

	return server, nil
}

// startServerGoroutine starts the server in a goroutine
func (m *Manager) startServerGoroutine(server *http.Server, cfg config.ListenerConfig) {
	go func() {
		log.Printf("[StartListener] Starting listener %s on %s:%d", cfg.Name, cfg.BindIP, cfg.Port)
		var err error

		if cfg.Protocol == "HTTPS" {
			err = server.ListenAndServeTLS("", "")
		} else {
			err = server.ListenAndServe()
		}

		if err != nil && err != http.ErrServerClosed {
			log.Printf("[StartListener] Failed to start %s listener %s: %v",
				cfg.Protocol, cfg.Name, err)
		} else {
			log.Printf("[StartListener] %s listener %s stopped",
				cfg.Protocol, cfg.Name)
		}
	}()
}

// StartListener creates and starts a listener based on the given configuration
func (m *Manager) StartListener(cfg config.ListenerConfig) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	// Check for existing listener
	if _, exists := m.listeners[cfg.Name]; exists {
		return fmt.Errorf("listener with name %s already exists", cfg.Name)
	}

	// Set allowed methods if not already set
	if len(cfg.AllowedMethods) == 0 {
		cfg.AllowedMethods = m.routes.GetAllowedMethods(cfg.Protocol)
		log.Printf("[StartListener] Setting allowed methods for %s: %v",
			cfg.Name, cfg.AllowedMethods)
	}

	// Set default headers if not already set
	if len(cfg.Headers) == 0 {
		cfg.Headers = m.routes.GetHeaders()
	}

	// Create handler
	handler := m.createHTTPHandler(cfg)

	// Create server
	server, err := m.createServer(cfg, handler)
	if err != nil {
		return fmt.Errorf("failed to create server: %v", err)
	}

	// Start server goroutine
	m.startServerGoroutine(server, cfg)

	// Store the listener
	m.listeners[cfg.Name] = server
	log.Printf("[StartListener] Listener %s added to active listeners map", cfg.Name)

	return nil
}

// StopListener stops an active listener by name
func (m *Manager) StopListener(name string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	listener, exists := m.listeners[name]
	if !exists {
		log.Printf("[StopListener] Listener %s does not exist", name)
		return fmt.Errorf("listener %s does not exist", name)
	}

	log.Printf("[StopListener] Stopping listener %s", name)

	// Gracefully shut down the server
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	log.Printf("[StopListener] Initiating shutdown for listener %s", name)
	if err := listener.Shutdown(ctx); err != nil {
		log.Printf("[StopListener] Failed to gracefully stop listener %s: %v", name, err)
		return err
	}

	log.Printf("[StopListener] Shutdown complete for listener %s", name)
	delete(m.listeners, name)
	log.Printf("[StopListener] Listener %s removed from active listeners map", name)
	return nil
}

// StopAll stops all active listeners
func (m *Manager) StopAll() {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	log.Println("[StopAll] Stopping all listeners...")
	for name, listener := range m.listeners {
		log.Printf("[StopAll] Stopping listener %s", name)

		// Gracefully shut down each server
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		log.Printf("[StopAll] Initiating shutdown for listener %s", name)
		if err := listener.Shutdown(ctx); err != nil {
			log.Printf("[StopAll] Failed to gracefully stop listener %s: %v", name, err)
		} else {
			log.Printf("[StopAll] Listener %s stopped successfully", name)
		}

		delete(m.listeners, name)
		log.Printf("[StopAll] Listener %s removed from active listeners map", name)
	}
	log.Println("[StopAll] All listeners stopped successfully")
}

// Helper function to check if the HTTP method is allowed
func methodAllowed(allowedMethods []string, method string) bool {
	for _, allowed := range allowedMethods {
		if allowed == method {
			return true
		}
	}
	return false
}

func (m *Manager) notifyWebsocketService(notification *pb.ConnectionNotification) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := m.grpcClient.NotifyNewConnection(ctx, notification)
	if err != nil {
		return fmt.Errorf("failed to notify via gRPC: %v", err)
	}

	if !resp.Success {
		return fmt.Errorf("gRPC notification failed: %s (error code: %d)",
			resp.Message, resp.ErrorCode)
	}

	return nil
}

func (m *Manager) UpdateGRPCClient(client *agent.Client) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.grpcClient = client
}

func (m *Manager) RegisterSocksRoute(path string, handler http.HandlerFunc) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if m.socksRoutes == nil {
		m.socksRoutes = &SocksRoutes{
			routes: make(map[string]*SocksRoute),
		}
	}
	m.socksRoutes.AddRoute(path, handler)
}

func (m *Manager) RemoveSocksRoute(path string) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if m.socksRoutes != nil {
		m.socksRoutes.RemoveRoute(path)
	}
}

func (sr *SocksRoutes) RemoveRoute(path string) {
	sr.mu.Lock()
	defer sr.mu.Unlock()

	if route, exists := sr.routes[path]; exists {
		route.Active = false
		delete(sr.routes, path)
		log.Printf("[SOCKS] Removed route for path: %s", path)
	}
}

func NewSocksRoutes() *SocksRoutes {
	return &SocksRoutes{
		routes: make(map[string]*SocksRoute),
	}
}

// Add Shutdown method to Manager
func (m *Manager) Shutdown(timeout time.Duration) error {
	log.Println("[Manager] Initiating shutdown...")

	// Stop all listeners first
	m.StopAll()

	// Stop heartbeat batcher and flush remaining updates
	if m.heartbeatBatcher != nil {
		log.Println("[Manager] Stopping heartbeat batcher...")
		m.heartbeatBatcher.Stop()
	}

	// If async is enabled, shutdown the async handler
	if m.asyncEnabled {
		if asyncHandler, ok := m.handler.(*AsyncHandler); ok {
			if err := asyncHandler.Shutdown(timeout); err != nil {
				return fmt.Errorf("async handler shutdown failed: %v", err)
			}
		}
	}

	log.Println("[Manager] Shutdown complete")
	return nil
}

// GetMetrics returns current processing metrics if async is enabled
func (m *Manager) GetMetrics() map[string]interface{} {
	metrics := make(map[string]interface{})

	metrics["listeners"] = len(m.listeners)
	metrics["active_connections"] = len(m.activeConnections.connections)
	metrics["init_data_count"] = len(m.initData)

	// Add heartbeat batcher metrics
	if m.heartbeatBatcher != nil {
		metrics["heartbeat_batcher"] = m.heartbeatBatcher.GetMetrics()
	}

	if m.asyncEnabled {
		if asyncHandler, ok := m.handler.(*AsyncHandler); ok {
			metrics["queue_size"] = len(asyncHandler.batchChannel)
			metrics["queue_capacity"] = cap(asyncHandler.batchChannel)
			metrics["async_enabled"] = true
		}
	} else {
		metrics["async_enabled"] = false
	}

	return metrics
}

// IsAsyncEnabled returns whether async processing is enabled
func (m *Manager) IsAsyncEnabled() bool {
	return m.asyncEnabled
}

// LoadActiveConnections loads all active connections from the database
func (m *Manager) LoadActiveConnections() error {
	log.Println("Loading active connections from database...")

	query := `
		SELECT newclientID, protocol, secret1, secret2 
		FROM connections 
		WHERE deleted_at IS NULL
	`

	rows, err := m.db.Query(query)
	if err != nil {
		return fmt.Errorf("failed to query connections: %v", err)
	}
	defer rows.Close()

	count := 0
	for rows.Next() {
		var conn ActiveConnection
		err := rows.Scan(&conn.ClientID, &conn.Protocol, &conn.Secret1, &conn.Secret2)
		if err != nil {
			log.Printf("Failed to scan connection row: %v", err)
			continue
		}

		// Store in activeConnections map using the mutex
		m.activeConnections.mutex.Lock()
		m.activeConnections.connections[conn.ClientID] = &conn
		m.activeConnections.mutex.Unlock()

		count++
	}

	if err := rows.Err(); err != nil {
		return fmt.Errorf("error iterating connections: %v", err)
	}

	log.Printf("Loaded %d active connections from database", count)

	// Log loaded connections for debugging
	log.Println("Current Active Connections:")
	m.activeConnections.mutex.Lock()
	for clientID, conn := range m.activeConnections.connections {
		log.Printf("ClientID: %s, Protocol: %s, Secret lengths: %d/%d",
			clientID, conn.Protocol, len(conn.Secret1), len(conn.Secret2))
	}
	m.activeConnections.mutex.Unlock()

	return nil
}

// LoadInitData loads all init data from the database
func (m *Manager) LoadInitData() error {
	log.Println("Loading InitData from database...")

	// Note: The inits table does NOT have a protocol column based on the schema
	query := `
		SELECT id, clientID, type, secret, os, arch, RSAkey
		FROM inits
		WHERE id IS NOT NULL
	`

	rows, err := m.db.Query(query)
	if err != nil {
		return fmt.Errorf("failed to query inits table: %v", err)
	}
	defer rows.Close()

	count := 0
	for rows.Next() {
		var initData InitData

		err := rows.Scan(
			&initData.ID,
			&initData.ClientID,
			&initData.Type,
			&initData.Secret,
			&initData.OS,
			&initData.Arch,
			&initData.RSAKey,
		)
		if err != nil {
			log.Printf("Failed to scan init data row: %v", err)
			continue
		}

		// Since protocol isn't in the database, we need to determine it another way
		// Check if there's a matching connection to get the protocol
		m.activeConnections.mutex.RLock()
		if conn, exists := m.activeConnections.connections[initData.ClientID]; exists {
			initData.Protocol = conn.Protocol
		} else {
			// Default to HTTPS if no connection found
			initData.Protocol = "HTTPS"
		}
		m.activeConnections.mutex.RUnlock()

		// Store init data in memory using the existing StoreInitData method
		if err := m.StoreInitData(&initData); err != nil {
			log.Printf("Failed to store init data for client %s: %v", initData.ClientID, err)
			continue
		}

		count++
	}

	if err := rows.Err(); err != nil {
		return fmt.Errorf("error iterating init data: %v", err)
	}

	log.Printf("Loaded InitData from Database (%d entries):", count)

	return nil
}

// StartExistingListeners loads and starts all listeners from the database
// This should be called during agent-handler initialization
func (m *Manager) StartExistingListeners() error {
	log.Println("[StartExistingListeners] Checking for existing listeners in database...")

	// Query for all listeners (no 'active' column exists in the schema)
	rows, err := m.db.Query(`
		SELECT name, protocol, port, ip 
		FROM listeners
	`)
	if err != nil {
		return fmt.Errorf("failed to query existing listeners: %v", err)
	}
	defer rows.Close()

	var listeners []struct {
		name     string
		protocol string
		port     string // Note: port is VARCHAR in the database
		bindIP   string
	}

	// Collect all listeners from database
	for rows.Next() {
		var l struct {
			name     string
			protocol string
			port     string // Changed to string to match DB schema
			bindIP   string
		}

		if err := rows.Scan(&l.name, &l.protocol, &l.port, &l.bindIP); err != nil {
			log.Printf("[StartExistingListeners] Failed to scan listener row: %v", err)
			continue
		}
		listeners = append(listeners, l)
	}

	if err := rows.Err(); err != nil {
		return fmt.Errorf("error iterating listeners: %v", err)
	}

	log.Printf("[StartExistingListeners] Found %d listener(s) in database", len(listeners))

	if len(listeners) == 0 {
		log.Printf("[StartExistingListeners] No existing listeners found in database")
		return nil
	}

	// Track results
	successCount := 0
	failedListeners := []string{}

	// Start each listener
	for _, l := range listeners {
		// Convert port string to int
		var port int
		if _, err := fmt.Sscanf(l.port, "%d", &port); err != nil {
			log.Printf("[StartExistingListeners] Invalid port format for listener %s: %s", l.name, l.port)
			failedListeners = append(failedListeners, fmt.Sprintf("%s (invalid port: %s)", l.name, l.port))
			continue
		}

		log.Printf("[StartExistingListeners] Attempting to start listener: %s (%s) on %s:%d",
			l.name, l.protocol, l.bindIP, port)

		// Create listener configuration
		listenerCfg := config.ListenerConfig{
			Name:     l.name,
			Protocol: l.protocol,
			Port:     port,
			BindIP:   l.bindIP,
			Secure:   l.protocol == "HTTPS",
		}

		// Attempt to start the listener
		if err := m.StartListener(listenerCfg); err != nil {
			log.Printf("[StartExistingListeners] Failed to start listener %s: %v", l.name, err)
			failedListeners = append(failedListeners, fmt.Sprintf("%s (%v)", l.name, err))
			continue
		}

		log.Printf("[StartExistingListeners] Successfully started listener: %s", l.name)
		successCount++
	}

	// Report summary
	if len(failedListeners) > 0 {
		log.Printf("[StartExistingListeners] Started %d/%d listeners. Failed: %v",
			successCount, len(listeners), failedListeners)
		// Return nil here so we don't fail the startup even if some listeners fail
		return nil
	}

	log.Printf("[StartExistingListeners] Successfully started all %d listener(s)", successCount)
	return nil
}
