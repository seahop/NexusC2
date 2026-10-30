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
	"encoding/json"
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

	// Shared port management - allows multiple listeners on the same port
	sharedPorts    map[int]*SharedPortServer // Port -> shared server
	listenerToPort map[string]int            // Listener name -> port number
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
		sharedPorts:       make(map[int]*SharedPortServer),
		listenerToPort:    make(map[string]int),
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

// UpdateProfiles replaces all HTTP profiles with the provided profiles
// This is called when the websocket service syncs uploaded profiles
func (m *Manager) UpdateProfiles(getProfiles []config.GetProfile, postProfiles []config.PostProfile, serverResponseProfiles []config.ServerResponseProfile) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if m.routes == nil {
		log.Printf("[Manager] Warning: Cannot update profiles - routes config is nil")
		return
	}

	// Replace all profiles
	m.routes.HTTPProfiles.Get = getProfiles
	m.routes.HTTPProfiles.Post = postProfiles
	m.routes.HTTPProfiles.ServerResponse = serverResponseProfiles

	log.Printf("[Manager] Profiles updated: %d GET, %d POST, %d Response",
		len(getProfiles), len(postProfiles), len(serverResponseProfiles))
}

// UpdateVariants replaces the stored profile variants and re-registers
// variant paths on all active shared-port listeners so that agents built
// with any variant are routed correctly.
func (m *Manager) UpdateVariants(variants []config.ProfileVariant) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	if m.routes == nil {
		return
	}
	m.routes.HTTPProfiles.Variants = variants

	// Re-register variant paths for every active shared-port listener.
	for listenerName, port := range m.listenerToPort {
		sps, ok := m.sharedPorts[port]
		if !ok {
			continue
		}
		sps.mu.Lock()
		handler, exists := sps.listenerHandlers[listenerName]
		if !exists {
			sps.mu.Unlock()
			continue
		}

		// Remove old variant routes (keep default routes)
		for _, gp := range handler.VariantGetProfiles {
			delete(sps.pathRoutes, gp.Method+":"+gp.Path)
		}
		for _, pp := range handler.VariantPostProfiles {
			delete(sps.pathRoutes, pp.Method+":"+pp.Path)
		}
		handler.VariantGetProfiles = nil
		handler.VariantPostProfiles = nil
		handler.VariantRespProfiles = nil

		// Resolve and register new variant routes
		for _, v := range variants {
			gp, pp, rp, err := m.routes.ResolveVariant(v.Name)
			if err != nil {
				log.Printf("[Manager] Variant %q skip: %v", v.Name, err)
				continue
			}
			handler.VariantGetProfiles = append(handler.VariantGetProfiles, gp)
			handler.VariantPostProfiles = append(handler.VariantPostProfiles, pp)
			handler.VariantRespProfiles = append(handler.VariantRespProfiles, rp)

			key := gp.Method + ":" + gp.Path
			if _, taken := sps.pathRoutes[key]; !taken {
				sps.pathRoutes[key] = listenerName
				log.Printf("[SharedPort:%d] Variant %q: registered %s -> '%s'",
					port, v.Name, key, listenerName)
			}
			key = pp.Method + ":" + pp.Path
			if _, taken := sps.pathRoutes[key]; !taken {
				sps.pathRoutes[key] = listenerName
				log.Printf("[SharedPort:%d] Variant %q: registered %s -> '%s'",
					port, v.Name, key, listenerName)
			}
		}
		sps.mu.Unlock()
	}

	log.Printf("[Manager] Profile variants updated: %d variants", len(variants))
}

// GetAllVariantNames returns the names of all defined profile variants
func (m *Manager) GetAllVariantNames() []string {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	if m.routes == nil {
		return nil
	}
	return m.routes.GetProfileVariantNames()
}

// createListenerHandler builds a ListenerHandler for a listener config
func (m *Manager) createListenerHandler(cfg config.ListenerConfig) *ListenerHandler {
	handler := &ListenerHandler{
		ListenerName:   cfg.Name,
		Headers:        cfg.Headers,
		AllowedMethods: cfg.AllowedMethods,
	}

	// Look up bound profiles (default)
	if cfg.GetProfile != "" {
		handler.GetProfile = m.routes.GetGetProfile(cfg.GetProfile)
		if handler.GetProfile != nil {
			log.Printf("[Listener %s] Handler using GET profile: %s (path: %s, method: %s)",
				cfg.Name, handler.GetProfile.Name, handler.GetProfile.Path, handler.GetProfile.Method)
		}
	}

	if cfg.PostProfile != "" {
		handler.PostProfile = m.routes.GetPostProfile(cfg.PostProfile)
		if handler.PostProfile != nil {
			log.Printf("[Listener %s] Handler using POST profile: %s (path: %s, method: %s)",
				cfg.Name, handler.PostProfile.Name, handler.PostProfile.Path, handler.PostProfile.Method)
		}
	}

	if cfg.ServerResponseProfile != "" {
		handler.ServerResponseProfile = m.routes.GetServerResponseProfile(cfg.ServerResponseProfile)
		if handler.ServerResponseProfile != nil {
			log.Printf("[Listener %s] Handler using server response profile: %s",
				cfg.Name, handler.ServerResponseProfile.Name)
		}
	}

	// Resolve variant profiles (additional routes this listener handles)
	for _, vName := range cfg.Variants {
		gp, pp, rp, err := m.routes.ResolveVariant(vName)
		if err != nil {
			log.Printf("[Listener %s] Warning: variant %q: %v", cfg.Name, vName, err)
			continue
		}
		handler.VariantGetProfiles = append(handler.VariantGetProfiles, gp)
		handler.VariantPostProfiles = append(handler.VariantPostProfiles, pp)
		handler.VariantRespProfiles = append(handler.VariantRespProfiles, rp)
		log.Printf("[Listener %s] Variant %q: GET=%s POST=%s Response=%s",
			cfg.Name, vName, gp.Name, pp.Name, rp.Name)
	}

	return handler
}

// createSharedPortHandler creates a multiplexing HTTP handler for a shared port
// that routes requests to the appropriate listener based on URL path matching
func (m *Manager) createSharedPortHandler(sps *SharedPortServer) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("[SharedPort:%d] Received %s request to %s from %s",
			sps.Port, r.Method, r.URL.Path, r.RemoteAddr)

		// Check for SOCKS WebSocket upgrade first (shared across all listeners)
		if m.socksRoutes != nil {
			if socksHandler := m.socksRoutes.GetHandler(r.URL.Path); socksHandler != nil {
				log.Printf("[SharedPort:%d] SOCKS handler found for path: %s", sps.Port, r.URL.Path)
				socksHandler(w, r)
				return
			}
		}

		// Look up which listener should handle this request
		listenerName, handler, found := sps.LookupListener(r.Method, r.URL.Path)
		if found {
			log.Printf("[SharedPort:%d] Routing %s %s to listener '%s'",
				sps.Port, r.Method, r.URL.Path, listenerName)

			// Get the listener config for additional settings
			cfg, _ := sps.GetListenerConfig(listenerName)

			// Apply listener-specific headers
			for k, v := range handler.Headers {
				w.Header().Set(k, v)
			}

			// Build combined profile lists (default + variants) for this handler
			spGetProfiles := make([]*config.GetProfile, 0, 1+len(handler.VariantGetProfiles))
			spRespForGet := make([]*config.ServerResponseProfile, 0, 1+len(handler.VariantRespProfiles))
			if handler.GetProfile != nil {
				spGetProfiles = append(spGetProfiles, handler.GetProfile)
				spRespForGet = append(spRespForGet, handler.ServerResponseProfile)
			}
			for i, gp := range handler.VariantGetProfiles {
				spGetProfiles = append(spGetProfiles, gp)
				spRespForGet = append(spRespForGet, handler.VariantRespProfiles[i])
			}
			spPostProfiles := make([]*config.PostProfile, 0, 1+len(handler.VariantPostProfiles))
			if handler.PostProfile != nil {
				spPostProfiles = append(spPostProfiles, handler.PostProfile)
			}
			spPostProfiles = append(spPostProfiles, handler.VariantPostProfiles...)

			// Try matching GET profiles
			for gi, gp := range spGetProfiles {
				getPathMatches := false
				if gp.Method == r.Method {
					getPathMatches = gp.Path == r.URL.Path
					if !getPathMatches && gp.ClientID != nil && gp.ClientID.Output == "uri_append" {
						getPathMatches = len(r.URL.Path) > len(gp.Path) &&
							r.URL.Path[:len(gp.Path)] == gp.Path
					}
				}

				if getPathMatches {
					var clientID string
					var err error

					if gp.ClientID != nil {
						clientID, err = m.extractClientIDFromDataBlock(r, gp.ClientID, config.Handler{}, gp.Path, "")
						if err != nil {
							log.Printf("[SharedPort:%d] GET DataBlock extraction failed (%v), trying legacy", sps.Port, err)
							profileHandler := config.Handler{
								Path:    gp.Path,
								Method:  gp.Method,
								Enabled: true,
								Params:  gp.Params,
							}
							clientID, err = m.extractClientID(r, profileHandler)
							if err != nil {
								log.Printf("[SharedPort:%d] GET legacy extraction also failed: %v", sps.Port, err)
								http.Error(w, err.Error(), http.StatusBadRequest)
								return
							}
						}
					} else {
						profileHandler := config.Handler{
							Path:    gp.Path,
							Method:  gp.Method,
							Enabled: true,
							Params:  gp.Params,
						}
						clientID, err = m.extractClientID(r, profileHandler)
						if err != nil {
							log.Printf("[SharedPort:%d] Failed to extract client ID: %v", sps.Port, err)
							http.Error(w, err.Error(), http.StatusBadRequest)
							return
						}
					}

					m.handleGetRequestWithProfile(w, clientID, m.commandBuffer, spRespForGet[gi])
					return
				}
			}

			// Try matching POST profiles
			for _, pp := range spPostProfiles {
				postPathMatches := false
				if pp.Method == r.Method {
					postPathMatches = pp.Path == r.URL.Path
					if !postPathMatches && pp.ClientID != nil && pp.ClientID.Output == "uri_append" {
						postPathMatches = len(r.URL.Path) > len(pp.Path) &&
							r.URL.Path[:len(pp.Path)] == pp.Path
					}
				}

				if postPathMatches {
					m.handlePostRequestWithProfile(w, r, pp)
					return
				}
			}

			log.Printf("[SharedPort:%d] Warning: Found listener but no profile match", sps.Port)
			_ = cfg
		}

		// No handler found
		log.Printf("[SharedPort:%d] No handler found for %s %s", sps.Port, r.Method, r.URL.Path)
		http.Error(w, "Not found", http.StatusNotFound)
	})
}

// setupTLSConfig sets up the TLS configuration for HTTPS
func (m *Manager) setupTLSConfig(cfg config.ListenerConfig) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(m.webCerts.CertFile, m.webCerts.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load cert and key: %v", err)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
	}, nil
}

// startServerGoroutine starts the server in a goroutine
func (m *Manager) startServerGoroutine(server *http.Server, cfg config.ListenerConfig) {
	go func() {
		log.Printf("[LISTENER] %s started on %s:%d (%s)", cfg.Name, cfg.BindIP, cfg.Port, cfg.Protocol)
		var err error

		if cfg.Protocol == "HTTPS" {
			err = server.ListenAndServeTLS("", "")
		} else {
			err = server.ListenAndServe()
		}

		if err != nil && err != http.ErrServerClosed {
			log.Printf("[LISTENER] %s failed: %v", cfg.Name, err)
		}
	}()
}

// StartListener creates and starts a listener based on the given configuration
// Supports shared ports: multiple listeners can share the same port if their
// profile paths don't conflict
func (m *Manager) StartListener(cfg config.ListenerConfig) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	// Check if listener name already exists
	if _, exists := m.listeners[cfg.Name]; exists {
		return fmt.Errorf("listener with name %s already exists", cfg.Name)
	}
	if _, exists := m.listenerToPort[cfg.Name]; exists {
		return fmt.Errorf("listener with name %s already exists on shared port", cfg.Name)
	}

	// Set allowed methods based on bound profiles
	if len(cfg.AllowedMethods) == 0 {
		methods := make(map[string]bool)
		// Add methods from bound profiles
		if cfg.GetProfile != "" {
			if getProfile := m.routes.GetGetProfile(cfg.GetProfile); getProfile != nil {
				methods[getProfile.Method] = true
			}
		}
		if cfg.PostProfile != "" {
			if postProfile := m.routes.GetPostProfile(cfg.PostProfile); postProfile != nil {
				methods[postProfile.Method] = true
			}
		}
		// Always allow OPTIONS and HEAD for HTTP compatibility
		methods["OPTIONS"] = true
		methods["HEAD"] = true
		// Convert map to slice
		for method := range methods {
			cfg.AllowedMethods = append(cfg.AllowedMethods, method)
		}
	}

	// Set default headers if not already set
	if len(cfg.Headers) == 0 {
		cfg.Headers = m.routes.GetHeaders()
	}

	// Create the listener handler (contains profile bindings)
	listenerHandler := m.createListenerHandler(cfg)

	// Check if port already has a shared server
	sps, portInUse := m.sharedPorts[cfg.Port]

	if portInUse {
		// Port already in use - verify protocol matches
		if sps.Protocol != cfg.Protocol {
			return fmt.Errorf("port %d already in use by %s listener, cannot share with %s",
				cfg.Port, sps.Protocol, cfg.Protocol)
		}

		// Check for path conflicts
		if hasConflict, msg := sps.HasPathConflict(listenerHandler); hasConflict {
			return fmt.Errorf("cannot add listener to port %d: %s", cfg.Port, msg)
		}

		// Register this listener on the existing shared port
		if err := sps.RegisterListener(cfg.Name, listenerHandler, cfg); err != nil {
			return fmt.Errorf("failed to register listener on shared port: %v", err)
		}

		// Track the listener->port mapping
		m.listenerToPort[cfg.Name] = cfg.Port

		log.Printf("[LISTENER] %s added to shared port %d (%s) - total listeners on port: %d",
			cfg.Name, cfg.Port, cfg.Protocol, sps.GetListenerCount())
		return nil
	}

	// No existing shared server on this port - create a new one
	sps = NewSharedPortServer(cfg.Port, cfg.Protocol)

	// Setup TLS if HTTPS
	if cfg.Protocol == "HTTPS" {
		tlsConfig, err := m.setupTLSConfig(cfg)
		if err != nil {
			return fmt.Errorf("failed to setup TLS: %v", err)
		}
		sps.TLSConfig = tlsConfig
	}

	// Register this listener on the new shared port
	if err := sps.RegisterListener(cfg.Name, listenerHandler, cfg); err != nil {
		return fmt.Errorf("failed to register listener: %v", err)
	}

	// Create http.Server with the multiplexing handler
	server := &http.Server{
		Addr:      fmt.Sprintf("0.0.0.0:%d", cfg.Port),
		Handler:   m.createSharedPortHandler(sps),
		TLSConfig: sps.TLSConfig,
	}
	sps.Server = server

	// Start the server
	m.startServerGoroutine(server, cfg)

	// Store references
	m.sharedPorts[cfg.Port] = sps
	m.listenerToPort[cfg.Name] = cfg.Port

	log.Printf("[LISTENER] %s started on new shared port %d (%s)",
		cfg.Name, cfg.Port, cfg.Protocol)
	return nil
}

// StopListener stops an active listener by name
// For listeners on shared ports, only unregisters from the port; the server
// continues running until the last listener is removed
func (m *Manager) StopListener(name string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	// First check if this is on a shared port
	port, onSharedPort := m.listenerToPort[name]
	if onSharedPort {
		sps, portExists := m.sharedPorts[port]
		if !portExists {
			// Inconsistent state - clean up the mapping
			delete(m.listenerToPort, name)
			return fmt.Errorf("listener %s references non-existent shared port %d", name, port)
		}

		// Unregister the listener from the shared port
		sps.UnregisterListener(name)
		delete(m.listenerToPort, name)

		log.Printf("[LISTENER] %s removed from shared port %d (remaining: %d)",
			name, port, sps.GetListenerCount())

		// If the shared port is now empty, shut down the server
		if sps.IsEmpty() {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			if err := sps.Server.Shutdown(ctx); err != nil {
				log.Printf("[LISTENER] Failed to shutdown shared port %d server: %v", port, err)
				return err
			}

			delete(m.sharedPorts, port)
			log.Printf("[LISTENER] Shared port %d shut down (no more listeners)", port)
		}

		return nil
	}

	// Legacy path: standalone listener (not on shared port)
	listener, exists := m.listeners[name]
	if !exists {
		return fmt.Errorf("listener %s does not exist", name)
	}

	// Gracefully shut down the server
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := listener.Shutdown(ctx); err != nil {
		log.Printf("[LISTENER] %s stop failed: %v", name, err)
		return err
	}

	delete(m.listeners, name)
	log.Printf("[LISTENER] %s stopped", name)
	return nil
}

// StopAll stops all active listeners (both shared port and standalone)
func (m *Manager) StopAll() {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	// Stop all shared port servers
	for port, sps := range m.sharedPorts {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		if err := sps.Server.Shutdown(ctx); err != nil {
			log.Printf("[LISTENER] Shared port %d stop failed: %v", port, err)
		} else {
			log.Printf("[LISTENER] Shared port %d stopped (had %d listeners)",
				port, sps.GetListenerCount())
		}
		cancel()
	}
	// Clear shared port maps
	m.sharedPorts = make(map[int]*SharedPortServer)
	m.listenerToPort = make(map[string]int)

	// Stop all standalone listeners
	for name, listener := range m.listeners {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		if err := listener.Shutdown(ctx); err != nil {
			log.Printf("[LISTENER] %s stop failed: %v", name, err)
		} else {
			log.Printf("[LISTENER] %s stopped", name)
		}
		cancel()
		delete(m.listeners, name)
	}
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
		SELECT newclientID, protocol, secret1, secret2, field_mapping
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
		var fieldMappingJSON sql.NullString
		err := rows.Scan(&conn.ClientID, &conn.Protocol, &conn.Secret1, &conn.Secret2, &fieldMappingJSON)
		if err != nil {
			log.Printf("Failed to scan connection row: %v", err)
			continue
		}

		if fieldMappingJSON.Valid && fieldMappingJSON.String != "" {
			if err := json.Unmarshal([]byte(fieldMappingJSON.String), &conn.FieldMapping); err != nil {
				log.Printf("Warning: Failed to parse field mapping for %s: %v", conn.ClientID, err)
			}
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

	// Query includes smb_profile and smb_xor_key for transform support
	query := `
		SELECT id, clientID, type, secret, os, arch, RSAkey,
		       COALESCE(smb_profile, ''), COALESCE(smb_xor_key, '')
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
			&initData.SMBProfile,
			&initData.SMBXorKey,
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

	// Query for all listeners including profile bindings
	rows, err := m.db.Query(`
		SELECT name, protocol, port, ip,
			COALESCE(get_profile, 'default-get'),
			COALESCE(post_profile, 'default-post'),
			COALESCE(server_response_profile, 'default-response')
		FROM listeners
	`)
	if err != nil {
		return fmt.Errorf("failed to query existing listeners: %v", err)
	}
	defer rows.Close()

	var listeners []struct {
		name                  string
		protocol              string
		port                  string // Note: port is VARCHAR in the database
		bindIP                string
		getProfile            string
		postProfile           string
		serverResponseProfile string
	}

	// Collect all listeners from database
	for rows.Next() {
		var l struct {
			name                  string
			protocol              string
			port                  string // Changed to string to match DB schema
			bindIP                string
			getProfile            string
			postProfile           string
			serverResponseProfile string
		}

		if err := rows.Scan(&l.name, &l.protocol, &l.port, &l.bindIP,
			&l.getProfile, &l.postProfile, &l.serverResponseProfile); err != nil {
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

		log.Printf("[StartExistingListeners] Attempting to start listener: %s (%s) on %s:%d, Profiles: GET=%s POST=%s Response=%s",
			l.name, l.protocol, l.bindIP, port, l.getProfile, l.postProfile, l.serverResponseProfile)

		// Create listener configuration with profile bindings
		listenerCfg := config.ListenerConfig{
			Name:                  l.name,
			Protocol:              l.protocol,
			Port:                  port,
			BindIP:                l.bindIP,
			Secure:                l.protocol == "HTTPS",
			GetProfile:            l.getProfile,
			PostProfile:           l.postProfile,
			ServerResponseProfile: l.serverResponseProfile,
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
