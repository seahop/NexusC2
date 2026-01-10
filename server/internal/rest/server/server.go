// internal/rest/server/server.go
package server

import (
	"context"
	"crypto/tls"
	"database/sql"
	"log"
	"net/http"
	"os"
	"runtime"
	"time"

	"c2/internal/common/config"
	"c2/internal/rest/auth"
	"c2/internal/rest/handlers"
	"c2/internal/rest/sse"
	"c2/internal/rest/wsproxy"
	"c2/internal/websocket/agent"
	"c2/internal/websocket/listeners"
	pb "c2/proto"

	"github.com/gin-gonic/gin"
)

type Server struct {
	config          *config.RESTConfig
	router          *gin.Engine
	httpServer      *http.Server
	db              *sql.DB
	jwtManager      *auth.JWTManager
	sseHub          *sse.Hub
	listenerManager *listeners.Manager
	agentClient     *agent.Client
	rateLimiter     *RateLimiter

	// WebSocket proxy for operations that need event broadcasting
	wsProxyClient   *wsproxy.Client
	wsProxyHandlers *wsproxy.ProxyHandlers
	useWSProxy      bool

	// Handlers (direct DB access for read operations)
	authHandler     *handlers.AuthHandler
	agentHandler    *handlers.AgentHandler
	commandHandler  *handlers.CommandHandler
	listenerHandler *handlers.ListenerHandler
	payloadHandler  *handlers.PayloadHandler
}

func NewServer(cfg *config.RESTConfig, db *sql.DB) (*Server, error) {
	// Create JWT manager
	jwtManager := auth.NewJWTManager(
		cfg.JWT.SecretKey,
		cfg.JWT.AccessExpiry,
		cfg.JWT.RefreshExpiry,
		db,
	)

	// Create SSE hub
	sseHub := sse.NewHub()

	// Create listener manager (still needed for direct DB reads)
	listenerManager := listeners.NewManager(db)

	// Create rate limiter
	rateLimiter := NewRateLimiter(cfg.RateLimit.RequestsPerMinute)

	s := &Server{
		config:          cfg,
		db:              db,
		jwtManager:      jwtManager,
		sseHub:          sseHub,
		listenerManager: listenerManager,
		rateLimiter:     rateLimiter,
	}

	// Initialize WebSocket proxy if WS_PROXY_URL is set
	// This allows the REST API to proxy operations through the WebSocket service
	// which ensures all events are properly broadcast to connected clients
	wsProxyURL := os.Getenv("WS_PROXY_URL")
	if wsProxyURL != "" {
		log.Printf("Initializing WebSocket proxy to %s", wsProxyURL)
		s.wsProxyClient = wsproxy.NewClient(wsProxyURL, "rest-api-proxy")
		s.wsProxyHandlers = wsproxy.NewProxyHandlers(s.wsProxyClient, db)
		s.useWSProxy = true

		// Connect to WebSocket service
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := s.wsProxyClient.Connect(ctx); err != nil {
			log.Printf("Warning: Failed to connect to WebSocket proxy: %v (will use direct handlers)", err)
			s.useWSProxy = false
		} else {
			log.Println("WebSocket proxy connected successfully")
		}
	} else {
		log.Println("WS_PROXY_URL not set - using direct handlers (no WebSocket proxy)")
	}

	// Create handlers for direct DB access (used for read operations and as fallback)
	s.authHandler = handlers.NewAuthHandler(jwtManager, cfg.APIPassword)
	s.agentHandler = handlers.NewAgentHandler(db)
	s.commandHandler = handlers.NewCommandHandler(db, nil) // agentClient set later
	s.listenerHandler = handlers.NewListenerHandler(db, listenerManager, nil, sseHub)

	payloadHandler, err := handlers.NewPayloadHandler(db, listenerManager, nil)
	if err != nil {
		return nil, err
	}
	s.payloadHandler = payloadHandler

	// Setup router
	s.setupRouter()

	return s, nil
}

func (s *Server) setupRouter() {
	// Set Gin to release mode in production
	gin.SetMode(gin.ReleaseMode)

	router := gin.New()

	// Global middleware
	router.Use(RecoveryMiddleware())
	router.Use(LoggingMiddleware())
	router.Use(CORSMiddleware(s.config.CORS.AllowedOrigins))
	router.Use(RateLimitMiddleware(s.rateLimiter))

	// Health check (no auth required)
	router.GET("/health", s.handleHealth)

	// API v1 routes
	v1 := router.Group("/api/v1")
	{
		// Auth routes (no auth required)
		authRoutes := v1.Group("/auth")
		{
			authRoutes.POST("/login", s.authHandler.Login)
			authRoutes.POST("/cert-login", s.authHandler.CertLogin) // Certificate-based login (no password)
			authRoutes.POST("/refresh", s.authHandler.Refresh)
		}

		// Protected routes
		protected := v1.Group("")
		protected.Use(AuthMiddleware(s.jwtManager))
		{
			// Auth (protected)
			protected.POST("/auth/logout", s.authHandler.Logout)
			protected.GET("/auth/me", s.authHandler.Me)

			// Agents - read operations always direct, write operations via proxy if available
			protected.GET("/agents", s.agentHandler.ListAgents)
			protected.GET("/agents/:id", s.agentHandler.GetAgent)
			if s.useWSProxy {
				// Use WebSocket proxy for agent modifications (ensures event broadcasting)
				protected.DELETE("/agents/:id", s.wsProxyHandlers.RemoveAgent)
				protected.PATCH("/agents/:id", s.wsProxyHandlers.RenameAgent)
				protected.POST("/agents/:id/tags", s.wsProxyHandlers.AddTag)
				protected.DELETE("/agents/:id/tags/:tag", s.wsProxyHandlers.RemoveTag)
			} else {
				protected.DELETE("/agents/:id", s.agentHandler.DeleteAgent)
				protected.PATCH("/agents/:id", s.agentHandler.UpdateAgent)
				protected.POST("/agents/:id/tags", s.agentHandler.AddTag)
				protected.DELETE("/agents/:id/tags/:tag", s.agentHandler.RemoveTag)
			}

			// Commands - read operations direct, send command via proxy if available
			protected.GET("/agents/:id/commands", s.commandHandler.GetCommandHistory)
			protected.GET("/agents/:id/commands/latest", s.commandHandler.GetLatestCommand)
			protected.GET("/commands/:id", s.commandHandler.GetCommand)
			protected.DELETE("/agents/:id/commands/queue", s.commandHandler.ClearQueue)
			if s.useWSProxy {
				protected.POST("/agents/:id/commands", s.wsProxyHandlers.SendAgentCommand)
			} else {
				protected.POST("/agents/:id/commands", s.commandHandler.SendCommand)
			}

			// Listeners - read operations direct, create/delete via proxy if available
			protected.GET("/listeners", s.listenerHandler.ListListeners)
			protected.GET("/listeners/:name", s.listenerHandler.GetListener)
			if s.useWSProxy {
				// Use WebSocket proxy for listener create/delete (ensures event broadcasting)
				protected.POST("/listeners", s.wsProxyHandlers.CreateListener)
				protected.DELETE("/listeners/:name", s.wsProxyHandlers.DeleteListener)
			} else {
				protected.POST("/listeners", s.listenerHandler.CreateListener)
				protected.DELETE("/listeners/:name", s.listenerHandler.DeleteListener)
			}

			// Payloads - always use proxy if available (complex build pipeline)
			if s.useWSProxy {
				protected.POST("/payloads/build", s.wsProxyHandlers.CreatePayload)
			} else {
				protected.POST("/payloads/build", s.payloadHandler.BuildPayload)
			}

			// Events (SSE)
			protected.GET("/events", sse.EventsHandler(s.sseHub))
		}
	}

	s.router = router
}

func (s *Server) handleHealth(c *gin.Context) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	wsProxyConnected := false
	if s.wsProxyClient != nil {
		wsProxyConnected = s.wsProxyClient.IsConnected()
	}

	health := gin.H{
		"status":            "healthy",
		"goroutines":        runtime.NumGoroutine(),
		"memory_mb":         m.HeapAlloc / 1024 / 1024,
		"sse_clients":       s.sseHub.ClientCount(),
		"grpc_connected":    s.agentClient != nil,
		"ws_proxy_enabled":  s.useWSProxy,
		"ws_proxy_connected": wsProxyConnected,
	}

	c.JSON(http.StatusOK, health)
}

// SetAgentClient sets the gRPC client for all handlers that need it
func (s *Server) SetAgentClient(client *agent.Client) {
	s.agentClient = client
	s.commandHandler.SetAgentClient(client)
	s.listenerHandler.SetAgentClient(client)
	s.payloadHandler.SetAgentClient(client)
}

// GetSSEHub returns the SSE hub for event broadcasting
func (s *Server) GetSSEHub() *sse.Hub {
	return s.sseHub
}

// GetListenerManager returns the listener manager
func (s *Server) GetListenerManager() *listeners.Manager {
	return s.listenerManager
}

// HandleGRPCMessage handles messages from gRPC and broadcasts to SSE clients
func (s *Server) HandleGRPCMessage(msg *pb.StreamMessage) {
	// Forward gRPC events to SSE clients
	s.sseHub.BroadcastJSON(msg.Type, msg.Content)
}

// Start starts the HTTP server
func (s *Server) Start() error {
	tlsConfig := &tls.Config{
		MinVersion:               tls.VersionTLS12,
		PreferServerCipherSuites: true,
		CurvePreferences: []tls.CurveID{
			tls.X25519,
			tls.CurveP256,
		},
	}

	s.httpServer = &http.Server{
		Addr:              s.config.ListenAddr,
		Handler:           s.router,
		TLSConfig:         tlsConfig,
		ReadTimeout:       6 * time.Minute, // Long timeout for payload builds
		WriteTimeout:      6 * time.Minute,
		IdleTimeout:       6 * time.Minute,
		MaxHeaderBytes:    1 << 20, // 1MB
		ReadHeaderTimeout: 10 * time.Second,
	}

	log.Printf("Starting REST API server on %s", s.config.ListenAddr)
	return s.httpServer.ListenAndServeTLS(s.config.TLS.CertFile, s.config.TLS.KeyFile)
}

// Shutdown gracefully shuts down the server
func (s *Server) Shutdown(ctx context.Context) error {
	log.Println("Shutting down REST API server...")

	// Stop rate limiter cleanup
	s.rateLimiter.Stop()

	// Close SSE hub
	s.sseHub.Close()

	// Clean up expired tokens
	s.jwtManager.CleanupExpiredTokens()

	// Close WebSocket proxy client
	if s.wsProxyClient != nil {
		if err := s.wsProxyClient.Close(); err != nil {
			log.Printf("WebSocket proxy close error: %v", err)
		}
	}

	// Shutdown HTTP server
	if s.httpServer != nil {
		return s.httpServer.Shutdown(ctx)
	}

	return nil
}
