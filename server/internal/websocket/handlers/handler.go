// internal/websocket/handlers/handler.go
package handlers

import (
	"c2/internal/websocket/agent"
	"c2/internal/websocket/hub"
	"c2/internal/websocket/reconnect"
	pb "c2/proto"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// WSHandler handles WebSocket connections and messages
type WSHandler struct {
	hub           *hub.Hub
	db            *sql.DB
	agentClient   *agent.Client // Persistent gRPC client
	mu            sync.Mutex
	activeUploads sync.Map
	// Worker pool for processing large messages
	resultWorkers chan messageJob
	workerWg      sync.WaitGroup
	// Stream manager for auto-reconnection
	streamManager *reconnect.StreamManager
}

// NewWSHandler creates a new WebSocket handler
func NewWSHandler(h *hub.Hub, db *sql.DB, agentClient *agent.Client) (*WSHandler, error) {
	handler := &WSHandler{
		hub:           h,
		db:            db,
		agentClient:   agentClient,
		resultWorkers: make(chan messageJob, 100), // Buffer up to 100 jobs
	}

	// Start worker pool for processing large messages
	workerCount := 5 // 5 workers to process messages
	for i := 0; i < workerCount; i++ {
		handler.workerWg.Add(1)
		go handler.messageWorker()
	}

	// If no agent client provided, we'll rely on the stream manager
	if agentClient == nil {
		log.Println("No initial agent client provided, will be set by stream manager")
	} else {
		// Ensure gRPC connection
		log.Println("Ensuring gRPC connection before starting listeners...")
		if err := handler.ensureGRPCConnection(); err != nil {
			return nil, fmt.Errorf("failed to establish gRPC connection: %v", err)
		}
	}

	// Start existing listeners from the database
	log.Println("Starting existing listeners...")
	if err := handler.StartExistingListeners(); err != nil {
		log.Printf("Failed to start existing listeners: %v", err)
	}

	return handler, nil
}

// SetStreamManager sets the stream manager for auto-reconnection
func (h *WSHandler) SetStreamManager(sm *reconnect.StreamManager) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.streamManager = sm
}

// GetAgentClient returns the current agent client, checking stream manager first
func (h *WSHandler) GetAgentClient() (*agent.Client, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	// If we have a stream manager, use it
	if h.streamManager != nil {
		client, err := h.streamManager.GetClient()
		if err != nil {
			return nil, fmt.Errorf("no gRPC connection available: %v", err)
		}
		// Update our local reference
		h.agentClient = client
		return client, nil
	}

	// Fall back to direct client
	if h.agentClient == nil {
		return nil, fmt.Errorf("no gRPC client available")
	}

	return h.agentClient, nil
}

// SetAgentClient sets the agent client
func (h *WSHandler) SetAgentClient(client *agent.Client) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.agentClient = client
}

// HandleWebSocket handles incoming WebSocket connections
func (h *WSHandler) HandleWebSocket(w http.ResponseWriter, r *http.Request) {
	log.Println("Received WebSocket connection request")

	username := r.Header.Get("Username")
	if username == "" {
		log.Println("Connection rejected: Missing username")
		http.Error(w, "Username required", http.StatusBadRequest)
		return
	}

	if h.hub.IsUsernameActive(username) {
		logMessage(LOG_NORMAL, "Connection rejected: Username '%s' already in use", username)
		http.Error(w, "Username already in use", http.StatusConflict)
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		logMessage(LOG_NORMAL, "Connection failed: Unable to upgrade connection: %v", err)
		return
	}

	// Set message size limits on the connection
	conn.SetReadLimit(1024 * 1024 * 4)

	client := &hub.Client{
		ID:       generateID(),
		Hub:      h.hub,
		Send:     make(chan []byte, 100),
		SendHigh: make(chan []byte, 200),
		Username: username,
		Conn:     conn,
	}

	if err := h.hub.RegisterClient(client); err != nil {
		logMessage(LOG_NORMAL, "Connection failed: Unable to register client: %v", err)
		conn.WriteMessage(websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseInternalServerErr, err.Error()))
		conn.Close()
		return
	}

	logMessage(LOG_MINIMAL, "Client %s (%s) connected successfully", client.Username, client.ID)

	// Create context with timeout for state export
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Export and send initial state
	state, err := h.exportState(ctx)
	if err != nil {
		logMessage(LOG_NORMAL, "Failed to export state: %v", err)
	} else {
		stateMsg := struct {
			Type string      `json:"type"`
			Data StateExport `json:"data"`
		}{
			Type: "initial_state",
			Data: *state,
		}

		stateJSON, err := json.Marshal(stateMsg)
		if err != nil {
			logMessage(LOG_NORMAL, "Failed to marshal state message: %v", err)
		} else {
			client.Send <- stateJSON
		}
	}

	// Start the pumps FIRST
	go client.WritePump()
	go client.ReadPump()

	// Send welcome message
	welcomeMessage := struct {
		Type    string `json:"type"`
		Message string `json:"message"`
	}{
		Type:    "welcome",
		Message: fmt.Sprintf("Welcome %s! Connected successfully.", username),
	}

	welcomeJSON, err := json.Marshal(welcomeMessage)
	if err != nil {
		logMessage(LOG_NORMAL, "Failed to marshal welcome message: %v", err)
		return
	}
	client.Send <- welcomeJSON

	// Small delay to ensure client is ready
	time.Sleep(100 * time.Millisecond)

	// Export and send initial state AFTER welcome
	ctx, cancel = context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	state, err = h.exportState(ctx)
	if err != nil {
		logMessage(LOG_NORMAL, "Failed to export state: %v", err)
	} else {
		stateMsg := struct {
			Type string      `json:"type"`
			Data StateExport `json:"data"`
		}{
			Type: "initial_state",
			Data: *state,
		}

		stateJSON, err := json.Marshal(stateMsg)
		if err != nil {
			logMessage(LOG_NORMAL, "Failed to marshal state message: %v", err)
		} else {
			logMessage(LOG_MINIMAL, "Sending initial state to client %s", client.Username)
			client.Send <- stateJSON
		}
	}

	// Check and notify about gRPC connection status
	if h.streamManager != nil && !h.streamManager.IsConnected() {
		statusMsg := struct {
			Type string `json:"type"`
			Data struct {
				Status  string `json:"status"`
				Message string `json:"message"`
			} `json:"data"`
		}{
			Type: "system",
			Data: struct {
				Status  string `json:"status"`
				Message string `json:"message"`
			}{
				Status:  "degraded",
				Message: "Agent service connection is being established...",
			},
		}

		if statusJSON, err := json.Marshal(statusMsg); err == nil {
			client.Send <- statusJSON
		}
	}
}

// HandleMessage processes incoming WebSocket messages
func (h *WSHandler) HandleMessage(client *hub.Client, msgType string, message []byte) error {
	logMessage(LOG_VERBOSE, "Handler processing message type: %s", msgType)

	// For commands that require gRPC, check connection first
	switch msgType {
	case "agent_command":
		logMessage(LOG_VERBOSE, "Processing agent_command message")
		// Check gRPC connection
		if _, err := h.GetAgentClient(); err != nil {
			return h.handleOfflineMessage(client, msgType, err)
		}
		return h.handleAgentCommand(client, message)

	case "create_listener":
		logMessage(LOG_VERBOSE, "Processing create_listener message")
		// Check gRPC connection
		if _, err := h.GetAgentClient(); err != nil {
			return h.handleOfflineMessage(client, msgType, err)
		}
		return h.hub.CreateListener(client, message)

	case "delete_listener":
		logMessage(LOG_VERBOSE, "Processing delete_listener message")
		// Check gRPC connection
		if _, err := h.GetAgentClient(); err != nil {
			return h.handleOfflineMessage(client, msgType, err)
		}
		return h.handleDeleteListener(client, message)

	case "create_payload":
		logMessage(LOG_VERBOSE, "Processing create_payload message")
		return h.handleCreatePayload(client, message)

	case "request_downloads":
		logMessage(LOG_VERBOSE, "Processing request_downloads message")
		return h.handleDownloadsRequest(client)

	case "request_file_download":
		logMessage(LOG_VERBOSE, "Processing request_file_download message")
		return h.handleFileDownload(client, message)

	case "file_upload":
		logMessage(LOG_VERBOSE, "Processing file_upload message")
		return h.handleFileUpload(client, message)

	case "socks":
		// Check gRPC connection
		if _, err := h.GetAgentClient(); err != nil {
			return h.handleOfflineMessage(client, msgType, err)
		}
		return h.handleSocksCommand(client, message)

	case "remove_agent":
		return h.handleRemoveAgent(client, message)

	case "rename_agent":
		logMessage(LOG_VERBOSE, "Processing rename_agent message")
		return h.handleRenameAgent(client, message)

	default:
		logMessage(LOG_NORMAL, "Unknown message type: %s", msgType)
		return nil
	}
}

// handleOfflineMessage handles messages when gRPC is unavailable
func (h *WSHandler) handleOfflineMessage(client *hub.Client, msgType string, err error) error {
	logMessage(LOG_NORMAL, "Cannot process %s: gRPC unavailable: %v", msgType, err)

	response := struct {
		Type string `json:"type"`
		Data struct {
			Error   string `json:"error"`
			Details string `json:"details"`
			MsgType string `json:"msg_type"`
		} `json:"data"`
	}{
		Type: "error",
		Data: struct {
			Error   string `json:"error"`
			Details string `json:"details"`
			MsgType string `json:"msg_type"`
		}{
			Error:   "Service temporarily unavailable",
			Details: "Agent service connection is being restored. Please try again in a few moments.",
			MsgType: msgType,
		},
	}

	responseJSON, _ := json.Marshal(response)
	client.Send <- responseJSON

	return nil
}

// HandleGRPCMessage handles messages from the gRPC agent service
func (h *WSHandler) HandleGRPCMessage(msg *pb.StreamMessage) {
	contentSize := len(msg.Content)

	// Log minimal info about the message
	logMessage(LOG_MINIMAL, "Received gRPC message: Type=%s, Size=%d bytes", msg.Type, contentSize)

	// For ALL messages, check size and use worker pool for large ones
	const largeMessageThreshold = 10240 // 10KB

	if contentSize > largeMessageThreshold {
		// Queue large messages to workers
		select {
		case h.resultWorkers <- messageJob{content: msg.Content, msgType: msg.Type}:
			logMessage(LOG_MINIMAL, "Queued large %s message (%d bytes) to workers",
				msg.Type, contentSize)
		default:
			// Queue is full, try with short timeout
			select {
			case h.resultWorkers <- messageJob{content: msg.Content, msgType: msg.Type}:
				logMessage(LOG_MINIMAL, "Queued large %s message after retry", msg.Type)
			case <-time.After(100 * time.Millisecond):
				logMessage(LOG_NORMAL, "WARNING: Worker queue full, dropping %s message (%d bytes)",
					msg.Type, contentSize)
			}
		}
		return
	}

	// For small messages, process directly but still use the job structure
	// This ensures consistent processing regardless of size
	h.processMessageJob(messageJob{
		content: msg.Content,
		msgType: msg.Type,
	})
}

// Close closes the handler and cleans up resources
func (h *WSHandler) Close() {
	// Close the worker channel
	if h.resultWorkers != nil {
		close(h.resultWorkers)
		// Wait for workers to finish
		h.workerWg.Wait()
	}

	// Stop the stream manager if it exists
	if h.streamManager != nil {
		h.streamManager.Stop()
	}

	// Close the gRPC client when shutting down
	if h.agentClient != nil {
		h.agentClient.Close()
		log.Println("gRPC client connection closed")
	}
}
