// internal/websocket/hub/client.go
package hub

import (
	"c2/internal/websocket/agent"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
)

const (
	// Time allowed to write a message to the peer
	writeWait = 10 * time.Second

	// Time allowed to read the next pong message from the peer
	pongWait = 60 * time.Second

	// Send pings to peer with this period
	pingPeriod = (pongWait * 9) / 10

	// Maximum message size allowed from peer
	maxMessageSize = 10 * 1024 * 1024 // 10MB for large chunks
)

type Client struct {
	ID        string
	SessionID uuid.UUID
	Hub       *Hub
	Conn      *websocket.Conn
	Send      chan []byte
	SendHigh  chan []byte
	Username  string
}

type Message struct {
	Type string          `json:"type"`
	Data json.RawMessage `json:"data"`
}

func (c *Client) ReadPump() {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("Recovered from panic in ReadPump for client %s: %v", c.Username, r)
		}

		// Unregister the client first to stop any further communication attempts
		if c.Hub != nil {
			c.Hub.UnregisterClient(c)
		}

		// After unregistering, safely close the WebSocket connection
		if c.Conn != nil {
			c.Conn.Close()
		}
	}()

	// Configure the connection
	c.Conn.SetReadLimit(maxMessageSize)
	c.Conn.SetReadDeadline(time.Now().Add(pongWait))
	c.Conn.SetPongHandler(func(string) error {
		c.Conn.SetReadDeadline(time.Now().Add(pongWait))
		return nil
	})

	// Create a channel for message processing with buffer
	msgChan := make(chan []byte, 100)

	// Start message processing workers
	workerCount := 3 // Process up to 3 messages concurrently
	var wg sync.WaitGroup
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go c.messageWorker(msgChan, &wg)
	}

	// Main read loop
	for {
		_, message, err := c.Conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("Unexpected close error for client %s: %v", c.Username, err)
			}
			break // Exit the loop if there's an error (e.g., connection closed)
		}

		if c.Hub == nil {
			log.Printf("Hub is nil for client %s, exiting ReadPump", c.Username)
			break
		}

		// Send message to workers for processing
		select {
		case msgChan <- message:
			// Message queued for processing
		default:
			// If channel is full, process synchronously to avoid dropping messages
			log.Printf("Message channel full for client %s, processing synchronously", c.Username)
			c.processMessage(message)
		}
	}

	// Close message channel and wait for workers to finish
	close(msgChan)
	wg.Wait()
}

// messageWorker processes messages from the channel
func (c *Client) messageWorker(msgChan <-chan []byte, wg *sync.WaitGroup) {
	defer wg.Done()

	for message := range msgChan {
		c.processMessage(message)
	}
}

// processMessage handles a single message
func (c *Client) processMessage(message []byte) {
	// Log raw message if it's not too large
	if len(message) < 1000 {
		log.Printf("Raw message received from %s: %s", c.Username, string(message))
	} else {
		log.Printf("Large message received from %s: %d bytes", c.Username, len(message))
	}

	var msg Message
	if err := json.Unmarshal(message, &msg); err != nil {
		log.Printf("Error unmarshaling message from %s: %v", c.Username, err)
		return
	}

	log.Printf("Message type: %s from client: %s", msg.Type, c.Username)

	// Check if this is a chunked message that needs priority handling
	if c.isChunkedMessage(msg) {
		// Process chunked messages with higher priority
		c.processChunkedMessage(msg, message)
	} else {
		// Regular message handling
		if c.Hub.wsHandler != nil {
			if err := c.Hub.wsHandler.HandleMessage(c, msg.Type, message); err != nil {
				log.Printf("Error handling message type %s from %s: %v", msg.Type, c.Username, err)
			}
		} else {
			log.Printf("wsHandler is nil, unable to handle message from %s", c.Username)
		}
	}
}

// isChunkedMessage determines if a message is part of a chunked transfer
func (c *Client) isChunkedMessage(msg Message) bool {
	// Quick check for agent_command with chunks
	if msg.Type == "agent_command" {
		var data struct {
			TotalChunks  int `json:"totalChunks"`
			CurrentChunk int `json:"currentChunk"`
		}

		if err := json.Unmarshal(msg.Data, &data); err == nil {
			return data.TotalChunks > 1
		}
	}

	// Check for file upload chunks
	if msg.Type == "file_upload" {
		return true // File uploads are always chunked
	}

	return false
}

// processChunkedMessage handles chunked messages with priority
func (c *Client) processChunkedMessage(msg Message, fullMessage []byte) {
	log.Printf("Processing chunked message type: %s from %s", msg.Type, c.Username)

	// Process chunked messages directly without additional goroutines
	// since we're already in a worker goroutine
	if c.Hub.wsHandler != nil {
		if err := c.Hub.wsHandler.HandleMessage(c, msg.Type, fullMessage); err != nil {
			log.Printf("Error handling chunked message type %s from %s: %v",
				msg.Type, c.Username, err)
		}
	}
}

func (c *Client) WritePump() {
	ticker := time.NewTicker(pingPeriod)
	defer func() {
		ticker.Stop()
		if c.Conn != nil {
			c.Conn.Close()
		}
		log.Printf("WritePump exited for client: %s", c.Username)
	}()

	// Track active binary transfer
	var binaryTransferActive bool
	var binaryTransferTimeout <-chan time.Time

	for {
		select {
		// High priority messages (binary chunks) - MUST be first
		case message, ok := <-c.SendHigh:
			if !ok {
				c.Conn.SetWriteDeadline(time.Now().Add(writeWait))
				c.Conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			// Set binary transfer active flag
			binaryTransferActive = true
			binaryTransferTimeout = time.After(5 * time.Second) // Reset timeout

			// Use goroutine for non-blocking write
			writeDone := make(chan error, 1)
			go func() {
				c.Conn.SetWriteDeadline(time.Now().Add(writeWait * 3)) // More time for chunks
				writeDone <- c.Conn.WriteMessage(websocket.TextMessage, message)
			}()

			// Non-blocking wait for write completion
			select {
			case err := <-writeDone:
				if err != nil {
					log.Printf("Error sending high priority message to %s: %v", c.Username, err)
					return
				}
			case <-time.After(writeWait * 2):
				log.Printf("Write timeout for high priority message to %s, continuing", c.Username)
				// Don't return, just log and continue to prevent blocking other messages
			}

		// Check for binary transfer timeout
		case <-binaryTransferTimeout:
			if binaryTransferActive {
				binaryTransferActive = false
				log.Printf("Binary transfer timeout for client %s, resuming normal operations", c.Username)
			}

		// Regular messages - process only if no active binary transfer or with lower priority
		case message, ok := <-c.Send:
			if !ok {
				c.Conn.SetWriteDeadline(time.Now().Add(writeWait))
				c.Conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			// If binary transfer is active, defer regular messages
			if binaryTransferActive && len(c.SendHigh) > 0 {
				// Put message back and continue to prioritize binary chunks
				go func() {
					time.Sleep(100 * time.Millisecond)
					select {
					case c.Send <- message:
					case <-time.After(1 * time.Second):
						log.Printf("Failed to requeue regular message for %s", c.Username)
					}
				}()
				continue
			}

			// Send regular message
			c.Conn.SetWriteDeadline(time.Now().Add(writeWait))
			if err := c.Conn.WriteMessage(websocket.TextMessage, message); err != nil {
				log.Printf("Error sending message to %s: %v", c.Username, err)
				return
			}

		case <-ticker.C:
			c.Conn.SetWriteDeadline(time.Now().Add(writeWait))
			if err := c.Conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

// sendBatch sends a batch of messages efficiently
func (c *Client) sendBatch(messages [][]byte) {
	if len(messages) == 0 {
		return
	}

	c.Conn.SetWriteDeadline(time.Now().Add(writeWait))

	// For a single message, send directly
	if len(messages) == 1 {
		if err := c.Conn.WriteMessage(websocket.TextMessage, messages[0]); err != nil {
			log.Printf("Error writing message for client %s: %v", c.Username, err)
			c.Hub.UnregisterClient(c)
			return
		}
		log.Printf("Sent message to client %s", c.Username)
		return
	}

	// For multiple messages, consider combining if they're small
	// or send individually if they're large
	for _, msg := range messages {
		if err := c.Conn.WriteMessage(websocket.TextMessage, msg); err != nil {
			log.Printf("Error writing batch message for client %s: %v", c.Username, err)
			c.Hub.UnregisterClient(c)
			return
		}
	}

	log.Printf("Sent batch of %d messages to client %s", len(messages), c.Username)
}

func (h *Hub) Run() {
	for {
		select {
		case client := <-h.register:
			if err := h.RegisterClient(client); err != nil {
				log.Printf("Failed to register client: %v", err)
			}
		case client := <-h.unregister:
			h.UnregisterClient(client)
		}
	}
}

// Keep the CreateListener method as is since it's working
func (h *Hub) CreateListener(client *Client, message []byte) error {
	log.Printf("Starting listener creation process")

	if h.ListenerManager == nil {
		err := fmt.Errorf("listener manager not initialized in createListener")
		log.Printf("ERROR: %v", err)
		return err
	}

	var msg ListenerMessage
	if err := json.Unmarshal(message, &msg); err != nil {
		log.Printf("Failed to unmarshal listener message: %v", err)
		return err
	}
	log.Printf("Unmarshaled message: name=%s, protocol=%s, port=%d, host=%s, pipe_name=%s, profiles: GET=%s POST=%s Response=%s SMB=%s TCP=%s",
		msg.Data.Name, msg.Data.Protocol, msg.Data.Port, msg.Data.Host, msg.Data.PipeName,
		msg.Data.GetProfile, msg.Data.PostProfile, msg.Data.ServerResponseProfile, msg.Data.SMBProfile, msg.Data.TCPProfile)

	// Check if this is an SMB or TCP listener - handle specially (no gRPC needed)
	isSMB := msg.Data.Protocol == "SMB" || msg.Data.Protocol == "smb"
	isTCP := msg.Data.Protocol == "TCP" || msg.Data.Protocol == "tcp"
	isLinkListener := isSMB || isTCP // Link-based listeners don't need gRPC port binding

	// Only check port availability for non-link listeners (HTTP/HTTPS)
	// Use CanSharePort to allow multiple listeners on same port with matching protocol
	if !isLinkListener && !h.ListenerManager.CanSharePort(msg.Data.Port, msg.Data.Protocol) {
		log.Printf("Port %d cannot be used for %s listener", msg.Data.Port, msg.Data.Protocol)
		response := ListenerResponse{
			Status:  "error",
			Message: fmt.Sprintf("Port %d is not available for %s listener", msg.Data.Port, msg.Data.Protocol),
		}
		responseJSON, _ := json.Marshal(response)
		client.Send <- responseJSON
		return fmt.Errorf("port %d is not available for %s listener", msg.Data.Port, msg.Data.Protocol)
	}

	// Use CreateWithProfiles to support profile bindings
	l, err := h.ListenerManager.CreateWithProfiles(
		msg.Data.Name,
		msg.Data.Protocol,
		msg.Data.Port,
		msg.Data.Host,
		msg.Data.PipeName,
		msg.Data.GetProfile,
		msg.Data.PostProfile,
		msg.Data.ServerResponseProfile,
		msg.Data.SMBProfile,
		msg.Data.TCPProfile,
	)
	if err != nil {
		log.Printf("Listener creation failed: %v", err)
		response := ListenerResponse{
			Status:  "error",
			Message: err.Error(),
		}
		responseJSON, _ := json.Marshal(response)
		client.Send <- responseJSON
		return err
	}

	log.Printf("Listener created successfully with ID: %s", l.ID)
	h.ListenerManager.DumpState()

	// Skip gRPC for link-based listeners (SMB/TCP) - they don't need to bind a port
	if !isLinkListener {
		// Use host.docker.internal for agent-handler running on host network
		// Falls back to localhost for local development
		grpcAddress := os.Getenv("GRPC_ADDRESS")
		if grpcAddress == "" {
			grpcAddress = "localhost:50051"
		}

		clientID := "websocket_hub"
		agentClient, err := agent.NewClient(grpcAddress, clientID)
		if err != nil {
			log.Printf("Failed to create agent gRPC client: %v", err)
			return err
		}
		defer agentClient.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		listenerType := agentClient.GetListenerType(msg.Data.Protocol)
		resp, err := agentClient.StartListener(ctx, msg.Data.Name, int32(msg.Data.Port), listenerType, false,
			msg.Data.GetProfile, msg.Data.PostProfile, msg.Data.ServerResponseProfile)
		if err != nil {
			log.Printf("gRPC StartListener failed: %v", err)
			response := ListenerResponse{
				Status:  "error",
				Message: fmt.Sprintf("Failed to start listener via agent service: %v", err),
			}
			responseJSON, _ := json.Marshal(response)
			client.Send <- responseJSON
			return err
		}

		if !resp.Success {
			log.Printf("gRPC StartListener returned failure: %s", resp.Message)
			response := ListenerResponse{
				Status:  "error",
				Message: resp.Message,
			}
			responseJSON, _ := json.Marshal(response)
			client.Send <- responseJSON
			return fmt.Errorf("agent service failed to start listener: %s", resp.Message)
		}

		log.Printf("gRPC StartListener succeeded for listener: %s", msg.Data.Name)
	} else {
		if isSMB {
			log.Printf("SMB listener created - no gRPC call needed (pipe: %s)", l.PipeName)
		} else if isTCP {
			log.Printf("TCP listener created - no gRPC call needed (port: %d)", l.Port)
		}
	}

	// Create broadcast message
	broadcastMsg := struct {
		Type string `json:"type"`
		Data struct {
			Event    string `json:"event"`
			Listener struct {
				ID                    string `json:"id"`
				Name                  string `json:"name"`
				Protocol              string `json:"protocol"`
				Port                  int    `json:"port"`
				IP                    string `json:"ip"`
				PipeName              string `json:"pipe_name,omitempty"`
				GetProfile            string `json:"get_profile,omitempty"`
				PostProfile           string `json:"post_profile,omitempty"`
				ServerResponseProfile string `json:"server_response_profile,omitempty"`
				SMBProfile            string `json:"smb_profile,omitempty"`
				TCPProfile            string `json:"tcp_profile,omitempty"`
			} `json:"listener"`
		} `json:"data"`
	}{
		Type: "listener_update",
		Data: struct {
			Event    string `json:"event"`
			Listener struct {
				ID                    string `json:"id"`
				Name                  string `json:"name"`
				Protocol              string `json:"protocol"`
				Port                  int    `json:"port"`
				IP                    string `json:"ip"`
				PipeName              string `json:"pipe_name,omitempty"`
				GetProfile            string `json:"get_profile,omitempty"`
				PostProfile           string `json:"post_profile,omitempty"`
				ServerResponseProfile string `json:"server_response_profile,omitempty"`
				SMBProfile            string `json:"smb_profile,omitempty"`
				TCPProfile            string `json:"tcp_profile,omitempty"`
			} `json:"listener"`
		}{
			Event: "created",
			Listener: struct {
				ID                    string `json:"id"`
				Name                  string `json:"name"`
				Protocol              string `json:"protocol"`
				Port                  int    `json:"port"`
				IP                    string `json:"ip"`
				PipeName              string `json:"pipe_name,omitempty"`
				GetProfile            string `json:"get_profile,omitempty"`
				PostProfile           string `json:"post_profile,omitempty"`
				ServerResponseProfile string `json:"server_response_profile,omitempty"`
				SMBProfile            string `json:"smb_profile,omitempty"`
				TCPProfile            string `json:"tcp_profile,omitempty"`
			}{
				ID:                    l.ID.String(),
				Name:                  l.Name,
				Protocol:              l.Protocol,
				Port:                  l.Port,
				IP:                    l.IP,
				PipeName:              l.PipeName,
				GetProfile:            l.GetProfile,
				PostProfile:           l.PostProfile,
				ServerResponseProfile: l.ServerResponseProfile,
				SMBProfile:            l.SMBProfile,
				TCPProfile:            l.TCPProfile,
			},
		},
	}

	broadcastJSON, _ := json.Marshal(broadcastMsg)
	log.Printf("Broadcasting listener creation to all clients")
	ctx := context.Background()
	if err := h.BroadcastToAll(ctx, broadcastJSON); err != nil {
		log.Printf("Error broadcasting listener creation: %v", err)
	}

	// Send success response to original client
	response := struct {
		Status  string `json:"status"`
		Message string `json:"message"`
		Data    struct {
			ID                    string `json:"id"`
			Name                  string `json:"name"`
			Protocol              string `json:"protocol"`
			Port                  string `json:"port"`
			IP                    string `json:"ip"`
			PipeName              string `json:"pipe_name,omitempty"`
			GetProfile            string `json:"get_profile,omitempty"`
			PostProfile           string `json:"post_profile,omitempty"`
			ServerResponseProfile string `json:"server_response_profile,omitempty"`
			SMBProfile            string `json:"smb_profile,omitempty"`
			TCPProfile            string `json:"tcp_profile,omitempty"`
		} `json:"data,omitempty"`
	}{
		Status:  "success",
		Message: "Listener created successfully",
		Data: struct {
			ID                    string `json:"id"`
			Name                  string `json:"name"`
			Protocol              string `json:"protocol"`
			Port                  string `json:"port"`
			IP                    string `json:"ip"`
			PipeName              string `json:"pipe_name,omitempty"`
			GetProfile            string `json:"get_profile,omitempty"`
			PostProfile           string `json:"post_profile,omitempty"`
			ServerResponseProfile string `json:"server_response_profile,omitempty"`
			SMBProfile            string `json:"smb_profile,omitempty"`
			TCPProfile            string `json:"tcp_profile,omitempty"`
		}{
			ID:                    l.ID.String(),
			Name:                  l.Name,
			Protocol:              l.Protocol,
			Port:                  fmt.Sprintf("%d", l.Port),
			IP:                    l.IP,
			PipeName:              l.PipeName,
			GetProfile:            l.GetProfile,
			PostProfile:           l.PostProfile,
			ServerResponseProfile: l.ServerResponseProfile,
			SMBProfile:            l.SMBProfile,
			TCPProfile:            l.TCPProfile,
		},
	}

	responseJSON, _ := json.Marshal(response)
	log.Printf("Sending success response to client")
	client.Send <- responseJSON
	return nil
}
