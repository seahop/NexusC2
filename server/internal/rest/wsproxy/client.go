// internal/rest/wsproxy/client.go
// WebSocket proxy client - connects REST API to WebSocket service
package wsproxy

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

const (
	// Connection timeouts
	dialTimeout     = 10 * time.Second
	writeWait       = 10 * time.Second
	pongWait        = 60 * time.Second
	pingPeriod      = (pongWait * 9) / 10
	reconnectDelay  = 5 * time.Second
	maxReconnects   = 5
	maxMessageSize  = 10 * 1024 * 1024 // 10MB
)

// Message represents a WebSocket message
type Message struct {
	Type string          `json:"type"`
	Data json.RawMessage `json:"data"`
	Raw  json.RawMessage `json:"-"` // Raw message bytes for non-standard formats
}

// ResponseHandler handles responses for a specific request
type ResponseHandler struct {
	ID          string
	MessageType string
	ResponseCh  chan Message
	ErrorCh     chan error
	Done        chan struct{}
}

// BinaryTransfer collects binary chunks for payload downloads
type BinaryTransfer struct {
	FileName    string
	TotalChunks int64
	Chunks      map[int64][]byte
	Complete    bool
	Error       error
	mu          sync.Mutex
}

// Client manages WebSocket connection to the WebSocket service
type Client struct {
	wsURL    string
	username string
	conn     *websocket.Conn
	mu       sync.RWMutex

	// Response handlers keyed by message type
	handlers   map[string]*ResponseHandler
	handlersMu sync.RWMutex

	// Binary transfers keyed by filename
	transfers   map[string]*BinaryTransfer
	transfersMu sync.RWMutex

	// Global message channel for broadcasting
	messageCh chan Message

	// Connection state
	connected bool
	done      chan struct{}
	reconnect bool
}

// NewClient creates a new WebSocket proxy client
func NewClient(wsURL, username string) *Client {
	return &Client{
		wsURL:     wsURL,
		username:  username,
		handlers:  make(map[string]*ResponseHandler),
		transfers: make(map[string]*BinaryTransfer),
		messageCh: make(chan Message, 100),
		done:      make(chan struct{}),
		reconnect: true,
	}
}

// Connect establishes connection to the WebSocket service
func (c *Client) Connect(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.connected {
		return nil
	}

	header := http.Header{}
	header.Set("Username", c.username)

	// Configure TLS to accept self-signed certificates (internal communication)
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true, // Accept self-signed certs for internal service communication
	}

	dialer := websocket.Dialer{
		HandshakeTimeout: dialTimeout,
		TLSClientConfig:  tlsConfig,
	}

	conn, _, err := dialer.DialContext(ctx, c.wsURL, header)
	if err != nil {
		return fmt.Errorf("failed to connect to WebSocket service: %w", err)
	}

	c.conn = conn
	c.connected = true
	c.conn.SetReadLimit(maxMessageSize)

	// Start read pump
	go c.readPump()

	// Start ping pump
	go c.pingPump()

	log.Printf("[WSProxy] Connected to WebSocket service as %s", c.username)
	return nil
}

// Close closes the WebSocket connection
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.reconnect = false
	close(c.done)

	if c.conn != nil {
		err := c.conn.Close()
		c.conn = nil
		c.connected = false
		return err
	}
	return nil
}

// IsConnected returns the connection state
func (c *Client) IsConnected() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.connected
}

// Send sends a message to the WebSocket service
func (c *Client) Send(ctx context.Context, msg interface{}) error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if !c.connected || c.conn == nil {
		return fmt.Errorf("not connected to WebSocket service")
	}

	data, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("failed to marshal message: %w", err)
	}

	c.conn.SetWriteDeadline(time.Now().Add(writeWait))
	if err := c.conn.WriteMessage(websocket.TextMessage, data); err != nil {
		return fmt.Errorf("failed to send message: %w", err)
	}

	return nil
}

// SendAndWait sends a message and waits for a response of the expected type
func (c *Client) SendAndWait(ctx context.Context, msg interface{}, expectedType string, timeout time.Duration) (*Message, error) {
	handler := &ResponseHandler{
		MessageType: expectedType,
		ResponseCh:  make(chan Message, 1),
		ErrorCh:     make(chan error, 1),
		Done:        make(chan struct{}),
	}

	// Register handler
	c.handlersMu.Lock()
	c.handlers[expectedType] = handler
	c.handlersMu.Unlock()

	// Cleanup on exit
	defer func() {
		c.handlersMu.Lock()
		delete(c.handlers, expectedType)
		c.handlersMu.Unlock()
		close(handler.Done)
	}()

	// Send message
	if err := c.Send(ctx, msg); err != nil {
		return nil, err
	}

	// Wait for response
	select {
	case resp := <-handler.ResponseCh:
		return &resp, nil
	case err := <-handler.ErrorCh:
		return nil, err
	case <-time.After(timeout):
		return nil, fmt.Errorf("timeout waiting for response type: %s", expectedType)
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// RegisterBinaryTransfer registers a binary transfer listener for a filename
func (c *Client) RegisterBinaryTransfer(filename string) *BinaryTransfer {
	transfer := &BinaryTransfer{
		FileName: filename,
		Chunks:   make(map[int64][]byte),
	}

	c.transfersMu.Lock()
	c.transfers[filename] = transfer
	c.transfersMu.Unlock()

	return transfer
}

// UnregisterBinaryTransfer removes a binary transfer listener
func (c *Client) UnregisterBinaryTransfer(filename string) {
	c.transfersMu.Lock()
	delete(c.transfers, filename)
	c.transfersMu.Unlock()
}

// WaitForBinaryTransfer waits for a binary transfer to complete
func (c *Client) WaitForBinaryTransfer(ctx context.Context, transfer *BinaryTransfer, timeout time.Duration) ([]byte, error) {
	deadline := time.Now().Add(timeout)
	var completionTime time.Time
	maxWaitAfterComplete := 5 * time.Second // Max time to wait for stragglers after completion

	for {
		transfer.mu.Lock()
		complete := transfer.Complete
		transferErr := transfer.Error
		totalChunks := transfer.TotalChunks
		chunksReceived := int64(len(transfer.Chunks))
		transfer.mu.Unlock()

		if complete {
			if transferErr != nil {
				return nil, transferErr
			}

			// Track when we first saw completion
			if completionTime.IsZero() {
				completionTime = time.Now()
				log.Printf("[WSProxy] Transfer marked complete, have %d/%d chunks", chunksReceived, totalChunks)
			}

			// Check if we have all chunks
			if chunksReceived >= totalChunks {
				// Reassemble chunks in order (chunks are 0-indexed: 0, 1, 2, ..., totalChunks-1)
				transfer.mu.Lock()
				data := make([]byte, 0)
				for i := int64(0); i < transfer.TotalChunks; i++ {
					chunk, ok := transfer.Chunks[i]
					if !ok {
						transfer.mu.Unlock()
						// Still missing a chunk, wait a bit more
						log.Printf("[WSProxy] Missing chunk %d during reassembly (have chunks: %v), waiting...", i, getChunkIndices(transfer.Chunks))
						goto waitMore
					}
					data = append(data, chunk...)
				}
				transfer.mu.Unlock()
				log.Printf("[WSProxy] Successfully reassembled %d bytes from %d chunks", len(data), totalChunks)
				return data, nil
			}

		waitMore:
			// Wait for stragglers but don't wait forever
			if time.Since(completionTime) > maxWaitAfterComplete {
				transfer.mu.Lock()
				missing := []int64{}
				for i := int64(0); i < transfer.TotalChunks; i++ {
					if _, ok := transfer.Chunks[i]; !ok {
						missing = append(missing, i)
					}
				}
				indices := getChunkIndices(transfer.Chunks)
				transfer.mu.Unlock()
				return nil, fmt.Errorf("timeout waiting for chunks after completion, missing: %v, have indices: %v", missing, indices)
			}
		}

		if time.Now().After(deadline) {
			return nil, fmt.Errorf("timeout waiting for binary transfer")
		}

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(50 * time.Millisecond):
			// Continue polling (faster polling for chunk arrival)
		}
	}
}

// Subscribe returns a channel that receives all incoming messages
func (c *Client) Subscribe() <-chan Message {
	return c.messageCh
}

// readPump reads messages from the WebSocket connection
func (c *Client) readPump() {
	defer func() {
		c.mu.Lock()
		c.connected = false
		if c.conn != nil {
			c.conn.Close()
		}
		c.mu.Unlock()

		// Attempt reconnection if enabled
		if c.reconnect {
			go c.attemptReconnect()
		}
	}()

	c.conn.SetReadDeadline(time.Now().Add(pongWait))
	c.conn.SetPongHandler(func(string) error {
		c.conn.SetReadDeadline(time.Now().Add(pongWait))
		return nil
	})

	for {
		select {
		case <-c.done:
			return
		default:
		}

		_, message, err := c.conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("[WSProxy] Read error: %v", err)
			}
			return
		}

		// Log the raw message for debugging
		if len(message) < 500 {
			log.Printf("[WSProxy] Received raw message: %s", string(message))
		} else {
			log.Printf("[WSProxy] Received large message: %d bytes", len(message))
		}

		var msg Message
		if err := json.Unmarshal(message, &msg); err != nil {
			log.Printf("[WSProxy] Failed to unmarshal message: %v", err)
			continue
		}

		// Always preserve the raw message
		msg.Raw = message

		// If message doesn't have a type field, use raw as data
		// This handles responses like ListenerResponse that don't follow {type, data} format
		if msg.Type == "" {
			msg.Data = message
		}

		// Handle the message
		c.handleMessage(msg)
	}
}

// handleMessage processes incoming WebSocket messages
func (c *Client) handleMessage(msg Message) {
	// Check for registered handler
	c.handlersMu.RLock()
	handler, exists := c.handlers[msg.Type]
	c.handlersMu.RUnlock()

	if exists {
		select {
		case handler.ResponseCh <- msg:
		default:
			log.Printf("[WSProxy] Handler channel full for type: %s", msg.Type)
		}
	}

	// Handle binary transfer messages
	switch msg.Type {
	case "binary_transfer_start":
		c.handleBinaryTransferStart(msg)
	case "binary_chunk":
		c.handleBinaryChunk(msg)
	case "binary_transfer_complete":
		c.handleBinaryTransferComplete(msg)
	}

	// Broadcast to general subscribers
	select {
	case c.messageCh <- msg:
	default:
		// Channel full, drop message
	}
}

// handleBinaryTransferStart handles the start of a binary transfer
func (c *Client) handleBinaryTransferStart(msg Message) {
	// binary_transfer_start HAS a nested data field: {"type":"...","data":{"file_name":"...","total_chunks":...}}
	var data struct {
		FileName    string `json:"file_name"`
		TotalChunks int64  `json:"total_chunks"`
		Status      string `json:"status"`
	}

	if err := json.Unmarshal(msg.Data, &data); err != nil {
		log.Printf("[WSProxy] Failed to parse binary_transfer_start: %v", err)
		return
	}

	c.transfersMu.Lock()
	if transfer, exists := c.transfers[data.FileName]; exists {
		transfer.mu.Lock()
		transfer.TotalChunks = data.TotalChunks
		transfer.mu.Unlock()
	}
	c.transfersMu.Unlock()

	log.Printf("[WSProxy] Binary transfer started: %s (%d chunks)", data.FileName, data.TotalChunks)
}

// handleBinaryChunk handles a binary chunk message
func (c *Client) handleBinaryChunk(msg Message) {
	// Binary chunk messages are flat (not nested under "data"), so use Raw
	var data struct {
		Type        string `json:"type"`
		ChunkNum    int64  `json:"chunk_num"`
		TotalChunks int64  `json:"total_chunks"`
		FileSize    int64  `json:"file_size"`
		FileName    string `json:"file_name"`
		Data        string `json:"data"` // base64 encoded
		Priority    bool   `json:"priority"`
	}

	if err := json.Unmarshal(msg.Raw, &data); err != nil {
		log.Printf("[WSProxy] Failed to parse binary_chunk: %v", err)
		return
	}

	c.transfersMu.RLock()
	transfer, exists := c.transfers[data.FileName]
	c.transfersMu.RUnlock()

	if !exists {
		// Try to find by partial match (filename may have been registered without full path)
		c.transfersMu.RLock()
		for name, t := range c.transfers {
			if name == "" || data.FileName == name {
				transfer = t
				exists = true
				break
			}
		}
		c.transfersMu.RUnlock()
	}

	if exists {
		chunkData, err := base64.StdEncoding.DecodeString(data.Data)
		if err != nil {
			log.Printf("[WSProxy] Failed to decode chunk data: %v", err)
			return
		}

		transfer.mu.Lock()
		transfer.TotalChunks = data.TotalChunks
		transfer.Chunks[data.ChunkNum] = chunkData
		transfer.mu.Unlock()

		log.Printf("[WSProxy] Received chunk %d/%d for %s", data.ChunkNum, data.TotalChunks, data.FileName)
	}
}

// handleBinaryTransferComplete handles the completion of a binary transfer
func (c *Client) handleBinaryTransferComplete(msg Message) {
	// binary_transfer_complete HAS a nested data field: {"type":"...","data":{"file_name":"...","status":"..."}}
	var data struct {
		FileName string `json:"file_name"`
		Status   string `json:"status"`
		Message  string `json:"message,omitempty"`
	}

	if err := json.Unmarshal(msg.Data, &data); err != nil {
		log.Printf("[WSProxy] Failed to parse binary_transfer_complete: %v", err)
		return
	}

	c.transfersMu.RLock()
	transfer, exists := c.transfers[data.FileName]
	c.transfersMu.RUnlock()

	if !exists {
		// Try to find by any registered transfer
		c.transfersMu.RLock()
		for _, t := range c.transfers {
			transfer = t
			exists = true
			break
		}
		c.transfersMu.RUnlock()
	}

	if exists {
		transfer.mu.Lock()
		transfer.Complete = true
		if data.Status != "success" {
			transfer.Error = fmt.Errorf("transfer failed: %s", data.Message)
		}
		transfer.mu.Unlock()
	}

	log.Printf("[WSProxy] Binary transfer complete: %s (status: %s)", data.FileName, data.Status)
}

// pingPump sends periodic pings to keep the connection alive
func (c *Client) pingPump() {
	ticker := time.NewTicker(pingPeriod)
	defer ticker.Stop()

	for {
		select {
		case <-c.done:
			return
		case <-ticker.C:
			c.mu.RLock()
			conn := c.conn
			connected := c.connected
			c.mu.RUnlock()

			if !connected || conn == nil {
				return
			}

			conn.SetWriteDeadline(time.Now().Add(writeWait))
			if err := conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				log.Printf("[WSProxy] Ping failed: %v", err)
				return
			}
		}
	}
}

// attemptReconnect tries to reconnect to the WebSocket service
func (c *Client) attemptReconnect() {
	for i := 0; i < maxReconnects; i++ {
		select {
		case <-c.done:
			return
		case <-time.After(reconnectDelay):
		}

		log.Printf("[WSProxy] Attempting reconnection (%d/%d)", i+1, maxReconnects)

		ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
		err := c.Connect(ctx)
		cancel()

		if err == nil {
			log.Printf("[WSProxy] Reconnected successfully")
			return
		}

		log.Printf("[WSProxy] Reconnection failed: %v", err)
	}

	log.Printf("[WSProxy] Max reconnection attempts reached")
}

// getChunkIndices returns a sorted list of chunk indices for debugging
func getChunkIndices(chunks map[int64][]byte) []int64 {
	indices := make([]int64, 0, len(chunks))
	for idx := range chunks {
		indices = append(indices, idx)
	}
	// Simple sort for small lists
	for i := 0; i < len(indices)-1; i++ {
		for j := i + 1; j < len(indices); j++ {
			if indices[i] > indices[j] {
				indices[i], indices[j] = indices[j], indices[i]
			}
		}
	}
	// Only return first and last few to avoid huge logs
	if len(indices) > 10 {
		return append(indices[:5], indices[len(indices)-5:]...)
	}
	return indices
}
