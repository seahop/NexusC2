// internal/websocket/hub/mesage_manager.go
package hub

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"sync"
	"time"
)

// MessageManager handles all outbound messages to ensure sequential sending
type MessageManager struct {
	messageQueue chan *OutboundMessage
	clients      map[*Client]bool
	mu           sync.RWMutex
	bufferSize   int
}

type OutboundMessage struct {
	Target  *Client // nil for broadcast
	Data    []byte
	ctx     context.Context
	errChan chan error
}

var (
	ErrClientNotFound   = errors.New("client not found")
	ErrQueueFull        = errors.New("message queue is full")
	ErrClientBufferFull = errors.New("client buffer is full")
	ErrPartialBroadcast = errors.New("partial broadcast failure")
)

func NewMessageManager(bufferSize int) *MessageManager {
	if bufferSize <= 0 {
		bufferSize = 1000 // default buffer size
	}

	mm := &MessageManager{
		messageQueue: make(chan *OutboundMessage, bufferSize),
		clients:      make(map[*Client]bool),
		bufferSize:   bufferSize,
	}

	go mm.processQueue()
	return mm
}

func (mm *MessageManager) SendMessage(ctx context.Context, target *Client, data []byte) error {
	//log.Printf("[DEBUG] SendMessage: Starting with target=%v, data length=%d", target != nil, len(data))

	errChan := make(chan error, 1)
	msg := &OutboundMessage{
		Target:  target,
		Data:    data,
		ctx:     ctx,
		errChan: errChan,
	}

	//log.Printf("[DEBUG] SendMessage: Created OutboundMessage, attempting to queue")

	// Try to queue the message with context timeout
	select {
	case mm.messageQueue <- msg:
		log.Printf("[DEBUG] SendMessage: Message queued successfully")
	case <-ctx.Done():
		log.Printf("[DEBUG] SendMessage: Context cancelled while queueing")
		return ctx.Err()
	case <-time.After(5 * time.Second):
		log.Printf("[DEBUG] SendMessage: Timeout while queueing message")
		return ErrQueueFull
	}

	//log.Printf("[DEBUG] SendMessage: Waiting for processing result")
	// Wait for message to be processed or context cancellation
	select {
	case err := <-errChan:
		log.Printf("[DEBUG] SendMessage: Received processing result: %v", err)
		return err
	case <-ctx.Done():
		log.Printf("[DEBUG] SendMessage: Context cancelled while waiting for result")
		return ctx.Err()
	}
}

func (mm *MessageManager) processQueue() {
	//log.Printf("[DEBUG] Message manager starting process queue")
	for msg := range mm.messageQueue {
		//log.Printf("[DEBUG] Processing queued message (target: %v)", msg.Target != nil)

		// Check context before processing
		if msg.ctx.Err() != nil {
			log.Printf("[DEBUG] Message context cancelled")
			msg.errChan <- msg.ctx.Err()
			continue
		}

		var err error
		if msg.Target != nil {
			// Single client message
			log.Printf("[DEBUG] Sending to single client")
			err = mm.sendToClient(msg.Target, msg.Data)
		} else {
			// Broadcast message
			log.Printf("[DEBUG] Broadcasting to all clients")
			err = mm.broadcast(msg.Data)
		}

		// Report back the result
		//log.Printf("[DEBUG] Message processing complete, err: %v", err)
		msg.errChan <- err
	}
}

func (mm *MessageManager) sendToClient(client *Client, data []byte) error {
	mm.mu.RLock()
	defer mm.mu.RUnlock()

	if !mm.clients[client] {
		return ErrClientNotFound
	}

	select {
	case client.Send <- data:
		return nil
	default:
		// If client's buffer is full, handle gracefully
		return ErrClientBufferFull
	}
}

func (mm *MessageManager) broadcast(data []byte) error {
	mm.mu.RLock()
	clientCount := len(mm.clients)
	mm.mu.RUnlock()

	//log.Printf("[DEBUG] broadcast: Starting broadcast to %d clients", clientCount)

	// Debug print current clients
	mm.mu.RLock()
	for client := range mm.clients {
		log.Printf("[DEBUG] broadcast: Registered client: ID=%s, Username=%s",
			client.ID, client.Username)
	}
	mm.mu.RUnlock()

	if clientCount == 0 {
		log.Printf("[WARN] broadcast: No clients registered to receive broadcast")
		return nil // Or return an error if you prefer
	}

	var msgData map[string]interface{}
	if err := json.Unmarshal(data, &msgData); err != nil {
		log.Printf("[DEBUG] broadcast: Failed to unmarshal message for debug: %v", err)
	} else {
		log.Printf("[DEBUG] broadcast: Broadcasting message type: %v", msgData["type"])
	}

	mm.mu.RLock()
	defer mm.mu.RUnlock()

	var failed int
	for client := range mm.clients {
		log.Printf("[DEBUG] broadcast: Attempting send to client: %s (ID: %s)",
			client.Username, client.ID)

		if client.Send == nil {
			log.Printf("[ERROR] broadcast: Client %s has nil Send channel", client.Username)
			failed++
			continue
		}

		select {
		case client.Send <- data:
			log.Printf("[DEBUG] broadcast: Successfully sent to client: %s", client.Username)
		default:
			log.Printf("[DEBUG] broadcast: Failed to send to client: %s (buffer full)",
				client.Username)
			failed++
		}
	}

	if failed > 0 {
		log.Printf("[WARN] broadcast: Partial broadcast failure - %d/%d clients failed",
			failed, clientCount)
		return ErrPartialBroadcast
	}

	//log.Printf("[SUCCESS] broadcast: Successfully sent to all %d clients", clientCount)
	return nil
}

// Add logging to client registration
func (mm *MessageManager) RegisterClient(client *Client) {
	mm.mu.Lock()
	defer mm.mu.Unlock()

	if client == nil {
		log.Printf("[ERROR] RegisterClient: Attempted to register nil client")
		return
	}

	log.Printf("[DEBUG] RegisterClient: Registering client ID=%s, Username=%s",
		client.ID, client.Username)
	mm.clients[client] = true
	log.Printf("[DEBUG] RegisterClient: Total clients after registration: %d",
		len(mm.clients))
}

// UnregisterClient removes a client from the manager
func (mm *MessageManager) UnregisterClient(client *Client) {
	mm.mu.Lock()
	defer mm.mu.Unlock()
	delete(mm.clients, client)
}
