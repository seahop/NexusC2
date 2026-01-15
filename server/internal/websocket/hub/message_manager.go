// internal/websocket/hub/mesage_manager.go
package hub

import (
	"context"
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
		// Message queued successfully
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(5 * time.Second):
		log.Printf("[WARN] SendMessage: Queue full, message dropped")
		return ErrQueueFull
	}

	// Wait for message to be processed or context cancellation
	select {
	case err := <-errChan:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (mm *MessageManager) processQueue() {
	for msg := range mm.messageQueue {
		// Check context before processing
		if msg.ctx.Err() != nil {
			msg.errChan <- msg.ctx.Err()
			continue
		}

		var err error
		if msg.Target != nil {
			err = mm.sendToClient(msg.Target, msg.Data)
		} else {
			err = mm.broadcast(msg.Data)
		}

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
	// Copy client list under lock, then iterate without lock to reduce contention
	mm.mu.RLock()
	clientCount := len(mm.clients)
	if clientCount == 0 {
		mm.mu.RUnlock()
		log.Printf("[WARN] broadcast: No clients registered to receive broadcast")
		return nil
	}

	// Create a snapshot of clients to send to
	clientSnapshot := make([]*Client, 0, clientCount)
	for client := range mm.clients {
		clientSnapshot = append(clientSnapshot, client)
	}
	mm.mu.RUnlock()

	// Now broadcast without holding the lock
	var failed int
	for _, client := range clientSnapshot {
		if client.Send == nil {
			log.Printf("[ERROR] broadcast: Client %s has nil Send channel", client.Username)
			failed++
			continue
		}

		select {
		case client.Send <- data:
			// Sent successfully
		default:
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

// RegisterClient adds a client to the manager
func (mm *MessageManager) RegisterClient(client *Client) {
	mm.mu.Lock()
	defer mm.mu.Unlock()

	if client == nil {
		log.Printf("[ERROR] RegisterClient: Attempted to register nil client")
		return
	}

	mm.clients[client] = true
}

// UnregisterClient removes a client from the manager
func (mm *MessageManager) UnregisterClient(client *Client) {
	mm.mu.Lock()
	defer mm.mu.Unlock()
	delete(mm.clients, client)
}
