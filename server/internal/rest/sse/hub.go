// internal/rest/sse/hub.go
package sse

import (
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// Event represents an SSE event
type Event struct {
	Type string      `json:"type"`
	Data interface{} `json:"data"`
}

// Client represents a connected SSE client
type Client struct {
	ID       string
	Username string
	Events   chan Event
	Done     chan struct{}
}

// Hub manages SSE client connections
type Hub struct {
	clients    map[*Client]bool
	register   chan *Client
	unregister chan *Client
	broadcast  chan Event
	mu         sync.RWMutex
	closed     bool
}

// NewHub creates a new SSE hub
func NewHub() *Hub {
	hub := &Hub{
		clients:    make(map[*Client]bool),
		register:   make(chan *Client, 10),
		unregister: make(chan *Client, 10),
		broadcast:  make(chan Event, 100),
	}
	go hub.run()
	return hub
}

func (h *Hub) run() {
	for {
		select {
		case client := <-h.register:
			h.mu.Lock()
			h.clients[client] = true
			h.mu.Unlock()
			log.Printf("[SSE] Client connected: %s (%s)", client.ID, client.Username)

		case client := <-h.unregister:
			h.mu.Lock()
			if _, ok := h.clients[client]; ok {
				delete(h.clients, client)
				close(client.Events)
			}
			h.mu.Unlock()
			log.Printf("[SSE] Client disconnected: %s (%s)", client.ID, client.Username)

		case event := <-h.broadcast:
			h.mu.RLock()
			for client := range h.clients {
				select {
				case client.Events <- event:
				default:
					// Client's channel is full, skip
					log.Printf("[SSE] Dropped event for slow client: %s", client.ID)
				}
			}
			h.mu.RUnlock()
		}
	}
}

// Register adds a new client to the hub
func (h *Hub) Register(client *Client) {
	h.register <- client
}

// Unregister removes a client from the hub
func (h *Hub) Unregister(client *Client) {
	h.unregister <- client
}

// Broadcast sends an event to all connected clients
func (h *Hub) Broadcast(eventType string, data interface{}) {
	event := Event{
		Type: eventType,
		Data: data,
	}

	select {
	case h.broadcast <- event:
	default:
		log.Println("[SSE] Broadcast channel full, dropping event")
	}
}

// BroadcastJSON sends a JSON string as an event
func (h *Hub) BroadcastJSON(eventType string, jsonData string) {
	var data interface{}
	if err := json.Unmarshal([]byte(jsonData), &data); err != nil {
		data = jsonData // Use raw string if not valid JSON
	}
	h.Broadcast(eventType, data)
}

// ClientCount returns the number of connected clients
func (h *Hub) ClientCount() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.clients)
}

// Close shuts down the hub
func (h *Hub) Close() {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.closed {
		return
	}
	h.closed = true

	for client := range h.clients {
		close(client.Done)
		delete(h.clients, client)
	}
}

// EventsHandler handles SSE connections
// GET /api/v1/events
func EventsHandler(hub *Hub) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get user info from auth context
		userID, _ := c.Get("user_id")
		username, _ := c.Get("username")

		userIDStr, _ := userID.(string)
		usernameStr, _ := username.(string)
		if usernameStr == "" {
			usernameStr = "anonymous"
		}

		// Create client
		client := &Client{
			ID:       fmt.Sprintf("%s-%d", userIDStr, time.Now().UnixNano()),
			Username: usernameStr,
			Events:   make(chan Event, 50),
			Done:     make(chan struct{}),
		}

		// Register client
		hub.Register(client)
		defer hub.Unregister(client)

		// Set SSE headers
		c.Header("Content-Type", "text/event-stream")
		c.Header("Cache-Control", "no-cache")
		c.Header("Connection", "keep-alive")
		c.Header("Transfer-Encoding", "chunked")
		c.Header("X-Accel-Buffering", "no") // Disable nginx buffering

		// Send initial connection event
		c.SSEvent("connected", gin.H{
			"message":   "Connected to event stream",
			"client_id": client.ID,
		})
		c.Writer.Flush()

		// Heartbeat ticker
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()

		// Event loop
		for {
			select {
			case event := <-client.Events:
				data, err := json.Marshal(event.Data)
				if err != nil {
					continue
				}
				c.SSEvent(event.Type, string(data))
				c.Writer.Flush()

			case <-ticker.C:
				c.SSEvent("heartbeat", gin.H{"timestamp": time.Now().Unix()})
				c.Writer.Flush()

			case <-client.Done:
				return

			case <-c.Request.Context().Done():
				return
			}
		}
	}
}
