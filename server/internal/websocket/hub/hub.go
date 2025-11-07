// internal/websocket/hub/hub.go
package hub

import (
	"c2/internal/websocket/listeners"
	pb "c2/proto"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/google/uuid"
)

type ListenerMessage struct {
	Type string `json:"type"`
	Data struct {
		Name     string `json:"name"`
		Protocol string `json:"protocol"`
		Port     int    `json:"port"`
		Host     string `json:"host"`
	} `json:"data"`
}

type ListenerResponse struct {
	Status  string `json:"status"`
	Message string `json:"message"`
	Data    struct {
		ID       string `json:"id"`
		Name     string `json:"name"`
		Protocol string `json:"protocol"`
		Port     string `json:"port"`
		IP       string `json:"ip"`
	} `json:"data,omitempty"`
}

type Hub struct {
	messageManager  *MessageManager
	register        chan *Client
	unregister      chan *Client
	clients         map[*Client]bool
	clientsByUser   map[string][]*Client
	activeUsers     map[string]bool
	db              *sql.DB
	mu              sync.RWMutex
	ListenerManager *listeners.Manager
	wsHandler       interface {
		HandleMessage(*Client, string, []byte) error
	} // Interface for handler
	ackCallbacks      map[int64]func()
	activeConnections *ActiveConnectionManager
	preparedStmts     struct {
		recordSession *sql.Stmt
		recordLogout  *sql.Stmt
	}
}

type ClientInfo struct {
	ID       string
	Username string
}

// And add the setter
func (h *Hub) SetWSHandler(handler interface {
	HandleMessage(*Client, string, []byte) error
}) {
	h.wsHandler = handler
}

func NewHub(db *sql.DB) *Hub {
	// Add debug logging
	log.Println("Initializing new Hub...")

	h := &Hub{
		messageManager:    NewMessageManager(1000),
		register:          make(chan *Client),
		unregister:        make(chan *Client),
		clients:           make(map[*Client]bool),
		clientsByUser:     make(map[string][]*Client),
		activeUsers:       make(map[string]bool),
		db:                db,
		ackCallbacks:      make(map[int64]func()),
		activeConnections: NewActiveConnectionManager(),
	}

	if err := h.initPreparedStatements(); err != nil {
		log.Printf("Warning: Failed to initialize prepared statements: %v", err)
		// Continue anyway - the recordSession and recordLogout methods will need to fall back to direct queries
	}

	// Initialize ListenerManager
	log.Println("Initializing ListenerManager...")
	h.ListenerManager = listeners.NewManager(db)
	log.Println("ListenerManager initialized successfully")

	return h
}

// New method to register acknowledgment callbacks
func (h *Hub) OnAck(chunkNum int64, callback func()) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.ackCallbacks[chunkNum] = callback
}

// Method to handle acknowledgment messages
func (h *Hub) HandleAck(chunkNum int64) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if callback, exists := h.ackCallbacks[chunkNum]; exists {
		go callback()                    // Call the registered callback
		delete(h.ackCallbacks, chunkNum) // Remove the callback after it's called
	}
}

func (h *Hub) IsUsernameActive(username string) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	isActive := h.activeUsers[username]
	log.Printf("Checking if username '%s' is active: %v", username, isActive)
	return isActive
}

func (h *Hub) RegisterClient(client *Client) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	log.Printf("Starting registration for client username: %s, ID: %s", client.Username, client.ID)
	log.Printf("Current state - Active users: %v, Total clients: %d", h.activeUsers, len(h.clients))

	if h.activeUsers[client.Username] {
		log.Printf("Registration failed: username %s is already marked as active", client.Username)
		return fmt.Errorf("username %s is already in use", client.Username)
	}

	sessionID := uuid.New()
	client.SessionID = sessionID

	if err := h.recordSession(client); err != nil {
		log.Printf("Failed to record session in database: %v", err)
		return fmt.Errorf("failed to record session: %v", err)
	}

	h.clients[client] = true
	h.clientsByUser[client.Username] = append(h.clientsByUser[client.Username], client)
	h.activeUsers[client.Username] = true
	h.messageManager.RegisterClient(client)

	log.Printf("Registration complete - New state - Active users: %v, Total clients: %d", h.activeUsers, len(h.clients))
	return nil
}

func (h *Hub) UnregisterClient(client *Client) {
	h.mu.Lock()
	defer h.mu.Unlock()

	log.Printf("Starting unregister for client username: %s, ID: %s", client.Username, client.ID)
	log.Printf("Current state - Active users: %v, Total clients: %d", h.activeUsers, len(h.clients))

	if _, ok := h.clients[client]; ok {
		if err := h.recordLogout(client); err != nil {
			log.Printf("Failed to record logout in database: %v", err)
		}

		delete(h.clients, client)
		h.removeFromUserMap(client)
		delete(h.activeUsers, client.Username)
		h.messageManager.UnregisterClient(client)

		close(client.Send) // Close the send channel to signal the WritePump to stop
		close(client.SendHigh)

		log.Printf("Unregister complete - New state - Active users: %v, Total clients: %d", h.activeUsers, len(h.clients))
	} else {
		log.Printf("Unregister skipped - Client not found in registry")
	}
}

func (h *Hub) removeFromUserMap(client *Client) {
	clients := h.clientsByUser[client.Username]
	for i, c := range clients {
		if c.ID == client.ID {
			h.clientsByUser[client.Username] = append(clients[:i], clients[i+1:]...)
			break
		}
	}
	if len(h.clientsByUser[client.Username]) == 0 {
		delete(h.clientsByUser, client.Username)
	}
}

func (h *Hub) BroadcastToAll(ctx context.Context, message []byte) error {
	h.mu.RLock()
	clientCount := len(h.clients)
	h.mu.RUnlock()

	log.Printf("[DEBUG] BroadcastToAll: Starting broadcast to %d clients", clientCount)

	// Debug print the message content
	var msgData map[string]interface{}
	if err := json.Unmarshal(message, &msgData); err != nil {
		log.Printf("[DEBUG] BroadcastToAll: Failed to unmarshal message for debug: %v", err)
	} else {
		log.Printf("[DEBUG] BroadcastToAll: Message type: %v", msgData["type"])
	}

	return h.messageManager.SendMessage(ctx, nil, message)
}

func (h *Hub) BroadcastToUser(ctx context.Context, username string, message []byte) error {
	h.mu.RLock()
	clients := h.clientsByUser[username]
	h.mu.RUnlock()

	for _, client := range clients {
		err := h.messageManager.SendMessage(ctx, client, message)
		if err != nil {
			log.Printf("Failed to send to client %s: %v", client.ID, err)
		}
	}
	return nil
}

func (h *Hub) GetConnectedUsers() []string {
	h.mu.RLock()
	defer h.mu.RUnlock()

	users := make([]string, 0, len(h.clientsByUser))
	for username := range h.clientsByUser {
		users = append(users, username)
	}
	return users
}

// Example to simulate client acknowledgment message handling
func (h *Hub) ProcessClientMessage(client *Client, message []byte) {
	// Assuming message contains acknowledgment info
	// Extract chunk number from message and call HandleAck
	var ackMsg struct {
		Type     string `json:"type"`
		ChunkNum int64  `json:"chunk_num"`
	}

	if err := json.Unmarshal(message, &ackMsg); err != nil {
		log.Printf("Failed to unmarshal acknowledgment message: %v", err)
		return
	}

	if ackMsg.Type == "ack" {
		h.HandleAck(ackMsg.ChunkNum)
	}
}

func (h *Hub) HandleNewConnection(notification *pb.ConnectionNotification) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[PANIC] HandleNewConnection recovered from panic: %v", r)
		}
	}()

	//log.Printf("[DEBUG] HandleNewConnection: Starting with notification for client %s", notification.NewClientId)
	//log.Printf("[DEBUG] HandleNewConnection: Initial state - messageManager exists: %v", h.messageManager != nil)

	// Add the connection to the internal active connections state
	//log.Printf("[DEBUG] HandleNewConnection: Creating ActiveConnection object")
	conn := &ActiveConnection{
		NewClientID: notification.NewClientId,
		ClientID:    notification.ClientId,
		Protocol:    notification.Protocol,
		ExtIP:       notification.ExtIp,
		IntIP:       notification.IntIp,
		Username:    notification.Username,
		Hostname:    notification.Hostname,
		Process:     notification.Process,
		PID:         notification.Pid,
		Arch:        notification.Arch,
		OS:          notification.Os,
		LastSeen:    time.Unix(notification.LastSeen, 0),
	}

	//log.Printf("[DEBUG] HandleNewConnection: Created ActiveConnection object for %s", conn.NewClientID)
	//log.Printf("[DEBUG] HandleNewConnection: Active clients count: %d", h.GetClientCount())

	if h.activeConnections == nil {
		log.Printf("[ERROR] HandleNewConnection: activeConnections is nil!")
		return
	}

	//log.Printf("[DEBUG] HandleNewConnection: About to add connection to ActiveConnections")
	if err := h.activeConnections.AddConnection(conn); err != nil {
		log.Printf("[ERROR] HandleNewConnection: Failed to add new connection: %v", err)
		return
	}
	//log.Printf("[DEBUG] HandleNewConnection: Successfully added to ActiveConnections")

	// Prepare the broadcast message
	//log.Printf("[DEBUG] HandleNewConnection: Beginning broadcast message creation")
	broadcastMsg := struct {
		Type string `json:"type"`
		Data struct {
			Event string `json:"event"`
			Agent struct {
				NewClientID string `json:"new_client_id"`
				ClientID    string `json:"client_id"`
				Protocol    string `json:"protocol"`
				ExtIP       string `json:"ext_ip"`
				IntIP       string `json:"int_ip"`
				Username    string `json:"username"`
				Hostname    string `json:"hostname"`
				Process     string `json:"process"`
				PID         string `json:"pid"`
				Arch        string `json:"arch"`
				OS          string `json:"os"`
				LastSeen    string `json:"last_seen"`
			} `json:"agent"`
		} `json:"data"`
	}{
		Type: "agent_connection",
		Data: struct {
			Event string `json:"event"`
			Agent struct {
				NewClientID string `json:"new_client_id"`
				ClientID    string `json:"client_id"`
				Protocol    string `json:"protocol"`
				ExtIP       string `json:"ext_ip"`
				IntIP       string `json:"int_ip"`
				Username    string `json:"username"`
				Hostname    string `json:"hostname"`
				Process     string `json:"process"`
				PID         string `json:"pid"`
				Arch        string `json:"arch"`
				OS          string `json:"os"`
				LastSeen    string `json:"last_seen"`
			} `json:"agent"`
		}{
			Event: "connected",
			Agent: struct {
				NewClientID string `json:"new_client_id"`
				ClientID    string `json:"client_id"`
				Protocol    string `json:"protocol"`
				ExtIP       string `json:"ext_ip"`
				IntIP       string `json:"int_ip"`
				Username    string `json:"username"`
				Hostname    string `json:"hostname"`
				Process     string `json:"process"`
				PID         string `json:"pid"`
				Arch        string `json:"arch"`
				OS          string `json:"os"`
				LastSeen    string `json:"last_seen"`
			}{
				NewClientID: conn.NewClientID,
				ClientID:    conn.ClientID,
				Protocol:    conn.Protocol,
				ExtIP:       conn.ExtIP,
				IntIP:       conn.IntIP,
				Username:    conn.Username,
				Hostname:    conn.Hostname,
				Process:     conn.Process,
				PID:         conn.PID,
				Arch:        conn.Arch,
				OS:          conn.OS,
				LastSeen:    conn.LastSeen.Format(time.RFC3339),
			},
		},
	}
	//log.Printf("[DEBUG] HandleNewConnection: Broadcast message structure created")

	// Marshal and broadcast
	//log.Printf("[DEBUG] HandleNewConnection: Attempting to marshal broadcast message")
	broadcastJSON, err := json.Marshal(broadcastMsg)
	if err != nil {
		log.Printf("[ERROR] HandleNewConnection: Failed to marshal broadcast message: %v", err)
		return
	}
	//log.Printf("[DEBUG] HandleNewConnection: Message marshaled successfully, size: %d bytes", len(broadcastJSON))

	// Debug print message content
	var msgMap map[string]interface{}
	if err := json.Unmarshal(broadcastJSON, &msgMap); err != nil {
		log.Printf("[DEBUG] HandleNewConnection: Could not unmarshal for debug: %v", err)
	} else {
		log.Printf("[DEBUG] HandleNewConnection: Message content: %+v", msgMap)
	}

	// Create context with timeout for the broadcast
	//log.Printf("[DEBUG] HandleNewConnection: Creating context for broadcast")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if h.messageManager == nil {
		log.Printf("[ERROR] HandleNewConnection: messageManager is nil before broadcast!")
		return
	}
	//log.Printf("[DEBUG] HandleNewConnection: MessageManager present, proceeding with broadcast")

	// Use message manager to broadcast
	//log.Printf("[DEBUG] HandleNewConnection: Initiating broadcast via messageManager")
	if err := h.messageManager.SendMessage(ctx, nil, broadcastJSON); err != nil {
		log.Printf("[ERROR] HandleNewConnection: Broadcasting failed: %v", err)
		return
	}

	//log.Printf("[DEBUG] HandleNewConnection: Broadcast completed")
	log.Printf("[SUCCESS] HandleNewConnection: Successfully completed all operations for %s", conn.NewClientID)
}

func (h *Hub) GetConnectedClients() []ClientInfo {
	h.mu.RLock()
	defer h.mu.RUnlock()

	clients := make([]ClientInfo, 0, len(h.clients))
	for client := range h.clients {
		clients = append(clients, ClientInfo{
			ID:       client.ID,
			Username: client.Username,
		})
	}
	return clients
}

func (h *Hub) GetClientCount() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.clients)
}

func (h *Hub) initPreparedStatements() error {
	var err error

	// Prepare session recording statement
	h.preparedStmts.recordSession, err = h.db.Prepare(`
        INSERT INTO user_sessions (sesion_id, username, login_time) 
        VALUES ($1, $2, $3)
    `)
	if err != nil {
		return fmt.Errorf("failed to prepare recordSession statement: %v", err)
	}

	// Prepare logout recording statement
	h.preparedStmts.recordLogout, err = h.db.Prepare(`
        UPDATE user_sessions 
        SET logout_time = $1 
        WHERE sesion_id = $2
    `)
	if err != nil {
		return fmt.Errorf("failed to prepare recordLogout statement: %v", err)
	}

	return nil
}

// Updated record session with prepared statement and transaction
func (h *Hub) recordSession(client *Client) error {
	if h.preparedStmts.recordSession == nil {
		// Fallback to direct query if prepared statement isn't available
		log.Printf("Warning: Using direct query for session recording (prepared statement not available)")
		query := `INSERT INTO user_sessions (sesion_id, username, login_time) VALUES ($1, $2, $3)`
		_, err := h.db.Exec(query, client.SessionID, client.Username, time.Now())
		if err != nil {
			return fmt.Errorf("failed to record session (direct): %v", err)
		}
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tx, err := h.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %v", err)
	}
	defer tx.Rollback()

	stmt := tx.Stmt(h.preparedStmts.recordSession)
	if _, err := stmt.ExecContext(ctx, client.SessionID, client.Username, time.Now()); err != nil {
		return fmt.Errorf("failed to record session: %v", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %v", err)
	}

	return nil
}

// Updated record logout with prepared statement and transaction
func (h *Hub) recordLogout(client *Client) error {
	if h.preparedStmts.recordLogout == nil {
		// Fallback to direct query if prepared statement isn't available
		log.Printf("Warning: Using direct query for logout recording (prepared statement not available)")
		query := `UPDATE user_sessions SET logout_time = $1 WHERE sesion_id = $2`
		_, err := h.db.Exec(query, time.Now(), client.SessionID)
		if err != nil {
			return fmt.Errorf("failed to record logout (direct): %v", err)
		}
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tx, err := h.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %v", err)
	}
	defer tx.Rollback()

	stmt := tx.Stmt(h.preparedStmts.recordLogout)
	if _, err := stmt.ExecContext(ctx, time.Now(), client.SessionID); err != nil {
		return fmt.Errorf("failed to record logout: %v", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %v", err)
	}

	return nil
}

// Close prepared statements when shutting down
func (h *Hub) Close() error {
	if h.preparedStmts.recordSession != nil {
		if err := h.preparedStmts.recordSession.Close(); err != nil {
			log.Printf("Error closing recordSession statement: %v", err)
		}
	}
	if h.preparedStmts.recordLogout != nil {
		if err := h.preparedStmts.recordLogout.Close(); err != nil {
			log.Printf("Error closing recordLogout statement: %v", err)
		}
	}
	return nil
}

func (h *Hub) BroadcastToUserHighPriority(ctx context.Context, username string, message []byte) error {
	h.mu.RLock()
	defer h.mu.RUnlock()

	clients := h.clientsByUser[username]
	if len(clients) == 0 {
		return fmt.Errorf("user %s not found", username)
	}

	for _, client := range clients {
		select {
		case client.SendHigh <- message:
			// Successfully queued
		default:
			// Channel full, try regular channel as fallback
			select {
			case client.Send <- message:
				log.Printf("High priority channel full, used regular channel for %s", username)
			default:
				log.Printf("Both channels full for client %s, dropping message", username)
			}
		}
	}
	return nil
}
