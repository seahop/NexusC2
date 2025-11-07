// internal/websocket/hub/active_connections.go
package hub

import (
	"fmt"
	"log"
	"runtime/debug"
	"sync"
	"time"
)

type ActiveConnection struct {
	NewClientID string
	ClientID    string
	Protocol    string
	Secret1     string
	Secret2     string
	ExtIP       string
	IntIP       string
	Username    string
	Hostname    string
	Process     string
	PID         string
	Arch        string
	OS          string
	Proto       string
	LastSeen    time.Time
}

type ActiveConnectionManager struct {
	connections map[string]*ActiveConnection // key is NewClientID
	mutex       sync.RWMutex
}

func NewActiveConnectionManager() *ActiveConnectionManager {
	return &ActiveConnectionManager{
		connections: make(map[string]*ActiveConnection),
	}
}

func (acm *ActiveConnectionManager) AddConnection(conn *ActiveConnection) error {
	//log.Printf("[DEBUG] AddConnection: Starting to add connection for NewClientID=%s", conn.NewClientID)

	// Validate connection object
	if conn == nil {
		log.Printf("[ERROR] AddConnection: Connection object is nil")
		return fmt.Errorf("connection object is nil")
	}

	if conn.NewClientID == "" {
		log.Printf("[ERROR] AddConnection: NewClientID is empty")
		return fmt.Errorf("NewClientID is required")
	}

	// Debug print connection details before adding
	/*
		log.Printf("[DEBUG] AddConnection: Connection details:")
		log.Printf("  NewClientID: %s", conn.NewClientID)
		log.Printf("  ClientID: %s", conn.ClientID)
		log.Printf("  Protocol: %s", conn.Protocol)
		log.Printf("  Host: %s", conn.Hostname)
		log.Printf("  IPs: ext=%s, int=%s", conn.ExtIP, conn.IntIP)
		log.Printf("  Process: %s (PID: %s)", conn.Process, conn.PID)
		log.Printf("  OS/Arch: %s/%s", conn.OS, conn.Arch)
		log.Printf("  LastSeen: %s", conn.LastSeen.Format(time.RFC3339))

		log.Printf("[DEBUG] AddConnection: Attempting to acquire lock")
	*/
	func() {
		acm.mutex.Lock()
		defer acm.mutex.Unlock()
		//log.Printf("[DEBUG] AddConnection: Lock acquired")
		acm.connections[conn.NewClientID] = conn
		//log.Printf("[DEBUG] AddConnection: Connection added to map")
	}()
	//log.Printf("[DEBUG] AddConnection: Lock acquired")

	// Check if connection already exists
	if existing, exists := acm.connections[conn.NewClientID]; exists {
		log.Printf("[WARN] AddConnection: Overwriting existing connection for NewClientID=%s", conn.NewClientID)
		log.Printf("[WARN] AddConnection: Existing connection details - ClientID=%s, Host=%s",
			existing.ClientID, existing.Hostname)
	}

	// Add the connection
	//log.Printf("[DEBUG] AddConnection: Adding connection to map")
	acm.connections[conn.NewClientID] = conn
	//log.Printf("[DEBUG] AddConnection: Connection added successfully")

	// Debug print current state
	//log.Printf("[DEBUG] AddConnection: Current connection count: %d", len(acm.connections))

	//log.Printf("[DEBUG] AddConnection: About to print connection state")
	acm.PrintConnectionState()
	//log.Printf("[DEBUG] AddConnection: Completed printing connection state")

	return nil
}

func (acm *ActiveConnectionManager) GetConnection(clientID string) (*ActiveConnection, error) {
	acm.mutex.RLock()
	defer acm.mutex.RUnlock()

	conn, exists := acm.connections[clientID]
	if !exists {
		return nil, fmt.Errorf("no active connection found for client ID: %s", clientID)
	}

	return conn, nil
}

func (acm *ActiveConnectionManager) ListConnections() []*ActiveConnection {
	acm.mutex.RLock()
	defer acm.mutex.RUnlock()

	connections := make([]*ActiveConnection, 0, len(acm.connections))
	for _, conn := range acm.connections {
		connections = append(connections, conn)
	}

	return connections
}

func (acm *ActiveConnectionManager) RemoveConnection(clientID string) {
	acm.mutex.Lock()
	defer acm.mutex.Unlock()

	delete(acm.connections, clientID)
}

func (acm *ActiveConnectionManager) PrintConnectionState() {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[PANIC] PrintConnectionState recovered from panic: %v", r)
			debug.PrintStack()
		}
	}()

	//log.Printf("[DEBUG] PrintConnectionState: Step 1 - Starting")

	//log.Printf("[DEBUG] PrintConnectionState: Step 2 - Attempting to acquire read lock")
	acm.mutex.RLock()
	//log.Printf("[DEBUG] PrintConnectionState: Step 3 - Read lock acquired")
	defer acm.mutex.RUnlock()

	//log.Printf("[DEBUG] PrintConnectionState: Step 4 - Checking map")
	if acm.connections == nil {
		log.Printf("[ERROR] PrintConnectionState: connections map is nil!")
		return
	}

	connectionsCount := len(acm.connections)
	//log.Printf("[DEBUG] PrintConnectionState: Step 5 - Found %d connections", connectionsCount)

	//log.Printf("[STATE] =========== Begin Active Connections State ===========")
	//log.Printf("[STATE] Total Active Connections: %d", connectionsCount)

	if connectionsCount == 0 {
		log.Printf("[STATE] No active connections")
		log.Printf("[STATE] ==========================================")
		log.Printf("[DEBUG] PrintConnectionState: Step 6a - Completed (no connections)")
		return
	}

	//log.Printf("[DEBUG] PrintConnectionState: Step 6b - Beginning connection iteration")

	// Debug print the keys first
	var keys []string
	for k := range acm.connections {
		keys = append(keys, k)
	}
	//log.Printf("[DEBUG] PrintConnectionState: Step 7 - Found keys: %v", keys)

	for i, newClientID := range keys {
		//log.Printf("[DEBUG] PrintConnectionState: Step 8 - Processing connection %d/%d", i+1, len(keys))

		conn := acm.connections[newClientID]
		if conn == nil {
			log.Printf("[WARN] PrintConnectionState: Found nil connection for ID: %s", newClientID)
			continue
		}

		// Print connection details with explicit string conversions and nil checks
		details := []struct{ label, value string }{
			{"NewClientID", newClientID},
			{"Original ClientID", conn.ClientID},
			{"Protocol", conn.Protocol},
			{"Hostname", conn.Hostname},
			{"Internal IP", conn.IntIP},
			{"External IP", conn.ExtIP},
			{"Username", conn.Username},
			{"Process", conn.Process},
			{"PID", conn.PID},
			{"OS", conn.OS},
			{"Arch", conn.Arch},
		}

		log.Printf("[STATE] ----------------------------------------------")
		for _, detail := range details {
			if detail.value != "" {
				log.Printf("[STATE] %s: %s", detail.label, detail.value)
			}
		}

		// Handle the timestamp separately
		if !conn.LastSeen.IsZero() {
			log.Printf("[STATE] Last Seen: %s", conn.LastSeen.Format(time.RFC3339))
		}

		log.Printf("[DEBUG] PrintConnectionState: Step 9 - Completed connection %d", i+1)
	}

	//log.Printf("[DEBUG] PrintConnectionState: Step 10 - Completed all connections")
	//log.Printf("[STATE] ==========================================")
	//log.Printf("[DEBUG] PrintConnectionState: Step 11 - Successfully completed")
}
