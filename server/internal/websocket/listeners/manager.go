// internal/websocket/listeners/manager.go
package listeners

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

type Manager struct {
	db              *sql.DB
	listeners       map[uuid.UUID]*Listener
	ListenersByName map[string]*Listener
	listenersByPort map[int][]*Listener // Multiple listeners can share a port
	mu              sync.RWMutex
}

type ValidationError struct {
	Field   string
	Message string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("%s: %s", e.Field, e.Message)
}

// Add validation rules
const (
	MinPort    = 1
	MaxPort    = 65535
	MaxNameLen = 50
	MinNameLen = 1
)

var ValidProtocols = map[string]bool{
	"HTTP":  true,
	"HTTPS": true,
	"RPC":   true,
	"SMB":   true,
}

func NewManager(db *sql.DB) *Manager {
	m := &Manager{
		db:              db,
		listeners:       make(map[uuid.UUID]*Listener),
		ListenersByName: make(map[string]*Listener),
		listenersByPort: make(map[int][]*Listener),
	}

	if err := m.loadExistingListeners(); err != nil {
		log.Printf("Error loading listeners: %v", err)
	}

	return m
}

func (m *Manager) Create(name, protocol string, port int, ip string) (*Listener, error) {
	return m.CreateWithProfiles(name, protocol, port, ip, "", "default-get", "default-post", "default-response")
}

// CreateWithPipe creates a listener with optional pipe name (uses default profiles)
func (m *Manager) CreateWithPipe(name, protocol string, port int, ip string, pipeName string) (*Listener, error) {
	return m.CreateWithProfiles(name, protocol, port, ip, pipeName, "default-get", "default-post", "default-response")
}

// CreateWithProfiles creates a listener with optional pipe name and bound profiles
func (m *Manager) CreateWithProfiles(name, protocol string, port int, ip string, pipeName string,
	getProfile, postProfile, serverResponseProfile string) (*Listener, error) {
	log.Printf("Validating listener creation request - Name: %s, Protocol: %s, Port: %d, IP: %s, PipeName: %s, Profiles: GET=%s POST=%s Response=%s",
		name, protocol, port, ip, pipeName, getProfile, postProfile, serverResponseProfile)

	// Normalize protocol to uppercase
	protocol = strings.ToUpper(protocol)

	// Input validation - use SMB-specific validation if SMB protocol
	if protocol == "SMB" {
		if err := m.validateSMBInput(name, pipeName); err != nil {
			log.Printf("SMB Validation failed: %v", err)
			return nil, err
		}
	} else {
		if err := m.validateInput(name, protocol, port, ip); err != nil {
			log.Printf("Validation failed: %v", err)
			return nil, err
		}
	}

	// Resource availability check - skip port check for SMB
	if protocol == "SMB" {
		if err := m.checkNameAvailability(name); err != nil {
			log.Printf("Resource check failed: %v", err)
			return nil, err
		}
	} else {
		if err := m.checkAvailability(name, port, protocol); err != nil {
			log.Printf("Resource check failed: %v", err)
			return nil, err
		}
	}

	// Set default profile names if not provided
	if getProfile == "" {
		getProfile = "default-get"
	}
	if postProfile == "" {
		postProfile = "default-post"
	}
	if serverResponseProfile == "" {
		serverResponseProfile = "default-response"
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	listenerID := uuid.New()
	l := &Listener{
		ID:                    listenerID,
		Name:                  name,
		Protocol:              protocol,
		Port:                  port,
		IP:                    ip,
		PipeName:              pipeName,
		GetProfile:            getProfile,
		PostProfile:           postProfile,
		ServerResponseProfile: serverResponseProfile,
		Created:               time.Now(),
	}

	// For SMB, use port 0 to indicate no port binding
	if protocol == "SMB" {
		l.Port = 0
		l.IP = "" // No IP needed for SMB listeners
	}

	// Save to database first
	log.Printf("Saving listener to database: ID=%s", listenerID)
	if err := m.saveToDB(l); err != nil {
		log.Printf("Database save failed: %v", err)
		return nil, &ValidationError{
			Field:   "database",
			Message: "failed to save listener",
		}
	}

	// Update memory maps
	log.Printf("Adding listener to memory maps")
	m.listeners[l.ID] = l
	m.ListenersByName[l.Name] = l
	if l.Port > 0 {
		m.listenersByPort[l.Port] = append(m.listenersByPort[l.Port], l)
	}

	return l, nil
}

func (m *Manager) validateInput(name, protocol string, port int, ip string) error {
	// Name validation
	name = strings.TrimSpace(name)
	if len(name) < MinNameLen {
		return &ValidationError{
			Field:   "name",
			Message: "name is too short",
		}
	}
	if len(name) > MaxNameLen {
		return &ValidationError{
			Field:   "name",
			Message: fmt.Sprintf("name exceeds maximum length of %d characters", MaxNameLen),
		}
	}
	if !isValidName(name) {
		return &ValidationError{
			Field:   "name",
			Message: "name contains invalid characters (use alphanumeric, hyphen, underscore only)",
		}
	}

	// Protocol validation
	protocol = strings.ToUpper(protocol)
	if !ValidProtocols[protocol] {
		return &ValidationError{
			Field:   "protocol",
			Message: "invalid protocol specified",
		}
	}

	// Port validation
	if port < MinPort || port > MaxPort {
		return &ValidationError{
			Field:   "port",
			Message: fmt.Sprintf("port must be between %d and %d", MinPort, MaxPort),
		}
	}

	// IP validation
	if ip == "" {
		return &ValidationError{
			Field:   "ip",
			Message: "IP address cannot be empty",
		}
	}
	if !isValidIP(ip) {
		return &ValidationError{
			Field:   "ip",
			Message: "invalid IP address format",
		}
	}

	return nil
}

func (m *Manager) checkAvailability(name string, port int, protocol string) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Check if name is already taken
	if _, exists := m.ListenersByName[name]; exists {
		return &ValidationError{
			Field:   "name",
			Message: fmt.Sprintf("listener with name %s already exists", name),
		}
	}

	// Check if port is already in use by a listener with a different protocol
	// We allow multiple listeners on the same port if they use the same protocol
	// (HTTP with HTTP, HTTPS with HTTPS) - the actual path conflict detection
	// happens at the agent handler level when starting the listener
	if existingListeners, exists := m.listenersByPort[port]; exists && len(existingListeners) > 0 {
		existingProtocol := existingListeners[0].Protocol
		if existingProtocol != protocol {
			return &ValidationError{
				Field:   "port",
				Message: fmt.Sprintf("port %d already in use by %s listener (cannot mix protocols)", port, existingProtocol),
			}
		}
		log.Printf("Port %d already has %d %s listener(s), allowing shared port", port, len(existingListeners), protocol)
	}

	return nil
}

// checkNameAvailability checks only if the name is available (for SMB listeners which don't use ports)
func (m *Manager) checkNameAvailability(name string) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if _, exists := m.ListenersByName[name]; exists {
		return &ValidationError{
			Field:   "name",
			Message: fmt.Sprintf("listener with name %s already exists", name),
		}
	}

	return nil
}

// validateSMBInput validates input specifically for SMB listeners
func (m *Manager) validateSMBInput(name, pipeName string) error {
	// Name validation
	name = strings.TrimSpace(name)
	if len(name) < MinNameLen {
		return &ValidationError{
			Field:   "name",
			Message: "name is too short",
		}
	}
	if len(name) > MaxNameLen {
		return &ValidationError{
			Field:   "name",
			Message: fmt.Sprintf("name exceeds maximum length of %d characters", MaxNameLen),
		}
	}
	if !isValidName(name) {
		return &ValidationError{
			Field:   "name",
			Message: "name contains invalid characters (use alphanumeric, hyphen, underscore only)",
		}
	}

	// Pipe name validation - if provided, validate it
	if pipeName != "" {
		if !isValidPipeName(pipeName) {
			return &ValidationError{
				Field:   "pipe_name",
				Message: "pipe name contains invalid characters (use alphanumeric, hyphen, underscore only)",
			}
		}
	}

	return nil
}

// isValidPipeName validates SMB pipe names
func isValidPipeName(pipeName string) bool {
	// Allow alphanumeric characters, hyphens, and underscores
	// Pipe names like "spoolss", "netlogon", "lsarpc" are valid
	validPipe := regexp.MustCompile(`^[a-zA-Z0-9\-_]+$`)
	return validPipe.MatchString(pipeName)
}

// Helper functions
func isValidName(name string) bool {
	// Allow alphanumeric characters, hyphens, and underscores
	validName := regexp.MustCompile(`^[a-zA-Z0-9\-_]+$`)
	return validName.MatchString(name)
}

func isValidIP(ip string) bool {
	// Special cases
	if ip == "0.0.0.0" || ip == "localhost" {
		return true
	}

	// Check if it's a valid IP address
	if net.ParseIP(ip) != nil {
		return true
	}

	// Check if it's a valid hostname
	_, err := net.LookupHost(ip)
	return err == nil
}

func (m *Manager) loadExistingListeners() error {
	log.Println("Loading existing listeners from database...")

	rows, err := m.db.Query(`SELECT id, name, protocol, port, ip, COALESCE(pipe_name, ''),
		COALESCE(get_profile, 'default-get'),
		COALESCE(post_profile, 'default-post'),
		COALESCE(server_response_profile, 'default-response')
		FROM listeners`)
	if err != nil {
		log.Printf("Error querying listeners: %v", err)
		return err
	}
	defer rows.Close()

	count := 0
	for rows.Next() {
		var l Listener
		var idStr string
		if err := rows.Scan(&idStr, &l.Name, &l.Protocol, &l.Port, &l.IP, &l.PipeName,
			&l.GetProfile, &l.PostProfile, &l.ServerResponseProfile); err != nil {
			log.Printf("Error scanning listener row: %v", err)
			return err
		}

		l.ID, err = uuid.Parse(idStr)
		if err != nil {
			log.Printf("Error parsing UUID %s: %v", idStr, err)
			continue
		}

		l.Created = time.Now()

		m.listeners[l.ID] = &l
		m.ListenersByName[l.Name] = &l
		// Only add to port map if port > 0 (SMB listeners have port 0)
		if l.Port > 0 {
			m.listenersByPort[l.Port] = append(m.listenersByPort[l.Port], &l)
		}

		count++
		log.Printf("Loaded listener: ID=%s, Name=%s, Protocol=%s, Port=%d, IP=%s, PipeName=%s, Profiles: GET=%s POST=%s Response=%s",
			l.ID, l.Name, l.Protocol, l.Port, l.IP, l.PipeName, l.GetProfile, l.PostProfile, l.ServerResponseProfile)
	}

	log.Printf("Successfully loaded %d listeners from database", count)
	return rows.Err()
}

func (m *Manager) DumpState() {
	m.mu.RLock()
	defer m.mu.RUnlock()

	log.Println("=== Current Listener State ===")
	log.Printf("Total listeners: %d", len(m.listeners))

	for _, l := range m.listeners {
		log.Printf("Listener: ID=%s, Name=%s, Protocol=%s, Port=%d, IP=%s, Created=%v",
			l.ID, l.Name, l.Protocol, l.Port, l.IP, l.Created)
	}
	log.Println("===========================")
}

func (m *Manager) DeleteByName(name string) error {
	log.Printf("Starting deletion process for listener: %s", name)

	m.mu.Lock()
	defer m.mu.Unlock()

	// Log current state before deletion
	log.Printf("Current state - Total listeners: %d", len(m.listeners))

	// Find the listener
	listener, exists := m.ListenersByName[name]
	if !exists {
		log.Printf("Error: Listener %s not found in memory", name)
		return fmt.Errorf("listener %s not found", name)
	}

	// Delete from database first
	log.Printf("Deleting listener %s from database", name)
	result, err := m.db.Exec("DELETE FROM listeners WHERE name = $1", name)
	if err != nil {
		log.Printf("Database deletion failed: %v", err)
		return fmt.Errorf("failed to delete listener from database: %v", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		log.Printf("Listener %s was not found in the database", name)
		return fmt.Errorf("listener %s not found in the database", name)
	}
	log.Printf("Database rows affected: %d", rowsAffected)

	// Remove from memory maps
	log.Printf("Removing listener from memory maps")
	delete(m.listeners, listener.ID)
	delete(m.ListenersByName, listener.Name)

	// Remove from port list (filter out this listener)
	if listener.Port > 0 {
		if portListeners, exists := m.listenersByPort[listener.Port]; exists {
			newList := make([]*Listener, 0, len(portListeners)-1)
			for _, l := range portListeners {
				if l.ID != listener.ID {
					newList = append(newList, l)
				}
			}
			if len(newList) > 0 {
				m.listenersByPort[listener.Port] = newList
			} else {
				delete(m.listenersByPort, listener.Port)
			}
		}
	}

	// Log final state
	log.Printf("Deletion complete - New state - Total listeners: %d", len(m.listeners))

	// Dump remaining listeners for verification
	log.Println("=== Remaining Listeners ===")
	for _, l := range m.listeners {
		log.Printf("Listener: ID=%s, Name=%s", l.ID, l.Name)
	}
	log.Println("=========================")

	return nil
}

func (m *Manager) GetListener(name string) (*Listener, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	l, exists := m.ListenersByName[name]
	return l, exists
}

func (lm *Manager) IsPortInUse(port int) bool {
	lm.mu.Lock()
	defer lm.mu.Unlock()

	// First check our internal state
	for _, listener := range lm.listeners {
		if listener.Port == port {
			return true
		}
	}

	// For privileged ports (<1024), we can't reliably test if they're in use
	// when running as non-root, even with CAP_NET_BIND_SERVICE in some configurations.
	// Skip the bind test for privileged ports - the agent-handler will handle the actual bind.
	if port < 1024 {
		log.Printf("[IsPortInUse] Skipping bind test for privileged port %d (agent-handler will handle bind)", port)
		return false
	}

	// Then try to actually bind to the port to check if it's really in use
	addr := fmt.Sprintf(":%d", port)
	l, err := net.Listen("tcp", addr)
	if err != nil {
		// Port is in use
		log.Printf("[IsPortInUse] Port %d appears to be in use: %v", port, err)
		return true
	}
	// Port is free
	l.Close()
	return false
}

// CanSharePort checks if a new listener can share a port with existing listeners
// Returns true if the port is free OR if it's already used by listeners with matching protocol
// Returns false if the port is used by an external process OR by a listener with different protocol
func (lm *Manager) CanSharePort(port int, protocol string) bool {
	lm.mu.RLock()
	defer lm.mu.RUnlock()

	// Check if we already have listeners on this port
	existingListeners := lm.listenersByPort[port]
	if len(existingListeners) > 0 {
		// Port is managed by us - check if protocols match
		existingProtocol := existingListeners[0].Protocol
		if existingProtocol == protocol {
			log.Printf("[CanSharePort] Port %d already has %s listeners, allowing shared port", port, protocol)
			return true
		}
		log.Printf("[CanSharePort] Port %d in use by %s listener, cannot add %s listener", port, existingProtocol, protocol)
		return false
	}

	// Port not managed by us - check if it's available for binding
	// For privileged ports, defer to agent-handler
	if port < 1024 {
		log.Printf("[CanSharePort] Skipping bind test for privileged port %d (agent-handler will handle bind)", port)
		return true
	}

	// Try to bind to see if port is externally in use
	addr := fmt.Sprintf(":%d", port)
	l, err := net.Listen("tcp", addr)
	if err != nil {
		log.Printf("[CanSharePort] Port %d appears to be in use externally: %v", port, err)
		return false
	}
	l.Close()
	return true
}

func withRetry(op func() error, maxRetries int, backoff time.Duration) error {
	var lastErr error
	for i := 0; i < maxRetries; i++ {
		if err := op(); err == nil {
			return nil
		} else {
			lastErr = err
			if i < maxRetries-1 { // Don't sleep after last attempt
				time.Sleep(backoff * time.Duration(i+1))
			}
		}
	}
	return fmt.Errorf("operation failed after %d retries: %v", maxRetries, lastErr)
}

// Replace the existing saveToDB method
func (m *Manager) saveToDB(l *Listener) error {
	return withRetry(func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		tx, err := m.db.BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("failed to begin transaction: %v", err)
		}
		defer tx.Rollback()

		if _, err := tx.ExecContext(ctx, `
            INSERT INTO listeners (id, name, protocol, port, ip, pipe_name, get_profile, post_profile, server_response_profile)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        `, l.ID, l.Name, l.Protocol, l.Port, l.IP, l.PipeName, l.GetProfile, l.PostProfile, l.ServerResponseProfile); err != nil {
			return fmt.Errorf("failed to insert listener: %v", err)
		}

		if err := tx.Commit(); err != nil {
			return fmt.Errorf("failed to commit transaction: %v", err)
		}

		return nil
	}, 3, time.Millisecond*100)
}
