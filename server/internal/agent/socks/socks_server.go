// internal/agent/socks/socks_server.go
package socks

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/ssh"
)

// Buffer pool for SOCKS5 parsing to reduce allocations
var socksParseBufferPool = sync.Pool{
	New: func() interface{} {
		buf := make([]byte, 512) // 512 bytes sufficient for SOCKS5 request
		return &buf
	},
}

type Server struct {
	socksPort     int
	path          string
	credentials   *Credentials
	socksListener net.Listener
	upgrader      websocket.Upgrader
	sshConfig     *ssh.ServerConfig
	running       bool
	mu            sync.RWMutex

	// SSH connection management
	sshConnMu   sync.RWMutex
	sshConn     *ssh.ServerConn
	sshChannels <-chan ssh.NewChannel
	sshRequests <-chan *ssh.Request

	// Channel for forwarding requests
	forwardChan chan *ForwardRequest

	// Context for graceful shutdown
	ctx    context.Context
	cancel context.CancelFunc

	// Callback invoked when connection dies
	onConnectionLost func()
}

type ForwardRequest struct {
	Target     string
	ClientConn net.Conn
	ResultChan chan error
}

func NewServer(socksPort int, path string, creds *Credentials) (*Server, error) {
	ctx, cancel := context.WithCancel(context.Background())
	s := &Server{
		socksPort:   socksPort,
		path:        path,
		credentials: creds,
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool {
				return true
			},
		},
		forwardChan: make(chan *ForwardRequest, 100),
		ctx:         ctx,
		cancel:      cancel,
	}

	// Setup SSH server config
	config := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if c.User() == creds.Username && string(pass) == creds.Password {
				return nil, nil
			}
			return nil, fmt.Errorf("invalid credentials")
		},
	}

	// Add SSH key authentication if provided
	if len(creds.SSHKey) > 0 {
		signer, err := ssh.ParsePrivateKey(creds.SSHKey)
		if err == nil {
			config.AddHostKey(signer)
		} else {
			// If the SSH key can't be used as host key, generate one
			hostKey, err := generateHostKey()
			if err != nil {
				return nil, fmt.Errorf("failed to generate host key: %v", err)
			}
			config.AddHostKey(hostKey)
		}
	} else {
		// Generate a temporary host key if no SSH key provided
		hostKey, err := generateHostKey()
		if err != nil {
			return nil, fmt.Errorf("failed to generate host key: %v", err)
		}
		config.AddHostKey(hostKey)
	}

	s.sshConfig = config
	return s, nil
}

func generateHostKey() (ssh.Signer, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	privateKeyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}

	privatePEM := pem.EncodeToMemory(privateKeyPEM)
	return ssh.ParsePrivateKey(privatePEM)
}

// parsePrivateKey attempts to parse a private key for SSH authentication
func parsePrivateKey(keyBytes []byte) ssh.Signer {
	key, err := ssh.ParsePrivateKey(keyBytes)
	if err != nil {
		return nil
	}
	return key
}

// dialWSS establishes a WebSocket connection over TLS
func dialWSS(addr, path string) (net.Conn, error) {
	dialer := websocket.Dialer{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
	wsURL := fmt.Sprintf("wss://%s%s", addr, path)
	c, _, err := dialer.Dial(wsURL, nil)
	if err != nil {
		return nil, err
	}
	return &wsConn{conn: c}, nil
}

func (s *Server) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.running {
		return fmt.Errorf("server already running")
	}

	// Start SOCKS listener
	socksAddr := fmt.Sprintf("0.0.0.0:%d", s.socksPort)
	listener, err := net.Listen("tcp", socksAddr)
	if err != nil {
		return fmt.Errorf("failed to start SOCKS listener: %v", err)
	}
	s.socksListener = listener
	s.running = true

	// Start forwarding handler
	go s.handleForwardRequests()

	// Start accepting SOCKS connections
	go s.acceptSocksConnections()

	log.Printf("[SOCKS] Started SOCKS server listening on %s", socksAddr)
	return nil
}

func (s *Server) acceptSocksConnections() {
	for s.running {
		conn, err := s.socksListener.Accept()
		if err != nil {
			if s.running {
				log.Printf("Failed to accept SOCKS connection: %v", err)
			}
			return
		}
		go s.handleSocksConnection(conn)
	}
}

func (s *Server) handleSocksConnection(conn net.Conn) {
	defer conn.Close()

	remoteAddr := conn.RemoteAddr().String()
	log.Printf("[SOCKS] New connection from: %s", remoteAddr)

	// Handle initial SOCKS5 handshake
	log.Printf("[SOCKS] Starting authentication for %s", remoteAddr)
	if err := s.handleSocksAuth(conn); err != nil {
		log.Printf("[SOCKS] Auth failed from %s: %v", remoteAddr, err)
		return
	}
	log.Printf("[SOCKS] Authentication successful for %s", remoteAddr)

	// Handle SOCKS5 request and get target
	target, err := s.parseSocksRequest(conn)
	if err != nil {
		log.Printf("[SOCKS] Failed to parse request from %s: %v", remoteAddr, err)
		return
	}

	log.Printf("[SOCKS] Client %s wants to connect to %s", remoteAddr, target)

	// Check if we have an SSH connection
	s.sshConnMu.RLock()
	hasSSH := s.sshConn != nil
	s.sshConnMu.RUnlock()

	if !hasSSH {
		log.Printf("[SOCKS] No SSH tunnel available for %s", remoteAddr)
		// Send SOCKS failure response
		conn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		return
	}

	// Forward through SSH tunnel
	if err := s.forwardThroughSSH(conn, target); err != nil {
		log.Printf("[SOCKS] Failed to forward connection: %v", err)
		// Send SOCKS failure response
		conn.Write([]byte{0x05, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		return
	}
}

func (s *Server) forwardThroughSSH(clientConn net.Conn, target string) error {
	// Request a new channel through the SSH connection
	s.sshConnMu.RLock()
	sshConn := s.sshConn
	s.sshConnMu.RUnlock()

	if sshConn == nil {
		return fmt.Errorf("SSH connection lost")
	}

	// Create forward request
	req := &ForwardRequest{
		Target:     target,
		ClientConn: clientConn,
		ResultChan: make(chan error, 1),
	}

	// Send to forward handler
	select {
	case s.forwardChan <- req:
		// Wait for result
		return <-req.ResultChan
	case <-time.After(10 * time.Second):
		return fmt.Errorf("forward request timeout")
	}
}

func (s *Server) handleForwardRequests() {
	for req := range s.forwardChan {
		go s.processForwardRequest(req)
	}
}

func (s *Server) processForwardRequest(req *ForwardRequest) {
	s.sshConnMu.RLock()
	channels := s.sshChannels
	s.sshConnMu.RUnlock()

	if channels == nil {
		req.ResultChan <- fmt.Errorf("no SSH channels available")
		return
	}

	// Wait for a direct-tcpip channel from the client
	// The payload should open a channel when it receives our forwarding request
	// For now, we'll signal success and handle the actual forwarding

	// Send SOCKS success response
	req.ClientConn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})

	// Signal the SSH session to handle this connection
	// This is where we need to coordinate with the payload
	s.handleTunnelForwarding(req.ClientConn, req.Target)

	req.ResultChan <- nil
}

func (s *Server) handleTunnelForwarding(clientConn net.Conn, target string) {
	// This function handles the actual forwarding through SSH channels
	// We need to signal the payload to open a connection to the target
	// and then bridge the data

	s.sshConnMu.RLock()
	sshConn := s.sshConn
	s.sshConnMu.RUnlock()

	if sshConn == nil {
		log.Printf("[SOCKS] SSH connection lost during forwarding")
		return
	}

	// Open a channel to the payload for this connection
	channel, reqs, err := sshConn.OpenChannel("direct-tcpip", ssh.Marshal(&struct {
		DestAddr   string
		DestPort   uint32
		OriginAddr string
		OriginPort uint32
	}{
		DestAddr:   target,
		DestPort:   0, // Port is included in target string
		OriginAddr: "127.0.0.1",
		OriginPort: 0,
	}))

	if err != nil {
		log.Printf("[SOCKS] Failed to open channel: %v", err)
		return
	}
	defer channel.Close()

	go ssh.DiscardRequests(reqs)

	// Create context for coordinated shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Error channel for propagation
	errChan := make(chan error, 2)

	// Bridge the connections with context-based error propagation
	var wg sync.WaitGroup
	wg.Add(2)

	// Client -> Target (through SSH)
	go func() {
		defer wg.Done()
		bytes, err := s.copyWithContext(ctx, channel, clientConn, target, "Client->Target")
		if err != nil && err != io.EOF && err != context.Canceled {
			log.Printf("[SOCKS] Client->Target error for %s: %v", target, err)
			select {
			case errChan <- err:
				cancel() // Signal other goroutine to abort
			default:
			}
		}
		log.Printf("[SOCKS] Client->Target transferred %d bytes for %s", bytes, target)
		channel.CloseWrite()
	}()

	// Target -> Client (through SSH)
	go func() {
		defer wg.Done()
		bytes, err := s.copyWithContext(ctx, clientConn, channel, target, "Target->Client")
		if err != nil && err != io.EOF && err != context.Canceled {
			log.Printf("[SOCKS] Target->Client error for %s: %v", target, err)
			select {
			case errChan <- err:
				cancel() // Signal other goroutine to abort
			default:
			}
		}
		log.Printf("[SOCKS] Target->Client transferred %d bytes for %s", bytes, target)
		if tcpConn, ok := clientConn.(*net.TCPConn); ok {
			tcpConn.CloseWrite()
		}
	}()

	wg.Wait()
	clientConn.Close()
	channel.Close()
	log.Printf("[SOCKS] Tunnel closed for target %s", target)
}

// copyWithContext performs buffered copy with context cancellation support
// Optimized for various workloads: small messages (tools), large transfers (files), streaming
func (s *Server) copyWithContext(ctx context.Context, dst io.Writer, src io.Reader, target, direction string) (int64, error) {
	const (
		bufferSize  = 32 * 1024       // 32KB buffer - good balance for all use cases
		idleTimeout = 10 * time.Minute // Very forgiving timeout for slow tools/transfers
	)

	buf := make([]byte, bufferSize)
	var written int64

	for {
		// Check context cancellation
		select {
		case <-ctx.Done():
			return written, ctx.Err()
		default:
		}

		// Set generous read deadline for idle timeout
		// This is very forgiving to support slow operations, large file transfers, etc.
		if conn, ok := src.(net.Conn); ok {
			conn.SetReadDeadline(time.Now().Add(idleTimeout))
		}

		nr, err := src.Read(buf)
		if nr > 0 {
			nw, ew := dst.Write(buf[0:nr])
			if nw > 0 {
				written += int64(nw)
			}
			if ew != nil {
				return written, ew
			}
			if nr != nw {
				return written, io.ErrShortWrite
			}
		}
		if err != nil {
			return written, err
		}
	}
}

func (s *Server) handleSocksAuth(conn net.Conn) error {
	// Read version and number of methods
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return err
	}

	if buf[0] != 0x05 {
		return fmt.Errorf("unsupported SOCKS version: %d", buf[0])
	}

	// Read methods
	methods := make([]byte, buf[1])
	if _, err := io.ReadFull(conn, methods); err != nil {
		return err
	}

	// Send no authentication required
	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
		return err
	}

	return nil
}

func (s *Server) parseSocksRequest(conn net.Conn) (string, error) {
	// Get buffer from pool for efficient parsing
	bufPtr := socksParseBufferPool.Get().(*[]byte)
	defer socksParseBufferPool.Put(bufPtr)
	buf := *bufPtr

	// Read request header (4 bytes)
	if _, err := io.ReadFull(conn, buf[:4]); err != nil {
		return "", err
	}

	if buf[0] != 0x05 {
		return "", fmt.Errorf("invalid SOCKS version")
	}

	if buf[1] != 0x01 { // Only support CONNECT
		return "", fmt.Errorf("unsupported command")
	}

	// Read address based on type
	var addr string
	var addrLen int

	switch buf[3] {
	case 0x01: // IPv4 (4 bytes)
		addrLen = 4
		if _, err := io.ReadFull(conn, buf[:addrLen]); err != nil {
			return "", err
		}
		addr = net.IP(buf[:addrLen]).String()

	case 0x03: // Domain name (1 byte length + domain)
		if _, err := io.ReadFull(conn, buf[:1]); err != nil {
			return "", err
		}
		domainLen := int(buf[0])
		if domainLen > 255 {
			return "", fmt.Errorf("invalid domain length")
		}
		if _, err := io.ReadFull(conn, buf[:domainLen]); err != nil {
			return "", err
		}
		addr = string(buf[:domainLen])

	case 0x04: // IPv6 (16 bytes)
		addrLen = 16
		if _, err := io.ReadFull(conn, buf[:addrLen]); err != nil {
			return "", err
		}
		addr = net.IP(buf[:addrLen]).String()

	default:
		return "", fmt.Errorf("unsupported address type: %d", buf[3])
	}

	// Read port (2 bytes)
	if _, err := io.ReadFull(conn, buf[:2]); err != nil {
		return "", err
	}
	port := (uint16(buf[0]) << 8) | uint16(buf[1])

	target := fmt.Sprintf("%s:%d", addr, port)
	return target, nil
}

func (s *Server) HandleWebSocket(w http.ResponseWriter, r *http.Request) {
	log.Printf("[SOCKS] WebSocket connection request at path: %s", r.URL.Path)

	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("[SOCKS] Failed to upgrade connection: %v", err)
		return
	}
	defer conn.Close()

	log.Printf("[SOCKS] WebSocket connection established")

	// Wrap websocket in net.Conn interface
	wsConn := &wsConn{conn: conn}

	// Handle SSH handshake
	sshConn, chans, reqs, err := ssh.NewServerConn(wsConn, s.sshConfig)
	if err != nil {
		log.Printf("[SOCKS] Failed SSH handshake: %v", err)
		return
	}
	defer sshConn.Close()

	log.Printf("[SOCKS] SSH connection established with user: %s", sshConn.User())

	// Store SSH connection
	s.sshConnMu.Lock()
	s.sshConn = sshConn
	s.sshChannels = chans
	s.sshRequests = reqs
	s.sshConnMu.Unlock()

	// Handle SSH requests
	go ssh.DiscardRequests(reqs)

	// Handle SSH channels
	s.handleSSHChannels(chans)

	// Clear SSH connection when done
	s.sshConnMu.Lock()
	s.sshConn = nil
	s.sshChannels = nil
	s.sshRequests = nil
	s.sshConnMu.Unlock()

	log.Printf("[SOCKS] SSH connection closed")

	// Invoke cleanup callback if set (connection died)
	s.mu.Lock()
	callback := s.onConnectionLost
	s.mu.Unlock()

	if callback != nil {
		log.Printf("[SOCKS] Connection lost, invoking cleanup callback")
		go callback() // Run in goroutine to avoid blocking
	}
}

func (s *Server) handleSSHChannels(chans <-chan ssh.NewChannel) {
	for {
		select {
		case newChannel, ok := <-chans:
			if !ok {
				log.Printf("[SOCKS] SSH channels closed")
				return
			}
			go s.handleSSHChannel(newChannel)
		case <-s.ctx.Done():
			log.Printf("[SOCKS] SSH channel handler shutting down")
			return
		}
	}
}

func (s *Server) handleSSHChannel(newChannel ssh.NewChannel) {
	log.Printf("[SOCKS] New SSH channel type: %s", newChannel.ChannelType())

	// Accept all channel types for now
	channel, requests, err := newChannel.Accept()
	if err != nil {
		log.Printf("[SOCKS] Could not accept channel: %v", err)
		return
	}
	defer channel.Close()

	// Handle channel requests
	go func() {
		for req := range requests {
			log.Printf("[SOCKS] Channel request type: %s", req.Type)
			if req.WantReply {
				req.Reply(true, nil)
			}
		}
	}()

	// Keep channel open until it's closed by the other side
	io.Copy(io.Discard, channel)
}

func (s *Server) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running {
		return nil
	}

	// Cancel context to signal all goroutines to shutdown
	if s.cancel != nil {
		s.cancel()
	}

	if s.socksListener != nil {
		s.socksListener.Close()
	}

	close(s.forwardChan)
	s.running = false
	return nil
}

func (s *Server) GetHandler() http.HandlerFunc {
	return s.HandleWebSocket
}

// SetConnectionLostCallback sets a callback to invoke when the agent connection dies
func (s *Server) SetConnectionLostCallback(callback func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.onConnectionLost = callback
}

// Buffer pool for WebSocket messages to reduce allocations (shared with agent implementation)
var wsBufferPool = sync.Pool{
	New: func() interface{} {
		buf := make([]byte, 0, 32*1024) // Pre-allocate 32KB capacity
		return &buf
	},
}

// wsConn wraps a websocket connection to implement net.Conn
// Unified implementation with buffer pooling for efficiency
type wsConn struct {
	conn        *websocket.Conn
	buf         []byte
	bufFromPool bool
}

func (w *wsConn) Read(p []byte) (n int, err error) {
	if len(w.buf) == 0 {
		_, message, err := w.conn.ReadMessage()
		if err != nil {
			return 0, err
		}

		// For large messages, use the message directly
		// For small messages, copy to pooled buffer to avoid holding WebSocket memory
		const largeMessageThreshold = 64 * 1024 // 64KB
		if len(message) > largeMessageThreshold {
			// Return pooled buffer if we had one
			if w.bufFromPool && cap(w.buf) > 0 {
				emptyBuf := w.buf[:0]
				wsBufferPool.Put(&emptyBuf)
				w.bufFromPool = false
			}
			w.buf = message
		} else {
			// Get pooled buffer for small messages
			if !w.bufFromPool {
				bufPtr := wsBufferPool.Get().(*[]byte)
				w.buf = (*bufPtr)[:0]
				w.bufFromPool = true
			}
			w.buf = append(w.buf[:0], message...)
		}
	}

	n = copy(p, w.buf)
	w.buf = w.buf[n:]

	// Return buffer to pool when fully consumed
	if len(w.buf) == 0 && w.bufFromPool {
		emptyBuf := w.buf[:0]
		wsBufferPool.Put(&emptyBuf)
		w.bufFromPool = false
		w.buf = nil
	}

	return n, nil
}

func (w *wsConn) Write(p []byte) (n int, err error) {
	err = w.conn.WriteMessage(websocket.BinaryMessage, p)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func (w *wsConn) Close() error {
	// Clean up any pooled buffer on close
	if w.bufFromPool && cap(w.buf) > 0 {
		emptyBuf := w.buf[:0]
		wsBufferPool.Put(&emptyBuf)
		w.bufFromPool = false
	}
	return w.conn.Close()
}

func (w *wsConn) LocalAddr() net.Addr {
	return w.conn.LocalAddr()
}

func (w *wsConn) RemoteAddr() net.Addr {
	return w.conn.RemoteAddr()
}

func (w *wsConn) SetDeadline(t time.Time) error {
	if err := w.conn.SetReadDeadline(t); err != nil {
		return err
	}
	return w.conn.SetWriteDeadline(t)
}

func (w *wsConn) SetReadDeadline(t time.Time) error {
	return w.conn.SetReadDeadline(t)
}

func (w *wsConn) SetWriteDeadline(t time.Time) error {
	return w.conn.SetWriteDeadline(t)
}
