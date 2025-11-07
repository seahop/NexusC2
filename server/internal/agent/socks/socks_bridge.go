// internal/agent/socks/socks_bridge.go
package socks

import (
	"fmt"
	"io"
	"log"
	"net"
	"sync"

	"golang.org/x/crypto/ssh"
)

// Bridge handles traffic between SOCKS and SSH connections
type Bridge struct {
	mu          sync.RWMutex
	connections map[string]*ProxyConn
	socksServer *Server
	sshListener net.Listener
}

type ProxyConn struct {
	socksConn net.Conn
	sshConn   net.Conn
	target    string
}

func NewBridge(socksServer *Server) *Bridge {
	return &Bridge{
		connections: make(map[string]*ProxyConn),
		socksServer: socksServer,
	}
}

func (b *Bridge) Start() error {
	var err error
	b.sshListener, err = net.Listen("tcp", ":0")
	if err != nil {
		return fmt.Errorf("failed to start SSH listener: %v", err)
	}

	go b.acceptSSHConnections()
	return nil
}

func (b *Bridge) acceptSSHConnections() {
	for {
		conn, err := b.sshListener.Accept()
		if err != nil {
			log.Printf("Failed to accept SSH connection: %v", err)
			return
		}
		log.Printf("[Bridge] Accepted new SSH connection from: %s", conn.RemoteAddr())
		go b.handleSSHConnection(conn)
	}
}

func (b *Bridge) handleSSHConnection(sshConn net.Conn) {
	defer sshConn.Close()

	sshServer, chans, reqs, err := ssh.NewServerConn(sshConn, b.socksServer.sshConfig)
	if err != nil {
		log.Printf("[Bridge] SSH handshake failed: %v", err)
		return
	}
	defer sshServer.Close()
	log.Printf("[Bridge] SSH handshake successful for: %s", sshServer.User())

	go ssh.DiscardRequests(reqs)

	// Handle channels
	for newChannel := range chans {
		if newChannel.ChannelType() != "session" {
			newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}

		channel, requests, err := newChannel.Accept()
		if err != nil {
			log.Printf("[Bridge] Could not accept channel: %v", err)
			continue
		}

		go func(requests <-chan *ssh.Request) {
			for req := range requests {
				req.Reply(req.Type == "shell", nil)
			}
		}(requests)

		// Get the connection ID
		connID := sshServer.User()
		log.Printf("[Bridge] Processing connection for user: %s", connID)

		b.mu.RLock()
		proxyConn, exists := b.connections[connID]
		b.mu.RUnlock()

		if !exists {
			log.Printf("[Bridge] No SOCKS connection found for ID: %s", connID)
			return
		}

		// Handle connection proxying
		targetConn, err := net.Dial("tcp", proxyConn.target)
		if err != nil {
			log.Printf("[Bridge] Failed to connect to target %s: %v", proxyConn.target, err)
			return
		}
		defer targetConn.Close()
		log.Printf("[Bridge] Successfully connected to target: %s", proxyConn.target)

		// Proxy data in both directions
		errCh := make(chan error, 2)

		// Client -> Target
		go func() {
			bytes, err := io.Copy(targetConn, channel)
			if err != nil {
				log.Printf("[Bridge] Error in client->target stream: %v", err)
				errCh <- err
			}
			log.Printf("[Bridge] Client->target stream closed, bytes transferred: %d", bytes)
			errCh <- nil
		}()

		// Target -> Client
		go func() {
			bytes, err := io.Copy(channel, targetConn)
			if err != nil {
				log.Printf("[Bridge] Error in target->client stream: %v", err)
				errCh <- err
			}
			log.Printf("[Bridge] Target->client stream closed, bytes transferred: %d", bytes)
			errCh <- nil
		}()

		// Wait for both goroutines to complete
		for i := 0; i < 2; i++ {
			if err := <-errCh; err != nil {
				log.Printf("[Bridge] Error in data transfer: %v", err)
			}
		}
		log.Printf("[Bridge] Connection closed for user: %s", connID)
	}
}

// RegisterSocksConnection registers a new SOCKS connection for proxying
func (b *Bridge) RegisterSocksConnection(id string, socksConn net.Conn, target string) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.connections[id] = &ProxyConn{
		socksConn: socksConn,
		target:    target,
	}
}

// UnregisterSocksConnection removes a SOCKS connection
func (b *Bridge) UnregisterSocksConnection(id string) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if conn, exists := b.connections[id]; exists {
		if conn.socksConn != nil {
			conn.socksConn.Close()
		}
		if conn.sshConn != nil {
			conn.sshConn.Close()
		}
		delete(b.connections, id)
	}
}

// Stop gracefully stops the bridge
func (b *Bridge) Stop() {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.sshListener != nil {
		b.sshListener.Close()
	}

	for id, conn := range b.connections {
		if conn.socksConn != nil {
			conn.socksConn.Close()
		}
		if conn.sshConn != nil {
			conn.sshConn.Close()
		}
		delete(b.connections, id)
	}
}
