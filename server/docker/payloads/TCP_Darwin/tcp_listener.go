// server/docker/payloads/TCP_Linux/tcp_listener.go
// TCP socket listener for TCP agent

//go:build darwin
// +build darwin

package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

const (
	// TCP configuration
	tcpBufferSize    = 65536
	maxMessageSize   = 10 * 1024 * 1024 // 10MB max message size
	readTimeout      = 300 * time.Second
	writeTimeout     = 60 * time.Second
	keepAlivePeriod  = 30 * time.Second
)

// TCPListener manages a TCP server
type TCPListener struct {
	address  string
	listener net.Listener
	mu       sync.Mutex
	closed   bool
}

// TCPConnection represents a client connection
type TCPConnection struct {
	conn   net.Conn
	closed bool
	mu     sync.Mutex
}

// NewTCPListener creates a new TCP listener on the specified address
func NewTCPListener(address string) (*TCPListener, error) {
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return nil, fmt.Errorf(ErrCtx(E37, err.Error()))
	}

	return &TCPListener{
		address:  address,
		listener: listener,
	}, nil
}

// Accept waits for and accepts a new TCP connection
func (tl *TCPListener) Accept() (*TCPConnection, error) {
	tl.mu.Lock()
	if tl.closed {
		tl.mu.Unlock()
		return nil, fmt.Errorf(Err(E4))
	}
	listener := tl.listener
	tl.mu.Unlock()

	conn, err := listener.Accept()
	if err != nil {
		return nil, fmt.Errorf(ErrCtx(E12, err.Error()))
	}

	// Enable TCP keepalive
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(keepAlivePeriod)
	}

	return &TCPConnection{
		conn: conn,
	}, nil
}

// GetAddress returns the listening address
func (tl *TCPListener) GetAddress() string {
	return tl.address
}

// Close closes the TCP listener
func (tl *TCPListener) Close() error {
	tl.mu.Lock()
	defer tl.mu.Unlock()

	if tl.closed {
		return nil
	}

	tl.closed = true
	return tl.listener.Close()
}

// ReadMessage reads a length-prefixed message from the connection
// Protocol: 4-byte little-endian length + data
func (tc *TCPConnection) ReadMessage() ([]byte, error) {
	tc.mu.Lock()
	defer tc.mu.Unlock()

	if tc.closed {
		return nil, fmt.Errorf(Err(E4))
	}

	// Set read deadline
	tc.conn.SetReadDeadline(time.Now().Add(readTimeout))

	// Read 4-byte length header (little-endian)
	header := make([]byte, 4)
	if _, err := io.ReadFull(tc.conn, header); err != nil {
		return nil, fmt.Errorf(ErrCtx(E10, err.Error()))
	}

	length := binary.LittleEndian.Uint32(header)

	// Sanity check
	if length > maxMessageSize {
		return nil, fmt.Errorf(Err(E2))
	}

	// Read message body
	data := make([]byte, length)
	if _, err := io.ReadFull(tc.conn, data); err != nil {
		return nil, fmt.Errorf(ErrCtx(E10, err.Error()))
	}

	return data, nil
}

// WriteMessage writes a length-prefixed message to the connection
// Protocol: 4-byte little-endian length + data
func (tc *TCPConnection) WriteMessage(data []byte) error {
	tc.mu.Lock()
	defer tc.mu.Unlock()

	if tc.closed {
		return fmt.Errorf(Err(E4))
	}

	// Set write deadline
	tc.conn.SetWriteDeadline(time.Now().Add(writeTimeout))

	// Create length header (little-endian)
	header := make([]byte, 4)
	binary.LittleEndian.PutUint32(header, uint32(len(data)))

	// Write header
	if _, err := tc.conn.Write(header); err != nil {
		return fmt.Errorf(ErrCtx(E11, err.Error()))
	}

	// Write data
	if _, err := tc.conn.Write(data); err != nil {
		return fmt.Errorf(ErrCtx(E11, err.Error()))
	}

	return nil
}

// Close closes the TCP connection
func (tc *TCPConnection) Close() error {
	tc.mu.Lock()
	defer tc.mu.Unlock()

	if tc.closed {
		return nil
	}

	tc.closed = true
	return tc.conn.Close()
}

// RemoteAddr returns the remote address of the connection
func (tc *TCPConnection) RemoteAddr() string {
	if tc.conn != nil {
		return tc.conn.RemoteAddr().String()
	}
	return ""
}

// LocalAddr returns the local address of the connection
func (tc *TCPConnection) LocalAddr() string {
	if tc.conn != nil {
		return tc.conn.LocalAddr().String()
	}
	return ""
}
