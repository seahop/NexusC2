// server/docker/payloads/Linux/link_pipe_linux.go
// SMB named pipe connection for Linux using go-smb2 library

//go:build linux
// +build linux

package main

import (
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/hirochachacha/go-smb2"
)

// smbPipeConn wraps an SMB2 file handle as a net.Conn
type smbPipeConn struct {
	file     *smb2.File
	share    *smb2.Share
	session  *smb2.Session
	tcpConn  net.Conn
	pipePath string
	closed   bool
}

// SMBCredentials holds credentials for SMB authentication
type SMBCredentials struct {
	Domain   string
	User     string
	Password string
}

// dialPipe connects to a Windows named pipe via SMB2
// pipePath format: \\server\pipe\pipename
// creds can be nil for anonymous authentication
func dialPipe(pipePath string, creds *SMBCredentials) (net.Conn, error) {
	// Parse the pipe path to extract server and pipe name
	// Expected format: \\server\pipe\pipename
	server, pipeName, err := parsePipePath(pipePath)
	if err != nil {
		return nil, err
	}

	// Connect to SMB port (445)
	tcpConn, err := net.DialTimeout("tcp", server+":445", 30*time.Second)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to SMB server: %w", err)
	}

	// Set up credentials - use provided or fall back to anonymous
	user := ""
	password := ""
	domain := ""
	if creds != nil {
		user = creds.User
		password = creds.Password
		domain = creds.Domain
	}

	// Create SMB2 dialer with credentials
	d := &smb2.Dialer{
		Initiator: &smb2.NTLMInitiator{
			User:     user,
			Password: password,
			Domain:   domain,
		},
	}

	// Establish SMB2 session
	session, err := d.Dial(tcpConn)
	if err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("failed to establish SMB session: %w", err)
	}

	// Mount IPC$ share (required for named pipes)
	share, err := session.Mount("IPC$")
	if err != nil {
		session.Logoff()
		tcpConn.Close()
		return nil, fmt.Errorf("failed to mount IPC$ share: %w", err)
	}

	// Open the named pipe
	file, err := share.OpenFile(pipeName, os.O_RDWR, 0)
	if err != nil {
		share.Umount()
		session.Logoff()
		tcpConn.Close()
		return nil, fmt.Errorf("failed to open named pipe: %w", err)
	}

	return &smbPipeConn{
		file:     file,
		share:    share,
		session:  session,
		tcpConn:  tcpConn,
		pipePath: pipePath,
	}, nil
}

// parsePipePath extracts server and pipe name from UNC path
// Input: \\server\pipe\pipename or \\server\pipe\path\to\pipe
// Returns: server, pipename (everything after \pipe\)
func parsePipePath(pipePath string) (string, string, error) {
	// Remove leading backslashes
	path := strings.TrimPrefix(pipePath, "\\\\")

	// Split by backslash
	parts := strings.SplitN(path, "\\", 3)
	if len(parts) < 3 {
		return "", "", fmt.Errorf("invalid pipe path format: %s", pipePath)
	}

	server := parts[0]
	if strings.ToLower(parts[1]) != "pipe" {
		return "", "", fmt.Errorf("expected 'pipe' in path, got: %s", parts[1])
	}

	pipeName := parts[2]
	return server, pipeName, nil
}

// Read implements net.Conn
func (c *smbPipeConn) Read(b []byte) (int, error) {
	if c.closed {
		return 0, net.ErrClosed
	}
	return c.file.Read(b)
}

// Write implements net.Conn
func (c *smbPipeConn) Write(b []byte) (int, error) {
	if c.closed {
		return 0, net.ErrClosed
	}
	return c.file.Write(b)
}

// Close implements net.Conn
func (c *smbPipeConn) Close() error {
	if c.closed {
		return nil
	}
	c.closed = true

	var errs []error
	if c.file != nil {
		if err := c.file.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if c.share != nil {
		if err := c.share.Umount(); err != nil {
			errs = append(errs, err)
		}
	}
	if c.session != nil {
		if err := c.session.Logoff(); err != nil {
			errs = append(errs, err)
		}
	}
	if c.tcpConn != nil {
		if err := c.tcpConn.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		return errs[0]
	}
	return nil
}

// LocalAddr implements net.Conn
func (c *smbPipeConn) LocalAddr() net.Addr {
	if c.tcpConn != nil {
		return c.tcpConn.LocalAddr()
	}
	return pipeAddr{path: "local"}
}

// RemoteAddr implements net.Conn
func (c *smbPipeConn) RemoteAddr() net.Addr {
	return pipeAddr{path: c.pipePath}
}

// SetDeadline implements net.Conn
func (c *smbPipeConn) SetDeadline(t time.Time) error {
	if c.tcpConn != nil {
		return c.tcpConn.SetDeadline(t)
	}
	return nil
}

// SetReadDeadline implements net.Conn
func (c *smbPipeConn) SetReadDeadline(t time.Time) error {
	if c.tcpConn != nil {
		return c.tcpConn.SetReadDeadline(t)
	}
	return nil
}

// SetWriteDeadline implements net.Conn
func (c *smbPipeConn) SetWriteDeadline(t time.Time) error {
	if c.tcpConn != nil {
		return c.tcpConn.SetWriteDeadline(t)
	}
	return nil
}

// pipeAddr implements net.Addr for named pipes
type pipeAddr struct {
	path string
}

func (a pipeAddr) Network() string {
	return "smb-pipe"
}

func (a pipeAddr) String() string {
	return a.path
}

// performLinkAuth performs authentication with an SMB agent
// This mirrors the Windows implementation
func performLinkAuth(conn net.Conn) error {
	// Set deadline for auth
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	defer conn.SetDeadline(time.Time{}) // Clear deadline

	// Read challenge
	challenge, err := readMessage(conn)
	if err != nil {
		return fmt.Errorf(ErrCtx(E10, err.Error()))
	}

	// Simple challenge-response (matches Windows implementation)
	response := append([]byte(lmAuthPrefix), challenge...)

	if err := writeMessage(conn, response); err != nil {
		return fmt.Errorf(ErrCtx(E11, err.Error()))
	}

	// Read confirmation
	confirm, err := readMessage(conn)
	if err != nil {
		return fmt.Errorf(ErrCtx(E10, err.Error()))
	}

	if string(confirm) != lmAuthOK {
		return fmt.Errorf(Err(E3))
	}

	return nil
}

// connectToPipe wraps dialPipe with retry logic
// creds can be nil for anonymous authentication
func connectToPipe(pipePath string, creds *SMBCredentials) (net.Conn, error) {
	timeout := 30 * time.Second
	deadline := time.Now().Add(timeout)

	var lastErr error
	for time.Now().Before(deadline) {
		conn, err := dialPipe(pipePath, creds)
		if err == nil {
			return conn, nil
		}
		lastErr = err
		time.Sleep(100 * time.Millisecond)
	}

	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf(Err(E9))
}
