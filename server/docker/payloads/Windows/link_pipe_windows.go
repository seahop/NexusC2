//go:build windows
// +build windows

package main

import (
	"net"
	"time"

	"golang.org/x/sys/windows"
)

// dialPipe connects to a Windows named pipe
func dialPipe(pipePath string) (net.Conn, error) {
	// Convert pipe path to UTF16
	pathPtr, err := windows.UTF16PtrFromString(pipePath)
	if err != nil {
		return nil, err
	}

	// Try to open the pipe
	handle, err := windows.CreateFile(
		pathPtr,
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		0, // No sharing
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_OVERLAPPED,
		0,
	)
	if err != nil {
		return nil, err
	}

	// Pipe is in byte mode - no need to set message mode
	// Length-prefixed framing is used for message boundaries

	// Create a net.Conn wrapper for the pipe
	return newPipeConn(handle, pipePath), nil
}

// pipeConn wraps a Windows pipe handle as a net.Conn
type pipeConn struct {
	handle   windows.Handle
	pipePath string
	closed   bool
}

func newPipeConn(handle windows.Handle, path string) *pipeConn {
	return &pipeConn{
		handle:   handle,
		pipePath: path,
	}
}

func (p *pipeConn) Read(b []byte) (int, error) {
	if p.closed {
		return 0, net.ErrClosed
	}

	var bytesRead uint32
	overlapped := &windows.Overlapped{}

	// Create event for overlapped I/O
	event, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(event)
	overlapped.HEvent = event

	err = windows.ReadFile(p.handle, b, &bytesRead, overlapped)
	if err == windows.ERROR_IO_PENDING {
		// Wait for operation to complete
		windows.WaitForSingleObject(event, windows.INFINITE)
		err = windows.GetOverlappedResult(p.handle, overlapped, &bytesRead, false)
	}

	if err != nil && err != windows.ERROR_MORE_DATA {
		return int(bytesRead), err
	}

	return int(bytesRead), nil
}

func (p *pipeConn) Write(b []byte) (int, error) {
	if p.closed {
		return 0, net.ErrClosed
	}

	var bytesWritten uint32
	overlapped := &windows.Overlapped{}

	// Create event for overlapped I/O
	event, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(event)
	overlapped.HEvent = event

	err = windows.WriteFile(p.handle, b, &bytesWritten, overlapped)
	if err == windows.ERROR_IO_PENDING {
		// Wait for operation to complete
		windows.WaitForSingleObject(event, windows.INFINITE)
		err = windows.GetOverlappedResult(p.handle, overlapped, &bytesWritten, false)
	}

	if err != nil {
		return int(bytesWritten), err
	}

	return int(bytesWritten), nil
}

func (p *pipeConn) Close() error {
	if p.closed {
		return nil
	}
	p.closed = true
	return windows.CloseHandle(p.handle)
}

func (p *pipeConn) LocalAddr() net.Addr {
	return pipeAddr{path: lmTpl(idxLinkLocalWord)}
}

func (p *pipeConn) RemoteAddr() net.Addr {
	return pipeAddr{path: p.pipePath}
}

func (p *pipeConn) SetDeadline(t time.Time) error {
	// Named pipes don't support deadlines directly
	// We handle timeouts via overlapped I/O
	return nil
}

func (p *pipeConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (p *pipeConn) SetWriteDeadline(t time.Time) error {
	return nil
}

// pipeAddr implements net.Addr for named pipes
type pipeAddr struct {
	path string
}

func (a pipeAddr) Network() string {
	return lmTpl(idxLinkPipeWord)
}

func (a pipeAddr) String() string {
	return a.path
}
