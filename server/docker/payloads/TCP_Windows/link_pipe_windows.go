//go:build windows
// +build windows

package main

import (
	"net"
	"time"

	"golang.org/x/sys/windows"
)

// dialPipe connects to a Windows named pipe (for connecting to other SMB agents)
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

	// Set pipe mode to message mode
	var mode uint32 = windows.PIPE_READMODE_MESSAGE
	err = windows.SetNamedPipeHandleState(handle, &mode, nil, nil)
	if err != nil {
		windows.CloseHandle(handle)
		return nil, err
	}

	// Create a net.Conn wrapper for the pipe
	return newPipeClientConn(handle, pipePath), nil
}

// pipeClientConn wraps a Windows pipe handle as a net.Conn (for outbound connections)
type pipeClientConn struct {
	handle   windows.Handle
	pipePath string
	closed   bool
}

func newPipeClientConn(handle windows.Handle, path string) *pipeClientConn {
	return &pipeClientConn{
		handle:   handle,
		pipePath: path,
	}
}

func (p *pipeClientConn) Read(b []byte) (int, error) {
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

func (p *pipeClientConn) Write(b []byte) (int, error) {
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

func (p *pipeClientConn) Close() error {
	if p.closed {
		return nil
	}
	p.closed = true
	return windows.CloseHandle(p.handle)
}

func (p *pipeClientConn) LocalAddr() net.Addr {
	return pipeClientAddr{path: "local"}
}

func (p *pipeClientConn) RemoteAddr() net.Addr {
	return pipeClientAddr{path: p.pipePath}
}

func (p *pipeClientConn) SetDeadline(t time.Time) error {
	// Named pipes don't support deadlines directly
	// We handle timeouts via overlapped I/O
	return nil
}

func (p *pipeClientConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (p *pipeClientConn) SetWriteDeadline(t time.Time) error {
	return nil
}

// pipeClientAddr implements net.Addr for named pipes
type pipeClientAddr struct {
	path string
}

func (a pipeClientAddr) Network() string {
	return "pipe"
}

func (a pipeClientAddr) String() string {
	return a.path
}
