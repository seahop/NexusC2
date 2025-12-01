// internal/websocket/handlers/types.go
package handlers

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/gorilla/websocket"
)

// Log levels for controlling output verbosity
const (
	LOG_MINIMAL = iota
	LOG_NORMAL
	LOG_VERBOSE
)

var logLevel = LOG_MINIMAL

func logMessage(level int, format string, args ...interface{}) {
	if level <= logLevel {
		log.Printf(format, args...)
	}
}

// Message represents a WebSocket message
type Message struct {
	Type    string      `json:"type"`
	Command string      `json:"command"`
	Data    interface{} `json:"data"`
}

// Response represents a WebSocket response
type Response struct {
	Type    string      `json:"type"`
	Status  string      `json:"status"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// DownloadInfo represents file download information
type DownloadInfo struct {
	ID        int       `json:"id"`
	Filename  string    `json:"filename"`
	Size      int64     `json:"size"`
	Timestamp time.Time `json:"timestamp"`
}

// DBOperationError represents a database operation error
type DBOperationError struct {
	Operation string
	Err       error
}

func (e *DBOperationError) Error() string {
	return fmt.Sprintf("database operation '%s' failed: %v", e.Operation, e.Err)
}

// StateExport represents the complete state export
type StateExport struct {
	Connections    []Connection     `json:"connections"`
	Commands       []Command        `json:"commands"`
	CommandOutputs []CommandOutput  `json:"command_outputs"`
	Listeners      []Listener       `json:"listeners"`
	AgentTags      map[string][]Tag `json:"agent_tags"` // Map of agent_guid -> tags
}

// Connection represents a connection record
type Connection struct {
	NewclientID string       `json:"newclient_id"`
	ClientID    string       `json:"client_id"`
	Protocol    string       `json:"protocol"`
	Secret1     string       `json:"secret1"`
	Secret2     string       `json:"secret2"`
	ExtIP       string       `json:"ext_ip"`
	IntIP       string       `json:"int_ip"`
	Username    string       `json:"username"`
	Hostname    string       `json:"hostname"`
	Note        string       `json:"note"`
	Process     string       `json:"process"`
	PID         string       `json:"pid"`
	Arch        string       `json:"arch"`
	LastSeen    time.Time    `json:"last_seen"`
	OS          string       `json:"os"`
	Proto       string       `json:"proto"`
	DeletedAt   sql.NullTime `json:"deleted_at"`
	Alias       *string      `json:"alias,omitempty"`
}

// Command represents a command record
type Command struct {
	ID        int       `json:"id"`
	Username  string    `json:"username"`
	GUID      string    `json:"guid"`
	Command   string    `json:"command"`
	Timestamp time.Time `json:"timestamp"`
}

// CommandOutput represents command output
type CommandOutput struct {
	ID        int       `json:"id"`
	CommandID int       `json:"command_id"`
	Output    string    `json:"output"`
	Timestamp time.Time `json:"timestamp"`
}

// Listener represents a listener configuration
type Listener struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Protocol string `json:"protocol"`
	Port     string `json:"port"`
	IP       string `json:"ip"`
}

// messageJob represents a message processing job
type messageJob struct {
	content string
	msgType string // Track the message type
}

// WebSocket upgrader configuration
var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024 * 1024 * 4, // 4MB read buffer
	WriteBufferSize: 1024 * 1024 * 4, // 4MB write buffer
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

// generateID generates a unique ID based on timestamp
func generateID() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}
