// internal/common/types/types.go
package types

import (
	"encoding/json"

	"github.com/google/uuid"
)

// Base message structure
type Message struct {
	Type string          `json:"type"`
	Data json.RawMessage `json:"data"`
}

// Listener related types
type ListenerConfig struct {
	Name     string `json:"name"`
	Protocol string `json:"protocol"`
	Port     int    `json:"port"`
	Host     string `json:"host"`
}

type Listener struct {
	ID       uuid.UUID `json:"id"`
	Name     string    `json:"name"`
	Protocol string    `json:"protocol"`
	Port     int       `json:"port"`
	IP       string    `json:"ip"`
}

// Response types
type Response struct {
	Status  string      `json:"status"`
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
}

// Command types (for future expansion)
type CommandRequest struct {
	AgentID string   `json:"agent_id"`
	Command string   `json:"command"`
	Args    []string `json:"args,omitempty"`
}

type CommandResponse struct {
	AgentID   string `json:"agent_id"`
	Output    string `json:"output"`
	ExitCode  int    `json:"exit_code"`
	Timestamp string `json:"timestamp"`
}
