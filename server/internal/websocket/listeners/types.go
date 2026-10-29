// internal/websocket/listeners/types.go
package listeners

import (
	"time"

	"github.com/google/uuid"
)

type Listener struct {
	ID                    uuid.UUID
	Name                  string
	Protocol              string
	Port                  int
	IP                    string
	PipeName              string   // For SMB listeners - the named pipe to listen on
	GetProfile            string   // Bound GET profile name (default)
	PostProfile           string   // Bound POST profile name (default)
	ServerResponseProfile string   // Bound server response profile name (default)
	SMBProfile            string   // Bound SMB profile name for transforms
	TCPProfile            string   // Bound TCP profile name for transforms
	Variants              []string // Supported profile variant names
	Active                bool
	Created               time.Time
}

type Message struct {
	Type string `json:"type"`
	Data struct {
		Name     string `json:"name"`
		Protocol string `json:"protocol"`
		Port     int    `json:"port"`
		Host     string `json:"host"`
		PipeName string `json:"pipe_name,omitempty"` // For SMB listeners
	} `json:"data"`
}

type Response struct {
	Status  string `json:"status"`
	Message string `json:"message"`
	Data    struct {
		ID       string `json:"id"`
		Name     string `json:"name"`
		Protocol string `json:"protocol"`
		Port     string `json:"port"`
		IP       string `json:"ip"`
		PipeName string `json:"pipe_name,omitempty"` // For SMB listeners
	} `json:"data,omitempty"`
}
