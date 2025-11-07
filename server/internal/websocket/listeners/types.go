// internal/websocket/listeners/types.go
package listeners

import (
	"time"

	"github.com/google/uuid"
)

type Listener struct {
	ID       uuid.UUID
	Name     string
	Protocol string
	Port     int
	IP       string
	Active   bool
	Created  time.Time
}

type Message struct {
	Type string `json:"type"`
	Data struct {
		Name     string `json:"name"`
		Protocol string `json:"protocol"`
		Port     int    `json:"port"`
		Host     string `json:"host"`
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
	} `json:"data,omitempty"`
}
