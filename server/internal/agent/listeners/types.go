// internal/agent/listeners/types.go
package listeners

import "time"

// PostData represents the incoming POST request data structure
type PostData struct {
	Data      string            `json:"data"`
	Metadata  map[string]string `json:"md"`
	Timestamp int64             `json:"ts"`
}

// SignedResponse represents the response sent after initial handshake
type SignedResponse struct {
	Status             string `json:"st"`
	NewClientID        string `json:"nc"`
	SecretsInitialized bool   `json:"si"`
	Signature          string `json:"sg"`
	Seed               string `json:"seed"`
	CommsTemplate      string `json:"ct,omitempty"` // Base64-encoded comms template
	ExecReqTemplate    string `json:"et,omitempty"` // Base64-encoded exec requirements template
}

// SystemInfo represents the received system information from agents
type SystemInfo struct {
	AgentInfo struct {
		PID         int       `json:"pid"`
		ProcessName string    `json:"pn"`
		Username    string    `json:"un"`
		Hostname    string    `json:"hn"`
		InternalIP  string    `json:"ip"`
		Arch        string    `json:"ac"`
		OS          string    `json:"os"`
		Timestamp   time.Time `json:"ts"`
		ClientID    string    `json:"cl"`
		Seed        string    `json:"seed"`
	} `json:"ag"`
	Metadata map[string]string `json:"md"`
	Status   string            `json:"st"`
}
