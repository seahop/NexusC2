// internal/agent/listeners/types.go
package listeners

import "time"

// PostData represents the incoming POST request data structure
type PostData struct {
	Data      string            `json:"data"`
	Metadata  map[string]string `json:"metadata"`
	Timestamp int64             `json:"timestamp"`
}

// SignedResponse represents the response sent after initial handshake
type SignedResponse struct {
	Status             string `json:"status"`
	NewClientID        string `json:"new_client_id"`
	SecretsInitialized bool   `json:"secrets_initialized"`
	Signature          string `json:"signature"`
	Seed               string `json:"seed"`
}

// SystemInfo represents the received system information from agents
type SystemInfo struct {
	AgentInfo struct {
		PID         int       `json:"pid"`
		ProcessName string    `json:"process_name"`
		Username    string    `json:"username"`
		Hostname    string    `json:"hostname"`
		InternalIP  string    `json:"internal_ip"`
		Arch        string    `json:"architecture"`
		OS          string    `json:"os"`
		Timestamp   time.Time `json:"timestamp"`
		ClientID    string    `json:"client_id"`
		Seed        string    `json:"seed"`
	} `json:"agent_info"`
	Metadata map[string]string `json:"metadata"`
	Status   string            `json:"status"`
}
