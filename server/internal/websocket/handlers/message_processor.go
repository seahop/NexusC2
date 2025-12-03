// internal/websocket/handlers/message_processor.go
package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"time"

	pb "c2/proto"
)

// messageWorker processes messages from the work queue
func (h *WSHandler) messageWorker() {
	defer h.workerWg.Done()

	for job := range h.resultWorkers {
		h.processMessageJob(job)
	}
}

// processMessageJob processes a single message job based on type
func (h *WSHandler) processMessageJob(job messageJob) {
	contentSize := len(job.content)

	// Log minimal info about the job
	logMessage(LOG_MINIMAL, "Processing %s message, size: %d bytes", job.msgType, contentSize)

	switch job.msgType {
	case "command_result":
		h.processCommandResult(job.content)
	case "agent_update":
		h.processAgentUpdate(job.content)
	case "new_connection":
		h.processNewConnection(job.content)
	case "agent_checkin":
		h.processAgentCheckin(job.content)
	default:
		// Generic processing for other large messages
		h.processGenericMessage(job.msgType, job.content)
	}
}

// processCommandResult processes command result messages
func (h *WSHandler) processCommandResult(content string) {
	var resultData map[string]interface{}
	if err := json.Unmarshal([]byte(content), &resultData); err != nil {
		logMessage(LOG_NORMAL, "Failed to unmarshal command_result: %v", err)
		return
	}

	// Extract basic info for logging
	agentID, _ := resultData["agent_id"].(string)
	commandID := 0
	if cmdID, ok := resultData["command_id"].(float64); ok {
		commandID = int(cmdID)
	}

	// Check for special message types first
	if msgType, ok := resultData["type"].(string); ok && msgType == "bof_async_status" {
		h.processBOFAsyncStatus(resultData)
		return
	}

	// Check if output exists and needs chunking
	if output, ok := resultData["output"].(string); ok {
		outputSize := len(output)

		// Log size only, never content
		logMessage(LOG_MINIMAL, "Command result: agent=%s, cmd=%d, size=%d bytes",
			agentID, commandID, outputSize)

		// Lower threshold to 10KB for aggressive chunking
		const chunkThreshold = 10240 // 10KB

		if outputSize > chunkThreshold {
			// Stream large outputs
			go h.streamChunkedOutput(resultData, output)
			return
		}

		// For smaller outputs, check for special cases (without logging content)
		// Check patterns without logging the actual content
		if h.isSpecialOutput(output) {
			h.processSpecialOutput(resultData, output)
			return
		}
	}

	// For normal outputs, broadcast the result
	h.broadcastMessage("command_result", resultData)
}

// isSpecialOutput checks if output is a special type (without logging content)
func (h *WSHandler) isSpecialOutput(output string) bool {
	specialPatterns := []string{
		"[+] Assembly executed",
		"[*] Assembly type:",
		"Active BOF Jobs",
		"No active BOF jobs",
		"Output for job",
		"Job not found",
	}

	for _, pattern := range specialPatterns {
		if strings.Contains(output, pattern) {
			return true
		}
	}
	return false
}

// processSpecialOutput processes special output types
func (h *WSHandler) processSpecialOutput(resultData map[string]interface{}, output string) {
	agentID, _ := resultData["agent_id"].(string)

	// Determine the type based on content patterns
	var wsType string
	if strings.Contains(output, "[+] Assembly executed") ||
		strings.Contains(output, "[*] Assembly type:") {
		wsType = "command_result" // Keep as command_result for inline-assembly
	} else if strings.Contains(output, "Active BOF Jobs") ||
		strings.Contains(output, "No active BOF jobs") {
		wsType = "bof_jobs_list"
	} else if strings.Contains(output, "Output for job") ||
		strings.Contains(output, "Job not found") {
		wsType = "bof_output"
	} else {
		wsType = "command_result"
	}

	wsMsg := struct {
		Type string                 `json:"type"`
		Data map[string]interface{} `json:"data"`
	}{
		Type: wsType,
		Data: resultData,
	}

	if wsJSON, err := json.Marshal(wsMsg); err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		h.hub.BroadcastToAll(ctx, wsJSON)
		cancel()
	}

	logMessage(LOG_NORMAL, "Processed special output type: %s for agent: %s", wsType, agentID)
}

// processAgentUpdate processes agent update messages
func (h *WSHandler) processAgentUpdate(content string) {
	var agentData struct {
		Event    string `json:"event"`
		AgentID  string `json:"agent_id"`
		Username string `json:"username"`
	}

	if err := json.Unmarshal([]byte(content), &agentData); err != nil {
		logMessage(LOG_NORMAL, "Failed to unmarshal agent_update message: %v", err)
		return
	}

	logMessage(LOG_MINIMAL, "Agent update: event=%s, agent=%s", agentData.Event, agentData.AgentID)

	// Forward to all websocket clients
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	h.hub.BroadcastToAll(ctx, []byte(content))
	cancel()
}

// processNewConnection processes new connection messages
func (h *WSHandler) processNewConnection(content string) {
	var connData struct {
		NewClientID    string `json:"new_client_id"`
		ClientID       string `json:"client_id"`
		Protocol       string `json:"protocol"`
		ExtIP          string `json:"ext_ip"`
		IntIP          string `json:"int_ip"`
		Username       string `json:"username"`
		Hostname       string `json:"hostname"`
		Process        string `json:"process"`
		PID            string `json:"pid"`
		Arch           string `json:"arch"`
		OS             string `json:"os"`
		LastSeen       int64  `json:"last_seen"`
		ParentClientID string `json:"parent_client_id,omitempty"` // For linked agents
		LinkType       string `json:"link_type,omitempty"`        // Link type (e.g., "smb")
	}

	if err := json.Unmarshal([]byte(content), &connData); err != nil {
		logMessage(LOG_NORMAL, "Failed to unmarshal new_connection message: %v", err)
		return
	}

	if connData.ParentClientID != "" {
		logMessage(LOG_MINIMAL, "New linked connection: %s from %s (parent: %s, type: %s)",
			connData.NewClientID, connData.Hostname, connData.ParentClientID, connData.LinkType)
	} else {
		logMessage(LOG_MINIMAL, "New connection: %s from %s", connData.NewClientID, connData.Hostname)
	}

	// Look up any existing alias for this agent
	var alias sql.NullString
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	h.db.QueryRowContext(ctx,
		"SELECT alias FROM agent_aliases WHERE guid = $1",
		connData.NewClientID,
	).Scan(&alias)
	cancel()

	// If alias exists, add it to the connection data before broadcasting
	if alias.Valid {
		// Convert to map to add the alias field
		connMap := make(map[string]interface{})
		connJSON, _ := json.Marshal(connData)
		json.Unmarshal(connJSON, &connMap)
		connMap["alias"] = alias.String

		// Re-marshal with alias and update content
		if newContent, err := json.Marshal(connMap); err == nil {
			content = string(newContent)
		}
	}

	connNotification := &pb.ConnectionNotification{
		NewClientId:    connData.NewClientID,
		ClientId:       connData.ClientID,
		Protocol:       connData.Protocol,
		ExtIp:          connData.ExtIP,
		IntIp:          connData.IntIP,
		Username:       connData.Username,
		Hostname:       connData.Hostname,
		Process:        connData.Process,
		Pid:            connData.PID,
		Arch:           connData.Arch,
		Os:             connData.OS,
		LastSeen:       connData.LastSeen,
		ParentClientId: connData.ParentClientID,
		LinkType:       connData.LinkType,
	}

	h.hub.HandleNewConnection(connNotification)
}

// processAgentCheckin processes agent checkin messages
func (h *WSHandler) processAgentCheckin(content string) {
	logMessage(LOG_NORMAL, "Processing agent checkin")

	// Forward checkin messages with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	h.hub.BroadcastToAll(ctx, []byte(content))
	cancel()
}

// processGenericMessage processes generic messages
func (h *WSHandler) processGenericMessage(msgType, content string) {
	contentSize := len(content)

	logMessage(LOG_MINIMAL, "Processing generic %s message, size: %d bytes", msgType, contentSize)

	// For large generic messages, consider chunking
	if contentSize > 10240 {
		// Parse to get basic info
		var msgData map[string]interface{}
		if err := json.Unmarshal([]byte(content), &msgData); err == nil {
			// Try to extract identifying info
			agentID, _ := msgData["agent_id"].(string)

			// Stream as generic large message
			h.streamGenericLargeMessage(msgType, agentID, content)
			return
		}
	}

	// Small messages, broadcast directly
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	h.hub.BroadcastToAll(ctx, []byte(content))
	cancel()
}

// broadcastMessage helper function to broadcast messages
func (h *WSHandler) broadcastMessage(msgType string, data interface{}) {
	wsMsg := struct {
		Type string      `json:"type"`
		Data interface{} `json:"data"`
	}{
		Type: msgType,
		Data: data,
	}

	if wsJSON, err := json.Marshal(wsMsg); err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		h.hub.BroadcastToAll(ctx, wsJSON)
		cancel()
	}
}
