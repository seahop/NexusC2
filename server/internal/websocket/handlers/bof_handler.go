// internal/websocket/handlers/bof_handler.go
package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// processBOFAsyncStatus processes BOF async status messages
func (h *WSHandler) processBOFAsyncStatus(resultData map[string]interface{}) {
	agentID, _ := resultData["agent_id"].(string)
	jobID, _ := resultData["job_id"].(string)
	status, _ := resultData["status"].(string)
	message, _ := resultData["message"].(string)

	messageSize := len(message)
	logMessage(LOG_MINIMAL, "[BOF Async] Agent=%s, Job=%s, Status=%s, Size=%d bytes",
		agentID, jobID, status, messageSize)

	// For large BOF async outputs, stream them
	if status == "BOF_ASYNC_OUTPUT" && messageSize > 10240 {
		h.streamBOFAsyncOutput(agentID, jobID, status, message)
		return
	}

	// Map status to WebSocket message type
	wsMessageType := h.mapBOFStatusToWSType(status)

	// Create and broadcast the message
	wsMsg := struct {
		Type string `json:"type"`
		Data struct {
			AgentID string `json:"agent_id"`
			JobID   string `json:"job_id"`
			Status  string `json:"status"`
			Message string `json:"message,omitempty"`
			Output  string `json:"output,omitempty"`
			Error   string `json:"error,omitempty"`
		} `json:"data"`
	}{
		Type: wsMessageType,
	}

	wsMsg.Data.AgentID = agentID
	wsMsg.Data.JobID = jobID

	// Set appropriate fields based on status
	switch status {
	case "BOF_ASYNC_CRASHED":
		wsMsg.Data.Error = message
	case "BOF_ASYNC_OUTPUT", "BOF_ASYNC_COMPLETED":
		wsMsg.Data.Output = message
	default:
		wsMsg.Data.Message = message
	}

	if wsJSON, err := json.Marshal(wsMsg); err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		h.hub.BroadcastToAll(ctx, wsJSON)
		cancel()
	}
}

// mapBOFStatusToWSType maps BOF status to WebSocket message type
func (h *WSHandler) mapBOFStatusToWSType(status string) string {
	switch status {
	case "BOF_ASYNC_STARTED":
		return "bof_async_started"
	case "BOF_ASYNC_COMPLETED":
		return "bof_async_completed"
	case "BOF_ASYNC_CRASHED":
		return "bof_async_crashed"
	case "BOF_ASYNC_KILLED":
		return "bof_async_killed"
	case "BOF_ASYNC_OUTPUT":
		return "bof_async_output"
	case "BOF_ASYNC_TIMEOUT":
		return "bof_async_timeout"
	default:
		return "bof_output"
	}
}

// streamBOFAsyncOutput streams large BOF async output
func (h *WSHandler) streamBOFAsyncOutput(agentID, jobID, status, output string) {
	const maxChunkSize = 8192 // 8KB chunks
	totalSize := len(output)
	totalChunks := (totalSize + maxChunkSize - 1) / maxChunkSize

	sessionID := fmt.Sprintf("bof-%s-%s-%d", agentID, jobID, time.Now().UnixNano())

	logMessage(LOG_MINIMAL, "Streaming BOF output: %d chunks for agent=%s, job=%s",
		totalChunks, agentID, jobID)

	// Send start notification
	startMsg := struct {
		Type string `json:"type"`
		Data struct {
			SessionID   string `json:"session_id"`
			AgentID     string `json:"agent_id"`
			JobID       string `json:"job_id"`
			TotalChunks int    `json:"total_chunks"`
			TotalSize   int    `json:"total_size"`
			Status      string `json:"status"`
		} `json:"data"`
	}{
		Type: "bof_output_chunk_start",
	}
	startMsg.Data.SessionID = sessionID
	startMsg.Data.AgentID = agentID
	startMsg.Data.JobID = jobID
	startMsg.Data.TotalChunks = totalChunks
	startMsg.Data.TotalSize = totalSize
	startMsg.Data.Status = status

	if startJSON, err := json.Marshal(startMsg); err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		h.hub.BroadcastToAll(ctx, startJSON)
		cancel()
	}

	// Stream chunks with rate limiting
	go h.streamChunksWithRateLimit(sessionID, agentID, jobID, output, totalChunks, maxChunkSize, "bof")
}
