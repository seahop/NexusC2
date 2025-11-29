// internal/websocket/handlers/streaming.go
package handlers

import (
	"bytes"
	"c2/internal/websocket/pool"
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// streamChunkedOutput streams chunked output for regular commands
func (h *WSHandler) streamChunkedOutput(resultData map[string]interface{}, output string) {
	agentID, _ := resultData["agent_id"].(string)
	commandID := 0
	if cmdID, ok := resultData["command_id"].(float64); ok {
		commandID = int(cmdID)
	}
	timestamp, _ := resultData["timestamp"].(string)
	status, _ := resultData["status"].(string)

	// Smaller chunks for streaming
	const maxChunkSize = 8192 // 8KB chunks
	totalSize := len(output)
	totalChunks := (totalSize + maxChunkSize - 1) / maxChunkSize

	sessionID := fmt.Sprintf("%s-%d-%d", agentID, commandID, time.Now().UnixNano())

	logMessage(LOG_MINIMAL, "Streaming %d chunks for agent=%s, cmd=%d",
		totalChunks, agentID, commandID)

	// Send start notification
	startMsg := struct {
		Type string `json:"type"`
		Data struct {
			SessionID   string `json:"session_id"`
			AgentID     string `json:"agent_id"`
			CommandID   int    `json:"command_id"`
			TotalChunks int    `json:"total_chunks"`
			TotalSize   int    `json:"total_size"`
			Timestamp   string `json:"timestamp"`
			Status      string `json:"status"`
		} `json:"data"`
	}{
		Type: "command_output_chunk_start",
	}
	startMsg.Data.SessionID = sessionID
	startMsg.Data.AgentID = agentID
	startMsg.Data.CommandID = commandID
	startMsg.Data.TotalChunks = totalChunks
	startMsg.Data.TotalSize = totalSize
	startMsg.Data.Timestamp = timestamp
	startMsg.Data.Status = status

	// Use buffer pool for JSON encoding
	bufPool := pool.GetBufferPool()
	buf := bufPool.Get(4096)
	defer bufPool.Put(buf)

	encoder := json.NewEncoder(bytes.NewBuffer((*buf)[:0]))
	if err := encoder.Encode(startMsg); err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		h.hub.BroadcastToAll(ctx, *buf)
		cancel()
	}

	// Stream chunks with rate limiting
	extraData := map[string]interface{}{
		"command_id": commandID,
	}
	go h.streamChunksWithRateLimit(sessionID, agentID, "", output, totalChunks, maxChunkSize, "command", extraData)
}

// streamChunksWithRateLimit generically streams chunks with rate limiting
func (h *WSHandler) streamChunksWithRateLimit(sessionID, agentID, jobID, output string,
	totalChunks, maxChunkSize int, outputType string, extraData ...map[string]interface{}) {

	// Rate limiter - max 100 chunks per second
	rateLimiter := time.NewTicker(10 * time.Millisecond)
	defer rateLimiter.Stop()

	// Get buffer pool for JSON encoding
	bufPool := pool.GetBufferPool()

	totalSize := len(output)

	for i := 0; i < totalChunks; i++ {
		<-rateLimiter.C // Wait for rate limit

		start := i * maxChunkSize
		end := start + maxChunkSize
		if end > totalSize {
			end = totalSize
		}

		chunk := output[start:end]

		// Build chunk message based on type
		var chunkMsg interface{}

		if outputType == "bof" {
			msg := struct {
				Type string `json:"type"`
				Data struct {
					SessionID   string `json:"session_id"`
					AgentID     string `json:"agent_id"`
					JobID       string `json:"job_id"`
					ChunkNumber int    `json:"chunk_number"`
					TotalChunks int    `json:"total_chunks"`
					ChunkData   string `json:"chunk_data"`
					ChunkSize   int    `json:"chunk_size"`
				} `json:"data"`
			}{
				Type: "bof_output_chunk",
			}
			msg.Data.SessionID = sessionID
			msg.Data.AgentID = agentID
			msg.Data.JobID = jobID
			msg.Data.ChunkNumber = i
			msg.Data.TotalChunks = totalChunks
			msg.Data.ChunkData = chunk
			msg.Data.ChunkSize = len(chunk)
			chunkMsg = msg
		} else {
			msg := struct {
				Type string `json:"type"`
				Data struct {
					SessionID   string `json:"session_id"`
					AgentID     string `json:"agent_id"`
					CommandID   int    `json:"command_id"`
					ChunkNumber int    `json:"chunk_number"`
					TotalChunks int    `json:"total_chunks"`
					ChunkData   string `json:"chunk_data"`
					ChunkSize   int    `json:"chunk_size"`
				} `json:"data"`
			}{
				Type: "command_output_chunk",
			}
			msg.Data.SessionID = sessionID
			msg.Data.AgentID = agentID
			if len(extraData) > 0 {
				if cmdID, ok := extraData[0]["command_id"].(int); ok {
					msg.Data.CommandID = cmdID
				}
			}
			msg.Data.ChunkNumber = i
			msg.Data.TotalChunks = totalChunks
			msg.Data.ChunkData = chunk
			msg.Data.ChunkSize = len(chunk)
			chunkMsg = msg
		}

		// Use buffer pool for encoding
		buf := bufPool.Get(16384) // 16KB buffer for chunk messages
		encoder := json.NewEncoder(bytes.NewBuffer((*buf)[:0]))
		if err := encoder.Encode(chunkMsg); err == nil {
			ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
			h.hub.BroadcastToAll(ctx, *buf)
			cancel()
		}
		bufPool.Put(buf)

		// Log progress every 10 chunks
		if (i+1)%10 == 0 || i == totalChunks-1 {
			logMessage(LOG_NORMAL, "Streamed %d/%d chunks for session %s",
				i+1, totalChunks, sessionID)
		}
	}

	// Send completion message
	var completeMsg interface{}

	if outputType == "bof" {
		msg := struct {
			Type string `json:"type"`
			Data struct {
				SessionID   string `json:"session_id"`
				AgentID     string `json:"agent_id"`
				JobID       string `json:"job_id"`
				TotalChunks int    `json:"total_chunks"`
				TotalSize   int    `json:"total_size"`
			} `json:"data"`
		}{
			Type: "bof_output_chunk_complete",
		}
		msg.Data.SessionID = sessionID
		msg.Data.AgentID = agentID
		msg.Data.JobID = jobID
		msg.Data.TotalChunks = totalChunks
		msg.Data.TotalSize = totalSize
		completeMsg = msg
	} else {
		msg := struct {
			Type string `json:"type"`
			Data struct {
				SessionID   string `json:"session_id"`
				AgentID     string `json:"agent_id"`
				CommandID   int    `json:"command_id"`
				TotalChunks int    `json:"total_chunks"`
				TotalSize   int    `json:"total_size"`
				Status      string `json:"status"`
			} `json:"data"`
		}{
			Type: "command_output_chunk_complete",
		}
		msg.Data.SessionID = sessionID
		msg.Data.AgentID = agentID
		if len(extraData) > 0 {
			if cmdID, ok := extraData[0]["command_id"].(int); ok {
				msg.Data.CommandID = cmdID
			}
		}
		msg.Data.TotalChunks = totalChunks
		msg.Data.TotalSize = totalSize
		msg.Data.Status = "completed"
		completeMsg = msg
	}

	if completeJSON, err := json.Marshal(completeMsg); err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		h.hub.BroadcastToAll(ctx, completeJSON)
		cancel()
	}

	logMessage(LOG_MINIMAL, "Completed streaming %d chunks for session %s", totalChunks, sessionID)
}

// streamGenericLargeMessage streams generic large messages
func (h *WSHandler) streamGenericLargeMessage(msgType, identifier, content string) {
	const maxChunkSize = 8192
	totalSize := len(content)
	totalChunks := (totalSize + maxChunkSize - 1) / maxChunkSize

	sessionID := fmt.Sprintf("%s-%s-%d", msgType, identifier, time.Now().UnixNano())

	logMessage(LOG_MINIMAL, "Streaming generic %s message: %d chunks, %d bytes",
		msgType, totalChunks, totalSize)

	// Send start notification
	startMsg := struct {
		Type string `json:"type"`
		Data struct {
			SessionID   string `json:"session_id"`
			MessageType string `json:"message_type"`
			Identifier  string `json:"identifier"`
			TotalChunks int    `json:"total_chunks"`
			TotalSize   int    `json:"total_size"`
		} `json:"data"`
	}{
		Type: "generic_message_chunk_start",
	}
	startMsg.Data.SessionID = sessionID
	startMsg.Data.MessageType = msgType
	startMsg.Data.Identifier = identifier
	startMsg.Data.TotalChunks = totalChunks
	startMsg.Data.TotalSize = totalSize

	if startJSON, err := json.Marshal(startMsg); err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		h.hub.BroadcastToAll(ctx, startJSON)
		cancel()
	}

	// Stream chunks
	rateLimiter := time.NewTicker(10 * time.Millisecond)
	defer rateLimiter.Stop()

	for i := 0; i < totalChunks; i++ {
		<-rateLimiter.C

		start := i * maxChunkSize
		end := start + maxChunkSize
		if end > totalSize {
			end = totalSize
		}

		chunk := content[start:end]

		chunkMsg := struct {
			Type string `json:"type"`
			Data struct {
				SessionID   string `json:"session_id"`
				ChunkNumber int    `json:"chunk_number"`
				TotalChunks int    `json:"total_chunks"`
				ChunkData   string `json:"chunk_data"`
				ChunkSize   int    `json:"chunk_size"`
			} `json:"data"`
		}{
			Type: "generic_message_chunk",
		}
		chunkMsg.Data.SessionID = sessionID
		chunkMsg.Data.ChunkNumber = i
		chunkMsg.Data.TotalChunks = totalChunks
		chunkMsg.Data.ChunkData = chunk
		chunkMsg.Data.ChunkSize = len(chunk)

		if chunkJSON, err := json.Marshal(chunkMsg); err == nil {
			ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
			h.hub.BroadcastToAll(ctx, chunkJSON)
			cancel()
		}
	}

	// Send completion
	completeMsg := struct {
		Type string `json:"type"`
		Data struct {
			SessionID   string `json:"session_id"`
			MessageType string `json:"message_type"`
			TotalChunks int    `json:"total_chunks"`
			TotalSize   int    `json:"total_size"`
		} `json:"data"`
	}{
		Type: "generic_message_chunk_complete",
	}
	completeMsg.Data.SessionID = sessionID
	completeMsg.Data.MessageType = msgType
	completeMsg.Data.TotalChunks = totalChunks
	completeMsg.Data.TotalSize = totalSize

	if completeJSON, err := json.Marshal(completeMsg); err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		h.hub.BroadcastToAll(ctx, completeJSON)
		cancel()
	}
}
